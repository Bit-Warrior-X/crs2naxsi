CRS → NAXSI converter (crs2naxsi)
================================

Convert OWASP Core Rule Set (ModSecurity SecLang) into NAXSI MainRule files
for use with wargio/naxsi (or compatible nginx WAF builds).

CRS and NAXSI are different engines. This tool converts the *translatable*
subset (regex / phrase / string matches on request data). It does NOT
recreate CRS's full anomaly-scoring, TX collections, or response-body
inspection. Treat the output as a strong starting ruleset, then tune with
LearningMode and whitelists.


1. Quick start
--------------

  cd crs2naxsi
  python3 crs2naxsi.py --self-test
  python3 crs2naxsi.py coreruleset/rules crs2naxsi_rules

  # Only paranoia levels 1–2 (fewer / safer rules):
  python3 crs2naxsi.py --max-paranoia 2 coreruleset/rules crs2naxsi_rules_pl2

Requirements: Python 3.8+ (stdlib only). Point rules_dir at a CRS `rules/`
tree that still contains the `*.data` phrase lists (sql-errors.data, etc.).


2. What gets converted
----------------------

Included CRS files:
  REQUEST-9xx-*.conf          (attack / protocol / scanner / multipart / …)
  RESPONSE-9xx-*.conf         (leakage / webshell signatures — see §5)
  REQUEST-900-*.conf.example  (scanned; usually produces 0 MainRules)

Operators:
  @rx, implicit regex
  @pm, @pmFromFile / @pmf
  @contains, @streq, @beginsWith, @endsWith
  @within          (literal word lists only; TX macros skipped)
  @validateByteRange (common CRS ranges → forbidden-byte regex)
  !@rx / other negated forms → NAXSI `MainRule negative …`
  @detectSQLi / @detectXSS → notes in libinjection.conf (use native LibInjection)

Also:
  - Non-chained rules in phases 1–4
  - Chain *heads* when the parent has a usable operator (children that only
    refine via TX/MATCHED_VARS are dropped)
  - Oversized regexes split into multiple MainRules (id, id*100+n, …)
  - ARGS_NAMES / BODY|NAME split into separate rules (id+500000) because
    NAXSI treats NAME as a rule-wide flag

CRS rule ids are preserved (900000+ range), so NAXSI_FMT `id0=942152` maps
to CRS documentation and to `BasicRule wl:942152 …`.


3. Output layout (crs2naxsi_rules/)
-----------------------------------

  request-9xx-*.rules              Converted request MainRules (one file per CRS category)
  response-9xx-*.rules             Adapted response signatures (see §5)
  checkrules.conf                  CheckRule "$FAMILY >= 8" BLOCK; for every score used
  libinjection.conf                LibInjectionSql / LibInjectionXss + CRS id notes
  method-enforcement.example.conf  nginx stand-in for CRS 911100 (allowed methods)
  include.example.conf             Sample location{} include list
  crs-machinery.notes              Why 901/949/959/980/etc. emit few/no MainRules
  skipped.log                      Every skipped CRS id + reason (tab-separated)

Typical conversion stats (OWASP CRS ~4.29, --max-paranoia 4):
  ~312 CRS rules converted (+ ~4 libinjection notes)
  ~57  of those adapted from RESPONSE_* rules
  ~31  salvaged from chain heads
  ~300 skipped (mostly ctl/skipAfter paranoia gates and TX/@eq/@gt machinery)


4. Score families (CheckRule)
-----------------------------

Converted rules score into named counters. Defaults in checkrules.conf
block when a counter reaches 8 (one CRITICAL hit, or several smaller ones):

  $SQL $XSS $RCE $RFI $TRAVERSAL $PHP $JAVA $SCANNER $PROTOCOL
  $SESSFIX $GENERIC $LEAKAGE $WEBSHELL $EXCEPTION

Tune per app, for example:
  CheckRule "$TRAVERSAL >= 5" BLOCK;
  CheckRule "$SQL >= 8" BLOCK;


5. Response rules (950–956) — important
---------------------------------------

NAXSI has no RESPONSE_BODY match zone. CRS response leakage / webshell
rules are *adapted* onto request zones:

  mz:ARGS|BODY|URL|HEADERS

Messages are tagged:
  [adapted CRS response→request; NAXSI has no response MZ]

They can still catch error strings / webshell markers in *requests*, but
they do NOT inspect HTTP responses. For real outbound leakage detection
you need a separate response filter (e.g. OpenResty body filter), not NAXSI.


6. CRS files that mostly do not convert
---------------------------------------

  REQUEST-900-*     Exclusion templates → write BasicRule wl:<id> by hand
  REQUEST-901-*     Initialization / TX setup → NAXSI LearningMode + CheckRule
  REQUEST-905/999   Exception / skip machinery → manual whitelists
  REQUEST-911-*     Method policy → method-enforcement.example.conf (nginx)
  REQUEST-949-*     Inbound anomaly evaluation → checkrules.conf
  RESPONSE-959-*    Outbound anomaly evaluation → checkrules.conf
  RESPONSE-980-*    Correlation / logging only → no NAXSI equivalent

See crs-machinery.notes and skipped.log for details.


7. Install into nginx / OpenResty
---------------------------------

1. Copy generated files next to your NAXSI rules, e.g.:
     /etc/nginx/naxsi/crs/

2. In http {} (or the server that loads MainRules), after naxsi_core.rules:
     include /etc/nginx/naxsi/crs/*.rules;
   Or include only the categories you want (recommended at first).

3. In each protected location {}:
     SecRulesEnabled;
     # LearningMode;          # enable first — see §8
     DeniedUrl /RequestDenied;
     include /etc/nginx/naxsi/crs/checkrules.conf;
     include /etc/nginx/naxsi/crs/libinjection.conf;
     # optional: include method-enforcement.example.conf logic via nginx if/limit_except

4. Keep native libinjection enabled — it covers many SQLi/XSS cases better
   than regex alone:
     LibInjectionSql;
     LibInjectionXss;

5. nginx -t && reload.

See include.example.conf for a full location skeleton.


8. LearningMode first (required for production)
-----------------------------------------------

Converted CRS rules will false-positive on real applications.

  1. Add LearningMode; to the location
  2. Pass production (or staging) traffic
  3. Collect NAXSI_FMT / extensive log lines
  4. Whitelist legitimate hits, then remove LearningMode

Example whitelist (CRS id preserved):
  BasicRule wl:942152 "mz:$ARGS_VAR:description";

Prefer narrow whitelists (specific $ARGS_VAR / $BODY_VAR / $URL) over
global wl:id with no match zone.


9. Known limitations
--------------------

- No CRS anomaly engine: NAXSI uses per-hit scores + CheckRule thresholds,
  not TX inbound_anomaly_score_plN.
- ctl / skipAfter / paranoia gates: skipped (~200 ids). Use --max-paranoia
  instead of CRS TX:DETECTION_PARANOIA_LEVEL.
- Chained rules: only convertible heads are emitted; refinement children lost.
- Lost transformations (base64Decode, cmdLine, htmlEntityDecode, …) are
  marked inline as [LOST t:…]; those rules are weaker against evasion.
- @eq / @gt / @ge on &HEADER counts, REQUEST_METHOD, RESPONSE_STATUS, and
  TX-macro @within: not expressible as MainRules.
- Quarantined standalone-dangerous rules (e.g. 921170 HPP): see QUARANTINE
  in crs2naxsi.py / skipped.log.
- Huge regexes are chunked; a few fragments may match slightly more broadly
  when a shared suffix had to be dropped to fit nginx's ~4KB token limit.
- Response-adapted rules are not a substitute for response body scanning.


10. Whitelist / log tips
------------------------

- Log field id0=<crs_id> → look up CRS docs or msg:CRS <id> in the .rules file
- Name-zone twin rules use id = original + 500000
- Chunked rules: first part keeps CRS id; further parts use id*100+n
- Messages may include [PL2], [chain head], [LOST t:…], [adapted CRS response→request…]


11. Regenerating after CRS updates
----------------------------------

  git -C coreruleset pull   # or replace the CRS tree
  python3 crs2naxsi.py coreruleset/rules crs2naxsi_rules
  diff -ru crs2naxsi_rules.bak crs2naxsi_rules   # review before deploy

Always re-run LearningMode after regenerating.

