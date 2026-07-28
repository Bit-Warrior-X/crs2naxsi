# CRS → NAXSI converter (`crs2naxsi`)

Convert [OWASP Core Rule Set](https://coreruleset.org/) (ModSecurity SecLang) into [NAXSI](https://github.com/wargio/naxsi) `MainRule` files for nginx / OpenResty WAF builds.

> **CRS and NAXSI are different engines.** This tool converts the *translatable* subset (regex / phrase / string matches on request data). It does **not** recreate CRS anomaly scoring, TX collections, or real response-body inspection. Treat the output as a strong starting ruleset, then tune with `LearningMode` and whitelists.

## Table of contents

- [Quick start](#quick-start)
- [What gets converted](#what-gets-converted)
- [Output layout](#output-layout)
- [Score families](#score-families-checkrule)
- [Response rules (950–956)](#response-rules-950956--important)
- [CRS files that mostly do not convert](#crs-files-that-mostly-do-not-convert)
- [Install into nginx / OpenResty](#install-into-nginx--openresty)
- [LearningMode first](#learningmode-first-required-for-production)
- [Known limitations](#known-limitations)
- [Whitelist / log tips](#whitelist--log-tips)
- [Regenerating after CRS updates](#regenerating-after-crs-updates)
- [Project layout](#project-layout)

---

## Quick start

```bash
cd crs2naxsi
python3 crs2naxsi.py --self-test
python3 crs2naxsi.py coreruleset/rules crs2naxsi_rules

# Only paranoia levels 1–2 (fewer / safer rules):
python3 crs2naxsi.py --max-paranoia 2 coreruleset/rules crs2naxsi_rules_pl2
```

| Requirement | Notes |
|---|---|
| Python | 3.8+ (stdlib only) |
| CRS tree | `rules_dir` must include `*.conf` **and** `*.data` phrase lists (`sql-errors.data`, etc.) |

```text
python3 crs2naxsi.py [-h] [--max-paranoia {1,2,3,4}] [--self-test] [rules_dir] [out_dir]
```

---

## What gets converted

### CRS files

| Pattern | Role |
|---|---|
| `REQUEST-9xx-*.conf` | Attack / protocol / scanner / multipart / … |
| `RESPONSE-9xx-*.conf` | Leakage / webshell signatures ([adapted](#response-rules-950956--important)) |
| `REQUEST-900-*.conf.example` | Scanned; usually produces 0 MainRules |

### Operators

| ModSecurity | NAXSI result |
|---|---|
| `@rx`, implicit regex | `rx:…` |
| `@pm`, `@pmFromFile` / `@pmf` | `rx:` alternation (chunked if needed) |
| `@contains` | `str:…` |
| `@streq`, `@beginsWith`, `@endsWith` | `rx:` anchors |
| `@within` (literal lists) | `rx:` alternation; **TX macros skipped** |
| `@validateByteRange` (common ranges) | Forbidden-byte `rx:` |
| `!@rx` and other negations | `MainRule negative …` |
| `@detectSQLi` / `@detectXSS` | Notes in [`libinjection.conf`](crs2naxsi_rules/libinjection.conf) → use native LibInjection |

### Other behavior

- Non-chained rules in phases **1–4**
- **Chain heads** when the parent has a usable operator (TX/MATCHED_VARS children dropped)
- Oversized regexes split into multiple MainRules (`id`, `id*100+n`, …)
- `ARGS_NAMES` / `BODY\|NAME` split into separate rules (`id+500000`) — NAXSI treats `NAME` as a rule-wide flag

CRS rule ids are preserved (900000+ range), so NAXSI_FMT `id0=942152` maps to CRS docs and to:

```nginx
BasicRule wl:942152 "mz:$ARGS_VAR:description";
```

---

## Output layout

Generated under [`crs2naxsi_rules/`](crs2naxsi_rules/):

| File | Description |
|---|---|
| `request-9xx-*.rules` | Converted request MainRules (one file per CRS category) |
| `response-9xx-*.rules` | Adapted response signatures |
| `checkrules.conf` | `CheckRule "$FAMILY >= 8" BLOCK;` for every score used |
| [`checkrules.txt`](checkrules.txt) | Same CheckRules with inline documentation (repo root copy) |
| `libinjection.conf` | `LibInjectionSql` / `LibInjectionXss` + CRS id notes |
| `method-enforcement.example.conf` | nginx stand-in for CRS **911100** (allowed methods) |
| `include.example.conf` | Sample `location {}` include list |
| `crs-machinery.notes` | Why 901/949/959/980/etc. emit few/no MainRules |
| `skipped.log` | Every skipped CRS id + reason (tab-separated) |

### Typical stats (OWASP CRS ~4.29, `--max-paranoia 4`)

| Metric | Approx. |
|---|---|
| CRS rules converted | ~312 (+ ~4 libinjection notes) |
| Adapted from `RESPONSE_*` | ~57 |
| Salvaged chain heads | ~31 |
| Skipped | ~300 (mostly `ctl`/`skipAfter` + TX/`@eq`/`@gt`) |

---

## Score families (`CheckRule`)

Converted rules score into named counters. Defaults block when a counter reaches **8** (one CRITICAL hit, or several smaller ones).

| Score | Typical CRS families |
|---|---|
| `$SQL` | 942 |
| `$XSS` | 941 |
| `$RCE` | 932 |
| `$RFI` | 931 |
| `$TRAVERSAL` | 930 (LFI) |
| `$PHP` | 933 |
| `$JAVA` | 944 |
| `$SCANNER` | 913 |
| `$PROTOCOL` | 920–922, 911 |
| `$SESSFIX` | 943 |
| `$GENERIC` | 934 |
| `$LEAKAGE` | 950–954, 956 |
| `$WEBSHELL` | 955 |
| `$EXCEPTION` | 900 / 905 |

Severity → score used by the converter:

| CRS severity | Score |
|---|---|
| CRITICAL | +8 |
| ERROR | +4 |
| WARNING | +2 |
| NOTICE | +1 |

Tune per app:

```nginx
CheckRule "$TRAVERSAL >= 5" BLOCK;
CheckRule "$SQL >= 8" BLOCK;
```

See [`checkrules.txt`](checkrules.txt) and [`crs2naxsi_rules/checkrules.conf`](crs2naxsi_rules/checkrules.conf).

---

## Response rules (950–956) — important

NAXSI has **no** `RESPONSE_BODY` match zone. CRS response leakage / webshell rules are **adapted** onto request zones:

```text
mz:ARGS|BODY|URL|HEADERS
```

Messages are tagged:

```text
[adapted CRS response→request; NAXSI has no response MZ]
```

They can still catch error strings / webshell markers in **requests**, but they do **not** inspect HTTP responses. For real outbound leakage detection, use a separate response filter (e.g. OpenResty body filter), not NAXSI.

---

## CRS files that mostly do not convert

| CRS file | What to use instead |
|---|---|
| `REQUEST-900-*` | Exclusion templates → `BasicRule wl:<id>` by hand |
| `REQUEST-901-*` | Initialization / TX setup → NAXSI `LearningMode` + `CheckRule` |
| `REQUEST-905` / `999` | Exception / skip machinery → manual whitelists |
| `REQUEST-911-*` | Method policy → [`method-enforcement.example.conf`](crs2naxsi_rules/method-enforcement.example.conf) |
| `REQUEST-949-*` | Inbound anomaly evaluation → `checkrules.conf` |
| `RESPONSE-959-*` | Outbound anomaly evaluation → `checkrules.conf` |
| `RESPONSE-980-*` | Correlation / logging only → no NAXSI equivalent |

Details: [`crs-machinery.notes`](crs2naxsi_rules/crs-machinery.notes), [`skipped.log`](crs2naxsi_rules/skipped.log).

---

## Install into nginx / OpenResty

1. Copy generated files next to your NAXSI rules, e.g. `/etc/nginx/naxsi/crs/`.

2. In `http {}` (or the context that loads MainRules), after `naxsi_core.rules`:

   ```nginx
   include /etc/nginx/naxsi/crs/*.rules;
   ```

   Or include only the categories you want (recommended at first).

3. In each protected `location {}`:

   ```nginx
   SecRulesEnabled;
   # LearningMode;          # enable first — see below
   DeniedUrl /RequestDenied;
   include /etc/nginx/naxsi/crs/checkrules.conf;
   include /etc/nginx/naxsi/crs/libinjection.conf;
   ```

4. Keep native libinjection enabled — it covers many SQLi/XSS cases better than regex alone:

   ```nginx
   LibInjectionSql;
   LibInjectionXss;
   ```

5. Test and reload:

   ```bash
   nginx -t && nginx -s reload
   ```

See [`include.example.conf`](crs2naxsi_rules/include.example.conf) for a full location skeleton.

---

## LearningMode first (required for production)

Converted CRS rules **will** false-positive on real applications.

1. Add `LearningMode;` to the location  
2. Pass production (or staging) traffic  
3. Collect `NAXSI_FMT` / extensive log lines  
4. Whitelist legitimate hits, then remove `LearningMode`

Example whitelist (CRS id preserved):

```nginx
BasicRule wl:942152 "mz:$ARGS_VAR:description";
```

Prefer narrow whitelists (specific `$ARGS_VAR` / `$BODY_VAR` / `$URL`) over global `wl:id` with no match zone.

---

## Known limitations

- **No CRS anomaly engine** — NAXSI uses per-hit scores + `CheckRule` thresholds, not `TX:inbound_anomaly_score_plN`.
- **`ctl` / `skipAfter` / paranoia gates** — skipped (~200 ids). Use `--max-paranoia` instead of CRS `TX:DETECTION_PARANOIA_LEVEL`.
- **Chained rules** — only convertible heads are emitted; refinement children are lost.
- **Lost transformations** (`base64Decode`, `cmdLine`, `htmlEntityDecode`, …) are marked inline as `[LOST t:…]`; those rules are weaker against evasion.
- **`@eq` / `@gt` / `@ge`** on `&HEADER` counts, `REQUEST_METHOD`, `RESPONSE_STATUS`, and TX-macro `@within` are not expressible as MainRules.
- **Quarantined** standalone-dangerous rules (e.g. `921170` HPP) — see `QUARANTINE` in [`crs2naxsi.py`](crs2naxsi.py) / `skipped.log`.
- **Huge regexes** are chunked; a few fragments may match slightly more broadly when a shared suffix had to be dropped to fit nginx’s ~4KB token limit.
- **Response-adapted rules** are not a substitute for response body scanning.

---

## Whitelist / log tips

| Log / id pattern | Meaning |
|---|---|
| `id0=<crs_id>` | Look up CRS docs or `msg:CRS <id>` in the `.rules` file |
| `id = original + 500000` | Name-zone twin rule |
| `id*100+n` | Chunked rule parts (`n > 1`) |

Messages may include `[PL2]`, `[chain head]`, `[LOST t:…]`, `[adapted CRS response→request…]`.

---

## Regenerating after CRS updates

```bash
git -C coreruleset pull   # or replace the CRS tree
python3 crs2naxsi.py coreruleset/rules crs2naxsi_rules
diff -ru crs2naxsi_rules.bak crs2naxsi_rules   # review before deploy
```

Always re-run **LearningMode** after regenerating.

---

## Unit tests

Test::Nginx cases live in [`../unit-tests/tests/039crs_converted_rules.t`](../unit-tests/tests/039crs_converted_rules.t). They load generated files from `crs2naxsi_rules/` and exercise representative SQLi / XSS / LFI / RFI / RCE / PHP / Java / leakage / webshell payloads, plus whitelist and multi-file load smoke tests.

```bash
# from repo (requires OpenResty + Test::Nginx as for other naxsi .t files)
cd ../unit-tests/tests
./test_naxsi 039crs_converted_rules.t
# verbose:
./test_naxsi -v 039crs_converted_rules.t
```

`./test_naxsi` sets `TEST_NGINX_NAXSI_CRS_RULES` to `crs2naxsi/crs2naxsi_rules` automatically.

---

## Project layout

```text
crs2naxsi/
├── crs2naxsi.py           # Converter
├── checkrules.txt         # Documented CheckRule snippet
├── README.md              # This file
├── coreruleset/           # OWASP CRS sources (rules/*.conf, *.data)
└── crs2naxsi_rules/       # Generated NAXSI rules + helpers
```

## License / attribution

- Converter: part of this repository’s nginx WAF / NAXSI packaging.
- Rule *content* originates from [OWASP CRS](https://github.com/coreruleset/coreruleset) (Apache-2.0). Review CRS licensing before redistribution of generated rule files.
