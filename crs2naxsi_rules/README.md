# CRS → NAXSI converted rules

Auto-generated from OWASP CRS (ModSecurity SecLang) into NAXSI MainRule format
by `crs2naxsi.py`. Validated against wargio/naxsi built on nginx: config loads,
all regexes compile, benign traffic passes, and SQLi/XSS/LFI/RCE/RFI/PHP/Log4Shell
payloads are blocked.

## What you get
- `request-9xx-*.rules` — converted MainRule sets, one file per CRS category
- `checkrules.conf` — the `CheckRule "$SCORE >= N" BLOCK;` thresholds to enable them
- `skipped.log` — every CRS rule that was NOT converted, with the reason

## Install
1. Copy `*.rules` and `checkrules.conf` next to your naxsi rules
   (e.g. `/etc/nginx/naxsi/crs/`).
2. In the `http {}` block, after `naxsi_core.rules`:
       include /etc/nginx/naxsi/crs/*.rules;
3. In each protected `location {}` (alongside SecRulesEnabled / DeniedUrl):
       include /etc/nginx/naxsi/crs/checkrules.conf;
   Keep NAXSI's native libinjection on — it covers SQLi/XSS better than regex:
       LibInjectionSql; LibInjectionXss;
       CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
       CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
4. `nginx -t`, then reload.

## IMPORTANT: deploy in LearningMode first
The converted rules WILL cause false positives on a real app. Add `LearningMode;`
to the location, run production traffic through it, collect the NAXSI_FMT log
lines, and turn matched benign ids into whitelists BEFORE removing LearningMode:
    BasicRule wl:942152 "mz:$ARGS_VAR:description";   # example
CRS ids are preserved, so a log `id0=942152` maps straight to CRS docs.

## Known limitations (see skipped.log for the full list)
- Chained rules, ctl/anomaly-scoring, TX collections: NOT converted (~150 rules).
  NAXSI has no equivalent to CRS's stateful anomaly engine.
- Lost transformations (base64Decode, cmdLine, normalizePath, htmlEntityDecode)
  are flagged inline as `[LOST t:...]`; those rules are weaker vs evasion.
- 11 pmFromFile rules whose combined regex exceeds nginx's ~4KB token limit and
  couldn't be word-chunked are skipped.
- A few broad/stateful rules (921170 HPP etc.) are quarantined — they match
  benign traffic when torn out of their chain.
- Threshold in checkrules.conf defaults to >=8. Tune per family; NAXSI docs
  suggest $TRAVERSAL >= 5.
