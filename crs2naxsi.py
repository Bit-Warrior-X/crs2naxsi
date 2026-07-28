#!/usr/bin/env python3
"""
crs2naxsi.py — Convert the translatable subset of OWASP CRS (ModSecurity SecLang)
rules into NAXSI (wargio/naxsi) MainRule format.

What it converts:
  - Single (non-chained) SecRule entries in request phases (1/2)
  - Operators: @rx (and implicit regex), @pm, @pmFromFile, @contains,
    @beginsWith, @endsWith, @streq
  - Request-side variables (ARGS, REQUEST_URI, REQUEST_HEADERS, cookies, files...)

What it skips (reported in stats):
  - Chained rules, TX/anomaly plumbing, ctl rules, response-phase rules,
    numeric/validation operators, @detectSQLi/@detectXSS (use NAXSI's native
    LibInjectionSql/LibInjectionXss instead)

CRS rule ids are preserved as NAXSI ids (900000+ range, no clash with
naxsi_core.rules 1000-1999), so NAXSI_FMT logs remain traceable to CRS docs
and whitelists can target original CRS ids.

Usage:
  python3 crs2naxsi.py /path/to/coreruleset/rules /path/to/output_dir
"""

import os
import re
import sys
from collections import defaultdict

# ---------------------------------------------------------------- mappings

# ModSecurity variable -> NAXSI matchzone fragment(s).
# ModSec ARGS covers GET+POST; NAXSI splits into ARGS (GET) and BODY (POST).
VAR_MAP = {
    "ARGS": ["ARGS", "BODY"],
    "ARGS_GET": ["ARGS"],
    "ARGS_POST": ["BODY"],
    "ARGS_NAMES": ["ARGS|NAME", "BODY|NAME"],
    "ARGS_GET_NAMES": ["ARGS|NAME"],
    "ARGS_POST_NAMES": ["BODY|NAME"],
    "REQUEST_BODY": ["BODY"],
    "REQUEST_URI": ["URL", "ARGS"],       # ModSec URI includes query string
    "REQUEST_URI_RAW": ["URL", "ARGS"],
    "REQUEST_FILENAME": ["URL"],
    "REQUEST_BASENAME": ["URL"],
    "PATH_INFO": ["URL"],
    "QUERY_STRING": ["ARGS"],
    "REQUEST_HEADERS": ["HEADERS"],
    "REQUEST_HEADERS_NAMES": ["HEADERS|NAME"],
    "REQUEST_COOKIES": ["$HEADERS_VAR:cookie"],
    "REQUEST_COOKIES_NAMES": ["$HEADERS_VAR:cookie"],
    "FILES": ["FILE_EXT"],
    "FILES_NAMES": ["FILE_EXT"],
    "REQUEST_LINE": ["URL", "ARGS"],
    "XML": None,          # unsupported -> skip rule
    "REQUEST_METHOD": None,
    "REQUEST_PROTOCOL": None,
    "REQBODY_PROCESSOR": None,
    "MULTIPART_PART_HEADERS": None,
}

# Rules that are meaningless (or dangerously broad) once removed from their
# CRS chain/anomaly context. These match benign traffic when emitted standalone.
QUARANTINE = {
    "921170",  # HPP: counts duplicate params via tx vars; standalone matches every param name
    "921160",  # HPP variant, same problem
    "920250",  # UTF8 validity, stateful
}

# CRS rule-id family -> NAXSI named score counter
FAMILY_SCORE = {
    "913": "$SCANNER",
    "920": "$PROTOCOL",
    "921": "$PROTOCOL",
    "922": "$PROTOCOL",
    "930": "$TRAVERSAL",   # LFI
    "931": "$RFI",
    "932": "$RCE",
    "933": "$PHP",
    "934": "$GENERIC",
    "941": "$XSS",
    "942": "$SQL",
    "943": "$SESSFIX",
    "944": "$JAVA",
}

# CRS severity -> score increment (thresholds below assume BLOCK at >= 8,
# i.e. one CRITICAL match blocks, two ERROR matches block, etc.)
SEVERITY_SCORE = {"CRITICAL": 8, "ERROR": 4, "WARNING": 2, "NOTICE": 1}

# Transformations NAXSI effectively applies natively (url/hex decode,
# case-insensitive matching). Others are lost; rule still emitted with a note.
NATIVE_TRANSFORMS = {
    "none", "lowercase", "urldecode", "urldecodeuni", "utf8tounicode",
}

# ------------------------------------------------------------- seclang parse

def read_logical_lines(path):
    """Join backslash-continued lines."""
    out, buf = [], ""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if buf:
                buf += " " + line.strip()
            else:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                buf = line.strip()
            if buf.endswith("\\"):
                buf = buf[:-1].rstrip()
                continue
            out.append(buf)
            buf = ""
    if buf:
        out.append(buf)
    return out


def split_secrule(line):
    """Split 'SecRule VARS "OP" "ACTIONS"' respecting quotes."""
    if not line.startswith("SecRule"):
        return None
    rest = line[len("SecRule"):].strip()
    parts, cur, inq, i = [], "", False, 0
    while i < len(rest):
        c = rest[i]
        if c == '"':
            inq = not inq
            cur += c
        elif c in " \t" and not inq:
            if cur:
                parts.append(cur)
                cur = ""
        else:
            cur += c
        i += 1
    if cur:
        parts.append(cur)
    if len(parts) < 2:
        return None
    variables = parts[0]
    op = parts[1].strip('"')
    actions = parts[2].strip('"') if len(parts) > 2 else ""
    return variables, op, actions


def parse_actions(actions):
    """Split action string on commas outside quotes."""
    items, cur, inq = [], "", False
    for c in actions:
        if c == "'":
            inq = not inq
            cur += c
        elif c == "," and not inq:
            items.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        items.append(cur.strip())
    d = defaultdict(list)
    for it in items:
        if ":" in it:
            k, v = it.split(":", 1)
            d[k.strip()].append(v.strip().strip("'"))
        else:
            d[it.strip()].append(True)
    return d

# ------------------------------------------------------------ nginx escaping

def nginx_safe_regex(rx):
    """
    Make a PCRE pattern safe inside an nginx double-quoted string:
      - '$' followed by [A-Za-z0-9_{] triggers nginx variable interpolation
        -> replace that '$' with \\x24 (valid inside and outside char classes)
      - escape embedded double quotes
    """
    out = []
    for i, c in enumerate(rx):
        if c == "$" and i + 1 < len(rx) and (rx[i + 1].isalnum() or rx[i + 1] in "_{"):
            out.append(r"\x24")
        elif c == '"':
            out.append(r"\x22")
        elif c == "'":
            out.append(r"\x27")
        else:
            out.append(c)
    # nginx's tokenizer collapses \\ -> \ and unescapes \" \' inside quoted
    # strings (ngx_conf_file.c); double every backslash so the regex survives
    # the unescape pass intact.
    return "".join(out).replace("\\", "\\\\")


def pm_to_regex(words):
    toks = [re.escape(w) for w in words if w]
    return "(?:" + "|".join(toks) + ")"

# ---------------------------------------------------------------- conversion

def map_variables(varstr):
    """Return (zones, skipped_selector) or (None, reason)."""
    zones, seen = [], set()
    for v in varstr.split("|"):
        v = v.strip()
        if v.startswith("!"):          # exclusions unsupported -> ignore selector
            continue
        if v.startswith("&"):
            continue  # count-variables can't map; drop this selector
        sel = None
        if ":" in v:
            v, sel = v.split(":", 1)
        base = VAR_MAP.get(v, "MISSING")
        if base == "MISSING":
            if v.startswith("TX") or v.startswith("GLOBAL") or v.startswith("IP"):
                return None, "TX/collection variable"
            continue  # unknown request var: drop selector, keep the rest
        if base is None:
            continue  # explicitly unsupported (XML, REQUEST_METHOD...): drop selector
        if sel and v == "REQUEST_HEADERS":
            sel = sel.strip("'").lower()
            if sel.startswith("/"):    # regex header selector
                zones_add = ["HEADERS"]
            else:
                zones_add = [f"$HEADERS_VAR:{sel}"]
        elif sel and v in ("ARGS", "ARGS_GET", "ARGS_POST"):
            sel = sel.strip("'").lower()
            if sel.startswith("/"):
                zones_add = VAR_MAP[v]
            else:
                zv = {"ARGS": ["$ARGS_VAR", "$BODY_VAR"],
                      "ARGS_GET": ["$ARGS_VAR"],
                      "ARGS_POST": ["$BODY_VAR"]}[v]
                zones_add = [f"{z}:{sel}" for z in zv]
        else:
            zones_add = base
        for z in zones_add:
            if z not in seen:
                seen.add(z)
                zones.append(z)
    if not zones:
        return None, "no mappable variables"
    return zones, None


def convert_file(path, data_dir, stats, skipped_log):
    rules_out = []
    lines = read_logical_lines(path)
    chain_skip = 0
    for line in lines:
        if chain_skip:
            # consume continuation rules of a skipped chain
            if line.startswith("SecRule"):
                sr = split_secrule(line)
                acts = parse_actions(sr[2]) if sr else {}
                chain_skip = 1 if "chain" in acts else 0
            continue
        if not line.startswith("SecRule"):
            continue
        sr = split_secrule(line)
        if not sr:
            continue
        variables, op, actions = sr
        acts = parse_actions(actions)
        rid = acts.get("id", [None])[0]

        if "chain" in acts:
            stats["skip:chained"] += 1
            skipped_log.append((rid, "chained rule"))
            chain_skip = 1
            continue
        if not rid:
            continue
        if rid in QUARANTINE:
            stats["skip:quarantine"] += 1
            skipped_log.append((rid, "quarantined: broad/stateful when standalone"))
            continue
        phase = acts.get("phase", ["2"])[0]
        if phase not in ("1", "2"):
            stats["skip:phase"] += 1
            skipped_log.append((rid, f"phase {phase}"))
            continue
        if "ctl" in acts or "skipAfter" in acts:
            stats["skip:control"] += 1
            skipped_log.append((rid, "ctl/skipAfter control rule"))
            continue

        # ---- operator
        neg = op.startswith("!")
        if neg:
            op = op[1:]
        pm_words = None
        if op.startswith("@rx "):
            pattern, kind = op[4:], "rx"
        elif not op.startswith("@"):
            pattern, kind = op, "rx"
        elif op.startswith("@pm "):
            pm_words = op[4:].split()
            pattern, kind = pm_to_regex(pm_words), "rx"
        elif op.startswith("@pmFromFile ") or op.startswith("@pmf "):
            fname = op.split(None, 1)[1].strip()
            fpath = os.path.join(data_dir, fname)
            if not os.path.exists(fpath):
                stats["skip:datafile"] += 1
                skipped_log.append((rid, f"missing data file {fname}"))
                continue
            words = []
            with open(fpath, encoding="utf-8", errors="replace") as df:
                for w in df:
                    w = w.strip()
                    if w and not w.startswith("#"):
                        words.append(w)
            if not words:
                stats["skip:datafile"] += 1
                continue
            pattern, kind = pm_to_regex(words), "rx"
            pm_words = words
        elif op.startswith("@contains "):
            pattern, kind = op[len("@contains "):], "str"
        elif op.startswith("@streq "):
            pattern, kind = "^" + re.escape(op[len("@streq "):]) + "$", "rx"
        elif op.startswith("@beginsWith "):
            pattern, kind = "^" + re.escape(op[len("@beginsWith "):]), "rx"
        elif op.startswith("@endsWith "):
            pattern, kind = re.escape(op[len("@endsWith "):]) + "$", "rx"
        else:
            stats["skip:operator"] += 1
            skipped_log.append((rid, f"operator {op.split()[0]}"))
            continue
        if neg:
            # NAXSI 'negative' exists but semantics differ per-zone; safer to skip
            stats["skip:negated"] += 1
            skipped_log.append((rid, "negated operator"))
            continue

        # ---- variables
        zones, err = map_variables(variables)
        if zones is None:
            stats["skip:vars"] += 1
            skipped_log.append((rid, err))
            continue

        # ---- score
        family = rid[:3]
        counter = FAMILY_SCORE.get(family, "$GENERIC")
        sev = acts.get("severity", ["WARNING"])[0].upper().strip("'")
        score = SEVERITY_SCORE.get(sev, 2)

        # ---- transformations lost?
        transforms = {t.lower() for t in acts.get("t", [])}
        lost = transforms - NATIVE_TRANSFORMS
        note = f" [LOST t:{','.join(sorted(lost))}]" if lost else ""

        msg = acts.get("msg", [""])[0].replace('"', "'")
        mz = "|".join(zones)
        prefix = "str" if kind == "str" else "rx"
        MAX_PAT = 3500  # nginx single-token limit is 4096 incl. "rx:" and quotes

        def emit(pat, rule_id, extra=""):
            rules_out.append(
                f'MainRule "{prefix}:{pat}" "msg:CRS {rid}{extra} {msg}{note}" '
                f'"mz:{mz}" "s:{counter}:{score}" id:{rule_id};'
            )

        # NAXSI treats NAME as a rule-wide "match the arg/header *name*"
        # modifier, not a per-zone flag. Mixing value-zones (ARGS, BODY) and
        # name-zones (ARGS|NAME) in one rule makes the whole rule match names
        # only. Split them into two rules with distinct ids.
        name_zones = [z for z in zones if z.endswith("NAME")]
        val_zones = [z for z in zones if not z.endswith("NAME")]
        if name_zones and val_zones:
            mz = "|".join(val_zones)
            # emit the NAME variant as id + 500000 offset
            nmz = "|".join(name_zones)
            def emit_name(pat):
                rules_out.append(
                    f'MainRule "{prefix}:{pat}" "msg:CRS {rid} (names){note}" '
                    f'"mz:{nmz}" "s:{counter}:{score}" id:{int(rid) + 500000};'
                )
            pat_n = nginx_safe_regex(pattern)
            if len(pat_n) <= MAX_PAT:
                emit_name(pat_n)
        elif name_zones:
            mz = "|".join(name_zones)
        else:
            mz = "|".join(val_zones)

        pattern = nginx_safe_regex(pattern)
        if len(pattern) <= MAX_PAT:
            emit(pattern, rid)
            stats["converted"] += 1
        elif pm_words:
            # chunk word list into multiple rules: id -> id*100 + n
            chunks, cur = [], []
            for w in pm_words:
                cur.append(w)
                if len(pm_to_regex(cur)) > MAX_PAT - 200:
                    chunks.append(cur[:-1]); cur = [cur[-1]]
            if cur:
                chunks.append(cur)
            for n, chunk in enumerate(chunks, 1):
                emit(nginx_safe_regex(pm_to_regex(chunk)), int(rid) * 100 + n,
                     extra=f" part {n}/{len(chunks)}")
            stats["converted"] += 1
            stats["chunked"] += 1
        else:
            stats["skip:too_long"] += 1
            skipped_log.append((rid, f"regex too long ({len(pattern)} chars)"))
    return rules_out


def main():
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "coreruleset/rules"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "naxsi_crs"
    os.makedirs(out_dir, exist_ok=True)
    stats = defaultdict(int)
    skipped_log = []
    counters = set()

    for fn in sorted(os.listdir(rules_dir)):
        if not fn.endswith(".conf") or not fn.startswith("REQUEST-9"):
            continue
        if any(x in fn for x in ("901-", "905-", "949-", "999-")):
            continue  # CRS init/exception/evaluation machinery
        rules = convert_file(os.path.join(rules_dir, fn), rules_dir, stats, skipped_log)
        if not rules:
            continue
        out_name = fn.replace(".conf", ".rules").lower()
        with open(os.path.join(out_dir, out_name), "w") as f:
            f.write(f"# Auto-converted from CRS {fn} by crs2naxsi.py\n")
            f.write("# Review before production use. NAXSI whitelists: wl:<crs_id>\n\n")
            f.write("\n".join(rules) + "\n")
        for r in rules:
            m = re.search(r's:(\$[A-Z_]+):', r)
            if m:
                counters.add(m.group(1))
        print(f"{fn}: {len(rules)} rules -> {out_name}")

    # CheckRule snippet
    with open(os.path.join(out_dir, "checkrules.conf"), "w") as f:
        f.write("# Add inside each protected location{} (thresholds: tune per app)\n")
        for c in sorted(counters):
            f.write(f'CheckRule "{c} >= 8" BLOCK;\n')

    with open(os.path.join(out_dir, "skipped.log"), "w") as f:
        for rid, reason in skipped_log:
            f.write(f"{rid}\t{reason}\n")

    print("\n--- stats ---")
    for k in sorted(stats):
        print(f"{k}: {stats[k]}")


if __name__ == "__main__":
    main()