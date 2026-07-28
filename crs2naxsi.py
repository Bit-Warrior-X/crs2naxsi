#!/usr/bin/env python3
"""
crs2naxsi.py — Convert the translatable subset of OWASP CRS (ModSecurity SecLang)
rules into NAXSI (wargio/naxsi) MainRule format.

What it converts:
  - REQUEST-9xx and RESPONSE-9xx SecRule files (phases 1–4)
  - Chain *heads* with a convertible operator (children often only refine via TX)
  - Operators: @rx, @pm, @pmFromFile, @contains, @beginsWith, @endsWith, @streq,
    @within (literal lists), @validateByteRange (common ranges), negated forms
  - Request variables (ARGS, URI, headers, cookies, files, multipart headers…)
  - Response leak signatures (RESPONSE_BODY/@pmFromFile/@rx) adapted onto
    request match-zones (NAXSI cannot inspect response bodies natively)
  - @detectSQLi / @detectXSS → noted as native LibInjection directives

What it skips (reported in skipped.log):
  - Paranoia skipAfter/ctl machinery, TX/anomaly plumbing (901/949/959/980),
    count/numeric operators (@eq/@gt on &collections), TX-macro @within,
    and REQUEST_METHOD policy (see method-enforcement.example.conf)

CRS rule ids are preserved as NAXSI ids (900000+ range, no clash with
naxsi_core.rules 1000-1999). Name-zone twins use id+500000.

Usage:
  python3 crs2naxsi.py [rules_dir] [output_dir]
  python3 crs2naxsi.py --max-paranoia 2 coreruleset/rules crs2naxsi_rules
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict
from typing import Iterable, Optional

# ---------------------------------------------------------------- mappings

# ModSecurity variable -> NAXSI matchzone fragment(s).
# ModSec ARGS covers GET+POST; NAXSI splits into ARGS (GET) and BODY (POST).
#
# RESPONSE_* vars are adapted onto request zones: NAXSI has no response MZ,
# but CRS leak/webshell signatures remain useful on inbound traffic.
VAR_MAP = {
    "ARGS": ["ARGS", "BODY"],
    "ARGS_GET": ["ARGS"],
    "ARGS_POST": ["BODY"],
    "ARGS_NAMES": ["ARGS|NAME", "BODY|NAME"],
    "ARGS_GET_NAMES": ["ARGS|NAME"],
    "ARGS_POST_NAMES": ["BODY|NAME"],
    "REQUEST_BODY": ["BODY"],
    "REQUEST_URI": ["URL", "ARGS"],  # ModSec URI includes query string
    "REQUEST_URI_RAW": ["URL", "ARGS"],
    "REQUEST_FILENAME": ["URL"],
    "REQUEST_BASENAME": ["URL"],
    "PATH_INFO": ["URL"],
    "QUERY_STRING": ["ARGS"],
    "REQUEST_HEADERS": ["HEADERS"],
    "REQUEST_HEADERS_NAMES": ["HEADERS|NAME"],
    # Cookie *values* only. Cookie *names* have no NAXSI equivalent.
    "REQUEST_COOKIES": ["$HEADERS_VAR:Cookie"],
    "REQUEST_COOKIES_NAMES": None,
    "FILES": ["FILE_EXT"],
    "FILES_NAMES": ["FILE_EXT"],
    "REQUEST_LINE": ["URL", "ARGS"],
    # Multipart part headers ≈ request headers for matching purposes.
    "MULTIPART_PART_HEADERS": ["HEADERS"],
    "XML": None,
    "REQUEST_METHOD": None,
    "REQUEST_PROTOCOL": None,
    "REQBODY_PROCESSOR": None,
    # Response → request adaptation (see note on emitted rules)
    "RESPONSE_BODY": ["ARGS", "BODY", "URL", "HEADERS"],
    "RESPONSE_HEADERS": ["HEADERS"],
    "RESPONSE_HEADERS_NAMES": ["HEADERS|NAME"],
    "RESPONSE_CONTENT_TYPE": ["$HEADERS_VAR:content-type"],
    "RESPONSE_STATUS": None,
}

RESPONSE_VAR_PREFIXES = (
    "RESPONSE_BODY",
    "RESPONSE_HEADERS",
    "RESPONSE_CONTENT_TYPE",
    "RESPONSE_STATUS",
)

# Rules that are meaningless (or dangerously broad) once removed from their
# CRS chain/anomaly context. These match benign traffic when emitted standalone.
QUARANTINE = {
    "921170",  # HPP: counts duplicate params via tx vars
    "921160",  # HPP variant
    "920250",  # UTF8 validity, stateful
}

# CRS rule-id family -> NAXSI named score counter
FAMILY_SCORE = {
    "900": "$EXCEPTION",
    "901": "$PROTOCOL",
    "905": "$EXCEPTION",
    "911": "$PROTOCOL",
    "913": "$SCANNER",
    "920": "$PROTOCOL",
    "921": "$PROTOCOL",
    "922": "$PROTOCOL",
    "930": "$TRAVERSAL",  # LFI
    "931": "$RFI",
    "932": "$RCE",
    "933": "$PHP",
    "934": "$GENERIC",
    "941": "$XSS",
    "942": "$SQL",
    "943": "$SESSFIX",
    "944": "$JAVA",
    "949": "$PROTOCOL",
    "950": "$LEAKAGE",
    "951": "$LEAKAGE",
    "952": "$LEAKAGE",
    "953": "$LEAKAGE",
    "954": "$LEAKAGE",
    "955": "$WEBSHELL",
    "956": "$LEAKAGE",
    "959": "$PROTOCOL",
    "980": "$PROTOCOL",
    "999": "$EXCEPTION",
}

# CRS severity -> score increment (thresholds assume BLOCK at >= 8)
SEVERITY_SCORE = {"CRITICAL": 8, "ERROR": 4, "WARNING": 2, "NOTICE": 1}

# Transformations NAXSI effectively applies natively (url/hex decode,
# case-insensitive matching via (?i)). Others are lost; rule still emitted.
NATIVE_TRANSFORMS = {
    "none",
    "lowercase",
    "urldecode",
    "urldecodeuni",
    "utf8tounicode",
    "compresswhitespace",  # approximate; NAXSI does not strip whitespace
    "normalisepath",
    "normalisepathwin",
    "removenulls",
}

# nginx config token soft limit is 4096; leave room for "rx:" / quotes / mz.
MAX_PAT = 3900
NAME_ID_OFFSET = 500000
ALLOWED_PHASES = {"1", "2", "3", "4"}

# ------------------------------------------------------------- seclang parse


def read_logical_lines(path: str) -> list[str]:
    """Join backslash-continued lines; drop blank/comment-only physical lines."""
    out: list[str] = []
    buf = ""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if buf:
                buf += " " + line.strip()
            else:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                buf = stripped
            if buf.endswith("\\"):
                buf = buf[:-1].rstrip()
                continue
            out.append(buf)
            buf = ""
    if buf:
        out.append(buf)
    return out


def split_secrule(line: str) -> Optional[tuple[str, str, str]]:
    """Split 'SecRule VARS "OP" "ACTIONS"' respecting quotes and escapes."""
    if not line.startswith("SecRule"):
        return None
    rest = line[len("SecRule") :].strip()
    parts: list[str] = []
    cur = ""
    inq = False
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == "\\" and inq and i + 1 < len(rest):
            # Keep escape + next char so \" inside the actions string stays intact.
            cur += c + rest[i + 1]
            i += 2
            continue
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
    # Operator/actions sit inside SecLang double quotes; unescape \" \\ \' etc.
    op = _unescape_dq(parts[1].strip('"'))
    actions = _unescape_dq(parts[2].strip('"')) if len(parts) > 2 else ""
    return variables, op, actions


def _unescape_dq(s: str) -> str:
    """Interpret only SecLang double-quote escapes; keep regex escapes like \\s, \\xHH."""
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in '\\"\'':
                out.append(nxt)
                i += 2
                continue
            # Preserve regex/PCRE escapes (\s, \x0b, \b, ...).
            out.append("\\")
            out.append(nxt)
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _unescape_action_value(v: str) -> str:
    """Undo SecLang-ish escapes commonly found in CRS action values."""
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1]
    return _unescape_dq(v)


def parse_actions(actions: str) -> dict:
    """Split action string on commas outside single quotes."""
    items: list[str] = []
    cur = ""
    inq = False
    i = 0
    while i < len(actions):
        c = actions[i]
        if c == "\\" and i + 1 < len(actions):
            cur += c + actions[i + 1]
            i += 2
            continue
        if c == "'":
            inq = not inq
            cur += c
        elif c == "," and not inq:
            if cur.strip():
                items.append(cur.strip())
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        items.append(cur.strip())

    d: dict = defaultdict(list)
    for it in items:
        if ":" in it:
            k, v = it.split(":", 1)
            d[k.strip()].append(_unescape_action_value(v))
        else:
            d[it.strip()].append(True)
    return d


def sanitize_msg(msg: str) -> str:
    """Make msg safe inside a NAXSI double-quoted directive argument."""
    msg = msg.replace("\n", " ").replace("\r", " ")
    msg = msg.replace('"', "'").replace("\\", "/")
    # Collapse leftover escape noise from partial CRS parses.
    msg = re.sub(r"\\+'", "'", msg)
    return msg.strip()


def paranoia_level(acts: dict) -> int:
    for tag in acts.get("tag", []):
        m = re.search(r"paranoia-level/(\d+)", tag, re.I)
        if m:
            return int(m.group(1))
    return 1


# ------------------------------------------------------------ nginx escaping


def nginx_safe_regex(rx: str) -> str:
    """
    Make a PCRE pattern safe inside an nginx double-quoted string:
      - nginx interpolates $var; map every '$' to \\x24 (literal dollar for PCRE)
      - map " and ' to hex escapes so the config tokenizer cannot break
      - double every backslash so nginx's unescape pass leaves the regex intact
    """
    out: list[str] = []
    i = 0
    while i < len(rx):
        c = rx[i]
        # Drop a redundant '\' before '$' — both \$ and $ become \x24.
        if c == "\\" and i + 1 < len(rx) and rx[i + 1] == "$":
            out.append(r"\x24")
            i += 2
            continue
        if c == "$":
            out.append(r"\x24")
        elif c == '"':
            out.append(r"\x22")
        elif c == "'":
            out.append(r"\x27")
        else:
            out.append(c)
        i += 1
    return "".join(out).replace("\\", "\\\\")


def nginx_safe_str(s: str) -> str:
    """Escape a literal str: value for NAXSI (nginx-quoted, not a regex)."""
    out = []
    for c in s:
        if c == "$":
            out.append(r"\x24")
        elif c == '"':
            out.append(r"\x22")
        elif c == "'":
            out.append(r"\x27")
        else:
            out.append(c)
    return "".join(out).replace("\\", "\\\\")


def pm_to_regex(words: Iterable[str], ignore_case: bool = False) -> str:
    toks = [re.escape(w) for w in words if w]
    body = "(?:" + "|".join(toks) + ")"
    return ("(?i)" + body) if ignore_case else body


def ensure_ignore_case(pattern: str, ignore_case: bool) -> str:
    if not ignore_case:
        return pattern
    if pattern.startswith("(?i)") or pattern.startswith("(?i:"):
        return pattern
    return "(?i)" + pattern


def split_top_level_alternation(pattern: str) -> list[str]:
    """Split a regex on top-level '|' so oversized patterns can be chunked."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    in_class = False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            buf.append(c)
            buf.append(pattern[i + 1])
            i += 2
            continue
        if c == "[" and not in_class:
            in_class = True
            buf.append(c)
        elif c == "]" and in_class:
            in_class = False
            buf.append(c)
        elif not in_class:
            if c == "(":
                depth += 1
                buf.append(c)
            elif c == ")":
                depth = max(0, depth - 1)
                buf.append(c)
            elif c == "|" and depth == 0:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(c)
        else:
            buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf))
    return parts if len(parts) > 1 else [pattern]


def _skip_char_class(pattern: str, i: int) -> int:
    """Return index just past a character class starting at pattern[i] == '['."""
    i += 1
    if i < len(pattern) and pattern[i] == "^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        i += 1
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern):
            i += 2
            continue
        if pattern[i] == "]":
            return i + 1
        i += 1
    return i


def _iter_paren_groups(pattern: str):
    """Yield (group_start, body_start, body_end, group_end_exclusive)."""
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(pattern, i)
            continue
        if c == "(":
            group_start = i
            j = i + 1
            # Skip extension markers: ?: ?i: ?i etc. until body begins.
            if j < n and pattern[j] == "?":
                j += 1
                while j < n and pattern[j] not in ":)":
                    j += 1
                if j < n and pattern[j] == ":":
                    j += 1
                elif j < n and pattern[j] == ")":
                    # empty (?...) group — skip
                    i = j + 1
                    continue
            body_start = j
            depth = 1
            k = body_start
            while k < n and depth:
                ck = pattern[k]
                if ck == "\\" and k + 1 < n:
                    k += 2
                    continue
                if ck == "[":
                    k = _skip_char_class(pattern, k)
                    continue
                if ck == "(":
                    depth += 1
                elif ck == ")":
                    depth -= 1
                k += 1
            body_end = k - 1  # index of closing ')'
            if body_end >= body_start:
                yield group_start, body_start, body_end, k
            i = k
            continue
        i += 1


def chunk_oversized_regex(pattern: str, max_len: int) -> list[str]:
    """
    Split an oversized PCRE into multiple patterns by carving alternations
    out of parenthesized groups (depth-aware). Returns [] if unsplittable.

    When prefix+alt+suffix still exceeds max_len, fall back to emitting the
    alt fragment alone (slightly broader match, still useful for RCE/PHP lists).
    """

    def safe_len(p: str) -> int:
        return len(nginx_safe_regex(p))

    if safe_len(pattern) <= max_len:
        return [pattern]

    candidates = []
    for gs, bs, be, ge in _iter_paren_groups(pattern):
        body = pattern[bs:be]
        alts = split_top_level_alternation(body)
        if len(alts) > 1:
            candidates.append((len(alts), -(be - bs), bs, be, alts))
    top = split_top_level_alternation(pattern)
    if len(top) > 1:
        candidates.append((len(top), -len(pattern), 0, len(pattern), top))

    candidates.sort(reverse=True)

    for _nalts, _size, bs, be, alts in candidates:
        if bs == 0 and be == len(pattern):
            prefix, suffix = "", ""
        else:
            prefix = pattern[:bs]
            suffix = pattern[be:]

        def wrap(piece: str) -> str:
            return prefix + piece + suffix

        def fit_alt(alt: str) -> Optional[list[str]]:
            """Return one or more patterns covering this alternative."""
            wrapped = wrap(alt)
            if safe_len(wrapped) <= max_len:
                return [wrapped]
            # Recurse into the wrapped form (nested groups).
            if wrapped != pattern:
                sub = chunk_oversized_regex(wrapped, max_len)
                if sub and all(safe_len(s) <= max_len for s in sub):
                    return sub
            # Recurse into the bare alt, then re-wrap or emit bare.
            if alt != pattern and len(alt) + 10 < len(pattern):
                inner = chunk_oversized_regex(alt, max_len)
                if not inner:
                    inner = [alt] if safe_len(alt) <= max_len else []
                out: list[str] = []
                for piece in inner:
                    w = wrap(piece)
                    if safe_len(w) <= max_len:
                        out.append(w)
                    elif safe_len(piece) <= max_len:
                        out.append(piece)
                    else:
                        return None
                return out or None
            return None

        packed: list[str] = []
        cur: list[str] = []
        failed = False
        for alt in alts:
            # Prefer packing multiple small alts into one wrapped rule.
            if cur:
                trial = wrap("|".join(cur + [alt]))
                if safe_len(trial) <= max_len:
                    cur.append(alt)
                    continue
                packed.append(wrap("|".join(cur)))
                cur = []

            fitted = fit_alt(alt)
            if fitted is None:
                failed = True
                break
            if len(fitted) == 1 and fitted[0] == wrap(alt):
                cur = [alt]
            else:
                packed.extend(fitted)

        if failed:
            continue
        if cur:
            packed.append(wrap("|".join(cur)))

        if packed and all(safe_len(s) <= max_len for s in packed):
            return packed

    return []


# ---------------------------------------------------------------- conversion


def _canonical_zones(zones: list[str]) -> list[str]:
    """
    NAXSI treats NAME as a rule-wide flag, not a per-zone suffix.
    Collapse 'ARGS|NAME|BODY|NAME' into 'ARGS|BODY|NAME'.
    """
    name = False
    values: list[str] = []
    seen = set()
    for z in zones:
        if z == "NAME" or z.endswith("|NAME"):
            name = True
            base = z[: -len("|NAME")] if z.endswith("|NAME") else ""
            if base and base not in seen:
                seen.add(base)
                values.append(base)
        else:
            if z not in seen:
                seen.add(z)
                values.append(z)
    if name:
        values.append("NAME")
    return values


def uses_response_vars(varstr: str) -> bool:
    for v in varstr.split("|"):
        base = v.split(":", 1)[0].strip().lstrip("!&")
        if base.startswith("RESPONSE_"):
            return True
    return False


def map_variables(varstr: str) -> tuple[Optional[list[str]], Optional[str]]:
    """Return (zones, None) or (None, reason)."""
    zones: list[str] = []
    seen: set[str] = set()
    for v in varstr.split("|"):
        v = v.strip()
        if not v or v.startswith("!") or v.startswith("&"):
            continue
        sel = None
        if ":" in v:
            v, sel = v.split(":", 1)
        base = VAR_MAP.get(v, "MISSING")
        if base == "MISSING":
            if v.startswith(("TX", "GLOBAL", "IP", "SESSION", "USER", "REMOTE")):
                return None, "TX/collection variable"
            continue
        if base is None:
            continue
        if sel and v in ("REQUEST_HEADERS", "RESPONSE_HEADERS", "MULTIPART_PART_HEADERS"):
            sel = sel.strip("'\"").lower()
            if sel.startswith("/"):
                zones_add = ["HEADERS"]
            else:
                zones_add = [f"$HEADERS_VAR:{sel}"]
        elif sel and v in ("ARGS", "ARGS_GET", "ARGS_POST"):
            sel = sel.strip("'\"").lower()
            if sel.startswith("/"):
                zones_add = list(VAR_MAP[v])
            else:
                zv = {
                    "ARGS": ["$ARGS_VAR", "$BODY_VAR"],
                    "ARGS_GET": ["$ARGS_VAR"],
                    "ARGS_POST": ["$BODY_VAR"],
                }[v]
                zones_add = [f"{z}:{sel}" for z in zv]
        else:
            zones_add = list(base)
        for z in zones_add:
            if z not in seen:
                seen.add(z)
                zones.append(z)
    if not zones:
        return None, "no mappable variables"
    return zones, None


def load_pm_file(fpath: str) -> list[str]:
    words: list[str] = []
    with open(fpath, encoding="utf-8", errors="replace") as df:
        for w in df:
            w = w.strip()
            if w and not w.startswith("#"):
                words.append(w)
    return words


def format_mainrule(
    prefix: str,
    pat: str,
    msg: str,
    mz: str,
    counter: str,
    score: int,
    rule_id,
    negative: bool = False,
) -> str:
    neg = "negative " if negative else ""
    return (
        f"MainRule {neg}\"{prefix}:{pat}\" \"msg:{msg}\" "
        f"\"mz:{mz}\" \"s:{counter}:{score}\" id:{rule_id};"
    )


def parse_operator(
    op: str, data_dir: str, ignore_case: bool
) -> tuple[Optional[dict], Optional[str]]:
    """
    Translate a ModSec operator into NAXSI match material.
    Returns ({kind, pattern, pm_words?, libinj?, negative?}, None) or (None, reason).
    """
    neg = op.startswith("!")
    if neg:
        op = op[1:]

    pm_words = None
    kind = "rx"
    pattern = ""
    libinj = None

    if op.startswith("@rx "):
        pattern = op[4:]
    elif not op.startswith("@"):
        pattern = op
    elif op.startswith("@within "):
        arg = op[len("@within ") :].strip()
        if "%{" in arg:
            return None, "operator @within with TX macro"
        pm_words = arg.split()
        pattern = "^(?:" + "|".join(re.escape(w) for w in pm_words if w) + ")$"
        pattern = ensure_ignore_case(pattern, ignore_case)
        ignore_case = False
    elif op.startswith("@pm ") or op.startswith("@pmFromFile ") or op.startswith("@pmf "):
        # Negated phrase-match is almost always a CRS skipAfter optimization
        # ("if none of these keywords appear, skip the expensive rules").
        if neg:
            return None, "negated @pm/@pmFromFile (CRS skip optimization)"
        if op.startswith("@pm "):
            pm_words = op[4:].split()
            pattern = pm_to_regex(pm_words, ignore_case)
            ignore_case = False
        else:
            fname = op.split(None, 1)[1].strip()
            fpath = os.path.join(data_dir, fname)
            if not os.path.exists(fpath):
                return None, f"missing data file {fname}"
            words = load_pm_file(fpath)
            if not words:
                return None, f"empty data file {fname}"
            pm_words = words
            pattern = pm_to_regex(words, ignore_case)
            ignore_case = False
    elif op.startswith("@contains "):
        pattern = op[len("@contains ") :]
        kind = "str"
    elif op.startswith("@streq "):
        pattern = "^" + re.escape(op[len("@streq ") :]) + "$"
        pattern = ensure_ignore_case(pattern, ignore_case)
        ignore_case = False
    elif op.startswith("@beginsWith "):
        pattern = "^" + re.escape(op[len("@beginsWith ") :])
        pattern = ensure_ignore_case(pattern, ignore_case)
        ignore_case = False
    elif op.startswith("@endsWith "):
        pattern = re.escape(op[len("@endsWith ") :]) + "$"
        pattern = ensure_ignore_case(pattern, ignore_case)
        ignore_case = False
    elif op in ("@detectSQLi", "@detectXSS"):
        libinj = "LibInjectionSql" if op == "@detectSQLi" else "LibInjectionXss"
    elif op.startswith("@validateByteRange "):
        # Approximate CRS byte-range checks with equivalent "forbidden byte" regexes.
        spec = op.split(None, 1)[1].strip().replace(" ", "")
        byte_map = {
            "1-255": r"\x00",
            "1-127": r"[\x00\x80-\xff]",
            "32-126": r"[\x00-\x1f\x7f-\xff]",
            "9,10,13,32-126": r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]",
            # Full ASCII printable + high bytes, forbid DEL and C0 controls except tab/LF/CR
            "9,10,13,32-126,128-255": r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]",
            # Printable ASCII without single-quote
            "32-36,38-126": r"[\x00-\x1f\x27\x7f-\xff]",
            # Very strict URI-ish charset used by CRS PL3/PL4
            "38,44-46,48-58,61,65-90,95,97-122": (
                r"[^\x26\x2c-\x2e\x30-\x3a\x3d\x41-\x5a\x5f\x61-\x7a]"
            ),
            "32,34,38,42-59,61,65-90,95,97-122": (
                r"[^\x20\x22\x26\x2a-\x3b\x3d\x41-\x5a\x5f\x61-\x7a]"
            ),
        }
        if spec not in byte_map:
            return None, f"operator @validateByteRange {spec}"
        pattern = byte_map[spec]
    else:
        return None, f"operator {op.split()[0]}"

    pattern = ensure_ignore_case(pattern, ignore_case)
    return {
        "kind": kind,
        "pattern": pattern,
        "pm_words": pm_words,
        "libinj": libinj,
        "negative": neg,
    }, None


def convert_file(
    path: str,
    data_dir: str,
    stats: dict,
    skipped_log: list,
    max_paranoia: int,
    libinj_notes: list,
) -> list[str]:
    rules_out: list[str] = []
    lines = read_logical_lines(path)
    chain_skip = 0

    def try_emit_rule(
        rid: str,
        variables: str,
        op: str,
        acts: dict,
        extra_note: str = "",
    ) -> bool:
        """Attempt to convert one SecRule into MainRule(s). Return True on success."""
        if not rid:
            return False
        if rid in QUARANTINE:
            stats["skip:quarantine"] += 1
            skipped_log.append((rid, "quarantined: broad/stateful when standalone"))
            return False
        pl = paranoia_level(acts)
        if pl > max_paranoia:
            stats["skip:paranoia"] += 1
            skipped_log.append((rid, f"paranoia-level/{pl} > max {max_paranoia}"))
            return False
        phase = str(acts.get("phase", ["2"])[0])
        if phase not in ALLOWED_PHASES:
            stats["skip:phase"] += 1
            skipped_log.append((rid, f"phase {phase}"))
            return False
        if "ctl" in acts or "skipAfter" in acts:
            stats["skip:control"] += 1
            skipped_log.append((rid, "ctl/skipAfter control rule"))
            return False

        transforms = {t.lower() for t in acts.get("t", [])}
        ignore_case = "lowercase" in transforms
        lost = transforms - NATIVE_TRANSFORMS
        note = extra_note
        response_adapted = uses_response_vars(variables)
        if response_adapted:
            note += " [adapted CRS response→request; NAXSI has no response MZ]"
        if lost:
            note += f" [LOST t:{','.join(sorted(lost))}]"
        if pl > 1:
            note = f" [PL{pl}]" + note

        parsed, err = parse_operator(op, data_dir, ignore_case)
        if parsed is None:
            stats["skip:operator"] += 1
            skipped_log.append((rid, err))
            return False

        zones, verr = map_variables(variables)
        if zones is None:
            stats["skip:vars"] += 1
            skipped_log.append((rid, verr))
            return False

        family = rid[:3]
        counter = FAMILY_SCORE.get(family, "$GENERIC")
        sev = str(acts.get("severity", ["WARNING"])[0]).upper().strip("'\"")
        score = SEVERITY_SCORE.get(sev, 2)
        msg = sanitize_msg(acts.get("msg", [""])[0])
        kind = parsed["kind"]
        pattern = parsed["pattern"]
        pm_words = parsed["pm_words"]
        negative = parsed["negative"]
        prefix = "str" if kind == "str" else "rx"

        if parsed["libinj"]:
            libinj = parsed["libinj"]
            libinj_notes.append(
                f"# CRS {rid}: enable `{libinj};` in the location "
                f"(native NAXSI equivalent of {op}) — {msg}"
            )
            stats["converted:libinjection"] += 1
            return True

        name_zones_raw = [z for z in zones if z == "NAME" or z.endswith("|NAME")]
        val_zones_raw = [z for z in zones if z != "NAME" and not z.endswith("|NAME")]
        name_zones = _canonical_zones(name_zones_raw) if name_zones_raw else []
        val_zones = _canonical_zones(val_zones_raw) if val_zones_raw else []

        def emit_one(pat: str, rule_id, mz: str, extra: str = "") -> None:
            full_msg = sanitize_msg(f"CRS {rid}{extra} {msg}{note}")
            safe_pat = nginx_safe_str(pat) if kind == "str" else nginx_safe_regex(pat)
            rules_out.append(
                format_mainrule(
                    prefix, safe_pat, full_msg, mz, counter, score, rule_id, negative
                )
            )

        def emit_pattern(pat: str) -> bool:
            probe = nginx_safe_regex(pat) if kind != "str" else nginx_safe_str(pat)
            if len(probe) > MAX_PAT:
                return False
            if val_zones:
                emit_one(pat, rid, "|".join(val_zones))
            if name_zones and val_zones:
                emit_one(
                    pat,
                    int(rid) + NAME_ID_OFFSET,
                    "|".join(name_zones),
                    extra=" (names)",
                )
            elif name_zones:
                emit_one(pat, rid, "|".join(name_zones))
            return True

        if emit_pattern(pattern):
            stats["converted"] += 1
            if response_adapted:
                stats["converted:response_adapted"] += 1
            return True

        # Oversized: chunk phrase lists or nested alternations.
        chunks: list[str] = []
        if pm_words:
            cur: list[str] = []
            for w in pm_words:
                trial = cur + [w]
                trial_pat = pm_to_regex(trial, ignore_case=False)
                if pattern.startswith("(?i)"):
                    trial_pat = ensure_ignore_case(trial_pat, True)
                if len(nginx_safe_regex(trial_pat)) > MAX_PAT - 50 and cur:
                    chunks.append(pm_to_regex(cur, False))
                    cur = [w]
                else:
                    cur = trial
            if cur:
                chunks.append(pm_to_regex(cur, False))
            if pattern.startswith("(?i)"):
                chunks = [ensure_ignore_case(c, True) for c in chunks]
        else:
            chunks = chunk_oversized_regex(pattern, MAX_PAT)

        if chunks and all(len(nginx_safe_regex(c)) <= MAX_PAT for c in chunks):
            for n, chunk in enumerate(chunks, 1):
                rule_id = rid if n == 1 else int(rid) * 100 + n
                extra = f" part {n}/{len(chunks)}"
                if val_zones:
                    emit_one(chunk, rule_id, "|".join(val_zones), extra=extra)
                if name_zones and val_zones:
                    emit_one(
                        chunk,
                        (int(rid) + NAME_ID_OFFSET) if n == 1 else int(rid) * 100 + 50 + n,
                        "|".join(name_zones),
                        extra=f" (names){extra}",
                    )
                elif name_zones:
                    emit_one(chunk, rule_id, "|".join(name_zones), extra=extra)
            stats["converted"] += 1
            stats["chunked"] += 1
            if response_adapted:
                stats["converted:response_adapted"] += 1
            return True

        stats["skip:too_long"] += 1
        skipped_log.append(
            (rid, f"regex too long ({len(nginx_safe_regex(pattern))} chars)")
        )
        return False

    for line in lines:
        if chain_skip:
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
            # Consume the rest of the chain either way.
            chain_skip = 1
            # Salvage: emit the chain head as a standalone MainRule when possible.
            # CRS children often only refine via TX/MATCHED_VARS which NAXSI lacks.
            if try_emit_rule(rid, variables, op, acts, extra_note=" [chain head]"):
                stats["converted:chain_head"] += 1
            else:
                # try_emit_rule already logged a more specific skip; if it only failed
                # because of chain-unrelated reasons we're done. If nothing was logged
                # for this id as operator/vars/etc., mark chained.
                if not any(s[0] == rid for s in skipped_log[-5:]):
                    stats["skip:chained"] += 1
                    skipped_log.append((rid, "chained rule (unconvertible head)"))
            continue

        try_emit_rule(rid, variables, op, acts)

    return rules_out


def _out_rules_name(src_name: str) -> str:
    name = src_name
    if name.endswith(".conf.example"):
        name = name[: -len(".conf.example")] + ".rules"
    elif name.endswith(".conf"):
        name = name[: -len(".conf")] + ".rules"
    return name.lower()


def write_outputs(
    out_dir: str,
    file_rules: list[tuple[str, list[str]]],
    counters: set[str],
    skipped_log: list,
    libinj_notes: list,
    stats: dict,
) -> None:
    os.makedirs(out_dir, exist_ok=True)

    for src_name, rules in file_rules:
        out_name = _out_rules_name(src_name)
        with open(os.path.join(out_dir, out_name), "w", encoding="utf-8") as f:
            f.write(f"# Auto-converted from CRS {src_name} by crs2naxsi.py\n")
            f.write("# Review before production use. Whitelist with wl:<crs_id>\n")
            if src_name.startswith("RESPONSE-"):
                f.write(
                    "# NOTE: CRS response rules adapted to request match-zones "
                    "(NAXSI cannot inspect RESPONSE_BODY).\n"
                )
            f.write("\n")
            f.write("\n".join(rules) + "\n")
        print(f"{src_name}: {len(rules)} rules -> {out_name}")

    with open(os.path.join(out_dir, "checkrules.conf"), "w", encoding="utf-8") as f:
        f.write("# NAXSI equivalent of CRS REQUEST-949 / RESPONSE-959 anomaly blocking\n")
        f.write("# (CRS sums TX anomaly scores; NAXSI uses per-family CheckRule scores)\n")
        f.write("# Add inside each protected location{} (tune thresholds per app)\n")
        for c in sorted(counters):
            f.write(f'CheckRule "{c} >= 8" BLOCK;\n')

    with open(os.path.join(out_dir, "libinjection.conf"), "w", encoding="utf-8") as f:
        f.write("# Native NAXSI replacements for CRS @detectSQLi / @detectXSS\n")
        f.write("# Place inside the protected location{}:\n")
        f.write("LibInjectionSql;\n")
        f.write("LibInjectionXss;\n\n")
        for note in libinj_notes:
            f.write(note + "\n")

    with open(os.path.join(out_dir, "method-enforcement.example.conf"), "w", encoding="utf-8") as f:
        f.write("# CRS REQUEST-911-METHOD-ENFORCEMENT (id 911100) has no NAXSI MainRule form:\n")
        f.write("# ModSec uses REQUEST_METHOD !@within %{tx.allowed_methods}.\n")
        f.write("# Enforce allowed methods in nginx instead, e.g.:\n\n")
        f.write("if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) {\n")
        f.write("    return 405;\n")
        f.write("}\n")

    with open(os.path.join(out_dir, "crs-machinery.notes"), "w", encoding="utf-8") as f:
        f.write(
            "# CRS files that are mostly TX/anomaly/ctl machinery (little or no MainRule output)\n"
            "#\n"
            "# REQUEST-900-*: exclusion templates (wl:… in NAXSI BasicRule)\n"
            "# REQUEST-901-INITIALIZATION: sets TX vars / CRS setup — use naxsi LearningMode / CheckRule\n"
            "# REQUEST-905 / REQUEST-999: exception/skip machinery — map manually to BasicRule wl:<id>\n"
            "# REQUEST-949 / RESPONSE-959: anomaly score blocking — see checkrules.conf\n"
            "# RESPONSE-980-CORRELATION: logging/correlation only — no NAXSI equivalent\n"
            "#\n"
            "# Response leak files (950–956) ARE converted: signatures adapted onto request MZs.\n"
        )

    with open(os.path.join(out_dir, "include.example.conf"), "w", encoding="utf-8") as f:
        f.write("# Example location snippet\n")
        f.write("location / {\n")
        f.write("    SecRulesEnabled;\n")
        f.write("    DeniedUrl /RequestDenied;\n")
        f.write("    include checkrules.conf;\n")
        f.write("    include libinjection.conf;\n")
        for src_name, rules in file_rules:
            if rules:
                f.write(f"    include {_out_rules_name(src_name)};\n")
        f.write("}\n")

    with open(os.path.join(out_dir, "skipped.log"), "w", encoding="utf-8") as f:
        for rid, reason in skipped_log:
            f.write(f"{rid}\t{reason}\n")

    print("\n--- stats ---")
    for k in sorted(stats):
        print(f"{k}: {stats[k]}")


def self_test() -> None:
    """Regression checks for quoting / escaping / zone canonicalization."""

    def nginx_unescape(s: str) -> str:
        out: list[str] = []
        i = 0
        while i < len(s):
            if s[i] == "\\" and i + 1 < len(s):
                c = s[i + 1]
                if c in '\\"\'':
                    out.append(c)
                else:
                    out.append("\\")
                    out.append(c)
                i += 2
                continue
            out.append(s[i])
            i += 1
        return "".join(out)

    line = (
        'SecRule ARGS "@rx (?i)[\\"\'`]foo\\s+\\$" '
        "\"id:942240,msg:'hello \\\"world\\\"',severity:'CRITICAL',phase:2,"
        "tag:'paranoia-level/1'\""
    )
    sr = split_secrule(line)
    assert sr is not None
    _vars, op, actions = sr
    assert op == """@rx (?i)["'`]foo\\s+\\$"""
    acts = parse_actions(actions)
    assert acts["id"] == ["942240"]
    assert acts["msg"] == ['hello "world"']
    assert acts["severity"] == ["CRITICAL"]
    assert paranoia_level(acts) == 1

    safe = nginx_safe_regex(op[4:])
    un = nginx_unescape(safe)
    assert un == """(?i)[\\x22\\x27`]foo\\s+\\x24"""
    assert _canonical_zones(["ARGS|NAME", "BODY|NAME"]) == ["ARGS", "BODY", "NAME"]
    assert sanitize_msg('a "b" c') == "a 'b' c"
    print("self-test: OK")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Convert OWASP CRS rules to NAXSI MainRule files")
    ap.add_argument(
        "rules_dir",
        nargs="?",
        default="coreruleset/rules",
        help="CRS rules directory (default: coreruleset/rules)",
    )
    ap.add_argument(
        "out_dir",
        nargs="?",
        default="crs2naxsi_rules",
        help="Output directory (default: crs2naxsi_rules)",
    )
    ap.add_argument(
        "--max-paranoia",
        type=int,
        default=4,
        choices=(1, 2, 3, 4),
        help="Only convert rules at this paranoia level or below (default: 4)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in regression checks and exit",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    rules_dir = args.rules_dir
    out_dir = args.out_dir
    if not os.path.isdir(rules_dir):
        print(f"error: rules dir not found: {rules_dir}", file=sys.stderr)
        return 1

    stats: dict = defaultdict(int)
    skipped_log: list = []
    libinj_notes: list = []
    counters: set[str] = set()
    file_rules: list[tuple[str, list[str]]] = []

    for fn in sorted(os.listdir(rules_dir)):
        # REQUEST-9xx / RESPONSE-9xx (+ optional REQUEST-900*.conf.example)
        is_example = fn.endswith(".conf.example") and fn.startswith("REQUEST-900")
        is_conf = fn.endswith(".conf") and (
            fn.startswith("REQUEST-9") or fn.startswith("RESPONSE-9")
        )
        if not is_conf and not is_example:
            continue
        rules = convert_file(
            os.path.join(rules_dir, fn),
            rules_dir,
            stats,
            skipped_log,
            args.max_paranoia,
            libinj_notes,
        )
        # Always record the file when it produced rules; machinery-only files
        # still get coverage via skipped.log / helper notes.
        if not rules:
            print(f"{fn}: 0 rules (see skipped.log / crs-machinery.notes)")
            continue
        file_rules.append((fn, rules))
        for r in rules:
            m = re.search(r"s:(\$[A-Z_]+):", r)
            if m:
                counters.add(m.group(1))

    write_outputs(out_dir, file_rules, counters, skipped_log, libinj_notes, stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
