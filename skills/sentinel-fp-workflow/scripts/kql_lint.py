#!/usr/bin/env python3
"""
KQL Static Lint for Sentinel analytics rules, XDR custom detections and hunting queries.

Encodes the defect classes that appear most often in real detection repositories (official and
community): bare `join` (silent innerunique dedup), unbounded make_set/make_list, short/unindexed
terms, positional dynamic indexing, platform column drift (Timestamp vs TimeGenerated), zero-overlap
schedule windows, tenant placeholders, full-sample has_all lists, case-sensitive file-name matches,
materialize() on single-reference lets, prev()/next() without a partitioned sort, syntax smells.

Heuristic (regex-based) — it does not parse KQL. Use it as the cheap first CI gate before the
offline Kusto parser and the fixture tests. False positives are possible; suppress a finding on a
line with `// lint:ignore CODE`.

Usage:
  python kql_lint.py rule.kql [more.kql ...] [--platform xdr|sentinel|auto] [--hunt] [--strict]
  python kql_lint.py detections/*.md          # lints every ```kql / ```kusto block; platform from headings
  python kql_lint.py --selftest

Exit codes: 0 clean (or warnings only), 1 errors (or warnings with --strict), 2 usage error.
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # works under python -I and when imported from elsewhere
from kql_text import segments, views

FENCE_RE = re.compile(r"^```\s*([A-Za-z0-9_+-]*)\s*$")
HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")
IGNORE_RE = re.compile(r"lint:ignore\s+([A-Z]\d{3}(?:\s*,\s*[A-Z]\d{3})*)")

PLACEHOLDER_RE = re.compile(
    r"(CHANGE IF DIFFERENT|YOUR_[A-Z_]+|ADD [A-Z ]+HERE|add_more_in|\bclient[12]\b|"
    r"1\.1\.1\.1/8|contoso\.|example\.com|supposedlygoodhost|simulandlabs|lorem ipsum)", re.I)
SMART_QUOTES_RE = re.compile(r"[“”‘’]")
EN_DASH_RE = re.compile(r"[–—]")
IDENTIFIER_COLS = r"(DeviceId|DeviceName|AccountSid|AccountObjectId|AccountUpn|SHA1|SHA256|MD5|RemoteIP|LocalIP|IPAddress|NetworkMessageId|FileName|InitiatingProcessFileName)"


def strip_strings_and_comments(line: str):
    """Return (code_without_string_literals, list_of_string_literals, comment)."""
    code, _, comment = views(line)
    literals = [line[a:b] for kind, a, b in segments(line) if kind == 'string']
    return code, literals, comment


def lint_query(text: str, platform: str = "auto", hunt: bool = False):
    """Lint one KQL query. Returns list of (line_no, code, level, message)."""
    findings = []
    lines = text.split("\n")
    full = "\n".join(lines)
    try:
        full_code, full_nc, full_comments = views(full)
    except ValueError as exc:
        return [(0, 'E017', 'error', str(exc))], platform
    code_lines = full_code.split('\n')
    nc_lines = full_nc.split('\n')
    comment_lines = full_comments.split('\n')

    def add(ln, code, level, msg):
        # per-line ignore
        if ln >= 1:
            m = IGNORE_RE.search(comment_lines[ln - 1])
            if m and code in [c.strip() for c in m.group(1).split(",")]:
                return
        findings.append((ln, code, level, msg))

    has_ts = re.search(r"\bTimestamp\b", full_code) is not None
    has_tg = re.search(r"\bTimeGenerated\b", full_code) is not None
    if platform == "auto":
        if has_ts and not has_tg:
            platform = "xdr"
        elif has_tg and not has_ts:
            platform = "sentinel"

    mat_lets = re.findall(r"^\s*let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*materialize\s*\(", full_code, re.M)
    for name in mat_lets:
        refs = len(re.findall(r"\b%s\b" % re.escape(name), full_code)) - 1
        if refs < 2:
            ln = next((i + 1 for i, l in enumerate(lines) if re.match(r"\s*let\s+%s\s*=" % re.escape(name), l)), 0)
            add(ln, "W008", "warn", f"materialize() on `{name}` which is referenced {refs}x — only worth it when referenced >= 2x")

    has_window_fn = re.search(r"\b(prev|next|row_number|row_cumsum)\s*\(", full_code)
    if has_window_fn:
        sorts = re.findall(r"\b(?:order|sort)\s+by\s+([^|\n]+)", full_code)
        partitioned = any("," in s_ for s_ in sorts)
        if not sorts:
            ln = next((i + 1 for i, l in enumerate(lines) if re.search(r"\b(prev|next|row_number|row_cumsum)\s*\(", l)), 0)
            add(ln, "W009", "warn", "prev()/next()/row_number() without an `order by` — results are meaningless")
        elif not partitioned:
            ln = next((i + 1 for i, l in enumerate(lines) if re.search(r"\b(order|sort)\s+by\b", l)), 0)
            add(ln, "W009", "warn", "window function after `order by <time>` only — sort by <entity>, <time> or rows of different entities get compared")

    if platform == "xdr" and has_tg:
        ln = next((i + 1 for i, l in enumerate(code_lines) if "TimeGenerated" in l), 0)
        add(ln, "W010", "warn", "TimeGenerated in an XDR (Advanced Hunting) query — use Timestamp (dual-platform copy drift)")
    if platform == "sentinel" and has_ts and not re.search(r"\b(Device|Email|Identity|CloudApp|Url|Alert)\w*\b", full_code):
        ln = next((i + 1 for i, l in enumerate(code_lines) if re.search(r"\bTimestamp\b", l)), 0)
        add(ln, "W010", "warn", "Timestamp in a Sentinel query on a non-XDR table — use TimeGenerated")

    has_ingestion = "ingestion_time()" in full_code
    if not hunt and platform == "sentinel" and not has_ingestion and re.search(r"TimeGenerated\s*>=?\s*ago\(", full_code):
        add(0, "I013", "info", "Sentinel rule bounds on TimeGenerated without ingestion_time() — add the ingestion-delay window (TimeGenerated >= ago(delay+lookback) and ingestion_time() > ago(lookback))")
    if not hunt and platform == "xdr" and re.search(r"\bTimestamp\s*>=?\s*ago\(", full_code) and not re.search(r"\bTimestamp\s+between\s*\(", full_code):
        ln = next((i + 1 for i, l in enumerate(code_lines) if re.search(r"\bTimestamp\s*>=?\s*ago\(", l)), 0)
        add(ln, "W012", "warn", "`Timestamp > ago()` on the recent window of an XDR custom detection drops late-arriving events — the service evaluates the lookback on ingestion_time(); keep explicit Timestamp bounds only on the baseline half")

    if not hunt and platform == "xdr" and re.search(r"\bsummarize\b", full_code) and "ReportId" not in full_code:
        add(0, "W020", "warn", "XDR custom detection aggregates but never carries ReportId — add (Timestamp, ReportId)=arg_max(...) (or arg_min for first event)")

    if not hunt and not re.search(r"ago\(|between\s*\(|ingestion_time\(|StartTimeISO|starttime|query_period|lookback", full_code, re.I):
        add(0, "I014", "info", "no time bound at all — fine in a portal with a time picker, not in a scheduled rule or a shared hunt")

    # dynamic([...]) lists bound to a let and consumed by has_any/has_all: look through the indirection
    for m in re.finditer(r"let\s+([A-Za-z_]\w*)\s*=\s*dynamic\s*\(\s*\[(.*?)\]\s*\)", full_nc, re.S):
        if full_code[m.start():m.start()+3] != 'let':
            continue
        name, body = m.group(1), m.group(2)
        items = [a or b for a, b in re.findall(r"@?\"([^\"]*)\"|@?'([^']*)'", body)]
        if not items:
            continue
        use = re.search(r"\b(has_any|has_all)\s*\(\s*%s\s*\)" % re.escape(name), full_code)
        if use and any(t.count(" ") >= 2 for t in items):
            ln = full.count("\n", 0, m.start()) + 1
            add(ln, "W015", "warn", f"`{name}` holds full command-line strings consumed by `{use.group(1)}` — reorder/quoting/omitted `.exe` evades it; anchor on FileName and match 2–4 unordered tokens")

    # term-match checks run on the whole text so multi-line literal lists are seen
    # list form: op ( "a", "b", ... ) may span lines; scalar form: op "a" takes exactly one literal
    LIT = r"(?:@?\"[^\"]*\"|@?'[^']*')"
    term_re = re.compile(r"\b(has_any|has_all|has|has_cs|contains|contains_cs|startswith|endswith)\s*(?:\(\s*((?:%s[\s,]*)+)\)|(%s))" % (LIT, LIT))
    for m in term_re.finditer(full_nc):
        if full_code[m.start():m.start()+len(m.group(1))] != m.group(1):
            continue
        ln = full_nc.count("\n", 0, m.start()) + 1
        op = m.group(1)
        terms = [a or b for a, b in re.findall(r"@?\"([^\"]*)\"|@?'([^']*)'", m.group(2) or m.group(3) or "")]
        for t in terms:
            if op.startswith("has") and 0 < len(t.strip()) < 3:
                add(ln, "W006", "warn", f"`{op}` term \"{t}\" is < 3 chars — not term-indexed (Kusto term index starts at 3 chars); full scan")
            elif op.startswith("has") and len(t.strip()) == 3:
                add(ln, "I006", "info", f"`{op}` term \"{t}\" is exactly 3 chars — indexed per Kusto docs, but the Defender advanced-hunting best-practices page says to avoid terms of 3 or fewer; prefer a longer anchor when one exists")
            elif op.startswith("contains") and len(t.strip()) <= 3 and t.strip():
                add(ln, "W006", "warn", f"`{op}` on \"{t}\" — substring scan on a tiny token; anchor on FileName/ActionType instead")
        if op == "has_all" and len(terms) >= 7:
            add(ln, "W015", "warn", f"`has_all` with {len(terms)} tokens — looks like a full report sample (IOC in disguise); keep 2–4 invariant tokens")
        if op in ("has_any", "has_all", "contains") and any(t.count(" ") >= 2 for t in terms):
            add(ln, "W015", "warn", f"`{op}` with full command-line strings — argument reorder, quoting or omitted `.exe` evades it; anchor on FileName and match 2–4 unordered tokens")
        if op in ("has_all", "contains") and any(re.search(r"[A-Za-z]:\\\\|\\\\[A-Za-z0-9_.-]+\.(sys|dll|exe)\b", t) for t in terms):
            add(ln, "I015", "info", "full path literal in a term match — lab/sample-specific path?")

    for i, raw in enumerate(lines, start=1):
        code, comment = code_lines[i - 1], comment_lines[i - 1]
        raw = nc_lines[i - 1]

        if SMART_QUOTES_RE.search(code):
            add(i, "E017", "error", "smart quotes in code — will not parse")
        if EN_DASH_RE.search(raw) and re.search(r'\bOperationName\s*==', code):
            add(i, "W017", "warn", "verify the exact OperationName against observed values; punctuation is significant")
        if re.search(r"\bago\(\s*\d+\s*(hr|hrs|mins|days?|hours?|minutes?)\s*\)", code):
            add(i, "E017", "error", "invalid timespan literal in ago() — use 1h / 10m / 7d")
        if re.search(r"\bwhere\b[^|]*?[^=!<>]=[^=~][^|]*", code) and not re.search(r"\b(extend|project|summarize|let)\b", code):
            add(i, "E017", "error", "single `=` in a where clause — comparison needs `==`")

        # joins
        for m in re.finditer(r"\bjoin\b(?!\s*kind\s*=)(?P<rest>[^(\n]*)", code):
            rest = m.group("rest")
            if "kind=" in rest.replace(" ", ""):
                continue
            add(i, "E001", "error", "`join` without `kind=` — default innerunique dedups the left side and silently drops rows")
        if re.search(r"\bjoin\b[^|\n]*kind\s*=\s*innerunique", code) and "innerunique" not in comment:
            add(i, "I021", "info", "`kind=innerunique` — state in a comment why dedup of the left side is intended")

        if not hunt:
            if re.search(r"(^|\|)\s*search\b", code):
                add(i, "E002", "error", "`search` in a rule — scope columns and tables explicitly (hunt/IR only)")
            if re.search(r"\bunion\s+(withsource\s*=\s*\w+\s+)?\*", code):
                add(i, "E003", "error", "`union *` in a rule — name the tables (hunt/IR only)")
            if re.search(r"(^|\|)\s*(take|limit)\s+\d+", code):
                add(i, "E004", "error", "bare `take`/`limit` in a rule — nondeterministic; aggregate or cap sets instead")

        for m in re.finditer(r"\b(make_set|make_list|make_set_if|make_list_if)\s*\(", code):
            # find the matching paren and count top-level commas
            start = m.end()
            depth, j, commas = 1, start, 0
            while j < len(code) and depth > 0:
                ch = code[j]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif ch == "," and depth == 1:
                    commas += 1
                j += 1
            fn = m.group(1)
            needed = 1 if fn.endswith("_if") else 0
            if commas <= needed:
                add(i, "W005", "warn", f"unbounded `{fn}()` — cap it (`{fn}(x, 100)`) or alerts carry huge payloads")

        if re.search(r"\bActionType\s+contains\s", code):
            add(i, "W018", "warn", "`contains` on ActionType (enum column) — use `==` / `in`")
        if re.search(r"\b%s\s+has_any\s*\(" % IDENTIFIER_COLS, code):
            add(i, "W019", "warn", "`has_any` on an identifier column — use `in`/`in~` (exact, cheaper, no partial-token matches)")
        if re.search(r"\b(FileName|InitiatingProcessFileName|InitiatingProcessParentFileName|ProcessVersionInfoOriginalFileName)\s*(==|in\b)", code) and re.search(r"\b(FileName|InitiatingProcessFileName|InitiatingProcessParentFileName|ProcessVersionInfoOriginalFileName)\s*(==|in)\s*\(?\s*@?[\"']", raw) and not re.search(r"\b(FileName|InitiatingProcessFileName|InitiatingProcessParentFileName|ProcessVersionInfoOriginalFileName)\s*(=~|in~)", code):
            add(i, "W016", "warn", "case-sensitive `==`/`in` on a file-name column — MDE keeps on-disk casing; use `=~` / `in~`")

        pos = re.findall(r"\b[A-Za-z_]\w*(?:\.\w+)?\[(\d+)\]\s*(?:\.|\[\s*[\"'])", code) + re.findall(r"\b(?:TargetResources|Parameters|AdditionalDetails|modifiedProperties|ModifiedProperties|Entities)\s*\)?\s*\[(\d+)\]", code)
        if pos:
            if any(int(x) > 0 for x in pos):
                add(i, "W007", "warn", "positional index into a dynamic array (`X[2].field`) — read by name with mv-apply (where p.Name == ...)")
            else:
                add(i, "I007", "info", "index [0] into a dynamic array — fine for single-target events; multi-target rows need mv-apply")

        if PLACEHOLDER_RE.search(raw):
            add(i, "W014", "warn", "placeholder / tenant-specific literal left in the query")

        if re.search(r"\bjoin\b[^|\n]*on\s+\$left\.\w*(ip|IP|Addr|Address)\w*\s*==\s*\$right\.\w*(cidr|CIDR|range|Range|prefix|Prefix)\w*", code):
            add(i, "E022", "error", "equi-join of an IP to a CIDR column yields zero rows — use evaluate ipv4_lookup() / ipv4_is_in_any_range()")

        if re.search(r"\bextract\s*\(\s*@?[\"'][^\"']*\\\.\(", raw):
            add(i, "I023", "info", "regex to extract a file extension — parse_path(FileName).Extension or `endswith` is cheaper and safer")

        if re.search(r"\+\s*\d+h\b", code) and re.search(r"(hourofday|dayofweek|LocalTime)", full_code) and "datetime_utc_to_local" not in full_code:
            add(i, "W024", "warn", "fixed UTC offset for local-time logic — DST-wrong; use datetime_utc_to_local()")

        if re.search(r"\b(where|extend)\s+\w+\s*==", code) and re.search(r"\b(RemotePort|LocalPort|EventID|IsExploitAvailable|IsInternetFacing|ErrorCode|ProcessId)\s*==\s*[\"']\d+[\"']", raw):
            add(i, "W025", "warn", "string literal compared to a numeric/bool column — use a typed literal")

    # magic numbers (info only): numeric comparisons not expressed via a let
    if not hunt:
        for i, code in enumerate(code_lines, start=1):
            if re.match(r"\s*let\b", code):
                continue
            for m in re.finditer(r"\bwhere\b[^|]*?\b([A-Za-z_]\w*)\s*(>=|<=|>|<)\s*(\d{2,})\b", code):
                add(i, "I011", "info", f"threshold literal `{m.group(1)} {m.group(2)} {m.group(3)}` — hoist to a `let` with a comment on what FP it trades against")

    # order & dedupe findings
    seen = set()
    out = []
    for f in sorted(findings, key=lambda x: (x[0], x[1])):
        key = (f[0], f[1], f[3][:40])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out, platform


def iter_queries(path: Path, platform_arg: str):
    """Yield (label, query_text, platform, line_offset) for a .kql file or each kql block of a .md."""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if path.suffix.lower() != ".md":
        yield (str(path), text, platform_arg, 0)
        return
    lines = text.split("\n")
    heading, in_block, buf, start, tagged, other_lang = "", False, [], 0, False, False
    block_platform = platform_arg
    for i, l in enumerate(lines, start=1):
        hm = HEADING_RE.match(l)
        if hm and not in_block:
            heading = hm.group(1).strip()
            continue
        fm = FENCE_RE.match(l.strip())
        if fm and not in_block:
            in_block, buf, start = True, [], i
            tag = (fm.group(1) or "").lower()
            tagged = tag in ("kql", "kusto")
            other_lang = tag not in ("", "kql", "kusto")
            h = heading.lower()
            if platform_arg == "auto":
                block_platform = "xdr" if ("defender" in h or "xdr" in h or "advanced hunting" in h or "mde" in h) else ("sentinel" if "sentinel" in h else "auto")
            continue
        if in_block and l.strip().startswith("```"):
            in_block = False
            body = "\n".join(buf)
            looks_kql = tagged or (not other_lang and re.search(r"^\s*(\||let\s+\w+\s*=)", body, re.M) is not None)
            if looks_kql:
                yield (f"{path}#L{start}[{heading}]", body, block_platform, start)
            continue
        if in_block:
            buf.append(l)


SELFTEST_CASES = [
    ("E001", "xdr", False, 'EmailEvents\n| join EmailUrlInfo on NetworkMessageId'),
    ("W005", "xdr", False, 'DeviceEvents\n| summarize X=make_set(DeviceName) by DeviceId'),
    ("W006", "xdr", False, 'DeviceProcessEvents\n| where ProcessCommandLine has_any ("-e","-enc")'),
    ("W007", "sentinel", False, 'AuditLogs\n| extend Role = tostring(TargetResources[2].displayName)'),
    ("W008", "sentinel", False, 'let x = materialize(SigninLogs | where TimeGenerated > ago(1d));\nx | count'),
    ("W009", "sentinel", False, 'SigninLogs\n| order by TimeGenerated asc\n| serialize\n| extend p = prev(IPAddress)'),
    ("W010", "xdr", False, 'DeviceEvents\n| summarize arg_max(Timestamp, ReportId) by bin(TimeGenerated, 1d), DeviceId'),
    ("W012", "xdr", False, 'DeviceNetworkEvents\n| where Timestamp > ago(1h)\n| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId) by DeviceId'),
    ("W014", "xdr", False, 'DeviceEvents\n| where DeviceName !in ("ADD DEVICES HERE")'),
    ("W015", "xdr", False, 'DeviceProcessEvents\n| where ProcessCommandLine has_all ("/c","schtasks","/create","/sc","ONSTART","/tn","Sens Api","/f")'),
    ("W015", "xdr", False, 'DeviceProcessEvents\n| where ProcessCommandLine has_any ("vssadmin.exe delete shadows /all /quiet", "wmic.exe shadowcopy delete")'),
    ("CLEAN", "xdr", False, 'DeviceProcessEvents\n| extend T = case(\n    FileName =~ "vssadmin.exe" and Canon contains "delete" and Canon contains "shadows",\n    "T1490 shadow copy deletion",\n    "other")\n| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId) by DeviceId'),
    ("I007", "sentinel", False, 'AuditLogs\n| extend T = tostring(TargetResources[0].displayName)'),
    ("W015", "xdr", False, 'let Cmds = dynamic(["vssadmin.exe delete shadows /all /quiet", "wmic.exe shadowcopy delete"]);\nDeviceProcessEvents\n| where ProcessCommandLine has_any (Cmds)'),
    ("W016", "xdr", False, 'DeviceProcessEvents\n| where FileName == "runas.exe"'),
    ("E017", "xdr", False, 'DeviceEvents\n| where Timestamp > ago(1hr)'),
    ("E017", "sentinel", False, 'Usage\n| where IsBillable = true'),
    ("W019", "xdr", False, 'DeviceInfo\n| where DeviceId has_any (InternetFacing)'),
    ("W020", "xdr", False, 'DeviceEvents\n| where ingestion_time() > ago(1h)\n| summarize count() by DeviceId'),
    ("E022", "sentinel", False, 'CommonSecurityLog\n| join kind=inner (DropList) on $left.DestinationIP == $right.cidr'),
    ("E002", "sentinel", False, 'search in (DeviceFileEvents) "ntds" and "dit"'),
    ("I013", "sentinel", False, 'SigninLogs\n| where TimeGenerated > ago(1h)\n| summarize count() by IPAddress'),
    ("W018", "xdr", False, 'DeviceNetworkEvents\n| where ActionType contains "Inspected"'),
]

SELFTEST_CLEAN = '''let query_frequency = 1h; let query_wait = 15m; let query_period = 14d;
let threshold = 10; // accounts per IP; corporate egress excluded via watchlist
let known = SigninLogs | where TimeGenerated between (ago(query_period) .. ago(query_frequency + query_wait)) | distinct UserPrincipalName, IPAddress;
SigninLogs
| where TimeGenerated >= ago(query_frequency + query_wait + 5m) and ingestion_time() > ago(query_frequency)
| where ResultType in ("50126", "50053")
| join kind=leftanti known on UserPrincipalName, IPAddress
| summarize Users = dcount(UserPrincipalName), Sample = make_set(UserPrincipalName, 20) by IPAddress, bin_at(TimeGenerated, 1h, now())
| where Users > threshold
'''


def selftest() -> int:
    failed = 0
    for code, plat, hunt, q in SELFTEST_CASES:
        found, _ = lint_query(q, plat, hunt)
        codes = {f[1] for f in found}
        if code == "CLEAN":
            if any(f[2] in ("error", "warn") for f in found):
                failed += 1
                print(f"SELFTEST FAIL: expected no warnings for:\n{q}\n  got {sorted(codes)}")
            continue
        if code not in codes:
            failed += 1
            print(f"SELFTEST FAIL: expected {code} for:\n{q}\n  got {sorted(codes)}")
    found, _ = lint_query(SELFTEST_CLEAN, "sentinel", False)
    bad = [f for f in found if f[2] in ("error", "warn")]
    if bad:
        failed += 1
        print("SELFTEST FAIL: clean query produced findings:", bad)
    print("selftest:", "PASS" if failed == 0 else f"FAIL ({failed})")
    return 0 if failed == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="KQL static lint (heuristic)")
    ap.add_argument("paths", nargs="*", help=".kql files or .md files with ```kql blocks")
    ap.add_argument("--platform", choices=["xdr", "sentinel", "auto"], default="auto")
    ap.add_argument("--hunt", action="store_true", help="hunting query: relax rule-only checks (search/union*/take/time bound)")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.paths:
        ap.print_help()
        return 2
    total_err = total_warn = 0
    for p in args.paths:
        path = Path(p)
        if not path.exists():
            print(f"{p}: not found", file=sys.stderr)
            return 2
        for label, q, plat, offset in iter_queries(path, args.platform):
            if not q.strip():
                continue
            found, resolved = lint_query(q, plat, args.hunt)
            for ln, code, level, msg in found:
                total_err += level == "error"
                total_warn += level == "warn"
                where = f"{label}:{ln + offset}" if ln else label
                print(f"{where}: {code} {level}: {msg}")
    print(f"-- {total_err} error(s), {total_warn} warning(s)")
    if total_err or (args.strict and total_warn):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
