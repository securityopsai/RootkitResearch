#!/usr/bin/env python3
"""Programmatic pre-grader for the sentinel-fp-workflow evals.
Usage: python3 grade_auto.py <run_outputs_dir> <case-name>  -> prints JSON {assertion_index: {passed, evidence}} for the
assertions it can judge mechanically; others are omitted (left to the LLM grader)."""
import sys, re, json, subprocess, pathlib
out = pathlib.Path(sys.argv[1]); case = sys.argv[2]
LINT = pathlib.Path(__file__).resolve().parent.parent / "sentinel-fp-workflow" / "scripts" / "kql_lint.py"

def rd(name):
    p = out / name
    return p.read_text(errors="replace") if p.exists() else None

def strip_comments(t):
    return "\n".join(l.split("//")[0] for l in t.split("\n"))

def joins_ok(code):
    c = strip_comments(code)
    joins = re.findall(r"\bjoin\b(?!\s*kind\s*=)([^(\n]*)", c)
    bare = [j for j in joins if "kind=" not in j.replace(" ", "")]
    return len(bare) == 0, f"{len(re.findall(r'\\bjoin\\b', c))} join(s), {len(bare)} without kind="

def sets_capped(code):
    c = strip_comments(code); bad = []
    for m in re.finditer(r"\b(make_set|make_list|make_set_if|make_list_if)\s*\(", c):
        depth, j, commas = 1, m.end(), 0
        while j < len(c) and depth:
            ch = c[j]; depth += (ch == "("); depth -= (ch == ")"); commas += (ch == "," and depth == 1); j += 1
        need = 1 if m.group(1).endswith("_if") else 0
        if commas <= need: bad.append(m.group(1))
    n = len(re.findall(r"\bmake_(set|list)", c))
    return len(bad) == 0, f"{n} make_set/list call(s), {len(bad)} uncapped"

def required_cols(code):
    c = strip_comments(code)
    have = [k for k in ("Timestamp", "ReportId", "DeviceId") if re.search(r"\b%s\b" % k, c)]
    return len(have) == 3, f"present: {have}"

def lint(code, platform, hunt=False):
    tmp = out / "_lint_tmp.kql"; tmp.write_text(code)
    r = subprocess.run([sys.executable, "-I", str(LINT), "--platform", platform] + (["--hunt"] if hunt else []) + [str(tmp)], capture_output=True, text=True)
    tmp.unlink(missing_ok=True)
    last = r.stdout.strip().split("\n")[-1] if r.stdout.strip() else "no output"
    return r.stdout, last

def dur(s):
    m = re.match(r"^\s*(?:P?T?)(\d+)\s*([mhdMHD])", s.strip().strip('"\''))
    if not m: return None
    n, u = int(m.group(1)), m.group(2).lower()
    return n * {"m": 1, "h": 60, "d": 1440}[u]

R = {}
def set_(i, ok, ev): R[str(i)] = {"passed": bool(ok), "evidence": ev}

if case == "xdr-first-seen-lsass-access":
    k = rd("detection.kql") or ""; d = rd("rule.md") or ""
    ok, ev = required_cols(k); set_(1, ok and bool(re.search(r"arg_(max|min)\s*\(", k)), ev + ("; arg_max/arg_min present" if re.search(r"arg_(max|min)\s*\(", k) else "; no arg_max/arg_min"))
    gap = re.search(r"between\s*\(\s*ago\([^)]+\)\s*\.\.\s*ago\([^)]+\)\s*\)", k) or re.search(r"<\s*ago\(|<=\s*ago\(", k)
    set_(2, bool(gap), (gap.group(0) if gap else "no baseline window ending before now() found"))
    jo, jev = joins_ok(k); anti = bool(re.search(r"!in\s*[~]?\s*\(|kind\s*=\s*(leftanti|rightanti)", k))
    set_(3, jo and (anti or "join" in k or "!in" in k), jev + (f"; anti-join form: {anti}"))
    bad = re.findall(r"Timestamp\s*>=?\s*ago\(\s*(?:[1-4]h|[1-9]\d*m|1d)\s*\)", strip_comments(k))
    set_(4, len(bad) == 0, f"recent-window Timestamp filters: {bad}" if bad else "no Timestamp > ago(<=4h) filter")
    ci = bool(re.search(r'(=~|in~|has)\s*\(?\s*@?"?lsass', k, re.I)); cs = bool(re.search(r'FileName\s*==\s*@?"lsass', k, re.I))
    strong = bool(re.search(r"\b(InitiatingProcess)?(SHA1|SHA256|MD5|FolderPath|Signer|ProcessVersionInfoOriginalFileName)\b", k))
    set_(5, ci and not cs and strong, f"case-insensitive lsass match: {ci}; case-sensitive ==: {cs}; strong identity column: {strong}")
    lets = re.findall(r"^\s*let\s+\w+", k, re.M); set_(6, len(lets) >= 2, f"{len(lets)} let statement(s)")
    set_(7, bool(re.search(r"T1003\.001", d)), "T1003.001 " + ("found" if re.search(r"T1003\.001", d) else "not found") + " in rule.md")
elif case == "sentinel-password-spray-rule":
    y = rd("rule.yaml") or ""
    qf = re.search(r"queryFrequency:\s*(\S+)", y); qp = re.search(r"queryPeriod:\s*(\S+)", y)
    f, p = (dur(qf.group(1)) if qf else None), (dur(qp.group(1)) if qp else None)
    ing = "ingestion_time()" in y
    set_(1, (f is not None and p is not None and p > f) or ing, f"queryFrequency={qf.group(1) if qf else None} queryPeriod={qp.group(1) if qp else None} ingestion_time={ing}")
    wait = bool(re.search(r"ingestion_time\(\)|query_wait|ingestion_delay|delay", y))
    set_(2, wait, "ingestion_time()/wait/delay " + ("present" if wait else "absent"))
    codes_let = bool(re.search(r"let\s+\w+\s*=\s*dynamic\s*\(\s*\[[^\]]*5\d{4}", y))
    valid = bool(re.search(r"5007[46]|5300[0-3]|50158", y)); invalid = bool(re.search(r"50126|50053", y))
    set_(3, codes_let and valid and invalid, f"codes in let: {codes_let}; interrupt codes present: {valid}; failure codes present: {invalid} (LLM: confirm they are classified, not lumped)")
    dc = bool(re.search(r"dcount\w*\s*\(\s*UserPrincipalName|dcount\w*\s*\(\s*UserId|dcount\w*\s*\(\s*User", y)); byip = bool(re.search(r"by\s+[^\n]*IPAddress", y)); thr = bool(re.search(r"let\s+\w*(threshold|Threshold|min|Min)\w*\s*=", y))
    set_(4, dc and byip and thr, f"dcount of users: {dc}; by IPAddress: {byip}; threshold in let: {thr}")
    m = re.search(r"entityType:\s*IP[\s\S]*?columnName:\s*(\w+)", y)
    if m:
        col = m.group(1); q = re.search(r"query:\s*\|([\s\S]*?)(\n\w+:|\Z)", y); qtext = q.group(1) if q else y
        set_(5, bool(re.search(r"\b%s\b" % re.escape(col), qtext)), f"IP columnName={col}; present in query: {bool(re.search(r'\b%s\b' % re.escape(col), qtext))}")
    else: set_(5, False, "no IP entity mapping found")
    ok, ev = sets_capped(y); set_(6, ok, ev)
    set_(7, "CredentialAccess" in y and "T1110.003" in y, f"CredentialAccess={'CredentialAccess' in y} T1110.003={'T1110.003' in y}")
    g = bool(re.search(r"groupingConfiguration|suppressionDuration|customDetails|alertDetailsOverride", y)); set_(8, g, "grouping/suppression/enrichment keys " + ("present" if g else "absent"))
elif case == "review-and-fix-flawed-query":
    k = rd("fixed.kql") or ""
    ok1, e1 = required_cols(k); ok2, e2 = joins_ok(k); ok3, e3 = sets_capped(k); set_(7, ok1 and ok2 and ok3, f"{e1}; {e2}; {e3}")
    full, last = lint(k, "xdr"); set_(8, last.startswith("-- 0 error(s), 0 warning(s)"), f"kql_lint: {last}")
elif case == "threat-report-to-hunt-pack":
    h = rd("hunts.md") or ""
    blocks = re.findall(r"```(?:kql|kusto|KQL)?\s*\n(.*?)```", h, re.S)
    unb = [b[:60].replace("\n", " ") for b in blocks if not re.search(r"ago\(|between\s*\(|StartTimeISO|starttime|datetime\(", b)]
    set_(8, len(blocks) > 0 and not unb, f"{len(blocks)} query block(s); unbounded: {len(unb)} {unb[:2]}")
    dom_ok = bool(re.search(r"has_any\s*\(", h)) and bool(re.search(r"RemoteUrl|Url\b|UrlDomain|DestinationHost|host", h)); ip_ok = bool(re.search(r"RemoteIP\s*(in|==)", h)); once = bool(re.search(r"let\s+\w+\s*=\s*(dynamic|externaldata)", h))
    set_(3, dom_ok and ip_ok and once, f"IOC lets: {once}; domain has_any on URL col: {dom_ok}; IP via in/==: {ip_ok}")
    va = bool(re.search(r"AlertInfo|AlertEvidence|SecurityAlert", h)); set_(4, va, "vendor-alert query " + ("present" if va else "absent"))
    verb = bool(re.search(r"OneDrive Sync Health|upd\.exe", h)); set_("2_hint", True, f"sample-specific strings present somewhere in hunts.md: {verb} (LLM must check whether a behaviour query relies on them solely)")
elif case == "promote-hunt-to-detection":
    k = rd("detection.kql") or ""; n = rd("promotion-notes.md") or ""
    srt = bool(re.search(r"\b(sort|order)\s+by\b", strip_comments(k))); lets = len(re.findall(r"^\s*let\s+\w+", k, re.M)); thr = bool(re.search(r"\bwhere\b[^\n]*(>=|>)\s*\w+", k))
    set_(1, not srt and lets >= 2 and thr, f"sort/order present: {srt}; lets: {lets}; threshold where: {thr}")
    pop = bool(re.search(r"(Devices|DeviceCount|dcount\w*\s*\([^)]*DeviceId\)[^\n]*)\s*(<=|<)\s*\w+", k)); minc = bool(re.search(r"(Connections|ConnectionCount|count_|Count|Total\w*)\s*(>=|>)\s*\w+", k))
    set_(2, pop and minc, f"population filter: {pop}; min connections: {minc}")
    ok, ev = required_cols(k); set_(3, ok, ev)
    ok, ev = sets_capped(k); set_(4, ok, ev)
    lb = bool(re.search(r"4[- ]?h(our)?|four[- ]hour", n, re.I)) and bool(re.search(r"7[- ]?d|7-day|seven[- ]day|30[- ]?d|24[- ]?h|baseline|lookback", n, re.I))
    set_(5, lb, f"mentions 4h lookback: {bool(re.search(r'4[- ]?h(our)?|four[- ]hour', n, re.I))}; mentions window resolution: {lb}")
    dd = bool(re.search(r"\b150\b|dedup|de-dup|duplicate|aggregat", n, re.I)); set_(6, dd, "volume/dedup terms " + ("present" if dd else "absent"))
    sm = bool(re.search(r"sampl|throttl|CDN|Windows Update|telemetry endpoint|shared destination", n, re.I)); set_(7, sm, "sampling/shared-destination terms " + ("present" if sm else "absent"))
    pd = bool(re.search(r"30[- ]day|30d|first run|first-run|review|expected volume|monitor", n, re.I)); set_(8, pd, "post-deploy terms " + ("present" if pd else "absent"))
print(json.dumps(R, indent=1))
