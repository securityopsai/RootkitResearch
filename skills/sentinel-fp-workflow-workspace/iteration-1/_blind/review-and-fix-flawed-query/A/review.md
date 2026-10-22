# Review — "Shadow copy deletion (ransomware pre-encryption)" XDR custom detection (hourly)

Source: `evals/review-and-fix-flawed-query/files/flawed.md`. Reviewed against the sentinel-fp-workflow
quality gates (`SKILL.md`), `references/kql-performance.md`, `references/kql-gotchas.md`,
`references/rule-windows-and-baselines.md`, `references/xdr-custom-detections.md`, and
`scripts/kql_lint.py` (1 error, 7 warnings on the original). Corrected rule: `fixed.kql`.

**Verdict: blocked.** As written the rule cannot be saved as an XDR custom detection (missing
required columns, a type-mismatched comparison), and if it could, the canonical true positive
(one `vssadmin delete shadows /all /quiet`) would not fire while an unrelated SMB join inflates the
count on every other device.

## Problems (line numbers refer to the ```kql block in flawed.md)

### Platform / save-time blockers

1. **L7 `TimeGenerated` in an XDR query** — Advanced Hunting device tables use `Timestamp`; this is a Sentinel column copied across (dual-platform drift, lint W010) and will not resolve in the portal.
2. **L12 `bin(TimeGenerated, 1h)`** — same wrong column a second time, and after the join the time column is ambiguous anyway.
3. **L12 output has no `Timestamp` / `ReportId`** — every XDR custom detection must return them; after `summarize` they must be recovered with `(Timestamp, ReportId) = arg_max(...)` (lint W020).
4. **L12 output has no `DeviceId`** — required impacted-asset column for Device tables is dropped by grouping on `DeviceName` only.
5. **L10 `RemotePort == "445"`** — `RemotePort` is an `int`; comparing it to a string literal is a type error, not a match (gotchas §1 "typed literals").

### Window / schedule

6. **L7 `> ago(1h)` on the recent window** — the service already evaluates the lookback on `ingestion_time()`; a self-inflicted event-time filter drops exactly the late-arriving events the 1h/4h lookback pair is designed to keep (lint W012 class; `rule-windows-and-baselines.md` §2).
7. **Zero-overlap schedule** — frequency 1h with a 1h event-time window means any event ingested later than its event time belongs to no run; hourly XDR rules use the fixed 1h/4h pair and need no in-query window.
8. **`bin()` for "N in 1h"** — epoch-aligned bins split a burst that straddles a clock boundary into two sub-threshold bins; with a count threshold this is a silent miss.

### Logic flaws (false negatives)

9. **L5/L9 `Commands` holds full command-line strings consumed by `has_any`** — a multi-word phrase matches terms in that exact order, so argument reorder, `/for=C:` inserted, `/quiet` omitted, or quoting evades every entry (lint W015; performance §Command-line discipline point 5 names this exact list as the counter-example).
10. **The normal invocation forms do not match** — `vssadmin delete shadows /all /quiet` and `wmic shadowcopy delete` carry no `.exe` token in the command line, so the phrases `vssadmin.exe delete shadows ...` / `wmic.exe shadowcopy delete` miss the way the tools are actually typed.
11. **L8 `FileName == "vssadmin.exe"` (case-sensitive)** — MDE preserves on-disk casing and attackers vary it; file names need `=~` / `in~` (lint W016).
12. **L8 chained `or` on FileName** — three separate clauses instead of one indexed `in~` list (performance §String matching).
13. **No `OriginalFileName` anchor** — a renamed copy of `vssadmin.exe` bypasses the file-name anchor; identify the binary by `ProcessVersionInfoOriginalFileName` with `FileName` as fallback (performance §Command-line discipline point 6).
14. **L13 `Count > 3`** — shadow-copy deletion is a single high-fidelity event; requiring more than three means the report's own true-positive sample (one command) never fires. The threshold is not hoisted, floored, or explained.
15. **Threshold counts the wrong thing** — after the DeviceId join, `Count` is the number of (process event x SMB connection) pairs, so a device with one deletion and many SMB sessions fires while a device with one deletion and no SMB telemetry never does.
16. **No `ActionType == "ProcessCreated"` filter** — `DeviceProcessEvents` now carries other ActionTypes; counts inflate and the match is no longer "a process was launched" (gotchas §3).

### Logic flaws (false positives / noise)

17. **L8 `ProcessCommandLine has_any ("-e", "-enc", "del")`** — all three terms are <= 3 characters: not term-indexed (full table scan) and `del` / `-e` match an enormous share of all process events (lint W006).
18. **Same clause is semantically unrelated** — `-e` / `-enc` are PowerShell encoded-command signals, not shadow-copy deletion; OR-ing them onto the FileName anchor destroys the anchor (any process with `del` in its arguments now passes line 8).
19. **L10 join to `DeviceNetworkEvents` on port 445** — SMB connections are ubiquitous on domain-joined hosts and have no causal link to shadow-copy deletion; the join adds no precision, only noise and cost.
20. **L10 join on `DeviceId` only, no time correlation** — every process row pairs with every 445 connection on the device across the whole lookback (cartesian fan-out), which is what the `Count` actually measures.

### KQL defects / performance

21. **L10 bare `join` (no `kind=`)** — default `innerunique` dedups the left side by `DeviceId`, silently keeping one process event per device (lint E001; the single most frequent defect in public rule repos).
22. **L10 right side of the join is not time-bound or projected** — scans the full `DeviceNetworkEvents` lookback with every column; "High" resource usage is a review blocker (performance §Joins, §Resource budget).
23. **Join makes the rule NRT-ineligible and non-portable for nothing** — single-table detections are an architectural choice; this one gives up Continuous frequency for an unjustified correlation (xdr-custom-detections §NRT).
24. **L11 `parse_json(AdditionalFields)[1].value` positional indexing** — `AdditionalFields` is a property bag, not an array; `[1]` returns null silently (gotchas §1). The parent process is already a first-class column (`InitiatingProcessFileName` / `InitiatingProcessCommandLine`).
25. **L11 `Parent` is computed then discarded** — the `summarize` on L12 drops it; dead code that costs a `parse_json` per surviving row after the join.
26. **L12 `make_set(DeviceName) by DeviceName`** — tautological (a one-element set of the group key) and unbounded (lint W005; cap with `make_set(x, N)`).
27. **L12 grouping by `DeviceName` alone** — hostname reuse collides across re-imaged devices and loses `DeviceId` (gotchas §1 "summarize by DeviceName").
28. **Filter-then-transform order inverted** — `has_any` on free text runs before the indexed FileName/ActionType narrowing is complete, and the `extend` runs after a fan-out join.

### Quality gates not met

29. **No stated intent / MITRE mapping** — T1490 Inhibit System Recovery (Impact) is never named; gate 1.
30. **No hoisted, commented tunables** — threshold and binary list are inline with no comment on meaning or the FP each trades against; gate 4.
31. **No environment-specific filter fence** — backup / imaging software is the known BTP generator for this technique and there is nowhere to exclude it without editing logic; gate 4 and FP-triage step 4 (blind-spot line).
32. **No dedup key documented next to the projection** — XDR dedups on entity + custom-detail values; the key must be explicit (`// DedupFields:`); gate 6.
33. **No evidence in the alert** — command line, account, parent process and OriginalFileName are all dropped, so the analyst gets a count and a hostname; gate 2 (entity-level alerting with context).
34. **No blind-spot / coverage statement** — PowerShell WMI (`Win32_ShadowCopy | Remove-WmiObject`), `diskshadow`, `bcdedit` recovery tampering, raw COM deletion and renamed binaries are not covered and not declared; gate 8.
35. **First-run 30-day scan not considered** — a new hourly rule scans 30 days on its first run; backup tooling in the estate will burst on deploy unless the fence is populated first (xdr-custom-detections §Frequency).
36. **Not unit-tested** — no TP fixture (the sample command line), benign lookalike (`vssadmin list shadows`, `wmic shadowcopy list`), boundary or empty-input cases; gate 7.

## What the fix does (summary; see fixed.kql)

- Single table, `ActionType == "ProcessCreated"`, no join; anchored on `ProcessVersionInfoOriginalFileName` / `FileName in~`.
- Command lines canonicalised (quotes, carets, commas stripped) and matched with unordered, case-insensitive token pairs per tool (`delete`+`shadows`, `resize`+`shadowstorage`, `shadowcopy`+`delete`, `delete`+`catalog`/`systemstatebackup`).
- No in-query recent-window filter; 1h frequency / 4h lookback pair; `let` contract mirrored for the reviewer.
- Aggregated to `DeviceId` + initiating account, `(Timestamp, ReportId) = arg_min(...)` so the alert points at the first deletion attempt; capped `make_set` evidence; `MinEvents = 1`.
- Fenced environment-specific exclusion for backup/imaging vendors with its blind-spot line; dedup key, MITRE, precision/coverage and blind spots stated in the header.
- `scripts/kql_lint.py --platform xdr --strict` clean.
