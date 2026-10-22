---
name: sentinel-fp-workflow
description: KQL detection engineering for Microsoft Sentinel and Defender XDR. Covers writing analytics rules and custom detections, KQL query performance and quality, unit testing detections with mock data, detection-as-code (CI/CD, YAML, code reuse via ASIM/functions/watchlists), FP triage and tuning, exclusion logic, and documentation standards. Use when writing or reviewing KQL detection rules, tuning analytics rules, building XDR custom detections, testing detection logic, analyzing alert noise, or managing FP ratios for client reporting.
---

# KQL Detection Engineering & FP Workflow

Detection engineering for Microsoft Sentinel and Defender XDR, quality-first. This file
is the router and the core workflows; depth lives in `references/`.

## Reference Routing

| Task | Load |
|------|------|
| Writing/reviewing any KQL query (performance, operators, joins) | `references/kql-performance.md` |
| Defender XDR custom detection (Advanced Hunting based) | `references/xdr-custom-detections.md` |
| Rule repos, CI/CD, unit testing, code reuse (ASIM/functions/watchlists) | `references/detection-as-code.md` |
| Documenting a change / FP analysis / client report | `references/documentation-templates.md` |

Scripts:

- `scripts/kql_test_harness.py` — build unit-test queries from fixtures (datatable substitution, pinned now()), emit or run.
- `scripts/kql_fp_patterns.py` — generate tuned KQL snippets for common FP fixes.

## Detection Authoring Quality Gates

Every new or modified rule must pass ALL gates before deploy. Treat a failed gate as a
review blocker, not a style nit.

1. **Intent stated** — one sentence: what attacker behavior does this catch, mapped to
   MITRE tactic + technique. If you can't state it, the rule is a hunt, not a detection.
2. **Entity-level alerting** — aggregate to the entity the analyst investigates
   (`summarize arg_max(...) by <entity>`), never one alert per raw event row.
3. **Tunables hoisted** — thresholds, lookback assumptions, and exclusion lists in `let`
   statements at the top or externalized to watchlists. No magic numbers mid-query.
4. **Performance reviewed** — passes the checklist in `references/kql-performance.md`
   (indexed operators, early filtering, join hygiene, no unscoped `search`/`union`).
5. **Platform contract met** — Sentinel: entity mappings + version bump.
   XDR: required columns (`Timestamp`, `ReportId`, device/account IDs), frequency/lookback
   pair valid, NRT restrictions respected. See `references/xdr-custom-detections.md`.
6. **Unit tested** — true positive, benign lookalike (true negative), threshold boundary
   (n-1 / n / n+1), and empty-input fixtures. Use `scripts/kql_test_harness.py`.
7. **Documented** — change record per `references/documentation-templates.md`, PR-reviewed.

## FP Triage Process

1. **Classify** — True Positive, Benign True Positive (BTP), or False Positive
2. **Root cause** — Query logic flaw, missing exclusion, environmental noise, or data quality issue
3. **Fix approach** — Rule tuning vs. watchlist exclusion vs. automation rule suppression
4. **Document** — Use templates in `references/documentation-templates.md`
5. **Validate** — Confirm FP reduction without detection gaps (re-run unit fixtures; the
   true-positive fixture must still fire after the exclusion is added)

## Fix Selection Matrix

| Root Cause | Fix Approach | Risk |
|------------|--------------|------|
| Overly broad query | Tune KQL in analytics rule | Medium |
| Known-good entity | Add to exclusion watchlist | Low |
| Vendor/tool noise | Automation rule auto-close | Low |
| Data quality (nulls) | Fix at source or null handling | High |
| Scheduled tasks | Time-based exclusion or BTP | Medium |

Rule of thumb: prefer the fix that does NOT require a rule redeploy (watchlist,
automation rule) when the exclusion is data, and a query change when the exclusion is
logic. Never copy-paste exclusions across rules — centralize (see code reuse section of
`references/detection-as-code.md`).

## Core KQL FP Patterns

Generate with `scripts/kql_fp_patterns.py --list`. Quick reference:

### Watchlist Exclusion (Sentinel)
```kql
let Excluded = _GetWatchlist('FP_Exclusions') | project Entity = tolower(Entity);
SecurityEvent
| where tolower(TargetUserName) !in (Excluded)
```

### Time-Window Exclusion
```kql
| where not(dayofweek(TimeGenerated) in (0, 6) and hourofday(TimeGenerated) between (2 .. 4))
```

### Threshold Tuning
```kql
| summarize Count = count() by TargetUserName, bin(TimeGenerated, 1h)
| where Count > 10
```

### Null-Safe Field Handling
```kql
| where isnotempty(TargetUserName) and TargetUserName != "-"
```

### Entity Dedup with Platform Contract Preserved (XDR)
```kql
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), EventCount = count() by DeviceId
| where EventCount > 5
```

## Validation Checklist

- [ ] Unit fixtures pass: TP fires, benign lookalike does not, boundary cases correct
- [ ] Test query with 7-day lookback against live data
- [ ] Confirm exclusion doesn't suppress known-bad patterns (TP fixture still fires)
- [ ] No syntax errors or timeouts; XDR resource indicator not "High"
- [ ] Entity mappings / required columns intact after the change
- [ ] Version bumped, change record written, peer review done
- [ ] Document expected FP reduction %
- [ ] Schedule 7-day post-deploy review
