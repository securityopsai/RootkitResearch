# Detection-as-Code: Repo, CI, Unit Testing, Code Reuse

## Repository Layout

```
Detections/          # Sentinel analytics rules (YAML, Azure-Sentinel repo schema)
DefenderDetections/  # XDR custom detections (YAML → Graph Security API)
HuntingQueries/      # YAML with KQL + MITRE annotations
Functions/           # Saved KQL functions (shared logic), deployed as code
Watchlists/          # JSON + CSV
AutomationRules/     # JSON
Playbooks/           # Logic Apps ARM
tests/
  fixtures/<rule-id>/   # one dir per rule: tp.json, tn_*.json, boundary_*.json, empty.json
Scripts/             # pipeline orchestration
```

## Rule YAML (Sentinel schema, minimum viable fields)

```yaml
id: <GUID — stable forever, never regenerate>
name: Suspicious service stop via net.exe
description: >
  Detects Defender firewall service stops via net.exe. MITRE T1562.001.
severity: Medium
requiredDataConnectors: [...]
queryFrequency: PT1H
queryPeriod: PT4H
triggerOperator: gt
triggerThreshold: 0
tactics: [DefenseEvasion]
relevantTechniques: [T1562.001]
query: |
  ...
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
version: 1.0.3          # bump on EVERY change; CI rejects unbumped diffs
```

Deployment: Sentinel Repositories (GitHub/ADO), or Terraform
`azurerm_sentinel_alert_rule_scheduled`, or Bicep/REST. XDR rules deploy via Graph
Security API upsert. Portal is read-only by policy; pipelines should detect
portal-modified rules and either skip (preserve tuning) or overwrite — pick one policy
and enforce it, silent drift is the failure mode.

## CI Gates (cheap → expensive; fail fast)

1. **Schema validation** — YAML validates against rule schema; GUID unique; version bumped.
2. **Offline KQL parse** — `Microsoft.Azure.Kusto.Language` (NuGet) against a schema
   snapshot of your tables. Catches column typos and syntax with zero infrastructure.
3. **Lint** — entity mappings present (Sentinel) / required columns projected (XDR);
   MITRE mapping present; no unscoped `search`/`union`; no bare `take`; thresholds in
   `let`; XDR frequency/lookback pair valid; NRT restriction check if continuous.
4. **Unit tests** — fixture-based, below. ~1 s/query against an empty workspace, or
   tenant-free against a local Kusto emulator (ADX emulator container).
5. **Deploy to dev workspace** — `whatIf`/`Test-AzResourceGroupDeployment` dry-run first.
6. **E2E smoke (nightly, not per-PR)** — ingest fixtures via Logs Ingestion API, assert
   incident/alert actually fires.

## Unit Testing KQL Detections

Core insight: a KQL detection is a pure function of its input tables. Substitute the
real table with an inline `datatable` of synthetic events (a `let` with the table's
name shadows the real table), pin `now()` to a fixed timestamp, execute, assert.

```kql
let query_now = datetime(2026-07-21T12:00:00Z);
let DeviceProcessEvents = datatable (Timestamp:datetime, ReportId:long,
    DeviceId:string, DeviceName:string, FileName:string, ProcessCommandLine:string) [
  datetime(2026-07-21T11:55:00Z), 1, "dev1", "host1.corp", "net.exe", "net stop MpsSvc",
  datetime(2026-07-21T11:56:00Z), 2, "dev2", "host2.corp", "net.exe", "net use \\\\share"
];
// ... original rule query follows unchanged, with now() replaced by query_now
```

`scripts/kql_test_harness.py` automates this: fixtures in → test query out (or executed).

### Fixture classes — all four per rule, no exceptions

| Fixture | Asserts | Catches |
|---------|---------|---------|
| `tp.json` — true positive | exactly N expected alerts, key columns/entities correct | broken logic |
| `tn_*.json` — benign lookalikes | 0 alerts | false-positive bugs (most bugs live here) |
| `boundary_*.json` — threshold n-1 / n / n+1 | correct on/off behavior at the edge | off-by-one, `>` vs `>=` |
| `empty.json` — schema only, no rows | 0 alerts, no error | null-handling, divide-by-zero, `arg_max` on empty |

Assert exact alert count AND the projected columns/entity fields — "returned something"
is not a passing test. When adding an FP exclusion, the TP fixture re-run is the
regression test that proves you didn't create a detection gap.

### Execution targets

| Target | Cost | Use |
|--------|------|-----|
| Empty Log Analytics workspace | ~1 s/query, needs a tenant | default CI |
| Kusto/ADX emulator (container) | tenant-free | fully offline CI; some LA/XDR-specific functions unavailable — keep a skip-list |
| Dev workspace + Logs Ingestion API | minutes | nightly E2E only |

## Code Reuse (in order of leverage)

1. **ASIM parsers** — write the detection once against a normalized schema
   (`imProcessCreate`, `imAuthentication`, ...) instead of N per-source variants.
   Highest payoff with heterogeneous log sources. Cost: parser performance overhead —
   use source-specific ASIM parsers where volume is high.
2. **Saved KQL functions** — shared allowlist checks, enrichment, normalization live in
   one function, deployed as code from `Functions/`. Rule queries call the function.
   Never copy-paste tuning exclusions between rules.
3. **Watchlists** — tunable DATA (VIPs, known-good IPs, service accounts) externalized
   so tuning changes need no rule redeploy and no version bump. Schema per
   documentation-templates.md (Entity, EntityType, Justification, ExpiryDate, RuleScope,
   TicketRef — expiry review is mandatory, permanent exclusions rot).
4. **YAML templating** — parameterized rule templates in the pipeline for families of
   near-identical rules (per-client thresholds, per-environment table names). Prefer a
   template + params over N diverging copies.

Decision rule: logic → function; data → watchlist; schema variance → ASIM; rule-family
variance → template.

## Versioning & Review

- Semantic-ish versioning per rule (`version:` field); CI rejects content changes
  without a bump.
- PR review checklist = quality gates in SKILL.md + kql-performance.md review checklist.
- Content-hub solutions: update only on newer semver; protect portal customizations
  deliberately.
- Every merged change gets a Detection Change Record (documentation-templates.md) —
  the rollback plan field is not optional.
