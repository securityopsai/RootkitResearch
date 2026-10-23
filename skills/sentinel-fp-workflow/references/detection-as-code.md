# Detection-as-Code: Repo, CI, Unit Testing, Code Reuse

## Repository Layout

```
Detections/          # Sentinel analytics rules (YAML, Azure-Sentinel repo schema)
DefenderDetections/  # XDR custom detections (YAML → Graph Security API)
HuntingQueries/      # YAML with KQL + MITRE annotations — NO scheduling block (see below)
IRQueryPacks/        # Log Analytics query packs (ARM) for incident-response pivots
SummaryRules/        # long-baseline materialisation feeding short-lookback rules
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

Full Sentinel contract fields the minimum omits — use them, they are where alert quality lives:

```yaml
kind: Scheduled                      # or NRT: then omit queryFrequency/queryPeriod/triggerOperator/triggerThreshold, prefix name "NRT "
requiredDataConnectors: []           # [] is valid (ASIM, Heartbeat, Anomalies, AgentsInfo); otherwise list EVERY connector that can feed the table with dataTypes
tags:                                # list of MAPS, not strings
  - Schema: ASimWebSession
    SchemaVersion: 0.2.1
  - ParentAlert: <url of the vendor-specific rule this ASIM rule derives from>
customDetails:                       # flat map AlertLabel: ColumnName, 3–6 keys — the "why"
  DetectionReason: DetectionReason
  NewCountry: NewCountry
alertDetailsOverride:                # pair with AlertPerResult, else {{placeholders}} are ambiguous
  alertDisplayNameFormat: "{{CVEid}} - exploitation attempt on {{DeviceName}}"
  alertDescriptionFormat: "..."
  alertSeverityColumnName: Severity  # severity computed in KQL from asset/identity tier
  alertTacticsColumnName: Tactics    # pass-through rules over Anomalies / SecurityAlert
  alertDynamicProperties:
    - alertProperty: Techniques
      value: Techniques
eventGroupingSettings:
  aggregationKind: AlertPerResult
incidentConfiguration:
  createIncident: true
  groupingConfiguration:
    enabled: true
    reopenClosedIncident: false
    lookbackDuration: 5h
    matchingMethod: Selected
    groupByEntities: [Account, Host]
suppressionDuration: 5h
suppressionEnabled: false           # pauses the WHOLE rule for suppressionDuration after an alert; not per-entity dedup
```

Entity-mapping discipline (official content ships ≥ 24 broken mappings — lint it):
- Account = `FullName` + `Name` + `UPNSuffix` (cloud) or `FullName` + `Name` + `NTDomain` (on-prem);
  Host = `FullName` + `HostName` + `DnsDomain`, computed with a fixed idiom:
  `HostName = tostring(split(Computer, ".")[0])`, `DnsDomain = iff(indexof(Computer, ".") != -1, substring(Computer, indexof(Computer, ".") + 1), "")`.
- Distinct roles get distinct blocks (`Initiating*` / `Target*`), plus `AadUserId`-only blocks;
  sets of entities → `make_set(X, 250)` for the threshold then `mv-expand X to typeof(string)`;
  Process needs `tostring(ProcessId)`; never map a dynamic column.
- `columnName` must exist, case-sensitively, in the **final** output; `{{placeholders}}` and
  `customDetails` columns must survive the last `summarize`. Legacy `*CustomEntity`/`timestamp`
  columns and auto-mapping are deprecated — write explicit mappings.
- Severity convention observed in Microsoft content: High = campaign IOC rules, privileged-identity
  persistence, named CVE exploitation, missing DC heartbeat; Medium = behavioural/anomaly; Low =
  hygiene/noisy; Informational = operational failures. Severity tracks confidence × impact; compute
  it from the affected tier where possible.
- Thresholds live in KQL; the wrapper is `triggerOperator: gt` / `triggerThreshold: 0` (164 of 168
  official rules). Frequency/period: equal for stateless rules, `1d/14d` or `1d/8d` for baseline rules,
  `15m/2h` for heartbeat gaps — never zero-overlap on `TimeGenerated` (see `rule-windows-and-baselines.md`).

Hunting-query YAML = detection YAML **minus** `severity`, `queryFrequency`, `queryPeriod`,
`triggerOperator`, `triggerThreshold`, `kind`. Hunts bind the picker with
`let starttime = todatetime('{{StartTimeISO}}'); let endtime = todatetime('{{EndTimeISO}}'); let lookback = starttime - 14d;`
(never `totimespan()` on it); detections use `ago()`. Keep a one-line `description` plus
`description_detailed` (keys compared, scenarios, references). Tactic vocabularies differ
(ATT&CK CamelCase `CommandAndControl` vs Defender UI `Command and control`, plus non-ATT&CK buckets
`Ransomware`, `Vulnerability`) — normalise in CI, reject scalar `tactics:`; posture hunts may use `tactics: []`.

Shipped rules keep a fenced tuning region so customer tuning survives upstream updates:
```kql
// Begin environment-specific filter.
// OPTION 1: | where not(AccountName in (ServiceAccounts))
// OPTION 2: | where not(DeviceName has_any (BuildServers))
// End environment-specific filter.
```
CI greps for `CHANGE IF DIFFERENT FOR YOUR ORG`, placeholder literals (`"1.1.1.1/8"`,
`"ADD DOMAINS HERE"`, `client1`) and tenant-specific values before deploy. Per-customer FP/FN
dials are template variables (Jinja: `enable_high_volume_dn`, `allow_same_folder_injection`),
not code edits. Retire a superseded rule by replacing the file with a pointer to its successor —
never delete (`tags: - Id: <guid>` links the replacement in Sentinel YAML).

Deployment: Sentinel Repositories (GitHub/ADO), or Terraform
`azurerm_sentinel_alert_rule_scheduled`, or Bicep/REST. XDR rules deploy via Graph
Security API upsert. Portal is read-only by policy; pipelines should detect
portal-modified rules and either skip (preserve tuning) or overwrite — pick one policy
and enforce it, silent drift is the failure mode.

## CI Gates (cheap → expensive; fail fast)

1. **Schema validation** — YAML validates against rule schema; GUID unique; version bumped.
2. **Offline KQL parse** — `Microsoft.Azure.Kusto.Language` (NuGet) against a schema
   snapshot of your tables. Catches column typos and syntax with zero infrastructure.
3. **Lint** (`scripts/kql_lint.py` covers the query-side checks) — entity `columnName`,
   `customDetails` and `{{placeholders}}` exist case-sensitively in the final projection (Sentinel) /
   required columns projected (XDR); MITRE mapping present, list-typed, normalised vocabulary; GUID
   valid and unique; `version` well-formed (`l.0.0` typos ship); hunts carry no scheduling fields;
   `queryFrequency <= queryPeriod <= 14d`; no zero-overlap `TimeGenerated` window; XDR
   frequency/lookback pair valid; NRT restriction check if continuous; **bare `join` is an error**;
   unbounded `make_set`; `has`/`contains` terms under 3 chars (3-char terms flagged as info); positional dynamic indexing; `materialize`
   on single-reference lets; `prev()` without partitioned `order by`; `search`/`union *`/`take`;
   tenant placeholders; `TimeGenerated` in an XDR block / `Timestamp` in a Sentinel block; both
   platform variants parsed (dual copies drift in ≈5 % of files); exact-string Entra operation names.
4. **Unit tests** — fixture-based, below. ~1 s/query against an empty workspace, or
   tenant-free against a local Kusto emulator (ADX emulator container).
5. **Deploy to dev workspace** — `whatIf`/`Test-AzResourceGroupDeployment` dry-run first.
6. **E2E smoke (nightly, not per-PR)** — ingest fixtures via Logs Ingestion API, assert
   incident/alert actually fires.

## Unit Testing KQL Detections

Core insight: a KQL detection is a pure function of its input tables. Substitute the
real table with an inline `datatable` of synthetic events (a `let` with the table's
name shadows the real table), pin `now()` and `ago()` to a fixed timestamp, model ingestion timestamps
explicitly (`__ingestion_time` column per row when the query uses `ingestion_time()`; the harness refuses
to invent one), execute, assert. Emission alone is not a passing test.

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

- **The TP fixture for a report-derived rule is the report's own (defanged) sample command line.**
  Store it in the rule doc (`### Example Script`) and generate `tp.json` from it; a query that cannot
  match its own evidence (`has_any ("invoke_webrequest")` vs a `curl.exe` sample) is the most common
  report-derived bug and this fixture catches it.
- One fixture set **per platform variant** (XDR and Sentinel copies drift).
- Skip-list: `FileProfile`, `SeenBy`, `DeviceFromIP`, `_GetWatchlist`, `externaldata`, Sentinel
  functions — rules using them need the dev-workspace / XDR-native target, not the emulator.

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
   TicketRef — expiry review is mandatory, permanent exclusions rot). Design notes from the most
   rigorous public Sentinel repo (ep3p):
   - Name by key type and purpose: `Activity-ExpectedSignificantActivity`, `ID-TIBenignProperty`,
     `RegEx-PrivilegedRoles`, `ResultType-SignInLogsErrorCodes`, `IP-CorporateRanges`, `DataType-IngestedTables`.
   - **One generic exclusion schema for all rules**, keyed by rule scope (`Activity`), with optional
     columns, `-` as wildcard and bracketed tags in `Notes` (`[App]`, `[HomeTenant]`, `[VPN]`):
     ```kql
     let _Expected = _GetWatchlist("Activity-ExpectedSignificantActivity")
         | where Activity == "SecretRetrieval"
         | project ActorId = tostring(ActorId), Resource = tostring(DestinationResource), Operation = tostring(Auxiliar);
     ...
     | join kind=leftanti (_Expected | where isnotempty(Resource)) on ActorId, Operation, Resource   // specific rows
     | join kind=leftanti (_Expected | where isempty(Resource))    on ActorId, Operation             // generic rows
     ```
     `tostring()` every watchlist column — `_GetWatchlist` returns dynamic and joins fail silently on type.
     The generated patterns read `RuleScope`/`ExpiryDate` with `column_ifexists()` and **fail closed** on
     expiry: a missing, invalid or past `ExpiryDate` excludes nothing; `RuleScope` `*` is an explicit global scope.
   - Watchlists are also **dictionaries** (result codes with `[Success]` tags → `toscalar(make_list(ResultType))`),
     **regex sources** (`strcat(@'^(', strcat_array(RegEx, '|'), @')$')`), **operational SLOs**
     (expected ingestion delay per table → `query_wait` and health rules), **monitored assets**
     (honeytokens with `-` prefix = exclude), and **detection substitution** lists (vendor alerts a custom rule supersedes).
   - Read defensively: `_GetWatchlist('X') | extend Col = column_ifexists("Col", "")`, merge with a
     `dynamic()` default via `array_concat()`. Single IP and CIDR in one column: split at query time
     (`contains "/"` → `ipv4_is_in_any_range`).
   - Diff deployed watchlists in CI from the raw `Watchlist` table
     (`_DTItemType == 'watchlist-item'`, `arg_max(_DTTimestamp, *) by _DTItemId`, `_DTItemStatus != 'Delete'`, `bag_unpack(WatchlistItem)`).
4. **YAML templating** — parameterized rule templates in the pipeline for families of
   near-identical rules (per-client thresholds, per-environment table names). Prefer a
   template + params over N diverging copies.

5. **Summary rules / KQL jobs** — any baseline longer than the rule lookback (90–365 d "first
   seen", prevalence, known countries) is materialised daily (recommended schedule 24 h, delay 60 min,
   `ReportDate = now()` column) into a custom table; the detection becomes a cheap `!in` within 14 d / 30 d.
6. **Shared entity derivation** — `HostName`/`DnsDomain`, `AccountName`/`AccountDomain`,
   `Initiator`/`InitiatorIP` from `InitiatedBy` live in one function; identifier churn (`FullName`
   deprecated) is then a one-place change plus a repo-wide sweep.
7. **Mirrored feeds** — `externaldata` sources that cannot be fetched (vendor CSVs, rate-limited APIs)
   are mirrored into the repo by a scheduled workflow; pin or hash feed versions; never point a
   scheduled rule at a dated file name.

Decision rule: logic → function; data → watchlist; schema variance → ASIM; rule-family
variance → template; long baseline → summary rule. ASIM is rare in community repos (parser cost);
use source-specific parsers where volume is high and keep a dual path
(`union isfuzzy=true (DeviceFileEvents ...), (imFileEvent ...)`) during migration.

## Versioning & Review

- Semantic-ish versioning per rule (`version:` field); CI rejects content changes
  without a bump.
- PR review checklist = quality gates in SKILL.md + kql-performance.md review checklist.
- Content-hub solutions: update only on newer semver; protect portal customizations
  deliberately.
- Every merged change gets a Detection Change Record (documentation-templates.md) —
  the rollback plan field is not optional. The rule's Version History table carries an `Impact`
  column (major/minor) and a one-line reason; read as a whole it is the lessons-learned log
  ("fixed blind spot introduced by performance update", "added ProcessCreated filter as MDE rolls
  out new ActionTypes", "updated dedup fields to match output columns").
- Detection health is a detection: per-table delayed/stopped ingestion rules driven by the
  expected-delay watchlist; "days since rule last fired" from `SecurityIncident`; per-rule
  precision / false-discovery-rate from closed-incident classifications with a `[prefix]` on custom
  rule names; rule-change auditing from `CloudAppEvents` / `AzureActivity` (see `xdr-custom-detections.md`).
