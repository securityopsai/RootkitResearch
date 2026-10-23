# Hunting Query Patterns & Hunt → Detection Promotion

Hunting queries and detection rules are different artefacts with different contracts. This
reference covers (1) what a hunt is and how it is documented, (2) the reusable hunting
patterns that recur across high-quality community and Microsoft content, and (3) the
mechanical steps that turn a hunt into a scheduled detection. For scheduling windows and
baselines see `rule-windows-and-baselines.md`; for operator gotchas see `kql-gotchas.md`.

## 1. Hunt vs Detection — the contract difference

| Dimension | Hunt | Detection |
|---|---|---|
| Window | Analyst-chosen: `{{StartTimeISO}}`/`{{EndTimeISO}}` placeholders (Sentinel hunting blade) or literal `ago(30d)` | `queryFrequency`/`queryPeriod` (Sentinel) or fixed frequency→lookback pair (XDR); baseline window excludes the alert window |
| Output | Wide, ranked (`sort by Score desc`, `top N by X asc`), `make_set` context, `project-reorder` who/where/what/how | One row per investigated entity, `arg_max`/`arg_min(..., *)`, platform-required columns, entity columns split for mapping |
| Thresholds | Loose and parameterised; prose says "raise to get fewer rows" | Compound, floored, with a population filter (`dcount(DeviceId) <= N`) |
| Noise | "You may need to exclude X" | Watchlist-backed exclusions inside a fenced tuning region |
| Dedup | Usually none | Run window + stable entity keys; XDR dedup key; Sentinel incident grouping (does not remove duplicate alerts) |
| Metadata | Hypothesis, analyst action, FP expectation label | Severity, MITRE, data sources, blind spots, version history |
| YAML (Sentinel repo) | `id, name, description, requiredDataConnectors, tactics, relevantTechniques, query, entityMappings, version` — **no** `severity`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`, `kind` | Full scheduling block |

A hunt that carries `severity` or `kind: Scheduled` is a lint error. A detection whose
description still says "this hunting query looks for" was promoted without rewriting.

A useful design habit (ep3p): write the **same parameterised function** so it is a hunt when
`query_frequency == query_period` (all activity in the window) and a detection when
`query_frequency < query_period` (new activity against the rest as baseline). This is a repository
convention, not a Sentinel rule — a scheduled detection may have equal frequency and period.

Taxonomy that works for a hunting library: **Detect** (alert-worthy if it fires), **Find**
(interesting, not necessarily bad), **Summarize**, **Visualize**; or `detection | hunt | posture`
with posture queries paired to their resource-graph check.

## 2. Hunt documentation header

Put the hypothesis in the query, so it survives copy-paste into a portal:

```kql
// DETECTION STRATEGY: <one sentence — the behaviour and why it matters>
// THE MECHANIC: <what the attacker does that produces this telemetry>
// THE RESILIENCE: <why the key chosen (e.g. DeviceId+FileName+Signer) survives benign change>
// DATA: <table / ActionType / connector> — retention assumed: <N d>  [sampled: yes/no]
// TP LIKELIHOOD WHEN IT FIRES: <high/med/low + why>   COVERAGE CAVEAT: <what it will miss>
// STEP 1..n: <what each block does>
// ANALYST ACTION: <what to check in the output; which `where` to drop to widen>
```

Rules: every tunable in a `let` with a comment stating its meaning **and the FP it trades
against** ("`FilePrevalenceThreshold = 250` — above this a file is probably benign"). Keep
`ReportId`, `DeviceId`, `DeviceName`, `Timestamp` in the projection so the hunt can be promoted.
Label noise honestly in-code (`// noisy — hunt only, not a SIEM analytic`). Mark untested
queries (`// UNTESTED — derived from report, no sample run`).

## 3. Hunt methodologies

### 3.1 The hunt funnel (3–5 queries, each output is a human decision input)

1. **Population statistics** — learn the environment before judging it:
   `summarize count() by ActionType` / `dcount(RemoteIP) by DeviceName | sort by`. Remove known
   noise sources with a documented reason (`not(DeviceId in (DomainControllers)) // MDI scanning`).
2. **Narrow by a derived attribute** — file extension, decoded command, `dcount` per process.
3. **Editable shortlist** — `let Suspicious = dynamic([...]); // add your own findings`.
4. **Pivot to the entity and enrich** — `invoke FileProfile(SHA1, 1000)`, `make_set(DeviceName)`,
   `make_set(FolderPath)`; or `IPsAccessed = make_set(RemoteIP) by DeviceName`.
5. **Corroborate across products** (MDI `IdentityDirectoryEvents`, MDO, CloudAppEvents) and
   **hand off** to parameterised DFIR pivots (`let VictimDeviceId`, `let LookupIP`, `let SearchWindow`).

Share one `TimeFrame` knob across every stage.

### 3.2 Threat report → hunt pack

The unit of output is a **pack of 3–10 narrow queries on one page**, not one correlated rule.

1. Quote each "detection opportunity" from the report verbatim as the query's intent; cite the
   report at page level **and** as a `//` comment inside each query (provenance survives paste).
2. Decompose into tiers and label them: **network IOC** (fast, brittle) → **static artefact**
   (hash, signer, `ProcessVersionInfoCompanyName`/`ProductName`, file path) → **behaviour**
   (process + argument + location). Keep IOC queries in separate files from behaviour queries;
   IOC lists go through `externaldata`/`dynamic`, never inline literals.
3. Translate the sample command line into **invariant tokens only**: anchor on `FileName in~`,
   then `has_all` of the 2–4 tokens the technique cannot do without. A `has_all` of the whole
   sample (10+ tokens, lab paths like `C:\m.sys`, task names) is an IOC in disguise.
4. **Store the raw (defanged) sample in the doc and run it as the TP fixture.** A query that
   cannot match its own evidence (`has_any ("invoke_webrequest")` against a `curl.exe` sample)
   is the most common report-derived bug.
5. Add the vendor-alert view (`AlertInfo | where Title has_any (...)`,
   `SecurityAlert | where AlertName has_any (...)`) so raw telemetry **and** the product's own
   detections are covered.
6. Record the map `report step → query → table/ActionType` and a MITRE table per page; mapping
   must name the behaviour the predicate asserts, not the data source ("T1059 because it is a
   command line" is wrong).
7. Vulnerability-driven: pair an **exposure** query (`DeviceTvmSoftwareVulnerabilities` ×
   `...KB`, `IsExploitAvailable`, `EpssScore`, `CvssVector has "/AV:N"`, internet-facing from
   `DeviceInfo.IsInternetFacing`) with a **post-exploitation behaviour** query per CVE.

### 3.3 Know your data before writing (schema radar)

```kql
// Which tables and sub-event types exist, and which are new vs a 180d baseline
union withsource=TableName *
| where TimeGenerated > ago(7d)
| extend Action = coalesce(column_ifexists("ActionType",""), column_ifexists("OperationName",""), column_ifexists("Operation",""))
| summarize FirstSeen=min(TimeGenerated), Events=count() by TableName, Action
| join kind=leftanti (
    union withsource=TableName * | where TimeGenerated between (ago(180d) .. ago(7d))
    | extend Action = coalesce(column_ifexists("ActionType",""), column_ifexists("OperationName",""), column_ifexists("Operation",""))
    | distinct TableName, Action) on TableName, Action
```
`union *` is hunting-only. Also: `T | getschema`, ingestion-delay percentiles per table (see
`rule-windows-and-baselines.md`), and `DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId`
to scope platform-specific hunts instead of guessing from hostnames.

## 4. Pattern catalogue

### 4.1 First-seen / not-in-baseline (the dominant shape)

```kql
let lookback = 30d; let gap = 2d;           // gap: a new value cannot whitelist itself
let known = DeviceProcessEvents
    | where Timestamp between (ago(lookback) .. ago(gap))
    | where FileName in~ (ToolList)
    | distinct DeviceId, FileName;           // baseline grain = join grain
DeviceProcessEvents
| where Timestamp > ago(gap)
| where FileName in~ (ToolList)
| join kind=leftanti known on DeviceId, FileName
| summarize (Timestamp, ReportId)=arg_min(Timestamp, ReportId), Count=count() by DeviceId, DeviceName, FileName
```

- Single key → `| where Key !in (known)`; composite key → `join kind=leftanti` / `rightanti`.
  **The join key must equal the baseline grain**: a baseline of `(UPN, AuthMethod, Location)`
  joined `on UPN, Location` silently drops the AuthMethod condition.
- Cast both sides to the same type (`tostring()` on dynamic-derived keys) or `!in` never matches.
- Baseline on **identity, not hash**, when software updates would churn the key:
  `DeviceId + FileName + Signer` (signer via `lookup kind=leftouter DeviceFileCertificateInfo`).
- `set_difference(make_set(New), KnownSet)` when comparing sets per entity (new countries per user).
- Normalise before baselining: users, GUIDs, versions, `$skiptoken` in paths/URIs →
  `replace_regex(Path, @'\\Users\\[^\\]+\\', @'\\Users\\<user>\\')`, then `reduce kind=source`
  for URI families. Rarity on raw strings is meaningless.
- Retention FP: a 90-day baseline on a 30-day table marks everything as new. State the retention
  assumption on line 1.

### 4.2 Rarity / prevalence (two-tier)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d) and isnotempty(SHA1)
| summarize MachineCount=dcount(DeviceId), Sample=take_any(FolderPath) by SHA1, FileName
| where MachineCount < 4                      // tier 1: local, cheap
| top 1000 by MachineCount asc                // FileProfile quota — profile only the rarest
| extend SHA1 = tolower(SHA1)                 // FileProfile is case-sensitive on hashes
| invoke FileProfile(SHA1, 1000)
| where not(ProfileAvailability =~ "Error")   // API failure ≠ unknown file
| extend GP = coalesce(GlobalPrevalence, 0)   // null = never seen = suspicious, not benign
| where GP < 200 or ((isempty(Signer) or not(IsCertificateValid)) and GP < 500)
| where not(SignatureState =~ "Unknown" and GP > 30000) // MDE bug: some MS-signed files report Unknown
```

- `FileProfile` is **XDR-only** (not Sentinel, not an emulator): rules using it are XDR-native
  and need a unit-test skip-list entry.
- `DeviceFileCertificateInfo` holds **only signed files** — an inner join cannot prove "unsigned";
  use `leftouter` and treat absence as "unknown".
- Fleet rarity by `dcount(DeviceId)`; ratio-to-population for shared destinations
  (`dcount(Users) per domain`); `top 1000 ... asc` before any quota-limited enrichment.
- Renamed binaries: `datatable(OriginalFileName, Expected:dynamic)` + `lookup kind=inner` +
  `not(set_has_element(Expected, tolower(FileName)))`; identify vendor tools by
  `ProcessVersionInfoCompanyName`/`ProductName`, not by file name.

### 4.3 Beaconing (three algorithms, pick by telemetry)

(a) **Aggregated reports** — cheap, no raw events:
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d) and ActionType == "ConnectionSuccessAggregatedReport"
| where not(ipv4_is_private(RemoteIP))
| extend Connections = toint(parse_json(AdditionalFields).uniqueEventsAggregated)
| summarize Devices=dcount(DeviceId), AvgConn=avg(Connections), Hashes=make_set(InitiatingProcessSHA256, 10) by RemoteIP, bin(Timestamp, 1d)
| where AvgConn >= 25 and Devices <= 5        // many connections, few devices …
// … then FileProfile the process hashes: rare process completes the triad
```
Inverse-anomaly variant: `make_list(ConnectionCount)` per hour → `series_decompose_anomalies` →
a beacon is a series with **few** anomalies (uniform hourly count).

(b) **Jitter on inter-arrival deltas** — collapse first, then compute inside the row:
```kql
| summarize hint.strategy=shuffle Times=make_set(Timestamp) by DeviceId, InitiatingProcessFileName, RemoteIP, RemotePort // lint:ignore W005 — bounded by the MaxEvents filter below
| where array_length(Times) between (MinEvents .. MaxEvents)   // MaxEvents = window / min_sleep
| project DeviceId, InitiatingProcessFileName, RemoteIP, RemotePort, Times=array_sort_asc(Times)
| mv-apply T=Times to typeof(datetime) on (
    extend Next=next(T,1) | extend Delta=datetime_diff('second', Next, T) | where isnotnull(Next) // lint:ignore W009 — array_sort_asc above is the order
    | summarize Deltas=make_list(Delta), percentiles(Delta, 5, 50, 95) ) // lint:ignore W005 — bounded by MaxEvents
| extend (DMin, DMinIdx, DMax, DMaxIdx, DAvg, DStdev, DVar) = series_stats(Deltas)
| extend Jitter = DStdev / DAvg * 100
| extend Outliers = series_outliers(Deltas)
| mv-apply o = Outliers to typeof(real) on (summarize OutlierCount = countif(abs(o) > 1.5))
| where Jitter < JitterThreshold and OutlierCount <= OutlierMax
| join kind=inner (/* population filter */ DeviceNetworkEvents | summarize dcount(DeviceId) by RemoteIP | where dcount_DeviceId <= CompromisedMax) on RemoteIP
```
Tuning arithmetic belongs in comments: "15-min sleep with 25 % jitter → `MinDelta = 900 - 225`".

(c) **RITA-style scoring** — Bowley skew + MADM on time deltas **and** bytes; `score >= 0.85`.
Caveat for all three: MDE **samples/throttles** network logging → false negatives; long sleeps
(6 h–1 d) are out of reach of a 3-day window.

### 4.4 Time-series anomaly (two-stage)

```kql
let sensitivity = 2;      // lower = more sensitive; default 1.5
let floor = 5;            // absolute floor: "1 → 2 events" is a relative anomaly, not a finding
let outliers = SigninLogs
| where TimeGenerated > startofday(ago(14d)) and ResultType == "53003"
| make-series Failures=count() default=0 on TimeGenerated from startofday(ago(14d)) to startofday(now()) step 1d by UserPrincipalName
| extend Anomalies = series_decompose_anomalies(Failures, sensitivity)
| mv-expand TimeGenerated to typeof(datetime), Failures to typeof(long), Anomalies to typeof(int)
| where Anomalies == 1 and Failures > floor
| distinct UserPrincipalName;
SigninLogs | where TimeGenerated > ago(1d) and UserPrincipalName in (outliers) // stage 2: raw rows for outliers only
```
Use `make-series ... default=0`, never `summarize by bin | make_list` (gapped series distort the
decomposition). `series_outliers` on small counts flags `1,1,1,1,5` — require `value > floor`.
Cheap XDR-compatible proxy: `toscalar(avg per day over 60d)` and a deviation ratio.

### 4.5 Sequences and time-window correlation

- Direction **and** bound: `| where (Later - Earlier) between (0min .. 30min)` — an open
  `< threshold` matches reversed order and mislabelled units.
- `bin()` splits bursts at clock boundaries (10:55–11:05 → two sub-threshold bins). Use
  `bin_at(T, 1h, now())`, a self-join window, `evaluate sliding_window_counts(...)` (may duplicate
  alerts — group them), or document the gap.
- Ordered multi-step within an entity: `scan` with `with_match_id` and `declare`d state
  (Sliver: connection → `\wkssvc` pipe → `samlib.dll` within 1 s; break-glass add→remove with
  dwell time). Sort `by Entity asc, Timestamp asc` first.
- `prev()`/`next()`/`row_number()` are only meaningful after `order by <partition key>, <time>`;
  restart per group with `row_number(1, prev(Key) != Key)`.
- Composite process identity when `ProcessUniqueId` is absent:
  `strcat(DeviceId, "|", InitiatingProcessId, "|", tostring(InitiatingProcessCreationTime))`.
- Zeek `*ConnectionInspected` rows carry no process → attribute via
  `join on LocalIP, RemoteIP, LocalPort, bin(Timestamp, 5m)` to `ConnectionSuccess`.
- Timeline around a pivot: `let Anchor = toscalar(... | summarize max(Timestamp));`
  `| where Timestamp between ((Anchor - Window) .. Anchor) | top N by Timestamp desc | extend Phase="pre"`
  unioned with the post-window and `sort by Timestamp asc`.

### 4.6 Flow fingerprinting (identity)

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| summarize Codes=make_set(ResultType, 50), IPs=make_set(IPAddress, 10), Tokens=dcount(UniqueTokenIdentifier) by CorrelationId, UserPrincipalName // Sentinel SigninLogs has no SessionId; AADSignInEventsBeta/EntraIdSignInEvents do
| where Codes has_all ("0", "50140", "50074")  // success + KMSI prompt + MFA required (AiTM shape); lint:ignore W006 — numeric codes are whole terms, term match is exact here
| join kind=inner (SigninLogs | where TimeGenerated > ago(1d) | summarize arg_min(TimeGenerated, *) by CorrelationId) on CorrelationId
```
`arg_min(..., *)` recovers the **first** event of the flow for `Timestamp`/`ReportId` mapping.
Device-code: `has_all (0, 50199)`; see `identity-email-patterns.md`.

### 4.7 "Threshold newly crossed" (alert once on the transition)

```kql
| as _Events
| join kind=leftsemi (
    _Events
    | evaluate activity_counts_metrics(Type, TimeGenerated, ago(query_period), now(), query_frequency, CallerObjectId) // query_period = 2 * query_frequency
    | summarize arg_min(PrevT = TimeGenerated, PrevCount = ["count"]), arg_max(CurT = TimeGenerated, CurCount = ["count"]) by CallerObjectId
    | extend PrevCount = iff(PrevT == CurT, 0, PrevCount)
    | where (not(PrevCount > threshold) and CurCount > threshold) or ((CurCount - PrevCount) > threshold)
  ) on CallerObjectId
```

### 4.8 Posture / graph hunts

- `ExposureGraphEdges | make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId`
  `| graph-match (S)-[e*1..3]->(T) project ...` for privilege paths; `EdgeLabel == "has credentials of"`,
  `NodeProperties.rawData.exposureScore`, `EntityIds.type == "DeviceInventoryId"` to join `DeviceId`.
- TVM: `materialize()` the device set and `toscalar(make_set(CveId))` to pre-narrow the KB join;
  `parse_version()` for version comparisons (never `toreal(extract(...))`).
- Snapshot-diff hunts (`AgentsInfo`, `OAuthAppInfo`, `IdentityInfo`): `arg_max(Timestamp,*) by Id`
  per window, then `set_difference`.
- Posture hunts legitimately carry `tactics: []`.

### 4.9 Threat-intelligence matching

Sentinel's TI table is `ThreatIntelIndicators` (STIX-shaped); `ThreatIntelligenceIndicator` is legacy.
```kql
let ioc_lookBack = 14d; let dt_lookBack = 1h;
let IP_IOCs = ThreatIntelIndicators
| where TimeGenerated >= ago(ioc_lookBack)
| extend IndicatorType = tostring(split(ObservableKey, ":", 0)[0])
| where IndicatorType in ("ipv4-addr", "ipv6-addr", "network-traffic")
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| project Id, IP = ObservableValue, ValidUntil, Confidence, Data;
IP_IOCs
| join kind=innerunique (CommonSecurityLog | where TimeGenerated >= ago(dt_lookBack) | project-rename LogTime=TimeGenerated) on $left.IP == $right.DestinationIP // innerunique is deliberate: one match per IOC
| where LogTime < ValidUntil
```
Domains need all levels checked (`has_any` on URL fields, not `==`); default rules only match
events **after** indicator ingestion — add a `table_query_lookback` pass for older events when
an indicator arrives. AppLocker emits PE256, not SHA256 — hash rules silently never fire there.

### 4.10 IOC feed hygiene (`externaldata`)

- Split by type and bind each to the right column **and operator**: domains → `RemoteUrl has_any (Domains)`;
  exact URLs/IPs/hashes → `in`; CIDRs → `evaluate ipv4_lookup(Ranges, IP, cidr, return_unmatched=true)`
  (an equi-join IP == CIDR string yields zero rows silently).
- Validate rows with a type regex, `distinct`, `tolower`, `materialize()` once, cap the feed
  (`verification_time > ago(8h)`) because `has_any` cost scales with list size.
- Emit a stats row (`union isfuzzy=true (FeedStats), (Hits)`) so an empty/404 feed is distinguishable
  from "no hits". Unpinned `main` URLs and dated file names rot; mirror unreachable feeds via CI.
- Not available in XDR NRT rules; treat feed content as adversarial (match only, never execute or exclude).

## 5. Promotion checklist: hunt → detection

1. **Fix the windows**: learning window = `query_period`, alert window = `query_frequency` (+ `query_wait`);
   baseline excludes the alert window; XDR: only the baseline half keeps an explicit time filter.
2. **Replace ranking with thresholds**: `sort by Score` → compound thresholds with floors and a
   population filter; thresholds stay in KQL (`triggerOperator: gt`, `triggerThreshold: 0`).
3. **Collapse per entity**: `summarize arg_min/arg_max(..., *), make_set(ctx, N) by <entity>`;
   split entity columns (`Name`/`UPNSuffix`, `HostName`/`DnsDomain`); sets of entities →
   `mv-expand` so each gets its own row.
4. **Externalise allow-lists** to watchlists keyed by rule scope; keep a fenced tuning region
   (`// Begin environment-specific filter.` … `// End environment-specific filter.`) with
   pre-written `// OPTION` lines; grep for `CHANGE IF DIFFERENT FOR YOUR ORG` in CI.
5. **Dedup**: stable entity keys and a correct run window; XDR dedup key documented next to the
   output projection and re-validated when columns change. Sentinel incident grouping does not remove
   duplicate alerts, and `suppressionEnabled` pauses the whole rule — document the choice.
6. **Drop portal-only operators**: `render`, `evaluate pivot`, `search`, `union *`, `take`; long
   baselines (90–365 d) move to a summary rule / custom table / watchlist, the rule becomes a cheap `!in`.
7. **Rewrite the description** ("Identifies/Detects …", threshold and window in prose, `Ref:`),
   add severity, MITRE, data sources with ActionType, **blind spots** for every filter the hunt
   loosened, and the sample as the TP fixture.
8. If the "detection" is a toggled filter on the hunt (`leftouter` enrichment + `where Severity == "Red"`),
   document the toggle lines rather than maintaining two diverging copies.

## 6. IR / DFIR query packs (a third artefact class)

Cloud IR packs (Log Analytics query packs) are single-table, exact-`OperationName` pivots with no
`ago()` and no aggregation — the portal time picker is the parameter. Better form: `let`-parameterised
inputs (`FlaggedIPs`, `CompromisedUsers`, `SearchWindow`), union/join across M365 tables, one
summarised timeline/matrix row per entity, `Indicator`/`EventSource`/`TableName` columns so a
multi-source timeline sorts and pivots. Verify exact-string operation names (en-dash, trailing
space) and use `has` for them. Scoped `union Device*` bounded by time is legitimate here; so is
`search in (T1..Tn) Timestamp between (...)`. Collect **configuration snapshots** as well as events
(permissions, roles, app credentials) — retention may not reach back to the event.

---
Provenance: distilled from Azure/Azure-Sentinel (Hunting Queries + Detections), FalconForce
FalconFriday, Cyb3r-Monk, ep3p, Bert-JanP, reprise99, HybridBrothers, SecurityAura, m4nbat,
Cloud-Architekt, f-bader and related community repos (reviewed 2026-10). Treat tenant-specific
thresholds in examples as placeholders.
