# Rule Windows, Ingestion Delay, Baselines & Deduplication

The single most common silent failure in community and official rules is a **time window that
does not match how the platform schedules the query**. This reference fixes that for Sentinel
scheduled rules and XDR custom detections, then covers baselines and dedup, which depend on it.

## 1. Mirror the rule contract inside the KQL

```kql
let query_frequency = 1h;   // == queryFrequency (Sentinel) / rule frequency (XDR)
let query_period    = 14d;  // == queryPeriod (Sentinel) / lookback (XDR)
let query_wait      = 15m;  // expected ingestion delay for this table (see §3)
```
The YAML/rule metadata and the KQL share names, so a reviewer can see the contract without
opening the portal. Comment any window deliberately delegated to the platform:
`// let authWindow = 20m; // implicit in the analytic rule query period`.
Frequency must be ≤ period (a `14d/4h` rule is undeployable). Sentinel caps `queryPeriod` at
**14 d** for scheduled rules; write `// query period limit 14d` on every rule that hits it.

## 2. Ingestion delay: never schedule with zero overlap

A rule with `queryFrequency == queryPeriod` on `TimeGenerated` drops any event ingested later
than its event time. Three correct forms:

**Sentinel (official Microsoft form):**
```kql
let ingestion_delay = 2min;
let rule_look_back  = 5min;
CommonSecurityLog
| where TimeGenerated >= ago(ingestion_delay + rule_look_back)   // wide scan on event time
| where ingestion_time() > ago(rule_look_back)                   // exact run window on ingestion time
```
The intended ingestion slices do not overlap, so under normal operation each event belongs to one run.
This is not an exactly-once guarantee: scheduler jitter, retries, null ingestion timestamps and delays
beyond the event-time scan can still produce gaps or repeats — test those cases. The `queryPeriod` must
cover `ingestion_delay + rule_look_back`.

**Sentinel (ep3p form) — explicit wait so the run looks at a settled slice:**
```kql
| where ingestion_time() between (ago(query_frequency + query_wait) .. ago(query_wait))
```
Use `TimeGenerated between (...)` instead when the table has a known, stable delay and you need
event-time semantics for the aggregation.

**Overlap form (FalconFriday) — `2 × frequency` on `ingestion_time()`, paired with dedup (§5):**
```kql
let timeframe = 2*1h;
DeviceEvents | where ingestion_time() >= ago(timeframe)
```

**XDR custom detections:** the service already evaluates the lookback on `ingestion_time()` —
events with old `Timestamp` values that arrive late still fire, and overlap between lookback and
frequency is deduplicated by the platform. Microsoft's own example adds
`| where ingestion_time() > ago(1d)` matched to the frequency for performance. Do **not** add
`Timestamp > ago(frequency)`: it is harmless on time but drops exactly the late-arriving events
the ingestion-time lookback was designed to keep. A `Timestamp` filter belongs only on the
**baseline** half of a baseline-vs-recent query.

Sentinel also pre-filters to `queryPeriod`; an in-query `ago()` is only for sub-windows.

## 3. Measure delay per table and keep it as data

```kql
union withsource=_Type *                                   // health hunt only, not a rule body
| where ingestion_time() > ago(1d)
| extend Delay = ingestion_time() - TimeGenerated
| summarize p50=percentile(Delay, 50), p90=percentile(Delay, 90), p99=percentile(Delay, 99) by _Type
```
Store the expected delay per table in a watchlist (`DataType-IngestedTables`: Type, Critical,
Frequency, DelayType, IngestionDelay) and use the same number to set `query_wait` **and** to
drive two health detections: *delayed ingestion* (`p90 > Expected * iff(DelayType == "offline", 2, 1)`)
and *stopped reception* (`max(TimeGenerated) by Type < ago(Expected)`). Detection health is itself a
detection. The Sentinel Workspace Usage Report workbook shows the same latency per table.

Streaming XDR tables into Log Analytics: if data lands more than 48 h late, `TimeGenerated` is
overwritten with `now()`; `Timestamp` keeps the event time. Prefer `Timestamp` for event-time math
on mirrored Device*/Email* tables.

## 4. Baselines

1. **The baseline window ends before the alert window starts** (`between (ago(14d) .. ago(1d))`
   vs `> ago(1d)`), with a guard gap (`runDelay`) so a "flash" attack is not its own baseline:
   ```kql
   let runDelay = 1d; let baselineDays = 14d;
   let startBaseline = ago(baselineDays + runDelay); let endBaseline = ago(runDelay);
   ```
   f-bader's `between (ago(14d) .. ago(70m))` vs `ingestion_time() > ago(60m)` is the same idea
   with a 10-minute guard.
2. **Floor the threshold**: `SuspiciousThreshold = max_of(PreviousMaxPerDay * factor, min_count)`
   so a quiet entity does not alert on 1 → 2. Thresholds are compound and dimensionally reasoned
   (unique accounts **and** failures per account **and** success/failure ratio), not one count.
3. **Baseline poisoning**: a self-updating baseline learns attacker activity after the first alert;
   repeat attacks by the same account go quiet. Document it in Blind Spots; consider a persisted
   baseline (watchlist / summary-rule table) that is reviewed, not auto-learned.
4. **Baseline grain = join grain** (see `hunting-patterns.md` §4.1).
5. **Population filter**: drop destinations/values shared by many entities
   (`dcount(DeviceId) <= N`) before alerting on rarity.
6. **Long baselines do not fit scheduled rules** (Sentinel 14 d, XDR 30 d). Materialise them with
   a **summary rule** (recommended schedule 24 h, delay 60 min) or a KQL job into a custom table
   (`_CL`) or a watchlist; the rule then becomes a cheap `!in` / `leftanti` within the allowed lookback.
   Hunting baseline (long lookback) → summary rule → detection (short lookback).
7. **Snapshot tables need `arg_max` first**: `IdentityInfo` (14-day snapshot cycle — look back ≥ 14 d),
   `DeviceInfo`, `OAuthAppInfo`, `AgentsInfo`, and the append-only `SecurityIncident`/`SecurityAlert`
   (every row is a version): `summarize arg_max(TimeGenerated, *) by <id>` before counting or joining,
   or every join fans out.

## 5. Deduplication across overlapping runs

- **Sentinel**: `eventGroupingSettings: AlertPerResult` + `incidentConfiguration.groupingConfiguration`
  (`matchingMethod: Selected`, `groupByEntities`, `lookbackDuration: 5h`) folds related alerts into one
  incident; it does not remove duplicate alerts. `suppressionEnabled` + `suppressionDuration` pause the
  **whole rule** after an alert, unrelated entities included — use only when that coverage loss is
  intended. Duplicate alerts are avoided by the run window (§2) and stable entity keys; hand-rolled
  dedup against `SecurityAlert` custom details must account for alert-table delay and replays.
- **XDR**: the platform dedups identical entity + custom-detail values within a run and across
  overlapping lookbacks. Make the dedup key explicit: define `DedupFields` next to the output
  projection and re-validate it whenever columns change (a FalconFriday dedup block broke when the
  projection changed). Aggregating to the investigated entity is what makes platform dedup work.
- **Feed-driven rules** (CISA KEV, TI): self-dedup against `SecurityIncident` titles over 24 h
  (`Title has_all ("CVE-", "...") | distinct Title`) and template the title via
  `alertDetailsOverride.alertDisplayNameFormat: "{{CVEid}} - ..."`.
- **"Threshold newly crossed"** (`activity_counts_metrics` over `2 × frequency`) alerts once on the
  transition instead of every run while the condition persists.

## 6. Time handling details

- `bin()` aligns to epoch, so bursts straddling a boundary split; `bin_at(T, 1h, now())` anchors
  to the run; `startofday()` on both ends of a daily baseline keeps bins aligned across runs.
- Local time: `datetime_utc_to_local(TimeGenerated, "Europe/Sofia")`, never `+ 2h` (DST-wrong).
  Working-hours exclusions use `dayofweek()` / `datetime_part("hour", Local)` on the converted value.
- Alert tables lag the raw tables; when correlating alert → raw, widen the raw-side window
  ("detections can be offline — retrieve a week of risk data").
- First run of a new XDR rule scans 30 days — pre-tune for the noise burst.

## 7. Review checklist

- [ ] `query_frequency`/`query_period`/`query_wait` lets mirror the rule metadata; frequency ≤ period
- [ ] Run window on `ingestion_time()`, scan window on `TimeGenerated` (Sentinel); no self-inflicted `Timestamp` filter on the recent half (XDR)
- [ ] Baseline window ends before the alert window; guard gap present; grain = join grain
- [ ] Thresholds floored and compound; population filter present for rarity logic
- [ ] Snapshot/append-only tables collapsed with `arg_max` before use
- [ ] Dedup strategy stated (grouping/suppression or `DedupFields`), key matches final projection
- [ ] Long baselines persisted (summary rule / watchlist), not re-derived inside a 14 d / 30 d rule
- [ ] `bin_at`/sliding window or documented boundary gap; local time via `datetime_utc_to_local`
