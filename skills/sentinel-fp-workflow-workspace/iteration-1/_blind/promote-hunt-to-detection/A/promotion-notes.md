# Promotion notes: `hunt.kql` -> `detection.kql` (Defender XDR custom detection, every hour)

Source hunt: "potential beaconing - rare public destination contacted many times by few devices"
(`DeviceNetworkEvents`, `ConnectionSuccess`, 7 d, `Hours > 12`, ranked by `Connections desc`).
Target: XDR custom detection, frequency **Every hour** (fixed platform lookback **4 h**). A Sentinel
scheduled-rule variant will follow; the last section lists what changes for it.

## 1. The one change that drives everything else: the window

| | Hunt | Detection |
|---|---|---|
| Window | `Timestamp > ago(7d)` | none in-query; platform pre-filters every table reference to `ingestion_time() > ago(4h)` |
| Persistence | `Hours > 12` (first-to-last span) | `ActiveBins >= 6` of 8 half-hour bins **and** `SpanMinutes >= 180` |
| Rarity | `Devices` shown, not thresholded | `Devices <= 3` (population filter, over the same 4 h) |
| Volume | none (ranked) | `Connections >= 16` per device<->IP pair (~ one per 15 min) |

Why: Microsoft Learn states that custom detections are pre-filtered to the lookback and that
"results outside of the lookback period are ignored". An hourly rule therefore never sees more than
4 h of data, in **every** branch of the query. The hunt's `Hours > 12` is structurally unsatisfiable
inside a 4 h window, so the criterion was rescaled rather than copied: "contacted across most of the
window" (6 of 8 bins, span >= 3 h) is the 4 h equivalent of "contacted across 12 h of 7 d".

Consequences you accept with the hourly schedule:
- Beacons with sleeps longer than ~15 min (fewer than 16 connections in 4 h) are below the floor.
- Prevalence over 4 h is weaker than over 7 d: a genuinely shared destination can look rare at 03:00.
  The Sentinel variant (14 d period) or an XDR **Every 24 hours / 30 d** variant is where the original
  7 d / 12 h criterion survives; if hourly latency is not actually required, prefer the 24 h pair.
- The hunt's `Timestamp > ago(7d)` was removed rather than replaced with `Timestamp > ago(4h)`: an
  explicit `Timestamp` filter on the recent window drops late-arriving events that the
  `ingestion_time()` lookback was designed to keep (lint W012). The rule has no `ago()` at all, which
  also makes it deterministic under the fixture harness.

## 2. Other changes and why

| Change | Hunt | Detection | Reason |
|---|---|---|---|
| Alert entity | one row per `RemoteIP` | one row per `DeviceId` + `RemoteIP` | The analyst investigates a device; XDR impacted asset = Device, RemoteIP = related evidence. A per-IP row cannot map a device. |
| Required columns | none | `Timestamp`, `ReportId`, `DeviceId`, `DeviceName` via `arg_max` of the latest event | XDR contract (lint W020 on the hunt). `arg_max` (latest), not `arg_min`: the alert should point at the most recent beacon. |
| Ranking -> thresholds | `sort by Connections desc` | compound floored thresholds in `let`s | Rules cannot rank; every tunable is hoisted with its meaning and the FP it trades against (lint I011 on the hunt). |
| Population filter | `Devices = dcount(DeviceId)` as output | `Devices <= MaxDevices` as a gate (stage 2) | Rarity logic needs a population cut or shared SaaS/CDN endpoints alert. |
| `make_set(InitiatingProcessFileName)` | unbounded | `make_set(..., 10)`, plus `RemotePorts` capped | Unbounded sets are capped at 1 M elements and bloat alert payloads (lint W005). |
| Process context | set only | latest `InitiatingProcessFileName` + `InitiatingProcessSHA256` kept | Gives a Process entity and a hash to pivot into `FileProfile` manually. |
| Performance | plain `summarize` | `hint.shufflekey = RemoteIP`; `materialize()` on `Pairs` (referenced 2x); `lookup kind=inner` for the small rare-IP set | High-cardinality key over the busiest MDE table; lookup keeps the left side intact and avoids a bare `join`. |
| Tuning region | none | fenced `// Begin/End environment-specific filter.` with four pre-written `OPTION` lines (known ranges, polling vendors by signer, bare-IP only, high-fan-out devices), each with its blind spot | No tenant literals in the rule; exclusions are data, added per environment, and every one is documented as a blind spot. |
| Header / metadata | one comment line | strategy / mechanic / resilience / data (sampled: yes) / TP likelihood / analyst action, MITRE TA0011 / T1071, severity Medium, DedupFields | Documentation gate; the description no longer says "hunt". |
| Dedup | none | `DedupFields: DeviceId, RemoteIP` documented next to the projection | Platform dedups identical entity + custom-detail rows within a run and across the 4 h / 1 h overlap. |

Portal settings to pair with the query: Frequency = Every hour; Impacted asset = Device (`DeviceId`);
Entities = IP (`RemoteIP`), Process (`InitiatingProcessFileName` / `InitiatingProcessSHA256`);
Custom details = `Devices`, `Connections`, `ActiveBins`, `SpanMinutes`, `AvgIntervalSeconds`,
`RemotePorts`, `Processes`; Severity = Medium; Category = Command and control; Technique = T1071.
**No automated response action** (no isolate): precision is unmeasured until the 7-day review.

## 3. Validation done / still to do

Done without tenant access:
- `scripts/kql_lint.py --platform xdr detection.kql`: 0 errors, 0 warnings (hunt scored W005, W012, W020, I011).
- `scripts/kql_test_harness.py` emits a self-contained test query from a fixture (datatable shadowing
  works because the rule has no `ingestion_time()`/`ago()` call).

Before enabling (needs the tenant):
1. Run the query body in Advanced Hunting over 7 d (`Timestamp > ago(7d)` temporarily on the first
   line, then remove) and count rows: target far below 150 per run. Expect to add 1-3 `OPTION`
   exclusions (monitoring / licence / update agents are the usual BTP generators).
2. Check the resource indicator after the run: must be Low or Medium.
3. Unit fixtures (one per case, `tables.DeviceNetworkEvents.events` with `Timestamp`, `ReportId`,
   `DeviceId`, `DeviceName`, `ActionType`, `RemoteIPType`, `RemoteIP`, `RemotePort`,
   `InitiatingProcessFileName`, `InitiatingProcessSHA256`):
   - TP: 1 device, 1 public IP, 16 connections every 15 min across 4 h -> 1 alert.
   - Benign lookalike (shared): same cadence from 4 devices to one IP -> 0 alerts (MaxDevices).
   - Benign lookalike (burst): 40 connections inside one 30-min bin -> 0 alerts (ActiveBins).
   - Boundary: 15 / 16 / 17 connections, 5 / 6 / 7 active bins, 179 / 180 / 181 min span.
   - Empty input (schema only) -> 0 rows, no error.
   - Private destination (`RemoteIPType == "Private"`) -> 0 alerts.

## 4. What to watch after deployment

- **First run burst.** On save the platform scans 30 days, not 4 h. Over 30 d, `ActiveBins` and
  `Connections` are trivially satisfied for any regularly-used destination and only `Devices <= 3`
  does any work, so the first run can hit the 150-alert cap. Treat that run as a baseline review:
  triage its alerts, feed the BTP generators into the `OPTION` exclusions, and re-save. Do not tune
  the thresholds on first-run data.
- **Repeat alerts per pair.** A beacon that keeps running produces a fresh alert roughly every 4 h
  once it leaves the dedup overlap (the platform only dedups across overlapping lookbacks; XDR custom
  detections have no suppression window). Incidents correlate these on `DeviceId`, so expect one
  incident with several alerts rather than many incidents. If this is too noisy, add the Sentinel
  variant's grouping or an alert-tuning rule, not a query change.
- **Volume per run vs 150.** Sustained counts anywhere near 150 mean the rule is silently dropping
  detections; sustained zero for more than a week means the throttled network telemetry or an
  exclusion has swallowed it ("days since last fired" tile).
- **BTP classes to expect** (from the skill's BTP taxonomy): MDE/MDI sensors, Intune and
  update agents, monitoring/RMM heartbeats, licence servers, VPN keep-alives, chat/telemetry clients.
  Exclude by signer/product or range in the fenced region, never by file name, and write the blind-spot
  line each time.
- **Blind spots to keep in the spec:** sleeps > 15 min; beacons on > 3 devices; beacons starting
  within the last 3 h of a window (alert comes on a later run); MDE network throttling (false
  negatives); anything inside an excluded range or vendor.
- **7-day post-deploy review:** classify every alert TP / BTP / FP with the FP worksheet, record
  precision, then decide whether the hourly pair is worth its weaker prevalence or whether the
  24 h / 30 d pair (with the hunt's 12 h span restored) is the better home.

## 5. For the Sentinel scheduled-rule variant (later)

- `Timestamp` -> `TimeGenerated` on the mirrored table; window becomes explicit:
  `TimeGenerated >= ago(ingestion_delay + rule_look_back)` and `ingestion_time() > ago(rule_look_back)`,
  with `queryFrequency = PT1H`, `queryPeriod` up to `P14D` so the 7 d / 12 h criterion can return as a
  baseline-vs-recent split (baseline on `TimeGenerated between (ago(7d) .. ago(1h))`, alert on the
  ingestion window).
- Entity mappings: Host (`HostName` from `DeviceName`), IP (`RemoteIP`), Process; grouping by Host +
  IP with `suppressionDuration` to solve the repeat-alert point above.
- Exclusions move from `OPTION` lets to a rule-scoped watchlist (`_GetWatchlist`, `tostring()` every
  column). Lint and parse the Sentinel copy separately; treat it as a generated variant.
