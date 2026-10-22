# Promotion Notes: hunt.kql -> Defender XDR custom detection

**Rule name:** Possible C2 beaconing - sustained, regular connections to a rare public IP
**Rule ID:** _assign at creation (Graph Security API / portal); never regenerate_
**Change date:** 2026-10-22
**Change type:** New rule (promotion of hunting query)
**Version:** 1.0.0
**Intent:** A device repeatedly contacts a public IP that almost no other device in the estate talks to, at a regular cadence across most of the window - consistent with C2 beaconing. MITRE TA0011 Command and Control: T1071 (Application Layer Protocol), T1571 (Non-Standard Port).
**Files:** `detection.kql` (the XDR query), `tests/fixtures/*.json` (unit-test fixtures for `scripts/kql_test_harness.py`).

## XDR rule settings

| Setting | Value | Why |
|---|---|---|
| Frequency | Every 1 hour | Requested. XDR fixes the lookback for this frequency. |
| Lookback | 4 h (fixed by platform) | Not configurable at 1 h frequency; drives every threshold below. |
| Impacted asset | Device -> `DeviceId` | The entity the analyst investigates. Max one column per entity type. |
| Related evidence | IP `RemoteIP`; Process `InitiatingProcessSHA256`/`InitiatingProcessFileName`; Account `InitiatingProcessAccountSid` | Pivots for triage; not impacted assets. |
| Severity / category | Medium / Command and control | Behavioural, not IOC-based; needs analyst confirmation. |
| Response actions | **None** | Do not attach Isolate/Restrict until FP rate is known (see watch list). |
| Alert title | `Possible beaconing: {DeviceName} -> {RemoteIP} ({Connections} conns / {SpanMinutes} min, {Devices} devices estate-wide)` | Custom details: Connections, ActiveBins, SpanMinutes, Devices, Processes. |

## What changed and why

| # | Hunt (hunt.kql) | Detection (detection.kql) | Why |
|---|---|---|---|
| 1 | `where Timestamp > ago(7d)` | **Removed.** No Timestamp filter at all. | XDR pre-filters to the rule lookback (ingestion-time based). A self-imposed filter fights it; 7 d is impossible at 1 h frequency anyway. |
| 2 | `Hours > 12` (span over 7 days) | Replaced by a cadence triad: `Connections >= 12`, `SpanMinutes >= 180`, `ActiveBins >= 8` (15-min buckets) | A 4 h window can never contain a >12 h span - the hunt condition would silently never fire. The triad expresses the same idea (sustained + regular) inside 4 h. Each is a hoisted `let` tunable. |
| 3 | `Devices = dcount(DeviceId)` computed but never filtered ("few devices" was eyeballed) | Explicit rarity gate `Devices <= MaxDevices (3)` computed estate-wide in `RareIPs`, joined with explicit `kind=inner` | Detections cannot rely on an analyst sorting and eyeballing. Rarity is computed over all successful public connections (before process/URL exclusions) so a popular destination is never "rare". |
| 4 | Grouped by `RemoteIP` only (DeviceId lost) | Grouped by `DeviceId, RemoteIP`; `(Timestamp, ReportId, DeviceName, ...) = arg_max(...)` recovered after `summarize` | XDR platform contract for device tables: `Timestamp`, `ReportId`, `DeviceId`, `DeviceName` must be in the final output. Alert is per device/IP pair = the investigation entity, so platform dedup works. |
| 5 | `sort by Connections desc` | Removed | Ordering is meaningless in a scheduled rule and costs a serialisation. |
| 6 | No exclusions | `ExcludedRemoteIPs`, `ExcludedProcessNames`, `ExcludedUrlTerms` as empty `dynamic([])` lists at the top | Tuning is data, not logic. Start empty; populate only from reviewed FP cases. XDR has no watchlists: grow into `externaldata()`; the Sentinel version uses `_GetWatchlist()`. |
| 7 | `make_set(InitiatingProcessFileName)` unbounded | `make_set(..., 10)` for Processes/Ports/Urls; `project` before `summarize`; `hint.shufflekey = RemoteIP` | Bounded evidence columns and early projection keep the resource indicator Low/Medium (High is a review blocker). |
| 8 | No null handling | `isnotempty(RemoteIP) and isnotempty(DeviceId)` | Empty keys would aggregate into a junk bucket and could satisfy the thresholds. |
| 9 | - | Case-sensitive `==` on `ActionType`/`RemoteIPType`; `!in~` on process names | Enum values are producer-controlled (cheap, exact); process names are attacker-controlled casing. |

Threshold rationale (defaults, tune after 7 days): 12 connections over >= 3 h in >= 8 of 16 quarter-hour buckets catches beacons with an interval of roughly 15 min or less, with jitter. Longer intervals (30-60 min) are **not** covered at 1 h frequency - if that matters, run a sibling rule at 12 h / 48 h lookback that keeps the hunt's long-span logic, or cover it in the Sentinel version (see below).

## Quality gates (SKILL.md)

- [x] Intent stated with MITRE mapping (header of `detection.kql`)
- [x] Entity-level alerting (`summarize ... by DeviceId, RemoteIP`)
- [x] Tunables hoisted (six `let` thresholds + three exclusion lists)
- [x] Performance checklist: filters on raw columns before `extend`; `project` before `summarize`; explicit `kind=inner`, smaller side left; no `search`/`union`/regex/bare `take`
- [x] Platform contract: required columns in final `project`; 1 h / 4 h pair valid; no self-inflicted Timestamp filter; not NRT (uses `join`, comments, two table references)
- [x] Unit fixtures written (`tests/fixtures/`): `tp`, `tn_popular_destination`, `tn_short_burst`, `tn_private_ip`, `boundary_n_minus_1 / n / n_plus_1` (MinConnections), `boundary_devices_n / n_plus_1` (MaxDevices), `empty`. Test queries emit cleanly via `kql_test_harness.py`; **they have not been executed** (no tenant access) - run with `--run --workspace <guid>` before merge.
- [ ] Peer review
- [ ] 7-day lookback dry run in Advanced Hunting (replace nothing - just paste and run; note resource indicator and row count)

## Watch after deployment

1. **First run scans 30 days, not 4 h.** Every threshold is calibrated for 4 h, so the first run will over-fire (any device with 12+ connections to a rare IP in a month qualifies). Expect a burst; if it approaches the **150 alerts/run cap** it is silently truncating. Either accept and bulk-close the first batch as "deployment noise", or create the rule with a temporarily stricter `MinConnections` (e.g. 200) and relax it after the first run.
2. **Alerts per run vs. the 150 cap.** Anything sustained above ~50/run means the rarity or cadence gates are too loose for this estate - tighten `MaxDevices` or raise `MinConnections` before adding exclusions.
3. **Repeat alerts for a continuing beacon.** The 4 h window slides 1 h per run; a persistent beacon re-qualifies every run with a new latest `ReportId`, so expect up to one alert per hour per device/IP until contained. XDR incident correlation should group them on the device; if it does not, switch the required-column recovery to `arg_min` (stable first event across overlapping runs) and re-test.
4. **Top FP drivers to expect** (review the `Processes`/`Urls` evidence columns weekly and feed the exclusion lists, not the thresholds): EDR/monitoring agents and telemetry uploaders; VPN/ZTNA clients and always-on tunnels; NTP, licensing and update servers; CDN/anycast edges where each device gets its own IP (looks "rare" per device - exclude by `RemoteUrl` term, never by IP); backup and sync agents on servers. Every exclusion entry needs a justification, ticket and expiry (watchlist entry format in `documentation-templates.md`).
5. **Ingestion delay.** Lookback is ingestion-time based: late-arriving events can fire with old Timestamps, and `FirstSeen`/`LastSeen` are window-relative, not the true start of the beacon. Pivot in Advanced Hunting for the real first contact.
6. **Resource indicator.** Check it after the first few runs; "High" is a blocker - first lever is removing `Urls`/`InitiatingProcessCommandLine` from the evidence set, second is dropping the `RareIPs` pass to a single pass with `arg_max` only.
7. **Schedule the 7-day post-deploy review**: FP %, TP/BTP/FP split, threshold adjustments, and version bump to 1.1.0 on any change. Target FP reduction after first tuning round: >= 60 % of the first-week FP volume via exclusion data only (no logic change).

## Rollback plan

Disable the rule in the portal (or `PATCH /security/rules/detectionRules/{id}` with `isEnabled: false`). No downstream automation depends on it. Re-enable after re-tuning and bumping the version.

## Notes for the Sentinel scheduled-rule version (later)

- Add the explicit time filter the XDR version deliberately omits: `| where TimeGenerated > ago(QueryPeriod)` on **both** table references.
- Sentinel allows `queryFrequency: PT1H` with `queryPeriod` up to 14 d, so the hunt's long-span condition (`Hours > 12`) can be reinstated there as an extra tunable; keep the same cadence triad so the two rules stay comparable.
- Replace the three `dynamic([])` lists with `_GetWatchlist('FP_Exclusions')` filtered by `RuleScope` (code reuse: data -> watchlist, per `detection-as-code.md`).
- Entity mappings: Host (`FullName` <- `DeviceName`), IP (`Address` <- `RemoteIP`), Process (`CommandLine` <- `InitiatingProcessCommandLine`), Account (`Sid` <- `InitiatingProcessAccountSid`). Event grouping: alert per result row. Version 1.0.0, bump on every change.
- Reuse the same fixtures; only the table name (`DeviceNetworkEvents` is identical in Sentinel's MDE connector) and the `TimeGenerated` column differ.
