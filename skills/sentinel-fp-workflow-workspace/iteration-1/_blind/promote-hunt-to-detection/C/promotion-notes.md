# Promotion notes: hunt.kql -> XDR custom detection (hourly)

## What the hunt did
`hunt.kql` looked back 7 days over `DeviceNetworkEvents`, grouped successful public
connections by `RemoteIP`, and surfaced destinations that were contacted repeatedly over
a span of more than 12 hours. It was an analyst-driven ranking (`sort by Connections desc`)
with no thresholds, no exclusions, no per-device output and no event identifiers. That is
fine for a human reading a table; it is not a detection.

## What changed and why

| Area | Hunt | Detection | Why |
|---|---|---|---|
| Lookback | `ago(7d)` | `ago(4h)` | XDR fixes the lookback by frequency; an hourly rule only sees the last 4 hours. The 7-day window cannot be reproduced at this cadence, so the logic had to be re-based on what *is* visible. |
| Persistence test | span > 12h | span >= 2h within a 4h window, >= 12 connections | The 12-hour test is impossible with 4h of data. Replaced with "sustained for at least half the window" plus a minimum volume. |
| Beaconing evidence | none (volume only) | inter-arrival regularity: average interval 30s-30min and `stdev/avg <= 0.35` | Volume alone over a short window is mostly CDN, telemetry and SaaS traffic. Periodicity is the actual beaconing signal and gives the rule a defensible reason to fire. |
| Rarity | implicit (analyst eyeballed `Devices`) | `dcount(DeviceId) <= 3` per RemoteIP, computed tenant-wide inside the window | Makes the "few devices" idea an explicit, tunable threshold. Note the baseline is only 4h wide now, so a destination that is genuinely common but quiet in that hour can still look rare. |
| Grouping key | `RemoteIP` | `DeviceId, RemoteIP, InitiatingProcessFileName, InitiatingProcessSHA256` | XDR needs an entity to attach the alert to. One row per device/destination/process also tells the analyst *which* binary is beaconing. |
| Required columns | none | `Timestamp`, `ReportId`, `DeviceId` | Mandatory for custom detections. They are taken from the **first** event of the beacon (`arg_min`) so that successive hourly runs over the same beacon return the same key and XDR de-duplicates instead of alerting every hour. Once the first event ages out of the 4h window the key changes and one fresh alert is raised, which is the intended "still beaconing" reminder. |
| `make_set(InitiatingProcessFileName)` | unbounded dynamic set | process is now part of the group key; `make_set` only used for ports/URLs with a cap of 10/5 | Unbounded sets bloat rows and cannot be mapped to an entity. Caps protect against noisy hosts. |
| Exclusions | none | small allowlist of Defender sensor/AV processes; empty CIDR allowlist; private-range guard | The sensor itself beacons to Microsoft on a regular cadence and would be the top result. Everything else is left in deliberately; see "what to watch". |
| `sort by` | yes | removed | Ordering has no meaning in a detection and costs time. |
| Tunables | hard-coded | `let` block at the top | Thresholds can be adjusted in one place during tuning and reused verbatim in the Sentinel version. |

Things deliberately *not* done:
- No exclusion by `InitiatingProcessVersionInfoCompanyName` ("Microsoft Corporation" etc.). Version-info strings are attacker-controlled and this is a C2 rule; the fields are projected for triage only.
- No `svchost.exe`/browser/Teams/OneDrive exclusions yet. They will produce FPs, but excluding them blind would also hide injected-process beaconing. Tune by destination (`RemoteIpAllowlist`) after review rather than by process.
- No automated response actions. Isolation on a periodicity heuristic is not safe until the FP rate is known.

## Rule configuration (XDR portal)
- Name: `Possible C2 beaconing to rare public IP`
- Frequency: Every hour
- Severity: Medium (raise to High only after tuning)
- Category: Command and control; MITRE T1071, T1571
- Impacted entities: Device (`DeviceId`/`DeviceName`); include process columns in the alert description
- Actions: none
- Recommended alert title: `Periodic connections from {InitiatingProcessFileName} to {RemoteIP}`

## What to watch after deployment
1. **Volume in the first 24-48h.** Expect the top FPs to be: endpoint management agents (Intune, SCCM, Tanium, Qualys, CrowdStrike/other EDR if dual-deployed), monitoring/RMM agents, VPN clients, time sync, printer and IoT firmware, long-lived WebSocket apps (Teams, Slack, Zoom), and any in-house agent. Add destinations to `RemoteIpAllowlist` as CIDRs once confirmed; avoid blanket process exclusions.
2. **De-duplication behaviour.** Confirm that a continuing beacon produces one alert per ~4h rather than one per hour. If XDR is not de-duplicating on the `Timestamp`/`ReportId` pair as expected, switch `arg_min` to `arg_max` and rely on incident grouping instead.
3. **Rarity baseline is only 4h.** During quiet periods (nights, weekends) almost every destination looks "rare". Watch for a weekend spike; if it appears, either raise `MinConnections` or move the rarity check to a 24h-frequency rule (30-day lookback) and keep this hourly rule for the periodicity test only.
4. **IPv6 destinations.** The private-range guard uses `coalesce` so IPv6 rows survive; verify a few IPv6 results are present and sane, since the hunt never saw them in bulk.
5. **Query cost.** `make_list(EpochSeconds, 5000)` per group is the heaviest step. If the rule hits the custom-detection timeout, add `| where Connections >= MinConnections` *before* computing intervals by splitting the summarize, or lower the 5000 cap (connections beyond the cap are dropped from the interval maths, not from the count).
6. **Jitter threshold.** Real malware frameworks commonly use 10-50% jitter. `MaxJitterRatio = 0.35` catches the low-jitter majority; if red-team or purple-team exercises with high jitter are missed, consider a second, lower-severity tier at 0.6 with a higher `MinConnections`.
7. **Interval edge cases.** Very long beacons (> 30 min) are intentionally out of scope for the hourly rule because they cannot reach 12 connections in 4h; cover them in the Sentinel version.

## Notes for the Sentinel scheduled rule (later)
- Sentinel is not bound to the 4h limit: use `queryPeriod` up to 14d with an hourly `queryFrequency`, so the original 7-day rarity baseline (`dcount(DeviceId) by RemoteIP` over 7d) can be restored while the periodicity test runs on the last few hours.
- Keep the same `let` tunables; map entities: Host (`DeviceName`, `DeviceId`), IP (`RemoteIP`), Process (`InitiatingProcessFileName`, `InitiatingProcessCommandLine`), FileHash (`InitiatingProcessSHA256`), Account (`InitiatingProcessAccountName`).
- Use alert grouping on `RemoteIP` + `DeviceId` with a 4-6h window, and `suppressionDuration` of 4h, to mirror the de-duplication behaviour of the XDR rule.
- The two rules will overlap; decide whether the XDR rule remains the primary (device-centric, lower latency) and the Sentinel rule becomes the long-baseline/reporting version, or disable one to avoid double incidents when the Defender-to-Sentinel incident sync is enabled.
