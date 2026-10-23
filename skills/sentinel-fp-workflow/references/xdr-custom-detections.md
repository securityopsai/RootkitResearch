# Defender XDR Custom Detections — Platform Contract

Fixed platform constraints for custom detection rules built on advanced hunting.
Numbers verified against Microsoft Learn 2026-07 and re-checked 2026-10. These are hard limits, not tuning
preferences — violating them fails silently or at save time, never loudly in CI unless
you lint for them (see detection-as-code.md).

## Required Columns

Microsoft phrases these as recommended; in practice they decide whether the alert gets the right
device-group scope, a process tree and a timeline, so treat them as the contract. Every custom
detection query should return, from the same original event:

| Table type | Required |
|-----------|----------|
| Device tables (MDE) | `Timestamp`, `ReportId`, `DeviceId`, `DeviceName` |
| All other XDR tables | `Timestamp`, `ReportId` |
| Email actions | additionally `NetworkMessageId` + `RecipientEmailAddress` |

After aggregation, recover them:

```kql
DeviceEvents
| where ingestion_time() > ago(1d)            // optional, matches the frequency — Microsoft's own example
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 5
```

- Use `arg_min(Timestamp, ReportId)` instead when the alert should point at the **first** event
  of a flow (sign-in flow by `CorrelationId`, first-seen logic).
- Device-keyed tables without `Timestamp`/`ReportId` (`DeviceTvm*`): bridge with
  `DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId | project DeviceId, Timestamp, ReportId`
  (DeviceInfo carries `ReportId`) — not a throw-away join to `DeviceProcessEvents`. `OAuthAppInfo` and
  `ExposureGraph*` have no `DeviceId`; use their own identifiers and validate alert provenance.
- Community XDR queries almost never carry the required columns (≈3 % of files); any
  "import from community repo" step needs an automatic required-column fix-up.

**Do NOT filter on `Timestamp` yourself for the recent window.** The service evaluates the
lookback on `ingestion_time()`: late-arriving events with old `Timestamp` values still fire, and
a `Timestamp > ago(frequency)` filter (common in community rules) drops exactly those events.
An `ingestion_time()` filter matched to the frequency is fine (performance). A `Timestamp`
filter belongs only on the **baseline** half of a baseline-vs-recent query
(`Timestamp between (ago(30d) .. ago(2d))`). See `rule-windows-and-baselines.md`.

## Frequency ↔ Lookback (fixed pairs, XDR data)

| Frequency | Lookback |
|-----------|----------|
| Every 24 h | 30 d |
| Every 12 h | 48 h |
| Every 3 h | 12 h |
| Every 1 h | 4 h |
| Continuous (NRT) | real-time, heavy restrictions below |
| Custom (5 min – 14 d) | Sentinel-sourced tables only; freq > 1 h → lookback < 48 h; freq > 1 d → ≤14 d; freq ≤ 1 d → ≤30 d |

- **First run always scans 30 days back** — expect and pre-tune for a noise burst on deploy.
- Lookback is evaluated against `ingestion_time()`, not event time. Late-arriving events
  with old Timestamps still fire; never assume event-time ordering.

## Hard Limits

- **150 alerts max per rule run.** A rule hitting this cap is silently dropping
  detections. Treat sustained counts anywhere near 150 as a broken rule.
- Max **1 column per entity type** as impacted asset (Account, Device, Mailbox, Cloud
  App, Azure/AWS/GCP Resource). Everything else goes in as related evidence
  (Process, File, IP, URL, Registry, OAuth App, ...).

## Deduplication Semantics (exploit these)

- Identical entity + custom-detail + dynamic-detail values within one run → ONE alert.
- Lookback > frequency overlap → duplicates auto-deduplicated across runs.
- Distinct events in the same run attach as separate events on a single alert.

Design consequence: aggregate to the entity the analyst investigates and let the
platform dedup do the noise reduction — do not emit per-event rows and hope. Make the dedup key
explicit (`// DedupFields: DeviceId, SHA1`) next to the output projection and re-validate it
whenever the projection changes. Per-event "detections" (`FileName endswith ".lnk" and
InitiatingProcessFileName has "explorer.exe"`) with extreme base rates hit the 150 cap on run one.

## Continuous (NRT) Restrictions

Eligible only if the query:

- references exactly ONE table (from the supported NRT table list — includes the main
  Device*, Email*, Identity*, CloudAppEvents, UrlClickEvents tables; check current docs
  before assuming a table qualifies);
- uses NO `join`, `union`, `externaldata`;
- contains no comments/info lines;
- restricts itself to the supported KQL feature subset; regex must be encoded as string
  literals (`"\\A"` not `\A`).

Design consequence: single-table detections are an architectural choice you make for
latency. Anything correlational runs at 1 h frequency minimum — decide per rule which
side of that line it lives on, and record the decision in the rule's YAML. Good NRT candidates
are atomic, high-fidelity single-table events: Identity Protection premium risk events
(`AADUserRiskEvents RiskEventType in ("nationStateIP", "attackerinTheMiddle")`), MDCA
`CloudAppEvents | where IPTags has_any ("Brute force attacker", "Password spray attacker", "Tor")`,
"Add member to role outside of PIM". Sentinel-saved functions are **not** supported in custom
detections and NRT frequency is unavailable for rules that include Sentinel data.

## Response Actions Need a Precision Bar

Any rule wired to isolate / purge / disable / collect must state its measured precision
(e.g. "≥ 90 % TP over the last 30 days") and a kill switch, and should be single-table NRT-eligible.
Counter-examples from public repos: isolate-device on any `.php` file created, purge on a subject
prefix, "Cobalt Strike" labelled on `RemoteUrl contains "graph.microsoft.com"`. Response actions
bolted onto low-precision logic are an outage generator.

## XDR-Only Telemetry and Functions

- `invoke FileProfile(SHA1, 1000)` / `SeenBy()` / `DeviceFromIP()` exist only in XDR: rules using
  them are XDR-native and need a unit-test skip-list entry (no emulator, no Sentinel). FileProfile
  quirks: lower-case hashes, 1,000-row cap (`top 1000 by MachineCount asc` first), drop
  `ProfileAvailability == "Error"`, `coalesce(GlobalPrevalence, 0)`, `SignatureState == "Unknown"` on
  some Microsoft-signed files.
- `DeviceProcessEvents` has ActionTypes beyond `ProcessCreated` — filter it explicitly in process-creation rules.
- `DeviceNetworkEvents` aggregated reports (`ConnectionSuccessAggregatedReport`,
  `AdditionalFields.uniqueEventsAggregated`) and Zeek inspection events (`HttpConnectionInspected`,
  `DnsQueryResponse`, `NetworkSignatureInspected` — sampled) are cheap detection sources; see `kql-gotchas.md` §3.
- Baseline windows differ: 30 d in XDR vs up to 90 d+ in Sentinel for the same logic.

## Auditing the Detection Platform Itself

- Rule changes: `CloudAppEvents | where ActionType in ("CreateCustomDetection", "EditCustomDetection",
  "ChangeCustomDetectionRuleStatus", "DeleteCustomDetection")` and `"ExclusionConfigurationAdded"`,
  `"SetAdvancedFeatures"` (e.g. Live Response unsigned scripts), `IsolateDevice`/`ReleaseFromIsolation`
  paired with `lookup kind=leftouter`. Sentinel: `AzureActivity OperationNameValue =~ "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE"`
  joined to `SentinelHealth`. A detection-as-code pipeline should diff these against the repo.
- Rule inventory snapshot from `CloudAppEvents.RawEventData` (`RuleName, RuleId, Query, AlertSeverity,
  MitreTechniques, RuleFrequency, IsEnabled`) requires each rule to have been edited once — add a
  `// inventory` comment to force an `EditCustomDetection` event.
- Prefix custom rule names (`[ORG]`) so precision / false-discovery-rate reporting from
  `SecurityIncident` classifications can separate custom from built-in rules; a "days since this
  rule last fired" tile catches rules that silently stopped.

## Detection-as-Code Hooks

- Manage rules via Microsoft Graph Security API: `POST/PATCH /security/rules/detectionRules`.
- Static lints worth automating in CI (the portal only tells you at save time):
  - required columns present in the final `project`/`summarize` output;
  - frequency/lookback pair is one of the valid combinations;
  - if `frequency: continuous` → single table, no join/union/externaldata, no comments;
  - entity column names are real identifier columns (`AccountObjectId`, `AccountSid`,
    `AccountUpn`, `DeviceId`, `RecipientEmailAddress`, ...), not display names.
- Graph API schema has churned recently — pin API version in the pipeline and treat
  upgrades as reviewed changes. (Confidence: medium on schema stability.)

## Rule Design Checklist

- [ ] Required columns present after final operator
- [ ] No self-inflicted Timestamp filter fighting the lookback pre-filter
- [ ] Frequency/lookback pair valid; NRT restrictions checked if continuous
- [ ] Expected alert volume «« 150/run; noise burst from first-run 30 d scan considered
- [ ] Aggregated to investigation entity; impacted assets ≤1 column per entity type
- [ ] ingestion-delay behavior considered (late events will fire)
- [ ] Resource indicator Low/Medium (see kql-performance.md)
- [ ] `arg_min` vs `arg_max` chosen deliberately (first event of a flow vs latest)
- [ ] Tables without `Timestamp`/`ReportId` bridged via `DeviceInfo`
- [ ] Dedup key documented next to the projection
- [ ] XDR-only functions (`FileProfile`, `SeenBy`) on the unit-test skip-list
- [ ] Response actions: precision measured and stated, kill switch exists
