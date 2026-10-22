# Defender XDR Custom Detections — Platform Contract

Fixed platform constraints for custom detection rules built on advanced hunting.
Numbers verified against Microsoft Learn 2026-07. These are hard limits, not tuning
preferences — violating them fails silently or at save time, never loudly in CI unless
you lint for them (see detection-as-code.md).

## Required Columns

Every custom detection query MUST return:

| Table type | Required |
|-----------|----------|
| Device tables (MDE) | `Timestamp`, `ReportId`, `DeviceId`, `DeviceName` |
| All other XDR tables | `Timestamp`, `ReportId` |
| Email actions | additionally `NetworkMessageId` + `RecipientEmailAddress` |

After aggregation, recover them:

```kql
DeviceEvents
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 5
```

**Do NOT filter on `Timestamp`/`TimeGenerated` yourself** — the service pre-filters to
the rule's lookback window. Add a Timestamp filter only to target a narrower subset
inside the lookback.

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
platform dedup do the noise reduction — do not emit per-event rows and hope.

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
side of that line it lives on, and record the decision in the rule's YAML.

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
