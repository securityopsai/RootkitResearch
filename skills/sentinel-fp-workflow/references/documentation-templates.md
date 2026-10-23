# Documentation Templates

## Detection Specification (one per rule; lives next to the query)

Derived from the most complete public write-up format (FalconForce "Falcon Friday", 13 sections,
every rule) plus fields other high-quality repos add. Sections are mandatory. Write "None expected."
only after assessing; where evidence is missing write "Not yet assessed" and the specific gap. Never
substitute "None expected" for unknown coverage.

```markdown
# <Rule ID> — <Title>

## Metadata
| Field | Value |
|---|---|
| Platform(s) | Defender XDR custom detection / Sentinel scheduled / Sentinel NRT |
| Severity | High / Medium / Low (how derived: fixed or `alertSeverityColumnName`) |
| MITRE | T1234.001 — <behaviour the predicate asserts, not the data source> |
| Permission required to execute the technique | User / Local admin / Domain admin |
| Frequency / lookback (+ ingestion wait) | 1h / 4h (XDR) · PT1H / P14D, query_wait 15m (Sentinel) |
| Status | Tested in lab / Derived from report (untested) / Production |

## Utilized data sources
| Product | Table | ActionType / EventID | ATT&CK data source · component | Prerequisite |
|---|---|---|---|---|
| MDE | DeviceEvents | OpenProcessApiCall | Process · Process Access | — |
| Windows | SecurityEvent | 5136 | AD Object · Modification | Audit policy + SACL on <object> |
Sampled / throttled telemetry: <yes: which — e.g. DeviceImageLoadEvents, NetworkSignatureInspected>
Licence / sensor / policy prerequisites: <MDI sensor on DCs, WDAC audit policy, O365 connector>
Query-side functions that limit portability: <FileProfile (XDR only), _GetWatchlist (Sentinel only)>

## Description of the attack
<what the adversary does and why; link the report; one query per "detection opportunity">

## Detection description
<what the query asserts, keyed on which columns; which `where` is the precision knob>
Precision / coverage statement (two sentences): "When this fires it is <≈100 % / likely / low
confidence> a TP because <…>." / "It will miss <…> because <sampling / evasion / exclusion>."

## Example (true-positive sample)
<the defanged command line / event from the report or lab — this IS the tp.json fixture>

## Considerations
<deployment prerequisites; FP/FN dials ("drop the 30-day DLL-age filter if the threat model
includes sophisticated actors: more FPs, fewer FNs"); why block-list vs allow-list; baseline poisoning>

## False positives
<named software / process / account classes; which are BTP vs FP; how each is excluded (watchlist key)>

## Detection blind spots (written from the attacker's side)
- Evasion: <parent-PID spoofing / slow-and-low below the floor / renamed binary ...>
- Telemetry: <sampled image loads / throttled network logging / redacted svchost args>
- Exclusion-induced: <"self-updates of msDS-KeyCredentialLink are excluded, so NTLM-relay abuse of it will not fire">
- Timing: <download and execution further apart than the window>
- None expected.  ← write this literally when applicable

## Suggested response actions
<what to pivot on and why, tied to the logic: "the injecting (untrusted) binary is the interesting one">

## Tunables
| `let` | Meaning | FP it trades against | Default |
|---|---|---|---|
| `GlobalPrevalenceThreshold` | files seen on more devices worldwide are treated as benign | rare in-house tools | 250 |

## Dedup / grouping
<Sentinel: grouping + suppression settings · XDR: DedupFields = [DeviceId, SHA1] — re-validate on projection change>

## Version history
| Version | Date | Impact | Change |
|---|---|---|---|
| 1.1 | 2026-10-01 | minor | Added ActionType == "ProcessCreated" filter (new MDE ActionTypes) |
| 1.0 | 2026-09-01 | major | Initial |
Superseded by: <rule id, when retired — keep this file as a pointer, never delete>
```

## Hunting Query Header (inside the query)

```kql
// DETECTION STRATEGY: ...   // THE MECHANIC: ...   // THE RESILIENCE: ...
// DATA: table / ActionType — retention assumed Nd — sampled: yes/no
// TP LIKELIHOOD WHEN IT FIRES: ...   COVERAGE CAVEAT: ...
// STEP n: ...   // ANALYST ACTION: ... (which `where` to drop to widen; FP rate label: High/Med/Low)
```
See `hunting-patterns.md` §2. Hunt YAML carries no `severity`/scheduling fields.

## Threat-report hunt pack page

```markdown
# <Report title> — <actor / campaign> (<date>)
References: <primary report> · <trigger (tweet/advisory)> · <this page's announcement>
Products needed: MDE (3 queries), MDO (1), Entra (2)
| # | Report step / "detection opportunity" (quoted) | Tier (IOC / artefact / behaviour) | Table · ActionType | Query | Noise |
|---|---|---|---|---|---|
MITRE table (one technique per predicate group)
Example scripts (defanged) — one per behaviour query → TP fixtures
```

## Benign-true-positive taxonomy (seed for FP worksheets)

Known BTP generators observed across estates — check before tuning a rule from scratch: MDI sensor
(`Microsoft.Tri.Sensor.exe`) and MDE device discovery (`sensendr.exe`) on SMB/RDP/LDAP; domain
controllers on LDAP/SMB fan-out; Microsoft Authentication Broker on device-code flows; browser and
Office updates on new user agents / rare hashes; iCloud Private Relay, VPN egress and mobile carriers on
new-IP/new-country logic; calendar items on hard-delete; inbound SMTP (port 25) and internet scanners on
TI-IP matches; Linux ISOs on rare-ISO; backup software on NTDS writes; OneDrive updater on AppData
scheduled tasks; Visual Studio/MSBuild on remote threads; `Enable-PSRemoting` during onboarding on
PsExec; `runas /netonly`; locale-specific `Shortcut.lnk`/`Raccourci.lnk`; Intune Management Extension
binaries in "unauthorised RMM" lists; Azure CLI on FOCI token logic; MDI service accounts on
"service account on new device"; Jira / Amazon SES / Adobe Sign on sender-domain spoof checks;
LogMeIn Rescue dropping `.bat` in `%LocalAppData%`.

---

## Detection Change Record

Use for any analytics rule modification.

```markdown
## Detection Change Record

**Rule Name:** [Analytics rule name]
**Rule ID:** [GUID from Sentinel]
**Change Date:** [YYYY-MM-DD]
**Changed By:** [Analyst name]
**Change Type:** [Tuning | Exclusion | Threshold | Disable | Enable]

### Reason for Change
[Why this change was necessary - link to incident/ticket if applicable]

### Previous Logic
```kql
[Original query or relevant snippet]
```

### New Logic
```kql
[Modified query or relevant snippet]
```

### Expected Impact
- FP Reduction: [Estimated %]
- Detection Coverage: [Any gaps introduced? Y/N - explain]
- Performance: [Query cost change if significant]

### Validation
- [ ] Tested with 7-day lookback
- [ ] Unit fixtures re-run (TP still fires after the exclusion; sample-based TP fixture intact)
- [ ] Reviewed for detection gaps — blind-spot section updated if the change adds an exclusion
- [ ] Peer reviewed by: [Name]
- [ ] Post-deployment review scheduled: [Date]

### Rollback Plan
[How to revert if issues arise]
```

---

## FP Analysis Worksheet

Use when triaging a batch of false positives.

```markdown
## FP Analysis: [Rule Name]

**Analysis Date:** [YYYY-MM-DD]
**Analyst:** [Name]
**Sample Size:** [N alerts reviewed]
**Time Period:** [Date range]

### Alert Distribution

| Classification | Count | % |
|---------------|-------|---|
| True Positive | | |
| Benign True Positive | | |
| False Positive | | |

### FP Root Causes

| Cause | Count | Example Entity |
|-------|-------|----------------|
| [e.g., Service account noise] | | |
| [e.g., Scheduled task] | | |
| [e.g., Security tool activity] | | |

### Recommended Actions

1. [Action with priority]
2. [Action with priority]

### Entities for Exclusion List

| Entity Type | Value | Justification |
|-------------|-------|---------------|
| User | | |
| Host | | |
| IP | | |
| Process | | |
```

---

## Client FP Report

Use for periodic client reporting.

```markdown
## False Positive Report: [Client Name]

**Reporting Period:** [Start] to [End]
**Prepared By:** [Analyst]
**Date:** [YYYY-MM-DD]

### Executive Summary

Total alerts processed: [N]
FP Rate: [X%] (Target: [Y%])
Trend: [↑/↓/→] vs. previous period

### Top FP-Generating Rules

| Rule | FP Count | FP Rate | Status |
|------|----------|---------|--------|
| | | | [Tuned/Pending/Monitoring] |

### Actions Taken This Period

| Date | Rule | Action | Impact |
|------|------|--------|--------|
| | | | |

### Pending Tuning Requests

| Rule | Issue | ETA | Blocker |
|------|-------|-----|---------|
| | | | |

### Recommendations

[Strategic recommendations for detection posture]
```

---

## Watchlist Entry Format

Standard format for FP exclusion watchlist entries.

| Column | Type | Description |
|--------|------|-------------|
| Entity | string | The value to exclude (username, hostname, IP, etc.) |
| EntityType | string | user / host / ip / process / hash |
| AddedDate | datetime | When added to list |
| AddedBy | string | Analyst who added |
| Justification | string | Why this is excluded |
| ExpiryDate | datetime | Exclusion valid only before this UTC timestamp; the generated patterns treat null/invalid/expired as inactive (fail closed) |
| RuleScope | string | Exact rule ID, or `*` as an explicit global scope |
| TicketRef | string | Related ticket/incident ID |
| Activity (optional) | string | Rule-scope key when one generic exclusion list serves many rules (`SecretRetrieval`, `CommonUserASN`); `-` = wildcard |
| Notes (optional) | string | Bracketed tags rules can filter on: `[App]`, `[HomeTenant]`, `[VPN]`, `[Success]` |

Public Sentinel repos ship watchlists **without** expiry/ticket columns; keep both — the schema above
is stricter on purpose. Consume with `tostring()` on every column and `column_ifexists()` for optional ones.
