# Documentation Templates

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
- [ ] Reviewed for detection gaps
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
| ExpiryDate | datetime | When to review (null = permanent) |
| RuleScope | string | Which rules this applies to (* = all) |
| TicketRef | string | Related ticket/incident ID |
