# KQL Performance & Quality Reference

Applies to Sentinel analytics rules, Defender XDR advanced hunting / custom detections,
and ad-hoc hunts. Source: Microsoft advanced hunting best practices (verified 2026-07).

## String Matching

| Do | Instead of | Why |
|----|-----------|-----|
| `has` | `contains` | `has` uses the term index; `contains` is a substring scan |
| `has_cs`, `==` | `has`, `=~` | Case-sensitive operators skip case folding — cheaper and more specific |
| `in` / `has_any` with a list | chained `or` clauses | Single indexed pass |
| terms of 4+ chars | 3-char-or-shorter terms | Terms ≤3 characters are NOT indexed → full scan |

Exception — command lines and anything attacker-controlled: use case-INSENSITIVE
matching (`=~`, `in~`, `contains`) because casing is an obfuscation dimension. Pay the
cost there deliberately; be case-sensitive everywhere the producer controls casing
(ActionType values, table enums, file names from telemetry).

## Filter Order

Filter early, transform late. Every `extend`, `parse_json()`, `extractjson()`,
`substring()`, `toupper()` runs per surviving row — push all `where` clauses on raw
indexed columns above them.

```kql
DeviceEvents
| where Timestamp > ago(1d)                      // time first (unless platform pre-filters)
| where ActionType == "UsbDriveMount"            // indexed enum
| where DeviceName == "user-desktop.domain.com"  // indexed string
| extend DriveLetter = extractjson("$.DriveLetter", AdditionalFields)  // last
```

Filter on stored columns, not calculated ones, whenever an equivalent exists.

## Joins

- **Smaller table on the LEFT.**
- **Always write `kind=inner` explicitly.** The default flavor is `innerunique`, which
  deduplicates the left side by join key and silently DROPS rows — a classic source of
  missed detections. Only accept `innerunique` when you have decided dedup is correct.
- **Time-bound both sides**, even when the rule lookback already bounds one:
  `| join kind=inner (DeviceFileEvents | where Timestamp > ago(1h)) on SHA256`
- **`project` before the join** — carry only the join key and the columns you need.
- **Prefer time-window joins** for causally-related events:
  `| where (LogonTime - EmailReceivedTime) between (0min .. 30min)`

### Join hints

| Hint | When |
|------|------|
| `hint.shufflekey = <col>` | High-cardinality join/summarize key (AccountObjectId, SHA256, message IDs) |
| `hint.strategy = broadcast` | Left side ≤ ~100k rows, right side huge |

Same `hint.shufflekey` applies to `summarize ... by <high-cardinality col>`.

## Regex vs. Parsers

Avoid `matches regex` and `extract()` unless nothing else fits. Purpose-built functions
are faster and less brittle:

| Input | Use |
|-------|-----|
| Command lines | `parse_command_line()` |
| File paths | `parse_path()` |
| Version strings | `parse_version()` |
| IPv4 / IPv6 | `parse_ipv4()`, `ipv4_is_in_range()`, `ipv4_compare()` / `parse_ipv6()`, `ipv6_compare()` |
| JSON columns | `parse_json()` once into a variable, then index into it — never parse the same column twice |

## Command-Line Matching Discipline

1. Identify the process by `FileName in~ ("net.exe", "net1.exe")` — never by command-line substring.
2. Normalize before matching: strip quotes, collapse whitespace, replace commas.
   `| extend Canon = replace_string(ProcessCommandLine, '"', '')`
3. Match arguments with multiple independent `contains` clauses, case-insensitive —
   attackers reorder and pad arguments, so never match one exact ordered string.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d) and FileName in~ ("net.exe", "net1.exe")
| extend Canon = replace_string(ProcessCommandLine, '"', '')
| where Canon contains "stop" and Canon contains "MpsSvc"
```

4. Process identity: use `ProcessUniqueId` / `InitiatingProcessUniqueId` (Windows), not
   PID + creation time — PIDs recycle.

## summarize / project

- `summarize by` is for genuinely repetitive values (dedup/aggregation). For already
  ~unique rows, `project` — a pointless `summarize` forces a shuffle.
- After `summarize`, recover platform-required columns with
  `(Timestamp, ReportId) = arg_max(Timestamp, ReportId)`.
- `project` down before any expensive operator (`join`, `mv-expand`, serialization).

## search / union

- Never unscoped `search "..."` or `union *` in anything scheduled. Scope explicitly:
  `search in (EmailEvents, EmailAttachmentInfo) "..."` and name columns instead of `*`.

## External Data

Long IOC lists: `externaldata()` from a URI (CSV/TXT/JSON) instead of hundreds of inline
literals. Sentinel alternative: watchlists (`_GetWatchlist`). Not available in XDR
Continuous/NRT rules.

```kql
let abuse_sha256 = (externaldata(sha256_hash: string)
  [@"https://bazaar.abuse.ch/export/txt/sha256/recent/"] with (format="txt"))
  | where sha256_hash !startswith "#";
```

Treat external feeds as adversarial input: they are attacker-observable and sometimes
attacker-influenced. Never let feed content flow into anything executed or into
exclusion logic; joins/matches only.

## Resource Budget

- XDR shows Low/Medium/High resource usage per query after execution. **"High" in a
  scheduled rule is a review blocker** — optimize or redesign.
- Per-tenant CPU quotas exist but exact numbers are unpublished; assume contention with
  analysts' interactive hunting.
- Sanity-check result volume with `count` before shipping; bound exploratory queries
  with `take`/`limit` (but never leave a bare `take` in a production detection — it is
  nondeterministic).

## Review Checklist (copy into PR template)

- [ ] `has`/`has_cs` over `contains`; no ≤3-char primary filter terms
- [ ] All `where` on raw columns before any `extend`/parse
- [ ] Joins: explicit `kind=`, smaller side left, both sides time-bound, projected inputs
- [ ] No `matches regex`/`extract()` where a parser function exists
- [ ] Command-line logic: FileName-anchored, normalized, unordered contains, case-insensitive
- [ ] No unscoped `search`/`union`, no `select *`-style column sprawl
- [ ] Tunables in `let` at top; IOC lists externalized
- [ ] Resource indicator Low/Medium
