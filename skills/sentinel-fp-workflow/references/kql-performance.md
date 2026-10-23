# KQL Performance & Quality Reference

Applies to Sentinel analytics rules, Defender XDR advanced hunting / custom detections,
and ad-hoc hunts. Source: Microsoft advanced hunting best practices (verified 2026-07) plus a review of ~5,000 community and
official queries (2026-10) — counts quoted below come from that review. Operator semantics that bite
are in `kql-gotchas.md`.

## String Matching

| Do | Instead of | Why |
|----|-----------|-----|
| `has` (whole-term match) | `contains` (substring) | `has` uses the term index; `contains` scans. Choose the semantics first: `"KustoExplorerQueryRun" has "Explorer"` is false, `contains` is true |
| `has_cs`, `==` | `has`, `=~` | Case-sensitive operators skip case folding — cheaper and more specific |
| `in` / `has_any` with a list | chained `or` clauses | Single indexed pass |
| terms of 3+ chars (4+ to be safe) | 1–2 char terms | The Kusto term index holds terms of 3+ characters (`datatypes-string-operators`); shorter terms scan. The Defender advanced-hunting best-practices page still says to avoid terms of 3 or fewer — prefer a longer anchor when one exists |

- **`in` / `in~` for exact identifiers** (`DeviceId`, `AccountSid`, `FileName`, hashes, IPs); `has_any`
  is for terms inside free text. `has_any` on an identifier list tokenises both sides and can match
  partial tokens. `in` is case-sensitive — `in~` or `tolower()` both sides for file names and domains.
- **`FileName`**: MDE preserves on-disk casing and installers/attackers vary it — `=~` / `in~`,
  never `==`. Use `==` only on producer-controlled enums (`ActionType`, `ResultType`).

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

Same `hint.shufflekey` applies to `summarize ... by <high-cardinality col>`; `hint.strategy=shuffle`
on the big `summarize` of beacon candidates and on TI joins.

### Join alternatives and pre-filters

- **`lookup kind=leftouter/inner`** for small dimension tables (expected-parent lists, renamed-binary
  tables, signer lookups, watchlists) — cheaper than `join` and keeps the left side intact.
- **Semi-join pre-filter before the real join**: `| where SHA1 in ((Candidates | project SHA1))`
  then `lookup`/`join` — narrows the big table on the indexed column first. Some `where` clauses
  that look redundant next to a join exist for this reason; comment them.
- **Composite keys**: build `strcat(DeviceId, "|", ProcessId, "|", tostring(CreationTime))` when
  the join needs process identity and `ProcessUniqueId` is absent.
- Reality check: the most frequent defect in both official and community content is a **bare
  `join`** (≈130 files in Azure-Sentinel, ≈100 across community sets), clustered exactly where
  `innerunique` is wrong (email tables on `NetworkMessageId`, hash → network, CVE → KB).
  Make `kind=` a hard CI error, not a lint warning.

## Regex vs. Parsers

Avoid `matches regex` and `extract()` unless nothing else fits. Purpose-built functions
are faster and less brittle:

| Input | Use |
|-------|-----|
| Command lines | `parse_command_line()` |
| File paths | `parse_path()` |
| Version strings | `parse_version()` |
| IPv4 / IPv6 | `parse_ipv4()`, `ipv4_is_in_range()`, `ipv4_compare()` / `parse_ipv6()`, `ipv6_compare()` |
| JSON columns | `parse_json()` once into a variable, then index into it — never parse the same column twice (one official rule parses the same blob five times) |
| File extension | `parse_path(FileName).Extension` or `endswith`, not `extract(@'.*\.(.*)', 1, FileName)` |
| User agents | `parse_user_agent(UserAgent, dynamic(["browser","os","device"]))` → `BrowserFamily !in (common)` surfaces `Go-http-client`, `Java`, `python-requests` |
| URLs | `parse_url(RemoteUrl).Host` after an indexed `has_any` pre-filter |
| GeoIP / CIDR | `geo_info_from_ip_address()`, `ipv4_is_private()`, `ipv4_is_in_any_range()`, `evaluate ipv4_lookup(Ranges, IP, cidr, return_unmatched=true)` — never an equi-join IP == CIDR |
| Parameter bags (`Parameters`, `modifiedProperties`, `AdditionalDetails`) | `mv-apply p = todynamic(Parameters) on (where p.Name == "X" \| extend V = tostring(p.Value))` — never positional `[1].Value` |
| Dynamic → columns | `evaluate bag_unpack(X)` with an explicit typed schema `: (A:string, B:long)`; `column_ifexists()` afterwards |
| String similarity | `jaccard_index(unicode_codepoints_from_string(a), unicode_codepoints_from_string(b))` for typosquats |

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
   PID + creation time — PIDs recycle (composite `DeviceId|PID|CreationTime` is the fallback).
5. From a report sample keep only the **invariant tokens** (2–4 per technique). A `has_all` of
   the whole sample (`"/c","schtasks","/create","/sc","ONSTART","/tn","Sens Api",...`) or of lab
   paths (`C:\m.sys`) is an IOC in disguise. Sixteen full command strings in one `has_any`
   (`'vssadmin.exe delete shadows /all /quiet'`, …) is the canonical counter-example: argument
   reorder, omitted `.exe` or different quoting evades every entry.
6. Identify vendor tools by `ProcessVersionInfoCompanyName` / `ProductName` / `OriginalFileName`
   rather than file name; renamed binaries: `lookup` a `datatable(OriginalFileName, Expected:dynamic)`
   and `not(set_has_element(Expected, tolower(FileName)))`.
7. Obfuscation signal without regex: `strlen(ProcessCommandLine) - strlen(parse_command_line(...))`
   length delta (ArgFuscator); encoded PowerShell: `extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, cmd)`
   → `base64_decode_tostring` → `replace_string(x, "\u0000", "")` → `| where Decoded != ""`.

## summarize / project

- `summarize by` is for genuinely repetitive values (dedup/aggregation). For already
  ~unique rows, `project` — a pointless `summarize` forces a shuffle.
- After `summarize`, recover platform-required columns with
  `(Timestamp, ReportId) = arg_max(Timestamp, ReportId)`.
- `project` down before any expensive operator (`join`, `mv-expand`, serialization).
- **Cap set outputs**: `make_set(x, 100)`, `make_list(x, 25)`; use `array_length(set)` instead of
  a second `dcount`; replace huge sets with a sentinel
  (`iff(dcount_X > 5, strcat("Too many (", dcount_X, ")"), tostring(set_X))`); `take_any(col)` as a
  sample column next to `dcount`. Unbounded `make_set` is the second most frequent defect found (≈260 files).
- `summarize arg_max(Timestamp, *), Items = make_set(X, 50) by Entity` in one call keeps a
  representative raw row plus the context list.
- Aggregate by `DeviceId` (plus `DeviceName` for display), never by `DeviceName` alone.
- `project-reorder` as the **last** operator (who / where / what / how) — keeps evidence columns,
  puts analyst columns first. `project-away *1` after joins drops duplicated right-side columns.
- Normalise before grouping (`tolower(FileName)`, user/GUID/version placeholders in paths), or
  rarity counts fragment.

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

## materialize() and let hygiene

- `materialize()` only when the `let` is referenced **≥ 2×** (union branches, self-joins); on a
  single-reference `let` it is pure overhead. `| as hint.materialized=true _Events` for self-reference.
- `toscalar(T | summarize make_set(X))` to feed a list into a parameterised parser or `in ()`;
  `toscalar` needs exactly one row — `make_set`/`make_list` guarantee it, `arg_max` on empty does not.
- Over-filtering a huge table before a join can trip a memory limit as readily as under-filtering
  trips CPU; test both directions on the real table.
- One query per file in rule repos; a gallery file with three alternative queries sharing `let`
  names breaks when pasted whole.

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
- [ ] Tunables in `let` at top, each with a comment stating its meaning and the FP it trades against; IOC lists externalized
- [ ] `in`/`in~` for identifiers, `has_any` only for free text; `FileName` matched with `=~`/`in~`
- [ ] `make_set`/`make_list` capped; aggregated by `DeviceId`; `project-reorder` last
- [ ] No positional dynamic indexing; parameter bags read by name
- [ ] `materialize()` only on multi-reference lets; `lookup` for dimension tables
- [ ] No full-sample `has_all` / lab-path literals from a threat report
- [ ] Resource indicator Low/Medium
- [ ] Both platform variants (XDR / Sentinel) parsed — no `TimeGenerated` in an XDR block or `Timestamp` in a Sentinel block
