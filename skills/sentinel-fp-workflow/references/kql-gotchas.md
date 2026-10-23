# KQL Gotchas, Platform Deltas & Table Churn

Operator semantics and platform facts that produced real bugs in widely used community and
official content. Each line is a review item. Performance rules live in `kql-performance.md`.

## 1. Operators that bite

| Gotcha | What happens | Do instead |
|---|---|---|
| `join` with no `kind=` | `innerunique` dedups the left side by key — on `NetworkMessageId` (many URLs/attachments per mail), hash→network, CVE→KB it silently drops evidence. The single most frequent defect found (≈130 files in Azure-Sentinel, ≈100 in community sets). | Always `kind=inner/leftouter/leftanti/...`; comment when `innerunique` is deliberate ("one match per IOC") |
| `has_any (list)` on identifier columns (`DeviceId`, `AccountSid`, `FileName`) | Term-tokenises both sides; slower and matches partial tokens | `in` / `in~` for exact identifiers; `has_any` for terms inside free text |
| `has` / `has_any` terms of 1–2 chars (`"-e"`, `"cl"`, `"@"`); 3-char terms (`"sql"`) are indexed per Kusto docs but discouraged by the Defender best-practices page | No term index → scan; `has_all ("-password", "*")` — `"*"` is not a term, the predicate is empty | 4+ char terms where possible, or `FileName`-anchored logic |
| `contains` on enum columns (`ActionType contains "Inspected"`) | Substring scan on a low-cardinality column | `==` / `in` / `has` |
| `FileName == "net.exe"` | MDE preserves on-disk casing; installers and attackers vary it | `=~` / `in~` for file names; `==` only for producer-controlled enums |
| `in` is case-sensitive | `RemoteUrl in ("Mega.nz")` never matches `mega.nz` | `in~`, or `tolower()` both sides |
| Empty has three spellings | Entra data: `""`, `"[]"` (`RiskEventTypes`), `"none"` (`RiskLevelDuringSignIn` in Sentinel) vs truly empty in XDR | `isempty(x) or x in ("[]", "none")` |
| Positional dynamic indexing (`TargetResources[2]`, `Parameters[1].Value`, `AdditionalDetails[4]`) | Returns null silently when the producer reorders | `mv-apply p = todynamic(Parameters) on (where p.Name == "X" \| extend V = tostring(p.Value))`; `mv-apply ... make_bag(bag_pack(key, value))` then `["Key"]` |
| `tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)` looks redundant | `InitiatedBy.user` is sometimes a *string containing JSON* in AuditLogs; direct `.user.userPrincipalName` returns null then | Keep the defensive double-parse on AuditLogs/OfficeActivity dynamic columns; parse once into a variable |
| `mv-expand` on an empty array | Drops the row | `mv-expand X = iff(array_length(A) == 0, dynamic([""]), A)` |
| Type mismatch in `!in` / join (`UserId !in (set of UPNs)`, dynamic vs string) | Never matches → every row is "new" / "dormant" | Cast **both** sides with `tostring()`; `_GetWatchlist` columns are dynamic — `tostring()` them before joining |
| `where IsBillable = true`, `IsInternetFacing == "1"`, `EventID == "4688"`, `RegistryValueData == 1` | Single `=` is a syntax error; string-vs-bool/int relies on coercion or never matches | Typed literals: `== true`, `== 4688`, `== "1"` only for string columns |
| `prev()` / `next()` / `row_number()` after `order by Time` only | Compares rows of *different* entities (bogus impossible-travel distances, missed owner changes) | `order by Entity asc, Time asc` then `row_number(1, prev(Entity) != Entity)` |
| `bin()` for "N in 1 h" | Burst straddling a clock boundary splits into two sub-threshold bins | `bin_at(T, 1h, now())`, sliding window, or document |
| `between (x .. threshold)` / `< threshold` for event ordering | Matches negative deltas (reversed order); `datetime_diff("hour")` named "Minutes" | `(Later - Earlier) between (0min .. window)` |
| `summarize ... by DeviceName` | Hostname reuse collides; drops `DeviceId` the XDR contract needs | Aggregate by `DeviceId` (+ `DeviceName` for display) |
| Unbounded `make_set(x)` / `make_list(x)` | 1,048,576-element cap, huge alert payloads | `make_set(x, 100)`; `iff(dcount > 5, strcat("Too many (", dcount, ")"), tostring(set))` |
| `materialize()` on a single-reference `let` | Pure overhead | Only when referenced ≥ 2× (`union` branches, self-joins); `| as hint.materialized=true _Events` for self-reference |
| `matches regex` / `extract()` for extensions, process names | Brittle; `extract(@'.*\.(.*)', 1, FileName)`; `matches regex @'(?i)^(chrome\|msedge)\.exe$'` | `parse_path(FileName).Extension`, `endswith`, `in~` |
| `base64_decode_tostring()` on `-enc` payloads | Returns `""` on invalid input (filter it); payload is UTF-16LE → interleaved NULs | `| where Decoded != ""`, `replace_string(Decoded, "\u0000", "")` or `base64_decode_toarray` → `unicode_codepoints_to_string` |
| `search`, `union *`, `take`/`limit` in rules | Unscoped, column sprawl, nondeterministic | Hunt/IR only; `search in (T1, T2) Timestamp between (...)` with named columns |
| `union isfuzzy=true` | Hides a missing table **and** a misspelled one (silent zero-row branch) | Fine for portable functions; CI parse must treat fuzzy branches as hard references |
| `toscalar()` on an empty result | Returns null → downstream filters evaluate false | Guarantee a row: `union isfuzzy=true (T \| count), (print Count=0)` |
| `arg_max` on empty input | No row (not a null row) | Fixture `empty.json` in unit tests |
| `has_all` of 10+ tokens from a report sample | Order-independent in name only; an IOC in disguise | 2–4 invariant tokens, `FileName`-anchored |
| Exact-string operation names | `"Update application – Certificates and secrets management "` (en-dash, trailing space), `"Add service principal."` (trailing period), `"(bulk)"` | `has` / `has_all`, never `==` on Entra/CloudApp operation names |
| Fixed UTC offsets (`+ 5h`) | DST-wrong | `datetime_utc_to_local(T, "Area/City")` |
| Equi-join IP == CIDR | Zero rows, silently | `evaluate ipv4_lookup(Ranges, IP, cidr, return_unmatched=true)`, `ipv4_is_in_any_range()` |
| `and`/`or` chains without parentheses (Sigma conversions) | `A or B and C` binds as `A or (B and C)` | Parenthesise every mixed chain |
| `parse` vs `parse-where` | `parse` keeps non-matching rows with empty columns | `parse-where` when the match is the filter |
| `has_all (0, 50140)` on `make_set(ResultType)` | Works via term match on numeric codes; risky on free text | `set_has_element()` / `array_index_of() >= 0` for exact membership |
| Shadowed `let` names in one file / undefined variables / missing commas in `dynamic([...])` / smart quotes / `ago(1hr)` / UTF-16 BOM files | Will not parse | Offline parse gate in CI on **every** platform variant |

## 2. Platform deltas: Defender XDR vs Sentinel

"Replace `Timestamp` with `TimeGenerated`" is syntax, not semantics. The full delta:

| Dimension | Defender XDR (Advanced Hunting) | Sentinel (Log Analytics) |
|---|---|---|
| Time column | `Timestamp` | `TimeGenerated` (mirrored XDR tables also carry `Timestamp`; `TimeGenerated` is overwritten to `now()` if data lands > 48 h late) |
| Interactive retention / rule lookback | 30 d / fixed pairs (24h→30d, 12h→48h, 3h→12h, 1h→4h) | per table (often 90 d) / `queryPeriod` ≤ 14 d |
| Sign-in table | `AADSignInEventsBeta` (legacy) → `EntraIdSignInEvents`: `ErrorCode`, `Country`, `AadDeviceId`, `IsGuestUser == 1`, risk levels numeric (10/50/100), `EndpointCall == "Cmsi:Cmsi"` for device code, `LogonType == @'["interactiveUser"]'` | `SigninLogs` + `AADNonInteractiveUserSignInLogs` (`union isfuzzy=true`): `ResultType`, `Location`, `DeviceDetail.deviceId`, `UserType == "Guest"`, risk as strings (`"none"`), `AuthenticationProtocol == "deviceCode"`; `SessionId` absent in `SigninLogs`; `_dynamic`/`_string` column pairs differ between the two tables (`DeviceDetail_dynamic` vs `DeviceDetail_string`) |
| Enrichment functions | `invoke FileProfile()`, `invoke SeenBy()`, `DeviceFromIP()`, `AssignedIPAddresses()` | not available ("not supported in Sentinel") |
| `AdditionalFields` | string → `extractjson("$.x", AdditionalFields, typeof(int))` or `parse_json()` | dynamic → `dynamic_to_json()`/`tostring()` before `extractjson` |
| Functions | Sentinel-saved functions **not** supported in custom detections; NRT analytics rules cannot call workspace functions — inline at deploy | Workspace functions, ASIM parsers, `_GetWatchlist` |
| Sentinel-only sources | — | `SecurityIncident`, `SentinelHealth`, `AzureActivity`, `BehaviorAnalytics`, `Anomalies`, `IdentityInfo` (UEBA columns), summary-rule tables, watchlists |
| Custom-detection extras | `IPTags`, `UncommonForUser`, `ActorInfoString` on `CloudAppEvents`; `ExposureGraph*`; `DeviceTvm*` (no `Timestamp`/`ReportId`) | — |

**Dual-platform copies drift** (≈5 % of files in the largest community repo: `bin(TimeGenerated)`
inside an XDR block, `Timestamp` inside a Sentinel block, baselines of 30 d copied where 90 d is
available). Treat the second variant as a generated artefact: lint and parse **both**.

## 3. Telemetry facts that change detection logic

- **MDE samples/throttles**: `DeviceImageLoadEvents` (heavy sampling), `DeviceNetworkEvents`
  (throttled; `NetworkSignatureInspected` sampled). Write this into Blind Spots; expect false negatives.
- `DeviceProcessEvents` now carries ActionTypes beyond `ProcessCreated` — filter
  `ActionType == "ProcessCreated"` in process-creation rules or counts inflate.
- `DeviceNetworkEvents` `*AggregatedReport` ActionTypes (`ConnectionSuccessAggregatedReport`) carry
  `AdditionalFields.uniqueEventsAggregated`; Zeek inspection ActionTypes `HttpConnectionInspected`
  (`method`, `host`, `uri`, `user_agent`, `status_code`), `DnsQueryResponse` (`query`),
  `NetworkSignatureInspected` (`SignatureName`, `SignatureMatchedContent`, `SamplePacketContent`) have
  no process context — attribute via `(LocalIP, RemoteIP, LocalPort, bin 5m)` join.
- `*RemoteSessionDeviceName` / `*RemoteSessionIP` columns attribute process/file/registry events to
  the originating RDP client; `IdentityLogonEvents` equivalent is `AdditionalFields.["FROM.DEVICE"]`.
- `DeviceFileCertificateInfo` contains **only signed files**. `FileProfile`: lower-case hashes,
  1,000-row cap, `ProfileAvailability == "Error"`, null `GlobalPrevalence`, `SignatureState == "Unknown"`
  on some Microsoft-signed files.
- `svchost` command lines: the first argument after `-p` is redacted (`**`).
- `FolderPath` for `CreateRemoteThreadApiCall` lacks the file name (unlike other DeviceEvents).
- Domain controllers without MDI: `DeviceNetworkEvents | where LocalPort == 88 and LocalIPType == "FourToSixMapping" | distinct DeviceId`.
- `DeviceTvm*` tables have no `Timestamp`/`ReportId`: bridge device-keyed rows with
  `DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId` (carries `ReportId`) — not a random
  `DeviceProcessEvents` join. `OAuthAppInfo` and graph tables have no `DeviceId`, so this bridge does
  not apply; use their own identifiers and validate the alert's provenance.
- `AADManagedIdentitySignInLogs` lacks `SignInIpAddress`; `ADFSSignInLogs` lacks `SessionId`.
- AppLocker emits PE256, not SHA256.
- A WDAC **audit** policy can be deployed purely to generate DLL-load telemetry
  (`DeviceEvents | where ActionType startswith "AppControl"`) that sampled `DeviceImageLoadEvents`
  would drop — record the policy as a data-source prerequisite.
- `IdentityInfo` refreshes on a 14-day cycle; `arg_max(TimeGenerated, *) by AccountObjectId` over ≥ 14 d.
- `externaldata` cannot fetch some vendor feeds (Apple/Google CSVs); mirror them via CI.

## 4. Table and column churn (deprecation map — verify against current docs before use)

| Legacy | Current | Note |
|---|---|---|
| `AADSignInEventsBeta` | `EntraIdSignInEvents` | keep both files with cross-links during migration |
| `ThreatIntelligenceIndicator` (`Active`, `ExpirationDateTime`, `NetworkIP`, …) | `ThreatIntelIndicators` (STIX: `ObservableKey`, `ObservableValue`, `IsActive`, `ValidUntil`, `Pattern`, `Data`) | type parsed from `ObservableKey`; dedup `arg_max by Id` |
| `pack()` | `bag_pack()` | |
| `makeset()` / `makelist()` / `mvexpand` | `make_set()` / `make_list()` / `mv-expand` | |
| Entity identifier `FullName` (some entity types) | `Name` + `UPNSuffix` / `NTDomain`; `HostName` + `DnsDomain` | repo-wide sweep when identifiers churn |
| `*CustomEntity` / `timestamp` output columns, `Account_0_Name` auto-mapping | explicit `entityMappings` | 34 official hunts still rely on auto-mapping |
| `DeviceTvmSoftwareEvidenceBeta` | still Beta | |
| `DriverLoad` vs `DriverLoaded` ActionType | check your tenant's enum | one spelling is wrong for a given tenant |
| New tables worth knowing | `AgentsInfo` (AI agents), `NetworkAccessTraffic` (Global Secure Access), `DeviceTvmBrowserExtensions`, `ExposureGraphNodes/Edges`, `MicrosoftGraphActivityLogs`, `UrlClickEvents`, `EmailPostDeliveryEvents` | |

Know-your-data query: new `ActionType`/`OperationName` values vs a 180-day baseline (see
`hunting-patterns.md` §3.3) is the schema-change radar — run it monthly.
