# Review: "Shadow copy deletion (ransomware pre-encryption)" — XDR custom detection, hourly

**Verdict:** do not deploy. The query will not save as a Defender XDR custom detection (wrong
column names, required output columns missing, int/string compare), and even if it parsed, its
logic would miss the real ransomware case and alert on SMB chatter instead. Corrected version in
`fixed.kql`. Numbered findings below; each has a one-line reason. Gate numbers refer to the
skill's Detection Authoring Quality Gates; checklist items refer to `xdr-custom-detections.md`
and `kql-performance.md`.

## A. Platform contract — rule cannot be saved / run as written (Gate 5)

1. **`TimeGenerated` is not an Advanced Hunting column** — XDR tables expose `Timestamp`; `TimeGenerated` only exists on the Sentinel-mirrored copy, so the query fails to parse in the XDR rule editor.
2. **Self-inflicted `| where TimeGenerated > ago(1h)`** — the service pre-filters to the rule's lookback (hourly ⇒ 4 h, evaluated on `ingestion_time()`); a 1 h event-time filter fights that and silently drops late-arriving events.
3. **Required columns are destroyed by the final `summarize`** — `Timestamp`, `ReportId` and `DeviceId` are not in the output (`Hosts`, `Count`, `DeviceName`, bin), so the portal rejects the rule; XDR needs `Timestamp`, `ReportId`, `DeviceId`, `DeviceName` after the last operator.
4. **Aggregates by `DeviceName` (display name) instead of `DeviceId`** — the impacted-asset entity must be an identifier column; display names are not unique and are not valid entity columns.
5. **`RemotePort == "445"` compares an `int` column to a string literal** — KQL raises a type-mismatch error (would have to be `RemotePort == 445`).
6. **`AdditionalFields` does not exist on `DeviceProcessEvents`** — it only resolves (post-join) to the network event's column; parent process is already a first-class column (`InitiatingProcessFileName` / `InitiatingProcessCommandLine`), and positional `[1].value` on a JSON object is undefined behaviour.
7. **`Parent` is computed and never used** — dead `extend` that runs `parse_json` per joined (fanned-out) row for nothing; transforms must come after filters and only when consumed.
8. **Join produces duplicate `Timestamp1`/`ReportId1`/`DeviceName1` columns** — ambiguous which side feeds the alert's time/report, and none of them survive to the output anyway.
9. **Frequency/lookback and impacted entity never stated** — an hourly rule pairs with a fixed 4 h lookback, first run scans 30 days (noise burst), and the design must name the one Device and one Account column; none of this is recorded.

## B. Detection logic — misses true positives, fires on the wrong thing (Gates 1, 2, 3)

10. **`or ProcessCommandLine has_any ("-e","-enc","del")` defeats the FileName anchor** — because it is OR'd, any process on any host with "del" or "-e" in its command line passes the first filter, so the rule is no longer FileName-anchored (command-line discipline rule 1).
11. **Those three terms are ≤3 characters, so they are not term-indexed** — forces a full command-line scan of `DeviceProcessEvents` over the whole lookback; also they target PowerShell encoded commands, which is unrelated to the stated shadow-copy intent (scope creep in a single rule).
12. **`has_any (Commands)` matches full, exact, ordered strings** — attackers reorder and pad arguments (`delete shadows /quiet /all`, `/for=C: /oldest`, `/nointeractive`), so coverage is brittle; the skill requires normalized, unordered, case-insensitive `contains` on independent terms.
13. **Two of three `Commands` entries carry the `.exe` suffix inside the command line** — `vssadmin delete shadows ...` and `wmic shadowcopy delete` are what actually gets logged, so `vssadmin.exe delete shadows /all /quiet` and `wmic.exe shadowcopy delete` only match when the binary is invoked by its full `.exe` name; in practice only the `wbadmin` entry can ever fire.
14. **Coverage gaps even where it does match** — no `vssadmin resize shadowstorage`, `wbadmin delete systemstatebackup`, or PowerShell `Win32_ShadowCopy` deletion (`Remove-WmiObject` / `Remove-CimInstance` / `.Delete()`), all standard pre-encryption variants.
15. **`join (DeviceNetworkEvents | where RemotePort == 445) on DeviceId` is an unbounded fan-out** — no time bound, no `project`, keyed on `DeviceId` only, so every SMB connection the device made in the lookback multiplies each process row; `Count` then measures SMB chatter, not shadow deletions.
16. **Join has no explicit `kind=`** — default flavour is `innerunique`, which dedups the left side by `DeviceId` and silently drops rows; the skill treats an unspecified join kind as a review blocker.
17. **The SMB correlation adds no fidelity and can suppress the true positive** — outbound 445 is normal on any domain-joined host (file shares, DCs, SYSVOL, printers), and an inner join drops a host that deleted its shadow copies but happened to make no SMB connection in the window.
18. **`| where Count > 3` is a magic number mid-query and the wrong semantics** — one `vssadmin delete shadows /all /quiet` IS the ransomware pattern; requiring 4+ (join-inflated) rows per host per hour misses the real case, and the threshold is not hoisted into a `let` (Gate 3).
19. **`make_set(DeviceName) by DeviceName` is always a one-element set** — pointless aggregate that adds a shuffle and no information.
20. **Chained `FileName == ... or FileName == ...` is case-sensitive and un-indexed as a list** — image casing varies (`VSSADMIN.EXE`), so use `FileName in~ (list)` for one indexed, case-insensitive pass.
21. **No benign-lookalike / exclusion handling** — backup agents (Veeam, Commvault, Veritas/Backup Exec, Windows Server Backup via scheduled `wbadmin`) legitimately prune shadow copies; with no hoisted exclusion list the rule is guaranteed BTP noise and the 30-day first run will burst.
22. **Alerting is per raw joined row, not per investigation entity** — Gate 2 requires `summarize arg_max(...) by DeviceId` so platform dedup (identical entity + details ⇒ one alert) does the noise reduction.

## C. Process gates not met (Gates 1, 6, 7)

23. **No intent statement or MITRE mapping** — should read: "attacker inhibits system recovery by deleting/shrinking Volume Shadow Copies or backup catalogs before encryption — TA0040 Impact / T1490 Inhibit System Recovery".
24. **No unit fixtures** — no true-positive, benign-lookalike (`vssadmin list shadows`, backup-agent prune), boundary or empty-input tests via `scripts/kql_test_harness.py`.
25. **No change record / version** — nothing per `documentation-templates.md`, no owner, no post-deploy review date.

## What `fixed.kql` changes

- Single-table `DeviceProcessEvents` detection, no join; FileName-anchored with `in~`, command line normalized (`replace_string` on quotes/commas) and matched with unordered, case-insensitive `contains` per technique; coverage extended to `resize shadowstorage`, `wbadmin delete systemstatebackup`, and PowerShell `Win32_ShadowCopy` deletion.
- No `Timestamp` filter (platform pre-filters to the 4 h lookback); tunables hoisted into `let`s (`ShadowTools`, `ExcludedInitiatingFolders`, `ExcludedAccounts`, `MinEvents = 1`).
- Exclusions are data (backup-vendor initiating-process folders, optional maintenance accounts) and deliberately start conservative; never exclude SYSTEM.
- `summarize arg_max(Timestamp, *), EventCount = count(), ... by DeviceId` then `project` — recovers `Timestamp`, `ReportId`, `DeviceId`, `DeviceName`, keeps `AccountSid`/`AccountUpn` for the Account entity (pick ONE as impacted asset in the rule UI) and process/command-line/SHA256 as related evidence.
- One alert per device per run; XDR dedup across the 4 h / 1 h overlap handles repeats.

## Deployment notes for the hourly rule

- Frequency: **Every 1 h** → lookback **4 h** (fixed pair). Expect a **30-day first-run burst**; run the query interactively over 7 days first and populate `ExcludedInitiatingFolders` from what you see before saving the rule.
- Impacted assets: Device = `DeviceId`; Account = `AccountSid` (or `AccountUpn`) — one column per entity type. Process (`ProcessCommandLine`, `SHA256`, `FileName`) as related evidence.
- Resource indicator must show Low/Medium after an interactive run; alert volume must stay ≪ 150/run.
- Known residual gaps (document, do not widen this rule): encoded/obfuscated PowerShell that hides `Win32_ShadowCopy`, renamed copies of `vssadmin.exe`, and `bcdedit /set recoveryenabled no` — these belong in sibling rules.
- Unit fixtures (TP `vssadmin Delete Shadows /quiet /All` with mixed casing and quotes, benign lookalike `vssadmin list shadows`, Veeam-initiated `/for=C: /oldest` prune, empty input) were built for `scripts/kql_test_harness.py` during this review and the harness emitted the three datatable-shadowed test queries without error; they could not be executed (no tenant access). Keep them under `tests/fixtures/<rule>/` in the rule repo and re-run whenever an exclusion is added so the TP fixture still fires.
