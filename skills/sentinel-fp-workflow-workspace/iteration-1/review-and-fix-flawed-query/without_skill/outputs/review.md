# Review: Shadow copy deletion (ransomware pre-encryption) — XDR custom detection

Source reviewed: `flawed.md` (Defender XDR custom detection, hourly). Each finding has a one-line reason; the corrected query is in `fixed.kql`.

## Blocking (query will not save or run as an XDR custom detection)

1. **`TimeGenerated` does not exist in Defender XDR advanced hunting** — `DeviceProcessEvents` uses `Timestamp`; `TimeGenerated` is the Sentinel/Log Analytics column name, so lines 7 and 12 fail to parse in XDR.
2. **`RemotePort == "445"` compares an int column to a string** — `RemotePort` is `int`, so the comparison is a type error (and even if coerced, it should be `== 445`).
3. **Output lacks the mandatory custom-detection columns** — the `summarize` drops `Timestamp`, `DeviceId` and `ReportId`; XDR refuses to save a custom detection whose result set does not return all three.
4. **`join ... on DeviceId` produces duplicate column names** — both tables carry `Timestamp`, `DeviceName`, `ReportId` etc.; the right side gets `*1` suffixes and the later `summarize` references become ambiguous/incorrect.

## Logic errors (false negatives: real ransomware is missed)

5. **Full-string command signatures are brittle** — `vssadmin.exe delete shadows /all /quiet` only matches if the operator typed `.exe`, used that exact flag order and included `/quiet`; real command lines are usually `vssadmin delete shadows /all /quiet`, `vssadmin delete shadows /for=C: /oldest`, `wmic shadowcopy delete` (no `.exe`), so most true positives never match.
6. **Coverage gaps for the same technique (T1490)** — no detection of `vssadmin resize shadowstorage`, `wbadmin delete systemstatebackup`, `bcdedit /set {default} recoveryenabled no` / `bootstatuspolicy ignoreallfailures`, `diskshadow`, or PowerShell/WMI `Win32_ShadowCopy ... Remove-WmiObject/Delete()`.
7. **`Count > 3` threshold suppresses the alert** — one shadow-copy deletion is already high-fidelity and most ransomware runs it exactly once per host, so requiring >3 in an hour misses the typical case.
8. **Inner join on SMB traffic drops hosts with no port-445 activity** — the `join` is an inner join, so a workstation that deletes shadow copies but has no `DeviceNetworkEvents` row on 445 in the window disappears from results.
9. **Default `join` kind is `innerunique`** — it de-duplicates the left side on `DeviceId` arbitrarily, silently discarding process events (and making `Count` depend on which row survived).
10. **Explicit `ago(1h)` window is wrong for a scheduled custom detection** — the platform scopes the lookback for the chosen frequency (hourly runs look back further than 1 h) and de-duplicates on `ReportId`; hard-coding 1 h creates gaps whenever a run is delayed and the `bin(..., 1h)` boundaries do not align with run windows.
11. **Case-sensitive `FileName ==`** — Windows process names vary in case (`VSSADMIN.EXE`, `WMIC.exe`); `==` is case-sensitive, so use `=~` / `in~`.
12. **Renamed/copied binaries bypass the filename check** — no use of `ProcessVersionInfoOriginalFileName`, so `copy vssadmin.exe v.exe` evades the rule.

## Noise / false positives

13. **`ProcessCommandLine has_any ("-e", "-enc", "del")` is unrelated and overly broad** — these are encoded-PowerShell/`del` tokens, not shadow-copy indicators; `has` tokenises so `"-e"` matches any command line containing the term `e`, pulling in huge volumes of unrelated rows before the next filter.
14. **Join with no time constraint fans out rows** — every port-445 connection from the device in the lookback multiplies each process event, inflating `Count` and making the threshold meaningless.
15. **No exclusion for legitimate backup agents** — Windows Server Backup, Veeam, Commvault, Acronis, Datto etc. routinely prune shadow copies via `vssadmin`/`wbadmin`; without a parent-process/folder allowlist every backup job alerts.

## Dead code / correctness

16. **`parse_json(AdditionalFields)[1].value` is wrong and unused** — `AdditionalFields` is a JSON object, not an array, so `[1]` returns null; the parent process is already in `InitiatingProcessFileName`/`InitiatingProcessCommandLine`; and `Parent` is discarded by the `summarize` anyway.
17. **`Hosts = make_set(DeviceName)` grouped `by DeviceName`** — a set of exactly one value per group; it carries no information.
18. **Grouping by `DeviceName` instead of `DeviceId`** — `DeviceName` is not unique/stable (re-imaged hosts, duplicate names across domains); `DeviceId` is the entity key XDR uses for alerts and response actions.
19. **The joined `DeviceNetworkEvents` data is never used** — nothing from the network side is projected or filtered on; it only adds cost, fan-out and false negatives.
20. **Aggregation destroys triage evidence** — the alert carries no command line, account, parent process, hash or path, so analysts cannot triage from the alert and impacted-entity mapping (device/user) is weakened.

## Hygiene / documentation

21. **No rule metadata** — no title, severity, MITRE technique (T1490 Inhibit System Recovery), description, tuning notes or impacted-entity mapping (DeviceId, AccountSid), all of which the custom-detection wizard needs.
22. **Redundant filters** — line 8's filename OR clause is subsumed by line 9's command check, so it only adds cost and confusion.
