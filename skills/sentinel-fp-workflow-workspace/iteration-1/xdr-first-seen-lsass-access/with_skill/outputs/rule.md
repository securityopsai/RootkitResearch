# CA-0001 — First-seen process accessing LSASS (fleet-wide)

Query: `detection.kql` (same folder). Status: **derived from expertise, untested in a tenant** — run the
pre-deployment checks in "Considerations" before enabling.

## Metadata

| Field | Value |
|---|---|
| Platform | Defender XDR custom detection (advanced hunting, `DeviceEvents`) |
| Severity | Medium (fixed). Raise to High for a tenant where LSASS-touching software is tightly controlled; the rule itself cannot vary severity per row. |
| Category / MITRE | Credential Access · **T1003.001 — OS Credential Dumping: LSASS Memory**. The predicate asserts "a process opened a handle to lsass.exe", which is the technique's defining action; "never seen fleet-wide" is the precision filter, not the behaviour. |
| Permission required to execute the technique | Local admin / SYSTEM (SeDebugPrivilege) on the endpoint; PPL bypass additionally needs a driver or an exploit |
| Frequency / lookback | **Every 1 h / 4 h** (fixed XDR pair). Mirrored in the query as `query_frequency = 1h`, `query_period = 4h`, `query_wait = 1h`. |
| Baseline | 30 d of `DeviceEvents`, ending `query_period + query_wait = 5 h` before now (guard gap) |
| Alert title | `[ORG] First-seen process accessed LSASS` |
| Impacted assets | Device → `DeviceId` · Account → `InitiatingProcessAccountSid` (one column per entity type) |
| Related evidence | Process → `InitiatingProcessId` + `InitiatingProcessCreationTime` + `InitiatingProcessCommandLine` · File → `InitiatingProcessSHA256` |
| Response actions | None wired. See "Suggested response actions". |
| Expected volume | Low single digits per day in a stable estate; bursts on rollout days are capped by `MaxDevicesPerNewKey` (≤ 25 rows per new key per run, ≪ 150/run cap) |

## Utilized data sources

| Product | Table | ActionType | ATT&CK data source · component | Prerequisite |
|---|---|---|---|---|
| MDE | `DeviceEvents` | `OpenProcessApiCall` (target `FileName =~ "lsass.exe"`, caller in `InitiatingProcess*`) | Process · Process Access | MDE sensor onboarded; Windows only |

- Sampled / throttled telemetry: the sensor records `OpenProcessApiCall` only for a sensitive-target set
  (lsass.exe is in it) and de-duplicates repeated opens from the same caller, so `EventCount` is
  indicative, not a true call count.
- Licence / sensor / policy prerequisites: MDE P2 (advanced hunting). No audit policy needed.
- Portability: XDR-native (`ingestion_time()`, `DeviceEvents`); no `FileProfile`/`SeenBy`, so the
  logic ports to Sentinel with `TimeGenerated` and a 90 d baseline if needed. `AdditionalFields` is a
  string in XDR (`parse_json`), dynamic in Sentinel.

## Description of the attack

Credential theft from LSASS memory is the standard post-compromise step for lateral movement and
domain escalation. Tooling varies (Mimikatz `sekurlsa::logonpasswords`, ProcDump `-ma lsass.exe`,
`rundll32 comsvcs.dll MiniDump`, Task Manager "Create dump file", nanodump, Dumpert, custom loaders
with direct syscalls, PPL-bypass drivers), but every user-mode variant must first obtain a handle to
`lsass.exe`, which the MDE sensor records as `OpenProcessApiCall`. Signature-based rules enumerate
tool names and are evaded by renaming; this rule inverts that and treats the **set of images that
legitimately touch LSASS in this fleet** as the known population and anything outside it as the
finding.

## Detection description

1. **Baseline (`Known`)**: every distinct `ProcessKey` that opened `lsass.exe` in the last 30 d,
   **ending 5 h ago** so an event inside the current 4 h lookback (plus 1 h ingestion margin) cannot
   whitelist itself. `ProcessKey` = lower-cased `InitiatingProcessFolderPath` with per-user profile
   directories, version directories, GUIDs and temp directories normalised, plus `|<PE CompanyName>`
   when `IncludeCompanyInKey` is true. Baseline grain equals join grain.
2. **Recent**: `OpenProcessApiCall` on `lsass.exe` scoped **only** by `ingestion_time() > ago(4h)` —
   no `Timestamp` filter, so late-arriving events still fire. Optional `RequireVmRead` mask filter
   (off by default, fails open).
3. **First-seen**: `join kind=leftanti Known on ProcessKey`.
4. **Collapse and guard**: one row per `(DeviceId, ProcessKey)` with `arg_min(Timestamp, ReportId, …)`
   so the alert points at the **first** access; fleet-wide `FleetDeviceCount` per key with the
   population filter `<= MaxDevicesPerNewKey`; `BaselineKeyCount >= MinBaselineKeys` sanity floor.

Precision knob: `MaxDevicesPerNewKey` (rollouts) and `RequireVmRead` (probes). Coverage knob:
`BaselineDays` and the two environment lists.

**Precision / coverage statement.** When this fires it is *likely but not certain* a true positive:
the caller is an image no device in the fleet has used against LSASS in 30 days, which is exactly how
a dumper looks, but new security/backup/inventory software and admin troubleshooting tools look the
same (BTP, see below). It will **miss** any dumper whose image path and CompanyName already appear in
the 30 d baseline — LOLBins that touched LSASS benignly once (taskmgr.exe, rundll32.exe, werfault.exe,
powershell.exe), tools used before the rule was deployed, and kernel-mode or handle-duplication
techniques that never call `OpenProcess` on LSASS.

## Example (true-positive sample)

Defanged lab sample for the `tp` fixture — a ProcDump copy under a fresh directory, never in baseline:

```
DeviceEvents row
  ActionType                                  OpenProcessApiCall
  FileName / FolderPath                        lsass.exe / c:\windows\system32\lsass.exe
  InitiatingProcessFileName                    pd64.exe
  InitiatingProcessFolderPath                  c:\users\jdoe\downloads\pd64.exe
  InitiatingProcessCommandLine                 pd64.exe -accepteula -ma lsass.exe c:\users\jdoe\downloads\l.dmp
  InitiatingProcessVersionInfoCompanyName      Sysinternals - www.sysinternals.com
  AdditionalFields                             {"DesiredAccess":2097151}   (0x1FFFFF, PROCESS_ALL_ACCESS)
Expected ProcessKey: c:\users\<user>\downloads\pd64.exe|sysinternals - www.sysinternals.com
```

Second TP variant worth keeping as a fixture: `mimikatz.exe` renamed to `svchost.exe` in
`c:\perflogs\` — the key is path-based, so the rename does not matter.

## Considerations (deployment)

- **Pre-deployment checks (no tenant access was available when this was written):**
  1. Confirm `InitiatingProcessFolderPath` includes the file name in your tenant (it does in MDE; the
     key assumes it).
  2. Measure the baseline: the query below must return comfortably more than `MinBaselineKeys`
     (expect ~30–200 keys). If it returns near zero, `OpenProcessApiCall` is not flowing and the
     sanity floor will (correctly) keep the rule silent — investigate the sensor, do not lower the floor.
  3. Run the full query over a 7-day window with `query_period = 7d` temporarily and review every
     "new" key: that review list is your BTP seed, and the volume must be ≪ 150.
  4. Confirm the `AdditionalFields.DesiredAccess` shape (decimal vs hex string) before enabling
     `RequireVmRead`; `tolong()` handles both, but check that it is not null everywhere.
- **First run**: XDR scans 30 d on the first run; the explicit `ingestion_time() > ago(query_period)`
  filter confines the recent side to 4 h anyway, so no deploy-day burst is expected.
- **Re-alert behaviour**: a new process that keeps touching LSASS re-fires on each run until its first
  event ages past the 5 h guard gap; runs inside the 4 h overlap are platform-deduplicated
  (`DedupFields`), so expect at most ~2 alerts per device per new key.
- **Baseline poisoning**: the baseline is self-learning. After the first alert, the attacker's image
  becomes "known" after 5 h and repeat use (or use from a second compromised host days later) is
  silent. Closing an alert as TP must be followed by containment of the image, not just the host.
  For a reviewed rather than learned baseline, persist `Known` into a watchlist / custom table and
  replace STEP 1 with a lookup (the rule becomes a cheap `!in`).
- **Mass deployment**: the population filter deliberately drops a key that appears on > 25 devices in
  one 4 h window. Pair with the built-in MDE "LSASS credential dumping" alerts, which have no such
  filter, or set `MaxDevicesPerNewKey` very high in a small fleet.
- **Tenant age / retention**: with less than 30 d of data every key is new; `MinBaselineKeys` guards
  the first weeks, but the rule reaches full precision only after 30 d of telemetry.

## False positives (BTP classes)

| Class | Example | Classification | Handling |
|---|---|---|---|
| New or updated security software | AV/EDR pilot engine, vulnerability scanner agent, MDI sensor update moving to a new version directory the normaliser did not catch | BTP | Close as BTP; baseline learns it after 5 h. Extend `NormalisePath` if the path shape recurs. |
| Backup / inventory agents | New backup agent reading process memory, software-inventory tools opening every process with `QUERY_LIMITED_INFORMATION` | BTP | `RequireVmRead = true` removes the handle-only probes; otherwise BTP once. |
| Admin troubleshooting | Process Explorer, Process Hacker/System Informer, WinDbg, perfmon on a server | BTP (verify the account and ticket) | Close as BTP; do not exclude — these are also attacker tools. |
| Staged software rollout | Key appears on 5–25 devices in one run | BTP | Already capped per key; lower `MaxDevicesPerNewKey` if rollouts are always wide. |
| Vendor metadata change | Same binary, new `CompanyName` string after an acquisition | BTP | One alert per vendor change; set `IncludeCompanyInKey = false` if this recurs. |
| Unnormalised path churn | Installers that use a random or dated directory name outside `temp`/`users`/version patterns | FP (logic) | Fix in `NormalisePath`, not with an exclusion. |

Exclusions go in `ExcludedProcessKeys` / `TrustedCompanyNames` inside the fenced region, each with a
blind-spot line below. Default is empty on purpose: the baseline is the exclusion mechanism.

## Detection blind spots (written from the attacker's side)

- **Evasion — use an image already in the baseline**: dump via `taskmgr.exe` (right-click → Create
  dump file), `rundll32.exe comsvcs.dll MiniDump`, `werfault.exe`, `powershell.exe`/`msbuild.exe`
  with in-memory dumpers, or any admin tool that has touched LSASS in the last 30 d. Cover with
  separate rules keyed on command line / target file write (`*.dmp` creation by these images).
- **Evasion — no `OpenProcess` on LSASS at all**: handle duplication from a process that already holds
  an LSASS handle (`DuplicateHandle` / `NtDuplicateObject`), inheriting a handle, reading via a kernel
  driver or a rootkit (BYOVD, PPL-kill drivers), dumping a hibernation file / VM snapshot / crash dump,
  `MiniDumpWriteDump` from inside LSASS via an injected SSP or DLL (SSP registration is a different
  detection), or offline SAM/NTDS extraction.
- **Evasion — timing / slow and low**: a tool first run during a period when the rule was disabled,
  or before deployment, is baselined and silent for 30 d. Wait-out is 30 d.
- **Evasion — mass deployment**: more than `MaxDevicesPerNewKey` devices in one window is treated as a
  rollout and suppressed.
- **Evasion — path squatting**: overwriting a baselined image path with a dumper keeps the key only if
  the PE CompanyName also matches (`IncludeCompanyInKey = true`); with it false, the path alone suffices.
- **Telemetry**: the sensor records `OpenProcessApiCall` for a sensitive-target set only and
  de-duplicates repeated opens; non-Windows and unonboarded devices are invisible; events older than
  the 5 h guard gap that arrive late (offline device syncing) land in both baseline and recent and
  are self-suppressed.
- **Exclusion-induced**: none by default. Every entry later added to `ExcludedProcessKeys` or
  `TrustedCompanyNames` must get a line here ("excluding X means a dumper masquerading as X will not fire").
- **Self-learning**: after the first alert the attacker's image is baselined after 5 h; repeat or
  second-host use is silent (see Considerations).

## Suggested response actions

The interesting entity is the **initiating image**, not the device: pivot on `InitiatingProcessSHA256`
across `DeviceProcessEvents` / `DeviceFileEvents` (where did it come from, which parent spawned it,
did it write a `*.dmp`), on `InitiatingProcessAccountSid` for other activity in the same hour, and on
`DeviceNetworkEvents` for the exfil of any dump file. If the key is a known admin tool, check the
account and a change ticket before closing as BTP. Do **not** wire isolate-device until a 30-day
measured precision ≥ 90 % exists; a kill switch (disable rule) is the only automation today.

## Tunables

| `let` | Meaning | FP it trades against | Default |
|---|---|---|---|
| `query_frequency` / `query_period` / `query_wait` | Rule contract: 1 h frequency, 4 h lookback, 1 h ingestion margin | n/a (must match the portal setting) | 1h / 4h / 1h |
| `BaselineDays` | How far back "ever seen" reaches | Shorter → more keys look new | 30d (retention cap) |
| `GuardGap` | Baseline end offset so the current window cannot self-whitelist | Larger → longer re-alert tail on persistent new processes | `query_period + query_wait` = 5h |
| `MinBaselineKeys` | Sanity floor on baseline size; below it the rule emits nothing | Too high → rule silent in a small fleet; too low → burst on a young tenant | 20 |
| `MaxDevicesPerNewKey` | Population filter; more devices than this per new key in one run = rollout | Lower → more mass-deployed dumpers missed; higher → rollout-day bursts | 25 |
| `IncludeCompanyInKey` | Add PE CompanyName to the key | true → alerts on vendor metadata changes; false → path-squatting blind spot | true |
| `RequireVmRead` | Only alert when DesiredAccess includes PROCESS_VM_READ (0x10); fails open on unparsable mask | true → handle-only reconnaissance missed; false → inventory-agent probes alert | false |
| `ExcludedProcessKeys` | Exact normalised keys never alerted | Each entry is a masquerade blind spot | `[]` |
| `TrustedCompanyNames` | Callers trusted by PE CompanyName | Attacker-controllable field; a dumper claiming the name is missed | `[]` |
| `NormalisePath` | Regexes collapsing user, version, GUID and temp directories | Too little → churn FPs; too much → distinct tools collapse into one key | 4 patterns |

## Dedup / grouping

XDR `DedupFields = [DeviceId, ProcessKey]`. The platform collapses identical entity + detail values
within a run and across the 4 h / 1 h overlap. Re-validate the key whenever the final `summarize by`
or `project-reorder` changes. Impacted-asset columns: `DeviceId` (Device), `InitiatingProcessAccountSid`
(Account) — one column per entity type.

## Unit-test plan (`scripts/kql_test_harness.py`, pinned `now()`)

| Fixture | Content | Expected |
|---|---|---|
| `tp` | Baseline rows for `c:\windows\system32\csrss.exe` etc. (Timestamp −10 d) + the ProcDump sample above (Timestamp −30 min, ingestion now) | 1 row, `InitiatingProcessFileName == "pd64.exe"`, `FleetDeviceCount == 1` |
| `benign_lookalike` | `MsMpEng.exe` from `c:\programdata\microsoft\windows defender\platform\4.18.2510.3-0\` in baseline, same image from `…\platform\4.18.2511.1-0\` recent | 0 rows (version dir normalised to `<ver>`) |
| `boundary_population` | New key on 25 vs 26 devices | 25 → 25 rows; 26 → 0 rows |
| `boundary_baseline_floor` | 19 vs 20 distinct baseline keys + one new key | 19 → 0 rows; 20 → 1 row |
| `boundary_guard_gap` | New key with Timestamp −4 h 59 m vs −5 h 01 m, both ingested now | −4h59m → fires; −5h01m → suppressed (documented) |
| `empty` | No rows | 0 rows, no error |

Lint: `python3 -I scripts/kql_lint.py detection.kql --platform xdr --strict` — clean at v1.0.

Baseline-size check to run in advanced hunting before enabling (should be well above `MinBaselineKeys`):

```kql
DeviceEvents
| where Timestamp between (ago(30d) .. ago(5h))
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| distinct InitiatingProcessFolderPath, InitiatingProcessVersionInfoCompanyName
| count
```

## Version history

| Version | Date | Impact | Change |
|---|---|---|---|
| 1.0 | 2026-10-22 | major | Initial. Written without tenant access; pre-deployment checks above are mandatory before enabling. |

Superseded by: —
