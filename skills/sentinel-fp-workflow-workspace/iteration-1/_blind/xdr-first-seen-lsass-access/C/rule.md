# First-seen process opening lsass.exe (fleet-wide baseline)

| Field | Value |
|---|---|
| Platform | Microsoft Defender XDR custom detection (advanced hunting, `DeviceEvents`) |
| Rule ID | *assign GUID at creation; never regenerate* |
| Version | 1.0.0 |
| Frequency / lookback | Every 1 hour / 4 hours (fixed platform pair) |
| Severity | Medium (raise to High if `RequireMemoryAccess` stays true and volume proves low) |
| Category | Credential Access |
| MITRE ATT&CK | Tactic **TA0006 Credential Access**; Technique **T1003.001 OS Credential Dumping: LSASS Memory**. Secondary: T1055 Process Injection (handles with `PROCESS_VM_WRITE`/`PROCESS_CREATE_THREAD` into LSASS). |
| Query file | `detection.kql` (same directory) |
| Status | Draft, not yet validated against a tenant |

## 1. What it detects (intent)

One sentence: **a process image that has not opened `lsass.exe` with memory-access rights anywhere in the fleet during the last 30 days does so for the first time.**

Credential dumpers (Mimikatz, ProcDump, `comsvcs.dll MiniDump`, Dumpert, nanodump, custom loaders, renamed copies of all of the above) must obtain a handle to LSASS with at least `PROCESS_VM_READ`. Defender for Endpoint records every such handle open as `DeviceEvents` / `ActionType == "OpenProcessApiCall"` with the target in `FileName` and the accessor in the `InitiatingProcess*` columns. In a stable estate the set of images that legitimately open LSASS with read rights is small and repetitive (AV engines, EDR sensors, LSA plug-ins, some backup/VDI agents, Windows components). Fleet-wide novelty of the accessor is therefore a strong, signature-free signal, and it stays strong against renamed or re-compiled tooling because the trigger is "we have never seen this image do this", not "this image is on a list".

### How the query works

1. **Single scan** of `DeviceEvents` over the 30-day baseline, filtered on indexed columns (`ActionType`, `FileName`) before any parsing.
2. **Access-mask filter** on `AdditionalFields.DesiredAccess`: keep opens whose mask includes any of `CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE | DUP_HANDLE` (`0x7A`). Query-only handles (`0x1000`, `0x1400`) are dropped, which removes the bulk of benign enumeration noise (Task Manager, Process Explorer, inventory agents).
3. **Process key normalisation**: lower-case image path with the user-profile segment, version-number directories, GUIDs and `temp\<random>\` subfolders wildcarded, so an update from `app\1.2.3\x.exe` to `app\1.2.4\x.exe` is *not* "new".
4. **Novelty test**: per key, take the earliest *ingested* record in the baseline. If that is inside the current 4-hour lookback, the key is new to the fleet.
5. **Entity aggregation**: join the new keys back to the current-window events and emit **one row per (process key, device)** with the platform-required `Timestamp, ReportId, DeviceId, DeviceName` recovered from the latest event (`arg_max`). Lookback (4 h) exceeds frequency (1 h), so the same new process is re-evaluated by up to four runs; the platform de-duplicates identical entity sets into one alert.

### Recommended alert configuration (portal / Graph API)

- Impacted assets: **Device** = `DeviceId`; **User** = `InitiatingProcessAccountSid` (or `InitiatingProcessAccountUpn` for Entra-joined fleets; choose one column per entity type).
- Related evidence: Process (`InitiatingProcessId` + `InitiatingProcessCreationTime`), File (`InitiatingProcessSHA1`).
- Custom details worth surfacing: `ProcKey`, `DesiredAccessHex`, `InitiatingProcessCommandLine`, `InitiatingProcessVersionInfoOriginalFileName`, `InitiatingProcessVersionInfoCompanyName`, `FleetDeviceCount`, `InitiatingProcessParentFileName`.
- Alert title: `First-seen LSASS access by {InitiatingProcessFileName} on {DeviceName}`.
- Recommended actions: collect investigation package; check for `.dmp` creation by the same `InitiatingProcessUniqueId` in `DeviceFileEvents`; check `DeviceImageLoadEvents` for `dbghelp.dll`/`dbgcore.dll`/`comsvcs.dll` loaded by that process; if confirmed, isolate the device and treat all credentials present on it as compromised.

## 2. Platform contract check (XDR)

| Check | Status |
|---|---|
| Required columns `Timestamp, ReportId, DeviceId, DeviceName` in final `project` | Yes, recovered via `arg_max(Timestamp, *)` |
| Frequency/lookback pair valid | 1 h / 4 h; `LookbackWindow` in the query **must be kept equal** to the platform lookback |
| Explicit time filters | `Timestamp > ago(30d)` bounds the baseline scan; novelty and candidate selection use `ingestion_time()`, which is what the service itself evaluates the lookback on. The first run after save scans 30 days on the platform side, but the query's own `ingestion_time() > ago(4h)` filter means it produces a normal-sized result, not a 30-day burst. |
| Continuous (NRT) eligible | **No** (uses `join`, `let` tabular expressions and comments). This is a deliberate choice: fleet-wide baselining is inherently correlational. |
| 150 alerts/run cap | Expected volume is single digits per run in a stable estate. If any run approaches 150 the rule is broken (see tuning) and is silently dropping alerts. |
| Impacted assets | at most one column per entity type (Device, Account) |
| Resource usage | Expected Low/Medium. The 30-day scan is filtered on two indexed columns before `parse_json`, and the regex normalisation runs only on the surviving LSASS-open rows. **Verify the resource indicator after the first run; "High" is a review blocker.** |

## 3. Tuning knobs (`let` block at the top of `detection.kql`)

| Knob | Default | Effect of changing it |
|---|---|---|
| `LookbackWindow` | `4h` | Must match the platform lookback for the frequency. If the rule is moved to every 3 h, set `12h`; every 12 h, `48h`; every 24 h, `30d` (at which point the baseline and candidate windows coincide and the rule degenerates, so do not run it daily). |
| `BaselineWindow` | `30d` | The "ever seen" horizon. Cannot exceed advanced-hunting retention. Shorter = more "new" processes (more alerts, more FPs); longer is not possible without the Sentinel-side pattern in section 7. |
| `TargetProcessNames` | `["lsass.exe"]` | Add targets only if MDE records `OpenProcessApiCall` for them (it does so for a small set of sensitive processes). |
| `MemoryAccessBits` | `0x7A` | Which access rights count. Tighten to `0x10` (VM_READ only) for a dump-only detector; widen to include `0x1000` (QUERY_LIMITED) only if you accept the enumeration noise. |
| `RequireMemoryAccess` | `true` | `false` makes every handle open in scope. Broader coverage (e.g. a tool that only queries first, then re-opens) at a large noise cost. |
| `BaselineKeyMode` | `"path"` | `"hash"` keys on `InitiatingProcessSHA1`; every patch of every legitimate accessor becomes "new". Use only on small, tightly controlled server fleets. |
| `SuppressRolloutDeviceCount` | `0` (off) | When > 0, a new key seen on more than N devices in one window is treated as a software rollout and suppressed. Trade-off: a worm/mass-dump campaign also looks like a rollout. Keep off until volume is measured; if enabled, pair with a separate high-volume rule. |
| `ExcludedProcessKeys` | empty | Inline hard exclusions by normalised key. Derive the key from an alert's `ProcKey` custom detail. Keep this list short; prefer alert tuning (below) for entity data. |

**Deriving a key for exclusion**: copy `ProcKey` from the alert's custom details. It is already normalised (`c:/users/*/appdata/local/temp/*/tool.exe`). Do not hand-write keys from raw paths.

**Where to put exclusions** (fix-selection rule: data belongs outside the query, logic inside it):

- Known-good *entity* (a specific vendor agent, a specific jump host): Defender **alert tuning** rule on the custom detection, scoped by file name/path/SHA1 or device group. No rule redeploy, no version bump.
- Known-good *pattern* (e.g. "anything under `c:/program files/<vendor>/`"): `ExcludedProcessKeys` or an extra normalisation regex, with a version bump and a Detection Change Record.
- Never paste external feed content (externaldata, watchlists) into the exclusion logic; feeds are attacker-observable.

## 4. Known false positives / benign true positives

The rule is a novelty detector, so every FP is "a legitimate thing happened for the first time". Expect a burst in the first week, then a trickle.

| Source | Why it fires | Handling |
|---|---|---|
| New or updated security tooling (AV engines, EDR sensors, vulnerability scanners, DLP agents, Sysinternals) installed to a path the normaliser does not wildcard | They legitimately read LSASS memory | Alert tuning by signer/path after one confirmation; most vendors install to a stable `Program Files` path and only fire once |
| Vendor rebrands / installer path changes (e.g. product moves from `Program Files (x86)` to `Program Files`, or adds a new sidecar binary) | New key, same product | Same as above |
| Backup, VDI, and credential-management agents (LSA SSP/AP providers, password filters loaded via helper exes, SSO agents) | Read LSASS during enrollment or sync | Confirm `InitiatingProcessVersionInfoCompanyName` and signed path, then tune |
| Newly onboarded device populations (acquisition, new OS build, new image) | Their standard agents may be new to *this* tenant's 30-day baseline | Expect a burst on onboarding day; stage onboarding with the rule in audit (no actions) |
| Windows servicing: new `svchost`-hosted components, `wininit`, `csrss`, `msiexec`, `TiWorker`, `MsMpEng` after feature updates | New image path containing a build number the normaliser did not catch | The version regex catches `n.n` and `n.n.n`; add a regex if your estate uses other patterns |
| Developers and debuggers (`windbg`, `procexp64`, `procmon`, Visual Studio, `dumpcap`) on engineering workstations | Legitimate but indistinguishable from reconnaissance; they also appear once per developer-tool version | Treat as Benign True Positive, tune per device group (dev workstations) rather than per tool |
| Authorised red-team or pentest activity | Working as designed | Benign True Positive; do not exclude, close with the engagement reference |
| Honest renames: a known accessor copied to a new location by an admin (`c:\temp\procdump64.exe`) | New key | Benign True Positive, but worth a conversation: that is exactly how an attacker stages the same tool |
| `DesiredAccess` missing from `AdditionalFields` on some sensor versions | The query fails open and admits those rows | If observed, confirm the sensor build and decide whether to fail closed (`isnull` branch) after measuring |

**Classify every alert** as True Positive / Benign True Positive / False Positive and record the root cause (missing exclusion, normaliser gap, environmental noise, data quality) in the FP Analysis Worksheet before changing the rule. Re-run the TP fixture after every exclusion.

## 5. What it would miss (coverage gaps, be explicit with the reviewer)

1. **Any accessor already in the 30-day baseline.** If an attacker uses a tool that has opened LSASS in your fleet in the last month (including your own red team's, or an admin's `procdump64.exe` left in `c:\tools\`), it is not "new" and will not fire. Pair with signature/behaviour rules (Microsoft built-ins, `comsvcs.dll MiniDump`, `.dmp` creation) rather than relying on this alone.
2. **Living-off-the-land via an already-baselined host process.** `rundll32.exe comsvcs.dll MiniDump`, `taskmgr.exe` "Create dump file", `werfault.exe`, PowerShell or WMI providers, or code injected into an AV/EDR process all run under an image that is almost certainly in the baseline. Only the *image* is keyed, not the command line or parent.
3. **30-day horizon only.** "Never seen in the fleet" is really "not seen in 30 days". A tool used once six weeks ago re-alerts; a tool used 20 days ago does not. Longer memory needs the Sentinel pattern in section 7.
4. **Kernel-mode / direct-memory readers and PPL-aware tooling.** Drivers that read LSASS memory without `OpenProcess` (BYOVD, `MmCopyVirtualMemory`), handle duplication from an already-open handle (`NtDuplicateObject` on a parent's handle), or reading `lsass` via `LsaIso`/Credential Guard side channels do not generate `OpenProcessApiCall` for the attacker's image.
5. **Access masks below the threshold.** With `RequireMemoryAccess = true`, an open with only `QUERY_LIMITED_INFORMATION` is ignored; some reconnaissance and some staged multi-open techniques start that way.
6. **Hash-level evasion is not what this rule covers; path-level evasion partly is.** Dropping the same tool into a *new* random path still fires (temp and user-profile segments are wildcarded, so the file name must change to evade), but an attacker who names the dropper after an already-baselined image in an already-baselined directory (`c:\program files\<vendor>\agent.exe`) evades it. Use `BaselineKeyMode = "hash"` where that threat model matters and the fleet is small.
7. **Late ingestion beyond retention edges and sensor gaps.** Devices offline for more than the baseline, or sensors in passive/limited mode that do not emit `OpenProcessApiCall`, are invisible.
8. **Rollout suppression, if enabled**, hides anything that appears on many devices at once, including a mass-dump stage of a ransomware deployment.
9. **Renamed targets.** The rule matches `FileName in~ ("lsass.exe")`; it does not verify `FolderPath` is `c:\windows\system32`. A decoy `lsass.exe` elsewhere can generate noise but cannot cause a miss of the real one.

## 6. Validation plan (quality gates before deploy)

Required fixtures, built with `scripts/kql_test_harness.py` (shadow `DeviceEvents` with a `datatable`, pin `now()`), each asserting exact alert count and key columns:

| Fixture | Contents | Expected |
|---|---|---|
| `tp.json` | 10 baseline rows (days -29..-2) of `msmpeng.exe` opening lsass with `0x1410`; 1 row at -30 min of `c:\users\bob\appdata\local\temp\abc123\dump.exe` with `0x1fffff` | 1 alert, `ProcKey = c:/users/*/appdata/local/temp/*/dump.exe`, correct `DeviceId`/`ReportId` |
| `tn_known_accessor.json` | same baseline, candidate = `msmpeng.exe` again | 0 alerts |
| `tn_version_bump.json` | baseline `c:\program files\vendor\1.2.3\agent.exe`; candidate `...\1.2.4\agent.exe` | 0 alerts (normaliser) |
| `tn_query_only.json` | candidate new image with `DesiredAccess = 0x1000` | 0 alerts (mask filter) |
| `boundary_window.json` | first ingestion of new key at exactly `-4h + 1m` vs `-4h - 1m` | fires / does not fire |
| `boundary_mask.json` | masks `0x1000` (no), `0x1010` (yes), `0x0002` (yes) | 2 alerts |
| `empty.json` | schema only | 0 alerts, no error (checks `arg_max` on empty, `tohex(null)`) |

Then, in the tenant (no access during authoring, so this is still open):

- [ ] Run the query interactively with a 7-day lookback and `count` first; note the resource indicator (must be Low/Medium).
- [ ] Note `DesiredAccess` encoding in `AdditionalFields` on your sensor builds (expected integer; if hex string, adjust `tolong`).
- [ ] Measure alerts per run for 7 days in audit mode (no response actions); confirm << 150.
- [ ] Confirm `arg_max(Timestamp, *)` carries `ReportId` from the same event (process tree renders in the alert).
- [ ] Peer review against the KQL performance checklist (indexed filters first, explicit `kind=inner`, small side left, no bare `take`).
- [ ] Schedule 7-day post-deploy review; expect to add 3-10 alert-tuning entries in week one.

## 7. Variants and future work

- **Longer memory (> 30 d)**: stream `DeviceEvents` to Sentinel and either (a) build the rule as a Sentinel analytics rule over the longer-retention table, or (b) maintain a *known LSASS accessors* watchlist refreshed daily by a summary rule and use `_GetWatchlist` as the baseline. The XDR-native version here cannot do this.
- **Key on command line for LOLBins**: a sibling rule keyed on `(image, normalised command line)` for `rundll32`, `powershell`, `wmic`, `taskmgr` closes gap 2 above at higher volume.
- **Per-device novelty** (`by ProcKey, DeviceId`, first seen on *this* device) is a different, noisier rule useful on tier-0 servers only.

## 8. Change record

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0.0 | 2026-10-22 | detection engineering | Initial draft from expertise, no tenant validation. Rollback: disable the custom detection; no other dependencies. |
