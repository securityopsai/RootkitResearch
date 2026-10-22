# First-seen process accessing LSASS (fleet-wide)

| Field | Value |
|---|---|
| Platform | Microsoft Defender XDR custom detection (Advanced Hunting) |
| Query file | `detection.kql` |
| Frequency | Every hour (XDR hourly rules evaluate the previous 4 hours of data) |
| Data source | `DeviceEvents`, `ActionType == "OpenProcessApiCall"`, target `lsass.exe` |
| Severity (suggested) | Medium (raise to High if `require_sensitive_access = true` and the estate is quiet after tuning) |
| Category | Credential Access |
| Status | Draft, not yet validated in a tenant |

## What it detects

A process opens a handle to `C:\Windows\System32\lsass.exe` and that process identity has not
been observed opening lsass on **any** device in the estate during the baseline window
(default 30 days, the Advanced Hunting retention limit).

Process identity defaults to the **normalized image path** (lower-cased, with `C:\Users\<name>\`,
version-number folders and GUID folders replaced by placeholders) so routine agent updates and
per-user installs do not look "new". It can be switched to SHA256.

By default the rule only alerts when the requested access mask contains rights usable for
credential theft or injection (`PROCESS_VM_READ`, `VM_WRITE`, `VM_OPERATION`, `DUP_HANDLE`,
`CREATE_THREAD`, `CREATE_PROCESS`, or any `GENERIC_*`). Rows where MDE did not report a
`DesiredAccess` are kept rather than dropped.

Results are collapsed to **one row per new process identity per run**, anchored on the earliest
event (`arg_min(Timestamp, *)`), carrying the device count, up to 10 device names, accounts and the
distinct access masks observed. XDR de-duplicates results that share `Timestamp`/`ReportId`/`DeviceId`
across runs, so the same first sighting re-surfacing in the overlapping 4h window does not re-alert.

### Why first-seen rather than a static allowlist

LSASS access by legitimate software is common (EDR/AV, monitoring, backup, Windows itself).
A static allowlist either goes stale or becomes so wide it hides tradecraft. Fleet-wide first-seen
lets the estate define "normal" and surfaces only genuinely novel accessors, which is what
`procdump`, `nanodump`, `mimikatz`, renamed `taskmgr` copies, custom loaders and dropped
Sysinternals binaries look like on day one.

## MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Credential Access (TA0006) | **T1003.001** OS Credential Dumping: LSASS Memory | Primary. Any VM_READ / DUP_HANDLE / ALL_ACCESS open of lsass by a novel process. |
| Defense Evasion / Privilege Escalation | T1055 Process Injection | Secondary, when the mask includes `VM_WRITE` / `CREATE_THREAD` (injecting into lsass to disable PPL, patch wdigest, etc.). |
| Credential Access | T1003.001 via T1218 / LOLBins | Only if the LOLBin itself is novel to lsass in the estate (see gaps). |

Set the custom detection's **Category = Credential access** and **Technique = T1003.001** so the
alert carries the mapping into incidents and Threat Analytics coverage views.

## Rule configuration (XDR portal)

- **Frequency:** Every hour. Keep `detection_window = 4h` in the query; it must be at least the
  platform lookback for the chosen frequency or events will fall between runs. If you move to
  "Every 3 hours" set it to `12h`, "Every 12 hours" -> `48h`, "Every 24 hours" -> `30d` (then drop
  the baseline/detection split, the whole window is one run).
- **Impacted entities:** Device = `DeviceId`; User = `InitiatingProcessAccountSid` (or
  `InitiatingProcessAccountUpn` if populated). Optionally File = `InitiatingProcessSHA256`.
- **Alert title:** `First-seen process accessing LSASS: {InitiatingProcessFileName}` (template
  columns are supported in the title field).
- **Automated actions:** none on first deployment. After two to four weeks of tuning consider
  "Collect investigation package" only. Do **not** enable device isolation; the rollout FP class
  would isolate fleets.
- **Columns required by the engine:** `Timestamp`, `ReportId`, `DeviceId` are projected explicitly.

## Tuning knobs

All knobs are `let` statements at the top of `detection.kql`.

| Knob | Default | Effect / when to change |
|---|---|---|
| `baseline_window` | `30d` | How far back "ever seen" looks. Cannot exceed Advanced Hunting retention. Lowering it increases FPs from rarely-run tooling. For a longer memory, move the rule to Sentinel and back the baseline with a watchlist or a scheduled summary table. |
| `detection_window` | `4h` | Must match the XDR lookback for the frequency. Do not shrink below 4h for an hourly rule: ingestion lag would drop events. |
| `baseline_on_hash` | `false` | `true` keys identity on SHA256. Catches an attacker dropping a binary at a baselined path (masquerading) but every vendor patch of every lsass-touching agent becomes a new alert. Recommended only in small, tightly managed estates, or run as a second lower-severity rule. |
| `require_sensitive_access` | `true` | `false` alerts on any first-seen lsass open including `QUERY_LIMITED_INFORMATION` (0x1000), which most inventory/monitoring tools use. Expect 3-10x more alerts. Useful during initial baseline validation to see everything. |
| `rollout_device_threshold` | `25` | A brand-new identity on more than N devices within the 4h window is suppressed as a software rollout. Lower for small estates (e.g. 5), raise or set to `0` (disable) in high-security segments where a mass dumping campaign is a realistic scenario. See "what it misses". |
| `allowlist_exact` | empty | Normalized full paths to ignore after the baseline check. Use sparingly; the baseline already absorbs stable tooling. Intended for tools with stable paths that run so rarely they age out of the 30d baseline (quarterly audit scripts, DR test agents). |
| `allowlist_regex` | `""` | Single RE2 pattern for tooling that runs from randomized folders the normalizer does not catch (e.g. `c:\windows\temp\nessus_<random>\nessusd.exe`, `%TEMP%\_MEI<pid>\` PyInstaller agents). |
| `sensitive_bits` / `generic_bits` | `0xFA` / `0xF0000000` | Which access rights count as sensitive. Add `0x0400` (`QUERY_INFORMATION`) to broaden; remove `0x0008` (`VM_OPERATION`) if a debugger-style tool is noisy. |
| Path normalizer regexes | in base set | Extend if you see the same product alerting repeatedly from paths that differ only by a build string, locale folder, or user-SID folder. Every new placeholder reduces precision slightly (an attacker can hide inside the wildcarded segment). |

Suggested tuning order: deploy with defaults -> review two weeks of alerts -> add normalizer
patterns for repeat offenders -> add `allowlist_regex` only for randomized-path tooling -> last
resort `allowlist_exact`.

## Known false positives

| Source | Why it fires | Handling |
|---|---|---|
| Security/EDR/AV agent **upgrades** that change the install path (Defender Platform `Platform\4.18.x-0\MsMpEng.exe`, third-party AV, Tanium, Rapid7, Qualys, CrowdStrike sensor side-by-side installs) | New versioned folder | Normalizer handles numeric segments. Anything else: extend the normalizer. Mass upgrades are also caught by `rollout_device_threshold`. |
| **New software deployment** (monitoring agents: Zabbix, Datadog, SolarWinds, Splunk UF; backup agents; vulnerability scanners; DLP; PAM session recorders) | Genuinely first-seen | Expected, one alert per product. Close as benign, the baseline absorbs it. Confirm with change management. |
| **Rarely-run legitimate tooling** that last ran >30d ago (quarterly audits, DR tests, forensic collectors used only in incidents, Sysinternals `procexp`/`procmon` used by admins) | Aged out of baseline | `allowlist_exact` for stable paths, or accept. Note `procdump`/`procexp` by admins is also exactly what attackers do; prefer to triage, not allowlist. |
| **Windows servicing / feature upgrades** (`C:\$WINDOWS.~BT\Sources\SetupHost.exe`, `SetupPlatform`, `WerFault.exe` / `WerFaultSecure.exe` after an lsass crash, `svchost` from a new build is *not* affected) | New path or novel crash-reporting | Short-lived; one alert per upgrade wave; rollout threshold suppresses large waves. |
| **Developer / IT power users** with per-user installed tools (`c:\users\*\appdata\local\programs\...`) | Per-user path | Normalizer collapses user names; the first user to install the tool still alerts, which is the intended behaviour. |
| **Randomized temp folders** (PyInstaller `_MEIxxxxxx`, Nessus `nessus_xxxx`, MSI `{GUID}` staging, ClickOnce `apps\2.0\<random>`) | Normalizer does not cover random alphanumerics | `allowlist_regex`; GUID folders are normalized already. |
| **Hash mode only:** every patch of any lsass-touching product | New SHA256 | Keep `baseline_on_hash = false` unless the extra precision is wanted. |
| **New site / OU onboarded to MDE** | Whole estate's "known" set does not include that site's tooling | Burst of alerts for a few days; rollout threshold helps; consider temporarily raising it during onboarding. |

Expected steady-state volume in a tuned mid-size estate: low single digits per day, mostly
deployments. If the first run returns hundreds of rows the baseline is probably being clipped by
the platform lookback (see Validation) or `require_sensitive_access` was set to `false`.

## What it would miss

- **Known-process abuse (the biggest gap).** Any process already baselined fleet-wide can dump
  lsass without alerting: `taskmgr.exe` "Create dump file", `rundll32 comsvcs.dll MiniDump`,
  `procdump` if admins already use it, `WerFault`/`WerFaultSecure` abuse, SQL Dumper, Defender's
  own `MpCmdRun`, a compromised monitoring agent, or an attacker injecting into a baselined
  process and opening lsass from there. Pair this rule with a static LOLBin lsass rule
  (`rundll32`+`comsvcs`, `taskmgr`, `procdump`, `createdump`, `dotnet-dump`, etc.) and with
  Defender's built-in ASR/credential-theft alerts; this rule is the novelty net, not the only net.
- **Known-process access escalation.** The baseline uses all access masks, so a process that
  historically opened lsass with `QUERY_LIMITED_INFORMATION` and now opens it with `VM_READ` is
  still "known". A sibling rule keyed on `(ProcessKey, SensitiveAccess)` would cover this at the
  cost of more noise.
- **Masquerading at a baselined path** (attacker drops `mimikatz` as
  `c:\program files\vendor\agent.exe` or replaces the binary). Path mode cannot see it; hash mode
  can, but see the noise trade-off. Defender's file-signature alerts and `DeviceFileEvents`
  write-to-program-files rules are the complement.
- **Wildcarded segments.** The normalizer turns `\<digits>\`, `\<guid>\` and `\users\<x>\` into
  placeholders; a binary at `c:\users\attacker\tool.exe` is "new" only until any user ran a tool
  at the same relative path.
- **Mass campaigns above `rollout_device_threshold`.** A tool run on >25 hosts inside 4 hours is
  suppressed by design. Ransomware operators dumping credentials estate-wide via a scheduled task
  or GPO would hit this. Set the knob to `0` in crown-jewel segments or run a second rule with no
  threshold at Informational severity.
- **Baseline poisoning.** If an attacker was already dumping lsass with the same tool during the
  previous 30 days, that tool is "known" and never alerts. Review the baseline set once when the
  rule is first deployed (`known_processes` subquery run standalone) and periodically.
- **Access paths that do not generate `OpenProcessApiCall` for lsass.** Kernel-mode reads via a
  vulnerable driver (BYOVD), handle inheritance/duplication from another process that already
  holds an lsass handle, snapshot/`PssCaptureSnapshot` from a baselined process, and reading an
  existing minidump or hiberfil/pagefile from disk. Credential theft that never touches lsass at
  all (SAM/SECURITY hive export, `ntds.dit`, DCSync, LSA secrets via `secretsdump` over the
  network, Kerberos ticket extraction from the user's own session) is out of scope.
- **Sensor coverage and sampling.** MDE reports `OpenProcessApiCall` only for a set of sensitive
  targets (lsass among them) and may rate-limit repeated opens from the same process; the first
  open is what matters here, but a process whose only lsass open was dropped by the sensor is
  invisible. Devices not onboarded, offline sensors, or Credential Guard configurations change the
  picture: with Credential Guard, lsass holds fewer secrets but access is still logged.
- **Late-arriving telemetry.** Hourly rules only evaluate events whose `Timestamp` falls in the
  last 4h at run time. An endpoint that was offline and uploads a day of events later will have
  its lsass opens land directly in the baseline, never in the detection window.
- **Non-Windows and the lsass process itself.** Linux/macOS have no lsass. An lsass that is
  itself compromised (e.g. SSP/DLL loaded into lsass, T1547.005) does not need to *open* lsass.

## Validation plan (no tenant access at time of writing; to be run by the reviewer)

1. **Schema check.** Run the query in Advanced Hunting as-is. Confirm `InitiatingProcessVersionInfo*`
   and `AdditionalFields.DesiredAccess` resolve in your tenant; remove or substitute columns if the
   schema differs.
2. **Baseline sanity.** Run only the `known_processes` subquery. Expect tens to a few hundred
   distinct `ProcessKey` values dominated by `c:\windows\system32\*`, Defender, and your agent
   fleet. Anything surprising here is a poisoned baseline or an existing problem.
3. **Lookback clipping check.** Save as a custom detection and compare the first run's result count
   against an Advanced Hunting run with `detection_window = 4h`. If the custom detection returns
   far more rows, the platform is constraining the whole query to 4h and the baseline is empty;
   in that case move the rule to "Every 24 hours" (30d lookback, `detection_window = 1d`) or
   to Sentinel with a watchlist-backed baseline.
4. **True-positive test.** On a test host already onboarded, run a freshly compiled or renamed
   lsass reader (e.g. `procdump -ma lsass.exe` copied to an unusual path, or a minimal
   `OpenProcess(PROCESS_VM_READ)` test binary). Expect one alert within ~1-2 hours with
   `DesiredAccessHex` showing `0x1010`, `0x1FFFFF` or similar and `DeviceCount = 1`.
5. **FP burn-in.** Leave at Medium with no automated actions for two weeks; record each alert's
   disposition and feed the normalizer/allowlist knobs.

## Triage pointers

- `DesiredAccessHex` of `0x1010`, `0x1038`, `0x1410`, `0x1438`, `0x143A`, `0x1FFFFF` = read memory;
  `0x1040`/`0x40` = handle duplication; `0x80` = create-process (fork-and-dump tricks).
- Unsigned or unknown `InitiatingProcessVersionInfoCompanyName`, parent of `cmd`/`powershell`/
  `wscript`/`rundll32`, user-writable path, or `InitiatingProcessAccountName` that is not SYSTEM
  or a service account: escalate.
- `DeviceCount` near the rollout threshold on a known change window: likely deployment, confirm
  with change records before closing.
- Pivot: `DeviceProcessEvents` for the process creation and signature, `DeviceFileEvents` for
  where the binary came from and any `.dmp` written afterwards, `DeviceNetworkEvents` for
  exfiltration of a dump file.
