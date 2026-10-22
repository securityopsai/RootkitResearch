# PASTEJACK hunt pack — Defender XDR Advanced Hunting + Sentinel

**Source:** threat advisory excerpt received 2026-10-22 (fictional test data; campaign observed 2026-10-20).
**Scope:** Defender XDR tenant (Advanced Hunting) with Sentinel attached.
**Status:** queries are written, reviewed against the KQL quality checklist, and are NOT yet executed
(no tenant access from the authoring session). Every query is bounded by `let lookback = 30d;` so it is
safe to paste into Advanced Hunting as-is. Expected result sizes are estimates, not measurements.

## 0. How to use this pack today

Run order (fastest signal first):

| Step | Hunt | Why first |
|------|------|-----------|
| 1 | H5 Existing-alert sweep | 30 seconds; tells you whether Defender already fired on any IOC |
| 2 | H3a Network IOC sweep, H4b File/process IOC sweep, H6 URL-click sweep | Pure IOC matches; near-zero noise; a hit = incident |
| 3 | H1a conhost --headless cradle, H2b Scheduled task into AppData\Roaming (DeviceEvents), H4a PowerShell drops EXE into Roaming | Behavioural; catches variants the IOCs miss; low expected volume |
| 4 | H1b Broad ClickFix, H2a schtasks.exe variant, H3b Roaming-process beaconing, H2c/H3c Sentinel-only | Noisier; need a baseline pass before trusting them |
| 5 | H1c RunMRU artefact | Coverage-dependent; see note |

Triage pivots for any hit: pivot on `InitiatingProcessUniqueId` / `ProcessUniqueId` (not PID), then
`DeviceId` + 24 h window across DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents,
DeviceRegistryEvents. The kill chain to confirm is: Run-dialog paste -> conhost --headless -> powershell
cradle -> `%APPDATA%\msbuild\upd.exe` written -> ONLOGON task -> HTTPS to the C2 domains -> POST `/api/upload`.

### IOC block (hoisted; paste above any query that references it)

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips = dynamic(["203.0.113.45"]);
// NOTE: the hash as published is 65 hex chars, which is not a valid SHA256. Confirm with the report
// authors before relying on a hash match. Kept here so the sweep is ready once corrected.
let ioc_sha256 = dynamic(["9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"]);
let ioc_task_names = dynamic(["OneDrive Sync Health"]);
let ioc_payload_path = @"\AppData\Roaming\msbuild\upd.exe";
let ioc_user_agent = "UpdateChecker/1.0";
let ioc_uri_path = "/api/upload";
let cradle_terms = dynamic(["irm", "iwr", "invoke-webrequest", "invoke-restmethod", "downloadstring",
  "downloadfile", "iex", "invoke-expression", "net.webclient", "start-bitstransfer", "frombase64string"]);
let shells = dynamic(["powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "curl.exe", "certutil.exe"]);
```

Sentinel alternative for the IOC data: a watchlist `PASTEJACK_IOC` (columns per the standard watchlist
format: `Entity, EntityType, AddedDate, AddedBy, Justification, ExpiryDate, RuleScope, TicketRef`) read with
`_GetWatchlist('PASTEJACK_IOC') | where EntityType == "domain" | project Entity`. Set `ExpiryDate`
on every IOC row; campaign infrastructure rots within weeks. Watchlists/`externaldata()` are not available
in XDR Continuous (NRT) rules, which is why the IOCs are inline `dynamic()` lists here.

Note on `irm` / `iex`: 3-character terms are not term-indexed, so these clauses cost a scan. That is
accepted deliberately: the queries anchor on `FileName` / `InitiatingProcessFileName` first so the scan
runs over a small surviving set, and command-line matching is case-insensitive on purpose (casing is an
obfuscation dimension).

---

## 1. Hunt index

| ID | Hypothesis (one line) | Table(s) | MITRE | Run today | Detection candidate |
|----|-----------------------|----------|-------|-----------|---------------------|
| H1a | conhost.exe --headless spawned a shell with a download cradle (PASTEJACK stage 1) | DeviceProcessEvents | T1204.004, T1059.001, T1105, T1564.003 | Yes | **Yes — XDR NRT or 1h** |
| H1b | Any shell launched from explorer.exe (Run dialog) with a download cradle (generic ClickFix) | DeviceProcessEvents | T1204.004, T1059.001 | Yes | After baseline — XDR 1h / Sentinel |
| H1c | Run-dialog history (RunMRU) contains a cradle / headless string | DeviceRegistryEvents | T1204.004 | Yes (coverage caveat) | No (hunt only) |
| H2a | schtasks.exe /create with /tr pointing into a user's AppData\Roaming | DeviceProcessEvents | T1053.005, T1036.005 | Yes | After baseline — corroboration for H2b |
| H2b | Scheduled task created (any method) whose action lives in AppData\Roaming | DeviceEvents (ScheduledTaskCreated) | T1053.005 | Yes | **Yes — XDR NRT or 1h, allowlist needed** |
| H2c | Same as H2b from Windows Security 4698 (Sentinel) | SecurityEvent | T1053.005 | If 4698 is collected | Sentinel scheduled (optional) |
| H3a | Endpoint connected / resolved the C2 domains or IP | DeviceNetworkEvents | T1071.001 | Yes | No — push IOCs to Defender Indicators + Sentinel TI instead |
| H3b | A binary running from AppData\Roaming is talking to the internet (rare/unsigned) | DeviceNetworkEvents + DeviceFileCertificateInfo | T1071.001, T1041 | Yes | After baseline — XDR 24h/30d or Sentinel; narrow `msbuild\` variant could go sooner |
| H3c | Proxy/web logs show the exfil user agent or `/api/upload` POST | CommonSecurityLog / ASIM `_Im_WebSession` (Sentinel) | T1041 | Yes (Sentinel) | Sentinel scheduled — IOC-fragile, short-lived |
| H4a | PowerShell wrote an executable into AppData\Roaming | DeviceFileEvents | T1105 | Yes | **Yes — XDR NRT or 1h** |
| H4b | Payload hash / path seen anywhere (file, process, image load) | DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents | T1105, T1036.005 | Yes | No — IOC only |
| H5 | Defender already alerted on any IOC | AlertEvidence | — | Yes, first | — |
| H6 | A user clicked a link to the lure domains | UrlClickEvents | T1204.004 | Yes | No — IOC only |

Gap acknowledged: the credential-theft stage (T1555.003) is not hunted. MDE does not log reads of
browser credential stores at hunt-usable fidelity; coverage for that stage comes from H3b/H3c (exfil).

---

## 2. Hunts

### H1a — conhost.exe --headless -> shell with download cradle

**Intent:** catch the exact PASTEJACK stage-1 chain and close variants (different domain, different shell).
In the Run-dialog ClickFix flow the grandparent is `explorer.exe`; the query surfaces that as a column
rather than requiring it, so other launchers (Terminal, cmd) still show.

```kql
// IOC block above
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "conhost.exe"
| where InitiatingProcessCommandLine has "headless"
| where FileName in~ (shells)
| extend Canon = replace_string(ProcessCommandLine, '"', '')
| extend HasCradle = Canon has_any (cradle_terms)
| extend HiddenWindow = Canon has_any ("-w hidden", "-windowstyle hidden", "-window hidden")
| extend IocHit = Canon has_any (ioc_domains)
| extend FromRunDialog = InitiatingProcessParentFileName =~ "explorer.exe"
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessCommandLine, GrandParent = InitiatingProcessParentFileName,
    FromRunDialog, HasCradle, HiddenWindow, IocHit, ProcessUniqueId, InitiatingProcessUniqueId, ReportId
| order by IocHit desc, HasCradle desc, Timestamp desc
```

**Expected volume:** very low. `conhost.exe --headless` as a parent of a shell is rare outside
developer tooling. Rows with `HasCradle == true` are the hits; rows with `HasCradle == false` are the
baseline you will need before promotion (note which products use `--headless` in your estate).

**Benign lookalikes to expect:** developer/IDE tooling and some RMM agents launching
`conhost.exe --headless` for console I/O; admin scripts doing `irm` from a terminal (then
`FromRunDialog == false` and usually no `-w hidden`).

**Triage on hit:** confirm `HiddenWindow`, pull the child tree by `ProcessUniqueId`, then run H4a/H4b and
H3a on the same `DeviceId` for the last 24 h.

---

### H1b — Generic ClickFix: shell from explorer.exe with a cradle (no conhost requirement)

**Intent:** the campaign's lure mechanic (paste into Run) will outlive its conhost trick. Anything
`explorer.exe` spawns directly that contains a cradle is suspicious; `explorer.exe` -> `powershell.exe`
with `irm`/`iex` is not something users do by accident.

```kql
// IOC block above
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ (shells) or FileName =~ "conhost.exe"
| extend Canon = replace_string(ProcessCommandLine, '"', '')
| where Canon has_any (cradle_terms)
    or (FileName =~ "conhost.exe" and Canon has "headless")
    or Canon has_any ("mshta", "http://", "https://")
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine,
    ProcessUniqueId, ReportId
| summarize Hits = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
    CommandLines = make_set(ProcessCommandLine, 10), (Timestamp, ReportId) = arg_max(Timestamp, ReportId)
    by DeviceId, DeviceName, AccountName
| order by Hits asc, LastSeen desc
```

**Expected volume:** low-to-medium depending on how many power users launch PowerShell one-liners from
Run. Devices with `Hits == 1` and a URL in the command line are the ones to look at first.

**Benign lookalikes:** admins pasting documented install one-liners (winget/choco bootstrap scripts),
`mshta` launched by legitimate installers. These should become an allowlist on `(AccountName,
command-line pattern)` before promotion, not device-wide exclusions.

---

### H1c — RunMRU artefact (what was pasted into the Run dialog)

**Intent:** Windows stores Run-dialog history in `HKCU\...\Explorer\RunMRU`. If MDE captured the value
write, this gives you the literal pasted string even when the process telemetry was missed.

```kql
// IOC block above
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"\Explorer\RunMRU"
| where RegistryValueData has_any (cradle_terms) or RegistryValueData has "headless"
    or RegistryValueData has_any (ioc_domains)
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, RegistryValueName,
    RegistryValueData, ReportId
```

**Coverage caveat:** MDE registry telemetry is selective and RunMRU is not guaranteed to be collected.
If this returns 0 rows on an estate where H1a found hits, treat it as "not collected", not "absent".
Validate once by typing a harmless command in Run on a test device and checking the table. Hunt only;
not a detection candidate while coverage is unverified.

---

### H2a — schtasks.exe /create with an action in AppData\Roaming

**Intent:** persistence as described in the report, by the described tool. Parses the `/tn` and `/tr`
arguments with `parse_command_line()` so the task action is matched as a value, not as a substring of
the whole line (attackers reorder/pad arguments).

```kql
// IOC block above
let roaming_allowlist = dynamic([]);   // task-action paths known-good in YOUR estate, e.g. a per-user updater
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "Roaming"                 // cheap indexed pre-filter on the raw column
| extend Args = parse_command_line(tolower(ProcessCommandLine), "windows")
| extend CreateIdx = array_index_of(Args, "/create"), TrIdx = array_index_of(Args, "/tr"),
    TnIdx = array_index_of(Args, "/tn"), ScIdx = array_index_of(Args, "/sc")
| where CreateIdx >= 0 and TrIdx >= 0
| extend TaskAction = tostring(Args[TrIdx + 1]),
    TaskName = iff(TnIdx >= 0, tostring(Args[TnIdx + 1]), ""),
    Schedule = iff(ScIdx >= 0, tostring(Args[ScIdx + 1]), "")
| where TaskAction contains @"\appdata\roaming\"
| where not(TaskAction has_any (roaming_allowlist))
| extend IocTaskName = TaskName in~ (ioc_task_names),
    IocPath = TaskAction contains tolower(ioc_payload_path),
    MasqueradeName = TaskName has_any ("onedrive", "microsoft", "windows", "update", "health")
| project Timestamp, DeviceId, DeviceName, AccountName, TaskName, Schedule, TaskAction,
    IocTaskName, IocPath, MasqueradeName, ProcessCommandLine,
    Parent = InitiatingProcessFileName, ParentCommandLine = InitiatingProcessCommandLine,
    InitiatingProcessUniqueId, ReportId
| order by IocTaskName desc, IocPath desc, Timestamp desc
```

**Expected volume:** low. Per-user software that registers tasks usually does so via the Task Scheduler
API (caught by H2b), and mostly from `AppData\Local`, not `Roaming`.

**Benign lookalikes:** per-user updaters for some productivity/VPN clients; IT scripts that register
user-context tasks. Capture their `TaskAction` into `roaming_allowlist` (or a Sentinel watchlist) with a
justification and expiry.

**Triage on hit:** `Parent` should be `powershell.exe` in the PASTEJACK chain; walk
`InitiatingProcessUniqueId` back to the cradle.

---

### H2b — Scheduled task created (any method) with its action in AppData\Roaming

**Intent:** same persistence hypothesis, source-agnostic. `DeviceEvents` `ScheduledTaskCreated` records
tasks created by schtasks.exe, PowerShell `Register-ScheduledTask`, COM/API, and the Task Scheduler UI.
This is the preferred source for the detection; H2a corroborates.

```kql
// IOC block above
let roaming_allowlist = dynamic([]);   // same list as H2a; keep them in one place when promoting
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType == "ScheduledTaskCreated"
| where AdditionalFields has "Roaming" or AdditionalFields has_any (ioc_task_names)   // raw-column pre-filter before parse_json
| extend AF = parse_json(AdditionalFields)
| extend TaskName = tostring(AF.TaskName), TaskContent = tostring(AF.TaskContent)
| where TaskContent contains @"\AppData\Roaming\" or TaskName has_any (ioc_task_names)
| where not(TaskContent has_any (roaming_allowlist))
| extend IocTaskName = TaskName has_any (ioc_task_names),
    IocPath = TaskContent contains ioc_payload_path,
    LogonTrigger = TaskContent has "LogonTrigger"
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, TaskName, LogonTrigger,
    IocTaskName, IocPath, InitiatingProcessFileName, InitiatingProcessCommandLine, TaskContent, ReportId
| order by IocTaskName desc, IocPath desc, Timestamp desc
```

**Expected volume:** low; whatever appears with `IocTaskName == false` is your baseline. Review every
distinct `(TaskName, action path)` pair once and decide allowlist vs. investigate.

---

### H2c — Sentinel: Windows Security event 4698 (only if task auditing is forwarded)

```kql
let lookback = 30d;
let ioc_task_names = dynamic(["OneDrive Sync Health"]);
SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4698
| where EventData has "Roaming" or EventData has_any (ioc_task_names)
| where TaskContent contains @"\AppData\Roaming\" or TaskName has_any (ioc_task_names)
| project TimeGenerated, Computer, SubjectUserName, TaskName, TaskContent
```

Use when 4698 is collected from servers/VDI that are not MDE-onboarded, or to cross-check H2b.

---

### H3a — Network IOC sweep (connections and DNS)

```kql
// IOC block above
union
  (DeviceNetworkEvents
   | where Timestamp > ago(lookback)
   | where RemoteIP in (ioc_ips) or RemoteUrl has_any (ioc_domains)
   | project Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
       Process = InitiatingProcessFileName, ProcessPath = InitiatingProcessFolderPath,
       Account = InitiatingProcessAccountName, InitiatingProcessUniqueId, ReportId, Source = "Connection"),
  (DeviceNetworkEvents
   | where Timestamp > ago(lookback)
   | where ActionType == "DnsConnectionInspected"
   | where AdditionalFields has_any (ioc_domains)
   | project Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl = AdditionalFields,
       Process = InitiatingProcessFileName, ProcessPath = InitiatingProcessFolderPath,
       Account = InitiatingProcessAccountName, InitiatingProcessUniqueId, ReportId, Source = "DNS")
| order by Timestamp desc
```

**Expected volume:** zero unless compromised. Any row is an incident; the `ProcessPath` column tells you
immediately whether it is the `AppData\Roaming\msbuild` implant or something else (a browser visiting
the lure page is also a meaningful hit: that user was targeted).

**Do not turn this into a custom detection.** Add the domains/IP to Defender custom Indicators
(alert + block) and to the Sentinel TI store so the built-in TI-match analytics rules cover every table
at once. Set expiry on the indicators.

---

### H3b — Internet-facing process running from AppData\Roaming (prevalence + signature)

**Intent:** stage-3 behaviour independent of the IOCs: an executable in a user's roaming profile talking to
public IPs. Aggregated per binary (folder + hash) so a rare, unsigned binary on one device stands out
from a popular, signed updater on hundreds.

```kql
// IOC block above
let roaming_app_allowlist = dynamic([]);   // InitiatingProcessFileName values you have baselined, e.g. known per-user updaters
let roaming_connections =
  DeviceNetworkEvents
  | where Timestamp > ago(lookback)
  | where ActionType == "ConnectionSuccess"
  | where RemoteIPType == "Public"
  | where InitiatingProcessFolderPath has "Roaming"            // indexed pre-filter
  | where InitiatingProcessFolderPath contains @"\AppData\Roaming\"
  | where not(InitiatingProcessFileName in~ (roaming_app_allowlist))
  | project Timestamp, DeviceId, DeviceName, RemoteIP, RemoteUrl, RemotePort,
      InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA1,
      InitiatingProcessSHA256, InitiatingProcessAccountName, ReportId
  | summarize ConnCount = count(), Devices = dcount(DeviceId), Users = dcount(InitiatingProcessAccountName),
      FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
      RemoteHosts = make_set(RemoteUrl, 15), RemoteIPs = make_set(RemoteIP, 15),
      SampleDevice = any(DeviceName), (Timestamp, ReportId) = arg_max(Timestamp, ReportId)
      by InitiatingProcessFileName, InitiatingProcessSHA1
  | extend IocHit = array_length(set_intersect(RemoteIPs, ioc_ips)) > 0 or tostring(RemoteHosts) has_any (ioc_domains),
      MsbuildMasquerade = InitiatingProcessFileName =~ "upd.exe";
roaming_connections
| join kind=leftouter (
    DeviceFileCertificateInfo
    | where Timestamp > ago(lookback)
    | project Timestamp, SHA1, IsSigned, Signer, IsTrusted
    | summarize arg_max(Timestamp, IsSigned, Signer, IsTrusted) by SHA1
  ) on $left.InitiatingProcessSHA1 == $right.SHA1
| project-away SHA1, Timestamp1
| order by IocHit desc, Devices asc, IsTrusted asc, ConnCount desc
```

**Expected volume:** medium on first run (Teams classic, Discord, Zoom-style per-user apps mostly live in
`AppData\Local`, but `Roaming` still hosts some updaters and add-ins). Sort order puts IOC hits first,
then the rarest and unsigned binaries. Everything with `Devices > ~20` and `IsTrusted == true` is almost
certainly baseline; record it in `roaming_app_allowlist` with a justification.

**Narrow variant for earlier promotion:** keep only `InitiatingProcessFolderPath contains
@"\AppData\Roaming\msbuild\"` or `IsSigned == false and Devices <= 3`. The join means this can never be
NRT; it would run at 24 h / 30 d (prevalence needs the long lookback).

---

### H3c — Sentinel: exfil user agent / upload path in proxy or firewall logs

Endpoint telemetry does not expose HTTP method, path, or user agent for TLS sessions; this needs
proxy/web logs. Preferred source: ASIM web session (works across proxy vendors).

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips = dynamic(["203.0.113.45"]);
_Im_WebSession(starttime = ago(lookback), endtime = now())
| where HttpUserAgent has "UpdateChecker"
    or DstIpAddr in (ioc_ips)
    or Url has_any (ioc_domains)
    or (HttpRequestMethod == "POST" and Url has "api/upload")
| project TimeGenerated, SrcIpAddr, SrcUsername, SrcHostname, DstIpAddr, Url, HttpRequestMethod,
    HttpUserAgent, HttpStatusCode, DstBytes, SrcBytes, EventVendor, EventProduct
| order by TimeGenerated desc
```

Raw `CommonSecurityLog` fallback if the ASIM parser is not deployed:

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips = dynamic(["203.0.113.45"]);
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestClientApplication has "UpdateChecker"
    or DestinationIP in (ioc_ips)
    or RequestURL has_any (ioc_domains)
    or DestinationHostName has_any (ioc_domains)
    or (RequestMethod =~ "POST" and RequestURL has "api/upload")
| project TimeGenerated, SourceIP, SourceUserName, DestinationIP, DestinationHostName, RequestURL,
    RequestMethod, RequestClientApplication, SentBytes, ReceivedBytes, DeviceVendor, DeviceProduct
| order by TimeGenerated desc
```

**Caveat:** `/api/upload` with POST alone will match legitimate SaaS; it is only interesting combined
with the user agent, the IOC hosts, or a `SourceIP` that also appears in H1a/H2b hits.

---

### H4a — PowerShell writes an executable into AppData\Roaming

**Intent:** stage-2 drop. The downloaded script (running inside the cradle's PowerShell) writes
`upd.exe` under `Roaming\msbuild`. Generalised: any shell writing PE files into a roaming profile.

```kql
// IOC block above
let dropper_processes = dynamic(["powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe",
  "cscript.exe", "curl.exe", "certutil.exe", "bitsadmin.exe"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessFileName in~ (dropper_processes)
| where FolderPath has "Roaming"                       // indexed pre-filter
| where FolderPath contains @"\AppData\Roaming\"
| extend Ext = tolower(tostring(parse_path(FileName).Extension))
| where Ext in ("exe", "dll", "scr", "ps1", "bat", "cmd", "vbs", "js", "hta")
| extend IocHash = SHA256 in (ioc_sha256),
    IocPath = FolderPath contains ioc_payload_path,
    MsbuildFolder = FolderPath contains @"\AppData\Roaming\msbuild\"
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName,
    Ext, SHA256, FileSize, IocHash, IocPath, MsbuildFolder,
    InitiatingProcessCommandLine, InitiatingProcessUniqueId, ReportId
| order by IocPath desc, MsbuildFolder desc, Timestamp desc
```

**Expected volume:** low. A folder named `msbuild` under `Roaming` is itself a masquerade (real MSBuild
lives under Program Files / .NET), so `MsbuildFolder == true` is near-certain malicious even without the
hash.

**Benign lookalikes:** deployment scripts (Intune/ConfigMgr/RMM) that stage installers into the user
profile via PowerShell. Their `InitiatingProcessCommandLine` is usually recognisable (signed script path,
`-ExecutionPolicy Bypass -File ...`) and can be allowlisted by script path, not by device.

---

### H4b — Payload hash / path sweep across file, process and image-load telemetry

```kql
// IOC block above
union
  (DeviceFileEvents
   | where Timestamp > ago(lookback)
   | where SHA256 in (ioc_sha256) or (FolderPath has "msbuild" and FolderPath contains ioc_payload_path)
   | project Timestamp, DeviceId, DeviceName, Account = InitiatingProcessAccountName, ActionType, FolderPath,
       SHA256, Process = InitiatingProcessFileName, ReportId, Source = "File"),
  (DeviceProcessEvents
   | where Timestamp > ago(lookback)
   | where SHA256 in (ioc_sha256) or (FolderPath has "msbuild" and FolderPath contains ioc_payload_path)
   | project Timestamp, DeviceId, DeviceName, Account = AccountName, ActionType, FolderPath,
       SHA256, Process = InitiatingProcessFileName, ReportId, Source = "Process"),
  (DeviceImageLoadEvents
   | where Timestamp > ago(lookback)
   | where SHA256 in (ioc_sha256) or (FolderPath has "msbuild" and FolderPath contains ioc_payload_path)
   | project Timestamp, DeviceId, DeviceName, Account = InitiatingProcessAccountName, ActionType, FolderPath,
       SHA256, Process = InitiatingProcessFileName, ReportId, Source = "ImageLoad")
| order by Timestamp desc
```

Remember the hash-length problem noted in the IOC block; the path match carries this sweep until the hash
is corrected.

---

### H5 — Did Defender already alert on any of this?

```kql
// IOC block above
AlertEvidence
| where Timestamp > ago(lookback)
| where SHA256 in (ioc_sha256)
    or RemoteIP in (ioc_ips)
    or RemoteUrl has_any (ioc_domains)
    or (FolderPath has "msbuild" and FolderPath contains @"\AppData\Roaming\msbuild\")
    or (ProcessCommandLine has "headless" and ProcessCommandLine has "conhost")
    or ProcessCommandLine has_any (ioc_domains)
| project Timestamp, AlertId, Title, Severity, Category, DetectionSource, EntityType, EvidenceRole,
    DeviceName, AccountUpn, FileName, FolderPath, RemoteUrl, RemoteIP, ProcessCommandLine
| order by Timestamp desc
```

If this returns rows, start from those incidents rather than the raw hunts: the device scope and timeline
are already assembled.

---

### H6 — Users who clicked a link to the lure domains (Safe Links)

```kql
// IOC block above
UrlClickEvents
| where Timestamp > ago(lookback)
| where Url has_any (ioc_domains)
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, Workload, ThreatTypes, NetworkMessageId, ReportId
| order by Timestamp desc
```

ClickFix lures are often web-delivered (malvertising, compromised sites) rather than emailed, so an empty
result here does not clear the estate; it only tells you the email/Teams vector is quiet.

---

## 3. Sentinel notes

- With the Microsoft Defender XDR connector, the `Device*`, `AlertEvidence` and `UrlClickEvents` tables are
  available in Sentinel under the same names and columns (plus `TimeGenerated`). All the XDR queries above
  run unchanged there; replace `Timestamp > ago(lookback)` with `TimeGenerated > ago(lookback)` to get
  ingestion-time partition pruning and to reach beyond the 30-day Advanced Hunting window if your
  workspace retention is longer.
- H2c and H3c are Sentinel-only (SecurityEvent, CommonSecurityLog / ASIM).
- Fast IOC coverage without writing rules: load the domains, IP and (corrected) hash into the Sentinel TI
  store and confirm the `TI map ... to DeviceNetworkEvents` / `... to DeviceFileEvents` analytics rules are
  enabled. Same IOCs into Defender custom Indicators for block + alert on endpoint.
- Hunting-query YAML for the repo (`HuntingQueries/`), one file per hunt, minimum fields:

```yaml
id: <new GUID, stable forever>
name: PASTEJACK - conhost headless spawning shell with download cradle (H1a)
description: >
  Hunts for conhost.exe --headless launching a shell with a download cradle, the ClickFix stage-1
  chain described in the PASTEJACK advisory (2026-10-22). MITRE T1204.004, T1059.001, T1105.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes: [DeviceProcessEvents]
tactics: [Execution, CommandAndControl]
relevantTechniques: [T1204.004, T1059.001, T1105]
query: |
  <H1a query>
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
version: 1.0.0
```

---

## 4. Which hunts become detections, and what has to happen first

Decision rule applied: a hunt is a detection candidate only when its intent can be stated in one sentence
with a MITRE mapping (gate 1), it alerts at the entity level (gate 2), its tunables are hoisted (gate 3),
it passes the performance checklist (gate 4), and it can meet the XDR platform contract (gate 5). IOC-only
hunts (H3a, H4b, H5, H6) fail gate 1 for a *rule* (they are indicators, not behaviour) and are routed to
Indicators / TI instead.

| Hunt | Verdict | Platform / cadence | Blockers before deploy |
|------|---------|--------------------|------------------------|
| H1a | **Promote** | XDR custom detection. NRT-eligible (single table, no join/union/externaldata). Fallback: 1 h / 4 h | Run H1a over 30 d; every `HasCradle == true` row must be explained. Fixtures: tp, tn, empty (no threshold, so boundary = N/A). Strip comments for NRT. |
| H4a | **Promote** | XDR custom detection, NRT-eligible; or 1 h / 4 h | Baseline deployment scripts that drop PE files into Roaming; allowlist by script path inline (`let`) because NRT cannot read watchlists. |
| H2b | **Promote after baseline** | XDR custom detection, NRT-eligible if the allowlist stays inline; Sentinel scheduled (PT1H / PT4H) if the allowlist should live in a watchlist | One full pass of H2b + H2a over 30 d; every distinct `(TaskName, action path)` reviewed; `roaming_allowlist` populated with justification + expiry. |
| H1b | **Hunt first, promote if quiet** | XDR 1 h / 4 h or Sentinel scheduled | Expect admin one-liner noise; needs an `(account, pattern)` allowlist. Not NRT until the allowlist is stable. |
| H3b (narrow) | **Later** | XDR 24 h / 30 d (prevalence join rules out NRT) or Sentinel PT24H / P30D | Needs the signed/trusted join and prevalence threshold; expect first-run noise burst from the 30-day scan. |
| H2a, H2c, H3c | Corroboration / Sentinel-only | Sentinel scheduled if at all | H3c is IOC-fragile (user agent changes cost nothing); if deployed, give it an expiry. |
| H1c | No | — | Coverage unverified. |
| H3a, H4b, H5, H6 | No rule | Defender Indicators + Sentinel TI | Correct the SHA256 first. Set expiry on all indicators. |

### Detection-ready form of H1a (shows the XDR contract applied)

Scheduled variant (1 h / 4 h), aggregated to the device + account the analyst investigates:

```kql
let cradle_terms = dynamic(["irm", "iwr", "invoke-webrequest", "invoke-restmethod", "downloadstring",
  "downloadfile", "iex", "invoke-expression", "net.webclient", "start-bitstransfer", "frombase64string"]);
let shells = dynamic(["powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "curl.exe", "certutil.exe"]);
let conhost_allowlist = dynamic([]);   // grandparent executables baselined in H1a (e.g. an IDE); if the tenant rejects an empty list, delete the clause below until it has entries
DeviceProcessEvents
| where InitiatingProcessFileName =~ "conhost.exe"
| where InitiatingProcessCommandLine has "headless"
| where FileName in~ (shells)
| where not(InitiatingProcessParentFileName in~ (conhost_allowlist))
| extend Canon = replace_string(ProcessCommandLine, '"', '')
| where Canon has_any (cradle_terms)
| summarize (Timestamp, ReportId) = arg_max(Timestamp, ReportId), EventCount = count(),
    CommandLines = make_set(ProcessCommandLine, 5), GrandParents = make_set(InitiatingProcessParentFileName, 5)
    by DeviceId, DeviceName, AccountSid, AccountName
```

Contract points: no self-inflicted `Timestamp` filter (the service pre-filters to the lookback);
`Timestamp`, `ReportId`, `DeviceId`, `DeviceName` recovered after `summarize`; impacted assets = Device
(`DeviceId`) and Account (`AccountSid`), one column per entity type; process command lines go in as
related evidence / custom details. Expected alerts per run: 0-1, far below the 150 cap. First run scans
30 days back, so run the hunt form first and clear the baseline.

Continuous (NRT) variant: identical filters, drop the `summarize` and the comments, project
`Timestamp, ReportId, DeviceId, DeviceName, AccountSid, AccountName, ProcessCommandLine,
InitiatingProcessCommandLine`. The platform dedups identical entity + details within a run. Confirm the
operator subset at save time; if `has_any` or `replace_string` is rejected by NRT validation, fall back to
the 1 h / 4 h scheduled variant and record that decision in the rule YAML.

### Promotion checklist (per candidate)

1. Intent sentence + MITRE mapping written into the rule YAML (`DefenderDetections/` or `Detections/`).
2. Hunt run over 30 d; benign hits documented and turned into hoisted `let` allowlists (XDR) or a watchlist
   with `ExpiryDate` (Sentinel). Never a device-wide exclusion.
3. Unit fixtures under `tests/fixtures/<rule-id>/`: `tp.json` (the exact PASTEJACK chain from the report),
   `tn_*.json` (conhost --headless from the allowlisted tool; admin `irm` from a terminal, not Run;
   legitimate per-user updater task in Roaming), `empty.json`. Build the test queries with
   `scripts/kql_test_harness.py`; assert exact alert count and entity columns.
4. Performance review: resource indicator Low/Medium after a 30-day run; `has`/`in~` on raw columns before
   any `extend`/`parse_json`; joins explicit `kind=` with projected, time-bound inputs (H3b only).
5. Platform contract check (required columns, frequency/lookback pair, NRT restrictions) in CI lint.
6. Detection Change Record written (rule name/ID, reason = PASTEJACK advisory 2026-10-22, expected FP
   rate, rollback = disable rule), peer review, 7-day post-deploy review scheduled.

---

## 5. Things to verify in the tenant before trusting a "no results"

- `DeviceNetworkEvents` `DnsConnectionInspected` requires the network-protection DNS inspection feature;
  if absent, H3a DNS leg is silent (connection leg still works).
- `DeviceEvents` `ScheduledTaskCreated` requires a current MDE sensor; if H2b returns nothing but H2a
  shows task creations, the ActionType is not populated in your estate.
- `DeviceFileCertificateInfo` only has rows for files MDE has scanned; `IsTrusted` can be null for rare
  binaries, which is itself a signal in H3b.
- Sentinel H2c needs the "Other Object Access Events" audit subcategory enabled and forwarded.
- The report's SHA256 is 65 hex characters; a hash sweep with that value will never match. Fix before
  loading into Indicators / TI.
