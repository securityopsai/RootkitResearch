# Hunt pack: "PASTEJACK" ClickFix infostealer campaign

Source: threat advisory excerpt received 2026-10-22 (campaign observed 2026-10-20, three European customers).
Target platforms: Microsoft Defender XDR Advanced Hunting (primary) and Microsoft Sentinel (for data that only lives there: proxy/firewall, DNS, Windows Security auditing, TI matching, sign-in logs).

All queries are read-only. They were written from the report plus table knowledge; they have not been executed against a tenant, so expect to adjust a column name or two on first run (notes flag the places most likely to need it).

---

## 0. How to use this pack

**Run order (today):**
1. H01 (IOC sweep, all tables) — fastest answer to "are we hit?"
2. H02 (conhost --headless -> PowerShell cradle) — the report's strongest behavioural signal
3. H04 (scheduled task into AppData\Roaming) and H05 (payload path/hash)
4. H06 / H07 (C2 and exfil, endpoint and network layers)
5. H09 (chained signals per device) — turns the above into a ranked device list
6. H10 (follow-on: credential-theft artefacts and risky sign-ins for any user on a hit device)

**Time window:** Defender XDR Advanced Hunting keeps 30 days; every XDR query uses `let lookback = 30d;`. Sentinel retention is per-workspace, so the Sentinel variants use `ago(90d)` — lower it if your workspace is shorter. The campaign is two days old, but run the full window anyway: precursor lures and earlier waves are common.

**Shared IOC block** (paste at the top of any query that references it):

```kql
// --- PASTEJACK IOCs (from report, 2026-10-22). Rotate as new intel arrives. ---
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips     = dynamic(["203.0.113.45"]);
let ioc_sha256  = dynamic(["9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"]);
let ioc_ua      = "Mozilla/5.0 (compatible; UpdateChecker/1.0)";
let ioc_taskname = "OneDrive Sync Health";
let ioc_path_fragment = @"\AppData\Roaming\msbuild\";
let ioc_url_path = "/api/upload";
```

**Legend for the "Detection potential" line on each hunt:**
- `HIGH` — behaviour is specific enough to become a rule with light tuning
- `MEDIUM` — needs a baseline/allow-list or a second signal before it is alert-worthy
- `LOW / IOC-only` — hunt now, then push to indicators/TI rather than a KQL rule (indicators will rotate)

---

## H01 - IOC sweep across all XDR device tables

**Hypothesis:** Any device, process, file, or connection in the last 30 days that touched the reported hash, domains, IP, task name, or payload path.
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceEvents, DeviceImageLoadEvents, AlertEvidence
**MITRE:** T1105, T1053.005, T1071.001

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips     = dynamic(["203.0.113.45"]);
let ioc_sha256  = dynamic(["9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"]);
let ioc_taskname = "OneDrive Sync Health";
let ioc_path_fragment = @"\AppData\Roaming\msbuild\";
let proc = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where SHA256 in (ioc_sha256) or InitiatingProcessSHA256 in (ioc_sha256)
        or FolderPath has ioc_path_fragment or InitiatingProcessFolderPath has ioc_path_fragment
        or ProcessCommandLine has_any (ioc_domains) or ProcessCommandLine has ioc_taskname
        or ProcessCommandLine has ioc_path_fragment
    | extend Hit = "process", Detail = ProcessCommandLine;
let file = DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where SHA256 in (ioc_sha256) or FolderPath has ioc_path_fragment
        or FileOriginUrl has_any (ioc_domains) or FileOriginIP in (ioc_ips)
    | extend Hit = "file", Detail = strcat(ActionType, " ", FolderPath);
let net = DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteIP in (ioc_ips) or RemoteUrl has_any (ioc_domains)
        or InitiatingProcessFolderPath has ioc_path_fragment
    | extend Hit = "network", Detail = strcat(ActionType, " ", InitiatingProcessFileName, " -> ", coalesce(RemoteUrl, RemoteIP), ":", tostring(RemotePort));
let evt = DeviceEvents
    | where Timestamp > ago(lookback)
    | where SHA256 in (ioc_sha256) or FolderPath has ioc_path_fragment
        or AdditionalFields has ioc_taskname or AdditionalFields has ioc_path_fragment
        or RemoteUrl has_any (ioc_domains)
    | extend Hit = strcat("event:", ActionType), Detail = tostring(AdditionalFields);
let img = DeviceImageLoadEvents
    | where Timestamp > ago(lookback)
    | where SHA256 in (ioc_sha256) or FolderPath has ioc_path_fragment
    | extend Hit = "imageload", Detail = FolderPath;
union proc, file, net, evt, img
| project Timestamp, Hit, DeviceName, AccountName = coalesce(AccountName, InitiatingProcessAccountName), Detail, DeviceId, ReportId
| order by Timestamp desc
```

Also check whether Defender already alerted on any of it:

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips     = dynamic(["203.0.113.45"]);
let ioc_sha256  = dynamic(["9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"]);
AlertEvidence
| where Timestamp > ago(lookback)
| where SHA256 in (ioc_sha256) or RemoteIP in (ioc_ips) or RemoteUrl has_any (ioc_domains)
    or FolderPath has @"\AppData\Roaming\msbuild\"
| join kind=inner (AlertInfo | project AlertId, Title, Severity, Category, DetectionSource) on AlertId
| project Timestamp, AlertId, Title, Severity, Category, DetectionSource, DeviceName, EntityType, EvidenceRole
| order by Timestamp desc
```

**Triage:** Any row is a true positive until proven otherwise; these indicators have no legitimate use. Zero rows means "no known-IOC hit", not "not compromised" — go to H02.
**Detection potential:** `LOW / IOC-only`. Push the hash, domains and IP to Defender custom indicators (alert + block) and to Sentinel TI; do not build a KQL rule around values that will rotate.

---

## H02 - conhost.exe --headless spawning a PowerShell download cradle

**Hypothesis:** The ClickFix lure launches `conhost.exe --headless powershell.exe -w hidden -c "irm ... | iex"` from the Run dialog, so `conhost` (with `--headless`) will be the direct parent of a hidden PowerShell with a web cradle, and `explorer.exe` will be the grandparent.
**Tables:** DeviceProcessEvents
**MITRE:** T1204.004 (Malicious Copy and Paste), T1059.001, T1105, T1564.003

```kql
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "conhost.exe"
    and InitiatingProcessCommandLine has "--headless"
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "curl.exe", "certutil.exe", "bitsadmin.exe", "wscript.exe", "cscript.exe")
| extend cl = tolower(ProcessCommandLine)
| extend HasCradle = cl has_any ("irm", "invoke-restmethod", "iwr", "invoke-webrequest", "downloadstring", "downloadfile",
                                  "net.webclient", "iex", "invoke-expression", "start-bitstransfer", "frombase64string", "http://", "https://")
| extend HasEvasion = cl matches regex @"-w(indowstyle)?\s+h(idden)?\b" or cl has_any ("-nop", "-noprofile", "-ep bypass", "-executionpolicy bypass", "-enc", "-encodedcommand", "-noni")
| where HasCradle or HasEvasion
| extend Url = extract(@"(?i)(?:hxxps?|https?)://[^\s'""|;)]+", 0, ProcessCommandLine)
| extend FromRunDialog = InitiatingProcessParentFileName =~ "explorer.exe"
| project Timestamp, DeviceName, AccountName, FromRunDialog,
          GrandParent = InitiatingProcessParentFileName, Parent = InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, Url, HasCradle, HasEvasion, DeviceId, ReportId
| order by Timestamp desc
```

**Wider ClickFix net (the cradle string will change before the technique does):** anything interactive-shell-like launched directly by `explorer.exe` (Run dialog, File Explorer address bar) that contains a URL.

```kql
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "conhost.exe", "curl.exe", "certutil.exe", "bitsadmin.exe", "wscript.exe", "cscript.exe", "msiexec.exe", "rundll32.exe")
| where ProcessCommandLine matches regex @"(?i)(hxxps?|https?)://" or ProcessCommandLine has_any ("irm", "iwr", "iex", "downloadstring", "-enc", "frombase64string", "--headless")
| extend Url = extract(@"(?i)(?:hxxps?|https?)://[^\s'""|;)]+", 0, ProcessCommandLine)
| summarize Count = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Devices = dcount(DeviceId),
            Sample = any(ProcessCommandLine) by FileName, Url, AccountName, DeviceName
| order by Count asc, FirstSeen desc
```

**Optional - RunMRU evidence (verify coverage first):** the Run dialog records history under `HKCU\...\Explorer\RunMRU`. MDE's registry telemetry is selective; run this once and, if it never returns rows even for ordinary Run usage on a test box, the key is not collected and you should rely on the process-tree queries above (or Sysmon Event ID 13 in Sentinel).

```kql
let lookback = 30d;
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"\CurrentVersion\Explorer\RunMRU"
| where RegistryValueData has_any ("powershell", "pwsh", "conhost", "mshta", "curl", "irm ", "iwr ", "iex", "http", "--headless")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryValueName, RegistryValueData, DeviceId, ReportId
```

**Triage / FPs:** `conhost.exe --headless` on its own is normal — Windows Terminal, VS Code, OpenSSH, Python/Node subprocesses and some installers spawn it. The combination with a cradle or a hidden/`-nop`/`-enc` PowerShell is what matters; FPs there are rare and usually admin scripts or RMM tools (check `InitiatingProcessParentFileName`: if it is a service host or an RMM agent rather than `explorer.exe`, it is probably not a user pasting into Run). Pivot every hit into H05/H06 for the same `DeviceId` within +/- 10 minutes.
**Detection potential:** `HIGH`. The first query, restricted to `HasCradle == true`, is a good XDR custom detection candidate as-is (see section 11).

---

## H03 - Any download cradle hitting the reported infrastructure

**Hypothesis:** Even if the launch chain differs (e.g., pasted into Terminal instead of Run), a script will still fetch `v.txt` from the C2 domain.
**Tables:** DeviceProcessEvents, DeviceEvents (PowerShell script block telemetry)

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips     = dynamic(["203.0.113.45"]);
union
  (DeviceProcessEvents
   | where Timestamp > ago(lookback)
   | where ProcessCommandLine has_any (ioc_domains) or ProcessCommandLine has_any (ioc_ips) or ProcessCommandLine has "/v.txt"
   | extend Source = "cmdline", Content = ProcessCommandLine, Proc = FileName),
  (DeviceEvents
   | where Timestamp > ago(lookback)
   | where ActionType == "PowerShellCommand"
   | extend Content = tostring(parse_json(AdditionalFields).Command)
   | where Content has_any (ioc_domains) or Content has_any (ioc_ips) or Content has "/v.txt"
   | extend Source = "powershell", Proc = InitiatingProcessFileName)
| project Timestamp, Source, DeviceName, AccountName = coalesce(AccountName, InitiatingProcessAccountName), Proc, Content, DeviceId, ReportId
| order by Timestamp desc
```

**Triage / FPs:** none expected; `/v.txt` alone is generic so treat that clause as a lead, not a verdict.
**Detection potential:** `LOW / IOC-only` (covered by indicators once pushed).

---

## H04 - Scheduled task creation whose action points into a user's AppData\Roaming

**Hypothesis:** Persistence is a logon-triggered task named to look like OneDrive, with an action under `C:\Users\<user>\AppData\Roaming\msbuild\upd.exe`. Hunt both the `schtasks.exe` command line and the task-creation event (catches tasks created via API/COM without `schtasks.exe`).
**Tables:** DeviceProcessEvents, DeviceEvents (`ScheduledTaskCreated` / `ScheduledTaskUpdated`); Sentinel SecurityEvent 4698
**MITRE:** T1053.005, T1036.004

**4a - schtasks.exe command line (XDR):**

```kql
let lookback = 30d;
let ioc_taskname = "OneDrive Sync Health";
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has_any ("/create", "/change")
| where ProcessCommandLine matches regex @"(?i)\\AppData\\Roaming\\" or ProcessCommandLine has ioc_taskname
| extend TaskName   = extract(@"(?i)/tn\s+""?([^""]+?)""?\s+/", 1, ProcessCommandLine),
         TaskAction = extract(@"(?i)/tr\s+""?([^""]+?)""?(\s+/|$)", 1, ProcessCommandLine),
         Trigger    = extract(@"(?i)/sc\s+(\w+)", 1, ProcessCommandLine)
| extend NamedIOC = ProcessCommandLine has ioc_taskname
| project Timestamp, DeviceName, AccountName, NamedIOC, TaskName, Trigger, TaskAction,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine, ProcessCommandLine, DeviceId, ReportId
| order by NamedIOC desc, Timestamp desc
```

**4b - task registration event (XDR, catches non-schtasks creation):**

```kql
let lookback = 30d;
let ioc_taskname = "OneDrive Sync Health";
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated")
| extend af = parse_json(AdditionalFields)
| extend TaskName = tostring(af.TaskName), TaskContent = tostring(af.TaskContent)
| where TaskContent has @"\AppData\Roaming\" or TaskName has ioc_taskname
| extend TaskExec = extract(@"(?i)<Command>([^<]+)</Command>", 1, TaskContent),
         TaskArgs = extract(@"(?i)<Arguments>([^<]+)</Arguments>", 1, TaskContent),
         LogonTrigger = TaskContent has "<LogonTrigger>"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, TaskName, LogonTrigger, TaskExec, TaskArgs,
          InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| order by Timestamp desc
```

**4c - Sentinel, Windows Security auditing (needs "Audit Other Object Access Events" enabled; Event 4698 lands in SecurityEvent via AMA/Defender for Servers):**

```kql
SecurityEvent
| where TimeGenerated > ago(90d)
| where EventID in (4698, 4702)   // task created / updated
| extend TaskName = extract(@"Task Name:\s*(\S.*?)\r?\n", 1, EventData),
         TaskContent = extract(@"<Task .*</Task>", 0, EventData)
| where TaskContent has @"\AppData\Roaming\" or TaskName has "OneDrive Sync Health"
| extend TaskExec = extract(@"(?i)<Command>([^<]+)</Command>", 1, TaskContent),
         LogonTrigger = TaskContent has "<LogonTrigger>"
| project TimeGenerated, Computer, SubjectUserName, EventID, TaskName, LogonTrigger, TaskExec
| order by TimeGenerated desc
```

If you ship Sysmon to Sentinel instead, swap in `Event | where EventID == 1 and RenderedDescription has "schtasks"` with the same regexes.

**Triage / FPs:** Legitimate per-user updaters register tasks under AppData, but they overwhelmingly use `AppData\Local` (Teams, Zoom, Discord, Spotify, OneDrive's own "OneDrive Standalone Update Task"). `AppData\Roaming` task actions are rarer; expect a short tail of things like Dropbox, some Electron apps, and custom scripts. Baseline with this before promoting:

```kql
DeviceEvents
| where Timestamp > ago(30d) and ActionType == "ScheduledTaskCreated"
| extend af = parse_json(AdditionalFields)
| extend TaskContent = tostring(af.TaskContent)
| where TaskContent has @"\AppData\Roaming\"
| extend TaskExec = extract(@"(?i)<Command>([^<]+)</Command>", 1, TaskContent)
| extend ExecNorm = replace_regex(tolower(TaskExec), @"c:\\users\\[^\\]+\\", @"c:\users\<user>\")
| summarize Devices = dcount(DeviceId), Count = count(), Creators = make_set(InitiatingProcessFileName, 10) by ExecNorm
| order by Devices desc
```

Anything with high device count is fleet software -> allow-list by normalised path. Low-prevalence, logon-triggered, and created by `schtasks.exe` under a `powershell.exe` parent is the shape of this campaign.
**Detection potential:** `MEDIUM -> HIGH` after baseline. Combination "task action in AppData\Roaming AND (LogonTrigger OR parent is powershell/cmd/mshta)" is rule-worthy.

---

## H05 - Payload drop: executables written under AppData\Roaming by a scripting host

**Hypothesis:** The downloaded script writes `upd.exe` into a fresh `%APPDATA%\msbuild\` directory. Hunt the exact path/hash and the generic pattern (a script host creating a PE in a new AppData\Roaming sub-folder).
**Tables:** DeviceFileEvents, DeviceProcessEvents, FileProfile()
**MITRE:** T1105, T1036.005

**5a - exact IOC plus any file in that folder:**

```kql
let lookback = 30d;
let ioc_sha256 = dynamic(["9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where SHA256 in (ioc_sha256)
    or FolderPath matches regex @"(?i)\\AppData\\Roaming\\msbuild\\"
    or (FileName =~ "upd.exe" and FolderPath has @"\AppData\Roaming\")
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256, FileOriginUrl, FileOriginReferrerUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, DeviceId, ReportId
| order by Timestamp desc
```

**5b - generic: PE dropped into AppData\Roaming by PowerShell/mshta/etc., enriched with prevalence and signer:**

```kql
let lookback = 30d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath matches regex @"(?i)^c:\\users\\[^\\]+\\appdata\\roaming\\[^\\]+\\[^\\]+\.(exe|dll|scr|com)$"
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe",
                                       "curl.exe", "certutil.exe", "bitsadmin.exe", "cmd.exe", "conhost.exe", "rundll32.exe")
| where isnotempty(SHA256)
| summarize arg_max(Timestamp, *) by DeviceId, SHA256
| invoke FileProfile("SHA256", 1000)
| where isempty(Signer) or IsCertificateValid != true or GlobalPrevalence < 50
| extend PathNorm = replace_regex(tolower(FolderPath), @"c:\\users\\[^\\]+\\", @"c:\users\<user>\")
| project Timestamp, DeviceName, PathNorm, SHA256, GlobalPrevalence, GlobalFirstSeen, Signer, IsCertificateValid,
          FileOriginUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| order by GlobalPrevalence asc, Timestamp desc
```

**5c - execution of anything from that folder (the task fires at logon):**

```kql
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FolderPath matches regex @"(?i)\\AppData\\Roaming\\msbuild\\"
    or (FileName =~ "upd.exe" and FolderPath has @"\AppData\Roaming\")
| project Timestamp, DeviceName, AccountName, FolderPath, SHA256, ProcessCommandLine,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine, DeviceId, ReportId
| order by Timestamp desc
```

**Triage / FPs:** 5a: none expected (real MSBuild never lives in AppData\Roaming). 5b: unsigned/low-prevalence binaries written by script hosts into AppData\Roaming will include some dev tooling and portable apps; the `FileOriginUrl` column and the writing process' parent usually settle it quickly. `FileProfile()` is capped at 1,000 rows per query, hence the `summarize` first.
**Detection potential:** 5a `LOW / IOC-only`; 5b `MEDIUM` (good as a scheduled custom detection with `GlobalPrevalence < 10` and a signer allow-list); 5c is covered by indicators.

---

## H06 - Endpoint network: C2 / exfil to the listed infrastructure and from AppData\Roaming processes

**Hypothesis:** The implant beacons over HTTPS to the two domains/IP and POSTs stolen credentials to `/api/upload`; the initiating process lives in `AppData\Roaming`.
**Tables:** DeviceNetworkEvents (connection events plus DNS/HTTP inspection events where enabled)
**MITRE:** T1071.001, T1041

**6a - connections to IOC infrastructure:**

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips     = dynamic(["203.0.113.45"]);
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteIP in (ioc_ips) or RemoteUrl has_any (ioc_domains)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Connections = count(),
            Actions = make_set(ActionType), Ports = make_set(RemotePort),
            Processes = make_set(strcat(InitiatingProcessFolderPath, " | ", InitiatingProcessSHA256), 10)
          by DeviceId, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP
| order by FirstSeen asc
```

**6b - DNS resolutions (network-inspection events; populated only on builds where MDE's DNS inspection is active):**

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "DnsConnectionInspected"
| extend af = parse_json(AdditionalFields)
| extend Query = tostring(af.query), Answers = tostring(af.answers)    // validate field names on first run
| where Query has_any (ioc_domains) or Answers has "203.0.113.45"
| project Timestamp, DeviceName, Query, Answers, InitiatingProcessFileName, InitiatingProcessFolderPath, DeviceId, ReportId
```

**6c - User agent / URI (only visible to the endpoint if the exfil is cleartext HTTP; the report is ambiguous, so try it, but expect the real answer from the proxy in H07):**

```kql
let lookback = 30d;
let ioc_ua = "UpdateChecker/1.0";
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "HttpConnectionInspected"
| extend af = parse_json(AdditionalFields)
| extend Host = tostring(af.host), Uri = tostring(af.uri), Method = tostring(af.method), UserAgent = tostring(af.user_agent)   // validate field names
| where UserAgent has ioc_ua or (Method =~ "POST" and Uri has "/api/upload")
| project Timestamp, DeviceName, Method, Host, Uri, UserAgent, InitiatingProcessFileName, InitiatingProcessFolderPath, DeviceId, ReportId
```

**6d - behavioural: any process running from AppData\Roaming talking to the internet, stacked by binary:**

```kql
let lookback = 30d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType in ("ConnectionSuccess", "ConnectionRequest", "ConnectionFailed")
| where RemoteIPType == "Public"
| where InitiatingProcessFolderPath matches regex @"(?i)^c:\\users\\[^\\]+\\appdata\\roaming\\"
| extend PathNorm = replace_regex(tolower(InitiatingProcessFolderPath), @"c:\\users\\[^\\]+\\", @"c:\users\<user>\")
| summarize Devices = dcount(DeviceId), Users = dcount(InitiatingProcessAccountName), Connections = count(),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Destinations = make_set(coalesce(RemoteUrl, RemoteIP), 15), SHA256 = any(InitiatingProcessSHA256)
          by PathNorm
| invoke FileProfile("SHA256", 1000)
| project PathNorm, Devices, Users, Connections, FirstSeen, LastSeen, GlobalPrevalence, Signer, IsCertificateValid, Destinations
| order by Devices asc, GlobalPrevalence asc
```

**Triage / FPs:** 6a-6c: none expected. 6d is noisy by design: Teams (classic), Zoom, Slack, Discord, Spotify, Dropbox and many Electron apps run from AppData\Roaming. Work from the bottom of the list: 1-2 devices, unsigned or low prevalence, newly first-seen, destinations that are bare IPs or freshly registered domains. Allow-list by `PathNorm` + `Signer`.
**Detection potential:** 6a-6c `LOW / IOC-only` -> indicators. 6d `MEDIUM`: viable as a scheduled rule once an allow-list of signed/high-prevalence paths exists; pair it with H04 or H05 on the same device for a `HIGH`-fidelity chained rule (see H09).

---

## H07 - Sentinel network layer: proxy, firewall, DNS, ASIM, TI match

**Hypothesis:** The C2 and exfil traffic (including the custom User-Agent and the `/api/upload` POST) is visible at the egress proxy/firewall and in DNS, which also covers unmanaged or non-MDE hosts.
**Tables:** CommonSecurityLog, ASIM (`_Im_WebSession`, `_Im_Dns`, `_Im_NetworkSession`), DnsEvents / ASimDnsActivityLogs, ThreatIntelligenceIndicator / ThreatIntelIndicators
**MITRE:** T1071.001, T1041

**7a - CEF-based proxy / firewall:**

```kql
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let ioc_ips     = dynamic(["203.0.113.45"]);
let ioc_ua = "UpdateChecker/1.0";
CommonSecurityLog
| where TimeGenerated > ago(90d)
| where DestinationIP in (ioc_ips)
    or DestinationHostName has_any (ioc_domains)
    or RequestURL has_any (ioc_domains)
    or RequestClientApplication has ioc_ua
    or (RequestMethod =~ "POST" and RequestURL has "/api/upload")
| project TimeGenerated, DeviceVendor, DeviceProduct, SourceIP, SourceUserName, DestinationIP, DestinationHostName,
          DestinationPort, RequestMethod, RequestURL, RequestClientApplication, DeviceAction, SentBytes
| order by TimeGenerated desc
```

**7b - ASIM parsers (vendor-agnostic; use these if your ASIM parsers are deployed):**

```kql
// Web sessions: host, URL, UA, method
_Im_WebSession(starttime=ago(90d), endtime=now(), url_has_any=dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]))
| project TimeGenerated, SrcIpAddr, SrcUsername, DstIpAddr, Url, HttpRequestMethod, HttpUserAgent, EventResult, DstBytes, SrcBytes
| union (
  _Im_WebSession(starttime=ago(90d), endtime=now())
  | where HttpUserAgent has "UpdateChecker/1.0" or (HttpRequestMethod =~ "POST" and Url has "/api/upload")
  | project TimeGenerated, SrcIpAddr, SrcUsername, DstIpAddr, Url, HttpRequestMethod, HttpUserAgent, EventResult, DstBytes, SrcBytes)
| order by TimeGenerated desc
```

```kql
// DNS
_Im_Dns(starttime=ago(90d), endtime=now(), domain_has_any=dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]))
| union (_Im_Dns(starttime=ago(90d), endtime=now(), response_has_any_prefix=dynamic(["203.0.113.45"])))
| project TimeGenerated, SrcIpAddr, SrcHostname, DnsQuery, DnsResponseName, DnsResponseCodeName, Dvc
| order by TimeGenerated desc
```

```kql
// Network sessions (firewall / NSG flow)
_Im_NetworkSession(starttime=ago(90d), endtime=now(), dstipaddr_has_any_prefix=dynamic(["203.0.113.45"]))
| project TimeGenerated, SrcIpAddr, SrcHostname, DstIpAddr, DstPortNumber, NetworkProtocol, DvcAction, SrcBytes, DstBytes, Dvc
| order by TimeGenerated desc
```

**7c - Legacy DNS table (if you still collect via the DNS Analytics / DNS via AMA connector):**

```kql
DnsEvents
| where TimeGenerated > ago(90d)
| where Name has_any ("cdn-updates-check.com", "telemetry-sync-cloud.net") or IPAddresses has "203.0.113.45"
| project TimeGenerated, Computer, ClientIP, Name, IPAddresses, QueryType
```

**7d - Threat intelligence matching (after you import the IOCs as TI; use whichever TI table your workspace has):**

```kql
let ti = union isfuzzy=true
    (ThreatIntelligenceIndicator
       | where TimeGenerated > ago(90d) and Active == true
       | where Description has "PASTEJACK" or Tags has "PASTEJACK"
       | extend Indicator = coalesce(DomainName, NetworkIP, NetworkDestinationIP, FileHashValue)),
    (ThreatIntelIndicators
       | where TimeGenerated > ago(90d) and IsActive == true
       | where tostring(Data) has "PASTEJACK"
       | extend Indicator = ObservableValue)
    | distinct Indicator;
union isfuzzy=true
    (CommonSecurityLog | where TimeGenerated > ago(90d) | extend Obs = DestinationIP),
    (CommonSecurityLog | where TimeGenerated > ago(90d) | extend Obs = DestinationHostName),
    (DeviceNetworkEvents | where TimeGenerated > ago(30d) | extend Obs = RemoteIP),
    (DeviceNetworkEvents | where TimeGenerated > ago(30d) | extend Obs = RemoteUrl),
    (DeviceFileEvents | where TimeGenerated > ago(30d) | extend Obs = SHA256)
| where isnotempty(Obs) and Obs in~ (ti)
| project TimeGenerated, Type, Obs, DeviceName, SourceIP, DestinationIP
```

**Triage / FPs:** none expected for the IOCs; the User-Agent clause is specific enough to stand on its own. Note the UA and `/api/upload` are only visible if your proxy performs TLS inspection; without it you will see only the SNI/hostname.
**Detection potential:** `LOW / IOC-only` for domains/IP (handled by Sentinel's built-in TI-map analytics rules once indicators are imported). The **User-Agent** `UpdateChecker/1.0` is `MEDIUM`: a scheduled Sentinel rule on `HttpUserAgent` is cheap and will outlive the current domains.

---

## H08 - Delivery: did the lure domain or C2 appear in email or in URL clicks?

**Hypothesis:** The ClickFix page or a redirect to it was delivered by email, or users clicked through Safe Links to the reported domains.
**Tables:** EmailUrlInfo, EmailEvents, UrlClickEvents

```kql
let lookback = 30d;
let ioc_domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let clicks = UrlClickEvents
    | where Timestamp > ago(lookback)
    | where Url has_any (ioc_domains)
    | project Timestamp, Hit = "click", AccountUpn, Url, ActionType, IsClickedThrough, Workload, NetworkMessageId;
let mail = EmailUrlInfo
    | where Timestamp > ago(lookback)
    | where Url has_any (ioc_domains) or UrlDomain in~ (ioc_domains)
    | join kind=inner (EmailEvents | where Timestamp > ago(lookback)
                       | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, ThreatTypes) on NetworkMessageId
    | project Timestamp, Hit = "email", AccountUpn = RecipientEmailAddress, Url, ActionType = DeliveryAction, Subject, SenderFromAddress, ThreatTypes, NetworkMessageId;
union clicks, mail
| order by Timestamp desc
```

**Triage / FPs:** none expected. If empty, the lure most likely arrived via web (malvertising, compromised site), which is typical for ClickFix; H02's `explorer.exe`-parent query is then the earliest visible point.
**Detection potential:** `LOW / IOC-only` (Defender for Office URL indicators).

---

## H09 - Chained signals per device (ranked device list)

**Hypothesis:** A truly compromised device shows two or more of: headless-conhost cradle (H02), PE dropped in AppData\Roaming by a script host (H05), task action in AppData\Roaming (H04), public connections from an AppData\Roaming process (H06d). Stacking them removes almost all FPs from each individual signal.
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceEvents, DeviceNetworkEvents

```kql
let lookback = 30d;
let window = 2h;
let s_cradle = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessFileName =~ "conhost.exe" and InitiatingProcessCommandLine has "--headless"
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any ("irm", "iwr", "iex", "downloadstring", "invoke-webrequest", "invoke-restmethod", "invoke-expression")
    | project DeviceId, DeviceName, T = Timestamp, Signal = "H02_cradle", Detail = ProcessCommandLine;
let s_drop = DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType in ("FileCreated", "FileRenamed", "FileModified")
    | where FolderPath matches regex @"(?i)\\AppData\\Roaming\\[^\\]+\\[^\\]+\.(exe|dll)$"
    | where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "cmd.exe")
    | project DeviceId, DeviceName, T = Timestamp, Signal = "H05_drop", Detail = FolderPath;
let s_task = union
    (DeviceProcessEvents
       | where Timestamp > ago(lookback)
       | where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create" and ProcessCommandLine has @"\AppData\Roaming\"
       | project DeviceId, DeviceName, T = Timestamp, Signal = "H04_task", Detail = ProcessCommandLine),
    (DeviceEvents
       | where Timestamp > ago(lookback)
       | where ActionType == "ScheduledTaskCreated" and AdditionalFields has @"\AppData\Roaming\"
       | project DeviceId, DeviceName, T = Timestamp, Signal = "H04_task", Detail = tostring(parse_json(AdditionalFields).TaskName));
let s_net = DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where ActionType in ("ConnectionSuccess", "ConnectionRequest") and RemoteIPType == "Public"
    | where InitiatingProcessFolderPath matches regex @"(?i)\\AppData\\Roaming\\"
    | project DeviceId, DeviceName, T = Timestamp, Signal = "H06_net", Detail = strcat(InitiatingProcessFolderPath, " -> ", coalesce(RemoteUrl, RemoteIP));
union s_cradle, s_drop, s_task, s_net
| summarize Signals = make_set(Signal), SignalCount = dcount(Signal), FirstSeen = min(T), LastSeen = max(T),
            Details = make_set(Detail, 12) by DeviceId, DeviceName, bin(T, window)
| where SignalCount >= 2
| order by SignalCount desc, FirstSeen desc
```

**Triage / FPs:** very low. `H05_drop + H06_net` alone can be a self-updating app; `H02_cradle` or `H04_task` in the set is the strong tell. Any device with 3+ signals goes straight to IR.
**Detection potential:** `HIGH`. This is the best rule candidate in the pack: run it as a scheduled XDR custom detection (every 1h, 2h window) with `SignalCount >= 2` and `Signals has "H02_cradle" or Signals has "H04_task"`.

---

## H10 - Follow-on: credential theft artefacts and account exposure

Run for every user/device surfaced by H01-H09.

**10a - browser credential stores copied by a non-browser process (stealers copy the locked DB before reading it):**

```kql
let lookback = 30d;
let cred_files = dynamic(["Login Data", "Login Data For Account", "Cookies", "Web Data", "Local State", "key4.db", "logins.json", "cookies.sqlite", "places.sqlite"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName in~ (cred_files) or (FileName endswith ".db" and FolderPath has_any ("Login Data", "Cookies"))
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "msedgewebview2.exe",
                                        "OneDrive.exe", "MsMpEng.exe", "SearchProtocolHost.exe", "backgroundTaskHost.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ActionType, FolderPath, DeviceId, ReportId
| order by Timestamp desc
```

**10b - Sentinel: risky / anomalous sign-ins for affected users (replace the list with H09 output):**

```kql
let affected_users = dynamic(["user1@contoso.com", "user2@contoso.com"]);   // from H09 / H02 AccountName -> UPN
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName in~ (affected_users)
| where RiskLevelDuringSignIn in ("medium", "high") or RiskState == "atRisk"
    or ResultType == 0 and isnotempty(Location) and Location !in ("GB", "DE", "FR", "NL")   // adjust to your countries
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, RiskLevelDuringSignIn, RiskEventTypes_V2, ResultType, UserAgent, DeviceDetail
| order by TimeGenerated desc
```

Also check `AADSignInEventsBeta` in XDR if you do not have SigninLogs in Sentinel, and `IdentityInfo` for the users' privilege level.

**Triage:** 10a has a tail of backup agents and sync clients; filter on the initiating process path (anything under AppData\Roaming or Temp is suspicious). 10b: any new-country or risky sign-in for an H09 user -> reset password, revoke sessions, rotate browser-saved secrets.
**Detection potential:** 10a `MEDIUM` (works as a rule when restricted to initiating process in user-writable paths); 10b is identity-protection territory, covered by Entra ID Protection rules.

---

## 11. Detection promotion matrix

| Hunt | Signal | Fidelity today | Where to build | Trigger / frequency | Tuning needed before go-live | Promote? |
|---|---|---|---|---|---|---|
| H01, H03, H05a, H05c, H06a-c, H07a-d, H08 | Hash / domains / IP / task name / path | High but perishable | Defender **custom indicators** (file, IP, URL/domain; alert + block) and Sentinel **TI import** (STIX/upload API) with existing TI-map analytics rules | Continuous | None; set expiry (30-60 days) and tag `PASTEJACK` | Yes, as indicators, not KQL rules |
| **H02** (first query, `HasCradle == true`) | `conhost --headless` -> PowerShell cradle | High | **XDR custom detection** (device tables, single table, no FileProfile) | NRT (continuous) | Exclude RMM/admin parents by `InitiatingProcessParentFileName` if seen in baseline | **Yes, first** |
| H02 wider net (`explorer.exe` -> shell with URL) | Generic ClickFix | Medium | XDR custom detection | Every 1h | Allow-list known internal portals/URLs in cmdline | Yes, after one week of hunting results |
| **H04** (4b + 4a) | Task action in AppData\Roaming, logon trigger or script-host parent | Medium -> High | XDR custom detection (DeviceEvents) and/or Sentinel scheduled rule on SecurityEvent 4698 for servers | Every 1h | Allow-list normalised `TaskExec` paths with `Devices > N` from the baseline query | Yes |
| H05b | Script host writes low-prevalence PE into AppData\Roaming | Medium | XDR custom detection (scheduled, uses FileProfile so not NRT) | Every 3h | `GlobalPrevalence < 10`, signer allow-list | Yes, as medium severity |
| H06d | AppData\Roaming process -> public internet | Low alone | Do not alert alone; feed into H09 | - | Signer / path allow-list | Only via H09 |
| H07 UA | `UpdateChecker/1.0` User-Agent (proxy/ASIM) | High | **Sentinel scheduled analytics rule** on `_Im_WebSession` / CommonSecurityLog | Every 1h, 1h lookback | None; add future campaign UAs to a watchlist and swap `has` for `has_any (watchlist)` | Yes |
| **H09** | 2+ chained signals on one device in 2h | High | **XDR custom detection** (scheduled) with automated response: isolate device, collect investigation package | Every 1h | Require `H02_cradle` or `H04_task` in the set | **Yes** |
| H10a | Non-browser process copies browser credential DBs | Medium | XDR custom detection | Every 1h | Restrict initiating path to user-writable dirs; allow-list backup agents | Yes, medium severity |
| H10b | Risky sign-in for affected users | n/a | Entra ID Protection / existing Sentinel identity rules | - | - | Already covered |

Notes for the rule-builders:
- XDR custom detections on device tables must project `Timestamp`, `DeviceId`, `ReportId`; the queries above already carry them (drop the `summarize` steps or re-add those columns after aggregation).
- NRT frequency requires a single-table query with no joins/unions/`FileProfile`; H02 qualifies, H09 and H05b do not and must run on a schedule.
- For Sentinel scheduled rules, set lookback = frequency (or slightly more) and map entities (Host, Account, Process, URL, IP) so incidents stitch together across the H02/H04/H07 rules.
- Put the IOCs in a Sentinel watchlist (`PASTEJACK_IOCs`) if you want the KQL in this pack to keep working after you rotate indicators: replace the `let ioc_* = dynamic([...])` lines with `_GetWatchlist('PASTEJACK_IOCs') | where Type == "domain" | project Value`.

---

## 12. Actions alongside the hunt

1. Push indicators now: SHA256, both domains, the IP (Defender XDR > Settings > Endpoints > Indicators; also Defender for Office URL indicator). Tag `PASTEJACK`, 60-day expiry, action = block + alert.
2. Import the same IOCs into Sentinel TI so the built-in TI-map rules fire for non-MDE sources (proxy, DNS, firewall).
3. There is no ASR rule that blocks `conhost.exe --headless` -> `powershell.exe` directly. Instead, confirm the ASR rules "Block execution of potentially obfuscated scripts" and "Block JavaScript or VBScript from launching downloaded executable content" are in block mode, and consider the "Prevent access to Run" GPO (or Windows Terminal-only shells) for high-risk user groups.
4. For any H09 device: isolate, collect investigation package, dump the scheduled task XML and `%APPDATA%\msbuild\`, reset the user's credentials and revoke refresh tokens, and force password rotation for anything saved in the browser.
5. User comms: short notice about "verify you are human / paste this into Run" lures.

---

## 13. Assumptions and coverage gaps

- The report's hash is explicitly fictional/placeholder and will differ per build; behaviour (H02, H04, H09) is what will generalise.
- `DnsConnectionInspected` / `HttpConnectionInspected` events and their `AdditionalFields` keys depend on MDE network-inspection being active on the device OS build; validate 6b/6c field names on the first run and expect no HTTP data if exfil is TLS.
- `RunMRU` registry collection by MDE is not guaranteed; the process-tree queries do not depend on it.
- Sentinel 4698 coverage requires the "Other Object Access Events" audit subcategory; without it, use DeviceEvents (H04b) for MDE-onboarded hosts.
- The User-Agent and `/api/upload` hunts assume TLS inspection at the proxy; without it only hostname/SNI matches (7a/7b hostname clauses) will return.
- Regexes on `schtasks` command lines assume quoted `/tn` and `/tr` arguments; unquoted single-token task names still match via the `has` clause.
- No tenant access was available while writing this pack, so no query has been executed; all column names are from current Defender XDR / Sentinel schemas as of the date above.
