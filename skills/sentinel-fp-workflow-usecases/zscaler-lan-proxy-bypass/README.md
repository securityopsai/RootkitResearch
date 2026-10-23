# Zscaler bypass via a local LAN proxy — detection rules

Use case: a user (or an attacker on the endpoint) points the browser or the system proxy at another host
on the local network, and that host egresses to the internet directly. Web traffic never reaches Zscaler
Internet Access, so URL filtering, SSL inspection, DLP and the ZIA web log all go dark for that device.
Zscaler Client Connector keeps running and reporting healthy, which is what makes this bypass attractive.

Four Defender XDR custom detections plus one Sentinel scheduled rule, written with the
`sentinel-fp-workflow` skill. All four `.kql` files pass the skill's lint with zero warnings; the Sentinel
YAML parses and every entity, custom-detail and placeholder column exists in the final projection.
**Nothing here has been run against a tenant.** The preflight queries in §6 come first.

## 1. Environment assumptions (mark and confirm)

| Item | Assumed | Why it matters |
|---|---|---|
| ZCC forwarding profile excludes RFC1918 destinations from the tunnel | `[ASSUMED]` | If LAN traffic is tunnelled too, the bypass does not work and D2/D3 will mostly see sanctioned proxies |
| ZCC runs in tunnel mode; its local listener is on loopback (127.0.0.1) | `[ASSUMED, VERIFY ports]` | D2 relies on `RemoteIPType == "Private"`, which excludes loopback by design |
| MDE collects `Internet Settings` and browser policy registry keys | `[VERIFY]` with preflight P1 | D1a is blind if the keys are not in the collected set |
| Zeek inspection (`HttpConnectionInspected`) is on | `[VERIFY]` with preflight P2 | The CONNECT signal in D2 depends on it; it is sampled |
| Zscaler NSS web logs are in Sentinel (`CommonSecurityLog`, DeviceVendor "Zscaler") | `[ASSUMED: no]` | Enables the conditional coverage-gap rule in §5 |
| Proxy host candidates may not be onboarded (personal laptop, Pi, phone hotspot) | `[ASSUMED]` | D3 only sees onboarded hosts; D2 is the client-side safety net |

## 2. The rules

| Rule | Table(s) | Frequency | NRT-eligible | Keys on | Severity |
|---|---|---|---|---|---|
| D1a Proxy configuration set to a LAN host | DeviceRegistryEvents | 1 h (4 h lookback) | Yes | private IPv4 or single-label host in `ProxyServer` / `AutoConfigURL` / browser policy values | Medium |
| D1b Proxy set on a command line | DeviceProcessEvents | 1 h | Yes | `--proxy-server` / `--proxy-pac-url`, `netsh winhttp set proxy`, `reg add ProxyServer`, PowerShell proxy settings, with a private IPv4 | Medium |
| D2 Browser traffic to a rare LAN proxy | DeviceNetworkEvents | 1 h | No (union + join) | ≥ 25 browser connections to a private IP on a proxy port, or ≥ 5 HTTP CONNECT to a private IP, destination used by ≤ 3 devices | Medium / High (CONNECT) |
| D3 LAN host acting as a proxy | DeviceNetworkEvents | 1 h | No (join) | ≥ 3 distinct private peers accepted on a proxy port by one device; listener process as context | Medium |
| D2-Sentinel (YAML) | DeviceNetworkEvents via XDR connector | PT1H / PT2H with `ingestion_time()` run window | n/a | same as D2, watchlist `ApprovedProxies` | data-driven |

MITRE: **T1090.001 Proxy: Internal Proxy** (the behaviour every rule asserts) and **T1562.001 Impair
Defenses** (the effect: the security control is bypassed). D1a additionally touches T1112 Modify Registry;
it is not the primary mapping because the registry write is the means, not the behaviour.

Permission required to execute the technique: standard user. Chrome and Edge command-line proxy flags
override the system proxy without admin rights; WinINET `ProxyServer` is per-user (HKCU). Only policy keys
under HKLM need admin.

Why not one correlated rule: the configuration signals (D1a/D1b) are high-precision and NRT-eligible; the
network signal (D2) catches configurations the first two cannot see (Firefox prefs, FQDN proxies, extension
proxies, PAC files hosted on the LAN). Keeping them separate preserves NRT latency for the sharp signals
and lets the platform group them into one incident per device.

## 3. Platform contract (XDR)

- All four queries return `Timestamp`, `ReportId`, `DeviceId`, `DeviceName` after aggregation (`arg_min`
  for configuration events so the alert points at the first change; `arg_max` for network aggregates).
- No rule filters the recent window on `Timestamp`; the service evaluates the 4 h lookback on
  `ingestion_time()`. There is no baseline half in these rules, so no `Timestamp between (...)` either.
- Impacted assets: Device = `DeviceId`; Account = `InitiatingProcessAccountSid` / `AccountSid`. Related
  evidence: IP = `RemoteIP` (D2) / `PeerSample` (D3).
- Dedup keys are stated at the bottom of each file. Expected volume ≪ 150 alerts per run; D2's population
  filter is what keeps sanctioned proxies out even before the allow-list is filled.
- First run scans 30 days: expect a burst from D2/D3 on estates with unregistered dev proxies. Run D2 as a
  hunt first (same query, `MaxDevicesPerDestination` raised to 50) to seed `ApprovedProxyIPs`.

## 4. Tunables

| `let` | Rule | Meaning | FP it trades against | Default |
|---|---|---|---|---|
| `ApprovedProxies` / `ApprovedProxyIPs` / `ApprovedProxyDevices` | all | sanctioned forward proxies, PAC hosts, reverse proxies | corporate proxy infrastructure, lab VLANs | empty |
| `ProxyPorts` | D2, D3 | ports treated as proxy ports | web UIs on 8080/8443 (printers, NAS, dev servers) | 3128, 3129, 8080, 8081, 8118, 8888, 1080, 1081, 9050, 8000, 8443 |
| `MinConnections` | D2 | browser connections per device+destination per run | a few hits on a device's web UI | 25 |
| `MinConnectRequests` (D2-Sentinel) / literal 5 (D2) | D2 | CONNECT requests to a private IP | a dev tool probing a local proxy | 5 |
| `MaxDevicesPerDestination` | D2 | destinations used by more devices are sanctioned infrastructure | an unregistered but legitimate proxy used by a small team (false negative) | 3 |
| `MinPeers` | D3 | distinct private peers accepted on a proxy port | a dev box one colleague connects to | 3 |
| `Browsers` | D1b, D2 | processes whose proxy use matters | Electron apps, curl, pip (currently not covered) | 8 browsers |

## 5. Blind spots (attacker's side)

- **No RFC1918 bypass in ZCC**: then LAN traffic is tunnelled, the bypass fails, and nothing fires. Not a
  gap in detection, a gap in the premise. Confirm the forwarding profile.
- **SSH dynamic port forward** (`ssh -D 1080 user@lanhost`, browser proxy = 127.0.0.1:1080): the browser
  talks to loopback, which these rules deliberately exclude. The SSH session to the LAN host on 22 is
  visible but ordinary. Separate rule: `ssh.exe` with `ListeningConnectionCreated` on loopback.
- **Non-standard port without CONNECT visibility**: a proxy on 4443 with Zeek inspection off or sampled
  out is caught only by D1a/D1b if the configuration was written through a monitored path.
- **SOCKS proxies**: no HTTP CONNECT, so only the port list catches them (1080/1081/9050 included).
- **Proxy named by FQDN** (`proxy.lan:3128`): D1a's single-label branch catches `proxy:3128`; a
  multi-label internal FQDN is missed by D1a/D1b and left to D2.
- **Firefox**: proxy lives in `prefs.js`/`user.js`; MDE sees the file write, not the content. D2 covers the
  effect. A FileModified rule on `prefs.js` by a non-Firefox process is a possible fifth rule, low value.
- **Browser extension proxies** (FoxyProxy and similar): same network footprint as D2; invisible to D1.
- **PAC file on the LAN**: `AutoConfigURL = http://192.168.x.y/proxy.pac` is caught by D1a; the PAC can
  then direct only selected domains to the LAN proxy, keeping volume under `MinConnections`. Lower the
  threshold or add `HttpConnectionInspected uri endswith ".pac"` from a private IP as a signal.
- **Telemetry**: MDE throttles `ConnectionSuccess` and samples Zeek events, so D2/D3 counts are floors.
  A low-and-slow proxied session can stay under 25 connections per 4 h.
- **The proxy host is not onboarded**: D3 is blind; only D2 sees the client side.
- **Baseline poisoning does not apply** (no learned baseline), but a rogue proxy used by ≥ 4 devices looks
  like sanctioned infrastructure to D2's population filter. D3 covers that case when the host is onboarded.
- **Exclusion-induced**: anything added to `ApprovedProxyIPs` can be used as a pivot; review the list with
  an expiry.

## 6. Preflight (run before deploying)

```kql
// P1 — does MDE collect the proxy registry keys in this tenant? Expect rows; none → D1a is blind here.
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryValueName in~ ("ProxyServer", "AutoConfigURL", "ProxyEnable")
| summarize Events = count(), Devices = dcount(DeviceId), Writers = make_set(InitiatingProcessFileName, 20) by RegistryValueName
```
```kql
// P2 — is Zeek HTTP inspection present, and do CONNECT requests appear? Expect Method values incl. "CONNECT".
DeviceNetworkEvents
| where Timestamp > ago(7d) and ActionType == "HttpConnectionInspected"
| extend Method = tostring(parse_json(AdditionalFields).method)
| summarize Events = count(), Devices = dcount(DeviceId) by Method, RemoteIPType
```
```kql
// P3 — seed ApprovedProxyIPs: private destinations on proxy ports used by many devices are your sanctioned proxies.
let ProxyPorts = dynamic([3128, 3129, 8080, 8081, 8118, 8888, 1080, 1081, 9050, 8000, 8443]);
DeviceNetworkEvents
| where Timestamp > ago(30d) and ActionType == "ConnectionSuccess" and RemoteIPType == "Private" and RemotePort in (ProxyPorts)
| summarize Devices = dcount(DeviceId), Connections = count(), Processes = make_set(InitiatingProcessFileName, 10) by RemoteIP, RemotePort
| sort by Devices desc
```

## 7. Validation

- Fixtures in `tests/fixtures/`: `D1b_tp_chrome_proxy_flag.json` (one TP, one benign Chrome launch, one
  public-IP proxy that must not fire), `D1b_tn_netsh_show.json` (`netsh winhttp show proxy` and `reg query`
  must not fire), `D2_tp_proxied_browsing.json` (30 proxied connections from one device, a sanctioned proxy
  used by four devices that the population filter must drop, a single NAS web-UI hit below threshold).
- Build with `scripts/kql_test_harness.py --query <rule> --fixture <json> --out-dir tests/build` (done;
  emitted queries are in `tests/build/`); run with `--run --workspace <guid>` against an empty workspace
  before enabling. Boundary fixtures still to write: 24/25/26 connections, 2/3/4 devices per destination.
- 7-day live validation as hunts, then enable D1a/D1b first (sharp), D2 after `ApprovedProxyIPs` is
  seeded, D3 after reverse proxies are excluded.

## 8. Conditional fifth rule: Zscaler coverage gap (Sentinel only)

If ZIA web logs are in Sentinel, the most direct signal is absence: a device whose browsers made outbound
connections in the window but whose user produced zero ZIA transactions. Sketch (not linted, not tested,
depends on your NSS field mapping):

```kql
let query_frequency = 1h; let ingestion_delay = 1h;
let Active = DeviceNetworkEvents
| where TimeGenerated >= ago(query_frequency + ingestion_delay) and ingestion_time() > ago(query_frequency)
| where ActionType == "ConnectionSuccess" and RemoteIPType in ("Public", "Private")
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| summarize Connections = count(), DeviceName = take_any(DeviceName) by DeviceId, Upn = tolower(InitiatingProcessAccountUpn)
| where Connections >= 50 and isnotempty(Upn);
let Zia = CommonSecurityLog
| where TimeGenerated >= ago(query_frequency + ingestion_delay) and DeviceVendor =~ "Zscaler"
| summarize ZiaTransactions = count() by Upn = tolower(SourceUserName);
Active
| join kind=leftanti Zia on Upn
```
Treat a hit as "ZIA saw nothing for a user whose browser was busy", which is also what a ZCC outage looks
like; pair it with D1/D2 before escalating.

## 9. Response guidance

Pivot on the destination first (`RemoteIP`): is it onboarded (`DeviceInfo`), what listens there (D3), who
else talks to it. Then the account's recent configuration changes (D1a/D1b) and ZIA log gap. Do not wire
isolation to D2 until a measured precision rate exists; D1b with a private IP in `--proxy-server` is the
only rule here that approaches auto-response precision, and even that needs the developer-tooling fence.
