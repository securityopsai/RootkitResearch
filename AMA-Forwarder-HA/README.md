# Highly available AMA syslog/CEF forwarder cluster

A design and build kit for a failover-capable Azure Monitor Agent (AMA) log forwarder tier that ships Syslog and CEF over TCP/IP into Microsoft Sentinel / Log Analytics. It is meant to be simple to build and simple to support.

Confidence tags used below: **[H]** means I verified it against primary documentation or a lab test, at roughly 95% confidence or better. **[M]** means it is well-grounded but not verified end to end, so check it in your environment. Section 15 lists every open item.

---

## 1. Recommendation in one paragraph

Build **two identical, shared-nothing Linux forwarders** (rsyslog + AMA via Azure Arc). Put them behind **two keepalived VIPs in an active/active split**: VIP-A normally lives on node 1 and VIP-B on node 2, and each VIP fails over to the other node. Point half of the appliances at each VIP over **TCP 514**. Point Linux hosts that cannot run AMA themselves at the VIPs over **RELP 2514**, with a disk-assisted queue on the sender. Protect the WAN leg by raising AMA's local cache (`MaxDiskQuotaInMB`) to cover the outage you must ride through. There is no load balancer appliance, no Pacemaker, no shared disk and no replication: a VIP is the only cluster state. In Azure, where VRRP cannot work, swap keepalived for a Standard internal load balancer with an HTTP health probe (section 7).

## 2. Assumptions (correct me if any is wrong)

1. The target is **Microsoft Sentinel / Log Analytics** via the *Syslog via AMA* and *CEF via AMA* connectors. Sources are appliances (firewalls, proxies, switches) plus some Linux hosts. Windows Event Forwarding is out of scope, because it has a different HA model.
2. The forwarders run **on-premises** on VMware or Hyper-V, with both nodes on the same L2 segment. They are therefore Azure Arc-enabled, since AMA requires Arc outside Azure [H].
3. Peak volume is **≤ 10,000 EPS per forwarder pair**. Above that, see section 11.
4. "Automatic failover" means *no human action*, and a loss window of seconds is acceptable for appliances that can only speak plain TCP or UDP. Zero loss is achievable only where the sender speaks RELP (section 5).

## 3. Where HA actually has to live

Your premise is correct but incomplete. AMA has no clustering, yet it already covers two of the three failure domains on each node. The HA work is almost entirely on the **receive side**.

| Failure domain | What covers it | Built in? |
|---|---|---|
| Source → forwarder (receive path) | VIP failover (keepalived) or LB, plus sender-side queue/RELP | **No, this is what we build** |
| rsyslog → AMA on the node | rsyslog disk-assisted action queue to AMA (AMA installs it, capped at 1 GB since Linux 1.32.6) [H] | Yes |
| AMA → Azure (WAN, Azure outage) | AMA local cache, default 10,000 MB, tunable 4,000–1,000,000 MB via AgentSettings DCR (Linux 1.33.4+) [H]. AMA's ingestion endpoints are themselves HA. | Yes, but the default is too small (section 9) |

Two consequences follow:

- **Nodes need to share nothing.** Each node's AMA uploads independently. Split brain (both nodes claiming a VIP) causes connection resets, not data corruption.
- **A WAN or Azure outage is not a failover event.** It hits both nodes equally, so the health checks deliberately ignore it and the design relies on buffering instead (sections 6.5 and 9).

## 4. Architecture

```
   Appliances (CEF/syslog) over TCP 514  ──►  half to VIP-A, half to VIP-B
   Linux hosts without AMA over RELP 2514 ──►  VIP-A / VIP-B (split or pool)

    VIP-A 10.10.20.21         VIP-B 10.10.20.22           keepalived, VRRP unicast (proto 112)
  normally on amafwd01      normally on amafwd02          moves a VIP off an unfit owner
            │                         │
 ┌──────────▼───────────────┐ ┌───────▼──────────────────┐ shared-nothing:
 │ amafwd01                 │ │ amafwd02 (identical)     │ no shared disk,
 │ rsyslog imtcp/imudp/relp │ │                          │ no replication,
 │   └─► DA queue (≤ 1 GB)  │ │                          │ no Pacemaker
 │ AMA  (tcp/28330, local)  │ │                          │
 │   └─► cache ≤ DiskQuota  │ │                          │
 └──────────┬───────────────┘ └───────┬──────────────────┘
            └─────── HTTPS 443 ───────┘  Arc + AMA endpoints (proxy / Private Link per policy)
                         ▼
        Log Analytics workspace / Microsoft Sentinel
        CommonSecurityLog, Syslog  (Computer = forwarder, HostName = source)
```

### Why keepalived rather than a load balancer (on-premises)

| Option | Failover behaviour for a long-lived TCP syslog session | Support burden | Verdict |
|---|---|---|---|
| **keepalived dual VIP** | The VIP moves, the new owner has no socket and **resets** the sender's next segment, and the sender reconnects within seconds (lab: VIP moved ~3 s after a simulated crash) [H] | Two packages already in every distro, one config file per node | **Recommended on-premises** |
| Enterprise L4 LB (F5, NetScaler) | Good *if* configured to reset connections on member-down (F5 calls this "Action On Service Down = Reset") [M]. Beware SNAT, which hides the source IP | Depends on the network team's change process | Fine if you already run one well |
| Azure Standard LB | On probe-down, **established TCP flows stay pinned to the unhealthy backend** and UDP flows move [H]. After a VM crash, a TCP sender stalls until its own TCP timeout [M] | Managed | **Only option inside Azure** (section 7) |
| DNS round robin | No health awareness, and appliances cache resolved IPs | Low | Not failover |
| Send every source to both nodes | Survives anything | Low | **Doubles ingestion cost and duplicates alerts.** Reject |
| HAProxy/nginx stream proxy on the nodes | Adds a hop, hides source IP, and still no application-level ack | Extra tier | Reject |

Also note that Microsoft's own Azure LB troubleshooting guide states that UDP syslog is *unsuitable* for a flow-hash load balancer: one sender is one 5-tuple, which lands in one bucket. It recommends client-side multi-destination instead [H].

## 5. Lab evidence: plain TCP versus RELP

I tested the design pieces on Ubuntu 24.04 with rsyslog 8.2312 and 8.2608, and keepalived 2.2.8. The tests used veth namespaces and fake AMA listeners, **not** real AMA or Azure, so treat them as mechanism tests (section 13 has the in-environment drills).

| Test | Result |
|---|---|
| keepalived, two nodes in separate netns, **11/11 checks passed across 8 scenarios**: receive-failure moves both VIPs; failback waits for `preempt_delay`; AMA-down moves only that node's VIP; **AMA down on both nodes leaves VIPs in place**; a receive failure wins over a peer with degraded AMA; hard crash moves the VIP | VIP move in ~3 s for crash or receive-fail (test timers: 1 s interval) [H] |
| rsyslog target pool (8.2608), 6,000 sequenced messages: one receiver killed, then both, then recovery | **0 lost, 1 duplicate** (at-least-once at the failover point) [H] |
| **Node power loss + VIP takeover after 4 s**, 8,000 messages at 400 msg/s, the same stream over plain TCP and RELP, run twice | **Plain TCP lost 2,489 and 2,535 messages (~6.2–6.3 s of traffic). RELP lost 0, with 0 duplicates.** [H] |
| Forwarder drop-ins, live: TCP, UDP and RELP messages reach the (fake) AMA listener; none are written to the local log files; a 20 KB CEF line arrives intact | Pass on both Ubuntu and RHEL include layouts [H] |
| `rsyslog-pool.conf` on stock rsyslog 8.2312 | **Fails to parse** (`parameter 'target' is not a string`). Target pools need 8.2408.0 or later [H] |

**What this means.** Plain TCP syslog has no application-level acknowledgement. Whatever a sender wrote into a connection whose peer has died is lost silently. Loss equals the outage plus TCP retransmit backoff, *regardless of how good the failover is*. Appliances that can only do TCP or UDP will lose a few seconds of their own traffic per unplanned failover. That limit comes from the protocol, and no forwarder design removes it. RELP removes it for Linux sources.

## 6. The build (on-premises, recommended)

### 6.1 Server specification

| Item | Spec | Why |
|---|---|---|
| Nodes | 2 VMs, **hypervisor anti-affinity** (e.g. a VMware DRS "separate VMs" rule), ideally different datastores | One host failure must not take both |
| OS | A distro on AMA's supported-OS list that your team already patches (RHEL 9 / Ubuntu LTS are typical) [M: check the current list] | Supportability beats novelty |
| vCPU / RAM | 4 vCPU / 16 GB up to ~5k EPS; 8 vCPU / 16 GB up to 10k EPS | Microsoft's 10k EPS benchmark ran on an F8s_v2 (8 vCPU/16 GiB): avg CPU 51% of 800%, max 262%, RSS max ~1 GB [H]. My sizing below 10k is a judgement [M] |
| Disks | OS disk plus a **dedicated `/var` volume** sized from section 9 | AMA cache, rsyslog queues and logs all live under `/var`. A full disk stops AMA [H] |
| Network | Static IPs on the same L2 segment as the two VIPs. Time sync (chrony) to the same NTP as the sources | VRRP and GARP are L2. EventTime depends on the clock and time zone (6.6) |
| Throughput per node | **≤ 10k EPS sustained**, and each node must carry **100% of the pair's peak** alone | Microsoft's per-forwarder target. Loss is more likely above it [H] |

### 6.2 Firewall matrix

| From | To | Port | Purpose |
|---|---|---|---|
| Appliances | VIP-A, VIP-B | 514/tcp (514/udp if the device cannot do TCP) | Syslog / CEF |
| Linux sources | VIP-A, VIP-B | 2514/tcp | RELP |
| amafwd01 ↔ amafwd02 | each other | IP protocol 112 (VRRP) | keepalived adverts |
| Forwarders | Azure Arc + AMA endpoints | 443/tcp | Control plane and ingestion ([endpoint list](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-network-configuration)) |
| Monitoring / LB probe | Forwarders | 8514/tcp | HTTP health endpoint (LB variants only) |

On RHEL with firewalld:

```bash
sudo firewall-cmd --permanent --add-port=514/tcp --add-port=514/udp --add-port=2514/tcp
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.10.20.12/32" protocol value="vrrp" accept'   # peer IP
sudo firewall-cmd --reload
```

### 6.3 Azure side (once)

1. **Arc-enable both nodes** (`azcmagent connect …`). Optionally lock Arc down with `azcmagent config set config.mode monitor`, which applies a Microsoft-managed extension allowlist aimed at monitoring-only machines [H].
2. In Sentinel, install the **Syslog** and **Common Event Format** solutions. Create one *CEF via AMA* DCR and one *Syslog via AMA* DCR, and select **both** forwarders as resources. The connector installs AMA and creates the associations.
   - CEF DCR: the facility your appliances use (e.g. `local4`).
   - Syslog DCR: the facilities your Linux sources use, plus **`syslog` at Info** so the rsyslog impstats counters reach the workspace (section 10).
   - Don't collect the same facility in both, or you will duplicate data between `Syslog` and `CommonSecurityLog`. If you can't avoid overlap, add Microsoft's transform `source | where ProcessName !contains "CEF" and SyslogMessage !contains "CEF:0"` to the Syslog DCR [H].
3. **Raise AMA's cache** with [`azure/agentsettings-dcr.json`](azure/agentsettings-dcr.json). An ARM template is the only supported way to create an AgentSettings DCR [H]. Associate it via CLI rather than the sample template on Microsoft's page, which references an undefined parameter and is missing a comma. `az connectedmachine` needs the `connectedmachine` CLI extension:

```bash
az deployment group create -g rg-soc-ingest --template-file azure/agentsettings-dcr.json \
  --parameters maxDiskQuotaInMB=100000
DCR_ID=$(az monitor data-collection rule show -g rg-soc-ingest -n dcr-ama-fwd-agentsettings --query id -o tsv)
for m in amafwd01 amafwd02; do
  az monitor data-collection rule association create --name agentSettings --rule-id "$DCR_ID" \
    --resource "$(az connectedmachine show -g rg-arc -n "$m" --query id -o tsv)"
done
# then on each node: sudo systemctl restart azuremonitoragent
```

### 6.4 Each node

```bash
# Packages (RHEL: dnf; Ubuntu: apt-get)
sudo dnf install -y rsyslog rsyslog-relp keepalived

# rsyslog: listeners + "don't also write remote logs to /var/log"
sudo install -m 0644 forwarder/rsyslog/00-ama-fwd-inputs.conf forwarder/rsyslog/20-ama-fwd-stop-remote.conf /etc/rsyslog.d/
#   If you previously ran Microsoft's Forwarder_AMA_installer.py, delete the imudp/imtcp
#   module()/input() lines it enabled in /etc/rsyslog.conf - each module may load only once.
sudo rsyslogd -N1 && sudo systemctl restart rsyslog
sudo install -m 0644 forwarder/sysctl/90-ama-fwd.conf /etc/sysctl.d/ && sudo sysctl --system

# Health check (used by keepalived; also by the HTTP endpoint in LB variants)
sudo install -m 0755 forwarder/health/ama-fwd-health /usr/local/sbin/
sudo mkdir -p /etc/ama-fwd
/usr/local/sbin/ama-fwd-health all          # must print: ok

# keepalived (node 2 gets keepalived-node2.conf)
sudo install -m 0644 forwarder/keepalived/keepalived-node1.conf /etc/keepalived/keepalived.conf
sudo keepalived -t && sudo systemctl enable --now keepalived
ip -br addr                                  # amafwd01 holds VIP-A, amafwd02 holds VIP-B
```

Edit the placeholders first: interface (`ens192`), node IPs, VIPs, and `virtual_router_id` (it must be unique on the segment).

**SELinux (RHEL) [M].** Run `semanage port -l | grep syslogd_port_t`. If `2514/tcp` is missing, add it with `semanage port -a -t syslogd_port_t -p tcp 2514`. keepalived scripts run confined. If `ausearch -m avc -ts recent` shows denials for the health script, label it as a keepalived unconfined script: `semanage fcontext -a -t keepalived_unconfined_script_exec_t /usr/local/sbin/ama-fwd-health && restorecon -v /usr/local/sbin/ama-fwd-health`. Test in enforcing mode; don't disable SELinux.

### 6.5 How the health check decides

[`ama-fwd-health`](forwarder/health/ama-fwd-health) has two modes, which keepalived uses differently:

| Check | Tests | keepalived use | Effect |
|---|---|---|---|
| `receive` | Maintenance flag absent; `rsyslog` active; listeners on 514/tcp, 514/udp, 2514/tcp; `/var` ≥ 10% free | Hard (`fall 3` × 5 s) | Failing node drops its VIPs (~10–20 s) |
| `forward` | `azuremonitoragent` active and listening on the port recorded in `config-cache/syslog.port` (AMA picks a random port if 28330 is taken [H]) | Weighted `-60` (`fall 6` × 5 s) | VIP moves **only if the peer's AMA is healthy**. If AMA is down on both (e.g. a simultaneous extension auto-upgrade), VIPs stay and rsyslog queues |

It deliberately does **not** check Azure reachability or cache backlog. A WAN outage hits both nodes, and failing probes on both would take the whole service down, which is worse than buffering. That case is handled by alerting (section 10).

### 6.6 Time zones (a subtle data-quality trap)

AMA's rsyslog template on the forwarder is `<%PRI%>%TIMESTAMP% %HOSTNAME% …`, which renders an RFC 3164 timestamp with no UTC offset [H]. `EventTime` is then interpreted in the **forwarder's** time zone, and `TimeGenerated` is the forwarder's processing time [H]. RFC 5424 at the source does **not** fix this, because the offset is dropped at that hop. **Put sources and forwarders in the same time zone, preferably UTC everywhere.**

## 7. Azure-hosted variant (forwarders in Azure)

VRRP cannot work in a VNet: it is L3-only, with no broadcast, multicast or gratuitous ARP [H]. Use a **Standard internal load balancer** instead:

- Two VMs in **different availability zones**, both in one backend pool.
- An HTTP probe on `8514`, path `/`, interval 5 s, served by [`ama-fwd-health.socket`](forwarder/health/ama-fwd-health.socket) and [`ama-fwd-health@.service`](forwarder/health/ama-fwd-health@.service). The probe must get HTTP 200; any other status marks the backend down. Probes come from `168.63.129.16`, so don't block it [H].
- Rules for TCP 514, UDP 514 and TCP 2514. On the TCP rules set the **idle timeout to 30 min and enable TCP reset**. The default is 4 min, the maximum 100 [H]. The forwarder's `keepAlive.time="600"` keeps idle senders' flows alive inside that window.

```bash
# Illustrative - verify flags with --help for your az version [M]
az network lb create -g rg-soc-ingest -n lb-ama-fwd --sku Standard --vnet-name vnet-soc --subnet snet-fwd \
  --frontend-ip-name fe-syslog --private-ip-address 10.20.1.10 --backend-pool-name be-ama-fwd
az network lb probe create -g rg-soc-ingest --lb-name lb-ama-fwd -n hp-ama-fwd --protocol Http --port 8514 --path / --interval 5
az network lb rule create -g rg-soc-ingest --lb-name lb-ama-fwd -n syslog-tcp --protocol Tcp --frontend-port 514 --backend-port 514 \
  --frontend-ip-name fe-syslog --backend-pool-name be-ama-fwd --probe-name hp-ama-fwd --idle-timeout 30 --enable-tcp-reset true
az network lb rule create -g rg-soc-ingest --lb-name lb-ama-fwd -n syslog-udp --protocol Udp --frontend-port 514 --backend-port 514 \
  --frontend-ip-name fe-syslog --backend-pool-name be-ama-fwd --probe-name hp-ama-fwd
az network lb rule create -g rg-soc-ingest --lb-name lb-ama-fwd -n relp --protocol Tcp --frontend-port 2514 --backend-port 2514 \
  --frontend-ip-name fe-syslog --backend-pool-name be-ama-fwd --probe-name hp-ama-fwd --idle-timeout 30 --enable-tcp-reset true
```

**Known weakness, and why on-premises keepalived is better where you have a choice.** On probe-down, Azure LB leaves **established TCP flows on the unhealthy backend** [H]. Two things follow:

- **Maintenance.** Set the backend's *Admin State* to Down first, then **restart rsyslog** on that VM to push its sessions over to the healthy node [H: Admin State semantics].
- **VM crash.** Nothing resets the sender. A plain-TCP appliance stalls until its own TCP retransmission timeout, which on Linux defaults to many minutes and varies by vendor elsewhere [M]. RELP senders recover through RELP's own timeout. UDP flows do move to a healthy instance on probe-down [H].

Also expect uneven load, because a 5-tuple hash with a few heavy senders is inherently lumpy. Size each node for the full load anyway.

## 8. Onboarding sources

| Source | Configure | Notes |
|---|---|---|
| Appliances with a single syslog target | VIP-A for half, VIP-B for half, **TCP 514** | Prefer TCP: it gets flow control and reconnects, while UDP drops silently under load. Use UDP only if the device can't do TCP. The loss window per unplanned failover is a few seconds of that device's traffic (section 5). Reconnect and buffering behaviour is **vendor-specific**; measure it in drill D3 |
| Appliances with "multiple syslog servers" | Usually **one** VIP only | Most such features fan out to *all* configured servers (duplication). Use two only if the vendor documents *failover* semantics [M] |
| Linux hosts that **can run AMA** | Install AMA on the host itself (Arc) | No forwarder hop, and each host gets its own cache. The forwarder tier is for things that can't run AMA |
| Linux, rsyslog, can add `rsyslog-relp` | [`sources/rsyslog-relp.conf`](sources/rsyslog-relp.conf) | **Recommended:** 0 loss in the crash test |
| Linux, rsyslog ≥ 8.2408.0 | [`sources/rsyslog-pool.conf`](sources/rsyslog-pool.conf) | Round-robin over both VIPs, skips a dead target. Plain TCP, so the crash-loss caveat applies |
| Linux, older rsyslog | [`sources/rsyslog-vip.conf`](sources/rsyslog-vip.conf) | One VIP plus a disk-assisted queue |
| Linux, syslog-ng | [`sources/syslog-ng-failover.conf`](sources/syslog-ng-failover.conf) | `failover()` to the other VIP, plus a disk buffer. Syntax-checked on syslog-ng 4.3.1 |

## 9. Sizing the buffers

**AMA cache (`MaxDiskQuotaInMB`).** The cache must hold `peak EPS × average event bytes × longest outage to survive`. Beyond the cap, AMA drops data [H]. The default of 10,000 MB is small for a forwarder:

| Peak EPS | Avg event | Ingest rate | Default 10 GB lasts | For 8 h you need | For 24 h you need |
|---|---|---|---|---|---|
| 2,000 | 500 B | 1.0 MB/s | ~2.8 h | ~29 GB | ~86 GB |
| 5,000 | 600 B | 3.0 MB/s | ~55 min | ~86 GB | ~259 GB |
| 10,000 | 500 B | 5.0 MB/s | **~33 min** | ~144 GB | ~432 GB |

This assumes the cache stores roughly raw event size. **I could not verify that [M]**, so measure it in drill D6 and adjust. Get your real average event size with `CommonSecurityLog | where TimeGenerated > ago(1d) | summarize avg(estimate_data_size(*))`. Size `/var` at **≥ 1.3 × the quota**, plus AMA's 1 GB rsyslog spool, plus logs. AMA upgrades temporarily double the agent's package footprint [H].

**Sender-side queues.** The source configs use a 2 GB disk-assisted queue. At typical per-host rates (tens of EPS, a few hundred bytes each) that is days of buffering; apply the same EPS × bytes × outage formula to chatty hosts.

## 10. Monitoring

Alert on these in Sentinel / Azure Monitor. They are written for this design; test them against your data.

```kusto
// 1. Forwarder down (warn on one, page on both)
Heartbeat
| where Computer startswith "amafwd"
| summarize LastHeartbeat = max(TimeGenerated) by Computer
| where LastHeartbeat < ago(10m)
```

```kusto
// 2. Upload backlog: TimeGenerated is set on the forwarder, so a growing gap = AMA is caching.
//    Filter on ingestion_time(): during an outage the backlog arrives with OLD TimeGenerated values.
union CommonSecurityLog, Syslog
| where TimeGenerated > ago(3d)                       // coarse guard: covers your cache horizon
| extend Ingested = ingestion_time()
| where Ingested > ago(30m) and Computer startswith "amafwd"
| summarize p95LagSec = percentile(datetime_diff('second', Ingested, TimeGenerated), 95)
    by Computer, bin(Ingested, 5m)
| where p95LagSec > 900
```

```kusto
// 3. Which node carries what (failovers show up as volume moving between Computers)
union CommonSecurityLog, Syslog
| where TimeGenerated > ago(24h) and Computer startswith "amafwd"
| summarize Events = count() by Computer, bin(TimeGenerated, 5m)
| render timechart
```

```kusto
// 4. Silent sources (dead device, or a TCP session stuck on a dead path)
CommonSecurityLog
| where TimeGenerated > ago(7d)
| summarize LastSeen = max(TimeGenerated) by DeviceVendor, DeviceProduct, DeviceName
| where LastSeen < ago(2h)
```

```kusto
// 5. rsyslog queue pressure / discards on the forwarders (impstats, facility syslog)
Syslog
| where Computer startswith "amafwd" and ProcessName == "rsyslogd-pstats"
| extend s = parse_json(SyslogMessage)
| where tostring(s.origin) == "core.queue"
| project TimeGenerated, Computer, Queue = tostring(s.name), Size = toint(s.size),
          Full = toint(s.full), DiscardedFull = toint(s['discarded.full']), DiscardedNF = toint(s['discarded.nf'])
| where DiscardedFull > 0 or DiscardedNF > 0 or Full > 0
```

On the nodes: keepalived logs every state change to the journal (`journalctl -u keepalived`). For UDP drops, run `nstat -az UdpRcvbufErrors`.

## 11. Scaling beyond one pair

- **Add cells, not nodes.** Each pair is a cell that handles ≤ 10k EPS; assign sources to cells by site or source group. This scales linearly and keeps every cell as simple as the first. It is what I'd choose.
- A **three-plus node keepalived** ring with rotated priorities works, but the priority and weight arithmetic stops being obvious to the next on-call engineer.
- **Azure Monitor pipeline** (GA for syslog; runs on Arc-enabled Kubernetes; TLS/mTLS; persistent buffering up to 48 h; auto-schematizes to `Syslog`/`CommonSecurityLog`) [H] is Microsoft's answer for very high volume or disconnected edges. **You own the Kubernetes cluster**, so only choose it if you already run Kubernetes or have outgrown several cells.

## 12. Operations runbook

**Patching a node (no data loss for RELP; seconds at most for plain-TCP appliances):**

```bash
sudo touch /etc/ama-fwd/maintenance     # receive check fails -> both VIPs move to the peer in ~10-20 s
ip -br addr                             # confirm this node holds no VIP
# optional: wait for AMA to drain -> du -sh /var/opt/microsoft/azuremonitoragent/events
sudo dnf -y upgrade && sudo reboot
/usr/local/sbin/ama-fwd-health all      # after reboot: must print ok
sudo rm /etc/ama-fwd/maintenance        # VIP returns after rise (15 s) + preempt_delay (60 s)
```

Patch one node at a time, during low traffic, and never both at once.

**Troubleshooting order:**

1. `ama-fwd-health all`
2. `ip -br addr` (who owns the VIPs)
3. `journalctl -u keepalived -n 50`
4. `ss -ltnup | grep -E ':(514|2514|28330)'`
5. `sudo tcpdump -ni any port 514 or port 2514 -c 20`
6. `/var/opt/microsoft/azuremonitoragent/log/mdsd.err`
7. Microsoft's [AMA Linux troubleshooter](https://learn.microsoft.com/azure/azure-monitor/agents/troubleshooter-ama-linux)

**Known failure modes and what they cost:**

| Event | Detection / failover time (production timers) | Data at risk |
|---|---|---|
| rsyslog crash | The kernel closes the dead process's sessions at once, so senders reconnect; the VIP moves in ~10–20 s unless systemd restarts rsyslog first | rsyslog in-memory queue contents; plain-TCP in-flight data. RELP resends |
| AMA crash or upgrade on one node | ~30 s (`fall 6`) + 60 s `preempt_delay`, then the VIP moves; rsyslog queues meanwhile (1 GB spool) | None expected [M: verify in D4] |
| AMA down on both nodes | No VIP movement by design; both nodes queue | None until the 1 GB rsyslog spool fills |
| Node power loss / kernel panic | ~3–4 s (VRRP master-down interval) | Plain TCP: about outage + retransmit backoff (lab: ~6 s of traffic). UDP: traffic during the outage. RELP: none [H: lab] |
| WAN / Azure outage | Not a failover | None until the AMA cache (section 9) fills |
| Split brain (VRRP adverts lost between nodes) | Both nodes hold the VIP | Connection resets only. Alert on "both nodes MASTER" in the journal |
| `/var` full | `receive` check fails, and the VIP moves | Whatever that node had not yet uploaded stays stranded until space is freed |

## 13. Acceptance tests (run before go-live)

Use [`tests/seqsender.py`](tests/seqsender.py) from a host positioned like your real senders. It sends sequence-numbered CEF (`local4.info`, so the CEF DCR must collect `local4`) over one long-lived TCP connection and reconnects the way an appliance does. For the RELP path, use a Linux test host whose rsyslog has `input(type="imtcp" address="127.0.0.1" port="10514")` plus `rsyslog-relp.conf`, and run `seqsender.py --target 127.0.0.1 --port 10514` on it; that is how the lab test in section 5 was wired.

| Drill | Action during a `seqsender` run | Pass criterion |
|---|---|---|
| D1 | `systemctl kill -s KILL rsyslog` on the VIP owner | TCP loss ≤ ~10 s of sender traffic; RELP 0 |
| D2 | Maintenance flag (planned) | RELP 0; TCP ≤ ~2 s of sender traffic [M: not lab-measured] |
| D3 | Hard power-off of the VIP owner (hypervisor "reset") | VIP moves ≤ 5 s; TCP loss ≤ ~10 s; RELP 0; note the appliance's reconnect time |
| D4 | `systemctl stop azuremonitoragent` on one node | VIP moves after ~90 s; loss 0 |
| D5 | Stop AMA on **both**, wait 5 min, start | VIPs stay; loss 0 after drain |
| D6 | Block outbound 443 for 1–2 h | Loss 0 after backfill; record cache growth per hour to validate section 9 |
| D7 | Fill `/var` past 90% | VIP moves off the node |

```kusto
let run = "drill1"; let sent = 300000;
CommonSecurityLog
| where TimeGenerated > ago(1d) and DeviceVendor == "HATest" and DeviceCustomString1 == run
| summarize copies = count() by seq = DeviceCustomNumber1
| summarize received = count(), duplicates = sum(copies - 1)
| extend lost = sent - received
```

```kusto
// where the gaps are (lines them up with the failover time)
CommonSecurityLog
| where TimeGenerated > ago(1d) and DeviceVendor == "HATest" and DeviceCustomString1 == "drill1"
| summarize by seq = DeviceCustomNumber1
| order by seq asc
| extend prevSeq = prev(seq)
| where seq - prevSeq > 1
| project gapFrom = prevSeq + 1, gapTo = seq - 1, missing = seq - prevSeq - 1
```

## 14. Anti-patterns

- Sending each source to both nodes. This doubles cost and duplicates incidents.
- An LB or keepalived health check that only tests "port 514 open", or one that fails on Azure backlog, which takes down both nodes at once.
- Writing forwarded messages to `/var/log` on the forwarder. A full disk stops AMA [H].
- Binding inputs to a non-default rsyslog ruleset. AMA's forwarding rule only sees the default ruleset [H].
- Leaving `imtcp` at its default `MaxSessions=200` [H]. Once a node is carrying both halves, connections beyond 200 are refused.
- Relying on UDP for anything you must not lose: there is no delivery feedback, and kernel buffer overflows are silent.
- Assuming "TCP" means "reliable delivery" for syslog (section 5).

## 15. Open items and uncertainties

| Item | Confidence | How to close |
|---|---|---|
| AMA cache bytes per event vs raw size | M | Drill D6 |
| Appliance reconnect and buffering after a reset, per vendor | L–M | Drills D1/D3 per device model |
| Azure LB: TCP stall duration after a backend VM crash | M | Drill D3 in the Azure variant |
| SELinux labels for keepalived scripts and port 2514 on your RHEL minor version | M | Enforcing-mode test plus `ausearch` |
| Whether AMA auto-upgrade can hit both Arc nodes at once | M | Mitigated by the weighted `forward` check either way (lab-tested) |
| Upstream switches or firewalls honouring gratuitous ARP on VIP move | M | Drill D3; `vrrp_garp_master_refresh 60` is set as a backstop |
| `az` CLI flags in section 7 | M | `--help` on your CLI version |

## 16. Files

| Path | Goes to |
|---|---|
| `forwarder/rsyslog/00-ama-fwd-inputs.conf` | `/etc/rsyslog.d/` on both nodes |
| `forwarder/rsyslog/20-ama-fwd-stop-remote.conf` | `/etc/rsyslog.d/` on both nodes |
| `forwarder/sysctl/90-ama-fwd.conf` | `/etc/sysctl.d/` on both nodes |
| `forwarder/health/ama-fwd-health` | `/usr/local/sbin/` on both nodes (defaults overridable in `/etc/ama-fwd/health.conf`) |
| `forwarder/health/ama-fwd-health.socket`, `ama-fwd-health@.service` | `/etc/systemd/system/`, LB variants only |
| `forwarder/keepalived/keepalived-node{1,2}.conf` | `/etc/keepalived/keepalived.conf` |
| `azure/agentsettings-dcr.json` | ARM deployment (cache quota) |
| `sources/*.conf` | Linux source hosts |
| `tests/seqsender.py` | Failover drills |

## Sources

Microsoft (primary):
- [Syslog and CEF via AMA connectors: architecture, TCP 28330, duplication avoidance](https://learn.microsoft.com/azure/sentinel/cef-syslog-ama-overview)
- [AMA performance benchmark: 10k EPS target, F8s_v2 results, "use a load balancer and redundant forwarders"](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-performance)
- [AMA agent settings: MaxDiskQuotaInMB 4,000–1,000,000, ARM-only](https://learn.microsoft.com/azure/azure-monitor/agents/agent-settings)
- [AMA extension versions: 1 GB rsyslog spool cap, random port on conflict, 1 MB row limit, disk quota in Linux 1.33.4](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-extension-versions)
- [AMA requirements: disk space per path](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-requirements)
- [Collect Syslog with AMA: default rsyslog template, default ruleset only, EventTime / time zone note](https://learn.microsoft.com/azure/azure-monitor/vm/data-collection-syslog)
- [Troubleshoot syslog with AMA on Linux: syslog.port, full-disk failure mode](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-troubleshoot-linux-vm-rsyslog)
- [AMA on non-Azure machines requires Azure Arc](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-supported-operating-systems)
- [Azure LB uneven distribution: syslog is unsuitable for flow-hash load balancing](https://learn.microsoft.com/troubleshoot/azure/load-balancer/troubleshoot-azure-load-balancer-uneven-traffic-distribution)
- [Azure LB health probes: probe-down behaviour, 168.63.129.16, HTTP 200](https://learn.microsoft.com/azure/load-balancer/load-balancer-custom-probe-overview)
- [Azure LB TCP reset and idle timeout (4–100 min)](https://learn.microsoft.com/azure/load-balancer/load-balancer-tcp-reset)
- [Azure LB Admin State](https://learn.microsoft.com/azure/load-balancer/admin-state-overview)
- [Azure VNet FAQ: no multicast/broadcast, no L2](https://learn.microsoft.com/azure/virtual-network/virtual-networks-faq)
- [Azure Monitor pipeline overview](https://learn.microsoft.com/azure/azure-monitor/data-collection/pipeline-overview) and [persistent storage limits](https://learn.microsoft.com/azure/azure-monitor/data-collection/pipeline-configure-cli)
- [az monitor data-collection rule association create](https://learn.microsoft.com/cli/azure/monitor/data-collection/rule/association)

rsyslog / syslog-ng (primary):
- [omfwd target pools (rsyslog docs source)](https://github.com/rsyslog/rsyslog/blob/main/doc/source/configuration/modules/omfwd/parameters/basic.rst). [ChangeLog: native load balancing in 8.2408.0](https://github.com/rsyslog/rsyslog/blob/main/ChangeLog)
- [imtcp MaxSessions (default 200)](https://github.com/rsyslog/rsyslog/blob/main/doc/source/reference/parameters/imtcp-maxsessions.rst), [imtcp KeepAlive.Time](https://github.com/rsyslog/rsyslog/blob/main/doc/source/reference/parameters/imtcp-keepalive-time.rst), [imudp RcvBufSize](https://github.com/rsyslog/rsyslog/blob/main/doc/source/reference/parameters/imudp-rcvbufsize.rst)
- [syslog-ng client-side failover](https://syslog-ng.github.io/admin-guide/070_Destinations/370_Client_side_failover.html)
