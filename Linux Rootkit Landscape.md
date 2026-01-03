# Linux Rootkit Landscape: A Comprehensive Research Document

*For educational and defensive security research purposes only.*

---

## Table of Contents

1. [Historical Evolution](#1-historical-evolution)
2. [Classification Taxonomy](#2-classification-taxonomy)
3. [Notable Rootkit Families](#3-notable-rootkit-families)
4. [Current Threat Landscape (2024-2025)](#4-current-threat-landscape-2024-2025)
5. [Emerging Trends](#5-emerging-trends)
6. [Threat Actor Usage](#6-threat-actor-usage)
7. [Detection Challenges](#7-detection-challenges)
8. [Defensive Recommendations](#8-defensive-recommendations)
9. [References](#9-references)

---

## 1. Historical Evolution

### 1.1 Origins (1990s)

The history of Linux rootkits reflects the broader evolution of system-level attacks:

| Year | Milestone |
|------|-----------|
| 1989 | First rootkit components (log cleaners) detected on compromised systems |
| 1994 | SunOS rootkits detected |
| 1996 | First Linux rootkits appear |
| 1997 | LKM rootkits proposed by Halflife in Phrack magazine |
| 1999 | Knark and Adore rootkits released |
| 2001 | SuckIT rootkit published (Phrack 58) - first major /dev/kmem rootkit |

The term "rootkit" combines "root" (the Unix/Linux superuser with full system access) and "kit" (the software providing that access).

### 1.2 Early LKM Era (1997-2005)

The first generation of kernel-level rootkits focused on **syscall table modification**:

```
Execution Flow (Classic LKM Rootkit):
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  User App   │───►│  sys_call   │───►│   Hooked    │
│  (ps, ls)   │    │   table     │    │  Function   │
└─────────────┘    └─────────────┘    └─────────────┘
                          │                   │
                          │           ┌───────▼───────┐
                          │           │  Malicious    │
                          │           │    Logic      │
                          └──────────►│  (filter/     │
                                      │   modify)     │
                                      └───────────────┘
```

**Key rootkits of this era:**

- **Knark** (Creed): One of the first comprehensive LKM rootkits
  - Hidden files, processes, and services
  - Remote command execution via magic packets
  - Self-hiding from module list

- **Adore** (Stealth): Foundational kernel rootkit
  - File, process, and network connection hiding
  - Userspace control tool "ava"
  - Still found on compromised machines today
  - Later evolved into Adore-ng (used by APT41/Winnti)

- **SuckIT**: Revolutionary /dev/kmem approach
  - Did not require LKM support
  - Direct kernel memory manipulation
  - Password-protected connect-back shell
  - Bypassed most firewall configurations

### 1.3 Maturing Techniques (2005-2014)

This period saw the development of more sophisticated evasion techniques:

- **Direct Kernel Object Manipulation (DKOM)**: Modifying kernel data structures directly instead of hooking
- **Virtual File System (VFS) hooking**: Intercepting filesystem operations at a lower level
- **Inline hooking**: Patching function prologues instead of modifying syscall table
- **Return-oriented programming (ROP)**: Bypassing kernel code integrity checks

### 1.4 Modern Era (2014-Present)

The introduction of eBPF in Linux 3.18 (2014) marked a paradigm shift:

```
Evolution Timeline:
────────────────────────────────────────────────────────────────►
1997        2001        2014        2020        2024
│           │           │           │           │
LKM         /dev/kmem   eBPF        eBPF        eBPF + LKM
Rootkits    Injection   Introduced  Rootkits    Hybrid
                                    Emerge      Attacks
```

---

## 2. Classification Taxonomy

### 2.1 By Execution Level

```
┌─────────────────────────────────────────────────────────────┐
│                    ROOTKIT CLASSIFICATION                    │
├─────────────────────────────────────────────────────────────┤
│  Level 0 - Firmware/Bootkit                                 │
│    └── UEFI/BIOS implants (rare in Linux)                   │
├─────────────────────────────────────────────────────────────┤
│  Level 1 - Kernel Space                                     │
│    ├── LKM Rootkits (Loadable Kernel Modules)               │
│    ├── /dev/kmem Injection (legacy)                         │
│    ├── eBPF-based Rootkits                                  │
│    └── Kprobe/Ftrace Hooking                                │
├─────────────────────────────────────────────────────────────┤
│  Level 2 - User Space (Ring 3)                              │
│    ├── LD_PRELOAD Injection                                 │
│    ├── GOT/PLT Hooking                                      │
│    ├── ptrace-based                                         │
│    └── Shared Library Replacement                           │
├─────────────────────────────────────────────────────────────┤
│  Level 3 - Application Level                                │
│    └── Modified binaries (trojaned tools)                   │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 By Implementation Mechanism

| Type | Mechanism | Persistence | Detection Difficulty |
|------|-----------|-------------|----------------------|
| **LKM** | Kernel module loading | High (survives reboot with loader) | Medium |
| **eBPF** | BPF syscall, verified programs | Low (typically memory-resident) | High |
| **LD_PRELOAD** | Dynamic linker hijacking | Medium | Low-Medium |
| **Memory Injection** | Direct /dev/kmem or /dev/mem | Low | Medium |
| **Ftrace/Kprobe** | Legitimate kernel tracing | Medium | High |

### 2.3 By Capability

1. **Process Hiding**
   - Hooking `getdents64()` to filter /proc entries
   - Modifying task_struct linked lists (DKOM)
   - Filtering /proc filesystem access

2. **File/Directory Hiding**
   - VFS hooking
   - `getdents()` manipulation
   - Extended attribute abuse

3. **Network Hiding**
   - Socket filtering (XDP, TC)
   - `/proc/net/*` manipulation
   - Netfilter hooks

4. **Credential Theft**
   - PAM module hooking
   - `ssh` binary replacement
   - Keylogging via input hooks

5. **Command & Control**
   - Magic packet activation
   - Covert channels (ICMP, DNS)
   - Reverse shells

---

## 3. Notable Rootkit Families

### 3.1 Classic Rootkits (Historical)

#### Knark (1999)
```
Type: LKM
Capabilities: File/process hiding, privilege escalation, remote commands
Status: Historical reference
```

#### Adore/Adore-ng (1999-2022)
```
Type: LKM
Capabilities: File/process/network hiding, privilege escalation
Status: Still observed in modern attacks (Syslogk 2022, RedXor)
Notable: APT41/Winnti toolset association
```

#### SuckIT (2001)
```
Type: /dev/kmem injection
Capabilities: Process/file/connection hiding, password-protected backdoor
Status: Deprecated (modern kernels block /dev/kmem access)
```

### 3.2 Modern Open-Source Rootkits

#### Reptile
```
Repository: github.com/f0rb1dd3n/Reptile
Type: LKM
Capabilities:
  - Process hiding (PID/filename based)
  - File/directory hiding
  - Network connection hiding
  - Port knocking activation
  - Reverse shell backdoor
Threat Usage: UNC3886 (Chinese APT), targeted attacks in South Korea
```

#### Medusa
```
Repository: github.com/ldpreload/Medusa
Type: LD_PRELOAD
Capabilities:
  - PAM backdoor
  - Process hiding
  - File hiding
  - Network hiding
  - Credential logging
Threat Usage: UNC3886, experimental deployment alongside Reptile
```

#### Diamorphine
```
Type: LKM
Capabilities: Process/module hiding, privilege escalation
Status: New variants discovered in-the-wild (March 2024)
```

### 3.3 eBPF-Based Rootkits

#### BPFDoor (2021-Present)
```
Type: eBPF (classic BPF socket filters)
Capabilities:
  - Magic packet activation on any port
  - Traffic inspection and filtering
  - Stealthy C2 communications
  - 2025: IPv6 support, DNS port masquerading
Threat Usage: State-sponsored, APT41 linked
Detection: 151 new samples in 2025
```

#### Symbiote (2021-Present)
```
Type: eBPF + LD_PRELOAD hybrid
Capabilities:
  - Parasitic process injection
  - setsockopt hooking for traffic hiding
  - Cross-protocol support (TCP/UDP/SCTP)
  - 2025: Non-standard port operation
Characteristics: Lives within legitimate processes
Detection: 3 new samples in 2025
```

#### LinkPro (2025)
```
Type: eBPF dual-module
Capabilities:
  - Hide module: Conceals files, processes, BPF maps
  - Activate module: Magic packet triggered
  - Fallback: LD_PRELOAD when eBPF restricted
Discovered: Synacktiv CSIRT on AWS infrastructure
```

#### Ebpfkit
```
Type: eBPF
Capabilities: Demonstration rootkit showcasing eBPF capabilities
Status: Research/educational
```

#### TripleCross
```
Type: eBPF
Capabilities: Syscall hooking, network manipulation
Status: Research/educational
```

### 3.4 Recent Notable Rootkits (2024-2025)

#### PUMAKIT (December 2024)
```
Type: Multi-stage (Dropper + LKM + Userland)
Architecture:
  ├── Dropper ("cron")
  ├── Memory-resident executables
  ├── LKM rootkit ("puma.ko")
  └── Userland rootkit ("Kitsune")

Capabilities:
  - 18+ syscall hooks via ftrace
  - Privilege escalation
  - C2 communication hiding
  - Anti-debugging

Techniques: Uses ftrace (legitimate kernel tracer) for hooking
```

#### HoneyMyte/Mustang Panda Rootkit (February 2025)
```
Type: Kernel-mode
Associated Malware: ToneShell backdoor
Targets: Government organizations in Southeast/East Asia
Primary Victims: Myanmar, Thailand
```

#### CentOS Rootkit (January 2025)
```
Type: LKM (sysinitd.ko)
Persistence: /etc/rc.local, /etc/rc.d/rc.local
Attack Vector: Multiple vulnerability exploitation
Analysis: FortiGuard Labs
```

---

## 4. Current Threat Landscape (2024-2025)

### 4.1 Statistics

| Metric | Value |
|--------|-------|
| New malware detected daily | ~560,000 |
| Active malware programs worldwide | 1+ billion |
| Rootkit detections Q4 2024 | 386 |
| BPFDoor samples detected 2025 | 151 |
| Symbiote samples detected 2025 | 3 |

### 4.2 Active Threat Actors Using Linux Rootkits

| Threat Actor | Rootkits Used | Targets |
|--------------|---------------|---------|
| UNC3886 | Reptile, Medusa | VMware ESXi, Critical Infrastructure |
| APT41/Winnti | BPFDoor, Adore-ng | Government, Telecom |
| Mustang Panda/HoneyMyte | Custom kernel rootkit | SE Asian Governments |
| Unknown (PUMAKIT) | PUMAKIT | Linux servers |

### 4.3 Attack Vectors

```
Common Infection Paths:
┌────────────────────────────────────────────────────────────┐
│                     INITIAL ACCESS                          │
├────────────────────────────────────────────────────────────┤
│  1. Exploiting vulnerabilities (CVE-2024-23897, etc.)      │
│  2. Compromised containers/orchestration                    │
│  3. Supply chain compromise                                 │
│  4. Credential theft/brute force                            │
│  5. Living-off-the-land techniques                          │
└────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────┐
│                   PRIVILEGE ESCALATION                      │
├────────────────────────────────────────────────────────────┤
│  • Kernel exploits                                          │
│  • Capability abuse (CAP_SYS_ADMIN, CAP_BPF)               │
│  • Container escape                                         │
│  • Misconfigured SUID binaries                             │
└────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────┐
│                   ROOTKIT DEPLOYMENT                        │
├────────────────────────────────────────────────────────────┤
│  • LKM loading (insmod/modprobe)                           │
│  • eBPF program attachment (bpf syscall)                   │
│  • LD_PRELOAD configuration                                │
│  • Persistence mechanisms                                   │
└────────────────────────────────────────────────────────────┘
```

---

## 5. Emerging Trends

### 5.1 eBPF as the New Frontier

eBPF is transforming the Linux malware landscape for several reasons:

1. **Portability**: Works across kernel versions without recompilation
2. **Stability**: Built-in verifier prevents crashes
3. **Stealth**: Operates at kernel level, below security tools
4. **Flexibility**: Multiple attachment points (XDP, TC, kprobes, tracepoints)

```
eBPF Rootkit Advantages over LKM:
┌─────────────────┬──────────────┬───────────────┐
│     Feature     │     LKM      │     eBPF      │
├─────────────────┼──────────────┼───────────────┤
│ Kernel Signing  │   Required*  │   Not needed  │
│ Portability     │   Low        │   High        │
│ Crash Risk      │   High       │   Low         │
│ Detection       │   Easier     │   Harder      │
│ Capabilities    │   Full       │   Limited**   │
│ Persistence     │   Easier     │   Harder      │
└─────────────────┴──────────────┴───────────────┘
* On Secure Boot systems
** But sufficient for rootkit functionality
```

### 5.2 Hybrid Approaches

Modern rootkits increasingly combine multiple techniques:

- **LinkPro**: eBPF primary + LD_PRELOAD fallback
- **PUMAKIT**: LKM + Ftrace + Userland components
- **Symbiote**: eBPF + LD_PRELOAD

### 5.3 Container/Cloud Targeting

- VMware ESXi specific targeting (UNC3886)
- AWS infrastructure compromises (LinkPro)
- Container escape + rootkit chains
- Orchestration platform abuse

### 5.4 io_uring Security Gap

A significant vulnerability: the `io_uring` interface allows rootkits to operate while bypassing advanced security software. This kernel interface for asynchronous I/O creates blind spots in security monitoring.

### 5.5 IPv6 and Protocol Evolution

2025 rootkit variants show:
- Full IPv6 support (BPFDoor, Symbiote)
- DNS traffic masquerading
- Multi-protocol operation (TCP/UDP/SCTP)
- Non-standard port usage

---

## 6. Threat Actor Usage

### 6.1 UNC3886 (Chinese APT)

**Timeline**: First reported 2022, active through 2025

**Targets**:
- VMware ESXi virtual machines
- Critical infrastructure (Singapore disclosed July 2024)
- Zero-day exploitation focus

**Toolset**:
```
UNC3886 Linux Rootkit Arsenal:
├── REPTILE (Primary)
│   ├── LKM-based concealment
│   ├── Port knocking C2
│   └── Credential theft
├── MEDUSA (Experimental)
│   ├── LD_PRELOAD hijacking
│   ├── PAM backdoor
│   └── Credential logging
└── SEAELF Loader
    └── Persistence mechanism
```

### 6.2 APT41/Winnti

**Association**: BPFDoor attribution (Mandiant)

**Targets**:
- South Asian government organizations
- Chinese multinational corporations
- Telecom sector

**Rootkit Evolution**:
- Early: Adore-ng variants
- Current: BPFDoor with continuous updates

### 6.3 Mustang Panda/HoneyMyte

**Active Campaign**: February 2025

**Characteristics**:
- Kernel-mode rootkit protecting ToneShell backdoor
- C2 servers registered September 2024
- Focus on SE Asian governments

---

## 7. Detection Challenges

### 7.1 Why Traditional Tools Fail

| Tool | Limitation |
|------|------------|
| chkrootkit | Signature-based; misses unknown rootkits |
| rkhunter | Pattern matching; defeated by polymorphism |
| Volatility | Requires memory capture timing |
| lsmod | Easily bypassed by hiding from lists |
| ps/top | Subject to syscall hooking |

### 7.2 eBPF-Specific Challenges

1. **Ephemeral Loading**: Programs can load, act, and unload quickly
2. **Legitimate Use**: eBPF is widely used for valid purposes
3. **Kernel-Level Operation**: Below most security tools
4. **setsockopt Abuse**: All eBPF socket filters use this syscall
5. **Map Hiding**: BPF maps can be pinned in unusual locations

### 7.3 Detection Approaches

```
Multi-Vector Detection Strategy:
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Behavioral Monitoring                          │
│    • Auditd (bpf syscall monitoring)                    │
│    • Falco/Tracee (runtime security)                    │
│    • Process behavior analysis                           │
├─────────────────────────────────────────────────────────┤
│  Layer 2: eBPF Enumeration                               │
│    • bpftool prog list                                  │
│    • bpftool net list                                   │
│    • /sys/fs/bpf monitoring                             │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Kernel Integrity                               │
│    • Syscall table verification                         │
│    • ftrace/kprobe enumeration                          │
│    • Module signature checking                           │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Memory Forensics                               │
│    • LiME/AVML memory acquisition                       │
│    • Volatility 3 analysis                              │
│    • YARA scanning                                       │
├─────────────────────────────────────────────────────────┤
│  Layer 5: Cross-Reference                                │
│    • Multiple enumeration method comparison              │
│    • procfs vs sysfs vs cgroups                         │
│    • Network socket analysis                             │
└─────────────────────────────────────────────────────────┘
```

---

## 8. Defensive Recommendations

### 8.1 Prevention

1. **Enable Secure Boot and Kernel Lockdown**
   - Requires signed modules
   - Blocks /dev/mem access
   - Prevents unsigned kernel modifications

2. **Restrict eBPF**
   ```bash
   # Disable unprivileged BPF
   sysctl kernel.unprivileged_bpf_disabled=1

   # Harden BPF JIT
   sysctl net.core.bpf_jit_harden=2
   ```

3. **Capability Management**
   - Minimize CAP_SYS_ADMIN distribution
   - Use CAP_BPF separately where needed
   - Container capability restrictions

4. **Kernel Parameter Hardening**
   ```bash
   kernel.kptr_restrict=2
   kernel.dmesg_restrict=1
   kernel.perf_event_paranoid=3
   kernel.yama.ptrace_scope=1
   ```

### 8.2 Detection

1. **Audit bpf() Syscalls**
   ```bash
   # /etc/audit/rules.d/ebpf.rules
   -a always,exit -F arch=b64 -S bpf -F key=ebpf_events
   ```

2. **Monitor eBPF Programs**
   ```bash
   # Continuous monitoring
   bpftool prog list
   bpftool net list
   ls -la /sys/fs/bpf/
   ```

3. **Deploy Runtime Security**
   - Tracee (Aqua Security)
   - Falco (Sysdig)
   - OSSEC/Wazuh

4. **Regular Memory Analysis**
   - Baseline comparison
   - Scheduled LiME captures
   - Volatility 3 with proper profiles

### 8.3 Response

1. **Memory Acquisition First**: Capture volatile evidence before shutdown
2. **Cross-Reference Everything**: Use multiple tools and methods
3. **Check for Persistence**: rc.local, systemd units, cron, module loading
4. **Network Analysis**: Look for magic packet patterns, unusual traffic

---

## 9. References

### Research Papers & Reports

- [The Hidden Threat: Analysis of Linux Rootkit Techniques](https://dl.acm.org/doi/10.1145/3688808) - ACM Digital Threats
- [In-Depth Study of Linux Rootkits: Evolution, Detection, and Defense](https://www.first.org/resources/papers/amsterdam25/FIRST_Amsterdam_2025_Linux_Rootkits.pdf) - FIRST 2025
- [Forensic Analysis of eBPF based Linux Rootkits](https://dfrws.org/forensic-analysis-of-ebpf-based-linux-rootkits/) - DFRWS EU 2023
- [Kernel-level hidden rootkit detection based on eBPF](https://www.sciencedirect.com/science/article/abs/pii/S0167404825002718) - ScienceDirect

### Threat Intelligence

- [UNC3886 Espionage Operations](https://cloud.google.com/blog/topics/threat-intelligence/uncovering-unc3886-espionage-operations) - Google Cloud/Mandiant
- [PUMAKIT Analysis](https://thehackernews.com/2024/12/new-linux-rootkit-pumakit-uses-advanced.html) - The Hacker News
- [HoneyMyte APT Rootkit](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/) - Kaspersky Securelist
- [LinkPro eBPF Rootkit Analysis](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis) - Synacktiv
- [BPFDoor and Symbiote Analysis](https://www.fortinet.com/blog/threat-research/new-ebpf-filters-for-symbiote-and-bpfdoor-malware) - FortiGuard Labs

### Technical Resources

- [eBPF Malware Analysis](https://redcanary.com/blog/threat-detection/ebpf-malware/) - Red Canary
- [BPF-Enabled Malware](https://www.trendmicro.com/vinfo/us/security/news/threat-landscape/how-bpf-enabled-malware-works-bracing-for-emerging-threats) - Trend Micro
- [Linux Rootkits Explained](https://www.wiz.io/blog/linux-rootkits-explained-part-2-loadable-kernel-modules) - Wiz
- [Reptile Malware Targeting Linux](https://asec.ahnlab.com/en/55785/) - ASEC

### Historical References

- [UNIX and Linux based Rootkits](https://www.first.org/resources/papers/conference2004/c17.pdf) - FIRST 2004
- [Linux Kernel Rootkits](https://www.giac.org/paper/gcux/243/linux-kernel-rootkits-protecting-systems-ring-zero/105411) - GIAC
- [List of Kernel Rootkits](https://la-samhna.de/library/rootkits/list.html) - la-samhna.de

---

*Document Version: 1.0*
*Last Updated: January 2025*
*Classification: Educational/Defensive Research*
