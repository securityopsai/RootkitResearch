

---

## 1. Evolving Kernel Security Landscape

### 1.1 Secure Boot and Kernel Lockdown

1. **Secure Boot**  
   On many modern systems (e.g., Ubuntu, Fedora, RHEL), Secure Boot requires that any kernel modules loaded at boot be signed by a trusted authority. Attackers who don’t have their modules properly signed will either fail to load them or must disable Secure Boot—often leaving a clear audit trail behind.

2. **Lockdown Mode**  
   Linux distributions increasingly use “lockdown” modes that restrict kernel functionality even when running as root. Lockdown can disallow direct kernel memory writes from user space, block access to `/dev/mem`, or forbid loading unsigned modules unless specifically configured otherwise.

**Impact on Rootkits**:

- **LKM** rootkits cannot simply insert unsigned modules in many out-of-the-box enterprise distributions.
- **eBPF** can still be loaded if the attacker has the right privileges (commonly `CAP_SYS_ADMIN` or `CAP_BPF`), but hooking ephemeral eBPF programs can be stealthier and bypass many traditional scanning tools.

### 1.2 KASLR, SMAP/SMEP, and KPTI

The kernel’s built-in defenses—KASLR (randomizing kernel memory), SMAP/SMEP (preventing kernel from executing or accessing user-space memory incorrectly), and KPTI (separating user/kernel page tables)—raise the bar for typical attacks. However, these don’t necessarily prevent a privileged attacker from loading eBPF code or hooking the kernel with a well-crafted LKM.

---

## 2. LKM Rootkits on Modern Systems

### 2.1 Challenges with Unsigned Modules

While older tutorials often demonstrate building an LKM and running `insmod <module.ko>` to compromise a system, modern Secure Boot setups will typically fail to load an unsigned module. Attackers might:

- **Disable Secure Boot** if they control the BIOS/UEFI settings.
- **Abuse a known-signed but vulnerable module** for hooking.
- **Exploit a zero-day** in the module loading process or use a key stolen from a trusted entity.

### 2.2 Ftrace and Kprobe-Based Hooks

Instead of patching the syscall table directly, modern LKM rootkits often use **ftrace** or **kprobes** to hook internal kernel functions. This approach can be subtler than the old method of overwriting the syscall table or function prologues with jump instructions.

**Detection**:

- Standard module listing (`lsmod`) may not reveal malicious modules if they remove themselves from `/proc/modules`.
- Inline patch detection is trickier if hooking is done via legitimate kernel mechanisms like ftrace.

---

## 3. eBPF Rootkits: The “Stealthier” Alternative

### 3.1 Why eBPF?

1. **Portability**  
   eBPF code can often run across different kernels without recompilation.

2. **Verifier**  
   The in-kernel verifier ensures the program won’t crash or do out-of-bounds writes—but doesn’t stop malicious, in-bounds logic.

3. **Varied Hooks**  
   eBPF can attach to networking (XDP, tc), tracepoints (syscalls, kernel events), and uprobes (user-space). This breadth grants rootkit authors many angles to intercept and manipulate data.

4. **Ephemeral Loading**  
   A malicious eBPF program can load, do its work briefly, then unload to reduce detection windows.

### 3.2 Privilege Requirements

Modern kernels typically allow eBPF program loading only with `CAP_SYS_ADMIN`, `CAP_BPF`, or a similarly high privilege set. On a hardened system, an attacker must escalate to these privileges before loading eBPF code. That said, many real-world servers run processes with `CAP_SYS_ADMIN` (especially in container or orchestration environments) if not carefully locked down.

---

## 4. Real-World Memory Forensics

### 4.1 The `/dev/mem` Restriction

On up-to-date distributions with kernel lockdown or secure boot, reading arbitrary kernel memory via `/dev/mem` is often blocked above a minimal range. *Old advice* like:

```bash
sudo dd if=/dev/mem of=/tmp/memdump bs=1M
```

… typically fails or yields partial data on modern systems.

### 4.2 Recommended Tools: LiME and fmem

- **LiME (Linux Memory Extractor)**  
  A kernel module specifically designed to dump RAM while minimizing its own footprint. Still subject to module signing issues if Secure Boot is active.

- **fmem**  
  Another specialized driver for memory acquisition. Similar constraints apply regarding module loading.

**Volatility** (2.x or 3.x) or **Rekall** can parse these dumps, but you must have the correct kernel profiles (Volatility 2) or symbol tables (Volatility 3). For ephemeral eBPF rootkits, you’ll need to capture memory *while* the rootkit’s code is loaded; if the attacker unloads it, your memory snapshot may miss the malicious program.

---

## 5. Hook Detection Strategies That *Actually Work*

### 5.1 Syscall Table Checking: Still Relevant, but Limited

On many systems, the syscall table is read-only after boot, and changes are more suspicious. However, advanced rootkits use other hooking methods (ftrace, kprobes, eBPF). Checking the table alone won’t catch those.

**Key Tools**  
- **SystemTap or eBPF-based detectors**  
  Tools that trace kernel functions can help detect anomalies, but ironically, they rely on eBPF themselves and might be circumvented by a truly advanced eBPF-based rootkit.

### 5.2 Ftrace and kprobe Visibility

To detect if ftrace or kprobes are used maliciously:

```bash
# Check debugfs for tracing
ls -l /sys/kernel/debug/tracing/func*
cat /sys/kernel/debug/tracing/trace
```

Use `trace-cmd`, `perf`, or `bpftrace` to see if unusual kernel functions are being traced. However, a rootkit might hide or repeatedly attach/detach hooks, so monitoring must be continuous.

### 5.3 eBPF Program Enumeration

```bash
# Show loaded eBPF programs
sudo bpftool prog list

# Check networking attachments
sudo bpftool net list

# Inspect pinned eBPF objects
ls -l /sys/fs/bpf/
```

1. **Continuous Monitoring**  
   Attackers could load an eBPF program briefly and then remove it. Tools like `bpftrace` can monitor events like `tracepoint:bpf:bpf_prog_load` and `tracepoint:bpf:bpf_prog_unload` in real time.

2. **Hidden BPF Maps/Pins**  
   If the rootkit pins eBPF maps in unusual mount points, you’ll need to scan for them across the entire system, not just the default `/sys/fs/bpf`.

---

## 6. Behavior-Based Detection on Modern Systems

### 6.1 Host Intrusion Detection Systems (HIDS)

- **OSSEC/Wazuh**  
  Real-time log analysis, file integrity checks, rootkit detection modules. May not directly detect ephemeral eBPF hooking, but can flag suspicious behaviors (like kernel messages, unusual logins, or changes to `/sys/fs/bpf`).

- **Auditd**  
  Linux’s audit framework can log `bpf()` syscalls if configured properly. This is often the best approach to catch attempts to load or modify eBPF programs. You’ll need entries like:

  ```bash
  -a exit,always -F arch=b64 -S bpf -k ebpf_load
  ```

### 6.2 EDR/Extended Detection & Response

Some commercial EDR solutions now monitor eBPF usage as part of kernel telemetry. They can detect ephemeral hooking by analyzing the sequence of system calls around BPF load/unload events—provided the sensor has enough access to kernel events.

---

## 7. Practical Scripts & Approaches

Below are updated script snippets and workflows that actually stand a chance on locked-down systems. Note that each still assumes certain privileges; otherwise, you won’t see kernel-level changes.

### 7.1 bpftrace-based Monitor

```bash
sudo bpftrace -e '
tracepoint:bpf:bpf_prog_load {
    printf("BPF load event: prog_type=%d, id=%d
", args->prog_type, args->prog_id);
}

tracepoint:bpf:bpf_prog_unload {
    printf("BPF unload event: id=%d
", args->prog_id);
}
'
```

- **Pros**: Catches program loads and unloads in real time.  
- **Cons**: Attackers can momentarily disable or block instrumentation if they manage the kernel’s tracing features.

### 7.2 Auditd Configuration for eBPF Calls

```bash
# /etc/audit/rules.d/ebpf.rules
-a always,exit -F arch=b64 -S bpf -F key=ebpf_events

# Then load the rule
sudo auditctl -R /etc/audit/rules.d/ebpf.rules
```

- **Pros**: Writes an audit log entry whenever a bpf() syscall is made (for program load, map create, etc.).  
- **Cons**: If the rootkit subverts or disables auditd itself, logs may be tampered with.

### 7.3 Checking ftrace Hooks

```bash
ls -l /sys/kernel/debug/tracing/func*
cat /sys/kernel/debug/tracing/trace
```

Look for unexpected function hooks. However, a determined rootkit may modify or hide entries in debugfs.

---

## 8. Specialized Tools for Modern Rootkits

1. **Lynis**  
   Good for auditing overall security posture. Won’t specifically unmask ephemeral eBPF code but can warn about insecure kernel settings (e.g., unprotected bpf syscalls).

2. **chkrootkit / rkhunter**  
   Still relevant for finding known LKM patterns or outdated rootkits. Less effective against brand-new or ephemeral eBPF malware.

3. **Process Decloak / File Decloak (Sand Fly)**  
   Cross-check multiple syscalls and enumeration methods to detect hidden processes/files. May catch certain hooking anomalies, especially if the rootkit modifies process or file listings.

4. **Volatility 3**  
   If you can capture memory with LiME/fmem, Volatility 3 plus the correct symbol table can analyze kernel structures, search for suspicious code regions, or reveal hidden eBPF programs pinned in memory. Ephemeral hooking can still vanish before you dump memory, so timing is key.

---

## 9. Putting It All Together

1. **Secure Boot & Lockdown**  
   Keep them enabled in production; require all modules to be signed. This alone thwarts many “classic” LKM rootkits.

2. **Restrict eBPF**  
   Only allow eBPF if you truly need it. Consider using `seccomp` or system policies (SELinux, AppArmor) to block or log `bpf()` calls.

3. **Audit & HIDS**  
   Enable `auditd` to track `bpf()` calls, maintain an active HIDS/EDR for real-time alerts.

4. **Memory Forensics**  
   If you suspect a compromise, use LiME to capture RAM and analyze with Volatility 3 or Rekall. Combine that with continuous bpftrace or ftrace checks to catch ephemeral hooking in real time.

5. **Regular Monitoring**  
   Tools like `bpftool prog list` or `bpftool net list` should be part of routine health checks. Compare against known baselines.

By following these practices—especially focusing on ephemeral hooking detection and proactive eBPF monitoring—admins can better catch modern stealth rootkits that slip under older detection radars.

---

## 10. Further Reading

- **Linux Kernel Documentation**: [kernel.org/doc/html/latest/](https://www.kernel.org/doc/html/latest/)  
- **eBPF Project**: [ebpf.io](https://ebpf.io/)  
- **LiME (Linux Memory Extractor)**: [GitHub - 504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME)  
- **Volatility 3**: [VolatilityFoundation/volatility3](https://github.com/volatilityfoundation/volatility3)  
- **Trace and Debug**: [trace-cmd.org](https://trace-cmd.org/)

