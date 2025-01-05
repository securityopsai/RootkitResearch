To Be used for learning only. Not malware grade detection stuff.
# Understanding Modern Linux Rootkits: From LKM to eBPF

Let's dive into how modern Linux rootkits work, particularly focusing on the shift from traditional LKM (Loadable Kernel Module) rootkits to the newer eBPF-based threats. This stuff gets pretty deep into kernel internals, so I'll break it down piece by piece.

First, let's look at how rootkits actually interface with the kernel:

```
    User Space        │        Kernel Space
    ────────────────────────────────────────────
    Process List      │        eBPF Programs
    ps, top, etc      │        Syscall Hooks
         │           │             │
         ▼           │             ▼
    syscall() ──────►│────► Intercepted Call
         ▲           │             │
         │           │             ▼
    Modified Data ◄──│◄──── Malicious Logic
    ────────────────────────────────────────────
```

## Kernel Space Access Control

Kernel space execution privileges vary significantly across Windows, macOS, and Linux, reflecting different approaches to system security and control:

- Windows: Only code signed by Microsoft or approved hardware vendors can run in kernel space. This centralized control enhances security but limits flexibility.
- macOS: Apple enforces strict code signing requirements for kernel extensions, with notarization required since macOS Catalina. This approach balances security with some developer freedom.
- Linux: Traditionally allows unsigned code to run in kernel space, offering maximum flexibility but potentially higher security risks.

### Understanding Linux Kernel Memory Layout
```
High Memory ─────► ┌────────────────────┐
                  │   Kernel Modules    │
                  ├────────────────────┤
                  │   Kernel Code      │
                  ├────────────────────┤
                  │   eBPF Programs    │
                  ├────────────────────┤
Low Memory ─────► │   User Space       │
                  └────────────────────┘
```

The Linux kernel's memory space is strictly segregated from user space, with several key regions:

1. **Kernel Text Segment** 
   - Contains core kernel code
   - Read-only after boot
   - Primary target for rootkit hooks

2. **Kernel Data** 
   - Runtime kernel data structures
   - Writable memory region
   - Common location for rootkit modifications

3. **Module Space** 
   - Loadable kernel modules
   - Dynamic code execution area
   - Preferred location for LKM rootkits

Centralized control through code signing provides several benefits:
- Malware prevention: Reduces the risk of malicious code execution in privileged space
- System stability: Helps ensure only vetted, compatible code runs at the kernel level
- Accountability: Creates a chain of trust for kernel-level software

### Kernel Security Mechanisms
Before we dive deeper, let's look at the security features modern kernels use to make life harder for rootkits:

1. KASLR (Kernel Address Space Layout Randomization)
```bash
# Check if KASLR is enabled
cat /proc/cmdline | grep kaslr
# See where the kernel got randomized to
sudo dmesg | grep 'Kernel Base'
```

2. SMAP/SMEP Protection (Supervisor Mode Access/Execution Prevention)
```bash
# Check if your CPU supports these
grep -E 'smap|smep' /proc/cpuinfo
# Verify kernel config
cat /boot/config-$(uname -r) | grep -E 'SMAP|SMEP'
```

3. KPTI (Kernel Page Table Isolation)
```bash
# Check KPTI status
cat /proc/cmdline | grep pti
# Look at interrupt handling
cat /proc/interrupts | grep NMI
```

## Kernel Compatibility Challenges

Traditional rootkits using LKMs have always been a pain to develop. Here's why:

- Kernel versions are all over the place. What works on Ubuntu 20.04 might crash Fedora 37
- Modern kernels do integrity checks that can catch unauthorized modifications
- One wrong move and you trigger a kernel panic, which is like waving a big red flag
- You need serious kernel development skills to write one that doesn't crash

But then eBPF came along and changed the game.

## The eBPF Game-Changer

eBPF (extended Berkeley Packet Filter) showed up in Linux 3.18 back in 2014, and it's pretty much revolutionized how we can interact with the kernel. Here's how it fits into the kernel:

```
User Space                 Kernel Space
──────────────────────────────────────────
                         ┌──────────────┐
                         │ eBPF Verifier│
                         └──────────────┘
                               ▲
┌──────────────┐               │
│eBPF Program  │──────────────►│
└──────────────┘               │
                         ┌──────────────┐
                         │eBPF VM      │
                         └──────────────┘
                               │
                               ▼
                         ┌──────────────┐
                         │Kernel Hooks  │
                         └──────────────┘
```

The cool (or scary) thing about eBPF is that it lets you run code in kernel context without actually modifying the kernel or loading kernel modules. Here's what makes it special:

- It's got a built-in verifier that checks your code won't crash the kernel
- You can hook into pretty much any kernel subsystem
- It's portable across kernel versions
- You can update your programs on the fly without reboots

## How eBPF Rootkits Work

Let's look at some actual eBPF rootkit code. Here's how they hook into different parts of the system:

1. Hooking system calls:
```c
SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    // This is where you'd hide processes or modify execution
    return 0;
}
```

2. Messing with network traffic:
```c
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    // Filter or modify network packets here
    return XDP_PASS;
}
```

3. Intercepting file operations:
```c
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    // Hide files or modify file operations
    return 0;
}
```

## The Process Hiding Game

When you run something like `ps` or `top`, here's what actually happens:

1. The shell forks a new process
2. execve() loads the ps binary
3. ps tries to read /proc for process info
4. It uses getdents64() to list directory entries
5. Reads /proc/[pid]/stat for each process
6. Writes the output to your terminal

A rootkit can mess with this flow in several ways:
- Hook getdents64() to filter out process entries
- Modify the data in /proc/[pid]/stat
- Inject fake process info
- Directly modify kernel memory structures
- Hide entire directories in /proc

## LKM vs eBPF Rootkits: The Trade-offs

Here's how they stack up:

Feature | LKM Rootkits | eBPF Rootkits
--------|--------------|---------------
Kernel Access | Full access | Limited, verified
Persistence | Survives reboots | Usually temporary
Portability | Version-specific | Works across versions
Detection | Easier to spot | Harder to find
Stability | Can crash system | Pretty stable
Flexibility | Do anything | Limited by verifier

## Advanced Detection Methods

### Kernel Memory Analysis
Let's get deeper into memory forensics. Here's a more comprehensive approach:

```bash
# Create a full memory dump
sudo dd if=/dev/mem of=/tmp/memdump bs=1M count=1024

# Look for hidden processes
sudo volatility -f /tmp/memdump linux_pslist
sudo volatility -f /tmp/memdump linux_pstree

# Check loaded modules
sudo volatility -f /tmp/memdump linux_lsmod
sudo volatility -f /tmp/memdump linux_kernel_opened_files

# Network connections
sudo volatility -f /tmp/memdump linux_netstat
sudo volatility -f /tmp/memdump linux_arp
```

### System Call Table Analysis
Here's how to dig deeper into syscall hooks:

```bash
# Get the syscall table address
sudo cat /proc/kallsyms | grep sys_call_table

# Monitor specific syscalls
sudo strace -e trace=process,network,file ps aux

# Watch for syscall modifications
sudo sysdig -c spy_users

# Check for inline hooks
sudo cat /proc/kallsyms | grep -E "sys_|syscall" | sort
```

### Network Traffic Analysis
Let's look at some advanced network monitoring:

```bash
# Watch for covert channels
sudo tcpdump -i any 'tcp[tcpflags] & (tcp-syn) != 0'

# Monitor specific ports
sudo tcpdump -i any port 31337 or port 4444

# Track eBPF network programs
sudo bpftool net list
sudo bpftool prog show

# Check for unusual traffic patterns
sudo netstat -plant | grep ESTABLISHED
```

Example of suspicious patterns:
```
# Potential C2 traffic
IP 192.168.1.100.31337 > 10.0.0.1.443: TCP SYN
IP 10.0.0.1.443 > 192.168.1.100.31337: TCP SYN-ACK

# Hidden service
TCP 127.0.0.1:8000 (LISTEN) [hidden]
```

### File System Timeline Analysis
Here's how to create and analyze a detailed filesystem timeline:

```bash
# Create timeline
sudo fls -m / -r /dev/sda1 > filesystem.csv
mactime -b filesystem.csv > timeline.txt

# Look for suspicious patterns
grep "2023-12-" timeline.txt | grep -E "execute|modify"
grep -E "insmod|rmmod" timeline.txt

# Track file changes
sudo inotifywait -m -r /lib/modules/ -e modify,attrib,create,delete
```

### Real-time Monitoring Scripts

1. Process Monitor (with memory maps):
```bash
#!/bin/bash
# Save as process_monitor.sh
while true; do
    # Get process list with memory maps
    for pid in $(ps aux | awk '{print $2}'); do
        if [ -f /proc/$pid/maps ]; then
            echo "=== PID $pid ==="
            cat /proc/$pid/maps 2>/dev/null
        fi
    done > /tmp/current_maps
    
    # Compare with previous state
    diff /tmp/last_maps /tmp/current_maps 2>/dev/null
    mv /tmp/current_maps /tmp/last_maps
    sleep 1
done
```

2. Enhanced Syscall Hook Detector:
```bash
#!/bin/bash
# Save as hook_detector.sh

SYSCALL_TABLE=$(sudo cat /proc/kallsyms | grep sys_call_table | awk '{print $1}')

# Check for common hooked syscalls
TARGETS=("sys_read" "sys_write" "sys_execve" "sys_getdents64")

for syscall in "${TARGETS[@]}"; do
    ADDR=$(sudo cat /proc/kallsyms | grep $syscall | awk '{print $1}')
    echo "Checking $syscall at $ADDR"
    
    # Read the first bytes to check for hooks
    BYTES=$(sudo dd if=/dev/mem bs=1 count=8 skip=$((0x$ADDR)) 2>/dev/null | xxd -p)
    
    # Check for common hook patterns
    if [[ $BYTES =~ ^(e9|ff|48b8) ]]; then
        echo "WARNING: Possible hook detected in $syscall"
    fi
done
```

3. Advanced eBPF Monitor:
```bash
sudo bpftrace -e '
tracepoint:bpf:bpf_prog_load { 
    printf("BPF Program Loaded:\n"); 
    printf("  Type: %d\n", args->prog_type);
    printf("  Tag: %s\n", str(args->prog_tag));
    printf("  Name: %s\n", str(args->prog_name));
    printf("  License: %s\n", str(args->license));
    printf("  Verified instructions: %d\n", args->prog_len);
    time("%H:%M:%S ");
}

tracepoint:bpf:bpf_prog_get_type {
    printf("BPF Program Type Access:\n");
    printf("  ID: %d\n", args->prog_id);
    time("%H:%M:%S ");
}

tracepoint:bpf:bpf_prog_put {
    printf("BPF Program Unloaded:\n");
    printf("  ID: %d\n", args->prog_id);
    time("%H:%M:%S ");
}'
```

## Useful Tools

Let's look at some specialized tools for rootkit detection. I'll break down what each one does and how effective they are:

1. Process Decloak (Sand Fly Security):
```bash
# Installation from GitHub
git clone https://github.com/sandflysecurity/sandfly-processdecloak.git
cd sandfly-processdecloak
make

# Usage
sudo ./processdecloak
```
What makes this tool special:
- Uses multiple methods to find hidden processes
- Bypasses common rootkit hiding techniques
- Compares different process listing methods
- Particularly effective against eBPF-based hiding
- Low false positive rate

2. File Decloak (Sand Fly Security):
```bash
# Installation
git clone https://github.com/sandflysecurity/sandfly-filedecloak.git
cd sandfly-filedecloak
make

# Usage
sudo ./filedecloak /path/to/check
```
Key features:
- Finds files hidden by rootkits
- Compares different file listing methods
- Checks for directory entry manipulation
- Detects common rootkit file hiding techniques
- Works well with Process Decloak for complete system analysis

3. chkrootkit:
```bash
# Installation
sudo apt install chkrootkit

# Basic scan
sudo chkrootkit

# Thorough scan with all tests
sudo chkrootkit -x

# Check specific areas
sudo chkrootkit -r /suspicious/directory
```
Effectiveness:
- Good for known rootkit signatures
- Can have false positives
- Might miss sophisticated eBPF rootkits
- Best used alongside other tools

4. rkhunter (Rootkit Hunter):
```bash
# Installation
sudo apt install rkhunter

# Update database
sudo rkhunter --update

# Full system check (skip common false positives)
sudo rkhunter --check --sk

# Check specific areas
sudo rkhunter --check --rwo
```
Strengths:
- Comprehensive system checks
- Regular signature updates
- Good for traditional rootkits
- File integrity checking

5. OSSEC:
```bash
# Installation
sudo apt install ossec-hids

# Configure (important - needs proper setup)
sudo ossec-control configure

# Start monitoring
sudo ossec-control start

# Check status
sudo ossec-control status
```
Benefits:
- Real-time monitoring
- File integrity checking
- Log analysis
- Rootkit detection module

6. Lynis:
```bash
# Installation
sudo apt install lynis

# Full system audit
sudo lynis audit system

# Focus on malware/rootkit checks
sudo lynis audit system --tests-from-group malware,kernel,security
```
Advantages:
- Comprehensive system auditing
- Security best practice checks
- Regular updates
- Detailed reports

### Tool Combination Strategy

For effective rootkit detection, use these tools together:

1. Regular Monitoring:
```bash
# Daily checks (add to cron)
sudo processdecloak > /var/log/security/proc_check_$(date +%F).log
sudo filedecloak / > /var/log/security/file_check_$(date +%F).log
sudo rkhunter --check --sk >> /var/log/security/rkhunter_$(date +%F).log
```

2. Weekly Deep Scan:
```bash
# Comprehensive check (add to weekly cron)
sudo chkrootkit -x > /var/log/security/chkrootkit_$(date +%F).log
sudo lynis audit system > /var/log/security/lynis_$(date +%F).log
```

3. Real-time Monitoring:
```bash
# Set up continuous monitoring
sudo ossec-control start
sudo auditd -f # For audit daemon
```

4. Custom Integration Script:
```bash
#!/bin/bash
# Save as rootkit_check.sh

echo "=== Process Check ==="
sudo processdecloak

echo "=== File System Check ==="
sudo filedecloak /

echo "=== Kernel Module Check ==="
lsmod | while read -r mod others; do
    echo "Checking $mod"
    modinfo "$mod" | grep -E "filename|version|description"
done

echo "=== System Call Table Check ==="
sudo cat /proc/kallsyms | grep sys_call_table

echo "=== eBPF Program Check ==="
sudo bpftool prog list
```

## Further Reading

If you want to dig deeper into this stuff:
- Linux Kernel docs: [kernel.org](https://www.kernel.org/doc/html/latest/)
- eBPF docs: [ebpf.io](https://ebpf.io/what-is-ebpf/)
- Volatility Framework: [volatilityfoundation.org](https://www.volatilityfoundation.org/)
- Linux Audit Framework: [linux-audit.com](https://linux-audit.com/)
