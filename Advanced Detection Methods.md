
## Advanced Detection Methods

### Modern Memory Forensics

Memory acquisition and analysis should be performed carefully on modern Linux systems. Here's the recommended approach:

#### 1. Preparation (on Forensics Workstation)

First, verify your forensics environment is properly isolated:
```bash
# Check if system is properly isolated
ip link | grep -v LOOPBACK | grep UP
iptables -L
sestatus  # SELinux should be enforcing
```

Required tools and security setup:
```bash
# Install dependencies
sudo apt-get update && sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    python3-pip \
    python3-dev \
    git \
    cryptsetup

# Install Volatility3 from source for reproducibility
git clone --depth 1 --branch 2.4.0 https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 -m pip install -r requirements.txt
python3 setup.py install

# Verify installation
python3 -m volatility3 -h 2>&1 | grep "Volatility 3 Framework"
```

Prepare encrypted storage:
```bash
# Create encrypted container for memory dumps
sudo truncate -s $(grep MemTotal /proc/meminfo | awk '{print $2 * 2.5}')K secure_dump.img
sudo cryptsetup -v --type luks2 --verify-passphrase luksFormat secure_dump.img
sudo cryptsetup luksOpen secure_dump.img secure_dump
sudo mkfs.ext4 /dev/mapper/secure_dump

# Mount with proper flags
sudo mkdir -p /mnt/secure_dump
sudo mount -o noexec,nodev,nosuid /dev/mapper/secure_dump /mnt/secure_dump
sudo chown $(whoami):$(whoami) /mnt/secure_dump
```

#### 2. Memory Acquisition (on Target System)

IMPORTANT: Document everything! Create an acquisition log:
```bash
exec 1> >(tee "acquisition_$(date +%Y%m%d_%H%M%S).log")
exec 2>&1
echo "Starting acquisition at $(date)"
echo "System info:"
uname -a
```

a. Using AVML (for modern systems):
```bash
# On forensics workstation
wget https://github.com/microsoft/avml/releases/download/v0.10.0/avml
echo "d7a39b2463aa... expected_sha256sum" | sha256sum -c  # Verify download

# Secure transfer (DO NOT USE nc!)
# Option 1: SSH with compression
rsync -e "ssh -c aes256-gcm@openssh.com -C" avml user@target:/tmp/

# Option 2: If SSH unavailable, use age encryption
age-keygen -o key.txt
age -e -r age1... avml > avml.age  # Transfer this file
age -d -i key.txt avml.age > avml  # On target

# On target system
DUMPPATH="/tmp/memdump_$(date +%Y%m%d_%H%M%S).raw"
chmod 700 /tmp/avml
/tmp/avml $DUMPPATH

# Generate hashes with device info
(
    echo "Acquisition device:"
    lsblk -f
    echo "SHA256 hash:"
    sha256sum "$DUMPPATH"
    echo "Acquisition completed at $(date)"
) | tee "${DUMPPATH}.meta"

# Secure transfer back (using SSH with compression)
rsync -e "ssh -c aes256-gcm@openssh.com -C" \
    "$DUMPPATH"* forensics:/mnt/secure_dump/
```

b. Using LiME (when kernel module loading is acceptable):
```bash
# On a BUILD system with MATCHING kernel
# DO NOT build on target or forensics system!
git clone --depth 1 https://github.com/504ensicsLabs/LiME
cd LiME/src
make
KMOD_SHA256=$(sha256sum lime-$(uname -r).ko)

# Transfer and verify on target
# Use same secure transfer methods as above
echo "$KMOD_SHA256" | sha256sum -c

# Load module and capture
DUMPPATH="/tmp/memdump_$(date +%Y%m%d_%H%M%S).lime"
sudo insmod ./lime-$(uname -r).ko "path=$DUMPPATH format=lime"
sudo rmmod lime

# Generate metadata and transfer
# Use same process as AVML section
```

#### 3. Analysis (on Forensics Workstation)

IMPORTANT: Never run analysis tools on the target system!

Setup analysis environment:
```bash
# Create isolated analysis directory
mkdir -p ~/analysis/$(date +%Y%m%d_%H%M%S)
cd ~/analysis/$(date +%Y%m%d_%H%M%S)

# Copy dump maintaining chain of custody
cp /mnt/secure_dump/memdump* .
sha256sum -c memdump*.meta

# Use full paths to avoid PATH manipulation
VOLATILITY="/usr/local/bin/python3 -m volatility3"

# Initial triage
$VOLATILITY -f memdump*.raw windows.info.Info > 000_image_info.txt
$VOLATILITY -f memdump*.raw linux.status.Status > 001_kernel_status.txt

# Process analysis (save all output!)
for plugin in pslist pstree psaux proc_maps proc_info; do
    $VOLATILITY -f memdump*.raw linux.$plugin > "002_${plugin}.txt"
done

# Kernel analysis
for plugin in lsmod check_syscall check_modules check_idt; do
    $VOLATILITY -f memdump*.raw linux.$plugin > "003_${plugin}.txt"
done

# Network analysis
for plugin in netstat sockstat; do
    $VOLATILITY -f memdump*.raw linux.$plugin > "004_${plugin}.txt"
done

# YARA scanning (use specific rules)
cat > rootkit_rules.yar << 'EOF'
rule suspicious_kernel_mod {
    strings:
        $s1 = "sys_call_table" nocase
        $s2 = "unlink_module" nocase
        $s3 = "_do_fork" nocase
    condition:
        any of them
}
EOF

$VOLATILITY -f memdump*.raw yarascan.YaraScan --yara-file=rootkit_rules.yar > 005_yara_scan.txt
```

#### Important Considerations for Modern Systems:

1. KASLR Impact:
   - Kernel addresses are randomized on each boot
   - Volatility3 handles this automatically via kernel symbol parsing

2. KPTI (Kernel Page Table Isolation):
   - Separate kernel/user page tables
   - Memory dumps contain both spaces

3. eBPF Programs:
   - Check for unauthorized eBPF programs
   - Use `linux.bpf_prog` plugin if available

4. Integrity Verification:
   - Always verify memory image hashes
   - Document acquisition process
   - Maintain chain of custody

5. Analysis Caveats:
   - Modern rootkits may detect analysis tools
   - Cross-reference multiple data sources
   - Consider live response data alongside memory analysis

### Kernel Security Validation

IMPORTANT: Modern Linux systems use multiple layers of security. Checking KASLR alone is insufficient.

```bash
#!/bin/bash
# Security validation for modern Linux kernels
# Requires: root, debugfs, sysfs

set -euo pipefail
IFS=$'\n\t'

# Log all output
exec 1> >(tee "kernel_security_$(date +%Y%m%d_%H%M%S).log")
exec 2>&1

# Function to check security prerequisites
check_security_prereqs() {
    # Check for root
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Must run as root"
        exit 1
    fi

    # Check SELinux/AppArmor
    if command -v getenforce >/dev/null 2>&1; then
        if [[ $(getenforce) != "Enforcing" ]]; then
            echo "WARNING: SELinux not in enforcing mode"
        fi
    elif command -v aa-status >/dev/null 2>&1; then
        if ! aa-status | grep -q "apparmor module is loaded"; then
            echo "WARNING: AppArmor not loaded"
        fi
    else
        echo "WARNING: No LSM (SELinux/AppArmor) detected"
    fi

    # Check secure boot
    if ! mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
        echo "WARNING: Secure Boot not enabled"
    fi
}

# Function to check kernel security features
check_kernel_security() {
    echo "Checking kernel security features..."
    
    # Check kernel command line securely
    local cmdline
    cmdline=$(cat /proc/cmdline)
    
    # KASLR
    if echo "$cmdline" | grep -q "nokaslr"; then
        echo "CRITICAL: KASLR disabled via kernel parameter"
    fi
    
    # KPTI
    if echo "$cmdline" | grep -q "nopti"; then
        echo "CRITICAL: KPTI (Page Table Isolation) disabled"
    fi
    
    # SMAP/SMEP
    if ! grep -q "smep" /proc/cpuinfo || ! grep -q "smap" /proc/cpuinfo; then
        echo "WARNING: SMAP/SMEP not available in CPU"
    fi

    # Check sysctl security settings
    local sysctl_checks=(
        "kernel.kptr_restrict:2"
        "kernel.dmesg_restrict:1"
        "kernel.perf_event_paranoid:3"
        "kernel.yama.ptrace_scope:1"
        "kernel.unprivileged_bpf_disabled:1"
        "net.core.bpf_jit_harden:2"
    )

    for check in "${sysctl_checks[@]}"; do
        local key="${check%:*}"
        local expected="${check#*:}"
        local actual
        
        if actual=$(sysctl -n "$key" 2>/dev/null); then
            if [[ "$actual" != "$expected" ]]; then
                echo "WARNING: $key = $actual (expected $expected)"
            fi
        else
            echo "WARNING: Could not check $key"
        fi
    done
}

# Function to validate kernel module security
check_module_security() {
    echo "Checking module security..."
    
    # Check module signing enforcement
    if ! grep -q "^1$" /proc/sys/kernel/modules_disabled 2>/dev/null; then
        echo "WARNING: Runtime module loading not disabled"
    fi
    
    if ! grep -q "^1$" /proc/sys/kernel/module_signature_required 2>/dev/null; then
        echo "WARNING: Module signature verification not required"
    fi

    # Check loaded modules
    echo "Checking loaded modules..."
    while read -r module; do
        # Skip empty lines
        [[ -z "$module" ]] && continue
        
        # Extract module name
        local name="${module%% *}"
        
        # Check if module is signed
        if ! modinfo "$name" 2>/dev/null | grep -q "^signature:"; then
            echo "WARNING: Unsigned module: $name"
        fi
    done < <(lsmod | tail -n +2)
}

# Function to check for common rootkit indicators
check_rootkit_indicators() {
    echo "Checking for rootkit indicators..."
    
    # Check for hidden kernel modules
    local modules_sysfs=()
    local modules_proc=()
    
    # Get modules from sysfs
    while read -r module; do
        modules_sysfs+=("$module")
    done < <(find /sys/module -mindepth 1 -maxdepth 1 -type d -printf "%f\n")
    
    # Get modules from /proc/modules
    while read -r module; do
        modules_proc+=("${module%% *}")
    done < <(cat /proc/modules)
    
    # Compare lists
    for module in "${modules_sysfs[@]}"; do
        if [[ ! " ${modules_proc[*]} " =~ " ${module} " ]]; then
            echo "ALERT: Module $module found in sysfs but not in /proc/modules"
        fi
    done
    
    # Check for syscall table modifications
    if ! diff <(cat /proc/kallsyms | grep "sys_call_table" | head -1) \
              <(cat /boot/System.map-"$(uname -r)" | grep "sys_call_table" | head -1) >/dev/null 2>&1; then
        echo "ALERT: Possible syscall table modification detected"
    fi
}

# Main execution
{
    echo "Starting kernel security validation at $(date)"
    echo "Kernel: $(uname -a)"
    echo
    
    check_security_prereqs
    check_kernel_security
    check_module_security
    check_rootkit_indicators
    
    echo
    echo "Validation completed at $(date)"
} 2>&1 | tee -a kernel_security.log

# Secure the log
chmod 600 kernel_security.log
```

### Modern System Call Monitoring

IMPORTANT: Modern rootkits often exploit multiple vectors. Single-vector detection is insufficient.

```bash
#!/bin/bash
# Comprehensive system call monitoring for modern Linux systems
# Requires: root, Linux 5.8+, proper capabilities

set -euo pipefail
IFS=$'\n\t'

readonly WORK_DIR="/var/lib/syscall_monitor"
readonly LOG_DIR="/var/log/syscall_monitor"
readonly SCRIPT_NAME="$(basename "$0")"

# Function to validate environment
check_environment() {
    # Check for root or proper capabilities
    if [[ $EUID -ne 0 ]]; then
        if ! capsh --print | grep -q "cap_sys_admin"; then
            echo "ERROR: Requires root or CAP_SYS_ADMIN capability"
            exit 1
        fi
    fi

    # Check kernel version (requires 5.8+)
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1,2)
    local min_version="5.8"
    if [[ "$(printf '%s\n' "$min_version" "$kernel_version" | sort -V | head -n1)" != "$min_version" ]]; then
        echo "ERROR: Requires Linux kernel 5.8 or newer (found $kernel_version)"
        exit 1
    fi

    # Check LSM status
    if ! grep -q "1" /sys/kernel/security/lsm 2>/dev/null; then
        echo "WARNING: No LSM enabled, system security may be compromised"
    fi

    # Create secure working directory
    install -d -m 0700 "$WORK_DIR" "$LOG_DIR"
}

# Function to setup monitoring using multiple methods
setup_monitoring() {
    local status=0
    
    # Method 1: syscall_user_dispatch (preferred for modern kernels)
    if [[ -f /proc/sys/kernel/syscall_user_dispatch ]]; then
        echo "Using syscall_user_dispatch monitoring"
        echo 1 > /proc/sys/kernel/syscall_user_dispatch || status=1
    fi
    
    # Method 2: seccomp-bpf (backup method)
    if command -v bpftool >/dev/null 2>&1; then
        echo "Setting up seccomp-bpf monitoring"
        setup_seccomp_bpf || status=1
    fi
    
    # Method 3: audit system (additional coverage)
    if command -v auditctl >/dev/null 2>&1; then
        echo "Setting up audit rules"
        setup_audit_rules || status=1
    fi
    
    return $status
}

# Function to setup seccomp-bpf monitoring
setup_seccomp_bpf() {
    local bpf_prog="${WORK_DIR}/syscall_monitor.o"
    
    # Critical syscalls to monitor
    local -a SYSCALLS=(
        "execve" "execveat" "fork" "vfork" "clone" "clone3"  # Process creation
        "ptrace" "personality" "prctl"                        # Process manipulation
        "init_module" "finit_module" "delete_module"          # Kernel modules
        "kexec_load" "kexec_file_load"                       # Kernel execution
        "iopl" "ioperm" "modify_ldt"                         # I/O privileges
        "perf_event_open" "bpf"                              # Performance/BPF
        "seccomp" "capset"                                   # Security
    )
    
    # Generate BPF program
    cat > "${WORK_DIR}/syscall_monitor.c" << 'EOF'
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

SEC("seccomp")
int monitor_syscalls(struct seccomp_data *ctx) {
    // Log suspicious syscalls
    if (ctx->nr >= 0 && ctx->nr < 400) {  // Valid syscall range
        bpf_trace_printk("Syscall %d from pid %d (args: %lx, %lx)\\n",
                        ctx->nr, bpf_get_current_pid_tgid(),
                        ctx->args[0], ctx->args[1]);
    }
    return SECCOMP_RET_ALLOW;  // Don't block, just monitor
}
EOF

    # Compile BPF program
    clang -O2 -target bpf -c "${WORK_DIR}/syscall_monitor.c" -o "$bpf_prog"
    
    # Load BPF program
    bpftool prog load "$bpf_prog" /sys/fs/bpf/syscall_monitor
}

# Function to setup audit rules
setup_audit_rules() {
    # Clear existing rules
    auditctl -D
    
    # Add rules for critical syscalls
    auditctl -a always,exit -F arch=b64 -S execve,execveat -k exec_monitor
    auditctl -a always,exit -F arch=b64 -S init_module,finit_module -k module_monitor
    auditctl -a always,exit -F arch=b64 -S ptrace -k ptrace_monitor
    
    # Monitor security-relevant files
    auditctl -w /proc/sys/kernel/modules_disabled -p wa -k module_lock
    auditctl -w /sys/kernel/security -p wa -k security_monitor
}

# Function to monitor for hooks and modifications
monitor_system() {
    echo "Starting system monitoring at $(date)"
    
    # Monitor BPF trace output
    bpftool prog tracelog | while read -r line; do
        # Parse and analyze syscall patterns
        if echo "$line" | grep -qE "execve|init_module|ptrace"; then
            log_suspicious_activity "$line"
        fi
    done &
    
    # Monitor audit logs
    ausearch --start recent -m SYSCALL | while read -r line; do
        analyze_audit_event "$line"
    done &
    
    # Monitor kernel message buffer
    dmesg -w | while read -r line; do
        if echo "$line" | grep -qE "Oops|Call Trace|segfault|general protection"; then
            log_suspicious_activity "Kernel error: $line"
        fi
    done &
    
    wait
}

# Function to analyze patterns
analyze_audit_event() {
    local event="$1"
    
    # Check for suspicious patterns
    if echo "$event" | grep -qE "ANOM_ABEND|ANOM_PROMISCUOUS|ANOM_ROOT"; then
        log_suspicious_activity "Anomaly detected: $event"
    fi
}

# Function to log suspicious activity
log_suspicious_activity() {
    local message="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log to file
    echo "[$timestamp] $message" >> "${LOG_DIR}/suspicious.log"
    
    # Send alert
    logger -p auth.alert -t "$SCRIPT_NAME" "$message"
    
    # If available, send to security monitoring system
    if command -v send_alert >/dev/null 2>&1; then
        send_alert "SYSCALL_MONITOR" "$message"
    fi
}

# Function to cleanup
cleanup() {
    echo "Cleaning up..."
    
    # Remove BPF programs
    bpftool prog detach pinned /sys/fs/bpf/syscall_monitor
    rm -f /sys/fs/bpf/syscall_monitor
    
    # Reset audit rules
    auditctl -D
    
    # Reset syscall_user_dispatch
    if [[ -f /proc/sys/kernel/syscall_user_dispatch ]]; then
        echo 0 > /proc/sys/kernel/syscall_user_dispatch
    fi
}

# Main execution
trap cleanup EXIT INT TERM

check_environment
setup_monitoring
monitor_system
```

### Enhanced eBPF Security Monitoring

IMPORTANT: Modern eBPF-based threats require comprehensive monitoring beyond just program loading.

```bash
#!/bin/bash
# Enhanced eBPF security monitor for modern Linux systems
# Requires: Linux 5.8+, proper capabilities, LSM

set -euo pipefail
IFS=$'\n\t'

readonly MONITOR_DIR="/var/lib/ebpf_monitor"
readonly LOG_DIR="/var/log/ebpf_monitor"
readonly SCRIPT_NAME="$(basename "$0")"

# Function to validate security environment
check_security_env() {
    # Check capabilities
    if [[ $EUID -ne 0 ]]; then
        if ! capsh --print | grep -qE "cap_sys_admin|cap_bpf"; then
            echo "ERROR: Requires root or CAP_BPF capability"
            exit 1
        fi
    fi

    # Check kernel version and features (requires 5.8+)
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1,2)
    local min_version="5.8"
    if [[ "$(printf '%s\n' "$min_version" "$kernel_version" | sort -V | head -n1)" != "$min_version" ]]; then
        echo "ERROR: Requires Linux kernel 5.8 or newer (found $kernel_version)"
        exit 1
    fi

    # Check BTF support
    if [[ ! -f "/sys/kernel/btf/vmlinux" ]]; then
        echo "ERROR: BTF support required"
        echo "Enable CONFIG_DEBUG_INFO_BTF in kernel config"
        exit 1
    fi

    # Check LSM and BPF restrictions
    if [[ "$(sysctl -n kernel.unprivileged_bpf_disabled)" != "1" ]]; then
        echo "WARNING: Unprivileged BPF not disabled"
        echo "Consider: sysctl kernel.unprivileged_bpf_disabled=1"
    fi

    # Create secure directories
    install -d -m 0700 "$MONITOR_DIR" "$LOG_DIR"
}

# Function to generate secure BPF monitoring program
generate_bpf_monitor() {
    local prog_file="${MONITOR_DIR}/bpf_monitor.c"
    
    cat > "$prog_file" << 'EOF'
#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u64);
} prog_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
    u32 pid;
    u32 uid;
    u32 prog_type;
    u32 attach_type;
    char comm[16];
    char prog_name[16];
};

SEC("tp/bpf/bpf_prog_load")
int trace_prog_load(struct trace_event_raw_bpf_prog_load *ctx) {
    struct event *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    
    // Allocate event in ringbuffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
        
    // Fill event data
    e->pid = pid;
    e->uid = uid;
    e->prog_type = ctx->prog_type;
    e->attach_type = ctx->attach_type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_str(&e->prog_name, sizeof(e->prog_name), ctx->prog_name);
    
    // Submit event
    bpf_ringbuf_submit(e, 0);
    
    // Track program count
    u64 *count = bpf_map_lookup_elem(&prog_map, &pid);
    if (count)
        __sync_fetch_and_add(count, 1);
    else {
        u64 init = 1;
        bpf_map_update_elem(&prog_map, &pid, &init, BPF_ANY);
    }
    
    return 0;
}

SEC("tp/bpf/bpf_prog_get_type")
int trace_prog_get_type(void *ctx) {
    return 0;
}

SEC("tp/bpf/bpf_prog_put")
int trace_prog_put(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    # Compile BPF program
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/$(uname -m)-linux-gnu \
        -c "$prog_file" -o "${MONITOR_DIR}/bpf_monitor.o"
}

# Function to load and attach BPF program
load_bpf_monitor() {
    local prog_file="${MONITOR_DIR}/bpf_monitor.o"
    
    # Load program
    bpftool prog load "$prog_file" /sys/fs/bpf/bpf_monitor \
        map name prog_map /sys/fs/bpf/prog_map \
        map name events /sys/fs/bpf/events
        
    # Attach to tracepoints
    bpftool prog attach /sys/fs/bpf/bpf_monitor tracepoint bpf bpf_prog_load
    bpftool prog attach /sys/fs/bpf/bpf_monitor tracepoint bpf bpf_prog_get_type
    bpftool prog attach /sys/fs/bpf/bpf_monitor tracepoint bpf bpf_prog_put
}

# Function to monitor BPF events
monitor_bpf_events() {
    local high_risk_types=(
        "kprobe" "tracepoint" "perf_event" "raw_tracepoint"
        "lsm" "sk_msg" "sock_ops" "xdp"
    )
    
    echo "Starting BPF monitoring at $(date)"
    
    # Monitor ringbuffer events
    bpftool prog tracelog | while read -r line; do
        # Parse event data
        local pid prog_type prog_name
        pid=$(echo "$line" | grep -oP 'pid=\K\d+')
        prog_type=$(echo "$line" | grep -oP 'type=\K[a-zA-Z_]+')
        prog_name=$(echo "$line" | grep -oP 'name=\K[a-zA-Z0-9_]+')
        
        # Check against high-risk types
        for risk_type in "${high_risk_types[@]}"; do
            if [[ "$prog_type" == "$risk_type" ]]; then
                log_suspicious_bpf "High-risk BPF program loaded: $prog_name (type=$prog_type) by PID $pid"
                break
            fi
        done
        
        # Check program loading patterns
        check_loading_patterns "$pid" "$prog_type"
    done
}

# Function to check for suspicious patterns
check_loading_patterns() {
    local pid="$1"
    local prog_type="$2"
    
    # Get program count for PID
    local count
    count=$(bpftool map lookup pinned /sys/fs/bpf/prog_map key $pid)
    
    # Alert on suspicious patterns
    if (( count > 10 )); then
        log_suspicious_bpf "Excessive BPF program loading from PID $pid (count=$count)"
    fi
}

# Function to log suspicious activity
log_suspicious_bpf() {
    local message="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log to file
    echo "[$timestamp] $message" >> "${LOG_DIR}/suspicious_bpf.log"
    
    # System log
    logger -p auth.alert -t "$SCRIPT_NAME" "$message"
    
    # If available, send to security monitoring
    if command -v send_alert >/dev/null 2>&1; then
        send_alert "BPF_MONITOR" "$message"
    fi
}

# Function to cleanup
cleanup() {
    echo "Cleaning up..."
    
    # Detach and remove programs
    bpftool prog detach pinned /sys/fs/bpf/bpf_monitor tracepoint bpf bpf_prog_load
    bpftool prog detach pinned /sys/fs/bpf/bpf_monitor tracepoint bpf bpf_prog_get_type
    bpftool prog detach pinned /sys/fs/bpf/bpf_monitor tracepoint bpf bpf_prog_put
    
    rm -f /sys/fs/bpf/bpf_monitor
    rm -f /sys/fs/bpf/prog_map
    rm -f /sys/fs/bpf/events
}

# Main execution
trap cleanup EXIT INT TERM

check_security_env
generate_bpf_monitor
load_bpf_monitor
monitor_bpf_events
```

### Modern Rootkit Detection Tools

IMPORTANT: No single tool provides complete coverage. Use a layered approach.

#### 1. Process and File Analysis

For process and file hiding detection, modern systems require multiple approaches:

a. Using procfs and sysfs comparison:
```bash
#!/bin/bash
# Save as process_analyzer.sh

set -euo pipefail
IFS=$'\n\t'

# Function to check prerequisites
check_prerequisites() {
    local missing_tools=()
    
    # Required tools
    local tools=(
        "find" "sort" "ps" "lsof" "bpftool" "nsenter"
        "readlink" "grep" "awk" "diff" "lsattr"
    )
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo "ERROR: Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check for root or required capabilities
    if [[ $EUID -ne 0 ]]; then
        if ! capsh --print | grep -qE "cap_sys_ptrace|cap_sys_admin"; then
            echo "ERROR: Must run as root or with required capabilities"
            exit 1
        fi
    fi
    
    # Check cgroup version
    if [[ -d "/sys/fs/cgroup/unified" ]]; then
        echo "INFO: Using cgroup v2"
        CGROUP_ROOT="/sys/fs/cgroup/unified"
    elif [[ -d "/sys/fs/cgroup/memory" ]]; then
        echo "INFO: Using cgroup v1"
        CGROUP_ROOT="/sys/fs/cgroup"
    else
        echo "ERROR: Cannot determine cgroup version"
        exit 1
    fi
    
    # Create secure temporary directory
    TEMP_DIR=$(mktemp -d)
    chmod 700 "$TEMP_DIR"
    
    # Verify namespace access
    if ! readlink /proc/1/ns/pid >/dev/null 2>&1; then
        echo "ERROR: Cannot access process namespaces"
        exit 1
    fi
}

# Get processes from different sources
get_processes() {
    echo "Getting process list from multiple sources..."
    
    # Method 1: procfs with namespace awareness
    find /proc -maxdepth 1 -type d -regex '/proc/[0-9]+' | while read -r proc_dir; do
        pid=${proc_dir##*/}
        # Get process namespace
        ns=$(readlink "$proc_dir/ns/pid" 2>/dev/null || echo "unknown")
        echo "$pid $ns"
    done | sort > "$TEMP_DIR/procs_procfs"
    
    # Method 2: cgroup-based listing
    {
        if [[ -d "$CGROUP_ROOT" ]]; then
            # Handle both cgroup v1 and v2
            if [[ "$CGROUP_ROOT" == "/sys/fs/cgroup/unified" ]]; then
                # cgroup v2
                find "$CGROUP_ROOT" -type f -name "cgroup.procs" -exec cat {} \; 2>/dev/null
            else
                # cgroup v1
                find "$CGROUP_ROOT/memory" -name "cgroup.procs" -exec cat {} \; 2>/dev/null
            fi
        fi
    } | sort -u > "$TEMP_DIR/procs_cgroup"
    
    # Method 3: ps with namespace info
    ps -eo pid=,nslist= | sort > "$TEMP_DIR/procs_ps"
    
    # Method 4: netlink listing with socket info
    if command -v lsof >/dev/null 2>&1; then
        lsof -n -P -i | awk '{print $2, $5, $8, $9}' | grep -v PID | sort -u > "$TEMP_DIR/procs_netlink"
    fi
    
    # Method 5: systemd-cgls if available
    if command -v systemd-cgls >/dev/null 2>&1; then
        systemd-cgls --no-pager | grep -oE '[0-9]+' | sort -u > "$TEMP_DIR/procs_systemd"
    fi
}

# Compare process listings
compare_processes() {
    echo "Comparing process listings..."

    for pid in $(cat "$TEMP_DIR/procs_procfs"); do
        if ! grep -q "^$pid$" "$TEMP_DIR/procs_ps"; then
            echo "[ALERT] PID $pid exists in procfs but not in ps output"
            analyze_suspicious_process "$pid"
        fi
    done

    for pid in $(cat "$TEMP_DIR/procs_netlink" 2>/dev/null); do
        if ! grep -q "^$pid$" "$TEMP_DIR/procs_procfs"; then
            echo "[ALERT] PID $pid exists in netlink but not in procfs"
            analyze_suspicious_process "$pid"
        fi
    done
}

# Analyze suspicious process
analyze_suspicious_process() {
    local pid="$1"
    
    echo "Analyzing suspicious PID: $pid"
    
    # Check process details
    if [[ -d "/proc/$pid" ]]; then
        echo "Process info:"
        cat "/proc/$pid/status" 2>/dev/null || echo "Cannot read status"
        echo "Open files:"
        ls -l "/proc/$pid/fd" 2>/dev/null || echo "Cannot list FDs"
        echo "Memory maps:"
        cat "/proc/$pid/maps" 2>/dev/null || echo "Cannot read maps"
    fi
    
    # Check for eBPF attachments
    if command -v bpftool >/dev/null 2>&1; then
        echo "BPF programs attached to PID $pid:"
        bpftool prog list pid "$pid" 2>/dev/null || echo "No BPF programs found"
    fi
}

# File system analysis
analyze_filesystem() {
    echo "Analyzing filesystem for hidden files..."

    # Method 1: Compare directory listings
    for dir in /proc /sys /dev; do
        echo "Checking $dir..."

        # Get listings using different methods
        ls -la "$dir" > "$TEMP_DIR/ls_output"
        find "$dir" -maxdepth 1 > "$TEMP_DIR/find_output"

        # Compare outputs
        if ! diff <(sort "$TEMP_DIR/ls_output") <(sort "$TEMP_DIR/find_output") >/dev/null; then
            echo "[ALERT] Discrepancy found in $dir listings"
            diff <(sort "$TEMP_DIR/ls_output") <(sort "$TEMP_DIR/find_output")
        fi
    done

    # Method 2: Check for suspicious file attributes
    echo "Checking for suspicious file attributes..."
    lsattr -R / 2>/dev/null | grep -E '^[-a-zA-Z]{4}i' || true

    # Method 3: Check for files with no links
    find / -type f -links 0 2>/dev/null
}

# Cleanup
cleanup() {
    rm -rf "$TEMP_DIR"
}

# Main execution
trap cleanup EXIT

get_processes
compare_processes
analyze_filesystem
```

#### 2. Tracee Configuration (by Aqua Security)

Modern configuration for container-aware monitoring:
```bash
# Installation with hardened security context and resource limits
cat > /etc/systemd/system/tracee.service << 'EOF'
[Unit]
Description=Tracee Runtime Security
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=5
StartLimitInterval=0

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=no
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=no
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

# Resource limits
CPUQuota=200%
MemoryMax=2G
TasksMax=200
LimitNOFILE=65535
LimitNPROC=200

ExecStartPre=-/usr/bin/docker rm -f tracee
ExecStart=/usr/bin/docker run --rm \
    --name tracee \
    --privileged \
    --pid=host \
    --cgroupns=host \
    --network=host \
    --security-opt seccomp=unconfined \
    --security-opt apparmor=unconfined \
    -v /etc/os-release:/etc/os-release-host:ro \
    -v /var/run:/var/run:ro \
    -v /var/log/tracee:/var/log/tracee \
    -v /etc/tracee/rules:/etc/tracee/rules:ro \
    -v /etc/tracee/policies:/etc/tracee/policies:ro \
    aquasec/tracee:latest \
    --rules-dir /etc/tracee/rules \
    --policies-dir /etc/tracee/policies \
    --output json \
    --output-file /var/log/tracee/tracee.log \
    --cache cache-type=mem \
    --cache mem-cache-size=1024 \
    --perf-buffer-size 2048 \
    --capabilities net_admin,sys_admin \
    --trace container=new \
    --trace proc=exec \
    --trace syscall=bpf,init_module,finit_module,delete_module,ptrace \
    --trace event=cap_capable,security_bprm_check,vfs_write,sched_process_exec

[Install]
WantedBy=multi-user.target
EOF

# Log rotation configuration
cat > /etc/logrotate.d/tracee << 'EOF'
/var/log/tracee/tracee.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl kill -s USR1 tracee.service
    endscript
}
EOF

# Security policy configuration
mkdir -p /etc/tracee/policies
cat > /etc/tracee/policies/security.yaml << 'EOF'
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: security-policy
spec:
  scope:
    - global
  defaultAction: log
  rules:
    - name: restrict_capabilities
      event: cap_capable
      filters:
        - capabilities not in [CHOWN, DAC_OVERRIDE, FOWNER, KILL, SETGID, SETUID]
      action: alert
    - name: restrict_syscalls
      event: syscall
      filters:
        - syscall in [init_module, finit_module, delete_module, kexec_load]
      action: alert
    - name: container_escape
      event: container
      filters:
        - container.privileged=true
        - container.capabilities contains "CAP_SYS_ADMIN"
      action: alert
EOF

# Custom rules configuration
cat > /etc/tracee/rules/rootkit.yaml << 'EOF'
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: rootkit-detection
spec:
  scope:
    - global
  rules:
    - name: detect_module_hiding
      event: init_module,finit_module
      filters:
        - args.name contains "hidden_"
        - args.name contains "rootkit"
    - name: detect_syscall_hooking
      event: bpf
      filters:
        - args.cmd == BPF_PROG_LOAD
        - args.prog_type in (BPF_PROG_TYPE_KPROBE, BPF_PROG_TYPE_TRACEPOINT)
    - name: detect_capability_abuse
      event: cap_capable
      filters:
        - args.cap == CAP_SYS_MODULE
        - args.cap == CAP_SYS_ADMIN
    - name: detect_proc_tampering
      event: vfs_write
      filters:
        - args.pathname startswith "/proc/"
        - args.pathname startswith "/sys/"
EOF
```

#### 3. Enhanced Falco Configuration

Modern Falco rules with container escape detection:
```yaml
# Enhanced rootkit detection ruleset
# Save as rootkit_rules.yaml

- list: privileged_containers
  items: []  # Add known privileged containers here

- list: trusted_capabilities
  items: [CHOWN, DAC_OVERRIDE, FOWNER, KILL, SETGID, SETUID]

- macro: is_privileged_container
  condition: >
    (container.privileged=true or
     container.capabilities contains "CAP_SYS_ADMIN" or
     container.capabilities contains "CAP_SYS_MODULE")

- macro: is_init_process
  condition: proc.pname in (systemd, init)

- macro: is_package_management
  condition: >
    proc.name in (dpkg, rpm, apt, yum, dnf, zypper, pacman)

# Core System Protection
- rule: detect_kernel_module_activity
  desc: Detect kernel module operations
  condition: >
    syscall.type in (init_module, finit_module, delete_module) and
    not (is_init_process or is_package_management)
  output: >
    Kernel module operation detected
    (user=%user.name user_id=%user.uid command=%proc.cmdline
    module=%fd.name container=%container.name)
  priority: CRITICAL
  tags: [module, rootkit]

# Process Manipulation
- rule: detect_process_manipulation
  desc: Detect process manipulation attempts
  condition: >
    syscall.type in (ptrace, process_vm_writev, process_vm_readv) and
    not proc.name in (gdb, lldb, strace, frida) and
    not is_privileged_container
  output: >
    Process manipulation attempt detected
    (user=%user.name command=%proc.cmdline target_pid=%proc.pid
    container=%container.name)
  priority: WARNING
  tags: [process, rootkit]

# Filesystem Integrity
- rule: detect_proc_sys_manipulation
  desc: Detect /proc and /sys manipulation
  condition: >
    ((evt.type in (open, openat) and evt.arg.flags contains O_WRONLY) or
     evt.type in (rename, unlink)) and
    fd.directory in (/proc, /sys) and
    not is_init_process
  output: >
    Proc/Sys manipulation attempt
    (user=%user.name command=%proc.cmdline file=%fd.name
    container=%container.name)
  priority: WARNING
  tags: [filesystem, rootkit]

# Container Escape Detection
- rule: detect_container_escape
  desc: Detect potential container escape attempts
  condition: >
    evt.type=container and
    ((container.privileged=true and not container.name in (privileged_containers)) or
     container.capabilities contains "CAP_SYS_ADMIN" or
     container.mount contains "/proc" or
     container.mount contains "/sys")
  output: >
    Potential container escape detected
    (container=%container.name image=%container.image
    privileges=%container.privileged caps=%container.capabilities)
  priority: CRITICAL
  tags: [container, escape, rootkit]

# Kernel Memory Access
- rule: detect_kernel_memory_access
  desc: Detect attempts to access kernel memory
  condition: >
    evt.type=open and
    fd.name=/dev/kmem and
    not is_init_process
  output: >
    Kernel memory access attempt
    (user=%user.name command=%proc.cmdline
    container=%container.name)
  priority: CRITICAL
  tags: [memory, rootkit]

# Capability Abuse
- rule: detect_capability_abuse
  desc: Detect abuse of dangerous capabilities
  condition: >
    evt.type=setuid and
    not proc.name in (sudo, su) and
    not container.capabilities in (trusted_capabilities)
  output: >
    Suspicious capability use detected
    (user=%user.name command=%proc.cmdline caps=%container.capabilities
    container=%container.name)
  priority: WARNING
  tags: [capabilities, rootkit]

# Network Manipulation
- rule: detect_network_manipulation
  desc: Detect suspicious network activity
  condition: >
    syscall.type=socket and
    (evt.arg[0]=AF_PACKET or
     (evt.arg[0]=AF_INET and evt.arg[1]=SOCK_RAW)) and
    not proc.name in (tcpdump, wireshark, dumpcap)
  output: >
    Raw socket creation detected
    (user=%user.name command=%proc.cmdline
    socket_family=%evt.arg[0] socket_type=%evt.arg[1]
    container=%container.name)
  priority: WARNING
  tags: [network, rootkit]
```

[Rest of the content remains the same]

## Further Reading

Updated resources:
- Linux Kernel Security: [https://www.kernel.org/doc/html/latest/security/](https://www.kernel.org/doc/html/latest/security/)
- eBPF Security: [https://ebpf.io/security/](https://ebpf.io/security/)
- Tracee Documentation: [https://aquasecurity.github.io/tracee/](https://aquasecurity.github.io/tracee/)
- Falco Documentation: [https://falco.org/docs/](https://falco.org/docs/)
