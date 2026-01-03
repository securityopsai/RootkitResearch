#!/bin/bash
#
# Linux Rootkit Indicator Detection Script
# For defensive security research and incident response
#
# Usage: sudo ./rootkit_detector.sh [--full] [--output <file>]
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
ALERTS=0
WARNINGS=0
INFO=0

# Output file
OUTPUT_FILE=""
FULL_SCAN=false

# Logging functions
log_alert() {
    ((ALERTS++))
    echo -e "${RED}[ALERT]${NC} $1" | tee -a "${OUTPUT_FILE:-/dev/null}"
}

log_warning() {
    ((WARNINGS++))
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${OUTPUT_FILE:-/dev/null}"
}

log_info() {
    ((INFO++))
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "${OUTPUT_FILE:-/dev/null}"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "${OUTPUT_FILE:-/dev/null}"
}

log_section() {
    echo "" | tee -a "${OUTPUT_FILE:-/dev/null}"
    echo -e "${BLUE}========================================${NC}" | tee -a "${OUTPUT_FILE:-/dev/null}"
    echo -e "${BLUE}  $1${NC}" | tee -a "${OUTPUT_FILE:-/dev/null}"
    echo -e "${BLUE}========================================${NC}" | tee -a "${OUTPUT_FILE:-/dev/null}"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            FULL_SCAN=true
            shift
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--full] [--output <file>]"
            echo "  --full    Run comprehensive scan (slower)"
            echo "  --output  Write results to file"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root for full detection capabilities"
        echo "Some checks will be skipped..."
        return 1
    fi
    return 0
}

# Initialize output file
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "Rootkit Detection Scan - $(date)" > "$OUTPUT_FILE"
    echo "Host: $(hostname)" >> "$OUTPUT_FILE"
    echo "Kernel: $(uname -r)" >> "$OUTPUT_FILE"
    echo "---" >> "$OUTPUT_FILE"
fi

echo ""
echo "====================================================="
echo "  Linux Rootkit Indicator Detection Script"
echo "  $(date)"
echo "  Host: $(hostname) | Kernel: $(uname -r)"
echo "====================================================="

IS_ROOT=true
check_root || IS_ROOT=false

###############################################################################
# 1. PROCESS HIDING DETECTION
###############################################################################
log_section "1. Process Hiding Detection"

check_hidden_processes() {
    log_info "Comparing process listings from multiple sources..."

    local TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" RETURN

    # Method 1: /proc filesystem
    find /proc -maxdepth 1 -type d -regex '/proc/[0-9]+' 2>/dev/null | \
        sed 's|/proc/||' | sort -n > "$TEMP_DIR/proc_pids"

    # Method 2: ps command
    ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n > "$TEMP_DIR/ps_pids"

    # Compare
    local hidden_count=0
    while read -r pid; do
        if ! grep -q "^${pid}$" "$TEMP_DIR/ps_pids" 2>/dev/null; then
            log_alert "Hidden process detected: PID $pid (in /proc but not in ps)"
            if [[ -f "/proc/$pid/comm" ]]; then
                log_info "  Command: $(cat /proc/$pid/comm 2>/dev/null || echo 'unknown')"
            fi
            ((hidden_count++))
        fi
    done < "$TEMP_DIR/proc_pids"

    if [[ $hidden_count -eq 0 ]]; then
        log_ok "No hidden processes detected via /proc vs ps comparison"
    fi

    # Check for processes hidden from /proc but visible in /sys/fs/cgroup
    if [[ -d "/sys/fs/cgroup" ]]; then
        log_info "Checking cgroup process visibility..."

        # Get PIDs from cgroup
        find /sys/fs/cgroup -name "cgroup.procs" -exec cat {} \; 2>/dev/null | \
            sort -u > "$TEMP_DIR/cgroup_pids" 2>/dev/null || true

        while read -r pid; do
            if [[ -n "$pid" ]] && ! grep -q "^${pid}$" "$TEMP_DIR/proc_pids" 2>/dev/null; then
                log_alert "Process $pid visible in cgroups but hidden from /proc"
                ((hidden_count++))
            fi
        done < "$TEMP_DIR/cgroup_pids"
    fi
}

check_hidden_processes

###############################################################################
# 2. eBPF PROGRAM DETECTION
###############################################################################
log_section "2. eBPF Program Analysis"

check_ebpf_programs() {
    if ! command -v bpftool &>/dev/null; then
        log_warning "bpftool not installed - cannot enumerate eBPF programs"
        log_info "Install with: apt install linux-tools-common linux-tools-\$(uname -r)"
        return
    fi

    log_info "Enumerating loaded eBPF programs..."

    local prog_count=0
    local suspicious_count=0

    # List all BPF programs
    while IFS= read -r line; do
        ((prog_count++))

        local prog_id=$(echo "$line" | grep -oP '^\d+')
        local prog_type=$(echo "$line" | grep -oP 'type \K\w+')
        local prog_name=$(echo "$line" | grep -oP 'name \K\w+' || echo "unnamed")

        # Check for suspicious program types
        case "$prog_type" in
            kprobe|tracepoint|raw_tracepoint|lsm)
                log_warning "Potentially suspicious eBPF program: ID=$prog_id Type=$prog_type Name=$prog_name"
                ((suspicious_count++))
                ;;
            xdp|tc|socket_filter)
                log_info "Network-attached eBPF: ID=$prog_id Type=$prog_type Name=$prog_name"
                ;;
        esac
    done < <(bpftool prog list 2>/dev/null | grep -E '^[0-9]+:')

    log_info "Total eBPF programs loaded: $prog_count"

    if [[ $suspicious_count -gt 0 ]]; then
        log_warning "$suspicious_count potentially suspicious eBPF programs found"
    else
        log_ok "No obviously suspicious eBPF program types detected"
    fi

    # Check network attachments
    log_info "Checking eBPF network attachments..."
    if bpftool net list 2>/dev/null | grep -qE 'xdp|tc'; then
        log_warning "eBPF programs attached to network interfaces:"
        bpftool net list 2>/dev/null | grep -E 'xdp|tc' | while read -r line; do
            log_info "  $line"
        done
    else
        log_ok "No eBPF network attachments found"
    fi

    # Check for pinned BPF objects
    log_info "Checking for pinned BPF objects..."
    if [[ -d "/sys/fs/bpf" ]]; then
        local pinned=$(find /sys/fs/bpf -type f 2>/dev/null | wc -l)
        if [[ $pinned -gt 0 ]]; then
            log_warning "$pinned pinned BPF objects found in /sys/fs/bpf:"
            find /sys/fs/bpf -type f 2>/dev/null | while read -r obj; do
                log_info "  $obj"
            done
        else
            log_ok "No pinned BPF objects found"
        fi
    fi
}

check_ebpf_programs

###############################################################################
# 3. KERNEL MODULE ANALYSIS
###############################################################################
log_section "3. Kernel Module Analysis"

check_kernel_modules() {
    log_info "Analyzing loaded kernel modules..."

    # Get modules from /proc/modules
    local proc_modules=$(cat /proc/modules 2>/dev/null | awk '{print $1}' | sort)

    # Get modules from sysfs
    local sysfs_modules=$(ls /sys/module 2>/dev/null | sort)

    # Compare lists
    log_info "Comparing /proc/modules vs /sys/module..."

    local hidden_count=0
    for mod in $sysfs_modules; do
        if ! echo "$proc_modules" | grep -q "^${mod}$"; then
            # Some modules in sysfs aren't in /proc/modules (built-in)
            if [[ ! -f "/sys/module/$mod/initstate" ]]; then
                continue  # Built-in module
            fi
            log_alert "Module '$mod' in sysfs but hidden from /proc/modules"
            ((hidden_count++))
        fi
    done

    if [[ $hidden_count -eq 0 ]]; then
        log_ok "No hidden kernel modules detected"
    fi

    # Check for unsigned modules (if supported)
    if [[ -f "/proc/sys/kernel/module_signature_required" ]]; then
        local sig_required=$(cat /proc/sys/kernel/module_signature_required 2>/dev/null)
        if [[ "$sig_required" != "1" ]]; then
            log_warning "Kernel module signature enforcement is disabled"
        else
            log_ok "Kernel module signature enforcement is enabled"
        fi
    fi

    # Check for suspicious module names
    log_info "Checking for suspicious module names..."
    local suspicious_patterns="rootkit|hide|stealth|backdoor|keylog|reptile|diamorphine|adore"
    while read -r mod; do
        if echo "$mod" | grep -qiE "$suspicious_patterns"; then
            log_alert "Suspicious module name detected: $mod"
        fi
    done < <(cat /proc/modules 2>/dev/null | awk '{print $1}')

    # Check module parameters for anomalies
    if [[ "$FULL_SCAN" == "true" ]]; then
        log_info "Checking module parameters..."
        for mod in $proc_modules; do
            if [[ -d "/sys/module/$mod/parameters" ]]; then
                local params=$(ls /sys/module/$mod/parameters 2>/dev/null | wc -l)
                # Most rootkits hide their parameters or have unusual ones
            fi
        done
    fi
}

check_kernel_modules

###############################################################################
# 4. SYSCALL TABLE INTEGRITY
###############################################################################
log_section "4. Syscall Table Analysis"

check_syscall_table() {
    if [[ "$IS_ROOT" != "true" ]]; then
        log_warning "Skipping syscall table check (requires root)"
        return
    fi

    log_info "Checking syscall table address..."

    # Get syscall table address
    local syscall_addr=$(grep -E '\bsys_call_table\b' /proc/kallsyms 2>/dev/null | head -1 | awk '{print $1}')

    if [[ -z "$syscall_addr" ]]; then
        log_warning "Cannot read syscall table address (kernel.kptr_restrict may be enabled)"
        return
    fi

    log_info "sys_call_table at: 0x$syscall_addr"

    # Check if System.map exists for comparison
    local system_map="/boot/System.map-$(uname -r)"
    if [[ -f "$system_map" ]]; then
        local expected_addr=$(grep -E '\bsys_call_table\b' "$system_map" 2>/dev/null | head -1 | awk '{print $1}')
        if [[ -n "$expected_addr" ]]; then
            # Note: With KASLR, addresses will differ - this is expected
            log_info "System.map sys_call_table: 0x$expected_addr"
            log_info "Address difference is expected with KASLR enabled"
        fi
    fi

    # Check for common hooked syscalls by looking at their addresses
    log_info "Checking critical syscall addresses..."
    local critical_syscalls="sys_read sys_write sys_open sys_openat sys_execve sys_getdents sys_getdents64 sys_kill"

    for syscall in $critical_syscalls; do
        local addr=$(grep -E "\b${syscall}\b" /proc/kallsyms 2>/dev/null | head -1 | awk '{print $1}')
        if [[ -n "$addr" ]]; then
            # Check if address is in expected kernel text range
            local addr_dec=$((16#$addr))
            # Kernel text typically starts at 0xffffffff80000000 on x86_64
            if [[ $addr_dec -lt $((16#ffffffff80000000)) ]] 2>/dev/null; then
                log_alert "$syscall address 0x$addr appears outside kernel text segment"
            fi
        fi
    done

    log_ok "Syscall address check complete"
}

check_syscall_table

###############################################################################
# 5. FTRACE AND KPROBE DETECTION
###############################################################################
log_section "5. Ftrace/Kprobe Hook Detection"

check_ftrace_hooks() {
    if [[ ! -d "/sys/kernel/debug/tracing" ]]; then
        log_warning "Debugfs tracing not available"
        return
    fi

    log_info "Checking for active ftrace hooks..."

    # Check enabled functions
    local enabled_funcs="/sys/kernel/debug/tracing/set_ftrace_filter"
    if [[ -r "$enabled_funcs" ]]; then
        local hook_count=$(cat "$enabled_funcs" 2>/dev/null | grep -v '^#' | grep -v '^$' | wc -l)
        if [[ $hook_count -gt 0 ]]; then
            log_warning "$hook_count ftrace hooks active:"
            cat "$enabled_funcs" 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20 | while read -r func; do
                log_info "  Hooked: $func"
            done
            if [[ $hook_count -gt 20 ]]; then
                log_info "  ... and $((hook_count - 20)) more"
            fi
        else
            log_ok "No custom ftrace hooks detected"
        fi
    fi

    # Check kprobes
    local kprobe_list="/sys/kernel/debug/kprobes/list"
    if [[ -r "$kprobe_list" ]]; then
        local kprobe_count=$(cat "$kprobe_list" 2>/dev/null | wc -l)
        if [[ $kprobe_count -gt 0 ]]; then
            log_warning "$kprobe_count active kprobes detected:"
            cat "$kprobe_list" 2>/dev/null | head -10 | while read -r line; do
                log_info "  $line"
            done
        else
            log_ok "No active kprobes detected"
        fi
    fi

    # Check for function graph tracer
    local current_tracer=$(cat /sys/kernel/debug/tracing/current_tracer 2>/dev/null)
    if [[ "$current_tracer" != "nop" ]] && [[ -n "$current_tracer" ]]; then
        log_warning "Active tracer detected: $current_tracer"
    fi
}

check_ftrace_hooks

###############################################################################
# 6. NETWORK ANOMALY DETECTION
###############################################################################
log_section "6. Network Anomaly Detection"

check_network_anomalies() {
    log_info "Checking for hidden network connections..."

    # Compare ss output with /proc/net
    local TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" RETURN

    # Get connections from ss
    ss -tunapw 2>/dev/null | tail -n +2 | awk '{print $5, $6}' | sort > "$TEMP_DIR/ss_conns"

    # Get connections from /proc/net
    cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null | \
        tail -n +2 > "$TEMP_DIR/proc_conns"

    local proc_conn_count=$(wc -l < "$TEMP_DIR/proc_conns")
    local ss_conn_count=$(wc -l < "$TEMP_DIR/ss_conns")

    log_info "/proc/net connections: $proc_conn_count, ss connections: $ss_conn_count"

    # Check for promiscuous mode
    log_info "Checking for promiscuous interfaces..."
    for iface in /sys/class/net/*; do
        local name=$(basename "$iface")
        local flags=$(cat "$iface/flags" 2>/dev/null)
        if [[ -n "$flags" ]]; then
            # IFF_PROMISC = 0x100
            if [[ $((flags & 0x100)) -ne 0 ]]; then
                log_warning "Interface $name is in promiscuous mode"
            fi
        fi
    done

    # Check for raw sockets
    log_info "Checking for raw sockets..."
    local raw_count=$(cat /proc/net/raw /proc/net/raw6 2>/dev/null | tail -n +2 | wc -l)
    if [[ $raw_count -gt 0 ]]; then
        log_warning "$raw_count raw sockets detected"
        if [[ "$IS_ROOT" == "true" ]]; then
            # Try to identify processes with raw sockets
            for pid in /proc/[0-9]*; do
                pid_num=$(basename "$pid")
                if ls -la "$pid/fd" 2>/dev/null | grep -q 'socket:'; then
                    # Check if this process has raw socket capability
                    if grep -q "CapEff:.*0000003f" "$pid/status" 2>/dev/null; then
                        local comm=$(cat "$pid/comm" 2>/dev/null)
                        log_info "  PID $pid_num ($comm) may have raw socket access"
                    fi
                fi
            done
        fi
    else
        log_ok "No raw sockets detected"
    fi

    # Check for suspicious listening ports
    log_info "Checking for suspicious listening ports..."
    local suspicious_ports="31337 4444 5555 6666 7777 8888 9999 12345 54321"
    while read -r port; do
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            log_warning "Suspicious port $port is listening"
        fi
    done <<< "$(echo $suspicious_ports | tr ' ' '\n')"
}

check_network_anomalies

###############################################################################
# 7. FILE HIDING DETECTION
###############################################################################
log_section "7. File Hiding Detection"

check_hidden_files() {
    log_info "Checking for hidden files/directories..."

    local TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" RETURN

    # Check critical directories for discrepancies
    local dirs_to_check="/tmp /var/tmp /dev/shm /usr/lib /lib"

    for dir in $dirs_to_check; do
        if [[ ! -d "$dir" ]]; then
            continue
        fi

        # Compare ls and find outputs
        ls -la "$dir" 2>/dev/null | tail -n +4 | awk '{print $NF}' | sort > "$TEMP_DIR/ls_out"
        find "$dir" -maxdepth 1 2>/dev/null | sed "s|^$dir/||" | grep -v '^$' | sort > "$TEMP_DIR/find_out"

        local diff_count=$(diff "$TEMP_DIR/ls_out" "$TEMP_DIR/find_out" 2>/dev/null | grep -c '^[<>]' || echo 0)
        if [[ $diff_count -gt 0 ]]; then
            log_warning "Discrepancy in $dir listing (diff count: $diff_count)"
        fi
    done

    # Check for files with suspicious attributes
    log_info "Checking for immutable files in unusual locations..."
    if command -v lsattr &>/dev/null; then
        for dir in /tmp /var/tmp /dev/shm; do
            if [[ -d "$dir" ]]; then
                lsattr -R "$dir" 2>/dev/null | grep -E '^....i' | while read -r line; do
                    log_warning "Immutable file found: $line"
                done
            fi
        done
    fi

    # Check for deleted but open files
    log_info "Checking for deleted but still open files..."
    if [[ "$IS_ROOT" == "true" ]]; then
        local deleted_count=$(find /proc/*/fd -type l 2>/dev/null | xargs ls -la 2>/dev/null | grep -c '(deleted)' || echo 0)
        if [[ $deleted_count -gt 10 ]]; then
            log_warning "$deleted_count deleted but open files found"
        fi
    fi

    # Check LD_PRELOAD
    log_info "Checking LD_PRELOAD environment..."
    if [[ -n "${LD_PRELOAD:-}" ]]; then
        log_alert "LD_PRELOAD is set: $LD_PRELOAD"
    else
        log_ok "LD_PRELOAD is not set"
    fi

    # Check /etc/ld.so.preload
    if [[ -f "/etc/ld.so.preload" ]]; then
        local preload_content=$(cat /etc/ld.so.preload 2>/dev/null)
        if [[ -n "$preload_content" ]]; then
            log_alert "/etc/ld.so.preload contains: $preload_content"
        fi
    else
        log_ok "/etc/ld.so.preload does not exist"
    fi
}

check_hidden_files

###############################################################################
# 8. PERSISTENCE MECHANISM DETECTION
###############################################################################
log_section "8. Persistence Mechanism Detection"

check_persistence() {
    log_info "Checking common persistence locations..."

    # Check rc.local
    for rc in /etc/rc.local /etc/rc.d/rc.local; do
        if [[ -f "$rc" ]] && [[ -x "$rc" ]]; then
            log_warning "Executable rc.local found: $rc"
            if grep -qE 'insmod|modprobe|\.ko' "$rc" 2>/dev/null; then
                log_alert "rc.local contains module loading commands"
            fi
        fi
    done

    # Check systemd services for suspicious entries
    log_info "Checking systemd services..."
    local suspicious_services=$(systemctl list-unit-files --type=service 2>/dev/null | \
        grep -iE 'hidden|backdoor|rootkit|stealth' || true)
    if [[ -n "$suspicious_services" ]]; then
        log_alert "Suspicious systemd services found:"
        echo "$suspicious_services" | while read -r line; do
            log_info "  $line"
        done
    fi

    # Check cron for suspicious entries
    log_info "Checking cron jobs..."
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron/crontabs; do
        if [[ -d "$crondir" ]]; then
            find "$crondir" -type f 2>/dev/null | while read -r cronfile; do
                if grep -qE 'insmod|modprobe|\.ko|/dev/tcp|nc -|ncat|socat' "$cronfile" 2>/dev/null; then
                    log_warning "Suspicious cron job: $cronfile"
                fi
            done
        fi
    done

    # Check for unauthorized SSH keys
    log_info "Checking for unauthorized SSH keys..."
    find /home -name "authorized_keys" -o -name "authorized_keys2" 2>/dev/null | while read -r keyfile; do
        local key_count=$(wc -l < "$keyfile" 2>/dev/null || echo 0)
        if [[ $key_count -gt 0 ]]; then
            log_info "Found $key_count keys in $keyfile"
        fi
    done

    if [[ -f "/root/.ssh/authorized_keys" ]]; then
        local root_keys=$(wc -l < /root/.ssh/authorized_keys 2>/dev/null || echo 0)
        if [[ $root_keys -gt 0 ]]; then
            log_warning "Root has $root_keys SSH authorized keys"
        fi
    fi
}

check_persistence

###############################################################################
# 9. KERNEL SECURITY SETTINGS
###############################################################################
log_section "9. Kernel Security Settings"

check_kernel_security() {
    log_info "Checking kernel security parameters..."

    local checks=(
        "kernel.kptr_restrict:2:Kernel pointer restriction"
        "kernel.dmesg_restrict:1:Dmesg restriction"
        "kernel.perf_event_paranoid:3:Perf event paranoid"
        "kernel.yama.ptrace_scope:1:Ptrace scope"
        "kernel.unprivileged_bpf_disabled:1:Unprivileged BPF disabled"
        "net.core.bpf_jit_harden:2:BPF JIT hardening"
        "kernel.modules_disabled:1:Module loading disabled"
    )

    for check in "${checks[@]}"; do
        local key=$(echo "$check" | cut -d: -f1)
        local expected=$(echo "$check" | cut -d: -f2)
        local desc=$(echo "$check" | cut -d: -f3)

        local actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")

        if [[ "$actual" == "N/A" ]]; then
            log_info "$desc: not available"
        elif [[ "$actual" -lt "$expected" ]] 2>/dev/null; then
            log_warning "$desc: $actual (recommended: $expected)"
        else
            log_ok "$desc: $actual"
        fi
    done

    # Check Secure Boot
    if command -v mokutil &>/dev/null; then
        if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
            log_ok "Secure Boot is enabled"
        else
            log_warning "Secure Boot is disabled or unavailable"
        fi
    fi

    # Check kernel lockdown
    if [[ -f "/sys/kernel/security/lockdown" ]]; then
        local lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null)
        log_info "Kernel lockdown mode: $lockdown"
    fi
}

check_kernel_security

###############################################################################
# 10. SUMMARY
###############################################################################
log_section "SCAN SUMMARY"

echo ""
echo "====================================================="
echo "  Scan Complete: $(date)"
echo "====================================================="
echo -e "  ${RED}ALERTS:${NC}   $ALERTS"
echo -e "  ${YELLOW}WARNINGS:${NC} $WARNINGS"
echo -e "  ${BLUE}INFO:${NC}     $INFO"
echo "====================================================="

if [[ $ALERTS -gt 0 ]]; then
    echo -e "${RED}CRITICAL: $ALERTS alert(s) require immediate investigation${NC}"
    exit 2
elif [[ $WARNINGS -gt 5 ]]; then
    echo -e "${YELLOW}WARNING: Multiple warnings detected - review recommended${NC}"
    exit 1
else
    echo -e "${GREEN}No critical issues detected${NC}"
    exit 0
fi
