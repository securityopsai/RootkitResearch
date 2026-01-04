#!/bin/bash
#
# Linux Rootkit Indicator Detection Script
# For defensive security research and incident response
#
# Usage: sudo ./rootkit_detector.sh [--full] [--output <file>]
#
# LIMITATIONS:
#   - If the host is compromised at kernel level, this script's reads can be lied to
#   - Cross-checking helps but is not foolproof from inside the blast radius
#   - For real IR: collect artifacts, boot from trusted media, analyze offline
#

# Don't use set -e globally - too many commands return non-zero for boring reasons
set -uo pipefail

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters - initialize to 1 to avoid ((var++)) returning 1 on first increment
# Then subtract 1 at the end. This avoids set -e issues if we re-enable it.
ALERTS=0
WARNINGS=0
INFO=0

# Output file
OUTPUT_FILE=""
FULL_SCAN=false

# Detect architecture
ARCH=$(uname -m)

# Known security/observability tooling (reduces false positive noise)
KNOWN_TOOLING=""
detect_known_tooling() {
    local found=()
    # Check for common eBPF-based security/networking tools
    command -v cilium &>/dev/null && found+=("cilium")
    command -v tetragon &>/dev/null && found+=("tetragon")
    pgrep -x falco &>/dev/null && found+=("falco")
    pgrep -x osqueryd &>/dev/null && found+=("osquery")
    pgrep -x datadog-agent &>/dev/null && found+=("datadog")
    systemctl is-active --quiet crowdstrike-falcon-sensor 2>/dev/null && found+=("crowdstrike")
    [[ -d "/opt/carbonblack" ]] && found+=("carbonblack")
    # Container networking
    [[ -d "/run/cilium" ]] && found+=("cilium-cni")
    [[ -d "/run/calico" ]] && found+=("calico")

    if [[ ${#found[@]} -gt 0 ]]; then
        KNOWN_TOOLING="${found[*]}"
    fi
}

# Collect evidence for a suspicious finding
collect_evidence() {
    local type="$1"  # process, module, ebpf, file
    local id="$2"    # PID, module name, prog ID, path

    [[ "$FULL_SCAN" != "true" ]] && return

    log_info "  --- Evidence Bundle ---"
    case "$type" in
        process)
            local pid="$id"
            [[ -d "/proc/$pid" ]] || return
            log_info "  exe: $(readlink -f /proc/$pid/exe 2>/dev/null || echo 'unreadable')"
            log_info "  cmdline: $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | head -c 200)"
            log_info "  cwd: $(readlink -f /proc/$pid/cwd 2>/dev/null || echo 'unreadable')"
            log_info "  uid: $(awk '/^Uid:/{print $2}' /proc/$pid/status 2>/dev/null)"
            log_info "  cgroup: $(head -1 /proc/$pid/cgroup 2>/dev/null)"
            # Hash the binary if possible
            local exe_path
            exe_path=$(readlink -f /proc/$pid/exe 2>/dev/null)
            if [[ -f "$exe_path" ]] && command -v sha256sum &>/dev/null; then
                log_info "  sha256: $(sha256sum "$exe_path" 2>/dev/null | awk '{print $1}')"
            fi
            ;;
        module)
            local mod="$id"
            log_info "  modinfo: $(modinfo "$mod" 2>/dev/null | grep -E '^(filename|version|author|description):' | tr '\n' ' ')"
            if [[ -d "/sys/module/$mod/sections" ]]; then
                log_info "  sections: $(ls /sys/module/$mod/sections/ 2>/dev/null | tr '\n' ' ')"
            fi
            ;;
        ebpf)
            local prog_id="$id"
            if command -v bpftool &>/dev/null; then
                log_info "  prog details: $(bpftool prog show id "$prog_id" 2>/dev/null | head -3 | tr '\n' ' ')"
            fi
            ;;
        file)
            local path="$id"
            [[ -e "$path" ]] || return
            log_info "  stat: $(stat -c '%A %U:%G %s %y' "$path" 2>/dev/null)"
            if command -v sha256sum &>/dev/null && [[ -f "$path" ]]; then
                log_info "  sha256: $(sha256sum "$path" 2>/dev/null | awk '{print $1}')"
            fi
            # Try to find package owner
            if command -v dpkg &>/dev/null; then
                local pkg
                pkg=$(dpkg -S "$path" 2>/dev/null | cut -d: -f1)
                [[ -n "$pkg" ]] && log_info "  package: $pkg"
            elif command -v rpm &>/dev/null; then
                local pkg
                pkg=$(rpm -qf "$path" 2>/dev/null)
                [[ -n "$pkg" ]] && log_info "  package: $pkg"
            fi
            ;;
    esac
    log_info "  --- End Evidence ---"
}

# Logging functions - use arithmetic that won't return exit status 1
log_alert() {
    ALERTS=$((ALERTS + 1))
    echo -e "${RED}[ALERT]${NC} $1" | tee -a "${OUTPUT_FILE:-/dev/null}"
}

log_warning() {
    WARNINGS=$((WARNINGS + 1))
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${OUTPUT_FILE:-/dev/null}"
}

log_info() {
    INFO=$((INFO + 1))
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
            echo "  --full    Run comprehensive scan (slower, more noise on busy systems)"
            echo "  --output  Write results to file"
            echo ""
            echo "NOTE: This script provides indicators, not definitive proof."
            echo "      False positives are expected in environments with observability"
            echo "      tooling (Falco, Cilium, Datadog, etc)."
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
        echo "This script should be run as root for full detection capabilities"
        echo "Some checks will be skipped or limited..."
        return 1
    fi
    return 0
}

# Initialize output file
if [[ -n "$OUTPUT_FILE" ]]; then
    {
        echo "Rootkit Detection Scan - $(date)"
        echo "Host: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Arch: $ARCH"
        echo "---"
    } > "$OUTPUT_FILE"
fi

echo ""
echo "====================================================="
echo "  Linux Rootkit Indicator Detection Script"
echo "  $(date)"
echo "  Host: $(hostname) | Kernel: $(uname -r) | Arch: $ARCH"
echo "====================================================="

IS_ROOT=true
check_root || IS_ROOT=false

# Detect known security tooling
detect_known_tooling
if [[ -n "$KNOWN_TOOLING" ]]; then
    echo "Detected tooling: $KNOWN_TOOLING"
    echo "(eBPF/kprobe findings from these tools are expected)"
fi

###############################################################################
# 1. PROCESS HIDING DETECTION
###############################################################################
log_section "1. Process Hiding Detection"

check_hidden_processes() {
    log_info "Comparing process listings from multiple sources..."

    # Use a subshell to scope temp directory cleanup
    (
        TEMP_DIR=$(mktemp -d)
        trap 'rm -rf -- "$TEMP_DIR"' EXIT

        # Take multiple samples to reduce race condition false positives
        local samples=3
        local delay=0.1

        for i in $(seq 1 $samples); do
            find /proc -maxdepth 1 -type d -name '[0-9]*' 2>/dev/null | \
                sed 's|/proc/||' | sort -n > "$TEMP_DIR/proc_pids_$i"
            ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n > "$TEMP_DIR/ps_pids_$i"
            sleep "$delay" 2>/dev/null || true
        done

        # Find PIDs that are consistently in /proc but not in ps across all samples
        local proc_count
        proc_count=$(wc -l < "$TEMP_DIR/proc_pids_1")
        local hidden_count=0

        while read -r pid; do
            [[ -z "$pid" ]] && continue

            # Check if this PID is missing from ps in ALL samples
            local missing_count=0
            for i in $(seq 1 $samples); do
                if ! grep -qx "$pid" "$TEMP_DIR/ps_pids_$i" 2>/dev/null; then
                    missing_count=$((missing_count + 1))
                fi
            done

            # Only alert if consistently hidden AND still exists
            if [[ $missing_count -eq $samples ]] && [[ -d "/proc/$pid" ]]; then
                local comm="unknown"
                comm=$(cat "/proc/$pid/comm" 2>/dev/null) || comm="unknown"
                log_alert "Hidden process: PID $pid ($comm) - consistently in /proc but not ps"
                collect_evidence process "$pid"
                hidden_count=$((hidden_count + 1))
            fi
        done < "$TEMP_DIR/proc_pids_1"

        if [[ $hidden_count -eq 0 ]]; then
            log_ok "No hidden processes detected ($proc_count PIDs, $samples samples)"
        fi

        # cgroup check - but note namespace visibility issues
        if [[ -d "/sys/fs/cgroup" ]] && [[ "$FULL_SCAN" == "true" ]]; then
            log_info "Checking cgroup process visibility (may be slow)..."
            # Limit to avoid massive slowdown on container-dense hosts
            find /sys/fs/cgroup -name "cgroup.procs" 2>/dev/null | head -100 | \
                xargs cat 2>/dev/null | sort -u > "$TEMP_DIR/cgroup_pids" || true

            while read -r pid; do
                [[ -z "$pid" ]] && continue
                if [[ -n "$pid" ]] && ! grep -qx "$pid" "$TEMP_DIR/proc_pids_1" 2>/dev/null; then
                    # Could be namespace visibility - INFO not WARNING
                    log_info "PID $pid in cgroups but not in /proc (likely namespace visibility)"
                fi
            done < "$TEMP_DIR/cgroup_pids"
        fi
    )
}

check_hidden_processes

###############################################################################
# 2. eBPF PROGRAM DETECTION
###############################################################################
log_section "2. eBPF Program Analysis"

check_ebpf_programs() {
    if ! command -v bpftool &>/dev/null; then
        log_warning "bpftool not installed - cannot enumerate eBPF programs"
        log_info "Install: apt install linux-tools-common linux-tools-\$(uname -r)"
        return
    fi

    log_info "Enumerating loaded eBPF programs..."

    # Use JSON output if available for reliable parsing
    if bpftool prog list -j &>/dev/null; then
        check_ebpf_json
    else
        check_ebpf_text
    fi

    # Check network attachments
    log_info "Checking eBPF network attachments..."
    local net_output
    net_output=$(bpftool net list 2>/dev/null) || true
    if echo "$net_output" | grep -qE 'xdp|tc'; then
        log_info "eBPF programs attached to network interfaces:"
        echo "$net_output" | grep -E 'xdp|tc' | while read -r line; do
            log_info "  $line"
        done
        log_info "NOTE: This is normal if using Cilium, Calico, or similar CNI"
    else
        log_ok "No eBPF XDP/TC network attachments found"
    fi

    # Check for pinned BPF objects
    log_info "Checking for pinned BPF objects..."
    if [[ -d "/sys/fs/bpf" ]]; then
        local pinned
        pinned=$(find /sys/fs/bpf -type f 2>/dev/null | wc -l) || pinned=0
        if [[ $pinned -gt 0 ]]; then
            log_info "$pinned pinned BPF objects in /sys/fs/bpf"
            find /sys/fs/bpf -type f 2>/dev/null | head -10 | while read -r obj; do
                log_info "  $obj"
            done
            [[ $pinned -gt 10 ]] && log_info "  ... and $((pinned - 10)) more"
        else
            log_ok "No pinned BPF objects found"
        fi
    fi
}

check_ebpf_json() {
    # Parse JSON output - much more reliable
    if ! command -v jq &>/dev/null; then
        check_ebpf_text
        return
    fi

    local prog_data
    prog_data=$(bpftool prog list -j 2>/dev/null) || return

    local prog_count
    prog_count=$(echo "$prog_data" | jq -e 'length' 2>/dev/null) || prog_count=0
    log_info "Total eBPF programs loaded: $prog_count"

    # Check each program with attribution - use defensive jq with fallbacks
    echo "$prog_data" | jq -c '.[]?' 2>/dev/null | while read -r prog; do
        [[ -z "$prog" ]] && continue

        local prog_id prog_type prog_name pids
        prog_id=$(echo "$prog" | jq -r '(.id // .prog_id // "?") | tostring' 2>/dev/null) || prog_id="?"
        prog_type=$(echo "$prog" | jq -r '.type // "unknown"' 2>/dev/null) || prog_type="unknown"
        prog_name=$(echo "$prog" | jq -r '.name // "unnamed"' 2>/dev/null) || prog_name="unnamed"
        # .pids may not exist in older bpftool versions
        pids=$(echo "$prog" | jq -r '(.pids // [])? | if type == "array" then join(",") else "" end' 2>/dev/null) || pids=""

        # Check if this looks like known tooling
        local known_tool_match=""
        if [[ -n "$KNOWN_TOOLING" ]]; then
            for tool in $KNOWN_TOOLING; do
                if [[ "$prog_name" == *"$tool"* ]] || [[ "$prog_name" == *"cilium"* ]] || \
                   [[ "$prog_name" == *"falco"* ]] || [[ "$prog_name" == *"tetra"* ]]; then
                    known_tool_match="$tool"
                    break
                fi
            done
        fi

        # Attribution matters more than type
        case "$prog_type" in
            kprobe|tracepoint|raw_tracepoint|raw_tracepoint_writable)
                if [[ -n "$known_tool_match" ]]; then
                    log_info "$prog_type (expected: $known_tool_match): ID=$prog_id Name=$prog_name"
                elif [[ -z "$pids" ]] || [[ "$pids" == "null" ]]; then
                    log_warning "Unattributed $prog_type program: ID=$prog_id Name=$prog_name"
                    collect_evidence ebpf "$prog_id"
                else
                    log_info "$prog_type program: ID=$prog_id Name=$prog_name PIDs=[$pids]"
                fi
                ;;
            lsm)
                if [[ -n "$known_tool_match" ]]; then
                    log_info "LSM BPF (expected: $known_tool_match): ID=$prog_id Name=$prog_name"
                else
                    log_warning "LSM BPF program: ID=$prog_id Name=$prog_name (security hook)"
                    collect_evidence ebpf "$prog_id"
                fi
                ;;
            *)
                # socket_filter, xdp, etc - usually benign but log in full mode
                if [[ "$FULL_SCAN" == "true" ]]; then
                    log_info "$prog_type: ID=$prog_id Name=$prog_name"
                fi
                ;;
        esac
    done
}

check_ebpf_text() {
    # Fallback text parsing - less reliable but portable
    local prog_count=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        prog_count=$((prog_count + 1))

        # Parse without grep -P (not portable)
        local prog_id prog_type prog_name
        prog_id=$(echo "$line" | awk -F: '{print $1}' | tr -d ' ')
        prog_type=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="type") print $(i+1)}')
        prog_name=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="name") print $(i+1)}')

        case "$prog_type" in
            kprobe|tracepoint|raw_tracepoint|lsm)
                log_warning "Hook-capable eBPF: ID=$prog_id Type=$prog_type Name=${prog_name:-unnamed}"
                ;;
        esac
    done < <(bpftool prog list 2>/dev/null | grep -E '^[0-9]+:')

    log_info "Total eBPF programs loaded: $prog_count"
}

check_ebpf_programs

###############################################################################
# 3. KERNEL MODULE ANALYSIS
###############################################################################
log_section "3. Kernel Module Analysis"

check_kernel_modules() {
    log_info "Analyzing loaded kernel modules..."

    # Check kernel taint - useful signal, but don't try to decode (kernel-version dependent)
    if [[ -f "/proc/sys/kernel/tainted" ]]; then
        local taint
        taint=$(cat /proc/sys/kernel/tainted 2>/dev/null) || taint="?"
        if [[ "$taint" != "0" ]] && [[ "$taint" != "?" ]]; then
            log_warning "Kernel is tainted (value: $taint)"
            log_info "  See: /usr/src/linux/Documentation/admin-guide/tainted-kernels.rst"
            log_info "  Or: https://docs.kernel.org/admin-guide/tainted-kernels.html"
        else
            log_ok "Kernel is not tainted"
        fi
    fi

    # Get modules from both sources
    local proc_modules sysfs_modules
    proc_modules=$(awk '{print $1}' /proc/modules 2>/dev/null | sort)
    sysfs_modules=$(ls /sys/module 2>/dev/null | sort)

    log_info "Comparing /proc/modules vs /sys/module..."

    local hidden_count=0
    for mod in $sysfs_modules; do
        if ! echo "$proc_modules" | grep -qx "$mod"; then
            # Check if it's actually a loadable module (has .text section)
            if [[ -d "/sys/module/$mod/sections" ]]; then
                # Has sections = was loaded as module, but hidden from /proc/modules
                log_alert "Module '$mod' has sections but hidden from /proc/modules"
                hidden_count=$((hidden_count + 1))
            fi
            # Note: modules without sections/ are typically built-in
        fi
    done

    if [[ $hidden_count -eq 0 ]]; then
        log_ok "No hidden kernel modules detected"
    fi

    # Check module signing
    if [[ -f "/proc/sys/kernel/module_signature_required" ]]; then
        local sig_required
        sig_required=$(cat /proc/sys/kernel/module_signature_required 2>/dev/null) || sig_required="?"
        if [[ "$sig_required" == "1" ]]; then
            log_ok "Kernel module signature enforcement is enabled"
        else
            log_warning "Kernel module signature enforcement is disabled"
        fi
    fi

    # Check for suspicious module names (cartoon villain detection)
    log_info "Checking for obviously suspicious module names..."
    local suspicious_patterns="rootkit|reptile|diamorphine|adore|bdvl|suterusu|azazel"
    while read -r mod; do
        if echo "$mod" | grep -qiE "$suspicious_patterns"; then
            log_alert "Suspicious module name: $mod"
        fi
    done < <(awk '{print $1}' /proc/modules 2>/dev/null)

    # Check for modules without corresponding files (INFO level - many false positives)
    if [[ "$FULL_SCAN" == "true" ]] && [[ "$IS_ROOT" == "true" ]]; then
        log_info "Checking module file locations (may have false positives)..."
        for mod in $proc_modules; do
            # Try modinfo first - it handles name normalization
            local mod_file
            mod_file=$(modinfo -n "$mod" 2>/dev/null)
            if [[ -z "$mod_file" ]] || [[ "$mod_file" == *"not found"* ]]; then
                # modinfo failed - could be built-in, initramfs, or actually missing
                # Also try with underscore/hyphen normalization
                local mod_alt="${mod//_/-}"
                mod_file=$(modinfo -n "$mod_alt" 2>/dev/null)
                if [[ -z "$mod_file" ]] || [[ "$mod_file" == *"not found"* ]]; then
                    log_info "Module '$mod' has no file via modinfo (may be built-in/initramfs)"
                fi
            fi
        done
    fi
}

check_kernel_modules

###############################################################################
# 4. SYSCALL TABLE INTEGRITY (Limited Value - See Notes)
###############################################################################
log_section "4. Syscall Table Analysis"

check_syscall_table() {
    log_info "NOTE: Syscall table checks have limited value on modern kernels"
    log_info "      Modern rootkits use ftrace/kprobe/eBPF, not syscall table patching"

    if [[ "$IS_ROOT" != "true" ]]; then
        log_warning "Skipping syscall table check (requires root)"
        return
    fi

    # Check if kallsyms is readable and useful
    local kptr_restrict
    kptr_restrict=$(sysctl -n kernel.kptr_restrict 2>/dev/null) || kptr_restrict="?"
    if [[ "$kptr_restrict" != "0" ]]; then
        log_info "kernel.kptr_restrict=$kptr_restrict - kallsyms addresses hidden (this is good)"
        return
    fi

    log_warning "kernel.kptr_restrict=0 - kernel addresses exposed (consider hardening)"

    # Architecture-aware syscall name prefix
    local syscall_prefix=""
    case "$ARCH" in
        x86_64)  syscall_prefix="__x64_sys_" ;;
        aarch64) syscall_prefix="__arm64_sys_" ;;
        *)       syscall_prefix="sys_" ;;
    esac

    local syscall_addr
    syscall_addr=$(awk '/\bsys_call_table\b/ {print $1; exit}' /proc/kallsyms 2>/dev/null)

    if [[ -n "$syscall_addr" ]] && [[ "$syscall_addr" != "0000000000000000" ]]; then
        log_info "sys_call_table at: 0x$syscall_addr"
    else
        log_info "sys_call_table address not available"
    fi
}

check_syscall_table

###############################################################################
# 5. FTRACE AND KPROBE DETECTION
###############################################################################
log_section "5. Ftrace/Kprobe Hook Detection"

check_ftrace_hooks() {
    # First check if debugfs is mounted
    if ! mount | grep -q "debugfs on /sys/kernel/debug"; then
        log_warning "debugfs not mounted - cannot check ftrace/kprobes"
        log_info "Mount with: mount -t debugfs none /sys/kernel/debug"
        return
    fi

    if [[ ! -d "/sys/kernel/debug/tracing" ]]; then
        log_warning "Tracing directory not available"
        return
    fi

    # The real signals for ftrace-based hooking:
    # 1. current_tracer != nop (active tracer)
    # 2. kprobes/list has entries (kprobe hooks)
    # 3. set_ftrace_filter alone is NOT a hook - just a filter for when tracing is enabled

    # Check current tracer FIRST - this is the primary signal
    local current_tracer
    current_tracer=$(cat /sys/kernel/debug/tracing/current_tracer 2>/dev/null) || current_tracer="unknown"
    if [[ "$current_tracer" != "nop" ]] && [[ "$current_tracer" != "unknown" ]]; then
        log_warning "Active ftrace tracer: $current_tracer"
    else
        log_ok "No active ftrace tracer (current_tracer=nop)"
    fi

    # Check set_ftrace_filter - but clarify this is NOT active hooking by itself
    local enabled_funcs="/sys/kernel/debug/tracing/set_ftrace_filter"
    if [[ -r "$enabled_funcs" ]] && [[ "$FULL_SCAN" == "true" ]]; then
        local filter_count
        filter_count=$(grep -cvE '^#|^$' "$enabled_funcs" 2>/dev/null) || filter_count=0
        if [[ $filter_count -gt 0 ]]; then
            log_info "$filter_count ftrace filter entries (filter config, not active hooks)"
        fi
    fi

    # Check kprobes - this IS where modern hooking happens
    log_info "Checking kprobes (primary kernel hook mechanism)..."
    local kprobe_list="/sys/kernel/debug/kprobes/list"
    if [[ -r "$kprobe_list" ]]; then
        local kprobe_count
        kprobe_count=$(wc -l < "$kprobe_list" 2>/dev/null) || kprobe_count=0
        if [[ $kprobe_count -gt 0 ]]; then
            # Check for known tooling
            if [[ -n "$KNOWN_TOOLING" ]]; then
                log_info "$kprobe_count active kprobes (known tooling detected: $KNOWN_TOOLING)"
            else
                log_warning "$kprobe_count active kprobes"
            fi

            # Look for suspicious targets (syscalls, security hooks, creds)
            local suspicious_targets="sys_|do_sys|security_|prepare_creds|commit_creds|__x64_sys|vfs_"
            local suspicious_kprobes
            suspicious_kprobes=$(grep -E "$suspicious_targets" "$kprobe_list" 2>/dev/null | head -10)
            if [[ -n "$suspicious_kprobes" ]]; then
                log_info "  Kprobes on sensitive functions:"
                echo "$suspicious_kprobes" | while read -r line; do
                    log_info "    $line"
                done
            fi

            if [[ "$FULL_SCAN" == "true" ]]; then
                log_info "  All kprobes:"
                head -10 "$kprobe_list" 2>/dev/null | while read -r line; do
                    log_info "    $line"
                done
                [[ $kprobe_count -gt 10 ]] && log_info "    ... and $((kprobe_count - 10)) more"
            fi
        else
            log_ok "No active kprobes"
        fi
    fi
}

check_ftrace_hooks

###############################################################################
# 6. NETWORK ANOMALY DETECTION
###############################################################################
log_section "6. Network Anomaly Detection"

check_network_anomalies() {
    log_info "Checking network indicators..."

    # Check for promiscuous mode interfaces
    log_info "Checking for promiscuous interfaces..."
    local promisc_found=false
    for iface in /sys/class/net/*; do
        [[ ! -d "$iface" ]] && continue
        local name flags
        name=$(basename "$iface")
        flags=$(cat "$iface/flags" 2>/dev/null) || continue

        # IFF_PROMISC = 0x100
        if [[ $((flags & 0x100)) -ne 0 ]]; then
            log_warning "Interface $name is in promiscuous mode"
            promisc_found=true
        fi
    done
    [[ "$promisc_found" == "false" ]] && log_ok "No promiscuous interfaces"

    # Check for raw sockets
    log_info "Checking for raw sockets..."
    local raw_count
    raw_count=$(cat /proc/net/raw /proc/net/raw6 2>/dev/null | tail -n +2 | wc -l) || raw_count=0

    if [[ $raw_count -gt 0 ]]; then
        log_info "$raw_count raw socket(s) detected"

        # Only do expensive inode->process mapping in --full mode
        if [[ "$IS_ROOT" == "true" ]] && [[ "$FULL_SCAN" == "true" ]]; then
            log_info "Mapping raw sockets to processes..."
            local raw_inodes match_count=0 max_matches=10
            # Field position may vary - try to be defensive
            raw_inodes=$(awk 'NR>1 && NF>=10 {print $10}' /proc/net/raw /proc/net/raw6 2>/dev/null | sort -u | head -20)

            for inode in $raw_inodes; do
                [[ -z "$inode" ]] || [[ "$inode" == "0" ]] && continue
                [[ $match_count -ge $max_matches ]] && break

                # Find which process has this socket - limit scan
                for pid_dir in /proc/[0-9]*; do
                    local pid
                    pid=$(basename "$pid_dir")
                    if ls -la "$pid_dir/fd" 2>/dev/null | grep -q "socket:\[$inode\]"; then
                        local comm
                        comm=$(cat "$pid_dir/comm" 2>/dev/null) || comm="unknown"
                        log_info "  Raw socket -> PID $pid ($comm)"
                        match_count=$((match_count + 1))
                        break
                    fi
                done
            done
            [[ $match_count -ge $max_matches ]] && log_info "  (limited to $max_matches matches)"
        elif [[ $raw_count -gt 5 ]]; then
            log_info "  Use --full to map sockets to processes"
        fi
    else
        log_ok "No raw sockets detected"
    fi

    # Check for suspicious listening ports
    log_info "Checking for commonly suspicious ports..."
    local suspicious_ports=(31337 4444 5555 6666 7777 12345 54321 1337)
    for port in "${suspicious_ports[@]}"; do
        if ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"; then
            log_warning "Port $port is listening (commonly used by backdoors)"
        fi
    done
}

check_network_anomalies

###############################################################################
# 7. FILE HIDING DETECTION
###############################################################################
log_section "7. File Hiding Detection"

check_hidden_files() {
    log_info "Checking for LD_PRELOAD hijacking..."

    # Check LD_PRELOAD env - most important
    if [[ -n "${LD_PRELOAD:-}" ]]; then
        log_alert "LD_PRELOAD is set: $LD_PRELOAD"
    else
        log_ok "LD_PRELOAD is not set in current environment"
    fi

    # Check /etc/ld.so.preload - system-wide hijack
    if [[ -f "/etc/ld.so.preload" ]]; then
        local preload_content
        preload_content=$(cat /etc/ld.so.preload 2>/dev/null | grep -v '^#' | grep -v '^$')
        if [[ -n "$preload_content" ]]; then
            log_alert "/etc/ld.so.preload contains: $preload_content"
        else
            log_ok "/etc/ld.so.preload exists but is empty/commented"
        fi
    else
        log_ok "/etc/ld.so.preload does not exist"
    fi

    # Check for immutable files in temp directories
    if command -v lsattr &>/dev/null; then
        log_info "Checking for immutable files in temp locations..."
        for dir in /tmp /var/tmp /dev/shm; do
            if [[ -d "$dir" ]]; then
                # lsattr can be slow, limit depth
                lsattr -d "$dir"/* 2>/dev/null | grep -E '^....i' | while read -r line; do
                    log_warning "Immutable file: $line"
                done
            fi
        done
    fi

    # File listing comparison is unreliable in bash due to filename handling
    # Just note that it's not being done
    if [[ "$FULL_SCAN" == "true" ]]; then
        log_info "NOTE: Reliable file hiding detection requires tools like unhide or comparison from trusted boot media"
    fi
}

check_hidden_files

###############################################################################
# 8. PERSISTENCE MECHANISM DETECTION
###############################################################################
log_section "8. Persistence Mechanism Detection"

check_persistence() {
    log_info "Checking persistence mechanisms..."

    # Check rc.local for module loading
    for rc in /etc/rc.local /etc/rc.d/rc.local; do
        if [[ -f "$rc" ]]; then
            if [[ -x "$rc" ]]; then
                log_warning "Executable rc.local: $rc"
            fi
            if grep -qE 'insmod|modprobe|\.ko\b' "$rc" 2>/dev/null; then
                log_alert "rc.local contains module loading commands:"
                grep -E 'insmod|modprobe|\.ko\b' "$rc" 2>/dev/null | head -3 | while read -r line; do
                    log_info "  $line"
                done
            fi
        fi
    done

    # Check systemd - look at actual ExecStart, not just names
    log_info "Checking systemd unit files..."
    if command -v systemctl &>/dev/null; then
        # Check for units that load kernel modules
        local unit_dirs="/etc/systemd/system /run/systemd/system /usr/lib/systemd/system"
        for dir in $unit_dirs; do
            [[ ! -d "$dir" ]] && continue
            find "$dir" -name "*.service" -type f 2>/dev/null | while read -r unit; do
                if grep -qE 'ExecStart=.*(insmod|modprobe)' "$unit" 2>/dev/null; then
                    log_warning "Service loads modules: $unit"
                fi
                if grep -qE 'ExecStart=.*/dev/tcp|ExecStart=.*\bnc\b|ExecStart=.*\bncat\b' "$unit" 2>/dev/null; then
                    log_alert "Service has suspicious network commands: $unit"
                fi
            done
        done

        # Check for drop-in overrides
        if [[ -d "/etc/systemd/system" ]]; then
            local dropins
            dropins=$(find /etc/systemd/system -name "*.conf" -path "*/*.d/*" 2>/dev/null | wc -l) || dropins=0
            if [[ $dropins -gt 0 ]]; then
                log_info "$dropins systemd drop-in override(s) found"
                if [[ "$FULL_SCAN" == "true" ]]; then
                    find /etc/systemd/system -name "*.conf" -path "*/*.d/*" 2>/dev/null | while read -r dropin; do
                        log_info "  $dropin"
                    done
                fi
            fi
        fi
    fi

    # Check cron - look for actual suspicious content
    log_info "Checking cron jobs..."
    local cron_locations="/etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron/crontabs"
    for loc in $cron_locations; do
        if [[ -e "$loc" ]]; then
            find "$loc" -type f 2>/dev/null | while read -r cronfile; do
                # Check for base64 encoded commands, reverse shells, module loading
                if grep -qE 'base64.*-d|/dev/tcp|bash -i|insmod|modprobe' "$cronfile" 2>/dev/null; then
                    log_warning "Suspicious cron content in: $cronfile"
                fi
            done
        fi
    done

    # Check shell init files for LD_PRELOAD or suspicious additions
    log_info "Checking shell init files..."
    local init_files="/etc/profile /etc/bash.bashrc /etc/environment"
    for f in $init_files; do
        if [[ -f "$f" ]] && grep -qE 'LD_PRELOAD|/dev/tcp' "$f" 2>/dev/null; then
            log_alert "Suspicious content in $f"
        fi
    done

    # Check PAM configuration - capture output properly
    if [[ -d "/etc/pam.d" ]]; then
        log_info "Checking PAM configuration..."
        local pam_exec_matches
        pam_exec_matches=$(grep -rlE 'pam_exec|pam_script' /etc/pam.d/ 2>/dev/null | head -10)
        if [[ -n "$pam_exec_matches" ]]; then
            log_info "PAM exec/script modules found (may be legitimate):"
            echo "$pam_exec_matches" | while read -r pam_file; do
                log_info "  $pam_file"
                if [[ "$FULL_SCAN" == "true" ]]; then
                    grep -E 'pam_exec|pam_script' "$pam_file" 2>/dev/null | grep -v '^#' | head -2 | while read -r line; do
                        log_info "    $line"
                    done
                fi
            done
        fi
    fi
}

check_persistence

###############################################################################
# 9. KERNEL SECURITY SETTINGS (Posture, not rootkit indicators)
###############################################################################
log_section "9. Kernel Security Posture"

check_kernel_security() {
    log_info "Checking kernel hardening settings..."
    log_info "NOTE: These are posture indicators, not rootkit detections"

    # Key security sysctls
    declare -A checks=(
        ["kernel.kptr_restrict"]="2:Kernel pointer restriction"
        ["kernel.dmesg_restrict"]="1:Dmesg restriction"
        ["kernel.perf_event_paranoid"]="2:Perf event paranoid (3=max)"
        ["kernel.yama.ptrace_scope"]="1:Ptrace scope"
        ["kernel.unprivileged_bpf_disabled"]="1:Unprivileged BPF disabled"
        ["net.core.bpf_jit_harden"]="2:BPF JIT hardening"
    )

    for key in "${!checks[@]}"; do
        local expected desc actual
        expected=$(echo "${checks[$key]}" | cut -d: -f1)
        desc=$(echo "${checks[$key]}" | cut -d: -f2)
        actual=$(sysctl -n "$key" 2>/dev/null) || actual="N/A"

        if [[ "$actual" == "N/A" ]]; then
            log_info "$desc: not available"
        elif [[ "$actual" -lt "$expected" ]] 2>/dev/null; then
            log_warning "$desc: $actual (hardened: $expected)"
        else
            log_ok "$desc: $actual"
        fi
    done

    # Secure Boot status
    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null) || sb_state="unknown"
        if echo "$sb_state" | grep -qi "enabled"; then
            log_ok "Secure Boot: enabled"
        else
            log_info "Secure Boot: $sb_state"
        fi
    fi

    # Kernel lockdown
    if [[ -f "/sys/kernel/security/lockdown" ]]; then
        local lockdown
        lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null) || lockdown="unknown"
        log_info "Kernel lockdown: $lockdown"
    fi
}

check_kernel_security

###############################################################################
# SUMMARY
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
echo ""
echo "IMPORTANT CAVEATS:"
echo "  - This script runs on potentially compromised host"
echo "  - Kernel-level rootkits can make all reads lie"
echo "  - Many warnings are expected in containerized/observability environments"
echo "  - For real IR: image disk, capture memory, analyze offline"
echo ""

if [[ $ALERTS -gt 0 ]]; then
    echo -e "${RED}$ALERTS alert(s) found - investigate before trusting this system${NC}"
    exit 2
elif [[ $WARNINGS -gt 10 ]]; then
    echo -e "${YELLOW}Many warnings - review in context of your environment${NC}"
    exit 1
else
    echo -e "${GREEN}No critical indicators (but absence of evidence != evidence of absence)${NC}"
    exit 0
fi
