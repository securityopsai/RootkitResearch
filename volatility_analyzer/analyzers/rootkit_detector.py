"""
Rootkit Detection Engine

Cross-references output from multiple Volatility 3 plugins to identify
indicators of rootkit activity. Uses heuristic analysis, anomaly detection,
and known rootkit signatures.
"""

import logging
import re
from collections import defaultdict


# Severity levels in ascending order
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Known suspicious kernel module names associated with rootkits
KNOWN_ROOTKIT_MODULES = {
    "diamorphine", "reptile", "reptile_module", "adore-ng", "adore",
    "knark", "azazel", "jynx", "jynx2", "vlany", "brootus",
    "suterusu", "rooty", "nurupo", "bdvl", "medusa",
    "kovid", "hiding", "rootkit", "r00tkit", "backdoor",
    "keylogger", "sniffer",
}

# Suspicious process names
SUSPICIOUS_PROCESSES = {
    "nc", "ncat", "socat", "cryptominer", "xmrig", "minerd",
    "kworkerds", "kdevtmpfsi", "ksoftirqd_exploit",
}

# Kernel threads should not have user-space memory maps
KERNEL_THREAD_COMM_PATTERNS = [
    r"^\[.*\]$",  # Kernel threads are typically shown in brackets
]

# Suspicious network ports
SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 6667, 7777, 8888, 9999,  # Common backdoor ports
    31337, 31338,  # Elite/leet ports
    12345, 23456, 54321,  # Common trojan ports
    1337, 1338,
}


class Finding:
    """Represents a single detection finding."""

    def __init__(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        evidence: list[str] | None = None,
        mitre_ids: list[str] | None = None,
    ):
        self.title = title
        self.severity = severity
        self.category = category
        self.description = description
        self.evidence = evidence or []
        self.mitre_ids = mitre_ids or []

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "mitre_ids": self.mitre_ids,
        }


class RootkitDetector:
    """
    Analyzes Volatility 3 plugin output to detect rootkit indicators.

    Detection categories:
    - hidden_process: Processes hidden from userspace but visible in memory
    - hidden_module: Kernel modules hidden from lsmod
    - syscall_hook: Modifications to the syscall table
    - idt_hook: Modifications to the interrupt descriptor table
    - network_anomaly: Suspicious network connections
    - suspicious_module: Known rootkit modules loaded
    - memory_injection: Code injection in process memory
    - privilege_escalation: Unusual capability or privilege patterns
    """

    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)
        self.findings: list[Finding] = []

    def analyze(self, plugin_results: dict[str, dict], config: dict | None = None) -> list[dict]:
        """
        Run all detection checks against the collected plugin output.

        Args:
            plugin_results: dict mapping plugin name -> result dict
            config: optional detection configuration overrides

        Returns:
            list of finding dicts
        """
        config = config or {}
        self.findings = []

        # Run each detection check if relevant data is available
        self._check_hidden_processes(plugin_results)
        self._check_hidden_modules(plugin_results)
        self._check_syscall_hooks(plugin_results)
        self._check_idt_hooks(plugin_results)
        self._check_suspicious_modules(plugin_results)
        self._check_network_anomalies(plugin_results)
        self._check_memory_injection(plugin_results)
        self._check_privilege_anomalies(plugin_results)
        self._check_suspicious_processes(plugin_results)
        self._check_kernel_threads(plugin_results)
        self._check_tty_hooks(plugin_results)
        self._check_keyboard_notifiers(plugin_results)

        self.logger.info("Detection complete: %d findings", len(self.findings))
        return [f.to_dict() for f in self.findings]

    def generate_summary(self, findings: list[dict]) -> dict:
        """Generate a summary of all findings."""
        by_severity = defaultdict(int)
        by_category = defaultdict(int)
        for f in findings:
            by_severity[f["severity"]] += 1
            by_category[f["category"]] += 1

        max_sev = "info"
        for sev in SEVERITY_ORDER:
            if by_severity.get(sev, 0) > 0:
                max_sev = sev

        return {
            "total_findings": len(findings),
            "max_severity": max_sev,
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
        }

    def _add_finding(self, **kwargs):
        finding = Finding(**kwargs)
        self.findings.append(finding)
        self.logger.info(
            "[%s] %s: %s", finding.severity.upper(), finding.category, finding.title
        )

    def _get_parsed_data(self, plugin_results: dict, *plugin_names: str) -> list[dict] | None:
        """Retrieve parsed data from the first available plugin in the list."""
        for name in plugin_names:
            result = plugin_results.get(name)
            if result and result.get("success") and result.get("parsed_data"):
                data = result["parsed_data"]
                # Handle Volatility 3 JSON format which nests data under a key
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
                if isinstance(data, list):
                    return data
        return None

    # -------------------------------------------------------------------
    # Detection: Hidden Processes
    # -------------------------------------------------------------------
    def _check_hidden_processes(self, results: dict):
        """
        Compare pslist output with pstree to find processes visible in
        one view but not the other - a hallmark of process hiding.
        """
        pslist_data = self._get_parsed_data(results, "pslist")
        pstree_data = self._get_parsed_data(results, "pstree")

        if not pslist_data:
            return

        # Extract PIDs from pslist
        pslist_pids = set()
        for entry in pslist_data:
            pid = entry.get("PID") or entry.get("pid")
            if pid is not None:
                pslist_pids.add(int(pid))

        if not pstree_data:
            return

        # Extract PIDs from pstree
        pstree_pids = set()
        for entry in pstree_data:
            pid = entry.get("PID") or entry.get("pid")
            if pid is not None:
                pstree_pids.add(int(pid))

        # Processes in pstree but not in pslist might be hidden
        hidden = pstree_pids - pslist_pids
        if hidden:
            self._add_finding(
                title="Potential hidden processes detected",
                severity="high",
                category="hidden_process",
                description=(
                    f"Found {len(hidden)} process(es) visible in pstree but missing "
                    f"from pslist. This is a strong indicator of process hiding, "
                    f"commonly used by rootkits to conceal malicious processes."
                ),
                evidence=[f"Hidden PIDs: {sorted(hidden)}"],
                mitre_ids=["T1014", "T1564.001"],
            )

        # Also check the reverse - pslist has entries pstree doesn't
        orphaned = pslist_pids - pstree_pids
        if orphaned:
            self._add_finding(
                title="Orphaned processes found (no parent in tree)",
                severity="medium",
                category="hidden_process",
                description=(
                    f"Found {len(orphaned)} process(es) in pslist that don't appear "
                    f"in the process tree. This could indicate DKOM (Direct Kernel "
                    f"Object Manipulation) or parent process manipulation."
                ),
                evidence=[f"Orphaned PIDs: {sorted(orphaned)}"],
                mitre_ids=["T1014"],
            )

    # -------------------------------------------------------------------
    # Detection: Hidden Kernel Modules
    # -------------------------------------------------------------------
    def _check_hidden_modules(self, results: dict):
        """
        Use check_modules and hidden_modules plugins to identify kernel
        modules that have been unlinked from the module list.
        """
        hidden_data = self._get_parsed_data(results, "hidden_modules")
        if hidden_data:
            module_names = []
            for entry in hidden_data:
                name = entry.get("Name") or entry.get("name") or "unknown"
                module_names.append(name)

            if module_names:
                self._add_finding(
                    title="Hidden kernel modules detected",
                    severity="critical",
                    category="hidden_module",
                    description=(
                        f"Found {len(module_names)} kernel module(s) present in memory "
                        f"but hidden from the module list. This is a primary indicator "
                        f"of an LKM rootkit that has unlinked itself."
                    ),
                    evidence=[f"Hidden modules: {module_names}"],
                    mitre_ids=["T1014", "T1547.006"],
                )

        # Cross-reference check_modules output
        check_data = self._get_parsed_data(results, "check_modules")
        if check_data:
            for entry in check_data:
                status = str(entry.get("Status", "")).lower()
                if "unlinked" in status or "hidden" in status:
                    name = entry.get("Name") or entry.get("name") or "unknown"
                    self._add_finding(
                        title=f"Module '{name}' flagged by check_modules",
                        severity="critical",
                        category="hidden_module",
                        description=(
                            f"The check_modules plugin reports module '{name}' "
                            f"has suspicious status: {status}"
                        ),
                        evidence=[f"Module: {name}, Status: {status}"],
                        mitre_ids=["T1014", "T1547.006"],
                    )

    # -------------------------------------------------------------------
    # Detection: Syscall Table Hooks
    # -------------------------------------------------------------------
    def _check_syscall_hooks(self, results: dict):
        """
        Analyze check_syscall output for syscall table modifications.
        Hooked syscalls are a classic rootkit technique.
        """
        syscall_data = self._get_parsed_data(results, "check_syscall")
        if not syscall_data:
            return

        hooked = []
        for entry in syscall_data:
            # check_syscall marks hooked entries
            status = str(entry.get("Status", "") or entry.get("Hooked", "")).lower()
            handler = str(entry.get("Handler", "") or entry.get("Address", ""))
            symbol = str(entry.get("Symbol", "") or entry.get("Name", ""))

            if any(word in status for word in ["hooked", "modified", "unknown"]):
                hooked.append(
                    f"Syscall {entry.get('Index', '?')}: {symbol} -> {handler}"
                )

        if hooked:
            self._add_finding(
                title=f"Syscall table hooks detected ({len(hooked)} hooks)",
                severity="critical",
                category="syscall_hook",
                description=(
                    "Modifications to the syscall table were detected. This is "
                    "a fundamental rootkit technique used to intercept system calls "
                    "and hide malicious activity from userspace tools."
                ),
                evidence=hooked[:20],  # Limit evidence to first 20
                mitre_ids=["T1014", "T1574.013"],
            )

    # -------------------------------------------------------------------
    # Detection: IDT Hooks
    # -------------------------------------------------------------------
    def _check_idt_hooks(self, results: dict):
        """Check for interrupt descriptor table modifications."""
        idt_data = self._get_parsed_data(results, "check_idt")
        if not idt_data:
            return

        suspicious = []
        for entry in idt_data:
            status = str(entry.get("Status", "")).lower()
            if "hooked" in status or "modified" in status:
                suspicious.append(
                    f"IDT[{entry.get('Index', '?')}]: {entry.get('Symbol', 'unknown')} "
                    f"-> {entry.get('Address', '?')}"
                )

        if suspicious:
            self._add_finding(
                title="IDT hooks detected",
                severity="high",
                category="idt_hook",
                description=(
                    "Modifications to the Interrupt Descriptor Table were found. "
                    "IDT hooking can intercept hardware/software interrupts to "
                    "control execution flow at a very low level."
                ),
                evidence=suspicious[:10],
                mitre_ids=["T1014"],
            )

    # -------------------------------------------------------------------
    # Detection: Suspicious Modules
    # -------------------------------------------------------------------
    def _check_suspicious_modules(self, results: dict):
        """Check loaded modules against known rootkit module names."""
        lsmod_data = self._get_parsed_data(results, "lsmod")
        if not lsmod_data:
            return

        for entry in lsmod_data:
            name = str(entry.get("Name") or entry.get("name") or "").lower()
            if name in KNOWN_ROOTKIT_MODULES:
                self._add_finding(
                    title=f"Known rootkit module loaded: {name}",
                    severity="critical",
                    category="suspicious_module",
                    description=(
                        f"The kernel module '{name}' matches a known rootkit. "
                        f"This module should be immediately investigated."
                    ),
                    evidence=[
                        f"Module: {name}",
                        f"Size: {entry.get('Size', 'unknown')}",
                    ],
                    mitre_ids=["T1014", "T1547.006"],
                )
            elif any(kw in name for kw in ["hide", "hook", "stealth", "invis", "sniff"]):
                self._add_finding(
                    title=f"Suspiciously named kernel module: {name}",
                    severity="high",
                    category="suspicious_module",
                    description=(
                        f"Module '{name}' has a name containing rootkit-related "
                        f"keywords. This may warrant further investigation."
                    ),
                    evidence=[f"Module: {name}"],
                    mitre_ids=["T1547.006"],
                )

    # -------------------------------------------------------------------
    # Detection: Network Anomalies
    # -------------------------------------------------------------------
    def _check_network_anomalies(self, results: dict):
        """Identify suspicious network connections."""
        net_data = self._get_parsed_data(results, "netstat", "sockstat")
        if not net_data:
            return

        suspicious_conns = []
        backdoor_ports = []

        for entry in net_data:
            local_port = entry.get("LocalPort") or entry.get("local_port")
            remote_addr = entry.get("ForeignAddr") or entry.get("remote_addr") or ""
            state = str(entry.get("State") or entry.get("state") or "").upper()
            pid = entry.get("PID") or entry.get("pid")

            if local_port is not None:
                try:
                    port_int = int(local_port)
                    if port_int in SUSPICIOUS_PORTS:
                        backdoor_ports.append(
                            f"PID {pid} listening on port {port_int} ({state})"
                        )
                except (ValueError, TypeError):
                    pass

            # Check for connections to non-RFC1918 addresses in ESTABLISHED state
            if "ESTABLISHED" in state and remote_addr:
                remote_ip = remote_addr.split(":")[0] if ":" in remote_addr else remote_addr
                if remote_ip and not self._is_private_ip(remote_ip):
                    suspicious_conns.append(
                        f"PID {pid} -> {remote_addr} ({state})"
                    )

        if backdoor_ports:
            self._add_finding(
                title="Connections on known backdoor ports",
                severity="high",
                category="network_anomaly",
                description=(
                    "Processes are listening on ports commonly associated with "
                    "backdoors and remote access tools."
                ),
                evidence=backdoor_ports,
                mitre_ids=["T1571", "T1095"],
            )

        if len(suspicious_conns) > 10:
            self._add_finding(
                title="High number of external connections",
                severity="medium",
                category="network_anomaly",
                description=(
                    f"Found {len(suspicious_conns)} established connections to "
                    f"external IP addresses. This may indicate C2 activity or "
                    f"data exfiltration."
                ),
                evidence=suspicious_conns[:15],
                mitre_ids=["T1071"],
            )

    # -------------------------------------------------------------------
    # Detection: Memory Injection (Malfind)
    # -------------------------------------------------------------------
    def _check_memory_injection(self, results: dict):
        """Analyze malfind output for code injection indicators."""
        malfind_data = self._get_parsed_data(results, "malfind")
        if not malfind_data:
            return

        injections = []
        for entry in malfind_data:
            pid = entry.get("PID") or entry.get("pid")
            comm = entry.get("Process") or entry.get("Comm") or entry.get("comm") or "unknown"
            protection = entry.get("Protection") or entry.get("protection") or ""
            address = entry.get("Start VPN") or entry.get("address") or "?"

            injections.append(f"PID {pid} ({comm}) at {address} [{protection}]")

        if injections:
            severity = "high" if len(injections) > 3 else "medium"
            self._add_finding(
                title=f"Suspicious memory regions found ({len(injections)} regions)",
                severity=severity,
                category="memory_injection",
                description=(
                    "Malfind detected memory regions with executable permissions "
                    "that may contain injected code. These regions don't correspond "
                    "to any mapped file on disk."
                ),
                evidence=injections[:15],
                mitre_ids=["T1055", "T1055.001"],
            )

    # -------------------------------------------------------------------
    # Detection: Privilege Anomalies
    # -------------------------------------------------------------------
    def _check_privilege_anomalies(self, results: dict):
        """Check for unusual process capabilities or privilege patterns."""
        caps_data = self._get_parsed_data(results, "capabilities")
        if not caps_data:
            return

        dangerous_caps = {
            "cap_sys_module", "cap_sys_rawio", "cap_sys_ptrace",
            "cap_sys_admin", "cap_dac_override", "cap_net_admin",
        }

        suspicious_procs = []
        for entry in caps_data:
            pid = entry.get("PID") or entry.get("pid")
            comm = entry.get("Name") or entry.get("comm") or "unknown"
            caps = str(entry.get("Capabilities") or entry.get("cap_effective") or "").lower()

            found_dangerous = [c for c in dangerous_caps if c in caps]
            if found_dangerous and pid and int(pid) > 1:
                suspicious_procs.append(
                    f"PID {pid} ({comm}): {', '.join(found_dangerous)}"
                )

        if suspicious_procs:
            self._add_finding(
                title="Processes with dangerous capabilities",
                severity="medium",
                category="privilege_escalation",
                description=(
                    "Processes were found with kernel-level capabilities that "
                    "could be used for privilege escalation or rootkit loading."
                ),
                evidence=suspicious_procs[:10],
                mitre_ids=["T1068", "T1548"],
            )

    # -------------------------------------------------------------------
    # Detection: Suspicious Process Names
    # -------------------------------------------------------------------
    def _check_suspicious_processes(self, results: dict):
        """Flag processes with names matching known attack tools."""
        pslist_data = self._get_parsed_data(results, "pslist", "pstree")
        if not pslist_data:
            return

        found = []
        for entry in pslist_data:
            comm = str(entry.get("COMM") or entry.get("comm") or entry.get("Name") or "").lower()
            if comm in SUSPICIOUS_PROCESSES:
                pid = entry.get("PID") or entry.get("pid")
                found.append(f"PID {pid}: {comm}")

        if found:
            self._add_finding(
                title="Suspicious processes detected",
                severity="high",
                category="suspicious_process",
                description=(
                    "Processes matching known attack tools or cryptominers were "
                    "found running on the system."
                ),
                evidence=found,
                mitre_ids=["T1059", "T1496"],
            )

    # -------------------------------------------------------------------
    # Detection: Kernel Thread Anomalies
    # -------------------------------------------------------------------
    def _check_kernel_threads(self, results: dict):
        """Detect userspace processes masquerading as kernel threads."""
        pslist_data = self._get_parsed_data(results, "pslist")
        maps_data = self._get_parsed_data(results, "proc_maps")

        if not pslist_data:
            return

        # Identify processes with kernel-thread-like names
        kernel_like = {}
        for entry in pslist_data:
            comm = str(entry.get("COMM") or entry.get("comm") or entry.get("Name") or "")
            pid = entry.get("PID") or entry.get("pid")
            if pid is None:
                continue
            for pattern in KERNEL_THREAD_COMM_PATTERNS:
                if re.match(pattern, comm):
                    kernel_like[int(pid)] = comm

        # If we have memory maps, check if these "kernel threads" have userspace mappings
        if maps_data and kernel_like:
            suspicious = []
            for entry in maps_data:
                pid = entry.get("PID") or entry.get("pid")
                if pid is not None and int(pid) in kernel_like:
                    suspicious.append(
                        f"PID {pid} ({kernel_like[int(pid)]}) has userspace memory maps"
                    )

            if suspicious:
                self._add_finding(
                    title="Fake kernel threads detected",
                    severity="high",
                    category="hidden_process",
                    description=(
                        "Processes with kernel-thread-like names were found to have "
                        "userspace memory mappings. Real kernel threads do not have "
                        "userspace memory. This is a common rootkit disguise technique."
                    ),
                    evidence=list(set(suspicious))[:10],
                    mitre_ids=["T1036.004", "T1014"],
                )

    # -------------------------------------------------------------------
    # Detection: TTY Hooks
    # -------------------------------------------------------------------
    def _check_tty_hooks(self, results: dict):
        """Check for TTY layer hooks used for keylogging."""
        tty_data = self._get_parsed_data(results, "tty_check")
        if not tty_data:
            return

        hooks = []
        for entry in tty_data:
            status = str(entry.get("Status", "")).lower()
            if "hooked" in status or "modified" in status:
                hooks.append(
                    f"{entry.get('Name', '?')}: {entry.get('Address', '?')} ({status})"
                )

        if hooks:
            self._add_finding(
                title="TTY hooks detected (potential keylogger)",
                severity="high",
                category="tty_hook",
                description=(
                    "Hooks were found in the TTY subsystem. This technique is "
                    "commonly used by rootkits to intercept terminal I/O for "
                    "credential theft (keylogging)."
                ),
                evidence=hooks,
                mitre_ids=["T1056.001"],
            )

    # -------------------------------------------------------------------
    # Detection: Keyboard Notifier Hooks
    # -------------------------------------------------------------------
    def _check_keyboard_notifiers(self, results: dict):
        """Check for keyboard notifier registrations (keylogger indicator)."""
        kb_data = self._get_parsed_data(results, "keyboard_notifiers")
        if not kb_data:
            return

        suspicious = []
        for entry in kb_data:
            module = str(entry.get("Module") or entry.get("module") or "")
            if module and module.lower() not in ("", "kernel"):
                suspicious.append(
                    f"Module '{module}' registered keyboard notifier at "
                    f"{entry.get('Address', '?')}"
                )

        if suspicious:
            self._add_finding(
                title="Keyboard notifier hooks (potential keylogger)",
                severity="high",
                category="keylogger",
                description=(
                    "Non-kernel modules have registered keyboard notifier callbacks. "
                    "This mechanism is used by rootkits to capture keystrokes."
                ),
                evidence=suspicious,
                mitre_ids=["T1056.001"],
            )

    # -------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if an IP address is in a private/reserved range."""
        if not ip or ip in ("0.0.0.0", "::"):
            return True
        parts = ip.split(".")
        if len(parts) != 4:
            return True  # Treat IPv6 and malformed as "private" to avoid FP
        try:
            first = int(parts[0])
            second = int(parts[1])
        except ValueError:
            return True
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        return False
