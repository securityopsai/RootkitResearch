"""
Volatility 3 Plugin Runner

Handles discovery, execution, and output parsing of Volatility 3 plugins.
Supports parallel execution, timeouts, and structured output collection.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


class VolatilityPluginRunner:
    """Orchestrates Volatility 3 plugin execution against a memory dump."""

    # Map of plugin short names to full Volatility 3 plugin paths
    PLUGIN_ALIASES = {
        # Linux plugins
        "pslist": "linux.pslist.PsList",
        "pstree": "linux.pstree.PsTree",
        "lsmod": "linux.lsmod.Lsmod",
        "check_modules": "linux.check_modules.Check_modules",
        "check_syscall": "linux.check_syscall.Check_syscall",
        "check_idt": "linux.check_idt.Check_idt",
        "hidden_modules": "linux.hidden_modules.Hidden_modules",
        "tty_check": "linux.tty_check.tty_check",
        "netstat": "linux.netstat.Netstat",
        "sockstat": "linux.sockstat.Sockstat",
        "lsof": "linux.lsof.Lsof",
        "bash": "linux.bash.Bash",
        "elfs": "linux.elfs.Elfs",
        "proc_maps": "linux.proc.Maps",
        "kmsg": "linux.kmsg.Kmsg",
        "mount": "linux.mountinfo.MountInfo",
        "keyboard_notifiers": "linux.keyboard_notifiers.Keyboard_notifiers",
        "malfind": "linux.malfind.Malfind",
        "envars": "linux.envars.Envars",
        "capabilities": "linux.capabilities.Capabilities",
        # Windows plugins
        "win_pslist": "windows.pslist.PsList",
        "win_pstree": "windows.pstree.PsTree",
        "win_netscan": "windows.netscan.NetScan",
        "win_modules": "windows.modules.Modules",
        "win_ssdt": "windows.ssdt.SSDT",
        "win_callbacks": "windows.callbacks.Callbacks",
        "win_malfind": "windows.malfind.Malfind",
        "win_svcscan": "windows.svcscan.SvcScan",
        "win_dlllist": "windows.dlllist.DllList",
        "win_handles": "windows.handles.Handles",
        "win_registry": "windows.registry.hivelist.HiveList",
        "win_cmdline": "windows.cmdline.CmdLine",
    }

    def __init__(
        self,
        memory_path: str,
        volatility_path: str | None = None,
        symbol_path: str | None = None,
        timeout: int = 600,
        parallel: int = 1,
        logger: logging.Logger | None = None,
    ):
        self.memory_path = memory_path
        self.volatility_path = volatility_path
        self.symbol_path = symbol_path
        self.timeout = timeout
        self.parallel = parallel
        self.logger = logger or logging.getLogger(__name__)
        self._vol_cmd = self._find_volatility()

    def _find_volatility(self) -> list[str]:
        """Locate the Volatility 3 executable."""
        # If explicit path provided, use it
        if self.volatility_path:
            vol_script = os.path.join(self.volatility_path, "vol.py")
            if os.path.isfile(vol_script):
                return ["python3", vol_script]
            vol_bin = os.path.join(self.volatility_path, "vol")
            if os.path.isfile(vol_bin):
                return [vol_bin]

        # Try 'vol' or 'vol.py' on PATH
        vol_on_path = shutil.which("vol") or shutil.which("vol3") or shutil.which("vol.py")
        if vol_on_path:
            return [vol_on_path]

        # Try python module
        try:
            result = subprocess.run(
                ["python3", "-m", "volatility3", "-h"],
                capture_output=True,
                timeout=15,
            )
            if result.returncode == 0:
                return ["python3", "-m", "volatility3"]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        raise RuntimeError(
            "Volatility 3 not found. Install it with:\n"
            "  pip install volatility3\n"
            "Or specify --volatility-path /path/to/volatility3"
        )

    def check_volatility(self) -> str:
        """Verify Volatility 3 is working and return version string."""
        try:
            result = subprocess.run(
                self._vol_cmd + ["-h"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Extract version from help output
            for line in result.stdout.splitlines():
                if "Volatility 3" in line or "volatility 3" in line.lower():
                    return line.strip()
            if result.returncode == 0:
                return "Volatility 3 (version unknown)"
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(f"Volatility 3 check failed: {e}")
        raise RuntimeError(
            "Volatility 3 does not appear to be working correctly"
        )

    def _resolve_plugin(self, name: str) -> str:
        """Resolve a plugin alias or validate a full plugin name."""
        if name in self.PLUGIN_ALIASES:
            return self.PLUGIN_ALIASES[name]
        # If it looks like a full plugin path (contains dots), use as-is
        if "." in name:
            return name
        self.logger.warning(
            "Unknown plugin alias '%s' - passing through to volatility", name
        )
        return name

    def _build_command(self, plugin: str, extra_args: list[str] | None = None) -> list[str]:
        """Build the full volatility command for a plugin."""
        cmd = list(self._vol_cmd)
        cmd.extend(["-f", self.memory_path])

        if self.symbol_path:
            cmd.extend(["-s", self.symbol_path])

        # Request JSON output for structured parsing
        cmd.extend(["-r", "json"])
        cmd.append(plugin)

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    def run_plugin(self, plugin_name: str, extra_args: list[str] | None = None) -> dict:
        """
        Run a single Volatility 3 plugin and return structured results.

        Returns:
            dict with keys: success, plugin, raw_output, parsed_data, error, duration
        """
        resolved = self._resolve_plugin(plugin_name)
        cmd = self._build_command(resolved, extra_args)

        self.logger.info("Running plugin: %s (%s)", plugin_name, resolved)
        self.logger.debug("Command: %s", " ".join(cmd))

        start = __import__("time").monotonic()
        result_data = {
            "success": False,
            "plugin": plugin_name,
            "plugin_full": resolved,
            "raw_output": "",
            "parsed_data": None,
            "error": None,
            "duration": 0,
        }

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            result_data["raw_output"] = proc.stdout
            result_data["duration"] = round(__import__("time").monotonic() - start, 2)

            if proc.returncode != 0:
                result_data["error"] = proc.stderr.strip() or f"Exit code {proc.returncode}"
                # Some plugins return non-zero but still produce output
                if proc.stdout.strip():
                    self.logger.warning(
                        "Plugin %s returned non-zero but produced output", plugin_name
                    )
                else:
                    self.logger.error("Plugin %s failed: %s", plugin_name, result_data["error"])
                    return result_data

            # Parse JSON output
            result_data["parsed_data"] = self._parse_output(proc.stdout)
            result_data["success"] = True

        except subprocess.TimeoutExpired:
            result_data["error"] = f"Timeout after {self.timeout}s"
            result_data["duration"] = self.timeout
            self.logger.error("Plugin %s timed out after %ds", plugin_name, self.timeout)
        except Exception as e:
            result_data["error"] = str(e)
            result_data["duration"] = round(__import__("time").monotonic() - start, 2)
            self.logger.error("Plugin %s raised exception: %s", plugin_name, e)

        return result_data

    def _parse_output(self, raw_output: str) -> list[dict] | dict | None:
        """Parse Volatility 3 JSON output into structured data."""
        if not raw_output.strip():
            return None

        try:
            data = json.loads(raw_output)
            return data
        except json.JSONDecodeError:
            pass

        # Fallback: try to parse as text table
        return self._parse_text_table(raw_output)

    def _parse_text_table(self, text: str) -> list[dict] | None:
        """Parse Volatility 3 text table output into list of dicts."""
        lines = text.strip().splitlines()
        if len(lines) < 2:
            return None

        # Find the header line (usually first non-empty line)
        header_line = None
        data_start = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("*"):
                header_line = stripped
                data_start = i + 1
                break

        if not header_line:
            return None

        # Split header by multiple spaces or tabs
        headers = re.split(r"\s{2,}|\t", header_line)
        headers = [h.strip() for h in headers if h.strip()]

        if not headers:
            return None

        # Skip separator line (dashes)
        if data_start < len(lines) and re.match(r"^[\s\-*]+$", lines[data_start]):
            data_start += 1

        rows = []
        for line in lines[data_start:]:
            if not line.strip() or re.match(r"^[\s\-*]+$", line):
                continue
            values = re.split(r"\s{2,}|\t", line.strip())
            row = {}
            for j, header in enumerate(headers):
                row[header] = values[j].strip() if j < len(values) else ""
            rows.append(row)

        return rows if rows else None

    def run_plugins(self, plugin_names: list[str]) -> dict[str, dict]:
        """
        Run multiple plugins, optionally in parallel.

        Returns:
            dict mapping plugin_name -> result dict
        """
        results = {}

        if self.parallel <= 1:
            for name in plugin_names:
                results[name] = self.run_plugin(name)
        else:
            with ThreadPoolExecutor(max_workers=self.parallel) as executor:
                future_map = {
                    executor.submit(self.run_plugin, name): name
                    for name in plugin_names
                }
                for future in as_completed(future_map):
                    name = future_map[future]
                    try:
                        results[name] = future.result()
                    except Exception as e:
                        results[name] = {
                            "success": False,
                            "plugin": name,
                            "error": str(e),
                            "parsed_data": None,
                            "raw_output": "",
                            "duration": 0,
                        }

        return results

    def run_yara_scan(self, rules_path: str) -> dict:
        """Run Volatility 3's YARA scanning plugin with the provided rules."""
        if not os.path.isfile(rules_path):
            return {"success": False, "error": f"YARA rules file not found: {rules_path}"}

        return self.run_plugin(
            "yarascan",
            extra_args=["--yara-file", rules_path],
        )

    def get_available_plugins(self) -> list[str]:
        """Query Volatility 3 for all available plugins."""
        try:
            # Run with a non-existent plugin to get the plugin list in error
            result = subprocess.run(
                self._vol_cmd + ["-f", self.memory_path, "--plugin-dirs", ".", "frameworkinfo"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Parse available plugins from output
            plugins = []
            for line in (result.stdout + result.stderr).splitlines():
                line = line.strip()
                if line.startswith("linux.") or line.startswith("windows."):
                    plugins.append(line.split()[0])
            return sorted(plugins)
        except Exception as e:
            self.logger.warning("Could not enumerate plugins: %s", e)
            return []
