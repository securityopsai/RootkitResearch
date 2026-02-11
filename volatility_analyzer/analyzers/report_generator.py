"""
Report Generator

Produces formatted analysis reports in text, HTML, and JSON formats.
Includes severity-based color coding and structured finding summaries.
"""

import html
import logging
from datetime import datetime


SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
}

SEVERITY_ICONS = {
    "critical": "[!!!]",
    "high": "[!!] ",
    "medium": "[!]  ",
    "low": "[*]  ",
    "info": "[-]  ",
}


class ReportGenerator:
    """Generate analysis reports in multiple formats."""

    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Text Report
    # ------------------------------------------------------------------
    def generate_text(self, results: dict) -> str:
        """Generate a plain-text report suitable for terminal output."""
        lines = []
        meta = results.get("metadata", {})
        findings = results.get("findings", [])
        summary = results.get("summary", {})

        # Header
        lines.append("=" * 72)
        lines.append("  VOLATILITY 3 AUTOMATED MEMORY ANALYSIS REPORT")
        lines.append("=" * 72)
        lines.append("")

        # Metadata
        lines.append("--- Analysis Metadata ---")
        lines.append(f"  Memory File     : {meta.get('memory_file', 'N/A')}")
        lines.append(f"  Memory Size     : {meta.get('memory_size_mb', '?')} MB")
        lines.append(f"  Profile Used    : {meta.get('profile', 'N/A')}")
        lines.append(f"  Volatility Ver  : {meta.get('volatility_version', 'N/A')}")
        lines.append(f"  Analysis Time   : {meta.get('analysis_time_seconds', '?')}s")
        lines.append(f"  Timestamp       : {meta.get('timestamp', 'N/A')}")
        lines.append(
            f"  Plugins Run     : {meta.get('plugins_succeeded', 0)}/{meta.get('plugins_run', 0)} succeeded"
        )
        lines.append("")

        # Summary
        lines.append("--- Summary ---")
        lines.append(f"  Total Findings  : {summary.get('total_findings', 0)}")
        lines.append(f"  Max Severity    : {summary.get('max_severity', 'info').upper()}")
        by_sev = summary.get("by_severity", {})
        if by_sev:
            sev_parts = [f"{k}: {v}" for k, v in sorted(by_sev.items())]
            lines.append(f"  Breakdown       : {', '.join(sev_parts)}")
        lines.append("")

        # Plugin Execution Summary
        plugin_results = results.get("plugin_results", {})
        if plugin_results:
            lines.append("--- Plugin Execution ---")
            for name, res in sorted(plugin_results.items()):
                status = "OK" if res.get("success") else "FAIL"
                duration = res.get("duration", 0)
                error = res.get("error", "")
                line = f"  [{status:4s}] {name:30s} ({duration}s)"
                if error and not res.get("success"):
                    line += f"  -- {error[:60]}"
                lines.append(line)
            lines.append("")

        # Findings
        if findings:
            lines.append("--- Findings ---")
            lines.append("")

            # Sort by severity (critical first)
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5)
            )

            for i, finding in enumerate(sorted_findings, 1):
                sev = finding.get("severity", "info")
                icon = SEVERITY_ICONS.get(sev, "     ")
                lines.append(f"{icon} Finding #{i}: {finding.get('title', 'Unknown')}")
                lines.append(f"      Severity : {sev.upper()}")
                lines.append(f"      Category : {finding.get('category', 'N/A')}")

                mitre = finding.get("mitre_ids", [])
                if mitre:
                    lines.append(f"      MITRE    : {', '.join(mitre)}")

                desc = finding.get("description", "")
                if desc:
                    # Wrap description text
                    words = desc.split()
                    current_line = "      Detail   : "
                    for word in words:
                        if len(current_line) + len(word) + 1 > 72:
                            lines.append(current_line)
                            current_line = "                 " + word
                        else:
                            current_line += (" " if not current_line.endswith(": ") else "") + word
                    if current_line.strip():
                        lines.append(current_line)

                evidence = finding.get("evidence", [])
                if evidence:
                    lines.append("      Evidence :")
                    for ev in evidence:
                        lines.append(f"        - {ev}")

                lines.append("")
        else:
            lines.append("--- No suspicious findings detected ---")
            lines.append("")

        # YARA Results
        yara = results.get("yara_results")
        if yara and yara.get("success") and yara.get("parsed_data"):
            lines.append("--- YARA Scan Results ---")
            yara_data = yara["parsed_data"]
            if isinstance(yara_data, dict) and "data" in yara_data:
                yara_data = yara_data["data"]
            if isinstance(yara_data, list):
                for match in yara_data[:20]:
                    rule = match.get("Rule") or match.get("rule") or "?"
                    pid = match.get("PID") or match.get("pid") or "?"
                    lines.append(f"  Rule: {rule}  PID: {pid}")
            lines.append("")

        # Footer
        lines.append("=" * 72)
        lines.append("  Report generated by vol3_analyzer - Defensive Forensics Tool")
        lines.append("=" * 72)

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # HTML Report
    # ------------------------------------------------------------------
    def generate_html(self, results: dict) -> str:
        """Generate an HTML report with styling and color-coded findings."""
        meta = results.get("metadata", {})
        findings = results.get("findings", [])
        summary = results.get("summary", {})
        plugin_results = results.get("plugin_results", {})

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5)
        )

        h = html.escape  # Shorthand

        parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1'>",
            "<title>Memory Analysis Report</title>",
            "<style>",
            self._get_css(),
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<h1>Volatility 3 Memory Analysis Report</h1>",
        ]

        # Metadata table
        parts.append("<div class='section'><h2>Analysis Metadata</h2>")
        parts.append("<table class='meta-table'>")
        meta_rows = [
            ("Memory File", meta.get("memory_file", "N/A")),
            ("Memory Size", f"{meta.get('memory_size_mb', '?')} MB"),
            ("Profile", meta.get("profile", "N/A")),
            ("Volatility Version", meta.get("volatility_version", "N/A")),
            ("Analysis Time", f"{meta.get('analysis_time_seconds', '?')}s"),
            ("Timestamp", meta.get("timestamp", "N/A")),
            ("Plugins", f"{meta.get('plugins_succeeded', 0)}/{meta.get('plugins_run', 0)} succeeded"),
        ]
        for label, value in meta_rows:
            parts.append(f"<tr><td class='label'>{h(label)}</td><td>{h(str(value))}</td></tr>")
        parts.append("</table></div>")

        # Summary banner
        max_sev = summary.get("max_severity", "info")
        sev_color = SEVERITY_COLORS.get(max_sev, "#6c757d")
        total = summary.get("total_findings", 0)
        parts.append(
            f"<div class='summary-banner' style='border-left: 6px solid {sev_color};'>"
            f"<h2>Summary</h2>"
            f"<p><strong>{total}</strong> finding(s) &mdash; "
            f"Maximum severity: <span class='sev-badge sev-{h(max_sev)}'>{h(max_sev.upper())}</span></p>"
        )
        by_sev = summary.get("by_severity", {})
        if by_sev:
            parts.append("<div class='sev-counts'>")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = by_sev.get(sev, 0)
                if count:
                    parts.append(
                        f"<span class='sev-badge sev-{sev}'>{sev.upper()}: {count}</span> "
                    )
            parts.append("</div>")
        parts.append("</div>")

        # Plugin results table
        if plugin_results:
            parts.append("<div class='section'><h2>Plugin Execution</h2>")
            parts.append("<table class='plugin-table'><thead><tr>")
            parts.append("<th>Plugin</th><th>Status</th><th>Duration</th><th>Details</th>")
            parts.append("</tr></thead><tbody>")
            for name, res in sorted(plugin_results.items()):
                ok = res.get("success")
                status_class = "status-ok" if ok else "status-fail"
                status_text = "OK" if ok else "FAIL"
                duration = res.get("duration", 0)
                error = h(str(res.get("error", ""))[:100]) if not ok else ""
                parts.append(
                    f"<tr><td>{h(name)}</td>"
                    f"<td class='{status_class}'>{status_text}</td>"
                    f"<td>{duration}s</td>"
                    f"<td>{error}</td></tr>"
                )
            parts.append("</tbody></table></div>")

        # Findings
        if sorted_findings:
            parts.append("<div class='section'><h2>Findings</h2>")
            for i, finding in enumerate(sorted_findings, 1):
                sev = finding.get("severity", "info")
                color = SEVERITY_COLORS.get(sev, "#6c757d")
                parts.append(
                    f"<div class='finding' style='border-left: 4px solid {color};'>"
                    f"<h3><span class='sev-badge sev-{h(sev)}'>{h(sev.upper())}</span> "
                    f"#{i}: {h(finding.get('title', 'Unknown'))}</h3>"
                    f"<p class='category'>Category: {h(finding.get('category', 'N/A'))}</p>"
                )

                mitre = finding.get("mitre_ids", [])
                if mitre:
                    mitre_links = ", ".join(
                        f"<a href='https://attack.mitre.org/techniques/{h(m)}/' "
                        f"target='_blank'>{h(m)}</a>"
                        for m in mitre
                    )
                    parts.append(f"<p class='mitre'>MITRE ATT&CK: {mitre_links}</p>")

                desc = finding.get("description", "")
                if desc:
                    parts.append(f"<p class='description'>{h(desc)}</p>")

                evidence = finding.get("evidence", [])
                if evidence:
                    parts.append("<details><summary>Evidence</summary><ul>")
                    for ev in evidence:
                        parts.append(f"<li><code>{h(str(ev))}</code></li>")
                    parts.append("</ul></details>")

                parts.append("</div>")
            parts.append("</div>")
        else:
            parts.append(
                "<div class='section no-findings'>"
                "<h2>No Suspicious Findings Detected</h2>"
                "<p>All checks passed without detecting rootkit indicators.</p>"
                "</div>"
            )

        # Footer
        parts.append(
            "<footer>"
            "<p>Generated by <strong>vol3_analyzer</strong> &mdash; Defensive Forensics Tool</p>"
            "</footer>"
        )
        parts.append("</div></body></html>")

        return "\n".join(parts)

    def _get_css(self) -> str:
        return """
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                background: #0d1117; color: #c9d1d9; line-height: 1.6;
            }
            .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }
            h1 { color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: 0.8rem; margin-bottom: 1.5rem; }
            h2 { color: #58a6ff; margin-bottom: 1rem; }
            .section { background: #161b22; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
            .meta-table { width: 100%; border-collapse: collapse; }
            .meta-table td { padding: 0.4rem 0.8rem; border-bottom: 1px solid #21262d; }
            .meta-table .label { color: #8b949e; width: 180px; font-weight: 600; }
            .summary-banner { background: #161b22; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
            .sev-counts { display: flex; gap: 0.5rem; margin-top: 0.5rem; flex-wrap: wrap; }
            .sev-badge {
                display: inline-block; padding: 2px 10px; border-radius: 12px;
                font-size: 0.85em; font-weight: 700; color: #fff;
            }
            .sev-critical { background: #dc3545; }
            .sev-high { background: #fd7e14; }
            .sev-medium { background: #ffc107; color: #000; }
            .sev-low { background: #17a2b8; }
            .sev-info { background: #6c757d; }
            .plugin-table { width: 100%; border-collapse: collapse; }
            .plugin-table th { text-align: left; padding: 0.6rem; background: #21262d; color: #58a6ff; }
            .plugin-table td { padding: 0.5rem 0.6rem; border-bottom: 1px solid #21262d; }
            .status-ok { color: #3fb950; font-weight: 700; }
            .status-fail { color: #f85149; font-weight: 700; }
            .finding {
                background: #0d1117; border-radius: 6px; padding: 1.2rem;
                margin-bottom: 1rem;
            }
            .finding h3 { margin-bottom: 0.5rem; }
            .finding .category { color: #8b949e; font-size: 0.9em; }
            .finding .mitre { color: #58a6ff; font-size: 0.9em; margin-top: 0.3rem; }
            .finding .mitre a { color: #58a6ff; }
            .finding .description { margin-top: 0.5rem; }
            details { margin-top: 0.5rem; }
            details summary { cursor: pointer; color: #58a6ff; font-weight: 600; }
            details ul { margin: 0.5rem 0 0 1.5rem; }
            details li { margin-bottom: 0.3rem; }
            code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
            .no-findings { text-align: center; color: #3fb950; }
            footer { text-align: center; color: #484f58; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #21262d; }
        """
