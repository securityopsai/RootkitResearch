#!/usr/bin/env python3
"""
Automated Memory Analysis Script for Volatility 3

A defensive forensics tool that orchestrates Volatility 3 plugins to perform
automated memory dump analysis with a focus on rootkit and malware detection.
Designed for incident response and threat hunting workflows.

Usage:
    python3 vol3_analyzer.py --memory /path/to/memdump.raw --profile full_analysis
    python3 vol3_analyzer.py --memory /path/to/memdump.raw --profile rootkit_hunt --output report.html
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from analyzers.plugin_runner import VolatilityPluginRunner
from analyzers.rootkit_detector import RootkitDetector
from analyzers.report_generator import ReportGenerator

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"


def setup_logging(verbosity: int, log_file: str | None = None) -> logging.Logger:
    """Configure logging with the requested verbosity level."""
    level = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}.get(
        verbosity, logging.DEBUG
    )
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=level, format=LOG_FORMAT, handlers=handlers)
    return logging.getLogger("vol3_analyzer")


def load_profile(profile_path: str) -> dict:
    """Load an analysis profile from a YAML file."""
    try:
        import yaml
    except ImportError:
        sys.exit(
            "PyYAML is required. Install with: pip install pyyaml"
        )
    with open(profile_path, "r") as f:
        return yaml.safe_load(f)


def resolve_profile(profile_name: str) -> str:
    """Resolve a profile name to its file path, checking built-in profiles."""
    # Direct path
    if os.path.isfile(profile_name):
        return profile_name
    # Check built-in profiles directory
    builtin = Path(__file__).parent / "profiles" / f"{profile_name}.yaml"
    if builtin.is_file():
        return str(builtin)
    sys.exit(
        f"Profile '{profile_name}' not found. "
        f"Available profiles: {list_profiles()}"
    )


def list_profiles() -> list[str]:
    """List available built-in analysis profiles."""
    profiles_dir = Path(__file__).parent / "profiles"
    return [p.stem for p in profiles_dir.glob("*.yaml")]


def validate_memory_file(path: str) -> str:
    """Validate that the memory dump file exists and is readable."""
    if not os.path.isfile(path):
        sys.exit(f"Memory dump not found: {path}")
    if not os.access(path, os.R_OK):
        sys.exit(f"Memory dump is not readable: {path}")
    size_mb = os.path.getsize(path) / (1024 * 1024)
    if size_mb < 1:
        logging.getLogger("vol3_analyzer").warning(
            "Memory dump is very small (%.1f MB) - may be incomplete", size_mb
        )
    return os.path.abspath(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automated Memory Analysis with Volatility 3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --memory memdump.raw --profile quick_scan
  %(prog)s --memory memdump.raw --profile rootkit_hunt --output report.html
  %(prog)s --memory memdump.raw --profile full_analysis --format json
  %(prog)s --list-profiles
  %(prog)s --memory memdump.raw --plugins linux.pslist,linux.lsmod
        """,
    )
    parser.add_argument(
        "--memory", "-m", help="Path to the memory dump file"
    )
    parser.add_argument(
        "--profile",
        "-p",
        default="quick_scan",
        help="Analysis profile to use (default: quick_scan)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path for the report (default: stdout for text, auto-named for html/json)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "html", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--volatility-path",
        default=None,
        help="Path to volatility3 installation (default: auto-detect)",
    )
    parser.add_argument(
        "--symbol-path",
        default=None,
        help="Path to volatility symbol tables",
    )
    parser.add_argument(
        "--plugins",
        help="Comma-separated list of specific plugins to run (overrides profile)",
    )
    parser.add_argument(
        "--yara-rules",
        help="Path to YARA rules file for scanning",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of plugins to run in parallel (default: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Timeout per plugin in seconds (default: 600)",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available analysis profiles and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v info, -vv debug)",
    )
    parser.add_argument(
        "--log-file", help="Write log output to file"
    )
    return parser


def run_analysis(args: argparse.Namespace, logger: logging.Logger) -> dict:
    """Execute the full analysis pipeline and return structured results."""
    memory_path = validate_memory_file(args.memory)
    start_time = time.monotonic()

    # Determine which plugins to run
    if args.plugins:
        plugin_list = [p.strip() for p in args.plugins.split(",")]
        profile_config = {"name": "custom", "plugins": plugin_list}
    else:
        profile_path = resolve_profile(args.profile)
        profile_config = load_profile(profile_path)
        logger.info("Loaded profile: %s", profile_config.get("name", args.profile))

    # Initialize the plugin runner
    runner = VolatilityPluginRunner(
        memory_path=memory_path,
        volatility_path=args.volatility_path,
        symbol_path=args.symbol_path,
        timeout=args.timeout,
        parallel=args.parallel,
        logger=logger,
    )

    # Verify volatility3 is available
    vol_version = runner.check_volatility()
    logger.info("Volatility 3 detected: %s", vol_version)

    # Run all plugins from the profile
    plugin_names = profile_config.get("plugins", [])
    logger.info("Running %d plugins...", len(plugin_names))
    plugin_results = runner.run_plugins(plugin_names)

    # Run YARA scan if rules provided
    yara_results = None
    if args.yara_rules:
        logger.info("Running YARA scan with rules: %s", args.yara_rules)
        yara_results = runner.run_yara_scan(args.yara_rules)

    # Perform rootkit detection analysis
    detector = RootkitDetector(logger=logger)
    detection_config = profile_config.get("detection", {})
    findings = detector.analyze(plugin_results, detection_config)

    elapsed = time.monotonic() - start_time

    # Build the final results structure
    results = {
        "metadata": {
            "memory_file": memory_path,
            "memory_size_mb": round(os.path.getsize(memory_path) / (1024 * 1024), 1),
            "profile": profile_config.get("name", args.profile),
            "volatility_version": vol_version,
            "analysis_time_seconds": round(elapsed, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "plugins_run": len(plugin_names),
            "plugins_succeeded": sum(
                1 for r in plugin_results.values() if r.get("success")
            ),
        },
        "plugin_results": plugin_results,
        "yara_results": yara_results,
        "findings": findings,
        "summary": detector.generate_summary(findings),
    }
    return results


def output_results(results: dict, args: argparse.Namespace, logger: logging.Logger):
    """Generate and write the analysis report."""
    generator = ReportGenerator(logger=logger)

    if args.format == "json":
        report = json.dumps(results, indent=2, default=str)
    elif args.format == "html":
        report = generator.generate_html(results)
    else:
        report = generator.generate_text(results)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        logger.info("Report written to: %s", args.output)
    else:
        print(report)


def main():
    parser = build_parser()
    args = parser.parse_args()
    logger = setup_logging(args.verbose, args.log_file)

    if args.list_profiles:
        profiles = list_profiles()
        print("Available analysis profiles:")
        for name in profiles:
            profile_path = resolve_profile(name)
            profile = load_profile(profile_path)
            desc = profile.get("description", "No description")
            print(f"  {name:20s} - {desc}")
        return

    if not args.memory:
        parser.error("--memory is required (unless using --list-profiles)")

    logger.info("Starting automated memory analysis")
    results = run_analysis(args, logger)

    # Print summary to stderr so it appears even when report goes to file
    summary = results["summary"]
    severity = summary.get("max_severity", "info")
    severity_colors = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[37m"}
    reset = "\033[0m"
    color = severity_colors.get(severity, "")

    print(
        f"\n{'=' * 60}\n"
        f"  Analysis Complete\n"
        f"  Plugins: {results['metadata']['plugins_succeeded']}/{results['metadata']['plugins_run']} succeeded\n"
        f"  Time: {results['metadata']['analysis_time_seconds']}s\n"
        f"  Findings: {summary.get('total_findings', 0)}\n"
        f"  Max Severity: {color}{severity.upper()}{reset}\n"
        f"{'=' * 60}",
        file=sys.stderr,
    )

    output_results(results, args, logger)


if __name__ == "__main__":
    main()
