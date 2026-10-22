#!/usr/bin/env python3
"""
KQL False Positive Pattern Generator

Generates tuned KQL snippets for common FP scenarios in Azure Sentinel
and Defender XDR custom detections.
Run with: python kql_fp_patterns.py --pattern <pattern_name> [options]
"""

import argparse
import sys

PATTERNS = {
    "watchlist_exclude": {
        "description": "Exclude entities via watchlist lookup (Sentinel)",
        "template": """let Excluded = _GetWatchlist('{watchlist_name}')
| project Entity = tolower({entity_field});
{base_table}
| where tolower({target_field}) !in (Excluded)""",
        "params": ["watchlist_name", "entity_field", "base_table", "target_field"]
    },

    "time_window": {
        "description": "Exclude events during maintenance windows",
        "template": """| where not(
    dayofweek(TimeGenerated) in ({excluded_days})
    and hourofday(TimeGenerated) between ({start_hour} .. {end_hour})
)""",
        "params": ["excluded_days", "start_hour", "end_hour"]
    },

    "threshold": {
        "description": "Aggregate and apply count threshold",
        "template": """| summarize Count = count() by {group_by_field}, bin(TimeGenerated, {time_bin})
| where Count > {threshold}""",
        "params": ["group_by_field", "time_bin", "threshold"]
    },

    "null_safe": {
        "description": "Filter out null/empty/placeholder values",
        "template": """| where isnotempty({field})
    and {field} != "-"
    and {field} != "N/A"
    and {field} != "SYSTEM"
    and {field} !startswith "$"  // service accounts""",
        "params": ["field"]
    },

    "process_exclude": {
        "description": "Exclude known-good processes by path/hash",
        "template": """let TrustedProcesses = dynamic([
    @"{process_1}",
    @"{process_2}"
]);
{base_table}
| where not(ProcessName has_any (TrustedProcesses))
    and not(ProcessPath has_any (TrustedProcesses))""",
        "params": ["process_1", "process_2", "base_table"]
    },

    "ip_range_exclude": {
        "description": "Exclude internal/known IP ranges",
        "template": """| where not(ipv4_is_in_range(IpAddress, "{cidr_1}"))
    and not(ipv4_is_in_range(IpAddress, "{cidr_2}"))""",
        "params": ["cidr_1", "cidr_2"]
    },

    "btp_tag": {
        "description": "Mark as Benign True Positive instead of suppressing",
        "template": """| extend AlertClassification = case(
    {condition}, "BenignPositive",
    "TruePositive"
)
| extend AlertClassificationReason = case(
    {condition}, "{reason}",
    ""
)""",
        "params": ["condition", "reason"]
    },

    "xdr_contract": {
        "description": "XDR custom detection: entity-level dedup preserving required columns",
        "template": """{base_table}
| summarize (Timestamp, ReportId) = arg_max(Timestamp, ReportId),
    EventCount = count() by {entity_field}, DeviceId, DeviceName
| where EventCount > {threshold}""",
        "params": ["base_table", "entity_field", "threshold"]
    },

    "asim_normalized": {
        "description": "Detection against ASIM normalized schema instead of per-source tables",
        "template": """{asim_parser}(starttime=ago({lookback}), endtime=now())
| where {filter_condition}
| summarize EventCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by {entity_field}
| where EventCount > {threshold}""",
        "params": ["asim_parser", "lookback", "filter_condition", "entity_field", "threshold"]
    },

    "externaldata_ioc": {
        "description": "Match against external IOC feed (scheduled rules only; not NRT)",
        "template": """let IOCs = (externaldata({ioc_column}: string)
    [@"{feed_url}"] with (format="{feed_format}"))
    | where {ioc_column} !startswith "#";
IOCs
| join kind=inner ({base_table}
    | where TimeGenerated > ago({lookback})
) on $left.{ioc_column} == $right.{match_column}""",
        "params": ["ioc_column", "feed_url", "feed_format", "base_table",
                   "lookback", "match_column"]
    },

    "commandline_canon": {
        "description": "Obfuscation-resistant command-line matching (normalize, unordered contains)",
        "template": """{base_table}
| where FileName in~ ({file_names})
| extend Canon = replace_string(replace_string(ProcessCommandLine, '"', ''), ',', ' ')
| where Canon contains "{term_1}" and Canon contains "{term_2}\"""",
        "params": ["base_table", "file_names", "term_1", "term_2"]
    }
}


def list_patterns():
    """Display all available patterns."""
    print("Available KQL FP Patterns:\n")
    for name, info in PATTERNS.items():
        print(f"  {name}")
        print(f"    {info['description']}")
        print(f"    Required params: {', '.join(info['params'])}")
        print()


def generate_pattern(pattern_name: str, params: dict) -> str:
    """Generate KQL snippet from pattern template."""
    if pattern_name not in PATTERNS:
        raise ValueError(f"Unknown pattern: {pattern_name}")

    pattern = PATTERNS[pattern_name]
    template = pattern["template"]

    # Check for missing params
    missing = [p for p in pattern["params"] if p not in params]
    if missing:
        raise ValueError(f"Missing required params: {', '.join(missing)}")

    return template.format(**params)


def main():
    parser = argparse.ArgumentParser(description="Generate KQL FP patterns")
    parser.add_argument("--list", action="store_true", help="List available patterns")
    parser.add_argument("--pattern", "-p", help="Pattern name to generate")
    parser.add_argument("--param", "-P", action="append", nargs=2, metavar=("KEY", "VALUE"),
                        help="Parameter key-value pair (can be repeated)")

    args = parser.parse_args()

    if args.list:
        list_patterns()
        return 0

    if not args.pattern:
        parser.print_help()
        return 1

    params = dict(args.param) if args.param else {}

    try:
        result = generate_pattern(args.pattern, params)
        print(result)
        return 0
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
