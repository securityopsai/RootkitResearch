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
        "description": "Exclude exact entities using an unexpired, rule-scoped watchlist (Sentinel)",
        "template": """let Excluded = _GetWatchlist('{watchlist_name}')
| extend _Expiry = todatetime(column_ifexists("ExpiryDate", "")),
         _Scope = tostring(column_ifexists("RuleScope", "")),
         _Type = tostring(column_ifexists("EntityType", "{entity_type}"))
| where isnotnull(_Expiry) and _Expiry > now()          // fail closed: a missing, invalid or past expiry never excludes
| where _Scope in ("{rule_scope}", "*") and _Type =~ "{entity_type}"
| project Entity = tolower(tostring({entity_field}))
| where isnotempty(Entity);
{base_table}
| where tolower(tostring({target_field})) !in (Excluded)""",
        "params": ["watchlist_name", "entity_field", "base_table", "target_field", "rule_scope", "entity_type"],
        "notes": "Schema per documentation-templates.md (Entity, EntityType, RuleScope, ExpiryDate). Columns are read with column_ifexists so a simpler watchlist still parses, but without ExpiryDate nothing is excluded — by design. RuleScope '*' is an explicit global scope."
    },

    "time_window": {
        "description": "Exclude events during maintenance windows",
        "template": """| where not(
    toint(dayofweek(TimeGenerated) / 1d) in ({excluded_days})
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
        "description": "Filter null/empty values only; retains SYSTEM and service accounts",
        "template": """| where isnotempty({field})""",
        "params": ["field"]
    },

    "entra_empty_safe": {
        "description": "Null/empty handling for Entra sign-in fields, where 'empty' is spelled three ways (\"\", \"[]\", \"none\")",
        "template": """| where isnotempty({field}) and {field} !in ("[]", "none")   // Sentinel SigninLogs: RiskEventTypes = "[]", RiskLevelDuringSignIn = "none"; XDR: genuinely empty""",
        "params": ["field"],
        "notes": "Use on RiskLevelDuringSignIn / RiskEventTypes / RiskState and similar; plain isnotempty() misses the string spellings."
    },

    "process_exclude": {
        "description": "Exclude explicit values of a chosen process field using exact matching",
        "template": """let TrustedProcesses = dynamic([
    @"{process_1}",
    @"{process_2}"
]);
{base_table}
| where tostring({process_field}) !in~ (TrustedProcesses)""",
        "params": ["process_1", "process_2", "base_table", "process_field"],
        "notes": "Choose a verified field such as FolderPath or SHA1. Paths/names alone do not establish trust; scope and review the exclusion."
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
    EventCount = count() by {group_by}
| where EventCount > {threshold}""",
        "params": ["base_table", "group_by", "threshold"],
        "notes": "group_by must include DeviceId (and DeviceName for display), e.g. 'DeviceId, DeviceName' or 'InitiatingProcessAccountSid, DeviceId, DeviceName' — listing DeviceId twice is a KQL error"
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

    "first_seen_gap": {
        "description": "First-seen / not-in-baseline with a guard gap (baseline grain == join grain)",
        "template": """let lookback = {lookback};
let gap = {gap};   // guard gap: a brand-new value cannot whitelist itself
let known = {base_table}
    | where {time_col} between (ago(lookback) .. ago(gap))
    | where {filter_condition}
    | distinct {key_cols};
{base_table}
| where {time_col} > ago(gap)
| where {filter_condition}
| join kind=leftanti known on {key_cols}
| summarize ({time_col}, ReportId) = arg_min({time_col}, ReportId), EventCount = count() by {key_cols}""",
        "params": ["lookback", "gap", "base_table", "time_col", "filter_condition", "key_cols"]
    },

    "ingestion_window": {
        "description": "Sentinel scheduled-rule ingestion window; validate delay budget and scheduler behavior",
        "template": """let ingestion_delay = {ingestion_delay};   // measured p90 for this table
let rule_look_back = {rule_look_back};     // == queryFrequency; queryPeriod must cover delay + look_back
{base_table}
| where TimeGenerated >= ago(ingestion_delay + rule_look_back)
| where ingestion_time() > ago(rule_look_back)""",
        "params": ["ingestion_delay", "rule_look_back", "base_table"]
    },

    "baseline_floor": {
        "description": "Per-entity baseline max * factor, floored, baseline window excludes the alert window",
        "template": """let timeframe = {timeframe};              // alert window (2 * frequency on ingestion_time)
let lookback_days = {lookback_days};
let suspicious_factor = {factor};
let min_suspicious_count = {min_count};  // floor: quiet entities must not alert on 1 -> 2
let Baseline = {base_table}
    | where TimeGenerated between (ago(timeframe + lookback_days) .. ago(timeframe))
    | summarize DailyCount = count() by {entity_field}, bin(TimeGenerated, 1d)
    | summarize PreviousMaxPerDay = max(DailyCount) by {entity_field};
{base_table}
| where ingestion_time() >= ago(timeframe)
| summarize CurrentCount = count() by {entity_field}
| join kind=leftouter Baseline on {entity_field}
| extend SuspiciousThreshold = max_of(coalesce(PreviousMaxPerDay, 0) * suspicious_factor, min_suspicious_count)
| where CurrentCount > SuspiciousThreshold""",
        "params": ["timeframe", "lookback_days", "factor", "min_count", "base_table", "entity_field"]
    },

    "flow_fingerprint": {
        "description": "Sign-in flow fingerprint: result-code set per CorrelationId, alert on the first event",
        "template": """let flows = {signin_table}
| where {time_col} > ago({lookback})
| summarize Codes = make_set({code_col}, 100), IPs = make_set({ip_col}, 10) by CorrelationId, {user_col}
| where Codes has_all ({code_list});
{signin_table}
| where {time_col} > ago({lookback})
| where CorrelationId in ((flows | project CorrelationId))
| summarize arg_min({time_col}, *) by CorrelationId   // first event of the flow carries Timestamp/ReportId""",
        "params": ["signin_table", "time_col", "lookback", "code_col", "ip_col", "user_col", "code_list"]
    },

    "named_param": {
        "description": "Read a parameter bag element by name with mv-apply (never positional [n].Value)",
        "template": """| mv-apply p = todynamic({bag_col}) on (
    where tostring(p.{name_key}) == "{wanted_name}"
    | extend {out_col} = tostring(p.{value_key}) )
| where isnotempty({out_col})""",
        "params": ["bag_col", "name_key", "wanted_name", "out_col", "value_key"]
    },

    "scoped_watchlist_exclusion": {
        "description": "One generic exclusion watchlist keyed by rule scope; specific and generic rows via two leftanti joins",
        "template": """let _Expected = _GetWatchlist('{watchlist_name}')
    | extend _Expiry = todatetime(column_ifexists("ExpiryDate", "")), _Scope = tostring(column_ifexists("RuleScope", ""))
    | where isnotnull(_Expiry) and _Expiry > now()          // fail closed on expiry
    | where _Scope in ("{rule_scope}", "*") and tostring(Activity) == "{activity_scope}"
    | project {actor_col} = tostring(ActorId), {resource_col} = tostring(DestinationResource), {op_col} = tostring(Auxiliar);
{base_table}
| join kind=leftanti (_Expected | where isnotempty({resource_col})) on {actor_col}, {op_col}, {resource_col}   // specific rows
| join kind=leftanti (_Expected | where isempty({resource_col}))    on {actor_col}, {op_col}                   // generic (wildcard) rows""",
        "params": ["watchlist_name", "activity_scope", "actor_col", "resource_col", "op_col", "base_table", "rule_scope"],
        "notes": "Requires explicit RuleScope and future ExpiryDate. Empty resource is an intentional wildcard; test its coverage impact."
    },

    "tvm_bridge": {
        "description": "XDR: enrich a device-keyed TVM query with DeviceInfo event identifiers",
        "template": """let Bridge = DeviceInfo
    | summarize arg_max(Timestamp, ReportId) by DeviceId
    | project DeviceId, Timestamp, ReportId;
{tvm_table}
| where {filter_condition}
| summarize {aggregates} by DeviceId, DeviceName
| join kind=inner Bridge on DeviceId
| project-away DeviceId1""",
        "params": ["tvm_table", "filter_condition", "aggregates"]
    },

    "anomaly_two_stage": {
        "description": "make-series + series_decompose_anomalies with an absolute floor, then re-query raw rows for outlier entities",
        "template": """let sensitivity = {sensitivity};   // lower = more sensitive (default 1.5)
let floor = {floor};               // absolute floor kills relative "1 -> 2" anomalies
let outliers = {base_table}
| where {time_col} > startofday(ago({lookback}))
| where {filter_condition}
| make-series Events = count() default=0 on {time_col} from startofday(ago({lookback})) to startofday(now()) step {step} by {entity_field}
| extend Anomalies = series_decompose_anomalies(Events, sensitivity)
| mv-expand {time_col} to typeof(datetime), Events to typeof(long), Anomalies to typeof(int)
| where Anomalies == 1 and Events > floor
| distinct {entity_field};
{base_table}
| where {time_col} > ago({step})
| where {filter_condition}
| where {entity_field} in (outliers)""",
        "params": ["sensitivity", "floor", "base_table", "time_col", "lookback", "filter_condition", "step", "entity_field"]
    },

    "threshold_newly_crossed": {
        "description": "Alert once when a per-entity count crosses the threshold (activity_counts_metrics over 2x frequency)",
        "template": """let query_frequency = {frequency};
let query_period = 2 * query_frequency;
let threshold = {threshold};
{base_table}
| where TimeGenerated > ago(query_period)
| where {filter_condition}
| as _Events
| join kind=leftsemi (
    _Events
    | evaluate activity_counts_metrics({count_col}, TimeGenerated, ago(query_period), now(), query_frequency, {entity_field})
    | summarize arg_min(PrevT = TimeGenerated, PrevCount = ["count"]), arg_max(CurT = TimeGenerated, CurCount = ["count"]) by {entity_field}
    | extend PrevCount = iff(PrevT == CurT, 0, PrevCount)
    | where (not(PrevCount > threshold) and CurCount > threshold) or ((CurCount - PrevCount) > threshold)
  ) on {entity_field}""",
        "params": ["frequency", "threshold", "base_table", "filter_condition", "count_col", "entity_field"]
    },

    "env_filter_fence": {
        "description": "Fenced environment-specific tuning region with pre-written OPTION lines (survives upstream updates)",
        "template": """// Begin environment-specific filter.
// OPTION 1: | where not({entity_col} in ((_GetWatchlist('{watchlist_name}') | where tostring(RuleScope) == "{rule_scope}" and todatetime(ExpiryDate) > now() | project tostring({watchlist_col}))))
// OPTION 2: | where {entity_col} !in~ ({inline_list}) // explicit, reviewed exact-value exclusion
// End environment-specific filter.""",
        "params": ["entity_col", "watchlist_name", "watchlist_col", "inline_list", "rule_scope"]
    },

    "local_time_window": {
        "description": "Working-hours / weekend exclusion in local time (DST-correct), not a fixed UTC offset",
        "template": """let Timezone = "{iana_timezone}";
| extend LocalTime = datetime_utc_to_local({time_col}, Timezone)
| extend DayOfWeek = toint(dayofweek(LocalTime) / 1d), HourOfDay = datetime_part("hour", LocalTime)
| where DayOfWeek in (0, 6) or HourOfDay !between ({start_hour} .. {end_hour})""",
        "params": ["iana_timezone", "time_col", "start_hour", "end_hour"]
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
        if info.get("notes"):
            print(f"    Note: {info['notes']}")
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
