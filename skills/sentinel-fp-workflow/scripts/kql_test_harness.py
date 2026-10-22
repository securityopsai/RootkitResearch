#!/usr/bin/env python3
"""
KQL Detection Unit Test Harness

Builds unit-test queries for Sentinel / Defender XDR detections by shadowing
real tables with inline datatable() literals built from JSON fixtures, and
pinning now() to a fixed timestamp for determinism.

Fixture format (JSON):
{
  "name": "tp_service_stop",
  "query_now": "2026-07-21T12:00:00Z",          // optional; pins now()
  "tables": {
    "DeviceProcessEvents": {
      "schema": {"Timestamp": "datetime", "ReportId": "long",
                 "DeviceId": "string", "FileName": "string",
                 "ProcessCommandLine": "string"},   // optional if events non-empty
      "events": [
        {"Timestamp": "2026-07-21T11:55:00Z", "ReportId": 1,
         "DeviceId": "dev1", "FileName": "net.exe",
         "ProcessCommandLine": "net stop MpsSvc"}
      ]
    }
  },
  "expected_alerts": 1,
  "expected_columns": {"DeviceId": ["dev1"]}     // optional per-column value asserts
}

Usage:
  # Emit the self-contained test query to stdout:
  python kql_test_harness.py --query rule.kql --fixture tests/fixtures/rule/tp.json

  # Emit test queries for every fixture in a directory:
  python kql_test_harness.py --query rule.kql --fixture-dir tests/fixtures/rule/ --out-dir build/tests/

  # Run via Azure CLI against an empty workspace and assert:
  python kql_test_harness.py --query rule.kql --fixture-dir tests/fixtures/rule/ \
      --run --workspace <workspace-guid>

Exit codes: 0 all pass, 1 assertion failure, 2 usage/input error.
Requires only the standard library; --run shells out to `az monitor log-analytics query`.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

KQL_TYPES = {"string", "long", "int", "real", "bool", "datetime", "dynamic", "guid",
             "timespan", "decimal"}

ISO_DT = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")

NOW_CALL = re.compile(r"\bnow\(\s*\)")
NOW_WITH_ARG = re.compile(r"\bnow\(\s*[^)\s]")


def infer_type(value):
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "long"
    if isinstance(value, float):
        return "real"
    if isinstance(value, (dict, list)):
        return "dynamic"
    if isinstance(value, str) and ISO_DT.match(value):
        return "datetime"
    return "string"


def kql_string_literal(s: str) -> str:
    # Verbatim literal avoids most escaping pitfalls; only quotes need doubling-out.
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_value(value, kql_type):
    if value is None:
        return {"string": '""', "long": "long(null)", "int": "int(null)",
                "real": "real(null)", "bool": "bool(null)",
                "datetime": "datetime(null)", "dynamic": "dynamic(null)",
                "guid": "guid(null)", "timespan": "timespan(null)",
                "decimal": "decimal(null)"}[kql_type]
    if kql_type == "datetime":
        return f"datetime({value})"
    if kql_type == "dynamic":
        return f"dynamic({json.dumps(value)})"
    if kql_type == "bool":
        return "true" if value else "false"
    if kql_type in ("long", "int", "real", "decimal"):
        return str(value)
    if kql_type == "guid":
        return f"guid({value})"
    return kql_string_literal(str(value))


def build_schema(table_fixture, table_name):
    schema = dict(table_fixture.get("schema") or {})
    for t in schema.values():
        if t not in KQL_TYPES:
            raise ValueError(f"{table_name}: unknown KQL type '{t}' in schema")
    for event in table_fixture.get("events", []):
        for col, val in event.items():
            if col not in schema:
                schema[col] = infer_type(val)
    if not schema:
        raise ValueError(
            f"{table_name}: empty fixture needs an explicit 'schema' "
            "(empty-input tests must still declare columns)")
    return schema


def build_datatable_let(table_name, table_fixture) -> str:
    schema = build_schema(table_fixture, table_name)
    cols = ", ".join(f"{c}:{t}" for c, t in schema.items())
    rows = []
    for event in table_fixture.get("events", []):
        cells = [render_value(event.get(c), t) for c, t in schema.items()]
        rows.append("    " + ", ".join(cells))
    body = ",\n".join(rows)
    return f"let {table_name} = datatable ({cols}) [\n{body}\n];"


def build_test_query(rule_query: str, fixture: dict) -> str:
    parts = []
    query = rule_query

    if NOW_WITH_ARG.search(query):
        raise ValueError(
            "Query uses now(<offset>); rewrite as (now() - <offset>) or bin on a "
            "pinned variable so the harness can substitute deterministically.")

    query_now = fixture.get("query_now")
    if NOW_CALL.search(query):
        if not query_now:
            raise ValueError("Query uses now() but fixture sets no 'query_now'.")
        parts.append(f"let __query_now = datetime({query_now});")
        query = NOW_CALL.sub("__query_now", query)

    tables = fixture.get("tables") or {}
    if not tables:
        raise ValueError("Fixture defines no tables.")
    for table_name, table_fixture in tables.items():
        if not re.search(rf"\b{re.escape(table_name)}\b", query):
            print(f"WARN: fixture table '{table_name}' not referenced by query",
                  file=sys.stderr)
        parts.append(build_datatable_let(table_name, table_fixture))

    parts.append(query.strip())
    return "\n".join(parts) + "\n"


def run_query(test_query: str, workspace: str, timeout: int):
    cmd = ["az", "monitor", "log-analytics", "query",
           "--workspace", workspace, "--analytics-query", test_query, "-o", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"az query failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout or "[]")


def assert_results(rows, fixture, fixture_name):
    failures = []
    expected = fixture.get("expected_alerts")
    if expected is not None and len(rows) != expected:
        failures.append(f"expected {expected} alert row(s), got {len(rows)}")
    for col, expected_vals in (fixture.get("expected_columns") or {}).items():
        actual = sorted(str(r.get(col)) for r in rows)
        if actual != sorted(str(v) for v in expected_vals):
            failures.append(f"column {col}: expected {sorted(map(str, expected_vals))}, got {actual}")
    if failures:
        print(f"FAIL {fixture_name}: " + "; ".join(failures))
        return False
    print(f"PASS {fixture_name} ({len(rows)} alert row(s))")
    return True


def load_fixtures(args):
    if args.fixture:
        return [Path(args.fixture)]
    fixtures = sorted(Path(args.fixture_dir).glob("*.json"))
    if not fixtures:
        raise ValueError(f"No *.json fixtures in {args.fixture_dir}")
    return fixtures


def main():
    p = argparse.ArgumentParser(description="KQL detection unit test harness")
    p.add_argument("--query", required=True, help="Path to .kql file (raw rule query)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--fixture", help="Single fixture JSON")
    src.add_argument("--fixture-dir", help="Directory of fixture JSONs")
    p.add_argument("--out-dir", help="Write emitted test queries here instead of stdout")
    p.add_argument("--run", action="store_true",
                   help="Execute via `az monitor log-analytics query` and assert")
    p.add_argument("--workspace", help="Log Analytics workspace GUID (with --run)")
    p.add_argument("--timeout", type=int, default=120, help="Per-query timeout seconds")
    args = p.parse_args()

    if args.run and not args.workspace:
        p.error("--run requires --workspace")

    rule_query = Path(args.query).read_text(encoding="utf-8")

    all_pass = True
    try:
        for fx_path in load_fixtures(args):
            fixture = json.loads(fx_path.read_text(encoding="utf-8"))
            name = fixture.get("name", fx_path.stem)
            test_query = build_test_query(rule_query, fixture)

            if args.run:
                rows = run_query(test_query, args.workspace, args.timeout)
                all_pass &= assert_results(rows, fixture, name)
            elif args.out_dir:
                out = Path(args.out_dir) / f"{name}.test.kql"
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(test_query, encoding="utf-8")
                print(f"wrote {out}")
            else:
                print(f"// ---- {name} ----")
                print(test_query)
    except (ValueError, RuntimeError, json.JSONDecodeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
