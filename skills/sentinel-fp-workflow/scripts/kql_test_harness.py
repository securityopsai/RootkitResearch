#!/usr/bin/env python3
"""
KQL Detection Unit Test Harness

Builds unit-test queries for Sentinel / Defender XDR detections by shadowing
real tables with inline datatable() literals built from JSON fixtures, and
pinning now()/ago() to a fixed timestamp for determinism. If the query uses
ingestion_time(), every fixture table must declare a datetime __ingestion_time
column and populate it on every row. No ingestion timestamp is invented.
Strings/comments are preserved. This helper does not parse or execute KQL locally.

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
import math
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # works under python -I and when imported from elsewhere
from kql_text import CLOCK_NAME, INGESTION_COLUMN, rewrite_time_calls, time_calls, views

KQL_TYPES = {"string", "long", "int", "real", "bool", "datetime", "dynamic", "guid",
             "timespan", "decimal"}

ISO_DT = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FIXTURE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"Unsupported fixture identifier: {value!r}; use simple KQL identifiers")
    return value


def datetime_literal(value):
    if not isinstance(value, str):
        raise ValueError('Datetime values must be ISO-8601 strings')
    if not (ISO_DT.fullmatch(value) or re.fullmatch(r'\d{4}-\d{2}-\d{2}', value)):
        raise ValueError(f'Unsupported fixture datetime format: {value!r}')
    fraction = re.search(r'\d{2}:\d{2}:\d{2}\.(\d+)', value)
    if fraction and len(fraction.group(1)) > 7:
        raise ValueError('KQL datetime fixtures support at most seven fractional digits')
    parse_value = value
    if fraction:
        a, b = fraction.span(1)
        parse_value = value[:a] + (fraction.group(1) + '000000')[:6] + value[b:]
    try:
        dt = datetime.fromisoformat(parse_value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError(f'Invalid fixture datetime: {value!r}') from exc
    # KQL datetimes are UTC; unzoned fixtures are interpreted as UTC.
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    # Python datetime stores microseconds; preserve Kusto's seventh (100 ns) digit.
    suffix = '.' + fraction.group(1) if fraction else (f'.{dt.microsecond:06d}' if dt.microsecond else '')
    return 'datetime(' + dt.strftime('%Y-%m-%dT%H:%M:%S') + suffix + 'Z)'


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
    # Ordinary KQL strings support these JSON escapes, including newlines/tabs.
    return json.dumps(s, ensure_ascii=False)


def render_value(value, kql_type):
    if value is None:
        return {"string": '""', "long": "long(null)", "int": "int(null)",
                "real": "real(null)", "bool": "bool(null)",
                "datetime": "datetime(null)", "dynamic": "dynamic(null)",
                "guid": "guid(null)", "timespan": "timespan(null)",
                "decimal": "decimal(null)"}[kql_type]
    if kql_type == "datetime":
        return datetime_literal(value)
    if kql_type == "dynamic":
        return f"dynamic({json.dumps(value, allow_nan=False)})"
    if kql_type == "bool":
        if not isinstance(value, bool):
            raise ValueError('bool fixtures require JSON true/false, not strings')
        return "true" if value else "false"
    if kql_type in ("long", "int"):
        bits = 64 if kql_type == 'long' else 32
        if type(value) is not int or not -(2**(bits-1)) <= value < 2**(bits-1):
            raise ValueError(f'{kql_type} fixture needs an in-range JSON integer')
        return str(value)
    if kql_type == 'real':
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError('real fixture needs a finite JSON number')
        return f'real({value})'
    if kql_type == 'decimal':
        try:
            number = Decimal(str(value))
        except InvalidOperation as exc:
            raise ValueError('Invalid decimal fixture') from exc
        if not number.is_finite():
            raise ValueError('Decimal fixture must be finite')
        return f'decimal({number})'
    if kql_type == "guid":
        return f"guid({uuid.UUID(str(value))})"
    if kql_type == 'timespan':
        value = str(value)
        if not re.fullmatch(r'[+-]?(?:\d+(?:\.\d+)?(?:d|h|m|min|s|sec|ms|microsecond|tick)?|(?:\d+\.)?\d+:\d{2}:\d{2}(?:\.\d+)?)', value):
            raise ValueError(f'Unsupported timespan fixture: {value!r}')
        return f'timespan({value})'
    return kql_string_literal(str(value))


def build_schema(table_fixture, table_name):
    identifier(table_name)
    if not isinstance(table_fixture, dict):
        raise ValueError(f'{table_name}: fixture must be an object')
    if not isinstance(table_fixture.get('schema', {}), dict):
        raise ValueError(f'{table_name}: schema must be an object')
    schema = dict(table_fixture.get("schema") or {})
    for col in schema:
        identifier(col)
    for t in schema.values():
        if t not in KQL_TYPES:
            raise ValueError(f"{table_name}: unknown KQL type '{t}' in schema")
    events = table_fixture.get('events', [])
    if not isinstance(events, list) or any(not isinstance(e, dict) for e in events):
        raise ValueError(f'{table_name}: events must be a list of objects')
    inferred = {}
    for event in events:
        for col, val in event.items():
            identifier(col)
            if col in schema:
                continue
            inferred.setdefault(col, set())
            if val is not None:
                inferred[col].add(infer_type(val))
    for col, types in inferred.items():
        if not types:
            raise ValueError(f'{table_name}.{col}: all-null column needs an explicit schema type')
        if types <= {'long', 'real'}:
            schema[col] = 'real' if 'real' in types else 'long'
        elif len(types) == 1:
            schema[col] = next(iter(types))
        else:
            raise ValueError(f'{table_name}.{col}: mixed types need an explicit schema type')
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
    if not isinstance(fixture, dict):
        raise ValueError('Fixture must be a JSON object')
    parts = []
    calls = time_calls(rule_query)
    code = views(rule_query)[0]
    if re.search(r'\b(?:__fixture_now|__ingestion_time)\b', code):
        raise ValueError('Query uses a reserved fixture variable/column name')
    query_now = fixture.get("query_now")
    if calls & {'now', 'ago'}:
        if not query_now:
            raise ValueError("Query uses now()/ago() but fixture sets no 'query_now'.")
        parts.append(f"let {CLOCK_NAME} = {datetime_literal(query_now)};")
    query = rewrite_time_calls(rule_query)

    tables = fixture.get("tables") or {}
    if not isinstance(tables, dict) or not tables:
        raise ValueError("Fixture must define a non-empty tables object.")
    for table_name, table_fixture in tables.items():
        schema = build_schema(table_fixture, table_name)
        if table_name in (CLOCK_NAME, INGESTION_COLUMN) or CLOCK_NAME in schema:
            raise ValueError('Fixture collides with reserved helper names')
        if 'ingestion_time' in calls:
            if schema.get(INGESTION_COLUMN) != 'datetime':
                raise ValueError(f'{table_name}: ingestion_time() needs a datetime {INGESTION_COLUMN} fixture column')
            for event in table_fixture.get('events', []):
                if event.get(INGESTION_COLUMN) is None:
                    raise ValueError(f'{table_name}: every row needs {INGESTION_COLUMN}')
        if not re.search(rf"\b{re.escape(table_name)}\b", code):
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


def validate_assertions(fixture):
    expected = fixture.get("expected_alerts")
    if type(expected) is not int or expected < 0:
        raise ValueError('Execution requires a non-negative integer expected_alerts assertion')
    columns = fixture.get('expected_columns', {})
    if not isinstance(columns, dict) or any(not isinstance(c, str) or not isinstance(v, list) for c, v in columns.items()):
        raise ValueError('expected_columns must map column names to lists of expected values')


def assert_results(rows, fixture, fixture_name):
    failures = []
    validate_assertions(fixture)
    expected = fixture['expected_alerts']
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise ValueError('Query results must be a list of row objects')
    if len(rows) != expected:
        failures.append(f"expected {expected} alert row(s), got {len(rows)}")
    for col, expected_vals in (fixture.get("expected_columns") or {}).items():
        if any(col not in r for r in rows):
            failures.append(f'column {col} missing from result rows')
            continue
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

    all_pass = True
    try:
        rule_query = Path(args.query).read_text(encoding="utf-8")
        prepared = []
        names = set()
        for fx_path in load_fixtures(args):
            fixture = json.loads(fx_path.read_text(encoding="utf-8"))
            if not isinstance(fixture, dict):
                raise ValueError(f'{fx_path}: fixture must be an object')
            name = fixture.get("name", fx_path.stem)
            if not isinstance(name, str) or not FIXTURE_NAME.fullmatch(name) or name in names:
                raise ValueError('Fixture names must be unique simple filenames without path separators')
            names.add(name)
            test_query = build_test_query(rule_query, fixture)
            if args.run:
                validate_assertions(fixture)
            prepared.append((name, fixture, test_query))
        for name, fixture, test_query in prepared:
            if args.run:
                rows = run_query(test_query, args.workspace, args.timeout)
                all_pass &= assert_results(rows, fixture, name)
            elif args.out_dir:
                out = Path(args.out_dir) / f"{name}.test.kql"
                if out.is_symlink():
                    raise ValueError(f'Refusing symlink output: {out}')
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(test_query, encoding="utf-8")
                print(f"wrote {out}")
            else:
                print(f"// ---- {name} ----")
                print(test_query)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
