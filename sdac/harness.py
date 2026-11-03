"""Run each rule's KQL against synthetic rows and compare the outcome with its test cases.

The rule's real query runs unchanged. Tables are supplied by prepending `let` statements,
so the Kusto emulator needs no ingestion and each case is isolated.
"""

from __future__ import annotations

import json
import operator
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import requests

from sdac.rules import Rule, required_columns

COMPARE = {"gt": operator.gt, "lt": operator.lt, "eq": operator.eq, "ne": operator.ne}
META_KEYS = {"minutes_ago", "repeat"}


def _literal(value, kql_type: str) -> str:
    if kql_type == "dynamic":
        return f"dynamic({json.dumps(value, ensure_ascii=False)})"
    if value is None:
        return '""' if kql_type == "string" else f"{kql_type}(null)"
    if kql_type == "string":
        return json.dumps(str(value), ensure_ascii=False)
    if kql_type == "bool":
        return "true" if value else "false"
    if kql_type in ("datetime", "timespan", "guid"):
        return f"{kql_type}({value})"
    return f"{kql_type}({value})"


def _substitute(value, index: int):
    if isinstance(value, str):
        return value.replace("{i}", str(index))
    if isinstance(value, dict):
        return {k: _substitute(v, index) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, index) for v in value]
    return value


def _expand(rows: list[dict]) -> list[dict]:
    """Apply `repeat: N`, replacing {i} in string values with the row's index."""
    expanded = []
    for row in rows or []:
        for index in range(int(row.get("repeat", 1))):
            expanded.append({k: _substitute(v, index) for k, v in row.items() if k != "repeat"})
    return expanded


def _datatable(columns: dict, rows: list[dict], now: datetime) -> str:
    schema = ", ".join(f"['{name}']:{kql_type}" for name, kql_type in columns.items())
    cells = []
    for row in _expand(rows):
        values = dict(row)
        if "TimeGenerated" not in values:
            minutes = float(values.get("minutes_ago", 1))
            values["TimeGenerated"] = (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cells.append(", ".join(_literal(values.get(name), kql_type) for name, kql_type in columns.items()))
    return f"datatable({schema})[\n" + ",\n".join(cells) + "\n]"


def build_query(rule: Rule, case: dict, tables: dict, now: datetime | None = None) -> str:
    """Return the rule's query with synthetic tables supplied through let statements."""
    now = now or datetime.now(timezone.utc)
    statements = []
    for table in rule.data_types:
        rows = (case.get("tables") or {}).get(table, [])
        statements.append(f"let {table} = {_datatable(tables[table], rows, now)};")
    query = rule.data["query"].strip()
    if "_GetWatchlist" in query:
        rows = [
            f"{json.dumps(alias)}, {json.dumps(str(key))}"
            for alias, keys in (case.get("watchlists") or {}).items()
            for key in keys
        ]
        statements.append(
            "let _GetWatchlist = (WatchlistAlias:string) { "
            "datatable(Alias:string, SearchKey:string)[" + ", ".join(rows) + "] "
            "| where Alias == WatchlistAlias | project SearchKey };"
        )
    return "\n".join(statements) + "\n" + query


class KustoClient:
    def __init__(self, uri: str, database: str = "NetDefaultDB", timeout: int = 60):
        self.uri = uri.rstrip("/")
        self.database = database
        self.timeout = timeout

    def query(self, csl: str) -> tuple[list[str], list[list]]:
        response = requests.post(
            f"{self.uri}/v1/rest/query",
            json={"db": self.database, "csl": csl},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Kusto returned HTTP {response.status_code}: {response.text[:1000]}")
        table = response.json()["Tables"][0]
        return [c["ColumnName"] for c in table["Columns"]], table["Rows"]

    def wait_until_ready(self, seconds: int) -> None:
        deadline = time.monotonic() + seconds
        last_error: Exception | None = None
        while True:
            try:
                self.query("print ready=1")
                return
            except (requests.RequestException, RuntimeError, KeyError, ValueError) as err:
                last_error = err
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Kusto was not ready after {seconds}s: {last_error}")
            time.sleep(min(5, max(0.05, seconds / 20)))


@dataclass
class CaseResult:
    rule: str
    case: str
    passed: bool
    detail: str


def evaluate_case(rule: Rule, case: dict, columns: list[str], rows: list[list]) -> list[str]:
    """Compare a query result with what the case expects. Returns the failures."""
    data = rule.data
    fired = COMPARE[data["triggerOperator"]](len(rows), data["triggerThreshold"])
    failures = []
    expected_fire = case["expect"] == "fire"
    if fired != expected_fire:
        outcome = "fired" if fired else "stayed silent"
        failures.append(f"expected {case['expect']}, but the rule {outcome} ({len(rows)} rows)")

    missing = required_columns(data) - set(columns)
    if missing:
        failures.append(f"query result is missing mapped columns: {', '.join(sorted(missing))}")

    if "expect_rows" in case and len(rows) != case["expect_rows"]:
        failures.append(f"expected {case['expect_rows']} rows, got {len(rows)}")

    expected_values = case.get("expect_first_row") or {}
    if expected_values:
        if not rows:
            failures.append("expect_first_row is set, but the query returned no rows")
        else:
            first = dict(zip(columns, rows[0]))
            for column, expected in expected_values.items():
                if first.get(column) != expected:
                    failures.append(f"{column}: expected {expected!r}, got {first.get(column)!r}")
    return failures


def run_tests(rules: list[Rule], tables: dict, client: KustoClient, only: str | None = None) -> list[CaseResult]:
    results = []
    for rule in rules:
        if only and only not in rule.relpath:
            continue
        for case in rule.cases:
            label = case.get("name", "unnamed")
            try:
                columns, rows = client.query(build_query(rule, case, tables))
                failures = evaluate_case(rule, case, columns, rows)
            except (RuntimeError, requests.RequestException) as err:
                failures = [str(err)]
            results.append(CaseResult(rule.name, label, not failures, "; ".join(failures)))
    return results
