import re
from datetime import datetime, timezone

import pytest

from sdac import harness
from sdac.cli import main
from sdac.rules import required_columns

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def rule_with(rules, table):
    return next(rule for rule in rules if table in rule.data_types)


def test_query_keeps_rule_text_and_defines_each_table(rules, tables):
    rule = rule_with(rules, "AzureActivity")
    query = harness.build_query(rule, rule.cases[0], tables, now=NOW)
    assert query.startswith("let AzureActivity = datatable(")
    assert query.endswith(rule.data["query"].strip())


def test_repeat_expands_rows_and_substitutes_index(rules, tables):
    rule = rule_with(rules, "SigninLogs")
    case = {"tables": {"SigninLogs": [{"repeat": 3, "minutes_ago": 2, "UserPrincipalName": "user{i}@contoso.com"}]}}
    query = harness.build_query(rule, case, tables, now=NOW)
    assert all(f'"user{i}@contoso.com"' in query for i in range(3))
    assert "user3@" not in query
    assert query.count("datetime(2026-11-03T11:58:00Z)") == 3


def test_literals_are_escaped():
    assert harness._literal('a"b\\c', "string") == r'"a\"b\\c"'
    assert harness._literal(None, "string") == '""'
    assert harness._literal(None, "long") == "long(null)"
    assert harness._literal(None, "dynamic") == "dynamic(null)"
    assert harness._literal({"a": [1]}, "dynamic") == 'dynamic({"a": [1]})'
    assert harness._literal(True, "bool") == "true"


@pytest.mark.parametrize(
    "operator,threshold,rows,expect,ok",
    [
        ("gt", 0, 1, "fire", True),
        ("gt", 0, 0, "fire", False),
        ("gt", 0, 0, "silent", True),
        ("gt", 0, 1, "silent", False),
        ("gt", 2, 2, "silent", True),
        ("lt", 2, 1, "fire", True),
        ("eq", 2, 2, "fire", True),
        ("ne", 2, 2, "silent", True),
    ],
)
def test_case_outcome_uses_the_rule_trigger(rules, operator, threshold, rows, expect, ok):
    rule = rules[0]
    data = dict(rule.data, triggerOperator=operator, triggerThreshold=threshold, entityMappings=[], customDetails={}, alertDetailsOverride={})
    subject = harness.Rule(path=rule.path, data=data)
    failures = harness.evaluate_case(subject, {"expect": expect}, ["TimeGenerated"], [["x"]] * rows)
    assert (not failures) is ok, failures


def test_missing_mapped_column_fails_a_case_even_when_it_fires(rules):
    failures = harness.evaluate_case(rules[0], {"expect": "fire"}, ["TimeGenerated"], [["x"]])
    assert any("missing mapped columns" in failure for failure in failures)


def test_expected_values_and_row_counts_are_checked(rules):
    rule = rules[0]
    columns = sorted(required_columns(rule.data))
    row = ["value"] * len(columns)
    case = {"expect": "fire", "expect_rows": 2, "expect_first_row": {columns[0]: "other"}}
    failures = harness.evaluate_case(rule, case, columns, [row])
    assert any("expected 2 rows" in failure for failure in failures)
    assert any("expected 'other'" in failure for failure in failures)


def test_cli_compares_each_case_with_the_query_result(fake_kusto, rules, capsys):
    rule = rules[0]
    fake_kusto.columns = sorted(required_columns(rule.data))
    fake_kusto.rows = []  # No rows: silent cases should pass and fire cases should fail.
    assert main(["test", "--kusto-uri", fake_kusto.uri, "--only", rule.path.name]) == 1
    output = capsys.readouterr().out
    silent = sum(case["expect"] == "silent" for case in rule.cases)
    assert output.count("PASS") == silent
    assert output.count("FAIL") == len(rule.cases) - silent
    assert len(fake_kusto.queries) == len(rule.cases)
    assert all(rule.data["query"].strip() in query for query in fake_kusto.queries)


def test_cli_exits_zero_when_every_case_passes(fake_kusto, rules, monkeypatch, capsys):
    rule = rules[0]
    silent_only = harness.Rule(path=rule.path, data=rule.data, cases=[c for c in rule.cases if c["expect"] == "silent"])
    monkeypatch.setattr("sdac.cli.load_rules", lambda: [silent_only])
    fake_kusto.columns = sorted(required_columns(rule.data))
    assert main(["test", "--kusto-uri", fake_kusto.uri]) == 0
    assert "test cases passed" in capsys.readouterr().out


def test_cli_reports_kusto_errors_as_failures(fake_kusto, rules, capsys):
    fake_kusto.status = 400
    assert main(["test", "--kusto-uri", fake_kusto.uri, "--only", rules[0].path.name]) == 1
    assert "HTTP 400" in capsys.readouterr().out


def test_cli_fails_when_no_tests_match(fake_kusto, capsys):
    assert main(["test", "--kusto-uri", fake_kusto.uri, "--only", "no-such-rule"]) == 1
    assert "No test cases matched" in capsys.readouterr().out


def test_wait_retries_until_kusto_is_ready(fake_kusto):
    fake_kusto.unavailable_for = 2
    client = harness.KustoClient(fake_kusto.uri)
    client.wait_until_ready(10)
    assert len(fake_kusto.queries) == 3


def test_wait_gives_up_with_a_clear_error(fake_kusto):
    fake_kusto.unavailable_for = 10_000
    client = harness.KustoClient(fake_kusto.uri)
    with pytest.raises(RuntimeError, match=re.escape("not ready after 1s")):
        client.wait_until_ready(1)
