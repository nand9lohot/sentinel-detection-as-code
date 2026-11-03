import copy
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest
import yaml

from sdac import catalog, harness, kql
from sdac.cli import _kql_errors
from sdac.rules import (
    MANAGED_MARKER,
    Rule,
    check_against_base,
    find_duplicates,
    iso_duration,
    lint_rule,
    parent_techniques,
    to_arm,
)
from tests.conftest import CONTRACT

needs_node = pytest.mark.skipif(
    not shutil.which("node") or not (kql.CHECK_DIR / "node_modules").exists(),
    reason="KQL analyzer is not installed",
)


def clone(rule: Rule) -> Rule:
    return Rule(path=rule.path, data=copy.deepcopy(rule.data), cases=copy.deepcopy(rule.cases))


def test_repo_rules_pass_lint(rules, tables):
    assert len(rules) >= 5
    for rule in rules:
        assert lint_rule(rule, tables) == [], rule.relpath
    assert find_duplicates(rules) == []


def test_generated_catalog_is_current(rules):
    assert catalog.stale_outputs(rules) == []


@needs_node
def test_repo_rules_and_test_queries_pass_kql_analysis(rules, tables):
    problems = {path: found for path, found in _kql_errors(rules, tables).items() if found}
    assert problems == {}


@pytest.mark.parametrize("value,expected", [("5m", "PT5M"), ("90m", "PT90M"), ("1h", "PT1H"), ("24h", "P1D"), ("14d", "P14D")])
def test_iso_duration(value, expected):
    assert iso_duration(value) == expected


def test_subtechniques_collapse_to_parents_without_duplicates():
    assert parent_techniques(["T1098.001", "T1098.003", "T1078"]) == ["T1098", "T1078"]


def test_every_rule_payload_matches_the_official_api_contract(rules):
    for rule in rules:
        body = to_arm(rule)
        jsonschema.validate(body, CONTRACT)
        assert MANAGED_MARKER in body["properties"]["description"]
        assert body["properties"]["query"] == rule.data["query"].strip()


def mutate(path, value):
    def apply(data):
        target = data
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return apply


@pytest.mark.parametrize(
    "change,expected",
    [
        (mutate(["id"], "not-a-guid"), "id:"),
        (mutate(["severity"], "Critical"), "severity:"),
        (mutate(["queryFrequency"], "1 hour"), "queryFrequency:"),
        (mutate(["queryFrequency"], "2h"), "must not be longer than queryPeriod"),
        (mutate(["queryPeriod"], "15d"), "queryPeriod must be between"),
        (mutate(["queryFrequency"], "1m"), "queryFrequency must be between"),
        (mutate(["tactics"], ["NotATactic"]), "tactics.0:"),
        (mutate(["relevantTechniques"], ["1098"]), "relevantTechniques.0:"),
        (mutate(["query"], "search * | take 1"), "search *"),
        (mutate(["version"], "v1"), "version:"),
        (mutate(["kind"], "NRT"), "kind:"),
        (mutate(["unknownField"], True), "unknownField"),
        (mutate(["suppressionDuration"], "25h"), "24h or less"),
        (mutate(["requiredDataConnectors"], [{"connectorId": "X", "dataTypes": ["NoSuchTable"]}]), "no schema"),
        (mutate(["entityMappings", 0, "fieldMappings", 0, "identifier"], "Nmae"), "not a known identifier"),
    ],
)
def test_lint_rejects_bad_rules(rules, tables, change, expected):
    rule = clone(rules[0])
    change(rule.data)
    found = lint_rule(rule, tables)
    assert any(expected in problem for problem in found), found


def test_lint_catches_table_missing_from_connectors(rules, tables):
    rule = clone(next(r for r in rules if "SigninLogs" in r.data_types))
    rule.data["query"] = "AuditLogs | take 1"
    found = lint_rule(rule, tables)
    assert any("does not list" in problem for problem in found), found


def test_lint_requires_both_fire_and_silent_cases(rules, tables):
    rule = clone(rules[0])
    rule.cases = [case for case in rule.cases if case["expect"] == "fire"]
    assert any("expect: silent" in problem for problem in lint_rule(rule, tables))
    rule.cases = []
    assert any("missing test cases" in problem for problem in lint_rule(rule, tables))


def test_lint_rejects_unknown_fixture_columns(rules, tables):
    rule = clone(rules[0])
    table = rule.data_types[0]
    rule.cases[0]["tables"][table][0]["NotAColumn"] = "x"
    assert any("unknown column" in problem for problem in lint_rule(rule, tables))


def test_lint_rejects_misspelled_case_keys(rules, tables):
    rule = clone(rules[0])
    rule.cases[0]["expect_firstrow"] = {"Caller": "x"}
    assert any("unknown keys: expect_firstrow" in problem for problem in lint_rule(rule, tables))


@needs_node
def test_kql_analysis_rejects_expected_values_for_missing_columns(rules, tables):
    rule = clone(rules[0])
    rule.cases[0]["expect_first_row"] = {"Callr": "x"}
    found = " | ".join(_kql_errors([rule], tables)[rule.relpath])
    assert "expect_first_row uses columns" in found and "Callr" in found


def test_lint_checks_grouping_references(rules, tables):
    rule = clone(rules[0])
    rule.data["incidentConfiguration"] = {
        "createIncident": True,
        "groupingConfiguration": {
            "enabled": True,
            "reopenClosedIncident": False,
            "lookbackDuration": "8d",
            "matchingMethod": "Selected",
            "groupByEntities": ["Host"],
            "groupByCustomDetails": ["Nope"],
        },
    }
    found = " | ".join(lint_rule(rule, tables))
    assert "between 5m and 7d" in found
    assert "'Host'" in found
    assert "'Nope'" in found


@needs_node
@pytest.mark.parametrize(
    "query,expected",
    [
        ("AzureActivity | where Callerr == 'x' | project TimeGenerated", "KS142"),
        ("AzureActivity | where (", "KS"),
        ("NoSuchTable | take 1", "KS204"),
        ("AzureActivity | project Caller", "TimeGenerated"),
    ],
)
def test_kql_analysis_rejects_bad_queries(rules, tables, query, expected):
    rule = clone(next(r for r in rules if "AzureActivity" in r.data_types))
    rule.data["query"] = query
    rule.cases = []
    found = " | ".join(_kql_errors([rule], tables)[rule.relpath])
    assert expected in found, found


@needs_node
def test_kql_analysis_rejects_unmapped_entity_column(rules, tables):
    rule = clone(next(r for r in rules if "AzureActivity" in r.data_types))
    rule.data["query"] = "AzureActivity | project TimeGenerated"
    rule.cases = []
    found = " | ".join(_kql_errors([rule], tables)[rule.relpath])
    assert "does not return mapped columns" in found and "AccountName" in found


@needs_node
def test_watchlist_queries_are_supported(rules, tables):
    rule = clone(next(r for r in rules if "AzureActivity" in r.data_types))
    rule.data["query"] = (
        "let allow = _GetWatchlist('allowed-callers') | project SearchKey;\n"
        + rule.data["query"].replace(
            "AzureActivity\n", "AzureActivity\n| where Caller !in (allow)\n", 1
        )
    )
    rule.cases = [dict(rule.cases[0], watchlists={"allowed-callers": ["svc@contoso.com"]})]
    assert _kql_errors([rule], tables)[rule.relpath] == []
    assert "svc@contoso.com" in harness.build_query(rule, rule.cases[0], tables)


def git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd, check=True, capture_output=True,
    )


@pytest.fixture
def versioned_rule(tmp_path, rules):
    source = rules[0]
    path = tmp_path / "rule.yaml"
    path.write_text(yaml.safe_dump(source.data), encoding="utf-8")
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "init")
    return tmp_path, Rule(path=path, data=copy.deepcopy(source.data))


def test_base_check_accepts_unchanged_and_bumped_rules(versioned_rule):
    root, rule = versioned_rule
    assert check_against_base([rule], "HEAD", root=root) == []
    rule.data["severity"] = "Low"
    rule.data["version"] = "1.0.1"
    assert check_against_base([rule], "HEAD", root=root) == []


def test_base_check_requires_version_bump(versioned_rule):
    root, rule = versioned_rule
    rule.data["severity"] = "Low"
    found = check_against_base([rule], "HEAD", root=root)
    assert len(found) == 1 and "bump version" in found[0]
    rule.data["version"] = "0.9.0"
    assert "bump version" in check_against_base([rule], "HEAD", root=root)[0]


def test_base_check_rejects_changed_id(versioned_rule):
    root, rule = versioned_rule
    rule.data["id"] = "00000000-0000-0000-0000-000000000000"
    assert "duplicate rule" in check_against_base([rule], "HEAD", root=root)[0]


def test_base_check_ignores_new_files(versioned_rule, tmp_path):
    root, rule = versioned_rule
    new_path = root / "new.yaml"
    new = Rule(path=new_path, data=rule.data)
    assert check_against_base([new], "HEAD", root=root) == []


def test_duplicate_ids_and_names_are_reported(rules):
    twin = clone(rules[0])
    twin.path = rules[1].path
    found = " | ".join(find_duplicates([rules[0], twin]))
    assert "duplicate id" in found and "duplicate name" in found
