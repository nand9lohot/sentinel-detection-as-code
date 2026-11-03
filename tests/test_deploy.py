import pytest

from sdac import arm
from sdac.cli import main
from sdac.rules import MANAGED_MARKER, load_rules, to_arm


@pytest.fixture
def workspace(fake_arm, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub")
    monkeypatch.setenv("SENTINEL_RESOURCE_GROUP", "rg")
    monkeypatch.setenv("SENTINEL_WORKSPACE", "ws")
    monkeypatch.setenv("AZURE_ACCESS_TOKEN", "test-token")
    monkeypatch.setenv("SDAC_ARM_ENDPOINT", fake_arm.endpoint)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setattr(arm.time, "sleep", lambda _: None)
    return fake_arm


def writes(state):
    return [call for call in state.calls if call[0] in ("PUT", "DELETE")]


def test_first_deploy_creates_every_rule(workspace, rules, capsys):
    assert main(["deploy"]) == 0
    assert set(workspace.rules) == {rule.id for rule in rules}
    assert f"**{len(rules)}** to create" in capsys.readouterr().out


def test_second_deploy_changes_nothing(workspace):
    assert main(["deploy"]) == 0
    workspace.calls.clear()
    assert main(["deploy"]) == 0
    assert writes(workspace) == []


def test_plan_never_writes(workspace, rules):
    assert main(["plan"]) == 0
    assert writes(workspace) == []
    assert workspace.rules == {}


def test_plan_detailed_exitcode_reports_pending_changes(workspace):
    assert main(["plan", "--detailed-exitcode"]) == 2
    assert main(["deploy"]) == 0
    assert main(["plan", "--detailed-exitcode"]) == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("query", "AzureActivity | take 1"),
        ("enabled", False),
        ("severity", "Low"),
        ("queryFrequency", "PT2H"),
        ("tactics", ["Discovery"]),
    ],
)
def test_portal_edits_show_as_drift_and_are_reverted(workspace, rules, field, value, capsys):
    assert main(["deploy"]) == 0
    rule = rules[0]
    workspace.rules[rule.id]["properties"][field] = value
    capsys.readouterr()

    assert main(["plan", "--detailed-exitcode"]) == 2
    assert field in capsys.readouterr().out

    assert main(["deploy"]) == 0
    expected = to_arm(rule)["properties"][field]
    assert workspace.rules[rule.id]["properties"][field] == expected
    assert main(["plan", "--detailed-exitcode"]) == 0


def test_custom_details_added_in_portal_are_drift(workspace, rules):
    rule = next(r for r in rules if "customDetails" in r.data)
    plan_rule = type(rule)(path=rule.path, data={k: v for k, v in rule.data.items() if k != "customDetails"})
    body = to_arm(plan_rule)
    remote = {"properties": {**body["properties"], "customDetails": {"Extra": "Caller"}}}
    assert arm.changed_fields(body, remote) == ["customDetails"]


def test_equivalent_durations_are_not_drift(rules):
    body = to_arm(rules[0])
    remote = {"properties": {**body["properties"], "queryFrequency": "PT60M", "suppressionDuration": "PT300M"}}
    assert arm.changed_fields(body, remote) == []


def test_tactic_order_is_not_drift(rules):
    rule = next(r for r in rules if len(r.data["tactics"]) > 1)
    body = to_arm(rule)
    remote = {"properties": {**body["properties"], "tactics": list(reversed(body["properties"]["tactics"]))}}
    assert arm.changed_fields(body, remote) == []


def test_update_sends_current_etag_and_keeps_rule_id(workspace, rules):
    assert main(["deploy"]) == 0
    rule = rules[0]
    workspace.rules[rule.id]["properties"]["severity"] = "Low"
    old_etag = workspace.rules[rule.id]["etag"]
    assert main(["deploy"]) == 0
    assert workspace.rules[rule.id]["etag"] != old_etag
    assert len(workspace.rules) == len(rules)


def test_stale_etag_conflict_is_reported(workspace, rules):
    assert main(["deploy"]) == 0
    rule = rules[0]
    workspace.rules[rule.id]["properties"]["severity"] = "Low"
    client = arm.client_from_env()
    plan = arm.build_plan(load_rules(), client.list_rules())
    workspace.rules[rule.id]["etag"] = '"changed-by-someone-else"'
    failures = arm.apply_plan(plan, client)
    assert len(failures) == 1 and "HTTP 409" in failures[0]


def seed(state, rule_id, description, name="Other rule"):
    state.rules[rule_id] = {
        "name": rule_id,
        "kind": "Scheduled",
        "etag": '"x"',
        "properties": {"displayName": name, "description": description},
    }


def test_prune_only_removes_rules_this_repo_manages(workspace, rules, capsys):
    seed(workspace, "11111111-1111-1111-1111-111111111111", f"Old. {MANAGED_MARKER} (version 1.0.0).", "Old managed rule")
    seed(workspace, "22222222-2222-2222-2222-222222222222", "Made by an analyst in the portal.", "Portal rule")
    seed(workspace, "33333333-3333-3333-3333-333333333333", None, "Fusion rule")

    assert main(["deploy"]) == 0
    assert "11111111-1111-1111-1111-111111111111" in workspace.rules, "must not delete without --prune"
    assert "Not in Git: Old managed rule" in capsys.readouterr().out
    assert main(["plan", "--detailed-exitcode"]) == 2

    assert main(["deploy", "--prune"]) == 0
    assert "11111111-1111-1111-1111-111111111111" not in workspace.rules
    assert "22222222-2222-2222-2222-222222222222" in workspace.rules
    assert "33333333-3333-3333-3333-333333333333" in workspace.rules
    assert main(["plan", "--detailed-exitcode"]) == 0


def test_no_local_rules_refuses_to_run(workspace, monkeypatch, capsys):
    seed(workspace, "11111111-1111-1111-1111-111111111111", f"{MANAGED_MARKER} (version 1.0.0).")
    monkeypatch.setattr("sdac.cli.load_rules", lambda: [])
    assert main(["deploy", "--prune"]) == 1
    assert "11111111-1111-1111-1111-111111111111" in workspace.rules
    assert "Refusing" in capsys.readouterr().err


def test_one_rejected_rule_does_not_block_the_others(workspace, rules, capsys):
    bad = rules[0]
    workspace.reject_rules[bad.id] = "Failed to run the analytics rule query. One of the tables does not exist."
    assert main(["deploy"]) == 1
    output = capsys.readouterr().out
    assert "One of the tables does not exist" in output
    assert set(workspace.rules) == {rule.id for rule in rules} - {bad.id}


@pytest.mark.parametrize("status", [429, 500, 503])
def test_transient_errors_are_retried(workspace, rules, status):
    assert main(["deploy"]) == 0
    workspace.rules[rules[0].id]["properties"]["severity"] = "Low"
    workspace.fail_once = [status, status]
    assert main(["deploy"]) == 0
    assert workspace.rules[rules[0].id]["properties"]["severity"] == rules[0].data["severity"]


def test_retries_are_limited(workspace, capsys):
    workspace.fail_once = [503] * 10
    assert main(["plan"]) == 1
    assert "HTTP 503" in capsys.readouterr().err


def test_authentication_failure_is_clear(workspace, monkeypatch, capsys):
    monkeypatch.setenv("AZURE_ACCESS_TOKEN", "wrong")
    assert main(["plan"]) == 1
    assert "HTTP 401" in capsys.readouterr().err


def test_missing_settings_are_named(monkeypatch, capsys):
    monkeypatch.delenv("SENTINEL_WORKSPACE", raising=False)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub")
    monkeypatch.setenv("SENTINEL_RESOURCE_GROUP", "rg")
    assert main(["plan"]) == 1
    assert "SENTINEL_WORKSPACE" in capsys.readouterr().err


def test_plan_is_written_to_the_github_summary(workspace, tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert main(["plan"]) == 0
    assert "Sentinel deployment plan" in summary.read_text(encoding="utf-8")
