import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "bootstrap-azure.sh"

STUB = """#!/usr/bin/env bash
echo "$*" >> "$AZ_LOG"
case "$*" in
  "account show"*) echo tenant-id ;;
  "ad app list"*sdac-reader*) echo "" ;;
  "ad app list"*sdac-deployer*) echo "" ;;
  "ad app create"*sdac-reader*) echo reader-client ;;
  "ad app create"*sdac-deployer*) echo deployer-client ;;
  "ad sp list"*) echo "" ;;
  "ad sp create --id reader-client"*) echo reader-object ;;
  "ad sp create --id deployer-client"*) echo deployer-object ;;
  "ad app federated-credential list"*) echo 0 ;;
esac
"""


def run(tmp_path, *args):
    stub = tmp_path / "az"
    stub.write_text(STUB)
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "az.log"
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "AZ_LOG": str(log)}
    result = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env)
    return result, log.read_text() if log.exists() else ""


def test_bootstrap_uses_least_privilege_and_exact_oidc_subjects(tmp_path):
    result, calls = run(tmp_path, "sub", "rg", "ws", "octo/repo")
    assert result.returncode == 0, result.stderr
    scope = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    assert f"--assignee-object-id reader-object --assignee-principal-type ServicePrincipal --role Microsoft Sentinel Reader --scope {scope}" in calls
    assert f"--assignee-object-id deployer-object --assignee-principal-type ServicePrincipal --role Microsoft Sentinel Contributor --scope {scope}" in calls
    assert "repo:octo/repo:environment:sentinel-read" in calls
    assert "repo:octo/repo:environment:sentinel-production" in calls
    assert "--env sentinel-read --body reader-client" in result.stdout
    assert "--env sentinel-production --body deployer-client" in result.stdout
    assert "--body tenant-id" in result.stdout


def test_bootstrap_rejects_bad_arguments(tmp_path):
    for args in (["sub", "rg", "ws"], ["sub", "rg", "ws", "not-a-repo"]):
        result, calls = run(tmp_path, *args)
        assert result.returncode == 1
        assert "Usage" in result.stderr
        assert calls == ""
