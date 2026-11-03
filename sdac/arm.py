"""Plan and apply rule changes through the Microsoft.SecurityInsights alertRules API."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field

import requests

from sdac.rules import MANAGED_MARKER, Rule, to_arm

DEFAULT_ENDPOINT = "https://management.azure.com"
DEFAULT_API_VERSION = "2025-09-01"
RETRY_STATUSES = {408, 429, 500, 502, 503, 504}


class ArmError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


def get_token(endpoint: str = DEFAULT_ENDPOINT) -> str:
    """Use AZURE_ACCESS_TOKEN if set, otherwise the Azure CLI session from azure/login or az login."""
    token = os.environ.get("AZURE_ACCESS_TOKEN")
    if token:
        return token
    if not shutil.which("az"):
        raise RuntimeError("Azure CLI not found. Run 'az login', or set AZURE_ACCESS_TOKEN.")
    result = subprocess.run(
        ["az", "account", "get-access-token", "--resource", endpoint, "--query", "accessToken", "-o", "tsv"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Could not get an Azure token: {result.stderr.strip()}")
    return result.stdout.strip()


class SentinelClient:
    def __init__(self, subscription_id: str, resource_group: str, workspace: str, token: str,
                 endpoint: str = DEFAULT_ENDPOINT, api_version: str = DEFAULT_API_VERSION,
                 max_retries: int = 4, backoff: float = 2.0):
        self.base = (
            f"{endpoint.rstrip('/')}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
            "/providers/Microsoft.SecurityInsights/alertRules"
        )
        self.api_version = api_version
        self.max_retries = max_retries
        self.backoff = backoff
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        attempt = 0
        while True:
            try:
                response = self.session.request(method, url, timeout=60, **kwargs)
            except requests.RequestException:
                if attempt >= self.max_retries:
                    raise
            else:
                if response.status_code not in RETRY_STATUSES or attempt >= self.max_retries:
                    return response
                retry_after = response.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    time.sleep(min(int(retry_after), 120))
                    attempt += 1
                    continue
            time.sleep(self.backoff * (2 ** attempt))
            attempt += 1

    @staticmethod
    def _raise_for_error(response: requests.Response) -> None:
        if response.status_code < 400:
            return
        try:
            message = response.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = response.text[:1000]
        raise ArmError(response.status_code, message)

    def list_rules(self) -> list[dict]:
        rules = []
        url = self.base
        params = {"api-version": self.api_version}
        while url:
            response = self._request("GET", url, params=params)
            self._raise_for_error(response)
            payload = response.json()
            rules.extend(payload.get("value", []))
            url = payload.get("nextLink")
            params = None  # nextLink already carries the query string.
        return rules

    def put_rule(self, rule_id: str, body: dict) -> dict:
        response = self._request("PUT", f"{self.base}/{rule_id}", params={"api-version": self.api_version}, json=body)
        self._raise_for_error(response)
        return response.json()

    def delete_rule(self, rule_id: str) -> None:
        response = self._request("DELETE", f"{self.base}/{rule_id}", params={"api-version": self.api_version})
        if response.status_code != 404:  # A retried delete may find the rule already gone.
            self._raise_for_error(response)


def _iso_seconds(value: str) -> int | None:
    match = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", value)
    if not match or not any(match.groups()):
        return None
    days, hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _equal(desired, actual) -> bool:
    """True if every value set in the repo matches Azure. Fields added by Azure are ignored."""
    if isinstance(desired, dict):
        if not isinstance(actual, dict):
            return not desired
        return all(_equal(value, actual.get(key)) for key, value in desired.items())
    if isinstance(desired, list):
        actual = actual or []
        if not isinstance(actual, list) or len(desired) != len(actual):
            return False
        if all(isinstance(item, str) for item in desired):
            return sorted(desired) == sorted(actual)
        return all(_equal(d, a) for d, a in zip(desired, actual))
    if isinstance(desired, str) and isinstance(actual, str):
        desired_time, actual_time = _iso_seconds(desired), _iso_seconds(actual)
        if desired_time is not None and actual_time is not None:
            return desired_time == actual_time
    return desired == actual


def _has_values(value) -> bool:
    if isinstance(value, dict):
        return any(_has_values(item) for item in value.values())
    return bool(value)


def changed_fields(desired: dict, remote: dict) -> list[str]:
    wanted = desired["properties"]
    actual = remote.get("properties") or {}
    changed = {key for key, value in wanted.items() if not _equal(value, actual.get(key))}
    # These are optional in the repo, so a value added in the portal counts as drift.
    for key in ("customDetails", "alertDetailsOverride"):
        if key not in wanted and _has_values(actual.get(key)):
            changed.add(key)
    return sorted(changed)


@dataclass
class Plan:
    create: list[Rule] = field(default_factory=list)
    update: list[tuple[Rule, list[str], dict]] = field(default_factory=list)
    unchanged: list[Rule] = field(default_factory=list)
    orphaned: list[dict] = field(default_factory=list)
    unmanaged: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.create or self.update or self.orphaned)


def is_managed(remote: dict) -> bool:
    return MANAGED_MARKER in ((remote.get("properties") or {}).get("description") or "")


def build_plan(rules: list[Rule], remote_rules: list[dict]) -> Plan:
    remote_by_id = {str(item.get("name", "")).lower(): item for item in remote_rules}
    local_ids = {rule.id for rule in rules}
    plan = Plan()
    for rule in rules:
        remote = remote_by_id.get(rule.id)
        if remote is None:
            plan.create.append(rule)
            continue
        fields = changed_fields(to_arm(rule), remote)
        if fields:
            plan.update.append((rule, fields, remote))
        else:
            plan.unchanged.append(rule)
    for rule_id, remote in remote_by_id.items():
        if rule_id in local_ids:
            continue
        if is_managed(remote):
            plan.orphaned.append(remote)
        else:
            plan.unmanaged += 1
    return plan


def render_plan(plan: Plan) -> str:
    lines = ["## Sentinel deployment plan", ""]
    lines.append(
        f"**{len(plan.create)}** to create, **{len(plan.update)}** to update, "
        f"**{len(plan.unchanged)}** unchanged, **{len(plan.orphaned)}** no longer in Git, "
        f"**{plan.unmanaged}** not managed by this repo (ignored)."
    )
    lines.append("")
    for rule in plan.create:
        lines.append(f"- Create: {rule.name} (`{rule.id}`)")
    for rule, fields, _ in plan.update:
        lines.append(f"- Update: {rule.name} (`{rule.id}`). Fields: {', '.join(fields)}")
    for remote in plan.orphaned:
        name = (remote.get("properties") or {}).get("displayName", "unknown")
        lines.append(f"- Not in Git: {name} (`{remote.get('name')}`). Removed only with --prune")
    if not plan.has_changes:
        lines.append("Workspace matches Git. Nothing to do.")
    return "\n".join(lines)


def apply_plan(plan: Plan, client: SentinelClient, prune: bool = False) -> list[str]:
    """Apply a plan. One rule failing does not stop the others. Returns the failures."""
    failures = []

    def attempt(label: str, action) -> None:
        try:
            action()
            print(f"OK    {label}")
        except (ArmError, requests.RequestException) as err:
            print(f"FAIL  {label}: {err}")
            failures.append(f"{label}: {err}")

    for rule in plan.create:
        attempt(f"create {rule.name}", lambda r=rule: client.put_rule(r.id, to_arm(r)))
    for rule, _, remote in plan.update:
        body = to_arm(rule)
        # Send the etag so a concurrent portal edit is rejected and not silently overwritten.
        if remote.get("etag"):
            body["etag"] = remote["etag"]
        attempt(f"update {rule.name}", lambda r=rule, b=body: client.put_rule(r.id, b))
    if prune:
        for remote in plan.orphaned:
            name = (remote.get("properties") or {}).get("displayName", remote.get("name"))
            attempt(f"delete {name}", lambda n=remote["name"]: client.delete_rule(n))
    return failures


def workspace_from_env() -> dict:
    names = {
        "subscription_id": "AZURE_SUBSCRIPTION_ID",
        "resource_group": "SENTINEL_RESOURCE_GROUP",
        "workspace": "SENTINEL_WORKSPACE",
    }
    values = {key: os.environ.get(env, "") for key, env in names.items()}
    missing = [names[key] for key, value in values.items() if not value]
    if missing:
        raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")
    return values


def client_from_env() -> SentinelClient:
    endpoint = os.environ.get("SDAC_ARM_ENDPOINT", DEFAULT_ENDPOINT)
    api_version = os.environ.get("SDAC_API_VERSION", DEFAULT_API_VERSION)
    return SentinelClient(**workspace_from_env(), token=get_token(endpoint), endpoint=endpoint, api_version=api_version)


def dumps(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)
