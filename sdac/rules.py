"""Load and lint rule files, and convert them to Sentinel API payloads."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = ROOT / "detections"
RULE_SCHEMA_PATH = ROOT / "schemas" / "rule.schema.json"
TABLES_PATH = ROOT / "schemas" / "tables.yaml"

# Written into each deployed description. It marks the rule as managed by this repo, so
# pruning can never touch rules created in the portal or by content hub solutions.
MANAGED_MARKER = "Managed by detection-as-code"

OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
MIN_INTERVAL = 5 * 60
MAX_INTERVAL = 14 * 24 * 3600
MAX_SUPPRESSION = 24 * 3600
MIN_GROUPING = 5 * 60
MAX_GROUPING = 7 * 24 * 3600
CASE_KEYS = {"name", "expect", "expect_rows", "expect_first_row", "tables", "watchlists"}

# Entity identifiers from the Microsoft Sentinel entity reference. Other entity types are
# checked by the API at deploy time.
KNOWN_IDENTIFIERS = {
    "Account": {"Name", "FullName", "UPNSuffix", "NTDomain", "DnsDomain", "AadTenantId", "AadUserId", "Sid", "PUID", "ObjectGuid"},
    "Host": {"HostName", "FullName", "NTDomain", "DnsDomain", "NetBiosName", "AzureID", "OMSAgentID", "OSFamily", "OSVersion", "IoTDevice"},
    "IP": {"Address", "AddressScope"},
    "AzureResource": {"ResourceId"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "URL": {"Url"},
}


@dataclass
class Rule:
    path: Path
    data: dict
    cases: list = field(default_factory=list)

    @property
    def id(self) -> str:
        return str(self.data.get("id", "")).lower()

    @property
    def name(self) -> str:
        return self.data.get("name", self.path.stem)

    @property
    def relpath(self) -> str:
        try:
            return self.path.relative_to(ROOT).as_posix()
        except ValueError:
            return str(self.path)

    @property
    def data_types(self) -> list[str]:
        found = []
        for connector in self.data.get("requiredDataConnectors", []):
            for table in connector.get("dataTypes", []):
                if table not in found:
                    found.append(table)
        return found


def load_tables(path: Path = TABLES_PATH) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_path_for(rule_path: Path) -> Path:
    return rule_path.with_name(rule_path.stem + ".tests.yaml")


def load_rules(root: Path = DETECTIONS_DIR) -> list[Rule]:
    rules = []
    for path in sorted(root.rglob("*.yaml")):
        if path.name.endswith(".tests.yaml"):
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rule = Rule(path=path, data=data)
        tests = test_path_for(path)
        if tests.exists():
            rule.cases = (yaml.safe_load(tests.read_text(encoding="utf-8")) or {}).get("cases") or []
        rules.append(rule)
    return rules


def duration_seconds(value: str) -> int:
    """Convert a rule duration such as 5m, 1h or 14d to seconds."""
    match = re.fullmatch(r"([1-9][0-9]*)([mhd])", value)
    if not match:
        raise ValueError(f"Invalid duration: {value!r}")
    return int(match.group(1)) * {"m": 60, "h": 3600, "d": 86400}[match.group(2)]


def iso_duration(value: str) -> str:
    """Convert a rule duration to the ISO 8601 form the API expects."""
    seconds = duration_seconds(value)
    if seconds % 86400 == 0:
        return f"P{seconds // 86400}D"
    if seconds % 3600 == 0:
        return f"PT{seconds // 3600}H"
    return f"PT{seconds // 60}M"


def lint_rule(rule: Rule, tables: dict, schema: dict | None = None) -> list[str]:
    """Return every static problem with a rule. An empty list means the rule is valid."""
    schema = schema or json.loads(RULE_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errors = [
        f"{'.'.join(str(p) for p in err.absolute_path) or 'rule'}: {err.message}"
        for err in sorted(validator.iter_errors(rule.data), key=lambda e: list(map(str, e.absolute_path)))
    ]
    if errors:
        return errors

    data = rule.data
    frequency = duration_seconds(data["queryFrequency"])
    period = duration_seconds(data["queryPeriod"])
    if not MIN_INTERVAL <= frequency <= MAX_INTERVAL:
        errors.append("queryFrequency must be between 5m and 14d")
    if not MIN_INTERVAL <= period <= MAX_INTERVAL:
        errors.append("queryPeriod must be between 5m and 14d")
    if frequency > period:
        errors.append("queryFrequency must not be longer than queryPeriod, or coverage has gaps")

    if "suppressionDuration" in data and duration_seconds(data["suppressionDuration"]) > MAX_SUPPRESSION:
        errors.append("suppressionDuration must be 24h or less")
    if data.get("suppressionEnabled") and "suppressionDuration" not in data:
        errors.append("suppressionEnabled requires suppressionDuration")

    if re.search(r"\b(search|union)\s+\*", data["query"]):
        errors.append("query must not use 'search *' or 'union *'")

    for table in rule.data_types:
        if table not in tables:
            errors.append(f"data type '{table}' has no schema in schemas/tables.yaml")
    for table in tables:
        if re.search(rf"\b{re.escape(table)}\b", data["query"]) and table not in rule.data_types:
            errors.append(f"query uses table '{table}', which requiredDataConnectors does not list")

    for mapping in data["entityMappings"]:
        known = KNOWN_IDENTIFIERS.get(mapping["entityType"])
        for field_mapping in mapping["fieldMappings"]:
            if known and field_mapping["identifier"] not in known:
                errors.append(f"'{field_mapping['identifier']}' is not a known identifier for {mapping['entityType']} entities")

    grouping = (data.get("incidentConfiguration") or {}).get("groupingConfiguration")
    if grouping:
        lookback = duration_seconds(grouping["lookbackDuration"])
        if not MIN_GROUPING <= lookback <= MAX_GROUPING:
            errors.append("grouping lookbackDuration must be between 5m and 7d")
        mapped = {m["entityType"] for m in data["entityMappings"]}
        for entity in grouping.get("groupByEntities", []):
            if entity not in mapped:
                errors.append(f"groupByEntities uses '{entity}', which entityMappings does not map")
        for key in grouping.get("groupByCustomDetails", []):
            if key not in data.get("customDetails", {}):
                errors.append(f"groupByCustomDetails uses '{key}', which customDetails does not define")
        if grouping["matchingMethod"] == "Selected" and not any(
            grouping.get(k) for k in ("groupByEntities", "groupByAlertDetails", "groupByCustomDetails")
        ):
            errors.append("matchingMethod Selected needs at least one groupBy list")

    errors.extend(lint_cases(rule, tables))
    return errors


def lint_cases(rule: Rule, tables: dict) -> list[str]:
    if not rule.cases:
        return [f"missing test cases: add {test_path_for(rule.path).name}"]

    errors = []
    expectations = {case.get("expect") for case in rule.cases}
    if "fire" not in expectations:
        errors.append("tests need at least one case with expect: fire")
    if "silent" not in expectations:
        errors.append("tests need at least one case with expect: silent")

    for index, case in enumerate(rule.cases):
        label = case.get("name") or f"case {index}"
        unknown = set(case) - CASE_KEYS
        if unknown:
            errors.append(f"test '{label}': unknown keys: {', '.join(sorted(unknown))}")
        if case.get("expect") not in ("fire", "silent"):
            errors.append(f"test '{label}': expect must be fire or silent")
        for table, rows in (case.get("tables") or {}).items():
            if table not in rule.data_types:
                errors.append(f"test '{label}': table '{table}' is not in requiredDataConnectors")
                continue
            columns = tables.get(table, {})
            for row in rows or []:
                for column in row:
                    if column not in columns and column not in ("minutes_ago", "repeat"):
                        errors.append(f"test '{label}': unknown column {table}.{column}")
    return errors


def required_columns(data: dict) -> set[str]:
    """Columns the query has to return for the rule's mappings to work."""
    columns = {"TimeGenerated"}
    for mapping in data.get("entityMappings", []):
        columns.update(fm["columnName"] for fm in mapping["fieldMappings"])
    columns.update((data.get("customDetails") or {}).values())
    override = data.get("alertDetailsOverride") or {}
    for key in ("alertDisplayNameFormat", "alertDescriptionFormat"):
        columns.update(re.findall(r"\{\{(\w+)\}\}", override.get(key, "")))
    for key in ("alertTacticsColumnName", "alertSeverityColumnName"):
        if override.get(key):
            columns.add(override[key])
    columns.update(p["value"] for p in override.get("alertDynamicProperties", []))
    return columns


def parent_techniques(techniques: list[str]) -> list[str]:
    """Map T1098.003 to T1098. The stable API's techniques field holds parent IDs only."""
    parents = []
    for technique in techniques:
        parent = technique.split(".")[0]
        if parent not in parents:
            parents.append(parent)
    return parents


def to_arm(rule: Rule) -> dict:
    """Build the alertRules PUT body for a rule."""
    data = rule.data
    description = f"{data['description'].strip()}\n\n{MANAGED_MARKER} (version {data['version']}). Change this rule in Git."
    incident = data.get("incidentConfiguration") or {"createIncident": True}
    incident = json.loads(json.dumps(incident))
    grouping = incident.setdefault(
        "groupingConfiguration",
        {"enabled": False, "reopenClosedIncident": False, "lookbackDuration": "5h", "matchingMethod": "AllEntities"},
    )
    grouping["lookbackDuration"] = iso_duration(grouping["lookbackDuration"])

    properties = {
        "displayName": data["name"],
        "description": description,
        "enabled": data.get("enabled", True),
        "severity": data["severity"],
        "query": data["query"].strip(),
        "queryFrequency": iso_duration(data["queryFrequency"]),
        "queryPeriod": iso_duration(data["queryPeriod"]),
        "triggerOperator": OPERATORS[data["triggerOperator"]],
        "triggerThreshold": data["triggerThreshold"],
        "suppressionEnabled": data.get("suppressionEnabled", False),
        "suppressionDuration": iso_duration(data.get("suppressionDuration", "5h")),
        "tactics": data["tactics"],
        "techniques": parent_techniques(data["relevantTechniques"]),
        "entityMappings": data["entityMappings"],
        "eventGroupingSettings": data.get("eventGroupingSettings", {"aggregationKind": "SingleAlert"}),
        "incidentConfiguration": incident,
    }
    for optional in ("customDetails", "alertDetailsOverride"):
        if optional in data:
            properties[optional] = data[optional]
    return {"kind": "Scheduled", "properties": properties}


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def check_against_base(rules: list[Rule], base_ref: str, root: Path = ROOT) -> list[str]:
    """Compare rules with a base Git ref. Rule IDs must stay fixed and changes need a version bump."""
    errors = []
    for rule in rules:
        relative = rule.path.relative_to(root).as_posix()
        shown = subprocess.run(
            ["git", "show", f"{base_ref}:{relative}"], cwd=root, capture_output=True, text=True, encoding="utf-8"
        )
        if shown.returncode != 0:
            continue  # A new file has nothing to compare with.
        old = yaml.safe_load(shown.stdout) or {}
        new = rule.data
        if str(old.get("id", "")).lower() != rule.id:
            errors.append(f"{relative}: id changed from {old.get('id')}. Changing it would deploy a duplicate rule.")
            continue
        strip = lambda d: {k: v for k, v in d.items() if k != "version"}
        if strip(old) != strip(new):
            try:
                bumped = _version_tuple(str(new.get("version"))) > _version_tuple(str(old.get("version")))
            except ValueError:
                continue  # Schema validation reports the malformed version.
            if not bumped:
                errors.append(f"{relative}: rule changed, so bump version above {old.get('version')}")
    return errors


def find_duplicates(rules: list[Rule]) -> list[str]:
    errors = []
    for attribute, label in ((lambda r: r.id, "id"), (lambda r: r.name, "name")):
        seen: dict[str, Rule] = {}
        for rule in rules:
            value = attribute(rule)
            if value in seen:
                errors.append(f"{rule.relpath}: duplicate {label} '{value}', also used by {seen[value].relpath}")
            seen[value] = rule
    return errors
