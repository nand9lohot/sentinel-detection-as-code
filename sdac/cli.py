"""Command line interface: validate, test, plan, deploy and catalog."""

from __future__ import annotations

import argparse
import os
import sys

import requests

from sdac import arm, catalog, harness, kql
from sdac.rules import (
    check_against_base,
    find_duplicates,
    load_rules,
    load_tables,
    lint_rule,
    required_columns,
)


def _write_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")


def _kql_errors(rules: list, tables: dict) -> dict[str, list[str]]:
    """Check each rule's query, and each test case's generated query, with the KQL analyzer."""
    items = []
    owners = {}
    for rule in rules:
        items.append({"id": f"rule:{rule.path}", "query": rule.data["query"]})
        owners[f"rule:{rule.path}"] = (rule, None, None)
        for index, case in enumerate(rule.cases):
            item_id = f"case:{rule.path}:{index}"
            items.append({"id": item_id, "query": harness.build_query(rule, case, tables)})
            owners[item_id] = (rule, case.get("name", f"case {index}"), case)

    errors: dict[str, list[str]] = {}
    for item_id, result in kql.analyze(items, tables).items():
        rule, case, case_data = owners[item_id]
        problems = errors.setdefault(rule.relpath, [])
        for err in result["errors"]:
            where = f"test '{case}'" if case else f"query line {err['line']}"
            problems.append(f"{where}: {err['code']} {err['message']}")
        if case is None:
            missing = required_columns(rule.data) - set(result["columns"])
            if missing:
                problems.append(f"query does not return mapped columns: {', '.join(sorted(missing))}")
        else:
            expected = set(case_data.get("expect_first_row") or {}) - set(result["columns"])
            if expected and not result["errors"]:
                problems.append(f"test '{case}': expect_first_row uses columns the query does not return: {', '.join(sorted(expected))}")
    return errors


def cmd_validate(args: argparse.Namespace) -> int:
    rules = load_rules()
    tables = load_tables()
    if not rules:
        print("No rules found under detections/.")
        return 1

    problems: dict[str, list[str]] = {}
    for rule in rules:
        found = lint_rule(rule, tables)
        if found:
            problems[rule.relpath] = found

    global_problems = find_duplicates(rules)
    if args.base:
        global_problems += check_against_base(rules, args.base)

    if args.no_kql:
        print("Skipped KQL analysis (--no-kql).")
    else:
        # Only analyze rules that passed linting, since a broken rule has no usable fields.
        clean = [rule for rule in rules if rule.relpath not in problems]
        try:
            for path, found in _kql_errors(clean, tables).items():
                if found:
                    problems.setdefault(path, []).extend(found)
        except kql.AnalyzerUnavailable as err:
            print(f"ERROR: {err}. Use --no-kql to skip this check.")
            return 1

    for path, found in sorted(problems.items()):
        for problem in found:
            print(f"ERROR {path}: {problem}")
    for problem in global_problems:
        print(f"ERROR {problem}")

    total = sum(len(found) for found in problems.values()) + len(global_problems)
    if total:
        print(f"\nValidation failed: {total} problem(s) across {len(rules)} rule(s).")
        return 1
    print(f"Validation passed: {len(rules)} rule(s).")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    rules = load_rules()
    tables = load_tables()
    client = harness.KustoClient(args.kusto_uri, args.database)
    if args.wait:
        print(f"Waiting up to {args.wait}s for Kusto at {args.kusto_uri}...")
        client.wait_until_ready(args.wait)
    results = harness.run_tests(rules, tables, client, only=args.only)
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"{status}  {result.rule} / {result.case}" + (f"\n      {result.detail}" if result.detail else ""))
    failed = sum(1 for result in results if not result.passed)
    if not results:
        print("No test cases matched.")
        return 1
    print(f"\n{len(results) - failed}/{len(results)} test cases passed.")
    return 1 if failed else 0


def _load_plan():
    rules = load_rules()
    if not rules:
        # An empty result usually means a bad checkout, so never treat it as "delete everything".
        raise RuntimeError("No rules found under detections/. Refusing to continue.")
    client = arm.client_from_env()
    return arm.build_plan(rules, client.list_rules()), client


def cmd_plan(args: argparse.Namespace) -> int:
    plan, _ = _load_plan()
    text = arm.render_plan(plan)
    print(text)
    _write_summary(text)
    return 2 if args.detailed_exitcode and plan.has_changes else 0


def cmd_deploy(args: argparse.Namespace) -> int:
    plan, client = _load_plan()
    text = arm.render_plan(plan)
    print(text + "\n")
    _write_summary(text)
    failures = arm.apply_plan(plan, client, prune=args.prune)
    if failures:
        print(f"\nDeployment finished with {len(failures)} failure(s).")
        _write_summary("\n### Failures\n" + "\n".join(f"- {failure}" for failure in failures))
        return 1
    print("\nDeployment finished.")
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    rules = load_rules()
    if args.check:
        stale = catalog.stale_outputs(rules)
        if stale:
            print(f"Out of date: {', '.join(stale)}. Run 'sdac catalog' and commit the result.")
            return 1
        print("Catalog is up to date.")
        return 0
    catalog.write_outputs(rules)
    print(f"Wrote {catalog.CATALOG_PATH.name} and {catalog.LAYER_PATH.name}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sdac", description="Detection-as-code for Microsoft Sentinel")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="lint rules and analyze KQL offline")
    validate.add_argument("--base", help="Git ref to compare with, for ID and version checks")
    validate.add_argument("--no-kql", action="store_true", help="skip KQL analysis, which needs Node.js")
    validate.set_defaults(func=cmd_validate)

    test = commands.add_parser("test", help="run test cases against a Kusto emulator")
    test.add_argument("--kusto-uri", default=os.environ.get("KUSTO_URI", "http://localhost:8080"))
    test.add_argument("--database", default=os.environ.get("KUSTO_DB", "NetDefaultDB"))
    test.add_argument("--wait", type=int, default=0, help="seconds to wait for the emulator to start")
    test.add_argument("--only", help="run only rules whose path contains this text")
    test.set_defaults(func=cmd_test)

    plan = commands.add_parser("plan", help="show what a deployment would change")
    plan.add_argument("--detailed-exitcode", action="store_true", help="exit 2 when changes or drift exist")
    plan.set_defaults(func=cmd_plan)

    deploy = commands.add_parser("deploy", help="apply the plan to Sentinel")
    deploy.add_argument("--prune", action="store_true", help="delete repo-managed rules no longer in Git")
    deploy.set_defaults(func=cmd_deploy)

    catalog_cmd = commands.add_parser("catalog", help="generate the catalog and ATT&CK layer")
    catalog_cmd.add_argument("--check", action="store_true", help="fail if the generated files are stale")
    catalog_cmd.set_defaults(func=cmd_catalog)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuntimeError, requests.RequestException) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
