"""Bridge to the offline KQL analyzer in kql-check/."""

from __future__ import annotations

import json
import shutil
import subprocess

from sdac.rules import ROOT

CHECK_DIR = ROOT / "kql-check"


class AnalyzerUnavailable(RuntimeError):
    pass


def analyze(items: list[dict], tables: dict) -> dict[str, dict]:
    """Analyze [{id, query}] items and return {id: {errors, columns}}."""
    if not shutil.which("node"):
        raise AnalyzerUnavailable("node was not found on PATH")
    if not (CHECK_DIR / "node_modules").exists():
        raise AnalyzerUnavailable("run 'npm ci --prefix kql-check' first")
    result = subprocess.run(
        ["node", str(CHECK_DIR / "check.js")],
        input=json.dumps({"tables": tables, "items": items}),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise AnalyzerUnavailable(f"KQL analyzer failed: {result.stderr.strip()[:500]}")
    return {entry["id"]: entry for entry in json.loads(result.stdout)}
