"""Shared fixtures, including in-process fakes of the Azure and Kusto HTTP APIs."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jsonschema
import pytest

from sdac.rules import load_rules, load_tables

CONTRACT = json.loads(
    (Path(__file__).parent / "contract" / "scheduled_alert_rule.2025-09-01.schema.json").read_text(encoding="utf-8")
)
RULES_PATH = re.compile(
    r"^/subscriptions/sub/resourceGroups/rg/providers/Microsoft\.OperationalInsights/workspaces/ws"
    r"/providers/Microsoft\.SecurityInsights/alertRules(?:/([^/]+))?$"
)


class FakeArm:
    """Enough of the alertRules API to exercise the deployer, including paging and etags."""

    def __init__(self):
        self.rules: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.etag_counter = 0
        self.page_size = 2
        self.fail_once: list[int] = []  # Status codes to return before succeeding.
        self.reject_rules: dict[str, str] = {}  # Rule ID to a 400 message.

    def store(self, rule_id: str, body: dict) -> dict:
        self.etag_counter += 1
        properties = dict(body["properties"])
        # Azure returns server-side fields that the repo never sets.
        properties.update({"lastModifiedUtc": "2026-11-03T00:00:00Z", "alertRuleTemplateName": None, "templateVersion": None})
        item = {
            "id": f"/x/alertRules/{rule_id}",
            "name": rule_id,
            "type": "Microsoft.SecurityInsights/alertRules",
            "kind": body["kind"],
            "etag": f'"etag-{self.etag_counter}"',
            "properties": properties,
        }
        self.rules[rule_id] = item
        return item


def _serve(handler_class):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def fake_arm():
    state = FakeArm()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, status, payload=None):
            body = json.dumps(payload).encode() if payload is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if status == 429:
                self.send_header("Retry-After", "0")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status, message):
            self._send(status, {"error": {"code": "Error", "message": message}})

        def _route(self):
            url = urlparse(self.path)
            query = parse_qs(url.query)
            state.calls.append((self.command, url.path))
            if self.headers.get("Authorization") != "Bearer test-token":
                self._error(401, "Missing or invalid token")
                return None
            if query.get("api-version") != ["2025-09-01"]:
                self._error(400, f"Unexpected api-version {query.get('api-version')}")
                return None
            match = RULES_PATH.match(url.path)
            if not match:
                self._error(404, f"Unexpected path {url.path}")
                return None
            if state.fail_once:
                self._error(state.fail_once.pop(0), "Temporary failure")
                return None
            return match, query

        def do_GET(self):
            routed = self._route()
            if not routed:
                return
            _, query = routed
            items = sorted(state.rules.values(), key=lambda item: item["name"])
            start = int(query.get("skip", ["0"])[0])
            payload = {"value": items[start:start + state.page_size]}
            if start + state.page_size < len(items):
                host, port = self.server.server_address
                payload["nextLink"] = (
                    f"http://{host}:{port}{urlparse(self.path).path}"
                    f"?api-version=2025-09-01&skip={start + state.page_size}"
                )
            self._send(200, payload)

        def do_PUT(self):
            routed = self._route()
            if not routed:
                return
            match, _ = routed
            rule_id = match.group(1)
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            try:
                jsonschema.validate(body, CONTRACT)
            except jsonschema.ValidationError as err:
                self._error(400, f"Contract violation: {err.message}")
                return
            if rule_id in state.reject_rules:
                self._error(400, state.reject_rules[rule_id])
                return
            existing = state.rules.get(rule_id)
            if existing and body.get("etag") and body["etag"] != existing["etag"]:
                self._error(409, "Newer version of the resource exists")
                return
            self._send(200 if existing else 201, state.store(rule_id, body))

        def do_DELETE(self):
            routed = self._route()
            if not routed:
                return
            match, _ = routed
            if state.rules.pop(match.group(1), None):
                self._send(200, {})
            else:
                self._send(204)

    server, thread = _serve(Handler)
    host, port = server.server_address
    state.endpoint = f"http://{host}:{port}"
    yield state
    server.shutdown()
    thread.join()


@pytest.fixture
def fake_kusto():
    """Records queries and returns canned rows. Query logic runs in detection-tests in CI."""

    class State:
        queries: list[str] = []
        columns = ["TimeGenerated", "AccountName"]
        rows: list[list] = []
        status = 200
        unavailable_for = 0

    state = State()
    state.queries = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))
            state.queries.append(payload["csl"])
            if state.unavailable_for > 0:
                state.unavailable_for -= 1
                status, body = 503, {"error": "starting"}
            elif state.status != 200:
                status, body = state.status, {"error": {"message": "Semantic error"}}
            else:
                status = 200
                body = {
                    "Tables": [
                        {
                            "TableName": "Table_0",
                            "Columns": [{"ColumnName": c, "DataType": "String"} for c in state.columns],
                            "Rows": state.rows,
                        }
                    ]
                }
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server, thread = _serve(Handler)
    host, port = server.server_address
    state.uri = f"http://{host}:{port}"
    yield state
    server.shutdown()
    thread.join()


@pytest.fixture
def rules():
    return load_rules()


@pytest.fixture
def tables():
    return load_tables()
