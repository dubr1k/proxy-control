"""Automatic classification of the panel tests (§10.4 step 5 of the Rust port plan).

Every collected test gets exactly one category marker:

- `blackbox` — talks to a panel only through `panel_server` (`server`/`client`/`pair`/`login_user`):
  HTTP, the doubles behind the managers' wire protocols, the CLI, read-only SQL on the database
  file, the harness hooks (`tick`, `clock`, `probe_bridge`). Runs unchanged against the Rust binary.
- `internal` — uses a panel but reaches into the Python process (`app.state`, `client._transport.app`,
  an app of its own from `create_app`/`panel_app`, `monkeypatch` of panel code, `caplog`): stays
  Python until converted (step 4); its fault-injection part becomes Rust unit tests.
- `unit` — imports panel modules and tests them without a server: ported as Rust unit tests.
- `static` — checks `panel/static/**` without a panel (text or `node`): independent of the server.
- `browser` — headless Chromium (against a stub server or `isolated_panel`).

Orthogonal: `fleet_v1` — touches the retired fleet v1 (mTLS agent ingress, node agent, the openssl CA,
`/api/fleet/nodes*`, enrollment of v1 nodes); not ported (owner decision 2026-10-25).

Under `PANEL_IMPL=rust`: `unit`, `internal`, `fleet_v1` and the `legacy` half of the writer
parametrisation (`PANEL_VNEXT_WRITER=legacy` is not ported) are deselected.

The scan reads the test function, every module-level function or fixture it names (transitively)
and the module-level fixtures it requests.
"""
from __future__ import annotations

import ast
import functools
import re
from pathlib import Path

CATEGORIES = ("blackbox", "internal", "unit", "static", "browser")
SERVER_FIXTURES = {"client", "server", "pair", "login_user", "panel_server"}
# the doubles a test may patch freely: the server dispatches to them
FAKE_FIXTURES = {"naive", "telemt", "mieru", "awg", "amneziawg", "trusttunnel", "router", "versions", "agent"}
SERVER_NAMES = {"start_panel", "create_app", "panel_app", "isolated_panel", "make_panel", "uvicorn"}
INTERNAL_NAMES = {"create_app", "panel_app", "Settings", "setup_metrics", "build_fleet_metrics_source",
                  "ASGITransport"}
# `server.app`/`node.state` are the Python process; `ASGITransport(app=server)` calls it in-process
INTERNAL_ATTRS = {"state", "_transport", "app", "ASGITransport"}

BROWSER_FILES = {
    "test_button_centering.py", "test_client_dialog_browser.py", "test_link_chooser_browser.py",
    "test_mobile_layout.py", "test_monitoring_layout.py", "test_protocol_dialog_browser.py",
    "test_subscription_page_browser.py",
}
STATIC_FILES = {
    "test_clients_filters_ui.py", "test_dashboard_ui_contract.py", "test_fleet_v2_ui_contract.py",
    "test_live_rates_ui_contract.py", "test_management_ui_contract.py", "test_mobile_badges_presets.py",
    "test_monitoring_ui_contract.py", "test_nav_counts_ui_contract.py", "test_placement_ui_contract.py",
    "test_routing_ui_contract.py", "test_subscription_ui_contract.py", "test_trusttunnel_clients_ui_contract.py",
    "test_trusttunnel_ui_contract.py", "test_view_addressing_ui.py", "test_ui_browser_findings.py",
}
FLEET_V1_FILES = {"test_fleet.py", "test_agent_transport.py"}
FLEET_V1_PATTERNS = re.compile(
    r"/api/fleet/nodes|certificates/revoke-all|enrollment_checklist|agent_transport|agent_ingress|agent_service"
    r"|node_agent|CertificateAuthority|fleet-ca-init|fleet-sign-csr|fleet-bind-cert|fleet-register-node"
    r"|fleet-revoke-cert|FleetStore|fleet_commands|fleet_certificates|post\(\s*\"/api/nodes\"|'unenrolled'")


@functools.cache
def _module(path: str):
    source = Path(path).read_text()
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    return source, functions, classes


def _reachable(path: str, name: str, argnames) -> list[ast.AST]:
    """The test's own node plus every module-level function/fixture/class it reaches by name."""
    _, functions, classes = _module(path)
    pending, seen, nodes = [name, *argnames], set(), []
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        node = functions.get(current) or classes.get(current)
        if node is None:
            continue
        nodes.append(node)
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                pending.append(child.id)
            elif isinstance(child, ast.arg):
                pending.append(child.arg)
    return nodes


def _internal(nodes: list[ast.AST], fixturenames) -> list[str]:
    reasons = []
    if "caplog" in fixturenames:
        reasons.append("caplog")
    for node in nodes:
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and child.attr in INTERNAL_ATTRS:
                reasons.append(f".{child.attr}")
            elif isinstance(child, ast.Name) and child.id in INTERNAL_NAMES:
                reasons.append(child.id)
            elif (isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                  and isinstance(child.func.value, ast.Name) and child.func.value.id == "monkeypatch"
                  and child.func.attr in {"setattr", "delattr", "setitem", "delitem"}):
                target = child.args[0] if child.args else None
                if not (isinstance(target, ast.Name) and target.id in FAKE_FIXTURES):
                    reasons.append("monkeypatch")
    return reasons


def classify(item) -> tuple[str, bool, list[str]]:
    """(category, fleet_v1, reasons) of one collected test."""
    path = str(item.path)
    filename = item.path.name
    function = getattr(item, "function", None)
    name = getattr(function, "__name__", item.name.split("[")[0])
    argnames = list(getattr(getattr(item, "_fixtureinfo", None), "argnames", ()) or ())
    fixturenames = set(getattr(item, "fixturenames", ()) or ())
    try:
        source, _, _ = _module(path)
        nodes = _reachable(path, name, argnames)
    except (OSError, SyntaxError):
        return "unit", False, []
    text = "\n".join(ast.get_source_segment(source, node) or "" for node in nodes)
    fleet_v1 = filename in FLEET_V1_FILES or bool(FLEET_V1_PATTERNS.search(text))
    if filename in BROWSER_FILES:
        return "browser", fleet_v1, []
    uses_server = bool(fixturenames & SERVER_FIXTURES) or any(
        isinstance(child, ast.Name) and child.id in SERVER_NAMES for node in nodes for child in ast.walk(node))
    if uses_server:
        reasons = _internal(nodes, fixturenames)
        return ("internal" if reasons else "blackbox"), fleet_v1, sorted(set(reasons))
    if filename in STATIC_FILES:
        return "static", fleet_v1, []
    return "unit", fleet_v1, []


def writer_of(item) -> str | None:
    callspec = getattr(item, "callspec", None)
    if callspec is None:
        return None
    for key in ("server", "client"):
        if key in callspec.params:
            return callspec.params[key]
    return None


def apply(config, items, *, impl: str) -> None:
    """Mark every item; under `rust` deselect what is not ported. `PANEL_HARNESS_REPORT=<file>`
    writes the classification (node id → category, fleet_v1, reasons) as JSON."""
    import os

    import pytest

    selected, deselected, report = [], [], {}
    for item in items:
        category, fleet_v1, reasons = classify(item)
        report[item.nodeid] = {"category": category, "fleet_v1": fleet_v1, "reasons": reasons,
                               "writer": writer_of(item)}
        item.add_marker(getattr(pytest.mark, category))
        item.user_properties.append(("panel_category", category))
        if reasons:
            item.user_properties.append(("panel_internal", ",".join(reasons)))
        if fleet_v1:
            item.add_marker(pytest.mark.fleet_v1)
        legacy = writer_of(item) == "legacy"
        if impl == "rust" and (category in {"unit", "internal"} or fleet_v1 or legacy):
            deselected.append(item)
        else:
            selected.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected
    target = os.environ.get("PANEL_HARNESS_REPORT")
    if target:
        import json

        with open(target, "w") as handle:
            json.dump(report, handle, indent=1, sort_keys=True)


def register(config) -> None:
    for name, text in (
        ("blackbox", "talks to the panel only over HTTP/CLI/SQL and the managers' wire (runs against Rust)"),
        ("internal", "uses a panel but reaches into the Python process (to be converted)"),
        ("unit", "tests panel modules without a server (ported as Rust unit tests)"),
        ("static", "checks panel/static without a panel"),
        ("browser", "headless Chromium"),
        ("fleet_v1", "touches the retired fleet v1 (not ported)"),
    ):
        config.addinivalue_line("markers", f"{name}: {text}")

