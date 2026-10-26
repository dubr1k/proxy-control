"""Actual Rust router operation inventory and runtime authorization gate contract."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/dev/route-coverage.py"

sys.path.insert(0, str(ROOT / "scripts/dev"))
route_coverage = __import__("route-coverage")


@pytest.fixture(scope="module")
def routes():
    return route_coverage.collect_routes()


def test_every_api_route_is_listed_with_its_observed_gate(routes):
    paths = {(r["method"], r["path"]) for r in routes}
    assert ("GET", "/api/routing/targets") in paths
    assert ("POST", "/api/routing/targets/{node_id}/{protocol}/attach") in paths
    assert ("PUT", "/api/fleet/v2/generation") in paths
    assert ("GET", "/api/dashboard") in paths
    assert ("GET", "/api/fleet/nodes") not in paths  # retired Fleet v1
    by_key = {(r["method"], r["path"]): r for r in routes}
    attach = by_key[("POST", "/api/routing/targets/{node_id}/{protocol}/attach")]
    assert attach["session_no_csrf_detail"] == "CSRF validation failed"
    assert attach["viewer_detail"] == "insufficient role"
    fleet = by_key[("PUT", "/api/fleet/v2/generation")]
    assert fleet["session_no_csrf_detail"] == "a node-sync or admin API key is required"
    assert attach["session_csrf_detail"] not in route_coverage.GATE_DETAILS
    assert attach["admin_detail"] == "insufficient role"
    assert fleet["node_key_detail"] not in {
        "authentication required", "a node-sync or admin API key is required",
    }
    assert by_key[("GET", "/api/dashboard")]["anonymous_detail"] == "authentication required"

def test_private_routes_carry_observed_rust_runtime_refusals(routes):
    private = [row for row in routes if (row["method"], row["path"]) not in route_coverage.PUBLIC]
    assert private
    assert all(row["anonymous_status"] == 401 for row in private)
    assert all(row["inventory"] == "panel_web::routes::all" for row in routes)


def test_gate_rejects_a_private_route_whose_runtime_answers_without_auth():
    changed = {"method": "GET", "path": "/api/dashboard", "inventory": "panel_web::routes::all",
               "anonymous_status": 200, "anonymous_detail": ""}
    assert any("anonymous runtime did not refuse" in problem for problem in route_coverage.gate_problems([changed]))

def test_gate_rejects_owner_with_valid_csrf_still_refused_at_the_gate():
    route = {"method": "POST", "path": "/api/keys", "inventory": "panel_web::routes::all",
             "anonymous_status": 401, "anonymous_detail": "authentication required",
             "session_no_csrf_status": 403, "session_no_csrf_detail": "CSRF validation failed",
             "session_csrf_detail": "insufficient role",
             "viewer_status": 403, "viewer_detail": "insufficient role",
             "admin_status": 403, "admin_detail": "insufficient role"}
    assert any("owner's valid-CSRF mutation did not reach the handler" in problem
               for problem in route_coverage.gate_problems([route]))


def test_gate_rejects_admin_access_to_owner_only_route():
    route = {"method": "GET", "path": "/api/keys", "inventory": "panel_web::routes::all",
             "anonymous_status": 401, "anonymous_detail": "authentication required",
             "owner_status": 200, "owner_detail": "",
             "viewer_status": 403, "viewer_detail": "insufficient role",
             "admin_status": 200, "admin_detail": ""}
    assert any("owner-only read accepted an admin" in problem
               for problem in route_coverage.gate_problems([route]))


def test_gate_rejects_viewer_refusal_on_a_regular_read():
    route = {"method": "GET", "path": "/api/dashboard", "inventory": "panel_web::routes::all",
             "anonymous_status": 401, "anonymous_detail": "authentication required",
             "owner_status": 200, "owner_detail": "",
             "viewer_status": 403, "viewer_detail": "insufficient role"}
    assert any("viewer read did not reach the handler" in problem
               for problem in route_coverage.gate_problems([route]))

def test_gate_rejects_admin_access_to_owner_only_mutation():
    route = {"method": "POST", "path": "/api/routing/targets/{node_id}/{protocol}/attach",
             "inventory": "panel_web::routes::all",
             "anonymous_status": 401, "anonymous_detail": "authentication required",
             "session_no_csrf_status": 403, "session_no_csrf_detail": "CSRF validation failed",
             "session_csrf_status": 404, "session_csrf_detail": "target not found",
             "viewer_status": 403, "viewer_detail": "insufficient role",
             "admin_status": 404, "admin_detail": "target not found"}
    assert any("owner-only mutation accepted an admin" in problem
               for problem in route_coverage.gate_problems([route]))

def test_gate_rejects_csrf_or_role_regressions():
    route = {"method": "POST", "path": "/api/keys", "inventory": "panel_web::routes::all",
             "anonymous_status": 401, "anonymous_detail": "authentication required",
             "session_no_csrf_status": 200, "session_no_csrf_detail": "",
             "viewer_status": 200, "viewer_detail": ""}
    problems = route_coverage.gate_problems([route])
    assert any("CSRF or API-key refusal" in problem for problem in problems)
    assert any("viewer" in problem for problem in problems)


def test_unknown_public_route_fails_closed():
    unexpected = {"method": "GET", "path": "/api/unintended-public", "inventory": "panel_web::routes::all",
                  "anonymous_status": 200, "anonymous_detail": ""}
    assert any("anonymous runtime did not refuse" in problem
               for problem in route_coverage.gate_problems([unexpected]))


def test_public_routes_are_exactly_the_documented_ones(routes):
    public = {(r["method"], r["path"]) for r in routes if (r["method"], r["path"]) in route_coverage.PUBLIC}
    assert public == set(route_coverage.PUBLIC)
    assert len(public) == 7
    assert len(routes) >= 100


def test_every_mutating_route_is_csrf_or_key_gated_and_role_checked(routes):
    problems = route_coverage.gate_problems(routes)
    assert problems == [], "\n".join(problems)


def test_every_route_is_mentioned_by_a_test_or_a_lab_scenario(routes):
    unmentioned = route_coverage.unmentioned(routes, ROOT)
    assert unmentioned == [], "\n".join(f"{m} {p}" for m, p in unmentioned)


def test_the_cli_reports_json_and_a_clean_exit():
    completed = subprocess.run([sys.executable, str(SCRIPT), "--json"], capture_output=True, text=True, cwd=ROOT)
    assert completed.returncode == 0, completed.stderr[-500:]
    document = json.loads(completed.stdout)
    assert {"method", "path", "anonymous_status", "inventory"} <= set(document[0])
    assert len(document) >= 100
