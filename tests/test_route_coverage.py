"""`scripts/dev/route-coverage.py` (v0.6): every panel route is named, gated and mentioned
by a test or a lab scenario — the audit the verification matrix stands on."""
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


def test_every_api_route_is_listed_with_its_gate(routes):
    paths = {(r["method"], r["path"]) for r in routes}
    assert ("GET", "/api/routing/targets") in paths
    assert ("POST", "/api/routing/targets/{node_id}/{protocol}/attach") in paths
    assert ("PUT", "/api/fleet/v2/generation") in paths
    assert ("GET", "/api/dashboard") in paths
    by_key = {(r["method"], r["path"]): r for r in routes}
    assert "roles:owner" in by_key[("POST", "/api/routing/targets/{node_id}/{protocol}/attach")]["gates"]
    assert "fleet_key" in by_key[("PUT", "/api/fleet/v2/generation")]["gates"]
    assert "current" in by_key[("GET", "/api/dashboard")]["gates"]


def test_public_routes_are_exactly_the_documented_ones(routes):
    public = sorted((r["method"], r["path"]) for r in routes if not r["gates"])
    assert public == sorted(route_coverage.PUBLIC)


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
    assert {"method", "path", "gates"} <= set(document[0])
    assert len(document) >= 100
