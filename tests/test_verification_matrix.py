"""The verification matrix (v0.6): every function promised in v0.2–v0.5 names the proof
that it works — a test, a lab scenario, a browser scenario or a live check — and the
guard keeps the names honest: a proof that does not exist in the tree is a lie, a route
or a screen without a row is a hole, and the rendered document is the fixture, not prose."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/verification-matrix.json"
DOCUMENT = ROOT / "docs/VERIFICATION_MATRIX.md"
sys.path.insert(0, str(ROOT / "scripts/dev"))
matrix = __import__("verification-matrix")
route_coverage = __import__("route-coverage")

SINCE = {"0.2", "0.3", "0.4", "0.5"}
AREAS = {"backend", "ui", "installer", "fleet", "routing", "router", "clients", "release"}
STATUSES = {"proven", "fixed-in-0.6", "gap"}
VIEWS = ("login", "dashboard", "clients", "users", "naive", "mieru", "versions", "fleet", "routing", "admins", "audit")


@pytest.fixture(scope="module")
def rows():
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == 1
    return document["rows"]


def test_rows_are_well_formed_and_unique(rows):
    ids = [row["id"] for row in rows]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for row in rows:
        assert set(row) == {"id", "since", "area", "claim", "proof", "routes", "status"}, row["id"]
        assert row["since"] in SINCE and row["area"] in AREAS and row["status"] in STATUSES, row["id"]
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", row["id"]), row["id"]
        assert 12 <= len(row["claim"]) <= 240, row["id"]
        assert isinstance(row["proof"], list) and isinstance(row["routes"], list)
        if row["status"] != "gap":
            assert row["proof"], f"{row['id']} is {row['status']} without a proof"


def test_every_proof_exists_in_the_tree(rows):
    missing = [f"{row['id']}: {proof} — {why}" for row in rows for proof in row["proof"]
               for why in [matrix.proof_problem(proof, ROOT)] if why]
    assert missing == [], "\n".join(missing)


def test_every_route_and_every_view_has_a_row(rows):
    claimed = {r for row in rows for r in row["routes"]}
    routes = {f"{r['method']} {r['path']}" for r in route_coverage.collect_routes()}
    assert routes - claimed == set(), sorted(routes - claimed)
    assert claimed - routes == set(), sorted(claimed - routes)
    views_with_rows = {proof.split("::", 1)[1].split(".", 1)[0] for row in rows for proof in row["proof"] if proof.startswith("ui::")}
    views_with_gap_rows = {row["id"].split("-", 1)[1] for row in rows if row["status"] == "gap" and row["id"].startswith("ui-")}
    for view in VIEWS:
        assert view in views_with_rows or view in views_with_gap_rows, f"no ui row for the view {view}"


def test_the_rendered_document_is_the_fixture(rows):
    assert DOCUMENT.read_text(encoding="utf-8") == matrix.render(rows), \
        "docs/VERIFICATION_MATRIX.md is stale: python3 scripts/dev/verification-matrix.py --render"


def test_no_gap_survives_the_release_gate(rows):
    """`VERIFICATION_STRICT=1` (the full gate on the release tree) refuses a matrix with a
    hole; a working tree in the middle of v0.6 may still carry them."""
    gaps = [row["id"] for row in rows if row["status"] == "gap"]
    if os.environ.get("VERIFICATION_STRICT") == "1":
        assert gaps == [], gaps
    completed = subprocess.run([sys.executable, str(ROOT / "scripts/dev/verification-matrix.py"), "--check"],
                               capture_output=True, text=True, cwd=ROOT)
    assert completed.returncode == 0, completed.stdout + completed.stderr
