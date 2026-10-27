"""Every maintained function names behavioral proof; native HTTP route inventory supplies routes.

Missing proofs, retired route claims, unclaimed operations and strict-gate gaps fail closed.
The generated matrix document must match the fixture exactly.
"""
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

SINCE = {"0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "0.10", "0.11", "0.12", "1.0", "1.1", "1.2", "1.3", "1.6", "2.0", "2.1", "2.2", "3.1", "3.2", "3.3"}
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
        assert set(row) == ({"id", "since", "area", "claim", "proof", "routes", "status"}
                            | ({"missing_proof"} if row["status"] == "gap" else set())), row["id"]
        assert row["since"] in SINCE and row["area"] in AREAS and row["status"] in STATUSES, row["id"]
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", row["id"]), row["id"]
        assert 12 <= len(row["claim"]) <= 240, row["id"]
        assert isinstance(row["proof"], list) and isinstance(row["routes"], list)
        if row["status"] != "gap":
            assert row["proof"], f"{row['id']} is {row['status']} without a proof"
        else:
            assert isinstance(row["missing_proof"], str) and len(row["missing_proof"]) >= 40, row["id"]
    assert matrix.row_problems(rows) == []


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

def test_route_matrix_rejects_stale_and_unclaimed_native_operations():
    claims = [{"routes": ["GET /retired"]}]
    actual = [{"method": "GET", "path": "/native"}]
    assert matrix.route_problems(claims, actual) == [
        "native route not covered: GET /native",
        "retired route still claimed: GET /retired",
    ]


def test_strict_cli_refuses_gaps_even_if_every_proof_and_route_is_valid(monkeypatch, tmp_path):
    rows = [{"id": "unproven", "since": "3.3", "area": "backend", "claim": "A missing behavioral proof.",
             "proof": [], "routes": [], "status": "gap", "missing_proof": "An executable behavioral proof is still required for this claim."}]
    document = tmp_path / "verification.md"
    document.write_text(matrix.render(rows), encoding="utf-8")
    monkeypatch.setattr(matrix, "DOCUMENT", document)
    monkeypatch.setattr(matrix, "load", lambda: rows)
    monkeypatch.setattr(route_coverage, "collect_routes", lambda: [])
    monkeypatch.setattr(route_coverage, "gate_problems", lambda routes: [])
    monkeypatch.delenv("VERIFICATION_STRICT", raising=False)
    assert matrix.main(["--check"]) == 0
    monkeypatch.setenv("VERIFICATION_STRICT", "1")
    assert matrix.main(["--check"]) == 1


def test_strict_cli_refuses_stale_document_and_nonexistent_proof(monkeypatch, tmp_path):
    rows = [{"id": "bound-proof", "since": "3.3", "area": "backend", "claim": "A maintained behavior has an executable proof.",
             "proof": ["pytest::tests/test_missing.py::test_missing"], "routes": [], "status": "proven"}]
    document = tmp_path / "verification.md"
    document.write_text(matrix.render(rows), encoding="utf-8")
    monkeypatch.setattr(matrix, "ROOT", tmp_path)
    monkeypatch.setattr(matrix, "DOCUMENT", document)
    monkeypatch.setattr(matrix, "load", lambda: rows)
    monkeypatch.setattr(route_coverage, "collect_routes", lambda: [])
    monkeypatch.setattr(route_coverage, "gate_problems", lambda routes: [])
    monkeypatch.setenv("VERIFICATION_STRICT", "1")
    assert matrix.main(["--check"]) == 1
    proof = tmp_path / "tests/test_missing.py"
    proof.parent.mkdir()
    proof.write_text("def test_missing():\n    assert 2 + 2 == 4\n", encoding="utf-8")
    document.write_text("stale generated content", encoding="utf-8")
    assert matrix.main(["--check"]) == 1
    document.write_text(matrix.render(rows), encoding="utf-8")
    assert matrix.main(["--check"]) == 0


def test_cli_refuses_native_authorization_regression(monkeypatch, tmp_path):
    document = tmp_path / "verification.md"
    document.write_text(matrix.render([]), encoding="utf-8")
    monkeypatch.setattr(matrix, "DOCUMENT", document)
    monkeypatch.setattr(matrix, "load", lambda: [])
    monkeypatch.setattr(route_coverage, "collect_routes", lambda: [])
    monkeypatch.setattr(route_coverage, "gate_problems", lambda routes: ["anonymous route accepted"])
    assert matrix.main(["--check"]) == 1


def test_proof_resolver_rejects_comments_and_unregistered_scenario_strings(tmp_path):
    lab = tmp_path / "scripts/lab"
    lab.mkdir(parents=True)
    source = lab / "ui-acceptance.py"
    source.write_text('# self.check("login.retired", True)\nlabel = "login.retired"\n', encoding="utf-8")
    assert matrix.proof_problem("ui::login.retired", tmp_path) == "no such ui scenario"
    source.write_text('def scenario(self):\n    self.check("login.current", 200 == 200)\n', encoding="utf-8")
    assert matrix.proof_problem("ui::login.current", tmp_path) is None
    assert matrix.proof_problem("ui::login.current_extra", tmp_path) == "no such ui scenario"


def test_proof_resolver_follows_parameterized_browser_checks(tmp_path):
    script = tmp_path / "checks.py"
    script.write_text(
        'def helper(self, label):\n    self.check(label, True)\n'
        'def scenario(self):\n'
        '    self.helper("audit.layout")\n'
        '    for protocol, label in (("naive", "clients.naive"), ("mieru", "clients.mieru")):\n'
        '        self.check(label, protocol != "")\n',
        encoding="utf-8",
    )
    assert set(matrix.check_names(script)) == {"audit.layout", "clients.naive", "clients.mieru"}


def test_non_gap_without_proof_and_undocumented_gap_fail_closed():
    assert matrix.row_problems([{"id": "empty", "status": "proven", "proof": []}]) == [
        "empty: non-gap row has no proof",
    ]
    assert matrix.row_problems([{"id": "unknown", "status": "gap", "proof": []}]) == [
        "unknown: gap has no explicit missing behavior",
    ]

def test_the_rendered_document_is_the_fixture(rows):
    assert DOCUMENT.read_text(encoding="utf-8") == matrix.render(rows), \
        "docs/VERIFICATION_MATRIX.md is stale: python3 scripts/dev/verification-matrix.py --render"


def test_no_gap_survives_the_release_gate(rows):
    """The release gate refuses every explicitly documented behavioral gap."""
    gaps = [row["id"] for row in rows if row["status"] == "gap"]
    if os.environ.get("VERIFICATION_STRICT") == "1":
        assert gaps == [], gaps
    completed = subprocess.run([sys.executable, str(ROOT / "scripts/dev/verification-matrix.py"), "--check"],
                               capture_output=True, text=True, cwd=ROOT)
    assert completed.returncode == 0, completed.stdout + completed.stderr
