"""placement.js is pure: rows from nodes+grants, a diff from ticks. Node runs the module
as shipped, so the test exercises the real code, not a re-implementation."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")

NODES = [
    {"node_id": "local", "display_name": "self", "transport": "local"},
    {"node_id": "fra", "display_name": "Frankfurt", "transport": "panel", "link": {"enabled": True}},
    {"node_id": "paused", "display_name": "Paused", "transport": "panel", "link": {"enabled": False}},
    {"node_id": "agent", "display_name": "Agent v1", "transport": "agent"},
]
GRANTS = [
    {"id": "g-naive-local", "protocol": "naive", "node_id": "local", "desired_state": "enabled", "observed_state": "enabled", "secret_ref": {"secret_id": "s", "version": 1}, "runtime_username": "alice"},
    {"id": "g-mieru-fra", "protocol": "mieru", "node_id": "fra", "desired_state": "disabled", "observed_state": "disabled", "secret_ref": {"secret_id": "s", "version": 1}, "runtime_username": "alice"},
    {"id": "g-mt-paused", "protocol": "mtproxy", "node_id": "paused", "desired_state": "enabled", "observed_state": "pending", "secret_ref": None, "runtime_username": "alice"},
    {"id": "g-deleted", "protocol": "mtproxy", "node_id": "local", "desired_state": "deleted", "observed_state": "missing", "secret_ref": None, "runtime_username": "alice"},
]


def run(script: str) -> dict:
    module = (ROOT / "static/js/placement.js").as_uri()
    code = f"import * as p from {json.dumps(module)}; const NODES={json.dumps(NODES)}; const GRANTS={json.dumps(GRANTS)}; {script}"
    result = subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_rows_offer_local_and_linked_panels_and_keep_nodes_that_already_hold_grants():
    rows = run("console.log(JSON.stringify(p.placementRows(NODES, GRANTS)))")
    by_id = {row["node_id"]: row for row in rows}
    assert [row["node_id"] for row in rows] == ["local", "fra", "paused"]
    assert by_id["local"]["offered"] and by_id["fra"]["offered"] and not by_id["paused"]["offered"]
    assert by_id["local"]["label"] == "Этот сервер" and by_id["paused"]["label"] == "Paused"
    assert by_id["local"]["cells"]["naive"]["id"] == "g-naive-local"
    assert by_id["local"]["cells"]["mtproxy"] is None  # deleted grants are empty cells
    assert by_id["paused"]["cells"]["mtproxy"]["id"] == "g-mt-paused"


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_diff_creates_enables_and_disables_from_ticks():
    diff = run("""
      const rows = p.placementRows(NODES, GRANTS);
      const checked = new Set(["fra:naive", "fra:mieru", "local:mieru"]);  // local:naive unticked
      console.log(JSON.stringify(p.placementDiff(rows, checked, "alice")));
    """)
    assert sorted((g["node_id"], g["protocol"]) for g in diff["create"]) == [("fra", "naive"), ("local", "mieru")]
    assert all(g["runtime_username"] == "alice" and g["options"] == {} for g in diff["create"])
    assert diff["enable"] == ["g-mieru-fra"] and diff["disable"] == ["g-naive-local"]


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_unoffered_rows_are_never_part_of_the_diff():
    diff = run("""
      const rows = p.placementRows(NODES, GRANTS);
      console.log(JSON.stringify(p.placementDiff(rows, new Set(["paused:naive"]), "alice")));
    """)
    assert diff == {"create": [], "enable": [], "disable": ["g-naive-local"]}


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_render_marks_cells_and_disables_what_cannot_change():
    html = run("""
      const rows = p.placementRows(NODES, GRANTS);
      console.log(JSON.stringify({rw: p.renderPlacement(rows, {canWrite: true}), ro: p.renderPlacement(rows, {canWrite: false})}));
    """)
    rw, ro = html["rw"], html["ro"]
    assert 'data-node="local" data-protocol="naive"' in rw and "checked" in rw
    assert 'data-node="paused"' in rw and "панель на паузе" in rw
    assert rw.count("data-placement-delete") == 3  # naive local, mieru fra, mtproxy paused
    assert "выключен" in rw and "ожидает узел" in rw and "без секрета" in rw
    assert "data-placement-delete" not in ro and ro.count("disabled") >= 9


def test_status_words_match_the_card():
    javascript = (ROOT / "static/js/placement.js").read_text()
    for word in ("ожидает узел", "выключен", "без секрета", "ошибка", "панель на паузе"):
        assert word in javascript, word
