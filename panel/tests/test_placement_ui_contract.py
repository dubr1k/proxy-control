"""Placement-row and grant-diff behavior from the JavaScript served by the Rust panel."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

import pytest

NODE = shutil.which("node")
pytestmark = pytest.mark.anyio

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


async def run(server, tmp_path, script: str) -> Any:
    for name in ("common", "placement"):
        response = await server.client.get(f"/static/js/{name}.js")
        assert response.status_code == 200, name
        (tmp_path / f"{name}.mjs").write_text(response.text.replace("./common.js", "./common.mjs"))
    module = (tmp_path / "placement.mjs").as_uri()
    code = f"import * as p from {json.dumps(module)}; const NODES={json.dumps(NODES)}; const GRANTS={json.dumps(GRANTS)}; {script}"
    assert NODE is not None
    result = subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


async def test_rows_offer_local_and_linked_panels_and_keep_nodes_that_already_hold_grants(server, tmp_path):
    rows = await run(server, tmp_path, "console.log(JSON.stringify(p.placementRows(NODES, GRANTS)))")
    by_id = {row["node_id"]: row for row in rows}
    assert [row["node_id"] for row in rows] == ["local", "fra", "paused"]
    assert by_id["local"]["offered"] and by_id["fra"]["offered"] and not by_id["paused"]["offered"]
    assert by_id["local"]["label"] == "Этот сервер" and by_id["paused"]["label"] == "Paused"
    assert by_id["local"]["cells"]["naive"]["id"] == "g-naive-local"
    assert by_id["local"]["cells"]["mtproxy"] is None  # deleted grants are empty cells
    assert by_id["paused"]["cells"]["mtproxy"]["id"] == "g-mt-paused"


async def test_diff_creates_enables_and_disables_from_ticks(server, tmp_path):
    diff = await run(server, tmp_path, """
      const rows = p.placementRows(NODES, GRANTS);
      const checked = new Set(["fra:naive", "fra:mieru", "local:mieru"]);  // local:naive unticked
      console.log(JSON.stringify(p.placementDiff(rows, checked, "alice")));
    """)
    assert sorted((g["node_id"], g["protocol"]) for g in diff["create"]) == [("fra", "naive"), ("local", "mieru")]
    assert all(g["runtime_username"] == "alice" and g["options"] == {} for g in diff["create"])
    assert diff["enable"] == ["g-mieru-fra"] and diff["disable"] == ["g-naive-local"]


async def test_unoffered_rows_are_never_part_of_the_diff(server, tmp_path):
    diff = await run(server, tmp_path, """
      const rows = p.placementRows(NODES, GRANTS);
      console.log(JSON.stringify(p.placementDiff(rows, new Set(["paused:naive"]), "alice")));
    """)
    assert diff == {"create": [], "enable": [], "disable": ["g-naive-local"]}


async def test_render_marks_cells_and_disables_what_cannot_change(server, tmp_path):
    html = await run(server, tmp_path, """
      const rows = p.placementRows(NODES, GRANTS);
      console.log(JSON.stringify({rw: p.renderPlacement(rows, {canWrite: true}), ro: p.renderPlacement(rows, {canWrite: false})}));
    """)
    rw, ro = html["rw"], html["ro"]
    assert 'data-node="local" data-protocol="naive"' in rw and "checked" in rw
    assert 'data-node="paused"' in rw and "панель на паузе" in rw
    assert rw.count("data-placement-delete") == 3  # naive local, mieru fra, mtproxy paused
    assert "выключен" in rw and "ожидает узел" in rw and "без секрета" in rw
    assert "data-placement-delete" not in ro and ro.count("disabled") >= 9


async def test_awg_versions_share_one_group_header_over_separate_cells(server, tmp_path):
    html = await run(server, tmp_path, """
      const nodes = [{node_id: "local", display_name: "self", transport: "local", identity: {awg_versions: ["1.5", "2.0", "3.1"]}}];
      const rows = p.placementRows(nodes, []);
      console.log(JSON.stringify(p.renderPlacement(rows, {canWrite: true})));
    """)
    assert html.count("AmneziaWG") == 1 and 'colspan="3"' in html
    assert '<th rowspan="2">MTProxy</th>' in html and '<th rowspan="2" class="placement-node">Узел</th>' in html
    assert "<th>1.5</th><th>2.0</th><th>3.1</th>" in html
    for version in ("1.5", "2.0", "3.1"):  # still one checkbox per version
        assert f'data-protocol="amneziawg:{version}"' in html


async def test_settling_is_true_while_a_node_has_not_confirmed_and_ignores_deleted_grants(server, tmp_path):
    """The card polls on this predicate: «ожидает узел» must not stay on screen after the
    node reported the account, and a grant on its way out is nobody's wait."""
    verdicts = await run(server, tmp_path, """
      const deleted = GRANTS.filter((g) => g.desired_state === "deleted").map((g) => ({...g, observed_state: "pending"}));
      console.log(JSON.stringify({
        pending: p.settling(GRANTS),
        converged: p.settling(GRANTS.filter((g) => g.observed_state !== "pending")),
        onlyDeleted: p.settling(deleted),
        empty: p.settling([]),
      }));
    """)
    assert verdicts == {"pending": True, "converged": False, "onlyDeleted": False, "empty": False}

