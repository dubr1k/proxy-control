"""The sidebar badges (owner, 2026-10-18: «количество клиентов появляется только после того как
я нажму, при старте панели у всех черточки»): every badge is painted at start-up from one
place, whichever section the panel opens on, and kept fresh while the tab is visible."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

JS = Path(__file__).resolve().parent.parent / "static/js"
NODE = shutil.which("node")



@pytest.mark.skipif(NODE is None, reason="node is not installed")
# The Clients badge counts working clients only: archived ones have their own pill.
def test_all_badges_fill_without_visiting_any_section_and_a_failed_list_shows_a_dash():
    tmp = Path(tempfile.mkdtemp())
    shutil.copy(JS / "common.js", tmp / "common.mjs")
    shutil.copy(JS / "state.js", tmp / "state.mjs")
    (tmp / "nav.mjs").write_text((JS / "nav-counts.js").read_text().replace("./common.js", "./common.mjs").replace("./state.js", "./state.mjs"))
    code = """
import * as nav from %s;
const badges = {};
const root = { querySelector(sel) { return (badges[sel] ||= { textContent: "—" }); } };
const answers = {
  "/api/dashboard": { protocols: {
    mieru: { available: true, credentials: { total: 10 } },
    naive: { available: true, credentials: { total: 7 } },
    amneziawg: { available: true, credentials: { total: 0 } },
    trusttunnel: { available: true, credentials: { total: 3 } } } },
  "/api/users": { items: new Array(10).fill({}) },
  "/api/clients": { items: [...new Array(25).fill({ client: { state: "active" } }), ...new Array(16).fill({ client: { state: "archived" } })] },
  "/api/nodes": { items: new Array(4).fill({}) },
};
const ok = { root, api: async (path) => answers[path] };
await nav.refreshNavCounts(ok);
const first = Object.fromEntries(Object.entries(badges).map(([k, v]) => [k, String(v.textContent)]));
for (const k of Object.keys(badges)) badges[k].textContent = "x";
const broken = { root, api: async (path) => { if (path === "/api/clients") throw new Error("down"); return answers[path]; } };
await nav.refreshNavCounts(broken);
console.log(JSON.stringify({ first, clientsWhenDown: String(badges["#clients-count"].textContent), usersWhenClientsDown: String(badges["#users-count"].textContent) }));
""" % json.dumps((tmp / "nav.mjs").as_uri())
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True).stdout)
    assert out["first"] == {
        "#clients-count": "25", "#users-count": "10", "#mieru-count": "10", "#naive-count": "7",
        "#amneziawg-count": "0", "#trusttunnel-count": "3", "#fleet-count": "4",
    }
    assert out["clientsWhenDown"] == "—"
    assert out["usersWhenClientsDown"] == "10"
