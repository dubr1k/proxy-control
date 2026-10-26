"""Sidebar badge refresh executes the navigation module served by the Rust panel."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

NODE = shutil.which("node")

pytestmark = pytest.mark.anyio

# The Clients badge counts working clients only: archived ones have their own pill.
async def test_all_badges_fill_without_visiting_any_section_and_a_failed_list_shows_a_dash(server, tmp_path):
    for name in ("common", "state", "nav-counts"):
        response = await server.client.get(f"/static/js/{name}.js")
        assert response.status_code == 200, name
        source = response.text.replace("./common.js", "./common.mjs").replace("./state.js", "./state.mjs")
        (tmp_path / f"{name}.mjs").write_text(source)
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
""" % json.dumps((tmp_path / "nav-counts.mjs").as_uri())
    assert NODE is not None
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True).stdout)
    assert out["first"] == {
        "#clients-count": "25", "#users-count": "10", "#mieru-count": "10", "#naive-count": "7",
        "#amneziawg-count": "0", "#trusttunnel-count": "3", "#fleet-count": "4",
    }
    assert out["clientsWhenDown"] == "—"
    assert out["usersWhenClientsDown"] == "10"
