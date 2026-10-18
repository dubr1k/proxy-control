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
MAIN = (JS / "main.js").read_text()
DASHBOARD = (JS / "dashboard.js").read_text()
NODE = shutil.which("node")

BADGES = ("clients", "users", "mieru", "naive", "amneziawg", "trusttunnel", "fleet")


def test_every_badge_is_painted_by_the_shared_module():
    source = (JS / "nav-counts.js").read_text()
    for name in BADGES:
        # The clients badge is painted by common.js's own helper, the rest by this module.
        assert (f"#{name}-count" in source) or (name == "clients" and "paintClientsCount" in source), name
    assert "export async function refreshNavCounts" in source
    assert "export function startNavCountsRefresh" in source


def test_the_panel_paints_the_badges_before_the_first_section_not_inside_it():
    assert 'from "./nav-counts.js"' in MAIN
    initialise = MAIN[MAIN.index("async function initialise"):MAIN.index("export function boot")]
    assert "refreshNavCounts(context)" in initialise
    assert "startNavCountsRefresh(context)" in initialise
    assert initialise.index("refreshNavCounts(context)") < initialise.index("context.navigate(start")


def test_the_overview_reuses_the_shared_painter_instead_of_its_own_copy():
    assert 'from "./nav-counts.js"' in DASHBOARD
    assert "function paintNavCounts" not in DASHBOARD
    assert "function fleetCount" not in DASHBOARD


@pytest.mark.skipif(NODE is None, reason="node is not installed")
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
  "/api/clients": { items: new Array(41).fill({}) },
  "/api/fleet/nodes": { items: new Array(4).fill({}) },
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
        "#clients-count": "41", "#users-count": "10", "#mieru-count": "10", "#naive-count": "7",
        "#amneziawg-count": "0", "#trusttunnel-count": "3", "#fleet-count": "4",
    }
    assert out["clientsWhenDown"] == "—"
    assert out["usersWhenClientsDown"] == "10"
