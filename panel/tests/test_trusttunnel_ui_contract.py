"""The TrustTunnel screen and every protocol map that learned about it (v1.6).

Static contract: the wiring a browser cannot be asked about in a unit test. The pure placement
module is also exercised in Node, as shipped.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "panel" / "static"
JS = STATIC / "js"
NODE = shutil.which("node")


def read(name: str) -> str:
    return (JS / name).read_text(encoding="utf-8")


def test_screen_module_reads_the_overview_and_creates_through_the_grant_api():
    source = read("trusttunnel.js")
    assert "/api/trusttunnel/overview" in source
    for export in ("renderTrusttunnel", "bindTrusttunnel", "handleTrusttunnelClick", "openTtModal"):
        assert f"export function {export}" in source or f"export async function {export}" in source
    # an access is a grant: the screen creates it through the clients' API, never its own route
    assert 'protocol: "trusttunnel"' in source and "/grants" in source
    assert "/api/trusttunnel/" not in source.replace("/api/trusttunnel/overview", "")
    for state in ("down", "pending", "certificate_trusted"):
        assert state in source


def test_main_wires_the_screen_behind_the_feature_flag():
    main = read("main.js")
    assert 'from "./trusttunnel.js"' in main
    assert "trusttunnel: renderTrusttunnel" in main
    assert 'trusttunnel: ["TrustTunnel"' in main
    assert 'trusttunnel: "TrustTunnel доступ"' in main
    assert "openTtModal(context)" in main and "bindTrusttunnel(context)" in main
    assert "handleTrusttunnelClick(context, button)" in main
    assert "me.features?.trusttunnel !== true" in main
    assert '"trusttunnel"' in main.split("const canCreate")[1].split(";")[0]


def test_index_has_hidden_nav_items_and_the_create_modal():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert html.count('data-view="trusttunnel" hidden') == 2  # sidebar and mobile nav
    assert 'id="trusttunnel-count"' in html
    for ident in ("tt-modal", "tt-form", "tt-client", "tt-name", "create-tt", "tt-error"):
        assert f'id="{ident}"' in html, ident


def test_every_protocol_map_knows_trusttunnel():
    for name in ("placement.js", "grant.js", "access.js", "subscriptions.js", "nodes.js"):
        assert "trusttunnel" in read(name), name
    assert 'PROTOCOLS = ["mtproxy", "naive", "mieru", "trusttunnel"]' in read("placement.js")
    assert "trusttunnel: 4" in read("clients.js")
    assert 'ROTATION_REQUIRED = new Set(["mieru"])' in read("clients.js")
    nodes = read("nodes.js")
    assert '["trusttunnel", "TrustTunnel"]' in nodes
    # the manager is not a version-agent component
    assert "trusttunnel" not in nodes.split("const COMPONENT_NAMES")[1].split("\n")[0].lower()
    dashboard = read("dashboard.js")
    assert "#trusttunnel-count" in dashboard and "protocols?.trusttunnel" in dashboard and "ttReady" in dashboard


def test_grant_window_shows_the_link_qr_and_the_toml():
    grant = read("grant.js")
    assert "tt:\\/\\/" in grant or "tt://" in grant
    assert "trusttunnel_toml" in grant
    assert "Скачать .toml" in grant and "application/toml" in grant
    assert "TrustTunnel — только TCP/HTTP2" in grant
    assert "LANE_PROTOCOLS = new Set([\"naive\", \"mieru\"])" in grant  # no lanes for TrustTunnel
    bundle = read("access.js")
    assert "application/toml" in bundle


def test_subscription_texts_say_what_trusttunnel_gets_in_each_format():
    source = read("subscriptions.js")
    assert 'SUBSCRIBABLE = new Set(["naive", "mieru", "trusttunnel"])' in source
    assert "у sing-box нет исходящего TrustTunnel" in source
    assert "tt://" in source


def test_style_has_the_screen_block_without_horizontal_scroll():
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    assert ".tt-overview" in css and ".tt-toml" in css


def test_every_new_russian_string_is_in_the_english_dictionary():
    en = json.loads((STATIC / "i18n" / "en.json").read_text(encoding="utf-8"))
    for key in (
        "TrustTunnel доступ", "Новый TrustTunnel-доступ", "Менеджер TrustTunnel",
        "Скачать .toml", "Доступов TrustTunnel пока нет",
    ):
        assert key in en, key


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_placement_has_a_fixed_trusttunnel_column_that_issues_plain_grants():
    tmp = Path(tempfile.mkdtemp())
    shutil.copy(JS / "common.js", tmp / "common.mjs")
    (tmp / "placement.mjs").write_text((JS / "placement.js").read_text().replace("./common.js", "./common.mjs"))
    code = (
        f'import * as p from {json.dumps((tmp / "placement.mjs").as_uri())};'
        'const nodes=[{node_id:"local",display_name:"s",transport:"local"}];'
        'const rows=p.placementRows(nodes,[]);'
        'const diff=p.placementDiff(rows,new Set(["local:trusttunnel"]),"alice");'
        'console.log(JSON.stringify({cols:p.columnsFor(rows).map(c=>c.key),diff,name:p.columnName({protocol:"trusttunnel",version:null})}));'
    )
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True).stdout)
    assert out["cols"] == ["mtproxy", "naive", "mieru", "trusttunnel"]
    assert out["diff"]["create"] == [{"protocol": "trusttunnel", "node_id": "local", "runtime_username": "alice", "options": {}}]
    assert out["name"] == "TrustTunnel"
