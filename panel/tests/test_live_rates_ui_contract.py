"""«Сейчас» next to every user on the protocol pages (owner, 2026-10-19: «обнови UI тоже везде»): each page
puts one cell per user and starts the shared poller; the poller paints the monitor's own numbers and shows
nothing for a user the monitor has no fresh rate for."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

JS = Path(__file__).resolve().parent.parent / "static/js"
NODE = shutil.which("node")

# page module -> (view name, protocol, the expression that names the user in the cell)
PAGES = {
    "mieru.js": ("mieru", "mieru", "user.username"),
    "naive.js": ("naive", "naive", "user.username"),
    "trusttunnel.js": ("trusttunnel", "trusttunnel", "row.username"),
    "amneziawg.js": ("amneziawg", "amneziawg", "row.username"),
    "users.js": ("users", "mtproxy", "user.username"),
}


@pytest.mark.parametrize("module", PAGES)
def test_every_protocol_page_has_a_live_cell_per_user_and_starts_the_poller(module):
    source = (JS / module).read_text()
    view, protocol, name = PAGES[module]
    assert 'from "./live-rates.js"' in source
    assert f'<small class="live-rate" data-live-rate="${{esc({name})}}"></small>' in source
    assert f'startLiveRates(context, generation, "{view}", "{protocol}")' in source


def test_pages_that_repaint_their_list_put_the_last_numbers_back():
    for module in ("naive.js", "users.js"):
        source = (JS / module).read_text()
        assert "repaintLiveRates(context);" in source, module


def test_the_dashboard_shows_mieru_volumes_when_the_manager_has_them():
    source = (JS / "dashboard.js").read_text()
    assert "mieru.traffic?.available" in source and "С запуска mita" in source


def test_the_poller_stops_with_its_page_and_never_sends_another_pages_numbers():
    source = (JS / "live-rates.js").read_text()
    assert "state.navigationGeneration === generation && state.view === view" in source
    assert "state.liveRatesLast = null" in source and "document.hidden" in source
    assert "style=" not in source


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_the_painter_shows_split_total_and_averaged_rates_and_clears_idle_users():
    tmp = Path(tempfile.mkdtemp())
    for name in ("common", "charts", "live-rates"):
        text = (JS / f"{name}.js").read_text().replace("./common.js", "./common.mjs").replace("./charts.js", "./charts.mjs")
        (tmp / f"{name}.mjs").write_text(text)
    code = """
import * as mod from %s;
const cell = (user) => ({ dataset: { liveRate: user }, textContent: "stale", title: "" });
const cells = { alice: cell("alice"), bob: cell("bob"), idle: cell("idle"), total: cell("total"), quiet: cell("quiet") };
const root = { querySelectorAll: () => Object.values(cells) };
const clients = {
  quiet: { up_bps: 0, down_bps: 0, total_bps: 0 },
  alice: { up_bps: 2048, down_bps: 3 * 1024 * 1024, total_bps: 3 * 1024 * 1024 + 2048 },
  bob: { up_bps: null, down_bps: null, total_bps: 1024 },
  total: { up_bps: null, down_bps: null, total_bps: 5 * 1024 },
};
const context = { state: { liveRatesLast: { live: true, clients } }, ui: { view: root } };
mod.repaintLiveRates(context);
const live = Object.fromEntries(Object.entries(cells).map(([k, v]) => [k, v.textContent]));
context.state.liveRatesLast = { live: false, clients };
mod.repaintLiveRates(context);
console.log(JSON.stringify({ live, naive: cells.alice.textContent, title: cells.alice.title, quiet: cells.quiet.textContent }));
""" % json.dumps((tmp / "live-rates.mjs").as_uri())
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True).stdout)
    assert out["live"]["alice"] == "Сейчас ↓ 3,00 МБ/с · ↑ 2,00 КБ/с" or out["live"]["alice"].startswith("Сейчас ↓ 3")
    assert out["live"]["bob"].startswith("Сейчас 1") and out["live"]["total"].startswith("Сейчас 5")
    assert out["live"]["idle"] == ""  # no fresh rate: nothing, not a zero
    assert out["quiet"] == ""  # an averaged row at zero is not shown: idle and mid-transfer look alike
    assert out["naive"].startswith("За минуту ↓ 3") and "закрывается" in out["title"]
