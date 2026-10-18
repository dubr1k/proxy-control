"""The monitoring screen (Proxy Control 2.0): «Мониторинг» is in the navigation for every role,
the three modules export what the plan names, nothing in them or in the templates would be
dropped by the CSP (`style-src 'self'`), every Russian string has an English line, and the pure
parts of the charts library (units, ticks, gaps) and of the live feed (back-off) behave."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parent.parent / "static"
JS = STATIC / "js"
INDEX = (STATIC / "index.html").read_text()
MAIN = (JS / "main.js").read_text()
CHARTS = (JS / "charts.js").read_text()
LIVE = (JS / "live.js").read_text()
MONITORING = (JS / "monitoring.js").read_text()
CSS = (STATIC / "style.css").read_text()
NODE = shutil.which("node")


def test_the_three_modules_export_the_names_the_plan_promises():
    for name in ("lineChart", "areaChart", "stackedAreaChart", "barChart", "gaugeRing", "sparkline", "formatRate", "formatBytes"):
        assert re.search(rf"export (async )?function {name}\b", CHARTS), name
    assert re.search(r"export function connectLive\(context, node, onSnapshot, onState\)", LIVE)
    assert "export async function renderMonitoring" in MONITORING
    assert "export function bindMonitoring" in MONITORING


def test_the_section_is_in_both_menus_and_in_the_router_for_every_role():
    for pattern in (r'class="nav-item" data-view="monitoring"', r'<button data-view="monitoring"'):
        assert re.search(pattern, INDEX), pattern
    # visible to everyone: no owner-only / hidden marker on the monitoring buttons
    for line in INDEX.splitlines():
        if 'data-view="monitoring"' in line:
            assert "owner-only" not in line and " hidden" not in line
    assert 'monitoring: ["Мониторинг", "Ресурсы и трафик в прямом эфире, по протоколам и узлам"]' in MAIN
    assert "monitoring: renderMonitoring" in MAIN
    assert "bindMonitoring(context)" in MAIN
    # after «Обзор», before «Клиенты» in the sidebar
    side = INDEX[INDEX.index('<nav aria-label="Основная навигация">'):]
    assert side.index('data-view="dashboard"') < side.index('data-view="monitoring"') < side.index('data-view="clients"')


def test_the_overview_resource_card_links_to_the_monitoring_screen():
    dashboard = (JS / "dashboard.js").read_text()
    assert 'href="#monitoring"' in dashboard and "Подробнее в мониторинге" in dashboard


@pytest.mark.parametrize("name", ["charts.js", "live.js", "monitoring.js"])
def test_nothing_the_csp_would_drop_is_written_into_markup(name):
    source = (JS / name).read_text()
    # an inline style ATTRIBUTE in a template or via setAttribute is blocked by style-src 'self';
    # the CSSOM (`element.style.width = …`) is allowed and is what the module uses
    assert not re.search(r"""<[a-z][^>]*\sstyle\s*=""", source), name
    assert "setAttribute(\"style\"" not in source and "setAttribute('style'" not in source, name
    assert "<script" not in source and "javascript:" not in source and "eval(" not in source, name
    assert "<style" not in source, name
    stripped = source.replace("http://www.w3.org/2000/svg", "")
    assert "http://" not in stripped and "https://" not in stripped, name


def test_the_monitoring_markup_in_index_has_no_inline_style():
    for line in INDEX.splitlines():
        if "monitoring" in line:
            assert " style=" not in line


def test_charts_use_tokens_for_both_themes_and_a_fixed_colour_per_protocol():
    for token in ("--chart-1", "--chart-8", "--chart-grid", "--chart-axis"):
        assert CSS.count(token + ":") >= 2, f"{token} must be defined for dark and light"
    # the protocol colours are aliases of the categorical slots, so they follow the theme
    for number, proto in enumerate(("mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"), start=1):
        assert f"--proto-{proto}:var(--chart-{number})" in CSS
    assert ':root[data-theme="light"]' in CSS
    for proto in ("mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"):
        assert f".ser-{proto}{{--c:var(--proto-{proto})}}" in CSS
    assert "prefers-reduced-motion" in CSS[CSS.index("Мониторинг (2.0)"):]


def test_charts_are_accessible_and_keyboard_driven():
    assert 'role: "img"' in CHARTS and 'tabindex: "0"' in CHARTS
    assert "aria-label" in CHARTS and "chart-sr" in CHARTS and "aria-live" in CHARTS
    for key in ("ArrowLeft", "ArrowRight", "Home", "End", "Escape"):
        assert f'"{key}"' in CHARTS, key
    assert "ResizeObserver" in CHARTS and "pointermove" in CHARTS


def test_the_live_feed_has_its_fallbacks_and_pauses():
    assert "EventSource" in LIVE and "/api/metrics/stream?node=" in LIVE and "/api/metrics/live?node=" in LIVE
    for state in ('"live"', '"polling"', '"reconnecting"', '"paused"'):
        assert state in LIVE
    assert "visibilitychange" in LIVE and "requestAnimationFrame" in LIVE
    assert "HIDDEN_PAUSE_MS = 60_000" in LIVE and "POLL_MS = 3000" in LIVE
    assert "navigationGeneration" in LIVE  # closes itself when the operator leaves the screen
    assert "context.live?.close()" in LIVE  # one connection per screen


def test_every_russian_string_of_the_screen_has_an_english_line():
    translated = json.loads((STATIC / "i18n/en.json").read_text())
    for fragment in ("Мониторинг", "Сейчас", "Трафик", "Узлы", "в эфире", "Пауза", "Продолжить", "Контейнеры",
                     "Активные клиенты", "Сравнение узлов", "Подробнее в мониторинге", "МБ/с", "Б/с"):
        assert fragment in translated or fragment in ("Сейчас", "Трафик", "Узлы", "Пауза", "Продолжить"), fragment
    script = Path(__file__).resolve().parents[2] / "scripts/dev/i18n-strings.py"
    result = subprocess.run(["python3", str(script), "--missing"], capture_output=True, text=True, check=True)
    assert "# 0 fragments" in result.stdout + result.stderr


CHARTS_HARNESS = r"""
import * as charts from "./charts.mjs";
import * as live from "./live.mjs";

class Node {
  constructor(tag) { this.tagName = tag; this.children = []; this.attributes = {}; this.className = ""; this.style = {}; this.innerHTML = ""; this.textContent = ""; this.hidden = false; this.clientWidth = 320; this.listeners = {}; }
  append(child) { this.children.push(child); child.parent = this; }
  remove() {}
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name]; }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  getBoundingClientRect() { return { left: 0, width: 320 }; }
}
globalThis.document = { documentElement: { lang: "ru" }, createElement: (tag) => new Node(tag), createElementNS: (_, tag) => new Node(tag), activeElement: null };
globalThis.window = globalThis;

const out = {};
out.rate = [0, 1, 1023, 1024, 1536, 5 * 1024 * 1024, 2.5 * 1024 ** 3, null].map((value) => charts.formatRate(value));
out.bytes = [0, 999, 2048, 10 * 1024 ** 2, 3 * 1024 ** 4].map((value) => charts.formatBytes(value));
out.percent = [0, 4.26, 55.5, null].map((value) => charts.formatPercent(value));
out.rateTicks = charts.rateTicks(7.3 * 1024 * 1024);
out.zeroTicks = charts.rateTicks(0);
out.nice = charts.niceTicks(87, 4);
out.segments = charts.splitSegments([0, 1, 2, 3, 4, 5, 6], [1, 2, null, 4, 5, 6, 7], 1.5);
out.holeSegments = charts.splitSegments([0, 1, 2, 10, 11], [1, 1, 1, 1, 1], 3);
out.gap = charts.defaultGap([0, 2, 4, 6, 8]);
out.time = charts.timeTicks(0, 600, 6, 0);
out.align = charts.alignSeries({ a: [[1, 10, 12], [3, 30, 33]], b: [[2, 5, 6]] });
const path = charts.monotonePath([[0, 10], [10, 0], [20, 0], [30, 10]]);
out.monotone = { path, below: /C[^M]*-\d/.test(path) };

// a sparkline with a hole in the middle must draw two separate lines, not bridge the gap
const host = new Node("div");
const spark = charts.sparkline(host, { x: [0, 2, 4, 6, 8, 10], domain: [0, 10], unit: "rate", series: [{ values: [1, 2, null, null, 5, 6], cls: "ser-mtproxy" }] });
const svg = host.children[0].children[0];
out.sparkLines = (svg.innerHTML.match(/class="chart-line /g) || []).length;
out.sparkAria = svg.attributes["aria-label"];

const chartHost = new Node("div");
const chart = charts.stackedAreaChart(chartHost, { x: [0, 2, 4, 6], domain: [0, 6], unit: "rate", label: "Трафик", series: [
  { id: "a", label: "A", cls: "ser-mtproxy", values: [1000, 2000, null, 3000] },
  { id: "b", label: "B", cls: "ser-naive", values: [500, 500, null, 500] },
] });
const root = chartHost.children[0];
out.chartRole = root.children[0].attributes.role;
out.chartTabindex = root.children[0].attributes.tabindex;
out.chartAria = root.children[0].attributes["aria-label"];
out.chartBands = (root.children[0].innerHTML.match(/class="chart-band /g) || []).length;
out.chartTable = root.children[4].innerHTML.includes("<caption>Трафик</caption>");

const gaugeHost = new Node("div");
const gauge = charts.gaugeRing(gaugeHost, { value: 93, label: "CPU" });
const gsvg = gaugeHost.children[0].children[0];
out.gauge = [gsvg.attributes.class.includes("gauge-critical"), gsvg.attributes["aria-label"].includes("критично")];

out.backoff = [0, 1, 2, 3, 4, 5, 9].map(live.backoffDelay);
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_units_ticks_gaps_and_backoff_behave_in_node():
    tmp = Path(tempfile.mkdtemp())
    shutil.copy(JS / "common.js", tmp / "common.mjs")
    (tmp / "charts.mjs").write_text(CHARTS.replace("./common.js", "./common.mjs"))
    (tmp / "live.mjs").write_text(LIVE)
    (tmp / "run.mjs").write_text(CHARTS_HARNESS)
    result = subprocess.run([NODE, str(tmp / "run.mjs")], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout.strip().splitlines()[-1])

    # rates: bytes per second, binary steps, the unit is always named; no data is a dash, never 0
    assert out["rate"] == ["0 Б/с", "1 Б/с", "1023 Б/с", "1,00 КБ/с", "1,50 КБ/с", "5,00 МБ/с", "2,50 ГБ/с", "—"]
    assert out["bytes"] == ["0 Б", "999 Б", "2,00 КБ", "10,0 МБ", "3,00 ТБ"]
    assert out["percent"] == ["0,0 %", "4,3 %", "56 %", "—"]
    # an axis for ~7.3 MB/s is scaled in MB/s, starts at 0 and covers the data
    ticks = out["rateTicks"]
    assert ticks["name"] == "МБ/с" and ticks["ticks"][0] == 0 and ticks["max"] >= 7.3 * 1024 * 1024
    assert [round(tick / 1024 / 1024, 1) for tick in ticks["ticks"]] == [0, 2, 4, 6, 8]
    assert out["zeroTicks"]["name"] == "КБ/с" and out["zeroTicks"]["ticks"][0] == 0
    assert out["nice"]["ticks"] == [0, 25, 50, 75, 100]
    # a null and a hole in time both break the line; nothing is bridged
    assert out["segments"] == [[0, 1], [3, 4, 5, 6]]
    assert out["holeSegments"] == [[0, 1, 2], [3, 4]]
    assert out["gap"] == 5
    assert out["time"] == [0, 120, 240, 360, 480, 600]
    assert out["align"] == {"x": [1, 2, 3], "series": {"a": [10, None, 30], "b": [None, 5, None]}}
    assert out["monotone"]["below"] is False  # the smooth curve never dips under the data
    # DOM output: two lines around the hole, an accessible chart with a data-table fallback
    assert out["sparkLines"] == 2
    assert "нет данных" not in out["sparkAria"] and "Б/с" in out["sparkAria"]
    assert out["chartRole"] == "img" and out["chartTabindex"] == "0"
    assert "Трафик" in out["chartAria"]
    assert out["chartBands"] == 2  # two series × the first run (the 3rd moment is a hole, the 4th alone)
    assert out["chartTable"] is True
    assert out["gauge"] == [True, True]
    assert out["backoff"] == [1000, 2000, 4000, 8000, 15000, 15000, 15000]


def test_history_primed_ring_is_not_drawn_as_gaps():
    # prefill from 60 s rollups must widen the gap threshold, or the primed minutes vanish
    assert "function ringGap(rt, ring)" in MONITORING
    assert "ring.gap = (Number(data.step) || 0) * 2.5" in MONITORING
    assert "Math.max(10, (rt.last?.interval || 2) * 5)" not in MONITORING


def test_zero_rate_translates_as_one_unit_and_the_chip_follows_stale_nodes():
    en = json.loads((STATIC / "i18n" / "en.json").read_text())
    # «0 Б» (3 chars) would otherwise win over «Б/с» and leave «0 B/since»
    assert en["0 Б/с"] == "0 B/s"
    assert 'stale: "данные устарели"' in MONITORING
    assert 'setBadge(context, "stale")' in MONITORING
    assert ".live-badge.stale" in CSS


def test_connections_replace_sessions_on_port_based_cards_and_fall_back_to_them():
    assert 'connections: parts.some((entry) => finite(entry.connections))' in MONITORING
    assert "Установленные TCP-соединения на портах протокола" in MONITORING
    en = json.loads((STATIC / "i18n" / "en.json").read_text())
    assert en["Соединений"] == "Connections"
    assert en["Установленные TCP-соединения на портах протокола"].startswith("Established TCP connections")


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_protocol_card_meta_prefers_connections_and_keeps_peer_sessions_for_amneziawg():
    source = re.search(r"function protoMeta\(entry\) \{.*?\n\}\n", MONITORING, re.S).group(0)
    script = (
        "const finite = (v) => typeof v === 'number' && Number.isFinite(v); const number = (v) => String(v);\n"
        + source
        + "\nconsole.log(JSON.stringify([protoMeta({connections: 5, sessions: 0, clients: 0}),"
          " protoMeta({connections: 0, clients: 2}), protoMeta({connections: null, sessions: 3, clients: 1}),"
          " protoMeta({connections: null, sessions: null, clients: null})]));"
    )
    tmp = Path(tempfile.mkdtemp())
    (tmp / "run.mjs").write_text(script)
    result = subprocess.run([NODE, str(tmp / "run.mjs")], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    with_conn, zero, peers, nothing = json.loads(result.stdout.strip().splitlines()[-1])
    assert "Соединений <b>5</b>" in with_conn and "Сессий" not in with_conn and "Клиентов" not in with_conn
    assert "Соединений <b>0</b>" in zero and "Клиентов <b>2</b>" in zero
    assert "Сессий <b>3</b>" in peers and "Клиентов <b>1</b>" in peers and "Соединений" not in peers
    assert "Сессий <b>—</b>" in nothing
