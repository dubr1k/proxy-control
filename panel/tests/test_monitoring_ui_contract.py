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


CHARTS = (JS / "charts.js").read_text()
LIVE = (JS / "live.js").read_text()
MONITORING = (JS / "monitoring.js").read_text()

NODE = shutil.which("node")





























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
