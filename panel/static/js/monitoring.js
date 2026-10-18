// «Мониторинг» (Proxy Control 2.0): resources and traffic of the server and of the linked nodes,
// live. Three tabs — «Сейчас» (the live feed, drawn from snapshots), «Трафик» (history by
// protocol) and «Узлы» (the comparison and a drill-down per node).
//
// Honesty rules of the screen: a number that the backend did not measure is a dash, not a zero;
// a protocol without live kernel counters says so; a stale node keeps its last values, greyed,
// with their age; a gap in the history stays a gap.
import { esc, locale, number, query, queryAll } from "./common.js";
import {
  alignSeries,
  areaChart,
  barChart,
  formatBytes,
  formatPercent,
  formatRate,
  gaugeRing,
  lineChart,
  sparkline,
  stackedAreaChart,
} from "./charts.js";
import { connectLive } from "./live.js";
import { isCurrent } from "./state.js";

const PROTOCOLS = [
  ["mtproxy", "MTProxy", "MTProto · FakeTLS"],
  ["naive", "NaiveProxy", "HTTPS · HTTP/2 CONNECT"],
  ["mieru", "Mieru", "Native AEAD"],
  ["amneziawg", "AmneziaWG", "UDP · WireGuard"],
  ["trusttunnel", "TrustTunnel", "HTTP/2 · TCP"],
];
const PROTOCOL_NAME = Object.fromEntries(PROTOCOLS.map(([id, name]) => [id, name]));
const RANGES = [["15m", "15 м"], ["1h", "1 ч"], ["6h", "6 ч"], ["24h", "24 ч"], ["7d", "7 д"], ["30d", "30 д"], ["90d", "90 д"]];
const TABS = [["now", "Сейчас"], ["traffic", "Трафик"], ["nodes", "Узлы"]];
const DIRECTIONS = [["down", "↓ к клиентам"], ["up", "↑ от клиентов"], ["sum", "Σ всего"]];
const WINDOW_SECONDS = 300; // the «Сейчас» charts show the last five minutes
const RING_SECONDS = 330;
const PREFILL_SERIES = ["host.cpu", "host.mem", "host.swap", "host.disk", "host.disk_read_bps", "host.disk_write_bps", "host.load1", "net.rx_bps", "net.tx_bps"];
const ALERT_NAME = { cpu: "CPU", mem: "RAM", disk: "Диск", swap: "Swap", net_spike: "Всплеск трафика", stale: "Нет данных" };
const STORAGE_KEY = "proxy-control.monitoring";

// -- state kept between visits -----------------------------------------------------------------

function remembered() {
  try {
    return JSON.parse(window.localStorage.getItem(STORAGE_KEY) || "{}") || {};
  } catch {
    return {};
  }
}

function remember(mon) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ tab: mon.tab, node: mon.node, range: mon.range, nodesRange: mon.nodesRange, dir: mon.dir }));
  } catch {
    // a private window: the choice lasts until the tab closes
  }
}

function ensureState(context) {
  if (!context.state.monitoring) {
    const saved = remembered();
    context.state.monitoring = {
      tab: TABS.some(([id]) => id === saved.tab) ? saved.tab : "now",
      node: typeof saved.node === "string" && saved.node ? saved.node : "local",
      range: RANGES.some(([id]) => id === saved.range) ? saved.range : "24h",
      nodesRange: RANGES.some(([id]) => id === saved.nodesRange) ? saved.nodesRange : "24h",
      dir: DIRECTIONS.some(([id]) => id === saved.dir) ? saved.dir : "sum",
      nodes: [],
      drill: "",
      epoch: 0,
    };
  }
  return context.state.monitoring;
}

// Everything that has to be torn down when the screen is left or redrawn.
function newRuntime() {
  return { charts: [], rings: new Map(), tiles: {}, protoEls: {}, last: null, lastJson: {}, chartHandle: null, paused: false, badge: "connecting" };
}

function runtimeOf(context) {
  return context.monitoringRuntime;
}

function destroyCharts(rt) {
  for (const chart of rt.charts) chart?.destroy?.();
  rt.charts = [];
  rt.tiles = {};
  rt.protoEls = {};
  rt.chartHandle = null;
}

function teardown(context) {
  context.live?.close();
  const rt = runtimeOf(context);
  if (rt) destroyCharts(rt);
}

// -- small helpers -----------------------------------------------------------------------------

const finite = (value) => value !== null && value !== undefined && Number.isFinite(Number(value));
const rateText = (value) => (finite(value) ? formatRate(value) : "—");

function ageText(seconds) {
  const age = Math.max(0, Math.round(Number(seconds) || 0));
  if (age < 60) return `${age} сек`;
  if (age < 3600) return `${Math.floor(age / 60)} мин`;
  if (age < 86400) return `${Math.floor(age / 3600)} ч ${Math.floor((age % 3600) / 60)} мин`;
  return `${Math.floor(age / 86400)} сут`;
}

function clock(seconds) {
  return new Date(seconds * 1000).toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function dayTime(seconds) {
  return new Date(seconds * 1000).toLocaleString(locale(), { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

function chip(proto) {
  return `<i class="chip ser-${esc(proto)}" aria-hidden="true"></i>`;
}

// Widths come through the CSSOM: an inline style attribute is what the CSP drops.
function fillWidths(root) {
  for (const bar of root.querySelectorAll("[data-width]")) bar.style.width = `${bar.dataset.width}%`;
}

function level(percent) {
  if (!finite(percent)) return "";
  return percent >= 90 ? "critical" : percent >= 75 ? "warn" : "";
}

function bar(percent, extra = "") {
  const value = finite(percent) ? Math.max(0, Math.min(100, Number(percent))) : 0;
  return `<span class="mon-bar ${level(percent)} ${extra}" role="img" aria-label="${esc(formatPercent(percent))}"><i data-width="${value.toFixed(1)}"></i></span>`;
}

function emptyBlock(title, text) {
  return `<div class="mon-empty"><b>${esc(title)}</b>${text ? `<p>${esc(text)}</p>` : ""}</div>`;
}

// -- the ring buffer of the live feed ----------------------------------------------------------

function ringOf(rt, nodeId) {
  if (!rt.rings.has(nodeId)) rt.rings.set(nodeId, { t: [], v: {} });
  return rt.rings.get(nodeId);
}

function pushSample(ring, ts, values) {
  if (ring.t.length && ts <= ring.t[ring.t.length - 1]) return;
  const keys = new Set([...Object.keys(ring.v), ...Object.keys(values)]);
  for (const key of keys) {
    ring.v[key] ||= new Array(ring.t.length).fill(null);
    ring.v[key].push(finite(values[key]) ? Number(values[key]) : null);
  }
  ring.t.push(ts);
  while (ring.t.length && ring.t[0] < ts - RING_SECONDS) {
    ring.t.shift();
    for (const key of keys) ring.v[key].shift();
  }
}

// Every number a snapshot of one node adds to the ring, under the series ids of the history API.
function sampleValues(node) {
  const host = node.host || {};
  const values = {
    "host.cpu": host.cpu_percent,
    "host.mem": host.mem?.percent,
    "host.swap": host.swap?.total ? host.swap.percent : null,
    "host.disk": host.disk?.percent,
    "host.disk_read_bps": host.disk?.read_bps,
    "host.disk_write_bps": host.disk?.write_bps,
    "host.load1": host.load?.[0],
    "net.rx_bps": host.net?.rx_bps,
    "net.tx_bps": host.net?.tx_bps,
  };
  for (const [proto] of PROTOCOLS) {
    const entry = node.protocols?.[proto];
    const live = entry?.available && entry.live !== false;
    values[`${proto}.up_bps`] = live ? entry.up_bps : null;
    values[`${proto}.down_bps`] = live ? entry.down_bps : null;
  }
  return values;
}

function sumNodes(nodes) {
  const total = {};
  for (const node of nodes) {
    if (node.status !== "ok") continue;
    for (const [key, value] of Object.entries(sampleValues(node))) {
      if (!key.endsWith("_bps") || !finite(value)) continue;
      total[key] = (total[key] || 0) + Number(value);
    }
  }
  return total;
}

function mergeProtocols(nodes) {
  const merged = {};
  for (const [proto] of PROTOCOLS) {
    const parts = nodes.filter((node) => node.status === "ok").map((node) => node.protocols?.[proto]).filter((entry) => entry?.available);
    if (!parts.length) {
      merged[proto] = { available: false };
      continue;
    }
    const live = parts.filter((entry) => entry.live !== false);
    const add = (key, list) => list.reduce((sum, entry) => sum + (finite(entry[key]) ? Number(entry[key]) : 0), 0);
    merged[proto] = {
      available: true,
      live: live.length > 0,
      source: live.length === parts.length ? "ядро" : "ядро и менеджер",
      partial: live.length > 0 && live.length < parts.length,
      up_bps: live.length ? add("up_bps", live) : null,
      down_bps: live.length ? add("down_bps", live) : null,
      up_bytes: add("up_bytes", parts),
      down_bytes: add("down_bytes", parts),
      sessions: add("sessions", parts),
      clients: add("clients", parts),
    };
  }
  return merged;
}

// -- shell: tabs, toolbar ----------------------------------------------------------------------

function tabsHtml(mon) {
  return `<div class="mon-tabs" role="tablist" aria-label="Разделы мониторинга">${TABS.map(([id, name]) => (
    `<button type="button" role="tab" class="${mon.tab === id ? "active" : ""}" aria-selected="${mon.tab === id}" data-mon-tab="${id}">${name}</button>`
  )).join("")}</div>`;
}

function nodeOptions(mon, { all }) {
  const nodes = mon.nodes.length ? mon.nodes : [{ node_id: "local", name: "Этот сервер" }];
  const options = nodes.map((node) => `<option value="${esc(node.node_id)}"${node.node_id === mon.node ? " selected" : ""}>${esc(node.name || node.node_id)}${node.status && node.status !== "ok" ? ` · ${node.status === "stale" ? "нет данных" : "недоступен"}` : ""}</option>`);
  if (all && nodes.length > 1) options.unshift(`<option value="all"${mon.node === "all" ? " selected" : ""}>Все узлы</option>`);
  return options.join("");
}

function nodeField(mon, all) {
  return `<label class="mon-field"><span>Узел</span><select data-mon-node aria-label="Узел">${nodeOptions(mon, { all })}</select></label>`;
}

function segmented(items, current, attribute, label) {
  return `<div class="mon-seg" role="group" aria-label="${esc(label)}">${items.map(([id, name]) => (
    `<button type="button" class="${current === id ? "active" : ""}" aria-pressed="${current === id}" data-${attribute}="${id}">${esc(name)}</button>`
  )).join("")}</div>`;
}

function paintSegmented(root, attribute, current) {
  for (const button of queryAll(`[data-${attribute}]`, root)) {
    const on = button.dataset[attribute.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] === current;
    button.classList.toggle("active", on);
    button.setAttribute("aria-pressed", String(on));
  }
}

function pickNodeNames(mon, snapshot) {
  const known = (snapshot.nodes || []).map((node) => ({ node_id: node.node_id, name: node.name || node.node_id, status: node.status }));
  if (known.length) mon.nodes = known;
}

// -- «Сейчас» ----------------------------------------------------------------------------------

const TILES = [
  { id: "cpu", title: "CPU" },
  { id: "mem", title: "Память" },
  { id: "disk", title: "Диск" },
  { id: "net", title: "Сеть" },
  { id: "load", title: "Нагрузка" },
];

function tileHtml(tile) {
  const gauge = tile.id === "net" ? "" : '<div class="tile-gauge" data-gauge></div>';
  return `<article class="mon-tile mon-tile-${tile.id}" data-tile="${tile.id}">
    <header><h3>${tile.title}</h3><small data-sub></small></header>
    <div class="tile-main">${gauge}<div class="tile-figures" data-figures></div></div>
    <div class="tile-spark" data-spark></div>
    <small class="tile-foot" data-foot></small>
  </article>`;
}

function protoCardHtml([id, name]) {
  return `<article class="mon-proto ser-${id}" data-proto="${id}">
    <header><i class="chip ser-${id}" aria-hidden="true"></i><h3>${name}</h3></header>
    <div class="proto-body" data-proto-body></div>
    <div class="tile-spark" data-spark></div>
    <small class="tile-foot" data-foot></small>
  </article>`;
}

function nowShell(mon) {
  return `<div class="mon-toolbar">
      ${nodeField(mon, true)}
      <span class="live-badge connecting" data-live-badge role="status"><i></i><b>подключение…</b></span>
      <span class="mon-stamp" data-stamp></span>
      <button type="button" class="secondary mon-pause" data-mon-pause>Пауза</button>
    </div>
    <div class="mon-banner" data-banner hidden></div>
    <div class="mon-live" data-live-content>
      <section class="mon-tiles" data-tiles aria-label="Ресурсы сервера">${TILES.map(tileHtml).join("")}</section>
      <section class="mon-nodes-strip" data-strip hidden></section>
      <section class="mon-protos" aria-label="Трафик по протоколам">${PROTOCOLS.map(protoCardHtml).join("")}</section>
      <section class="panel-card mon-card">
        <div class="mon-card-head"><div><h2>Трафик по протоколам · последние 5 минут</h2><small>Сетевой трафик по счётчикам ядра, с заголовками пакетов</small></div>
          ${segmented(DIRECTIONS, mon.dir, "mon-dir", "Направление")}</div>
        <div class="mon-chart" data-chart-now></div>
      </section>
      <div class="mon-two">
        <section class="panel-card mon-card"><div class="mon-card-head"><div><h2>Активные клиенты</h2><small>Топ по скорости сейчас</small></div></div><div data-clients></div></section>
        <section class="panel-card mon-card" data-containers-card><div class="mon-card-head"><div><h2>Контейнеры</h2><small>CPU и память по cgroup</small></div></div><div data-containers></div></section>
      </div>
      <p class="mon-note">↑ — от клиентов к серверу, ↓ — от сервера к клиентам. Скорости — сетевой трафик (с заголовками пакетов), а не байты приложений; единицы — байты в секунду (в КБ 1024 Б).</p>
    </div>`;
}

function setBadge(context, state, detail = {}) {
  const rt = runtimeOf(context);
  const badge = query("[data-live-badge]", context.ui.view);
  if (!badge || !rt) return;
  rt.badge = state;
  const text = {
    live: "в эфире",
    polling: "в эфире · опрос раз в 3 с",
    reconnecting: `нет связи · повтор через ${Math.max(1, Math.round((detail.retryInMs || 1000) / 1000))} сек`,
    paused: detail.reason === "hidden" ? "пауза · вкладка была скрыта" : "пауза",
    connecting: "подключение…",
  }[state] || state;
  badge.className = `live-badge ${state}`;
  query("b", badge).textContent = text;
  const pause = query("[data-mon-pause]", context.ui.view);
  if (pause) {
    const paused = state === "paused";
    pause.textContent = paused ? "Продолжить" : "Пауза";
    pause.setAttribute("aria-pressed", String(paused));
  }
}

function ensureTile(rt, root, id) {
  if (rt.tiles[id]) return rt.tiles[id];
  const element = query(`[data-tile="${id}"]`, root);
  const tile = { element, gauge: null, spark: null };
  if (query("[data-gauge]", element)) tile.gauge = gaugeRing(query("[data-gauge]", element), { value: null, label: query("h3", element).textContent });
  tile.spark = sparkline(query("[data-spark]", element), { x: [], series: [], height: 34, label: query("h3", element).textContent });
  rt.charts.push(tile.gauge, tile.spark);
  rt.tiles[id] = tile;
  return tile;
}

function setText(element, selector, text) {
  const target = query(selector, element);
  if (target && target.textContent !== text) target.textContent = text;
}

function setHtmlIfChanged(rt, key, element, html) {
  if (rt.lastJson[key] === html) return;
  rt.lastJson[key] = html;
  element.innerHTML = html;
  fillWidths(element);
}

function windowOf(ring) {
  const end = ring.t.length ? ring.t[ring.t.length - 1] : Date.now() / 1000;
  return { x: ring.t, domain: [end - WINDOW_SECONDS, end] };
}

function paintTiles(context, node, ring, single) {
  const rt = runtimeOf(context);
  const root = context.ui.view;
  const host = node?.host;
  const win = windowOf(ring);
  const gap = Math.max(10, (rt.last?.interval || 2) * 5);
  const spark = (id, series, unit, extra = {}) => {
    const tile = ensureTile(rt, root, id);
    tile.spark.update({ x: win.x, domain: win.domain, series, unit, gap, ...extra });
  };
  const fig = (id, html) => {
    const tile = ensureTile(rt, root, id);
    setHtmlIfChanged(rt, `fig-${id}`, query("[data-figures]", tile.element), html);
  };
  const gauge = (id, value) => ensureTile(rt, root, id).gauge?.update({ value });
  const foot = (id, text) => setText(ensureTile(rt, root, id).element, "[data-foot]", text);
  const sub = (id, text) => setText(ensureTile(rt, root, id).element, "[data-sub]", text);
  if (!single || !host) return;

  const cpu = host.cpu_percent;
  gauge("cpu", cpu);
  fig("cpu", `<b>${finite(cpu) ? formatPercent(cpu) : "—"}</b><small>занято</small>`);
  sub("cpu", finite(host.cores) ? `Ядер: ${host.cores}` : "");
  spark("cpu", [{ values: ring.v["host.cpu"] || [], cls: "ser-tile" }], "percent", { yMax: "auto" });
  foot("cpu", "Последние 5 минут");

  const mem = host.mem || {};
  gauge("mem", mem.percent);
  fig("mem", `<b>${finite(mem.percent) ? formatPercent(mem.percent) : "—"}</b><small>${finite(mem.used) ? `${formatBytes(mem.used)} из ${formatBytes(mem.total)}` : ""}</small>`);
  sub("mem", "");
  spark("mem", [{ values: ring.v["host.mem"] || [], cls: "ser-tile" }], "percent", { yMax: "auto" });
  const swap = host.swap || {};
  const swapText = swap.total ? `Swap ${formatPercent(swap.percent)} · ${formatBytes(swap.used)} из ${formatBytes(swap.total)}` : "Swap выключен";
  foot("mem", `${finite(mem.available) ? `Доступно ${formatBytes(mem.available)} · ` : ""}${swapText}`);

  const disk = host.disk || {};
  gauge("disk", disk.percent);
  fig("disk", `<b>${finite(disk.percent) ? formatPercent(disk.percent) : "—"}</b><small>${finite(disk.used) ? `${formatBytes(disk.used)} из ${formatBytes(disk.total)}` : ""}</small>`);
  sub("disk", "Корень");
  spark("disk", [
    { values: ring.v["host.disk_write_bps"] || [], cls: "ser-tile" },
    { values: ring.v["host.disk_read_bps"] || [], cls: "ser-tile-2", dash: true, noArea: true },
  ], "rate");
  foot("disk", `Запись ${rateText(disk.write_bps)} · чтение ${rateText(disk.read_bps)}${finite(disk.busy_percent) ? ` · занят ${formatPercent(disk.busy_percent)}` : ""}`);

  const net = host.net || {};
  fig("net", `<div class="net-pair"><span><small>↓ отдача</small><b>${rateText(net.tx_bps)}</b></span><span><small>↑ приём</small><b>${rateText(net.rx_bps)}</b></span></div>`);
  sub("net", "Все интерфейсы");
  spark("net", [
    { values: ring.v["net.tx_bps"] || [], cls: "ser-tile" },
    { values: ring.v["net.rx_bps"] || [], cls: "ser-tile-2", dash: true, noArea: true },
  ], "rate");
  foot("net", "Сплошная — отдача, пунктир — приём");

  const load = host.load || [];
  const perCore = finite(load[0]) && host.cores ? (load[0] / host.cores) * 100 : null;
  gauge("load", perCore === null ? null : Math.min(100, perCore));
  fig("load", `<b>${finite(load[0]) ? load[0].toFixed(2) : "—"}</b><small>1 · 5 · 15 мин: ${load.map((value) => (finite(value) ? Number(value).toFixed(2) : "—")).join(" · ")}</small>`);
  sub("load", "Load average");
  spark("load", [{ values: ring.v["host.load1"] || [], cls: "ser-tile" }], "load");
  foot("load", host.cores ? `Кольцо — доля от числа ядер (${host.cores})` : "");
}

function paintStrip(context, nodes) {
  const rt = runtimeOf(context);
  const strip = query("[data-strip]", context.ui.view);
  const rows = nodes.map((node) => {
    if (node.status === "unsupported" || node.status === "unavailable") {
      return `<article class="mon-strip-node muted"><b>${esc(node.name || node.node_id)}</b><small>${node.status === "unsupported" ? "не поддерживает мониторинг" : "недоступен"}</small></article>`;
    }
    const host = node.host || {};
    const stale = node.status === "stale";
    const meter = (label, value) => `<span><small>${label}</small>${bar(value)}<b>${finite(value) ? formatPercent(value) : "—"}</b></span>`;
    return `<article class="mon-strip-node${stale ? " is-stale" : ""}">
      <header><b>${esc(node.name || node.node_id)}</b>${stale ? `<em class="mon-pill warn">данные устарели · ${esc(ageText(node.age_seconds))}</em>` : '<em class="mon-pill ok">в сети</em>'}</header>
      <div class="strip-meters">${meter("CPU", host.cpu_percent)}${meter("RAM", host.mem?.percent)}${meter("Диск", host.disk?.percent)}</div>
      <small>↓ ${rateText(host.net?.tx_bps)} · ↑ ${rateText(host.net?.rx_bps)}</small>
    </article>`;
  }).join("");
  setHtmlIfChanged(rt, "strip", strip, rows);
}

function paintProtocols(context, protocols, ring, single) {
  const rt = runtimeOf(context);
  const win = windowOf(ring);
  const gap = Math.max(10, (rt.last?.interval || 2) * 5);
  for (const [proto, name] of PROTOCOLS) {
    const card = query(`[data-proto="${proto}"]`, context.ui.view);
    const entry = protocols[proto] || { available: false };
    const body = query("[data-proto-body]", card);
    const spark = query("[data-spark]", card);
    card.classList.toggle("is-off", !entry.available);
    card.classList.toggle("not-live", Boolean(entry.available && !entry.live));
    if (!entry.available) {
      setHtmlIfChanged(rt, `proto-${proto}`, body, `<p class="proto-off">Не включён${single ? " на этом узле" : " ни на одном узле"}</p>`);
      spark.hidden = true;
      setText(card, "[data-foot]", "");
      continue;
    }
    if (!entry.live) {
      setHtmlIfChanged(rt, `proto-${proto}`, body, `<p class="proto-off">Счётчики не в реальном времени</p>
        <div class="proto-totals"><span><small>↓ всего</small><b>${formatBytes(entry.down_bytes)}</b></span><span><small>↑ всего</small><b>${formatBytes(entry.up_bytes)}</b></span></div>`);
      spark.hidden = true;
      setText(card, "[data-foot]", "Источник: менеджер протокола · обновляется раз в минуту и реже");
      continue;
    }
    spark.hidden = false;
    setHtmlIfChanged(rt, `proto-${proto}`, body, `<div class="proto-rates">
        <span><small>↓ к клиентам</small><b>${rateText(entry.down_bps)}</b></span>
        <span><small>↑ от клиентов</small><b>${rateText(entry.up_bps)}</b></span></div>
      <div class="proto-meta"><span>Сессий <b>${finite(entry.sessions) ? number(entry.sessions) : "—"}</b></span><span>Клиентов <b>${finite(entry.clients) ? number(entry.clients) : "—"}</b></span></div>`);
    if (!rt.protoEls[proto]) {
      rt.protoEls[proto] = sparkline(spark, { x: [], series: [], height: 36, label: name, unit: "rate" });
      rt.charts.push(rt.protoEls[proto]);
    }
    rt.protoEls[proto].update({
      x: win.x,
      domain: win.domain,
      gap,
      unit: "rate",
      series: [
        { values: ring.v[`${proto}.down_bps`] || [], cls: `ser-${proto}`, label: "↓" },
        { values: ring.v[`${proto}.up_bps`] || [], cls: `ser-${proto}`, dash: true, noArea: true, label: "↑" },
      ],
    });
    setText(card, "[data-foot]", `Источник: ${entry.partial ? "ядро и менеджер" : entry.source === "manager" ? "менеджер" : "ядро"}${entry.partial ? " · часть узлов без счётчиков ядра" : ""}`);
  }
}

function directionValues(ring, proto, dir) {
  const up = ring.v[`${proto}.up_bps`] || [];
  const down = ring.v[`${proto}.down_bps`] || [];
  if (dir === "up") return up;
  if (dir === "down") return down;
  return up.map((value, index) => (finite(value) || finite(down[index]) ? (finite(value) ? Number(value) : 0) + (finite(down[index]) ? Number(down[index]) : 0) : null));
}

function paintChartNow(context, protocols, ring) {
  const rt = runtimeOf(context);
  const mon = ensureState(context);
  const host = query("[data-chart-now]", context.ui.view);
  const win = windowOf(ring);
  const list = PROTOCOLS
    .filter(([proto]) => protocols[proto]?.available && protocols[proto].live)
    .map(([proto, name]) => ({ id: proto, label: name, cls: `ser-${proto}`, values: directionValues(ring, proto, mon.dir) }));
  const options = { x: ring.t, domain: win.domain, series: list, unit: "rate", height: 230, gap: Math.max(10, (rt.last?.interval || 2) * 5), label: "Трафик по протоколам за последние 5 минут", legend: true };
  if (!list.length) {
    host.innerHTML = emptyBlock("Нет протоколов с данными в реальном времени", "Счётчики ядра недоступны или протоколы выключены.");
    rt.chartHandle = null;
    return;
  }
  if (!rt.chartHandle || !host.querySelector(".chart")) {
    host.innerHTML = "";
    rt.chartHandle = stackedAreaChart(host, options);
    rt.charts.push(rt.chartHandle);
  } else {
    rt.chartHandle.update(options);
  }
}

function clientsHtml(clients, nodesNote) {
  if (!clients.length) return emptyBlock("Сейчас никто не передаёт трафик", "Появятся активные клиенты — они будут здесь.");
  const top = Math.max(...clients.map((row) => Number(row.total_bps) || 0), 1);
  return `<div class="mon-table-wrap"><table class="mon-table mon-clients"><thead><tr><th>Клиент</th><th>Протокол</th><th class="num">↓</th><th class="num">↑</th><th class="num">Σ</th></tr></thead><tbody>${clients.map((row) => (
    `<tr><td data-label="Клиент"><span class="cellv"><b>${esc(row.client_name || row.username)}</b>${row.node_name ? `<small>${esc(row.node_name)}</small>` : ""}</span></td>
      <td data-label="Протокол"><span class="cellv">${chip(row.protocol)}${esc(PROTOCOL_NAME[row.protocol] || row.protocol)}</span></td>
      <td class="num" data-label="↓"><span class="cellv">${row.down_bps === null || row.down_bps === undefined ? '<span class="muted" title="Протокол отдаёт только суммарный счётчик">—</span>' : rateText(row.down_bps)}</span></td>
      <td class="num" data-label="↑"><span class="cellv">${row.up_bps === null || row.up_bps === undefined ? '<span class="muted" title="Протокол отдаёт только суммарный счётчик">—</span>' : rateText(row.up_bps)}</span></td>
      <td class="num" data-label="Σ"><span class="cellv"><span class="num-bar"><b>${rateText(row.total_bps)}</b><span class="mini-bar"><i data-width="${Math.max(2, ((Number(row.total_bps) || 0) / top) * 100).toFixed(1)}"></i></span></span></span></td></tr>`
  )).join("")}</tbody></table></div>${nodesNote || ""}`;
}

function containersHtml(containers, memTotal) {
  if (!containers?.length) return emptyBlock("Нет данных о контейнерах", "Агент не вернул статистику cgroup.");
  const rows = [...containers].sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0));
  return `<div class="mon-table-wrap"><table class="mon-table"><thead><tr><th>Контейнер</th><th class="num">CPU</th><th class="num">Память</th></tr></thead><tbody>${rows.map((row) => (
    `<tr><td data-label="Контейнер"><span class="cellv"><b>${esc(row.name)}</b></span></td>
      <td class="num" data-label="CPU"><span class="cellv"><span class="num-bar"><b>${formatPercent(row.cpu_percent)}</b>${bar(Math.min(100, row.cpu_percent), "thin")}</span></span></td>
      <td class="num" data-label="Память"><span class="cellv"><span class="num-bar"><b>${formatBytes(row.mem_bytes)}</b>${bar(memTotal ? (row.mem_bytes / memTotal) * 100 : 0, "thin")}</span></span></td></tr>`
  )).join("")}</tbody></table></div>`;
}

function paintNow(context, snapshot) {
  const mon = ensureState(context);
  const rt = runtimeOf(context);
  const root = context.ui.view;
  if (!query("[data-live-content]", root)) return;
  rt.last = snapshot;
  pickNodeNames(mon, snapshot);
  const all = mon.node === "all";
  const nodes = snapshot.nodes || [];
  const banner = query("[data-banner]", root);
  const content = query("[data-live-content]", root);
  setText(root, "[data-stamp]", `обновлено ${clock(snapshot.ts)} · шаг ${snapshot.interval || 2} сек`);

  let node = null;
  if (!all) {
    node = nodes.find((entry) => entry.node_id === mon.node) || nodes[0];
    if (!node) return;
    if (node.status === "unsupported" || node.status === "unavailable") {
      banner.hidden = false;
      banner.className = "mon-banner error";
      banner.textContent = node.status === "unsupported"
        ? "Этот узел не поддерживает мониторинг: обновите панель на узле до версии 2.0."
        : "Узел сейчас недоступен — данных нет. Как только связь вернётся, они появятся здесь.";
      content.hidden = true;
      return;
    }
    content.hidden = false;
    const stale = node.status === "stale";
    content.classList.toggle("is-stale", stale);
    banner.hidden = !stale;
    banner.className = "mon-banner warn";
    if (stale) banner.innerHTML = `<b>Данные узла устарели</b> · последний замер ${esc(ageText(node.age_seconds))} назад. <span>Показаны последние известные значения — они не обновляются.</span>`;
  } else {
    content.hidden = false;
    content.classList.remove("is-stale");
    const stale = nodes.filter((entry) => entry.status !== "ok");
    banner.hidden = stale.length === 0;
    banner.className = "mon-banner warn";
    if (stale.length) banner.textContent = `Суммы без узлов: ${stale.map((entry) => entry.name || entry.node_id).join(", ")} — нет свежих данных.`;
  }

  // the ring that feeds the charts
  if (all) {
    pushSample(ringOf(rt, "all"), snapshot.ts, sumNodes(nodes));
  } else if (node && node.status === "ok") {
    pushSample(ringOf(rt, node.node_id), snapshot.ts, sampleValues(node));
  }
  const ring = ringOf(rt, all ? "all" : node.node_id);

  query("[data-tiles]", root).hidden = all;
  query("[data-strip]", root).hidden = !all;
  query("[data-containers-card]", root).hidden = all;
  query(".mon-two", root).classList.toggle("single", all);
  if (all) paintStrip(context, nodes);
  else paintTiles(context, node, ring, true);

  const protocols = all ? mergeProtocols(nodes) : node.protocols || {};
  paintProtocols(context, protocols, ring, !all);
  paintChartNow(context, protocols, ring);

  const clients = all
    ? nodes.flatMap((entry) => (entry.status === "ok" ? (entry.top_clients || []).map((row) => ({ ...row, node_name: entry.name })) : []))
      .sort((a, b) => (b.total_bps || 0) - (a.total_bps || 0)).slice(0, 10)
    : (node.top_clients || []).slice(0, 10);
  const naiveHint = protocols.naive?.available && !protocols.naive.live
    ? '<p class="mon-note">NaiveProxy и Mieru не дают скорость по клиентам в реальном времени — их объёмы смотрите на вкладке «Трафик».</p>'
    : "";
  setHtmlIfChanged(rt, "clients", query("[data-clients]", root), clientsHtml(clients, naiveHint));
  if (!all) setHtmlIfChanged(rt, "containers", query("[data-containers]", root), containersHtml(node.host?.containers, node.host?.mem?.total));
}

async function prefill(context, nodeId, generation, epoch) {
  const mon = ensureState(context);
  const rt = runtimeOf(context);
  if (nodeId === "all") return;
  const ring = ringOf(rt, nodeId);
  if (ring.t.length) return;
  const series = [...PREFILL_SERIES, ...PROTOCOLS.flatMap(([proto]) => [`${proto}.up_bps`, `${proto}.down_bps`])];
  try {
    const data = await context.api(`/api/metrics/history?node=${encodeURIComponent(nodeId)}&series=${series.join(",")}&range=15m&points=450`);
    if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch || ring.t.length) return;
    const aligned = alignSeries(data.series || {});
    const end = aligned.x.length ? aligned.x[aligned.x.length - 1] : 0;
    aligned.x.forEach((stamp, index) => {
      if (stamp < end - RING_SECONDS) return;
      const values = {};
      for (const [key, list] of Object.entries(aligned.series)) values[key] = list[index];
      pushSample(ring, stamp, values);
    });
  } catch {
    // no history yet: the charts start empty and fill from the live feed
  }
}

async function openNow(context, generation) {
  const mon = ensureState(context);
  const rt = runtimeOf(context);
  const body = query("[data-mon-body]", context.ui.view);
  const epoch = ++mon.epoch;
  context.live?.close();
  destroyCharts(rt);
  rt.last = null;
  rt.lastJson = {};
  rt.badge = "connecting";
  // the node list (and the first picture) before the shell: «Все узлы» exists only with links
  try {
    const first = await context.api("/api/metrics/live?node=all");
    if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
    pickNodeNames(mon, first);
  } catch (error) {
    if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
    if (!mon.nodes.length) {
      body.innerHTML = `<div class="empty-state"><span>!</span><h3>Мониторинг недоступен</h3><p>${esc(error.message)}</p><button class="secondary" data-action="retry">Повторить</button></div>`;
      return;
    }
  }
  if (mon.node !== "all" && !mon.nodes.some((node) => node.node_id === mon.node)) mon.node = mon.nodes[0]?.node_id || "local";
  if (mon.node === "all" && mon.nodes.length < 2) mon.node = mon.nodes[0]?.node_id || "local";
  body.innerHTML = nowShell(mon);
  setBadge(context, "connecting");
  await prefill(context, mon.node, generation, epoch);
  if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
  const handle = connectLive(context, mon.node, (snapshot) => {
    if (mon.epoch === epoch) paintNow(context, snapshot);
  }, (state, detail) => {
    if (mon.epoch === epoch && isCurrent(context.state, generation, "monitoring")) setBadge(context, state, detail);
  });
  handle.onClose = () => {
    const current = runtimeOf(context);
    if (current === rt) destroyCharts(rt);
  };
}

// -- «Трафик» ----------------------------------------------------------------------------------

function trafficNode(mon) {
  if (mon.node !== "all") return mon.node;
  return mon.nodes[0]?.node_id || "local";
}

function trafficShell(mon) {
  return `<div class="mon-toolbar">
      ${nodeField({ ...mon, node: trafficNode(mon) }, false)}
      ${segmented(RANGES, mon.range, "mon-range", "Период")}
      <span class="mon-stamp" data-stamp></span>
    </div>
    <div data-traffic><div class="skeleton-grid mon-skeleton"><i></i><i></i><i></i><i></i></div></div>`;
}

function sumDirection(up, down, dir) {
  if (dir === "up") return up;
  if (dir === "down") return down;
  return up.map((value, index) => (finite(value) || finite(down[index]) ? (finite(value) ? Number(value) : 0) + (finite(down[index]) ? Number(down[index]) : 0) : null));
}

function trafficSeries(history, dir) {
  const aligned = alignSeries(history.series || {});
  const list = [];
  for (const [proto, name] of PROTOCOLS) {
    const up = aligned.series[`${proto}.up_bps`];
    const down = aligned.series[`${proto}.down_bps`];
    if (!up && !down) continue;
    const values = sumDirection(up || new Array(aligned.x.length).fill(null), down || new Array(aligned.x.length).fill(null), dir);
    if (!values.some(finite)) continue;
    list.push({ id: proto, label: name, cls: `ser-${proto}`, values });
  }
  return { x: aligned.x, series: list };
}

function totalsHtml(summary) {
  const rows = PROTOCOLS.map(([proto, name]) => ({ proto, name, row: summary.protocols?.[proto] })).filter((entry) => entry.row)
    .sort((a, b) => (b.row.total_bytes || 0) - (a.row.total_bytes || 0));
  if (!rows.length) return emptyBlock("Нет данных об объёмах", "За выбранный период сервер не накопил статистику.");
  const sum = (key) => rows.reduce((total, entry) => total + (Number(entry.row[key]) || 0), 0);
  return `<div class="mon-table-wrap"><table class="mon-table stack"><thead><tr><th>Протокол</th><th class="num">↓ отдано</th><th class="num">↑ принято</th><th class="num">Всего</th><th>Доля</th><th class="num">Средняя</th><th class="num">Пик</th></tr></thead><tbody>${rows.map(({ proto, name, row }) => (
    `<tr><td data-label="Протокол"><span class="cellv">${chip(proto)}<b>${esc(name)}</b></span></td>
      <td class="num" data-label="↓ отдано"><span class="cellv">${formatBytes(row.down_bytes)}</span></td>
      <td class="num" data-label="↑ принято"><span class="cellv">${formatBytes(row.up_bytes)}</span></td>
      <td class="num" data-label="Всего"><span class="cellv"><b>${formatBytes(row.total_bytes)}</b></span></td>
      <td data-label="Доля"><span class="cellv"><span class="share ser-${proto}"><span class="mini-bar"><i data-width="${Math.max(1, Number(row.share_percent) || 0).toFixed(1)}"></i></span><b>${formatPercent(row.share_percent)}</b></span></span></td>
      <td class="num" data-label="Средняя"><span class="cellv">${rateText(row.avg_bps)}</span></td>
      <td class="num" data-label="Пик"><span class="cellv">${rateText(row.peak_bps)}${finite(row.peak_at) ? `<small>${esc(dayTime(row.peak_at))}</small>` : ""}</span></td></tr>`
  )).join("")}</tbody><tfoot><tr><td>Итого</td><td class="num">${formatBytes(sum("down_bytes"))}</td><td class="num">${formatBytes(sum("up_bytes"))}</td><td class="num"><b>${formatBytes(sum("total_bytes"))}</b></td><td></td><td></td><td></td></tr></tfoot></table></div>`;
}

function hoursChart(host, summary, rt) {
  const hours = summary.hours_of_day || {};
  const list = PROTOCOLS.filter(([proto]) => Array.isArray(hours[proto]) && hours[proto].some(finite))
    .map(([proto, name]) => ({ id: proto, label: name, cls: `ser-${proto}`, values: hours[proto] }));
  if (!list.length) {
    host.innerHTML = emptyBlock("Распределение по часам суток считается от 7 дней", "Выберите период 7 д, 30 д или 90 д — тогда здесь появится средняя нагрузка по часам.");
    return;
  }
  rt.charts.push(barChart(host, {
    categories: Array.from({ length: 24 }, (_, hour) => String(hour).padStart(2, "0")),
    series: list,
    unit: "rate",
    height: 210,
    label: "Средний трафик по часам суток",
    totalLabel: "Всего",
    legend: true,
    legendValues: false,
  }));
}

async function openTraffic(context, generation) {
  const mon = ensureState(context);
  const rt = runtimeOf(context);
  const body = query("[data-mon-body]", context.ui.view);
  const epoch = ++mon.epoch;
  destroyCharts(rt);
  context.live?.close();
  if (!mon.nodes.length) {
    try {
      pickNodeNames(mon, await context.api("/api/metrics/live?node=all"));
    } catch {
      // the history call below reports the failure
    }
  }
  if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
  body.innerHTML = trafficShell(mon);
  const target = query("[data-traffic]", body);
  const node = trafficNode(mon);
  const series = PROTOCOLS.flatMap(([proto]) => [`${proto}.up_bps`, `${proto}.down_bps`]).join(",");
  let history;
  let summary;
  try {
    [history, summary] = await Promise.all([
      context.api(`/api/metrics/history?node=${encodeURIComponent(node)}&series=${series}&range=${mon.range}&points=240`),
      context.api(`/api/metrics/summary?node=${encodeURIComponent(node)}&range=${mon.range}`).then((data) => summaryOf(data, node)),
    ]);
  } catch (error) {
    if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
    target.innerHTML = `<div class="empty-state"><span>!</span><h3>Не удалось загрузить историю</h3><p>${esc(error.message)}</p><button class="secondary" data-action="retry">Повторить</button></div>`;
    return;
  }
  if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
  if (summary.status === "unsupported" || summary.status === "unavailable") {
    target.innerHTML = emptyBlock(summary.status === "unsupported" ? "Узел не поддерживает мониторинг" : "Узел недоступен", "История хранится на самом узле — пока он не отвечает, её не показать.");
    return;
  }
  const stamp = summary.status === "stale" ? `<div class="mon-banner warn">Данные узла устарели: ${esc(ageText(summary.age_seconds))} назад.</div>` : "";
  target.innerHTML = `${stamp}<section class="panel-card mon-card">
      <div class="mon-card-head"><div><h2>Трафик по протоколам</h2><small>Площадь под графиком — объём. Сетевой трафик с заголовками пакетов</small></div>${segmented(DIRECTIONS, mon.dir, "mon-dir", "Направление")}</div>
      <div class="mon-chart" data-chart-traffic></div></section>
    <section class="panel-card mon-card"><div class="mon-card-head"><div><h2>Итоги за период</h2><small>Объёмы и скорости по протоколам</small></div></div><div data-totals>${totalsHtml(summary)}</div></section>
    <section class="panel-card mon-card"><div class="mon-card-head"><div><h2>Нагрузка по часам суток</h2><small>Средняя скорость по часам, по протоколам</small></div></div><div class="mon-chart" data-chart-hours></div></section>`;
  fillWidths(target);
  rt.trafficHistory = history;
  paintTrafficChart(context, history, mon.range);
  hoursChart(query("[data-chart-hours]", target), summary, rt);
  setText(body, "[data-stamp]", `${new Date((history.to || Date.now() / 1000) * 1000).toLocaleString(locale(), { hour: "2-digit", minute: "2-digit" })} · шаг ${history.step || "—"} сек`);
}

function paintTrafficChart(context, history, range) {
  const mon = ensureState(context);
  const rt = runtimeOf(context);
  const host = query("[data-chart-traffic]", context.ui.view);
  if (!host) return;
  const { x, series } = trafficSeries(history, mon.dir);
  const options = { x, series, domain: [history.from ?? x[0] ?? 0, history.to ?? x[x.length - 1] ?? 1], unit: "rate", height: 280, label: `Трафик по протоколам, период ${range}`, legend: true, legendValues: false };
  if (!series.length) {
    host.innerHTML = emptyBlock("За этот период данных нет", "Узел мог быть выключен, или счётчики ещё не накопили статистику.");
    rt.trafficChart = null;
    return;
  }
  if (rt.trafficChart && host.querySelector(".chart")) {
    rt.trafficChart.update(options);
    return;
  }
  host.innerHTML = "";
  rt.trafficChart = stackedAreaChart(host, options);
  rt.charts.push(rt.trafficChart);
}

// -- «Узлы» ------------------------------------------------------------------------------------

function nodesShell(mon) {
  return `<div class="mon-toolbar">
      ${segmented(RANGES.filter(([id]) => id !== "15m"), mon.nodesRange, "mon-range", "Период")}
      <span class="mon-stamp" data-stamp></span>
    </div>
    <div data-nodes><div class="skeleton-grid mon-skeleton"><i></i><i></i><i></i><i></i></div></div>
    <div data-drill></div>`;
}

function alertBadges(alerts) {
  if (!alerts?.length) return '<span class="muted">нет</span>';
  return alerts.map((alert) => (
    `<span class="mon-pill ${alert.severity === "critical" ? "crit" : "warn"}" title="${esc(alert.detail || "")}">${alert.severity === "critical" ? "●" : "▲"} ${esc(ALERT_NAME[alert.kind] || alert.kind)}</span>`
  )).join(" ");
}

function statusChip(row) {
  if (row.status === "stale") return `<span class="mon-pill warn">данные устарели · ${esc(ageText(row.age_seconds))}</span>`;
  if (row.status === "unavailable") return '<span class="mon-pill crit">недоступен</span>';
  if (row.status === "unsupported") return '<span class="mon-pill muted">не поддерживает</span>';
  return '<span class="mon-pill ok">в сети</span>';
}

function statCell(stat, kind) {
  if (!stat) return '<span class="muted">—</span>';
  const format = kind === "rate" ? rateText : (value) => (finite(value) ? formatPercent(value) : "—");
  return `<b>${format(stat.avg)}</b><small>пик ${format(stat.max)}</small>`;
}

function totalOf(row) {
  return finite(row.total_bytes) ? Number(row.total_bytes) : Object.values(row.protocols || {}).reduce((sum, entry) => sum + (Number(entry.total_bytes) || 0), 0);
}

function shareBar(row) {
  const total = totalOf(row);
  if (!total) return '<span class="muted">—</span>';
  const parts = PROTOCOLS.map(([proto]) => ({ proto, bytes: Number(row.protocols?.[proto]?.total_bytes) || 0 })).filter((entry) => entry.bytes > 0);
  return `<span class="stack-share" role="img" aria-label="${esc(parts.map((entry) => `${PROTOCOL_NAME[entry.proto]} ${formatPercent((entry.bytes / total) * 100)}`).join(", "))}">${parts.map((entry) => `<i class="ser-${entry.proto}" data-width="${((entry.bytes / total) * 100).toFixed(1)}"></i>`).join("")}</span>`;
}

function compareHtml(rows, mon) {
  if (!rows.length) return emptyBlock("Нет узлов для сравнения", "Свяжите ещё одну панель на экране «Узлы» — она появится здесь.");
  return `<div class="mon-table-wrap"><table class="mon-table stack mon-compare"><thead><tr><th>Узел</th><th>Состояние</th><th class="num">CPU</th><th class="num">RAM</th><th class="num">Диск</th><th class="num">Сеть ↓ / ↑ (средняя)</th><th>Трафик за период</th><th>Алерты</th></tr></thead><tbody>${rows.map((row) => {
    const host = row.host || {};
    const usable = row.status === "ok" || row.status === "stale";
    return `<tr class="${usable ? "clickable" : "muted-row"}${mon.drill === row.node_id ? " selected" : ""}${row.status === "stale" ? " is-stale" : ""}" data-node-row="${esc(row.node_id)}">
      <td data-label="Узел"><span class="cellv">${usable ? `<button type="button" class="link-button" data-mon-drill="${esc(row.node_id)}" aria-expanded="${mon.drill === row.node_id}">${esc(row.name || row.node_id)}</button>` : `<b>${esc(row.name || row.node_id)}</b>`}</span></td>
      <td data-label="Состояние"><span class="cellv">${statusChip(row)}</span></td>
      <td class="num" data-label="CPU"><span class="cellv"><span class="cell-flex"><span class="cell-spark" data-spark="${esc(row.node_id)}:host.cpu"></span><span class="cell-nums">${statCell(host.cpu)}</span></span></span></td>
      <td class="num" data-label="RAM"><span class="cellv">${statCell(host.mem)}</span></td>
      <td class="num" data-label="Диск"><span class="cellv">${statCell(host.disk)}</span></td>
      <td class="num" data-label="Сеть ↓ / ↑"><span class="cellv"><b>${host.net_tx_bps ? rateText(host.net_tx_bps.avg) : "—"}</b><small>↑ ${host.net_rx_bps ? rateText(host.net_rx_bps.avg) : "—"}</small></span></td>
      <td data-label="Трафик"><span class="cellv"><b>${usable ? formatBytes(totalOf(row)) : "—"}</b>${usable ? shareBar(row) : ""}<span class="cell-spark" data-spark="${esc(row.node_id)}:net"></span></span></td>
      <td data-label="Алерты"><span class="cellv">${alertBadges(row.alerts)}</span></td></tr>`;
  }).join("")}</tbody></table></div>
  <p class="mon-note">Строка раскрывается: кликните на узел, чтобы увидеть историю ресурсов и объёмы по протоколам.</p>`;
}

async function paintCompareSparks(context, rows, generation, epoch) {
  const mon = ensureState(context);
  const rt = runtimeOf(context);
  await Promise.all(rows.filter((row) => row.status === "ok" || row.status === "stale").map(async (row) => {
    try {
      const data = await context.api(`/api/metrics/history?node=${encodeURIComponent(row.node_id)}&series=host.cpu,net.rx_bps,net.tx_bps&range=${mon.nodesRange}&points=48`);
      if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
      const aligned = alignSeries(data.series || {});
      const domain = [data.from ?? aligned.x[0] ?? 0, data.to ?? aligned.x[aligned.x.length - 1] ?? 1];
      const cpuHost = query(`[data-spark="${CSS.escape(row.node_id)}:host.cpu"]`, context.ui.view);
      const netHost = query(`[data-spark="${CSS.escape(row.node_id)}:net"]`, context.ui.view);
      if (cpuHost) rt.charts.push(sparkline(cpuHost, { x: aligned.x, domain, unit: "percent", yMax: "auto", height: 26, label: `CPU ${row.name || row.node_id}`, series: [{ values: aligned.series["host.cpu"] || [], cls: "ser-tile" }] }));
      if (netHost) {
        const total = (aligned.series["net.rx_bps"] || []).map((value, index) => (finite(value) || finite(aligned.series["net.tx_bps"]?.[index]) ? (Number(value) || 0) + (Number(aligned.series["net.tx_bps"]?.[index]) || 0) : null));
        rt.charts.push(sparkline(netHost, { x: aligned.x, domain, unit: "rate", height: 26, label: `Трафик ${row.name || row.node_id}`, series: [{ values: total, cls: "ser-tile" }] }));
      }
    } catch {
      // a node whose history does not load keeps its numbers and no sparkline
    }
  }));
}

// `GET /api/metrics/summary` answers `{range, nodes: [one full summary per node], compare?}`; the
// `compare` list is a slim ranking, so the table is built from `nodes` and sorted by traffic.
function summaryRows(data) {
  if (Array.isArray(data.nodes)) return [...data.nodes].sort((a, b) => totalOf(b) - totalOf(a));
  return data.host ? [data] : [];
}

function summaryOf(data, nodeId) {
  return summaryRows(data).find((row) => row.node_id === nodeId) || (data.protocols ? data : { status: "unavailable", protocols: {} });
}

async function openNodes(context, generation) {
  const mon = ensureState(context);
  const rt = runtimeOf(context);
  const body = query("[data-mon-body]", context.ui.view);
  const epoch = ++mon.epoch;
  destroyCharts(rt);
  context.live?.close();
  body.innerHTML = nodesShell(mon);
  let data;
  try {
    data = await context.api(`/api/metrics/summary?node=all&range=${mon.nodesRange}`);
  } catch (error) {
    if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
    query("[data-nodes]", body).innerHTML = `<div class="empty-state"><span>!</span><h3>Не удалось загрузить сравнение узлов</h3><p>${esc(error.message)}</p><button class="secondary" data-action="retry">Повторить</button></div>`;
    return;
  }
  if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch) return;
  const rows = summaryRows(data);
  rt.compare = rows;
  query("[data-nodes]", body).innerHTML = `<section class="panel-card mon-card"><div class="mon-card-head"><div><h2>Сравнение узлов</h2><small>Средние значения за период, по убыванию трафика</small></div></div>${compareHtml(rows, mon)}</section>`;
  fillWidths(body);
  setText(body, "[data-stamp]", `обновлено ${clock(Date.now() / 1000)}`);
  void paintCompareSparks(context, rows, generation, epoch);
  if (mon.drill && rows.some((row) => row.node_id === mon.drill)) await openDrill(context, mon.drill, generation, epoch);
  else mon.drill = "";
}

function protocolVolumes(row) {
  const entries = PROTOCOLS.map(([proto, name]) => ({ proto, name, entry: row.protocols?.[proto] })).filter((item) => item.entry);
  if (!entries.length) return emptyBlock("Нет объёмов за период", "");
  const total = entries.reduce((sum, item) => sum + (Number(item.entry.total_bytes) || 0), 0) || 1;
  return `<ul class="vol-list">${entries.sort((a, b) => (b.entry.total_bytes || 0) - (a.entry.total_bytes || 0)).map(({ proto, name, entry }) => (
    `<li class="ser-${proto}"><span>${chip(proto)}<b>${esc(name)}</b></span><span class="mini-bar"><i data-width="${Math.max(1, ((entry.total_bytes || 0) / total) * 100).toFixed(1)}"></i></span><span class="num">${formatBytes(entry.total_bytes)}</span><small>↓ ${formatBytes(entry.down_bytes)} · ↑ ${formatBytes(entry.up_bytes)}${finite(entry.peak_bps) ? ` · пик ${rateText(entry.peak_bps)}` : ""}</small></li>`
  )).join("")}</ul>`;
}

async function openDrill(context, nodeId, generation, epoch) {
  const mon = ensureState(context);
  const rt = runtimeOf(context);
  const row = (rt.compare || []).find((entry) => entry.node_id === nodeId);
  const host = query("[data-drill]", context.ui.view);
  if (!row || !host) return;
  mon.drill = nodeId;
  for (const tr of queryAll("[data-node-row]", context.ui.view)) {
    const on = tr.dataset.nodeRow === nodeId;
    tr.classList.toggle("selected", on);
    query("[data-mon-drill]", tr)?.setAttribute("aria-expanded", String(on));
  }
  host.innerHTML = `<section class="panel-card mon-card mon-drill" aria-label="Узел ${esc(row.name || row.node_id)}">
    <div class="mon-card-head"><div><h2>${esc(row.name || row.node_id)} ${statusChip(row)}</h2><small>История ресурсов и трафика за выбранный период</small></div><button type="button" class="secondary" data-mon-close-drill>Закрыть</button></div>
    ${row.alerts?.length ? `<div class="drill-alerts">${row.alerts.map((alert) => `<p><span class="mon-pill ${alert.severity === "critical" ? "crit" : "warn"}">${alert.severity === "critical" ? "●" : "▲"} ${esc(ALERT_NAME[alert.kind] || alert.kind)}</span> ${esc(alert.detail || "")}${finite(alert.since) ? ` <small>с ${esc(dayTime(alert.since))}</small>` : ""}</p>`).join("")}</div>` : ""}
    <div class="drill-grid" data-drill-grid><div class="skeleton-grid mon-skeleton"><i></i><i></i></div></div>
    <h3 class="drill-sub">Объёмы по протоколам</h3>${protocolVolumes(row)}</section>`;
  fillWidths(host);
  host.scrollIntoView?.({ block: "nearest", behavior: "smooth" });
  const protoSeries = PROTOCOLS.flatMap(([proto]) => [`${proto}.up_bps`, `${proto}.down_bps`]);
  let history;
  try {
    history = await context.api(`/api/metrics/history?node=${encodeURIComponent(nodeId)}&series=${["host.cpu", "host.mem", "host.disk", "net.rx_bps", "net.tx_bps", ...protoSeries].join(",")}&range=${mon.nodesRange}&points=240`);
  } catch (error) {
    if (isCurrent(context.state, generation, "monitoring") && mon.epoch === epoch) query("[data-drill-grid]", host).innerHTML = emptyBlock("История не загрузилась", error.message);
    return;
  }
  if (!isCurrent(context.state, generation, "monitoring") || mon.epoch !== epoch || mon.drill !== nodeId) return;
  const aligned = alignSeries(history.series || {});
  const domain = [history.from ?? aligned.x[0] ?? 0, history.to ?? aligned.x[aligned.x.length - 1] ?? 1];
  const grid = query("[data-drill-grid]", host);
  if (!aligned.x.length) {
    grid.innerHTML = emptyBlock("Нет истории за период", "Узел мог быть выключен или связан недавно.");
    return;
  }
  grid.innerHTML = ["cpu", "mem", "disk", "net", "protocols"].map((id) => `<div class="drill-chart drill-${id}"><h4>${{ cpu: "CPU", mem: "Память", disk: "Диск", net: "Сеть", protocols: "Трафик по протоколам" }[id]}</h4><div data-drill-chart="${id}"></div></div>`).join("");
  const percentLine = (id, key, label) => rt.charts.push(areaChart(query(`[data-drill-chart="${id}"]`, grid), {
    x: aligned.x, domain, unit: "percent", yMax: "auto", height: 150, label,
    series: [{ id: key, label, cls: "ser-tile", values: aligned.series[key] || [] }], legend: false,
  }));
  percentLine("cpu", "host.cpu", "CPU");
  percentLine("mem", "host.mem", "Память");
  percentLine("disk", "host.disk", "Диск");
  rt.charts.push(lineChart(query('[data-drill-chart="net"]', grid), {
    x: aligned.x, domain, unit: "rate", height: 150, label: "Сеть",
    series: [
      { id: "tx", label: "↓ отдача", cls: "ser-tile", values: aligned.series["net.tx_bps"] || [] },
      { id: "rx", label: "↑ приём", cls: "ser-tile-2", dash: true, values: aligned.series["net.rx_bps"] || [] },
    ],
    legend: true, legendValues: false,
  }));
  const traffic = trafficSeries(history, "sum");
  if (traffic.series.length) {
    rt.charts.push(stackedAreaChart(query('[data-drill-chart="protocols"]', grid), {
      x: traffic.x, domain, unit: "rate", height: 150, label: "Трафик по протоколам", series: traffic.series, legend: true, legendValues: false,
    }));
  } else {
    query('[data-drill-chart="protocols"]', grid).innerHTML = emptyBlock("Нет трафика", "");
  }
}

// -- entry points ------------------------------------------------------------------------------

async function openTab(context, generation) {
  const mon = ensureState(context);
  if (mon.tab === "traffic") await openTraffic(context, generation);
  else if (mon.tab === "nodes") await openNodes(context, generation);
  else await openNow(context, generation);
}

export async function renderMonitoring(context, generation) {
  teardown(context);
  context.monitoringRuntime = newRuntime();
  const mon = ensureState(context);
  context.ui.view.innerHTML = `<div class="mon" data-mon>${tabsHtml(mon)}<div class="mon-body" data-mon-body aria-live="off"></div></div>`;
  await openTab(context, generation);
}

function refreshTab(context) {
  void openTab(context, context.state.navigationGeneration);
}

export function bindMonitoring(context) {
  const view = context.ui.view;
  view.addEventListener("click", (event) => {
    if (context.state.view !== "monitoring") return;
    const mon = ensureState(context);
    const target = event.target.closest("[data-mon-tab],[data-mon-pause],[data-mon-dir],[data-mon-range],[data-mon-drill],[data-mon-close-drill],[data-node-row]");
    if (!target) return;
    if (target.dataset.monTab) {
      if (mon.tab === target.dataset.monTab) return;
      mon.tab = target.dataset.monTab;
      remember(mon);
      for (const tab of queryAll("[data-mon-tab]", view)) {
        tab.classList.toggle("active", tab.dataset.monTab === mon.tab);
        tab.setAttribute("aria-selected", String(tab.dataset.monTab === mon.tab));
      }
      refreshTab(context);
    } else if (target.hasAttribute("data-mon-pause")) {
      const live = context.live;
      if (!live) return;
      if (live.paused) live.resume();
      else live.pause();
    } else if (target.dataset.monDir) {
      mon.dir = target.dataset.monDir;
      remember(mon);
      paintSegmented(view, "mon-dir", mon.dir);
      const rt = runtimeOf(context);
      if (mon.tab === "now" && rt?.last) paintNow(context, rt.last);
      else if (mon.tab === "traffic" && rt?.trafficHistory) paintTrafficChart(context, rt.trafficHistory, mon.range);
    } else if (target.dataset.monRange) {
      if (mon.tab === "nodes") mon.nodesRange = target.dataset.monRange;
      else mon.range = target.dataset.monRange;
      remember(mon);
      refreshTab(context);
    } else if (target.hasAttribute("data-mon-close-drill")) {
      mon.drill = "";
      const host = query("[data-drill]", view);
      if (host) host.innerHTML = "";
      for (const tr of queryAll("[data-node-row].selected", view)) tr.classList.remove("selected");
    } else {
      const id = target.dataset.monDrill || target.dataset.nodeRow;
      if (id && !(event.target.closest("a") && !target.dataset.monDrill)) void openDrill(context, id, context.state.navigationGeneration, mon.epoch);
    }
  });
  view.addEventListener("change", (event) => {
    if (context.state.view !== "monitoring") return;
    const select = event.target.closest("[data-mon-node]");
    if (!select) return;
    const mon = ensureState(context);
    mon.node = select.value;
    remember(mon);
    refreshTab(context);
  });
}
