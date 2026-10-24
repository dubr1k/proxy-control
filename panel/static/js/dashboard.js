import { bytes, esc, locale, number, offeredVersions, paintClientsCount, plural, query } from "./common.js";
import { countClientsWithIssue, showClientIssue } from "./clients.js";
import { connectLive } from "./live.js";
import { clientEntries, fleetCount, paintNavCounts, workingClients } from "./nav-counts.js";
import { COMPONENT_SHORT } from "./nodes.js";
import { isCurrent } from "./state.js";
import { refreshUsers } from "./users.js";

// Above this the resource is the story, so the bar turns amber then red; below
// it a filled bar would cry wolf on a server that is simply being used.
const HOST_WARN_PERCENT = 75;
const HOST_CRITICAL_PERCENT = 90;
// v0.15 (owner: «не вижу, что что-то обновляется»): the resource card follows the host while
// the overview is open. `/api/host` asks the agent alone, not every protocol runtime.
// 3.1 (owner: «сделай чтоб я видел обновления в прямом эфире»): the card rides the monitor's live
// stream (a snapshot every collector interval, 2 s); this poll is only the fallback for a panel
// whose monitor is switched off.
const HOST_REFRESH_MS = 5000;

function usageLevel(percent) {
  return percent >= HOST_CRITICAL_PERCENT ? "critical" : percent >= HOST_WARN_PERCENT ? "warn" : "";
}

function usageBar(key, label, percent) {
  return `<span class="usage-bar ${usageLevel(percent)}" data-host-bar="${key}" role="img" aria-label="${esc(label)}: ${percent.toFixed(1)} процентов"><i data-usage-percent="${percent.toFixed(1)}"></i></span>`;
}

function hostRow(key, label, usage, detail, extra = "") {
  const percent = usage?.used_percent;
  if (typeof percent !== "number") {
    return `<span><small>${esc(label)}</small><b>—</b><em>Нет данных</em>${extra}</span>`;
  }
  return `<span><small>${esc(label)}</small><b data-host-value="${key}">${percent.toFixed(1)} %</b>
    ${usageBar(key, label, percent)}
    <em data-host-detail="${key}">${esc(detail)}</em>${extra}</span>`;
}

// Swap sits under RAM: it is the same story (memory pressure) told one step later. An
// agent older than the panel sends no swap section, and then the card says nothing.
function swapLine(swap) {
  if (!swap) return "";
  if (!swap.total_bytes) return '<span class="host-swap"><small>Swap</small><em>выключен на сервере</em></span>';
  const percent = typeof swap.used_percent === "number" ? swap.used_percent : 0;
  return `<span class="host-swap"><small>Swap</small><b data-host-value="swap">${percent.toFixed(1)} %</b>
    ${usageBar("swap", "Swap", percent)}
    <em data-host-detail="swap">${esc(swapDetail(swap))}</em></span>`;
}

function swapDetail(swap) {
  return `${bytes(swap.used_bytes)} из ${bytes(swap.total_bytes)}`;
}

function memoryDetail(memory) {
  return memory ? `${bytes(memory.used_bytes)} из ${bytes(memory.total_bytes)}` : "";
}

function diskDetail(disk) {
  return disk ? `${bytes(disk.available_bytes)} свободно из ${bytes(disk.total_bytes)}` : "";
}

function cpuDetail(host) {
  return host.live ? "Среднее за секунду" : "Мгновенная утилизация, окно 150 мс";
}

function updatedAt(when) {
  return `обновлено ${when.toLocaleTimeString(locale())}`;
}

function loadLine(cpu) {
  const load = Array.isArray(cpu?.load_average)
    ? `load ${cpu.load_average.map((value) => value.toFixed(2)).join(" · ")}`
    : "load average недоступен";
  return typeof cpu?.cores === "number" ? `${number(cpu.cores)} ${plural(cpu.cores, "ядро", "ядра", "ядер")} · ${load}` : load;
}

function strainedBy(host) {
  const worst = Math.max(
    ...[host.cpu?.used_percent, host.memory?.used_percent, host.disk?.used_percent]
      .filter((value) => typeof value === "number"),
    0,
  );
  return worst >= HOST_WARN_PERCENT;
}

// The line under the title: what the numbers are and how fresh. On the live stream a pulsing
// dot says so; on the fallback poll it is the time of the last answer.
function freshness(host, when) {
  return host.live
    ? `<span class="live-badge" data-host-fresh><i></i>в прямом эфире · ${esc(updatedAt(when))}</span>`
    : `<span data-host-fresh>${esc(updatedAt(when))}</span>`;
}

function hostCard(host, when = new Date()) {
  const stamp = `data-host-updated="${when.getTime()}"`;
  if (!host || host.available !== true) {
    const reason = host?.reason === "version_agent_unavailable"
      ? "Host-agent не отвечает. Метрики хоста читает только он: панель работает read-only и не монтирует ни /proc, ни файловую систему хоста."
      : "Агент вернул метрики в неизвестном формате.";
    return `<article class="protocol-card host-card host-row degraded" ${stamp}>
      <div class="protocol-head"><span><small>CPU · RAM · Диск</small><h2>Ресурсы сервера</h2></span><span class="status-pill blocked"><i></i>Недоступны</span></div>
      <p class="protocol-note">${esc(reason)} · ${esc(updatedAt(when))}</p>
    </article>`;
  }
  const { cpu, memory, swap, disk } = host;
  const strained = strainedBy(host);
  return `<article class="protocol-card host-card host-row ${strained ? "degraded" : ""}" ${stamp} data-host-shape="${hostShape(host)}">
    <div class="protocol-head"><span><small>CPU · RAM · Диск</small><h2>Ресурсы сервера</h2></span><span class="status-pill ${strained ? "blocked" : "active"}" data-host-pill><i></i>${strained ? "Нагружен" : "В норме"}</span></div>
    <p class="protocol-note"><span data-host-load>${esc(loadLine(cpu))}</span> · ${freshness(host, when)} · <a class="mon-link" href="#monitoring">Подробнее в мониторинге</a></p>
    <div class="protocol-metrics host-metrics">
      ${hostRow("cpu", "Загрузка CPU", cpu, cpuDetail(host))}
      ${hostRow("memory", "Оперативная память", memory, memoryDetail(memory), swapLine(swap))}
      ${hostRow("disk", "Диск (корень)", disk, diskDetail(disk))}
    </div>
  </article>`;
}

// Which rows the card has: a new sample with the same shape is painted into the card in place
// (the numbers change, the bars slide), any other one rebuilds it.
function hostShape(host) {
  return [host.live ? "live" : "poll", host.cpu ? 1 : 0, host.memory ? 1 : 0, host.disk ? 1 : 0,
    !host.swap ? "-" : host.swap.total_bytes ? "s" : "0"].join("");
}

// The bars' widths go through the CSSOM: an inline style attribute is what the CSP
// (style-src 'self') drops, and a bar that never fills is worse than no bar.
function fillBars(root) {
  for (const bar of root.querySelectorAll("[data-usage-percent]")) bar.style.width = `${bar.dataset.usagePercent}%`;
}

function paintHost(card, host, when = new Date()) {
  if (card.dataset.hostShape !== hostShape(host) || host.available !== true) {
    card.outerHTML = hostCard(host, when);
    return;
  }
  const rows = { cpu: host.cpu, memory: host.memory, disk: host.disk, swap: host.swap };
  const details = { cpu: cpuDetail(host), memory: memoryDetail(host.memory), disk: diskDetail(host.disk),
    swap: host.swap?.total_bytes ? swapDetail(host.swap) : "" };
  for (const [key, usage] of Object.entries(rows)) {
    const percent = usage?.used_percent;
    if (typeof percent !== "number") continue;
    const value = card.querySelector(`[data-host-value="${key}"]`);
    if (value) value.textContent = `${percent.toFixed(1)} %`;
    const bar = card.querySelector(`[data-host-bar="${key}"]`);
    if (bar) {
      bar.className = `usage-bar ${usageLevel(percent)}`;
      const fill = bar.querySelector("i");
      fill.dataset.usagePercent = percent.toFixed(1);
      fill.style.width = `${percent.toFixed(1)}%`;
    }
    const detail = card.querySelector(`[data-host-detail="${key}"]`);
    if (detail) detail.textContent = details[key];
  }
  const strained = strainedBy(host);
  card.classList.toggle("degraded", strained);
  const pill = card.querySelector("[data-host-pill]");
  pill.className = `status-pill ${strained ? "blocked" : "active"}`;
  pill.lastChild.textContent = strained ? "Нагружен" : "В норме";
  card.querySelector("[data-host-load]").textContent = loadLine(host.cpu);
  card.querySelector("[data-host-fresh]").outerHTML = freshness(host, when);
  card.dataset.hostUpdated = String(when.getTime());
}

// The monitor's snapshot of this node, in the shape `/api/host` answers.
export function hostFromLive(sample) {
  if (!sample || typeof sample !== "object") return null;
  const usage = (part) => (part && typeof part.percent === "number"
    ? { used_percent: part.percent, used_bytes: part.used, total_bytes: part.total } : null);
  const disk = usage(sample.disk);
  if (disk) disk.available_bytes = Math.max(0, (sample.disk.total || 0) - (sample.disk.used || 0));
  return {
    available: true,
    live: true,
    cpu: typeof sample.cpu_percent === "number"
      ? { used_percent: sample.cpu_percent, cores: sample.cores, load_average: sample.load } : null,
    memory: usage(sample.mem),
    swap: sample.swap ? { used_percent: sample.swap.percent ?? 0, used_bytes: sample.swap.used, total_bytes: sample.swap.total } : null,
    disk,
  };
}

// Replaces the card in place every HOST_REFRESH_MS while this very render of the overview is
// on screen; a hidden tab skips the call, another screen (or «Обновить») ends the loop.
async function followHost(context, generation) {
  const { api, state, ui } = context;
  for (;;) {
    await new Promise((resolve) => window.setTimeout(resolve, HOST_REFRESH_MS));
    if (!isCurrent(state, generation, "dashboard")) return;
    if (document.hidden) continue;
    let host;
    try {
      host = await api("/api/host");
    } catch {
      continue; // a dropped request keeps the last numbers; the next tick tries again
    }
    const card = query(".host-card", ui.view);
    if (!isCurrent(state, generation, "dashboard") || !card) return;
    card.outerHTML = hostCard(host);
    fillBars(query(".host-card", ui.view));
  }
}

// The live card: every snapshot of the monitor's stream is painted as it arrives. A panel whose
// monitor is off never sends one; then the stream is closed and the card falls back to the poll.
function followLive(context, generation) {
  const { state, ui } = context;
  let delivered = false;
  let fellBack = false;
  let handle = null;
  const fallBack = () => {
    if (fellBack) return;
    fellBack = true;
    if (!handle) return; // reported while connecting; closed right after connectLive returns
    handle.close();
    if (isCurrent(state, generation, "dashboard")) void followHost(context, generation);
  };
  handle = connectLive(context, "local", (snapshot) => {
    const node = snapshot?.nodes?.find((entry) => entry.node_id === "local") || snapshot?.nodes?.[0];
    const host = node && node.status !== "unavailable" ? hostFromLive(node.host) : null;
    const card = query(".host-card", ui.view);
    if (!host || !card || !isCurrent(state, generation, "dashboard")) return;
    delivered = true;
    paintHost(card, host);
    fillBars(query(".host-card", ui.view));
  }, (next) => {
    // `polling`: the stream failed twice (a monitor that is off answers 404) before any snapshot.
    if (!delivered && next === "polling") fallBack();
  }, { view: "dashboard" });
  if (fellBack) {
    fellBack = false;
    fallBack();
  }
}

// The agents report English state words; the services list shows them in plain Russian.
const STATUS_WORDS = { ready: "в порядке", ok: "в порядке", degraded: "сбой", unavailable: "недоступно", disabled: "отключено" };

function statusWord(status, ready) {
  return STATUS_WORDS[status] || status || (ready ? STATUS_WORDS.ready : STATUS_WORDS.degraded);
}

// One line of «Состояние сервисов» for a protocol that is switched on: green when its manager is ready.
function serviceRow(name, available, ready, status) {
  if (!available) return "";
  return `<div class="service-row ${ready ? "" : "degraded"}"><i></i><span><b>${name}</b><small>${ready ? "Менеджер работает" : "Менеджер недоступен"}</small></span><em>${esc(statusWord(status, ready))}</em></div>`;
}

// 3.1 (owner: «приведи к одному виду»): every protocol card is the same three blocks — the head
// with its status, the active/disabled pair, and one traffic tile across the card (value on one
// line, its source under it), pinned to the bottom so the cards of a row line up.
function protocolCard({ name, kind, ready, available = true, status, active, disabled, traffic, source, className = "" }) {
  const pill = !available ? "Отключён" : status || (ready ? "Работает" : "Недоступен");
  return `<article class="protocol-card ${className} ${ready || !available ? "" : "degraded"}"${available ? "" : " hidden"}>
      <div class="protocol-head"><span><small>${esc(kind)}</small><h2>${esc(name)}</h2></span><span class="status-pill ${ready ? "active" : "blocked"}"><i></i>${esc(pill)}</span></div>
      <div class="protocol-access"><span><small>Активные доступы</small><strong>${active}</strong></span><span><small>Отключённые</small><strong>${disabled}</strong></span></div>
      <div class="protocol-traffic"><small>Трафик (↓ к клиентам · ↑ от клиентов)</small><b>${traffic}</b><em>${source}</em></div>
    </article>`;
}

function upDown(up, down) {
  return `↑ ${bytes(up)} · ↓ ${bytes(down)}`;
}

// --- «Требует внимания»: what needs a hand, each line a link to the screen that resolves it. ---

// Client lines reuse the Clients screen's own filters (`issue`), so the number here is the
// length of the list behind the link.
const CLIENT_ATTENTION = [["failed", "Доступы с ошибкой"], ["pending", "Доступы ждут узел"], ["orphan", "Доступы без секрета"]];

function nodeProblem(node) {
  const link = node.link;
  if (node.kind === "local" || !link) return "";
  if (link.status === "offline") return "не отвечает";
  if (link.enabled === false) return "на паузе";
  return link.observed_state === "failed" ? "конфигурация не применилась" : "";
}

function attentionLine(title, detail, href, attributes = "") {
  return `<li><a class="attention-link" href="${href}"${attributes}><span><b>${esc(title)}</b><small>${esc(detail)}</small></span><i aria-hidden="true">→</i></a></li>`;
}

// `entries` is the client list the overview already fetched, `versions` the Versions screen's
// answer (null when this role cannot read it), `nodes` the node list; nothing is polled for it.
function attentionBlock(context, { entries, nodes, versions, services }) {
  const lines = [];
  for (const [issue, title] of CLIENT_ATTENTION) {
    const count = entries ? countClientsWithIssue(context, entries, issue) : 0;
    if (count) lines.push(attentionLine(title, `Клиентов: ${number(count)}`, "#clients", ` data-attention-issue="${issue}"`));
  }
  for (const node of nodes) {
    const problem = nodeProblem(node);
    if (problem) lines.push(attentionLine(node.display_name || node.node_id, problem, "#fleet"));
  }
  const outdated = Object.entries(versions?.components || {}).filter(([, item]) => offeredVersions(item).hasNewer)
    .map(([component]) => COMPONENT_SHORT[component] || component);
  if (versions?.enabled === true && outdated.length) lines.push(attentionLine("Есть обновления компонентов", outdated.join(", "), "#versions"));
  if (services.length) lines.push(attentionLine("Сервисы не работают", services.join(", "), "#dashboard", " data-attention-services"));
  return lines.length
    ? `<section class="panel-card attention-card" data-attention><div class="panel-head"><h2>Требует внимания</h2></div><ul class="attention-list">${lines.join("")}</ul></section>`
    : "";
}

// A client line opens the Clients screen with its filter preselected (the click runs before
// the hash changes); the services line stays here and scrolls to the list it names.
function bindAttention(context, generation) {
  const block = query("[data-attention]", context.ui.view);
  if (!block) return;
  block.addEventListener("click", (event) => {
    const link = event.target.closest("a.attention-link");
    if (!link || !isCurrent(context.state, generation, "dashboard")) return;
    if (link.dataset.attentionIssue) showClientIssue(context, link.dataset.attentionIssue);
    else if ("attentionServices" in link.dataset) {
      event.preventDefault();
      query(".service-list", context.ui.view)?.scrollIntoView?.({ block: "center" });
    }
  });
}

export async function renderDashboard(context, generation) {
  const { api, root, state, ui } = context;
  const owner = state.me?.role === "owner";
  const [data, users, nodes, entries, nodeList, versions] = await Promise.all([
    api("/api/dashboard"),
    refreshUsers(context, generation),
    fleetCount(context),
    clientEntries(context),
    // Courtesies, like on the Nodes screen: a list that does not load just adds no lines.
    api("/api/nodes").then((answer) => answer.items || [], () => []),
    owner ? api("/api/versions").catch(() => null) : null,
  ]);
  paintNavCounts(context, data, nodes);
  paintClientsCount(context, workingClients(entries));
  if (!isCurrent(state, generation, "dashboard") || users === null) return;

  const mt = data.protocols?.mtproxy || {};
  const naive = data.protocols?.naive || { available: false, status: "disabled" };
  const mieru = data.protocols?.mieru || { available: false, status: "disabled" };
  const mtReady = mt.ready === true;
  const naiveReady = naive.ready === true;
  const naiveAvailable = naive.available === true;
  const mieruReady = mieru.ready === true;
  const mieruAvailable = mieru.available === true;
  const awg = data.protocols?.amneziawg || { available: false, status: "disabled" };
  const awgAvailable = awg.available === true;
  const awgReady = awg.ready === true;
  const awgVersions = Object.entries(awg.versions || {}).map(([version, count]) => `${version}: ${count}`).join(" · ");
  const tt = data.protocols?.trusttunnel || { available: false, status: "disabled" };
  const ttAvailable = tt.available === true;
  const ttReady = tt.ready === true;
  const allReady = mtReady && (!naiveAvailable || naiveReady) && (!mieruAvailable || mieruReady) && (!awgAvailable || awgReady) && (!ttAvailable || ttReady);
  const system = query(".system-mini", root);
  system.classList.toggle("degraded", !allReady);
  query("b", system).textContent = allReady ? "Прокси-сервисы работают" : "Есть неполадки";
  query("small", system).textContent = allReady ? "Сводка актуальна" : "Откройте обзор состояния";

  if (naiveAvailable) state.naiveService = { ready: naiveReady, host: naive.host || state.naiveService.host };
  const mtCredentials = mt.credentials || {};
  const naiveCredentials = naive.credentials || {};
  const naiveKnown = naiveCredentials.available !== false;
  const naiveState = !naiveAvailable ? "Функция отключена" : naiveReady ? "Менеджер работает" : "NaiveProxy недоступен";
  const naiveStatus = !naiveAvailable ? "Отключён" : naiveReady ? "Работает" : "Сбой менеджера";
  const naiveTotals = naive.traffic?.aggregate;

  const cards = [
    protocolCard({
      name: "MTProxy", kind: "MTProto · FakeTLS", ready: mtReady, status: mtReady ? "Работает" : "Недоступен",
      active: number(mtCredentials.active), disabled: number(mtCredentials.disabled),
      traffic: `Σ ${bytes(mt.runtime?.traffic_octets)}`,
      source: `С последнего запуска MTProxy, это не квота · соединений сейчас ${number(mt.runtime?.current_connections)} · активных IP ${number(mt.runtime?.active_ips)}`,
    }),
    protocolCard({
      name: "Mieru", kind: "Native AEAD · TCP", ready: mieruReady, available: mieruAvailable,
      active: number(mieru.credentials?.active), disabled: number(mieru.credentials?.disabled),
      traffic: mieru.traffic?.available ? upDown(mieru.traffic.upload_bytes, mieru.traffic.download_bytes) : "—",
      source: mieru.traffic?.available ? "С запуска mita" : "Менеджер не отдаёт счётчики",
    }),
    protocolCard({
      name: "AmneziaWG", kind: "UDP · WireGuard с маскировкой", ready: awgReady, available: awgAvailable,
      active: number(awg.credentials?.active), disabled: number(awg.credentials?.disabled),
      traffic: upDown(awg.traffic?.upload_bytes, awg.traffic?.download_bytes),
      source: `Счётчики туннелей${awgVersions ? ` · версии доступов ${esc(awgVersions)}` : ""}`,
    }),
    protocolCard({
      name: "TrustTunnel", kind: "HTTP/2 · TCP", ready: ttReady, available: ttAvailable,
      active: number(tt.credentials?.active), disabled: number(tt.credentials?.disabled),
      traffic: upDown(tt.traffic?.upload_bytes, tt.traffic?.download_bytes),
      source: "Счётчики по каждому доступу",
    }),
    protocolCard({
      name: "NaiveProxy", kind: "HTTPS · HTTP/2 CONNECT", ready: naiveReady, status: naiveStatus, className: "naive-card",
      active: naiveKnown ? number(naiveCredentials.active) : "—", disabled: naiveKnown ? number(naiveCredentials.disabled) : "—",
      traffic: `${upDown(naiveTotals?.upload_bytes_decimal, naiveTotals?.download_bytes_decimal)} · Σ ${bytes(naiveTotals?.total_bytes_decimal)}`,
      source: `Считаются только завершённые соединения; текущие появятся после закрытия${naive.host ? ` · ${esc(naive.host)}` : ""}`,
    }),
  ];

  const down = [["MTProxy", true, mtReady], ["NaiveProxy", naiveAvailable, naiveReady], ["Mieru", mieruAvailable, mieruReady],
    ["AmneziaWG", awgAvailable, awgReady], ["TrustTunnel", ttAvailable, ttReady]]
    .filter(([, available, ready]) => available && !ready).map(([name]) => name);
  ui.view.innerHTML = `${attentionBlock(context, { entries, nodes: nodeList, versions, services: down })}<div class="protocol-overview">
    ${hostCard(data.host)}
    ${cards.join("\n    ")}
  </div>
  <div class="dashboard-grid"><section class="panel-card"><div class="panel-head"><h2>Состояние сервисов</h2><span>обновлено сейчас</span></div><div class="service-list">
    <div class="service-row ${mtReady ? "" : "degraded"}"><i></i><span><b>MTProxy · Telemt</b><small>${mtReady ? "Управление отвечает" : "Проверьте Telemt"}</small></span><em>${esc(statusWord(mt.status, mtReady))}</em></div>
    <div class="service-row ${naiveReady || !naiveAvailable ? "" : "degraded"}"><i></i><span><b>NaiveProxy · manager</b><small>${naiveState}</small></span><em>${esc(statusWord(naive.status, naiveReady))}</em></div>
    ${serviceRow("Mieru · manager", mieruAvailable, mieruReady, mieru.status)}
    ${serviceRow("AmneziaWG · manager", awgAvailable, awgReady, awg.status)}
    ${serviceRow("TrustTunnel · manager", ttAvailable, ttReady, tt.status)}
    <div class="service-row ${location.protocol === "https:" ? "" : "degraded"}"><i></i><span><b>Proxy Control${state.me?.panel_version ? ` · ${esc(state.me.panel_version)}` : ""}</b><small>${location.protocol === "https:" ? "HTTPS · защищённое соединение" : "HTTP · соединение не защищено"}</small></span><em>${location.protocol === "https:" ? "защищено" : "не защищено"}</em></div>
  </div></section></div>`;
  fillBars(ui.view);
  bindAttention(context, generation);
  followLive(context, generation);
}
