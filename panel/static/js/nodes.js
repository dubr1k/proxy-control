import { bytes, cssEscape, date, esc, initials, number, query, queryAll } from "./common.js";
import { nodeDetail, refreshCommands, updateCommandFieldsAfterRender } from "./fleet.js";
import { routingSummary } from "./routing.js";
import { isCurrent } from "./state.js";

const ENROLLMENT = {
  local: ["active", "Этот сервер"],
  enrolled: ["active", "Enrolled"],
  unenrolled: ["blocked", "Ожидает сертификат"],
  revoked: ["blocked", "Сертификаты отозваны"],
};

const CONNECTIVITY = {
  not_applicable: "Транспорт не используется",
  never: "Агент ещё не подключался",
  online: "На связи",
  stale: "Давно не выходил на связь",
};

const EXPIRY_WARNING_SECONDS = 14 * 86400;

// The local node is managed directly, so its health is the health of the three managers.
const SERVICES = [["telemt", "Telemt"], ["naive", "NaiveProxy"], ["mieru", "Mieru"]];
const SERVICE_STATE = {
  ok: ["", "работает"],
  unavailable: ["blocked", "недоступен"],
  disabled: ["muted", "выключен"],
};

// A linked panel (Fleet v2) is reached over HTTPS by the central itself: its heartbeat
// decides whether it is on the air, and its own status report describes the daemons.
const LINK_STATUS = {
  online: ["active", "На связи"],
  offline: ["blocked", "Не отвечает"],
  unknown: ["muted", "Ещё не опрашивалась"],
};
const DAEMONS = [["mtproxy", "Telemt"], ["naive", "NaiveProxy"], ["mieru", "Mieru"]];
const DAEMON_STATE = {
  ok: ["", "работает"],
  down: ["blocked", "недоступен"],
  off: ["muted", "выключен"],
};
const PROTOCOL_NAMES = { mtproxy: "MTProxy", naive: "NaiveProxy", mieru: "Mieru" };
const COMPONENT_NAMES = { telemt: "Telemt / MTProxy", naive: "NaiveProxy / Caddy", mita: "Mieru / mita", xray: "Xray-router / Xray-core" };
// Те же компоненты одним словом: строка «Компоненты» в обзоре узла должна помещаться.
const COMPONENT_SHORT = { telemt: "Telemt", naive: "Caddy", mita: "mita", xray: "Xray", panel: "панель" };
const TABS = [["overview", "Обзор"], ["users", "Пользователи"], ["updates", "Обновления"]];
const SHA256 = /^[0-9a-f]{64}$/;

function servicesBlock(node) {
  const services = node.services || {};
  const items = SERVICES.map(([key, label]) => {
    const [tone, word] = SERVICE_STATE[services[key]] || ["muted", "неизвестно"];
    return `<li><span class="status-pill ${tone}"><i></i>${esc(label)} · ${esc(word)}</span></li>`;
  }).join("");
  return `<div class="node-services"><ul>${items}</ul>
    <p class="form-hint">Локальные протоколы управляются напрямую: у этого узла нет ни очереди команд, ни сертификатов.</p></div>`;
}

// What the owner types into a central to link this panel, and — once a central has done
// so — who manages it and the way out (spec §7).
function localLinkBlock(context, node) {
  const identity = node.identity || {};
  const unlink = context.state.me?.role === "owner"
    ? '<button class="danger ghost" data-node-action="unlink">Отвязать</button>'
    : "";
  const master = identity.master_guid
    ? `<div class="node-link-actions"><span class="status-pill"><i></i>управляется центром ${esc(identity.master_guid)}</span>${unlink}</div>`
    : "";
  return `<div class="node-local-link">
    <dl class="node-facts">
      <div><dt>GUID этой панели</dt><dd><code>${esc(identity.guid || "—")}</code></dd></div>
      <div><dt>URL для добавления на центре</dt><dd><code>${esc(window.location.origin)}</code></dd></div>
    </dl>
    <p class="form-hint">Чтобы этим сервером управляла центральная панель, создайте ключ node-sync в «Администраторы → API-ключи» и введите этот URL и ключ на центре.</p>
    ${master}
  </div>`;
}

function certificateLine(certificate) {
  const soon = certificate.state === "active"
    && certificate.not_after - Math.floor(Date.now() / 1000) < EXPIRY_WARNING_SECONDS;
  const note = certificate.state === "active"
    ? `до ${date(certificate.not_after)}${soon ? " · истекает скоро" : ""}`
    : `отозван${certificate.revoked_at ? ` ${date(certificate.revoked_at)}` : ""}`;
  return `<li class="${soon ? "expiring" : ""}"><code>${esc(certificate.serial)}</code> <small>${esc(note)}</small></li>`;
}

function actions(context, node) {
  if (context.state.me?.role !== "owner" || node.kind === "local") return "";
  const toggle = node.disabled
    ? '<button class="secondary" data-node-action="enable">Включить</button>'
    : '<button class="secondary" data-node-action="disable">Отключить</button>';
  return `<div class="node-actions">
    <button class="secondary" data-node-action="rename">Переименовать</button>
    ${toggle}
    <button class="danger ghost" data-node-action="revoke-all">Отозвать все сертификаты</button>
  </div>`;
}

function facts(items) {
  return `<dl class="node-facts">${items.map(([name, value]) => `<div><dt>${name}</dt><dd>${esc(String(value))}</dd></div>`).join("")}</dl>`;
}

// «Маршрутизация: naive → WARP, 2 блокир.; mieru → напрямую» — from the targets table (spec §8.4).
function routingLine(context, node) {
  const items = (context.state.routingTargets || []).filter((item) => item.node_id === node.node_id);
  return ["Маршрутизация", routingSummary(items)];
}

function nodeCard(context, node, expanded) {
  if (node.transport === "panel" && node.link) return linkedCard(context, node, context.state.nodeTab[node.node_id] || "overview");
  const [tone, label] = ENROLLMENT[node.enrollment_state] || ["blocked", node.enrollment_state];
  const inventory = node.inventory || {};
  const summary = [
    ["Транспорт", `${CONNECTIVITY[node.connectivity_state] || node.connectivity_state}${node.last_seen_at ? ` · ${date(node.last_seen_at)}` : ""}`],
    ["Демон", `${inventory.telemt_version ? `Telemt ${inventory.telemt_version}` : "Telemt не определён"} · ${inventory.agent_version ? `агент ${inventory.agent_version}` : "агент не определён"}`],
    ["Команды в очереди", number(node.pending_commands)],
    // Своя версия — рядом с версиями узлов, одной меркой: «эта панель такая-то, на узлах такие».
    ...(node.kind === "local"
      ? [["Панель", `${context.state.me?.panel_version || "версия не определена"} · GUID ${node.identity?.guid || node.node_id}`],
         componentsLine(context.state.versions),
         routingLine(context, node)]
      : []),
  ];
  const certificates = node.certificates?.length
    ? `<ul class="node-certificates">${node.certificates.map(certificateLine).join("")}</ul>`
    : '<p class="form-hint">Сертификатов нет: узел ещё не прошёл enrollment.</p>';
  return `<article class="data-row node-card${node.kind === "local" ? " local-node" : ""}" data-node-id="${esc(node.node_id)}">
    <span class="user-glyph">${esc(initials(node.node_id))}</span>
    <div class="node-identity">
      <b>${esc(node.display_name)}</b>
      <small>${esc(node.node_id)} · ${node.kind === "local" ? "Этот сервер" : "Удалённый узел"}${node.disabled ? " · отключён" : ""}</small>
    </div>
    <span class="status-pill ${tone}"><i></i>${esc(label)}</span>
    ${facts(summary)}
    ${node.kind === "local" ? servicesBlock(node) : certificates}
    ${node.kind === "local" ? localLinkBlock(context, node) : actions(context, node)}
    ${node.kind === "local" ? "" : `<div class="advanced-drawer"><button class="ghost" data-node-action="advanced" aria-expanded="${expanded ? "true" : "false"}">Advanced: транспорт v1</button>${expanded ? `<div class="advanced-body">${nodeDetail(context, context.state.fleet.find((item) => item.node_id === node.node_id), context.state.fleetCommands)}</div>` : ""}</div>`}
  </article>`;
}

// --- linked panels (Fleet v2) -------------------------------------------------------

function daemonsBlock(link) {
  const protocols = link.status_json?.protocols || link.identity?.protocols || {};
  const items = DAEMONS.map(([protocol, label]) => {
    const entry = protocols[protocol] || {};
    const known = Object.hasOwn(DAEMON_STATE, entry.daemon) ? DAEMON_STATE[entry.daemon] : ["muted", "неизвестно"];
    const [tone, word] = entry.enabled === false ? DAEMON_STATE.off : known;
    return `<li><span class="status-pill ${tone}"><i></i>${esc(label)} · ${esc(word)}</span></li>`;
  }).join("");
  return `<div class="node-services"><ul>${items}</ul></div>`;
}

function trafficTotal(link) {
  let total = 0n;
  let reported = false;
  for (const entry of Object.values(link.status_json?.protocols || {})) {
    const value = entry?.traffic?.total_bytes;
    if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
      total += BigInt(Math.floor(value));
      reported = true;
    }
  }
  return reported ? bytes(total.toString()) : "узел не сообщил";
}

function usersSummary(link) {
  let central = 0;
  let local = 0;
  for (const entry of Object.values(link.status_json?.users || {})) {
    central += Number(entry?.central) || 0;
    local += Number(entry?.local) || 0;
  }
  return `центр ${number(central)} · локальные ${number(local)}`;
}

// `config_dirty` stays set until every credential the generation names is in escrow
// (spec §6), so a node that has applied the generation and only owes a credential is
// told apart from one that has not applied it yet.
function generationNote(link) {
  if (!link.config_dirty) return "";
  const applied = link.observed_generation === link.desired_generation && link.observed_state === "converged";
  return applied ? " · применено, ожидает учётные данные" : " · есть недоставленные изменения";
}

// Что где стоит — прямо в обзоре узла, а не только во вкладке «Обновления»: версии берутся
// из его же отчёта, панель ничего дополнительно не спрашивает. Своя версия панели узла —
// отдельной строкой выше, здесь только runtime-компоненты.
function componentsLine(versions) {
  if (!versions || versions.enabled !== true) return ["Компоненты", "узел не сообщил версии"];
  const parts = Object.entries(versions.components || {})
    .filter(([component]) => component !== "panel")
    .map(([component, item]) => `${COMPONENT_SHORT[component] || component} ${item?.current || "—"}`);
  return ["Компоненты", parts.length ? parts.join(" · ") : "каталог версий узла пуст"];
}

function overviewTab(context, node) {
  const link = node.link;
  const [, status] = LINK_STATUS[link.status] || ["muted", link.status];
  const heartbeat = link.last_heartbeat_at ? `heartbeat ${date(link.last_heartbeat_at)}` : "heartbeat ещё не было";
  const latency = link.latency_ms === null || link.latency_ms === undefined ? "" : ` · ${number(link.latency_ms)} мс`;
  const summary = [
    ["Связь", `${status}${latency} · ${heartbeat}`],
    ["Панель", `${link.panel_version || link.identity?.panel_version || "версия не определена"} · GUID ${node.node_id}`],
    componentsLine(link.status_json?.versions),
    ["Поколение", `desired ${number(link.desired_generation)} · applied ${number(link.acknowledged_generation)}${generationNote(link)}`],
    ["Пользователи", `${usersSummary(link)} · ${link.auto_import === false ? "импорт вручную" : "подхватываются автоматически"}`],
    ["Трафик", trafficTotal(link)],
    routingLine(context, node),
  ];
  return `${facts(summary)}
    ${daemonsBlock(link)}
    ${link.last_error ? `<p class="form-hint node-error">Ошибка: ${esc(link.last_error)}</p>` : ""}`;
}

function inventoryRow(protocol, item, canImport) {
  const linked = item.linked_grant_id !== null && item.linked_grant_id !== undefined;
  const pick = !linked && canImport ? '<input type="checkbox" class="node-import-pick" aria-label="Импортировать">' : "";
  return `<tr data-import-protocol="${esc(protocol)}" data-import-username="${esc(item.runtime_username)}">
    <td>${pick}</td>
    <td>${esc(PROTOCOL_NAMES[protocol] || protocol)}</td>
    <td><code>${esc(item.runtime_username)}</code></td>
    <td>${item.enabled === false ? "выключен" : "включён"} · ${item.ownership === "central" ? "управляется центром" : "локальный"}</td>
    <td><small>${linked ? "привязан" : "не импортирован"}</small></td>
  </tr>`;
}

function usersTab(context, node) {
  const entry = context.state.nodeInventory[node.node_id];
  if (!entry) return '<p class="form-hint">Читаем пользователей узла…</p>';
  if (entry.error) return `<p class="form-hint node-error">${esc(entry.error)}</p>`;
  const canImport = context.state.me?.role === "owner";
  const accounts = Object.entries(entry.protocols || {})
    .flatMap(([protocol, items]) => (items || []).map((item) => [protocol, item]));
  const rows = accounts.map(([protocol, item]) => inventoryRow(protocol, item, canImport));
  const importable = canImport && accounts.some(([, item]) => item.linked_grant_id === null || item.linked_grant_id === undefined);
  return `<div class="import-table-wrap"><table class="import-table">
      <thead><tr><th></th><th>Протокол</th><th>Учётная запись</th><th>Состояние</th><th>Доступ</th></tr></thead>
      <tbody>${rows.join("") || '<tr><td colspan="5">Узел не сообщил ни одного пользователя.</td></tr>'}</tbody>
    </table></div>
    ${importable ? '<div class="node-import-actions"><button class="secondary" data-node-action="import">Импортировать выбранных</button><span class="form-hint">На каждую учётную запись создаётся клиент; секрет забирается там, где протокол это позволяет.</span></div>' : ""}`;
}

function updatesTab(context, node) {
  const versions = node.link.status_json?.versions;
  if (!versions || versions.enabled !== true) {
    return '<p class="form-hint">Агент обновлений на узле недоступен: версии компонентов не сообщены.</p>';
  }
  const canUpdate = context.state.me?.role === "owner";
  const items = Object.entries(versions.components || {}).map(([component, item]) => {
    const current = item?.current || "не определена";
    const offered = (Array.isArray(item?.available) ? item.available : [])
      .filter((entry) => entry?.version && entry.version !== current);
    const control = offered.length && canUpdate
      ? `<select data-node-version-select="${esc(component)}" aria-label="Версия ${esc(component)}"><option value="">Выберите версию</option>${offered.map((entry) => `<option value="${esc(entry.version)}">${esc(entry.version)} · ${esc(entry.kind || "artifact")}</option>`).join("")}</select>
        <button class="secondary" data-node-action="update-component" data-component="${esc(component)}" data-current="${esc(current)}">Обновить</button>`
      : `<small>${offered.length ? "" : "обновлений в каталоге узла нет"}</small>`;
    return `<li class="node-component"><span><b>${esc(COMPONENT_NAMES[component] || component)}</b><small>текущая версия: ${esc(current)}</small></span>${control}</li>`;
  }).join("");
  // v0.11: a node that reports `versions.check` can be asked to poll upstream; the result
  // lands in its next heartbeat. An older node without it keeps the catalog-only tab.
  const canCheck = canUpdate && (node.link.identity?.capabilities || []).includes("versions.check") && versions.upstream_enabled !== false;
  const checked = versions.checked_at ? `проверено ${date(versions.checked_at)}` : "upstream ещё не проверялся";
  const checkBar = canCheck
    ? `<div class="node-link-actions"><small>${esc(checked)}</small><button class="secondary" data-node-action="check-versions">Проверить обновления</button></div>`
    : "";
  return `${checkBar}<ul class="node-components">${items || '<li class="node-component"><span><b>Каталог версий узла пуст</b></span></li>'}</ul>
    <p class="form-hint">Обновляет version-agent самого узла по своему каталогу и кэшу upstream; панель передаёт только имя версии и ту, что показана как текущая.</p>`;
}

function linkedActions(context, node) {
  if (context.state.me?.role !== "owner") return "";
  // `NodeView.disabled` does not reflect a paused link; `link.enabled` does.
  const toggle = node.link.enabled
    ? '<button class="secondary" data-node-action="pause">Пауза</button>'
    : '<button class="secondary" data-node-action="resume">Возобновить</button>';
  return `<div class="node-actions">
    ${toggle}
    <button class="secondary" data-node-action="probe">Проверить</button>
    <button class="secondary" data-node-action="edit">Изменить</button>
    <button class="danger ghost" data-node-action="remove">Удалить</button>
  </div>`;
}

function linkedCard(context, node, tab) {
  const link = node.link;
  const [tone, label] = LINK_STATUS[link.status] || ["muted", link.status];
  const body = tab === "users" ? usersTab(context, node) : tab === "updates" ? updatesTab(context, node) : overviewTab(context, node);
  const tabs = TABS.map(([key, name]) => `<button class="${key === tab ? "active" : ""}" role="tab" aria-selected="${key === tab ? "true" : "false"}" data-node-action="tab-${key}">${name}</button>`).join("");
  return `<article class="data-row node-card linked-node" data-node-id="${esc(node.node_id)}">
    <span class="user-glyph">${esc(initials(node.display_name))}</span>
    <div class="node-identity">
      <b>${esc(node.display_name)}</b>
      <small>${esc(link.panel_url)} · панель ${esc(link.panel_version || "?")}${link.enabled ? "" : " · пауза"}</small>
    </div>
    <span class="status-pill ${tone}"><i></i>${esc(label)}</span>
    <div class="node-tabs" role="tablist">${tabs}</div>
    <div class="node-tab-body">${body}</div>
    ${linkedActions(context, node)}
  </article>`;
}

async function loadInventories(context) {
  const open = context.state.nodes.filter((node) => node.transport === "panel" && context.state.nodeTab[node.node_id] === "users");
  const entries = await Promise.all(open.map(async (node) => {
    try {
      return [node.node_id, await context.api(`/api/nodes/${encodeURIComponent(node.node_id)}/inventory`)];
    } catch (error) {
      return [node.node_id, { error: error.message }];
    }
  }));
  return Object.fromEntries(entries);
}

export async function renderNodes(context, generation) {
  const [data, transport, routing, versions] = await Promise.all([
    context.api("/api/nodes"),
    context.api("/api/fleet/nodes"),
    // The routing line is a courtesy: a panel whose routing targets cannot be read still lists its nodes.
    context.api("/api/routing/targets").catch(() => ({ items: [] })),
    // Свои версии — такая же любезность: без version-agent строка скажет, что версий нет.
    context.api("/api/versions").catch(() => ({ enabled: false, components: {} })),
  ]);
  if (!isCurrent(context.state, generation, "fleet")) return;
  context.state.versions = versions || { enabled: false, components: {} };
  context.state.nodes = data.items || [];
  context.state.fleet = transport.items || [];
  context.state.routingTargets = routing.items || [];
  const count = query("#fleet-count", context.root);
  if (count) count.textContent = context.state.nodes.length;
  const expanded = context.state.fleetSelection;
  if (expanded && context.state.nodes.some((node) => node.node_id === expanded && node.kind !== "local")) {
    const commands = await refreshCommands(context, expanded, generation);
    if (commands === null) return;
  }
  // A linked panel's users are read only for an open «Пользователи» tab (spec §7).
  const inventories = await loadInventories(context);
  if (!isCurrent(context.state, generation, "fleet")) return;
  context.state.nodeInventory = inventories;
  const owner = context.state.me?.role === "owner";
  context.ui.view.innerHTML = `<div class="security-note">Связанные панели центр опрашивает сам по HTTPS с их API-ключом node-sync; узлы v1 подключаются исходящим mTLS long-poll, идентичность привязана к сертификату. Отключённый или поставленный на паузу узел не получает изменений.</div>
    ${owner ? '<div class="toolbar"><button class="secondary" data-node-action="register-v1">Зарегистрировать узел v1 (mTLS-агент)</button></div>' : ""}
    <section class="node-list">${context.state.nodes.length
      ? context.state.nodes.map((node) => nodeCard(context, node, node.node_id === expanded)).join("")
      : '<div class="empty-state"><span>◇</span><h3>Узлов пока нет</h3><p>Владелец может добавить панель по URL и API-ключу или зарегистрировать узел v1 — панель покажет пошаговый enrollment.</p></div>'}</section>`;
  // The v1 command form hides fields per operation, so it needs one pass after render.
  if (expanded) updateCommandFieldsAfterRender(context);
}

function checklist(steps) {
  return `<ol class="enrollment-checklist">${steps.map((step) => `<li><code>${esc(step)}</code></li>`).join("")}</ol>`;
}

export function openNodeModal(context) {
  const form = query("#node-form", context.root);
  form.reset();
  query("#node-error", context.root).textContent = "";
  query("#node-checklist", context.root).innerHTML = "";
  context.ui.openModal("#node-modal", "#node-id");
}

// One dialog for both linking a panel and editing the link: in edit mode the key field
// left blank means "не менять", and the probe/import step is not offered.
export function openLinkModal(context, node = null) {
  const { root } = context;
  const editing = Boolean(node);
  query("#link-form", root).reset();
  context.state.linkProbe = null;
  query("#link-node-id", root).value = node?.node_id || "";
  query("#link-title", root).textContent = editing ? "Изменить связь с панелью" : "Добавить панель";
  query("#link-save", root).textContent = editing ? "Сохранить" : "Добавить";
  query("#link-name", root).value = node?.display_name || "";
  query("#link-url", root).value = node?.link?.panel_url || "";
  query("#link-key", root).required = !editing;
  query("#link-key-hint", root).textContent = editing
    ? (node.link?.has_api_key ? "Ключ сохранён: оставьте поле пустым, чтобы не менять" : "Ключ не сохранён: введите новый")
    : "Ключ со scope node-sync, созданный на добавляемой панели";
  queryAll('input[name="tls_verify"]', root).forEach((radio) => {
    radio.checked = radio.value === (node?.link?.tls_verify || "verify");
  });
  query("#link-private-row", root).hidden = editing;
  query("#link-auto-import", root).checked = node?.link ? node.link.auto_import !== false : true;
  query("#link-test", root).hidden = editing;
  query("#link-result", root).hidden = true;
  query("#node-import-list", root).innerHTML = "";
  query("#link-error", root).textContent = "";
  context.ui.openModal("#link-modal", editing ? "#link-name" : "#link-url");
}

function linkForm(context) {
  const { root } = context;
  const tls = query('input[name="tls_verify"]:checked', root)?.value || "verify";
  const pinned = query("#link-pinned", root).value.trim().toLowerCase();
  if (tls === "pin" && pinned && !SHA256.test(pinned)) {
    throw new Error("Отпечаток — 64 шестнадцатеричных символа SHA-256");
  }
  // Editing keeps the stored pin when the field is blank; a new link has none to keep.
  if (tls === "pin" && !pinned && !query("#link-node-id", root).value) {
    throw new Error("Для режима pin укажите отпечаток: введите его или нажмите «Получить отпечаток»");
  }
  const payload = {
    url: query("#link-url", root).value.trim(),
    tls_verify: tls,
    allow_private_address: query("#link-private", root).checked,
    auto_import: query("#link-auto-import", root).checked,
  };
  if (tls === "pin" && pinned) payload.pinned_sha256 = pinned;
  const key = query("#link-key", root).value;
  if (key) payload.api_key = key;
  return payload;
}

function probeResult(probe) {
  const identity = probe.identity || {};
  const protocols = Object.entries(identity.protocols || {})
    .map(([protocol, entry]) => `${PROTOCOL_NAMES[protocol] || protocol}${entry?.enabled === false ? " (выкл.)" : ""}${entry?.public_host ? ` · ${entry.public_host}` : ""}`);
  const summary = [
    ["GUID", identity.guid || "—"],
    ["Версия панели", identity.panel_version || "—"],
    ["Протоколы", protocols.join(", ") || "не сообщены"],
    ["Задержка", `${number(probe.latency_ms)} мс`],
  ];
  return facts(summary);
}

function importCandidates(probe) {
  return Object.entries(probe.inventory?.protocols || {})
    .flatMap(([protocol, items]) => (items || []).map((item) => ({ protocol, ...item })));
}

function importList(candidates) {
  if (!candidates.length) return '<p class="form-hint">Пользователей для импорта на панели нет.</p>';
  const rows = candidates.map((item) => `<tr data-import-protocol="${esc(item.protocol)}" data-import-username="${esc(item.runtime_username)}">
      <td><input type="checkbox" class="node-import-pick" aria-label="Импортировать"${item.ownership === "central" ? " disabled" : ""}></td>
      <td>${esc(PROTOCOL_NAMES[item.protocol] || item.protocol)}</td>
      <td><code>${esc(item.runtime_username)}</code></td>
      <td>${item.enabled === false ? "выключен" : "включён"}${item.ownership === "central" ? " · уже управляется центром" : ""}</td>
    </tr>`).join("");
  return `<p class="form-hint">Отметьте учётные записи, которые центр заберёт под управление; на каждую будет создан клиент.</p>
    <div class="import-table-wrap"><table class="import-table">
      <thead><tr><th></th><th>Протокол</th><th>Учётная запись</th><th>Состояние</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

function pickedImports(scope) {
  return queryAll("tr", scope)
    .filter((row) => query(".node-import-pick", row)?.checked)
    .map((row) => ({ protocol: row.dataset.importProtocol, runtime_username: row.dataset.importUsername, client: "new" }));
}

function importSummary(result) {
  const parts = [`импортировано: ${result.imported?.length || 0}`];
  if (result.without_credential?.length) parts.push(`без секрета: ${result.without_credential.length}`);
  if (result.already_linked?.length) parts.push(`уже привязано: ${result.already_linked.length}`);
  return parts.join(", ");
}

async function importInto(context, nodeId, resources) {
  if (!resources.length) return null;
  return context.api(`/api/nodes/${encodeURIComponent(nodeId)}/import`, {
    method: "POST",
    body: JSON.stringify({ resources }),
  });
}

function bindLinkDialog(context) {
  const { api, root, ui } = context;
  const form = query("#link-form", root);
  if (!form) return;
  // A probe describes the fields as they were: any edit after it invalidates the result.
  // Ticking an import checkbox inside the result is not such an edit.
  form.addEventListener("input", (event) => {
    if (event.target.closest("#link-result")) return;
    context.state.linkProbe = null;
    query("#link-result", root).hidden = true;
  });
  query("#link-fingerprint", root).addEventListener("click", async ({ currentTarget: button }) => {
    const error = query("#link-error", root);
    const url = query("#link-url", root).value.trim();
    error.textContent = "";
    if (!url) {
      error.textContent = "Сначала укажите URL панели";
      return;
    }
    try {
      ui.setBusy(button, true, "Запрашиваем…");
      const result = await api("/api/nodes/fingerprint", { method: "POST", body: JSON.stringify({ url }) });
      query("#link-pinned", root).value = result.sha256;
      query('input[name="tls_verify"][value="pin"]', root).checked = true;
      ui.toast("Отпечаток получен: сверьте его с тем, что показывает сама панель");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#link-test", root).addEventListener("click", async ({ currentTarget: button }) => {
    const error = query("#link-error", root);
    if (!form.reportValidity()) return;
    error.textContent = "";
    try {
      const payload = linkForm(context);
      ui.setBusy(button, true, "Проверяем…");
      const probe = await api("/api/nodes/test", { method: "POST", body: JSON.stringify(payload) });
      context.state.linkProbe = probe;
      query("#link-result-facts", root).innerHTML = probeResult(probe);
      query("#node-import-list", root).innerHTML = importList(importCandidates(probe));
      query("#link-result", root).hidden = false;
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#link-save", root).addEventListener("click", async ({ currentTarget: button }) => {
    const error = query("#link-error", root);
    if (!form.reportValidity()) return;
    error.textContent = "";
    const nodeId = query("#link-node-id", root).value;
    const displayName = query("#link-name", root).value.trim();
    try {
      const payload = linkForm(context);
      if (nodeId) {
        // Update: `allow_private_address` stays what it was at link time.
        delete payload.allow_private_address;
        ui.setBusy(button, true, "Сохраняем…");
        await api(`/api/nodes/${encodeURIComponent(nodeId)}/link`, {
          method: "POST",
          body: JSON.stringify({ ...payload, display_name: displayName }),
        });
        query("#link-modal", root).close();
        ui.toast("Связь с панелью обновлена");
      } else {
        if (!context.state.linkProbe) {
          error.textContent = "Сначала нажмите «Проверить»: панель должна ответить на identity и status";
          return;
        }
        const resources = pickedImports(query("#node-import-list", root));
        ui.setBusy(button, true, "Добавляем…");
        const linked = await api("/api/nodes/link", {
          method: "POST",
          body: JSON.stringify({ ...payload, display_name: displayName }),
        });
        query("#link-modal", root).close();
        ui.toast("Панель добавлена");
        try {
          const result = await importInto(context, linked.node_id, resources);
          if (result) ui.toast(`Импорт с панели — ${importSummary(result)}`);
        } catch (exception) {
          // The link is in place; the import can be repeated from the «Пользователи» tab.
          ui.toast(`Панель добавлена, но импорт не удался: ${exception.message}`, "error");
        }
      }
      context.state.linkProbe = null;
      await context.navigate("fleet");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#link-modal", root).addEventListener("close", () => {
    // The key never lingers in the form once the dialog is gone.
    query("#link-key", root).value = "";
    context.state.linkProbe = null;
  });
}

export function bindNodes(context) {
  const { api, root, ui } = context;
  query("#create-node", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#node-form", root);
    const error = query("#node-error", root);
    if (!form.reportValidity()) return;
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Регистрируем…");
      const body = await api("/api/nodes", {
        method: "POST",
        body: JSON.stringify({
          node_id: query("#node-id", root).value,
          display_name: query("#node-name", root).value.trim(),
        }),
      });
      // The dialog stays open: the operator still has to run the enrollment steps.
      query("#node-checklist", root).innerHTML = checklist(body.enrollment_checklist || []);
      ui.toast("Узел зарегистрирован; выполните enrollment");
      await context.navigate("fleet");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#confirm-node-revoke", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const error = query("#node-revoke-error", root);
    const nodeId = query("#node-revoke-id", root).value;
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Отзываем…");
      const result = await api(`/api/nodes/${encodeURIComponent(nodeId)}/certificates/revoke-all`, {
        method: "POST",
        body: JSON.stringify({ confirm: query("#node-revoke-confirm", root).value.trim() }),
      });
      query("#node-revoke-modal", root).close();
      ui.toast(`Отозвано сертификатов: ${result.revoked}`);
      await context.navigate("fleet");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#save-node-name", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#node-rename-form", root);
    const error = query("#node-rename-error", root);
    if (!form.reportValidity()) return;
    const nodeId = query("#node-rename-id", root).value;
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Сохраняем…");
      await api(`/api/nodes/${encodeURIComponent(nodeId)}/rename`, {
        method: "POST",
        body: JSON.stringify({ display_name: query("#node-rename-name", root).value.trim() }),
      });
      query("#node-rename-modal", root).close();
      ui.toast("Имя узла обновлено");
      await context.navigate("fleet");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#confirm-unlink", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const error = query("#unlink-error", root);
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Отвязываем…");
      const result = await api("/api/nodes/local/unlink", { method: "POST" });
      query("#unlink-modal", root).close();
      ui.toast(`Связь с центром разорвана; учётных записей переведено в локальные: ${number(result.released)}`);
      await context.navigate("fleet");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  bindLinkDialog(context);
}

async function lifecycle(context, nodeId, action) {
  const node = context.state.nodes.find((item) => item.node_id === nodeId);
  if (!node) return;
  try {
    if (action === "rename") {
      query("#node-rename-id", context.root).value = nodeId;
      query("#node-rename-name", context.root).value = node.display_name;
      query("#node-rename-error", context.root).textContent = "";
      context.ui.openModal("#node-rename-modal", "#node-rename-name");
      return;
    }
    if (action === "revoke-all") {
      // Typed confirmation lives in its own dialog: the operator repeats the node id,
      // so an accidental click cannot cut a node off the transport.
      query("#node-revoke-id", context.root).value = nodeId;
      query("#node-revoke-confirm", context.root).value = "";
      query("#node-revoke-name", context.root).textContent = `${node.display_name} (${nodeId})`;
      query("#node-revoke-error", context.root).textContent = "";
      context.ui.openModal("#node-revoke-modal", "#node-revoke-confirm");
      return;
    }
    {
      if (action === "disable") {
        const confirmed = await context.ui.confirmed(
          "Отключить узел?",
          `${node.display_name} перестанет проходить аутентификацию, пока его не включат обратно.`,
          "Отключить",
        );
        if (!confirmed) return;
      }
      await context.api(`/api/nodes/${encodeURIComponent(nodeId)}/${action}`, { method: "POST" });
      context.ui.toast(action === "disable" ? "Узел отключён" : "Узел включён");
    }
    await context.navigate("fleet");
  } catch (exception) {
    context.ui.toast(exception.message, "error");
  }
}

// Actions of a linked panel: pause/resume/probe/remove call the central's routes; edit
// reopens the link dialog; import and update-component act on the open tab.
async function linkLifecycle(context, node, action, button) {
  const path = (suffix) => `/api/nodes/${encodeURIComponent(node.node_id)}${suffix}`;
  try {
    if (action === "edit") {
      openLinkModal(context, node);
      return;
    }
    if (action === "remove") {
      const confirmed = await context.ui.confirmed(
        "Удалить связь с панелью?",
        `${node.display_name} перестанет управляться этим центром. Импортированные пользователи останутся на узле локальными; панель откажет, пока остаются неудалённые выданные доступы.`,
        "Удалить",
      );
      if (!confirmed) return;
      context.ui.setBusy(button, true, "Удаляем…");
      await context.api(path(""), { method: "DELETE" });
      context.ui.toast("Связь с панелью удалена");
    } else if (action === "import") {
      const card = button.closest("[data-node-id]");
      const resources = pickedImports(card);
      if (!resources.length) {
        context.ui.toast("Не отмечено ни одной учётной записи", "error");
        return;
      }
      context.ui.setBusy(button, true, "Импортируем…");
      const result = await importInto(context, node.node_id, resources);
      context.ui.toast(`Импорт с панели — ${importSummary(result)}`);
    } else if (action === "update-component") {
      const { component, current } = button.dataset;
      const version = query(`[data-node-version-select="${cssEscape(component)}"]`, button.closest(".node-component"))?.value;
      if (!version) {
        context.ui.toast("Выберите версию", "error");
        return;
      }
      const confirmed = await context.ui.confirmed(
        "Обновить компонент узла?",
        `${node.display_name} · ${component}: ${current} → ${version}. Version-agent узла перезапустит сервис и при ошибке выполнит rollback.`,
        "Обновить",
      );
      if (!confirmed) return;
      context.ui.setBusy(button, true, "Обновляем…");
      await context.api(path(`/versions/${encodeURIComponent(component)}`), {
        method: "POST",
        body: JSON.stringify({ version, expected_current: current === "не определена" ? null : current }),
      });
      context.ui.toast(`${component} на узле обновляется до ${version}; версии обновятся после следующего heartbeat`);
    } else if (action === "check-versions") {
      context.ui.setBusy(button, true, "Проверяем…");
      await context.api(path("/versions/check"), { method: "POST" });
      context.ui.toast("Узел опросил upstream; список версий обновится после следующего heartbeat");
    } else {
      const [route, message] = LINK_ROUTES[action];
      context.ui.setBusy(button, true);
      await context.api(path(route), { method: "POST" });
      context.ui.toast(message);
    }
    await context.navigate("fleet");
  } catch (exception) {
    context.ui.toast(exception.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

// The central's routes for a linked panel, by card action (spec §6).
const LINK_ROUTES = {
  pause: ["/pause", "Узел поставлен на паузу"],
  resume: ["/resume", "Узел возобновлён"],
  probe: ["/probe", "Узел опрошен"],
};
const LINK_ACTIONS = new Set([...Object.keys(LINK_ROUTES), "edit", "remove", "import", "update-component"]);

export function handleNodesClick(context, button) {
  const action = button.dataset.nodeAction;
  if (!action) return false;
  if (action === "register-v1") {
    openNodeModal(context);
    return true;
  }
  const card = button.closest("[data-node-id]");
  if (!card) return false;
  const nodeId = card.dataset.nodeId;
  if (action === "advanced") {
    context.state.fleetSelection = context.state.fleetSelection === nodeId ? "" : nodeId;
    context.state.fleetCommands = [];
    void context.navigate("fleet");
    return true;
  }
  if (action.startsWith("tab-")) {
    const tab = action.slice(4);
    if (TABS.some(([key]) => key === tab)) {
      context.state.nodeTab[nodeId] = tab;
      void context.navigate("fleet");
    }
    return true;
  }
  if (action === "unlink") {
    const node = context.state.nodes.find((item) => item.node_id === nodeId);
    query("#unlink-master", context.root).textContent = node?.identity?.master_guid || "—";
    query("#unlink-error", context.root).textContent = "";
    context.ui.openModal("#unlink-modal");
    return true;
  }
  if (LINK_ACTIONS.has(action)) {
    const node = context.state.nodes.find((item) => item.node_id === nodeId);
    if (node?.link) void linkLifecycle(context, node, action, button);
    return true;
  }
  void lifecycle(context, nodeId, action);
  return true;
}
