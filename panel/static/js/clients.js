import { esc, icon, OPERATION_MESSAGE, OPERATION_OK, paintClientsCount, query, queryAll } from "./common.js";
import { grantRowHtml, nodeName, PROTOCOL_NAMES } from "./grant.js";
import { placementDiff, placementRows, readPlacement, renderPlacement } from "./placement.js";
import { isCurrent } from "./state.js";

const CLIENT_STATE = {
  active: ["active", "Активен"],
  suspended: ["blocked", "Приостановлен"],
  archived: ["muted", "В архиве"],
};

// One order on every card, whatever order the grants were issued in.
const PROTOCOL_ORDER = { mtproxy: 0, naive: 1, mieru: 2 };

function byProtocol(left, right) {
  return (PROTOCOL_ORDER[left.protocol] ?? 9) - (PROTOCOL_ORDER[right.protocol] ?? 9)
    || String(left.node_id || "").localeCompare(String(right.node_id || ""))
    || String(left.runtime_username).localeCompare(String(right.runtime_username));
}

function liveGrants(entry) {
  return (entry?.grants || []).filter((grant) => grant.desired_state !== "deleted");
}

// Only Mieru cannot hand its credential back, so only Mieru costs the subscriber
// their current link when adopted.
const ROTATION_REQUIRED = new Set(["mieru"]);

function adoptNote(context, grants) {
  const orphans = grants.filter((grant) => grant.secret_ref === null && grant.desired_state !== "deleted");
  if (!orphans.length || context.state.me?.role === "viewer") return "";
  const buttons = orphans.map((grant) => {
    const warn = ROTATION_REQUIRED.has(grant.protocol);
    return `<button class="secondary" data-client-action="adopt" data-grant-id="${esc(grant.id)}"
      data-grant-protocol="${esc(grant.protocol)}"
      title="${warn ? "Потребуется ротация: старая ссылка перестанет работать" : "Панель прочитает текущий секрет, ссылка продолжит работать"}"
      >Принять ${esc(PROTOCOL_NAMES[grant.protocol] || grant.protocol)} · ${esc(grant.runtime_username)}</button>`;
  }).join("");
  return `<div class="client-note"><p class="form-hint">Нет сохранённого секрета у доступов: ${orphans.length}. Такой доступ не попадает в подписку и не даёт ссылку.</p><span class="client-note-actions">${buttons}</span></div>`;
}

function actions(context, client) {
  // The client window is read-only for viewers, so it is offered to everyone; the buttons
  // that change anything appear inside it by role.
  const open = '<button class="secondary" data-client-action="open">Открыть</button>';
  if (context.state.me?.role === "viewer" || client.state === "archived") {
    return `<div class="client-actions">${open}</div>`;
  }
  const toggle = client.state === "suspended"
    ? '<button class="secondary" data-client-action="resume">Возобновить</button>'
    : '<button class="secondary" data-client-action="suspend">Приостановить</button>';
  // The same window, opened on its node × protocol matrix: add a node with a tick, take one
  // away with the cross — without hunting for it below the subscription block (v0.11).
  const placement = '<button class="secondary" data-client-action="placement">Узлы и доступы</button>';
  return `<div class="client-actions">
    ${open}
    ${placement}
    ${toggle}
    <button class="danger ghost" data-client-action="archive">Архивировать</button>
  </div>`;
}

function plural(count, one, few, many) {
  const tens = count % 100;
  const units = count % 10;
  if (tens >= 11 && tens <= 14) return many;
  if (units === 1) return one;
  if (units >= 2 && units <= 4) return few;
  return many;
}

// Under the name: how many accesses and where, so the card says it before it is opened.
function summary(context, grants) {
  if (!grants.length) return "Доступов нет";
  const nodes = new Set(grants.map((grant) => grant.node_id || "local"));
  const where = nodes.size === 1
    ? nodeName(context.state.nodes, [...nodes][0])
    : `${nodes.size} ${plural(nodes.size, "узел", "узла", "узлов")}`;
  return `${grants.length} ${plural(grants.length, "доступ", "доступа", "доступов")} · ${where}`;
}

function clientCard(context, entry) {
  const { client } = entry;
  const grants = liveGrants(entry);
  const [tone, label] = CLIENT_STATE[client.state] || ["blocked", client.state];
  const empty = client.state === "archived"
    ? "Доступов нет — клиент в архиве"
    : "Доступов пока нет — выдайте их в «Узлы и доступы» или импортируйте существующие";
  return `<article class="client-card" data-client-id="${esc(client.id)}" data-client-state="${esc(client.state)}">
    <span class="user-glyph" aria-hidden="true">${icon("client")}</span>
    <button type="button" class="client-identity" data-client-action="open">
      <b>${esc(client.display_name)}</b>
      <small>${esc(summary(context, grants))}</small>
    </button>
    <span class="status-pill ${tone}"><i></i>${esc(label)}</span>
    ${actions(context, client)}
    ${grants.length
      ? `<ul class="client-grants">${[...grants].sort(byProtocol).map((grant) => grantRowHtml(grant, { nodes: context.state.nodes })).join("")}</ul>`
      : `<p class="client-empty">${esc(empty)}</p>`}
    ${adoptNote(context, grants)}
  </article>`;
}

// Working clients first, archived ones at the bottom; the list's own order within each.
const STATE_ORDER = { active: 0, suspended: 1, archived: 2 };

function byState(left, right) {
  return (STATE_ORDER[left?.client?.state] ?? 1) - (STATE_ORDER[right?.client?.state] ?? 1);
}

// One malformed entry (an option shape a newer node reports, say) must not take the whole
// list down: the card says what it could not render, the rest of the clients stay visible.
function safeCard(context, entry) {
  try {
    return clientCard(context, entry);
  } catch (error) {
    console.error("client card failed to render", error);
    const name = entry?.client?.display_name || entry?.client?.id || "?";
    return `<article class="client-card client-card-error"><b>${esc(String(name))}</b>
      <small>Карточку не удалось отобразить — обновите страницу или проверьте консоль браузера.</small></article>`;
  }
}

// --- Search and filters (v1.0.2): by name, account, node, protocol and the state of grants. ---

export const CLIENT_FILTER_DEFAULT = { query: "", state: "all", protocol: "", node: "", issue: "" };

const ISSUES = {
  problem: ["С проблемами", (grant) => ["failed", "pending", "drifted", "missing"].includes(grant.observed_state) || grant.secret_ref === null],
  pending: ["Ожидают узел", (grant) => grant.observed_state === "pending"],
  failed: ["С ошибкой", (grant) => grant.observed_state === "failed"],
  orphan: ["Без секрета", (grant) => grant.secret_ref === null],
  disabled: ["С выключенными доступами", (grant) => grant.desired_state === "disabled"],
  lane: ["Со своей полосой", (grant) => grant.routing_lane === "own"],
};

function filters(context) {
  if (!context.state.clientFilter) context.state.clientFilter = { ...CLIENT_FILTER_DEFAULT };
  return context.state.clientFilter;
}

function haystack(context, entry) {
  const parts = [entry.client.display_name, entry.client.id];
  for (const grant of liveGrants(entry)) {
    parts.push(grant.runtime_username, PROTOCOL_NAMES[grant.protocol] || grant.protocol, nodeName(context.state.nodes, grant.node_id));
  }
  return parts.join("\n").toLowerCase();
}

export function matchesClient(context, entry, filter = filters(context)) {
  if (filter.state !== "all" && entry.client.state !== filter.state) return false;
  const needle = filter.query.trim().toLowerCase();
  if (needle && !needle.split(/\s+/).every((word) => haystack(context, entry).includes(word))) return false;
  // The grant-level conditions hold on one and the same grant: «Mieru on Frankfurt» means
  // a Mieru grant there, not a Mieru grant somewhere and anything in Frankfurt.
  const placed = liveGrants(entry).filter((grant) => (!filter.protocol || grant.protocol === filter.protocol)
    && (!filter.node || (grant.node_id || "local") === filter.node));
  // «Без доступов» reads with the other two: no Mieru at all, nothing on Frankfurt.
  if (filter.issue === "empty") return placed.length === 0;
  if (!filter.protocol && !filter.node && !filter.issue) return true;
  return placed.some((grant) => !filter.issue || ISSUES[filter.issue]?.[1](grant));
}

function filtered(context) {
  return [...context.state.clients].sort(byState).filter((entry) => matchesClient(context, entry));
}

function filterActive(filter) {
  return Object.entries(CLIENT_FILTER_DEFAULT).some(([key, value]) => filter[key] !== value);
}

function countLabel(shown, total) {
  return shown === total ? `Клиентов: ${total}` : `Показано ${shown} из ${total}`;
}

function nodeFilterOptions(context, selected) {
  const ids = new Set(["local"]);
  for (const node of context.state.nodes || []) if (node.node_id === "local" || node.transport === "panel") ids.add(node.node_id);
  for (const entry of context.state.clients) for (const grant of liveGrants(entry)) ids.add(grant.node_id || "local");
  return [...ids].map((id) => `<option value="${esc(id)}"${id === selected ? " selected" : ""}>${esc(nodeName(context.state.nodes, id))}</option>`).join("");
}

function toolbar(context) {
  const filter = filters(context);
  const clients = context.state.clients;
  const count = (state) => clients.filter((entry) => entry.client.state === state).length;
  const pill = (value, label) => `<button type="button" class="filter-pill${filter.state === value ? " active" : ""}" data-client-filter-state="${value}" aria-pressed="${filter.state === value}">${label}</button>`;
  const option = (value, label, current) => `<option value="${esc(value)}"${value === current ? " selected" : ""}>${esc(label)}</option>`;
  const canImport = context.state.me?.role !== "viewer";
  return `<div class="client-toolbar">
      <div class="client-toolbar-row">
        <div class="search"><input id="client-search" type="search" value="${esc(filter.query)}" placeholder="Поиск: клиент, учётная запись, узел" aria-label="Поиск клиентов" autocomplete="off"></div>
        ${canImport ? '<button class="secondary" data-client-action="import">Импорт существующих</button>' : ""}
      </div>
      <div class="filter-pills client-state-filter" role="group" aria-label="Состояние клиента">
        ${pill("all", `Все · ${clients.length}`)}${pill("active", `Активные · ${count("active")}`)}${pill("suspended", `Приостановленные · ${count("suspended")}`)}${pill("archived", `В архиве · ${count("archived")}`)}
      </div>
      <div class="client-filters">
        <select id="client-filter-protocol" aria-label="Протокол">${option("", "Любой протокол", filter.protocol)}${Object.entries(PROTOCOL_NAMES).map(([value, label]) => option(value, label, filter.protocol)).join("")}</select>
        <select id="client-filter-node" aria-label="Узел">${option("", "Любой узел", filter.node)}${nodeFilterOptions(context, filter.node)}</select>
        <select id="client-filter-issue" aria-label="Состояние доступов">${option("", "Любые доступы", filter.issue)}${Object.entries(ISSUES).map(([value, [label]]) => option(value, label, filter.issue)).join("")}${option("empty", "Без доступов", filter.issue)}</select>
        <button type="button" class="ghost" data-client-action="reset-filters"${filterActive(filter) ? "" : " hidden"}>Сбросить</button>
        <span class="client-count" id="client-count" aria-live="polite">${esc(countLabel(filtered(context).length, clients.length))}</span>
      </div>
    </div>`;
}

function listHtml(context) {
  if (!context.state.clients.length) {
    return '<div class="empty-state"><span>◇</span><h3>Клиентов пока нет</h3><p>Импортируйте пользователей, которые уже работают на этом сервере, — панель ничего в них не меняет.</p></div>';
  }
  const items = filtered(context);
  return items.length
    ? items.map((entry) => safeCard(context, entry)).join("")
    : '<div class="empty-state"><span>◇</span><h3>Никто не подходит</h3><p>Измените запрос или сбросьте фильтры.</p><button class="secondary" data-client-action="reset-filters">Сбросить фильтры</button></div>';
}

// A keystroke repaints the list and the counter only — the search field keeps its focus.
function paintList(context) {
  const view = context.ui.view;
  const list = view.querySelector?.(".client-list");
  if (!list) return;
  list.innerHTML = listHtml(context);
  const filter = filters(context);
  const counter = view.querySelector("#client-count");
  if (counter) counter.textContent = countLabel(filtered(context).length, context.state.clients.length);
  const reset = view.querySelector(".client-filters [data-client-action=reset-filters]");
  if (reset) reset.hidden = !filterActive(filter);
  view.querySelectorAll("[data-client-filter-state]").forEach((button) => {
    const active = button.dataset.clientFilterState === filter.state;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
}

export async function renderClients(context, generation) {
  // Nodes are read alongside: a grant on a linked panel is labelled with the panel's name.
  const [data, nodes] = await Promise.all([context.api("/api/clients"), context.api("/api/nodes")]);
  if (!isCurrent(context.state, generation, "clients")) return;
  context.state.clients = data.items || [];
  context.state.nodes = nodes.items || [];
  paintClientsCount(context, context.state.clients.length);
  context.ui.view.innerHTML = `${toolbar(context)}<section class="client-list">${listHtml(context)}</section>`;
}

const FILTER_FIELDS = {
  "client-search": "query",
  "client-filter-protocol": "protocol",
  "client-filter-node": "node",
  "client-filter-issue": "issue",
};

export function handleClientsInput(context, target) {
  const key = FILTER_FIELDS[target?.id];
  if (!key || context.state.view !== "clients") return false;
  filters(context)[key] = target.value;
  paintList(context);
  return true;
}

function resetFilters(context) {
  context.state.clientFilter = { ...CLIENT_FILTER_DEFAULT };
  const view = context.ui.view;
  for (const [id, key] of Object.entries(FILTER_FIELDS)) {
    const field = view.querySelector(`#${id}`);
    if (field) field.value = CLIENT_FILTER_DEFAULT[key];
  }
  paintList(context);
}

// One dialog creates the client and, when cells of the node × protocol matrix are ticked,
// its first grants — the two-step «create, then grant» stays available from the window.
export async function openClientModal(context) {
  const form = query("#client-form", context.root);
  form.reset();
  query("#client-error", context.root).textContent = "";
  query("#client-username-row", context.root).hidden = true;
  query("#client-username", context.root).dataset.typed = "";
  query("#client-placement", context.root).innerHTML = '<p class="form-hint">Читаем узлы…</p>';
  context.ui.openModal("#client-modal", "#client-name");
  try {
    const nodes = await context.api("/api/nodes");
    context.state.nodes = nodes.items || [];
  } catch (exception) {
    context.ui.toast(`Список узлов не загружен: ${exception.message}`, "error");
    context.state.nodes = context.state.nodes || [];
  }
  // The operator may have closed the dialog (or reopened it) while the list was in flight.
  if (!query("#client-modal", context.root).open) return;
  query("#client-placement", context.root).innerHTML = renderPlacement(placementRows(context.state.nodes, []), { canWrite: true });
}

// A runtime account name proposed from the display name: Latin letters, digits, `.`, `-`,
// `_` only (the managers' shape), Cyrillic transliterated, anything else a dash.
const TRANSLIT = {
  а: "a", б: "b", в: "v", г: "g", д: "d", е: "e", ё: "e", ж: "zh", з: "z", и: "i", й: "y", к: "k", л: "l", м: "m",
  н: "n", о: "o", п: "p", р: "r", с: "s", т: "t", у: "u", ф: "f", х: "h", ц: "ts", ч: "ch", ш: "sh", щ: "sch",
  ъ: "", ы: "y", ь: "", э: "e", ю: "yu", я: "ya",
};

export function proposeUsername(displayName) {
  const latin = String(displayName || "").toLowerCase().split("").map((char) => TRANSLIT[char] ?? char).join("");
  const slug = latin.replace(/[^a-z0-9_.-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").replace(/-{2,}/g, "-");
  return slug.slice(0, 64) || "client";
}

function proposalRow(proposal, clients) {
  const item = proposal.items[0];
  const imported = item.imported_grant_id !== null;
  const options = clients
    .map((entry) => `<option value="${esc(entry.client.id)}">${esc(entry.client.display_name)}</option>`)
    .join("");
  return `<tr data-import-protocol="${esc(item.protocol)}" data-import-username="${esc(item.runtime_username)}">
    <td><input type="checkbox" class="import-pick"${imported ? " disabled" : " checked"}></td>
    <td>${esc(PROTOCOL_NAMES[item.protocol] || item.protocol)}</td>
    <td><code>${esc(item.runtime_username)}</code></td>
    <td>${item.enabled ? "включён" : "выключен"}${proposal.same_username_hint ? ' <small class="hint-flag">имя встречается в других протоколах</small>' : ""}</td>
    <td>${imported
      ? "<small>уже импортирован</small>"
      : `<select class="import-target"><option value="">Новый клиент</option>${options}</select>`}</td>
  </tr>`;
}

export async function openImportModal(context) {
  const error = query("#client-import-error", context.root);
  const body = query("#client-import-rows", context.root);
  error.textContent = "";
  body.innerHTML = '<tr><td colspan="5">Читаем менеджеры…</td></tr>';
  context.ui.openModal("#client-import-modal");
  try {
    const [inventory, clients] = await Promise.all([
      context.api("/api/clients/import/inventory"),
      context.api("/api/clients"),
    ]);
    const proposals = inventory.proposals || [];
    query("#client-import-summary", context.root).textContent =
      `Найдено доступов: ${proposals.length}, уже импортировано: ${inventory.already_imported}.`;
    body.innerHTML = proposals.length
      ? proposals.map((proposal) => proposalRow(proposal, clients.items || [])).join("")
      : '<tr><td colspan="5">Импортировать нечего: менеджеры не сообщили ни одного пользователя.</td></tr>';
  } catch (exception) {
    body.innerHTML = "";
    error.textContent = exception.message;
  }
}

function collectDecisions(context) {
  const byClient = new Map();
  const decisions = [];
  queryAll("#client-import-rows tr", context.root).forEach((row) => {
    const pick = query(".import-pick", row);
    if (!pick || pick.disabled || !pick.checked) return;
    const item = [row.dataset.importProtocol, row.dataset.importUsername];
    const target = query(".import-target", row)?.value || "";
    if (!target) {
      // Default: one runtime account, one client. A shared name is never a merge.
      decisions.push({ display_name: row.dataset.importUsername, client_id: null, items: [item] });
      return;
    }
    if (!byClient.has(target)) byClient.set(target, { display_name: "", client_id: target, items: [] });
    byClient.get(target).items.push(item);
  });
  return [...decisions, ...byClient.values()].map((decision) => ({
    ...decision,
    display_name: decision.display_name || "—",
  }));
}

// The node a grant lives on: this panel's own runtime or a linked panel that is not
// paused (spec §7). Anything else is refused by the API, so it is not offered.
function nodeOptions(nodes) {
  return nodes
    .filter((node) => node.node_id === "local" || (node.transport === "panel" && node.link?.enabled === true))
    .map((node) => `<option value="${esc(node.node_id)}">${esc(node.node_id === "local" ? "Этот сервер" : node.display_name)}</option>`)
    .join("");
}

// The node list is read when the dialog opens, so a panel linked a moment ago is offered;
// the dialog keeps its «Этот сервер» default while the list loads or when it fails.
export async function loadNodeOptions(context, dialogSelector, select) {
  select.innerHTML = '<option value="local">Этот сервер</option>';
  try {
    const nodes = await context.api("/api/nodes");
    context.state.nodes = nodes.items || [];
    if (query(dialogSelector, context.root).open) select.innerHTML = nodeOptions(context.state.nodes) || select.innerHTML;
  } catch (exception) {
    context.ui.toast(`Список узлов не загружен: ${exception.message}`, "error");
  }
}

// The protocol screens («MTProxy», «NaiveProxy», «Mieru») manage this server's own
// services; an account on a linked panel is a client's grant there. When one of those
// dialogs names another node, the access is issued that way: a client with the account's
// name, one grant on the node, the bundle revealed as on «Клиенты».
export async function issueOnNode(context, { protocol, username, nodeId, options = {} }) {
  const { api, ui } = context;
  const client = await api("/api/clients", { method: "POST", body: JSON.stringify({ display_name: username, subscription: false }) });
  const result = await api(`/api/clients/${encodeURIComponent(client.id)}/grants`, {
    method: "POST",
    body: JSON.stringify({ grants: [{ protocol, node_id: nodeId, runtime_username: username, options }] }),
  });
  const node = context.state.nodes.find((item) => item.node_id === nodeId);
  const where = node?.display_name || nodeId;
  ui.toast(result.status === "succeeded" ? `Доступ выдан на узле ${where}: карточка — в «Клиентах»` : OPERATION_MESSAGE[result.status] || result.status, OPERATION_OK.has(result.status) ? "" : "error");
  if (result.status === "manual_intervention_required") {
    ui.toast(`Операция ${result.operation_id}: продолжить можно командой operations-resume`, "error");
  }
  if (result.status === "succeeded") await context.access.openOperationBundle(result.operation_id);
  return result;
}

export function bindClients(context) {
  const { api, root, ui } = context;
  // Ticking a cell reveals the account name, proposed from the display name until the
  // operator types their own; unticking every cell hides it again.
  query("#client-form", root)?.addEventListener("change", (event) => {
    if (!event.target.matches?.("#client-placement input[type=checkbox]")) return;
    const row = query("#client-username-row", root);
    const input = query("#client-username", root);
    const any = readPlacement(query("#client-placement", root)).size > 0;
    row.hidden = !any;
    if (any && !input.dataset.typed) input.value = proposeUsername(query("#client-name", root).value);
  });
  query("#client-username", root)?.addEventListener("input", ({ currentTarget: input }) => {
    input.dataset.typed = input.value ? "1" : "";
  });
  // Enter in a dialog form submits it — here the first submit button is the head ×, so the
  // window would simply close. Enter means «Создать», and nothing else.
  const submitClientOnEnter = (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    query("#create-client", root)?.click();
  };
  query("#client-name", root)?.addEventListener("keydown", submitClientOnEnter);
  query("#client-username", root)?.addEventListener("keydown", submitClientOnEnter);
  query("#create-client", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#client-form", root);
    const error = query("#client-error", root);
    const usernameInput = query("#client-username", root);
    const rows = placementRows(context.state.nodes || [], []);
    const diff = placementDiff(rows, readPlacement(query("#client-placement", root)), usernameInput.value.trim());
    // A hidden `required` input fails `reportValidity()` silently, so the row is made
    // visible in the same breath as the flag: both follow the ticks, never diverge.
    const needsUsername = diff.create.length > 0;
    query("#client-username-row", root).hidden = !needsUsername;
    usernameInput.required = needsUsername;
    if (!form.reportValidity()) return;
    error.textContent = "";
    const displayName = query("#client-name", root).value.trim();
    let client = null;
    let subscription = null;
    try {
      ui.setBusy(button, true, "Создаём…");
      client = await api("/api/clients", { method: "POST", body: JSON.stringify({ display_name: displayName }) });
      // The subscription is issued with the client; its reveal is consumed once, here.
      if (client.subscription_reveal_token) {
        subscription = await api(`/api/reveal/${encodeURIComponent(client.subscription_reveal_token)}`);
      }
      if (!diff.create.length) {
        query("#client-modal", root).close();
        ui.toast("Клиент создан");
        await context.navigate("clients");
        if (subscription) await context.subscriptions.open(client.id, displayName, subscription);
        return;
      }
      ui.setBusy(button, true, "Выдаём доступы…");
      const result = await api(`/api/clients/${encodeURIComponent(client.id)}/grants`, {
        method: "POST",
        body: JSON.stringify({ grants: diff.create }),
      });
      query("#client-modal", root).close();
      ui.toast(result.status === "succeeded" ? "Клиент создан, доступы выданы" : OPERATION_MESSAGE[result.status] || result.status, OPERATION_OK.has(result.status) ? "" : "error");
      if (result.status === "manual_intervention_required") {
        ui.toast(`Операция ${result.operation_id}: продолжить можно командой operations-resume`, "error");
      }
      // The bundle carries the subscription on top; when there is no bundle to show, the
      // client window does — the link must not be lost on the way either way.
      if (result.status === "succeeded") await context.access.openOperationBundle(result.operation_id, { subscription });
      else if (subscription) await context.subscriptions.open(client.id, displayName, subscription);
      await context.navigate("clients");
    } catch (exception) {
      // The client may already exist when the grants are refused: say so, and let the list
      // behind the dialog show the card, so nothing is created twice on a retry.
      error.textContent = client ? `Клиент «${displayName}» создан, но доступы не выданы: ${exception.message}. Выдайте их из окна клиента.` : exception.message;
      if (client) await context.navigate("clients");
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#confirm-client-import", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const error = query("#client-import-error", root);
    const decisions = collectDecisions(context);
    error.textContent = "";
    if (!decisions.length) {
      error.textContent = "Не отмечено ни одного доступа";
      return;
    }
    try {
      ui.setBusy(button, true, "Импортируем…");
      const result = await api("/api/clients/import", {
        method: "POST",
        body: JSON.stringify({ decisions }),
      });
      query("#client-import-modal", root).close();
      ui.toast(`Импортировано доступов: ${result.created_grants}, пропущено: ${result.skipped.length}`);
      await context.navigate("clients");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
}

async function lifecycle(context, clientId, action) {
  const entry = context.state.clients.find((item) => item.client.id === clientId);
  if (!entry) return;
  const state = { suspend: "suspended", resume: "active", archive: "archived" }[action];
  if (!state) return;
  try {
    if (action === "archive") {
      const confirmed = await context.ui.confirmed(
        "Архивировать клиента?",
        `${entry.client.display_name} исчезнет из активных. Панель откажет, пока у клиента есть неудалённые доступы.`,
        "Архивировать",
      );
      if (!confirmed) return;
    }
    await context.api(`/api/clients/${encodeURIComponent(clientId)}/state`, {
      method: "POST",
      body: JSON.stringify({ state }),
    });
    context.ui.toast("Состояние клиента обновлено");
    await context.navigate("clients");
  } catch (exception) {
    context.ui.toast(exception.message, "error");
  }
}

async function adopt(context, button) {
  const { grantId, grantProtocol } = button.dataset;
  const rotation = ROTATION_REQUIRED.has(grantProtocol);
  if (rotation) {
    // Rotation is not implied by "adopt": the operator has to accept losing the link.
    const confirmed = await context.ui.confirmed(
      "Принять доступ с ротацией?",
      `${PROTOCOL_NAMES[grantProtocol] || grantProtocol} не отдаёт сохранённый пароль, поэтому панель выпустит новый. Старая ссылка перестанет работать, клиенту придётся выдать новую.`,
      "Ротировать и принять",
    );
    if (!confirmed) return;
  }
  try {
    context.ui.setBusy(button, true, "Принимаем…");
    await context.api(`/api/clients/grants/${encodeURIComponent(grantId)}/adopt`, {
      method: "POST",
      body: JSON.stringify({ allow_rotation: rotation }),
    });
    context.ui.toast(rotation ? "Доступ принят, выдана новая ссылка" : "Доступ принят");
    await context.navigate("clients");
  } catch (exception) {
    context.ui.toast(exception.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

// A click on a grant's row opens its own window: details, link and QR, its actions.
function openGrant(context, button) {
  const card = button.closest("[data-client-id]");
  if (!card) return;
  context.grants.open(card.dataset.clientId, button.dataset.grantOpen);
}

export function handleClientsClick(context, button) {
  if (button.dataset.grantOpen) {
    openGrant(context, button);
    return true;
  }
  if (button.dataset.clientFilterState) {
    filters(context).state = button.dataset.clientFilterState;
    paintList(context);
    return true;
  }
  const action = button.dataset.clientAction;
  if (!action) return false;
  if (action === "reset-filters") {
    resetFilters(context);
    return true;
  }
  if (action === "import") {
    void openImportModal(context);
    return true;
  }
  if (action === "adopt") {
    void adopt(context, button);
    return true;
  }
  if (action === "open" || action === "placement") {
    const card = button.closest("[data-client-id]");
    const entry = context.state.clients.find((item) => item.client.id === card?.dataset.clientId);
    if (entry) void context.subscriptions.open(entry.client.id, entry.client.display_name, null, { focus: action === "placement" ? "placement" : null });
    return true;
  }
  const card = button.closest("[data-client-id]");
  if (!card) return false;
  void lifecycle(context, card.dataset.clientId, action);
  return true;
}
