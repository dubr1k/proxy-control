import { OPERATION_MESSAGE, OPERATION_OK, esc, initials, paintClientsCount, query, queryAll } from "./common.js";
import { placementDiff, placementRows, readPlacement, renderPlacement } from "./placement.js";
import { isCurrent } from "./state.js";

const CLIENT_STATE = {
  active: ["active", "Активен"],
  suspended: ["blocked", "Приостановлен"],
  archived: ["muted", "В архиве"],
};

const PROTOCOL_NAMES = { mtproxy: "MTProxy", naive: "NaiveProxy", mieru: "Mieru" };

const GRANT_STATE = {
  enabled: "включён",
  disabled: "выключен",
  deleted: "удалён",
};

// What the node last reported about a grant, when it differs from what the panel wants:
// a grant on a linked panel stays `pending` until the pusher delivers it (spec §7).
const OBSERVED_STATE = {
  pending: "ожидает узел",
  failed: "ошибка",
  drifted: "расхождение",
  missing: "удалён",
};

function grantStatus(grant) {
  const observed = OBSERVED_STATE[grant.observed_state];
  if (!observed) return GRANT_STATE[grant.desired_state] || grant.desired_state;
  return grant.observed_state === "failed" && grant.last_error ? `${observed}: ${grant.last_error}` : observed;
}

function nodeLabel(context, grant) {
  if (!grant.node_id || grant.node_id === "local") return "";
  const node = context.state.nodes.find((item) => item.node_id === grant.node_id);
  return `<span class="grant-node">· ${esc(node?.display_name || grant.node_id)}</span>`;
}

// Enable/disable/rotate/delete of one grant go through /api/clients/grants/{id}/{action};
// on a linked panel they only record what the central wants and the pusher delivers it.
// The route of a grant (v0.7): the service's, or its own lane on the node — the owner
// flips it here; the lane's rules live on «Маршрутизация».
const LANE_PROTOCOLS = new Set(["naive", "mieru"]);

function laneControl(context, grant) {
  if (!LANE_PROTOCOLS.has(grant.protocol) || grant.desired_state === "deleted") return "";
  const own = grant.routing_lane === "own";
  const owner = context.state.me?.role === "owner";
  const button = owner ? `<button class="ghost" data-client-action="grant-lane" data-lane-mode="${own ? "service" : "own"}">${own ? "как у сервиса" : "своя полоса"}</button>` : "";
  return `<span class="grant-lane" data-lane="${own ? "own" : "service"}"><small>маршрут: ${own ? "своя полоса" : "как у сервиса"}</small>${button}</span>`;
}

function grantTools(grant) {
  if (grant.desired_state === "deleted") return "";
  const toggle = grant.desired_state === "enabled"
    ? '<button class="ghost" data-client-action="grant-disable">Выключить</button>'
    : '<button class="ghost" data-client-action="grant-enable">Включить</button>';
  return `<span class="grant-tools">${toggle}<button class="ghost" data-client-action="grant-rotate">Ротировать</button><button class="ghost danger-text" data-client-action="grant-delete">Удалить</button></span>`;
}

function grantChip(context, grant, canWrite) {
  const orphan = grant.secret_ref === null
    ? '<em title="Панель не хранит его секрет, поэтому доступ не попадает в подписку">· без секрета</em>'
    : "";
  return `<li class="grant-chip" data-grant-protocol="${esc(grant.protocol)}" data-grant-id="${esc(grant.id)}">
    <b>${esc(PROTOCOL_NAMES[grant.protocol] || grant.protocol)}</b>
    <span>${esc(grant.runtime_username)}</span>
    <small>${esc(grantStatus(grant))}</small>
    ${nodeLabel(context, grant)}
    ${orphan}
    ${laneControl(context, grant)}
    ${canWrite ? grantTools(grant) : ""}
  </li>`;
}

// Only Mieru cannot hand its credential back, so only Mieru costs the subscriber
// their current link when adopted.
const ROTATION_REQUIRED = new Set(["mieru"]);

function adoptNote(context, grants) {
  const orphans = grants.filter((grant) => grant.secret_ref === null);
  if (!orphans.length || context.state.me?.role === "viewer") return "";
  const buttons = orphans.map((grant) => {
    const warn = ROTATION_REQUIRED.has(grant.protocol);
    return `<button class="secondary" data-client-action="adopt" data-grant-id="${esc(grant.id)}"
      data-grant-protocol="${esc(grant.protocol)}"
      title="${warn ? "Потребуется ротация: старая ссылка перестанет работать" : "Панель прочитает текущий секрет, ссылка продолжит работать"}"
      >Принять ${esc(PROTOCOL_NAMES[grant.protocol] || grant.protocol)} · ${esc(grant.runtime_username)}</button>`;
  }).join("");
  return `<p class="form-hint">Нет сохранённого секрета у доступов: ${orphans.length}. Такой доступ не попадает в подписку. ${buttons}</p>`;
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

function clientCard(context, entry) {
  const { client, grants } = entry;
  const [tone, label] = CLIENT_STATE[client.state] || ["blocked", client.state];
  const canWrite = context.state.me?.role !== "viewer" && client.state !== "archived";
  return `<article class="data-row client-card" data-client-id="${esc(client.id)}">
    <span class="user-glyph">${esc(initials(client.display_name))}</span>
    <button type="button" class="client-identity" data-client-action="open">
      <b>${esc(client.display_name)}</b>
      <small>Доступов: ${grants.length}</small>
    </button>
    <span class="status-pill ${tone}"><i></i>${esc(label)}</span>
    <ul class="client-grants">${grants.length
      ? grants.map((grant) => grantChip(context, grant, canWrite)).join("")
      : '<li class="grant-chip empty"><small>Доступов пока нет — импортируйте существующие</small></li>'}</ul>
    ${adoptNote(context, grants)}
    ${actions(context, client)}
  </article>`;
}

export async function renderClients(context, generation) {
  // Nodes are read alongside: a grant on a linked panel is labelled with the panel's name.
  const [data, nodes] = await Promise.all([context.api("/api/clients"), context.api("/api/nodes")]);
  if (!isCurrent(context.state, generation, "clients")) return;
  context.state.clients = data.items || [];
  context.state.nodes = nodes.items || [];
  paintClientsCount(context, context.state.clients.length);
  const canImport = context.state.me?.role !== "viewer";
  context.ui.view.innerHTML = `<div class="toolbar">
      ${canImport ? '<button class="secondary" data-client-action="import">Импорт существующих</button>' : ""}
    </div>
    <section class="client-list">${context.state.clients.length
      ? context.state.clients.map((entry) => safeCard(context, entry)).join("")
      : '<div class="empty-state"><span>◇</span><h3>Клиентов пока нет</h3><p>Импортируйте пользователей, которые уже работают на этом сервере, — панель ничего в них не меняет.</p></div>'}</section>`;
}

// One malformed entry (an option shape a newer node reports, say) must not take the whole
// list down: the card says what it could not render, the rest of the clients stay visible.
function safeCard(context, entry) {
  try {
    return clientCard(context, entry);
  } catch (error) {
    console.error("client card failed to render", error);
    const name = entry?.client?.display_name || entry?.client?.id || "?";
    return `<article class="data-row client-card client-card-error"><b>${esc(String(name))}</b>
      <small>Карточку не удалось отобразить — обновите страницу или проверьте консоль браузера.</small></article>`;
  }
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

const GRANT_CONFIRMATION = {
  rotate: ["Ротировать доступ?", "выпустит новый секрет: старая ссылка перестанет работать, клиенту понадобится новая.", "Ротировать"],
  delete: ["Удалить доступ?", "будет удалён из протокола; на связанной панели — после доставки узлу.", "Удалить"],
};

async function grantAction(context, button) {
  const chip = button.closest("[data-grant-id]");
  const card = button.closest("[data-client-id]");
  const entry = context.state.clients.find((item) => item.client.id === card?.dataset.clientId);
  const grant = entry?.grants.find((item) => item.id === chip?.dataset.grantId);
  if (!grant) return;
  const action = button.dataset.clientAction.slice("grant-".length);
  const label = `${PROTOCOL_NAMES[grant.protocol] || grant.protocol} · ${grant.runtime_username}`;
  try {
    if (GRANT_CONFIRMATION[action]) {
      const [title, text, ok] = GRANT_CONFIRMATION[action];
      if (!await context.ui.confirmed(title, `${label} ${text}`, ok)) return;
    }
    context.ui.setBusy(button, true);
    await context.api(`/api/clients/grants/${encodeURIComponent(grant.id)}/${action}`, { method: "POST" });
    context.ui.toast({
      enable: "Доступ включён",
      disable: "Доступ выключен",
      rotate: "Секрет ротирован; выдайте клиенту новую ссылку",
      delete: "Доступ удалён",
    }[action]);
    await context.navigate("clients");
  } catch (exception) {
    context.ui.toast(exception.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

async function laneAction(context, button) {
  const chip = button.closest("[data-grant-id]");
  const card = button.closest("[data-client-id]");
  const entry = context.state.clients.find((item) => item.client.id === card?.dataset.clientId);
  const grant = entry?.grants.find((item) => item.id === chip?.dataset.grantId);
  if (!grant) return;
  const mode = button.dataset.laneMode;
  const label = `${PROTOCOL_NAMES[grant.protocol] || grant.protocol} · ${grant.runtime_username}`;
  const link = grant.protocol === "mieru" ? " Ссылка Mieru изменится (другой порт); подписка обновится сама." : "";
  const [title, text, ok] = mode === "own"
    ? ["Своя полоса для доступа?", `${label} получит собственный маршрут на узле: его правила — на экране «Маршрутизация», вкладка полосы.${link}`, "Создать полосу"]
    : ["Вернуть к маршруту сервиса?", `${label} пойдёт как весь сервис; политика полосы будет удалена.${link}`, "Вернуть"];
  if (!await context.ui.confirmed(title, text, ok)) return;
  context.ui.setBusy(button, true);
  try {
    const result = await context.api(`/api/routing/lanes/${encodeURIComponent(grant.id)}`, { method: "POST", body: JSON.stringify({ mode }) });
    context.ui.toast(result.pending ? "Отправлено узлу: результат появится после heartbeat" : mode === "own" ? "Полоса создана: правила — на «Маршрутизации»" : "Доступ вернулся в полосу сервиса");
    await context.navigate("clients");
  } catch (exception) {
    context.ui.toast(exception.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

export function handleClientsClick(context, button) {
  const action = button.dataset.clientAction;
  if (!action) return false;
  if (action === "import") {
    void openImportModal(context);
    return true;
  }
  if (action === "adopt") {
    void adopt(context, button);
    return true;
  }
  if (action === "grant-lane") {
    void laneAction(context, button);
    return true;
  }
  if (action.startsWith("grant-")) {
    void grantAction(context, button);
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
