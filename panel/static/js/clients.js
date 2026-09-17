import { esc, initials, query, queryAll } from "./common.js";
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
  // The subscription dialog is read-only for viewers, so it is offered to everyone;
  // the buttons that change anything appear inside it by role.
  const subscription = client.state === "archived"
    ? ""
    : '<button class="secondary" data-client-action="subscription">Подписка</button>';
  if (context.state.me?.role === "viewer" || client.state === "archived") {
    return subscription ? `<div class="client-actions">${subscription}</div>` : "";
  }
  const grant = '<button class="secondary" data-client-action="grant">Выдать доступ</button>';
  const toggle = client.state === "suspended"
    ? '<button class="secondary" data-client-action="resume">Возобновить</button>'
    : '<button class="secondary" data-client-action="suspend">Приостановить</button>';
  return `<div class="client-actions">
    ${grant}
    ${subscription}
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
    <div class="client-identity">
      <b>${esc(client.display_name)}</b>
      <small>Доступов: ${grants.length}</small>
    </div>
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

export function openClientModal(context) {
  const form = query("#client-form", context.root);
  form.reset();
  query("#client-error", context.root).textContent = "";
  context.ui.openModal("#client-modal", "#client-name");
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

export async function openGrantModal(context, clientId) {
  const form = query("#grant-form", context.root);
  form.reset();
  query("#grant-client-id", context.root).value = clientId;
  query("#grant-error", context.root).textContent = "";
  const select = query("#grant-node", context.root);
  select.innerHTML = '<option value="local">Этот сервер</option>';
  context.ui.openModal("#grant-modal", "#grant-username");
  try {
    const nodes = await context.api("/api/nodes");
    context.state.nodes = nodes.items || [];
    if (query("#grant-modal", context.root).open) select.innerHTML = nodeOptions(context.state.nodes) || select.innerHTML;
  } catch (exception) {
    context.ui.toast(`Список узлов не загружен: ${exception.message}`, "error");
  }
}

const OPERATION_MESSAGE = {
  succeeded: "Доступы выданы",
  compensated: "Операция отменена: созданное удалено, ничего лишнего не тронуто",
  manual_intervention_required: "Требуется вмешательство: часть изменений не удалось откатить",
};

export function bindClients(context) {
  const { api, root, ui } = context;
  query("#create-client", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#client-form", root);
    const error = query("#client-error", root);
    if (!form.reportValidity()) return;
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Создаём…");
      await api("/api/clients", {
        method: "POST",
        body: JSON.stringify({ display_name: query("#client-name", root).value.trim() }),
      });
      query("#client-modal", root).close();
      ui.toast("Клиент создан");
      await context.navigate("clients");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#create-grants", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#grant-form", root);
    const error = query("#grant-error", root);
    if (!form.reportValidity()) return;
    const username = query("#grant-username", root).value.trim();
    const clientId = query("#grant-client-id", root).value;
    const nodeId = query("#grant-node", root).value || "local";
    // Only this dialog's boxes: the link dialog reuses the class for its TLS radios, and a
    // document-wide query used to hand «verify» to the API as a protocol (422 every time).
    const protocols = [...queryAll("#grant-form .grant-protocol input:checked", root)].map((box) => box.value);
    error.textContent = "";
    if (!protocols.length) {
      error.textContent = "Выберите хотя бы один протокол";
      return;
    }
    try {
      ui.setBusy(button, true, "Выдаём…");
      const result = await api(`/api/clients/${encodeURIComponent(clientId)}/grants`, {
        method: "POST",
        body: JSON.stringify({
          grants: protocols.map((protocol) => ({ protocol, node_id: nodeId, runtime_username: username, options: {} })),
        }),
      });
      query("#grant-modal", root).close();
      // Any outcome is reported as itself; a compensated operation is not a success.
      ui.toast(OPERATION_MESSAGE[result.status] || result.status, result.status === "succeeded" ? "" : "error");
      if (result.status === "manual_intervention_required") {
        ui.toast(`Операция ${result.operation_id}: продолжить можно командой operations-resume`, "error");
      }
      if (result.status === "succeeded") await context.access.openOperationBundle(result.operation_id);
      await context.navigate("clients");
    } catch (exception) {
      error.textContent = exception.message;
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
  if (action.startsWith("grant-")) {
    void grantAction(context, button);
    return true;
  }
  if (action === "grant") {
    const card = button.closest("[data-client-id]");
    if (card) void openGrantModal(context, card.dataset.clientId);
    return true;
  }
  if (action === "subscription") {
    const card = button.closest("[data-client-id]");
    const entry = context.state.clients.find((item) => item.client.id === card?.dataset.clientId);
    if (entry) void context.subscriptions.open(entry.client.id, entry.client.display_name);
    return true;
  }
  const card = button.closest("[data-client-id]");
  if (!card) return false;
  void lifecycle(context, card.dataset.clientId, action);
  return true;
}
