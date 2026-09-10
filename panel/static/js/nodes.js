import { date, esc, initials, number, query } from "./common.js";
import { nodeDetail, refreshCommands, updateCommandFieldsAfterRender } from "./fleet.js";
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

function servicesBlock(node) {
  const services = node.services || {};
  const items = SERVICES.map(([key, label]) => {
    const [tone, word] = SERVICE_STATE[services[key]] || ["muted", "неизвестно"];
    return `<li><span class="status-pill ${tone}"><i></i>${esc(label)} · ${esc(word)}</span></li>`;
  }).join("");
  return `<div class="node-services"><ul>${items}</ul>
    <p class="form-hint">Локальные протоколы управляются напрямую: у этого узла нет ни очереди команд, ни сертификатов.</p></div>`;
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

function nodeCard(context, node, expanded) {
  const [tone, label] = ENROLLMENT[node.enrollment_state] || ["blocked", node.enrollment_state];
  const inventory = node.inventory || {};
  const facts = [
    ["Транспорт", `${CONNECTIVITY[node.connectivity_state] || node.connectivity_state}${node.last_seen_at ? ` · ${date(node.last_seen_at)}` : ""}`],
    ["Демон", `${inventory.telemt_version ? `Telemt ${inventory.telemt_version}` : "Telemt не определён"} · ${inventory.agent_version ? `агент ${inventory.agent_version}` : "агент не определён"}`],
    ["Команды в очереди", number(node.pending_commands)],
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
    <dl class="node-facts">${facts.map(([name, value]) => `<div><dt>${name}</dt><dd>${esc(String(value))}</dd></div>`).join("")}</dl>
    ${node.kind === "local" ? servicesBlock(node) : certificates}
    ${actions(context, node)}
    ${node.kind === "local" ? "" : `<div class="advanced-drawer"><button class="ghost" data-node-action="advanced" aria-expanded="${expanded ? "true" : "false"}">Advanced: транспорт v1</button>${expanded ? `<div class="advanced-body">${nodeDetail(context, context.state.fleet.find((item) => item.node_id === node.node_id), context.state.fleetCommands)}</div>` : ""}</div>`}
  </article>`;
}

export async function renderNodes(context, generation) {
  const [data, transport] = await Promise.all([
    context.api("/api/nodes"),
    context.api("/api/fleet/nodes"),
  ]);
  if (!isCurrent(context.state, generation, "fleet")) return;
  context.state.nodes = data.items || [];
  context.state.fleet = transport.items || [];
  const count = query("#fleet-count", context.root);
  if (count) count.textContent = context.state.nodes.length;
  const expanded = context.state.fleetSelection;
  if (expanded && context.state.nodes.some((node) => node.node_id === expanded && node.kind !== "local")) {
    const commands = await refreshCommands(context, expanded, generation);
    if (commands === null) return;
  }
  context.ui.view.innerHTML = `<div class="security-note">Узлы подключаются исходящим mTLS long-poll: идентичность привязана к сертификату, bearer-токенов нет. Отключённый узел не проходит аутентификацию.</div>
    <section class="node-list">${context.state.nodes.length
      ? context.state.nodes.map((node) => nodeCard(context, node, node.node_id === expanded)).join("")
      : '<div class="empty-state"><span>◇</span><h3>Узлов пока нет</h3><p>Владелец может зарегистрировать узел — панель покажет пошаговый enrollment.</p></div>'}</section>`;
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

export function handleNodesClick(context, button) {
  const action = button.dataset.nodeAction;
  if (!action) return false;
  const card = button.closest("[data-node-id]");
  if (!card) return false;
  if (action === "advanced") {
    context.state.fleetSelection = context.state.fleetSelection === card.dataset.nodeId ? "" : card.dataset.nodeId;
    context.state.fleetCommands = [];
    void context.navigate("fleet");
    return true;
  }
  void lifecycle(context, card.dataset.nodeId, action);
  return true;
}
