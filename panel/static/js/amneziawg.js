// The AmneziaWG screen: the versions this server serves (port, subnet, state), every access with
// who holds it, when it last connected and how much it carried. Read-only: an access is changed in
// its own window (the same one the client card opens), because the panel owns the client's keys.
import { bytes, esc, initials, number, query } from "./common.js";
import { isCurrent } from "./state.js";
import { AWG_VERSIONS, awgAccount, awgVersions } from "./placement.js";

const STATUS = { ok: ["active", "Работает"], degraded: ["blocked", "Есть неполадки"], down: ["blocked", "Менеджер недоступен"] };

function ago(seconds) {
  if (!seconds) return "ещё не подключался";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - seconds);
  if (diff < 90) return "только что";
  if (diff < 5400) return `${Math.round(diff / 60)} мин назад`;
  if (diff < 129600) return `${Math.round(diff / 3600)} ч назад`;
  return `${Math.round(diff / 86400)} дн. назад`;
}

function versionCard(item) {
  return `<article>
    <small>AmneziaWG ${esc(item.version)} · ${esc(item.interface)}</small>
    <strong>${esc(item.port)}/udp</strong>
    <span class="status-pill ${item.running ? "active" : "blocked"}"><i></i>${item.running ? "Работает" : "Не запущена"}</span>
    <small>${esc(item.subnet)} · MTU ${esc(item.mtu ?? "—")}</small>
    <small>Доступов: ${number(item.active)} активных из ${number(item.peers)}</small>
  </article>`;
}

function accessRow(context, row) {
  const holder = row.client_name
    ? `<small>Клиент: ${esc(row.client_name)}</small>`
    : "<small>Нет в панели: ключ клиента не хранится, конфиг не собрать</small>";
  const open = row.grant_id && context.state.me.role !== "viewer"
    ? `<button class="action-button share" data-awg-action="open" data-client="${esc(row.client_id)}" data-grant="${esc(row.grant_id)}">Открыть доступ</button>`
    : (row.grant_id ? `<button class="action-button" data-awg-action="open" data-client="${esc(row.client_id)}" data-grant="${esc(row.grant_id)}">Подробности</button>` : "");
  return `<div class="data-row naive-grid">
    <div class="identity"><span class="user-glyph">${esc(initials(row.client_name || row.username))}</span><span><b>${esc(row.username)}</b><small>AmneziaWG ${esc(row.version)} · ${esc(row.address)}</small>${holder}</span></div>
    <div class="cell"><span class="status-pill ${row.enabled ? "active" : "blocked"}"><i></i>${row.enabled ? "Включён" : "Выключен"}</span><small>${esc(ago(row.latest_handshake))}</small></div>
    <div class="cell"><b>↑ ${bytes(row.rx)} · ↓ ${bytes(row.tx)}</b><small>принято / отдано узлом</small></div>
    <div class="row-actions">${open || "—"}</div>
  </div>`;
}

export async function renderAmneziawg(context, generation) {
  const data = await context.api("/api/amneziawg/overview");
  if (!isCurrent(context.state, generation, "amneziawg")) return;
  const [tone, word] = STATUS[data.status] || STATUS.degraded;
  const badge = query("#amneziawg-count", context.root);
  if (badge) badge.textContent = (data.peers || []).length;
  const note = data.ip_forward === false
    ? '<div class="security-note">Пересылка IPv4 на сервере выключена: туннели поднимутся, но трафик наружу не пойдёт (<code>net.ipv4.ip_forward</code>).</div>'
    : "";
  const waiting = (data.pending || []).length
    ? `<div class="security-note">Ждут узел или потеряны на узле: ${data.pending.map((item) => `${esc(item.username)} (${esc(item.client_name)})`).join(", ")}.</div>`
    : "";
  context.ui.view.innerHTML = `${note}${waiting}
  <div class="security-note">Клиенты подключаются по имени <code>${esc(data.public_host || "—")}</code> и порту своей версии. Новый доступ — кнопка «+ AmneziaWG доступ» вверху; тот же доступ можно выдать и из карточки клиента («Узлы и доступы»). Конфиг с ключом показывает окно доступа.</div>
  <div class="awg-overview"><article><small>Менеджер AmneziaWG</small><strong>${esc(word)}</strong><span class="status-pill ${tone}"><i></i>${esc(word)}</span></article>${(data.versions || []).map(versionCard).join("")}</div>
  <section class="data-panel"><div class="data-head naive-grid"><span>Доступ</span><span>Состояние</span><span>Трафик</span><span class="align-right">Действия</span></div>${(data.peers || []).length ? data.peers.map((row) => accessRow(context, row)).join("") : '<div class="empty-state"><b>Доступов AmneziaWG пока нет</b><small>Нажмите «+ AmneziaWG доступ» вверху справа.</small></div>'}</section>`;
}

export function handleAmneziawgClick(context, button) {
  if (button.dataset.awgAction !== "open") return false;
  const { client, grant } = button.dataset;
  void (async () => {
    try {
      const data = await context.api(`/api/clients/${encodeURIComponent(client)}`);
      context.grants.open(client, grant, data);
    } catch (exception) {
      context.ui.toast(exception.message);
    }
  })();
  return true;
}

// «+ AmneziaWG доступ»: a client with the given name and one grant per ticked version on the node.
function offeredNodes(context) {
  return (context.state.nodes || []).filter((node) => node.node_id === "local" || (node.transport === "panel" && node.link?.enabled === true));
}

function syncAwgCreate(context) {
  const root = context.root;
  const name = query("#new-awg-user", root).value.trim();
  const picked = [...root.querySelectorAll("[data-awg-version]:checked")].length;
  query("#create-awg", root).disabled = !name || !picked || !query("#new-awg-user", root).validity.valid;
}

export function openAwgModal(context) {
  const root = context.root;
  query("#awg-form", root).reset();
  query("#awg-error", root).textContent = "";
  const nodes = offeredNodes(context);
  const select = query("#awg-node", root);
  select.innerHTML = (nodes.length ? nodes : [{ node_id: "local", display_name: "Этот сервер" }])
    .map((node) => `<option value="${esc(node.node_id)}">${esc(node.node_id === "local" ? "Этот сервер" : node.display_name || node.node_id)}</option>`).join("");
  paintVersions(context);
  syncAwgCreate(context);
  context.ui.openModal("#awg-modal", "#new-awg-user");
}

// A node that reports the versions it serves offers exactly those; one that reports none (older
// panel) offers all three and the server refuses an unserved one with its own message.
function paintVersions(context) {
  const node = (context.state.nodes || []).find((item) => item.node_id === query("#awg-node", context.root).value);
  const served = awgVersions(node);
  context.root.querySelectorAll("[data-awg-version]").forEach((box) => {
    const ok = !served.length || served.includes(box.dataset.awgVersion);
    box.disabled = !ok;
    if (!ok) box.checked = false;
  });
}

export function bindAmneziawg(context) {
  const { api, root, ui } = context;
  query("#awg-form", root)?.addEventListener("input", () => syncAwgCreate(context));
  query("#awg-node", root)?.addEventListener("change", () => { paintVersions(context); syncAwgCreate(context); });
  query("#awg-form", root)?.addEventListener("submit", (event) => {
    event.preventDefault();
    query("#create-awg", root).click();
  });
  query("#create-awg", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const error = query("#awg-error", root);
    error.textContent = "";
    if (!query("#awg-form", root).reportValidity()) return;
    const username = query("#new-awg-user", root).value.trim();
    const nodeId = query("#awg-node", root).value || "local";
    const versions = AWG_VERSIONS.filter((version) => root.querySelector(`[data-awg-version="${version}"]`)?.checked);
    try {
      ui.setBusy(button, true);
      const client = await api("/api/clients", { method: "POST", body: JSON.stringify({ display_name: username, subscription: false }) });
      const result = await api(`/api/clients/${encodeURIComponent(client.id)}/grants`, {
        method: "POST",
        body: JSON.stringify({ grants: versions.map((version) => ({ protocol: "amneziawg", node_id: nodeId, runtime_username: awgAccount(username, version), options: { version } })) }),
      });
      root.querySelector("#awg-modal")?.close?.();
      if (result.status === "succeeded") await context.access.openOperationBundle(result.operation_id);
      else ui.toast(result.status === "manual_intervention_required" ? `Операция ${result.operation_id}: продолжить можно командой operations-resume` : "Доступ ещё выдаётся, он появится в списке", "error");
      await context.navigate("amneziawg");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
}
