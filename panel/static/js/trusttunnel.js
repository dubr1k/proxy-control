// The TrustTunnel screen: the endpoint this server's manager runs (domain, port, version,
// certificate), every access with who holds it, its live sessions and traffic. Read-only like the
// AmneziaWG screen: an access is changed in its own window (the one the client card opens),
// because the panel owns the password. «+ TrustTunnel доступ» issues a new one through the same
// grant API the client card uses.
import { bytes, esc, initials, number, query } from "./common.js";
import { isCurrent } from "./state.js";
import { proposeUsername } from "./clients.js";

const STATUS = { ok: ["active", "Работает"], degraded: ["blocked", "Есть неполадки"], down: ["blocked", "Менеджер недоступен"] };

function endpointCards(data) {
  const endpoint = data.endpoint;
  if (!endpoint) {
    return `<article><small>Менеджер TrustTunnel</small><strong>${esc(data.public_host || "—")}</strong><span class="status-pill blocked"><i></i>Менеджер недоступен</span><small>Список доступов и трафик появятся, когда менеджер ответит.</small></article>`;
  }
  const cert = endpoint.certificate_trusted
    ? '<span class="status-pill active"><i></i>Сертификат публичный</span>'
    : '<span class="status-pill blocked"><i></i>Сертификат свой</span>';
  const certNote = endpoint.certificate_trusted
    ? "<small>Приложению достаточно домена</small>"
    : "<small>Сертификат кладётся в ссылку и конфиг доступа</small>";
  return `<article>
      <small>Endpoint · ${esc(endpoint.hostname || data.public_host || "—")}</small>
      <strong>${esc(endpoint.port)}/tcp</strong>
      <span class="status-pill ${endpoint.running ? "active" : "blocked"}"><i></i>${endpoint.running ? "Работает" : "Не запущен"}</span>
      <small>Версия: ${esc(endpoint.version || "—")}</small>
    </article>
    <article><small>TLS</small><strong>${endpoint.certificate_trusted ? "Публичный" : "Свой"}</strong>${cert}${certNote}</article>`;
}

function totalsCard(data) {
  const totals = data.totals || {};
  return `<article>
      <small>Доступы и сессии</small>
      <strong>${number(totals.active)} из ${number(totals.clients)}</strong>
      <small>Сессий сейчас: ${number(totals.sessions)}</small>
      <small>↑ ${bytes(totals.upload_bytes)} · ↓ ${bytes(totals.download_bytes)}</small>
    </article>`;
}

function accessRow(context, row) {
  const holder = row.client_name
    ? `<small>Клиент: ${esc(row.client_name)}${row.name ? ` · профиль «${esc(row.name)}»` : ""}</small>`
    : "<small>Нет в панели: пароль не хранится, ссылку не собрать</small>";
  const writer = context.state.me.role !== "viewer";
  const open = row.grant_id
    ? `<button class="action-button${writer ? " share" : ""}" data-tt-action="open" data-client="${esc(row.client_id)}" data-grant="${esc(row.grant_id)}">${writer ? "Открыть доступ" : "Подробности"}</button>`
    : "";
  return `<div class="data-row naive-grid">
    <div class="identity"><span class="user-glyph">${esc(initials(row.client_name || row.username))}</span><span><b>${esc(row.username)}</b><small>TrustTunnel</small>${holder}</span></div>
    <div class="cell"><span class="status-pill ${row.enabled ? "active" : "blocked"}"><i></i>${row.enabled ? "Включён" : "Выключен"}</span><small>Сессий: ${number(row.sessions)}</small></div>
    <div class="cell"><b>↑ ${bytes(row.upload_bytes)} · ↓ ${bytes(row.download_bytes)}</b><small>отправлено / получено клиентом</small></div>
    <div class="row-actions">${open || "—"}</div>
  </div>`;
}

export async function renderTrusttunnel(context, generation) {
  const data = await context.api("/api/trusttunnel/overview");
  if (!isCurrent(context.state, generation, "trusttunnel")) return;
  const [tone, word] = STATUS[data.status] || STATUS.degraded;
  const badge = query("#trusttunnel-count", context.root);
  if (badge) badge.textContent = (data.clients || []).length;
  const waiting = (data.pending || []).length
    ? `<div class="security-note">Ждут менеджера или потеряны на нём: ${data.pending.map((item) => `${esc(item.username)} (${esc(item.client_name)})`).join(", ")}.</div>`
    : "";
  const rows = data.clients || [];
  context.ui.view.innerHTML = `${waiting}
  <div class="security-note">Клиенты подключаются по имени <code>${esc(data.public_host || "—")}</code>, порт 443, только TCP/HTTP2. Новый доступ — кнопка «+ TrustTunnel доступ» вверху; тот же доступ можно выдать и из карточки клиента («Узлы и доступы»). Ссылка, QR и конфиг TOML — в окне доступа.</div>
  <div class="awg-overview tt-overview"><article><small>Менеджер TrustTunnel</small><strong>${esc(word)}</strong><span class="status-pill ${tone}"><i></i>${esc(word)}</span></article>${endpointCards(data)}${totalsCard(data)}</div>
  <section class="data-panel"><div class="data-head naive-grid"><span>Доступ</span><span>Состояние</span><span>Трафик</span><span class="align-right">Действия</span></div>${rows.length ? rows.map((row) => accessRow(context, row)).join("") : '<div class="empty-state"><b>Доступов TrustTunnel пока нет</b><small>Нажмите «+ TrustTunnel доступ» вверху справа.</small></div>'}</section>`;
}

export function handleTrusttunnelClick(context, button) {
  if (button.dataset.ttAction !== "open") return false;
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

// «+ TrustTunnel доступ»: one grant on this server for a chosen client, with an optional profile
// name (the label the app shows). The password is made by the node's manager, never typed here.
function syncCreate(context) {
  const root = context.root;
  query("#create-tt", root).disabled = !query("#tt-client", root).value;
}

export async function openTtModal(context) {
  const root = context.root;
  query("#tt-form", root).reset();
  query("#tt-error", root).textContent = "";
  const select = query("#tt-client", root);
  select.innerHTML = '<option value="">…</option>';
  query("#create-tt", root).disabled = true;
  context.ui.openModal("#tt-modal", "#tt-client");
  try {
    const data = await context.api("/api/clients");
    const clients = (data.items || []).filter((entry) => entry.client.state !== "archived");
    context.state.clients = data.items || context.state.clients;
    select.innerHTML = clients.length
      ? clients.map((entry) => `<option value="${esc(entry.client.id)}">${esc(entry.client.display_name)}</option>`).join("")
      : '<option value="">Клиентов пока нет</option>';
    query("#tt-no-clients", root).hidden = clients.length > 0;
  } catch (exception) {
    query("#tt-error", root).textContent = exception.message;
  }
  syncCreate(context);
}

// The account name on the manager: the client's name in Latin, made unique among the client's
// own TrustTunnel accesses on this server.
function accountFor(context, clientId) {
  const entry = (context.state.clients || []).find((item) => item.client.id === clientId);
  const base = proposeUsername(entry?.client.display_name).slice(0, 56);
  const taken = new Set((entry?.grants || []).filter((grant) => grant.protocol === "trusttunnel" && grant.desired_state !== "deleted").map((grant) => grant.runtime_username));
  let name = base;
  for (let index = 2; taken.has(name); index += 1) name = `${base}-${index}`;
  return name;
}

export function bindTrusttunnel(context) {
  const { api, root, ui } = context;
  query("#tt-client", root)?.addEventListener("change", () => syncCreate(context));
  query("#tt-form", root)?.addEventListener("submit", (event) => {
    event.preventDefault();
    query("#create-tt", root).click();
  });
  query("#create-tt", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const error = query("#tt-error", root);
    error.textContent = "";
    if (!query("#tt-form", root).reportValidity()) return;
    const clientId = query("#tt-client", root).value;
    const name = query("#tt-name", root).value.trim();
    try {
      ui.setBusy(button, true);
      const result = await api(`/api/clients/${encodeURIComponent(clientId)}/grants`, {
        method: "POST",
        body: JSON.stringify({ grants: [{ protocol: "trusttunnel", node_id: "local", runtime_username: accountFor(context, clientId), options: name ? { name } : {} }] }),
      });
      root.querySelector("#tt-modal")?.close?.();
      if (result.status === "succeeded") await context.access.openOperationBundle(result.operation_id);
      else ui.toast(result.status === "manual_intervention_required" ? `Операция ${result.operation_id}: продолжить можно командой operations-resume` : "Доступ ещё выдаётся, он появится в списке", "error");
      await context.navigate("trusttunnel");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
}
