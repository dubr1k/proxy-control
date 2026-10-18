// The AmneziaWG screen: the versions this server serves (port, subnet, state), every access with
// who holds it, when it last connected and how much it carried. Read-only: an access is changed in
// its own window (the same one the client card opens), because the panel owns the client's keys.
import { bytes, esc, initials, number, query } from "./common.js";
import { isCurrent } from "./state.js";

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
  <div class="security-note">Клиенты подключаются по имени <code>${esc(data.public_host || "—")}</code> и порту своей версии. Доступы выдаются клиентам: «Клиенты» → «Узлы и доступы» → колонки AmneziaWG 1.5 / 2.0 / 3.1. Конфиг с ключом показывает окно доступа.</div>
  <div class="awg-overview"><article><small>Менеджер AmneziaWG</small><strong>${esc(word)}</strong><span class="status-pill ${tone}"><i></i>${esc(word)}</span></article>${(data.versions || []).map(versionCard).join("")}</div>
  <section class="data-panel"><div class="data-head naive-grid"><span>Доступ</span><span>Состояние</span><span>Трафик</span><span class="align-right">Действия</span></div>${(data.peers || []).length ? data.peers.map((row) => accessRow(context, row)).join("") : '<div class="empty-state"><b>Доступов AmneziaWG пока нет</b><small>Откройте клиента → «Узлы и доступы» и отметьте нужные версии AmneziaWG.</small></div>'}</section>`;
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
