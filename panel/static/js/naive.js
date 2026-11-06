import { bindLimitToggles, trafficLimit, validityLimit } from "./access-limits.js";
import { bindProtocolFilters, bytesToGb, measured, measuredBytes, protocolIdentity, protocolRowAttrs, protocolSettings, protocolToolbar, protocolWritable } from "./protocol-users.js";
import { bytes, date, esc, number, query, serviceSummary, sumNaiveTraffic } from "./common.js";
import { isCurrent } from "./state.js";
import { repaintLiveRates, startLiveRates } from "./live-rates.js";
import { issueOnNode, loadNodeOptions } from "./clients.js";

export async function refreshNaive(context, generation = null) {
  const data = await context.api("/api/naive/users");
  if (generation !== null && !isCurrent(context.state, generation, context.state.view)) return null;
  context.state.naiveUsers = data.items || [];
  context.state.naiveService = data.service || { ready: false, host: "" };
  const badge = query("#naive-count", context.root);
  if (badge) badge.textContent = context.state.naiveUsers.length;
  return context.state.naiveUsers;
}

function filteredNaive(state) {
  const needle = state.naiveQuery.toLowerCase();
  return state.naiveUsers.filter((user) => (
    (state.naiveFilter === "all"
      || (state.naiveFilter === "active" && user.enabled)
      || (state.naiveFilter === "blocked" && !user.enabled))
    && String(user.username).toLowerCase().includes(needle)
  ));
}

function naiveRow(context, user) {
  const enabled = user.enabled === true;
  const exhausted = user.quota_exhausted === true;
  const quota = user.quota_bytes_decimal == null
    ? "Без квоты"
    : `${bytes(user.quota_used_bytes_decimal)} / ${bytes(user.quota_bytes_decimal)}`;
  const status = exhausted ? "Квота исчерпана" : enabled ? "Активен" : "Отключён";
  const actions = !protocolWritable(context, user)
    ? '<span class="cell">Только просмотр</span>'
    : `<button class="action-button share" data-naive-action="access" data-user="${esc(user.username)}">Конфигурация</button>
       ${protocolSettings(`<button class="action-button" data-naive-action="quota" data-user="${esc(user.username)}">Квота</button>
       <button class="action-button" data-naive-action="reset-traffic" data-user="${esc(user.username)}">Сбросить трафик</button>
       ${enabled ? `<button class="action-button" data-naive-action="disable" data-user="${esc(user.username)}">Отключить</button>` : exhausted ? '<span class="action-note">Сбросьте трафик или увеличьте квоту</span>' : `<button class="action-button" data-naive-action="enable" data-user="${esc(user.username)}">Включить</button>`}
       <button class="action-button" data-naive-action="rotate" data-user="${esc(user.username)}">Новый пароль</button>`, user)}
       <button class="action-button danger-text" data-naive-action="delete" data-user="${esc(user.username)}">Удалить доступ</button>`;
  return `<div class="data-row protocol-user-row" ${protocolRowAttrs(user)} data-naive-name="${esc(user.username)}">
    ${protocolIdentity(user, "HTTPS · HTTP/2 CONNECT")}
    <div class="cell"><span class="status-pill ${enabled ? "active" : "blocked"}"><i></i>${status}</span></div>
    <div class="cell"><b>↑ ${measuredBytes(user.upload_bytes_decimal)} · ↓ ${measuredBytes(user.download_bytes_decimal)} · Σ ${measuredBytes(user.total_bytes_decimal)}</b><small>${user.period_start ? `с ${date(user.period_start)} · ` : ""}квота ${quota}</small><small class="live-rate" data-live-rate="${esc(user.username)}"></small></div>
    <div class="row-actions">${actions}</div>
  </div>`;
}

export function paintNaive(context) {
  const list = query("#naive-list", context.root);
  if (!list) return;
  const items = filteredNaive(context.state);
  list.innerHTML = items.length
    ? items.map((user) => naiveRow(context, user)).join("")
    : '<div class="empty-state"><span>◇</span><h3>Naive-доступы не найдены</h3><p>Измените поиск или создайте новый доступ.</p></div>';
  repaintLiveRates(context);
}

export async function renderNaive(context, generation) {
  const users = await refreshNaive(context, generation);
  if (!isCurrent(context.state, generation, "naive") || users === null) return;
  const active = users.filter((user) => user.enabled).length;
  const blocked = users.length - active;
  const ready = context.state.naiveService.ready === true;
  context.ui.view.innerHTML = `<div class="naive-overview service-overview">
    ${serviceSummary({ name: "NaiveProxy / Caddy", detail: context.state.naiveService.host || "HTTPS · HTTP/2 CONNECT", status: ready ? "Работает" : "Менеджер недоступен", tone: ready ? "active" : "blocked" })}
    <article><small>Доступы</small><strong>${number(active)}</strong><span>${blocked ? `${blocked} отключено` : "Все активны"}</span></article>
    <article><small>Учёт</small><strong>${bytes(sumNaiveTraffic(users))}</strong><span>payload-байты закрытых CONNECT</span></article>
  </div>
  ${protocolToolbar(context, "naive", users.length)}
  <section class="data-panel"><div class="data-head protocol-user-row"><span>Клиент / учётная запись</span><span>Статус</span><span>Трафик ↑ / ↓ / Σ</span><span class="align-right">Действия</span></div><div id="naive-list"></div></section>`;
  paintNaive(context);
  bindProtocolFilters(context, "naive");
  startLiveRates(context, generation, "naive", "naive");
}

function naiveQuotaBytes(context, prefix) {
  return trafficLimit(context.root, prefix);
}

function syncNaiveCreateButton(context) {
  const form = query("#naive-form", context.root);
  const input = query("#new-naive-user", context.root);
  query("#create-naive", context.root).disabled = !input.value || !form.checkValidity();
}

export function openNaiveModal(context) {
  query("#naive-form", context.root).reset();
  bindLimitToggles(context.root);
  query("#naive-error", context.root).textContent = "";
  syncNaiveCreateButton(context);
  context.ui.openModal("#naive-modal", "#new-naive-user");
  void loadNodeOptions(context, "#naive-modal", query("#naive-node", context.root));
}

function openNaiveQuotaModal(context, user) {
  const { root, ui } = context;
  const form = query("#naive-quota-form", root);
  const input = query("#naive-quota-traffic-gb", root);
  form.reset();
  query("#naive-quota-user", root).value = user.username;
  query("#naive-quota-title", root).textContent = `Квота · ${user.username}`;
  query("#naive-quota-error", root).textContent = "";
  if (user.quota_bytes_decimal != null) {
    try {
      input.value = bytesToGb(user.quota_bytes_decimal);
    } catch {
      input.value = "";
    }
  }
  query("#naive-quota-current", root).textContent = user.quota_bytes_decimal == null
    ? "Сейчас квоты нет"
    : `Сейчас: ${user.quota_bytes_decimal} Б`;
  query("#naive-quota-traffic-enabled", root).checked = user.quota_bytes_decimal != null;
  bindLimitToggles(root);
  form.dataset.initialQuota = `${input.disabled}:${input.value}`;
  ui.openModal("#naive-quota-modal");
}

export async function handleNaiveAction(context, action, username, button) {
  try {
    const { api, state, ui } = context;
    if (action === "access") {
      ui.setBusy(button, true, "Загрузка…");
      context.access.showNaiveAccess(await api(`/api/naive/users/${encodeURIComponent(username)}/access`, { method: "POST" }), username);
      return;
    }
    if (action === "quota") {
      const user = state.naiveUsers.find((item) => item.username === username);
      if (user) openNaiveQuotaModal(context, user);
      return;
    }
    const confirmations = {
      "reset-traffic": ["Сбросить локальный счётчик?", `Учётные данные ${username} не изменятся. Активные туннели будут учтены после закрытия.`, "Сбросить"],
      disable: ["Отключить Naive-доступ?", `${username} больше не сможет подключаться после применения Caddy.`, "Отключить"],
      enable: ["Включить Naive-доступ?", `${username} снова сможет использовать HTTPS-прокси.`, "Включить"],
      rotate: ["Сменить пароль?", `Текущая конфигурация ${username} немедленно перестанет работать.`, "Сменить пароль"],
      delete: ["Удалить Naive-доступ?", `${username} будет удалён без возможности восстановления.`, "Удалить"],
    };
    if (confirmations[action] && !await ui.confirmed(...confirmations[action])) return;
    ui.setBusy(button, true);
    if (action === "delete") {
      await api(`/api/naive/users/${encodeURIComponent(username)}`, { method: "DELETE" });
    } else if (action === "reset-traffic") {
      await api(`/api/naive/users/${encodeURIComponent(username)}/traffic/reset`, { method: "POST" });
    } else {
      const data = await api(`/api/naive/users/${encodeURIComponent(username)}/${action}`, { method: "POST" });
      if (action === "rotate") await context.access.revealNaiveToken(data.reveal_token, username);
    }
    ui.toast({ delete: "Naive-доступ удалён", disable: "Naive-доступ отключён", enable: "Naive-доступ включён", "reset-traffic": "Счётчик Naive-трафика сброшен", rotate: "Пароль обновлён" }[action]);
    await context.navigate("naive");
  } catch (error) {
    context.ui.toast(error.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

export function bindNaive(context) {
  const { api, root, ui } = context;
  query("#naive-form", root)?.addEventListener("input", () => syncNaiveCreateButton(context));
  query("#create-naive", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#naive-form", root);
    const input = query("#new-naive-user", root);
    const error = query("#naive-error", root);
    error.textContent = "";
    if (!form.reportValidity()) return;
    const nodeId = query("#naive-node", root).value || "local";
    try {
      ui.setBusy(button, true, "Применяем…");
      const validUntil = validityLimit(root, "new-naive");
      if (nodeId !== "local" || validUntil !== null) {
        // A linked panel: the access is a client's grant there, with the same quota option.
        const quota = naiveQuotaBytes(context, "new-naive");
        const result = await issueOnNode(context, { protocol: "naive", username: input.value, nodeId, options: quota === null ? {} : { quota_bytes: quota }, validUntil });
        closeCreateDialog(root);
        if (result.status === "succeeded") await context.navigate("clients");
        return;
      }
      const data = await api("/api/naive/users", { method: "POST", body: JSON.stringify({ username: input.value, quota_bytes: naiveQuotaBytes(context, "new-naive") }) });
      const access = await api(`/api/reveal/${encodeURIComponent(data.reveal_token)}`);
      query("#naive-modal", root).close();
      context.access.showNaiveAccess(access, input.value);
      ui.toast("Naive-доступ создан");
      await context.navigate("naive");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
      syncNaiveCreateButton(context);
    }
  });
  query("#save-naive-quota", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#naive-quota-form", root);
    const input = query("#naive-quota-traffic-gb", root);
    const error = query("#naive-quota-error", root);
    const username = query("#naive-quota-user", root).value;
    error.textContent = "";
    if (!form.reportValidity()) return;
    if (`${input.disabled}:${input.value}` === form.dataset.initialQuota) {
      query("#naive-quota-modal", root).close();
      return;
    }
    try {
      ui.setBusy(button, true, "Сохраняем…");
      const result = await api(`/api/naive/users/${encodeURIComponent(username)}/quota`, { method: "POST", body: JSON.stringify({ quota_bytes: naiveQuotaBytes(context, "naive-quota") }) });
      query("#naive-quota-modal", root).close();
      ui.toast(result.quota_bytes == null ? "Квота Naive отключена" : "Квота Naive сохранена");
      await context.navigate("naive");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
}

export function handleNaiveInput(context, target) {
  if (target.id !== "naive-search") return false;
  context.state.naiveQuery = target.value;
  paintNaive(context);
  return true;
}

export function handleNaiveClick(context, button) {
  if (button.dataset.naiveFilter) {
    context.state.naiveFilter = button.dataset.naiveFilter;
    context.ui.view.querySelectorAll("[data-naive-filter]").forEach((item) => item.classList.toggle("active", item === button));
    paintNaive(context);
    return true;
  }
  if (button.dataset.naiveAction && button.dataset.user) {
    void handleNaiveAction(context, button.dataset.naiveAction, button.dataset.user, button);
    return true;
  }
  return false;
}

// The creation dialog closes only once the remote issue has answered — the same order the
// local path keeps (reveal fetched, then close), so an error stays visible in the dialog.
function closeCreateDialog(root) {
  query("#naive-modal", root).close();
}
