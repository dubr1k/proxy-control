import { cssEscape, date, esc, initials, offeredVersions, query, updateRequestBody, versionOptions } from "./common.js";
import { renderKeys } from "./keys.js";
import { isCurrent } from "./state.js";

const ROLE_NAMES = { owner: "Владелец", admin: "Администратор", viewer: "Наблюдатель" };
// The panel's own update (v0.11) restarts the panel: the browser polls until the agent's
// state leaves `updating`, ignoring the fetch errors of the restart window.
const PANEL_POLL_MS = 3000;
const PANEL_POLL_LIMIT_MS = 10 * 60 * 1000;
const PANEL_CONFIRM = "Панель пересоберётся и перезапустится; страница перезагрузится сама, когда панель ответит новой версией. База данных и код сохраняются в rollback-копии.";
let panelPoll = null;
let rebuildTimer = null;

export { ROLE_NAMES };

export async function renderVersions(context, generation) {
  const data = await context.api("/api/versions");
  if (!isCurrent(context.state, generation, "versions")) return;
  context.state.versions = data || { enabled: false, components: {} };
  if (context.state.versions.enabled !== true) {
    context.ui.view.innerHTML = '<div class="empty-state"><span>!</span><h3>Агент обновлений недоступен</h3><p>Установите и запустите host version-agent. Панель не скачивает runtime-файлы и не получает Docker socket.</p></div>';
    return;
  }
  // The agent lists `xray` only on a host that runs the Xray-router, so there is no
  // "router not installed" branch here.
  // 3.2 (owner): the panel's own card first, then the runtimes in the order of the overview.
  const names = { panel: "Proxy Control / панель", telemt: "Telemt / MTProxy", mita: "Mieru / mita", amneziawg: "AmneziaWG / amneziawg-go", trusttunnel: "TrustTunnel / endpoint", naive: "NaiveProxy / Caddy", xray: "Xray-router / Xray-core" };
  const order = Object.keys(names);
  const rank = (component) => (order.includes(component) ? order.indexOf(component) : order.length);
  const checkedAt = context.state.versions.checked_at ? `Проверено ${date(context.state.versions.checked_at)}` : "Обновления с GitHub ещё не проверялись";
  const checkBar = context.state.versions.upstream_enabled === false ? "" : `<div class="version-check"><span>${esc(checkedAt)}</span><button class="ghost" data-version-check="1">Проверить обновления</button></div>`;
  const cards = Object.entries(context.state.versions.components || {}).sort(([a], [b]) => rank(a) - rank(b)).map(([component, item]) => {
    const { raw, current, offered, hasNewer } = offeredVersions(item);
    const available = Array.isArray(item.available) ? item.available : [];
    const upstream = item.upstream || {};
    const notInstallable = !hasNewer && upstream.latest && upstream.reason === "no_published_digest"
      ? `<p class="version-empty"><b>Вышла ${esc(upstream.latest)}</b>, но релиз без опубликованного хэша — установка невозможна</p>`
      : "";
    // The panel's own update runs in the agent's background (another tab may have started it).
    const updating = component === "panel" && item.status === "updating";
    const control = updating
      ? `<p class="version-empty"><b>Обновление идёт…</b> Панель пересобирается и перезапускается; страница перезагрузится сама.</p><button class="primary version-update" disabled>Обновление идёт…</button>`
      : offered.length
        ? `${hasNewer ? "" : notInstallable || upToDate(current, upstream, available)}<label>Установить версию<select data-version-select="${esc(component)}">${versionOptions(offered)}</select></label><button class="primary version-update" data-version-update="${esc(component)}" data-current="${esc(raw)}" data-current-label="${esc(current)}" disabled>Установить</button>`
        : `${notInstallable || upToDate(current, upstream, available)}<button class="primary version-update" disabled>Установить</button>`;
    const failure = upstream.last_error ? `<small class="version-note">Проверка не удалась: ${esc(upstream.last_error)}</small>` : "";
    // Managers the agent does not rebuild: their sources changed with the release.
    // The agent rebuilds them itself after a panel update; the button is for a failed or disabled rebuild.
    const pendingList = Array.isArray(item.pending_rebuild) ? item.pending_rebuild : [];
    const rebuilding = component === "panel" && item.rebuilding_managers === true;
    const canRebuild = context.state.me?.role === "owner" && !rebuilding && item.status !== "updating"
      && pendingList.some((name) => name !== "docker");
    const rebuildError = item.rebuild_error ? `<small class="version-note">Пересборка менеджеров не удалась: ${esc(item.rebuild_error)}</small>` : "";
    const pending = rebuilding
      ? '<p class="version-empty"><b>Пересборка менеджеров…</b> Туннели и сессии могут ненадолго оборваться.</p>'
      : pendingList.length
        ? `<p class="version-empty">${esc(pendingList.join(", "))} — ещё не пересобраны</p>${rebuildError}${canRebuild ? '<button class="ghost" data-managers-rebuild="1">Пересобрать менеджеры</button>' : ""}`
        : "";
    const lastError = component === "panel" && item.last_error ? `<small class="version-note">Последнее обновление: ${esc(item.last_error)}</small>` : "";
    return `<article class="version-card"><div class="panel-head"><div><h2>${esc(names[component] || component)}</h2><span>Текущая версия: <b>${esc(current)}</b></span></div><span class="status-pill ${current === "не определена" ? "blocked" : "active"}"><i></i>${current === "не определена" ? "Не определена" : "Установлена"}</span></div>${control}${pending}${lastError}${failure}</article>`;
  }).join("");
  context.ui.view.innerHTML = `<details class="page-help"><summary>Как обновлять</summary><p>Перед заменой проверяется контрольная сумма, а прежняя версия сохраняется для отката. «Каталог» — версии, проверенные оператором сервера; «с GitHub» — свежие релизы, проект их сам не проверял.</p></details>${checkBar}<section class="version-grid">${cards || '<div class="empty-state"><h3>Каталог версий пуст</h3></div>'}</section>`;
  if (context.state.versions.components?.panel?.status === "updating") void pollPanelUpdate(context, null);
  // A manager rebuild runs in the agent's background: look again until it is over.
  window.clearTimeout(rebuildTimer);
  if (context.state.versions.components?.panel?.rebuilding_managers === true) {
    rebuildTimer = window.setTimeout(() => { if (isCurrent(context.state, generation, "versions")) void context.navigate("versions"); }, 4000);
  }
}

function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

// Waits for the panel's own update to finish: `GET /api/versions` every 3 s (the panel is
// down for part of it — a failed fetch is expected, not an error), at most 10 minutes.
// The page reloads itself once the panel answers with the new version.
async function pollPanelUpdate(context, version) {
  if (panelPoll) return panelPoll;
  panelPoll = (async () => {
    const deadline = Date.now() + PANEL_POLL_LIMIT_MS;
    let panel = null;
    while (Date.now() < deadline) {
      await sleep(PANEL_POLL_MS);
      try {
        const data = await context.api("/api/versions");
        panel = data?.components?.panel || null;
      } catch {
        continue; // the panel is restarting
      }
      if (panel && panel.status !== "updating") break;
      panel = null;
    }
    if (panel && (version ? panel.current === version : !panel.last_error)) {
      context.ui.toast(`Панель обновлена до ${panel.current}`);
      window.location.reload();
      return;
    }
    context.ui.toast(panel ? (panel.last_error || "Панель не обновилась") : "Панель не ответила за 10 минут", "error");
    if (context.state.view === "versions") await context.navigate("versions");
  })().finally(() => { panelPoll = null; });
  return panelPoll;
}

// Nothing to offer is good news once upstream answered: say so instead of «в каталоге нет
// версий», which reads like a fault. Without a check the catalog is all there is.
function upToDate(current, upstream, available) {
  if (upstream.checked_at && upstream.latest) {
    const same = upstream.latest === current || current.startsWith(`${upstream.latest}-`);
    return `<p class="version-empty"><b>Установлена актуальная версия</b> — ${same ? "новее релизов на GitHub нет" : `последний релиз ${esc(upstream.latest)} не новее установленной`}</p>`;
  }
  if (upstream.checked_at) return '<p class="version-empty"><b>Обновлений не обнаружено</b> — GitHub не ответил версией, каталог пуст</p>';
  return `<p class="version-empty"><b>Обновлений не обнаружено</b>${available.length ? "" : " — в каталоге нет версий; нажмите «Проверить обновления»"}</p>`;
}

async function checkVersions(context, button) {
  try {
    context.ui.setBusy(button, true, "Проверяем…");
    await context.api("/api/versions/check", { method: "POST" });
    context.ui.toast("Обновления с GitHub проверены");
    await context.navigate("versions");
  } catch (error) {
    context.ui.toast(`Не удалось проверить: ${error.message}`, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

async function rebuildManagers(context, button) {
  try {
    context.ui.setBusy(button, true, "Пересобираем…");
    await context.api("/api/versions/panel/rebuild-managers", { method: "POST" });
    context.ui.toast("Пересборка менеджеров запущена");
    await context.navigate("versions");
  } catch (error) {
    context.ui.toast(`Не удалось пересобрать: ${error.message}`, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

async function versionAction(context, component, button) {
  const select = query(`[data-version-select="${cssEscape(component)}"]`, context.ui.view);
  const version = select?.value;
  const raw = button.dataset.current;
  const current = button.dataset.currentLabel || raw;
  if (!version) return;
  // A `naive` candidate of kind `build` rebuilds Caddy on the host (up to 15 min); a `telemt`
  // one builds a local image from the upstream release binary.
  const building = (component === "naive" || component === "telemt") && select.selectedOptions[0]?.dataset.kind === "build";
  // 3.2: the AmneziaWG and TrustTunnel managers carry their runtime in their own image.
  const manager = component === "amneziawg" || component === "trusttunnel";
  const warning = manager
    ? component === "amneziawg"
      ? " Образ менеджера AmneziaWG будет пересобран на хосте с amneziawg-go этой версии (несколько минут); туннели оборвутся на несколько секунд и клиенты переподключатся сами."
      : " Образ менеджера TrustTunnel будет пересобран на хосте с endpoint этой версии (около минуты); сессии оборвутся на несколько секунд."
    : !building ? "" : component === "naive"
      ? " Caddy будет пересобран на хосте, это занимает до 15 минут."
      : " Образ Telemt будет собран на хосте из бинарника релиза, это занимает несколько минут.";
  const panel = component === "panel";
  const back = select.selectedOptions[0]?.dataset.newer === "0";
  const text = panel ? `Панель: ${current} → ${version}. ${PANEL_CONFIRM}` : `${component}: ${current} → ${version}. Сервис будет перезапущен или перезагружен, а при ошибке агент выполнит rollback.${warning}`;
  const title = panel ? "Обновить панель?" : back ? "Откатить компонент?" : "Обновить компонент?";
  if (!await context.ui.confirmed(title, text, back ? "Откатить" : "Обновить")) return;
  try {
    context.ui.setBusy(button, true, panel ? "Перезапускаем…" : building || manager ? "Собираем…" : "Обновляем…");
    await context.api(`/api/versions/${encodeURIComponent(component)}/update`, { method: "POST", body: JSON.stringify(updateRequestBody(version, raw)) });
    if (panel) {
      // The agent answered before restarting the panel: do not navigate, wait for it.
      await pollPanelUpdate(context, version);
      return;
    }
    context.ui.toast(`${component}: установлена ${version}`);
    await context.navigate("versions");
  } catch (error) {
    context.ui.toast(error.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

export async function renderAdmins(context, generation) {
  const data = await context.api("/api/admins");
  if (!isCurrent(context.state, generation, "admins")) return;
  context.state.admins = data.items || [];
  const activeOwners = context.state.admins.filter((admin) => admin.role === "owner" && admin.active).length;
  const rows = context.state.admins.map((admin) => {
    const lastOwner = admin.role === "owner" && admin.active && activeOwners === 1;
    return `<div class="data-row admin-grid"><div class="identity"><span class="user-glyph">${esc(initials(admin.username))}</span><span><b>${esc(admin.username)}</b><small>Создан ${date(admin.created_at)}</small></span></div><div class="cell"><b>${esc(ROLE_NAMES[admin.role] || admin.role)}</b></div><div class="cell"><span class="status-pill ${admin.active ? "active" : "blocked"}"><i></i>${admin.active ? "Активен" : "Отключён"}</span></div><div class="row-actions"><button class="action-button" data-management-action="edit-admin" data-admin-id="${admin.id}">Настроить</button><button class="action-button ${lastOwner ? "" : "danger-text"}" data-management-action="toggle-admin" data-admin-id="${admin.id}" ${lastOwner ? "disabled title=\"Нельзя отключить последнего владельца\"" : ""}>${admin.active ? "Отключить" : "Включить"}</button></div></div>`;
  }).join("");
  context.ui.view.innerHTML = `<section class="data-panel"><div class="data-head admin-grid"><span>Администратор</span><span>Роль</span><span>Статус</span><span class="align-right">Действия</span></div>${rows || '<div class="empty-state"><h3>Администраторы не найдены</h3></div>'}</section>
    <section id="api-keys" class="keys-section"><div class="skeleton-grid"><i></i><i></i></div></section>`;
  // API keys are the second half of this view (spec §7); they load after the table so a
  // slow key listing never delays the administrators.
  await renderKeys(context, query("#api-keys", context.ui.view));
}

export function openAdminModal(context, admin = null) {
  const { root, state, ui } = context;
  const lastOwner = admin?.role === "owner" && admin?.active && state.admins.filter((item) => item.role === "owner" && item.active).length === 1;
  query("#admin-form", root).reset();
  query("#admin-id", root).value = admin?.id || "";
  query("#admin-user", root).value = admin?.username || "";
  query("#admin-user", root).disabled = Boolean(admin);
  query("#admin-role", root).value = admin?.role || "viewer";
  query("#admin-role", root).disabled = lastOwner;
  query("#admin-modal-title", root).textContent = admin ? "Настроить администратора" : "Новый администратор";
  query("#password-hint", root).textContent = admin ? "Оставьте пустым, чтобы не менять" : "Обязателен для нового администратора";
  query("#admin-password", root).required = !admin;
  query("#admin-error", root).textContent = "";
  query("#delete-admin", root).hidden = !admin || lastOwner;
  ui.openModal("#admin-modal", admin ? "#admin-role" : "#admin-user");
}

export function bindManagement(context) {
  const { root, api, ui } = context;
  query("#save-admin", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#admin-form", root);
    const error = query("#admin-error", root);
    if (!form.reportValidity()) return;
    const id = query("#admin-id", root).value;
    const password = query("#admin-password", root).value;
    const payload = { role: query("#admin-role", root).value };
    if (password) payload.password = password;
    if (!id) {
      payload.username = query("#admin-user", root).value;
      payload.password = password;
    }
    if (!id && password.length < 12) {
      error.textContent = "Пароль должен содержать не менее 12 символов";
      return;
    }
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Сохраняем…");
      await api(id ? `/api/admins/${id}` : "/api/admins", { method: id ? "PATCH" : "POST", body: JSON.stringify(payload) });
      query("#admin-modal", root).close();
      ui.toast(id ? "Администратор обновлён" : "Администратор добавлен");
      await context.navigate("admins");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#delete-admin", root)?.addEventListener("click", async () => {
    const id = query("#admin-id", root).value;
    const admin = context.state.admins.find((item) => String(item.id) === id);
    if (!admin || !await ui.confirmed("Удалить администратора?", `${admin.username} потеряет доступ к панели.`, "Удалить")) return;
    try {
      await api(`/api/admins/${id}`, { method: "DELETE" });
      query("#admin-modal", root).close();
      ui.toast("Администратор удалён");
      await context.navigate("admins");
    } catch (error) {
      ui.toast(error.message, "error");
    }
  });
}

export function handleManagementChange(context, target) {
  const component = target.dataset.versionSelect;
  if (!component) return false;
  const button = query(`[data-version-update="${cssEscape(component)}"]`, context.ui.view);
  if (button) button.disabled = !target.value;
  return true;
}

export function handleManagementClick(context, button) {
  if (button.dataset.versionCheck) {
    void checkVersions(context, button);
    return true;
  }
  if (button.dataset.managersRebuild) {
    void rebuildManagers(context, button);
    return true;
  }
  if (button.dataset.versionUpdate) {
    void versionAction(context, button.dataset.versionUpdate, button);
    return true;
  }
  if (button.dataset.managementAction === "edit-admin") {
    openAdminModal(context, context.state.admins.find((admin) => String(admin.id) === button.dataset.adminId));
    return true;
  }
  if (button.dataset.managementAction === "toggle-admin") {
    const admin = context.state.admins.find((item) => String(item.id) === button.dataset.adminId);
    if (!admin || button.disabled) return true;
    void (async () => {
      if (!await context.ui.confirmed(admin.active ? "Отключить администратора?" : "Включить администратора?", admin.active ? `${admin.username} потеряет доступ, активные сессии будут закрыты.` : `${admin.username} снова сможет войти в панель.`, admin.active ? "Отключить" : "Включить")) return;
      try {
        context.ui.setBusy(button, true);
        await context.api(`/api/admins/${admin.id}`, { method: "PATCH", body: JSON.stringify({ active: !admin.active }) });
        context.ui.toast(admin.active ? "Администратор отключён" : "Администратор включён");
        await context.navigate("admins");
      } catch (error) {
        context.ui.toast(error.message, "error");
      } finally {
        context.ui.setBusy(button, false);
      }
    })();
    return true;
  }
  return false;
}
