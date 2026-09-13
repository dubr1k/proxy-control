import { date, esc, initials, query } from "./common.js";

// Scoped Bearer keys (ADR 008): what each scope may do, in the operator's words.
const SCOPE_NAMES = {
  admin: ["admin", "полный доступ владельца"],
  monitor: ["monitor", "только чтение"],
  "node-sync": ["node-sync", "синхронизация с центром"],
};

function keyRow(key) {
  const [scope, scopeHint] = SCOPE_NAMES[key.scope] || [key.scope, ""];
  const now = Math.floor(Date.now() / 1000);
  const expired = key.expires_at !== null && key.expires_at <= now;
  const [tone, status] = !key.enabled ? ["blocked", "Выключен"] : expired ? ["blocked", "Истёк"] : ["active", "Активен"];
  return `<div class="data-row key-grid" data-key-id="${esc(key.id)}">
    <div class="identity"><span class="user-glyph">${esc(initials(key.name))}</span><span><b>${esc(key.name)}</b><small><code>${esc(key.prefix)}…</code> · создан ${date(key.created_at)}${key.created_by ? ` · ${esc(key.created_by)}` : ""}</small></span></div>
    <div class="cell"><b>${esc(scope)}</b><small>${esc(scopeHint)}</small></div>
    <div class="cell"><b>${key.expires_at === null ? "бессрочно" : date(key.expires_at)}</b><small>срок</small></div>
    <div class="cell"><b>${key.last_used_at ? date(key.last_used_at) : "не использовался"}</b><small>последнее использование</small></div>
    <div class="cell"><span class="status-pill ${tone}"><i></i>${status}</span></div>
    <div class="row-actions">
      <button class="action-button" data-key-action="toggle">${key.enabled ? "Выключить" : "Включить"}</button>
      <button class="action-button danger-text" data-key-action="delete">Удалить</button>
    </div>
  </div>`;
}

export async function renderKeys(context, root) {
  if (!root) return;
  let items;
  try {
    items = (await context.api("/api/keys")).items || [];
  } catch (error) {
    if (root.isConnected) root.innerHTML = `<div class="empty-state"><h3>Не удалось загрузить API-ключи</h3><p>${esc(error.message)}</p></div>`;
    return;
  }
  // The admins view may have been left while the keys were loading.
  if (!root.isConnected || context.state.view !== "admins") return;
  context.state.keys = items;
  root.innerHTML = `<div class="panel-head keys-head"><div><h2>API-ключи</h2><span>Bearer-ключи для автоматизации и для центральной панели; плейнтекст показывается один раз</span></div>
      <button class="secondary" data-key-action="create">Создать ключ</button></div>
    <section class="data-panel">
      <div class="data-head key-grid"><span>Ключ</span><span>Scope</span><span>Срок</span><span>Последнее использование</span><span>Статус</span><span class="align-right">Действия</span></div>
      ${items.length
        ? items.map(keyRow).join("")
        : '<div class="empty-state"><h3>Ключей пока нет</h3><p>Ключ node-sync нужен, чтобы добавить этот сервер на центральную панель.</p></div>'}
    </section>`;
}

function openKeyModal(context) {
  query("#key-form", context.root).reset();
  query("#key-error", context.root).textContent = "";
  context.ui.openModal("#key-modal", "#key-name");
}

function expiresAt(value) {
  if (!value) return null;
  const stamp = new Date(value).getTime();
  return Number.isNaN(stamp) ? null : Math.floor(stamp / 1000);
}

export function bindKeys(context) {
  const { api, root, ui } = context;
  query("#create-key", root)?.addEventListener("click", async ({ currentTarget: button }) => {
    const form = query("#key-form", root);
    const error = query("#key-error", root);
    if (!form.reportValidity()) return;
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Создаём…");
      const result = await api("/api/keys", {
        method: "POST",
        body: JSON.stringify({
          name: query("#key-name", root).value.trim(),
          scope: query("#key-scope", root).value,
          expires_at: expiresAt(query("#key-expires", root).value),
        }),
      });
      query("#key-modal", root).close();
      // The plaintext exists only in the reveal dialog: not in the table, not in state after close.
      context.state.keyPlaintext = result.plaintext;
      query("#key-reveal-name", root).textContent = `${result.key.name} · ${result.key.scope}`;
      query("#key-plaintext", root).value = result.plaintext;
      ui.openModal("#key-reveal", "#copy-key");
      await context.navigate("admins");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  });
  query("#copy-key", root)?.addEventListener("click", async () => {
    await ui.copyText(query("#key-plaintext", root));
    ui.toast("Ключ скопирован");
  });
  query("#key-reveal", root)?.addEventListener("close", () => {
    query("#key-plaintext", root).value = "";
    context.state.keyPlaintext = null;
  });
}

async function keyAction(context, key, action, button) {
  try {
    if (action === "delete") {
      const confirmed = await context.ui.confirmed(
        "Удалить API-ключ?",
        `${key.name} перестанет приниматься немедленно; связанная с ним автоматизация или центральная панель потеряет доступ.`,
        "Удалить",
      );
      if (!confirmed) return;
      context.ui.setBusy(button, true);
      await context.api(`/api/keys/${encodeURIComponent(key.id)}`, { method: "DELETE" });
      context.ui.toast("Ключ удалён");
    } else {
      context.ui.setBusy(button, true);
      await context.api(`/api/keys/${encodeURIComponent(key.id)}/enabled`, {
        method: "POST",
        body: JSON.stringify({ enabled: !key.enabled }),
      });
      context.ui.toast(key.enabled ? "Ключ выключен" : "Ключ включён");
    }
    await context.navigate("admins");
  } catch (error) {
    context.ui.toast(error.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

export function handleKeysClick(context, button) {
  const action = button.dataset.keyAction;
  if (!action) return false;
  if (action === "create") {
    openKeyModal(context);
    return true;
  }
  const row = button.closest("[data-key-id]");
  const key = context.state.keys.find((item) => String(item.id) === row?.dataset.keyId);
  if (!key) return true;
  void keyAction(context, key, action, button);
  return true;
}
