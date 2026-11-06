// Presentation only: protocol adapters keep their existing APIs, permissions and counter semantics.
import { bytes, esc, initials, query } from "./common.js";

export const measured = (value) => value !== null && value !== undefined && value !== "" && /^\d+$/.test(String(value));
export const measuredBytes = (value) => measured(value) ? bytes(value) : "—";
export const protocolWritable = (context, row) => context.state.me?.role !== "viewer" && row.client_state !== "archived";

export function protocolIdentity(row, detail) {
  const name = row.client_name || row.username;
  return `<div class="identity"><span class="user-glyph">${esc(initials(name))}</span><span><b>${esc(name)}</b><small>${row.client_name ? esc(row.username) : "Не привязан к клиенту"}</small><small>${esc(detail)}</small></span></div>`;
}

export function protocolRowAttrs(row) {
  const match = [row.client_name, row.username, row.name, row.version].filter(Boolean).join(" ").toLowerCase();
  return `data-protocol-row data-protocol-match="${esc(match)}" data-protocol-enabled="${row.enabled !== false}"`;
}

export function protocolSettings(controls, row = {}) {
  const validity = row.grant_id && row.client_id ? `<button type="button" class="action-button" data-protocol-validity="${esc(row.grant_id)}" data-client="${esc(row.client_id)}">Срок действия</button>` : "";
  return `<details class="actions-menu protocol-settings"><summary>Настроить</summary><div class="actions-menu-body">${controls}${validity}</div></details>`;
}

export function protocolToolbar(context, protocol, total) {
  const filters = context.state.protocolFilters ||= {};
  const saved = filters[protocol] ||= { query: "", status: "all" };
  return `<div class="toolbar protocol-toolbar" data-protocol-toolbar="${esc(protocol)}"><div class="search"><input type="search" data-protocol-search value="${esc(saved.query)}" aria-label="Поиск клиента или учётной записи" placeholder="Клиент или учётная запись"></div><div class="filter-pills" role="group" aria-label="Состояние доступа">${[["all", `Все · ${total}`], ["active", "Активные"], ["blocked", "Отключённые"]].map(([id,label]) => `<button type="button" class="filter-pill${saved.status === id ? " active" : ""}" data-protocol-filter="${id}" aria-pressed="${saved.status === id}">${label}</button>`).join("")}</div><p class="form-hint" data-protocol-empty hidden>Доступы не найдены. Измените поиск или фильтр.</p></div>`;
}

export function bindProtocolFilters(context, protocol) {
  const root = context.ui.view;
  const toolbar = query(`[data-protocol-toolbar="${protocol}"]`, root);
  if (!toolbar) return;
  const saved = context.state.protocolFilters[protocol];
  const paint = () => {
    for (const row of root.querySelectorAll("[data-protocol-row]")) {
      row.hidden = !row.dataset.protocolMatch.includes(saved.query.toLowerCase())
        || (saved.status !== "all" && (row.dataset.protocolEnabled === "true") !== (saved.status === "active"));
    }
    const rows = [...root.querySelectorAll("[data-protocol-row]")];
    const empty = query("[data-protocol-empty]", toolbar);
    if (empty) empty.hidden = !rows.length || rows.some((row) => !row.hidden);
    for (const button of toolbar.querySelectorAll("[data-protocol-filter]")) {
      const active = button.dataset.protocolFilter === saved.status;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    }
  };
  toolbar.addEventListener("input", (event) => {
    if (!event.target.matches("[data-protocol-search]")) return;
    saved.query = event.target.value;
    paint();
  });
  toolbar.addEventListener("click", (event) => {
    const button = event.target.closest("[data-protocol-filter]");
    if (!button) return;
    saved.status = button.dataset.protocolFilter;
    paint();
  });
  if (!root.dataset.protocolValidityBound) {
  root.dataset.protocolValidityBound = "true";
  root.addEventListener("click", (event) => {
    const button = event.target.closest("[data-protocol-validity]");
    if (!button) return;
    void (async () => {
      try {
        const data = await context.api(`/api/clients/${encodeURIComponent(button.dataset.client)}`);
        context.grants.open(button.dataset.client, button.dataset.protocolValidity, data);
        const settings = query("#grant-settings", context.root);
        if (settings) settings.open = true;
      } catch (error) { context.ui.toast(error.message, "error"); }
    })();
  });
  }
  paint();
}

// Decimal GB is explicit; API byte integers are never silently rounded from unsafe numbers.
export function gbToBytes(value) {
  const text = String(value).trim();
  if (!text) return null;
  if (!/^\d+(?:\.\d{1,9})?$/.test(text) || !(Number(text) > 0)) throw new Error("Укажите положительное число ГБ (до 9 знаков после точки)");
  const [whole, fraction = ""] = text.split(".");
  const result = BigInt(whole) * 1_000_000_000n + BigInt(fraction.padEnd(9, "0"));
  if (result > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Лимит трафика слишком большой");
  return Number(result);
}

export function bytesToGb(value) {
  if (value === null || value === undefined || value === "") return "";
  const count = BigInt(String(value));
  const fraction = (count % 1_000_000_000n).toString().padStart(9, "0").replace(/0+$/, "");
  return `${count / 1_000_000_000n}${fraction ? `.${fraction}` : ""}`;
}
