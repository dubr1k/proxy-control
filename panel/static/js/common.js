// Numbers and dates follow the interface language (v0.17): `<html lang>` is set by the
// language switch before the first render.
export function locale() {
  // globalThis: the renderers also run outside a browser (the layout tests render them in Node).
  return globalThis.document?.documentElement?.lang === "en" ? "en-GB" : "ru-RU";
}

export function query(selector, root = document) {
  return root.querySelector(selector);
}

export function queryAll(selector, root = document) {
  return [...root.querySelectorAll(selector)];
}

export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

export function icon(name) {
  const shapes = {
    status: '<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/>',
    key: '<path d="M14 7a5 5 0 1 0 3 9l4-4-3-3-2 2-2-2"/>',
    activity: '<path d="M4 13h4l2-5 4 9 2-5h4"/>',
    transfer: '<path d="m8 7 4-4 4 4M12 3v14m4 0-4 4-4-4"/>',
    check: '<path d="m6 12 4 4 8-9"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    manage: '<path d="M5 7h14M8 12h8M10 17h4"/>',
    refresh: '<path d="M20 7v5h-5M19 12a7 7 0 1 0-2 5"/>',
    client: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c0-3.5 2.7-5.5 7-5.5s7 2 7 5.5"/>',
    server: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>',
  };
  return `<svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true">${shapes[name] || ""}</svg>`;
}

export function initials(name) {
  return String(name || "?").slice(0, 2).toUpperCase();
}

// The sidebar's «Клиенты» badge: the overview paints it from the list, the clients screen
// after every change to the list; `null` (the list did not load) shows the dash.
export function paintClientsCount(context, total) {
  const badge = query("#clients-count", context.root);
  if (badge) badge.textContent = typeof total === "number" ? String(total) : "—";
}

export function number(value) {
  return new Intl.NumberFormat(locale()).format(Number(value) || 0);
}

export function bytes(value) {
  let count;
  try {
    count = BigInt(String(value ?? 0));
    if (count < 0n) throw new Error("negative byte count");
  } catch {
    return "0 Б";
  }

  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"];
  let unit = 0;
  let scale = 1n;
  while (unit < units.length - 1 && count >= scale * 1024n) {
    scale *= 1024n;
    unit += 1;
  }
  if (unit === 0) return `${count} ${units[unit]}`;

  const tenths = (count * 10n + scale / 2n) / scale;
  const valueText = tenths < 100n
    ? `${tenths / 10n}.${tenths % 10n}`
    : String((count + scale / 2n) / scale);
  return `${valueText} ${units[unit]}`;
}

export function sumNaiveTraffic(users) {
  return users.reduce((total, user) => total + BigInt(String(user.total_bytes_decimal ?? "0")), 0n);
}

export function date(value) {
  if (!value) return "—";
  const numeric = Number(value);
  const result = new Date(numeric ? (numeric < 1e12 ? numeric * 1000 : numeric) : value);
  if (Number.isNaN(result.valueOf())) return "—";
  return result.toLocaleString(locale(), {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function localDateTime(value) {
  if (!value) return "";
  const result = new Date(value);
  if (Number.isNaN(result.valueOf())) return "";
  const local = new Date(result.getTime() - result.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

export function serialise(value) {
  try {
    return JSON.stringify(value ?? {}, null, 2);
  } catch {
    return "Не удалось отобразить детали";
  }
}

// How a grant saga ended, in the operator's words. Shared: «Новый клиент» and the client
// window both start sagas and must say the same thing about the same status.
export const OPERATION_MESSAGE = {
  succeeded: "Доступы выданы",
  // A grant on a linked node (v0.7): the central has recorded it, the node picks it up on
  // its next heartbeat — not an error, and not «done» either.
  pending_remote: "Отправлено узлу: доступ появится после доставки",
  compensated: "Операция отменена: созданное удалено, ничего лишнего не тронуто",
  manual_intervention_required: "Требуется вмешательство: часть изменений не удалось откатить",
};
// The outcomes that are not failures: done, or handed to the node.
export const OPERATION_OK = new Set(["succeeded", "pending_remote"]);

// v1.0.1: a component's recent releases, split into updates and roll-backs by the agent's
// `newer` flag (an agent before 1.0.1 lists only newer releases and sends no flag).
export function versionOptions(entries) {
  const option = (entry) => `<option value="${esc(entry.version)}" data-kind="${esc(entry.kind || "artifact")}" data-newer="${entry.newer === false ? "0" : "1"}">${esc(entry.version)} · ${entry.source === "upstream" ? "с GitHub" : "каталог"}${entry.newer === false ? " · откат" : ""}</option>`;
  const group = (label, list) => (list.length ? `<optgroup label="${label}">${list.map(option).join("")}</optgroup>` : "");
  const newer = entries.filter((entry) => entry.newer !== false);
  const older = entries.filter((entry) => entry.newer === false);
  return `<option value="">Выберите версию</option>${group("Новее установленной", newer)}${group("Откат на прежнюю", older)}`;
}

// A running build the agent knows only by its image digest («sha256:7c84…»): the catalog or
// upstream entry with that digest gives it the human version, else it is a «сборка sha256:…».
// The body of «install this version»: the agent compares `expected_current` with the value
// it reported itself, so it is the raw one (a digest stays a digest), never the display label.
export function updateRequestBody(version, rawCurrent) {
  return { version, expected_current: rawCurrent === "не определена" ? null : rawCurrent };
}

export function installedVersion(current, available) {
  if (typeof current !== "string" || !current.startsWith("sha256:")) return { label: current, entry: null };
  const digest = current.slice("sha256:".length);
  const entry = (available || []).find((item) => digest.length >= 12
    && [item.image, item.base_image, item.sha256].some((value) => typeof value === "string" && value.includes(digest)));
  return entry ? { label: entry.version, entry } : { label: `сборка ${current}`, entry: null };
}

// Dotted numeric order (3.5.9 < 3.5.14) for the releases around a digest-identified build.
export function versionIsNewer(version, installed) {
  const parse = (text) => {
    const [base, ...rest] = String(text).trim().replace(/^v/i, "").split(/[-+]/);
    return { numbers: base.split(".").map((part) => Number.parseInt(part, 10) || 0), pre: rest.length > 0 };
  };
  const left = parse(version);
  const right = parse(installed);
  for (let i = 0; i < Math.max(left.numbers.length, right.numbers.length); i += 1) {
    const diff = (left.numbers[i] || 0) - (right.numbers[i] || 0);
    if (diff) return diff > 0;
  }
  // 26.10.17-beta ranks below 26.10.17
  return left.pre === right.pre ? false : right.pre;
}

// What the Versions screen and the overview's attention block both ask of a component: the
// version it runs (a digest-only build is named through the catalog) and the catalog entries
// that differ from it, each marked as newer or as a roll-back.
export function offeredVersions(item) {
  const available = Array.isArray(item?.available) ? item.available : [];
  const raw = item?.current || "не определена";
  const { label: current, entry: installed } = installedVersion(raw, available);
  const offered = available.filter((entry) => entry.version !== current)
    .map((entry) => (installed ? { ...entry, newer: versionIsNewer(entry.version, installed.version) } : entry));
  return { raw, current, offered, hasNewer: offered.some((entry) => entry.newer !== false) };
}

export function plural(count, one, few, many) {
  const tens = count % 100;
  const units = count % 10;
  if (tens >= 11 && tens <= 14) return many;
  if (units === 1) return one;
  if (units >= 2 && units <= 4) return few;
  return many;
}

export function cssEscape(value) {
  if (globalThis.CSS?.escape) return globalThis.CSS.escape(value);
  return String(value).replace(/[^A-Za-z0-9_-]/g, "\\$&");
}

// Native disclosure keeps secondary controls reachable by keyboard without portal positioning.
export function actionMenu(controls) {
  return `<details class="actions-menu"><summary aria-label="Ещё действия">⋯</summary><div class="actions-menu-body">${controls}</div></details>`;
}
