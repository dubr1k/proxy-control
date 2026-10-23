import { PROTOCOL_NAMES } from "./placement.js";

function cookie(name) {
  return document.cookie
    .split("; ")
    .find((entry) => entry.startsWith(`${name}=`))
    ?.split("=")
    .slice(1)
    .join("=");
}

const API_REASONS = {
  quota_exhausted: "Квота исчерпана: сбросьте трафик или увеличьте квоту",
};
// Refusals whose English `detail` says more than the code alone (what Xray or the node
// rejected): it follows the operator's words in parentheses.
const DETAIL_WORTH_SHOWING = new Set(["exit_invalid", "egress_invalid", "lanes_invalid", "geodata_rejected", "geodata_fetch_failed", "geodata_invalid", "exit_link_invalid"]);

// The managers' and the panel's English refusals that reach the operator in the client and
// login flows, in the operator's words. Anything unknown keeps the server's own text.
const DETAIL_TEXT = {
  "client still has grants that are not deleted": "У клиента остались неудалённые доступы",
  "only an archived client can be deleted": "Удалить можно только клиента из архива",
  "node has not confirmed grant deletion yet": "Узел ещё не подтвердил удаление доступов клиента: повторите позже",
  "client has an unfinished provisioning operation": "У клиента есть незавершённая операция выдачи доступов: дождитесь её окончания",
  "client has an operation waiting for manual intervention": "У клиента есть операция, требующая ручного вмешательства: завершите её (operations-resume), затем удалите клиента",
  "invalid credentials": "Неверный логин или пароль",
  "runtime_username is already granted on this endpoint": "Это имя учётной записи уже выдано на узле",
};
const TAKEN_NAME = /^(mtproxy|naive|mieru|amneziawg|trusttunnel): runtime username already exists$/;

function detailText(detail) {
  if (Object.hasOwn(DETAIL_TEXT, detail)) return DETAIL_TEXT[detail];
  const taken = TAKEN_NAME.exec(detail);
  return taken ? `Имя учётной записи уже занято на узле: ${PROTOCOL_NAMES[taken[1]]}` : detail;
}

// A screen registers the operator's words for the refusal codes its API speaks (v0.9):
// a `{detail, code}` refusal is then shown in those words, not as the server's English.
export function registerReasons(reasons) {
  Object.assign(API_REASONS, reasons);
}

// FastAPI validation failures are structured objects. Convert only their safe,
// human-facing fields rather than rendering "[object Object]" in a dialog.
export function problemText(body) {
  if (!body || typeof body !== "object") return "";
  if (API_REASONS[body.code]) {
    const detail = typeof body.detail === "string" && DETAIL_WORTH_SHOWING.has(body.code) && body.detail !== body.code ? ` (${body.detail})` : "";
    return API_REASONS[body.code] + detail;
  }
  if (typeof body.detail === "string") return detailText(body.detail);
  if (!Array.isArray(body.detail)) return "";

  return body.detail
    .map((item) => {
      if (!item || typeof item !== "object" || typeof item.msg !== "string") return "";
      const field = Array.isArray(item.loc)
        ? item.loc.filter((part) => typeof part === "string" && part !== "body").join(".")
        : "";
      return field ? `${field}: ${item.msg}` : item.msg;
    })
    .filter(Boolean)
    .slice(0, 3)
    .join("; ");
}

export async function api(url, options = {}) {
  const headers = {
    ...options.headers,
    "X-CSRF-Token": cookie("panel_csrf") || "",
  };
  if (options.body && !headers["content-type"]) headers["content-type"] = "application/json";

  const response = await fetch(url, { ...options, headers });
  // A 401 on the login page is the form's own answer (a wrong password): it is shown
  // there. Anywhere else it means the session is gone, and the form is the next screen.
  if (response.status === 401 && window.location.pathname !== "/login") {
    window.location.assign("/login");
    throw new Error("Сессия завершена");
  }
  if (!response.ok) {
    let detail = "Не удалось выполнить действие";
    try {
      detail = problemText(await response.json()) || detail;
    } catch {
      // A gateway failure may not carry JSON. Keep the generic, safe message.
    }
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}
