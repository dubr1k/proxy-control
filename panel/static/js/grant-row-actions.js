// Row actions on the AmneziaWG and TrustTunnel screens (v3.0.0): disable/enable, a new key or password
// and delete, right in the list — like the Mieru and NaiveProxy rows — through the same grant API the
// access window uses. An account the panel does not hold (no grant) has no actions here.
import { esc } from "./common.js";

const ROTATE_LABEL = { amneziawg: "Новый ключ", trusttunnel: "Новый пароль" };
const CONFIRM = {
  disable: ["Отключить доступ?", "не сможет подключаться, пока доступ не включат снова.", "Отключить"],
  enable: ["Включить доступ?", "снова сможет подключаться.", "Включить"],
  rotate: {
    amneziawg: ["Выпустить новый ключ?", "получит новую пару ключей: старый конфиг перестанет работать, клиенту понадобится новый файл или QR.", "Выпустить"],
    trusttunnel: ["Сменить пароль?", "получит новый пароль: старая ссылка перестанет работать, клиенту понадобится новая.", "Сменить пароль"],
  },
  delete: ["Удалить доступ?", "будет удалён из протокола; на связанной панели — после доставки узлу.", "Удалить"],
};
const DONE = { disable: "Доступ отключён", enable: "Доступ включён", rotate: "Секрет обновлён; покажите клиенту новый конфиг", delete: "Доступ удалён" };
const TITLES = { amneziawg: "AmneziaWG", trusttunnel: "TrustTunnel" };

export function grantRowActions(row, protocol) {
  if (!row.grant_id) return "";
  const id = esc(row.grant_id);
  const toggle = row.enabled ? "disable" : "enable";
  return `<button class="action-button" data-grant-row-action="${toggle}" data-grant="${id}" data-protocol="${esc(protocol)}" data-user="${esc(row.username)}">${row.enabled ? "Отключить" : "Включить"}</button>`
    + `<button class="action-button" data-grant-row-action="rotate" data-grant="${id}" data-protocol="${esc(protocol)}" data-user="${esc(row.username)}">${ROTATE_LABEL[protocol] || "Новый секрет"}</button>`
    + `<button class="action-button danger-text" data-grant-row-action="delete" data-grant="${id}" data-protocol="${esc(protocol)}" data-user="${esc(row.username)}">Удалить</button>`;
}

export function handleGrantRowAction(context, button) {
  const action = button.dataset.grantRowAction;
  if (!action) return false;
  const { grant, protocol, user } = button.dataset;
  void (async () => {
    const [title, text, ok] = action === "rotate" ? CONFIRM.rotate[protocol] : CONFIRM[action];
    if (!await context.ui.confirmed(title, `${TITLES[protocol] || protocol} · ${user} ${text}`, ok)) return;
    try {
      context.ui.setBusy(button, true);
      await context.api(`/api/clients/grants/${encodeURIComponent(grant)}/${action}`, { method: "POST" });
      context.ui.toast(DONE[action]);
      await context.navigate(context.state.view);
    } catch (exception) {
      context.ui.toast(exception.message, "error");
    } finally {
      context.ui.setBusy(button, false);
    }
  })();
  return true;
}
