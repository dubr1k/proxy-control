import { query } from "./common.js";
import { gbToBytes } from "./protocol-users.js";

export function bindLimitToggles(root) {
  const sync = (toggle) => {
    for (const input of root.querySelectorAll(`[data-limit-group="${toggle.dataset.limitToggle}"]`)) {
      input.disabled = !toggle.checked;
      input.required = toggle.checked && !input.hasAttribute("data-limit-optional");
    }
  };
  for (const toggle of root.querySelectorAll("[data-limit-toggle]")) {
    if (!toggle.dataset.limitBound) {
      toggle.addEventListener("change", () => sync(toggle));
      toggle.dataset.limitBound = "true";
    }
    sync(toggle);
  }
}

export function trafficLimit(root, prefix) {
  if (!query(`#${prefix}-traffic-enabled`, root)?.checked) return null;
  const value = gbToBytes(query(`#${prefix}-traffic-gb`, root).value);
  if (value === null) throw new Error("Укажите лимит трафика в ГБ");
  return value;
}

export function validityLimit(root, prefix, now = Date.now()) {
  if (!query(`#${prefix}-validity-enabled`, root)?.checked) return null;
  const input = query(`#${prefix}-validity-days`, root);
  // Editing other settings must never slide an existing expiry forward by rounded days.
  if (input.dataset.original && input.value === input.dataset.initial) return Number(input.dataset.original);
  const days = Number(input.value);
  if (!Number.isInteger(days) || days < 1 || days > 36500) throw new Error("Срок должен быть целым числом дней от 1 до 36500");
  return Math.floor(now / 1000) + days * 86400;
}

export function setValidityLimit(root, prefix, until) {
  const toggle = query(`#${prefix}-validity-enabled`, root);
  const input = query(`#${prefix}-validity-days`, root);
  toggle.checked = until !== null && until !== undefined;
  input.value = toggle.checked ? String(Math.max(1, Math.ceil((Number(until) - Date.now() / 1000) / 86400))) : "";
  input.dataset.original = toggle.checked ? String(until) : "";
  input.dataset.initial = input.value;
  bindLimitToggles(root);
}

export const mieruQuota = (bytes, days) => {
  const windowDays = Number(days);
  if (!Number.isInteger(windowDays) || windowDays < 1 || windowDays > 3650) throw new Error("Укажите окно Mieru от 1 до 3650 дней");
  const megabytes = Math.ceil(bytes / 1_048_576);
  if (megabytes > 2147483647) throw new Error("Лимит трафика Mieru слишком большой");
  return { days: windowDays, megabytes };
};

export function applyManualLimits(grants, root, prefix) {
  const bytes = trafficLimit(root, prefix);
  const until = validityLimit(root, prefix);
  return grants.map((grant) => {
    const options = { ...(grant.options || {}) };
    if (bytes !== null) {
      if (grant.protocol === "mtproxy") options.data_quota_bytes = bytes;
      else if (grant.protocol === "naive") options.quota_bytes = bytes;
      else if (grant.protocol === "mieru") options.quotas = [mieruQuota(bytes, query(`#${prefix}-rolling-days`, root)?.value)];
      else throw new Error("AmneziaWG и TrustTunnel не поддерживают лимит трафика: снимите ограничение или выберите другой протокол");
    }
    return { ...grant, options, ...(until !== null ? { valid_until: until } : {}) };
  });
}
