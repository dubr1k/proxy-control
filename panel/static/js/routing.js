// «Маршрутизация» (spec §8.4): one egress policy per node × protocol, edited in a neutral
// form and previewed as what the node's backend would actually enforce. The preview is the
// compiler's honest answer: an unsupported rule is named, not silently dropped, and
// «Применить» is enabled only for a saved, supported policy.
import { date, esc, number, query, queryAll } from "./common.js";
import { isCurrent } from "./state.js";

const PROTOCOL_NAMES = { naive: "NaiveProxy", mieru: "Mieru", mtproxy: "MTProxy" };
const PREVIEW_DEBOUNCE_MS = 400;
const REASON_TEXT = {
  protocol_out_of_scope: "вне области маршрутизации",
  protocol_disabled_on_node: "протокол выключен на узле",
  node_lacks_egress_v1: "узел нужно обновить до v0.4",
  node_offline: "узел не на связи",
  manager_unavailable: "менеджер не отвечает",
  managed_by_central: "маршрутизацией управляет центральная панель",
  backend_capability_missing: "backend узла не умеет этого",
  rule_kind_unsupported: "такое правило здесь не применяется",
  private_destination: "локальные и приватные сети можно только блокировать",
  provider_unavailable: "на узле нет WARP",
  provider_unreachable: "WARP на узле не отвечает",
  document_too_large: "политика слишком велика для узла",
  policy_conflict: "политику изменили параллельно — обновите экран",
  policy_applied: "сначала «Сбросить» и применить, потом удалять",
  egress_conflict: "конфигурация узла изменилась — повторите",
  egress_invalid: "узел отверг документ",
  egress_unreachable: "WARP на узле не отвечает — применение отклонено",
  egress_readback_mismatch: "узел не подтвердил конфигурацию и откатил её",
  manual_intervention_required: "узлу требуется ручное вмешательство",
  egress_no_previous: "нечего откатывать",
  unsupported: "политика не применима на этом узле",
  // The node's Xray-router (v0.5).
  router_unavailable: "Xray-router на узле не установлен или не отвечает",
  router_unreachable: "менеджер сервиса не достучался до ingress Xray-router",
  not_attached: "сервис не подключён к Xray-router — сначала «Подключить»",
  node_lacks_router: "узел нужно обновить до v0.5 и установить Xray-router",
  artifact_mismatch: "бинарь или geodata Xray-router не совпадают с релизом — роутер не запущен",
  geosite_unknown: "Xray не знает такого кода geosite",
  geoip_unknown: "Xray не знает такого кода geoip",
  // Lanes and chains (v0.7).
  lane_requires_router: "своя полоса клиента работает только на Xray-router узла",
  lane_not_attached: "сервис не подключён к Xray-router — полоса ждёт «Подключить»",
  lane_unknown: "узел не знает такой полосы",
  lanes_invalid: "менеджер сервиса отверг полосы",
  lane_slots_exhausted: "у Mieru на узле кончились слоты полос",
  node_lacks_lanes: "узел нужно обновить до v0.7 для полос и цепей",
  node_lacks_relay: "у этого узла нет relay — обновите его до v0.7 и включите relay",
  relay_disabled: "relay узла-выхода выключен",
  relay_credential_pending: "узел-выход ещё не подтвердил учётку relay — повторите после heartbeat",
  relay_no_warp: "у узла-выхода нет WARP",
  relay_unavailable: "панель не ведёт реестр relay",
  chain_loop: "цепь проходит через этот же узел",
  node_unknown: "такого узла нет в парке",
  grant_not_found: "доступ не найден",
  node_not_local: "на связанной панели это делается через её поколение",
};
const WARNING_TEXT = {
  provider_unreachable: "WARP на узле не отвечает: политика применится напрямую (fallback)",
  adopts_unmanaged_upstream: "на узле есть upstream, заданный вручную — он будет заменён и сохранён для отката",
  adopts_unmanaged_egress: "на узле есть секция egress, заданная вручную — она будет заменена и сохранена для отката",
  policy_empty: "политика пустая: узел пойдёт напрямую без правил",
  router_credential_stale: "ключ ingress на узле обновлён, менеджер перерисует блок при перезапуске",
  // v0.8: custom exits and geodata
  exit_unknown: "политика называет выход, которого нет",
  exit_disabled: "выход выключен",
  exit_other_node: "выход принадлежит другому узлу",
  exit_secret_pending: "у выхода нет читаемого секрета — задайте пароль заново",
  exit_in_use: "выход используется в политиках",
  exit_unreachable: "через выход ничего не отвечает",
  exit_invalid: "Xray отверг такой аутбаунд",
  exit_test_failed: "проба выхода не запустилась",
  exit_test_busy: "проверка выхода уже идёт",
  exit_link_invalid: "ссылка не разобрана: поддерживаются vless://, trojan://, ss://, socks://, http(s)://",
  node_lacks_exits: "панель узла ещё не умеет свои выходы — обновите её до v0.8",
  node_lacks_geodata: "панель узла ещё не управляет geodata — обновите её до v0.8",
  secret_store_disabled: "нужен мастер-ключ панели (PANEL_MASTER_KEY_FILE)",
  geodata_rejected: "текущая конфигурация не собирается с новыми списками",
  geodata_fetch_failed: "списки не скачались",
  geodata_digest_mismatch: "контрольная сумма списков не совпала с опубликованной",
  geodata_too_large: "файл списков больше допустимого",
  geodata_corrupt: "файл списков не читается",
  geodata_busy: "обновление списков уже идёт",
  geodata_invalid: "источник geodata задан неверно",
  geodata_install_failed: "списки не удалось положить на место",
};
const BACKEND_NAMES = { naive_native: "Caddy", mieru_native: "mita", xray_router: "Xray-router" };
const EXIT_PROTOCOL_NAMES = { vless: "VLESS", trojan: "Trojan", shadowsocks: "Shadowsocks", socks: "SOCKS5", http: "HTTP" };
const SNIFFED_PROTOCOLS = ["tls", "http", "quic", "bittorrent"];
const STATE_TEXT = {
  draft: "черновик", applying: "применяется", applied: "применено", failed: "ошибка", rolled_back: "откачено",
};

export function reasonText(code) {
  return REASON_TEXT[code] || code || "";
}

function emptyPolicy() {
  return { default_action: "direct", default_egress: null, fallback: "fail_closed", rules: [], revision: null };
}

function newRule() {
  return { id: null, enabled: true, action: "block", egress: null, match: { domains: [], cidrs: [], ports: [], geosites: [], geoips: [], protocols: [] }, note: "", preset: null };
}

// Exits (v0.7): `warp` — this node's WARP; `node:<guid>[,<guid>][:warp]` — a chain through
// the relays of other nodes, leaving directly or through the last hop's WARP.
const LANE_SERVICE = "svc";

function currentLane(context) {
  return context.state.routingLane || LANE_SERVICE;
}

function laneQuery(context) {
  const lane = currentLane(context);
  return lane === LANE_SERVICE ? "" : `?lane=${encodeURIComponent(lane)}`;
}

// Plain-text labels (data, not markup): every place that paints one passes it through esc().
function exitOptions(target) {
  const options = [{ value: "warp", label: "WARP этого узла" }];
  for (const exit of target?.custom_exits || []) {
    options.push({ value: "exit:" + exit.id, label: "⇢ " + exit.name + " (" + (EXIT_PROTOCOL_NAMES[exit.protocol] || exit.protocol) + ")" + (exit.enabled ? "" : " — выключен") });
  }
  for (const exit of target?.exits || []) {
    options.push({ value: exit.exit, label: "→ " + exit.display_name + " → напрямую" });
    options.push({ value: exit.exit + ":warp", label: "→ " + exit.display_name + " → WARP " + exit.display_name });
  }
  return options;
}

function exitLabel(target, value) {
  if (!value) return "";
  const known = exitOptions(target).find((option) => option.value === value);
  if (known) return known.label;
  const hops = String(value).replace(/^node:/, "").replace(/:warp$/, "").split(",");
  const names = hops.map((guid) => (target?.exits || []).find((exit) => exit.guid === guid)?.display_name || guid.slice(0, 8));
  return "→ " + names.join(" → ") + " → " + (String(value).endsWith(":warp") ? "WARP" : "напрямую");
}

function exitSelect(target, name, value, index, editable) {
  const options = exitOptions(target);
  if (value && !options.some((option) => option.value === value)) options.push({ value, label: exitLabel(target, value) });
  const attrs = index === null ? `name="${name}"` : `data-rule-field="egress" data-rule-index="${index}"`;
  const items = options.map((option) => `<option value="${esc(option.value)}"${option.value === (value || "warp") ? " selected" : ""}>${esc(option.label)}</option>`).join("");
  return `<select class="routing-exit" ${attrs}${editable ? "" : " disabled"}>${items}</select>`;
}

function splitList(value) {
  return String(value || "").split(/[\s,;]+/).map((item) => item.trim()).filter(Boolean);
}

function draftFromPolicy(policy) {
  return {
    default_action: policy.default_action,
    default_egress: policy.default_egress,
    fallback: policy.fallback,
    revision: policy.revision,
    rules: (policy.rules || []).map((rule) => ({
      id: rule.id, enabled: rule.enabled, action: rule.action, egress: rule.egress, note: rule.note || "", preset: rule.preset || null,
      match: { domains: [...rule.match.domains], cidrs: [...rule.match.cidrs], ports: [...rule.match.ports],
        geosites: [...(rule.match.geosites || [])], geoips: [...(rule.match.geoips || [])], protocols: [...(rule.match.protocols || [])] },
    })),
  };
}

// The body `PUT` and `preview` take: the draft without the UI's own bookkeeping.
// `backend` is the target's current one (Xray-router while the service is attached, the
// native backend otherwise): a new policy is born on the backend that will enforce it.
export function policyBody(draft, backend = null) {
  return {
    ...(backend ? { backend } : {}),
    default_action: draft.default_action,
    default_egress: draft.default_action === "egress" ? draft.default_egress || "warp" : null,
    fallback: draft.fallback,
    rules: draft.rules.map((rule) => ({
      ...(rule.id ? { id: rule.id } : {}),
      enabled: rule.enabled,
      action: rule.action,
      egress: rule.action === "egress" ? rule.egress || "warp" : null,
      match: { domains: rule.match.domains, cidrs: rule.match.cidrs, ports: rule.match.ports,
        geosites: rule.match.geosites, geoips: rule.match.geoips, protocols: rule.match.protocols || [] },
      note: rule.note,
      preset: rule.preset || null,
    })),
  };
}

function policyState(policy, loading = false) {
  if (loading) return ["muted", "загружается…"];
  if (!policy) return ["muted", "политика не задана"];
  if (policy.state === "failed") return ["blocked", `ошибка: ${reasonText(policy.last_error)}`];
  if (policy.state === "applying") return ["", "применяется…"];
  if (policy.applied_current) return ["active", `применено (rev ${number(policy.applied_revision)})`];
  if (policy.applied_revision) return ["", `есть неприменённые изменения (на узле rev ${number(policy.applied_revision)})`];
  return ["muted", STATE_TEXT[policy.state] || policy.state];
}

// The one-line summary the node card shows (spec §8.4): «naive → WARP, 2 блокировки».
export function routingSummary(items) {
  const parts = items
    .filter((item) => item.policy && item.backend)
    .map((item) => {
      const policy = item.policy;
      const target = policy.default_action === "egress" ? "WARP" : "напрямую";
      const blocks = policy.rules?.block ? `, ${number(policy.rules.block)} блокир.` : "";
      const selective = (policy.rules?.direct || 0) + (policy.rules?.egress || 0);
      const extra = selective ? `, ${number(selective)} исключ.` : "";
      const note = policy.applied_current ? "" : policy.state === "failed" ? " (ошибка)" : " (не применено)";
      const via = item.backend === "xray_router" ? " [Xray-router]" : "";
      const lanes = item.lanes?.length ? `, полос: ${number(item.lanes.length)}` : "";
      const exits = new Set([...(policy.node_exits || []), ...(item.lanes || []).flatMap((lane) => lane.node_exits || [])]);
      const chainText = [...exits].map((value) => value.replace(/^node:/, "→ ").replace(/:warp$/, " → WARP").split(",").map((part) => part.slice(0, 10)).join(" → ")).join(", ");
      const chains = exits.size ? ", выходы: " + chainText : "";
      return `${item.protocol} → ${target}${blocks}${extra}${lanes}${chains}${via}${note}`;
    });
  return parts.length ? parts.join("; ") : "не настроена";
}

function targetsFor(context) {
  return context.state.routingTargets.filter((item) => item.node_id === context.state.routingNode);
}

function currentTarget(context) {
  return targetsFor(context).find((item) => item.protocol === context.state.routingProtocol) || null;
}

function nodeOptions(context) {
  const seen = new Map();
  for (const item of context.state.routingTargets) {
    if (!seen.has(item.node_id)) seen.set(item.node_id, { name: item.node_name, kind: item.kind });
  }
  return [...seen.entries()].map(([id, meta]) => `<option value="${esc(id)}"${id === context.state.routingNode ? " selected" : ""}>${esc(meta.name)}${meta.kind === "local" ? " (этот сервер)" : ""}</option>`).join("");
}

function protocolTabs(context) {
  return targetsFor(context).map((item) => {
    const active = item.protocol === context.state.routingProtocol;
    return `<button class="${active ? "active" : ""}" role="tab" aria-selected="${active}" data-routing-action="protocol" data-protocol="${esc(item.protocol)}">${esc(PROTOCOL_NAMES[item.protocol] || item.protocol)}</button>`;
  }).join("");
}

// One rule as a table row (v0.8): what it matches, where it sends, its note — edited in a
// modal, reordered by drag or the arrows. The enabled box is the one inline control.
function whatChips(match) {
  const chips = [];
  for (const [key, prefix] of [["domains", ""], ["geosites", "geosite:"], ["cidrs", ""], ["geoips", "geoip:"], ["protocols", "протокол "]]) {
    for (const item of match[key] || []) chips.push(`<span class="routing-chip">${esc(prefix + item)}</span>`);
  }
  if ((match.ports || []).length) chips.push(`<span class="routing-chip">порт ${esc(match.ports.join(", "))}</span>`);
  return chips.join("") || '<span class="routing-chip muted">пусто</span>';
}

function whereLabel(target, rule) {
  if (rule.action === "block") return "⛔ блок";
  if (rule.action === "direct") return "напрямую";
  return "→ " + (exitLabel(target, rule.egress) || "WARP");
}

function ruleRow(target, rule, index, total, editable) {
  const preset = rule.preset ? `<small class="routing-preset-mark">пресет</small>` : "";
  return `<tr class="routing-rule${rule.enabled ? "" : " disabled"}" data-rule-index="${index}" draggable="${editable}">
    <td class="routing-rule-order">${index + 1}</td>
    <td><input type="checkbox" data-rule-field="enabled" data-rule-index="${index}" aria-label="включено"${rule.enabled ? " checked" : ""}${editable ? "" : " disabled"}></td>
    <td class="routing-rule-what">${whatChips(rule.match)}</td>
    <td class="routing-rule-where">${esc(whereLabel(target, rule))}</td>
    <td class="routing-rule-note">${esc(rule.note || "")}${preset}</td>
    <td class="routing-rule-tools">
      <button type="button" class="ghost" data-routing-action="rule-edit" data-rule-index="${index}"${editable ? "" : " disabled"}>Изменить</button>
      <button type="button" class="ghost" data-routing-action="rule-up" data-rule-index="${index}" title="Выше"${index === 0 || !editable ? " disabled" : ""}>↑</button>
      <button type="button" class="ghost" data-routing-action="rule-down" data-rule-index="${index}" title="Ниже"${index === total - 1 || !editable ? " disabled" : ""}>↓</button>
      <button type="button" class="ghost danger-text" data-routing-action="rule-remove" data-rule-index="${index}"${editable ? "" : " disabled"}>✕</button>
    </td>
  </tr>`;
}

// Quick settings (v0.8): each toggle is one preset rule in the draft.
function presetsLine(context, target, draft, editable) {
  const presets = context.state.routingPresets || [];
  if (!presets.length || target.backend !== "xray_router") return "";
  const buttons = presets.map((item) => {
    const on = draft.rules.some((rule) => rule.preset === item.id);
    return `<label class="routing-preset${on ? " on" : ""}" title="${esc(item.description)}"><input type="checkbox" data-routing-preset="${esc(item.id)}"${on ? " checked" : ""}${editable ? "" : " disabled"}> ${esc(item.title)}</label>`;
  }).join("");
  return `<div class="routing-presets"><b>Быстрые настройки</b>${buttons}</div>`;
}

function editor(context, target, draft, editable) {
  const rules = draft.rules.map((rule, index) => ruleRow(target, rule, index, draft.rules.length, editable)).join("");
  const table = rules
    ? `<div class="import-table-wrap"><table class="import-table routing-table"><thead><tr><th>#</th><th>вкл</th><th>Что</th><th>Куда</th><th>Заметка</th><th></th></tr></thead><tbody id="routing-rules">${rules}</tbody></table></div>`
    : '<p class="routing-empty">Правил нет: весь сервис идёт по умолчанию.</p>';
  return `<form class="routing-editor" id="routing-form" data-node-id="${esc(target.node_id)}" data-protocol="${esc(target.protocol)}">
    <div class="routing-defaults">
      <label>По умолчанию
        <select name="default_action"${editable ? "" : " disabled"}>
          <option value="direct"${draft.default_action === "direct" ? " selected" : ""}>Напрямую</option>
          <option value="egress"${draft.default_action === "egress" ? " selected" : ""}>Через выход</option>
        </select></label>
      ${draft.default_action === "egress" ? `<label>Куда ${exitSelect(target, "default_egress", draft.default_egress, null, editable)}</label>` : ""}
      <label>При недоступности WARP
        <select name="fallback"${editable ? "" : " disabled"}>
          <option value="fail_closed"${draft.fallback === "fail_closed" ? " selected" : ""}>отказать</option>
          <option value="approved_direct"${draft.fallback === "approved_direct" ? " selected" : ""}>напрямую</option>
        </select></label>
    </div>
    ${presetsLine(context, target, draft, editable)}
    ${table}
    <div class="routing-editor-actions">
      <button type="button" class="secondary" data-routing-action="rule-add"${editable ? "" : " disabled"}>Добавить правило</button>
      <button type="button" class="secondary" data-routing-action="reset"${editable ? "" : " disabled"}>Сбросить</button>
      <button type="submit" class="primary" id="routing-save"${editable ? "" : " disabled"}>Сохранить</button>
    </div>
  </form>`;
}

function previewPanel(compiled, policy, dirty) {
  if (!compiled) return '<div class="routing-preview" id="routing-preview"><p class="form-hint">Предпросмотр появится после изменения политики.</p></div>';
  const supported = compiled.status === "supported";
  const reasons = (compiled.reasons || []).map((reason) => `<li class="routing-reason" data-rule-id="${esc(reason.rule_id || "")}">${esc(reasonText(reason.code))}${reason.rule_id ? ` <small>(правило ${esc(ruleLabel(policy, reason.rule_id))})</small>` : ""}${reason.message ? `<small>${esc(reason.message)}</small>` : ""}</li>`).join("");
  const warnings = (compiled.warnings || []).map((warning) => `<li class="routing-warning">${esc(WARNING_TEXT[warning] || warning)}</li>`).join("");
  const diff = (compiled.diff || []).map((line) => `<span class="${line.startsWith("+") ? "added" : line.startsWith("-") ? "removed" : ""}">${esc(line)}</span>`).join("\n");
  const rollback = compiled.rollback ? `откат к ревизии узла ${esc(String(compiled.rollback.to_revision).slice(0, 12))}` : "отката нет: это первая запись";
  return `<div class="routing-preview" id="routing-preview">
    <div class="routing-preview-head">
      <span class="status-pill ${supported ? "active" : "blocked"}"><i></i>${supported ? "поддерживается" : "не применимо"}</span>
      <small>${esc(compiled.backend || "")} · компилятор ${esc(compiled.compiler_version || "")}${dirty ? " · черновик не сохранён" : ""}</small>
    </div>
    ${reasons ? `<ul class="routing-reasons">${reasons}</ul>` : ""}
    ${warnings ? `<ul class="routing-warnings">${warnings}</ul>` : ""}
    <p class="form-hint">${compiled.restart_required ? "потребуется перезапуск сервиса на узле" : "перезапуск не требуется"} · ${rollback}${compiled.runtime_version ? ` · ${esc(compiled.runtime_version)}` : ""}</p>
    ${diff ? `<pre class="routing-diff">${diff}</pre>` : '<p class="form-hint">Изменений относительно узла нет.</p>'}
    ${compiled.document ? `<details class="routing-document"><summary>Документ для менеджера</summary><pre>${esc(JSON.stringify(compiled.document, null, 2))}</pre></details>` : ""}
  </div>`;
}

function ruleLabel(policy, ruleId) {
  const index = (policy?.rules || []).findIndex((rule) => rule.id === ruleId);
  return index >= 0 ? String(index + 1) : ruleId;
}

function historyTable(rows) {
  if (!rows?.length) return '<p class="form-hint">Применений ещё не было.</p>';
  const body = rows.map((row) => `<tr><td>${esc(String(row.created_at ? new Date(row.created_at * 1000).toLocaleString("ru-RU") : "—"))}</td><td>${esc(STATE_TEXT[row.outcome] || row.outcome)}</td><td>rev ${number(row.revision)}</td><td><code>${esc(String(row.digest || "").slice(0, 12))}</code></td><td>${esc(row.actor || "")}</td></tr>`).join("");
  return `<div class="import-table-wrap"><table class="import-table routing-history"><thead><tr><th>Когда</th><th>Исход</th><th>Ревизия</th><th>Digest</th><th>Кто</th></tr></thead><tbody>${body}</tbody></table></div>`;
}

function cardActions(context, policy, compiled, dirty, editable) {
  const owner = context.state.me?.role === "owner";
  const canApply = owner && editable && policy && !dirty && compiled?.status === "supported";
  const canRollback = owner && editable && policy && policy.applied_revision !== null && policy.applied_revision !== undefined;
  return `<div class="routing-actions">
    <button class="primary" data-routing-action="apply"${canApply ? "" : " disabled"}>Применить</button>
    <button class="secondary" data-routing-action="rollback"${canRollback ? "" : " disabled"}>Откатить</button>
    <button class="secondary" data-routing-action="history">История</button>
    <button class="danger ghost" data-routing-action="delete"${owner && policy ? "" : " disabled"}>Удалить политику</button>
  </div>`;
}

// The node's Xray-router (v0.5): where the service's traffic goes before any policy, and the
// one action that moves it — an explicit, confirmed step, never a side effect of a policy.
function routerLine(context, target) {
  const router = target.router;
  if (!router) return "<p class='form-hint routing-router-line'>Xray-router: не установлен — политика применяется собственным backend сервиса.</p>";
  const owner = context.state.me?.role === "owner";
  const status = !router.available ? `не отвечает (${esc(reasonText(router.reason))})` : router.attached ? "сервис подключён" : "сервис не подключён";
  const tone = !router.available ? "blocked" : router.attached ? "" : "muted";
  const version = router.xray_version ? ` · ${esc(router.xray_version)}` : "";
  const action = router.attached
    ? `<button class="secondary" data-routing-action="detach"${owner && !target.reason ? "" : " disabled"}>Отключить от Xray-router</button>`
    : `<button class="secondary" data-routing-action="attach"${owner && router.available && !target.reason ? "" : " disabled"}>Подключить к Xray-router</button>`;
  return `<div class="routing-router-line"><span class="status-pill ${tone}"><i></i>Xray-router: ${status}</span><small>${version}</small>${action}</div>`;
}

// The exits of the node (v0.7, spec §6.3): where a policy may send traffic — this node's
// WARP and every node of the fleet with a relay, with what it can do next.
function exitsLine(context, target) {
  const warp = target.providers?.warp;
  const warpTone = !warp ? "muted" : warp.reachable === false ? "blocked" : "";
  const warpNote = !warp ? " (нет)" : warp.reachable === false ? " (не отвечает)" : "";
  const chips = [
    '<span class="routing-exit-chip" data-exit="direct">Напрямую</span>',
    `<span class="routing-exit-chip ${warpTone}" data-exit="warp">WARP${warpNote}</span>`,
    '<span class="routing-exit-chip" data-exit="block">Блок</span>',
    ...(target.exits || []).map((exit) => {
      const tone = !exit.online ? "blocked" : exit.enabled ? "" : "muted";
      const note = !exit.online ? "не на связи" : exit.enabled ? "relay доступен" : "relay выключен";
      return `<span class="routing-exit-chip ${tone}" data-exit="${esc(exit.exit)}" title="дальше: напрямую или WARP ${esc(exit.display_name)}">→ ${esc(exit.display_name)} <small>${note}</small></span>`;
    }),
  ];
  return `<div class="routing-exits" id="routing-exits"><b>Выходы узла</b>${chips.join("")}</div>`;
}

// Geodata (v0.8): what the router's geosite/geoip codes are resolved against, and where
// the lists come from — the operator sees the version and refreshes or changes the source.
const GEODATA_SOURCES = { xray: "архив Xray-core (пин)", loyalsoldier: "Loyalsoldier", custom: "свои URL" };

function geodataLine(context, target) {
  const state = ensureState(context);
  if (!target.router?.available) return "";
  const owner = context.state.me?.role === "owner";
  if (state.geodataError) return `<div class="routing-geodata"><b>Geodata</b><span class="status-pill blocked"><i></i>${esc(reasonText(state.geodataError))}</span></div>`;
  const geo = state.geodata;
  if (!geo) return "";
  const files = geo.files || {};
  const counts = `geosite: ${number(files.geosite?.codes || 0)} кодов · geoip: ${number(files.geoip?.codes || 0)}`;
  const source = GEODATA_SOURCES[geo.source?.kind] || geo.source?.kind || "?";
  const version = geo.version ? ` ${esc(geo.version)}` : "";
  const when = geo.updated_at ? ` · обновлено ${esc(date(Date.parse(geo.updated_at) / 1000))}` : "";
  const auto = geo.auto_update ? ` · автообновление раз в ${number(geo.interval_hours || 24)} ч` : " · без автообновления";
  const error = geo.last_error ? `<small class="routing-geodata-error">последняя попытка: ${esc(geo.last_error)}</small>` : "";
  const canUpdate = owner && geo.source?.kind !== "xray";
  return `<div class="routing-geodata" id="routing-geodata">
    <b>Geodata</b>
    <span class="status-pill ${geo.last_error ? "blocked" : ""}"><i></i>${esc(source)}${version}</span>
    <small>${esc(counts)}${when}${auto}</small>
    ${error}
    <span class="routing-geodata-tools">
      <button class="ghost" data-routing-action="geodata-update"${canUpdate ? "" : " disabled"}>Обновить сейчас</button>
      <button class="ghost" data-routing-action="geodata-settings"${owner ? "" : " disabled"}>Источник…</button>
    </span>
    <datalist id="geodata-geosite-codes">${codeOptions(state.codes?.geosite)}</datalist>
    <datalist id="geodata-geoip-codes">${codeOptions(state.codes?.geoip)}</datalist>
  </div>`;
}

function codeOptions(codes) {
  return (codes || []).map((code) => `<option value="${esc(code)}"></option>`).join("");
}

function openGeodataModal(context) {
  const { root } = context;
  const geo = ensureState(context).geodata;
  if (!geo) return;
  query("#geodata-form", root).reset();
  query("#geodata-error", root).textContent = "";
  query("#geodata-source", root).value = geo.source?.kind || "xray";
  query("#geodata-geosite-url", root).value = geo.source?.geosite_url || "";
  query("#geodata-geoip-url", root).value = geo.source?.geoip_url || "";
  query("#geodata-auto", root).checked = geo.auto_update === true;
  query("#geodata-interval", root).value = String(geo.interval_hours || 24);
  query("#geodata-custom", root).hidden = query("#geodata-source", root).value !== "custom";
  context.ui.openModal("#geodata-modal", "#geodata-source");
}

async function saveGeodata(context, button) {
  const { root } = context;
  const target = currentTarget(context);
  const error = query("#geodata-error", root);
  const kind = query("#geodata-source", root).value;
  const body = {
    source: { kind },
    auto_update: query("#geodata-auto", root).checked,
    interval_hours: Number(query("#geodata-interval", root).value) || 24,
  };
  if (kind === "custom") {
    body.source.geosite_url = query("#geodata-geosite-url", root).value.trim();
    body.source.geoip_url = query("#geodata-geoip-url", root).value.trim();
  }
  if (!query("#geodata-form", root).reportValidity()) return;
  error.textContent = "";
  context.ui.setBusy(button, true, "Сохраняем…");
  try {
    await context.api(`/api/routing/geodata/settings?node=${encodeURIComponent(target.node_id)}`, { method: "PUT", body: JSON.stringify(body) });
    query("#geodata-modal", root).close();
    ensureState(context).geodata = null;
    context.ui.toast(kind === "xray" ? "Источник — пин установщика; списки вернутся к нему кнопкой «Вернуть пин» или сами при следующем обновлении" : "Настройки geodata сохранены");
    await context.navigate("routing");
  } catch (exception) {
    error.textContent = exception.message;
  } finally {
    context.ui.setBusy(button, false);
  }
}

async function geodataUpdate(context, button) {
  const target = currentTarget(context);
  const geo = ensureState(context).geodata;
  if (!target || !geo) return;
  const action = geo.source?.kind === "xray" ? "restore" : "update";
  const text = action === "restore"
    ? "Списки вернутся к паре, закреплённой установщиком; роутер перезапустится."
    : "Оба файла будут скачаны из источника, проверены и подменены; роутер перезапустится, сессии подключённых сервисов прервутся на мгновение.";
  if (!(await context.ui.confirmed(action === "restore" ? "Вернуть списки к пину?" : "Обновить списки geodata?", text, action === "restore" ? "Вернуть" : "Обновить"))) return;
  context.ui.setBusy(button, true, "…");
  try {
    const result = await context.api(`/api/routing/geodata/${action}?node=${encodeURIComponent(target.node_id)}`, { method: "POST" });
    ensureState(context).geodata = null;
    context.ui.toast(result.changed ? `Списки обновлены${result.version ? ` до ${esc(result.version)}` : ""}` : "Списки уже актуальны");
    await context.navigate("routing");
  } catch (error) {
    context.ui.toast(error.message, "error");
    context.ui.setBusy(button, false);
  }
}

// Custom exits (v0.8): the operator's own outbounds on this node's router.
function customExitsPanel(context, target) {
  if (!target.router) return "";
  const owner = context.state.me?.role === "owner";
  const rows = (target.custom_exits || []).map((exit) => {
    const test = exit.last_test
      ? (exit.last_test.ok ? `✓ ${esc(exit.last_test.ip || "")} ${esc(exit.last_test.colo || "")} · ${number(exit.last_test.latency_ms || 0)} мс` : `✗ ${esc(reasonText(exit.last_test.code) || exit.last_test.error || "не отвечает")}`)
      : "не проверялся";
    const used = (exit.used_by || []).length;
    return `<tr data-exit-id="${esc(exit.id)}" class="${exit.enabled ? "" : "disabled"}">
      <td><b>${esc(exit.name)}</b>${exit.enabled ? "" : " <small>выключен</small>"}</td>
      <td>${esc(EXIT_PROTOCOL_NAMES[exit.protocol] || exit.protocol)}</td>
      <td>${esc(exit.address)}:${number(exit.port)}${exit.security?.kind && exit.security.kind !== "none" ? ` · ${esc(exit.security.kind)}` : ""}</td>
      <td class="${exit.last_test && !exit.last_test.ok ? "danger-text" : ""}">${test}</td>
      <td class="routing-rule-tools">
        <button type="button" class="ghost" data-routing-action="exit-test" data-exit-id="${esc(exit.id)}"${owner && target.router.available ? "" : " disabled"}>Проверить</button>
        <button type="button" class="ghost" data-routing-action="exit-edit" data-exit-id="${esc(exit.id)}"${owner ? "" : " disabled"}>Изменить</button>
        <button type="button" class="ghost" data-routing-action="${exit.enabled ? "exit-disable" : "exit-enable"}" data-exit-id="${esc(exit.id)}"${owner ? "" : " disabled"}>${exit.enabled ? "Выключить" : "Включить"}</button>
        <button type="button" class="ghost danger-text" data-routing-action="exit-delete" data-exit-id="${esc(exit.id)}"${owner && !used ? "" : " disabled"} title="${used ? "используется в политиках" : ""}">Удалить</button>
      </td>
    </tr>`;
  }).join("");
  const table = rows
    ? `<div class="import-table-wrap"><table class="import-table routing-exits-table"><thead><tr><th>Выход</th><th>Протокол</th><th>Сервер</th><th>Проверка</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
    : '<p class="form-hint">Своих выходов нет. Добавьте VPN или прокси — и его можно будет выбрать в «Куда».</p>';
  return `<details class="routing-custom-exits" id="routing-custom-exits"${(target.custom_exits || []).length ? " open" : ""}>
    <summary><b>Свои выходы</b> <small>${number((target.custom_exits || []).length)}</small><span class="spacer"></span><button type="button" class="secondary" data-routing-action="exit-add"${owner ? "" : " disabled"}>+ Выход</button></summary>
    ${table}
  </details>`;
}

// This node's own relay: the door other nodes' chains come in through.
function relayLine(context, target) {
  const relay = target.relay;
  if (!relay || !target.router) return "";
  const owner = context.state.me?.role === "owner";
  const status = relay.enabled ? (relay.pending ? "relay включается (ждём отчёт узла)" : `relay включён · порт ${number(relay.port)}`) : "relay выключен: другие узлы не могут выходить через этот";
  const button = relay.enabled ? "" : `<button class="secondary" data-routing-action="relay-enable"${owner && target.router.available ? "" : " disabled"}>Включить relay</button>`;
  return `<div class="routing-relay-line"><span class="status-pill ${relay.enabled ? "" : "muted"}"><i></i>${esc(status)}</span>${button}</div>`;
}

// Lanes (v0.7): the service's policy and one per client with their own lane.
function laneTabs(context, target) {
  const lane = currentLane(context);
  const serviceActive = lane === LANE_SERVICE;
  const tabs = [`<button class="${serviceActive ? "active" : ""}" role="tab" aria-selected="${serviceActive}" data-routing-action="lane" data-lane="svc">Сервис</button>`];
  for (const item of target.lanes || []) {
    const active = lane === item.lane;
    const label = item.grant ? esc(item.grant.runtime_username) + " · " + esc(item.grant.client_name) : esc(item.lane.replace(/^grant:/, "grant ").slice(0, 14));
    tabs.push(`<button class="${active ? "active" : ""}" role="tab" aria-selected="${active}" data-routing-action="lane" data-lane="${esc(item.lane)}">${label}</button>`);
  }
  const owner = context.state.me?.role === "owner";
  const add = owner && target.backend === "xray_router" ? '<button class="ghost" data-routing-action="lane-add">Добавить полосу для клиента…</button>' : "";
  return `<div class="node-tabs routing-lanes" role="tablist" id="routing-lanes">${tabs.join("")}${add}</div>`;
}

// «Куда пойдёт…»: the compiler walks the saved policy of the lane for one destination.
function explainPanel(context) {
  const state = ensureState(context);
  const result = state.explained;
  let answer = '<p class="form-hint">Введите домен или IP — и увидите, каким правилом и куда уйдёт трафик по сохранённой политике.</p>';
  if (result) {
    const rule = result.rule_id ? `правило ${esc(ruleLabel(state.policy, result.rule_id))}` : "по умолчанию";
    const where = esc(result.action === "block" ? "блок" : result.action === "direct" ? "напрямую" : exitLabel(currentTarget(context), result.exit) || "WARP");
    const unsureRules = (result.uncertain || []).map((id) => esc(ruleLabel(state.policy, id))).join(", ");
    const unsure = unsureRules ? ` <small>(geosite/geoip правила ${unsureRules} решает узел)</small>` : "";
    answer = `<p class="routing-explain-answer" id="routing-explain-answer">полоса ${esc(result.lane)} → ${rule} → <b>${where}</b>${unsure}</p>`;
  }
  return `<form class="routing-explain" id="routing-explain">
    <label>Куда пойдёт… <input name="host" placeholder="youtube.com или 203.0.113.9" maxlength="253" value="${esc(state.explainHost || "")}"></label>
    <label>порт <input name="port" type="number" min="1" max="65535" value="${esc(String(state.explainPort || 443))}"></label>
    <button type="submit" class="secondary"${state.policy ? "" : " disabled"}>Проверить</button>
    ${answer}
  </form>`;
}

function targetCard(context) {
  const target = currentTarget(context);
  if (!target) return '<div class="empty-state"><span>◇</span><h3>Нет узлов для маршрутизации</h3><p>Появятся этот сервер и связанные панели, когда будут на связи.</p></div>';
  const state = context.state.routing;
  const lane = currentLane(context);
  const laneKnown = lane === LANE_SERVICE ? Boolean(target.policy) : (target.lanes || []).some((item) => item.lane === lane);
  const policy = laneKnown ? state.policy : null;
  const [tone, statusText] = policyState(policy, state.loading);
  const reason = target.reason ? `<p class="form-hint routing-reason-line">${esc(reasonText(target.reason))}</p>` : "";
  const editable = context.state.me?.role === "owner" && !target.reason && Boolean(target.backend) && !state.loading;
  if (!target.backend) {
    return `<article class="panel-card routing-card">
      <div class="routing-head"><b>${esc(PROTOCOL_NAMES[target.protocol] || target.protocol)}</b><span class="status-pill muted"><i></i>${esc(reasonText(target.reason) || "недоступно")}</span></div>
      ${reason}
    </article>`;
  }
  const providers = Object.entries(target.providers || {}).map(([name, value]) => `${name}: ${value.reachable === false ? "не отвечает" : value.reachable ? "доступен" : "не проверялся"}`).join(", ") || "провайдеров нет";
  const backendName = BACKEND_NAMES[target.backend] || target.backend;
  const laneBadge = lane === LANE_SERVICE ? "" : ` · <span class="routing-lane-badge">полоса ${esc(lane.replace(/^grant:/, "").slice(0, 8))}</span>`;
  const laneItem = (target.lanes || []).find((item) => item.lane === lane);
  const owner = context.state.me?.role === "owner";
  const laneTools = lane === LANE_SERVICE ? "" : `<div class="routing-lane-tools"><small>${laneItem?.grant ? `доступ ${esc(laneItem.grant.runtime_username)} клиента ${esc(laneItem.grant.client_name)}: свой маршрут` : "полоса клиента"}</small><button class="secondary" data-routing-action="lane-remove"${owner && laneItem?.grant ? "" : " disabled"}>Вернуть в полосу сервиса</button></div>`;
  return `<article class="panel-card routing-card">
    <div class="routing-head">
      <b>${esc(PROTOCOL_NAMES[target.protocol] || target.protocol)} · <span class="routing-backend">${esc(backendName)}</span>${laneBadge}</b>
      <span class="status-pill ${tone}"><i></i>${esc(statusText)}</span>
    </div>
    <p class="form-hint">Возможности: ${esc((target.capabilities || []).join(", ") || "—")} · провайдеры — ${esc(providers)}${target.mode === "custom" ? " · на узле ручная настройка egress" : ""}</p>
    ${exitsLine(context, target)}
    ${customExitsPanel(context, target)}
    ${routerLine(context, target)}
    ${geodataLine(context, target)}
    ${relayLine(context, target)}
    ${reason}
    ${laneTabs(context, target)}
    ${laneTools}
    <div class="routing-layout">
      ${editor(context, target, state.draft, editable)}
      ${previewPanel(state.compiled, policy, state.dirty)}
    </div>
    ${explainPanel(context)}
    ${cardActions(context, policy, state.compiled, state.dirty, editable)}
    <div id="routing-history" hidden></div>
  </article>`;
}

function ensureState(context) {
  if (!context.state.routing) {
    context.state.routing = { policy: null, draft: emptyPolicy(), compiled: null, dirty: false, loading: false, previewTimer: null, previewSeq: 0,
      explained: null, explainHost: "", explainPort: 443, geodata: null, geodataError: null, codes: null };
  }
  return context.state.routing;
}

// Forget the policy of the previous card before anything is painted: a card that still
// showed the last visit's badge and buttons while its own policy was loading answered a
// click with silence (`operate` found no policy) — and, on another tab, with a lie.
function resetPolicy(context) {
  const state = ensureState(context);
  state.policy = null;
  state.compiled = null;
  state.dirty = false;
  state.draft = emptyPolicy();
  state.loading = true;
  state.explained = null;
  return state;
}

// The router's geodata (v0.8): shown on every card of a node that has a router; the codes
// feed the rule inputs' suggestions. One fetch per node, never per protocol tab.
async function loadGeodata(context, target) {
  const state = ensureState(context);
  if (!target?.router?.available) {
    state.geodata = null;
    state.geodataError = null;
    return;
  }
  if (state.geodata && state.geodata.node_id === target.node_id) return;
  try {
    const view = await context.api(`/api/routing/geodata?node=${encodeURIComponent(target.node_id)}`);
    state.geodata = { ...view, node_id: target.node_id };
    state.geodataError = null;
  } catch (error) {
    state.geodata = null;
    state.geodataError = error.message;
    return;
  }
  try {
    const codes = await context.api(`/api/routing/geodata/codes?node=${encodeURIComponent(target.node_id)}`);
    state.codes = codes.codes || null;
  } catch {
    state.codes = null;
  }
}

async function loadPolicy(context, target) {
  const state = resetPolicy(context);
  await loadGeodata(context, target);
  if (!target?.backend) {
    state.loading = false;
    return;
  }
  const lane = currentLane(context);
  const known = lane === LANE_SERVICE ? Boolean(target.policy) : (target.lanes || []).some((item) => item.lane === lane);
  if (known) {
    try {
      state.policy = await context.api(`${policyPath(target)}${laneQuery(context)}`);
      state.draft = draftFromPolicy(state.policy);
    } catch (error) {
      context.ui.toast(error.message, "error");
    }
  }
  state.loading = false;
  await previewNow(context, target);
}

function policyPath(target) {
  return `/api/routing/policies/${encodeURIComponent(target.node_id)}/${encodeURIComponent(target.protocol)}`;
}

async function previewNow(context, target) {
  const state = ensureState(context);
  const seq = ++state.previewSeq;
  const url = `${policyPath(target)}/preview${laneQuery(context)}`;
  try {
    // A rule still being typed (no selector yet) is not a question for the compiler: the
    // preview leaves it out; «Сохранить» still refuses it, as the server does.
    const filled = { ...state.draft, rules: state.draft.rules.filter((rule) => Object.values(rule.match).some((items) => items.length)) };
    const body = state.dirty || !state.policy ? JSON.stringify(policyBody(filled, target.backend)) : undefined;
    const compiled = await context.api(url, { method: "POST", body });
    if (seq !== state.previewSeq) return;
    state.compiled = compiled;
  } catch (error) {
    if (seq !== state.previewSeq) return;
    state.compiled = { status: "unsupported", reasons: [{ code: "preview_failed", message: error.message }], warnings: [], diff: [] };
  }
  rerender(context);
}

function schedulePreview(context) {
  const state = ensureState(context);
  const target = currentTarget(context);
  if (!target) return;
  window.clearTimeout(state.previewTimer);
  state.previewTimer = window.setTimeout(() => { void previewNow(context, target); }, PREVIEW_DEBOUNCE_MS);
}

function rerender(context) {
  if (context.state.view !== "routing") return;
  const focused = document.activeElement;
  const marker = focused?.dataset?.ruleField ? [focused.dataset.ruleField, focused.dataset.ruleIndex, focused.selectionStart] : null;
  context.ui.view.innerHTML = screen(context);
  if (marker) {
    const again = query(`[data-rule-field="${marker[0]}"][data-rule-index="${marker[1]}"]`, context.ui.view);
    if (again) {
      again.focus();
      if (typeof marker[2] === "number" && again.setSelectionRange) again.setSelectionRange(marker[2], marker[2]);
    }
  }
}

function screen(context) {
  return `<div class="security-note">Политика описывает, куда сервис выпускает трафик клиентов: напрямую, через WARP, через другой узел парка (цепь) или блокирует. Предпросмотр показывает, что именно применит backend узла — NaiveProxy (Caddy) умеет только «весь сервис» и блокировки, Mieru (mita) — ещё и выборочные правила, а сервис, подключённый к Xray-router узла, — geosite, geoip, порты, цепи и свои полосы для клиентов.</div>
    <div class="toolbar routing-toolbar">
      <label>Узел <select id="routing-node">${nodeOptions(context)}</select></label>
      <div class="node-tabs" role="tablist">${protocolTabs(context)}</div>
    </div>
    ${targetCard(context)}`;
}

export async function renderRouting(context, generation) {
  const [data, presets] = await Promise.all([context.api("/api/routing/targets"), context.state.routingPresets ? null : context.api("/api/routing/presets").catch(() => null)]);
  if (!isCurrent(context.state, generation, "routing")) return;
  context.state.routingTargets = data.items || [];
  if (presets) context.state.routingPresets = presets.items || [];
  const nodes = [...new Set(context.state.routingTargets.map((item) => item.node_id))];
  if (!nodes.includes(context.state.routingNode)) context.state.routingNode = nodes.includes("local") ? "local" : nodes[0] || null;
  const protocols = targetsFor(context).map((item) => item.protocol);
  if (!protocols.includes(context.state.routingProtocol)) context.state.routingProtocol = protocols.includes("naive") ? "naive" : protocols[0] || null;
  const lanes = (currentTarget(context)?.lanes || []).map((item) => item.lane);
  if (currentLane(context) !== LANE_SERVICE && !lanes.includes(currentLane(context))) context.state.routingLane = LANE_SERVICE;
  resetPolicy(context);
  context.ui.view.innerHTML = screen(context);
  await loadPolicy(context, currentTarget(context));
  if (!isCurrent(context.state, generation, "routing")) return;
  rerender(context);
}

function readDraft(context) {
  const state = ensureState(context);
  const form = query("#routing-form", context.ui.view);
  if (!form) return state.draft;
  state.draft.default_action = form.elements.default_action.value;
  state.draft.default_egress = form.elements.default_egress ? form.elements.default_egress.value : state.draft.default_egress;
  state.draft.fallback = form.elements.fallback.value;
  for (const input of queryAll("[data-rule-field=enabled]", form)) {
    const rule = state.draft.rules[Number(input.dataset.ruleIndex)];
    if (rule) rule.enabled = input.checked;
  }
  return state.draft;
}

function markDirty(context) {
  const state = ensureState(context);
  state.dirty = true;
  schedulePreview(context);
}

export function handleRoutingInput(context, element) {
  if (context.state.view !== "routing" || !element.closest?.("#routing-form")) return Boolean(element.closest?.("#routing-explain"));
  readDraft(context);
  markDirty(context);
  return true;
}

export function handleRoutingChange(context, element) {
  if (context.state.view !== "routing") return false;
  if (element.id === "geodata-source") {
    query("#geodata-custom", context.root).hidden = element.value !== "custom";
    return true;
  }
  if (element.id === "routing-node") {
    ensureState(context).geodata = null;
    context.state.routingNode = element.value;
    context.state.routingProtocol = null;
    context.state.routingLane = LANE_SERVICE;
    void context.navigate("routing");
    return true;
  }
  if (element.dataset.routingPreset) {
    togglePreset(context, element.dataset.routingPreset, element.checked);
    return true;
  }
  if (!element.closest?.("#routing-form")) return Boolean(element.closest?.("#routing-explain"));
  readDraft(context);
  markDirty(context);
  rerender(context);
  return true;
}

function togglePreset(context, presetId, on) {
  const state = ensureState(context);
  const item = (context.state.routingPresets || []).find((preset) => preset.id === presetId);
  if (!item) return;
  readDraft(context);
  state.draft.rules = state.draft.rules.filter((rule) => rule.preset !== presetId);
  if (on) {
    const rule = { ...newRule(), action: item.rule.action, egress: item.rule.egress || null, note: item.rule.note || "", preset: presetId,
      match: { ...newRule().match, ...Object.fromEntries(Object.entries(item.rule.match || {}).map(([key, values]) => [key, [...values]])) } };
    if (item.placement === "first") state.draft.rules.unshift(rule);
    else state.draft.rules.push(rule);
  }
  markDirty(context);
  rerender(context);
}

// -- the rule modal (v0.8) ---------------------------------------------------------------

function openRuleModal(context, index) {
  const { root } = context;
  const state = ensureState(context);
  const target = currentTarget(context);
  const adding = index === null;
  const rule = adding ? newRule() : state.draft.rules[index];
  if (!rule || !target) return;
  query("#rule-form", root).reset();
  query("#rule-error", root).textContent = "";
  query("#rule-index", root).value = adding ? "" : String(index);
  query("#rule-title", root).textContent = adding ? "Новое правило" : `Правило ${index + 1}`;
  query("#rule-action", root).value = rule.action;
  const select = query("#rule-egress", root);
  select.innerHTML = exitOptions(target).map((option) => `<option value="${esc(option.value)}"${option.value === (rule.egress || "warp") ? " selected" : ""}>${esc(option.label)}</option>`).join("");
  query("#rule-egress-row", root).hidden = rule.action !== "egress";
  for (const key of ["domains", "geosites", "cidrs", "geoips", "ports"]) query(`#rule-${key}`, root).value = (rule.match[key] || []).join(", ");
  for (const box of queryAll("[data-rule-protocol]", root)) box.checked = (rule.match.protocols || []).includes(box.value);
  query("#rule-note", root).value = rule.note || "";
  query("#rule-enabled", root).checked = rule.enabled !== false;
  context.ui.openModal("#rule-modal", "#rule-domains");
}

function saveRuleModal(context) {
  const { root } = context;
  const state = ensureState(context);
  const raw = query("#rule-index", root).value;
  const index = raw === "" ? null : Number(raw);
  const existing = index === null ? newRule() : state.draft.rules[index];
  if (!existing) return;
  const match = {
    domains: splitList(query("#rule-domains", root).value), geosites: splitList(query("#rule-geosites", root).value),
    cidrs: splitList(query("#rule-cidrs", root).value), geoips: splitList(query("#rule-geoips", root).value),
    ports: splitList(query("#rule-ports", root).value),
    protocols: queryAll("[data-rule-protocol]", root).filter((box) => box.checked).map((box) => box.value),
  };
  if (!Object.values(match).some((items) => items.length)) {
    query("#rule-error", root).textContent = "Правилу нужен хотя бы один селектор: домен, geosite, IP, geoip, порт или протокол";
    return;
  }
  const action = query("#rule-action", root).value;
  const rule = { ...existing, match, action, egress: action === "egress" ? query("#rule-egress", root).value || "warp" : null,
    note: query("#rule-note", root).value.trim(), enabled: query("#rule-enabled", root).checked };
  // An edited preset rule is the operator's rule now: the toggle must not claim it.
  if (existing.preset && JSON.stringify([existing.match, existing.action, existing.egress]) !== JSON.stringify([match, action, rule.egress])) rule.preset = null;
  readDraft(context);
  if (index === null) state.draft.rules.push(rule);
  else state.draft.rules[index] = rule;
  query("#rule-modal", root).close();
  markDirty(context);
  rerender(context);
}

// -- the exit modal (v0.8) ---------------------------------------------------------------

const EXIT_FIELDS = {
  vless: ["uuid", "flow", "network", "path", "host", "security", "sni", "fp", "pbk", "sid", "insecure"],
  trojan: ["password", "network", "path", "host", "security", "sni", "fp", "pbk", "sid", "insecure"],
  shadowsocks: ["password", "method"],
  socks: ["username", "password"],
  http: ["username", "password", "security", "sni", "fp", "insecure"],
};

function syncExitFields(context) {
  const { root } = context;
  const protocol = query("#exit-protocol", root).value;
  const shown = new Set(EXIT_FIELDS[protocol] || []);
  const security = query("#exit-security", root).value;
  const network = query("#exit-network", root).value;
  for (const label of queryAll("[data-exit-field]", root)) {
    const field = label.dataset.exitField;
    let visible = shown.has(field);
    if (["sni", "fp", "insecure"].includes(field) && security === "none") visible = false;
    if (["pbk", "sid"].includes(field) && security !== "reality") visible = false;
    if (field === "insecure" && security !== "tls") visible = false;
    if (field === "path" && network === "tcp") visible = false;
    if (field === "host" && !["ws", "xhttp"].includes(network)) visible = false;
    label.hidden = !visible;
  }
  const editing = Boolean(query("#exit-id", root).value);
  query("#exit-password-hint", root).textContent = editing ? "Пусто — оставить прежний" : "";
  query("#exit-uuid-hint", root).textContent = editing ? "Пусто — оставить прежний" : "";
}

function openExitModal(context, exit = null) {
  const { root } = context;
  query("#exit-form", root).reset();
  query("#exit-error", root).textContent = "";
  query("#exit-id", root).value = exit?.id || "";
  query("#exit-title", root).textContent = exit ? "Выход «" + exit.name + "»" : "Новый выход";
  setExitTab(context, "form");
  if (exit) {
    query("#exit-name", root).value = exit.name;
    query("#exit-protocol", root).value = exit.protocol;
    query("#exit-address", root).value = exit.address;
    query("#exit-port", root).value = String(exit.port);
    query("#exit-method", root).value = exit.method || "aes-256-gcm";
    query("#exit-flow", root).value = exit.flow || "";
    query("#exit-network", root).value = exit.transport?.network || "tcp";
    query("#exit-path", root).value = exit.transport?.path || exit.transport?.service_name || "";
    query("#exit-host", root).value = exit.transport?.host || "";
    query("#exit-security", root).value = exit.security?.kind || "none";
    query("#exit-sni", root).value = exit.security?.server_name || "";
    query("#exit-fp", root).value = exit.security?.fingerprint || "chrome";
    query("#exit-pbk", root).value = exit.security?.public_key || "";
    query("#exit-sid", root).value = exit.security?.short_id || "";
    query("#exit-insecure", root).checked = exit.security?.insecure === true;
  }
  query("#exit-protocol", root).disabled = Boolean(exit);
  syncExitFields(context);
  context.ui.openModal("#exit-modal", exit ? "#exit-name" : "#exit-name");
}

function setExitTab(context, tab) {
  const { root } = context;
  for (const button of queryAll("[data-exit-tab]", root)) button.classList.toggle("active", button.dataset.exitTab === tab);
  query("#exit-form-tab", root).hidden = tab !== "form";
  query("#exit-link-tab", root).hidden = tab !== "link";
}

function exitBody(context) {
  const { root } = context;
  const protocol = query("#exit-protocol", root).value;
  const network = query("#exit-network", root).value;
  const securityKind = query("#exit-security", root).value;
  const shown = new Set(EXIT_FIELDS[protocol] || []);
  const body = { name: query("#exit-name", root).value.trim(), protocol, address: query("#exit-address", root).value.trim(),
    port: Number(query("#exit-port", root).value) || 0, transport: { network: shown.has("network") ? network : "tcp" }, security: { kind: shown.has("security") ? securityKind : "none" } };
  if (shown.has("network")) {
    const path = query("#exit-path", root).value.trim();
    if (network === "grpc" && path) body.transport.service_name = path;
    else if (network !== "tcp" && path) body.transport.path = path;
    const host = query("#exit-host", root).value.trim();
    if (["ws", "xhttp"].includes(network) && host) body.transport.host = host;
  }
  if (body.security.kind !== "none") {
    const sni = query("#exit-sni", root).value.trim();
    if (sni) body.security.server_name = sni;
    body.security.fingerprint = query("#exit-fp", root).value;
    if (body.security.kind === "reality") {
      body.security.public_key = query("#exit-pbk", root).value.trim();
      body.security.short_id = query("#exit-sid", root).value.trim();
    }
    if (body.security.kind === "tls" && query("#exit-insecure", root).checked) body.security.insecure = true;
  }
  if (protocol === "shadowsocks") body.method = query("#exit-method", root).value;
  if (protocol === "vless") body.flow = query("#exit-flow", root).value;
  const uuid = query("#exit-uuid", root).value.trim();
  const username = query("#exit-username", root).value.trim();
  const password = query("#exit-password", root).value;
  if (protocol === "vless" && uuid) body.credential = { uuid };
  else if (["trojan", "shadowsocks"].includes(protocol) && password) body.credential = { password };
  else if (["socks", "http"].includes(protocol) && (username || password)) body.credential = { username, password };
  return body;
}

async function saveExit(context, button) {
  const { root } = context;
  const target = currentTarget(context);
  const error = query("#exit-error", root);
  error.textContent = "";
  const exitId = query("#exit-id", root).value;
  const linkTab = !query("#exit-link-tab", root).hidden;
  context.ui.setBusy(button, true, "Сохраняем…");
  try {
    if (linkTab && !exitId) {
      const link = query("#exit-link", root).value.trim();
      if (!link) throw new Error("Вставьте ссылку");
      const name = query("#exit-name", root).value.trim();
      await context.api("/api/routing/exits/import", { method: "POST", body: JSON.stringify({ node_id: target.node_id, link, ...(name ? { name } : {}) }) });
    } else {
      const body = exitBody(context);
      if (!body.name || !body.address || !body.port) throw new Error("Заполните имя, адрес и порт");
      if (exitId) await context.api(`/api/routing/exits/${encodeURIComponent(exitId)}`, { method: "PUT", body: JSON.stringify(body) });
      else await context.api("/api/routing/exits", { method: "POST", body: JSON.stringify({ ...body, node_id: target.node_id }) });
    }
    query("#exit-link", root).value = "";
    query("#exit-modal", root).close();
    context.ui.toast(exitId ? "Выход сохранён" : "Выход добавлен — проверьте его кнопкой «Проверить»");
    await context.navigate("routing");
  } catch (exception) {
    error.textContent = exception.message;
  } finally {
    context.ui.setBusy(button, false);
  }
}

async function exitAction(context, action, button) {
  const target = currentTarget(context);
  const exitId = button.dataset.exitId;
  const exit = (target?.custom_exits || []).find((item) => item.id === exitId);
  if (!exit) return;
  if (action === "exit-edit") {
    openExitModal(context, exit);
    return;
  }
  const verb = action.slice("exit-".length);
  if (verb === "delete" && !(await context.ui.confirmed("Удалить выход?", "«" + exit.name + "» исчезнет из списка выходов узла; политики его не используют.", "Удалить"))) return;
  context.ui.setBusy(button, true, verb === "test" ? "Проверяем…" : "…");
  try {
    const result = await context.api(`/api/routing/exits/${encodeURIComponent(exitId)}/${verb}`, { method: "POST" });
    if (verb === "test") context.ui.toast(result.ok ? "Выход отвечает: " + (result.ip || "?") + " " + (result.colo || "") + " за " + number(result.latency_ms || 0) + " мс" : "Выход не отвечает: " + (reasonText(result.code) || result.error || ""), result.ok ? "" : "error");
    else context.ui.toast({ enable: "Выход включён", disable: "Выход выключен: политики с ним стали черновиками", delete: "Выход удалён" }[verb]);
    await context.navigate("routing");
  } catch (error) {
    context.ui.toast(error.message, "error");
    context.ui.setBusy(button, false);
  }
}

async function save(context) {
  const target = currentTarget(context);
  const state = ensureState(context);
  const button = query("#routing-save", context.ui.view);
  context.ui.setBusy(button, true, "Сохраняем…");
  try {
    readDraft(context);
    const body = { ...policyBody(state.draft, target.backend), expected_revision: state.policy?.revision ?? null };
    state.policy = await context.api(`${policyPath(target)}${laneQuery(context)}`, { method: "PUT", body: JSON.stringify(body) });
    state.draft = draftFromPolicy(state.policy);
    state.dirty = false;
    context.ui.toast(`Политика сохранена (rev ${number(state.policy.revision)})`);
    await context.navigate("routing");
  } catch (error) {
    context.ui.toast(error.message, "error");
    context.ui.setBusy(button, false);
  }
}

export function handleRoutingSubmit(context, form) {
  if (context.state.view !== "routing") return false;
  if (form.id === "routing-explain") {
    void explain(context, form);
    return true;
  }
  if (form.id !== "routing-form") return false;
  void save(context);
  return true;
}

async function explain(context, form) {
  const target = currentTarget(context);
  const state = ensureState(context);
  if (!target) return;
  state.explainHost = form.elements.host.value.trim();
  state.explainPort = Number(form.elements.port.value) || 443;
  if (!state.explainHost) return;
  try {
    state.explained = await context.api(`${policyPath(target)}/explain${laneQuery(context)}`, { method: "POST", body: JSON.stringify({ host: state.explainHost, port: state.explainPort }) });
  } catch (error) {
    state.explained = null;
    context.ui.toast(error.message, "error");
  }
  rerender(context);
}

// A client's own lane (v0.7): the grant's traffic gets its own policy on this node.
async function laneAdd(context, button) {
  const target = currentTarget(context);
  if (!target) return;
  const data = await context.api("/api/clients");
  const laned = new Set((target.lanes || []).map((item) => item.grant?.id).filter(Boolean));
  const candidates = (data.items || []).flatMap((entry) => entry.grants
    .filter((grant) => grant.protocol === target.protocol && grant.node_id === target.node_id && grant.desired_state !== "deleted" && !laned.has(grant.id))
    .map((grant) => ({ id: grant.id, label: grant.runtime_username + " · " + entry.client.display_name })));
  if (!candidates.length) {
    context.ui.toast("У этого сервиса на узле нет доступов без своей полосы", "error");
    return;
  }
  const protocolName = PROTOCOL_NAMES[target.protocol] || target.protocol;
  const mieruNote = target.protocol === "mieru" ? "; ссылка Mieru изменится (порт слота), подписка обновится сама" : "";
  const chosen = await context.ui.choose("Полоса для клиента", "Доступ " + protocolName + " получит свой маршрут на этом узле" + mieruNote + ".", candidates, "Создать полосу");
  if (!chosen) return;
  context.ui.setBusy(button, true, "…");
  try {
    const result = await context.api(`/api/routing/lanes/${encodeURIComponent(chosen)}`, { method: "POST", body: JSON.stringify({ mode: "own" }) });
    context.state.routingLane = result.lane;
    context.ui.toast(result.pending ? "Отправлено узлу: полоса появится после heartbeat" : "Полоса создана");
    await context.navigate("routing");
  } catch (error) {
    context.ui.toast(error.message, "error");
    context.ui.setBusy(button, false);
  }
}

async function laneRemove(context, button) {
  const target = currentTarget(context);
  const item = (target?.lanes || []).find((lane) => lane.lane === currentLane(context));
  if (!item?.grant) return;
  const mieruNote = target.protocol === "mieru" ? "; ссылка Mieru изменится (основной порт)" : "";
  const text = "Доступ " + item.grant.runtime_username + " вернётся к маршруту сервиса, политика полосы будет удалена" + mieruNote + ".";
  if (!(await context.ui.confirmed("Вернуть в полосу сервиса?", text, "Вернуть"))) return;
  context.ui.setBusy(button, true, "…");
  try {
    await context.api(`/api/routing/lanes/${encodeURIComponent(item.grant.id)}`, { method: "POST", body: JSON.stringify({ mode: "service" }) });
    context.state.routingLane = LANE_SERVICE;
    context.ui.toast("Доступ вернулся в полосу сервиса");
    await context.navigate("routing");
  } catch (error) {
    context.ui.toast(error.message, "error");
    context.ui.setBusy(button, false);
  }
}

async function relayEnable(context, button) {
  const target = currentTarget(context);
  if (!target) return;
  if (!(await context.ui.confirmed("Включить relay узла?", "Xray-router откроет relay-порт (vless+reality за TLS панели): другие узлы парка смогут выходить в интернет через этот узел по цепям — только со своими учётками.", "Включить"))) return;
  context.ui.setBusy(button, true, "…");
  try {
    const result = await context.api(`/api/routing/relay/${encodeURIComponent(target.node_id)}/enable`, { method: "POST", body: JSON.stringify({}) });
    context.ui.toast(result.pending ? "Отправлено узлу: relay включится после heartbeat" : `Relay включён на порту ${number(result.port)}`);
    await context.navigate("routing");
  } catch (error) {
    context.ui.toast(error.message, "error");
    context.ui.setBusy(button, false);
  }
}

async function operate(context, action, button) {
  const target = currentTarget(context);
  const state = ensureState(context);
  if (!target || !state.policy) return;
  const titles = { apply: ["Применить политику?", target.backend === "xray_router" ? "Xray-router перезапустится с новым поколением: сессии подключённых сервисов прервутся на мгновение. Откат доступен из истории." : "Узел получит новую конфигурацию egress. Откат доступен из истории.", "Применить"],
    rollback: ["Откатить к предыдущей записи?", "Узел вернётся к предыдущей конфигурации egress менеджера.", "Откатить"],
    delete: ["Удалить политику?", "Узел при этом не трогается: удалить можно только политику, уже сведённую к «напрямую без правил».", "Удалить"] };
  const [title, text, label] = titles[action];
  if (!(await context.ui.confirmed(title, text, label))) return;
  context.ui.setBusy(button, true, "…");
  const base = policyPath(target);
  const suffix = laneQuery(context);
  try {
    if (action === "delete") {
      await context.api(`${base}${suffix}`, { method: "DELETE" });
      context.ui.toast("Политика удалена");
    } else {
      const result = await context.api(`${base}/${action}${suffix}`, { method: "POST", body: JSON.stringify({ expected_revision: state.policy.revision }) });
      const policy = result.policy;
      context.ui.toast(policy.state === "applying" ? "Отправлено узлу: результат появится после heartbeat" : action === "apply" ? `Применено (rev ${number(policy.applied_revision)})` : "Откачено");
    }
    await context.navigate("routing");
  } catch (error) {
    context.ui.toast(error.message, "error");
    context.ui.setBusy(button, false);
  }
}

// Hand the service to the router, or take it back: confirmed, then one POST; the policy
// moves to the other backend as a draft and the screen reloads with the node's word.
async function attachment(context, action, button) {
  const target = currentTarget(context);
  if (!target) return;
  const name = PROTOCOL_NAMES[target.protocol] || target.protocol;
  const [title, text, label] = action === "attach"
    ? [`Подключить ${name} к Xray-router?`, "Весь трафик сервиса пойдёт через роутер узла; политика будет применяться роутером (geosite, geoip, порты, блокировки рядом с WARP); сессии сервиса прервутся.", "Подключить"]
    : [`Отключить ${name} от Xray-router?`, "Сервис вернётся к своему backend'у и пойдёт напрямую; политика останется черновиком для него; сессии сервиса прервутся.", "Отключить"];
  if (!(await context.ui.confirmed(title, text, label))) return;
  context.ui.setBusy(button, true, "…");
  try {
    const path = action === "attach" ? "/attach" : "/detach";
    const result = await context.api(`/api/routing/targets/${encodeURIComponent(target.node_id)}/${encodeURIComponent(target.protocol)}${path}`, { method: "POST" });
    const state = result.target?.policy?.state;
    context.ui.toast(state === "applying" ? "Отправлено узлу: результат появится после heartbeat" : action === "attach" ? "Сервис подключён к Xray-router" : "Сервис отключён от Xray-router");
    await context.navigate("routing");
  } catch (error) {
    context.ui.toast(error.message, "error");
    context.ui.setBusy(button, false);
  }
}

async function showHistory(context, button) {
  const target = currentTarget(context);
  const box = query("#routing-history", context.ui.view);
  if (!target || !box) return;
  if (!box.hidden) {
    box.hidden = true;
    return;
  }
  context.ui.setBusy(button, true, "…");
  try {
    const data = await context.api(`${policyPath(target)}/history${laneQuery(context)}`);
    box.innerHTML = historyTable(data.items);
    box.hidden = false;
  } catch (error) {
    context.ui.toast(error.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

function moveRule(context, index, delta) {
  const state = ensureState(context);
  const next = index + delta;
  if (next < 0 || next >= state.draft.rules.length) return;
  const [rule] = state.draft.rules.splice(index, 1);
  state.draft.rules.splice(next, 0, rule);
}

export function handleRoutingClick(context, button) {
  if (context.state.view !== "routing") return false;
  const action = button.dataset.routingAction;
  if (!action) return false;
  const state = ensureState(context);
  if (action === "protocol") {
    context.state.routingProtocol = button.dataset.protocol;
    context.state.routingLane = LANE_SERVICE;
    void context.navigate("routing");
    return true;
  }
  if (action === "lane") {
    context.state.routingLane = button.dataset.lane || LANE_SERVICE;
    void context.navigate("routing");
    return true;
  }
  if (action === "lane-add") {
    void laneAdd(context, button);
    return true;
  }
  if (action === "lane-remove") {
    void laneRemove(context, button);
    return true;
  }
  if (action === "relay-enable") {
    void relayEnable(context, button);
    return true;
  }
  if (action === "geodata-update") {
    void geodataUpdate(context, button);
    return true;
  }
  if (action === "rule-edit") {
    readDraft(context);
    openRuleModal(context, Number(button.dataset.ruleIndex));
    return true;
  }
  if (action === "exit-add") {
    openExitModal(context);
    return true;
  }
  if (action.startsWith("exit-")) {
    void exitAction(context, action, button);
    return true;
  }
  if (action === "geodata-settings") {
    openGeodataModal(context);
    return true;
  }
  if (action === "apply" || action === "rollback" || action === "delete") {
    void operate(context, action, button);
    return true;
  }
  if (action === "attach" || action === "detach") {
    void attachment(context, action, button);
    return true;
  }
  if (action === "history") {
    void showHistory(context, button);
    return true;
  }
  readDraft(context);
  const index = Number(button.dataset.ruleIndex);
  if (action === "rule-add") {
    openRuleModal(context, null);
    return true;
  }
  if (action === "rule-remove") state.draft.rules.splice(index, 1);
  else if (action === "rule-up") moveRule(context, index, -1);
  else if (action === "rule-down") moveRule(context, index, 1);
  else if (action === "reset") state.draft = { ...emptyPolicy(), revision: state.draft.revision };
  else return false;
  markDirty(context);
  rerender(context);
  return true;
}

// HTML5 drag between rule rows: the dragged row lands before the row it is dropped on.
export function bindRouting(context) {
  const view = context.ui.view;
  query("#geodata-save", context.root)?.addEventListener("click", ({ currentTarget: button }) => { void saveGeodata(context, button); });
  query("#rule-save", context.root)?.addEventListener("click", () => saveRuleModal(context));
  query("#rule-action", context.root)?.addEventListener("change", ({ currentTarget: select }) => {
    query("#rule-egress-row", context.root).hidden = select.value !== "egress";
  });
  query("#rule-form", context.root)?.addEventListener("submit", (event) => { event.preventDefault(); saveRuleModal(context); });
  query("#exit-save", context.root)?.addEventListener("click", ({ currentTarget: button }) => { void saveExit(context, button); });
  query("#exit-form", context.root)?.addEventListener("submit", (event) => { event.preventDefault(); void saveExit(context, query("#exit-save", context.root)); });
  for (const id of ["exit-protocol", "exit-security", "exit-network"]) {
    query(`#${id}`, context.root)?.addEventListener("change", () => syncExitFields(context));
  }
  for (const button of queryAll("[data-exit-tab]", context.root)) {
    button.addEventListener("click", () => setExitTab(context, button.dataset.exitTab));
  }
  query("#geodata-source", context.root)?.addEventListener("change", ({ currentTarget: select }) => {
    query("#geodata-custom", context.root).hidden = select.value !== "custom";
  });
  let dragged = null;
  view.addEventListener("dragstart", (event) => {
    const row = event.target.closest?.(".routing-rule");
    if (!row || context.state.view !== "routing") return;
    dragged = Number(row.dataset.ruleIndex);
    event.dataTransfer.effectAllowed = "move";
  });
  view.addEventListener("dragover", (event) => {
    if (dragged !== null && event.target.closest?.(".routing-rule")) event.preventDefault();
  });
  view.addEventListener("drop", (event) => {
    const row = event.target.closest?.(".routing-rule");
    if (dragged === null || !row) return;
    event.preventDefault();
    const target = Number(row.dataset.ruleIndex);
    readDraft(context);
    moveRule(context, dragged, target - dragged);
    dragged = null;
    markDirty(context);
    rerender(context);
  });
  view.addEventListener("dragend", () => { dragged = null; });
}
