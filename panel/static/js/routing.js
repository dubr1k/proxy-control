// «Маршрутизация» (spec §8.4): one egress policy per node × protocol, edited in a neutral
// form and previewed as what the node's backend would actually enforce. The preview is the
// compiler's honest answer: an unsupported rule is named, not silently dropped, and
// «Применить» is enabled only for a saved, supported policy.
import { esc, number, query, queryAll } from "./common.js";
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
};
const BACKEND_NAMES = { naive_native: "Caddy", mieru_native: "mita", xray_router: "Xray-router" };
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
  return { id: null, enabled: true, action: "block", egress: null, match: { domains: [], cidrs: [], ports: [], geosites: [], geoips: [] }, note: "" };
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
      id: rule.id, enabled: rule.enabled, action: rule.action, egress: rule.egress, note: rule.note || "",
      match: { domains: [...rule.match.domains], cidrs: [...rule.match.cidrs], ports: [...rule.match.ports],
        geosites: [...(rule.match.geosites || [])], geoips: [...(rule.match.geoips || [])] },
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
        geosites: rule.match.geosites, geoips: rule.match.geoips },
      note: rule.note,
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

function ruleRow(target, rule, index, total, editable) {
  const match = rule.match;
  const selective = rule.action !== "block";
  return `<li class="routing-rule${rule.enabled ? "" : " disabled"}" data-rule-index="${index}" draggable="${editable}">
    <div class="routing-rule-head">
      <span class="routing-rule-order">${index + 1}</span>
      <label class="routing-rule-toggle"><input type="checkbox" data-rule-field="enabled" data-rule-index="${index}"${rule.enabled ? " checked" : ""}${editable ? "" : " disabled"}> включено</label>
      <select data-rule-field="action" data-rule-index="${index}"${editable ? "" : " disabled"}>
        <option value="block"${rule.action === "block" ? " selected" : ""}>Блокировать</option>
        <option value="direct"${rule.action === "direct" ? " selected" : ""}>Напрямую</option>
        <option value="egress"${rule.action === "egress" ? " selected" : ""}>Через выход</option>
      </select>
      ${rule.action === "egress" ? `<label class="routing-rule-exit">Куда ${exitSelect(target, "", rule.egress, index, editable)}</label>` : ""}
      <span class="routing-rule-tools">
        <button class="ghost" data-routing-action="rule-up" data-rule-index="${index}" title="Выше"${index === 0 || !editable ? " disabled" : ""}>↑</button>
        <button class="ghost" data-routing-action="rule-down" data-rule-index="${index}" title="Ниже"${index === total - 1 || !editable ? " disabled" : ""}>↓</button>
        <button class="ghost danger-text" data-routing-action="rule-remove" data-rule-index="${index}"${editable ? "" : " disabled"}>Удалить</button>
      </span>
    </div>
    <div class="routing-rule-fields">
      <label>Домены <small>example.com, *.cdn.example</small><input data-rule-field="domains" data-rule-index="${index}" value="${esc(match.domains.join(", "))}" placeholder="example.com, *.example.com"${editable ? "" : " disabled"}></label>
      <label>CIDR <small>1.2.3.0/24</small><input data-rule-field="cidrs" data-rule-index="${index}" value="${esc(match.cidrs.join(", "))}" placeholder="203.0.113.0/24"${editable ? "" : " disabled"}></label>
      <label>geosite <small>только Xray-router</small><input data-rule-field="geosites" data-rule-index="${index}" value="${esc((match.geosites || []).join(", "))}" placeholder="category-ads-all, cn"${editable ? "" : " disabled"}></label>
      <label>geoip <small>только Xray-router</small><input data-rule-field="geoips" data-rule-index="${index}" value="${esc((match.geoips || []).join(", "))}" placeholder="cn, cloudflare"${editable ? "" : " disabled"}></label>
      <label>Порты <small>только Xray-router</small><input data-rule-field="ports" data-rule-index="${index}" value="${esc(match.ports.join(", "))}" placeholder="443, 1000-2000"${editable ? "" : " disabled"}></label>
      <label>Заметка<input data-rule-field="note" data-rule-index="${index}" value="${esc(rule.note)}" maxlength="120"${editable ? "" : " disabled"}></label>
    </div>
    ${selective ? '<p class="form-hint">Выборочное правило: NaiveProxy его не умеет (один upstream на сервис), Mieru и Xray-router — умеют.</p>' : ""}
  </li>`;
}

function editor(target, draft, editable) {
  const rules = draft.rules.map((rule, index) => ruleRow(target, rule, index, draft.rules.length, editable)).join("");
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
    <ol class="routing-rules" id="routing-rules">${rules || '<li class="routing-empty">Правил нет: весь сервис идёт по умолчанию.</li>'}</ol>
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
    ${routerLine(context, target)}
    ${relayLine(context, target)}
    ${reason}
    ${laneTabs(context, target)}
    ${laneTools}
    <div class="routing-layout">
      ${editor(target, state.draft, editable)}
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
      explained: null, explainHost: "", explainPort: 443 };
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

async function loadPolicy(context, target) {
  const state = resetPolicy(context);
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
    const body = state.dirty || !state.policy ? JSON.stringify(policyBody(state.draft, target.backend)) : undefined;
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
  const data = await context.api("/api/routing/targets");
  if (!isCurrent(context.state, generation, "routing")) return;
  context.state.routingTargets = data.items || [];
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
  for (const input of queryAll("[data-rule-field]", form)) {
    const rule = state.draft.rules[Number(input.dataset.ruleIndex)];
    if (!rule) continue;
    const field = input.dataset.ruleField;
    if (field === "enabled") rule.enabled = input.checked;
    else if (field === "action") rule.action = input.value;
    else if (field === "egress") rule.egress = input.value;
    else if (field === "note") rule.note = input.value;
    else rule.match[field] = splitList(input.value);
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
  if (element.id === "routing-node") {
    context.state.routingNode = element.value;
    context.state.routingProtocol = null;
    context.state.routingLane = LANE_SERVICE;
    void context.navigate("routing");
    return true;
  }
  if (!element.closest?.("#routing-form")) return Boolean(element.closest?.("#routing-explain"));
  readDraft(context);
  markDirty(context);
  rerender(context);
  return true;
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
  if (action === "rule-add") state.draft.rules.push(newRule());
  else if (action === "rule-remove") state.draft.rules.splice(index, 1);
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
