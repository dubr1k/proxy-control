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
};
const WARNING_TEXT = {
  provider_unreachable: "WARP на узле не отвечает: политика применится напрямую (fallback)",
  adopts_unmanaged_upstream: "на узле есть upstream, заданный вручную — он будет заменён и сохранён для отката",
  adopts_unmanaged_egress: "на узле есть секция egress, заданная вручную — она будет заменена и сохранена для отката",
  policy_empty: "политика пустая: узел пойдёт напрямую без правил",
};
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
  return { id: null, enabled: true, action: "block", egress: null, match: { domains: [], cidrs: [], ports: [] }, note: "" };
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
      match: { domains: [...rule.match.domains], cidrs: [...rule.match.cidrs], ports: [...rule.match.ports] },
    })),
  };
}

// The body `PUT` and `preview` take: the draft without the UI's own bookkeeping.
export function policyBody(draft) {
  return {
    default_action: draft.default_action,
    default_egress: draft.default_action === "egress" ? "warp" : null,
    fallback: draft.fallback,
    rules: draft.rules.map((rule) => ({
      ...(rule.id ? { id: rule.id } : {}),
      enabled: rule.enabled,
      action: rule.action,
      egress: rule.action === "egress" ? "warp" : null,
      match: { domains: rule.match.domains, cidrs: rule.match.cidrs, ports: rule.match.ports },
      note: rule.note,
    })),
  };
}

function policyState(policy) {
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
      return `${item.protocol} → ${target}${blocks}${extra}${note}`;
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

function ruleRow(rule, index, total, editable) {
  const match = rule.match;
  const selective = rule.action !== "block";
  return `<li class="routing-rule${rule.enabled ? "" : " disabled"}" data-rule-index="${index}" draggable="${editable}">
    <div class="routing-rule-head">
      <span class="routing-rule-order">${index + 1}</span>
      <label class="routing-rule-toggle"><input type="checkbox" data-rule-field="enabled" data-rule-index="${index}"${rule.enabled ? " checked" : ""}${editable ? "" : " disabled"}> включено</label>
      <select data-rule-field="action" data-rule-index="${index}"${editable ? "" : " disabled"}>
        <option value="block"${rule.action === "block" ? " selected" : ""}>Блокировать</option>
        <option value="direct"${rule.action === "direct" ? " selected" : ""}>Напрямую</option>
        <option value="egress"${rule.action === "egress" ? " selected" : ""}>Через WARP</option>
      </select>
      <span class="routing-rule-tools">
        <button class="ghost" data-routing-action="rule-up" data-rule-index="${index}" title="Выше"${index === 0 || !editable ? " disabled" : ""}>↑</button>
        <button class="ghost" data-routing-action="rule-down" data-rule-index="${index}" title="Ниже"${index === total - 1 || !editable ? " disabled" : ""}>↓</button>
        <button class="ghost danger-text" data-routing-action="rule-remove" data-rule-index="${index}"${editable ? "" : " disabled"}>Удалить</button>
      </span>
    </div>
    <div class="routing-rule-fields">
      <label>Домены <small>example.com, *.cdn.example</small><input data-rule-field="domains" data-rule-index="${index}" value="${esc(match.domains.join(", "))}" placeholder="example.com, *.example.com"${editable ? "" : " disabled"}></label>
      <label>CIDR <small>1.2.3.0/24</small><input data-rule-field="cidrs" data-rule-index="${index}" value="${esc(match.cidrs.join(", "))}" placeholder="203.0.113.0/24"${editable ? "" : " disabled"}></label>
      <label>Порты <small>не применяются в v0.4</small><input data-rule-field="ports" data-rule-index="${index}" value="${esc(match.ports.join(", "))}" placeholder="443, 1000-2000"${editable ? "" : " disabled"}></label>
      <label>Заметка<input data-rule-field="note" data-rule-index="${index}" value="${esc(rule.note)}" maxlength="120"${editable ? "" : " disabled"}></label>
    </div>
    ${selective ? '<p class="form-hint">Выборочное правило: NaiveProxy его не умеет (один upstream на сервис), Mieru — умеет.</p>' : ""}
  </li>`;
}

function editor(target, draft, editable) {
  const rules = draft.rules.map((rule, index) => ruleRow(rule, index, draft.rules.length, editable)).join("");
  return `<form class="routing-editor" id="routing-form" data-node-id="${esc(target.node_id)}" data-protocol="${esc(target.protocol)}">
    <div class="routing-defaults">
      <label>По умолчанию
        <select name="default_action"${editable ? "" : " disabled"}>
          <option value="direct"${draft.default_action === "direct" ? " selected" : ""}>Напрямую</option>
          <option value="egress"${draft.default_action === "egress" ? " selected" : ""}>Через WARP</option>
        </select></label>
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
    <p class="form-hint">${compiled.restart_required ? "потребуется перезапуск сервиса на узле" : "перезапуск не требуется"} · ${rollback}</p>
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

function targetCard(context) {
  const target = currentTarget(context);
  if (!target) return '<div class="empty-state"><span>◇</span><h3>Нет узлов для маршрутизации</h3><p>Появятся этот сервер и связанные панели, когда будут на связи.</p></div>';
  const state = context.state.routing;
  const policy = target.policy ? state.policy : null;
  const [tone, statusText] = policyState(policy);
  const reason = target.reason ? `<p class="form-hint routing-reason-line">${esc(reasonText(target.reason))}</p>` : "";
  const editable = context.state.me?.role === "owner" && !target.reason && Boolean(target.backend);
  if (!target.backend) {
    return `<article class="panel-card routing-card">
      <div class="routing-head"><b>${esc(PROTOCOL_NAMES[target.protocol] || target.protocol)}</b><span class="status-pill muted"><i></i>${esc(reasonText(target.reason) || "недоступно")}</span></div>
      ${reason}
    </article>`;
  }
  const providers = Object.entries(target.providers || {}).map(([name, value]) => `${name}: ${value.reachable === false ? "не отвечает" : value.reachable ? "доступен" : "не проверялся"}`).join(", ") || "провайдеров нет";
  return `<article class="panel-card routing-card">
    <div class="routing-head">
      <b>${esc(PROTOCOL_NAMES[target.protocol] || target.protocol)} · ${esc(target.backend)}</b>
      <span class="status-pill ${tone}"><i></i>${esc(statusText)}</span>
    </div>
    <p class="form-hint">Возможности: ${esc((target.capabilities || []).join(", ") || "—")} · WARP — ${esc(providers)}${target.mode === "custom" ? " · на узле ручная настройка egress" : ""}</p>
    ${reason}
    <div class="routing-layout">
      ${editor(target, state.draft, editable)}
      ${previewPanel(state.compiled, policy, state.dirty)}
    </div>
    ${cardActions(context, policy, state.compiled, state.dirty, editable)}
    <div id="routing-history" hidden></div>
  </article>`;
}

function ensureState(context) {
  if (!context.state.routing) {
    context.state.routing = { policy: null, draft: emptyPolicy(), compiled: null, dirty: false, previewTimer: null, previewSeq: 0 };
  }
  return context.state.routing;
}

async function loadPolicy(context, target) {
  const state = ensureState(context);
  state.policy = null;
  state.compiled = null;
  state.dirty = false;
  state.draft = emptyPolicy();
  if (!target?.backend) return;
  if (target.policy) {
    try {
      state.policy = await context.api(`/api/routing/policies/${encodeURIComponent(target.node_id)}/${encodeURIComponent(target.protocol)}`);
      state.draft = draftFromPolicy(state.policy);
    } catch (error) {
      context.ui.toast(error.message, "error");
    }
  }
  await previewNow(context, target);
}

async function previewNow(context, target) {
  const state = ensureState(context);
  const seq = ++state.previewSeq;
  const url = `/api/routing/policies/${encodeURIComponent(target.node_id)}/${encodeURIComponent(target.protocol)}/preview`;
  try {
    const body = state.dirty || !state.policy ? JSON.stringify(policyBody(state.draft)) : undefined;
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
  return `<div class="security-note">Политика описывает, куда сервис выпускает трафик клиентов: напрямую, через WARP или блокирует. Предпросмотр показывает, что именно применит backend узла — NaiveProxy умеет только «весь сервис» и блокировки, Mieru — ещё и выборочные правила.</div>
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
  ensureState(context);
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
  state.draft.fallback = form.elements.fallback.value;
  for (const input of queryAll("[data-rule-field]", form)) {
    const rule = state.draft.rules[Number(input.dataset.ruleIndex)];
    if (!rule) continue;
    const field = input.dataset.ruleField;
    if (field === "enabled") rule.enabled = input.checked;
    else if (field === "action") rule.action = input.value;
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
  if (context.state.view !== "routing" || !element.closest?.("#routing-form")) return false;
  readDraft(context);
  markDirty(context);
  return true;
}

export function handleRoutingChange(context, element) {
  if (context.state.view !== "routing") return false;
  if (element.id === "routing-node") {
    context.state.routingNode = element.value;
    context.state.routingProtocol = null;
    void context.navigate("routing");
    return true;
  }
  if (!element.closest?.("#routing-form")) return false;
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
    const body = { ...policyBody(state.draft), expected_revision: state.policy?.revision ?? null };
    state.policy = await context.api(`/api/routing/policies/${encodeURIComponent(target.node_id)}/${encodeURIComponent(target.protocol)}`, { method: "PUT", body: JSON.stringify(body) });
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
  if (context.state.view !== "routing" || form.id !== "routing-form") return false;
  void save(context);
  return true;
}

async function operate(context, action, button) {
  const target = currentTarget(context);
  const state = ensureState(context);
  if (!target || !state.policy) return;
  const titles = { apply: ["Применить политику?", "Узел получит новую конфигурацию egress. Откат доступен из истории.", "Применить"],
    rollback: ["Откатить к предыдущей записи?", "Узел вернётся к предыдущей конфигурации egress менеджера.", "Откатить"],
    delete: ["Удалить политику?", "Узел при этом не трогается: удалить можно только политику, уже сведённую к «напрямую без правил».", "Удалить"] };
  const [title, text, label] = titles[action];
  if (!(await context.ui.confirmed(title, text, label))) return;
  context.ui.setBusy(button, true, "…");
  const base = `/api/routing/policies/${encodeURIComponent(target.node_id)}/${encodeURIComponent(target.protocol)}`;
  try {
    if (action === "delete") {
      await context.api(base, { method: "DELETE" });
      context.ui.toast("Политика удалена");
    } else {
      const result = await context.api(`${base}/${action}`, { method: "POST", body: JSON.stringify({ expected_revision: state.policy.revision }) });
      const policy = result.policy;
      context.ui.toast(policy.state === "applying" ? "Отправлено узлу: результат появится после heartbeat" : action === "apply" ? `Применено (rev ${number(policy.applied_revision)})` : "Откачено");
    }
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
    const data = await context.api(`/api/routing/policies/${encodeURIComponent(target.node_id)}/${encodeURIComponent(target.protocol)}/history`);
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
    void context.navigate("routing");
    return true;
  }
  if (action === "apply" || action === "rollback" || action === "delete") {
    void operate(context, action, button);
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
