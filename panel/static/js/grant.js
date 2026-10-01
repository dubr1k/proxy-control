// The window of one access (v1.0.2): everything the panel knows about a single grant — where it
// lives, what the node reports, its route and limits — and, on request, its own link with a QR.
// The client card and the client window both open it by a click on the grant's row.
import { bytes, esc, locale, query } from "./common.js";
import { proxyLink, qrSource } from "./access.js";

export const PROTOCOL_NAMES = { mtproxy: "MTProxy", naive: "NaiveProxy", mieru: "Mieru" };

const CLIENT_STATE = { active: "активен", suspended: "приостановлен", archived: "в архиве" };
const DESIRED = { enabled: "включён", disabled: "выключен", deleted: "удалён" };
const OBSERVED = {
  unknown: "ещё не сообщал",
  pending: "ожидает узел",
  enabled: "включён",
  disabled: "выключен",
  missing: "учётной записи нет",
  failed: "ошибка",
  drifted: "расхождение",
};
const APPS = ["karing", "singbox", "mihomo", "throne"];
const AUTO_REFRESH = { supported: "обновляется", unsupported: "не поддерживает", unproven: "не проверено" };
const LANE_PROTOCOLS = new Set(["naive", "mieru"]);

// What a grant is in one phrase, for its row: the node's report when it is not yet what was
// asked, the ask otherwise; a missing secret is a second, independent fact.
export function grantTone(grant) {
  return ["failed", "pending"].includes(grant.observed_state) ? grant.observed_state : grant.desired_state;
}

export function grantStatus(grant) {
  if (grant.observed_state === "failed") return grant.last_error ? `ошибка: ${grant.last_error}` : "ошибка";
  if (["pending", "drifted", "missing"].includes(grant.observed_state) && grant.desired_state !== "deleted") {
    return OBSERVED[grant.observed_state];
  }
  return DESIRED[grant.desired_state] || grant.desired_state;
}

export function nodeName(nodes, nodeId) {
  if (!nodeId || nodeId === "local") return "Этот сервер";
  return (nodes || []).find((node) => node.node_id === nodeId)?.display_name || nodeId;
}

// One row of the grant list, the same in the card and in the client window: the whole row is
// the button that opens the grant, so a tap anywhere on it shows the details and the link.
export function grantRowHtml(grant, { nodes = [], extra = "" } = {}) {
  const orphan = grant.secret_ref === null
    ? '<em class="grant-flag" title="Панель не хранит его секрет: ссылку собрать нельзя, в подписку он не попадает">без секрета</em>'
    : "";
  const lane = LANE_PROTOCOLS.has(grant.protocol)
    ? `<small class="grant-route-label">${grant.routing_lane === "own" ? "своя полоса" : "маршрут сервиса"}</small>`
    : '<small class="grant-route-label"></small>';
  return `<li class="grant-item" data-grant-id="${esc(grant.id)}" data-grant-protocol="${esc(grant.protocol)}">
    <button type="button" class="grant-row" data-grant-open="${esc(grant.id)}" data-grant-state="${esc(grantTone(grant))}" aria-label="Доступ ${esc(PROTOCOL_NAMES[grant.protocol] || grant.protocol)} · ${esc(grant.runtime_username)}: подробности и ссылка">
      <b class="grant-proto">${esc(PROTOCOL_NAMES[grant.protocol] || grant.protocol)}</b>
      <span class="grant-account"><span>${esc(grant.runtime_username)}</span><small class="grant-node">${esc(nodeName(nodes, grant.node_id))}</small></span>
      <span class="grant-state"><small>${esc(grantStatus(grant))}</small>${orphan}</span>
      ${lane}
      ${extra}
      <span class="grant-chevron" aria-hidden="true">›</span>
    </button>
  </li>`;
}

function formatDate(seconds) {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString(locale(), { dateStyle: "medium", timeStyle: "short" });
}

function rate(bps) {
  return `${bytes(Math.round(Number(bps) / 8))}/с`;
}

// The limits a grant carries, in words; none named means none.
function limits(grant) {
  const options = grant.options || {};
  const parts = [];
  if (grant.protocol === "mtproxy") {
    if (options.data_quota_bytes) parts.push(`трафик ${bytes(options.data_quota_bytes)}`);
    if (options.rate_limit_up_bps) parts.push(`отдача ${rate(options.rate_limit_up_bps)}`);
    if (options.rate_limit_down_bps) parts.push(`загрузка ${rate(options.rate_limit_down_bps)}`);
    if (options.max_tcp_conns) parts.push(`соединений ${options.max_tcp_conns}`);
    if (options.max_unique_ips) parts.push(`IP-адресов ${options.max_unique_ips}`);
    if (options.expiration) parts.push(`до ${formatDate(options.expiration)}`);
  } else if (grant.protocol === "naive") {
    if (options.quota_bytes) parts.push(`трафик ${bytes(options.quota_bytes)}`);
  } else if (grant.protocol === "mieru") {
    for (const quota of options.quotas || []) parts.push(`${bytes(quota.megabytes * 1024 * 1024)} за ${quota.days} дн.`);
  }
  return parts.length ? parts.join(", ") : "без ограничений";
}

function validity(grant) {
  if (!grant.valid_from && !grant.valid_until) return "";
  const from = grant.valid_from ? `с ${formatDate(grant.valid_from)}` : "";
  const until = grant.valid_until ? `до ${formatDate(grant.valid_until)}` : "";
  return [from, until].filter(Boolean).join(" ");
}

function fact(label, value, { html = false, wide = false } = {}) {
  return `<div class="grant-fact${wide ? " wide" : ""}"><dt>${esc(label)}</dt><dd>${html ? value : esc(value)}</dd></div>`;
}

// A link is shown in a field and a QR, never as markup; only Telegram's own link becomes an
// `href`, and it passes the same check as everywhere else in the panel.
function checkedLink(protocol, value) {
  if (protocol === "mtproxy") return proxyLink(value);
  const scheme = protocol === "naive" ? /^(naive\+)?https:\/\/[^\s]+$/ : /^mierus?:\/\/[^\s]+$/;
  if (typeof value !== "string" || value.length > 4096 || !scheme.test(value)) {
    throw new Error("Панель вернула некорректную ссылку доступа");
  }
  return value;
}

export function createGrantDialog(context) {
  const { api, root, ui } = context;
  const state = { clientId: null, grantId: null, generation: 0, matrix: null, link: null };

  function entry() {
    const found = (context.state.clients || []).find((item) => item.client.id === state.clientId);
    if (found) return found;
    // Opened from the client window before the list was read (a deep link, a fresh tab).
    return state.fallback || null;
  }

  function current() {
    const item = entry();
    const grant = item?.grants.find((candidate) => candidate.id === state.grantId);
    return grant ? { client: item.client, grant } : null;
  }

  function canWrite(client) {
    return context.state.me?.role !== "viewer" && client.state !== "archived";
  }

  function subscriptionFact(grant) {
    if (grant.protocol === "mtproxy") return fact("Подписка", "не входит: Telegram открывает только ссылку tg://proxy");
    if (!state.matrix) return fact("Подписка", "…");
    const marks = APPS.map((app) => {
      const status = state.matrix[grant.protocol]?.[app] || "unsupported";
      return `<small class="refresh-${esc(status)}" title="${esc(app)}: ${esc(AUTO_REFRESH[status] || status)}">${esc(app)}</small>`;
    }).join("");
    const note = grant.secret_ref === null
      ? '<small class="form-hint">без секрета — в подписке как unsupported</small>'
      : (grant.desired_state === "enabled" ? "" : '<small class="form-hint">выключен — в подписку не попадает</small>');
    return fact("Подписка", `<span class="auto-refresh">${marks}</span>${note}`, { html: true });
  }

  function renderFacts(client, grant) {
    const observed = OBSERVED[grant.observed_state] || grant.observed_state;
    const error = grant.observed_state === "failed" && grant.last_error ? `: ${grant.last_error}` : "";
    const rows = [
      fact("Клиент", `${client.display_name} · ${CLIENT_STATE[client.state] || client.state}`, { wide: true }),
      fact("Протокол", PROTOCOL_NAMES[grant.protocol] || grant.protocol),
      fact("Учётная запись", `<code>${esc(grant.runtime_username)}</code>`, { html: true }),
      fact("Узел", nodeName(context.state.nodes, grant.node_id)),
      fact("Состояние", `<span class="grant-state-word" data-grant-state="${esc(grantTone(grant))}">${esc(DESIRED[grant.desired_state] || grant.desired_state)}</span>`, { html: true }),
      fact("Узел сообщает", `${observed}${error}`),
    ];
    if (LANE_PROTOCOLS.has(grant.protocol)) {
      rows.push(fact("Маршрут", grant.routing_lane === "own" ? "своя полоса (правила — на «Маршрутизации»)" : "как у сервиса"));
    }
    rows.push(fact("Ограничения", limits(grant)));
    const period = validity(grant);
    if (period) rows.push(fact("Срок действия", period));
    rows.push(subscriptionFact(grant));
    rows.push(fact("Секрет", grant.secret_ref === null ? "панель его не хранит" : "хранится в панели"));
    rows.push(fact("Происхождение", grant.origin === "imported" ? "импортирован из менеджера" : "выдан панелью"));
    rows.push(fact("Выдан", formatDate(grant.created_at)));
    rows.push(fact("Изменён", formatDate(grant.updated_at)));
    rows.push(fact("ID доступа", `<code>${esc(grant.id)}</code>`, { html: true }));
    query("#grant-facts", root).innerHTML = rows.join("");
  }

  function renderLink(client, grant) {
    const box = query("#grant-link", root);
    const body = query("#grant-link-body", root);
    const actions = query("#grant-link-actions", root);
    const hint = query("#grant-link-hint", root);
    box.hidden = grant.desired_state === "deleted";
    if (box.hidden) return;
    const writer = context.state.me?.role !== "viewer";
    const apps = writer && grant.node_id === "local" && LANE_PROTOCOLS.has(grant.protocol)
      ? '<button type="button" class="secondary" data-grant-action="profiles">Профили для приложений</button>'
      : "";
    if (grant.secret_ref === null) {
      hint.textContent = "Панель не хранит секрет этого доступа, поэтому ссылку собрать не может.";
      actions.innerHTML = canWrite(client)
        ? `<button type="button" class="secondary" data-grant-action="adopt">Принять доступ</button>${apps}`
        : apps;
      body.innerHTML = "";
      return;
    }
    if (!writer) {
      hint.textContent = "Ссылку показывает владелец или администратор.";
      actions.innerHTML = "";
      body.innerHTML = "";
      return;
    }
    hint.textContent = grant.desired_state === "enabled"
      ? "Ссылка собирается из хранилища панели по запросу и в окне не остаётся."
      : "Доступ выключен: ссылка заработает, когда его включат.";
    actions.innerHTML = `<button type="button" class="primary" data-grant-action="show">${state.link ? "Показать заново" : "Показать ссылку"}</button>${apps}`;
    if (!state.link) {
      body.innerHTML = "";
      return;
    }
    const { value, qr, label } = state.link;
    const telegram = grant.protocol === "mtproxy"
      ? `<a class="primary button" href="${esc(value)}">Открыть в Telegram</a>`
      : "";
    body.innerHTML = `<label class="grant-link-field">${esc(label)}
        <span class="copy-field"><input readonly value="${esc(value)}" aria-label="${esc(label)}"><button type="button" class="copy" data-copy="${esc(value)}">Копировать</button></span>
      </label>
      ${qr ? `<img class="link-qr" src="${esc(qr)}" alt="QR-код: ${esc(grant.runtime_username)}">` : ""}
      <span class="link-card-actions">${telegram}${qr ? `<a class="secondary button" href="${esc(qr)}" download="${esc(grant.protocol)}-${esc(grant.runtime_username)}.svg">Скачать QR</a>` : ""}</span>`;
  }

  function renderActions(client, grant) {
    const box = query("#grant-actions", root);
    if (!canWrite(client) || grant.desired_state === "deleted") {
      box.innerHTML = "";
      return;
    }
    const toggle = grant.desired_state === "enabled"
      ? '<button type="button" class="secondary" data-grant-action="disable">Выключить</button>'
      : '<button type="button" class="secondary" data-grant-action="enable">Включить</button>';
    const owner = context.state.me?.role === "owner";
    const lane = owner && LANE_PROTOCOLS.has(grant.protocol)
      ? `<button type="button" class="secondary" data-grant-action="lane" data-lane-mode="${grant.routing_lane === "own" ? "service" : "own"}">${grant.routing_lane === "own" ? "Вернуть общий маршрут" : "Выделить полосу"}</button>`
      : "";
    box.innerHTML = `${toggle}<button type="button" class="secondary" data-grant-action="rotate">Ротировать секрет</button>${lane}<button type="button" class="danger ghost" data-grant-action="delete">Удалить доступ</button>`;
  }

  function render() {
    const found = current();
    if (!found) return false;
    const { client, grant } = found;
    query("#grant-title", root).textContent = `${PROTOCOL_NAMES[grant.protocol] || grant.protocol} · ${grant.runtime_username}`;
    renderFacts(client, grant);
    renderLink(client, grant);
    renderActions(client, grant);
    return true;
  }

  async function loadMatrix(generation) {
    if (state.matrix) return;
    try {
      const compatibility = await api("/api/subscriptions/compatibility");
      state.matrix = compatibility.matrix || {};
      if (generation === state.generation) render();
    } catch {
      state.matrix = {};
      if (generation === state.generation) render();
    }
  }

  // `fallback`: the client's entry when the caller has it but the list may not (the window).
  function open(clientId, grantId, fallback = null) {
    state.generation += 1;
    state.clientId = clientId;
    state.grantId = grantId;
    state.fallback = fallback;
    state.link = null;
    query("#grant-error", root).textContent = "";
    if (!render()) return;
    const dialog = query("#grant-window", root);
    if (!dialog.open) ui.openModal("#grant-window");
    void loadMatrix(state.generation);
  }

  // After a change the list is read again; the window follows it — or closes when the grant
  // is gone (deleted, the client archived elsewhere).
  async function refresh() {
    const data = await api(`/api/clients/${encodeURIComponent(state.clientId)}`);
    const list = context.state.clients || [];
    const index = list.findIndex((item) => item.client.id === state.clientId);
    if (index >= 0) list[index] = data;
    state.fallback = data;
    if (!render()) query("#grant-window", root).close();
    if (context.state.view === "clients") await context.navigate("clients");
    await context.subscriptions.reloadIfOpen?.(state.clientId);
  }

  async function show(button) {
    const found = current();
    if (!found) return;
    const generation = state.generation;
    const error = query("#grant-error", root);
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Показываем…");
      const { reveal_token: token } = await api(
        `/api/clients/${encodeURIComponent(state.clientId)}/links?grant_id=${encodeURIComponent(state.grantId)}`, { method: "POST" },
      );
      const payload = await api(`/api/reveal/${encodeURIComponent(token)}`);
      if (generation !== state.generation) return;
      const revealed = (payload.grants || []).find((item) => item.grant_id === state.grantId);
      const artifact = revealed?.artifacts?.[0];
      if (!artifact) throw new Error("Панель вернула доступ без ссылки");
      state.link = {
        value: checkedLink(found.grant.protocol, artifact.value),
        qr: artifact.qr ? qrSource(artifact.qr) : null,
        label: artifact.label || "Ссылка",
      };
    } catch (exception) {
      if (generation !== state.generation) return;
      state.link = null;
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
    if (generation === state.generation) render();
  }

  // The rich per-app profiles (sing-box JSON, NekoBox, Karing…) come from the node's own
  // manager, so they are offered for this server's accesses only.
  async function profiles(button) {
    const found = current();
    if (!found) return;
    const { grant } = found;
    const error = query("#grant-error", root);
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Открываем…");
      const path = grant.protocol === "naive" ? "naive" : "mieru";
      const data = await api(`/api/${path}/users/${encodeURIComponent(grant.runtime_username)}/access`, { method: "POST" });
      if (grant.protocol === "naive") context.access.showNaiveAccess(data, grant.runtime_username);
      else context.access.showMieruAccess(data, grant.runtime_username);
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  }

  const CONFIRM = {
    rotate: ["Ротировать секрет?", "выпустит новый секрет: старая ссылка перестанет работать, клиенту понадобится новая.", "Ротировать"],
    delete: ["Удалить доступ?", "будет удалён из протокола; на связанной панели — после доставки узлу.", "Удалить"],
  };
  const DONE = {
    enable: "Доступ включён",
    disable: "Доступ выключен",
    rotate: "Секрет ротирован; покажите клиенту новую ссылку",
    delete: "Доступ удалён",
  };

  async function change(button, action) {
    const found = current();
    if (!found) return;
    const { grant } = found;
    const label = `${PROTOCOL_NAMES[grant.protocol] || grant.protocol} · ${grant.runtime_username}`;
    const error = query("#grant-error", root);
    error.textContent = "";
    if (CONFIRM[action]) {
      const [title, text, ok] = CONFIRM[action];
      if (!await ui.confirmed(title, `${label} ${text}`, ok)) return;
    }
    try {
      ui.setBusy(button, true);
      await api(`/api/clients/grants/${encodeURIComponent(grant.id)}/${action}`, { method: "POST" });
      ui.toast(DONE[action]);
      state.link = null;
      await refresh();
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  }

  async function lane(button) {
    const found = current();
    if (!found) return;
    const { grant } = found;
    const mode = button.dataset.laneMode;
    const label = `${PROTOCOL_NAMES[grant.protocol] || grant.protocol} · ${grant.runtime_username}`;
    const link = grant.protocol === "mieru" ? " Ссылка Mieru изменится (другой порт); подписка обновится сама." : "";
    const [title, text, ok] = mode === "own"
      ? ["Своя полоса для доступа?", `${label} получит собственный маршрут на узле: его правила — на экране «Маршрутизация», вкладка полосы.${link}`, "Создать полосу"]
      : ["Вернуть к маршруту сервиса?", `${label} пойдёт как весь сервис; политика полосы будет удалена.${link}`, "Вернуть"];
    if (!await ui.confirmed(title, text, ok)) return;
    const error = query("#grant-error", root);
    error.textContent = "";
    try {
      ui.setBusy(button, true);
      const result = await api(`/api/routing/lanes/${encodeURIComponent(grant.id)}`, { method: "POST", body: JSON.stringify({ mode }) });
      ui.toast(result.pending ? "Отправлено узлу: результат появится после heartbeat" : mode === "own" ? "Полоса создана: правила — на «Маршрутизации»" : "Доступ вернулся в полосу сервиса");
      state.link = null;
      await refresh();
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  }

  async function adopt(button) {
    const found = current();
    if (!found) return;
    const { grant } = found;
    const rotation = grant.protocol === "mieru";
    if (rotation && !await ui.confirmed(
      "Принять доступ с ротацией?",
      "Mieru не отдаёт сохранённый пароль, поэтому панель выпустит новый. Старая ссылка перестанет работать, клиенту придётся выдать новую.",
      "Ротировать и принять",
    )) return;
    const error = query("#grant-error", root);
    error.textContent = "";
    try {
      ui.setBusy(button, true, "Принимаем…");
      await api(`/api/clients/grants/${encodeURIComponent(grant.id)}/adopt`, { method: "POST", body: JSON.stringify({ allow_rotation: rotation }) });
      ui.toast(rotation ? "Доступ принят, выдана новая ссылка" : "Доступ принят");
      await refresh();
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  }

  function bind() {
    const dialog = query("#grant-window", root);
    if (!dialog) return;
    dialog.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-grant-action]");
      if (!button) return;
      const action = button.dataset.grantAction;
      if (action === "show") void show(button);
      else if (action === "profiles") void profiles(button);
      else if (action === "lane") void lane(button);
      else if (action === "adopt") void adopt(button);
      else void change(button, action);
    });
    // Nothing of the link survives the window.
    dialog.addEventListener("close", () => {
      if (dialog.open) return;
      state.generation += 1;
      state.link = null;
      query("#grant-link-body", root).innerHTML = "";
      query("#grant-facts", root).innerHTML = "";
    });
  }

  return { bind, open };
}
