// «На чём клиент?»: платформа → приложение → одна ссылка, её QR и кнопка «Открыть в приложении».
// Каталог приложений приходит из `GET /api/subscriptions/compatibility` (panel/subscriptions/apps.py),
// ссылки — из того же reveal'а, что и в окне клиента (`variants`). Один модуль на два окна:
// окно клиента и окно выданных доступов.
import { esc } from "./common.js";
import { qrCard } from "./qr.js";

const PROTOCOL_NAMES = { naive: "NaiveProxy", mieru: "Mieru", trusttunnel: "TrustTunnel" };
const HTTPS = /^https:\/\/[^\s"'<>]+$/;
// Схема кнопки приходит из каталога панели; href проверяется всё равно: разрешена только
// схема вида `app://`, но не javascript: и не data:.
const DEEPLINK = /^(?!javascript:|data:|vbscript:)[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+$/i;

const states = new WeakMap();
let sequence = 0;

function saveSelection(state) {
  if (!state.clientId) return;
  try {
    localStorage.setItem(`proxy-control-delivery:${state.clientId}`, JSON.stringify({ platform: state.platform, app: state.app }));
  } catch { /* Browser storage may be unavailable. */ }
}

function savedSelection(clientId) {
  if (!clientId) return {};
  try {
    const value = JSON.parse(localStorage.getItem(`proxy-control-delivery:${clientId}`) || "{}");
    const safe = (item) => typeof item === "string" && /^[a-z0-9_-]{1,64}$/i.test(item) ? item : "";
    return { platform: safe(value.platform), app: safe(value.app) };
  } catch { return {}; }
}

// The protocols of a client's accesses that a subscription link carries (not MTProxy, not AmneziaWG).
export function subscriptionProtocols(protocols) {
  return [...new Set(protocols)].filter((protocol) => Object.hasOwn(PROTOCOL_NAMES, protocol));
}

function listNames(protocols) {
  const names = protocols.map((protocol) => PROTOCOL_NAMES[protocol] || protocol);
  return names.length > 1 ? `${names.slice(0, -1).join(", ")} и ${names[names.length - 1]}` : names.join("");
}

// Что получит клиент в этом приложении: считается по доступам клиента, а не вообще.
function split(app, protocols) {
  const pick = (status) => protocols.filter((protocol) => app.protocols[protocol] === status);
  return { works: pick("works"), unverified: pick("unverified"), pending: pick("pending"), no: pick("no") };
}

export function whatItGets(app, protocols) {
  const { works, unverified, pending, no } = split(app, protocols);
  const lines = [];
  if (works.length) lines.push(`Получит: ${listNames(works)}.`);
  if (unverified.length) lines.push(`Должен получить, но мы это не проверяли: ${listNames(unverified)}.`);
  if (pending.length) lines.push(`В выпусках приложения пока нет: ${listNames(pending)}.`);
  if (no.length) lines.push(`${listNames(no)} в этом приложении ${no.length > 1 ? "не работают" : "не работает"}.`);
  return lines;
}

// Первым идёт приложение, которое возьмёт больше всего проверенного; при равенстве — то,
// что теряет меньше. Протокол, которого в выпусках приложения ещё нет, не обещаем: такое приложение
// идёт после тех, что отдадут хоть что-то. Приложение, которое не получит ничего, не предлагается.
function ranked(apps, protocols) {
  return apps
    .map((app, order) => ({ app, order, ...split(app, protocols) }))
    .map((entry) => ({ ...entry, gives: entry.works.length + entry.unverified.length }))
    .filter((entry) => entry.gives || entry.pending.length)
    .sort((left, right) => Number(!left.gives) - Number(!right.gives) || right.works.length - left.works.length || left.no.length - right.no.length || left.order - right.order);
}

// encodeURIComponent leaves ! ' ( ) * as they are; the href guard refuses quotes, so a name like O'Brien
// would lose its button. They go out percent-encoded too.
function encodePart(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function deepLink(app, link, name) {
  if (!app.deeplink) return "";
  const href = app.deeplink
    .replaceAll("{url_enc}", encodePart(link))
    .replaceAll("{name_enc}", encodePart(name))
    .replaceAll("{url}", link);
  return DEEPLINK.test(href) ? href : "";
}

function downloads(app) {
  const items = (app.downloads || []).filter((item) => HTTPS.test(item.url));
  if (!items.length) return "";
  const links = items.map((item) => `<a href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">${esc(item.label)}</a>`).join("");
  return `<span class="chooser-downloads">Приложения ещё нет на устройстве клиента? ${links}</span>`;
}

function steps(app, href) {
  return `<ol class="chooser-steps">
      <li>Установите <b>${esc(app.name)}</b> на устройство клиента.</li>
      <li>${href ? "Нажмите «Добавить в приложение» на самом устройстве клиента или скопируйте" : "Скопируйте"} ссылку и добавьте её в приложении как подписку.</li>
      <li>Включите соединение в приложении.</li>
    </ol>`;
}

function result(state, app) {
  const variant = state.payload.variants?.[app.variant] || (app.variant === "singbox" ? { url: state.payload.url, qr: state.payload.qr } : null);
  if (!variant) return '<p class="form-hint">Для этого приложения панель не выдала ссылку — откройте «Все варианты ссылки».</p>';
  const href = deepLink(app, variant.url, state.name);
  const gets = whatItGets(app, state.protocols).map((line) => `<span>${esc(line)}</span>`).join("");
  return `<div class="chooser-result">
      <div class="chooser-result-head"><div><small>Подключение</small><h4>${esc(app.name)}</h4></div></div>
      <p class="chooser-gets">${gets}</p>
      <div class="chooser-main-actions">
        ${href ? `<a class="primary button" href="${esc(href)}" data-chooser-open>Добавить в приложение</a>` : ""}
        <button type="button" class="secondary copy" data-copy="${esc(variant.url)}">Копировать ссылку</button>
      </div>
      ${href ? '<p class="form-hint">Добавляйте подписку на устройстве, где установлено приложение.</p>' : ""}
      <div class="chooser-qr">${qrCard(variant.qr, `QR-код ссылки для ${app.name}`, "subscription-qr.svg", "subscription-qr")}</div>
      <details class="chooser-link-details"><summary>Посмотреть ссылку</summary><label><span>Ссылка для <b>${esc(app.name)}</b></span><input readonly value="${esc(variant.url)}" data-chooser-url></label></details>
      <details class="chooser-instructions"><summary>Как подключиться</summary>${steps(app, href)}${downloads(app)}</details>
    </div>`;
}

function choices(name, items, current, label) {
  return items.map((item) => `<label class="chooser-chip">
      <input type="radio" name="${esc(name)}" value="${esc(item.id)}"${item.id === current ? " checked" : ""}><span>${label(item)}</span></label>`).join("");
}

function render(host) {
  const state = states.get(host);
  const modes = `<div class="delivery-modes" role="group" aria-label="Способ подключения">
    <button type="button" data-delivery-mode="page" aria-pressed="${state.mode === "page"}">Страница клиента</button>
    <button type="button" data-delivery-mode="import" aria-pressed="${state.mode === "import"}">Импорт в приложение</button>
  </div>`;
  if (state.mode === "page") {
    const url = state.payload.page_url;
    const qr = state.payload.page_qr;
    host.innerHTML = `${modes}<div class="delivery-page">
      <div class="delivery-page-actions"><h3>Постоянная ссылка</h3>
        <p>Откройте страницу, чтобы увидеть все доступы клиента.</p>
        <label>Ссылка страницы<span class="copy-field"><input readonly data-client-page-url value="${esc(url)}"><button type="button" class="primary copy" data-copy="${esc(url)}">Копировать</button></span></label>
      </div>
      <figure class="qr-card"><button type="button" class="qr-preview" data-qr-expand data-qr-filename="client-page.svg" aria-label="Увеличить QR страницы клиента"><img data-client-page-qr src="${esc(qr)}" alt="QR страницы клиента"></button><figcaption>Откройте камерой телефона</figcaption></figure>
    </div>`;
    return;
  }
  if (!(state.catalogue.platforms || []).length) {
    host.innerHTML = `${modes}<p class="form-hint">Каталог приложений недоступен. Откройте страницу клиента или попробуйте позже.</p>`;
    return;
  }
  let apps = "";
  let body = "";
  if (state.platform) {
    const entries = ranked((state.catalogue.apps || []).filter((app) => app.platforms.includes(state.platform)), state.protocols);
    if (!entries.length) {
      body = '<p class="form-hint">Для этой платформы нет приложения, которое возьмёт доступы клиента. Выберите другую платформу или откройте «Все варианты ссылки».</p>';
    } else {
      if (!entries.some((entry) => entry.app.id === state.app)) state.app = entries[0].app.id;
      const label = (app) => `<b>${esc(app.name)}</b>${app.id === entries[0].app.id ? " <em>рекомендуем</em>" : ""}`;
      const selected = entries.find((entry) => entry.app.id === state.app).app;
      apps = `<fieldset class="chooser-step"><legend>Приложение</legend>
        <p>Выбрано: <b>${esc(selected.name)}</b>${selected.id === entries[0].app.id ? " · рекомендуем" : ""}</p>
        <details class="chooser-app-select"><summary>Сменить приложение</summary><div class="chooser-chips">${
        choices(`${state.id}-app`, entries.map((entry) => entry.app), state.app, label)}</div></details></fieldset>`;
      body = result(state, entries.find((entry) => entry.app.id === state.app).app);
    }
  }
  host.innerHTML = `${modes}<div class="link-chooser">
      <fieldset class="chooser-step"><legend>На чём клиент?</legend><div class="chooser-chips">${
    choices(`${state.id}-platform`, state.catalogue.platforms || [], state.platform, (item) => esc(item.name))}</div></fieldset>
      ${apps}${body}
    </div>`;
}

function bind(host) {
  host.addEventListener("click", (event) => {
    const button = event.target.closest?.("[data-delivery-mode]");
    const state = states.get(host);
    if (!button || !state?.payload) return;
    state.mode = button.dataset.deliveryMode;
    render(host);
    host.querySelector(`[data-delivery-mode="${state.mode}"]`)?.focus();
  });
  host.addEventListener("change", (event) => {
    const state = states.get(host);
    const input = event.target;
    if (!state?.payload || input.type !== "radio") return;
    const group = input.name;
    if (group === `${state.id}-platform`) {
      state.platform = input.value;
      state.app = "";
    } else if (group === `${state.id}-app`) {
      state.app = input.value;
    } else {
      return;
    }
    render(host);
    saveSelection(state);
    host.querySelector(`input[name="${group}"]:checked`)?.focus();
  });
}

// Рисует выбор в `host`. Выбор оператора живёт, пока живёт `host`: перерисовка с новой ссылкой
// (после «Выпустить новую ссылку») его не сбрасывает; `resetChooser` стирает всё.
export function renderChooser(host, { catalogue, payload, protocols, name, clientId = null }) {
  let state = states.get(host);
  if (!state) {
    sequence += 1;
    state = { id: `chooser-${sequence}`, platform: "", app: "", mode: "page", clientId: null };
    states.set(host, state);
    bind(host);
  }
  if (state.clientId !== clientId) {
    Object.assign(state, { platform: "", app: "", clientId }, savedSelection(clientId));
  }
  Object.assign(state, { catalogue, payload, protocols: [...protocols], name });
  render(host);
}

export function resetChooser(host) {
  const state = states.get(host);
  if (state) Object.assign(state, { platform: "", app: "", mode: "page", payload: null, clientId: null });
  host.innerHTML = "";
}
