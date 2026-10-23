// «На чём клиент?»: платформа → приложение → одна ссылка, её QR и кнопка «Открыть в приложении».
// Каталог приложений приходит из `GET /api/subscriptions/compatibility` (panel/subscriptions/apps.py),
// ссылки — из того же reveal'а, что и в окне клиента (`variants`). Один модуль на два окна:
// окно клиента и окно выданных доступов.
import { esc } from "./common.js";

const PROTOCOL_NAMES = { naive: "NaiveProxy", mieru: "Mieru", trusttunnel: "TrustTunnel" };
const HTTPS = /^https:\/\/[^\s"'<>]+$/;
// Схема кнопки приходит из каталога панели; href проверяется всё равно: разрешена только
// схема вида `app://`, но не javascript: и не data:.
const DEEPLINK = /^(?!javascript:|data:|vbscript:)[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+$/i;

const states = new WeakMap();
let sequence = 0;

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
  return { works: pick("works"), unverified: pick("unverified"), no: pick("no") };
}

export function whatItGets(app, protocols) {
  const { works, unverified, no } = split(app, protocols);
  const lines = [];
  if (works.length) lines.push(`Получит: ${listNames(works)}.`);
  if (unverified.length) lines.push(`Должен получить, но мы это не проверяли: ${listNames(unverified)}.`);
  if (no.length) lines.push(`${listNames(no)} в этом приложении ${no.length > 1 ? "не работают" : "не работает"}.`);
  return lines;
}

// Первым идёт приложение, которое возьмёт больше всего проверенного; при равенстве — то,
// что теряет меньше. Приложение, которое не получит ничего, не предлагается.
function ranked(apps, protocols) {
  return apps
    .map((app, order) => ({ app, order, ...split(app, protocols) }))
    .filter((entry) => entry.works.length || entry.unverified.length)
    .sort((left, right) => right.works.length - left.works.length || left.no.length - right.no.length || left.order - right.order);
}

function deepLink(app, link, name) {
  if (!app.deeplink) return "";
  const href = app.deeplink
    .replaceAll("{url_enc}", encodeURIComponent(link))
    .replaceAll("{name_enc}", encodeURIComponent(name))
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
      <li>${href ? "Нажмите «Открыть в приложении» на самом устройстве клиента или скопируйте" : "Скопируйте"} ссылку и добавьте её в приложении как подписку.</li>
      <li>Включите соединение в приложении.</li>
    </ol>`;
}

function result(state, app) {
  const variant = state.payload.variants?.[app.variant] || (app.variant === "singbox" ? { url: state.payload.url, qr: state.payload.qr } : null);
  if (!variant) return '<p class="form-hint">Для этого приложения панель не выдала ссылку — откройте «Все варианты ссылки».</p>';
  const href = deepLink(app, variant.url, state.name);
  const gets = whatItGets(app, state.protocols).map((line) => `<span>${esc(line)}</span>`).join("");
  return `<div class="chooser-result">
      <h4>${esc(app.name)}</h4>
      <p class="chooser-gets">${gets}</p>
      <label><span>Ссылка для <b>${esc(app.name)}</b></span>
        <span class="copy-field"><input readonly value="${esc(variant.url)}" data-chooser-url><button type="button" class="copy" data-copy="${esc(variant.url)}">Копировать</button></span>
      </label>
      ${href ? `<span class="chooser-open"><a class="primary button" href="${esc(href)}" data-chooser-open>Открыть в приложении</a>
        <small>Кнопка работает на устройстве, где установлено приложение.</small></span>` : ""}
      <img class="subscription-qr" src="${esc(variant.qr)}" alt="QR-код ссылки для ${esc(app.name)}">
      ${steps(app, href)}
      ${downloads(app)}
    </div>`;
}

function choices(name, items, current, label) {
  return items.map((item) => `<label class="chooser-chip">
      <input type="radio" name="${esc(name)}" value="${esc(item.id)}"${item.id === current ? " checked" : ""}><span>${label(item)}</span></label>`).join("");
}

function render(host) {
  const state = states.get(host);
  let apps = "";
  let body = "";
  if (state.platform) {
    const entries = ranked((state.catalogue.apps || []).filter((app) => app.platforms.includes(state.platform)), state.protocols);
    if (!entries.length) {
      body = '<p class="form-hint">Для этой платформы нет приложения, которое возьмёт доступы клиента. Выберите другую платформу или откройте «Все варианты ссылки».</p>';
    } else {
      if (!entries.some((entry) => entry.app.id === state.app)) state.app = entries[0].app.id;
      const label = (app) => `<b>${esc(app.name)}</b>${app.id === entries[0].app.id ? " <em>рекомендуем</em>" : ""}`;
      apps = `<fieldset class="chooser-step"><legend>Приложение</legend><div class="chooser-chips">${
        choices(`${state.id}-app`, entries.map((entry) => entry.app), state.app, label)}</div></fieldset>`;
      body = result(state, entries.find((entry) => entry.app.id === state.app).app);
    }
  }
  host.innerHTML = `<div class="link-chooser">
      <fieldset class="chooser-step"><legend>На чём клиент?</legend><div class="chooser-chips">${
    choices(`${state.id}-platform`, state.catalogue.platforms || [], state.platform, (item) => esc(item.name))}</div></fieldset>
      ${apps}${body}
    </div>`;
}

function bind(host) {
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
    host.querySelector(`input[name="${group}"]:checked`)?.focus();
  });
}

// Рисует выбор в `host`. Выбор оператора живёт, пока живёт `host`: перерисовка с новой ссылкой
// (после «Выпустить новую ссылку») его не сбрасывает; `resetChooser` стирает всё.
export function renderChooser(host, { catalogue, payload, protocols, name }) {
  let state = states.get(host);
  if (!state) {
    sequence += 1;
    state = { id: `chooser-${sequence}`, platform: "", app: "" };
    states.set(host, state);
    bind(host);
  }
  Object.assign(state, { catalogue, payload, protocols: [...protocols], name });
  render(host);
}

export function resetChooser(host) {
  const state = states.get(host);
  if (state) Object.assign(state, { platform: "", app: "", payload: null });
  host.innerHTML = "";
}
