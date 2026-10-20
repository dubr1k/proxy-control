// Which apps take a TrustTunnel access and how (v2.1): the «Как подключить» table and the card with the
// fields for apps that import neither the tt:// link nor the TOML. Shown in the grant window next to the
// link; the subscription page (renderers/html.py) carries only the entries marked `verified: true`.
import { esc } from "./common.js";

const HIDDIFY_QUERY = "?format=singbox&client=hiddify";
const NEKOBOX_QUERY = "?format=singbox&client=nekobox";

// `verified: false` marks what the vendors document but this panel has not run itself.
export const TT_APPS = [
  {
    name: "AdGuard TrustTunnel", platforms: "iOS, Android", how: "ссылка tt:// или QR-код", verified: true,
    links: [["App Store", "https://apps.apple.com/us/app/trusttunnel/id6755807890"], ["Google Play", "https://play.google.com/store/apps/details?id=com.adguard.trusttunnel"]],
  },
  {
    name: "TrustTunnel CLI", platforms: "Linux, macOS, Windows", how: "файл TOML", verified: true,
    links: [["GitHub", "https://github.com/TrustTunnel/TrustTunnelClient"]],
  },
  {
    name: "Throne", platforms: "Windows, Linux, macOS, Android",
    how: "вручную: Профиль → Тип TrustTunnel (карточка ниже); подписка sing-box тоже несёт TrustTunnel, но импорт в Throne не проверен", verified: false, links: [],
  },
  {
    name: "Surge", platforms: "macOS, iOS", how: "строка политики из карточки ниже", verified: false,
    links: [["документация", "https://manual.nssurge.com/policies/trust-tunnel.html"]],
  },
  {
    name: "Clash Verge Rev, FlClash, Mihomo Party, ClashMi", platforms: "Windows, macOS, Linux, Android, iOS",
    how: "подписка Clash (ядро mihomo должно быть свежим; проверено на mihomo v1.19.32)", verified: true, links: [],
  },
  {
    name: "Hiddify, NekoBox", platforms: "по клиенту",
    how: `подписка sing-box: ссылка подписки с ${HIDDIFY_QUERY} / ${NEKOBOX_QUERY}; ядро Hiddify проверено нами только собранным из исходников (в выпусках приложения исходящего нет), NekoBox не проверен`, verified: false, links: [],
  },
  {
    name: "Shadowrocket, Trusty, FreeTunnel, FireTunnel, TrustTunnel-GUI-Client", platforms: "iOS, Windows, macOS, Linux",
    how: "не проверено: проверьте импорт ссылки tt:// или TOML либо введите данные вручную", verified: false,
    links: [["Trusty", "https://github.com/Meddelin/trusty"], ["FreeTunnel", "https://github.com/dimmmmmmmer/freetunnel"], ["FireTunnel", "https://github.com/pnsrc/firetunnel"], ["TrustTunnel-GUI-Client", "https://github.com/blazuryk/TrustTunnel-GUI-Client"]],
  },
];

const HTTPS = /^https:\/\/[^\s"'<>]+$/;

function linkHtml([label, url]) {
  return HTTPS.test(url) ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>` : "";
}

export function appsHtml() {
  const items = TT_APPS.map((app) => `<li class="tt-app">
      <b>${esc(app.name)}</b><small>${esc(app.platforms)}</small>
      <span>${esc(app.how)}${app.verified ? "" : ' <em class="tt-unverified">не проверено нами</em>'}</span>
      ${app.links.length ? `<span class="tt-app-links">${app.links.map(linkHtml).join("")}</span>` : ""}
    </li>`).join("");
  return `<section class="tt-apps" aria-label="Как подключить"><h3>Как подключить</h3><ul>${items}</ul>
    <p class="form-hint">Список составлен по документации производителей; что помечено «не проверено нами», панель сама не запускала.</p></section>`;
}

// The artifact is JSON typed by the panel; anything off its shape is dropped rather than shown.
export function parseManual(value) {
  if (typeof value !== "string" || value.length > 65536) return null;
  let data;
  try {
    data = JSON.parse(value);
  } catch {
    return null;
  }
  const text = (key) => (typeof data?.[key] === "string" ? data[key] : "");
  if (!text("server") || !text("username") || !text("password") || !Number.isInteger(data.port)) return null;
  return {
    server: text("server"), port: String(data.port), username: text("username"), password: text("password"),
    sni: text("sni"), protocol: "HTTP/2, QUIC выключен", certificate: text("certificate_pem"), surge: text("surge"),
  };
}

function field(label, value, { secret = false } = {}) {
  const shown = secret
    ? `<code class="tt-secret" data-tt-secret="${esc(value)}">••••••••</code><button type="button" class="secondary" data-tt-reveal aria-pressed="false">Показать</button>`
    : `<code>${esc(value)}</code>`;
  return `<div class="tt-field"><dt>${esc(label)}</dt><dd>${shown}<button type="button" class="secondary button copy" data-copy="${esc(value)}" aria-label="Копировать: ${esc(label)}">Копировать</button></dd></div>`;
}

export function manualHtml(manual) {
  const certificate = manual.certificate
    ? `<div class="tt-field wide"><dt>Сертификат (PEM)</dt><dd><code class="tt-pem">${esc(manual.certificate)}</code><button type="button" class="secondary button copy" data-copy="${esc(manual.certificate)}">Копировать</button></dd></div>`
    : "";
  const surge = manual.surge ? field("Строка политики Surge", `Proxy-TrustTunnel = ${manual.surge}`, { secret: true }) : "";
  return `<section class="tt-manual" aria-label="Данные для ручной настройки"><h3>Данные для ручной настройки</h3>
    <dl>${field("Сервер", manual.server)}${field("Порт", manual.port)}${field("Логин", manual.username)}${field("Пароль", manual.password, { secret: true })}${field("SNI", manual.sni)}
      <div class="tt-field"><dt>Протокол</dt><dd><code>${esc(manual.protocol)}</code></dd></div>${certificate}${surge}</dl>
    <p class="form-hint">Throne: Ctrl+N → Тип «TrustTunnel» → адрес, порт, логин, пароль, SNI → OK. Галочку QUIC не включайте: сервер работает по TCP (HTTP/2).</p></section>`;
}

// One delegated click for the «Показать» buttons: the password is in the page only as masked dots until pressed.
export function bindReveal(container) {
  container.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-tt-reveal]");
    if (!button) return;
    const code = button.parentElement.querySelector("[data-tt-secret]");
    const open = button.getAttribute("aria-pressed") !== "true";
    code.textContent = open ? code.dataset.ttSecret : "••••••••";
    button.setAttribute("aria-pressed", String(open));
    button.textContent = open ? "Скрыть" : "Показать";
  });
}
