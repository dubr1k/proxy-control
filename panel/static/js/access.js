import { query } from "./common.js";

function validServer(value) {
  if (/^[A-Za-z0-9.-]{1,253}$/.test(value)) return true;
  if (!/^[0-9A-Fa-f:.]+$/.test(value) || !value.includes(":")) return false;
  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}

function proxyLink(value) {
  try {
    const url = new URL(value);
    const allowed = (url.protocol === "tg:" && url.hostname === "proxy" && ["", "/"].includes(url.pathname))
      || (url.protocol === "https:" && ["t.me", "telegram.me"].includes(url.hostname) && url.pathname === "/proxy");
    const keys = [...url.searchParams.keys()];
    const server = url.searchParams.getAll("server");
    const port = url.searchParams.getAll("port");
    const secret = url.searchParams.getAll("secret");
    if (!allowed || url.hash || keys.length !== 3 || new Set(keys).size !== 3
      || server.length !== 1 || port.length !== 1 || secret.length !== 1
      || !validServer(server[0]) || !/^[0-9]{1,5}$/.test(port[0])
      || Number(port[0]) < 1 || Number(port[0]) > 65535
      || !/^[0-9A-Fa-f]{32,512}$/.test(secret[0])) throw new Error("invalid proxy link");
    return value;
  } catch {
    throw new Error("Сервис вернул некорректную ссылку подключения");
  }
}

function qrSource(value) {
  if (typeof value !== "string" || value.length > 500_000
    || !/^data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+$/.test(value)) {
    throw new Error("Сервис вернул некорректный QR-код");
  }
  return value;
}

function plainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function jsonConfig(value) {
  if (!plainObject(value) || !Array.isArray(value.outbounds)) {
    throw new Error("Сервис вернул некорректную конфигурацию");
  }
  return JSON.stringify(value, null, 2);
}

function filename(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.-]{1,128}\.json$/.test(value)) {
    throw new Error("Сервис вернул некорректное имя конфигурации");
  }
  return value;
}

function qrFor(value, payload) {
  if (!plainObject(value) || value.payload !== payload) {
    throw new Error("QR-код не соответствует выбранному клиенту");
  }
  return { payload, image: qrSource(value.image) };
}

function karingVariant(value) {
  if (!plainObject(value) || value.label !== "Karing" || value.type !== "link") {
    throw new Error("Сервис вернул некорректный профиль Karing");
  }
  const configText = jsonConfig(value.config);
  try {
    const link = new URL(value.import_url);
    const keys = [...link.searchParams.keys()];
    const embedded = JSON.parse(link.searchParams.get("url") || "");
    if (link.protocol !== "karing:" || link.hostname !== "install-config"
      || link.pathname || link.hash || keys.length !== 2
      || new Set(keys).size !== 2 || !keys.includes("url") || !keys.includes("name")
      || JSON.stringify(embedded) !== JSON.stringify(value.config)) {
      throw new Error("invalid Karing link");
    }
  } catch {
    throw new Error("Сервис вернул некорректную ссылку Karing");
  }
  return {
    label: "Karing",
    payloadType: "link",
    payloadLabel: "Ссылка импорта Karing",
    payload: value.import_url,
    copyLabel: "Копировать ссылку",
    openLabel: "Открыть в Karing",
    description: "QR и кнопка открытия передают Karing полный профиль, а не URL прокси-сервера.",
    downloadLabel: "Скачать sing-box JSON",
    downloadText: `${configText}\n`,
    filename: filename(value.filename),
    qr: qrFor(value.qr, value.import_url),
  };
}


function naiveNative(value, username) {
  if (!plainObject(value) || value.label !== "NaiveProxy" || value.type !== "config"
    || !plainObject(value.config) || value.config.listen !== "socks://127.0.0.1:1080") {
    throw new Error("Сервис вернул некорректный config.json NaiveProxy");
  }
  try {
    const endpoint = new URL(value.config.proxy);
    if (endpoint.protocol !== "https:" || !endpoint.password
      || decodeURIComponent(endpoint.username) !== username || endpoint.search || endpoint.hash
      || !["", "/"].includes(endpoint.pathname)) throw new Error("invalid Naive endpoint");
  } catch {
    throw new Error("Сервис вернул некорректный config.json NaiveProxy");
  }
  const payload = JSON.stringify(value.config, null, 2);
  return {
    label: "Native",
    payloadType: "config",
    payloadLabel: "Содержимое config.json",
    payload,
    copyLabel: "Копировать config.json",
    description: "Официальный NaiveProxy использует файл config.json. QR-импорт для него не заявлен.",
    downloadLabel: "Скачать config.json",
    downloadText: `${payload}\n`,
    filename: filename(value.filename),
    qr: null,
  };
}

function naiveNekobox(value, username, native) {
  if (!plainObject(value) || value.label !== "NekoBox" || value.type !== "link"
    || typeof value.share_url !== "string"
    || !value.share_url.startsWith("naive+https://")) {
    throw new Error("Сервис вернул некорректную ссылку NekoBox");
  }
  const endpoint = new URL(native.config.proxy);
  try {
    const link = new URL(value.share_url.slice("naive+".length));
    if (link.protocol !== "https:" || link.hostname !== endpoint.hostname
      || (link.port || "443") !== (endpoint.port || "443")
      || decodeURIComponent(link.username) !== username
      || decodeURIComponent(link.password) !== decodeURIComponent(endpoint.password)
      || link.search || !["", "/"].includes(link.pathname)) {
      throw new Error("invalid NekoBox link");
    }
  } catch {
    throw new Error("Сервис вернул некорректную ссылку NekoBox");
  }
  return {
    label: "NekoBox",
    payloadType: "link",
    payloadLabel: "Ссылка naive+https",
    payload: value.share_url,
    copyLabel: "Копировать ссылку",
    description: "NekoBox и совместимые форки импортируют NaiveProxy по ссылке naive+https://. Отсканируйте QR или вставьте ссылку из буфера обмена.",
    qr: qrFor(value.qr, value.share_url),
  };
}

function shadowrocketVariant(value, native) {
  if (!plainObject(value) || value.label !== "Shadowrocket" || value.type !== "manual"
    || !plainObject(value.fields)) {
    throw new Error("Сервис вернул некорректные поля Shadowrocket");
  }
  const fields = value.fields;
  if (fields.proxy_type !== "HTTPS" || !validServer(fields.server)
    || !Number.isInteger(fields.port) || fields.port < 1 || fields.port > 65535
    || typeof fields.username !== "string" || !fields.username
    || typeof fields.password !== "string" || !fields.password) {
    throw new Error("Сервис вернул некорректные поля Shadowrocket");
  }
  const endpoint = new URL(native.config.proxy);
  if (endpoint.hostname !== fields.server || Number(endpoint.port || 443) !== fields.port
    || decodeURIComponent(endpoint.username) !== fields.username
    || decodeURIComponent(endpoint.password) !== fields.password) {
    throw new Error("Поля Shadowrocket не соответствуют доступу NaiveProxy");
  }
  return {
    label: "Shadowrocket",
    payloadType: "manual",
    payloadLabel: "Поля для ручного ввода",
    payload: [
      `Тип: ${fields.proxy_type}`,
      `Сервер: ${fields.server}`,
      `Порт: ${fields.port}`,
      `Пользователь: ${fields.username}`,
      `Пароль: ${fields.password}`,
    ].join("\n"),
    copyLabel: "Копировать поля",
    description: "Добавьте HTTPS-прокси вручную. Проверенная URI-схема импорта Shadowrocket не используется.",
    qr: null,
  };
}

function mieruNative(value) {
  if (!plainObject(value) || value.label !== "Mieru" || value.type !== "config"
    || !plainObject(value.config) || typeof value.simple_share_url !== "string"
    || typeof value.apply_command !== "string") {
    throw new Error("Сервис вернул некорректную конфигурацию Mieru");
  }
  const configName = filename(value.filename);
  if (value.apply_command !== `mieru apply config ${configName}`) {
    throw new Error("Сервис вернул некорректную команду Mieru");
  }
  try {
    const link = new URL(value.simple_share_url);
    const profiles = value.config.profiles;
    const profile = Array.isArray(profiles) && profiles.length === 1 ? profiles[0] : null;
    const server = plainObject(profile) && Array.isArray(profile.servers)
      && profile.servers.length === 1 ? profile.servers[0] : null;
    const user = plainObject(profile) ? profile.user : null;
    const bindings = plainObject(server) ? server.portBindings : null;
    const ports = link.searchParams.getAll("port");
    const protocols = link.searchParams.getAll("protocol");
    const serverHost = plainObject(server) ? (server.domainName || server.ipAddress) : "";
    const linkHost = link.hostname.startsWith("[") && link.hostname.endsWith("]")
      ? link.hostname.slice(1, -1) : link.hostname;
    if (link.protocol !== "mierus:" || !link.username || !link.password || !link.hostname
      || !plainObject(profile) || !plainObject(user) || !Array.isArray(bindings)
      || bindings.length !== ports.length || ports.length !== protocols.length
      || profile.profileName !== link.searchParams.get("profile")
      || value.config.activeProfile !== profile.profileName
      || user.name !== decodeURIComponent(link.username)
      || user.password !== decodeURIComponent(link.password)
      || serverHost !== linkHost
      || value.config.rpcPort !== 50000 || value.config.socks5Port !== 1080
      || value.config.socks5ListenLAN !== false || value.config.loggingLevel !== "INFO"
      || bindings.some((binding, index) => !plainObject(binding)
        || binding.protocol !== protocols[index]
        || String(binding.port ?? binding.portRange) !== ports[index])) {
      throw new Error("invalid Mieru config");
    }
  } catch {
    throw new Error("Сервис вернул некорректную конфигурацию Mieru");
  }
  const payload = JSON.stringify(value.config, null, 2);
  return {
    label: "Native",
    payloadType: "config",
    payloadLabel: "Содержимое mieru-client.json",
    payload,
    copyLabel: "Копировать конфигурацию",
    description: "Сохраните полный конфиг, выполните mieru apply config mieru-client.json, затем mieru start. Ссылка mierus:// и QR добавляют профиль только в уже настроенный клиент.",
    secondaryLabel: "Ссылка mierus:// для настроенного клиента",
    secondaryPayload: value.simple_share_url,
    secondaryCopyLabel: "Копировать ссылку",
    downloadLabel: "Скачать mieru-client.json",
    downloadText: `${payload}\n`,
    filename: configName,
    qr: qrFor(value.qr, value.simple_share_url),
    qrLabel: "Ссылка mierus:// для настроенного клиента",
  };
}

function unsupportedText(value) {
  if (value === undefined) return "";
  if (!plainObject(value)) throw new Error("Сервис вернул некорректную матрицу клиентов");
  const labels = { karing: "Karing", nekobox: "NekoBox+", shadowrocket: "Shadowrocket" };
  return Object.entries(value).map(([client, reason]) => {
    if (!labels[client] || typeof reason !== "string" || !reason) {
      throw new Error("Сервис вернул некорректную матрицу клиентов");
    }
    return `${labels[client]}: ${reason}`;
  }).join(" ");
}

export function normaliseAccessPayload(data, service, username) {
  if (!plainObject(data) || data.service !== service || data.username !== username
    || !plainObject(data.clients)) {
    throw new Error("Сервис вернул некорректный набор клиентских профилей");
  }
  if (service === "naive") {
    const native = data.clients.native;
    if (!native || !data.clients.nekobox || !data.clients.karing
      || !data.clients.shadowrocket) {
      throw new Error("Сервис вернул неполный набор профилей NaiveProxy");
    }
    return {
      native: naiveNative(native, username),
      nekobox: naiveNekobox(data.clients.nekobox, username, native),
      karing: karingVariant(data.clients.karing),
      shadowrocket: shadowrocketVariant(data.clients.shadowrocket, native),
      unsupported: unsupportedText(data.unsupported_clients),
    };
  }
  if (service === "mieru") {
    if (!data.clients.native) throw new Error("Сервис не вернул профиль Mieru");
    const result = {
      native: mieruNative(data.clients.native),
      unsupported: unsupportedText(data.unsupported_clients),
    };
    if (data.clients.karing) result.karing = karingVariant(data.clients.karing);
    return result;
  }
  throw new Error("Неизвестный тип доступа");
}

export function createAccessDialogs(context) {
  const { root, api, ui } = context;
  const dialogs = {
    naive: { data: null, selected: "", objectUrl: "" },
    mieru: { data: null, selected: "", objectUrl: "" },
  };

  function showAccess(data, username) {
    const link = proxyLink(data.link);
    const qr = qrSource(data.qr);
    query("#access-title", root).textContent = `Доступ · ${username}`;
    query("#access-link", root).value = link;
    query("#qr-image", root).src = qr;
    query("#open-telegram", root).href = link;
    query("#download-qr", root).href = qr;
    query("#download-qr", root).download = `mtproxy-${username}.svg`;
    ui.openModal("#access-modal");
  }

  async function revealToken(token, username) {
    showAccess(await api(`/api/reveal/${encodeURIComponent(token)}`), username);
  }

  function setDownload(prefix, variant) {
    const current = dialogs[prefix];
    const download = query(`#download-${prefix}-payload`, root);
    if (current.objectUrl) URL.revokeObjectURL(current.objectUrl);
    current.objectUrl = "";
    download.hidden = !variant.downloadText;
    download.removeAttribute("href");
    download.removeAttribute("download");
    if (!variant.downloadText) return;
    current.objectUrl = URL.createObjectURL(
      new Blob([variant.downloadText], { type: "application/json" }),
    );
    download.href = current.objectUrl;
    download.download = variant.filename;
    download.textContent = variant.downloadLabel;
  }

  function renderVariant(prefix, client) {
    const current = dialogs[prefix];
    const variant = current.data[client];
    if (!variant) return;
    current.selected = client;
    query(`#${prefix}-client-tabs`, root).querySelectorAll("button").forEach((button) => {
      const active = button.dataset.client === client;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
    });
    query(`#${prefix}-client-description`, root).textContent = variant.description;
    query(`#${prefix}-payload-label`, root).textContent = variant.payloadLabel;
    query(`#${prefix}-payload`, root).value = variant.payload;
    query(`#copy-${prefix}-payload`, root).textContent = variant.copyLabel;

    const secondary = query(`#${prefix}-secondary`, root);
    secondary.hidden = !variant.secondaryPayload;
    query(`#${prefix}-secondary-label`, root).textContent = variant.secondaryLabel || "";
    query(`#${prefix}-secondary-payload`, root).value = variant.secondaryPayload || "";
    query(`#copy-${prefix}-secondary`, root).textContent = variant.secondaryCopyLabel || "";

    const open = query(`#open-${prefix}-client`, root);
    open.hidden = !variant.openLabel;
    open.textContent = variant.openLabel || "";
    open.removeAttribute("href");
    if (variant.openLabel) open.href = variant.payload;
    setDownload(prefix, variant);

    const image = query(`#${prefix}-qr-image`, root);
    const wrap = query(`#${prefix}-qr-wrap`, root);
    const layout = query(`#${prefix}-access-layout`, root);
    const qrDownload = query(`#download-${prefix}-qr`, root);
    if (!image || !wrap || !layout || !qrDownload) return;
    // Without a QR the pane is dropped entirely: an empty white placeholder
    // reads as a broken code and invites scanning it into the wrong client.
    wrap.hidden = !variant.qr;
    layout.classList.toggle("no-qr", !variant.qr);
    image.hidden = !variant.qr;
    image.removeAttribute("src");
    qrDownload.hidden = !variant.qr;
    qrDownload.removeAttribute("href");
    if (variant.qr) {
      const qrLabel = variant.qrLabel || variant.payloadLabel;
      image.src = variant.qr.image;
      image.alt = `QR-код: ${qrLabel}`;
      qrDownload.href = variant.qr.image;
      qrDownload.download = `${prefix}-${client}.svg`;
      query(`#${prefix}-qr-caption`, root).textContent = `QR: ${qrLabel}`;
    }
  }

  function showClientAccess(prefix, data, username) {
    const parsed = normaliseAccessPayload(data, prefix, username);
    const state = dialogs[prefix];
    state.data = parsed;
    const tabs = query(`#${prefix}-client-tabs`, root);
    tabs.innerHTML = Object.entries(parsed)
      .filter(([client]) => client !== "unsupported")
      .map(([client, variant]) => (
        `<button type="button" role="tab" data-client="${client}" aria-selected="false">${variant.label}</button>`
      )).join("");
    query(`#${prefix}-unsupported`, root).textContent = parsed.unsupported;
    query(`#${prefix}-unsupported`, root).hidden = !parsed.unsupported;
    query(`#${prefix}-access-title`, root).textContent = `${prefix === "naive" ? "NaiveProxy" : "Mieru"} · ${username}`;
    renderVariant(prefix, "native");
    ui.openModal(`#${prefix}-access-modal`);
  }

  function showMieruAccess(data, username) {
    showClientAccess("mieru", data, username);
  }

  async function revealMieruToken(token, username) {
    showMieruAccess(await api(`/api/reveal/${encodeURIComponent(token)}`), username);
  }

  function showNaiveAccess(data, username) {
    showClientAccess("naive", data, username);
  }

  async function revealNaiveToken(token, username) {
    showNaiveAccess(await api(`/api/reveal/${encodeURIComponent(token)}`), username);
  }

  function clearClientDialog(prefix) {
    const current = dialogs[prefix];
    query(`#${prefix}-payload`, root).value = "";
    query(`#${prefix}-secondary-payload`, root).value = "";
    query(`#${prefix}-qr-image`, root)?.removeAttribute("src");
    query(`#open-${prefix}-client`, root).removeAttribute("href");
    query(`#download-${prefix}-qr`, root)?.removeAttribute("href");
    query(`#download-${prefix}-payload`, root).removeAttribute("href");
    query(`#${prefix}-client-tabs`, root).textContent = "";
    if (current.objectUrl) URL.revokeObjectURL(current.objectUrl);
    current.data = null;
    current.selected = "";
    current.objectUrl = "";
  }

  function bindClientDialog(prefix) {
    query(`#${prefix}-client-tabs`, root)?.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-client]");
      if (button) renderVariant(prefix, button.dataset.client);
    });
    query(`#copy-${prefix}-payload`, root)?.addEventListener("click", async () => {
      await ui.copyText(query(`#${prefix}-payload`, root));
      ui.toast(`${dialogs[prefix].data[dialogs[prefix].selected].payloadLabel} скопировано`);
    });
    query(`#copy-${prefix}-secondary`, root)?.addEventListener("click", async () => {
      await ui.copyText(query(`#${prefix}-secondary-payload`, root));
      ui.toast("Команда импорта скопирована");
    });
    query(`#${prefix}-access-modal`, root)?.addEventListener("close", () => {
      clearClientDialog(prefix);
    });
  }

  function bind() {
    query("#copy-link", root)?.addEventListener("click", async () => {
      await ui.copyText(query("#access-link", root));
      ui.toast("Ссылка скопирована");
    });
    query("#access-modal", root)?.addEventListener("close", () => {
      query("#access-link", root).value = "";
      query("#qr-image", root).removeAttribute("src");
      query("#open-telegram", root).removeAttribute("href");
      query("#download-qr", root).removeAttribute("href");
    });
    bindClientDialog("mieru");
    bindClientDialog("naive");
  }

  return {
    bind,
    revealToken,
    revealMieruToken,
    revealNaiveToken,
    showAccess,
    showMieruAccess,
    showNaiveAccess,
  };
}
