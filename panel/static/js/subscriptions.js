import { esc, query, queryAll } from "./common.js";

const PROTOCOL_NAMES = { mtproxy: "MTProxy", naive: "NaiveProxy", mieru: "Mieru" };

// One link variant per client family (owner decision 2): what each carries and what it
// leaves out is stated next to it, so nobody hands a Telegram user a sing-box feed.
const VARIANTS = [
  {
    format: "singbox",
    label: "sing-box JSON для Karing",
    clients: "Karing (оба ядра)",
    carries: "NaiveProxy и Mieru как outbound'ы",
    leaves: "MTProxy — в unsupported (в sing-box нет MTProto); Mieru с диапазоном портов — тоже",
  },
  {
    format: "singbox-official",
    label: "sing-box JSON для официального sing-box",
    clients: "sing-box ≥ 1.13 (Apple, Android, Windows, часть сборок Linux)",
    carries: "только NaiveProxy",
    leaves: "Mieru и MTProxy — в unsupported: официальный sing-box не загрузит конфиг с неизвестным outbound'ом",
  },
  {
    format: "clash",
    label: "Clash YAML",
    clients: "mihomo и Clash-совместимые, Karing",
    carries: "Mieru как proxies (TCP/UDP, диапазоны портов)",
    leaves: "NaiveProxy и MTProxy — в unsupported (у mihomo нет таких типов)",
  },
  {
    format: "raw",
    label: "Ссылки текстом",
    clients: "ручной импорт, QR, человек",
    carries: "tg://proxy, naive+https://, mierus:// по одной на строку",
    leaves: "автообновления нет: клиенту придётся переимпортировать после изменений",
  },
];

const AUTO_REFRESH = { supported: "обновляется", unsupported: "не обновляется", unproven: "не проверено" };

function formatDate(seconds) {
  if (!seconds) return "никогда";
  return new Date(seconds * 1000).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" });
}

function grantRow(grant, matrix) {
  const marks = ["karing", "singbox", "mihomo"].map((client) => {
    const status = matrix[grant.protocol]?.[client] || "unsupported";
    return `<small class="refresh-${esc(status)}" title="${esc(client)}: ${esc(AUTO_REFRESH[status] || status)}">${esc(client)}</small>`;
  }).join("");
  const note = !grant.has_credential
    ? '<em>без секрета — в подписке как unsupported</em>'
    : (grant.enabled ? "" : "<em>выключен — в подписку не попадает</em>");
  return `<li class="grant-chip">
    <b>${esc(PROTOCOL_NAMES[grant.protocol] || grant.protocol)}</b>
    <span>${esc(grant.runtime_username)}</span>
    <span class="auto-refresh" data-auto-refresh>${marks}</span>
    ${note}
  </li>`;
}

function variantOption(variant, selected) {
  return `<label class="subscription-variant">
    <input type="radio" name="subscription-format" value="${esc(variant.format)}"${variant.format === selected ? " checked" : ""}>
    <span><b>${esc(variant.label)}</b> <small>${esc(variant.clients)}</small>
      <small>Попадёт: ${esc(variant.carries)}. Не попадёт: ${esc(variant.leaves)}.</small></span>
  </label>`;
}

export function createSubscriptionDialog(context) {
  const { api, root, ui } = context;
  const state = { clientId: null, name: "", reveal: null, format: "singbox", matrix: {} };

  function render(overview) {
    const current = overview.subscription;
    const canWrite = context.state.me?.role !== "viewer";
    query("#subscription-title", root).textContent = `Подписка · ${state.name}`;
    const status = query("#subscription-status", root);
    if (!overview.configured) {
      status.innerHTML = "<b>Домен подписки не настроен.</b> Задайте <code>domains.subscription</code> в install.toml (переменная <code>PANEL_SUBSCRIPTION_URL</code>) — без него URL выдать нечего.";
    } else if (current) {
      status.innerHTML = `URL выдан ${esc(formatDate(current.created_at))}, поколение <b>${esc(String(current.generation))}</b>.
        Последнее обновление клиентом: ${esc(formatDate(current.last_fetched_at))}. Интервал автообновления: ${esc(String(current.update_interval_hours))} ч.`;
    } else {
      status.textContent = "Подписка ещё не создана. URL показывается один раз — сразу после создания или ротации.";
    }
    query("#subscription-grants", root).innerHTML = overview.grants.length
      ? overview.grants.map((grant) => grantRow(grant, state.matrix)).join("")
      : '<li class="grant-chip empty"><small>У клиента нет доступов — подписке нечего отдавать</small></li>';
    query("#subscription-variants", root).innerHTML = VARIANTS.map((variant) => variantOption(variant, state.format)).join("");
    const actions = query("#subscription-actions", root);
    if (!canWrite || !overview.configured) {
      actions.innerHTML = "";
    } else if (current) {
      actions.innerHTML = `<button type="button" class="secondary" data-subscription-action="rotate">Ротировать URL</button>
        <button type="button" class="danger ghost" data-subscription-action="revoke">Отозвать</button>`;
    } else {
      actions.innerHTML = '<button type="button" class="primary" data-subscription-action="create">Создать URL</button>';
    }
    showReveal();
  }

  function showReveal() {
    const box = query("#subscription-reveal", root);
    if (!state.reveal) {
      box.hidden = true;
      query("#subscription-url", root).value = "";
      query("#subscription-qr", root).removeAttribute("src");
      return;
    }
    const variant = state.reveal.variants?.[state.format] || { url: state.reveal.url, qr: state.reveal.qr };
    query("#subscription-url", root).value = variant.url;
    query("#subscription-qr", root).src = variant.qr;
    box.hidden = false;
  }

  async function open(clientId, name) {
    state.clientId = clientId;
    state.name = name;
    state.reveal = null;
    query("#subscription-error", root).textContent = "";
    ui.openModal("#subscription-modal");
    try {
      const [overview, compatibility] = await Promise.all([
        api(`/api/clients/${encodeURIComponent(clientId)}/subscription`),
        api("/api/subscriptions/compatibility"),
      ]);
      state.matrix = compatibility.matrix || {};
      render(overview);
    } catch (exception) {
      query("#subscription-error", root).textContent = exception.message;
    }
  }

  async function refresh() {
    render(await api(`/api/clients/${encodeURIComponent(state.clientId)}/subscription`));
  }

  async function issue(path, button, busy) {
    const error = query("#subscription-error", root);
    error.textContent = "";
    try {
      ui.setBusy(button, true, busy);
      const { reveal_token: token } = await api(path, { method: "POST" });
      // The reveal is consumed on first read: the dialog keeps what it received and
      // never asks again — after it closes the URL exists only where the operator put it.
      state.reveal = await api(`/api/reveal/${encodeURIComponent(token)}`);
      await refresh();
      ui.toast("URL подписки выдан — скопируйте его сейчас");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  }

  async function act(button) {
    const action = button.dataset.subscriptionAction;
    const base = `/api/clients/${encodeURIComponent(state.clientId)}`;
    if (action === "create") return issue(`${base}/subscription`, button, "Создаём…");
    if (action === "rotate") {
      const confirmed = await ui.confirmed(
        "Ротировать URL подписки?",
        "Старая ссылка перестанет открываться в тот же момент. Новую придётся отправить клиенту заново.",
        "Ротировать",
      );
      if (!confirmed) return undefined;
      return issue(`${base}/subscription/rotate`, button, "Ротируем…");
    }
    if (action === "revoke") {
      const confirmed = await ui.confirmed(
        "Отозвать подписку?",
        "Ссылка перестанет открываться. Доступы клиента остаются, но обновляться по подписке больше не будут.",
        "Отозвать",
      );
      if (!confirmed) return undefined;
      try {
        ui.setBusy(button, true, "Отзываем…");
        await api(`${base}/subscription/revoke`, { method: "POST" });
        state.reveal = null;
        await refresh();
        ui.toast("Подписка отозвана");
      } catch (exception) {
        query("#subscription-error", root).textContent = exception.message;
      } finally {
        ui.setBusy(button, false);
      }
    }
    return undefined;
  }

  function bind() {
    const dialog = query("#subscription-modal", root);
    if (!dialog) return;
    dialog.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-subscription-action]");
      if (button) void act(button);
    });
    dialog.addEventListener("change", (event) => {
      if (event.target.name !== "subscription-format") return;
      state.format = event.target.value;
      showReveal();
    });
    query("#copy-subscription-url", root)?.addEventListener("click", async () => {
      await ui.copyText(query("#subscription-url", root));
      ui.toast("Ссылка подписки скопирована");
    });
    dialog.addEventListener("close", () => {
      // Nothing of the one-time URL survives the dialog.
      state.reveal = null;
      showReveal();
      queryAll("#subscription-grants li", root).forEach((node) => node.remove());
    });
  }

  return { bind, open };
}
