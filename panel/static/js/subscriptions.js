import { esc, query, queryAll } from "./common.js";
import { placementDiff, placementRows, readPlacement, renderPlacement } from "./placement.js";
import { proposeUsername } from "./clients.js";

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

const OPERATION_MESSAGE = {
  succeeded: "Доступы выданы",
  compensated: "Операция отменена: созданное удалено, ничего лишнего не тронуто",
  manual_intervention_required: "Требуется вмешательство: часть изменений не удалось откатить",
};

// The client window: the subscription link on top (shown on request, never kept), the
// node × protocol matrix below. Both read the same client, so one load feeds both.
export function createSubscriptionDialog(context) {
  const { api, root, ui } = context;
  const state = { clientId: null, name: "", client: null, grants: [], rows: [], reveal: null, format: "singbox", matrix: {} };

  function canWrite() {
    return context.state.me?.role !== "viewer" && state.client?.state !== "archived";
  }

  function renderSubscription(overview) {
    const current = overview.subscription;
    const status = query("#subscription-status", root);
    const actions = query("#subscription-actions", root);
    if (!overview.configured) {
      status.innerHTML = "<b>Домен подписки не настроен.</b> Задайте <code>domains.subscription</code> в install.toml (переменная <code>PANEL_SUBSCRIPTION_URL</code>) — без него URL выдать нечего.";
      actions.innerHTML = "";
      return;
    }
    if (!current) {
      status.textContent = "Подписка не создана.";
      actions.innerHTML = canWrite() ? '<button type="button" class="primary" data-subscription-action="create">Создать URL</button>' : "";
      return;
    }
    status.innerHTML = `URL выдан ${esc(formatDate(current.created_at))}, поколение <b>${esc(String(current.generation))}</b>.
      Последнее обновление клиентом: ${esc(formatDate(current.last_fetched_at))}. Интервал автообновления: ${esc(String(current.update_interval_hours))} ч.`;
    if (!canWrite()) {
      actions.innerHTML = "";
      return;
    }
    // The link comes back only from escrow: without a master key, or for a token issued
    // before escrow existed, the panel says so instead of offering a button that would 409.
    let show = '<button type="button" class="primary" data-subscription-action="show">Показать</button>';
    if (!overview.secret_store) {
      show = '<small class="form-hint">Панель без хранилища секретов показывает ссылку один раз — при создании и ротации.</small>';
    } else if (!overview.escrowed) {
      show = '<small class="form-hint">Ссылка выдана до включения хранилища — ротируйте, новая будет доступна для показа.</small>';
    }
    actions.innerHTML = `${show}
      <button type="button" class="secondary" data-subscription-action="rotate">Ротировать URL</button>
      <button type="button" class="danger ghost" data-subscription-action="revoke">Отозвать</button>`;
  }

  function renderPlacementBox(overview) {
    const rows = placementRows(context.state.nodes || [], state.grants);
    state.rows = rows;
    query("#placement-body", root).innerHTML = renderPlacement(rows, { canWrite: canWrite() });
    const username = query("#placement-username", root);
    const names = new Set(state.grants.filter((grant) => grant.desired_state !== "deleted").map((grant) => grant.runtime_username));
    if (!username.dataset.typed) username.value = names.size === 1 ? [...names][0] : proposeUsername(state.name);
    query("#placement-username-row", root).hidden = !canWrite();
    query("#subscription-grants", root).innerHTML = overview.grants.length
      ? overview.grants.map((grant) => grantRow(grant, state.matrix)).join("")
      : '<li class="grant-chip empty"><small>У клиента нет доступов — подписке нечего отдавать</small></li>';
    query("#placement-actions", root).innerHTML = canWrite()
      ? '<button type="button" class="primary" data-placement-action="apply">Применить</button>'
      : "";
  }

  function render(overview) {
    query("#subscription-title", root).textContent = `${state.name}${state.client?.state === "archived" ? " · в архиве" : ""}`;
    query("#subscription-variants", root).innerHTML = VARIANTS.map((variant) => variantOption(variant, state.format)).join("");
    renderSubscription(overview);
    renderPlacementBox(overview);
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

  async function load() {
    const id = encodeURIComponent(state.clientId);
    const [overview, detail, nodes, compatibility] = await Promise.all([
      api(`/api/clients/${id}/subscription`),
      api(`/api/clients/${id}`),
      api("/api/nodes"),
      api("/api/subscriptions/compatibility"),
    ]);
    state.client = detail.client;
    state.grants = detail.grants || [];
    state.name = detail.client.display_name;
    context.state.nodes = nodes.items || [];
    state.matrix = compatibility.matrix || {};
    render(overview);
  }

  // `reveal` may be a payload already in hand (the client was just created): shown at once.
  async function open(clientId, name, reveal = null) {
    state.clientId = clientId;
    state.name = name;
    state.reveal = reveal;
    query("#subscription-error", root).textContent = "";
    query("#placement-username", root).dataset.typed = "";
    ui.openModal("#subscription-modal");
    try {
      await load();
    } catch (exception) {
      query("#subscription-error", root).textContent = exception.message;
    }
  }

  async function issue(path, button, busy) {
    const error = query("#subscription-error", root);
    error.textContent = "";
    try {
      ui.setBusy(button, true, busy);
      const { reveal_token: token } = await api(path, { method: "POST" });
      // One reveal, consumed on first read: the window keeps what it received until it closes.
      state.reveal = await api(`/api/reveal/${encodeURIComponent(token)}`);
      await load();
      ui.toast("Ссылка подписки на экране");
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
    if (action === "show") return issue(`${base}/subscription/reveal`, button, "Показываем…");
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
        await load();
        ui.toast("Подписка отозвана");
      } catch (exception) {
        query("#subscription-error", root).textContent = exception.message;
      } finally {
        ui.setBusy(button, false);
      }
    }
    return undefined;
  }

  // The matrix diff goes to the endpoints the card already uses: one saga for every new
  // cell, one call per enable/disable. What actually happened is re-read afterwards.
  async function apply(button) {
    const error = query("#subscription-error", root);
    error.textContent = "";
    const username = query("#placement-username", root);
    const diff = placementDiff(state.rows, readPlacement(query("#placement-body", root)), username.value.trim());
    if (diff.create.length && !username.reportValidity()) return;
    if (diff.create.length && !username.value.trim()) {
      error.textContent = "Для новых доступов нужно имя учётной записи";
      return;
    }
    if (!diff.create.length && !diff.enable.length && !diff.disable.length) {
      ui.toast("Изменений нет");
      return;
    }
    const base = `/api/clients/${encodeURIComponent(state.clientId)}`;
    try {
      ui.setBusy(button, true, "Применяем…");
      for (const id of diff.disable) await api(`/api/clients/grants/${encodeURIComponent(id)}/disable`, { method: "POST" });
      for (const id of diff.enable) await api(`/api/clients/grants/${encodeURIComponent(id)}/enable`, { method: "POST" });
      let result = null;
      if (diff.create.length) {
        result = await api(`${base}/grants`, { method: "POST", body: JSON.stringify({ grants: diff.create }) });
        ui.toast(OPERATION_MESSAGE[result.status] || result.status, result.status === "succeeded" ? "" : "error");
        if (result.status === "manual_intervention_required") {
          ui.toast(`Операция ${result.operation_id}: продолжить можно командой operations-resume`, "error");
        }
      } else {
        ui.toast("Состав клиента обновлён");
      }
      await load();
      if (result?.status === "succeeded") await context.access.openOperationBundle(result.operation_id);
    } catch (exception) {
      error.textContent = exception.message;
      await load().catch(() => {});
    } finally {
      ui.setBusy(button, false);
    }
  }

  async function removeGrant(button) {
    const grant = state.grants.find((item) => item.id === button.dataset.grantId);
    if (!grant) return;
    const label = `${PROTOCOL_NAMES[grant.protocol] || grant.protocol} · ${grant.runtime_username}`;
    const confirmed = await ui.confirmed("Удалить доступ?", `${label} будет удалён из протокола; на связанной панели — после доставки узлу.`, "Удалить");
    if (!confirmed) return;
    try {
      ui.setBusy(button, true);
      await api(`/api/clients/grants/${encodeURIComponent(grant.id)}/delete`, { method: "POST" });
      ui.toast("Доступ удалён");
      await load();
    } catch (exception) {
      query("#subscription-error", root).textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
  }

  function bind() {
    const dialog = query("#subscription-modal", root);
    if (!dialog) return;
    dialog.addEventListener("click", (event) => {
      const subscription = event.target.closest("button[data-subscription-action]");
      if (subscription) return void act(subscription);
      const placement = event.target.closest("button[data-placement-action]");
      if (placement) return void apply(placement);
      const remove = event.target.closest("button[data-placement-delete]");
      if (remove) void removeGrant(remove);
    });
    dialog.addEventListener("change", (event) => {
      if (event.target.name !== "subscription-format") return;
      state.format = event.target.value;
      showReveal();
    });
    query("#placement-username", root)?.addEventListener("input", ({ currentTarget: input }) => {
      input.dataset.typed = input.value ? "1" : "";
    });
    query("#copy-subscription-url", root)?.addEventListener("click", async () => {
      await ui.copyText(query("#subscription-url", root));
      ui.toast("Ссылка подписки скопирована");
    });
    dialog.addEventListener("close", async () => {
      // Nothing of the URL survives the window; the list behind it shows what changed.
      state.reveal = null;
      showReveal();
      state.client = null;
      state.grants = [];
      state.rows = [];
      queryAll("#subscription-grants li", root).forEach((node) => node.remove());
      query("#placement-body", root).innerHTML = "";
      query("#placement-actions", root).innerHTML = "";
      if (context.state.view === "clients") await context.navigate("clients");
    });
  }

  return { bind, open };
}
