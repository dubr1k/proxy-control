import { OPERATION_MESSAGE, OPERATION_OK, esc, query, queryAll } from "./common.js";
import { placementDiff, placementRows, readPlacement, renderPlacement, settling } from "./placement.js";
import { proposeUsername } from "./clients.js";
import { proxyLink, qrSource } from "./access.js";

const PROTOCOL_NAMES = { mtproxy: "MTProxy", naive: "NaiveProxy", mieru: "Mieru" };

// Что подписка действительно умеет отдавать. MTProxy сюда не входит и не может войти:
// Telegram открывает ссылку `tg://proxy` и никогда не опрашивает URL подписки.
const SUBSCRIBABLE = new Set(["naive", "mieru"]);

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

// Паузы между перечитываниями карточки, пока узел не подтвердил доступ. Первая короче
// такта pusher'а (15 с) — узел нередко отвечает раньше; дальше реже, и всего около двух
// минут: столько ждёт оператор, а не окно, открытое на весь день.
const SETTLE_DELAYS = [3000, 5000, 8000, 12000, 20000, 30000, 45000];

function formatDate(seconds) {
  if (!seconds) return "никогда";
  return new Date(seconds * 1000).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" });
}

// A managed node refuses grant changes from the central panel with a raw invariant message;
// the operator cannot act on that wording, so it is replaced with where the change belongs.
function explain(exception) {
  if (String(exception.message).includes("managed by central")) {
    return "Этот узел управляется центральной панелью — доступы клиента меняйте оттуда.";
  }
  return exception.message;
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

// The client window: the subscription link on top (shown on request, never kept), the
// node × protocol matrix below. Both read the same client, so one load feeds both.
export function createSubscriptionDialog(context) {
  const { api, root, ui } = context;
  // `generation` counts the openings: an answer that comes back after the window was
  // reopened for another client belongs to nobody and is dropped.
  const state = { clientId: null, name: "", client: null, grants: [], rows: [], reveal: null, links: null, format: "singbox", matrix: {}, generation: 0, settling: false };

  function liveGrants() {
    return state.grants.filter((grant) => grant.desired_state !== "deleted");
  }

  function canWrite() {
    return context.state.me?.role !== "viewer" && state.client?.state !== "archived";
  }

  function renderSubscription(overview) {
    const current = overview.subscription;
    const status = query("#subscription-status", root);
    const actions = query("#subscription-actions", root);
    // Подписка показывается, только если клиенту есть что по ней отдавать. У клиента с
    // одним MTProxy её нечем наполнить — вместо блока объяснение и ссылки ниже.
    // Уже выданная подписка остаётся на экране в любом случае: её нужно уметь отозвать.
    const serves = liveGrants().filter((grant) => SUBSCRIBABLE.has(grant.protocol));
    const unavailable = query("#subscription-unavailable", root);
    const hide = serves.length === 0 && current === null;
    query("#subscription-box", root).hidden = hide;
    unavailable.hidden = serves.length > 0;
    if (!serves.length) {
      unavailable.textContent = liveGrants().length
        ? "Подписка этому клиенту не нужна: Telegram её не читает. Раздайте ссылки MTProxy ниже."
        : "Подписке пока нечего отдавать — у клиента нет доступов.";
      if (hide) return;
    }
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

  // Одна карточка на узел: где выдан доступ, ссылка, кнопка в Telegram и QR к той же ссылке.
  function linkCard(entry) {
    return `<article class="link-card">
      <h4>${esc(entry.node)}<small>${esc(entry.username)}</small></h4>
      <span class="copy-field"><input readonly value="${esc(entry.link)}"><button type="button" class="copy" data-copy="${esc(entry.link)}">Копировать</button></span>
      <img class="link-qr" src="${esc(entry.qr)}" alt="QR-код: ${esc(entry.username)}">
      <span class="link-card-actions">
        <a class="primary button" href="${esc(entry.link)}">Открыть в Telegram</a>
        <a class="secondary button" href="${esc(entry.qr)}" download="mtproxy-${esc(entry.username)}.svg">Скачать QR</a>
      </span>
    </article>`;
  }

  function renderLinks() {
    const box = query("#links-box", root);
    const grants = liveGrants().filter((grant) => grant.protocol === "mtproxy");
    box.hidden = grants.length === 0;
    if (box.hidden) return;
    const orphans = grants.filter((grant) => grant.secret_ref === null).length;
    query("#links-hint", root).textContent = orphans
      ? `Без сохранённого секрета: ${orphans}. Такую ссылку панель собрать не может — примите доступ в карточке клиента.`
      : "";
    query("#links-actions", root).innerHTML = grants.length > orphans
      ? `<button type="button" class="primary" data-links-action="show">${state.links ? "Показать заново" : "Показать ссылки"}</button>`
      : "";
    query("#links-body", root).innerHTML = (state.links || []).map(linkCard).join("");
  }

  function render(overview) {
    query("#subscription-title", root).textContent = `${state.name}${state.client?.state === "archived" ? " · в архиве" : ""}`;
    query("#subscription-variants", root).innerHTML = VARIANTS.map((variant) => variantOption(variant, state.format)).join("");
    renderSubscription(overview);
    renderLinks();
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
    const generation = state.generation;
    const id = encodeURIComponent(state.clientId);
    const [overview, detail, nodes, compatibility] = await Promise.all([
      api(`/api/clients/${id}/subscription`),
      api(`/api/clients/${id}`),
      api("/api/nodes"),
      api("/api/subscriptions/compatibility"),
    ]);
    // The window is already someone else's (or closed): its rows must not be replaced by
    // this client's, or «Применить» would act on grants that are no longer on screen.
    if (generation !== state.generation) return;
    state.client = detail.client;
    state.grants = detail.grants || [];
    state.name = detail.client.display_name;
    context.state.nodes = nodes.items || [];
    state.matrix = compatibility.matrix || {};
    render(overview);
    void settle();
  }

  // Есть ли на экране неприменённая правка матрицы: галочка, поставленная или снятая
  // после последней загрузки. Читается из самой матрицы, а не из отдельного флага, —
  // источник один и тот же и для «Применить».
  function edited() {
    const body = query("#placement-body", root);
    if (!body || !state.rows.length) return false;
    const diff = placementDiff(state.rows, readPlacement(body), "");
    return diff.create.length > 0 || diff.enable.length > 0 || diff.disable.length > 0;
  }

  // Доступ на связанной панели центр записывает сразу, а доставляет узлу pusher — своим
  // тактом, в пределах пары десятков секунд. Карточка рисуется один раз на загрузку, и без
  // этого «ожидает узел» оставалось бы на экране после того, как узел уже подтвердил
  // учётную запись. Пока в матрице есть такие клетки, окно перечитывает клиента само;
  // опрос идёт с растущими паузами и живёт ровно столько, сколько открыто это окно для
  // этого клиента (закрытие и переоткрытие двигают `generation`).
  async function settle() {
    if (state.settling) return;
    const generation = state.generation;
    state.settling = true;
    try {
      for (const delay of SETTLE_DELAYS) {
        if (generation !== state.generation || !settling(state.grants)) return;
        await new Promise((resolve) => setTimeout(resolve, delay));
        // Перерисовка стирает галочки, которые оператор успел расставить, но ещё не
        // применил. Его правка важнее свежей подписи: опрос уходит, а «Применить» сам
        // перечитает карточку и запустит его заново.
        if (generation !== state.generation || edited()) return;
        await load();
      }
    } catch {
      // Перечитать не удалось: на экране остаётся последнее, что знала панель.
    } finally {
      state.settling = false;
    }
  }

  // Clears everything a previous client left on screen: the URL, the matrix, the status
  // line. Shared by close (nothing survives after the window shuts) and open (nothing of
  // the previous client survives a reopen whose load() fails before render() runs).
  function reset() {
    state.reveal = null;
    showReveal();
    // Ссылки клиента — такой же одноразовый показ: за окном они не живут.
    state.links = null;
    query("#links-body", root).innerHTML = "";
    query("#links-actions", root).innerHTML = "";
    query("#links-hint", root).textContent = "";
    query("#links-box", root).hidden = true;
    // Какие блоки видны, решает render() по составу доступов этого клиента, а не
    // остатки от предыдущего: до успешной загрузки не показывается ни один.
    query("#subscription-box", root).hidden = true;
    query("#subscription-unavailable", root).hidden = true;
    state.client = null;
    state.grants = [];
    state.rows = [];
    queryAll("#subscription-grants li", root).forEach((node) => node.remove());
    query("#placement-body", root).innerHTML = "";
    query("#placement-actions", root).innerHTML = "";
    query("#subscription-status", root).textContent = "";
    query("#subscription-actions", root).innerHTML = "";
  }

  // `reveal` may be a payload already in hand (the client was just created): shown at once.
  // `focus: "placement"` (the card's «Узлы и доступы», v0.11) lands the operator on the
  // node × protocol matrix instead of the subscription block at the top.
  async function open(clientId, name, reveal = null, { focus = null } = {}) {
    state.generation += 1;
    const generation = state.generation;
    reset();
    state.clientId = clientId;
    state.name = name;
    state.reveal = reveal;
    query("#subscription-error", root).textContent = "";
    query("#placement-username", root).dataset.typed = "";
    ui.openModal("#subscription-modal");
    try {
      await load();
    } catch (exception) {
      if (generation !== state.generation) return;
      query("#subscription-error", root).textContent = exception.message;
      return;
    }
    if (generation !== state.generation || focus !== "placement") return;
    const box = query(".placement-box", root);
    box?.scrollIntoView({ block: "start", behavior: "smooth" });
    query("#placement-body input[type=checkbox]:not(:disabled)", root)?.focus({ preventScroll: true });
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

  // Ссылки MTProxy: панель собирает их из своего хранилища по запросу, поэтому показать их
  // можно и через неделю после выдачи. Ответ разбирается теми же проверками, что и окно
  // одиночного доступа, — кривая ссылка не доедет до `href` и до QR.
  async function showLinks(button) {
    const error = query("#subscription-error", root);
    error.textContent = "";
    const generation = state.generation;
    try {
      ui.setBusy(button, true, "Показываем…");
      const { reveal_token: token } = await api(
        `/api/clients/${encodeURIComponent(state.clientId)}/links?protocol=mtproxy`, { method: "POST" },
      );
      const payload = await api(`/api/reveal/${encodeURIComponent(token)}`);
      if (generation !== state.generation) return;
      state.links = (payload.grants || []).map((grant) => {
        const artifact = (grant.artifacts || []).find((item) => item.kind === "link");
        if (!artifact) throw new Error("Панель вернула доступ без ссылки");
        const node = context.state.nodes.find((item) => item.node_id === grant.node_id);
        return {
          node: grant.node_id === "local" ? "Этот сервер" : (node?.display_name || grant.node_id),
          username: grant.runtime_username,
          link: proxyLink(artifact.value),
          qr: qrSource(artifact.qr),
        };
      });
    } catch (exception) {
      if (generation !== state.generation) return;
      state.links = null;
      error.textContent = exception.message;
    } finally {
      ui.setBusy(button, false);
    }
    if (generation === state.generation) renderLinks();
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
        ui.toast(OPERATION_MESSAGE[result.status] || result.status, OPERATION_OK.has(result.status) ? "" : "error");
        if (result.status === "manual_intervention_required") {
          ui.toast(`Операция ${result.operation_id}: продолжить можно командой operations-resume`, "error");
        }
      } else {
        ui.toast("Состав клиента обновлён");
      }
      await load();
      if (result?.status === "succeeded") await context.access.openOperationBundle(result.operation_id);
    } catch (exception) {
      error.textContent = explain(exception);
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
      query("#subscription-error", root).textContent = explain(exception);
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
      const links = event.target.closest("button[data-links-action]");
      if (links) return void showLinks(links);
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
    // Enter in a dialog form submits it — here the first submit button is the head ×, so the
    // window would simply close. Enter means «Применить», and nothing else.
    query("#placement-username", root)?.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      query("#placement-actions button[data-placement-action]", root)?.click();
    });
    query("#copy-subscription-url", root)?.addEventListener("click", async () => {
      await ui.copyText(query("#subscription-url", root));
      ui.toast("Ссылка подписки скопирована");
    });
    dialog.addEventListener("close", async () => {
      // `close` fires one task after dialog.close() returns. If open() already reopened the
      // dialog in that gap (a script, or a fast click on another card), it has already bumped
      // the generation and started its own load(); this delayed handler must not wipe that
      // fresh state out from under it.
      if (dialog.open) return;
      // Nothing of the URL survives the window; the list behind it shows what changed.
      state.generation += 1;
      reset();
      if (context.state.view === "clients") await context.navigate("clients");
    });
  }

  return { bind, open };
}
