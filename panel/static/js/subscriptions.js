import { qrCard } from "./qr.js";
import { actionMenu, esc, locale, OPERATION_MESSAGE, OPERATION_OK, query, queryAll } from "./common.js";
import { placementDiff, placementRows, readPlacement, renderPlacement, settling } from "./placement.js";
import { proposeUsername, reloadClientList } from "./clients.js";
import { proxyLink, qrSource } from "./access.js";
import { AUTO_REFRESH, grantRowHtml, limits, validity } from "./grant.js";
import { renderChooser, resetChooser } from "./link-chooser.js";

const PROTOCOL_NAMES = { mtproxy: "MTProxy", naive: "NaiveProxy", mieru: "Mieru", amneziawg: "AmneziaWG", trusttunnel: "TrustTunnel" };

// Что подписка действительно умеет отдавать. MTProxy сюда не входит и не может войти:
// Telegram открывает ссылку `tg://proxy` и никогда не опрашивает URL подписки.
const SUBSCRIBABLE = new Set(["naive", "mieru", "trusttunnel"]);

// One link variant per client family (owner decision 2): what each carries and what it
// leaves out is stated next to it, so nobody hands a Telegram user a sing-box feed.
const VARIANTS = [
  {
    format: "singbox",
    label: "sing-box JSON для Karing и Throne",
    clients: "Karing (оба ядра), Throne и другие клиенты на доработанном sing-box с поддержкой Mieru",
    carries: "NaiveProxy и Mieru; Throne 1.3.1 подключает Mieru по UDP, только если сервер задан IP-адресом, по TCP — всегда",
    leaves: "MTProxy (в sing-box нет MTProto) и Mieru с диапазоном портов; для Karing ещё TrustTunnel: в официальном sing-box его нет, а Throne, NekoBox и Hiddify получают его по User-Agent или параметру client",
  },
  {
    format: "singbox-hiddify",
    label: "sing-box JSON с TrustTunnel для Hiddify",
    clients: "Hiddify — у его ядра есть TrustTunnel; без параметра client Hiddify опознаётся по User-Agent",
    carries: "TrustTunnel (HTTP/2 поверх TCP, QUIC выключен); документировано производителем, нами не проверено",
    leaves: "NaiveProxy, Mieru и MTProxy; в официальный sing-box этот вариант не загружайте: он не примет неизвестное подключение и отвергнет весь файл",
  },
  {
    format: "singbox-nekobox",
    label: "sing-box JSON с TrustTunnel для NekoBox",
    clients: "NekoBox на сборке NyameBox (и NekoRay), в которой есть TrustTunnel; без параметра client опознаётся по User-Agent",
    carries: "NaiveProxy, Mieru и TrustTunnel (HTTP/2 поверх TCP, QUIC выключен); поддержка зависит от сборки NekoBox",
    leaves: "MTProxy и Mieru с диапазоном портов; в официальный sing-box этот вариант не загружайте",
  },
  {
    format: "singbox-official",
    label: "sing-box JSON для официального sing-box",
    clients: "sing-box ≥ 1.13 (Apple, Android, Windows, часть сборок Linux); Throne — если нужен только NaiveProxy",
    carries: "только NaiveProxy",
    leaves: "Mieru, MTProxy и TrustTunnel: официальный sing-box не загрузит файл с неизвестным подключением",
  },
  {
    format: "clash",
    label: "Clash YAML",
    clients: "mihomo и Clash-совместимые, Karing; не для Throne — он не берёт из Clash YAML ни Mieru, ни NaiveProxy",
    carries: "Mieru (TCP/UDP, диапазоны портов) и TrustTunnel (mihomo)",
    leaves: "NaiveProxy и MTProxy (у mihomo нет таких типов)",
  },
  {
    format: "raw",
    label: "Ссылки текстом",
    clients: "ручной импорт, QR, человек",
    carries: "tg://proxy, naive+https://, mierus://, tt:// по одной на строку",
    leaves: "автообновления нет: клиенту придётся переимпортировать после изменений; Throne склеивает порты ссылки mierus:// в один TCP-профиль и теряет UDP",
  },
];


// Паузы между перечитываниями карточки, пока узел не подтвердил доступ. Первая короче
// такта pusher'а (15 с) — узел нередко отвечает раньше; дальше реже, и всего около двух
// минут: столько ждёт оператор, а не окно, открытое на весь день.
const SETTLE_DELAYS = [3000, 5000, 8000, 12000, 20000, 30000, 45000];

function formatDate(seconds) {
  if (!seconds) return "никогда";
  return new Date(seconds * 1000).toLocaleString(locale(), { dateStyle: "short", timeStyle: "short" });
}

// A managed node refuses grant changes from the central panel with a raw invariant message;
// the operator cannot act on that wording, so it is replaced with where the change belongs.
function explain(exception) {
  if (String(exception.message).includes("managed by central")) {
    return "Этот узел управляется центральной панелью — доступы клиента меняйте оттуда.";
  }
  return exception.message;
}

// The grant list of the window: the same clickable rows as on the card, each with the apps
// that refresh it from the subscription. A click opens the grant's own window — its link.
function grantRow(grant, matrix, nodes) {
  const marks = SUBSCRIBABLE.has(grant.protocol)
    ? ["karing", "singbox", "mihomo", "throne"].map((client) => {
      const status = matrix[grant.protocol]?.[client] || "unsupported";
      return `<small class="refresh-${esc(status)}" title="${esc(client)}: ${esc(AUTO_REFRESH[status] || status)}">${esc(client)}</small>`;
    }).join("")
    : (grant.protocol === "amneziawg"
      ? '<small class="refresh-unsupported" title="AmneziaWG выдаётся файлом конфигурации и QR, а не подпиской">только конфиг</small>'
      : '<small class="refresh-unsupported" title="Telegram не читает подписку: только ссылка tg://proxy">только ссылка</small>');
  const period = validity(grant);
  const restriction = `${limits(grant)}${period ? ` · ${period}` : ""}`;
  return grantRowHtml(grant, { nodes, extra: `<span class="grant-restrictions">${esc(restriction)}</span><span class="auto-refresh" data-auto-refresh>${marks}</span>` });
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
  const state = { clientId: null, name: "", client: null, grants: [], rows: [], reveal: null, links: null, format: "singbox", matrix: {}, catalogue: { platforms: [], apps: [] }, generation: 0, settling: false };

  function liveGrants() {
    return state.grants.filter((grant) => grant.desired_state !== "deleted");
  }

  function canWrite() {
    return context.state.me?.role !== "viewer" && state.client?.state !== "archived";
  }

  function placementError() {
    return state.management?.page.querySelector('[role="alert"]') || query("#subscription-error", root);
  }

  function renderSubscription(overview) {
    const current = overview.subscription;
    const status = query("#subscription-status", root);
    const actions = query("#subscription-actions", root);
    query("#subscription-status-details", root).open = !overview.configured || !current;
    query(".subscription-warning", root).hidden = true;
    const unavailable = query("#subscription-unavailable", root);
    query("#subscription-box", root).hidden = false;
    unavailable.hidden = true;
    if (!overview.configured) {
      status.innerHTML = "<b>Домен подписки не настроен.</b> Задайте <code>domains.subscription</code> в install.toml (переменная <code>PANEL_SUBSCRIPTION_URL</code>) — без него URL выдать нечего.";
      actions.innerHTML = "";
      return;
    }
    if (!current) {
      status.textContent = "Подписка не создана.";
      actions.innerHTML = canWrite() ? '<button type="button" class="primary" data-subscription-action="create">Создать ссылку</button>' : "";
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
    let show = state.reveal ? "" : '<button type="button" class="primary" data-subscription-action="show">Показать</button>';
    if (!overview.secret_store) {
      show = '<small class="form-hint">Панель без хранилища секретов показывает ссылку один раз — при создании и ротации.</small>';
    } else if (!overview.escrowed) {
      show = '<small class="form-hint">Ссылка выдана до включения хранилища: её невозможно извлечь. Прежний адрес продолжает работать.</small>';
    }
    actions.innerHTML = `${show}${actionMenu(`
      <button type="button" class="secondary" data-subscription-action="rotate">Заменить ссылку</button>
      <button type="button" class="danger ghost" data-subscription-action="revoke">Отозвать</button>`)}`;
  }

  function renderPlacementBox() {
    const rows = placementRows(context.state.nodes || [], state.grants);
    state.rows = rows;
    query("#placement-body", root).innerHTML = renderPlacement(rows, { canWrite: canWrite() });
    const username = query("#placement-username", root);
    const names = new Set(state.grants.filter((grant) => grant.desired_state !== "deleted").map((grant) => grant.runtime_username));
    if (!username.dataset.typed) username.value = names.size === 1 ? [...names][0] : proposeUsername(state.name);
    query("#placement-username-row", root).hidden = !canWrite();
    const order = { mtproxy: 0, naive: 1, mieru: 2, amneziawg: 3, trusttunnel: 4 };
    const grants = liveGrants().sort((left, right) => (order[left.protocol] ?? 9) - (order[right.protocol] ?? 9)
      || String(left.node_id).localeCompare(String(right.node_id)));
    query("#grant-legend", root).hidden = grants.length === 0;
    query("#subscription-grants", root).innerHTML = grants.length
      ? grants.map((grant) => grantRow(grant, state.matrix, context.state.nodes)).join("")
      : '<li class="client-empty">У клиента нет доступов — отметьте узлы и протоколы выше</li>';
    query("#placement-actions", root).innerHTML = canWrite()
      ? '<button type="button" class="primary" data-placement-action="apply">Применить</button>'
      : "";
  }

  // Одна карточка на узел: где выдан доступ, ссылка, кнопка в Telegram и QR к той же ссылке.
  function linkCard(entry) {
    return `<article class="link-card">
      <h4>${esc(entry.node)}<small>${esc(entry.username)}</small></h4>
      <span class="copy-field"><input readonly value="${esc(entry.link)}"><button type="button" class="copy" data-copy="${esc(entry.link)}">Копировать</button></span>
      ${qrCard(entry.qr, `QR-код: ${entry.username}`, `mtproxy-${entry.username}.svg`)}
      <span class="link-card-actions">
        <a class="primary button" href="${esc(entry.link)}">Открыть в Telegram</a>
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
    renderPlacementBox();
    showReveal();
  }

  function showReveal() {
    const box = query("#subscription-reveal", root);
    query("#subscription-box > .modal-copy", root).hidden = Boolean(state.reveal);
    if (!state.reveal) {
      box.hidden = true;
      query("#subscription-url", root).value = "";
      query("#subscription-qr", root).removeAttribute("src");
      resetChooser(query("#subscription-chooser", root));
      return;
    }
    const variant = state.reveal.variants?.[state.format] || { url: state.reveal.url, qr: state.reveal.qr };
    query("#subscription-url", root).value = variant.url;
    query("#subscription-qr", root).src = variant.qr;
    renderChooser(query("#subscription-chooser", root), {
      catalogue: state.catalogue,
      payload: state.reveal,
      protocols: [...new Set(liveGrants().map((grant) => grant.protocol).filter((protocol) => SUBSCRIBABLE.has(protocol)))],
      name: state.name,
      clientId: state.clientId,
    });
    box.hidden = false;
  }

  async function load() {
    const generation = state.generation;
    const id = encodeURIComponent(state.clientId);
    const [overview, detail, nodes, compatibility] = await Promise.all([
      api(`/api/clients/${id}/subscription`),
      api(`/api/clients/${id}`),
      api("/api/nodes"),
      api("/api/subscriptions/compatibility").catch(() => ({ matrix: {}, platforms: [], apps: [] })),
    ]);
    // The window is already someone else's (or closed): its rows must not be replaced by
    // this client's, or «Применить» would act on grants that are no longer on screen.
    if (generation !== state.generation) return;
    state.client = detail.client;
    state.grants = detail.grants || [];
    state.name = detail.client.display_name;
    context.state.nodes = nodes.items || [];
    state.matrix = compatibility.matrix || {};
    state.catalogue = { platforms: compatibility.platforms || [], apps: compatibility.apps || [] };
    state.overview = overview;
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
    state.overview = null;
    state.grants = [];
    state.rows = [];
    queryAll("#subscription-grants li", root).forEach((node) => node.remove());
    query("#grant-legend", root).hidden = true;
    query("#placement-body", root).innerHTML = "";
    query("#placement-actions", root).innerHTML = "";
    query("#subscription-status", root).textContent = "";
    query("#subscription-actions", root).innerHTML = "";
  }

  // `reveal` may be a payload already in hand (the client was just created): shown at once.
  // `focus: "placement"` (the card's «Узлы и доступы», v0.11) lands the operator on the
  // node × protocol matrix instead of the subscription block at the top.
  function closeManagement({ restore = true } = {}) {
    const management = state.management;
    if (!management) return;
    state.management = null;
    state.generation += 1;
    const placement = query(".placement-box", root);
    const error = query("#subscription-error", root);
    error.before(placement);
    management.page.remove();
    for (const [node, hidden] of management.previous) node.hidden = hidden;
    reset();
    if (restore) {
      window.scrollTo(0, management.scroll);
      management.trigger?.focus({ preventScroll: true });
    } else if (window.history.state?.clientManagement) {
      const history = { ...window.history.state };
      delete history.clientManagement;
      window.history.replaceState(history, "");
    }
  }

  async function openManagement(clientId, name, trigger) {
    if (state.management) closeManagement({ restore: false });
    state.generation += 1;
    const generation = state.generation;
    reset();
    state.clientId = clientId;
    state.name = name;
    query("#placement-username", root).dataset.typed = "";
    const view = context.ui.view;
    const previous = [...view.children].map((node) => [node, node.hidden]);
    const scroll = window.scrollY;
    for (const [node] of previous) node.hidden = true;
    const page = root.createElement("section");
    page.id = "client-management";
    page.dataset.clientId = clientId;
    page.innerHTML = '<button type="button" class="secondary" data-management-back>← К списку клиентов</button><h2></h2><p class="form-error" role="alert"></p>';
    page.querySelector("h2").textContent = name;
    const placement = query(".placement-box", root);
    placement.hidden = false;
    page.append(placement);
    view.append(page);
    state.management = { page, previous, scroll, trigger };
    window.history.pushState({ ...window.history.state, clientManagement: clientId }, "");
    window.scrollTo(0, 0);
    try {
      await load();
    } catch (exception) {
      if (generation === state.generation) page.querySelector('[role="alert"]').textContent = exception.message;
    }
  }

  async function open(clientId, name, reveal = null, { focus = null } = {}) {
    state.generation += 1;
    const generation = state.generation;
    reset();
    state.clientId = clientId;
    state.name = name;
    state.reveal = reveal;
    query("#subscription-error", root).textContent = "";
    query("#placement-username", root).dataset.typed = "";
    query("#client-subscription-panel", root).hidden = false;
    query(".placement-box", root).hidden = true;
    ui.openModal("#subscription-modal");
    try {
      await load();
      if (generation === state.generation && focus === "subscription" && !state.reveal
          && state.overview?.subscription && state.overview.escrowed && state.overview.secret_store && canWrite()) {
        const { reveal_token: token } = await api(`/api/clients/${encodeURIComponent(clientId)}/subscription/reveal`, { method: "POST" });
        const payload = await api(`/api/reveal/${encodeURIComponent(token)}`);
        if (generation !== state.generation) return;
        state.reveal = payload;
        renderSubscription(state.overview);
        showReveal();
      }
    } catch (exception) {
      if (generation !== state.generation) return;
      query("#subscription-error", root).textContent = exception.message;
      return;
    }
  }

  async function issue(path, button, busy) {
    const error = query("#subscription-error", root);
    const generation = state.generation;
    error.textContent = "";
    try {
      ui.setBusy(button, true, busy);
      const { reveal_token: token } = await api(path, { method: "POST" });
      // One reveal, consumed on first read: the window keeps what it received until it closes.
      const payload = await api(`/api/reveal/${encodeURIComponent(token)}`);
      if (generation !== state.generation) return;
      state.reveal = payload;
      await load();
      ui.toast("Ссылка подписки на экране");
    } catch (exception) {
      if (generation === state.generation) error.textContent = exception.message;
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
    const generation = state.generation;
    if (action === "create") return issue(`${base}/subscription`, button, "Создаём…");
    if (action === "show") return issue(`${base}/subscription/reveal`, button, "Показываем…");
    if (action === "rotate") {
      const confirmed = await ui.confirmed(
        "Заменить ссылку?",
        "Старая ссылка перестанет открываться сразу же, и приложения клиента по ней обновляться не смогут. Новую ссылку придётся отправить клиенту заново.",
        "Заменить ссылку",
      );
      if (!confirmed || generation !== state.generation) return undefined;
      return issue(`${base}/subscription/rotate`, button, "Выпускаем…");
    }
    if (action === "revoke") {
      const confirmed = await ui.confirmed(
        "Отозвать подписку?",
        "Ссылка перестанет открываться. Доступы клиента остаются, но обновляться по подписке больше не будут.",
        "Отозвать",
      );
      if (!confirmed || generation !== state.generation) return undefined;
      try {
        ui.setBusy(button, true, "Отзываем…");
        await api(`${base}/subscription/revoke`, { method: "POST" });
        if (generation !== state.generation) return undefined;
        state.reveal = null;
        await load();
        ui.toast("Подписка отозвана");
      } catch (exception) {
        if (generation === state.generation) query("#subscription-error", root).textContent = exception.message;
      } finally {
        ui.setBusy(button, false);
      }
    }
    return undefined;
  }

  // The matrix diff goes to the endpoints the card already uses: one saga for every new
  // cell, one call per enable/disable. What actually happened is re-read afterwards.
  async function apply(button) {
    const error = placementError();
    const generation = state.generation;
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
      if (generation !== state.generation) return;
      await load();
      if (generation !== state.generation) return;
      if (result?.status === "succeeded") {
        await context.access.openOperationBundle(result.operation_id, {
          subscription: state.reveal,
          protocols: liveGrants().map((grant) => grant.protocol),
          name: state.name,
        });
      }
    } catch (exception) {
      if (generation === state.generation) {
        error.textContent = explain(exception);
        await load().catch(() => {});
      }
    } finally {
      ui.setBusy(button, false);
    }
  }

  async function removeGrant(button) {
    const grant = state.grants.find((item) => item.id === button.dataset.grantId);
    const generation = state.generation;
    if (!grant) return;
    const label = `${PROTOCOL_NAMES[grant.protocol] || grant.protocol} · ${grant.runtime_username}`;
    const confirmed = await ui.confirmed("Удалить доступ?", `${label} будет удалён из протокола; на связанной панели — после доставки узлу.`, "Удалить");
    if (!confirmed || generation !== state.generation) return;
    try {
      ui.setBusy(button, true);
      await api(`/api/clients/grants/${encodeURIComponent(grant.id)}/delete`, { method: "POST" });
      if (generation !== state.generation) return;
      ui.toast("Доступ удалён");
      await load();
    } catch (exception) {
      if (generation === state.generation) placementError().textContent = explain(exception);
    } finally {
      ui.setBusy(button, false);
    }
  }

  function bind() {
    const dialog = query("#subscription-modal", root);
    if (!dialog) return;
    window.addEventListener("popstate", () => {
      if (state.management && !window.history.state?.clientManagement) closeManagement();
    });
    root.addEventListener("click", (event) => {
      if (!state.management || !state.management.page.contains(event.target)) return;
      if (event.target.closest("[data-management-back]")) return void window.history.back();
      const placement = event.target.closest("button[data-placement-action]");
      if (placement) return void apply(placement);
      const remove = event.target.closest("button[data-placement-delete]");
      if (remove) return void removeGrant(remove);
      const grant = event.target.closest("button[data-grant-open]");
      if (grant) context.grants.open(state.clientId, grant.dataset.grantOpen, { client: state.client, grants: state.grants });
    });
    dialog.addEventListener("click", (event) => {
      const subscription = event.target.closest("button[data-subscription-action]");
      if (subscription) return void act(subscription);
      const links = event.target.closest("button[data-links-action]");
      if (links) return void showLinks(links);
      const placement = event.target.closest("button[data-placement-action]");
      if (placement) return void apply(placement);
      const remove = event.target.closest("button[data-placement-delete]");
      if (remove) return void removeGrant(remove);
      const grant = event.target.closest("button[data-grant-open]");
      if (grant) context.grants.open(state.clientId, grant.dataset.grantOpen, { client: state.client, grants: state.grants });
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
      if (context.state.view === "clients") await reloadClientList(context);
    });
  }

  // The grant window changed something of this client: the open window follows.
  async function reloadIfOpen(clientId) {
    if ((!query("#subscription-modal", root)?.open && !state.management) || state.clientId !== clientId) return;
    await load().catch(() => {});
  }

  return { bind, open, openManagement, closeManagement, reloadIfOpen };
}
