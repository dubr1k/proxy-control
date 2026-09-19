import { api } from "./api.js";
import { createAccessDialogs } from "./access.js";
import { handleAuditClick, handleAuditSubmit, renderAudit } from "./audit.js";
import { bindClients, handleClientsClick, openClientModal, renderClients } from "./clients.js";
import { query, queryAll } from "./common.js";
import { renderDashboard } from "./dashboard.js";
import { handleFleetChange, handleFleetClick, handleFleetSubmit } from "./fleet.js";
import { bindKeys, handleKeysClick } from "./keys.js";
import {
  bindManagement,
  handleManagementChange,
  handleManagementClick,
  openAdminModal,
  renderAdmins,
  renderVersions,
  ROLE_NAMES,
} from "./management.js";
import { bindMieru, handleMieruClick, openMieruModal, renderMieru } from "./mieru.js";
import { bindNodes, handleNodesClick, openLinkModal, renderNodes } from "./nodes.js";
import { bindNaive, handleNaiveClick, handleNaiveInput, openNaiveModal, renderNaive } from "./naive.js";
import {
  bindRouting,
  handleRoutingChange,
  handleRoutingClick,
  handleRoutingInput,
  handleRoutingSubmit,
  renderRouting,
} from "./routing.js";
import { createPanelState } from "./state.js";
import { createSubscriptionDialog } from "./subscriptions.js";
import { createUi } from "./ui.js";
import { bindUsers, handleUsersClick, handleUsersInput, openUserModal, renderUsers } from "./users.js";

const TITLES = {
  dashboard: ["Обзор", "Состояние всех прокси-протоколов в одном месте"],
  clients: ["Клиенты", "Абоненты и их доступы MTProxy · Naive · Mieru"],
  mieru: ["Mieru", "Пользователи, rolling-квоты и application-byte трафик"],
  users: ["MTProxy", "Пользователи, ссылки и ключи доступа"],
  naive: ["NaiveProxy", "HTTPS-прокси, конфигурации и доступы"],
  versions: ["Версии", "Проверенные обновления runtime-компонентов"],
  fleet: ["Узлы", "Связанные панели, этот сервер и узлы v1; raw-команды Telemt v1 — в Advanced"],
  routing: ["Маршрутизация", "Куда сервисы выпускают трафик: напрямую, через WARP или блокировка — с честным предпросмотром по backend узла"],
  admins: ["Администраторы", "Роли, доступ к панели и API-ключи"],
  audit: ["Журнал действий", "Изменения, входы и операции с ключами"],
};

const RENDERERS = {
  dashboard: renderDashboard,
  clients: renderClients,
  users: renderUsers,
  mieru: renderMieru,
  naive: renderNaive,
  versions: renderVersions,
  fleet: renderNodes,
  routing: renderRouting,
  admins: renderAdmins,
  audit: renderAudit,
};

function createNavigator(context) {
  return async function navigate(name) {
    const renderer = RENDERERS[name];
    if (!renderer) return;
    const generation = ++context.state.navigationGeneration;
    context.state.view = name;
    const [title, subtitle] = TITLES[name];
    query("#title", context.root).textContent = title;
    query("#subtitle", context.root).textContent = subtitle;
    queryAll("[data-view]", context.root).forEach((button) => button.classList.toggle("active", button.dataset.view === name));
    // The phone bar scrolls sideways: the current section is brought into view and the
    // edges say there is more (v0.9 — «Узлы» and «Маршруты» used to sit off-screen without a hint).
    query(".mobile-nav .active", context.root)?.scrollIntoView?.({ inline: "center", block: "nearest" });
    markMobileNavEdges(context.root);

    const canCreate = (context.state.me?.role !== "viewer" && ["users", "naive", "mieru", "clients"].includes(name))
      || (name === "fleet" && context.state.me?.role === "owner")
      || (name === "admins" && context.state.me?.role === "owner");
    const add = query("#add", context.root);
    add.hidden = !canCreate;
    query("#add-label", context.root).textContent = {
      admins: "Администратора",
      clients: "Клиента",
      fleet: "Панель",
      naive: "Naive доступ",
      mieru: "Mieru доступ",
      users: "Подключение",
    }[name] || "Добавить";

    context.ui.renderSkeleton();
    try {
      await renderer(context, generation);
    } catch (error) {
      if (context.state.navigationGeneration === generation && context.state.view === name) context.ui.renderError(error);
    }
  };
}

function bindLogin(root) {
  const form = query("#login", root);
  if (!form) return false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = query("button", form);
    const error = query("#error", root);
    error.textContent = "";
    const previous = button.textContent;
    try {
      button.textContent = "Входим…";
      button.disabled = true;
      await api("/api/auth/login", { method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(form))) });
      window.location.assign("/");
    } catch (exception) {
      error.textContent = exception.message;
      button.textContent = previous;
      button.disabled = false;
    }
  });
  const transport = query("#transport-state", root);
  if (transport) {
    const secure = window.location.protocol === "https:";
    transport.classList.toggle("degraded", !secure);
    transport.lastChild.textContent = secure ? " Защищённое HTTPS-соединение" : " HTTP-соединение не защищено";
  }
  return true;
}

// `more-left` / `more-right` on the phone bar: which side still hides sections; the CSS
// fades that edge so the operator sees the bar goes on.
function markMobileNavEdges(root) {
  const bar = query(".mobile-nav", root);
  if (!bar) return;
  bar.classList.toggle("more-left", bar.scrollLeft > 12);
  bar.classList.toggle("more-right", bar.scrollLeft + bar.clientWidth < bar.scrollWidth - 4);
}

function bindPanel(context) {
  const { root, ui } = context;
  queryAll("[data-view]", root).forEach((button) => button.addEventListener("click", () => context.navigate(button.dataset.view)));
  query(".mobile-nav", root)?.addEventListener("scroll", () => markMobileNavEdges(root), { passive: true });
  window.addEventListener("resize", () => markMobileNavEdges(root));
  markMobileNavEdges(root);
  query("#add", root).addEventListener("click", () => {
    if (context.state.view === "admins") openAdminModal(context);
    else if (context.state.view === "clients") void openClientModal(context);
    else if (context.state.view === "fleet") openLinkModal(context);
    else if (context.state.view === "naive") openNaiveModal(context);
    else if (context.state.view === "mieru") openMieruModal(context);
    else openUserModal(context);
  });
  query("#refresh", root).addEventListener("click", ({ currentTarget: button }) => {
    ui.setBusy(button, true, "…");
    context.navigate(context.state.view).finally(() => ui.setBusy(button, false));
  });
  query("#logout", root).addEventListener("click", async () => {
    try {
      await context.api("/api/auth/logout", { method: "POST" });
      window.location.assign("/login");
    } catch (error) {
      ui.toast(error.message, "error");
    }
  });
  query("#mobile-logout", root)?.addEventListener("click", () => query("#logout", root).click());
  // The chevron promises a menu, so there is one: who is signed in, the screens that belong to
  // the account (admins with passwords and API keys, the journal — as the role allows) and sign-out.
  const profileButton = query("#profile-button", root);
  const profileMenu = query("#profile-menu", root);
  const setProfileMenu = (open) => {
    profileMenu.hidden = !open;
    profileButton.setAttribute("aria-expanded", String(open));
    if (open) profileMenu.querySelector("button:not([hidden])")?.focus();
  };
  profileButton.addEventListener("click", () => setProfileMenu(profileMenu.hidden));
  profileMenu.addEventListener("click", (event) => {
    const item = event.target.closest("[data-profile-action]");
    if (!item) return;
    setProfileMenu(false);
    if (item.dataset.profileAction === "logout") query("#logout", root).click();
    else void context.navigate(item.dataset.profileAction);
  });
  document.addEventListener("click", (event) => {
    if (!profileMenu.hidden && !profileMenu.contains(event.target) && !profileButton.contains(event.target)) setProfileMenu(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !profileMenu.hidden) { setProfileMenu(false); profileButton.focus(); }
  });

  bindUsers(context);
  bindClients(context);
  bindMieru(context);
  bindNaive(context);
  bindNodes(context);
  bindRouting(context);
  bindManagement(context);
  bindKeys(context);
  context.access.bind();
  context.subscriptions.bind();

  ui.view.addEventListener("input", (event) => {
    handleRoutingInput(context, event.target) || handleUsersInput(context, event.target) || handleNaiveInput(context, event.target);
  });
  ui.view.addEventListener("change", (event) => {
    handleRoutingChange(context, event.target) || handleManagementChange(context, event.target) || handleFleetChange(context, event.target);
  });
  ui.view.addEventListener("submit", (event) => {
    event.preventDefault();
    handleRoutingSubmit(context, event.target) || handleFleetSubmit(context, event.target) || handleAuditSubmit(context, event.target);
  });
  ui.view.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    if (button.dataset.action === "retry") {
      void context.navigate(context.state.view);
      return;
    }
    if (handleAuditClick(context, button)) return;
    if (handleRoutingClick(context, button)) return;
    if (handleClientsClick(context, button)) return;
    if (handleNodesClick(context, button)) return;
    if (handleFleetClick(context, button)) return;
    if (handleManagementClick(context, button)) return;
    if (handleKeysClick(context, button)) return;
    if (handleMieruClick(context, button)) return;
    if (handleNaiveClick(context, button)) return;
    handleUsersClick(context, button);
  });
}

async function initialise(context) {
  try {
    context.state.me = await context.api("/api/auth/me");
    query("#profile-name", context.root).textContent = context.state.me.username;
    query("#profile-role", context.root).textContent = ROLE_NAMES[context.state.me.role] || context.state.me.role;
    query("#profile-menu-name", context.root).textContent = context.state.me.username;
    query("#profile-menu-role", context.root).textContent = ROLE_NAMES[context.state.me.role] || context.state.me.role;
    query("#avatar", context.root).textContent = context.state.me.username.slice(0, 2).toUpperCase();
    queryAll('[data-view="naive"]', context.root).forEach((item) => { item.hidden = context.state.me.features?.naive !== true; });
    queryAll('[data-view="mieru"]', context.root).forEach((item) => { item.hidden = context.state.me.features?.mieru !== true; });
    queryAll(".owner-only", context.root).forEach((item) => { item.hidden = context.state.me.role !== "owner"; });
    queryAll(".audit-nav", context.root).forEach((item) => { item.hidden = false; });
    await context.navigate("dashboard");
  } catch (error) {
    context.ui.renderError(error);
  }
}

export function boot(root = document) {
  if (bindLogin(root)) return;
  if (!query("#view", root)) return;
  const context = {
    root,
    api,
    state: createPanelState(),
    ui: createUi(root),
    access: null,
    subscriptions: null,
    navigate: null,
  };
  context.access = createAccessDialogs(context);
  context.subscriptions = createSubscriptionDialog(context);
  context.navigate = createNavigator(context);
  bindPanel(context);
  void initialise(context);
}
