import { paintClientsCount, query } from "./common.js";

// The sidebar badges belong to the whole panel, not to the section that happens to be open
// (owner, 2026-10-18: the numbers appeared only after a click on each section, and a panel
// opened straight on `#clients` kept dashes everywhere else). One call fills all of them; a
// list that did not load shows the dash, never a stale or invented number.
const REFRESH_MS = 60_000;

async function listLength(context, path) {
  try {
    return ((await context.api(path)).items || []).length;
  } catch {
    return null;
  }
}

export const fleetCount = (context) => listLength(context, "/api/fleet/nodes");
// The badge is working clients: archived ones have their own pill on the Clients screen.
export async function clientsCount(context) {
  try {
    return ((await context.api("/api/clients")).items || []).filter((entry) => entry.client?.state !== "archived").length;
  } catch {
    return null;
  }
}
const usersCount = (context) => listLength(context, "/api/users");

async function dashboardData(context) {
  try {
    return await context.api("/api/dashboard");
  } catch {
    return null;
  }
}

function paintBadge(context, selector, value) {
  const badge = query(selector, context.root);
  if (badge) badge.textContent = value ?? "—";
}

export function paintNavCounts(context, data, nodes) {
  const protocols = data?.protocols || {};
  const total = (credentials) => (
    credentials && credentials.available !== false && credentials.total != null ? credentials.total : null
  );
  paintBadge(context, "#mieru-count", total(protocols.mieru?.credentials));
  paintBadge(context, "#naive-count", total(protocols.naive?.credentials));
  paintBadge(context, "#amneziawg-count", total(protocols.amneziawg?.credentials));
  paintBadge(context, "#trusttunnel-count", total(protocols.trusttunnel?.credentials));
  paintBadge(context, "#fleet-count", nodes);
}

export async function refreshNavCounts(context) {
  const [data, users, nodes, clients] = await Promise.all([
    dashboardData(context),
    usersCount(context),
    fleetCount(context),
    clientsCount(context),
  ]);
  paintNavCounts(context, data, nodes);
  paintBadge(context, "#users-count", users);
  paintClientsCount(context, clients);
}

// Fresh while the tab is in front; a hidden tab asks for nothing.
export function startNavCountsRefresh(context) {
  if (context.state.navCountsTimer) return;
  context.state.navCountsTimer = window.setInterval(() => {
    if (!document.hidden) void refreshNavCounts(context);
  }, REFRESH_MS);
}
