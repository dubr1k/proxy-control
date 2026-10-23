// Where a client lives: one row per node, one column per protocol, one grant per cell.
// Pure functions — the dialogs render the HTML and hand the ticks back here for the diff,
// so «Новый клиент» and the client window share one definition of what a tick means.
import { esc } from "./common.js";

export const PROTOCOLS = ["mtproxy", "naive", "mieru", "trusttunnel"];
export const PROTOCOL_NAMES = { mtproxy: "MTProxy", naive: "NaiveProxy", mieru: "Mieru", amneziawg: "AmneziaWG", trusttunnel: "TrustTunnel" };

// AmneziaWG versions are not compatible with each other, so each one is its own column and a
// client can hold several: one grant per node and version, named `<account>-awg<ver>`.
export const AWG_VERSIONS = ["1.5", "2.0", "3.1"];
const BASE_COLUMNS = PROTOCOLS.map((protocol) => ({ key: protocol, protocol, version: null }));
const AWG_COLUMNS = AWG_VERSIONS.map((version) => ({ key: `amneziawg:${version}`, protocol: "amneziawg", version }));

export function columnName(column) {
  return column.version ? `AmneziaWG ${column.version}` : PROTOCOL_NAMES[column.protocol];
}

// The versions a node's manager serves: a linked panel reports them in `link.identity`,
// the local server in `identity.awg_versions`.
export function awgVersions(node) {
  const linked = node?.link?.identity?.protocols?.amneziawg;
  if (linked && linked.enabled !== false && Array.isArray(linked.versions)) return linked.versions;
  return Array.isArray(node?.identity?.awg_versions) ? node.identity.awg_versions : [];
}

// An AmneziaWG column appears once some node serves that version or a grant already uses it.
export function columnsFor(rows) {
  const shown = new Set();
  for (const row of rows) {
    for (const version of row.awg) shown.add(version);
    for (const version of Object.keys(row.cells)) if (row.cells[version] && version.startsWith("amneziawg:")) shown.add(version.slice(10));
  }
  return [...BASE_COLUMNS, ...AWG_COLUMNS.filter((column) => shown.has(column.version))];
}

// A runtime account on the node's manager: lower case, `[a-z0-9._-]`, the version in the name
// so one client can hold every version at once.
export function awgAccount(username, version) {
  const suffix = `-awg${version.replace(".", "")}`;
  const base = (username || "client").toLowerCase().replace(/[^a-z0-9._-]/g, "-").replace(/^[^a-z0-9]+/, "") || "client";
  return base.slice(0, 64 - suffix.length) + suffix;
}

function granted(live, id, column) {
  return live.find((g) => g.node_id === id && g.protocol === column.protocol
    && (column.version === null || g.options?.version === column.version)) || null;
}

const OBSERVED = { pending: "ожидает узел", failed: "ошибка", drifted: "расхождение", missing: "удалён" };

function offered(node) {
  return node.node_id === "local" || (node.transport === "panel" && node.link?.enabled === true);
}

function label(node) {
  return node.node_id === "local" ? "Этот сервер" : node.display_name || node.node_id;
}

// A grant's state in one phrase: what the card says, shortened to fit a cell. A grant can be
// both mid-transition (pending/disabled/...) and missing a secret at once, so both parts show,
// joined with " · " — the two facts are independent, not alternatives.
export function cellStatus(grant) {
  if (!grant) return "";
  if (grant.observed_state === "failed") return grant.last_error ? `ошибка: ${grant.last_error}` : "ошибка";
  const parts = [];
  if (OBSERVED[grant.observed_state]) parts.push(OBSERVED[grant.observed_state]);
  else if (grant.desired_state === "disabled") parts.push("выключен");
  else parts.push("включён");
  if (grant.secret_ref === null || grant.secret_ref === undefined) parts.push("без секрета");
  return parts.join(" · ");
}

// «Ожидает узел» — состояние на полпути: центр записал доступ, узел ещё не подтвердил его.
// Доставляет pusher, поэтому клетка меняется без участия оператора — по этому признаку
// карточка решает, нужно ли перечитать клиента, вместо того чтобы оставить на экране
// подпись, которая уже неверна.
export function settling(grants) {
  return grants.some((grant) => grant.desired_state !== "deleted" && grant.observed_state === "pending");
}

export function placementRows(nodes, grants) {
  const live = grants.filter((grant) => grant.desired_state !== "deleted");
  const known = new Map();
  for (const node of nodes) known.set(node.node_id, node);
  const ids = [];
  for (const node of nodes) if (offered(node)) ids.push(node.node_id);
  for (const grant of live) if (!ids.includes(grant.node_id)) ids.push(grant.node_id);
  if (!ids.includes("local")) ids.unshift("local");
  return ids.map((id) => {
    const node = known.get(id) || { node_id: id, display_name: id };
    const cells = {};
    for (const column of [...BASE_COLUMNS, ...AWG_COLUMNS]) cells[column.key] = granted(live, id, column);
    return { node_id: id, label: label(node), offered: offered(node), cells, awg: awgVersions(node), trusttunnel: node.identity?.protocols?.trusttunnel?.enabled !== false };
  });
}

function cell(row, column, canWrite) {
  const grant = row.cells[column.key];
  const ticked = grant !== null && grant.desired_state === "enabled";
  // A node that does not serve this AmneziaWG version cannot take a new one; an existing grant stays.
  const unserved = grant === null && (column.version !== null ? !row.awg.includes(column.version) : (column.protocol === "trusttunnel" && row.trusttunnel === false));
  const locked = !canWrite || !row.offered || unserved;
  // Deleting an existing grant never needs the node reachable, so it stays available even on
  // a row that is not currently offered (a paused linked panel) — only new ticks are locked.
  const remove = canWrite && grant
    ? `<button type="button" class="ghost danger-text" data-placement-delete data-grant-id="${esc(grant.id)}" title="Удалить доступ">×</button>`
    : "";
  return `<td class="placement-cell">
    <label><input type="checkbox" data-node="${esc(row.node_id)}" data-protocol="${esc(column.key)}"${ticked ? " checked" : ""}${locked ? " disabled" : ""}>
    <small>${esc(cellStatus(grant))}</small></label>${remove}
  </td>`;
}

export function renderPlacement(rows, { canWrite }) {
  const columns = columnsFor(rows);
  const head = columns.map((column) => `<th>${esc(columnName(column))}</th>`).join("");
  const body = rows.map((row) => `<tr data-placement-node="${esc(row.node_id)}"${row.offered ? "" : ' class="placement-row-locked"'}>
    <th scope="row">${esc(row.label)}${row.offered ? "" : " <small>панель на паузе</small>"}</th>
    ${columns.map((column) => cell(row, column, canWrite)).join("")}
  </tr>`).join("");
  return `<div class="placement-scroll"><table class="placement"><thead><tr><th>Узел</th>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

export function readPlacement(root) {
  const checked = new Set();
  root.querySelectorAll("input[data-node][data-protocol]:checked").forEach((box) => {
    checked.add(`${box.dataset.node}:${box.dataset.protocol}`);
  });
  return checked;
}

// Ticks against rows: a tick without a grant creates, a tick on a disabled grant enables,
// a missing tick on an enabled grant disables. Rows that are not offered never change.
export function placementDiff(rows, checked, username) {
  const diff = { create: [], enable: [], disable: [] };
  for (const row of rows) {
    if (!row.offered) continue;
    for (const column of columnsFor(rows)) {
      const grant = row.cells[column.key];
      const ticked = checked.has(`${row.node_id}:${column.key}`);
      if (ticked && grant === null) {
        diff.create.push(column.version
          ? { protocol: column.protocol, node_id: row.node_id, runtime_username: awgAccount(username, column.version), options: { version: column.version } }
          : { protocol: column.protocol, node_id: row.node_id, runtime_username: username, options: {} });
      }
      else if (ticked && grant && grant.desired_state === "disabled") diff.enable.push(grant.id);
      else if (!ticked && grant !== null && grant.desired_state === "enabled") diff.disable.push(grant.id);
    }
  }
  return diff;
}
