// Where a client lives: one row per node, one column per protocol, one grant per cell.
// Pure functions — the dialogs render the HTML and hand the ticks back here for the diff,
// so «Новый клиент» and the client window share one definition of what a tick means.
import { esc } from "./common.js";

export const PROTOCOLS = ["mtproxy", "naive", "mieru"];
export const PROTOCOL_NAMES = { mtproxy: "MTProxy", naive: "NaiveProxy", mieru: "Mieru" };

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
    for (const protocol of PROTOCOLS) cells[protocol] = live.find((g) => g.node_id === id && g.protocol === protocol) || null;
    return { node_id: id, label: label(node), offered: offered(node), cells };
  });
}

function cell(row, protocol, canWrite) {
  const grant = row.cells[protocol];
  const ticked = grant !== null && grant.desired_state === "enabled";
  const locked = !canWrite || !row.offered;
  // Deleting an existing grant never needs the node reachable, so it stays available even on
  // a row that is not currently offered (a paused linked panel) — only new ticks are locked.
  const remove = canWrite && grant
    ? `<button type="button" class="ghost danger-text" data-placement-delete data-grant-id="${esc(grant.id)}" title="Удалить доступ">×</button>`
    : "";
  return `<td class="placement-cell">
    <label><input type="checkbox" data-node="${esc(row.node_id)}" data-protocol="${esc(protocol)}"${ticked ? " checked" : ""}${locked ? " disabled" : ""}>
    <small>${esc(cellStatus(grant))}</small></label>${remove}
  </td>`;
}

export function renderPlacement(rows, { canWrite }) {
  const head = PROTOCOLS.map((protocol) => `<th>${esc(PROTOCOL_NAMES[protocol])}</th>`).join("");
  const body = rows.map((row) => `<tr data-placement-node="${esc(row.node_id)}"${row.offered ? "" : ' class="placement-row-locked"'}>
    <th scope="row">${esc(row.label)}${row.offered ? "" : " <small>панель на паузе</small>"}</th>
    ${PROTOCOLS.map((protocol) => cell(row, protocol, canWrite)).join("")}
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
    for (const protocol of PROTOCOLS) {
      const grant = row.cells[protocol];
      const ticked = checked.has(`${row.node_id}:${protocol}`);
      if (ticked && grant === null) diff.create.push({ protocol, node_id: row.node_id, runtime_username: username, options: {} });
      else if (ticked && grant.desired_state === "disabled") diff.enable.push(grant.id);
      else if (!ticked && grant !== null && grant.desired_state === "enabled") diff.disable.push(grant.id);
    }
  }
  return diff;
}
