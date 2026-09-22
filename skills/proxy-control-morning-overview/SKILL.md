---
name: proxy-control-morning-overview
description: Use when asked how the Proxy Control panel and its nodes are doing — a morning check, a status report, «что было за сутки», before a planned change, or whenever a summary of the fleet's health is wanted through the MCP server.
---

# Overview of the panel and its nodes

Four read calls; the report is short and starts with what needs action. Change nothing, reveal
nothing; `overview` and `get_*` write no audit rows.

## What to read

| Call | Fields |
|---|---|
| `overview` → `dashboard` | `health.ready`, `admission`, `resources` (CPU/memory/disk), `protocols.*.ok/ready`, `connections`, accounts |
| `overview` → `nodes[]` | `link.status` (`online`/`offline`), `link.last_heartbeat_at` — the node's freshness (`last_checked_at` is the link time, not freshness); `observed_state: converged`; `desired_generation` = `acknowledged_generation`; `latency_ms`; `status_json`: `protocols.*.daemon`, `warnings`, `identity.router.available`, `providers.warp.reachable`, `versions` (the node's cache, `checked_at`) |
| `overview` → `versions` | `available[].source: upstream` = newer than installed; a component's `status` (`ready`/`updating`/`rollback_failed`) |
| `get_events` (limit 200) | `node.down`/`node.up`. All nodes at once — a central event (network/docker), not the nodes; one node many times — its link |
| `audit_tail` (limit 40, no more — `detail_json` bloats the answer) | `actor_username`: the owner, `installer`, `system`, `key:mcp` (actions through MCP); `action`: `client.*`, `grant.*`, `subscription.*`, `routing.*`, `admin.*`, `api_key.*`, `runtime.version.*` |
| `get_admins` | surplus or temporary administrators, keys without an expiry |

## What counts as a problem

- a node `offline`, `observed_state ≠ converged`, `desired_generation ≠ acknowledged_generation`,
  a heartbeat older than 5 minutes;
- `rollback_failed` — updates are blocked until a person intervenes; `updating` for over an hour;
- disk > 85 %, memory > 90 %, `health.ready: false`, `daemon ≠ ok`;
- new keys, administrators, deletions or subscription rotations in the audit log the owner did not
  expect; temporary administrators that did not remove themselves (`get_admins`).

Not a problem: `egress.restart_required: true` on Mieru and on the router (a constant: applying an egress change restarts that daemon; it is not a pending state); `tls_handshake_bad_client` in MTProxy counters (scanners); `adopts_unmanaged_*` on
nodes without a router (a hand-made egress the panel adopted); `422` on the upstream check of a
custom NaiveProxy build; a node's `versions` older than the central's (cached until its next check);
node latency of seconds while polling.

## Report shape

1. **Needs attention** — 0–5 items, each with a proposed action; one line if empty.
2. **Panel** — version, health, resources in one line, live connections.
3. **Nodes** — one line per node: online, generation, remarks.
4. **Last 24 hours** — events and audit, only what matters, with times.
5. **Updates** — what is available, one line; do not install (that is another skill).

Do not retell JSON, do not list users, do not reveal subscriptions or keys. Convert unix time to
date and time; the zone is the one the owner named, otherwise the local one.
