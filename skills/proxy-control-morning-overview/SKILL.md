---
name: proxy-control-morning-overview
description: Use when asked how the Proxy Control panel and its nodes are doing — a morning check, a status report, «что было за сутки», before a planned change, or whenever a summary of the fleet's health is wanted through the MCP server.
---

# Overview of the panel and its nodes

Four read calls (the first already carries the live meters); the report is short and starts with what needs action. Change nothing, reveal
nothing; `overview` and `get_*` write no audit rows.

## What to read

| Call | Fields |
|---|---|
| `overview` → `dashboard` | `health.ready`, `admission`, `resources` (CPU/memory/disk), `protocols.*.ok/ready` (including `protocols.trusttunnel`: `status` `ready`/`degraded`/`disabled`, accesses and traffic), `connections`, accounts |
| `overview` → `nodes[]` | `link.status` (`online`/`offline`), `link.last_heartbeat_at` — the node's freshness (`last_checked_at` is the link time, not freshness); `observed_state: converged`; `desired_generation` = `acknowledged_generation`; `latency_ms`; `status_json`: `protocols.*.daemon`, `warnings`, `identity.router.available`, `providers.warp.reachable`, `versions` (the node's cache, `checked_at`) |
| `overview` → `metrics.nodes[]` | per node: `status` (`ok`/`stale`/`unavailable`/`unsupported`), `age_seconds`; `cpu_percent`, `mem_percent`, `disk_percent`, `load1`; `net_rx_bps`/`net_tx_bps`; `protocols.<x>.up_bps`/`down_bps`/`sessions` (only protocols that are measurable; ↑ = from clients, ↓ = to clients, bytes per second, network layer); `alerts[]` (`kind`, `severity` `warn`/`critical`, `detail`). `metrics: null` = monitoring is off or the call failed — say so, do not guess |
| `get_metrics_summary` (`range=24h`, `node=all`) | only when «what happened over the day» is asked: per node CPU/memory peaks and averages, `protocols.<x>.total_bytes`, `peak_bps`, `share_percent`; `compare` ranks nodes by traffic |
| `overview` → `versions` | `available[].source: upstream` = newer than installed; a component's `status` (`ready`/`updating`/`rollback_failed`) |
| `get_events` (limit 200) | `node.down`/`node.up`. All nodes at once — a central event (network/docker), not the nodes; one node many times — its link |
| `audit_tail` (limit 40, no more — `detail_json` bloats the answer) | `actor_username`: the owner, `installer`, `system`, `key:mcp` (actions through MCP); `action`: `client.*`, `grant.*`, `subscription.*`, `routing.*`, `admin.*`, `api_key.*`, `runtime.version.*` |
| `get_admins` | surplus or temporary administrators, keys without an expiry |

## What counts as a problem

- a node `offline`, `observed_state ≠ converged`, `desired_generation ≠ acknowledged_generation`,
  a heartbeat older than 5 minutes;
- `rollback_failed` — updates are blocked until a person intervenes; `updating` for over an hour;
- a metrics alert with `severity: critical`, or `warn` that is still there; `status: stale` (the node's agent is not answering) or `unsupported` (a node older than 2.0); disk > 85 %, memory > 90 %, `health.ready: false`, `daemon ≠ ok`; TrustTunnel `degraded` (most often `certificate_missing`: the domain's certificate is not issued yet);
- new keys, administrators, deletions or subscription rotations in the audit log the owner did not
  expect; temporary administrators that did not remove themselves (`get_admins`).

Not a problem: a protocol absent from `metrics.nodes[].protocols` (not enabled there, or Mieru without counters); a few seconds of `stale` right after a node's agent restart; `egress.restart_required: true` on Mieru and on the router (a constant: applying an egress change restarts that daemon; it is not a pending state); a few brief TrustTunnel reconnects after an access was added, changed or disabled (the endpoint restarts on every credential change); `protocols.trusttunnel.status: disabled` on a node that was never meant to serve it; `tls_handshake_bad_client` in MTProxy counters (scanners); `adopts_unmanaged_*` on
nodes without a router (a hand-made egress the panel adopted); `422` on the upstream check of a
custom NaiveProxy build; a node's `versions` older than the central's (cached until its next check);
node latency of seconds while polling.

## Report shape

1. **Needs attention** — 0–5 items, each with a proposed action; one line if empty.
2. **Panel** — version, health, resources in one line (CPU/RAM/disk from `metrics`), live connections.
3. **Nodes** — one line per node: online, generation, load, the busiest protocol right now (rate and sessions), alerts, remarks.
4. **Last 24 hours** — events and audit, only what matters, with times.
5. **Updates** — what is available, one line; do not install (that is another skill).

Do not retell JSON, do not list users, do not reveal subscriptions or keys. Convert unix time to
date and time; the zone is the one the owner named, otherwise the local one.
