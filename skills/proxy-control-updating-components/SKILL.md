---
name: proxy-control-updating-components
description: Use when asked to check for or install updates of Telemt, Mieru (mita), NaiveProxy (Caddy), the Xray-router or the panel itself on a Proxy Control panel or its nodes through the MCP server, or when a version shows as updating, upstream or rollback_failed.
---

# Updating components through the version-agent

The panel downloads nothing itself: the host agent installs a version, verifies it and rolls back on
failure. Your job is to choose what to install, in which order, and to check after every step.

## Steps

1. **Candidates**: `versions_check` — the central (the answer carries `components` with
   `available`); nodes — `overview` → `nodes[].status_json.versions` (the node's cache; the same
   candidates, upstream is shared). If a node's `checked_at` is older than a day, before installing
   on it run `post_nodes_by_node_id_versions_check` (`confirm`).
2. **The list** to the owner before installing: host × component, `current → version`, source
   (`catalog` — the operator's catalog; `upstream` — from the project's release, not verified on the
   lab host), what restarts. Install only after an explicit yes; the Xray-router on a node with live
   routing — a separate yes (a router on the central shows in `get_routing_targets` as
   `backend: xray_router` for `local`).
3. **One at a time**: a node — `post_nodes_by_node_id_versions_by_component(node_id, component,
   version, expected_current, confirm: true)`; the central — `versions_update(component, version,
   expected_current, confirm: true)`. `expected_current` is the actually installed version; a 409
   means someone already changed it — re-read.
4. **Verify** before the next step: `get_nodes_by_node_id` / `get_versions` → new `current`,
   `status: ready`, `protocols.<x>.daemon: ok`, the node `online` and `converged`.
5. **Summary**: a table «host × component: before → after» and what was left alone.

Host order: the node with the fewest accounts first, the central last. Components from cheap to
costly: `telemt` → `mita` → `xray` → `naive` → `panel`.

## What to know about each component

| Component | What happens | Check afterwards |
|---|---|---|
| `telemt` | image by digest, only `mtproxy` is recreated (seconds; MTProxy clients reconnect) | `daemon: ok`, connections return |
| `mita` | binary, restart of `mita` and its slots, `mieru-manager` recreated; a version outside the manager's window is marked `manager_unsupported` and is not installable | `daemon: ok`, `egress.restart_required` became `false`, `get_mieru_users` intact |
| `xray` | three router files, the container recreated; naive/mieru traffic through the router drops for seconds | `identity.router.available`, new `identity.router.xray_version`, `providers.warp.reachable`, naive/mieru `egress.providers.router.reachable` |
| `naive` | Caddy is built on the host (`docker build`), up to 15 minutes, «Собираем…»; a custom build (`-custom.N`) never updates from upstream, a 422 on its check is normal | `daemon: ok`, version |
| `panel` | the release archive, rebuild, restart; the answer is `async: true` | poll `get_versions` until `status` leaves `updating`; `pending_rebuild` names managers to rebuild by hand; then `reload_tools` |

## Stop rules

- `status: rollback_failed` — install nothing more; `last_error`, `audit_tail`,
  `get_operations_by_operation_id`; a person is needed on the host.
- A failed step, `daemon ≠ ok`, a node gone `offline`, `expected_current` mismatch — stop and report.
- A node with `node.down`/`node.up` in the last hour (`get_events`) — postpone it, re-check the
  events in an hour; if all nodes fell at once it was a central event, the nodes are not at fault.
- A release without a published digest is visible but the agent will not install it — do not offer it.
- «Update everything» ≠ everything at once: list → yes → one at a time with a check.
