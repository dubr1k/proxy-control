---
name: proxy-control-diagnosing-access
description: Use when a Proxy Control client reports that a proxy does not connect, a subscription «is there but nothing works», a protocol is missing in the app, or traffic stopped — and the investigation goes through the panel's MCP server before anyone opens SSH.
---

# Diagnosing a client's access

Cheap checks first, stop as soon as the cause is found. Usually 6–8 calls; the server side is most
often intact and the app or the link itself is to blame. After every step ask: does what I found
explain the symptom?

## Steps

| # | Call | What to look for |
|---|---|---|
| 1 | `get_clients` (grant details are already there; `get_clients_by_client_id` is not needed) | `client.state: active`; the grant has `desired_state: enabled`, `observed_state: enabled`, `valid_until` not passed |
| 2 | ask the owner | the app and the link variant; does another protocol from the same subscription work; does this protocol work for neighbours on the same node |
| 3 | `get_subscriptions_compatibility` | can this app take this protocol from a subscription. Mieru — only Karing (`singbox`) and mihomo (`clash`), everything else `unsupported` |
| 4 | `get_nodes_by_node_id` | `link.status: online`, fresh `link.last_heartbeat_at`, `observed_state: converged`; `protocols.<x>.daemon: ok`, `egress.restart_required`, `identity.router.available`, `providers.*.reachable` |
| 5 | `get_nodes_by_node_id_inventory` | the account exists on the node, `enabled`, `linked_grant_id` matches; neighbours on the protocol for comparison |
| 6 | `get_nodes_by_node_id_generations` | the resource `grant:<id>` — `state: enabled`, `error: null`; `reconcile_state: converged` — the exact answer to «did it reach the node» |
| 7 | `audit_tail` without `target`, limit 40, read `action` | `subscription.rotate/revoke`, `grant.disable`, `client.state`, `routing.*.apply`; the subscription's state without a reveal is visible only here. An import is written with `target` = the node, so an imported grant's own audit is empty |
| 8 | `get_routing_policies_by_node_id_by_protocol` + `…_explain` | only when specific sites fail. `404 policy_not_found` = no policy, the default applies, `explain` is pointless |

Beyond that the panel cannot see: `mita`/Caddy/Telemt logs and restarts are SSH only — say so.
Mieru has no traffic counters (`traffic: null`); that does not mean «nobody connects».

## Symptom → likely cause

| Symptom | Cause |
|---|---|
| The protocol is missing from the app's server list | the link variant does not carry it (`singbox`: naive+mieru; `singbox-official`: naive; `clash`: mieru; `raw`: everything, no refresh) or the app does not support it |
| Mieru «connects» but no data flows | the app uses UDP or a port range; our Mieru is **TCP only**, server-side UDP was verified — the client side is at fault |
| Nobody on the node works | the node `offline`, not `converged`, WARP `reachable: false`, `restart_required` after an egress change (the daemon runs the old configuration; cleared by a restart on the host or a `mita` update) |
| One person does not work | the grant `disabled`, expiry, `archived`, the subscription revoked or rotated (audit) |
| Sites open partially | the policy: an exit disabled, a block rule, stale geodata |
| The subscription does not refresh | `raw` never refreshes, nor does a Telegram proxy — re-send the link |
| A grant on a linked node «issued» but not working | the operation is `pending_remote`: the node was offline — `get_operations_by_operation_id` |

## What not to do

- Do not rotate or revoke the subscription «just in case» — it breaks the people it works for.
- Do not apply a policy or restart anything before the cause is named; any change is a separate
  agreement with `confirm`.
- Do not call `client_subscription` needlessly: every reveal lands in the audit log.
- Do not filter the audit by the client's or grant's `target` on a guess — one unfiltered call is
  cheaper than three empty ones.

## Report to the owner

The cause (or the two most likely ones and how to tell them apart — most often «does it work for a
neighbour on the same node»), what was checked and is intact, what to do and by whom (the client,
the panel, SSH), in 5–8 lines.
