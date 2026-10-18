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
| 3 | `get_subscriptions_compatibility` | can this app take this protocol from a subscription. Mieru — only Karing (`singbox`) and mihomo (`clash`), everything else `unsupported`. TrustTunnel — mihomo only (`supported`); Karing, Shadowrocket, NekoBox, v2rayN are `unproven`, the sing-box family `unsupported`; the official AdGuard TrustTunnel apps take the `tt://` link, not a feed |
| 4 | `get_nodes_by_node_id` | `link.status: online`, fresh `link.last_heartbeat_at`, `observed_state: converged`; `protocols.<x>.daemon: ok`, `identity.router.available`, `providers.*.reachable` |
| 5 | `get_nodes_by_node_id_inventory` | the account exists on the node, `enabled`, `linked_grant_id` matches; neighbours on the protocol for comparison |
| 6 | `get_nodes_by_node_id_generations` | the resource `grant:<id>` — `state: enabled`, `error: null`; `reconcile_state: converged` — the exact answer to «did it reach the node» |
| 7 | `audit_tail` without `target`, limit 40, read `action` | `subscription.rotate/revoke`, `grant.disable`, `client.state`, `routing.*.apply`; the subscription's state without a reveal is visible only here. An import is written with `target` = the node, so an imported grant's own audit is empty |
| 8 | `get_routing_policies_by_node_id_by_protocol` + `…_explain` | only when specific sites fail. `404 policy_not_found` = no policy, the default applies, `explain` is pointless |

Beyond that the panel cannot see: `mita`/Caddy/Telemt logs and restarts are SSH only — say so.
Mieru has no traffic counters (`traffic: null`); that does not mean «nobody connects». TrustTunnel counts traffic per access in the manager (the counters survive restarts).

## Symptom → likely cause

| Symptom | Cause |
|---|---|
| The protocol is missing from the app's server list | the link variant does not carry it (`singbox`: naive+mieru; `singbox-official`: naive; `clash`: mieru and trusttunnel; `raw`: everything, no refresh) or the app does not support it. TrustTunnel is never in a sing-box feed (sing-box has no outbound for it) |
| Mieru «connects» but no data flows | the app uses UDP or a port range; our Mieru is **TCP only**, server-side UDP was verified — the client side is at fault |
| TrustTunnel: nobody connects, the manager is `degraded` | `get_dashboard` → `protocols.trusttunnel` (`status`, `ready`) or the node's `protocols.trusttunnel.daemon`; `degraded` with `certificate_missing` = the domain's certificate is not issued or readable (the owner issues it; the manager picks a renewal up by itself); `endpoint_down` = the endpoint process is not running |
| TrustTunnel: the app is refused on connect | the profile holds an IP address or another name instead of the TrustTunnel **domain** (the endpoint accepts only that SNI), or the domain is behind a CDN proxy (it must be DNS only); a 407 means the name/password is wrong, the access is disabled, or a rotation replaced the password |
| TrustTunnel: sessions drop for seconds, then come back | expected: any credential change (a new, changed or disabled access, an Xray-router attach or detach) restarts the endpoint; changes within ~2 s are merged. Look at `audit_tail` for what happened a moment before, and do not «fix» it |
| TrustTunnel works direct but not through WARP or an exit | routing: `get_routing_targets` for `trusttunnel` — `router_lacks_trusttunnel` (rebuild the node's router) or `node_lacks_trusttunnel_egress` (update the node); its policy is for the whole service, there are no per-client lanes |
| Nobody on the node works | the node `offline`, not `converged`, WARP `reachable: false`, a daemon `≠ ok`. (`egress.restart_required: true` on Mieru and the router is a constant — «applying restarts the daemon» — not a pending state) |
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
