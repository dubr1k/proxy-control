---
name: proxy-control-changing-routing
description: Use when asked to change where a node's proxy traffic goes through the Proxy Control MCP server — block torrents or ads, send some sites direct, route through WARP, a custom exit or another node, give one client its own lane, or roll a routing change back.
---

# Changing routing

One policy per (node, protocol): `default_action` plus first-match `rules`. Saving makes a draft;
`routing_apply` puts it on the node as a transaction with rollback. Never apply without a
`supported` preview and the owner's yes.

## Steps

1. **Target**: `get_routing_targets` — nodes × protocols, `backend` (`xray_router` or native),
   `matches_node`, what is applied. Blocking by protocol, `geosite`/`geoip`, ports and lanes need
   `xray_router`; native backends answer `rule_kind_unsupported`. Several nodes fit the request
   (e.g. two with a router) → ask the owner which one before saving anything.
2. **Current policy**: `get_routing_policies_by_node_id_by_protocol` — note `revision`, `rules`
   with their `id`, `default_*`, `fallback`. A `404 policy_not_found` means no policy yet, the
   default applies. «Everything else as now» = leave default and fallback alone.
3. **Body**: pass existing rules with their `id` (no `id` = a new rule); for quick settings take the
   rule from `get_routing_presets` with its `note` **and add `"preset": "<preset id>"`** (`torrent`,
   `ads`, `ru_direct`) so the UI toggle shows it on. Blocks first, «direct» last. Exits: `warp`,
   `exit:<id>` (from `get_routing_exits`), `node:<guid>[:warp]`. Leave `backend` out — the policy
   keeps the one it has. Baseline before changing: `post_routing_policies_by_node_id_by_protocol_explain`
   for two hosts (e.g. `yandex.ru`, `youtube.com`).
4. **Preview**: `routing_preview` with `policy` = the **whole** body (default, fallback and rules,
   not the rules alone); several candidate nodes can be previewed before asking the owner. Wait for
   `status: supported`, read `warnings` and `restart_required` (the router restarts — a short drop
   for every service on it). On a linked node the `diff` may start from `null` even though a policy
   is applied — compare digests, not the diff.
5. **Save**: `put_routing_policies_by_node_id_by_protocol` with the body and `expected_revision`
   (409 `policy_conflict` — someone saved in parallel, re-read). The answer carries the new `revision`.
6. **Show the owner** the document and what restarts; after the yes —
   `routing_apply(node_id, protocol, expected_revision: <new revision>, confirm: true)`.
7. **Verify**: the policy `state: applied`, `applied_revision = revision`; a linked node —
   `get_nodes_by_node_id` → `converged`; `explain` for the same hosts shows the expected
   `action`/`exit`.

Rollback: `post_routing_policies_by_node_id_by_protocol_rollback` with the **current**
`expected_revision` and `confirm` — the panel returns to the previous applied document (the
preview's `rollback.to_digest` shows which). A lane for one client — `post_routing_lanes_by_grant_id`,
then the same policy with `lane: grant:<id>`.

## `unsupported` reasons and what to do

| Reason | Action |
|---|---|
| `rule_kind_unsupported`, `backend_capability_missing` | the rule needs the router: `post_routing_targets_by_node_id_by_protocol_attach` (restarts the service) or drop the rule |
| `not_attached`, `router_unavailable`, `node_lacks_router` | no router on the node or the service is not attached — fix that first, not the policy |
| `provider_unavailable` / `provider_unreachable` | WARP not configured / not answering; `fallback: approved_direct` trades fail-closed for «direct» — only with consent |
| `geosite_unknown` / `geoip_unknown` | no such code: `get_routing_geodata_codes`, refresh geodata (`post_routing_geodata_by_action`) |
| `exit_disabled`, `relay_*`, `chain_loop` | the exit is disabled, the exit node lacks a relay, or the chain loops — fix the exit |

Warnings `adopts_unmanaged_*` — a hand-made setting on the node; the first apply takes it under
management and keeps it for rollback. `policy_empty` is what «Сбросить» applies. A `restart_required`
already `true` in `get_routing_targets.router` before any change means the router waits for a
restart since an earlier change — the apply will restart it anyway; mention it.

## What to tell the owner

Before applying: node, protocol, the rules in words, that «direct» means leaving with the node's real
IP, what restarts. After: revision and digest, the `explain` results, that rollback is one call away.
