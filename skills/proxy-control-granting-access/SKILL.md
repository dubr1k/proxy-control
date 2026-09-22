---
name: proxy-control-granting-access
description: Use when asked to give a person access to the proxies through the Proxy Control MCP server — create a client, put it on nodes and protocols, hand out a subscription link, or re-send or rotate a link someone lost.
---

# Granting access to a client

A client is a person; a grant is their account on one node for one protocol; the subscription is
one link covering all their grants. Everything goes through the curated tools of the
`proxy-control` MCP server.

## Steps

1. **Nodes and the subscription domain**: `overview` → `nodes` (id, `link.status`, services). The
   panel's own server is `node_id: "local"`. Whether a subscription domain exists:
   `get_clients_by_client_id_subscription` on any existing client → `configured: true`.
2. **Name**: `get_clients` — is this person already there (including `archived`)? Is the account
   name free — `get_naive_users` / `get_mieru_users` / `get_users`, only for the protocols asked for.
3. **Create**: `create_client` with `display_name` and `placement` = a list of `{node_id, protocol,
   runtime_username}` for every wanted cell. The answer: `client.id`; `grants` = `{operation_id,
   status}` of one operation for all cells; `subscription.url` and `subscription.variants.<key>`.
   **The link is shown here once** — keep it from this answer.
4. **Wait for the grant**:
   - `local`: `grants.status: succeeded`; in `get_clients` every grant has `observed_state: enabled`;
   - a linked node: `grants.status: pending_remote` — the node must be `online`; poll
     `get_operations_by_operation_id` until `succeeded`. Until `enabled` the access is not granted;
     `manual_intervention_required` — report to the owner, delete nothing, do not retry.
5. **Hand out the link** — the variant from the table below plus two sentences on what to do in the app.

An existing client: `set_client_placement` without `confirm` shows the plan (`issue`/`enable`/
`disable`), with `confirm: true` runs it; surplus grants are disabled, never deleted. The link again —
`client_subscription` (the reveal lands in the audit log); a lost or leaked link —
`post_clients_by_client_id_subscription_rotate` with `confirm` (the old link stops working).

## Link variants (`subscription.variants`)

| Key | For whom | What it carries |
|---|---|---|
| `singbox` | Karing (iPhone, Android, Windows) | NaiveProxy + Mieru; no MTProxy |
| `singbox-official` | official sing-box ≥ 1.13 | NaiveProxy only |
| `clash` | mihomo, Clash-compatible apps | Mieru only |
| `raw` | manual import, QR, Telegram | `tg://proxy`, `naive+https://`, `mierus://` one per line; no auto-refresh |

In doubt, `get_subscriptions_compatibility` gives the app × protocol matrix. Karing: «Add profile →
from link»; a Telegram proxy is `raw`, the `tg://proxy` link opens inside Telegram itself.

## Pitfalls

- **Non-Latin display names**: the account name is derived from `display_name` by `[A-Za-z0-9_.-]`;
  «Иван Петров» becomes `client`, and a second such client conflicts. Always pass a Latin
  `runtime_username`.
- One account name for all of a client's cells; it cannot change after the grant. Deleted names in
  NaiveProxy and Mieru are burnt forever — never reuse them.
- Cell `options` only when asked: naive `{"quota_bytes"}`, mieru `{"quotas": [{"days",
  "megabytes"}]}`, mtproxy `{"data_quota_bytes", "expiration", "max_unique_ips", …}`.
- Without a subscription domain `create_client` returns `subscription.note` instead of a link — say so.
- In the audit log your actions appear as `actor_username: key:mcp`; after granting, `audit_tail`
  with `limit: 10` confirms the record.
- Delete nothing: a client goes to `archived` through `post_clients_by_client_id_state`.

## Report to the owner

Name, nodes and protocols, account name; the link of the right variant; one sentence on what to do in
the app; a reminder that the link can be shown again (audited) or rotated.
