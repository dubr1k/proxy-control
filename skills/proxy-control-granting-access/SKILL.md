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

Renaming is presentation only (accounts, endpoints and secrets never change, the link stays the
same): `post_clients_by_client_id_rename` renames a client; `post_clients_grants_by_grant_id_label` sets
the name one access carries in the subscription (an empty `label` puts «node · protocol» back);
`post_nodes_by_node_id_rename` renames a node. The app shows the new names after it refreshes the
subscription.

## AmneziaWG (UDP VPN, a config file instead of a subscription)

AmneziaWG is handed out as a `.conf` file and a QR, never through the subscription. The protocol
has **versions 1.5, 2.0 and 3.1**, they are not compatible with one another, and each runs on its own
port of the node; one access = one version, and a person can hold several. Put it in the placement
as `{node_id, protocol: "amneziawg", options: {"version": "1.5"|"2.0"|"3.1"}}` (default 2.0); the
account is named `<name>-awg<ver>` unless you pass `runtime_username`. Ask the node first: `overview` →
`nodes` → `identity` shows the versions a node serves (`awg_versions` for `local`,
`identity.protocols.amneziawg.versions` for a linked panel); a version the node does not serve is
refused. The config holds the client's private key, so it is never returned through MCP: the owner opens the access in the panel (client → the access → «Показать конфиг») and downloads the `.conf` or scans the QR; the reveal is one-time and audited. 
Newer versions hide traffic better but need a client that supports them: per Amnezia's announcements
AmneziaWG 2.0 needs AmneziaVPN 4.8.12.9 or later and 3.1 needs 5.0.1.5 or later. Rotation issues a new key pair: the old file stops working.

## TrustTunnel (TCP VPN, a link and a config file)

TrustTunnel (AdGuard's HTTP/2-over-TLS VPN) is TCP only and shares port 443 with the other services; the node needs its
own TrustTunnel domain (an A record, DNS only), so ask the owner first whether the node serves it: `overview` → `nodes` →
`identity.protocols.trusttunnel.enabled` (a node without the capability `protocol.trusttunnel.v1` is refused at once, nothing is
written). Put it in the placement as `{node_id, protocol: "trusttunnel"}`; `options` is optional, `{"name": "<profile name shown in
the app>"}`. The account is named like the others (`runtime_username`).

- **What the person gets**: a `tt://?…` deep link (also a QR) and a client TOML for the official **AdGuard TrustTunnel** app
  (iOS, Android) and the command-line client; the Clash/mihomo feed carries a `type: trusttunnel` proxy, and the `raw`
  feed carries the `tt://` line. The password is inside the link and the TOML, so the owner opens the access in the panel (client
  → the access → the access window) to copy them; the reveal is audited. The panel is the only copy of the password:
  capture and import of existing runtime users are not supported, and rotation (`post_clients_grants_by_grant_id_by_action`)
  issues a new password, so the old link stops working.
- **Tell the owner about the restart**: the endpoint reads credentials only at start, so every new, changed or disabled access
  restarts it; changes within about two seconds are merged, active TrustTunnel sessions drop and the apps reconnect by
  themselves. Do not batch dozens of single grants at peak time.
- **Not in every app**: sing-box, Karing's sing-box cut, Hiddify and Throne have no TrustTunnel outbound (the `singbox` feeds name
  the gap, nothing breaks); mihomo is the one verified subscription client; Surge needs its `trust-tunnel` policy set up by hand.
  `get_subscriptions_compatibility` gives the app × protocol matrix.

## Link variants (`subscription.variants`)

| Key | For whom | What it carries |
|---|---|---|
| `singbox` | Karing (iPhone, Android, Windows) | NaiveProxy + Mieru; no MTProxy, no TrustTunnel |
| `singbox-official` | official sing-box ≥ 1.13 | NaiveProxy only (no TrustTunnel) |
| `clash` | mihomo, Clash-compatible apps | Mieru and TrustTunnel |
| `raw` | manual import, QR, Telegram | `tg://proxy`, `naive+https://`, `mierus://`, `tt://` one per line; no auto-refresh |

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
