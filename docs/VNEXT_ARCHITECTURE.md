# vNext architecture

This document is the architectural record of the vNext control plane: a local control
plane with a reserved local node identity, a `Client`/`AccessGrant` domain model,
encrypted secret storage and a stable, revocable subscription URL. Decisions are
recorded one per file in [ADR 001–009](#decision-records); this page is the map
between them. The section [Fleet v2](#fleet-v2) describes the fleet of linked panels
built on top of it.

## Goal

Turn "a panel that calls three protocol managers" into a control plane that owns
subscribers:

- the central host becomes an ordinary, reserved node with `node_id = local`, so
  every existing MTProxy/Naive/Mieru resource has a real node instead of `NULL`;
- a person is a `Client`; each concrete access is an `AccessGrant`;
- credentials are stored encrypted and referenced, never copied into state, logs
  or audit;
- every subscriber gets one stable URL that always renders the current set of
  grants, with `ETag`/`304` semantics and honest per-client compatibility;
- Fleet v2, routing and the dedicated Xray router build on this model. Old Fleet v1
  deployments require explicit migration; their mTLS services are not shipped.

## Target model

The core entities:

```text
Client
  id: UUID
  display_name
  state: active | suspended | archived
  metadata

AccessGrant
  id: UUID
  client_id
  protocol: mtproxy | naive | mieru
  node_id
  endpoint_id
  runtime_username
  secret_ref
  desired_state
  observed_state
  valid_from / valid_until
  protocol_options_json

ClientSubscription
  id: UUID
  client_id
  public_token_hash
  generation
  state: active | revoked
  update_interval_hours
  last_fetched_at

Node
  id: stable UUID/string
  enrollment_state
  connectivity_state
  daemon_health
  capability_manifest
  last_checked_at
  last_seen_at

SecretVersion
  secret_id / version
  purpose / grant_id / permitted_node_id
  key_id
  encrypted_payload
  state: pending | active | retiring | revoked
```

`DesiredGeneration` and `ObservedGeneration` belong to Fleet v2 (see below); routing
policies, egress providers and enforcement backends are described in
[ROUTING](ROUTING.en.md), [XRAY_ROUTER](XRAY_ROUTER.en.md) and ADR 006–007.

Ownership vocabulary used across the model: `managed`, `adopted`, `foreign`,
`drifted`, `tombstoned` (see ADR 003).

## What does not change

- **Linked panels use Fleet v2:** one panel reaches another over its HTTPS API with a
  scoped `node-sync` key; no extra Compose Fleet agent or ingress is installed.
- **Installed Fleet v1 state is not discarded:** a legacy systemd unit, an
  on-disk/configured overlay, or even a stopped legacy container in either
  historical Compose project stops native panel self-update before any tree or
  database mutation. Operators must preserve the writer, certificates and volumes
  for an explicit migration (see [COMPATIBILITY](COMPATIBILITY.md)).
- **Host identifiers remain stable:** `/opt/mtproxy-shared443` and the existing Compose
  project's name, volumes and panel database are preserved by the host migration.
- **One database:** the panel owns `panel.sqlite3`; a retired Fleet v1 ingress cannot
  continue writing it across a native panel self-update.

## Secret boundaries

- State, Fleet payloads, audit detail, logs, exception messages and API
  responses carry references only. The single exception is a deliberate one-time
  reveal and the subscription response itself (ADR 005).
- Values live in `secret_versions`, AES-256-GCM, under a master key stored
  outside the database (`secrets/panel-master-key` →`/run/panel/master-key`).
  The installer creates it on install and on upgrade; `panel cli master-key-init`
  exists for installations assembled by hand.
- The panel starts without the key while no encrypted row exists, and refuses to
  start when rows exist and the key is missing.
- Threat model: this protects a stolen database or backup, not a compromised
  panel process.
- Backups keep the key separately from the database dump
  (`BACKUP_RESTORE.en.md`).

## Subscription client compatibility

One stable URL can always return the current bundle, but consumers differ, so
every cell of the matrix is explicit (`supported | unsupported | unproven`) and
lives in `panel/crates/subscriptions/src/compatibility.rs`. The summary below covers:

| Client | MTProxy | Naive | Mieru |
| --- | --- | --- | --- |
| Karing | unsupported | supported | supported |
| sing-box ≥ 1.13 | unsupported | supported | unsupported |
| mihomo / Clash.Meta | unsupported | unsupported | supported |
| Official mieru client | unsupported | unsupported | unsupported (no subscriptions at all) |
| Telegram | unsupported | — | — |

"Supported" means the renderer emits a format that client parses and refreshes
on its own schedule. It never means the panel pushes an update: the subscription
is a pull projection, and operator-visible events are a separate feature.

Renderers: `manifest` (canonical JSON), `singbox` (JSON with `naive` and `mieru`
outbounds), `clash` (YAML with `mieru` proxies), `raw` (one URI per line, plain
text, no base64) and `html` (a page with links, QR codes and this matrix). A
protocol a renderer cannot express is emitted as an explicit `unsupported` entry
with a reason — never as a plausible-looking link.

The public endpoint lives on its own domain (`PANEL_SUBSCRIPTION_HOST`), not on
the panel domain, and that vhost logs no access lines.

## Fleet v2

Fleet v2 turns the control plane into a fleet: one panel (the central) manages other
panels (the nodes) over their own HTTPS panel domains with scoped Bearer API keys. The
decision is [ADR 008](adr/008-panel-to-panel-transport.md), which supersedes the
transport direction of ADR 001 (pull-only mTLS) while keeping its typed-payload rule and
applying ADR 002 (immutable generations) and ADR 003 (one writer per resource) unchanged.
Operator documentation: [FLEET.en.md](guides/FLEET.en.md).

What it adds, and what it deliberately does not:

- Enrollment is three UI actions (a `node-sync` key on the node, «Добавить узел» on the
  central, import); nothing is installed on a host beyond the panel image.
- The node's desired state is a `DesiredGeneration` — an immutable, numbered, digested,
  secret-free `GenerationDocument` compiled from the central's grants; the node answers
  with an `ObservedGeneration`. Credentials travel next to the document by reference.
- A node records the GUID of the first central whose generation it accepts (one master
  per node) and refuses generations from any other until unlinked.
- Ownership on the node follows ADR 003: `central` vs `local` runtime users, adoption
  only for explicitly imported users, collisions reported `failed`, orphans deleted,
  local users never touched.
- Routing is capability-limited native egress policies (`docs/ROUTING.en.md`, ADR 006,
  ADR 007 for the native backends) plus the optional dedicated Xray-router
  (`docs/XRAY_ROUTER.en.md`, ADR 007 for the router: a separate pinned runtime with
  its own generations, authenticated per-service ingresses, attach/detach as explicit
  actions, `companion` documents in a generation).

Native components (paths relative to `panel/crates/`):

| File | Responsibility |
| --- | --- |
| `core/src/migrations/`, `core/src/db.rs` | panel database migrations and connection lifecycle |
| `secrets/src/api_keys.rs`, `web/src/routes/api_keys.rs`, `web/src/auth.rs` | scoped API keys, authentication, `/api/keys*` |
| `secrets/src/identity.rs`, `model/src/fleet.rs` | panel GUID, master GUID, typed generation and observation wire models |
| `fleet/src/node/managed.rs`, `fleet/src/node/reconcile.rs`, `fleet/src/node/guard.rs` | node's generation ownership, reconciliation and local-writer conflicts |
| `web/src/routes/fleet_node.rs` | node's `/api/fleet/v2/*` and unlink routes |
| `fleet-central/src/client.rs`, `fleet-central/src/links.rs` | verified/pinned HTTPS client, linked panel lifecycle |
| `fleet-central/src/generations.rs`, `fleet-central/src/pusher.rs`, `fleet-central/src/importing.rs` | compilation, delivery, observation and inventory import |
| `web/src/routes/fleet_central.rs` | central's node-link and generation API |
| `clients/src/lifecycle.rs`, `clients/src/provisioning.rs` | local and remote grant lifecycle and provisioned operations |
| `web/src/routes/clients.rs`, `web/src/routes/subscriptions.rs`, `clients/src/subscriptions.rs` | client API and public subscriptions |
| `static/js/keys.js`, `nodes.js`, `clients.js`, `index.html`, `style.css` | linked-panel and client UI |

## Release train

- Every gate runs on the disposable lab host `ams-test`: repository suite,
  Compose/image checks, the container lab, the destructive host lab and a real
  installation with live protocol probes. Local macOS is not an authoritative
  host.
- GitHub Actions runs native tests, the full external Rust-panel suite, dependency
  auditing and repeat release builds. A CI result does not replace a fresh lab-host
  run or an observed Fleet v2 native-central scenario against the release archive.
- Tags are `vX.Y.Z`; while 3.3.0 hosts still exist, do not publish public 4.0
  pre-releases. Test candidates privately from local archives on `ams-test`.
- Graphify is rerun after each architecture-scale change and before final review.

## Decision records

- [ADR 001 — Superseded pull-only transport; retained typed-payload boundary](adr/001-pull-only-node-transport.md)
- [ADR 002 — Declarative immutable generations](adr/002-declarative-generations.md)
- [ADR 003 — One writer per resource](adr/003-one-writer-per-resource.md)
- [ADR 004 — Client, AccessGrant and subscription as a projection](adr/004-client-access-grant-subscription.md)
- [ADR 005 — Secrets travel as references](adr/005-secret-references.md)
- [ADR 006 — Engine-neutral routing policy IR](adr/006-routing-policy-ir.md)
- [ADR 007 — Routing enforcement ownership](adr/007-routing-enforcement-ownership.md)
- [ADR 008 — Panel-to-panel transport with scoped API keys](adr/008-panel-to-panel-transport.md)
- [ADR 009 — Lanes per client and chains through the fleet's relays](adr/009-lanes-and-chains.md)

See also the [capability matrix](VNEXT_CAPABILITIES.md), [compatibility
guarantees](COMPATIBILITY.md) and [validation gates](VALIDATION.md).
