# vNext architecture (v0.2 and v0.3)

This document is the architectural record for the v0.2 line: a local control
plane with a reserved local node identity, a `Client`/`AccessGrant` domain model,
encrypted secret storage and a stable, revocable subscription URL. Decisions are
recorded one per file in [ADR 001–007](#decision-records); this page is the map
between them. The v0.2 text below is kept as written; the section [v0.3 — Fleet
v2](#v03--fleet-v2) records what the next release added on top of it.

## Goal of v0.2

Turn "a panel that calls three protocol managers" into a control plane that owns
subscribers:

- the central host becomes an ordinary, reserved node with `node_id = local`, so
  every existing MTProxy/Naive/Mieru resource has a real node instead of `NULL`;
- a person is a `Client`; each concrete access is an `AccessGrant`;
- credentials are stored encrypted and referenced, never copied into state, logs
  or audit;
- every subscriber gets one stable URL that always renders the current set of
  grants, with `ETag`/`304` semantics and honest per-client compatibility;
- Fleet v1 keeps working byte-for-byte. Fleet v2, routing and a dedicated Xray
  router are later releases with their own gates.

## Target model

The v0.2 entities, verbatim from the design document:

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

`DesiredGeneration`, `ObservedGeneration`, `RoutingPolicy`, `EgressProvider`,
`EnforcementBackend` and `CompiledRoutingGeneration` belong to v0.3–v0.5 and are
described in the design document; v0.2 does not implement them (v0.3 implements the
first two — see below).

Ownership vocabulary used across the model: `managed`, `adopted`, `foreign`,
`drifted`, `tombstoned` (see ADR 003).

## What does not change in v0.2

- **Fleet v1 is frozen and byte-compatible**: the `OPERATIONS` set, the
  `TypedCommand` shape, sequence/outbox semantics, mTLS enrollment and the
  `GET /agent/v1/...` paths. It stays Telemt-only.
- **Frozen runtime identifiers** (see `COMPATIBILITY.md`): Compose project
  `mtproxy`, volume `mtproxy_panel-data`, `/opt/mtproxy-shared443`,
  `/var/lib/mtproxy-panel`, `/etc/mtproxy-agent`, the unit file names and the
  `urn:mtproxy-panel:node:` prefix.
- **One database**: new tables are added to the existing `panel.sqlite3`;
  existing tables are not renamed. Migrations are safe across the two processes
  that open that file (panel and fleet-ingress).
- **Existing protocol endpoints keep working** during the transition, as a
  compatibility façade behind `PANEL_VNEXT_WRITER` (ADR 003).

## Secret boundaries

- State, Fleet payloads, audit detail, logs, exception messages and API
  responses carry references only. The single exception is a deliberate one-time
  reveal and the subscription response itself (ADR 005).
- Values live in `secret_versions`, AES-256-GCM, under a master key stored
  outside the database (`secrets/panel-master-key` →`/run/panel/master-key`).
  The installer creates it on install and on upgrade; `panel.cli master-key-init`
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
lives in `tests/fixtures/vnext-capabilities.json`. As of 2026-09-10:

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

## v0.3 — Fleet v2

v0.3 turns the v0.2 control plane into a fleet: one panel (the central) manages other
panels (the nodes) over their own HTTPS panel domains with scoped Bearer API keys. The
decision is [ADR 008](adr/008-panel-to-panel-transport.md), which supersedes the
transport direction of ADR 001 (pull-only mTLS) while keeping its typed-payload rule and
applying ADR 002 (immutable generations) and ADR 003 (one writer per resource) unchanged.
Design: `superpowers/specs/2026-09-11-v0.3-central-panel-design.md`; operator
documentation: [FLEET.en.md](../FLEET.en.md).

What v0.3 adds, and what it deliberately does not:

- Enrollment is three UI actions (a `node-sync` key on the node, «Добавить панель» on the
  central, import); nothing is installed on a host beyond the panel image.
- The node's desired state is a `DesiredGeneration` — an immutable, numbered, digested,
  secret-free `GenerationDocument` compiled from the central's grants; the node answers
  with an `ObservedGeneration`. Credentials travel next to the document by reference.
- A node records the GUID of the first central whose generation it accepts (one master
  per node) and refuses generations from any other until unlinked.
- Ownership on the node follows ADR 003: `central` vs `local` runtime users, adoption
  only for explicitly imported users, collisions reported `failed`, orphans deleted,
  local users never touched.
- Fleet v1 stays frozen and byte-compatible; routing shipped in v0.4 as capability-limited
  native egress policies (`docs/ROUTING.en.md`, ADR 006 accepted, ADR 007 for the native
  backends) and in v0.5 with the optional dedicated Xray-router (`docs/XRAY_ROUTER.en.md`,
  ADR 007 accepted for the router: a separate pinned runtime with its own generations,
  authenticated per-service ingresses, attach/detach as explicit actions, `companion`
  documents in a generation). There are no transitive nodes, no metric history, no
  panel-to-panel mTLS, no 3x-ui bridge and no canary rollouts.

Components (all under `panel/` unless stated):

| File | Responsibility |
| --- | --- |
| `migrations.py` | migrations 9–12: `panel_settings` + `api_keys`; `managed_generations` + `managed_resources`; `node_links` + `desired_generations` + `observed_generations` + `fleet_nodes.transport`; `provisioning_operations` rebuilt with `pending_remote` |
| `api_keys.py`, `api_key_routes.py` | `ApiKeyService` — issue / list / enable-disable / delete / authenticate, scope → role; `/api/keys*` (owner) |
| `web_context.py` | `Authorization: Bearer` in `RequestContext.current`, the `fleet_key` dependency, `KeyRateLimiter` (120/min per key) |
| `fleet_v2/identity.py` | the panel's `panel_guid` and `fleet_master_guid`, `VERSION` → `panel_version` |
| `fleet_v2/protocol.py` | wire models `Resource`, `GenerationDocument`, `PushRequest`, `ObservedGeneration`, `PushResponse`; canonical digest; conflict codes |
| `fleet_v2/managed.py` | node: `ManagedStore` — accepted generations, owned resources, ownership check, unlink |
| `fleet_v2/reconcile.py` | node: `Reconciler` — discover / plan / apply / verify through the protocol adapters, startup retry |
| `fleet_v2/guard.py` | node: `require_unmanaged` — 409 `managed_by_central` for every local writer |
| `fleet_v2/node_routes.py` | node: `/api/fleet/v2/*`, `POST /api/nodes/local/unlink` |
| `fleet_v2/client.py` | central: `NodeClient` (httpx, `verify`/`pin`), `fingerprint()`, `validate_panel_url()` |
| `fleet_v2/links.py` | central: `NodeLinkService` — test / add / update / pause / probe / delete, heartbeat bookkeeping |
| `fleet_v2/generations.py` | central: `DesiredStore`, `compile()`, `publish()` (content digest) |
| `fleet_v2/pusher.py` | central: `FleetPusher` — heartbeat, delivery, 202 polling, resync, per-node backoff, `node.up`/`node.down` |
| `fleet_v2/importing.py` | central: import of a node's runtime users → clients + `origin=imported` grants, credential capture |
| `fleet_v2/central_routes.py` | central: `/api/nodes/fingerprint\|test\|link`, `/api/nodes/{id}/link\|pause\|resume\|probe\|inventory\|import\|versions\|generations`, `DELETE /api/nodes/{id}`, `public_hosts_for()` |
| `clients/lifecycle.py`, `clients/provisioning.py` | grants: enable / disable / rotate / delete for local and remote nodes; the `remote` step and `pending_remote` operations |
| `protocols/telemt.py`, `telemt.py` | caller-supplied secret with manager fallback (`credential_origin`), `update_options` |
| `protocols/naive.py`, `protocols/mieru.py` | `update_options`, capture support flags |
| `subscription_routes.py`, `client_routes.py`, `subscriptions/renderers/base.py` | public hosts per node in subscriptions and bundles |
| `static/js/keys.js`, `nodes.js`, `clients.js`, `index.html`, `style.css` | UI: «API-ключи», «Добавить панель», linked node card, «ожидает узел» |

## Release train

- Every gate runs on the disposable lab host `ams-test`: repository suite,
  Compose/image checks, the container lab, the destructive host lab and a real
  installation with live protocol probes. Local macOS is not an authoritative
  host.
- GitHub Actions no longer gates: it rebuilds the release twice, verifies the
  bytes match the archive that passed `ams-test` (`expected_sha256`), attests
  provenance and publishes after a human approval.
- Tags: `v0.2.0-alpha.1` → `v0.2.0-beta.1` → `v0.2.0`; the workflow accepts
  pre-release suffixes. v0.3 follows the same train: `v0.3.0-beta.1` → `v0.3.0`; its
  gate gains a `fleet` lab tier (two panels on the lab host) before the tag, tracked in
  `releases/v0.3.0-beta.1.md`.
- Graphify is rerun after each architecture-scale change and before final review.

## Decision records

- [ADR 001 — Pull-only node transport](adr/001-pull-only-node-transport.md)
- [ADR 002 — Declarative immutable generations](adr/002-declarative-generations.md)
- [ADR 003 — One writer per resource](adr/003-one-writer-per-resource.md)
- [ADR 004 — Client, AccessGrant and subscription as a projection](adr/004-client-access-grant-subscription.md)
- [ADR 005 — Secrets travel as references](adr/005-secret-references.md)
- [ADR 006 — Engine-neutral routing policy IR](adr/006-routing-policy-ir.md)
- [ADR 007 — Routing enforcement ownership](adr/007-routing-enforcement-ownership.md)
- [ADR 008 — Panel-to-panel transport with scoped API keys](adr/008-panel-to-panel-transport.md) (v0.3)

See also the [capability matrix](VNEXT_CAPABILITIES.md) (machine-readable source:
`tests/fixtures/vnext-capabilities.json`), [compatibility
guarantees](COMPATIBILITY.md) and [validation gates](VALIDATION.md).
