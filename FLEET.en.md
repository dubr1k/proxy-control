# Proxy Control fleet: linked panels (v2) and the legacy mTLS transport (v1)

**English** · [Русский](FLEET.ru.md)

## Overview

Since v0.3 one panel — the **central** — manages other panels — the **nodes** — over
each node's own HTTPS panel domain, authenticated with a scoped Bearer API key
([ADR 008](docs/adr/008-panel-to-panel-transport.md)). Linking a panel is three actions
in the web UI; nothing is installed on any host beyond the panel image — no ingress, no
agent, no CA, no CSR.

Every panel image carries both halves. The node half answers `/api/fleet/v2/*`; the
central half owns the «Узлы» (Nodes) screen, the `/api/nodes/*` routes and a heartbeat
loop. Which of the new tables a given panel fills depends on its role in a link:

| Role | Tables | What they hold |
| --- | --- | --- |
| every panel | `panel_settings`, `api_keys` | the panel's own `panel_guid`, its `fleet_master_guid` once managed, hashed API keys |
| node | `managed_generations`, `managed_resources` | the generations it accepted and the runtime users it owns for the central |
| central | `node_links`, `desired_generations`, `observed_generations`, `fleet_nodes.transport = 'panel'` | how to reach each linked panel, what was asked of it, what it last reported |

What travels over the link is typed and secret-free by construction: an immutable,
numbered, digested **generation document** compiled from the central's access grants
(ADR 002), the node's **observed** report, and a bounded set of operations (identity,
status, inventory, credential capture, component update, unlink). No shell, URL, HTTP
method, YAML or runtime configuration ever crosses it. Credentials travel next to the
document over the same TLS request, by reference inside it.

The mTLS pull agent of Fleet v1 is unchanged and still works; it is described in
[Legacy transport v1](#legacy-transport-v1) at the end.

## Link a panel

Three actions. Screenshots of the two screens (views `fleet` and `admins`) are
collected for the release in [docs/releases/v0.3.0-beta.1.md](docs/releases/v0.3.0-beta.1.md).

### 1. On the panel that will become a node: create a `node-sync` key

«Администраторы» → section **«API-ключи»** → **«Создать ключ»** (owner only): a name,
scope `node-sync`, an optional expiry. The key is shown **once**, in the form
`pc_<prefix>_<secret>` (an 8-hex lookup prefix and a 43-character URL-safe secret); the
database stores only the prefix and a SHA-256 hash of the whole key. Copy it now — it
cannot be displayed again, only replaced. The card «Этот сервер» on the «Узлы» screen
shows the panel's GUID and the URL to type into the central.

### 2. On the central: «Узлы» → «+ Панель» → «Проверить»

The dialog «Добавить панель» asks for a display name, the panel URL (`https://` only,
optional port and base path, no query string), the API key, and how to check TLS:

- **`verify`** (default) — the node's certificate must chain to the system trust store,
  exactly like a browser; every production host already serves its panel with a
  WebPKI certificate.
- **`pin`** — the SHA-256 of the leaf certificate presented at that URL must match.
  «Получить отпечаток» connects to the URL, ignores the chain and shows the digest —
  compare it with what the node panel itself shows before trusting it. Meant for
  self-signed and lab certificates; there is deliberately no «skip verification».

A private, loopback, link-local or `*.local` address is refused unless «Разрешить
приватный адрес» is ticked (a lab or an internal network).

**«Проверить»** calls the node's `identity`, `status` and `inventory` with the key and
stores nothing. The dialog then shows what the panel reported about itself (GUID,
version, protocols and their daemons, latency) and lists its runtime users with
checkboxes for the import step below. Refusals are explicit: the panel does not speak
Fleet API v2 (a v0.2 panel answers 404), it is already managed by another central, it is
already linked here, it is this very panel, the key is wrong (401/403 → «the node
refused the API key»), or it is unreachable.

### 3. «Добавить» — and, optionally, import

One transaction on the central: a `fleet_nodes` row whose `node_id` is the node's GUID
(`transport = 'panel'`, `auth_state = 'linked'`), the `node_links` row (URL, TLS mode,
pin, `allow_private_address`), and the key encrypted in `secret_versions`
(`purpose = 'node-api-key'`, bound to that GUID). API responses and the UI only ever say
`has_api_key: true`; the plaintext is never shown again. The users ticked in the dialog
are imported right after (see [Import existing users](#import-existing-users)).

The link starts as `unknown` and becomes **online** on the first heartbeat (within
`PANEL_FLEET_HEARTBEAT_SECONDS`, default 15 s) with a `node.up` event. The node records
the central's GUID as its master when it accepts the first generation — not at link
time — so a linked panel that never received a generation is still unmastered.

Equivalent API, all owner-only: `POST /api/nodes/fingerprint {url}` → `{sha256}`;
`POST /api/nodes/test` and `POST /api/nodes/link {display_name, url, api_key,
tls_verify, pinned_sha256?, allow_private_address}` (201 `{node_id}`);
`POST /api/nodes/{id}/link` changes only the fields given (name, URL, key, TLS mode,
pin — a new key is a new secret row and the old one is revoked; the private-address
flag stays what it was at link time).

## What is synchronised

### Generations

Everything the central wants a node to run is one **generation document**: the node's
grants (`access_grants` with `node_id` = the node's GUID and `origin ∈ provisioned |
imported`) as `Resource` entries. Each resource carries `ref = grant:<id>`, `protocol`,
`runtime_username`, `desired_state ∈ enabled | disabled | deleted`, `credential_ref =
grant:<id>:<version>`, `credential_origin ∈ caller | manager`, `origin`, the
protocol options and `valid_from`/`valid_until`. The document itself is
`schema_version: 1` with `node_guid`, `master_guid`, `generation`,
`previous_generation`, `created_at`, `created_by` and at most 500 resources; two
resources may not name the same (protocol, runtime user). Credentials are never in the
document; the push request carries them separately as `secrets: {credential_ref:
plaintext}` and the node refuses secrets for refs the document does not name.

A generation is **compiled, never edited**. Every grant mutation on the central —
issue, enable, disable, rotate, delete, import — goes through `ClientService.notify`,
which publishes inside the same transaction: a rolled-back change publishes nothing. A
new row appears only when the *content* changed (the same resources renumbered are not
a new generation); the number then increases by one and the link is marked
`config_dirty`. Generations are immutable and only ever grow: the node rejects a
smaller number (409 `stale_generation`) and the same number with a different digest
(409 `digest_conflict`); a rollback is a new, higher generation from the central (ADR
002).

**Egress (v0.4).** A generation may carry an optional `egress` section — per protocol
(`naive`, `mieru`) an `EgressDocument {backend, policy_id, policy_revision, document,
digest}`: the routing policy of that node compiled for the node's backend
([docs/ROUTING.en.md](docs/ROUTING.en.md)). The central includes it only for a node
whose `identity.capabilities` lists `egress.v1` (a v0.3 node's strict model would refuse
the whole document), and only the policies the operator applied (or rolled back): a draft
is never published. The field is left out of the wire form and of the digest when there
is nothing to say, so every document without egress keeps the digest it had in v0.3 in
both directions of a mixed-version link. On the node the section is applied **after the
resources**, through the same manager adapters the local screen uses, idempotently
(the manager already running that digest is not asked again), with `operation_id =
<guid>:<generation>:egress:<protocol>`; a failed section fails the generation the way a
resource does — the users are provisioned regardless — and the report carries
`egress: {protocol: {state: converged | failed | unsupported, revision, digest, error}}`
(`managed_egress` on the node). The central moves the policy to `applied` at the
revision the section named, or to `failed` with the node's code, from a settled report
about the generation it currently wants; a section absent from a later generation means
«leave the egress as it is», and `unlink` never touches the data plane. While a central
manages a node, the node's own routing screen refuses to apply (`managed_by_central`).

### Ownership on the node

A runtime user on a node belongs either to the central (`central`) or to the node
itself (`local`); the register is `managed_resources` (ADR 003). The rules the node's
reconcile applies to each resource of the latest accepted generation:

- **absent from the runtime** → created through the protocol adapter with the pushed
  credential (a placeholder row is written before the call, so a crash between
  `create` and its record is recovered by an idempotent rotate on the next apply);
- **present and owned by the central** → credential rotated when `credential_ref`
  changed, enabled/disabled to match, options updated where the adapter can (an
  option it cannot apply leaves the resource `drifted`, on/off state still correct);
- **present but not owned by the central** → for a `provisioned` resource this is a
  **collision** with a local (or someone else's) account: the resource is reported
  `failed` («runtime user exists and is not managed») and never adopted or touched.
  The one deliberate adoption is an `imported` resource — the operator chose that user
  from this node's inventory — which is recorded as the central's **without any
  adapter call**;
- **`deleted`** → removed from the runtime if the central owns it, reported `missing`
  once, then forgotten by the node;
- **orphan** — a central-owned user the current document no longer names → deleted;
- **local users are never touched**, and the node's own UI and API refuse to mutate a
  central-owned user with 409 `managed_by_central` (`X-Reason` header): one writer per
  resource.

A failed resource does not stop the others: the generation ends `failed` with a
per-resource breakdown and is applied again when the central re-pushes (see the
backoff below). A generation accepted before a restart is applied again at panel start;
apply is idempotent by discovery, so nothing is created twice. Secrets the node receives
are escrowed in its own `secret_versions` (`purpose = 'fleet-managed'`) before apply —
a node without a master key cannot do that and answers 409 `secret_store_disabled`
(ADR 005).

### Node API v2

Every route requires a `node-sync` or `admin` API key (`Authorization: Bearer`); a web
session is refused, and a `node-sync` key is refused everywhere outside this prefix.

| Method and path | Purpose |
| --- | --- |
| `GET /api/fleet/v2/identity` | `{guid, panel_version, api_version: 2, master_guid, protocols: {mtproxy\|naive\|mieru: {enabled, public_host, public_port, daemon: ok\|down\|off}}, capabilities}` — `mtproxy.public_host` is the node's `MTPROXY_DOMAIN` (its first allowed host when unset); a grant's own `host`/`port`, learned from the link Telemt served, win over it when a link is rendered |
| `GET /api/fleet/v2/status` | versions and host facts from the node's version-agent (or `version_agent_unavailable`), `managed_resources`, `users` per protocol `{central, local}`, `protocols[*].traffic` (best effort: Telemt total only, NaiveProxy up/down/total, Mieru `null`) |
| `GET /api/fleet/v2/inventory` | runtime users per protocol: `{runtime_username, enabled, options, ownership: central\|local, ref}` — no secrets; for MTProxy `options` also carries the `host`/`port` of the link Telemt serves, so an imported grant renders at the runtime's endpoint |
| `PUT /api/fleet/v2/generation` | the push: `{expected_guid, generation, secrets}`, body ≤ 64 KiB. 409 with a `code`: `guid_mismatch`, `foreign_master`, `stale_generation`, `digest_conflict`, `secret_store_disabled`; 422 for an unknown field or protocol. `200 {observed, credentials}` when the reconcile finished within 25 s, `202 {observed}` when it continues in the background. `credentials` returns the credentials the node's runtime chose itself and the runtime's own reframed form of a caller credential (Telemt's Fake-TLS `ee…` secret for the bare one pushed); `Cache-Control: no-store` |
| `GET /api/fleet/v2/observed` | `{applied_generation, digest, reconcile_state: idle\|applying\|converged\|failed, resources: [{ref, protocol, runtime_username, state: enabled\|disabled\|missing\|failed\|drifted, error, revision, learned}], reported_at}` — `learned` is what the runtime taught the node about the link (Telemt's `host`/`port`, mita's `share_template`), never a credential. A report may gain fields; a central ignores the ones it does not know |
| `POST /api/fleet/v2/credentials/capture` | `{resources: [{protocol, runtime_username}]}` (≤ 200) → `{credentials: {"proto:user": plaintext\|null}, unsupported: [...]}`, `no-store`; Mieru is always `unsupported` |
| `POST /api/fleet/v2/versions/update` | `{component: telemt\|naive\|mita, version, expected_current}` → the node's own version-agent |
| `POST /api/fleet/v2/unlink` | forget the master; central-owned users become local; the runtime is untouched |

Pushing the same generation again is idempotent: the reconcile passes over what already
converged and the response has the same shape. The node's owner has one session route
of their own, `POST /api/nodes/local/unlink` («Отвязать» on the card «Этот сервер»).

### Central API

Owner-only over a session or an `admin` key; reads (`GET`) also for administrators (role `admin`):
`POST /api/nodes/{id}/pause` and `/resume` (a paused link is skipped by the heartbeat
and push loop; «Отключить» on such a node means the same), `POST /api/nodes/{id}/probe`
(heartbeat and delivery now), `GET /api/nodes/{id}/inventory` (the node's users with the
grant this panel already holds for each, `linked_grant_id`), `POST /api/nodes/{id}/import`,
`POST /api/nodes/{id}/versions/{component}`, `GET /api/nodes/{id}/generations` (desired
and observed: numbers, digests, per-resource states — credentials by reference only),
`DELETE /api/nodes/{id}`. What the node refused comes back with a code the UI can act
on: `node_unreachable` (502), `node_auth_failed` (409) or the node's own.

## Heartbeat and health

The central runs one loop for the whole fleet, every `PANEL_FLEET_HEARTBEAT_SECONDS`
(default 15, minimum 1). One tick visits every enabled link in parallel, each node
isolated from the others and serialised with the operator's «Проверить» so the two
never interleave:

1. **Heartbeat** — `GET identity` + `GET status`. Success records `online`, latency,
   `panel_version`, the identity and status JSON and clears `last_error`; a transport
   error or an error status (401/403 for a bad key, 404 from a panel without the
   API, a bare 502/503/504 page from the reverse proxy in front of a stopped panel)
   records `offline` with the failure class and code (never a response body) in
   `last_error`, keeping the last good report. A **refusal the panel itself wrote** —
   429, or a 5xx with the panel's JSON `{detail, code}` (a manager hiccup) — only
   records the error and backs the delivery off: the node is up, not down. Only a
   transition emits an event, `node.up` or `node.down` (`GET /api/events`).
2. **Delivery** — when the node owes the central a generation (`config_dirty`, or the
   acknowledged generation is behind), the latest one is pushed with its credentials
   revealed for that node only. A `202` is polled with `GET observed` on the following
   ticks (re-pushed if the node has been `applying` the same generation for 10 min). The
   report lands in `observed_generations`, in each grant's `observed_state`, in the
   provisioning operations that waited for it, and — for a credential the runtime chose
   itself — in escrow under the exact `secret_id:version` the document named.
3. **Backoff** — after the node reported the generation `failed`, or rejected the push
   with a code the central cannot answer (`guid_mismatch`, `foreign_master`,
   `secret_store_disabled`, a 422 from an older build), the re-push of that generation
   waits 30 s, then 60 s, doubling to a 10-minute cap. The backoff is dropped as soon
   as a new generation exists for that node or the node reports `converged`; the
   heartbeat itself never backs off. `stale_generation` and `digest_conflict` are
   answered differently: the central republishes the same content above the number
   the node reports (a database restored from a backup, a link cut and re-made). An
   unreachable node simply waits for the next heartbeat; the periodic retry lives on
   the central, the node retries only at its own start.

The node card («Обзор») separates **transport health** (online/offline, latency, last
heartbeat, `last_error`) from **daemon health** (`ok | down | off` per protocol, from
the node's own health checks), and shows the versions the node's version-agent
reports, users per protocol (central vs local), best-effort traffic, and `desired` vs
`applied` generation with a marker while changes are undelivered. «Проверить» runs the
same heartbeat and delivery immediately.

## Import existing users

Import makes users a node already runs the central's — **without touching them**.
From the link dialog (after «Проверить») or later from the node card's tab
«Пользователи» → «Импортировать выбранных»:

1. The central reads `GET /api/fleet/v2/inventory`; users already linked to a grant
   here are marked and skipped (`already_linked`). A user another central already owns
   (`ownership: central`) is refused — never two masters for one account, never a
   silent takeover.
2. It asks the node for the current credentials (`POST credentials/capture`) **before
   writing anything**: a node that cannot answer leaves no half-imported client.
   MTProxy and NaiveProxy hand their credential back; Mieru cannot (it stores a hash),
   so those users come back `unsupported`.
3. One transaction: a client per user (named after the runtime username) or an
   attachment to the client you picked, a grant with `origin = imported`, the
   observed enabled/disabled state and the runtime's options (for MTProxy: the
   `host`/`port` of the link Telemt serves), secret version 1 `active` where a credential came
   back, an audit row `node.import` naming the accounts (never the credentials), and
   the generation that carries them.
4. On the next push the node **adopts** these users: it records them in
   `managed_resources` with the pushed `credential_ref` and makes no adapter call —
   nothing is created, rotated or deleted by adopting (ADR 003 `adopted`).

A grant imported without a credential (Mieru) renders in the client's subscription as
`unsupported: no stored credential` — and while the client has such a grant, a
subscription cannot be **created or rotated** for it at all (409 from
`SubscriptionService`: every grant must be renderable first) — until you press
**«Ротация»** on it: the new version becomes the credential of the next generation and
the node rotates the account.

## Rotate, disable, delete

Grants on a linked panel are operated from the «Клиенты» screen exactly like local
ones; the difference is that a remote change is **declarative**. Enable, disable,
rotate and delete write the grant row, the audit row and the new generation in one
transaction and call no manager; the pusher delivers, and the node's report is what
moves `observed_state`. Until then the UI shows the grant as **«ожидает узел»**
(`observed_state = pending`).

- **Issue access** to a client on a linked panel: the grant, its `pending` credential
  and the generation are written together; the operation waits as `pending_remote` and
  finishes when the node reports the account `enabled` (or `disabled`, if you disabled
  it meanwhile). The one-time bundle of links is available after that.
- **Enable / disable** — a new `desired_state`; asking for the state the grant already
  has changes nothing.
- **Rotate** — a new credential version `pending`, the current one `retiring`; the
  changed `credential_ref` makes the node rotate the account; once the node confirms,
  the new version is `active` and the retiring one `revoked`. Telemt accepts the
  caller's secret (the pinned fork was probed on the lab host: `TELEMT_CALLER_SECRET =
  supported`); a runtime that insists on its own credential returns it in the push
  response (`credential_origin = manager`) and the central escrows it under the same
  version. Telemt frames the caller's secret as Fake-TLS (`ee` + secret + domain): the
  node hands that form back too, and the central escrows it, so the `tg://` link the
  subscription renders is the one the runtime serves. Likewise the node reports what
  the runtime taught it about the link — Telemt's public host and port, mita's share
  template with its real port — as `learned` per resource, and the central keeps it in
  the grant's options exactly as the local saga does, so a remote grant renders with the
  runtime's endpoint rather than the node's panel domain and a default port.
- **Delete** — `desired_state = deleted`; the node removes the account it owns and
  reports `missing`; the central then **purges** the grant row and revokes every version
  of its credential, so the same `runtime_username` can be granted again on the central
  (the NaiveProxy and Mieru managers retire the name on the node). An operation
  still waiting for a grant deleted before the node applied it settles as
  `compensated` instead of waiting forever.

The node's own UI and protocol API refuse enable/disable/rotate/delete on a
central-owned user with 409 `managed_by_central`; local users of the node are not
affected by any of this.

## Unlink and rollback

**Pause** (`POST /api/nodes/{id}/pause`, «Пауза») keeps the link and stops both the
heartbeat and the delivery for that node; subscribers keep working. «Возобновить»
undoes it.

**Delete on the central** («Удалить», `DELETE /api/nodes/{id}`) is refused with 409
while any *provisioned* grant on the node remains — deletions the node has not confirmed
yet included (a confirmed one is purged, so a `deleted` row still here is an account
still alive on the node) — delete the client's accesses first and wait for the node's
report, so that subscribers do not lose them silently and no account escapes as a live
local user. *Imported* grants do not block it
and are **released**, not deleted: those users existed before the link and stay on the
node as local users, untouched; the central drops their grant rows and revokes the
credentials it captured (the audit row records `released_imported`). It then tells the
node to forget its master (best effort — a revoked key must not make a link undeletable;
the audit row `node.unlink` records `node_released: true|false`), and removes the node's
grant history, the encrypted key and the `fleet_nodes` row with its link, desired and
observed generations.

**Unlink on the node** («Отвязать» on the card «Этот сервер», owner session
`POST /api/nodes/local/unlink`, or the central's `POST /api/fleet/v2/unlink`) releases
ownership: `managed_resources` and `managed_generations` are cleared and
`fleet_master_guid` is removed. Nothing on the runtime changes — every user, imported or
provisioned, keeps working and is simply local again. The central does not learn of
this by itself and still holds its link; remove the node there too, otherwise the next
generation it publishes would be accepted and make it master again (imported users
re-adopted, provisioned ones failing as collisions).

**Rolling a node back** to a previous panel image follows the general rule of
[UPGRADING](docs/UPGRADING.md): restore the complete previous generation, database
included. A v0.2 image refuses to start on a database migrated to schema 13
(«database schema 13 is newer than this code»), so the previous image alone is not a
rollback. Nothing on the node's runtime was touched by the upgrade itself:
`managed_resources` stays empty until a central pushes a generation, so restoring the
pre-upgrade database loses no fleet state on a node that was never linked. Unlink
before rolling back a node that was managed; on the central, delete its grants and the
link first.

## Security model

- **Keys.** Hashed at rest (SHA-256 of the full key, constant-time comparison, a
  prefix for lookup), shown once, revocable: disabling or deleting a key takes effect on
  the next request (401). Expiry is optional. A key acts as the pseudo-user
  `key:<name>` in the audit trail; request and response bodies are never audited or
  logged. `last_used_at` is refreshed at most once a minute. Every key is limited to
  **120 requests per minute** (429), counted per panel process.
- **Scopes.** `admin` = the owner role on the whole API (a session-less owner — treat
  it like the owner's password), `monitor` = the viewer role (reads only), `node-sync`
  = **only** `/api/fleet/v2/*` — anything else is 403. Managing keys (`/api/keys*`)
  needs the owner role — which an `admin`-scope key **holds**: such a key can mint and
  revoke keys, including further `admin` ones; a Bearer request carries no cookie, so
  there is no CSRF token to check. Give a central a `node-sync` key, never `admin`.
- **The key travels one way.** The central holds the node's key encrypted under its
  master key (`secret_versions`, bound to that node's GUID); the node holds nothing of
  the central's. A compromised node learns nothing about the others; a compromised
  central reaches every node it manages — the same boundary 3x-ui accepts.
- **TLS.** `verify` (WebPKI, system trust store, hostname check) by default; `pin`
  (SHA-256 of the leaf) for self-signed and lab certificates; no «skip». Plain `http://`
  URLs are refused. Private and local addresses need an explicit `allow_private_address`.
- **One master per node.** The node remembers the GUID of the first central whose
  generation it accepted and answers 409 `foreign_master` to any other until it is
  unlinked. Adding a panel that already reports another `master_guid` is refused on the
  central before anything is stored.
- **Bounded, typed surface.** Request bodies ≤ 64 KiB (413 above), ≤ 500 resources per
  document, ≤ 200 items per capture or import; pydantic models with `extra = forbid`.
  The node accepts documents and typed operations only — never shell, URLs, HTTP
  method/path, YAML or runtime configuration.
- **No secret leaves by accident.** `Cache-Control: no-store` on every panel response
  except `/s/` (which sets its own caching); credentials appear only inside the push
  request, the push response and the capture response; `identity`, `inventory`,
  `observed`, the node card, `GET /api/nodes/{id}/generations` and audit rows carry
  references and names only. `last_error` records the failure class and code, never a
  body.

## Legacy transport v1

Fleet v1 is the outbound-only mTLS pull agent that shipped before v0.3. It is frozen,
byte-compatible and unchanged in v0.3 — `panel/fleet.py`, the `/api/fleet/nodes*`
registry routes, the `/agent/v1/*` ingress paths, the `TypedCommand` shape and its
sequence/outbox semantics — and it remains Telemt-only. New nodes should be linked as
panels; the text below stays for installations that enrolled v1 nodes and for the
«Advanced: transport v1» drawer of a v1 node card (raw typed commands). A v1 node is
listed on the «Узлы» screen with `transport = v1` next to linked panels; «Зарегистрировать
узел v1 (mTLS-агент)» in the toolbar starts the enrollment checklist.

### Contract

- Nodes make **outbound-only HTTPS connections** to a dedicated central ingress that
  terminates TLS itself and derives node identity from the verified client certificate
  — no identity headers, no bearer fallback.
- Server identity: a WebPKI certificate for the exact `FLEET_CENTRAL_URL` hostname,
  checked against the OS trust store (`FLEET_SERVER_CA` only for private test PKI).
  Client identity: a private CA issues one certificate per node with the sole URI SAN
  `urn:mtproxy-panel:node:<node-id>`; central additionally requires an active database
  record matching node ID, serial, SHA-256 fingerprint and validity.
- TLS 1.2+, mandatory client certificate, no compression. An unknown CA fails the
  handshake; a certificate for another node, an unregistered serial/fingerprint or an
  application-revoked certificate gets 403.
- Bounds: 4 KiB request line, 8 KiB headers, body limit ≤ 64 KiB (default 16 KiB), no
  chunked request bodies, 30-second long poll, per-certificate in-process rate limit
  (default 120/minute, reset on restart).
- Commands carry protocol version, UUID, node ID, monotonic sequence, idempotency key,
  allowlisted operation, expected Telemt revision, actor, expiry, canonical payload
  SHA-256 and a typed payload; states `queued`, `dispatched`, `succeeded`, `failed`,
  `indeterminate`. An expired command is still delivered in sequence and journaled as a
  failed no-op, so expiry never executes a mutation or leaves a sequence gap.
- The agent journals receipt (SQLite WAL, `synchronous=FULL`) before invoking Telemt;
  completed results form a durable outbox; a lost acknowledgment resends the stored
  result, never the mutation; crash residue is `indeterminate` and never re-executed.
  Its only authority is a fixed loopback Telemt URL with a node-local bearer; every
  method/path/body comes from the typed allowlist and mutations carry `If-Match`.
- Allowlisted operations: inventory refresh, enable, disable, limit updates, quota
  reset. Create/delete/rotate/reveal and Mieru operations are refused — that is exactly
  what linked panels provide instead.

### Central deployment

Run the panel and the ingress against the **same** `PANEL_DATABASE`; back it up before
first start.

1. Obtain a WebPKI server certificate whose SAN matches the ingress hostname
   (`fleet.example.com` below). Never use the fleet client CA as the public server
   identity.
2. Initialise the offline client CA on a protected operator system, not in the panel
   container:

   ```sh
   python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
     fleet-ca-init --ca-dir /root/mtproxy-fleet-ca
   install -m 0644 /root/mtproxy-fleet-ca/ca.crt /etc/mtproxy-panel/fleet-client-ca.crt
   # Keep ca.key offline/root-only; the ingress needs only ca.crt.
   ```

3. Install `deploy/mtproxy-fleet-ingress.service` with `deploy/fleet-ingress.env.example`,
   adjusting the root-only Certbot source paths and the hostname. The unit's root-only
   `ExecStartPre=+` steps stage the certificate (`0444`) and key (`0400`), owned by
   `panel:panel`, into its `0700` runtime directory `/run/mtproxy-fleet-ingress`; the
   process itself runs as `panel:panel`. Restart the unit after certificate renewal
   (`systemctl restart mtproxy-fleet-ingress.service` from a root-owned deploy hook).
   Expose only the ingress TCP port; the listener terminates mTLS directly.
4. For containers, `compose.fleet-central.yaml` is a hardened overlay of the same
   `mtproxy` project sharing `panel-data`; invoke it together with `compose.yaml`, never
   alone. Bind-mounted ingress keys must be readable only by UID/GID 10001 (the agent
   image runs as UID 10002).

### Enrolling a node (`example-node-02`)

Registration, renaming, disabling and certificate revocation live on the «Узлы» screen;
the steps below stay manual precisely because the private key never leaves the node.
After «Зарегистрировать» the panel shows this checklist inside the dialog.

```sh
# central: register
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-register-node example-node-02 --display-name 'Example Region 2'

# node: key and CSR, locally
install -d -m 0700 /etc/mtproxy-agent
openssl req -new -newkey rsa:3072 -nodes -sha256 -subj '/CN=example-node-02' \
  -keyout /etc/mtproxy-agent/example-node-02.key -out /etc/mtproxy-agent/example-node-02.csr
chmod 0600 /etc/mtproxy-agent/example-node-02.key

# CA system: sign (the signer ignores requested extensions and writes the canonical URI SAN)
python -m panel.cli fleet-sign-csr example-node-02 --ca-dir /root/mtproxy-fleet-ca \
  --csr /secure-inbox/example-node-02.csr --out /secure-outbox/example-node-02.crt --days 90

# central: bind the exact serial/fingerprint/validity
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-bind-cert example-node-02 --cert /secure-inbox/example-node-02.crt
```

Move only the CSR and the issued certificate between systems — never
`example-node-02.key` or `ca.key`. On the node install the package/venv,
`deploy/mtproxy-agent.service` and `deploy/agent.env.example`; store the local Telemt
bearer as `/etc/mtproxy-agent/telemt-api-token`, restricted to the service. The service
requires a key with no group/world bits and writes only `/var/lib/mtproxy-agent`. Then
`systemctl daemon-reload && systemctl enable --now mtproxy-agent` and check
`journalctl -u mtproxy-agent --since -5m`. `auth_state` moves `unenrolled` → `enrolled`
(certificate bound) → `connected` (mTLS authorised). Queue a short-lived inventory
command first and inspect its result before any mutation.

The optional `compose.agent.yaml` joins the same private Compose network, reaches
Telemt only as `http://mtproxy:9091`, mounts no Docker socket and publishes no port; it
is valid only as an overlay of `compose.yaml`, with the key bind `0400`/`0600` owned by
UID 10002.

### Rotation, revocation and checks

Rotation is overlap-first: new key and CSR on the node → `fleet-sign-csr` →
`fleet-bind-cert` (both serials accepted) → atomic replacement and agent restart →
`auth_state=connected` plus a completed inventory command → revoke the old serial:

```sh
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-revoke-cert example-node-02 --serial OLD_HEX_SERIAL
```

Application revocation is immediate for new requests even while the TLS chain is valid;
for a compromise revoke first, stop the agent, then issue a fresh key/certificate. The v1
CA tooling publishes no OCSP or CRL — never rely on handshake-time revocation alone.

Operational checks: `openssl s_client` without a client certificate and a certificate
from another CA must both fail the handshake; a valid certificate on another node's path
and a revoked serial must return 403; confirm `auth_state`, `last_seen_at`,
`dispatched_at`, completion status and that no completed journal row remains unuploaded;
confirm Telemt still listens only on loopback and no Compose file mounts
`/var/run/docker.sock`.

### v1 limitations

Enrollment approval and CSR transfer are manual by design (no bearer enrollment
endpoint); revocation is enforced after TLS by the central database; the rate limiter is
per ingress process; only the five Telemt operations above are allowlisted. No
production host was ever enrolled with v1; the artifacts and workflow are complete, but
a real deployment still needs its DNS/WebPKI certificate, approved port and CSR
transfer. For everything beyond inventory and limits, link the panel instead.

See also [operations](docs/OPERATIONS.en.md), [upgrading](docs/UPGRADING.md),
[backup](docs/BACKUP_RESTORE.en.md), [security](SECURITY.md) and
[troubleshooting](docs/TROUBLESHOOTING.en.md).
