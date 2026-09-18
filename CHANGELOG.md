# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Historical entries below are preserved as originally recorded.

## [Unreleased]

## [0.7.0-beta.1] - 2026-09-18

Chains and lanes: a client's own traffic routed by geosite/geoip rules through a chosen node
of the fleet, the rest through the node's WARP — set up per client, from the central panel,
with the relay between nodes issued and rotated by the panel. Release note:
[docs/releases/v0.7.0-beta.1.md](docs/releases/v0.7.0-beta.1.md); design:
[ADR 009](docs/adr/009-lanes-and-chains.md).

### Added

- **Exits through the fleet** — a policy's `default_egress` and a rule's `egress` are now
  `warp | node:<guid>[,<guid>[,<guid>]][:warp]`: a chain of up to three relays of other nodes,
  leaving directly or through the last hop's WARP ([ROUTING](docs/ROUTING.en.md), «Chains and lanes»).
  The compiler resolves hops (address, port, `serverName`, public key, `shortId`, account) and
  refuses by code: `node_unknown`, `node_lacks_relay`, `relay_disabled`, `relay_credential_pending`,
  `relay_no_warp`, `chain_loop`, `node_lacks_lanes`.
- **Relay** — every node with an Xray-router carries a `vless`+`reality` inbound on a public port
  (`[egress] relay_port`, 45443 by default) behind the node's own panel TLS; it accepts only the
  accounts the central issued — one `(source node, direct|warp)` pair per source, escrowed as
  `relay-account` secrets, minted on `apply`, delivered to the local router at once or to a linked
  panel in the `relay` section of its next generation, confirmed by the node's report.
  `POST /api/routing/relay/{node}/enable | rotate` (owner, audited).
- **Lanes** — `POST /api/routing/lanes/{grant_id}` `{mode: own | service}`: a grant's own SOCKS
  account on the router's ingress, its own policy `(node, protocol, lane)` (`?lane=grant:<id>` on
  every policy route, born as a copy of the service's), every lane of a service applied as **one
  schema-2 intent**; NaiveProxy gets a `forward_proxy` handler per lane (the `LANES` block),
  Mieru a slot daemon `mita@<n>` (`[mieru] lane_slots`, ports 46101…) whose port the grant's link
  and subscription carry; on a linked panel the resource travels with `lane: own` and the node
  builds the lane itself — the lane key never leaves the node. Deleting a grant withdraws its lane.
- **«Where will it go»** — `POST …/explain {host, port}` walks a lane's saved rules.
- **UI** — «Выходы узла» chips, the node's relay line, lane tabs («Добавить полосу для клиента…»,
  «Вернуть в полосу сервиса»), a «Куда» column with chains, «Куда пойдёт…»; «Клиенты» shows and
  flips a grant's lane. Compiled documents mask relay accounts in the API, diffs and history.
- **Router manager** — `GET|POST /v1/lanes/{svc}`, `DELETE /v1/lanes/{svc}/{lane}`,
  `GET|POST|DELETE /v1/relay`, `PUT /v1/relay/accounts`; chain hops checked for reachability on
  `plan`/`apply`; `healthcheck --relay`, `--relay-enable`.
- **Installer** — `[egress] relay_port` and `[mieru] lane_slots` (defaults with `router = true`),
  UFW rules, the `mita@.service` template (its own `/var/lib/mita` per slot), relay enabled and
  proven on verify, slots verified by their sockets; upgrade path in [UPGRADING](docs/UPGRADING.md).
- **Fleet v2** — capabilities `egress.lanes.v1`, `relay.v1`; `identity.router.relay` and
  `.lanes`; generation `relay` section and resource `lane` (absent from the wire and the digest
  when unused — a v0.6 node never sees them); `observed.relay`, `observed.egress[].lanes`.
- **Lab** — tier `chains` (`remote-gate.sh chains`): a second node started from the tree on the
  stand (router with its own stub-WARP, panel over TLS), linked, its relay enabled through a
  generation, the probe grant's lane with a chain through it, `geoip → direct`, the Mieru slot,
  account rotation, rollback, withdrawal — 31 checks beside routing/router; tier `ui` drives the
  lane flow in a real browser; matrix rows `routing-lanes`, `routing-chains`, `routing-relay`,
  `routing-over-fleet-chains`, `installer-chains`, `ui-routing-chains`.

### Changed

- Migration 16 (`routing-chains-lanes`): `routing_policies` keyed by `(node, protocol, lane)`,
  the `egress = warp` constraint dropped, `access_grants.routing_lane`, tables `relay_peers` and
  `router_relays`, `observed_generations.relay_json` — additive in effect.
- The router's schema-2 render makes the service's lane the user-less catch-all: a lane account
  without an applied policy follows the service's policy instead of Xray's first outbound.
- Audit: `grant.lane.enable | disable`, `routing.relay.enable | rotate`; `routing.policy.*` rows
  carry `lane`.

### Fixed

- The Xray-router crash-looped at start when the running intent named a lane whose account had
  been forgotten (found by the `chains` tier): a lane is forgotten atomically — the intent loses
  its rules in the same generation, `lanes.json` changes only after a successful swap — and a
  start or a rollback strips such lanes instead of dying.
- A withdrawn lane on a linked panel left the service's section with the lane and its chain, so
  the node's router kept checking a hop that might be gone and refused every generation: the next
  generation carries the section without the lane.
- The fleet pusher logged a traceback when a node was unlinked during its own heartbeat.
- The installer's Mieru slot verification raced `enable --now` (the RPC server opens after
  systemd returns); the ingress probe of the router gets three tries.
- The routing preview no longer sends a rule still being typed (no selector) to the compiler.

### Fixed (post-v0.6, on the branch before this tag)


- A managed 3x-ui (`managed-new`) whose password the wizard generated could not be reached afterwards: the password was written nowhere and the panel's base path is random. `provision` now records the URL with the base path, the username and the password in the root-only `/var/lib/proxy-control/three-xui/panel-access` (0600, beside the subscription URL) — only once the panel is really configured; a failed provisioning leaves no record.
- The Journal is one line per entry again: the whole line is the `<details>` summary, «Details and IP» ends the line and the body opens underneath at full width; 11 px type and 44 px rows like the other tables (the v0.1 rule had left 10 px type and, after the overlap fix, two-storey rows). Every action name from `docs/AUDIT_EVENTS.md` now has a Russian label (`ACTION_NAMES` had stopped at v0.2, so `routing.*`, `grant.*`, `client.*`, `subscription.*`, `api_key.*`, `node.*`, `fleet.*` rows showed raw codes); a test keeps the two in step.
- The sidebar's profile button opens a real menu (who is signed in, «Administrators and API keys» for the owner, «Journal», «Sign out»); its chevron used to answer with a toast naming the role. The `ui` tier checks the menu, the one-line rows and the disclosure geometry.
- The Journal's rows overlapped the actor and the «Details and IP» disclosure at desktop widths: a v0.1 four-column rule on `.audit-row` had survived the v0.2 layout that moved the columns into `.audit-main`. The row is one column at every width; the `ui` tier now checks that no two cells of a journal row share pixels (`audit.cells_do_not_overlap`), and a test refuses a multi-track `.audit-row` rule. Seen on AMS_Z after the v0.6 upgrade.

## [0.6.0-beta.1] - 2026-09-17

The verification release: v0.6 adds no function. It answers whether everything promised
in v0.2–v0.5 works on a real host, through the real API and a real browser — and answers
with artifacts: a matrix of 58 promised functions and the proof of each
([VERIFICATION_MATRIX](docs/VERIFICATION_MATRIX.md), guarded by a test), a route audit,
a browser tier that drives every screen, a managed-3x-ui run against the real 3x-ui, a
backup-and-restore drill by the book, and the fixes for what all of that found. Release
note: [docs/releases/v0.6.0-beta.1.md](docs/releases/v0.6.0-beta.1.md).

### Added

- **Verification matrix** — `tests/fixtures/verification-matrix.json` rendered to
  `docs/VERIFICATION_MATRIX.md`: one row per promised function of v0.2–v0.5 (58) with its
  proofs (`pytest::`, `lab-host::`, `fleet::`, `ui::`, `live::`, `script::`, `doc::`), the
  routes it covers and a status; `tests/test_verification_matrix.py` refuses a proof that
  does not exist in the tree, a route or a screen without a row, a stale document, and —
  under `VERIFICATION_STRICT=1`, the release gate — any `gap`.
- **Route audit** — `scripts/dev/route-coverage.py` (in `remote-gate.sh full`): every panel
  route with the gate it enforces (`RequestContext` names them), every mutation behind CSRF
  or an API key and a role, the public routes exactly the documented seven, every route
  mentioned by a test or a lab scenario. It found three routes no test touched: Mieru
  quotas, resuming an operation, a node's version update from the central — tested now.
- **Tier `ui`** — `scripts/lab/ui-acceptance.py` (`remote-gate.sh ui`): headless Chrome over
  CDP on the lab host drives every view as the owner and once as a viewer — login (a wrong
  password refused, logout), overview, MTProxy / NaiveProxy / Mieru users (create with the
  one-time reveals, limits and quotas, disable/enable, rotate, delete), clients (grants on
  three protocols with the bundle reveal, subscription URL issued / rotated / revoked and
  proven at the public endpoint, import and adoption, suspend/resume/archive), versions
  (against the host version-agent, installed per docs/UPGRADING), nodes, routing (v0.4 and
  the v0.5 router), admins and scoped API keys, the journal with its filters; then a
  second panel from the same tree as the central: link by fingerprint with import, the
  node card's tabs, probe, pause/resume, edit, a grant delivered to the node by the pusher
  and deleted, the node's own card «управляется центром», unlink. 180 checks; no console
  error, no uncaught exception, no secret in any frame; the node's runtime users equal the
  initial ones at the end. The lab node now carries a subscription domain (`sub.lab.test`).
- **Tier `managed-xui`** — `scripts/lab/managed-xui-acceptance.sh` on the lab host: the
  pinned 3x-ui installed and provisioned through its API, every promised inbound listening
  (the coexistence fixture is moved aside for the run).
- **Scenario `backup-restore`** in `lab-host` — `scripts/lab/backup-restore-drill.py`
  follows docs/BACKUP_RESTORE on the installed node: the online SQLite copy, the master key
  apart, each manager's and the router's state and secrets with their writers stopped,
  `SHA256SUMS`; the generation broken (database, states, secrets gone); restored with
  `master-key-verify` first; users, grants, the policy, the Caddyfile, mita's config, the
  ingress keys, the router generation and the subscription URL are the same afterwards.
- `scripts/lab/guest-runner.sh host` without `LAB_KEEP_INSTALL` (uninstall and coexistence)
  and `lab-container` were run again on this tree.

### Fixed

- **Clients: issuing grants from the screen answered 422 since v0.3.** The grant dialog
  collected `.grant-protocol input:checked` over the whole document, and the link dialog
  (v0.3) reuses that class for its TLS radios — `verify` travelled to the API as a
  protocol. The collection is scoped to the grant form. Beside it, Mieru's options required
  `quotas` while the dialog sends `options: {}` for every protocol: no quota is now the
  default (`MieruOptions.quotas = []`), wire-compatible.
- **Overview: the CPU/RAM/disk usage bars never filled.** Their width was an inline
  `style` attribute, which the panel's CSP (`style-src 'self'`) drops; the width goes
  through the CSSOM after the paint, and a test refuses any inline style in the modules.
- **Login: a wrong password reloaded the form blank.** `api()` treated every 401 as an
  expired session and sent the browser back to `/login`; on the login page the 401 is the
  form's own answer and is shown as the server's refusal.
- **Routing (v0.5): a policy could not be deleted right after a detach** — attach/detach
  now record the pass-through the node runs (as a linked node's report does), so «delete»
  sees the reset it asks for; the routing card no longer paints the previous visit's
  policy while its own loads («загружается…», actions disabled), which used to swallow a
  click.
- **Installer (v0.5): the real Xray-router runner had no `compose_service_present`**, so
  `rollback`/`uninstall` left the router container running (found by the AMS_Z live
  check; the lab never saw it because `LAB_KEEP_INSTALL=1` skips uninstall). The wizard
  looks for the Xray archive under `--root` (its tests no longer depend on the host), and
  the archive is fetched from its pin when absent, like the mita package.
- **3x-ui: a refusal names its kind** (a certificate or key file, a port, validation)
  without repeating the panel's message, which echoes request fields; the managed-3x-ui
  acceptance issues the panel certificate 3x-ui checks.
- Lab probes through the Internet (a lost UDP DNS datagram, curl 28/35/52/56 to the
  control target) get a second try; a refusal by the thing under test never does.

## [0.5.0-beta.1] - 2026-09-16

The Xray-router: a node may run one dedicated, pinned Xray process as the egress
router for NaiveProxy and Mieru. A service the operator attaches to it sends its
whole traffic through the router's private, authenticated loopback ingress, and
its routing policy is then enforced by Xray — `geosite`, `geoip` and port
selectors, and a block rule beside a WARP default, which the native backends
cannot do. It is optional, never touches 3x-ui's Xray, and a node without it
behaves exactly as in v0.4. [ADR 007](docs/adr/007-routing-enforcement-ownership.md)
is accepted for the router; the spec is
`docs/superpowers/specs/2026-09-16-v0.5-xray-router-design.md`, the spike that
proved every cell on the stand `docs/spikes/XRAY_EGRESS_ROUTER.md`;
[XRAY_ROUTER](docs/XRAY_ROUTER.en.md), [ROUTING](docs/ROUTING.en.md),
[release note](docs/releases/v0.5.0-beta.1.md). This is the last vNext stage:
Phase 8 (backup/restore, the negative-test matrix, frozen identifiers) closes here.

### Added

- **Pinned artifact `xray`** (Xray-core 26.3.27, `Xray-linux-64.zip`, MPL-2.0) in
  `release/external-artifacts.json` with a digest for the archive and for each of
  the three members the installer extracts (`xray`, `geoip.dat`, `geosite.dat`);
  `installer.release.safe_extract_zip` writes exactly the reviewed members through
  the same private-stage swap as the tar extractor, bounded and digest-checked; the
  SBOM lists the members. The archive lives in `/var/lib/proxy-control/`: the
  installer fetches it from its pinned URL when absent (the mita path — the digest
  is what makes the download safe, a mismatch is discarded), a hand-staged file is
  used as it is.
- **`xray_router_manager`** — the router runtime: container `proxy-control-xray-router`
  (`compose.xray-router.yaml`, host network, identity 10006, read-only, `cap_drop:
  ALL`), a supervisor over one child `xray run` with generations, a per-service
  journal and a typed egress API on its own UDS (`/v1/status`, `/v1/health`,
  `/v1/egress/{naive|mieru}` and `plan | apply | rollback`; header
  `X-Xray-Router-Token`). An apply renders one configuration from both services'
  intents, runs `xray run -test`, swaps, reads back and commits; a failure restores
  the last known good generation, a dead child is restarted by a watchdog, a binary
  or geodata that does not match its digest keeps the router down
  (`artifact_mismatch`). Two SOCKS5 ingresses on the loopback (`naive` 45101,
  `mieru` 45102) with a per-service credential as the service's identity;
  `geoip:private → block` first on every ingress and `IPOnDemand` resolution,
  so a rebinding name cannot reach the host; UDP is not relayed.
- **Provider `router` in the managers**: the naive-manager renders `upstream
  socks5://user:password@127.0.0.1:45101` from `NAIVE_EGRESS_ROUTER` and the
  credential file in its state directory, the mieru-manager mita's `egress` with
  `socks5Authentication` from `MIERU_EGRESS_ROUTER`; both probe the ingress with
  the SOCKS5 username/password method before applying, redact the credential in
  every view and diff, and re-render their block at bootstrap after a key rotation
  (`router_credential_stale` until then), the installer's seed included.
- **Routing backend `xray_router`** (migration 15): `RuleMatch` gains `geosites`
  and `geoips` (Xray geodata codes; `private` refused) and ports-only rules;
  the compiler produces the router's typed intent — never raw Xray JSON — for an
  attached service and names the router when a native backend cannot enforce a
  rule; `Compiled.compiler_version` is `"2"`.
- **Attach and detach** as explicit owner actions (`POST
  /api/routing/targets/{node}/{protocol}/attach | detach`, audit
  `routing.target.attach | detach`): the router's section first (pass-through),
  then the native block to the ingress; detach in the reverse order. The policy
  is retargeted as a draft; `targets[].router = {available, attached,
  xray_version, …}`. Refusals: `router_unavailable`, `router_unreachable`,
  `not_attached`, `node_lacks_router`, `artifact_mismatch`, `geosite_unknown`,
  `geoip_unknown`.
- **Fleet v2**: the node declares `egress.router.v1` and `identity.router`; a
  generation's `egress` section may carry `backend: xray_router`, a `companion`
  document for the other manager and `passthrough` — all omitted from the wire
  and the digest when absent, so a v0.4 node and a v0.4 central keep every
  digest and ignore what they do not know; the pusher records the router's
  revision beside the native one.
- **Installer `[egress] router`** with the choice `router` for `naive` / `mieru`:
  adapter `xray_router` (between `warp` and the services) verifies the staged
  archive, extracts the members, creates identity 10006, prepares
  `/var/lib/xray-router`, writes the manager token and the two ingress
  credentials (root:10006 0440), `.env.xray-router`, and starts the service;
  verify reads the manager's status, checks both ingresses are loopback-only and
  sends one authenticated CONNECT through the NaiveProxy ingress. `naive` and
  `mieru` learn the router through their env and keep their own credential
  copies; the wizard offers the router to every profile with NaiveProxy or Mieru.
  `scripts/rotate-xray-router-ingress.sh` rotates the keys and recreates the
  router and the managers; `scripts/prepare-xray-router-state.sh` owns the state
  directory.
- **UI «Маршрутизация»**: the backend badge (Caddy / mita / Xray-router), the
  router line with «Подключить к Xray-router» / «Отключить от Xray-router» and
  their confirmations, the fields geosite / geoip / ports in a rule, the router's
  reasons and warnings in the preview.
- **Lab tier `router`** (`remote-gate.sh router`, `fleet-acceptance.py --router`):
  router-01…14 on the node installed with `[egress] router = true` — attach,
  whole-WARP and a block beside it through the router, port / geosite / geoip
  rules, an unknown geodata code refused by Xray, Mieru attached with a selective
  rule, the ingress refusing a missing or a cross-service credential, rollback
  with the Caddyfile untouched, the watchdog after a SIGKILL, fail-closed without
  the provider, no credential in the API, audit, database or logs, key rotation,
  detach and the untouched host. `lab-host` installs the router by default.
- **Phase 8**: `docs/SECURITY_TEST_MATRIX.md` maps every row of the vNext
  negative-test matrix to a test or a lab scenario; `BACKUP_RESTORE` gains the
  router's state and secrets; `tests/test_deploy.py` freezes the router's
  identifiers and proves nothing of it names a 3x-ui path;
  [COMPATIBILITY](docs/COMPATIBILITY.md) records what v0.5 froze.

### Changed

- **Fix-wave of the v0.4 findings**: the naive-manager redacts the userinfo of a
  hand-written `upstream` in its egress views and `plan` diffs; the dead
  `installer.planner.profile_environment` is gone.
- The naive-manager's state allowlist (`prepare-naive-state.py`) admits
  `xray-router-ingress`; the mieru-manager's `egress.refresh` restart transaction
  re-renders a seeded router section after a rotation; Core treats the router's
  secrets and Compose service as adjacent (repair, ownership).
- The routing screen sends `backend` with a policy so a new policy is born on
  the backend that will enforce it.

### Security

- The ingress credential lives only in the secret files, the managers' copies,
  Caddy's `upstream`, mita's `socks5Authentication` and the router's rendered
  generations; every API view, plan diff, identity, generation, audit row,
  report and log is free of it, and the lab's secret scan fails on the shape.
- The router is its own runtime: no `/usr/local/x-ui`, no `/etc/x-ui`, no shared
  template; a digest mismatch of a member refuses to start rather than run an
  unpinned binary.
- Management traffic never enters the router; the router blocks private
  destinations before any policy rule and refuses `private` as a selector.

### Deferred (roadmap)

- A static bridge into 3x-ui's Xray, canary rollouts of a policy, per-grant
  routing, UDP relay through the router, regular expressions in selectors
  (spec §15).

## [0.4.0-beta.1] - 2026-09-14

Routing: the operator sets, per node and per proxy service, where the clients'
traffic leaves — directly, through the host's WARP, or not at all — as an
engine-neutral policy that the panel compiles for the backend the node actually
runs and applies transactionally with a rollback, locally and on linked panels.
The design is [ADR 006](docs/adr/006-routing-policy-ir.md) (accepted)
and [ADR 007](docs/adr/007-routing-enforcement-ownership.md); the spec
`docs/superpowers/specs/2026-09-14-v0.4-routing-design.md`; the spike that
fixed what each backend can honestly enforce —
`docs/spikes/VNEXT_ROUTING_ENGINE.md`. The Xray router (v0.5) stays roadmap:
this release is capability-limited on purpose, and the preview says so instead
of narrowing a rule silently — [ROUTING](docs/ROUTING.en.md),
[release note](docs/releases/v0.4.0-beta.1.md).

### Added

- **Routing policies** (migration 14: `routing_policies`, `routing_rules`,
  `routing_applies`, `managed_egress`): one policy per (node, protocol) for
  NaiveProxy and Mieru — a default (`direct` | `egress: warp`), a fallback when
  WARP is down (`fail_closed` | `approved_direct`) and ordered first-match rules
  (`domains`, `cidrs`, `ports`; `direct` | `block` | `egress`), with optimistic
  revisions. MTProxy is out of scope (`protocol_out_of_scope`).
- **Compiler and preview** (`panel/routing/compiler.py`): the policy compiled
  into the document the node's manager validates — `naive_native` (Caddy
  forwardproxy `upstream` + `acl`) or `mieru_native` (mita `egress`) — against
  the capabilities the manager declares. Whatever a backend cannot enforce
  comes back as `unsupported` with the rule named: NaiveProxy has one upstream
  per service and no selective rules, and forwardproxy skips its ACL beside an
  upstream, so a block rule cannot hold with a WARP default; block by port is
  not a deny in either engine; loopback, link-local and private networks may be
  blocked but never opened. A reachable-but-down WARP fails closed unless the
  policy chose `approved_direct`, shown as a warning.
- **Egress API of the managers** (`/v1/egress`, `/v1/egress/plan|apply|rollback`
  on both UDS): the naive-manager owns a marked block inside `forward_proxy`
  (an `upstream` written by hand is adopted as `custom` and restored verbatim
  on rollback), the mieru-manager owns mita's `egress` section (applied by a
  restart — `mita reload` does not pick it up). Revision CAS, a reachability
  probe of the provider before apply, a readback after reload, a journal of
  the last ten entries; `egress_conflict`, `egress_invalid`,
  `egress_unreachable`, `egress_readback_mismatch`,
  `manual_intervention_required`. The mieru-manager container moves to the
  host network for the probe (still `read_only`, `cap_drop: ALL`, no listener).
- **Installer `[egress]`** (`warp`, `warp_port`, `naive`, `mieru`): WARP moves
  out of `[three_xui]` (dual-read of the old keys, one warning) and each
  service chooses its egress; `NAIVE_EGRESS_WARP` / `MIERU_EGRESS_WARP` reach
  the managers through `.env` and Compose. The initial egress is seeded once;
  upgrade and repair leave it alone — [INSTALLER_REFERENCE](docs/INSTALLER_REFERENCE.en.md).
- **Routing over Fleet v2**: a node declares `egress.v1` and its egress targets
  in `identity`; a generation carries an optional `egress` section (omitted
  from the wire and the digest when absent, so a v0.3 node or central still
  agrees on every document without one); the node applies it after the
  resources, idempotently by digest, and reports `converged | failed |
  unsupported` per protocol; the central moves the policy to `applied` /
  `failed` from that report. A local apply is refused while a central manages
  the node (`managed_by_central`).
- **`/api/routing/*`**: targets (nodes × protocols with backend, capabilities,
  providers — never the provider's endpoint — and the policy's state), `GET`/
  `PUT`/`DELETE` of a policy, `preview` of a draft without saving, `apply`,
  `rollback`, `history`; audited as `routing.policy.update | apply | rollback |
  delete` — [PANEL](PANEL.en.md), [AUDIT_EVENTS](docs/AUDIT_EVENTS.md).
- **UI «Маршрутизация»**: node and protocol tabs, the policy editor (defaults,
  rules with ↑/↓ and drag), a live preview (status, reasons tied to the rule,
  warnings, diff, rollback target), «Применить» only for a saved supported
  policy, history; the node card gains the line «Маршрутизация: …».
- **Lab tier `routing`** (`scripts/dev/remote-gate.sh routing`,
  `fleet-acceptance.py --routing`, `scripts/lab/socks5-stub.py`): whole-service
  WARP through a logging SOCKS5 stub, block by domain and CIDR with the cover
  site alive, Mieru's selective rule, rollback byte for byte, a provider down
  → fail-closed, nginx and nftables untouched.
- **`scripts/install-release.sh`**: fetches the four release files, checks
  `SHA256SUMS`, the manifest, optionally a pinned digest (`--sha256`) and the
  GitHub attestation, extracts and hands over to the installer's wizard through
  one `sudo`; `--requirements` prints what the host needs and what gets
  installed. The same path README documents for beta releases. A Russian
  changelog starts with this release: [CHANGELOG.ru.md](CHANGELOG.ru.md).

### Changed

- **Fix-wave of the v0.3 post-merge findings**: a node answering 429, or a 5xx it
  wrote itself (JSON `{detail, code}`), keeps its link status (backoff, not
  `offline`) — a bare 502/503/504 page from the proxy in front of a stopped panel
  is still `offline`; escrow only from a report about the
  current generation; unchanged plaintext is not re-escrowed; heartbeat bodies
  capped at 1 MiB; `POST credentials/capture` takes `purpose: escrow | import`
  and refuses unmanaged users for escrow; `DELETE /api/nodes/{id}?force=1`;
  «применено, ожидает учётные данные» on the node card; tmpfs `/tmp` for the
  managers and the agent; audit event names unified in `docs/AUDIT_EVENTS.md`.
- `GenerationDocument.canonical_digest` is computed over the wire form
  (`egress` left out when absent); every document without egress keeps the
  digest it had in v0.3.

### Security

- Routing documents, policies, `identity`, observed reports and audit rows
  carry no secret and no provider endpoint: the WARP URL lives only in the
  managers' environment. A `direct`/`egress` rule for loopback or a private
  network is refused at compile time (`private_destination`); the manager
  refuses the same in its own validation.

## [0.3.0-beta.1] - 2026-09-14

Fleet v2: one panel becomes the **central panel** and manages other panels over
their own HTTPS domains with scoped API keys. Linking is three actions in the
UI, and nothing beyond the panel image appears on a host. The design is
[ADR 008](docs/adr/008-panel-to-panel-transport.md) and the spec
`docs/superpowers/specs/2026-09-11-v0.3-central-panel-design.md`; the release
was gated on the disposable lab host and checked live against a production
node — [release note](docs/releases/v0.3.0-beta.1.md). Routing (v0.4), the
Xray router (v0.5), transitive nodes, metric history, panel-to-panel mTLS and
remote update of a node's own panel remain roadmap.

### Added

- **Scoped API keys** (migration 9): «Администраторы → API-ключи» — a name, a
  scope `admin | monitor | node-sync`, an optional expiry. Only the SHA-256 is
  stored; the plaintext `pc_<prefix>_<secret>` is shown once. `Authorization:
  Bearer` is accepted on the whole `/api/*` (`admin` acts as the owner,
  `monitor` as a viewer, `node-sync` reaches `/api/fleet/v2/*` only), 120
  requests per minute per key, audited as `key:<name>`; enable, disable and
  delete take effect on the next request. `/api/keys*` for the owner —
  [PANEL](PANEL.ru.md).
- **Linking a panel** («Узлы → + Панель»): the panel URL and its `node-sync`
  key, TLS `verify` (WebPKI) or `pin` (SHA-256 of the leaf, «Получить
  отпечаток»), private addresses only behind an explicit checkbox, an SSRF
  guard on the URL; «Проверить» saves nothing. The node key lives encrypted
  under the central's master key. A linked panel gets a card (Обзор /
  Пользователи / Обновления) with Пауза / Проверить / Изменить / Удалить, a
  heartbeat every 15 s (`PANEL_FLEET_HEARTBEAT_SECONDS`), `node.up` /
  `node.down` events, 202 polling, resync on `stale_generation` /
  `digest_conflict`, and a per-node backoff (30 s → 10 min) after a failed or
  rejected generation; `GET /api/nodes/{id}/generations` —
  [FLEET](FLEET.ru.md).
- **Generations** (node side, migrations 10–11): the desired state of a node is
  an immutable, numbered, digested document (≤ 64 KiB, ≤ 500 resources)
  compiled from the central's grants and published only when its content
  changes. The node refuses a lower number, a digest conflict and a foreign
  master (one master per node, 409 `guid_mismatch | foreign_master |
  stale_generation | digest_conflict | secret_store_disabled`); its reconciler
  creates, rotates, enables, disables and updates options through the protocol
  adapters, deletes orphans, reports a collision with a local user as `failed`
  instead of adopting it, never touches local users, answers 409
  `managed_by_central` to every local writer that touches a central-owned
  user, resumes an unfinished generation at start and answers 202 when an
  apply exceeds 25 s. «Отвязать» on the card «Этот сервер»
  (`POST /api/nodes/local/unlink`); a stable `panel_guid` per panel and the
  release version reported from `VERSION` (`PANEL_VERSION_FILE`).
- **Import** of a node's existing users: they become clients and
  `origin=imported` grants without any change on the node; MTProxy and
  NaiveProxy arrive with their credentials (capture), Mieru without one until
  «Ротация».
- **Grants on a linked panel**: issue, enable, disable, rotate and delete are
  declarative — row, audit and generation in one transaction, «ожидает узел»
  until the node reports (migration 12, `pending_remote`). A confirmed deletion
  purges the grant and revokes its credential versions, so the name can be
  granted again. A credential the runtime chose itself (Telemt's Fake-TLS form
  of a caller secret) is escrowed under the version the document named, and
  the node reports what its runtime taught it about a link (`learned`:
  Telemt's public host and port, mita's share template; migration 13), so a
  remote grant renders the link the runtime actually serves. Subscriptions and
  bundles carry every node's own public hosts.
- **Telemt**: the pinned fork accepts a caller-supplied `secret` on create and
  rotate; a runtime that refuses falls back to a manager-generated secret and
  says so (`credential_origin`). `update_options` on all three adapters.
- **UI**: the «API-ключи» section, the «+ Панель» dialog with «Проверить»,
  «Получить отпечаток» and the import list, the linked-panel card, GUID and
  «Отвязать» on «Этот сервер», linked panels in the node picker of «Выдать
  доступ».
- **Lab tier `fleet`** (`scripts/lab/fleet-acceptance.py`,
  `scripts/dev/remote-gate.sh fleet`, the case `fleet` of `guest-runner.sh
  host`): the installed node linked to an in-process central over HTTPS with a
  `node-sync` key — key → link → import → grants on all three protocols proven
  with sing-box, mihomo and the TDLib resPQ probe → disable / rotate / delete →
  offline convergence → restart mid-apply → key revoke → unlink, the node left
  exactly as found. `LAB_KEEP_INSTALL=1` keeps the `lab-host` install for it —
  [VALIDATION](docs/VALIDATION.md).
- Documentation: ADR 008; [FLEET](FLEET.ru.md) rewritten for v2 with v1 as
  «Legacy transport v1»; [PANEL](PANEL.ru.md) (API keys);
  [OPERATIONS](docs/OPERATIONS.ru.md) §11; [UPGRADING](docs/UPGRADING.ru.md)
  («до v0.3»: migrations 9–13, nodes before the central, `VERSION` shipped by
  rsync); [COMPATIBILITY](docs/COMPATIBILITY.md) (the frozen panel-to-panel
  contract); [VNEXT_ARCHITECTURE](docs/VNEXT_ARCHITECTURE.md).

### Changed

- `compose.yaml` bind-mounts `./VERSION:/app/VERSION:ro` and the installer
  copies `VERSION` into the project directory; hosts updated by rsync must
  ship it with the code.
- `fleet_nodes` gained `transport` (`v1` for every existing node, `panel` for a
  linked one); a linked panel appears on the «Узлы» screen next to v1 nodes
  and the local node, and «Отключить» on it pauses the link.
- `provisioning_operations` was rebuilt to admit the status `pending_remote`
  (rows, index and foreign key preserved).
- The panel reads `MTPROXY_DOMAIN` (already in `.env` for `mask` and
  `mtproxy`) to report its MTProxy endpoint to a central; the host and port a
  grant learned from Telemt take precedence in rendered links.
- A `TelemtIndeterminate` outcome propagates raw through the caller-secret
  fallback, so the saga resumes instead of compensating.
- `DELETE /api/nodes/{id}` releases imported grants (rows dropped, captured
  credentials revoked, audit `released_imported`) and refuses only while a
  provisioned grant is not confirmed deleted.

### Fixed

- Found on the lab tier `fleet`: a remote MTProxy grant rendered a bare 32-hex
  secret at the node's panel domain and a remote Mieru grant rendered the
  node's Naive host with port 8443 — both links unusable. Links are now built
  from the facts the node learned from its runtime (above).
- Found on the live check (a production node linked to the lab central):
  `DELETE /api/nodes/{id}` on a containerised central answered 500 `disk I/O
  error` — the panel runs as uid 10001 on a read-only root while `/tmp` was a
  root-only tmpfs, so SQLite had nowhere to spill the statement journal of the
  cascading delete. `Database.connect()` sets `PRAGMA temp_store=MEMORY` and
  the `/tmp` tmpfs of the panel and of the v1 fleet ingress is owned by the
  service user.
- Found in the final review of the branch: the TLS `pin` of a linked panel is
  checked inside the handshake, before any request leaves the central
  (previously the leaf was compared after the response, when the Bearer key
  and the generation had already been sent); ADR 003 is enforced before the
  adapter is called on the node's local lifecycle paths, and `capture` /
  `adopt` are gated the same way; a node whose runtime reframes a caller
  secret is re-asked for it after a lost push reply or a 202, and a one-time
  `missing` report survives a 202; imported MTProxy grants render Telemt's
  host and port; the node's unlink dialog says what unlink does.
- Regressions of that fix wave, each caught by its scoped re-review: a
  re-granted name under a new ref keeps its ownership row; credential capture
  asks the node in batches of `CAPTURE_MAX_RESOURCES` (200) and a capture
  failure never marks the node offline; capture, escrow and confirmation
  happen only on a settled report (`converged | failed`, never `applying`); a
  capture failure of any kind (transport error, node 4xx/5xx, `null` for a
  manager-chosen credential) leaves the version `pending`, withholds the
  generation's acknowledgement and re-sends the same generation on the next
  tick instead of activating an un-captured secret; `TelemtAdapter.capture`
  wraps `TelemtError` like every other adapter call.
- A deleted grant no longer blocks re-granting the same `runtime_username`
  forever: the row is purged once the deletion is confirmed (locally right
  away, on a linked panel when the node reports `missing`).
- `read_panel_version` tolerates a missing, unreadable or empty `VERSION`
  (`dev`) instead of keeping the panel from starting.

## [0.2.0-beta.1] - 2026-09-11

The local control plane: the panel owns **clients**, their **accesses** and
the credentials behind them, and hands each client one invalidatable
**subscription URL** on a dedicated domain. The design is ADR 001–007 and
[VNEXT_ARCHITECTURE](docs/VNEXT_ARCHITECTURE.md); the release was gated on the
disposable lab host, not in CI — [release note](docs/releases/v0.2.0-beta.1.md).
Fleet v2, routing and the Xray router stayed roadmap; the on-device import of a
subscription into Karing is the owner's manual check.

### Added

- **One database boundary** (`panel/database.py`) with versioned, checksummed
  migrations (`db-migrate`, `db-status`); the baseline migration adopts a
  v0.1.0 database in place. Audit rows are written inside the transaction of
  the change they describe and carry `X-Request-Id`, so a response and its
  trail can be matched.
- **An encrypted secret store** (AES-256-GCM, per-row AAD) behind a master
  keyring that the installer creates and preserves; the panel refuses to start
  when encrypted rows exist and the key is missing. `master-key-init | rotate
  | verify` in the CLI; what to back up and how to restore —
  [BACKUP_RESTORE](docs/BACKUP_RESTORE.ru.md).
- **Clients and access grants**: import existing manager accounts read-only,
  adopt their credentials (MTProxy and NaiveProxy by capture, Mieru by an
  explicit rotation), issue new accesses through a journaled saga that ends in
  exactly one of `succeeded`, `compensated` or
  `manual_intervention_required` (`operations-resume` in the CLI). Node
  lifecycle with a reserved `local` node; the screens «Клиенты» and «Узлы».
- **Idempotent manager operations**: NaiveProxy and Mieru accept a
  caller-supplied credential and an operation id and replay a lost reply;
  Telemt reads its live link back after an indeterminate call.
- `PANEL_VNEXT_WRITER=legacy|domain`: the protocol endpoints keep their v0.1.0
  contract in both modes (the whole API suite runs twice); in `domain` the
  panel owns the credential — the migration order is in [PANEL](PANEL.ru.md).
- **Client subscriptions**: a bearer URL `https://<subscription domain>/s/<token>`
  (stored as a hash, revealed once), rendered from escrow as `raw`, `singbox`
  (Karing; `client=singbox` for the official core), `clash` (mihomo),
  `manifest` and `html`; an ETag from the effective set of grants, `304` on
  `If-None-Match`, `Profile-Update-Interval`, a per-address rate limit, no
  access log anywhere on the path, and a compatibility matrix that names what
  a client cannot consume instead of shipping a link it cannot parse. The
  generation moves in the transaction of the change; `subscription.*` events
  and `GET /api/events`.
- **A dedicated subscription domain** — `domains.subscription` in
  `install.toml` (the wizard asks for it): a SAN on the core certificate, an
  SNI route and its own Nginx `server` that serves only `/s/` with
  `access_log off`; the panel's own name refuses the path without logging it.
- Lab tooling the gate relies on: `scripts/dev/remote-gate.sh`
  (`quick | full | compose | lab-container | lab-host`),
  `scripts/lab/host-teardown.sh` and `scripts/lab/subscription-acceptance.py`
  (the live subscription check with the real sing-box and mihomo cores).
- ADR 001–007, [VNEXT_ARCHITECTURE](docs/VNEXT_ARCHITECTURE.md) and the
  capability matrix [VNEXT_CAPABILITIES](docs/VNEXT_CAPABILITIES.md) /
  `tests/fixtures/vnext-capabilities.json`.

### Changed

- **The release train**: the lab host gates, CI confirms. `release.yml`
  rebuilds the tagged commit twice, refuses any archive whose digest differs
  from the one the lab accepted (`expected_sha256` input or a `lab-sha256:`
  tag annotation), attests and publishes; the QEMU `lab-amd64` job is gone.
  Pre-release tags (`vX.Y.Z-*`) build the same way.
- `panel/entrypoint.sh` runs uvicorn with `--no-access-log`; the subscription
  path is a bearer token and an access line would be a copy of it.
- MTProxy links are rebuilt from the host and port Telemt itself reported
  (learned into the grant's options), not from the panel's domain.
- The `mierus://` link parser lives in `panel.protocols.mieru` and serves both
  the reveal and the subscription renderers.

### Fixed

- `full` profile installs ended with a panel that did not know NaiveProxy
  (`feature unavailable`): the Naive and Mieru adapters each started Compose
  with only their own overlay, and whichever applied last recreated the panel
  without the other's environment. Both now include the sibling overlay
  whenever its generation is present.
- `repair` on a `managed-new` 3x-ui host failed twice over: the route verify
  demanded that the 3x-ui panel and subscription listeners be Xray inbounds,
  and the runtime verify ran before the restarted panel had bound its port.
- A finished `uninstall` blocked the next `install` with «an installer
  transaction already exists» although the host owned nothing anymore; it is
  now cleared like a finished rollback, so `uninstall` → `install` re-renders
  owned files from a new release over the preserved data (`managed-new` 3x-ui
  still refuses a preserved `/etc/x-ui/x-ui.db`, as documented).
- `db-status` on a v0.1.0 database crashed instead of reporting that nothing
  was applied.
- The release workflow read the lab digest from the local tag ref, which
  `actions/checkout` peels to the commit; the annotation is now read from the
  tag object through the API.
- The one-time bundle dialog's «copy» buttons had no handler.
- `Database.__init__` retried `PRAGMA journal_mode=WAL` under contention
  (found by a 300-run stress of a test that failed once in a full run).

## [0.1.0] - 2026-09-09

The first packaged release: a transactional installer that takes a clean
Ubuntu 24.04 host from nothing to a verified deployment, and a release
acceptance lab that proves it on real hardware. The panel itself carries the
work done since 1.3.0 on the MTProxy, NaiveProxy and Mieru contours.

### Added

- A transactional release **installer** (`installer/`) with a durable journal
  and an explicit `prepare → apply → verify` lifecycle per adapter. Nothing is
  applied until the operator confirms the plan digest, every mutation is owned
  by exactly one adapter, and an interrupted run resumes or rolls back instead
  of leaving a half-installed host.
- A bilingual interactive wizard, and the `wizard`, `plan`, `install`, `status`,
  `resume`, `repair`, `report`, and `uninstall` subcommands.
- Profiles `core`, `core-naive`, `core-mieru`, and `full`, selecting exactly the
  adapters a configuration needs: `packages`, `nginx`, `certificates`,
  `firewall`, `core`, `naive`, `mieru`, `three_xui`.
- Per-protocol acceptance that proves the deployment works rather than that it
  started: a real `resPQ` exchange for MTProto, cover HTTPS plus an
  authenticated `CONNECT` with closed-tunnel accounting for NaiveProxy, and the
  pinned official client carrying traffic over each transport for Mieru.
- Reproducible release builds, an SPDX SBOM, build provenance, and
  `install-bootstrap`, which verifies the archive, its checksum, and its
  manifest before its single `exec sudo` and never downloads and executes in one
  step.
- A release acceptance lab that installs a real release archive into a
  disposable systemd container and onto a disposable bare-metal host, covering
  install, repair, a repeated install, reboot recovery, an interrupted phase,
  reporting, secret scanning, uninstall, and shared-443 coexistence.
- Pinned upstream artifacts with URLs, digests, and SPDX licences in
  `release/external-artifacts.json`: the `mita` server, the official `mieru`
  client used by the acceptance, and the 3x-ui panel with its Xray core.
- [Installer reference](docs/INSTALLER_REFERENCE.ru.md) /
  [installer reference](docs/INSTALLER_REFERENCE.en.md), and a documentation
  contract that runs every documented command through the shipped argument
  parser so the documentation cannot drift from the CLI.
- A host resource card on the overview (CPU, memory, root filesystem, with
  warning thresholds) sourced from a read-only `GET /v1/host` on the host
  version-agent — the panel runs read-only with every capability dropped and
  mounts nothing from the host but the agent socket, so when the agent is
  unreachable the card states the reason instead of guessing.
- NaiveProxy per-user traffic quotas: `quota_bytes` on create and a quota
  endpoint, with usage, remaining and exhaustion reported in the panel; a
  manager thread enforces them on an interval (`NAIVE_QUOTA_INTERVAL_SECONDS`,
  default 60 s) and transactionally removes an exhausted user from the managed
  Caddy block.
- A NekoBox tab in the NaiveProxy one-time reveal with a
  `naive+https://USER:PASSWORD@HOST:443#NAME` link and a matching QR.
- Standalone documentation, governance templates, a screenshot policy,
  third-party notices, and CI over the whole Python suite, Ruff, every tracked
  shell script, every Compose variant, the project images and documentation
  links.

### Changed

- WARP is documented and wired as one loopback SOCKS5 endpoint at
  `127.0.0.1:45000`, with the per-protocol split stated explicitly: Xray routes
  only `warp_domains` through it, while NaiveProxy and Mieru route all traffic
  through it.
- The NaiveProxy site listens on a port-only address and enables probe
  resistance, so a tunnelled `CONNECT` reaches `forward_proxy` and an
  unauthenticated request is served the cover site instead of `407`.
- NaiveProxy requires an explicit `NAIVE_PUBLIC_HOST`; the personal fallback
  is gone.
- Quota enforcement moved out of the Naive manager's socket accept loop into
  its own thread with backoff, so a Caddy validate/reload can no longer stall
  the control socket; `GET /v1/health` and `GET /v1/traffic` are reads again
  and never rewrite the managed config. A refused enable carries the reason
  `quota_exhausted` to the panel; removing or raising a quota records
  `disabled_reason: manual`.
- Managers tolerate a client that hangs up mid-response instead of logging a
  traceback per probe, and their health probes read the full response before
  closing.
- The panel backend is composed from protocol- and responsibility-specific
  route modules behind the same `panel.app:create_app`, API paths, RBAC,
  security headers and one-time reveal behaviour; audit reads support bounded
  cursor pagination and actor / action / target filters.
- Fleet v1 is Telemt-only: Mieru operations and capability advertisement were
  removed from its models, node execution path and documentation.
- Naive and Mieru one-time reveals expose client-specific Native, Karing and
  verified manual variants; Karing receives a full profile through its
  documented deep link instead of a raw endpoint QR, and unsupported
  combinations (Shadowrocket with Mieru, Mieru port ranges) are reported
  instead of fabricated.
- The Mieru manager, deployment guidance and panel version metadata admit
  pinned mita 3.36.x binaries while keeping 3.35.x compatibility; product
  descriptions are neutral across Telemt/MTProto, NaiveProxy/Caddy, Mieru/mita,
  panel and fleet, and the documentation describes persistent Telemt
  configuration and its authenticated private API accurately.

### Fixed

- An opt-in, idempotent systemd-managed TCP MSS clamp for Mieru listeners
  addresses confirmed mobile return-path black holes without touching
  unrelated firewall rules and removes its exact rule on stop.
- Creating or rotating an MTProxy access refreshes the list without a page
  reload: the reveal payload carried no QR while the dialog required one, so
  it threw after the modal closed and the new profile stayed invisible until
  F5. The QR now travels with the reveal, and a dialog that cannot render is
  reported without blocking the refresh.
- Busy buttons no longer stick on «Создаём…»: handlers read
  `event.currentTarget` in `finally`, after dispatch had ended and it was
  already null; the target is captured while it is still live.
- Mieru transactions no longer re-hash the blanked password mita returns for
  an already stored user, so the second and later create / rotate / delete /
  quota edits succeed instead of failing the readback check.
- Mieru Native reveals provide a complete `mieru-client.json` (active profile,
  RPC port, SOCKS5 port) that a brand-new official client can apply; the
  `mierus://` link and QR are kept for adding the profile to a configured
  client. Rotated Mieru credentials produce a generation-specific Karing
  profile name, so Karing imports the replacement instead of keeping the
  revoked password; NekoBox+ is marked unsupported for Mieru.
- Installer panel TLS vhosts serve a neutral cover at `/` for unauthenticated
  requests; public ACME roots are forced to `0755` under restrictive umasks;
  route repair / uninstall validates and removes only the marked Proxy Control
  block, preserving adjacent SNI routes.
- Naive private-listener start / reload disables automatic HTTPS redirects, and
  Naive Karing reveals again provide a verified `karing://install-config` deep
  link with a matching QR.
- Client tabs without a verified QR format drop the QR pane instead of
  rendering an empty white placeholder, and toasts are raised into the top
  layer, so «ссылка скопирована» is no longer painted behind an open modal.

### Security

- Login attempts are atomically reserved in SQLite before Argon2 verification,
  each request can release only its own reservation after success, and
  password checks have bounded concurrency, so concurrent or cross-account
  batches cannot bypass the configured rate limit.
- The former host/systemd MTProxy install and uninstall scripts are gone;
  supported deployments use the Compose/Telemt installer path.
- The panel / RBAC, local manager, accounting, Mieru external-process, fleet
  mTLS, transactional host mutation, backup and fail-closed boundaries are
  documented in [SECURITY](SECURITY.md).

## [1.3.0] - 2026-08-11

### New Features

*   **Multi-user secret management**: Per-user secrets in `/etc/mtproxy/secrets.d/` with `mtproxy-user.sh` utility (add / del / list / link). Revoking one user's access doesn't affect others.
*   **Fake TLS domain auto-selection**: Installer picks a plausible domain from a built-in list (Microsoft, Discord CDN, Cloudflare, etc.), verifying DNS resolution and TLS 1.3 support. Custom list via `--domain-list`.
*   **Port flexibility**: `--port auto` (random), `--port 443` (HTTPS camouflage), or explicit port number. Default is random to avoid fingerprinting.
*   **IPv6 support**: `--ipv6` flag enables `-6` mode and outputs an IPv6 connection link.
*   **Network tuning**: `--tune-net` applies sysctl tuning (BBR congestion control, buffer sizes, backlog).
*   **Watchdog**: systemd timer checks service health every 2 minutes and auto-restarts on failure (with 3-strike threshold for stats endpoint).
*   **Binary auto-update**: Weekly cron job pulls upstream changes, rebuilds, and restarts — with automatic rollback on build or startup failure.
*   **Configuration persistence**: Settings saved to `/etc/mtproxy/env` for seamless re-installs and use by `mtproxy-user.sh`.
*   **QR code**: Connection link displayed as QR code if `qrencode` is available.
*   **Journald limit**: Log volume capped at 200M via journald drop-in.

### Improvements

*   **Uninstall**: Now removes watchdog timer/service, `mtproxy-user.sh`, sysctl drop-in, journald drop-in, and watchdog state file.
*   **Rate-limiting resilience**: Installation continues with a warning if `iptables` modules (hashlimit/conntrack) are unavailable, instead of crashing.
*   **NAT detection**: Auto-detects internal vs external IP for cloud VPS (AWS, Hetzner, etc.) and adds `--nat-info`.
*   **Restart-storm protection**: `StartLimitIntervalSec=60` + `StartLimitBurst=5` in systemd unit.
*   **Documentation**: README rewritten in English (Russian preserved as `README.ru.md`). CONTRIBUTING.md and SECURITY.md translated to English.

---

## [1.2.0] - 2026-02-22

### Исправления

*   **Критическая ошибка установки**: Порог валидации файла `proxy-multi.conf` был установлен в 1024 байта, тогда как реальный размер файла от серверов Telegram составляет ~500-900 байт. Установка завершалась ошибкой «повреждён или слишком мал». Порог понижен до 64 байт с выводом фактического размера при ошибке.
*   **Конфликт systemd и setuid()**: Одновременное использование директивы `User=mtproxy` в systemd-юните и флага `-u mtproxy` в mtproto-proxy приводило к ошибке: процесс запускался от имени `mtproxy` и не мог выполнить `setuid()`. Директива `User=` удалена — сброс привилегий выполняется самим mtproto-proxy.
*   **Владелец файлов после обновления**: Скрипт `update_config.sh`, запущенный через cron от root, создавал файлы, недоступные для чтения пользователю `mtproxy`. Добавлен принудительный `chown` после каждого обновления конфигурации.

### Новые возможности

*   **Автоматическое определение NAT**: Для облачных VPS (AWS, Hetzner и др.) скрипт определяет внутренний и внешний IP и автоматически добавляет параметр `--nat-info`.
*   **Корректная установка xxd**: Обработка различий в именах пакетов между Ubuntu 22.04 (`vim-common`) и 23.10+ (`xxd`).
*   **Диагностика при ошибке запуска**: При невозможности запустить службу в терминал выводятся последние 20 строк журнала `journalctl`.
*   **Устойчивость rate-limiting**: При недоступности модулей iptables (hashlimit, conntrack) установка продолжается с предупреждением вместо аварийного завершения.

### Инфраструктурные изменения

*   Переход с `After=network.target` на `After=network-online.target` для корректного запуска при загрузке.
*   Улучшена диагностика при ошибках валидации (вывод фактического размера файла).
*   Оптимизирована установка зависимостей: безусловная установка вместо поэлементной проверки через dpkg.

---

## [1.1.0] - 2026-02-21

### Безопасность и обфускация протокола
*   Реализована поддержка Fake TLS с параметром `--domain` и секретами формата `ee`.
*   Переход от учетной записи `nobody` к выделенному пользователю `mtproxy`.
*   Изоляция секретов в директории `/etc/mtproxy/` с правами доступа `0600`.
*   Ограничение частоты соединений через `iptables hashlimit`.

### Отказоустойчивость
*   Скрипт обновления конфигурации с валидацией и откатом.
*   Сохранение правил межсетевого экрана через `netfilter-persistent`.
*   Каскадное определение внешнего IP через 8 независимых сервисов.
*   Добавлен параметр `--http-stats` для доступа к диагностической статистике.
*   Проверка и установка cron.

---

## [1.0.0] - 2026-02-11
### Первоначальный релиз
*   Автоматизированное развертывание MTProxy из исходного кода.
*   Интеграция с systemd и настройка межсетевого экрана.
