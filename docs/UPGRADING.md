# Upgrading and rollback

This procedure applies to a running installation and to the panel's `version-agent`. Treat every runtime as a separate change boundary.

## General procedure

1. Read the changelog, compatibility policy, upstream licenses, and pinned-artifact notes.
2. Run the full validation commands in [VALIDATION.md](VALIDATION.md).
3. Quiesce mutations. Back up secret files, named volumes, SQLite with WAL/SHM, manager state/journal keys, Nginx files and ownership manifests as one generation.
4. Render Compose and installer plans without applying them. Review image/binary digests, numeric identities, ports, mounts, and SNI routes.
5. Confirm every running project container has Compose project label `com.docker.compose.project=mtproxy`, then use the exact persisted `COMPOSE_FILE` overlay set for the entire change. Never use `--remove-orphans` from a partial model.
6. Upgrade one boundary at a time inside that one stack. Validate configuration, service health, protocol behavior, accounting, and adjacent SNI routes.
7. On failure, stop the changed service and restore the complete previous generation with the same stack name and overlay set. Do not regenerate journal keys or partially copy state.

## Upgrading to v0.2: the panel master key

v0.2 stores client credentials encrypted, so the panel service now mounts one more
Compose secret: `secrets/panel-master-key`.

- **Installed with `proxy-control`**: nothing to do. The installer creates the key
  during install and upgrade, preserves an existing one, and never regenerates it
  (a new key would make every stored credential undecryptable).
- **Assembled by hand from `compose.yaml`**: create the key once before
  `docker compose up`, otherwise Compose refuses to start with a missing secret
  file:

```bash
umask 077
docker run --rm -v "$PWD/secrets":/out --entrypoint python mtproxy-panel:latest \
  -m panel.cli master-key-init --path /out/panel-master-key
```

Then back it up **separately from the database** ([backup and
restore](BACKUP_RESTORE.en.md)). A panel that has never stored a secret still
starts without the key; once encrypted rows exist and the key is missing, the
panel refuses to start rather than serving empty subscriptions.

Rotation is a separate, deliberate operation and never part of an upgrade:

```bash
docker compose exec panel python -m panel.cli master-key-rotate --path /run/panel/master-key
```

It adds a new active key, re-encrypts every stored secret in batches, verifies
the result, and only then narrows the keyring to the new key — an interrupted
rotation leaves everything readable.

## Upgrading to v0.3: linked panels

v0.3 lets one panel (the central) manage others (the nodes) over their HTTPS panel
domains with scoped API keys ([FLEET.en.md](../FLEET.en.md), [ADR
008](adr/008-panel-to-panel-transport.md)). The upgrade itself is the ordinary panel
upgrade — `docker compose up -d --build --wait panel` with the persisted overlay set —
and adds no service, port, secret file or host component.

**Migrations 9–13** run at the first start (or `python -m panel.cli db-migrate`) and are
additive:

| # | Name | Adds |
| --- | --- | --- |
| 9 | `panel-settings-and-api-keys` | `panel_settings` (the panel's `panel_guid`, later its `fleet_master_guid`) and `api_keys` (prefix + SHA-256 hash, scope, expiry) |
| 10 | `fleet-v2-managed` | `managed_generations`, `managed_resources` — the node side: accepted generations and the runtime users owned for a central |
| 11 | `fleet-v2-links` | `node_links`, `desired_generations`, `observed_generations` and `fleet_nodes.transport` (`v1` for every existing node) — the central side |
| 12 | `provisioning-pending-remote` | widens the `provisioning_operations.status` CHECK with `pending_remote`; SQLite cannot alter a CHECK in place, so the table is rebuilt with every row, index and foreign key preserved |
| 13 | `fleet-v2-learned-options` | `managed_resources.learned_json` — what the runtime taught the node about a resource it owns for a central (Telemt's host and port, mita's share template), reported with every observed generation |

`python -m panel.cli db-status` lists all thirteen as applied. A `panel_guid` (uuid4) is
minted on the first start and never changes; the panel's `VERSION` is reported to a
central through `PANEL_VERSION_FILE` (default `/app/VERSION`, bind-mounted from the
project directory by `compose.yaml`; the installer copies `VERSION` there; a missing file
reads as `dev` and never blocks startup).

**What appears.** «Администраторы → API-ключи» (owner only); the card «Этот сервер» on
«Узлы» with the panel's GUID, the URL for a central and — once managed — «Отвязать»; the
header button «+ Панель» on «Узлы»; linked panels in the node picker of «Выдать доступ»;
`/api/fleet/v2/*` on every panel, answering only to a `node-sync` or `admin` API key
(401 without a key; 403 for a session or a `monitor` key); `Authorization: Bearer` on the
whole `/api/*`; the setting `PANEL_FLEET_HEARTBEAT_SECONDS` (default 15) for a central;
`compose.yaml` now also hands the panel container `MTPROXY_DOMAIN` (already in `.env` for
the `mask` and `mtproxy` services) — the MTProxy endpoint the panel reports to a central
and falls back to for a link it has not learned from Telemt; nothing to configure.

**What does not change.** Fleet v1 (mTLS agent, `/api/fleet/nodes*`, `/agent/v1/*`)
keeps working byte-for-byte; the protocol endpoints, `PANEL_VNEXT_WRITER`, subscriptions
and the master-key requirement are the same as in v0.2; local users are untouched;
nothing talks to any other panel until an owner creates a `node-sync` key and a central
adds the panel with it. A panel without a master key still starts and works locally; it
cannot be managed by a central (a push answers 409 `secret_store_disabled`).

**Same build on both ends.** The generation document is validated strictly on the node,
so a node on an older build refuses a document with a field it does not know (422) and
the central backs off; a v0.2 panel has no `/api/fleet/v2/*` and cannot be added.
Upgrade the **nodes first, then the central**; keep every panel of one fleet on the same
release.

**Hosts updated by rsync** must receive `VERSION` together with the code, or the node
reports `dev` ([OPERATIONS](OPERATIONS.en.md), section 11).

**Rollback** follows the general procedure above — the complete previous generation,
database included: a v0.2 image refuses to start on a database at schema 13 («database
schema 13 is newer than this code»). On a node that was never linked the upgrade touched
no runtime user, so restoring the pre-upgrade database loses no fleet state; unlink a
managed node («Отвязать») before rolling it back.

Verify after the upgrade (the health check needs the `Host` header as before):

```bash
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 13
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: panel.example.com' http://127.0.0.1:8787/api/fleet/v2/identity   # 401: routes present, key required
```

## Upgrading to v0.4: routing

v0.4 adds egress policies per node and service ([ROUTING](ROUTING.en.md)). The upgrade
is the ordinary one — the panel **and both managers** are rebuilt, because the egress API
lives in the managers: `docker compose up -d --build --wait panel naive-manager
mieru-manager` with the persisted overlay set, once the new release's `panel/`,
`naive_manager/`, `mieru_manager/`, `compose*.yaml` and `VERSION` are copied into the
project directory (`/opt/mtproxy-shared443` for an installer host) — the way the
production node was upgraded during the v0.4 live check. No new port, secret file or host
component.

**Migration 14** (`routing-policies`) runs at the first start and is additive:
`routing_policies`, `routing_rules`, `routing_applies` (the central's and the local
policies with their history) and `managed_egress` (what egress a node runs for a
central). `python -m panel.cli db-status` lists fourteen as applied.

**What changes on the host.**

- `compose.mieru.yaml` puts the mieru-manager container on the **host network** (it had
  none of its own; still `read_only`, `cap_drop: ALL`, no listening socket) so it can
  probe the WARP endpoint on the host loopback before it applies a policy. `up -d`
  recreates the container once.
- `.env` gains `NAIVE_EGRESS_WARP` and `MIERU_EGRESS_WARP` — the WARP proxy-mode endpoint
  each manager may route its service through (`socks5://127.0.0.1:<port>`), empty when the
  host has no WARP. The installer writes them from the new `[egress]` section (with
  `[three_xui].warp` / `warp_port` still honoured, one warning); a **host assembled or
  updated by hand** sets them itself before `up -d`, otherwise the routing screen shows no
  `warp` provider for that node (`provider_unavailable`) — a truthful state, not an error.
- The managers seed nothing: an `upstream` a hand-written Caddyfile already carries, or
  an `egress` section mita already has, is reported as `custom` and stays until the first
  policy is applied; that apply moves it under the manager's ownership and keeps the
  original lines for a rollback. Nothing changes in either config until an owner applies
  a policy.

**Order in a fleet.** Upgrade the **nodes first, then the central**: a v0.4 central sends
the `egress` section only to a node that declares `egress.v1`, and a document without one
keeps the digest it had in v0.3 in both directions — a mixed fleet keeps working, and
the routing screen marks an older node «узел нужно обновить до v0.4» instead of failing.
A v0.3 central talking to a v0.4 node ignores the node's egress report.

**Rollback** follows the general procedure — the previous generation, database included:
a v0.3 image refuses a database at schema 14. A rollback of the panel does not undo an
applied policy: reset it to «напрямую» and apply before, or roll back the manager's block
by hand (`# BEGIN NAIVE-MANAGER EGRESS … # END`; mita's `egress` section) from the
manager's backups (`/var/lib/naive-manager/backups`, the mieru-manager's journal).

Verify after the upgrade:

```bash
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 14
curl -sS -H 'Host: panel.example.com' http://127.0.0.1:8787/api/routing/targets   # 401 without a session: the routes are present
docker inspect proxy-control-mieru-manager --format '{{.HostConfig.NetworkMode}}'   # host
```

## Upgrading to v0.5: the Xray-router

v0.5 adds the optional dedicated egress router ([XRAY_ROUTER](XRAY_ROUTER.en.md)). The
upgrade itself is the ordinary one and **does not install a router**: copy the new
release's `panel/`, `naive_manager/`, `mieru_manager/`, `xray_router_manager/`,
`compose*.yaml`, `scripts/` and `VERSION` into the project directory and run
`docker compose up -d --build --wait panel naive-manager mieru-manager` with the
persisted overlay set. A node without a router behaves exactly as in v0.4: the routing
screen says «Xray-router: не установлен», policies compile for the native backends.

**Migration 15** (`routing-xray-router`) runs at the first start and is additive in effect: it
rebuilds `routing_policies` / `routing_rules` / `routing_applies` to admit the backend
`xray_router` (every v0.4 row survives with its history) and adds
`managed_egress.router_revision` / `router_digest`. `python -m panel.cli db-status`
lists fifteen as applied.

**What changes on the host without a router.** The managers accept two new, empty
variables — `NAIVE_EGRESS_ROUTER` / `NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE` and
`MIERU_EGRESS_ROUTER` / `MIERU_EGRESS_ROUTER_CREDENTIAL_FILE` (compose defaults) — and
report the `router` provider only when they are set. The policy model accepts
`geosites`, `geoips` and ports-only rules; on a native backend they preview as
`rule_kind_unsupported` naming the router.

**Adding the router to an installed node.** Add `router = true` to `[egress]` in the
installer configuration (the pinned archive `/var/lib/proxy-control/Xray-linux-64.zip`
is fetched by the installer when absent; URL and SHA-256 in
`release/external-artifacts.json`, an offline host stages the file in advance) (and
`naive = "router"` / `mieru = "router"` only if the service should start attached) and
run the installer again: the plan gains one `xray_router.runtime` action between `warp`
and the services; apply creates the identity 10006, extracts the three members,
prepares `/var/lib/xray-router`, writes `secrets/xray-router-*` and `.env.xray-router`
and starts the container; `naive` and `mieru` then re-apply with the router env and
their credential copies. Services are **not** attached by an upgrade: attach them on
the routing screen when you are ready (their sessions are interrupted once). A host
assembled by hand follows the same steps in `INSTALLER_REFERENCE` («The Xray-router»)
with `COMPOSE_FILE` extended by `compose.xray-router.yaml` — the v0.5 live check on the
production node did exactly that (`docs/releases/v0.5.0-beta.1.md`).

**Order in a fleet.** Nodes first, then the central, as in v0.4: a v0.5 central sends a
router section, a `companion` or `passthrough` only to a node that declares
`egress.router.v1`; a v0.4 node never sees them and keeps its digests; a v0.4 central
ignores `identity.router` and `router_attached`. An attached service on a node managed
by a v0.4 central keeps working (the central simply cannot change its policy until it is
upgraded).

**Rollback** follows the general procedure — the previous generation, database included:
a v0.4 image refuses a database at schema 15. Detach every service from the router
**before** rolling the panel back (a detach is a native `direct` plus a router
pass-through, both applied by the managers, so the older panel finds native blocks it
understands); a router left running with attached services keeps serving them
pass-through, but the v0.4 screen shows their upstream as `custom`.

Verify after the upgrade:

```bash
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 15
curl -sS -H 'Host: panel.example.com' http://127.0.0.1:8787/api/routing/targets   # 401 without a session
# with a router:
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -E 'verified|generation'
```

## Upgrading to v0.7: chains and lanes

v0.7 adds **exits through other nodes of the fleet** (the router's relay + chains) and a
grant's **own lane** ([ROUTING](ROUTING.en.md), «Chains and lanes»; [ADR 009](adr/009-lanes-and-chains.md)).
The update itself is the usual one: copy `panel/`, `naive_manager/`, `mieru_manager/`,
`xray_router_manager/`, `compose*.yaml`, `deploy/`, `scripts/` and `VERSION` from the new release
into the project directory and run `docker compose up -d --build --wait panel naive-manager
mieru-manager xray-router` with the overlay set you keep. A node without a router behaves as in
v0.6; a node with a router can do lanes (their keys on the panel's request) and chains as a
**source** right after the update, while the relay and the Mieru slots come with the steps below.

**Migration 16** (`routing-chains-lanes`) runs on the first start and is additive in effect: it
rebuilds `routing_policies` / `routing_rules` / `routing_applies` (the policy key gains `lane`, the
`egress = warp` constraint goes — an exit is now a string `warp | node:<guid>…`; every v0.6 row is
kept as the `svc` lane), adds `access_grants.routing_lane`, the `relay_peers` and `router_relays`
tables and `observed_generations.relay_json`. `python -m panel.cli db-status` shows sixteen applied.

**The relay and the slots on an installed node.** Run the installer with the same TOML: with
`router = true` the plan gets `relay_port = 45443` and `lane_slots = 4` by default (set them
explicitly for other values or `0`); `xray_router.runtime` enables the relay through the manager
(the Reality keypair is minted once), `mieru.runtime` installs the `mita@.service` template,
enables `mita@1…4` and writes `MIERU_LANE_SLOTS` into `.env.mieru`; UFW opens `45443/tcp` and
`46101…46104/tcp`. A hand-built host:

```bash
# the relay (the panel's domain is the Reality cover; the port is public)
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --relay-enable panel.example.com 45443
ufw allow 45443/tcp
# Mieru slots: the unit template, the daemons, the manager's env
install -m 0644 deploy/mita@.service /etc/systemd/system/mita@.service && systemctl daemon-reload
for n in 1 2 3 4; do systemctl enable --now mita@$n; ufw allow $((46100+n))/tcp; done
printf 'MIERU_LANE_SLOTS=%s\n' "$(for n in 1 2 3 4; do printf '%s:%s:/run/mita/lane-%s.sock:/var/lib/mita/lanes/%s,' $n $((46100+n)) $n $n; done | sed 's/,$//')" >> .env.mieru
docker compose --env-file .env --env-file .env.mieru -f compose.yaml -f compose.mieru.yaml up -d --wait mieru-manager
```

**Order in a fleet.** Nodes first, then the central, as before: a v0.7 central sends a
resource's `lane` and the `relay` section only to a node that declared `egress.lanes.v1` /
`relay.v1`; a v0.6 node never sees them and keeps its digests (a schema-2 intent is never sent
to such a node: `node_lacks_lanes`, `node_lacks_relay`); a v0.6 central ignores
`identity.router.relay`, `router.lanes` and `observed.relay`.

**Rollback** follows the general procedure: the previous generation together with the database
(a v0.6 image refuses a database at schema 16). Withdraw the grants' lanes and return the policies
to `warp`/`direct` **before** rolling the panel back (a lane is a Caddy handler / mita slot and an
ingress account the old panel does not know, and the old router refuses a schema-2 intent); the
relay and the slots may stay — the old panel simply does not see them.

Verification after the update:

```bash
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 16
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --relay | python3 -m json.tool   # enabled, public_key
systemctl is-active mita@1 mita@2 mita@3 mita@4; ss -lnt | grep -E ':45443|:4610[1-4]'
```

## Upgrading to v0.8: geodata, custom exits, quick settings, auto-import

v0.8 adds **refreshable geodata** for the router, **custom exits** (VPN/proxy outbounds) and
**quick settings** for routing, **auto-import** of linked panels' users and a **one-step**
client with its node ([ROUTING](ROUTING.en.md) «Custom exits, quick settings and geodata»,
[FLEET](../FLEET.en.md) «Import existing users»). The upgrade itself is the usual one:
`panel/`, `xray_router_manager/`, `compose*.yaml`, `scripts/`, `VERSION` into the project
directory and `docker compose up -d --build --wait panel xray-router` with the overlays you keep
(the naive/mieru managers did not change).

**Migrations 17–19** (`links-auto-import`, `routing-presets`, `routing-exits`) run on first start
and are additive: `node_links.auto_import` (default **1**), `routing_rules.preset`, the table
`egress_exits`. `python -m panel.cli db-status` shows nineteen applied.

**Auto-import switches itself on.** After the upgrade a central adopts, on every heartbeat, the
users its linked panels run on their own: each becomes a client of the central named after the
account (one name across protocols and nodes is one client), MTProxy/NaiveProxy credentials are
captured, Mieru accounts wait for «Принять с ротацией». Untick the box in «Изменить связь»
**before** upgrading the central, or right after (`auto_import: false` in
`POST /api/nodes/{id}/link`), where that is not wanted.

**The router's geodata.** On its first v0.8 start the manager copies the pinned pair into
`/var/lib/xray-router/geodata/` (the state directory is already writable to it; ≈ 30 MB) and
reads the lists from there from then on; the source stays `xray` (the pin) without automatic
refresh until you pick Loyalsoldier or your own URLs on «Маршрутизация» → Geodata → «Источник…».
A v0.7 node does not know `exits`/`protocols` in an intent and answers `egress_invalid`: a v0.8
central shows `backend_capability_missing`/`node_lacks_exits` and does not send such an intent
until the node is upgraded.

**Order in the fleet** — nodes first, then the central: a v0.8 central needs `geodata.v1` from
the node for geodata and exit probes and `custom_exits` from its router for policies with exits;
a v0.7 central sees none of it and works as before.

**Rollback** — the general procedure (a v0.7 image refuses a schema-19 database). Remove
`exit:<id>` and rules with `protocols` from the policies before rolling back (a v0.7 router
refuses such an intent); `geodata/` in the state directory may stay — the old manager reads the
lists from the binary directory.

Verification after the upgrade:

```bash
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 19
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -A3 '"geodata"'
```

## Upgrading to v0.9: the panel says what the node already does

v0.9 is a panel-only release ([note](releases/v0.9.0-beta.1.md)): `matches_node` on the policies
of `GET /api/routing/targets`, API refusals in the screen's words, fixes on the «Маршрутизация»
screen and the node card. **No migrations**; the NaiveProxy/Mieru/Xray-router managers did not
change: copy `panel/`, `VERSION` and `CHANGELOG*` from the archive into the project directory and
run `docker compose up -d --build --wait --no-deps panel` with the overlays you keep. Order in the
fleet does not matter: a v0.9 central asks nothing new of its nodes, a v0.9 node under a v0.8
central works as before.

**Rollback** — the previous panel image (`docker tag mtproxy-panel:<old> mtproxy-panel:latest`,
`up -d --no-deps panel`); the database did not change.

Verification after the upgrade:

```bash
docker exec proxy-control-panel cat /app/VERSION   # 0.9.0-beta.1
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 19, as in v0.8
```

## Upgrading to v0.10: the subscription at hand

Panel only; database migration 20 (`subscription-escrow`) runs at start-up. A subscription issued before v0.10 has no encrypted copy and cannot be shown — it gets no «Показать» button; rotate it from the client window. The panel master key (`secrets/panel-master-key`) is required for showing; without it the panel behaves as before. Rollback: the previous panel image; migration 20's columns do not get in the old code's way.

On an installer-based host, `/app/VERSION` is bind-mounted from the project directory's `VERSION` file: update `VERSION` in the project directory, not only the image, or the container keeps reporting the previous release.

Verification after the upgrade:

```bash
docker compose exec -T panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 20
docker exec proxy-control-panel cat /app/VERSION   # 0.11.0-beta.1
```

## Panel version-agent

The panel never downloads a runtime artifact and never receives the Docker socket. A separate root-owned `version-agent` reads `/etc/proxy-control/versions.json` and exposes only a Unix socket at `/run/proxy-control/version-agent.sock`.

Before enabling it:

```bash
sudo install -d -m 0750 /etc/proxy-control
sudo install -o root -g root -m 0644 deploy/version-agent.service /etc/systemd/system/version-agent.service
sudo install -o root -g root -m 0644 deploy/proxy-control-version-agent.tmpfiles.conf /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo install -o root -g root -m 0600 deploy/version-agent.env.example /etc/proxy-control/version-agent.env
sudo install -o root -g root -m 0600 deploy/version-catalog.example.json /etc/proxy-control/versions.json
sudo systemd-tmpfiles --create /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo systemctl daemon-reload
```

Replace every example catalog entry with an operator-verified artifact. Telemt entries must be immutable image references (`@sha256:...`). NaiveProxy/Caddy and mita entries must be HTTPS artifacts with lowercase SHA-256. The catalog is an allowlist, not a discovery mechanism; the browser cannot extend it.

Configure the deployment path and the complete Compose overlay list in `/etc/proxy-control/version-agent.env`. The agent writes only the generated `version-overrides/compose.versions.yaml`, configured binary targets, and its state/backup directory. It refuses symlink targets and invalid relative Compose paths. When a configured container pins a host binary, the preflight Docker inspect is fail-closed: only Docker's exact `No such object` result permits the update; daemon, permission, timeout, and other uncertain inspect failures block it.

Record the currently installed versions in `/var/lib/proxy-control/version-agent/state.json` before the first update. The UI sends `expected_current`; a mismatch returns `409` and prevents a stale browser tab from updating a changed runtime. A component marked `rollback_failed` remains blocked until an operator restores and verifies the complete generation, then reconciles the root-owned state.

Enable and verify the agent without changing the running stack:

```bash
sudo systemctl enable --now version-agent
sudo systemctl is-active version-agent
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/versions
```

The panel Compose service must mount `/run/proxy-control` and set `VERSION_AGENT_SOCKET=/run/proxy-control/version-agent.sock`. The socket is created with mode `0660`; make its numeric group accessible to panel UID `10001` without making it world-writable.

### Telemt

The agent reads back the current container image, pulls the selected immutable image, uses the full configured Compose model plus `version-overrides/compose.versions.yaml`, recreates only `mtproxy`, and verifies both the selected image reference and `healthy` status. A failed pull, start, image readback, or health check restores the previous override and starts the previous image. The rollback is successful only after the previous image reference and container health pass the same gates. It never calls `down -v`.

### NaiveProxy/Caddy and Mieru/mita

The agent downloads at most 256 MiB from the HTTPS host recorded in the catalog, verifies SHA-256, stages the executable with mode `0755`, runs the configured checker, and atomically replaces the target. Caddy is additionally validated against its Caddyfile and module checker. The version pin is read back, the service is restarted, and `systemctl is-active` is required after the operation.

Any failure restores the previous binary and pin, verifies the restored binary hash and pin readback, repeats the configured checker and Caddyfile validation, restarts the service, and requires `systemctl is-active`. State is written as the new version only after success. A rollback that fails any restore, config/readback, restart, or health gate is persisted and returned as `rollback_failed`; do not retry the update endpoint until an operator has restored and verified the complete previous generation.

### Updates from upstream (v0.11)

«Проверить обновления» on the «Версии» screen asks the agent to poll the projects' own sources. The `versions.json` catalog stays and wins («каталог» in the list); versions from upstream appear beside it («upstream»). The hosts are fixed in the agent: `api.github.com`, `github.com`, `objects.githubusercontent.com`, `ghcr.io`, `registry-1.docker.io`, `auth.docker.io`; an arbitrary URL is still impossible from the browser and from the configuration alike.

| Component | Source | What is installed | Digest |
|---|---|---|---|
| Xray-router (`xray`) | GitHub Releases `XTLS/Xray-core` | `xray`, `geoip.dat`, `geosite.dat` from `Xray-linux-64.zip` | the release's `.dgst` |
| Mieru (`mita`) | GitHub Releases `enfein/mieru` | `mita` from `mita_<v>_linux_amd64.tar.gz` | the release's `.sha256.txt` |
| Telemt | registry `ghcr.io/samnet-dev/mtproxymax-telemt` | the image by manifest digest | registry digest |
| NaiveProxy (`naive`) | GitHub Releases `caddyserver/caddy` + branch `caddy2` of `klzgrad/forwardproxy` | Caddy is built on the host (`docker build`, builder image by digest, up to 15 minutes) | the pin of the built binary |

**What a release digest proves and what it does not.** A match against `.dgst`/`.sha256.txt`/the registry digest means the download is intact and identical to what the project's author published. It does not mean this project verified that version on its lab host: the UI marks such versions «из upstream, проектом не проверялась». A release without a published digest is listed but cannot be installed.

The check result is cached in `state.json` (`upstream`); polling more often than once a minute answers from the cache, and an unreachable source keeps the previous list with a `last_error` line. Variables in `version-agent.env`:

- `PROXY_CONTROL_UPSTREAM_CHECK=off` turns the poll off; only the catalog remains;
- `PROXY_CONTROL_XRAY_ROUTER=on` enables the `xray` component (the Xray-router installer writes `on` itself); `PROXY_CONTROL_XRAY_BIN_DIR` and `PROXY_CONTROL_XRAY_OVERLAY` name the binary directory and `.env.xray-router`;
- `PROXY_CONTROL_CONSUMER_OVERLAYS=mita=/opt/mtproxy-shared443/.env.mieru:MIERU_MITA_SHA256:mieru-manager` replaces `PROXY_CONTROL_PINNED_CONSUMERS`: a `mita` update no longer refuses because of the `mieru-manager` container; it rewrites the pin in `.env.mieru`, restarts `mita` and the `mita@<n>` slots and recreates the manager. Remove the old variable from the env file when upgrading the agent;
- the unit's `ReadWritePaths` gained `/usr/local/lib/proxy-control`: reinstall `deploy/version-agent.service` and run `systemctl daemon-reload`.

An `xray` update replaces the three files in the router's directory, rewrites `XRAY_ROUTER_*_SHA256` in `.env.xray-router`, recreates the `xray-router` container and checks `xray version` inside it; any failure restores the files, the overlay and the container. The installer learns the new version from `state.json`: `verify`/`repair` accept either their own pin or the version the agent recorded.

## Verification after any update

Run, at minimum:

```bash
docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml ps
curl --fail -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
sudo nginx -t
sudo systemctl is-active version-agent caddy-naive mita
sudo journalctl -u version-agent --since=-15min --no-pager
```

Then perform the real protocol smoke tests for the changed boundary and check adjacent SNI routes. Redact URLs, tokens, QR payloads, cookies, certificates, private keys, and journal contents before sharing output.

`repair` and `uninstall` use the recorded ownership manifest and intentionally reject foreign drift; see [COMPATIBILITY.md](COMPATIBILITY.md). Product branding never authorizes runtime-path migration.
