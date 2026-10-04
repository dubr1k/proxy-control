# Upgrading and rollback

This guide is for a host that already runs Proxy Control 1.0.0 or later: how to update it, what
the panel's `version-agent` does, how to roll back, and how to enable optional components on a
node that is already installed. Treat every runtime — the panel, each manager, Telemt,
NaiveProxy/Caddy, Mieru/mita and the Xray-router — as a separate change boundary.

## General procedure

1. Read the [changelog](../CHANGELOG.md) and the release notes of every release between the
   installed one and the target, the [compatibility policy](COMPATIBILITY.md), upstream licenses
   and the pinned-artifact notes (`release/external-artifacts.json`).
2. Back up one consistent generation: secret files, named volumes, SQLite together with its
   WAL/SHM, the managers' state and journal keys, Nginx files and the ownership manifest. Keep the
   panel master key `secrets/panel-master-key` apart from the database ([backup and
   restore](BACKUP_RESTORE.en.md)).
3. In a fleet, update the linked nodes first and the central panel last ([order in a
   fleet](#order-in-a-fleet)).
4. Update with [one command](#updating-with-one-command) or from the panel's «Versions» screen
   ([the panel's version-agent](#the-panels-version-agent)). Both verify the release archive
   against `SHA256SUMS`, keep a rollback copy and restore it on failure.
5. For any step taken by hand, render the Compose model and the installer plan without applying
   them, and review image and binary digests, numeric identities, ports, mounts and SNI routes.
   Confirm that every running project container carries the Compose label
   `com.docker.compose.project=mtproxy`, and use the exact persisted `COMPOSE_FILE` overlay set
   for the whole change. Never use `--remove-orphans` from a partial model.
6. Change one boundary at a time inside that one stack. After each change check the
   configuration, service health, protocol behaviour, accounting and the adjacent SNI routes
   ([verification](#verification-after-any-update)).
7. On failure, stop the changed service and restore the complete previous generation with the same
   project name and overlay set ([rollback](#rollback)). Do not regenerate journal keys and do not
   copy state partially.

If you deploy from a source tree rather than from a published release, run the repository gates
from [VALIDATION.md](VALIDATION.md) first.

## Updating with one command

An installed host updates with the same script that installs a new one, in `--update` mode. Make
the backup first, then run the commands as a regular user with `sudo` access, in a directory
without a previous `proxy-control-v<version>/`:

```bash
curl -fsSLO https://github.com/dubr1k/proxy-control/releases/latest/download/install-release.sh
curl -fsSLO https://github.com/dubr1k/proxy-control/releases/latest/download/install-release.sh.sha256
sha256sum --check install-release.sh.sha256
bash install-release.sh --update
```

The script is downloaded, checked against its own published checksum and read before it runs; it
is never piped into a shell. It carries its release's version and archive SHA-256 and is attested
too: `gh attestation verify install-release.sh --repo dubr1k/proxy-control`.

What it does:

1. **Unprivileged**, it downloads the four release files into `./proxy-control-v<version>/`
   (`--dir` chooses another new directory), checks `SHA256SUMS`, the manifest and the archive
   digest written into the script, verifies the attestation when `gh` is present (`--attest` makes
   that mandatory) and extracts the archive. A swapped archive does not pass, even with a swapped
   `SHA256SUMS`.
2. Through **one `sudo`** it runs `scripts/update-host.sh` from the verified tree. That asks the
   host's version-agent to update the panel — only if the agent offers exactly the archive digest
   verified in step 1 — and waits until the panel reports the new version. The agent keeps copies
   of the tree, the image and the database and rolls everything back on failure ([updating the
   panel itself](#updating-the-panel-itself-from-the-ui)).
3. It rebuilds the managers the agent reports in `pending_rebuild` (`mieru-manager`,
   `naive-manager`, `xray-router`), an enabled MCP server and, on a host with the Xray-router, the
   `xray-router-ingress` bridge — with the same Compose call the agent uses. The image of every
   running service is tagged `mtproxy-<service>:rollback-<timestamp>` first; a failed rebuild puts
   the previous images back, checks their health and still reports the update as failed.
4. It migrates the owned Nginx ingress templates (with their own backup and rollback) and finally
   requires every `proxy-control-*` container to be healthy or running.

**Not touched:** Telemt and `mask`, certificates, `.env*` and `secrets/`. When `docker/` changed,
restart Telemt and `mask` yourself ([below](#restarting-telemt-and-mask-after-docker-changed)).

**Refusals.** The update stops before changing anything when a running optional service (MCP, a
manager, the Xray-router or its bridge, the legacy fleet services) is missing from the agent's
overlay list `PROXY_CONTROL_COMPOSE_FILES` in `/etc/proxy-control/version-agent.env` — that service
would otherwise keep its old code. It needs the version-agent, which the installer sets up; without
it the script stops with `version-agent not found` ([installing the version-agent by
hand](#installing-the-version-agent-by-hand)).

`--check-only` downloads and verifies without extracting; `--requirements` prints what the host
needs. A host whose agent comes from 1.1.0 or earlier has one more step after its first such update
([notes for upgrading from 1.0.x and 1.1.0](#notes-for-upgrading-from-10x-and-110)).

## Order in a fleet

Update the **linked nodes first, then the central panel**, and keep every panel of one fleet on the
same release. A node validates the generation document strictly and refuses a field it does not
know (422), while a central sends a new section only to a node that declares the matching
capability. A mixed fleet therefore keeps working during the rollout: a node that is still older
keeps its digests, and the routing screen names it with a code such as
`node_lacks_mtproxy_egress` instead of failing.

A node is updated with the one-command update on that host or from the central: «Nodes» → the node
→ «Updates».

A host updated by copying files (rsync) must receive `VERSION` together with the code. The panel
reports the version it finds in the project directory's `VERSION`, bind-mounted at `/app/VERSION`;
a stale file reports the previous release to the central, a missing one reports `dev`
([OPERATIONS](OPERATIONS.en.md), section 11).

## Rebuilding changed managers by hand

An update of the panel from the «Versions» screen does not rebuild the managers. When
`mieru_manager/`, `naive_manager/`, `xray_router_manager/`, `mcp_server/` or `docker/` changed
between the two releases, the agent names them in `pending_rebuild` and the panel card says
«Managers changed: …». The one-command update rebuilds them itself. After an update from the panel,
rebuild them with the installation's own environment files and overlays — the set the agent uses,
`PROXY_CONTROL_COMPOSE_DIR` and `PROXY_CONTROL_COMPOSE_FILES` in
`/etc/proxy-control/version-agent.env`:

```bash
cd /opt/mtproxy-shared443
docker compose --env-file .env --env-file .env.mieru --env-file .env.xray-router --env-file .env.naive \
  -f compose.yaml -f compose.mieru.yaml -f compose.xray-router.yaml -f compose.naive.yaml \
  up -d --build --no-deps --wait mieru-manager xray-router
```

Keep only the `--env-file` and `-f` your installation has (add `--env-file .optional.env`,
`--env-file .env.mcp` and `-f compose.mcp.yaml` where they exist) and name only the services that
changed: `mieru-manager`, `naive-manager`, `xray-router` together with `xray-router-ingress`, `mcp`.
Tag the running image of each first, as the one-command update does
(`docker tag <image ID> mtproxy-<service>:rollback-<timestamp>`, the ID from
`docker inspect --format '{{.Image}}' proxy-control-<service>`).

The other host steps of the one-command update also stay with you after an update from the panel:
restarting Telemt and `mask` ([below](#restarting-telemt-and-mask-after-docker-changed)) and the
Nginx ingress migration ([notes, 1.1.1](#notes-for-upgrading-from-10x-and-110)).

## Restarting Telemt and mask after `docker/` changed

`docker/` holds, among others, the Telemt entrypoint and the cover site's Caddyfile, bind-mounted
into the `mtproxy` and `mask` containers. Neither the agent nor the one-command update restarts
them. When `docker` is in `pending_rebuild`, recreate both when convenient — every MTProxy session
reconnects once:

```bash
cd /opt/mtproxy-shared443
docker compose --env-file .env --env-file .env.mieru --env-file .env.xray-router --env-file .env.naive \
  -f compose.yaml -f compose.mieru.yaml -f compose.xray-router.yaml -f compose.naive.yaml \
  -f version-overrides/compose.versions.yaml \
  up -d --no-deps --force-recreate --wait mask mtproxy
```

Keep the `--env-file` and `-f` your installation has, as for the managers. Keep
`-f version-overrides/compose.versions.yaml` whenever the file exists (it appears once the agent has
updated Telemt): it carries the Telemt image the agent installed, and without it `mtproxy` returns
to the image pinned in `compose.yaml`. The Telemt configuration in the `telemt-config` volume is
kept: the entrypoint never regenerates an existing one.

## Verification after any update

Run, at minimum (with the installation's overlay set):

```bash
docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml ps
curl --fail -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
docker exec proxy-control-panel cat /app/VERSION
docker compose exec -T panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 21 from 1.1.0 on
sudo nginx -t
sudo systemctl is-active version-agent caddy-naive mita
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
sudo journalctl -u version-agent --since=-15min --no-pager
# with the Xray-router:
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -E 'verified|generation'
```

The health check needs the `Host` header: the installer allows only the panel domain. For an
owner/admin readiness snapshot use `GET /api/readiness` ([OPERATIONS](OPERATIONS.en.md), section 2).

Then perform the real protocol smoke tests for the changed boundary and check the adjacent SNI
routes. Redact URLs, tokens, QR payloads, cookies, certificates, private keys and journal contents
before sharing output.

`repair` and `uninstall` use the recorded ownership manifest and intentionally reject foreign
drift; see [COMPATIBILITY.md](COMPATIBILITY.md). Product branding never authorizes runtime-path
migration.

## Rollback

**The panel only moves forward.** Its database migrates at start, and an older image refuses a
newer schema («database schema N is newer than this code»). The agent therefore offers the panel
only forward and refuses a downgrade; going back is a restore of the complete previous generation,
database included ([backup and restore](BACKUP_RESTORE.en.md), «Upgrade rollback»). The runtimes —
Telemt, NaiveProxy, Mieru, the Xray-router — can be rolled back from the «Versions» screen (the
«Roll back to an earlier one» group); the agent verifies and keeps a copy as for an update.

**A failed update rolls itself back.** The agent restores the tree, the database files and the
previous image; the one-command update also restores the manager images it tagged. If even the
restored state does not pass its checks, the component is `rollback_failed` and accepts no further
update until an operator has restored and verified the complete previous generation and reconciled
the root-owned state; everything needed is in `/var/lib/proxy-control/version-agent/backups/`.

**By hand:**

1. Stop the changed boundary and keep the failed generation for investigation.
2. Restore the complete previous generation: the images (`mtproxy-panel:rollback-<timestamp>`,
   `mtproxy-<service>:rollback-<timestamp>`), the database with its WAL/SHM, the tree, the binaries,
   units and the overlay set.
3. Validate before start or reload, then run health and real protocol probes and confirm adjacent
   SNI routes and accounting continuity. Without a verified restore, do not claim a rollback and do
   not delete the recovery journal.

**What a panel rollback does not undo.** Policies and attachments the managers applied stay on the
node. Before rolling the panel back across a release that introduced something you use, undo it in
the panel first — for example, disconnect MTProxy from the Xray-router before going back to 1.0.x:
Telemt then goes direct on its previous upstream. A manager's own block can also be restored from
its backups (`/var/lib/naive-manager/backups`, the mieru-manager's journal).

**In a fleet.** Unlink a managed node («Unlink» on the «This server» card) before rolling it back:
its users become local and keep working. On a central, pause or delete its links first; its nodes
keep serving the generation they last applied.

## Notes for upgrading from 1.0.x and 1.1.0

- **One command from 1.0.x.** The `install-release.sh --update` of release 1.1.0 or later also
  updates a 1.0.x host: the version-agent the installer set up is all it needs. The scripts of
  releases before 1.1.0 have no `--update` path.
- **First update by an older agent.** An agent from 1.1.0 or earlier cannot hand the installer's
  ownership of Core and of the agent's own code over to the new release. Once the panel reports the
  new version, run the new release's installer from its extracted directory with the exact archive
  and its verified SHA-256 (printed by `install-release.sh`, and its line in `SHA256SUMS`) —
  before the next `repair`:

  ```bash installer-check
  cd proxy-control-vX.Y.Z/proxy-control
  sudo python3 -m installer.cli reconcile-panel-update --archive ../proxy-control-vX.Y.Z.tar.gz --sha256 '<64-character archive digest>'
  sudo python3 -m installer.cli repair --json
  ```

  The command verifies the archive, the running panel version, the replaced files and every
  unrelated owned file, and refuses foreign drift ([installer
  reference](INSTALLER_REFERENCE.en.md#commands)). Agents from 1.1.1 on hand over by themselves.
- **From 1.0.0: managers.** 1.0.1 changed `mieru_manager` and `xray_router_manager`; rebuild them if
  the update came from the panel ([rebuilding changed managers](#rebuilding-changed-managers-by-hand)).
  The Mieru manager then takes any mita (3.38 and newer install from «Versions»), and a router whose
  geodata nobody set up moves to Loyalsoldier with daily refreshes and fetches fresh lists at once
  (one router restart).
- **1.0.2 and 1.0.3** change only the panel and only the installer with the release files,
  respectively: no migrations, no manager rebuild.
- **To 1.1.0 and later.** Migration 21 (`routing-mtproxy`) rebuilds `routing_policies`,
  `routing_rules`, `routing_applies` and `managed_egress` to allow `mtproxy` and `mtproxy_native`;
  every row is kept with its history. On a node with the Xray-router the router is rebuilt and the
  `xray-router-ingress` bridge starts (the one-command update does both; by hand —
  `up -d --build --no-deps --wait xray-router xray-router-ingress`). The router mints its `mtproxy`
  ingress credential and re-renders its generation: one Xray restart, NaiveProxy and Mieru sessions
  through the router reconnect once. Until then the routing screen shows `router_lacks_mtproxy` for
  MTProxy, and NaiveProxy and Mieru keep working. A 1.0.x image refuses a schema-21 database.
- **1.1.1: client IPs.** The one-command update migrates the owned Nginx ingress templates of a
  `fresh` installation so that the panel sees client IPs; edited templates are refused, and a
  foreign `coexist` frontend stays unchanged and needs an operator-managed PROXY bridge. After an
  update from the panel alone, run the same host step from the extracted release — first without
  `--apply` for a read-only plan, then as root with it ([installer
  reference](INSTALLER_REFERENCE.en.md)):

  ```bash
  python3 -m installer.ingress_upgrade --project-dir /opt/mtproxy-shared443
  sudo python3 -m installer.ingress_upgrade --project-dir /opt/mtproxy-shared443 --apply
  ```

- **1.1.1: 3x-ui.** Managed 3x-ui installations pin 3x-ui 3.9.0. An existing 3x-ui is updated
  through 3x-ui itself; an update of Proxy Control does not change its version.

## The panel's version-agent

The panel never downloads a runtime artifact and never receives the Docker socket. A separate
root-owned `version-agent` reads `/etc/proxy-control/versions.json` and exposes only a Unix socket
at `/run/proxy-control/version-agent.sock`.

The installer sets the agent up: its `version_agent` adapter runs last, copies the agent's code to
`/opt/proxy-control`, installs the unit and the tmpfiles fragment, writes `version-agent.env` with
the profile's complete Compose overlay list and the Xray-router flag, seeds an empty
`versions.json` and a `state.json` that records the versions it just installed, and waits for
`/v1/health`. `repair` rewrites the owned files and never touches the catalog or the state.

The «Versions» screen lists, for each runtime — Telemt, NaiveProxy/Caddy, Mieru/mita and the
Xray-router when installed — several recent releases in two groups, «Newer than installed» and
«Roll back to an earlier one»; the «Proxy Control / panel» card offers only newer releases.
Installing is an `owner` action. The UI sends `expected_current`; a mismatch returns `409`, so a stale browser tab
cannot update a runtime that has already changed. A component marked `rollback_failed` stays
blocked until an operator restores and verifies the complete generation and then reconciles the
root-owned state. Linked nodes are updated from the central the same way: «Nodes» → the node →
«Updates».

### Telemt

The agent reads back the current container image, pulls the selected immutable image, uses the full
configured Compose model plus `version-overrides/compose.versions.yaml`, recreates only `mtproxy`,
and verifies both the selected image reference and `healthy` status. A failed pull, start, image
readback, or health check restores the previous override and starts the previous image. The
rollback is successful only after the previous image reference and container health pass the same
gates. It never calls `down -v`.

### NaiveProxy/Caddy and Mieru/mita

The agent downloads at most 256 MiB from the HTTPS host recorded for the version, verifies SHA-256,
stages the executable with mode `0755`, runs the configured checker, and atomically replaces the
target. Caddy is additionally validated against its Caddyfile and module checker. The version pin
is read back, the service is restarted, and `systemctl is-active` is required after the operation.

Any failure restores the previous binary and pin, verifies the restored binary hash and pin
readback, repeats the configured checker and Caddyfile validation, restarts the service, and
requires `systemctl is-active`. State is written as the new version only after success. A rollback
that fails any restore, config/readback, restart, or health gate is persisted and returned as
`rollback_failed`; do not retry the update endpoint until an operator has restored and verified the
complete previous generation.

A `mita` update rewrites the pin in `.env.mieru`, restarts `mita` and the `mita@<n>` lane slots and
recreates the `mieru-manager` container (`PROXY_CONTROL_CONSUMER_OVERLAYS`, below).

### Updates from upstream

«Check for updates» on the «Versions» screen asks the agent to poll the projects' own sources. The
`versions.json` catalog stays and wins («catalog» in the list); versions from upstream appear beside
it («upstream»). The hosts are fixed in the agent: `api.github.com`, `github.com`,
`objects.githubusercontent.com`, `ghcr.io`, `registry-1.docker.io`, `auth.docker.io`; an arbitrary
URL is impossible from the browser and from the configuration alike.

| Component | Source | What is installed | Digest |
|---|---|---|---|
| Xray-router (`xray`) | GitHub Releases `XTLS/Xray-core` | `xray`, `geoip.dat`, `geosite.dat` from `Xray-linux-64.zip` | the release's `.dgst` |
| Mieru (`mita`) | GitHub Releases `enfein/mieru` | `mita` from `mita_<v>_linux_amd64.tar.gz` | the release's `.sha256.txt` |
| Telemt | registry `ghcr.io/samnet-dev/mtproxymax-telemt` | the image by manifest digest | registry digest |
| NaiveProxy (`naive`) | GitHub Releases `caddyserver/caddy` + the `naive` branch of `klzgrad/forwardproxy` | Caddy is built on the host (`docker build`, builder image by digest, up to 15 minutes) | the pin of the built binary |
| The panel | GitHub Releases `dubr1k/proxy-control` | the release archive | the archive's line in `SHA256SUMS` |

**What a release digest proves and what it does not.** A match against
`.dgst`/`.sha256.txt`/the registry digest means the download is intact and identical to what the
project's author published. It does not mean this project verified that version, and the UI says so
next to every such version. A release without a published digest is listed but cannot be installed.

The check result is cached in `state.json` (`upstream`); polling more often than once a minute
answers from the cache, and an unreachable source keeps the previous list with a `last_error` line.
Variables in `version-agent.env`:

- `PROXY_CONTROL_UPSTREAM_CHECK=off` turns the poll off; only the catalog remains;
- `PROXY_CONTROL_UPSTREAM_CHECK_INTERVAL` (seconds, default `21600`): the agent polls upstream by
  itself this often, so a node's list reaches the central with its heartbeat without anyone pressing
  «Check for updates»; `0` polls only on request;
- `PROXY_CONTROL_XRAY_ROUTER=on` enables the `xray` component (the installer writes `on` together
  with the router); `PROXY_CONTROL_XRAY_BIN_DIR` and `PROXY_CONTROL_XRAY_OVERLAY` name the binary
  directory and `.env.xray-router`;
- `PROXY_CONTROL_CONSUMER_OVERLAYS=mita=/opt/mtproxy-shared443/.env.mieru:MIERU_MITA_SHA256:mieru-manager`
  names the overlay that pins a binary for a container: a `mita` update rewrites that pin and
  recreates the manager instead of refusing because of it.

The unit's `ReadWritePaths` include `/usr/local/lib/proxy-control`, `/opt/proxy-control` and
`/var/lib/docker/volumes`, which the panel's self-update needs.

An `xray` update replaces the three files in the router's directory, rewrites
`XRAY_ROUTER_*_SHA256` in `.env.xray-router`, recreates the `xray-router` container and checks
`xray version` inside it; any failure restores the files, the overlay and the container. The
installer learns the new version from `state.json`: `verify`/`repair` accept either their own pin or
the version the agent recorded.

### Updating the panel itself from the UI

The «Proxy Control / panel» card on the «Versions» screen lists this project's own GitHub releases
(`dubr1k/proxy-control`) with the archive's line of `SHA256SUMS`, and the agent installs the chosen
one only from the release archive, never from a branch. The request answers at once
(`async: true`) because the panel restarts in the middle: the browser polls `GET /api/versions`
until the component's `status` leaves `updating` and reloads the page when the panel answers with
the new version.

What the agent does, in order:

1. downloads `proxy-control-v<version>.tar.gz`, checks its SHA-256 against `SHA256SUMS`, and refuses
   an archive with a member outside `proxy-control/`, with `..`, absolute or not a regular file or
   directory — nothing on the host is touched at this point;
2. moves the current copies into `/var/lib/proxy-control/version-agent/backups/panel.previous/` and
   copies from the archive into the project directory exactly this set: `panel/`, `installer/`,
   `scripts/`, `docker/`, `mieru_manager/`, `naive_manager/`, `xray_router_manager/`,
   `mcp_server/`, `release/`, `docs/`, the `compose*.yaml` files, `VERSION`, `uninstall.sh`,
   `install.sh`, `install-bootstrap`, `CHANGELOG*`, `README*`, `THIRD_PARTY_NOTICES.md`, `LICENSE`.
   **Not touched**: `secrets/`, `.env*`, `version-overrides/`, certificates, anything else in the
   directory. `version_agent/` goes into `/opt/proxy-control` the same way (backed up too);
3. tags the running container's immutable image ID `mtproxy-panel:rollback-<timestamp>` (even if a
   separate build has already moved `mtproxy-panel:latest`), runs `docker compose … build panel`,
   stops the panel and the legacy `fleet-ingress` service when installed, checks that no running
   container still mounts the panel volume, copies `panel.sqlite3`, `-wal` and `-shm` from the
   `mtproxy_panel-data` volume into `backups/panel-db.previous/` (owner and mode kept), starts the
   panel with `up -d --wait` (legacy ingress after it) and checks
   `docker exec proxy-control-panel cat /app/VERSION`.

**The current version** is what the running container reports (`cat /app/VERSION`), not the file in
the project directory: the file can run ahead when the tree was synced from elsewhere and the panel
never rebuilt. The file is read only when the container does not answer.

**Rollback.** Any failure after step 2 moves the backed-up entries back, stops the failed new panel,
restores the database files into the volume (an older panel refuses a newer, migrated database, so
the copy is part of the rollback), retags the previous image as `latest`, starts the panel and
checks that it reports the previous version. A failed stop or a remaining writer prevents the
restore and leaves the backup intact for the operator; an incomplete snapshot is never used. The
state then says `ready` with `last_error`; if even the check of the restored panel fails, the state
is `rollback_failed` and the agent accepts no further panel update until the operator has looked.

**Managers are not rebuilt.** If `mieru_manager/`, `naive_manager/`, `xray_router_manager/`,
`mcp_server/` or `docker/` changed between the two releases, the agent reports them in
`pending_rebuild` and the card says so: rebuild those services
([by hand](#rebuilding-changed-managers-by-hand)) or run the [one-command
update](#updating-with-one-command), which also reconciles an enabled MCP server from the verified
release tree even when an older agent omitted its sources (the previous sources are kept in
`version-overrides/mcp-source-previous-*`). The agent's own code is synced with the release; if it
changed, the agent schedules its restart (`systemd-run --on-active=5 … systemctl restart
version-agent`) as the very last step, after the state is written.

Variables in `version-agent.env` (defaults match the installer):
`PROXY_CONTROL_AGENT_DIR=/opt/proxy-control`, `PROXY_CONTROL_PANEL_IMAGE=mtproxy-panel`,
`PROXY_CONTROL_PANEL_CONTAINER=proxy-control-panel`,
`PROXY_CONTROL_PANEL_VOLUME=mtproxy_panel-data`.

### Installing the version-agent by hand

For a host assembled by hand, or one where the agent was removed. Install the files without
changing the running stack:

```bash
sudo install -d -m 0750 /etc/proxy-control
sudo install -o root -g root -m 0644 deploy/version-agent.service /etc/systemd/system/version-agent.service
sudo install -o root -g root -m 0644 deploy/proxy-control-version-agent.tmpfiles.conf /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo install -o root -g root -m 0600 deploy/version-agent.env.example /etc/proxy-control/version-agent.env
sudo install -o root -g root -m 0600 deploy/version-catalog.example.json /etc/proxy-control/versions.json
sudo systemd-tmpfiles --create /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo systemctl daemon-reload
```

Replace every example catalog entry with an operator-verified artifact. Telemt entries must be
immutable image references (`@sha256:...`). NaiveProxy/Caddy and mita entries must be HTTPS
artifacts with lowercase SHA-256. The catalog is an allowlist, not a discovery mechanism; the
browser cannot extend it.

Configure the deployment path and the complete Compose overlay list in
`/etc/proxy-control/version-agent.env` (`PROXY_CONTROL_COMPOSE_DIR`, `PROXY_CONTROL_COMPOSE_FILES`).
The agent writes only the generated `version-overrides/compose.versions.yaml`, configured binary
targets, and its state/backup directory. It refuses symlink targets and invalid relative Compose
paths. When a configured container pins a host binary, the preflight Docker inspect is
fail-closed: only Docker's exact `No such object` result permits the update; daemon, permission,
timeout, and other uncertain inspect failures block it.

Record the currently installed versions in `/var/lib/proxy-control/version-agent/state.json` before
the first update. Then enable and verify the agent:

```bash
sudo systemctl enable --now version-agent
sudo systemctl is-active version-agent
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/versions
```

The panel Compose service must mount `/run/proxy-control` and set
`VERSION_AGENT_SOCKET=/run/proxy-control/version-agent.sock`. The socket is created with mode
`0660`; make its numeric group accessible to panel UID `10001` without making it world-writable.

## The panel master key

Client credentials, kept subscription copies and node keys are stored encrypted with the key in
`secrets/panel-master-key`, a Compose secret of the `panel` service.

- **Installed with the installer**: nothing to do. The installer creates the key during
  installation, preserves it on every update and `repair`, and never regenerates it — a new key would
  make every stored credential undecryptable.
- **Assembled by hand from `compose.yaml`**: create the key once before the first
  `docker compose up`, otherwise Compose refuses to start with a missing secret file:

```bash
umask 077
docker run --rm -v "$PWD/secrets":/out --entrypoint python mtproxy-panel:latest \
  -m panel.cli master-key-init --path /out/panel-master-key
```

Back it up **separately from the database** ([backup and restore](BACKUP_RESTORE.en.md)). A panel
that has never stored a secret starts without the key; once encrypted rows exist and the key is
missing, the panel refuses to start rather than serving empty subscriptions. A panel without a
master key cannot show a subscription again and cannot be managed by a central (a push answers 409
`secret_store_disabled`).

Rotation is a separate, deliberate operation and never part of an update:

```bash
docker compose exec panel python -m panel.cli master-key-rotate --path /run/panel/master-key
```

It adds a new active key, re-encrypts every stored secret in batches, verifies the result, and only
then narrows the keyring to the new key — an interrupted rotation leaves everything readable.

## Enabling the Xray-router on an installed node

An update never installs the optional egress router ([XRAY_ROUTER](XRAY_ROUTER.en.md)). A node
without it keeps working: the routing screen says «Xray-router: not installed», policies compile for
the services' own backends, and rules with `geosites`, `geoips` or ports only preview as
`rule_kind_unsupported` naming the router.

**What the installer does with it.** The router is part of the installer configuration:
`router = true` in `[egress]` (the profile needs NaiveProxy or Mieru), and `naive = "router"` /
`mieru = "router"` only when a service should start attached. The pinned archive
`/var/lib/proxy-control/Xray-linux-64.zip` is fetched by the installer when absent (URL and SHA-256
in `release/external-artifacts.json`; an offline host stages the file in advance). The plan gains
one `xray_router.runtime` action between `warp` and the services: it creates the identity 10006,
extracts the three pinned members, prepares `/var/lib/xray-router`, writes `secrets/xray-router-*`
and `.env.xray-router` and starts `xray-router` and the `xray-router-ingress` bridge; `naive` and
`mieru` then re-apply with the router's environment and their own credential copies, and the
agent's environment gets `PROXY_CONTROL_XRAY_ROUTER=on` and the router's overlay.

**On a host installed with the installer.** The installer applies a configuration as one
installation: on a host whose installation is active, a plan from a changed configuration is
refused (`an installer transaction already exists`), and running the same configuration again
changes nothing. A finished `uninstall` without `--purge-data` does not block the next `install`,
which picks up the preserved data — the master key, the panel database, credentials, manager state
and named volumes ([installer reference](INSTALLER_REFERENCE.en.md), «Recovery, repair, rollback,
and uninstall»). The services are down between the two steps: take a backup and plan a window.

**On a host assembled by hand.** Follow the same steps from the installer reference («The
Xray-router») with `COMPOSE_FILE` extended by `compose.xray-router.yaml`. The managers learn the
router from `NAIVE_EGRESS_ROUTER` / `NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE` and
`MIERU_EGRESS_ROUTER` / `MIERU_EGRESS_ROUTER_CREDENTIAL_FILE` (empty by default, and the `router`
provider appears only when they are set). Add `compose.xray-router.yaml` to
`PROXY_CONTROL_COMPOSE_FILES` and `PROXY_CONTROL_XRAY_ROUTER=on` to the agent's environment;
otherwise the next one-command update refuses to start.

**Attaching the services.** Enabling the router attaches nothing: attach NaiveProxy and Mieru on
the routing screen when you are ready («Connect to Xray-router»; their sessions are interrupted
once). Attaching with a native policy still applied is refused (`policy_applied`): reset it first.

```bash
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -E 'verified|generation'
ss -ltnp 'sport = :45101 or sport = :45102'   # 127.0.0.1 only, owned by xray
```

## Enabling the relay and lane slots

The relay lets other nodes of the fleet exit through this one (chains); lane slots give Mieru
grants their own lanes ([ROUTING](ROUTING.en.md), «Chains and lanes»). Both need the Xray-router.

In the installer configuration `[egress].relay_port` (45443 by default with `router = true`; `0` —
no relay) and `[mieru].lane_slots` (0…8, 4 by default with the router) control them: the
`xray_router.runtime` action enables the relay through the manager (the Reality keypair is minted
once and kept in `/var/lib/xray-router/relay.json`), `mieru.runtime` installs the `mita@.service`
template, enables `mita@1…4` and writes `MIERU_LANE_SLOTS` into `.env.mieru`; on a managed fresh
host UFW opens `45443/tcp` and `46101…46104/tcp`. `repair` enables the relay again, idempotently.
Adding them to an active installation follows the same installer rule as the router above.

A host assembled by hand:

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

Verification:

```bash
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --relay | python3 -m json.tool   # enabled, public_key
systemctl is-active mita@1 mita@2 mita@3 mita@4; ss -lnt | grep -E ':45443|:4610[1-4]'
```

## The router's geodata

The router reads its geosite/geoip lists from `/var/lib/xray-router/geodata/` (the state directory,
writable to it). The source is chosen on «Routing» → Geodata → «Source…»: Loyalsoldier (a new router
starts on it with daily refreshes), the lists of the Xray-core archive (the pin; they follow an Xray
update), «Russia — runetfreedom» (`ru-blocked`, `ru-available-only-inside`), «Iran — chocolate4u»,
«v2fly», or your own URLs. Every download is checked against its published checksum; files up to
128 MB are accepted.

New lists restart the router and drop its connections for a few seconds, so a daily refresh waits
for the chosen hour — 02:00 UTC by default, any of the 24 hours or «any hour». The geodata line shows
when the lists were last checked, when the next check is due, and a router restart failure if one
happened.

```bash
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -A3 '"geodata"'
```

An `xray` update from the «Versions» screen replaces the binary together with the lists of its
archive; with the Xray-core archive as the source the router moves to the new archive's lists.

## Routing MTProxy through the Xray-router

On a node with the Xray-router, MTProxy can leave through WARP, a custom exit or another node of the
fleet ([ROUTING](ROUTING.en.md)). It goes through the `xray-router-ingress` bridge: Telemt runs on the
Docker network, the router on the host network, and the bridge (the router's own image) joins them
with no new host port and no firewall rule; the router mints the credential of its `mtproxy`
ingress itself.

1. Make sure the router and the bridge run the current release (the one-command update does it; by
   hand — [rebuilding changed managers](#rebuilding-changed-managers-by-hand) with
   `xray-router xray-router-ingress`).
2. «Routing» → MTProxy → «Connect to Xray-router», then the exit: WARP, your own exit or another
   node. Attaching changes Telemt's upstream through its API without restarting the container; open
   sessions finish on the previous path. «Disconnect from Xray-router» puts back the upstream Telemt
   had before.

Rules by CIDR, `geoip` and port work; rules by domain, `geosite` and protocol are refused in the
preview (`rule_kind_unsupported`) because Telemt reaches Telegram's data centres by IP. The routing
screen names what is missing: `router_lacks_mtproxy` (the router has not been rebuilt yet),
`ingress_unreachable` (the bridge does not answer), `node_lacks_mtproxy_egress` (a linked node older
than 1.1).

```bash
docker inspect --format '{{.State.Health.Status}}' proxy-control-xray-router-ingress   # healthy
```
