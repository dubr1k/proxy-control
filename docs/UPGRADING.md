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
(401 otherwise); `Authorization: Bearer` on the whole `/api/*`; the setting
`PANEL_FLEET_HEARTBEAT_SECONDS` (default 15) for a central.

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
