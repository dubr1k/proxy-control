# Proxy Control operations runbook

**English** · [Русский](OPERATIONS.ru.md)

Use this guide for an already deployed node. It does not replace the [installation guide](../INSTALL.en.md), [backup contract](BACKUP_RESTORE.en.md), or protocol-specific acceptance tests.

## 1. Start of change window

Capture context without printing secret-bearing environment:

```bash
cd /opt/mtproxy-shared443   # or the actual checkout/deployment path
git rev-parse HEAD 2>/dev/null || true
docker compose ps
systemctl is-active nginx docker
sudo nginx -t
ss -lntup
```

Confirm the complete deployment overlay set is active. Prefer a root-only `.env` containing one line such as:

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml:compose.mieru.yaml
```

Never dump the complete `.env` into a terminal transcript, issue, or CI log. Never use `docker compose --remove-orphans` when the current model omits any deployed overlay.

## 2. Daily health

```bash
docker compose ps
curl -fsS -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
sudo nginx -t
systemctl --no-pager --full status nginx
```

For enabled host runtimes:

```bash
systemctl is-active caddy-naive mita
sudo -u mita env MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

Accept only anchored mita status output of this exact form:

```text
mita server status is "RUNNING"
```

Do not treat an unrelated `RUNNING` token in stderr or another line as success.

## 3. Protocol acceptance

### MTProxy / Telemt

1. Confirm Nginx owns public TCP/443 and Telemt uses the expected loopback backend.
2. Run an external Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ` probe for every active secret.
3. Test a real Telegram client from the target network.
4. Regression-test adjacent SNI routes.

HTTP health and an open port do not prove MTProto.

### NaiveProxy

1. Check unauthenticated cover HTTPS.
2. Open authenticated CONNECT and transfer a known payload.
3. Close the tunnel before checking the accounting increment.
4. Confirm authorization is absent from access logs.
5. Regression-test adjacent SNI routes.

### Mieru

1. Verify pinned `/usr/bin/mita` version/digest and exact status.
2. Run a real client → server → Internet probe for the configured TCP/UDP listeners.
3. Check manager health and panel typed status.
4. Do not expect per-user traffic counters: the safe typed boundary is unavailable and the UI reports `unavailable`.

## 4. User lifecycle

### Roles

- `owner`: administrators, users, reveal/rotation, API keys, the fleet registry and linked panels;
- `admin`: protocol users and audit within allowed boundaries;
- `viewer`: read-only, with no reveal, reset, or mutations.

Every mutation over a session requires CSRF; a Bearer request carries no cookie and is gated by its key's scope instead. Audit stores action/actor/target/result but never credentials, URLs, QR payloads, or reveal tokens.

### One-time credentials

Naive and Mieru create/rotate return credentials only through a one-time reveal with `Cache-Control: no-store`. Closing the dialog clears URL, QR, and config fields from frontend state.

An existing Mieru password cannot be recovered from `hashedPassword`. Use **New link + QR** to rotate; the previous client configuration stops working.

## 5. Configuration changes

Before mutation:

1. Back up one consistent generation.
2. Record current revision, image/binary digests, and service status.
3. Run configuration validation/read-only plan.
4. Change one protocol boundary.
5. Verify health, the real protocol path, accounting, and adjacent SNI.
6. Only then expire temporary rollback artifacts under the retention policy.

Naive and Mieru managers have their own journals and recovery. That does not replace a host-level backup before a deployment change.

## 6. Logs

Use bounded queries and inspect recent events first:

```bash
docker compose logs --since=15m --tail=300 panel mtproxy
journalctl -u nginx -u caddy-naive -u mita --since=-15m --no-pager
```

Before sharing logs, remove passwords, complete access URLs, QR/reveal payloads, tokens, API keys (`pc_…`), cookies/CSRF values, and PKI material. Keep infrastructure identity only in an approved private incident channel.

### Subscriptions: logs and rotation

A client subscription URL (`https://<subscription domain>/s/<token>`) is a bearer
credential: whoever holds it receives every access of that client. By design it
never reaches a log — the panel runs uvicorn without an access log, the Nginx
`server` block for the subscription domain has `access_log off`, and the panel
stores only a hash of the token. Do not add request logging to that path, and do
not paste a subscription URL into a ticket.

If a URL leaks, rotate the client's subscription in the panel: the old token stops
answering (404, same as an unknown token) in the same transaction that issues the
new one, so there is never a window with two live URLs. Revoking without
reissuing has the same effect. Rotating an access credential (Naive/Mieru/MTProxy)
does not change the subscription URL; clients pick the new link up on their next
refresh (`Profile-Update-Interval: 12`, and `ETag`/`If-None-Match` keep unchanged
fetches at 304).

## 7. Accounting

- Telemt runtime counter and quota usage are different values.
- Naive bytes appear after a successful CONNECT closes.
- Mieru per-user traffic is unavailable; its quota is a rolling approximate session-admission check.
- Reset creates a local baseline. It does not create billing precision or a calendar period.

See [ACCOUNTING.md](ACCOUNTING.md).

## 8. Restart and recovery

Restart one boundary at a time:

```bash
docker compose restart panel
systemctl restart caddy-naive
systemctl restart mita
```

Repeat the boundary's acceptance test after every restart. Never delete `journal.json`, `journal.key`, `transaction.json`, WAL/SHM, or manager backups to force startup; use documented repair/restore.

For installer-owned core:

```bash
sudo python3 scripts/proxyctl.py repair
```

`repair` loads the private ownership manifest and intentionally accepts no arbitrary path.

## 9. Incident sequence

1. Stop new mutations without destroying process/state.
2. Capture service status, exact revision, bounded logs, and listener ownership.
3. Create a forensic backup of the current generation.
4. Isolate the boundary: Nginx, panel, Telemt, Caddy/Naive, mita/Mieru, the link to a central or linked panel, or fleet v1.
5. Run negative and positive probes for that boundary.
6. Repair or roll back only after establishing root cause.
7. Run complete protocol regression, including adjacent SNI routes.

See [Troubleshooting](TROUBLESHOOTING.en.md).

## 10. End-of-window checklist

- expected Compose services are healthy;
- `nginx -t` passes;
- public listener ownership is unchanged;
- acceptance passed for every changed protocol boundary;
- SQLite integrity and backup checksums pass;
- temporary configs, clients, worktrees, packages, and caches are removed;
- no production credential remains in shell history, logs, or artifacts.

## 11. Central panel and linked panels (Fleet v2)

Since v0.3 a panel can manage other panels over HTTPS with a `node-sync` API key; the
model is in [FLEET.en.md](../FLEET.en.md). What the runbook adds is the order of
operations on a fleet of hosts.

### Rollout order

The central and its nodes must run the **same v0.3 build**. A node validates the
generation document strictly (`extra = forbid`), so a node on an older build refuses a
document with a field it does not know (for example `origin`) with 422; the central then
records `last_error: push 422: rejected` for that node and backs off (30 s → 10 min) until
something changes. A v0.2 panel has no `/api/fleet/v2/*` at all and cannot be added
(«the node answered 404»). Therefore:

1. **Upgrade the nodes first, then the central.** On every host, in the project
   directory: `docker compose up -d --build --wait panel` with the persisted overlay set.
   Migrations 9–13 apply at start; `panel_guid` is created on first start
   ([UPGRADING](UPGRADING.md)).
2. On each node create a `node-sync` key («Администраторы → API-ключи → Создать ключ»).
3. On the central add the panels («Узлы → + Панель → Проверить → Добавить») and import
   their users. The first heartbeat (≤ `PANEL_FLEET_HEARTBEAT_SECONDS`, default 15 s)
   turns the card `online`.

**Hosts updated by rsync.** The panel reports the version it finds in `VERSION`,
bind-mounted read-only at `/app/VERSION` by `compose.yaml`; the installer copies that
file into the project directory itself. A host you update by rsync must receive
`VERSION` **together with the code** — otherwise the node reports `dev` to the central
and its card reads «панель dev». A missing or unreadable file never stops the panel.

### Heartbeat and daily health

`PANEL_FLEET_HEARTBEAT_SECONDS` in the central's environment sets the cadence (default
15, minimum 1; the lab uses 3). One tick costs two requests per node (`identity`,
`status`) plus a push when a generation is pending, all under the node's 120/min key
limit. On the central's «Узлы» screen every linked card should be `online`, show
`desired` equal to `applied` with no «есть недоставленные изменения» marker, and carry no
`last_error`; `GET /api/events` lists `node.up`/`node.down` transitions. On a node, the
card «Этот сервер» names the central that manages it; users the central owns are shown
as «управляется центром» and refuse local mutation with 409 `managed_by_central`.

### Pause, unlink, delete

- **Pause** («Пауза», or «Отключить» on a linked panel): the heartbeat and delivery skip
  the node, the link and its grants stay, subscribers keep working. Use it during a
  maintenance window on the node.
- **Unlink on the node** («Отвязать» on the card «Этот сервер», owner only, or
  `POST /api/nodes/local/unlink`): the node forgets its master and every account it held
  for the central becomes local again; the runtime is untouched. The central keeps its
  link and would re-master the node with the next generation it publishes, so remove the
  node there too.
- **Delete on the central** («Удалить», `DELETE /api/nodes/{id}`): refused (409) while the
  panel carries grants that are not `deleted` — delete the clients' accesses on that node
  first and wait for them to report `missing`; the row is purged and the runtime user is
  gone. Deleting the link then unlinks the node best-effort and removes the encrypted key.

### Rotating or revoking a node's key

Create a new `node-sync` key on the node, enter it on the central with «Изменить», then
disable or delete the old key on the node — the central stores the new key as a new
secret row and revokes the old one. Disabling the key on the node without updating the
central turns that node `offline` (`node.down`) on the next heartbeat and nothing else
changes; subscribers are unaffected.

### Rollback

Rolling a **node** back to the previous panel image follows the general rule: restore the
complete previous generation, database included ([UPGRADING](UPGRADING.md)). A v0.2 image
refuses to start on a database at schema 13 («database schema 13 is newer than this
code»), so the previous image alone is not a rollback. On a node that was never linked the
upgrade touched no runtime user and `managed_resources` is empty, so the pre-upgrade
database loses no fleet state. A node that was managed: unlink it first (its users become
local and keep working), then roll back. A **central**: pause or delete its links first;
its nodes keep serving whatever generation they last applied.

## 12. Routing (v0.4)

An egress policy is applied by a service's **manager**, never by editing a config by
hand: the naive-manager owns `# BEGIN NAIVE-MANAGER EGRESS … # END` inside
`/var/lib/naive-manager/Caddyfile` (reload, no restart), the mieru-manager owns mita's
`egress` section (a restart of mita: every Mieru session reconnects once). A hand-written
`upstream` or `egress` is left alone until the first apply adopts it, and a rollback
brings it back verbatim — [ROUTING](ROUTING.en.md).

- **Before applying WARP** the preview must show `warp: доступен`; a WARP that does not
  answer fails closed (`provider_unreachable` / `egress_unreachable`) and nothing changes
  on the node. `NAIVE_EGRESS_WARP` / `MIERU_EGRESS_WARP` in `.env` name the endpoint.
- **Check after applying**: the badge «применено (rev N)»; `curl --proxy https://<naive
  host>` with a client credential to a blocked and to an allowed target; a Mieru client
  the same way; the cover site `https://<naive host>/` still answers 200; `nginx -T` and
  `nft list ruleset` unchanged (routing never touches them).
- **A failed apply** leaves the last applied revision running (`state = failed`,
  `last_error` names the code); «Откатить» returns the manager's previous entry;
  `manual_intervention_required` means the manager could not restore its config after a
  readback mismatch — its backups are in `/var/lib/naive-manager/backups` and the
  mieru-manager's journal, and `docker compose logs naive-manager mieru-manager` says
  which file.
- **Linked panels**: the central applies through the next generation; the node card and
  the routing screen say «применяется…» until the node's report arrives (one heartbeat);
  the node's own screen refuses to apply while a central manages it
  (`managed_by_central`). Unlinking leaves the egress as it is.
- Audit: `routing.policy.update | apply | rollback | delete` on the panel that applied.

