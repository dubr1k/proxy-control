# Proxy Control panel

The panel manages distinct Telemt/MTProto, NaiveProxy/Caddy, Mieru/mita, and fleet boundaries. Protocol-specific capabilities and accounting semantics are not interchangeable.

The panel binds to host loopback only at `http://127.0.0.1:8787`. Use an SSH tunnel (`ssh -L 8787:127.0.0.1:8787 server`) or your own HTTPS reverse proxy remotely. Never publish Telemt port `9091`; Compose intentionally exposes no host port for it.

## First start

The deployment renderer creates `secrets/telemt-api-token` with mode `0600`; it is never placed in `.env`, deployment state, or logs. Do not reuse any example or production password. Create the first owner with a new password supplied on stdin:

```sh
read -rsp 'New password: ' PANEL_INITIAL_PASSWORD; echo
# exec, not run: the image entrypoint ignores the container command and always
# starts uvicorn, so `run` would simply bring up a second server.
docker compose up -d panel
printf '%s\n' "$PANEL_INITIAL_PASSWORD" | docker compose exec -T panel \
  python -m panel.cli create-admin --username owner --role owner --password-stdin
unset PANEL_INITIAL_PASSWORD
docker compose up -d
```

Passwords require at least 12 characters and are stored with Argon2id. SQLite stores administrators, opaque-session SHA-256 digests, login throttling, and audit records only. Proxy secrets are never persisted by the panel: Telemt owns them, while a reveal lives in memory for at most 120 seconds and can be consumed once.

## Settings and roles

- `PANEL_ALLOWED_HOSTS`: comma-separated accepted Host values; add the public hostname behind a reverse proxy.
- `PANEL_COOKIE_SECURE=true`: keep enabled with HTTPS; set temporarily to `false` only for direct local HTTP testing.
- `PANEL_DATABASE=/data/panel.sqlite3`: SQLite database on the `panel-data` volume.
- `TELEMT_API_TOKEN_FILE=/run/secrets/telemt-api-token`: internal API-token transport.

`owner` manages administrators and users; `admin` manages users and reads audit; `viewer` is read-only. The last active owner cannot be removed or demoted. Disabling an administrator invalidates their sessions. Every mutation requires CSRF and is audited without passwords, tokens, links, or proxy secrets.

`GET /api/audit` remains a read-only `items` response and supports `limit` (1–200), `before_id`, and equality filters for `actor`, `action`, and `target` (`actor` is case-insensitive). When more matching rows exist, `next_cursor` is the `before_id` value for the next page.

The panel also contains a durable fleet registry and typed per-node command queue. Its Fleet view, direct mTLS pull ingress, manual CSR enrollment, and outbound node service are documented in [FLEET.en.md](FLEET.en.md).

For owners and administrators, the Connections view can create, block, unblock, rotate, and remove individual proxy access records. An active Telegram link and QR code can be reopened through the explicit “QR and link” action. Every reveal is audited, while the link and secret are excluded from audit records and user-list responses.

## Telemt 3.4.25 traffic, quotas, and limits

The panel deliberately exposes two different counters:

- `runtime_total_octets` comes from `GET /v1/users` (`total_octets`) and is summed on the dashboard as traffic of the current Telemt runtime generation. It normally starts with the process, but a 3.4.25 in-runtime reload creates a new statistics generation and starts this counter again. It is a diagnostic runtime metric, not quota usage; resetting quota does not clear it.
- `quota_used_bytes` comes from `GET /v1/stats/users/quota` (`used_bytes`) and is displayed against `data_quota_bytes`. This is the resettable counter Telemt uses for quota enforcement. `quota_last_reset_epoch_secs` is the last manual-reset time, or `0` when no reset has occurred.

“Reset quota” calls `POST /v1/users/{username}/reset-quota`: Telemt clears quota usage and immediately persists quota state without changing the configured quota or runtime `total_octets`. Telemt 3.4.25 has no periodic quota-state checkpoint. State is saved on an explicit reset and graceful shutdown, so an abrupt termination can lose usage accumulated since the last save. The panel does not claim or emulate automatic daily/monthly resets; use separately verified external automation when a calendar period is required.

The limits form changes only documented Telemt fields: quota bytes, up/down bits per second, TCP connections, unique IPs, and RFC3339 expiration. An empty field sends `null` and removes that override. Panel responses use explicit field allowlists: Telemt `links`, `secret`, ad tags, IP lists, and any unknown or future nested fields from list/update/reset responses are not passed through.

## Optional NaiveProxy management

The host-Caddy integration is enabled through a separate Docker override, so a regular MTProxy deployment without NaiveProxy remains compatible:

```sh
COMPOSE_FILE=compose.yaml:compose.naive.yaml docker compose up -d --build
```

Store production-specific values in the local, Git-ignored `.env`:

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml
NAIVE_PUBLIC_HOST=proxy.example.com
NAIVE_DATA_DIR=/var/lib/naive-manager
```

`naive-manager` is a dedicated unprivileged container. It uses host networking only for the loopback Caddy Admin API and TLS probe, has no Docker socket, and can write only `NAIVE_DATA_DIR` and its private runtime socket volume. `/var/log/naive-proxy` is mounted read-only at `/logs`; accounting state is the mode-`0600` SQLite/WAL set under `/data`. The panel sees only the token-authenticated Unix socket. The manager accepts only complete, successful CONNECT records for managed usernames and exposes explicit secret-free response allowlists. Counters are payload bytes (`bytes_read` client→proxy and `size` proxy→client), appear when a tunnel closes, and are not TLS/IP usage.

The Control Panel's NaiveProxy “Quota, MiB” field sets a per-user `quota_bytes`. `null` means the quota is disabled and the user is unlimited; zero and negative values are rejected. A dedicated manager thread collects completed CONNECT records on an interval (60 s by default, `NAIVE_QUOTA_INTERVAL_SECONDS`) even when the panel is closed, and transactionally disables a user when `total_bytes >= quota_bytes` by removing that user's credentials from the managed Caddy block. Enforcement never runs on a read path: `GET /v1/health` and `GET /v1/traffic` report state and never rewrite the managed config. This is admission enforcement, not a byte-level hard cap: an already-open tunnel may finish and cause overshoot, and a user may keep transferring until the next enforcement pass. Do not use it as an exact billing limit.

Resetting Naive traffic clears only the local accounting baseline and does not automatically re-enable a user disabled by quota. After a reset, explicitly click “Enable”. Removing the quota (`null`) or raising it above the recorded usage does not re-enable access either: the manager only records that the quota no longer holds the user back (`disabled_reason` becomes `manual`), and enabling stays a separate operation. Enabling a user whose usage still exceeds the quota is refused with `409` and the reason code `quota_exhausted`, which the panel shows as an actionable message rather than a manager outage. User passwords, usernames, and access URLs are not returned by list or quota API responses.

Deploy the manager before the panel: an older manager silently ignores `quota_bytes` on create and has no quota endpoint, so a newer panel would report a failure the operator cannot act on.

The production accounting contract keeps ten 10 MiB Caddy rotations plus the active file (110 MiB declared footprint) and allows at most 128 MiB of exact consumed-prefix verification per collection request. Prefix verification is synchronous and request-wide across all retained files; the extra 18 MiB is bounded headroom for an active file crossing its rotation boundary. Startup rejects a verification budget below the declared footprint. A changed prefix or a footprint that exceeds the bounded budget fails closed and makes accounting unhealthy instead of returning counters that may have been replayed or omitted.

Before first start, copy the active Caddyfile to `${NAIVE_DATA_DIR}/Caddyfile`, create `secrets/naive-manager-token` mode `0600`, and provide the same token as `${NAIVE_DATA_DIR}/manager-token`. Do not let restrictive `umask 077` make the source/build context unreadable to UID `10002`. Bootstrap validates through Caddy Admin `/adapt`, so start host Caddy from the legacy-credential generation before the initial import:

```sh
NAIVE_DATA_DIR=${NAIVE_DATA_DIR:-/var/lib/naive-manager}
test ! -L "${NAIVE_DATA_DIR}" || { echo "NAIVE_DATA_DIR must not be a symlink" >&2; exit 1; }
# Fail closed if the fixed production IDs belong to another account/group.
uid_name=$(getent passwd 10003 | cut -d: -f1 || true)
gid_name=$(getent group 10004 | cut -d: -f1 || true)
test -z "${uid_name}" -o "${uid_name}" = naive-caddy || { echo "UID 10003 collision: ${uid_name}" >&2; exit 1; }
test -z "${gid_name}" -o "${gid_name}" = naive-accounting || { echo "GID 10004 collision: ${gid_name}" >&2; exit 1; }
getent group naive-accounting >/dev/null || groupadd --system --gid 10004 naive-accounting
id naive-caddy >/dev/null 2>&1 || useradd --system --uid 10003 --gid naive-accounting --home /nonexistent --shell /usr/sbin/nologin naive-caddy
test "$(id -u naive-caddy)" = 10003 || { echo "naive-caddy must use UID 10003" >&2; exit 1; }
test "$(id -g naive-caddy)" = 10004 || { echo "naive-caddy must use GID 10004" >&2; exit 1; }
# UID 10002/GID 101 remain the manager identity; GID 10004 is read-only supplementary access.
install -d -o 10002 -g 101 -m 0700 "${NAIVE_DATA_DIR}"
install -d -o 10003 -g 10004 -m 0750 /var/log/naive-proxy
for file in Caddyfile manager-token; do
  test -f "${NAIVE_DATA_DIR}/${file}" && test ! -L "${NAIVE_DATA_DIR}/${file}" || exit 1
done
chown -h 10002:101 "${NAIVE_DATA_DIR}/Caddyfile" "${NAIVE_DATA_DIR}/manager-token"
chmod 0640 "${NAIVE_DATA_DIR}/Caddyfile"
chmod 0400 "${NAIVE_DATA_DIR}/manager-token"
# The unit runs /usr/local/bin/caddy and checks that build before starting, so
# the pinned binary has to be installed first:
#   docker buildx build --file docker/Dockerfile.caddy-naive \
#     --output type=local,dest=/tmp/pc-caddy .
#   install -o root -g root -m 0755 /tmp/pc-caddy/caddy /usr/local/bin/caddy
test -x /usr/local/bin/caddy
install -o root -g root -m 0755 scripts/check-naive-caddy-build.sh /usr/local/libexec/check-naive-caddy-build
install -o root -g root -m 0755 scripts/caddy-naive-adapt /usr/local/libexec/caddy-naive-adapt
install -o root -g root -m 0644 deploy/caddy-naive.service /etc/systemd/system/caddy-naive.service
systemctl daemon-reload
systemctl enable --now caddy-naive
test "$(ss -H -lnt 'sport = :2019' | awk '{print $4}')" = 127.0.0.1:2019
test "$(ss -H -lnt 'sport = :4443' | awk '{print $4}')" = 127.0.0.1:4443
docker compose -f compose.yaml -f compose.naive.yaml run --rm --build naive-manager --bootstrap-only
systemctl reload caddy-naive
# Complete one authenticated public CONNECT, close it, and require:
test -f /var/log/naive-proxy/access.json
test "$(stat -c %a /var/log/naive-proxy/access.json)" = 640
docker compose -f compose.yaml -f compose.naive.yaml up -d --build --wait
```

Current `caddy-naive-adapt` and `naive_manager` disable automatic HTTPS redirects in the private generation. Without that, unprivileged Caddy attempts `127.0.0.1:80`. Initial bootstrap writes managed credentials/accounting but does not activate them: `systemctl reload caddy-naive` must precede the long-running manager, and the first completed CONNECT must precede accounting health.

Host Caddy and the container manager have separate identities: Caddy is UID `10003`, while the manager remains `10002:101` and receives only supplementary accounting GID `10004`. `/var/log/naive-proxy` is `10003:10004` mode `0750`; Caddy creates mode-`0640` logs, so the manager can read but cannot create, truncate, rename, or append them. Manager data remains `10002:101` mode `0700`. At Caddy start and systemd reload, privileged `install` stages the manager-owned source as `/run/caddy-naive/Caddyfile` (`10003:10004`, `0400`) in a mode-`0700` runtime directory. Caddy cannot traverse `/var/lib/naive-manager` at runtime. Manager-driven mutations do not use the staged file: they adapt and validate the just-written source through the loopback admin API and send that exact JSON to `/load`, preserving transactional rollback without a stale-stage window. Verify `systemd-analyze verify`, inspect `systemctl show caddy-naive -p User -p Group`, and confirm the manager cannot append the log while Caddy cannot read manager state before cutover.

For migration, first stop manager mutations and Caddy, then back up the active unit, binary, Caddyfile, manager data, and log directory. Run the UID/GID collision preflight before changing ownership; create the separate identities and permissions; install the pinned binary/checker; run the checker and exact `caddy adapt --validate`; bootstrap the manager; switch the unit; then start Caddy and the Compose override. Re-running bootstrap is idempotent. Faults at prepared, files-replaced, or reload-pending migration phases restore the paired old config/state generation before retry. Do not delete the old unit or backup until health, cover HTTPS, authenticated CONNECT, traffic collection, and all adjacent SNI routes pass. Every later credential mutation follows paired backup → Caddy adapt with `validate=true` → fsync journal → atomic replace → Caddy `/load` → HTTPS probe. Failure restores both files and verifies the restored live generation. An unconfirmed rollback leaves the manager unhealthy and keeps the journal for startup recovery.

Rollback is deliberately host-controlled: stop `naive-manager` and Caddy; restore the saved Caddyfile/unit/binary, manager-data snapshot, log ownership/modes, and previous service identities as one generation; run the restored build's validation; restart Caddy; and re-run cover/authenticated/SNI probes before removing the override. Never copy only `traffic.sqlite3` without its `-wal`/`-shm` files while the manager is running. A traffic reset changes only the local baseline; viewers are denied reset, and audit records the username/action without credentials or authorization headers.

The one-time access dialog separates formats by client:

- **Native** downloads or copies the official NaiveProxy `config.json`; the native client has no documented QR import, so this tab does not show a QR:

  ```json
  {"listen":"socks://127.0.0.1:1080","proxy":"https://USER:PASSWORD@proxy.example.com"}
  ```
- **NekoBox** exposes a `naive+https://USER:PASSWORD@HOST:443#NAME` link and its QR. That is the format `parseNaive` accepts in NekoBox for Android and its forks, so QR import works there.
- **Karing** downloads the complete sing-box JSON profile and offers a `karing://install-config` deep link. Its QR encodes that deep link with the full profile content, never the raw `https://USER:PASSWORD@HOST` endpoint.
- **Shadowrocket** shows explicit manual fields (`HTTPS`, server, port, username, password). Proxy Control does not generate an unverified Shadowrocket URI or QR.

Tabs without a QR (Native, Shadowrocket) drop the QR pane entirely instead of rendering an empty white placeholder: a blank plate reads as a broken code and invites scanning it into the wrong client.

Karing's current source accepts `karing://install-config?url=...` and imports sing-box configuration content; its current protocol editor includes Naive. See the [Karing URL-scheme contract](https://karing.app/en/cooperation/scheme), [Karing import guide](https://karing.app/en/quickstart), and [sing-box Naive outbound schema](https://sing-box.sagernet.org/configuration/outbound/naive/). All variants contain the same credential and remain subject to the one-time reveal and `Cache-Control: no-store` rules.

## Switching the writer: `PANEL_VNEXT_WRITER`

Since v0.2 the protocol endpoints have two writers, selected by
`PANEL_VNEXT_WRITER`:

- `legacy` (default) — the panel calls the managers directly, exactly as v0.1.0 did;
- `domain` — the same requests go through clients and grants, so the panel **owns the
  credential** and can render a subscription.

From outside the two are indistinguishable: same status codes, same response shapes,
same audit actions. That is enforced by running the whole API test suite in both modes.

Cut over in this order:

1. Import the existing users on the Clients screen.
2. Adopt the grants with the "Adopt" button (for Mieru, with a deliberate rotation).
3. Set `PANEL_VNEXT_WRITER=domain` and restart the panel.
4. Verify create/enable/rotate on one user of each protocol.

If step 3 finds users the panel does not know, that is fine: the first operation on
such a user records it as `imported`, without recreating it and without merging it with
a same-named account of another protocol. No credential appears for that row — the
panel does not have one; adopt it explicitly.

Elevated Mieru flags (`allow_private_ip`, `allow_loopback_ip`) stay on the direct
manager call even in `domain` mode: that path is deliberately manual, and smuggling it
through a generic intent would change what it means.

## The Clients screen

A client is a person or a device; a grant is their account in one protocol on one
node. The card shows the client's name, its state (active / suspended / archived) and
one chip per grant: "protocol · runtime account · state".

"Import existing" lists what the managers already run. The panel only **reads** them:
passwords, quotas and enabled flags are untouched, and no `create`, `rotate`, `enable`
or `delete` is ever issued. Import is therefore safe on a live server and can be
repeated — already adopted accounts are marked and skipped.

An identical username across protocols is **a hint only**. The panel flags those rows,
but by default every (protocol, runtime account) pair becomes its own client: three
`alice` accounts in three managers are not evidence of one person, and a silent merge
would hand one subscriber somebody else's access. Merge deliberately by picking an
existing client in the "Where" column.

An imported grant carries no secret: the panel never saw the password the manager
issued earlier. Such a grant is marked "no stored secret" and stays out of the
subscription until it is adopted with the "Adopt" button.

Adoption differs by protocol, and the difference is not cosmetic:

- **MTProxy and NaiveProxy** hand the current credential back on request, so the panel
  simply reads it and files it in encrypted storage. The link a subscriber already
  holds keeps working.
- **Mieru** stores only a password hash, so neither the panel nor mita itself can read
  it back. The only honest option is to issue a new one, and the panel asks first, in
  those words: **the current `mierus://` link will stop working** and the subscriber
  needs a new one. Without that consent the panel refuses (409) and never touches the
  manager.

Neither the API response nor the audit log ever contains the password: the audit
records the protocol and whether a rotation happened (`rotated: true|false`).

### Issuing access

The "Issue access" button on a client card creates accounts in several protocols as a
**single operation**. Three managers cannot share a transaction, so "all or nothing" is
not available — instead the operation keeps a journal, and every run ends in exactly one
of three outcomes:

- **succeeded** — every access exists and its credential is in encrypted storage;
- **compensated** — something refused, and everything **this operation** created was
  removed. Anything that existed on the server beforehand is never touched;
- **manual_intervention_required** — the runtime changed but cannot be rolled back
  safely. The panel names the operation id; continue with
  `python -m panel.cli operations-resume <id>`.

The journal survives a restart: a second `run` resumes from the last checkpoint instead
of starting over, so a duplicate account with the same name never appears.

After success the panel shows every link of the operation once. The same token does not
open twice — it is a one-time reveal.

A node that still carries grants cannot be disabled; subscribers would lose access
silently. Delete the grants first, then disable the node.

## The Nodes screen

A node card shows four things: identity (name, `node_id`, "this server" or "remote
[REDACTED:API key param]"), enrollment state, transport (when the node last checked in) and daemon
state. Certificates are listed with their expiry; anything expiring within two weeks
is highlighted.

Owner actions:

- **Register** (the Add button) creates the node and immediately shows the
  enrollment checklist. The panel cannot issue the certificate for you: the private
  key is generated on the node and never copied anywhere.
- **Rename** changes the display name only. `node_id` is immutable because
  certificates and grants are bound to it.
- **Disable / Enable**: a disabled node fails transport authentication. The panel
  refuses to disable a node that still has pending commands — they would otherwise
  sit in the queue with nobody to run them.
- **Revoke all certificates** requires retyping `node_id` in the dialog; the node
  stays off the transport until a new certificate is issued and bound.

The reserved "this server" node exists in every installation — a database migration
creates it, not the operator — and it is always listed first. It has no enrollment
actions at all: local protocols are managed directly, with no command queue and no
certificates. Instead of a certificate list, its card shows the health of the three
managers — Telemt, NaiveProxy, Mieru: "ok", "unavailable", or "disabled" for a
protocol this installation does not run. It can be renamed, but not disabled and not
revoked; the `node_id` `local` is reserved, so registering an ordinary node under it
is refused.

Raw Telemt v1 typed commands live in the card's "Advanced: transport v1" drawer —
the same interface as before, simply not on the first screen. See also
[FLEET.en.md](FLEET.en.md).

## Master key and rotation

Since v0.2 the panel can store a client credential so that a subscription still
renders tomorrow. Those values are encrypted with AES-256-GCM under the keyring
in `secrets/panel-master-key`, staged read-only into the container at
`/run/panel/master-key`. Encryption is bound to each row's identity, so a
ciphertext copied into another row — or handed to another node — fails to
decrypt rather than leaking.

What this protects: a stolen database file or backup. What it does not protect:
a compromised panel process, which holds the key while it runs.

- The installer creates the key on install and upgrade and never regenerates it.
- A panel with no stored secrets starts without the key; once encrypted rows
  exist and the key is gone, it refuses to start instead of serving empty
  subscriptions.
- Back the key up separately from the database ([backup and
  restore](docs/BACKUP_RESTORE.en.md)).

```sh
# check that a key and a database belong together (prints counts, never values)
docker compose exec panel python -m panel.cli master-key-verify --path /run/panel/master-key

# rotate: add a new active key, re-encrypt in batches, verify, then narrow the keyring
docker compose exec panel python -m panel.cli master-key-rotate --path /run/panel/master-key
```

Rotation is overlap-first: the file carries both keys while rows are rewrapped,
so an interrupted rotation leaves every secret readable. Take a fresh key backup
after it finishes.

## Backup

Back up volumes `panel-data` and `telemt-config`, `${NAIVE_DATA_DIR}` when the Naive integration is enabled, and secret files separately with mode `0600`. `users.conf` is imported only when `telemt-config/config.toml` is first created. Telemt then becomes the source of truth and atomically persists API mutations. Deleting `telemt-config` causes the original `users.conf` to be imported again.

```sh
curl -fsS -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
docker compose ps
docker compose logs panel mtproxy   # output must contain no secrets
```
