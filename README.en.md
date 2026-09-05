**English** · [Русский](README.md)

<div align="center">

# Proxy Control

**A proxy control panel that shares a server with 3x-ui instead of replacing it**

MTProxy, NaiveProxy, and Mieru behind one panel, with a transactional installer
that either finishes the job or puts the server back the way it was.

[![CI](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml/badge.svg)](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[What it is](#what-this-is) · [Port 443](#how-it-shares-port-443-with-3x-ui) · [Install](#installation) · [Protocols](#the-protocols) · [Operations](#day-to-day-operation) · [Security](SECURITY.md)

</div>

<p align="center"><img src="assets/proxy-control-cover.png" alt="Proxy Control illustration" width="100%"></p>

> [!IMPORTANT]
> This project is for people who know what DNS, TLS, Nginx, and Docker are. The
> installer takes care of the routine and refuses to take a dangerous step
> silently, but it does not replace understanding your own server.

## What this is

Proxy Control is a standalone alternative to 3x-ui: a separate panel that
manages **other** protocols and credentials. It is not a fork of 3x-ui and not
an attempt to replace it.

The central idea: **you do not have to choose between Proxy Control and 3x-ui**.
Both run on one server, behind one shared port 443, without fighting each other.

What you get:

| Boundary | What it is for |
|---|---|
| **MTProxy / Telemt** | A proxy for Telegram. The panel hands out `tg://` links and QR codes, sets limits and expiry, and reports service state. |
| **NaiveProxy** | An HTTPS proxy that looks like an ordinary website from the outside. One access works as both HTTPS and HTTP/2. Per-user quota and traffic accounting included. |
| **Mieru** | An obfuscated proxy with its own protocol over TCP and UDP. The panel issues a one-time `mierus://` link and QR. |
| **3x-ui** | VLESS Reality (TCP and XHTTP) and Hysteria2. The installer can install 3x-ui from scratch, or adopt an existing one without touching its files. |
| **Panel** | Owner, administrator, and viewer roles. Secret-free audit, one-time credential reveal, quota management. |
| **Fleet** *(optional)* | Inventory and limited management of remote nodes over mTLS. Installed by hand. |

Traffic accounting differs per protocol, and the panel does not hide that:
Telemt separates the process counter from quota consumption, Naive counts
payload bytes only after a tunnel closes successfully, and Mieru honestly
reports `unavailable` when no safe per-user counter exists.

## How it shares port 443 with 3x-ui

Public port 443 stays with Nginx. Nginx looks only at the domain name in the TLS
greeting (SNI) and hands each connection to the right service. Proxy Control
does not take 443 for itself — it asks Nginx for a couple of routes and nothing
more.

```text
Client ── TCP/443 ──► Nginx stream + SNI
                         ├──► 3x-ui and its protocols
                         ├──► MTProxy / Telemt
                         ├──► NaiveProxy
                         ├──► your other sites
                         └──► the Proxy Control panel
```

So the installer adds only its own lines to your SNI map and never rewrites it
wholesale. If it cannot understand your Nginx configuration unambiguously, it
stops instead of guessing.

Where everything listens:

| Boundary | Address | Who can reach it |
|---|---|---|
| Public entry point | TCP/443 | Only your Nginx `stream`, routed by SNI |
| Telemt / MTProxy | `127.0.0.1:8445` | Only Nginx and the local system |
| Panel | `127.0.0.1:8787` (HTTP) | Locally; published through a TLS vhost on `127.0.0.1:8443` |
| NaiveProxy (Caddy) | `127.0.0.1:4443` | Only Nginx |
| Telemt API | `mtproxy:9091` | Only inside the Compose network, never published |
| Mieru | Your chosen TCP and UDP ports | Public; port 443 is not used |
| Mieru management | `/run/mita/mita.sock` | Local Unix socket only |
| Fleet ingress | TCP/8790 | HTTPS with mTLS only, when the boundary is enabled |

Containers are named `proxy-control-*`. The Compose project name (`mtproxy`) and
existing volumes are preserved, which is what makes upgrading a running
installation safe.

## Before you install

- Ubuntu 24.04 with `systemd`, and `root` or `sudo` access.
- DNS A/AAAA records for every name point **directly** at the server. For
  MTProto, CDN proxying must be off — DNS-only mode.
- TCP/80 free: this is how Let's Encrypt validates your domains.
- A working Nginx with `stream` owning public 443, and **exactly one**
  understandable `$ssl_preread_server_name` map in the route file.
- The local ports from the table above, free.
- Your own separate backup of Nginx, services, routes, and Docker state.

The installer stops and touches nothing when it sees: DNS that does not match
the server, NAT, a CDN in front of raw MTProto, an ambiguous Nginx map, a busy
port, an owner of 443 that is not Nginx, or a failing `nginx -t`. That is not a
reason to "continue anyway" — it is a reason to fix the cause first.

If your profile includes **Mieru**, stage two packages in
`/var/lib/proxy-control/` in advance. The installer deliberately downloads
nothing for you:

- `mita_3.36.0_<arch>.deb` — the server;
- `mieru_3.36.0_<arch>.deb` — the official client the installer uses to prove
  traffic actually flows.

Both URLs and checksums are in
[`release/external-artifacts.json`](release/external-artifacts.json). The
installer verifies them and refuses to continue on a mismatch.

## Domains and certificates

This is where installation stops most often, so here it is in detail.

### How many domains you need

It depends on the profile. Not every protocol needs one:

| Domain | When it is needed | Certificate required |
|---|---|---|
| `panel` — the panel | Always | Yes |
| `mtproxy` — MTProxy | Always | Yes |
| `naive` — NaiveProxy | Profiles with Naive | Yes |
| `mieru` — Mieru | Profiles with Mieru | **No** |
| `three_xui.panel_domain` | When installing 3x-ui from scratch | Yes |
| `three_xui.hysteria_domain` | When installing 3x-ui from scratch | Yes |
| `three_xui.vless_tcp_domain` | When installing 3x-ui from scratch | **No** |
| `three_xui.vless_xhttp_domain` | When installing 3x-ui from scratch | **No** |

Mieru and VLESS Reality need no Let's Encrypt certificate: Mieru speaks its own
protocol, and Reality borrows the certificate of the site it imitates. They
still need a domain — it goes into the client configuration.

### What the installer checks before issuing

For every name that needs a certificate, the installer resolves DNS itself and
requires four things:

1. **An A record exists** and at least one of its addresses is an address of
   this server. A domain pointing somewhere else is a hard stop.
2. **Either there is no AAAA record, or all of its addresses belong to this
   server too.** A forgotten AAAA pointing at an old host is the most common
   reason a certificate is issued and the protocol still does not work.
3. **CAA does not forbid Let's Encrypt.** The domain and its parents are both
   checked.
4. **If a certificate already exists**, it must cover this name. The installer
   never touches a certificate that is not its own.

CDN proxying (the orange cloud) must be off for the MTProxy domain: it needs
DNS-only mode. Otherwise the A record points at the CDN rather than the server,
and the check stops the installation — correctly.

### How certificates are issued

The installer groups domains by service, and each group gets its own lineage
(`--cert-name`):

| Lineage | Names it covers |
|---|---|
| `proxy-control` | The panel domain and the MTProxy domain — **one certificate for both** |
| `naive` | The NaiveProxy domain |
| `three-xui-panel` | The 3x-ui panel domain |
| `three-xui-hysteria` | The Hysteria2 domain |

Issuance runs through `certbot certonly --webroot`: each name uses its own
`/var/www/<domain>` directory, where Let's Encrypt drops the validation file
over TCP/80. No DNS-01 and no registrar API is involved — which is exactly why
port 80 must be free.

Immediately after issuance the installer runs `certbot renew --dry-run` for that
lineage. The point is simple: renewal is proven **at install time**, not three
months later when the certificate quietly expires.

### Check your domains in advance

You do not have to wait for the installation: the plan checks all of this and
changes nothing. Run it from the unpacked release — it does not work from a Git
clone, which has no `release/release.json`, and the installer refuses to run
without a release identity.

```bash installer-check
python3 -m installer.cli plan --config examples/installer/core.toml --json
```

If the plan succeeds, your domains and DNS are fine. If it stops, the output
names exactly which domain failed which check.

## Installation

### Step 1. Download the release and verify it

Take the archive, `SHA256SUMS`, and `release-manifest.json` from the release
page. Verify provenance **before** anything gains root:

```bash installer-check
gh attestation verify proxy-control-v0.1.0.tar.gz --repo dubr1k/proxy-control
sha256sum --check --ignore-missing SHA256SUMS
./install-bootstrap --archive proxy-control-v0.1.0.tar.gz --checksum SHA256SUMS --manifest release-manifest.json
```

The order matters. `install-bootstrap` refuses to run as root, and before its
single `exec sudo` it checks that every file belongs to you and is not writable
by anyone else, that the archive matches the published checksum, that the
manifest names the same archive, that the version is not a prerelease, and that
no member inside the archive escapes it.

This project deliberately never offers "download and run in one command".

### Step 2. Answer the wizard

There is no separate command to run: once the archive checks out,
`install-bootstrap` hands over to the installer, which with no arguments opens a
bilingual wizard. It asks about the profile, domains, certificate email, and
3x-ui mode, and writes a configuration file — ordinary TOML you can read and
edit by hand.

Profiles:

| Profile | What gets installed |
|---|---|
| `core` | Telemt/MTProxy and the panel |
| `core-naive` | The same plus NaiveProxy |
| `core-mieru` | The same plus Mieru |
| `full` | Everything |

Any profile can additionally deal with 3x-ui through `three_xui.mode`:

- `none` — leave 3x-ui alone entirely;
- `existing` — adopt an installed one: the installer adds routes for its domains
  and changes none of its files;
- `managed-new` — install 3x-ui `3.7.0` from scratch and issue its certificates.

Ready-made configuration examples live in
[`examples/installer/`](examples/installer).

### Step 3. Read the plan and approve it

```bash installer-check
python3 -m installer.cli plan --config examples/installer/full-three-xui.toml --json
```

The plan is the complete list of what will happen: which packages get installed,
which files are created, which Nginx routes are added, which certificates are
issued, which services are started. It contains no secrets and cannot.

The plan has a digest, and installation does not start until you approve that
exact digest:

```bash installer-check
sudo python3 -m installer.cli install --config examples/installer/full-three-xui.toml --accept-plan DIGEST
```

This is the guard against "I ran the wrong thing": if the server changed between
the plan and the install, the digest no longer matches and nothing runs.

### Step 4. Wait for acceptance

The installer does not treat "the container started" as success. It proves each
protocol with a real client:

- **MTProxy** — Fake-TLS, Obfuscated2, `req_pq_multi`, and a validated `resPQ`;
- **NaiveProxy** — the cover site answers without credentials, then an
  authenticated `CONNECT`, a known payload, a closed tunnel, and an accounting
  record that appears;
- **Mieru** — the exact `RUNNING` status and the official client actually
  reaching the internet over every transport;
- **the panel** — login, roles, creating and revoking a temporary access;
- **adjacent routes** — every foreign SNI still works.

If any check fails, the installer rolls back and returns the server to its
previous state.

### What the installer owns, and what it does not

It owns: the Ubuntu packages from its list, certificates and their renewal,
Nginx routes and the panel TLS vhost, containers and volumes, the NaiveProxy and
Mieru host services, UFW rules when you allow it, and 3x-ui in the chosen mode.

It does not own: DNS, WARP, Fleet, your own websites, foreign containers, or
foreign Nginx routes. Its journal and ownership records live in
`/var/lib/proxy-control/` — do not delete them by hand.

The complete surface — every command, every configuration field, ownership
boundaries, hard stops, and recovery — is in the
[installer reference](docs/INSTALLER_REFERENCE.en.md).

### Installing without the installer

If you manage certificates, Nginx, and the whole environment yourself, the core
boundary can be brought up directly with Compose:
[DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md). Manual host-service setup is
described in [PANEL.en.md](PANEL.en.md) (NaiveProxy) and
[MIERU.en.md](MIERU.en.md) (Mieru).

## First login

The initial owner password is in
`/opt/mtproxy-shared443/secrets/panel-bootstrap-password` with mode `0600`. Read
it through a secure console, log in at `https://panel.example.com/login`
immediately, and change it.

Never copy that file into `.env`, Git, tickets, logs, or shared backups.

Roles:

- **owner** — administrators, users, credential rotation, the Fleet registry;
- **admin** — protocol users and audit within allowed boundaries;
- **viewer** — read only.

The last active owner cannot be deleted or demoted. Every change requires CSRF
and lands in the audit trail — without passwords, tokens, links, or QR codes.

Naive and Mieru credentials are revealed **once**, with `Cache-Control:
no-store`. User lists contain no secrets. An existing Mieru password cannot be
shown again — there is only **New link + QR**, which rotates the access and
revokes the old one.

## The protocols

### MTProxy / Telemt

A proxy for Telegram. The panel creates users, hands out `tg://` links and QR
codes, and sets limits and expiry.

After the first start the `telemt-config` volume becomes the source of truth:
every later change goes through the internal API and survives container
recreation. `secrets/users.conf` is only used for the first import. Deleting the
volume is a destructive reset: the entrypoint imports the original file again.

Quota and the current process counter are different quantities. Resetting a
quota by hand does not zero the process counter, and a crash can lose usage
recorded after the last save. There is no automatic calendar reset.

More: [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md).

### NaiveProxy

From the outside the NaiveProxy domain looks like an ordinary website: a request
without credentials gets a cover page, not "407 Proxy Authentication Required".
The proxy answers only someone who knows the credentials.

The same access works as HTTPS (HTTP/1.1) and as HTTP/2 — the panel issues a URL
of the form `https://<user>:<pass>@<domain>`, and the protocol is chosen during
the TLS handshake. Clients that list "HTTPS" and "HTTP2" as separate options
take the same URL; there is no need to create one access per variant.

HTTP/3 is not published: the Nginx `stream` router routes TCP by SNI and does
not parse QUIC, and no public UDP port is allocated to the project. Caddy's
private listener keeps HTTP/3 enabled, but nothing outside can reach it.

Accounting counts payload bytes of completed tunnels, without TLS and IP
overhead. A per-user quota disables the access once the observed limit is
reached, but it is not a byte-exact hard cap: an active tunnel can overshoot.

More: [PANEL.en.md](PANEL.en.md).

### Mieru

An obfuscated proxy with its own protocol over TCP and UDP. It does not take
port 443 — you choose the ports explicitly and open them in both the cloud and
the local firewall.

Creating a user produces a one-time `mierus://` link, a QR code, and an import
command. Rotation, disabling, and deletion require a controlled restart so the
access is genuinely revoked.

The quota is an approximate admission check on application bytes, not a billing
counter. There is no safe per-user traffic counter, so the interface may show
`unavailable` — that is an honest answer, not a failure.

If a mobile path loses large segments on the return flow, there is an optional
`deploy/mieru-mss-clamp.service`: it pins the measured TCP MSS for the Mieru
listener only and touches no unrelated firewall rules. Install it only after you
have seen the characteristic `Send-Q`/retransmission/RTO signature.

When restoring, always bring back `journal.json` together with its original
`journal.key`. Never delete or regenerate the key to "fix" the journal.

More: [MIERU.en.md](MIERU.en.md) and
[credential sharing](docs/MIERU_SHARING.en.md).

### 3x-ui

VLESS Reality (TCP and XHTTP) and Hysteria2 come from here. The installer either
installs 3x-ui `3.7.0` from scratch (`managed-new`) or adopts an existing one
(`existing`) — in the second case it only adds routes for its domains, while
3x-ui's own files, database and unit stay byte for byte identical, which the lab
verifies by hashing them before and after the run.

Upgrading an already installed 3x-ui is prepared in the adapter as its own
transaction, but no command exposes it yet — upgrade it with 3x-ui's own
tooling.

3x-ui stays a separate panel with its own interface — Proxy Control does not
duplicate its management, it makes sure you can both live on one 443 without
conflict.

### Fleet mTLS

An optional boundary: inventory and limited management of remote nodes over
outbound connections. The installer does **not** deploy it.

Creating a node record in the panel with status `unenrolled` is not enrollment.
Enrollment needs a local key and CSR on the node, an offline CA signature, a
certificate bound centrally, mTLS authorization, and a successful inventory
command.

Fleet v1 works with Telemt only: inventory refresh, enable, disable, limit
changes, and quota reset are allowed. Mieru operations, remote
create/delete/rotate/reveal, and secret-bearing configuration apply are refused.

Full procedure: [FLEET.en.md](FLEET.en.md).

## Egress: WARP as one SOCKS5 endpoint

WARP is one loopback **SOCKS5** endpoint at `127.0.0.1:45000`. This project
never provisions WARP itself: you run your own client, bind it there, and the
installer wires the protocols to it when `warp = true`.

The three protocols do **not** treat that endpoint the same way, and the
difference is deliberate:

| Protocol | What goes through WARP |
|---|---|
| **Xray / 3x-ui** | **Only the selected traffic.** Routing rules are keyed to `warp_domains`; everything else leaves directly, and the mandatory final rule keeps unmatched traffic direct. Available in `managed-new` mode only: an adopted instance (`existing`) is not managed by the installer, which never touches its routing. |
| **NaiveProxy** | **All tunnelled traffic.** The `forward_proxy` block carries one `upstream socks5://127.0.0.1:45000`, which has no per-domain form. |
| **Mieru** | **All traffic**, as a single egress rule covering every domain and every IP. |

So a Naive or Mieru user's whole session leaves through WARP, while an Xray
user's session leaves through WARP only for the domains you listed. With
`warp = false` no WARP outbound, upstream, or rule is emitted anywhere, and the
Mieru egress rule stays `DIRECT`.

## Day-to-day operation

### Health checks

```bash
cd /opt/mtproxy-shared443
docker compose ps
curl -fsS -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
systemctl is-active nginx docker
systemctl is-active caddy-naive mita
```

The `Host` header is required: the panel accepts only its own public name and
rejects a request with `Host: 127.0.0.1`. Expect `{"status":"ok"}`.

Before showing this output to anyone, strip passwords, full access URLs, QR
payloads, tokens, cookies, certificates, and private keys.

### What to back up

| Boundary | Complete generation |
|---|---|
| Panel | SQLite through an online backup, or the database with `-wal`/`-shm` while the writer is stopped |
| Telemt | The `telemt-config` volume, `secrets/users.conf`, the API token, and the exact image version |
| Naive | The whole data directory, the Caddyfile, `users.json`, paired backups, `transaction.json`, the accounting database with WAL/SHM, the binary, the unit, and log permissions |
| Mieru | The state directory, `journal.json` together with its original `journal.key`, backups, the token, the binary, the unit, and the `mita` configuration |
| Fleet | The panel database and the ingress configuration; the offline CA key is stored separately |
| Nginx | stream/http configuration, certificates, owners, modes, and the ownership manifest |
| Deployment | The Git revision, the complete `COMPOSE_FILE`, image digests, binary versions, and unit files |

A safe online backup of the panel database:

```bash
docker exec -i proxy-control-panel python - <<'PY'
import sqlite3
src = sqlite3.connect('/data/panel.sqlite3')
dst = sqlite3.connect('/data/panel.backup.sqlite3')
with dst:
    src.backup(dst)
print(dst.execute('PRAGMA integrity_check').fetchone()[0])
dst.close(); src.close()
PY
```

It must print exactly `ok`. Never copy the single SQLite file while a WAL writer
is running.

More: [backup and restore](docs/BACKUP_RESTORE.en.md).

### Upgrading versions from the panel

The panel can safely upgrade three boundaries — **Telemt**, **NaiveProxy/Caddy**
and **Mieru/mita** — through a separate root-owned `version-agent`. The panel
itself never gets a Docker socket, never downloads binaries, and never accepts a
URL from the browser.

Only versions from a root-owned catalogue that you populate can be installed.
The agent verifies the SHA-256, replaces the binary atomically, restarts only
the service concerned, and restores the previous version on failure. The
operation is available to the `owner` role only and requires naming the current
version.

Full protocol and rollback: [docs/UPGRADING.md](docs/UPGRADING.md).

### If an installation was interrupted

```bash installer-check
sudo python3 -m installer.cli status --json
sudo python3 -m installer.cli resume --json
sudo python3 -m installer.cli repair --json
```

`resume` continues an interrupted installation from its recorded phase. `repair`
checks that everything the installer owns is present and unmodified by foreign
hands, and restarts only its own services.

Never delete `journal.json`, `journal.key`, `transaction.json`, WAL/SHM files,
or backups to "fix" a start-up. When in doubt, restore the complete previous
generation rather than one file.

### Uninstalling

```bash installer-check
sudo python3 -m installer.cli uninstall --json
```

Uninstall stops Compose and removes only installer-owned routes, files, and
packages, while secrets, certificates, and cover roots are preserved until a
separate ownership review. Afterwards check `nginx -t`, the public listeners,
and adjacent SNI routes.

If SSH ended with code `255`, that proves only that the transport dropped. Check
`status`, the phase, the services, and Nginx first; do not blindly re-run the
installation.

## When something does not work

- **The panel does not open.** Check `127.0.0.1:8787`, `PANEL_ALLOWED_HOSTS`,
  `PANEL_COOKIE_SECURE`, the TLS vhost on `8443`, the SQLite database, and the
  volume owner.
- **MTProxy is healthy but clients cannot connect.** Check A/AAAA, the absence
  of a CDN in front of raw TCP, the SNI map, the Fake-TLS name, every secret,
  and a real `resPQ`. A healthy container and an open port prove nothing by
  themselves.
- **The Naive manager is unhealthy.** Check the token, the Unix socket, the
  pinned Caddy build, `caddy adapt --validate`, `transaction.json`, and the
  identities `10002:101` and `10003:10004`.
- **Naive accounting does not grow.** A record appears only after a
  successfully **closed** `CONNECT`; an active or aborted tunnel yields nothing.
- **The Mieru manager is unhealthy.** Check the exact `mita` digest and version,
  `/run/mita/mita.sock`, the socket GID, and the token and state metadata. Do
  not apply a recursive `chown` blindly.
- **No QR for an existing Mieru user.** That is by design: the reveal is
  one-time. Use **New link + QR**, understanding that the old configuration is
  revoked.
- **Orphan containers appeared.** Restore the complete saved `COMPOSE_FILE`; do
  not confirm orphan removal with an incomplete model.
- **Fleet stays `unenrolled`.** A registry record is not enrollment. Repeat the
  CSR, the offline signature, the certificate binding, the node installation,
  mTLS authorization, and the inventory result.

More cases: [troubleshooting](docs/TROUBLESHOOTING.en.md) and the
[operations runbook](docs/OPERATIONS.en.md).

## What is inside

### Host packages

The `packages` adapter installs exactly these and nothing else:
`ca-certificates`, `certbot`, `curl`, `docker-compose-v2`, `docker.io`,
`nginx-full`, `openssl`, `python3`.

### Pinned external artifacts

These are published by other projects under their own licenses. The installer
never downloads them for you: you stage the package, and the installer refuses
to continue unless its digest matches the pin.

| Artifact | Version | License | Purpose |
|---|---|---|---|
| `mita` (`enfein/mieru`) | 3.36.0 | GPL-3.0-or-later | The Mieru server. Only the executable and a license notice are installed; the package itself never is. |
| `mieru` (`enfein/mieru`) | 3.36.0 | GPL-3.0-or-later | The official Mieru client, used to build the acceptance harness that proves each transport carries traffic. |
| `three_xui` (`MHSanaei/3x-ui`) | 3.7.0 | GPL-3.0-only | The 3x-ui panel and its Xray core for VLESS Reality TCP, VLESS Reality XHTTP, and Hysteria2. |

Caddy `v2.11.4` with the `http.handlers.forward_proxy` module is not downloaded
as a binary; it is built from the pinned recipe in
`docker/Dockerfile.caddy-naive`. Every URL, digest, and SPDX identifier lives in
[`release/external-artifacts.json`](release/external-artifacts.json), which the
release build embeds in the SBOM.

### Container images

| Dockerfile | Image | Base |
|---|---|---|
| `panel/Dockerfile` | The panel API and UI | `python:3.13.5-slim` |
| `naive_manager/Dockerfile` | The NaiveProxy credential and accounting manager | `python:3.13.5-slim` |
| `mieru_manager/Dockerfile` | The Mieru credential and quota manager | `python:3.13.5-slim` |
| `deploy/Dockerfile.agent` | The Fleet node agent | `python:3.13.5-slim` |
| `deploy/Dockerfile.ingress` | The Fleet mTLS ingress | `python:3.13.5-slim` |
| `deploy/mieru-client/Dockerfile` | The official Mieru client used by the acceptance | `python:3.13.5-slim` |
| `probe/Dockerfile` | The MTProto acceptance probe on TDLib | `node` |
| `docker/Dockerfile.caddy-naive` | The Caddy build carrying `forward_proxy` | `caddy:2.11.4-builder` → `scratch` |
| `scripts/lab/Dockerfile.acceptance` | The disposable systemd container the lab installs into | `ubuntu` |

Every base image is pinned by digest.

### Python dependencies

Runtime (`panel/requirements.txt`): `fastapi`, `starlette`, `pydantic`,
`pydantic_core`, `annotated-types`, `typing-inspection`, `typing_extensions`,
`httpx`, `httpcore`, `h11`, `certifi`, `idna`, `anyio`, `Jinja2`, `MarkupSafe`,
`argon2-cffi`, `argon2-cffi-bindings`, `cffi`, `pycparser`, `uvicorn`, `click`,
`qrcode`.

Development only (`panel/requirements-dev.txt`): `pytest`, `pytest-anyio`,
`iniconfig`, `packaging`, `pluggy`, `Pygments`, `ruff`.

Every version is pinned exactly. The installer itself and both managers use only
the Python standard library.

## Security

- Never publish `.env`, `secrets/`, access URLs, QR codes, tokens, databases,
  logs, or PKI keys.
- Never publish the Telemt API, the management Unix sockets, or the Caddy Admin
  API.
- Never give project services a Docker socket.
- Never change the pinned Telemt, Caddy, or `mita` without checking provenance,
  digest, and a rollback plan.
- A hidden button in the interface is not a substitute for a server-side role
  check.
- Read [SECURITY.md](SECURITY.md) and the
  [compatibility policy](docs/COMPATIBILITY.md) before a production deployment.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r panel/requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
python3 scripts/check-doc-links.py
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
git diff --check
```

Contribution rules are in [CONTRIBUTING.md](CONTRIBUTING.md). The mandatory
operating protocol for AI agents is in [AGENTS.md](AGENTS.md).

Detailed boundary guides: [documentation map](docs/README.md),
[installation](INSTALL.en.md), [installer reference](docs/INSTALLER_REFERENCE.en.md),
[complete installer/auditor](INSTALLER_AUDITOR.md), [panel](PANEL.en.md),
[MTProto behind Nginx](DOCKER_DEPLOYMENT.md), [Mieru](MIERU.en.md),
[Mieru sharing](docs/MIERU_SHARING.en.md), [Fleet](FLEET.en.md),
[operations](docs/OPERATIONS.en.md), [backup and restore](docs/BACKUP_RESTORE.en.md),
[upgrades](docs/UPGRADING.md), [troubleshooting](docs/TROUBLESHOOTING.en.md),
[accounting](docs/ACCOUNTING.md), and [validation](docs/VALIDATION.md).

## Status and license

Python tests, quality checks, Compose rendering, image builds, the
MTProxy/NaiveProxy/Mieru panel integrations, and the responsive interface are
validated.

The complete release lifecycle — install, a repeated install, `repair`, reboot
recovery, an interrupted phase, reporting, uninstall, and shared-443
coexistence — runs against a real release archive in two labs: a disposable
systemd container and a disposable bare-metal host. Each protocol is accepted
with a real client.

Production Fleet enrollment and billing-grade traffic accounting are still not
claimed as completed release gates.

Repository code is released under the [MIT License](LICENSE). Telemt,
Caddy/forwardproxy, Mieru/`mita`, 3x-ui, third-party images, and Python packages
retain their own licenses. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
