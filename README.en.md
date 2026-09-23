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

> [!WARNING]
> **The current release is [v0.13.0-beta.1](https://github.com/dubr1k/proxy-control/releases/tag/v0.13.0-beta.1)** (mobile client and node cards use pictograms instead of square initial tiles; routing quick settings occupy separate rows; [release note](docs/releases/v0.13.0-beta.1.md)). The previous [v0.12.0-beta.1](docs/releases/v0.12.0-beta.1.md) added addressable sections, MTProxy links and automatic node confirmation; v0.11.0-beta.1 added upstream component updates with rollback, the MCP server and version-agent ([note](docs/releases/v0.11.0-beta.1.md)). It also ships v0.10.0-beta.1 — a client on several nodes through a node × protocol matrix, the subscription at once and again ([CHANGELOG](CHANGELOG.md#0100-beta1---2026-09-21)); before them: [v0.9.0-beta.1](https://github.com/dubr1k/proxy-control/releases/tag/v0.9.0-beta.1) — the panel says what the node already does; API refusals in the screen's words ([note](docs/releases/v0.9.0-beta.1.md)); [v0.8.0-beta.1](https://github.com/dubr1k/proxy-control/releases/tag/v0.8.0-beta.1) — custom VPN/proxy exits, a rule table with quick settings, refreshable geodata, auto-import of node users ([note](docs/releases/v0.8.0-beta.1.md)); [v0.7.0-beta.1](https://github.com/dubr1k/proxy-control/releases/tag/v0.7.0-beta.1) — chains and lanes ([note](docs/releases/v0.7.0-beta.1.md)); [v0.6.0-beta.1](https://github.com/dubr1k/proxy-control/releases/tag/v0.6.0-beta.1) — the verification of everything promised in v0.2–v0.5 (the matrix, the `ui` and `managed-xui` tiers); v0.5 — the Xray-router ([note](docs/releases/v0.5.0-beta.1.md); never published on its own, shipped inside v0.6); [v0.4.0-beta.1](https://github.com/dubr1k/proxy-control/releases/tag/v0.4.0-beta.1) — routing (egress policies with a preview); [v0.3.0-beta.1](https://github.com/dubr1k/proxy-control/releases/tag/v0.3.0-beta.1) — linked panels; [v0.2.0-beta.1](https://github.com/dubr1k/proxy-control/releases/tag/v0.2.0-beta.1) — clients, encrypted credentials and subscriptions; [v0.1.0 Beta](https://github.com/dubr1k/proxy-control/releases/tag/v0.1.0) — the transactional installer and the only release without a pre-release suffix, which is what `install-bootstrap` accepts. All of them are betas: use them on new or isolated servers, or only after backing up the configuration and the panel's master key. What changed — [CHANGELOG.md](CHANGELOG.md); the upgrade order — [docs/UPGRADING.md](docs/UPGRADING.md).

> [!IMPORTANT]
> This project is for people who know what DNS, TLS, Nginx, and Docker are. The
> installer takes care of the routine and refuses to take a dangerous step
> silently, but it does not replace understanding your own server.

## What this is

Proxy Control is a standalone companion panel for 3x-ui that manages **other**
protocols and credentials. It is not a fork of 3x-ui and does not attempt to
replace its interface.

The central idea: **you do not have to choose between Proxy Control and 3x-ui**.
Both run on one server, behind one shared port 443, without fighting each other.

What you get:

| Boundary | What it is for |
|---|---|
| **MTProxy / Telemt** | A proxy for Telegram. The panel hands out `tg://` links and QR codes, sets limits and expiry, and reports service state. |
| **NaiveProxy** | An HTTPS proxy that looks like an ordinary website from the outside. Protocols: HTTPS (HTTP/1.1 CONNECT) and HTTP/2 CONNECT over TLS/TCP, one access for both; TCP only — UDP and HTTP/3 are not proxied. Per-user quota and traffic accounting included. |
| **Mieru** | An obfuscated proxy with its own protocol over TCP. UDP transport does not work for clients on real networks and is not claimed. The panel issues a one-time `mierus://` link and QR. |
| **3x-ui** | VLESS Reality (TCP and XHTTP) and Hysteria2. In `existing` mode the installer adopts an installed 3x-ui, shares port 443 with it, and leaves its files unchanged. In `managed-new` mode on a clean server it installs 3x-ui `3.7.0` and creates those inbounds. |
| **Panel** | Owner, administrator, and viewer roles; API keys scoped `admin \| monitor \| node-sync` (v0.3). Secret-free audit written in the transaction of the change, one-time credential reveal, quota management, versioned database migrations. Since v0.11 — «Проверить обновления»: the panel asks the host agent to poll upstream and updates the Xray-router, Mieru, Telemt and NaiveProxy (by rebuilding Caddy) with rollback. |
| **Clients and subscriptions** | Since v0.2 the panel owns the accounts of all three protocols: import of existing ones, "adopt access", new accesses issued by one journaled operation with an honest outcome. Credentials live under a master key (AES-256-GCM). Each client gets one revocable link `https://<subscription domain>/s/<token>` for all of their accesses: `raw`, sing-box/Karing, Clash/mihomo, `manifest`, `html`; no access log anywhere on the path. |
| **Fleet** *(optional)* | Since v0.3 — linked panels: a central panel manages other panels over HTTPS with a `node-sync` API key (issue, rotate and revoke accesses, import users), three actions in the UI. Legacy v1 — Telemt inventory and limits over mTLS, installed by hand. |
| **Routing** | Since v0.4 — an egress policy per node and service: NaiveProxy and Mieru direct or through WARP, block by domain and CIDR, selective rules on Mieru; the preview tells exactly what the node's backend will enforce, and apply is transactional with a rollback — locally and on linked panels ([docs/ROUTING.en.md](docs/ROUTING.en.md)). Since v0.5 — an optional **Xray-router** on the node: a service attached to it gets geosite, geoip, ports and blocks beside WARP through a dedicated, pinned Xray with an authenticated ingress ([docs/XRAY_ROUTER.en.md](docs/XRAY_ROUTER.en.md)). |
| **MCP** *(optional, central)* | Since v0.11 — the `proxy-control-mcp` container on the central panel: the panel's API as Model Context Protocol tools for Claude Code and Claude Desktop over `https://<mcp domain>/mcp` with a bearer token; irreversible actions require `confirm`, every call goes through the `mcp` API key and shows in the audit log ([docs/MCP.en.md](docs/MCP.en.md)). Skills for the operator's routine tasks live in [`skills/`](skills/). |

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
| Mieru | Your chosen TCP ports (the server listens on UDP there too, but it is not claimed) | Public; port 443 is not used |
| Mieru management | `/run/mita/mita.sock` | Local Unix socket only |
| Fleet ingress | TCP/8790 | HTTPS with mTLS only, when the boundary is enabled |

Containers are named `proxy-control-*`. The Compose project name (`mtproxy`) and
existing volumes are preserved, which is what makes upgrading a running
installation safe.

## Before you install

- An **x86-64** server, which is what the overwhelming majority of VPS hosts
  are. Any other architecture is refused during the audit rather than part-way
  through an installation: the release is built for x86-64 only, and that is
  the only architecture the lab proves.
- Ubuntu 24.04 with `systemd`, and `root` or `sudo` access.
- DNS A/AAAA records for every name point **directly** at the server. For
  MTProto, CDN proxying must be off — DNS-only mode.
- TCP/80 free: this is how Let's Encrypt validates your domains.
- In `coexist` mode, a working Nginx with `stream` owning public 443 and
  **exactly one** understandable `$ssl_preread_server_name` map in the route
  file. In `fresh` mode the installer installs and configures Nginx itself;
  no foreign process may own port 443.
- The local ports from the table above, free.
- Your own separate backup of Nginx, services, routes, and Docker state.

The installer stops and touches nothing when it sees: DNS that does not match
the server, NAT, a CDN in front of raw MTProto, an ambiguous Nginx map, a busy
port, an owner of 443 that is not Nginx, or a failing `nginx -t`. That is not a
reason to "continue anyway" — it is a reason to fix the cause first.

Nothing to stage for the pinned external artifacts: the installer fetches them
from their pinned HTTPS URLs into `/var/lib/proxy-control/` and proves the SHA-256
before anything uses them (a mismatch is a refusal, the file is discarded). An
offline host stages them there in advance — a file staged by hand is used as it
is and never replaced. For a profile with **Mieru** these are two packages:

- `mita_3.36.0_<arch>.deb` — the server;
- `mieru_3.36.0_<arch>.deb` — the official client the installer uses to prove
  traffic actually flows.

With `[egress] router = true` (v0.5) `Xray-linux-64.zip` arrives the same way: the
Xray egress-router is extracted from it. All URLs and checksums are in
[`release/external-artifacts.json`](release/external-artifacts.json). The
installer verifies them and refuses to continue on a mismatch.

## Domains and certificates

This is where installation stops most often, so here it is in detail.

### How many domains you need

**The complete beta package** — the `full` profile, `managed-new` 3x-ui mode, a separate client subscription domain and the MCP server domain — requires **11 distinct domains**: the Proxy Control panel, MTProxy Fake-TLS, NaiveProxy, Mieru, the 3x-ui panel, VLESS Reality TCP, VLESS Reality XHTTP, Hysteria2, the 3x-ui subscription, the Proxy Control client subscription (the tenth) and the MCP server (the eleventh, on the central panel only — nodes do not need it). All must resolve correctly to the VPS; not all require certificates.

It depends on the profile. Not every protocol needs one:

| Domain | When it is needed | Certificate required |
|---|---|---|
| `panel` — the panel | Always | Yes |
| `mtproxy` — MTProxy | Always | Yes |
| `naive` — NaiveProxy | Profiles with Naive | Yes |
| `mieru` — Mieru | Profiles with Mieru | **No** |
| `three_xui.panel_domain` | In a 3x-ui mode | Yes |
| `three_xui.hysteria_domain` | In a 3x-ui mode | Yes |
| `three_xui.vless_tcp_domain` | In a 3x-ui mode | **No** |
| `three_xui.vless_xhttp_domain` | In a 3x-ui mode | **No** |
| `three_xui.subscription_domain` | `managed-new`, when a separate subscription is wanted | Yes |
| `subscription` — client subscriptions | When subscription links `https://<subscription>/s/<token>` are wanted | Yes |
| `mcp` — the MCP server | On the central panel only, when wanted | Yes |

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
| `three-xui-subscription` | The separate 3x-ui subscription domain |

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

## The full guide and the protocol for AI agents

- **[Operator guide v0.6–v0.7 (Russian)](docs/releases/v0.6-operator-guide.ru.md)** — one document for everything:
  the node's final architecture (what runs where, ports, the shared 443), which domains are needed and how
  to spread them over a fleet of several hosts (with fictitious examples), unattended deployment through
  the wizard or a TOML (exactly what every adapter installs, 3x-ui included), linking nodes to the central,
  issuing grants and subscriptions from the central panel onto other panels, egress routing and the
  Xray-router with policy examples, chains and client lanes (§8.8, v0.7), upgrades and backups,
  end-to-end checklists.
- **[AGENTS.md → «Эксплуатационный протокол для ИИ-агентов (v0.6–v0.7)»](AGENTS.md)** — the same operations as
  algorithms for an agent: unattended install (`plan --json` → digest → `install`), preparing and linking a
  node through the API, grants and subscriptions, routing and the Xray-router, upgrade and rollback — each
  with its verification command, a «refusal code → action» table, the production-host prohibitions, the
  «no secret ever in the output» rule and a report template (Russian; the development protocol in the same
  file is bilingual).

## Installation

### Step 1. Download the release and verify it

Download all four files under Assets: the archive, `SHA256SUMS`,
`release-manifest.json`, and `sbom.spdx.json`. v0.1.0 has no published GitHub
attestation; from v0.2.0-beta.1 on, the release workflow publishes a provenance
attestation of the archive in the repository. The command below checks the three payload files named by the
downloaded `SHA256SUMS`; the checksum file itself remains trusted as downloaded
from the release page, with no independent provenance proof. After that check,
extract the bootstrap from the verified archive before allowing any root step:

```bash installer-check
sha256sum --check SHA256SUMS
tar -xOf proxy-control-v0.1.0.tar.gz proxy-control/install-bootstrap > install-bootstrap
chmod 700 install-bootstrap
./install-bootstrap --archive proxy-control-v0.1.0.tar.gz --checksum SHA256SUMS --manifest release-manifest.json
```

The order matters. `install-bootstrap` refuses to run as root, and before its
single `exec sudo` it checks that every file belongs to you and is not writable
by anyone else, that the archive matches the published checksum, that the
manifest names the same archive, that the manifest version has no prerelease
suffix, and that no member inside the archive escapes it.

This project deliberately never offers "download and run in one command".

**Beta releases (v0.2.0-beta.1 … v0.11.0-beta.1).** `install-bootstrap` refuses a
version with a pre-release suffix, so a beta is installed without it: the same
four files from the release page, the same `SHA256SUMS` check, then extract the
archive and run the wizard from the extracted directory — it writes the
configuration, shows the plan and applies nothing until you confirm the plan
digest. This is the path the release gate takes on the lab host
(`scripts/lab/guest-runner.sh host` installs the beta from the extracted
archive), and it is how every beta from v0.2 to v0.11 was installed:

```bash installer-check
sha256sum --check SHA256SUMS
tar -xzf proxy-control-v0.11.0-beta.1.tar.gz
cd proxy-control
sudo python3 -m installer.cli wizard
```

The same four steps are what [`scripts/install-release.sh`](scripts/install-release.sh)
does (from a clone of the repository, or downloaded on its own and read before it runs): it
fetches the four release files to disk, checks `SHA256SUMS` and the manifest, with `--sha256`
also the pinned archive digest (the `lab-sha256` of the tag annotation), with `gh` present the
attestation, extracts and hands over to the wizard through one `sudo`. Like
`install-bootstrap` it refuses to run as root; `--requirements` prints what the host needs and
what gets installed, `--check-only` downloads and verifies only:

```bash
scripts/install-release.sh --requirements
scripts/install-release.sh --version 0.11.0-beta.1 --sha256 <lab-sha256 from the release note>
```

The installer does not run from a Git clone: there is no `release/release.json`.

### Step 2. Answer the wizard

There is no separate command to run: once the archive checks out,
`install-bootstrap` hands over to the installer, which opens a bilingual wizard
when given no arguments. It writes a configuration file — ordinary TOML you can
read and edit by hand.

Here is everything it asks, in order.

**Language.** English or Russian.

**Host mode.** `fresh` — the server is yours entirely and the installer sets up
Nginx itself. `coexist` — the server already runs an Nginx that owns port 443,
and the installer only adds its own routes to it.

**Profile.**

| Profile | What gets installed |
|---|---|
| `core` | Telemt/MTProxy and the panel |
| `core-naive` | The same plus NaiveProxy |
| `core-mieru` | The same plus Mieru |
| `full` | Everything |

**3x-ui mode.**

- `none` — leave 3x-ui alone entirely;
- `existing` — adopt an installed one: the installer adds routes for its domains
  and changes none of its files. You create its inbounds yourself;
- `managed-new` — install 3x-ui `3.7.0` itself. The installer issues its
  certificates, moves the panel off its public ports onto `127.0.0.1` under a
  private path, replaces the factory `admin/admin` with your own, and **creates
  the inbounds for you** — VLESS Reality TCP, VLESS Reality XHTTP, and
  Hysteria2. It requires `fresh` mode: installing 3x-ui means owning Nginx and
  the certificates too, and on a host that already runs Nginx those have an
  owner already.

**Domains.** Only the ones the chosen profile actually needs:

| Question | When it is asked | What it is for |
|---|---|---|
| Panel domain | always | the Proxy Control panel |
| MTProxy Fake-TLS domain | always | MTProxy |
| NaiveProxy domain | profiles with Naive | NaiveProxy |
| Mieru hostname | profiles with Mieru | Mieru (needs no certificate) |
| Mieru TCP and UDP ports | profiles with Mieru | the Mieru listeners |
| 3x-ui panel domain | `existing` and `managed-new` | the 3x-ui panel |
| VLESS Reality TCP domain | the same | the VLESS Reality TCP inbound |
| VLESS Reality XHTTP domain | the same | the VLESS Reality XHTTP inbound |
| Hysteria2 domain | the same | the Hysteria2 inbound |
| 3x-ui subscription domain | Not asked by the wizard; add `subscription_domain` to the `managed-new` TOML | serving the 3x-ui subscription over HTTPS |
| Client subscription domain | always; blank keeps subscriptions off | the panel's client links `https://<domain>/s/<token>` |
| MCP server domain | always; blank keeps MCP off. **Central panel only** — nodes leave it blank | MCP for Claude Code and Claude Desktop (v0.11) |

**WARP.** In `managed-new` mode the wizard asks whether to enable WARP for Xray
and, on yes, requires a non-empty list of domain selectors; NaiveProxy and Mieru
keep direct egress in that case. In 3x-ui modes `none` and `existing`, the wizard
asks when the profile includes NaiveProxy or Mieru: yes routes all of their
traffic through WARP and does not change an existing 3x-ui. The installer deploys
the pinned official Cloudflare client itself and creates a Proxy Control-owned
SOCKS5 endpoint at `127.0.0.1:40000`; no pre-existing WARP client is needed, and
foreign WARP state is instead a hard stop. Inspect the resulting plan first.

**ACME email.** The address Let's Encrypt will use.

**Panel credentials.**

- the first Proxy Control panel owner and their password;
- the 3x-ui panel username and password — in `managed-new` mode only.

A password is typed twice and never echoed. **A blank answer means "generate
one"** — the installer then creates a random password and you read it after the
installation. The only requirement is at least 12 characters.

> [!IMPORTANT]
> Passwords never enter the configuration file: it is read to build the plan,
> the plan is printed on screen, and reports are derived from the same values.
> The wizard writes them beside it instead, to `<configuration-name>.credentials`
> with mode `0600`. **Delete that file once the installation has finished.** The
> installer erases its own working copy as soon as the installation ends,
> successfully or not.

**Manage UFW.** On a fresh host only: whether the installer may open the ports
it needs in the firewall itself.

At the end the wizard shows everything you answered and offers to correct any
field, save the configuration, or go ahead with the installation.

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
Nginx and the panel's TLS vhost, containers and volumes, NaiveProxy and Mieru
host services, UFW rules if you allow them, 3x-ui in its selected mode, its
own pinned WARP boundary when `warp = true` and, since v0.11, the version-agent
(code, unit, env for the profile, catalog and a state recording the installed versions) and
the MCP server when `domains.mcp` is set (the `proxy-control-mcp` container, the panel API key
it uses, the clients' bearer token, the vhost and SNI route, the certificate on the panel's lineage).

It does not own: DNS, Fleet, your own websites, foreign containers, foreign
WARP, or foreign Nginx routes. The journal and ownership files live under
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

## First sign-in to the panels

**The Proxy Control panel.** If you chose a password in the wizard, sign in with
it at `https://panel.example.com/login`. If you left the field blank, the
installer generated one and put it in
`/opt/mtproxy-shared443/secrets/panel-bootstrap-password` with mode `0600`: read
it through a secure console, sign in, and change it immediately.

**The MCP server (v0.11, when `domains.mcp` is set).** The address `https://<mcp domain>/mcp`
and the bearer token are in the root-only `credentials/handoff.json` (mode `0600`) next to the
`report` output; the token also lives in `/opt/mtproxy-shared443/secrets/mcp-token`. Connecting
from Claude Code in one command and the tool list: [docs/MCP.en.md](docs/MCP.en.md).

Never copy that file into `.env`, Git, tickets, logs, or shared backups.

**The 3x-ui panel** (`managed-new` mode only). It does not listen on a public
port: it answers on `127.0.0.1:8451` under a private path of the form
`/<random-characters>/`, and the factory `admin/admin` no longer works. From
outside it is reachable through its own domain over the shared 443, and its path
and credentials are the ones you gave the wizard. If you did not give any, the
installer generated them and the report shows where to look:

```bash
sudo python3 -m installer.cli status --json
```

Remember to delete the `<configuration-name>.credentials` file the wizard wrote:
it is no longer needed.

Roles:

- **owner** — administrators, API keys, clients and accesses, rotation, linked
  panels and the Fleet registry;
- **admin** — protocol users and audit within allowed boundaries;
- **viewer** — read only.

The last active owner cannot be deleted or demoted. Every change requires CSRF
and lands in the audit trail — without passwords, tokens, links, or QR codes.

Naive and Mieru credentials are revealed **once**, with `Cache-Control:
no-store`. User lists contain no secrets. An existing Mieru password cannot be
shown again — there is only **New link + QR**, which rotates the access and
revokes the old one.

## Clients, accesses and subscriptions

Since v0.2 the panel is not just a window onto three managers — it owns the
accounts. The "Clients" screen keeps a person and their accesses to MTProxy,
NaiveProxy and Mieru together, while the protocol screens keep working as
before.

- **Import and adoption.** Existing manager users are imported read-only —
  nothing changes on the server. "Adopt access" takes the credentials into the
  panel: MTProxy and NaiveProxy by reading them, Mieru only through an explicit
  rotation, because `mita` never hands a password back.
- **Issuing.** A new access is one journaled operation that ends in exactly one
  of `succeeded`, `compensated` (everything done so far rolled back) or
  `manual_intervention_required` (the panel says plainly that it could neither
  finish nor undo; `operations-resume` in the CLI continues after a lost
  manager reply).
- **Encrypted store.** Credentials live in the database under a master key
  (AES-256-GCM, a separate AAD per row). The installer creates and preserves
  the key (`secrets/panel-master-key`); without it, while secrets exist, the
  panel refuses to start — protection, not a bug. `master-key-init | rotate |
  verify` in the CLI; **the key's backup lives apart from the database** —
  [BACKUP_RESTORE.en.md](docs/BACKUP_RESTORE.en.md).
- **Subscription.** Each client gets one link
  `https://<subscription domain>/s/<token>` for all of their accesses: `raw`
  (plain text, no base64), `singbox` (Karing; `&client=singbox` for the
  official sing-box), `clash` (mihomo, Mieru over TCP only), `manifest`, `html`. The
  token is stored as a hash and shown once; the `ETag` changes with the set of
  accesses, `304` on `If-None-Match`, `Profile-Update-Interval`, a per-address
  rate limit; no access log anywhere on the path — uvicorn or Nginx. The
  compatibility matrix names what a client cannot consume instead of shipping
  a link it cannot parse. Revocation is immediate; the old link stops
  answering.
- **Subscription domain.** A separate name (`domains.subscription` in
  `install.toml`; the wizard asks for it): a SAN on the certificate, its own
  SNI route and its own Nginx `server` with `access_log off`; on the panel's
  own domain the path `/s/` does not exist.
- **Database and audit.** One database boundary, versioned migrations
  (`db-migrate`, `db-status`), a v0.1.0 database upgrades in place; every audit
  row is written in the transaction of the change and carries `X-Request-Id`,
  so a response and its trail match.
- **Writer flag** `PANEL_VNEXT_WRITER=legacy|domain`: the old protocol APIs are
  indistinguishable from the outside in both modes; the switch to `domain` is
  described in [PANEL.en.md](PANEL.en.md).

Details: [PANEL.en.md](PANEL.en.md); the architecture —
[docs/VNEXT_ARCHITECTURE.md](docs/VNEXT_ARCHITECTURE.md); what each client can
consume — [docs/VNEXT_CAPABILITIES.md](docs/VNEXT_CAPABILITIES.md).

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

**Which protocols and clients NaiveProxy works with.** The transport is TLS over
TCP on 443; inside it, HTTP/1.1 CONNECT ("HTTPS") or HTTP/2 CONNECT ("HTTP2").
Only application TCP traffic goes through the proxy; UDP (QUIC, games, VoIP) is
not proxied by NaiveProxy. Clients the project verifies: the official `naive`,
Karing and sing-box (a `naive` outbound from the `singbox` subscription).
mihomo/Clash cannot speak NaiveProxy — the `clash` subscription does not offer
it to them. The NekoBox family, v2rayN, Hiddify and Shadowrocket import a
`naive+https://` link but are unverified against our subscription
([compatibility matrix](docs/VNEXT_ARCHITECTURE.md#subscription-client-compatibility)).

Accounting counts payload bytes of completed tunnels, without TLS and IP
overhead. A per-user quota disables the access once the observed limit is
reached, but it is not a byte-exact hard cap: an active tunnel can overshoot.

More: [PANEL.en.md](PANEL.en.md).

### Mieru

An obfuscated proxy with its own protocol over TCP. It does not take
port 443 — you choose the ports explicitly and open them in both the cloud and
the local firewall.

**UDP is not claimed.** The mita server listens on the chosen port over UDP as
well, but UDP profiles do not work for clients on real networks: mobile carriers
and some Wi-Fi networks drop or throttle non-QUIC UDP, and forked clients expand
one `mierus://` link into two entries and stall on the second. The project
verifies and promises TCP only; if a client shows a TCP and a UDP variant, use
TCP.

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

VLESS Reality (TCP and XHTTP) and Hysteria2 come from here. There are two paths.

**Adopt an installed one** (`existing`). The installer only adds routes for its
domains; 3x-ui's own files, database, and unit stay byte for byte identical,
which the lab verifies by hashing them before and after the run. You create the
inbounds yourself, and they must listen on loopback or there is nothing to share
port 443 with.

**Install it yourself** (`managed-new`). The installer deploys 3x-ui `3.7.0` and
brings it to a working state with no manual step:

1. it moves the panel off the public `*:2053` and `*:2096` onto
   `127.0.0.1:8451` under a private path;
2. it replaces the factory `admin/admin` with your credentials, and does so
   inside an isolated network namespace, so the panel is never reachable from
   outside with a known password;
3. it creates three inbounds: VLESS Reality TCP (`127.0.0.1:8449`), VLESS
   Reality XHTTP (`127.0.0.1:8450`), and Hysteria2 (`0.0.0.0:443/UDP`);
4. it checks the pinned version, the panel's private listener, and a listener for
   each created inbound. This proves that Xray accepted the configuration; it is
   not a full VLESS/Hysteria2 client acceptance.
5. it records how to reach the panel — its URL with the random base path, the
   username and the password (the wizard's or a generated one) — in the root-only
   file `/var/lib/proxy-control/three-xui/panel-access` (0600), beside the
   subscription URL.

The Reality keypair is minted by the very Xray that will serve it, and the cover
site is the panel's own local TLS listener: a foreign site can change its
certificate or disappear, and Reality then fails for every client at once.

> [!NOTE]
> The 3x-ui subscription is published only when the `managed-new` TOML contains
> a separate `subscription_domain`. The installer issues its certificate, routes
> that SNI through shared TCP/443 to the loopback listener on `127.0.0.1:2096`,
> and stores the subscription URL in root-only state. Entries in the subscription
> advertise public protocol names on port `443`, never private backend ports.
> Without `subscription_domain`, the subscription is not published externally.

Upgrading an already installed 3x-ui is prepared in the adapter as its own
transaction, but no command exposes it yet — upgrade it with 3x-ui's own
tooling.

3x-ui stays a separate panel with its own interface — Proxy Control does not
duplicate its management, it makes sure you can both live on one 443 without
conflict.

### Fleet: linked panels and the legacy mTLS transport

Since v0.3 one panel becomes the **central panel** and manages other panels over
their own HTTPS domains. Three actions in the UI: on the node panel the owner
creates an API key scoped `node-sync` («Администраторы → API-ключи»), on the
central «Узлы → + Панель» takes the URL and the key, then "Import" the existing
users. Nothing beyond the panel image appears on a host — no agent, no
certificates, no open ports.

- **Keys.** `admin | monitor | node-sync`, an optional expiry; only the SHA-256
  is stored, the plaintext `pc_<prefix>_<secret>` is shown once; `node-sync`
  opens `/api/fleet/v2/*` only; 120 requests per minute per key; audited as
  `key:<name>`. Disabling or deleting a key takes effect on the next request.
- **Trust.** TLS `verify` (WebPKI) or `pin` — the SHA-256 of the leaf
  certificate («Получить отпечаток»), checked inside the handshake before
  anything is sent; private addresses only behind an explicit checkbox;
  «Проверить» saves nothing. The node's key is stored on the central encrypted
  under the master key.
- **Generations.** The desired state of a node is an immutable, numbered,
  digested document compiled from the accesses. The node refuses a lower
  number, a digest conflict and a foreign central (one master per node),
  applies the document through its own adapters, deletes orphans, never touches
  local users, reports a name collision with a local user as `failed`, and
  answers 409 `managed_by_central` to a local mutation of a central-owned
  resource. A heartbeat every 15 s, `node.up`/`node.down` events, a redelivery
  backoff of 30 s → 10 min.
- **Accesses on the node.** Issue, enable, disable, rotate and delete are
  declarative ("waiting for the node"); a secret the runtime chose itself
  (Telemt's Fake-TLS form) is captured by the central and kept under the same
  version; a confirmed deletion purges the access, and the name can be granted
  again. A client's subscription merges the accesses of every node with each
  node's public hosts.
- **Unlinking.** «Отвязать» on the card «Этот сервер» releases the central's
  ownership; the users on the node stay as they are.
- **Upgrade order** — nodes first, then the central
  ([docs/UPGRADING.md](docs/UPGRADING.md)); the panel-to-panel contract is
  frozen in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md). All of it is
  checked on the lab host by a dedicated `fleet` tier — from the key to the
  unlink, with the real sing-box, mihomo and the `resPQ` probe — and was
  checked live against a production node
  ([release note](docs/releases/v0.3.0-beta.1.md)).

Full description: [FLEET.en.md](FLEET.en.md).

Legacy Fleet v1 is an optional boundary: inventory and limited management of remote
nodes over outbound mTLS connections. The installer does **not** deploy it.

Creating a node record in the panel with status `unenrolled` is not enrollment.
Enrollment needs a local key and CSR on the node, an offline CA signature, a
certificate bound centrally, mTLS authorization, and a successful inventory
command.

Fleet v1 works with Telemt only: inventory refresh, enable, disable, limit
changes, and quota reset are allowed. Mieru operations, remote
create/delete/rotate/reveal, and secret-bearing configuration apply are refused.

Full procedure: [FLEET.en.md](FLEET.en.md).

## Egress: WARP as one SOCKS5 endpoint

WARP is one loopback **SOCKS5** endpoint, defaulting to `127.0.0.1:40000`.
With `warp = true`, the installer downloads the pinned official Cloudflare
client, verifies SHA-256, registers it, enables `warp-svc`, and selects proxy
mode. This is an optional proprietary external dependency: it is not covered
by the project's MIT licence and is not bundled in the release archive.

Since v0.4 the settings live under `[egress]` (`warp`, `warp_port`, and the
initial choice per service — `naive`, `mieru` = `direct | warp | router`; `router = true`
since v0.5 installs the Xray-router from the pinned `Xray-linux-64.zip`, fetched by itself); the old
`[three_xui].warp` / `warp_port` are still read, with one warning. `warp_port`
defaults to `40000` and is passed to every consumer; an explicitly configured
alternative is preserved. An existing foreign WARP installation is never adopted
or reconfigured: it requires a separate, explicit migration.

| Protocol | What goes through WARP |
|---|---|
| **Xray / managed 3x-ui** | Domains in `warp_domains`, with the rule following blocking rules. Adopted (`existing`) routing is not changed. |
| **NaiveProxy** | The installer seeds `[egress].naive` once (`warp` = `upstream socks5://127.0.0.1:40000` for the whole service); from then on the panel's **routing policy** decides — whole service direct or through WARP, plus block rules — [docs/ROUTING.en.md](docs/ROUTING.en.md). |
| **Mieru** | The installer seeds `[egress].mieru` once; from then on the routing policy decides — whole service, block rules, and selective rules by domain and CIDR. |

The managers learn the endpoint through `NAIVE_EGRESS_WARP` / `MIERU_EGRESS_WARP`
in `.env`; the panel never sends an address, only `warp` by name, and the
routing screen previews exactly what each backend will enforce.

With `warp = false`, WARP is not installed. Acceptance requires a fully
configured pinned package, an active and boot-enabled service, a loopback
listener owned by `warp-svc`, and an actual HTTPS request through SOCKS5 showing
`warp=on/plus` and an external IP different from direct egress. An open port
alone is not success. Ownership drift blocks mutations; `resume` handles
interrupted operations and `repair` restores a stopped service.

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
| Panel | SQLite through an online backup, or the database with `-wal`/`-shm` while the writer is stopped; the **master key** `secrets/panel-master-key` apart from the database — without it the encrypted credentials and node keys cannot be restored |
| Telemt | The `telemt-config` volume, `secrets/users.conf`, the API token, and the exact image version |
| Naive | The whole data directory, the Caddyfile, `users.json`, paired backups, `transaction.json`, the accounting database with WAL/SHM, the binary, the unit, and log permissions |
| Mieru | The state directory, `journal.json` together with its original `journal.key`, backups, the token, the binary, the unit, and the `mita` configuration |
| Fleet | v2 — the central's database together with the master key (node keys are encrypted in it); legacy v1 — the ingress configuration, the offline CA key stored separately |
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

The panel can safely upgrade four boundaries — **Telemt**, **NaiveProxy/Caddy**,
**Mieru/mita** and, when installed, **Xray-router/Xray-core** — through a
separate root-owned `version-agent`. The panel itself never gets a Docker
socket, never downloads binaries, and never accepts a URL from the browser.

Since v0.11, «Проверить обновления» on the Versions screen asks the agent to
poll the projects themselves: GitHub Releases for Xray-core, mieru and Caddy,
the image registry for Telemt — over a host list fixed in the agent. Versions
newer than the installed one appear marked "upstream" with the release's digest
(`.dgst`, `.sha256.txt`, the manifest digest); a release without a published
digest is visible but not installable. The digest proves the download is intact
and authored by the project, not that this project verified the version — the
UI says so. The root-owned `versions.json` catalogue stays and wins
("catalog"); the poll is switched off with one variable.

Installing: the agent verifies the digest, replaces files atomically, rewrites
the pins in the Compose environment (the manager's pin for Mieru, the three
files and their digests for the router), restarts only the service concerned
and restores the previous version on failure. NaiveProxy is updated by
rebuilding Caddy with forwardproxy on the host (builder image by digest, up to
15 minutes). The operation is available to the `owner` role only and requires
naming the current version; the installer accepts such an update as its own.

The panel itself updates from the same screen: the «Proxy Control / панель»
card lists the project's releases, the agent copies the release's files,
rebuilds and restarts the panel with a rollback copy of the files, the database
and the image, and the page reloads by itself once the panel answers with the
new version.

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
fetches them from their pinned HTTPS URLs when the file is absent from
`/var/lib/proxy-control/` and refuses to continue unless the digest matches the
pin; a file staged by hand is used as it is.

| Artifact | Version | License | Purpose |
|---|---|---|---|
| `mita` (`enfein/mieru`) | 3.36.0 | GPL-3.0-or-later | The Mieru server. Only the executable and a license notice are installed; the package itself never is. |
| `mieru` (`enfein/mieru`) | 3.36.0 | GPL-3.0-or-later | The official Mieru client, used to build the acceptance harness that proves each transport carries traffic. |
| `three_xui` (`MHSanaei/3x-ui`) | 3.7.0 | GPL-3.0-only | The 3x-ui panel and its Xray core for VLESS Reality TCP, VLESS Reality XHTTP, and Hysteria2. |
| `xray` (`XTLS/Xray-core`) | 26.3.27 | MPL-2.0 | The Xray egress-router (v0.5, `[egress] router = true`): only `xray`, `geoip.dat` and `geosite.dat` are extracted from the pinned `Xray-linux-64.zip`, each against its own digest. |

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
| `xray_router_manager/Dockerfile` | The Xray egress-router and its manager (v0.5) | `python:3.13.5-slim` |
| `mcp_server/Dockerfile` | The MCP server for Claude Code and Claude Desktop (v0.11, central only) | `python:3.13.5-slim` |
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

The MCP server (`mcp_server/requirements.txt`, its own image): `mcp`, `mcp-types`,
`starlette`, `sse-starlette`, `uvicorn`, `httpx`, `httpx2`, `httpcore`, `httpcore2`, `h11`,
`anyio`, `pydantic`, `pydantic_core`, `annotated-types`, `typing-inspection`,
`typing_extensions`, `jsonschema`, `jsonschema-specifications`, `referencing`, `rpds-py`,
`attrs`, `PyJWT`, `cryptography`, `cffi`, `pycparser`, `python-multipart`,
`opentelemetry-api`, `truststore`, `certifi`, `idna`, `click`.

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

The installer is verified against a real release archive in two labs, described
in [tests/lab/README.md](tests/lab/README.md). The mode that installs 3x-ui
itself has its own run, against a real 3x-ui on a disposable server:

```bash
sudo bash scripts/lab/managed-xui-acceptance.sh
```

It refuses to run where a 3x-ui already exists and removes what it created;
`KEEP=1` leaves the staged panel in place for inspection.

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

Also validated: the 3x-ui subscription public contract (public SNI endpoints on
443 only), the live WARP lifecycle with real egress and rollback, and
`managed-new` against real 3x-ui `3.7.0`: the installer creates VLESS Reality
TCP, VLESS Reality XHTTP, and Hysteria2, and issues SSL certificates for the
3x-ui panel, Hysteria2, and the separate subscription.

Since v0.2 the lab host also runs the live subscription acceptance — the
official sing-box carries traffic through NaiveProxy and mihomo through Mieru
over TCP, a canary scan of the logs and of a database dump finds no
token and no password — and a restore drill of the "database + master key"
pair. Since v0.3 — the `fleet` tier: the installed node is linked to a central,
users imported, accesses on all three protocols, disable, rotation, deletion,
convergence after being offline, a node restart mid-apply, key revocation and
unlink; v0.3 was also checked live against a production node.

Routing (v0.4) and the Xray-router (v0.5) are beta, checked on the lab host and live
on a production node to the extent of their release notes. v0.6 verifies everything promised
in v0.2–v0.5: the [function → proof matrix](docs/VERIFICATION_MATRIX.md) under a guard test, a
route audit, every screen in a real browser (`remote-gate.sh ui`), the managed 3x-ui against the
real 3x-ui, a backup/restore drill — and the fixes for what that found (see the release note).
v0.7 — [chains and lanes](docs/releases/v0.7.0-beta.1.md): a policy's exit through the relays of
other nodes of the fleet (a chain of up to three hops), a grant's own lane and policy, the `chains`
tier on the stand and a live «central → exit node» check. v0.8 — custom exits and the rule
table, v0.9 — the seam between screen and backend, v0.10 — a client on several nodes and the
subscription at hand, v0.11 — [updates from upstream](docs/releases/v0.11.0-beta.1.md): release
and registry polling with digests, the Xray-router component, a Caddy rebuild from the panel.
Not claimed as completed: a 3x-ui bridge, canary rollouts of policies, UDP through the router
and through Mieru for clients, metric history and updating a node's own panel from the
central, and billing-grade traffic accounting.

## Acknowledgements

Proxy Control relies on the work of upstream authors and maintainers:

| Component | What we thank it for | Link |
|---|---|---|
| Telemt | Rust MTProto/MTProxy runtime | [telemt/telemt](https://github.com/telemt/telemt) |
| Mieru and mita | TCP/UDP proxy runtime and manager | [enfein/mieru](https://github.com/enfein/mieru) |
| 3x-ui | Xray/3x-ui control plane | [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) |
| Caddy | HTTPS reverse proxy and TLS automation | [caddyserver/caddy](https://github.com/caddyserver/caddy) |
| forwardproxy | Caddy HTTP CONNECT module | [klzgrad/forwardproxy](https://github.com/klzgrad/forwardproxy) |
| Nginx | shared-443 SNI routing | [nginx.org](https://nginx.org/) |
| Certbot and Let's Encrypt | ACME HTTP-01 and certificate issuance/renewal | [Certbot](https://github.com/certbot/certbot) · [Let's Encrypt](https://letsencrypt.org/) |
| Docker and Compose | isolated service execution | [Docker](https://www.docker.com/) · [Compose](https://github.com/docker/compose) |
| Python web stack | FastAPI, Starlette, Pydantic, HTTPX, Uvicorn, Argon2, cryptography, and qrcode | [requirements](panel/requirements.txt) |

Thank you to every developer, maintainer, and contributor to these projects.
Exact versions, licences, provenance, and separate notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
[`release/external-artifacts.json`](release/external-artifacts.json), and
`panel/requirements*.txt`.

Repository code is released under the [MIT License](LICENSE); external
components retain their own licences.
