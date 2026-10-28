# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The history starts with 1.0.0, the first stable release.

## [Unreleased]

### Host installer
- Replace host Python entry points with verified static binaries. Release/bootstrap verification
  uses Bash/awk and rejects unsafe archive members and mismatched executable digests/modes.
- Bootstrap verification rejects missing/trailing JSON commas and repeated manifest closing
  braces before privilege escalation; Compose migration preserves operator-named data volumes.
- The supported 3.3.0 → 4.0 path is `install-release.sh --update`: replace and verify the Rust
  agent's exact release before submitting a panel update; restore code/unit/tmpfiles and journal
  on failure, preserve operator overrides, then reconcile managers, ingress and Compose.
- `update-host` retires the unused Fleet v1 overlays (`compose.agent.yaml`, `compose.fleet-central.yaml`) of a 3.x tree: after proving no Fleet v1 unit, container, volume, Compose reference or `FLEET_*` setting exists, it removes them from the installer journal and moves them to `/var/lib/proxy-control/retired/`. Hosts installed through the installer no longer read the missing files as drift.
- Core repair and apply start the whole installed stack: `compose.yaml`, the overlay of every installed sibling (NaiveProxy, Mieru, Xray-router, AmneziaWG, TrustTunnel, MCP) with its env file, and the version overrides. The panel used to be recreated from `compose.yaml` alone, lost the manager mounts, and NaiveProxy/Mieru grants hung in `pending`.
- Core acceptance takes the MTProxy secret in the form the panel reveals it (the key followed by the hex of the Fake-TLS domain) and hands the resPQ probe the key only; fresh installs and journal updates used to fail with `Core acceptance failed: resPQ`. The grant-less client created for the temporary user is deleted with it.
- Fresh native installations no longer select or own a Python interpreter. Existing package
  journals keep their recorded ownership so repair and uninstall do not remove a pre-existing Python.
- Native host commands decode systemd environment quoting, escapes and line continuations
  without shell expansion. Repair keeps the operator's version catalog and state selections;
  project, socket, GID and enabled-profile fields remain installer-controlled.

### Changed
- The Rust panel routing engine preserves policy preview/apply/rollback, custom exits, per-grant lanes, relays, chains and destination explanations. Escaped protocol-manager errors retain their HTTP status and protocol-specific response; actual runtime crashes remain HTTP 500.
- The Rust panel's Fleet v2 central keeps the existing link/import/generation API, encrypted node-key escrow, heartbeat delivery, routing readback and linked-node metrics. HTTPS uses system CA/hostname verification or a leaf-DER SHA-256 pin checked before sending credentials; every DNS answer is checked in full before connecting, with private networks requiring explicit opt-in.
- The panel container runs the native Rust `panel` executable on Debian, without a Python interpreter. Administrative commands use `panel cli`; secret staging and health checks are subcommands of the same executable. UID 10001, GID 101, socket groups and the read-only runtime contract are unchanged.
- Panel image builds reject an incomplete or stale shared-source generation. `pc_common/RELEASE` must match `VERSION`; the release builder checks the same invariant before assembling an archive.
- The Rust panel implements the existing MTProxy, NaiveProxy, Mieru, AmneziaWG, TrustTunnel, dashboard, host-resource and version APIs, including their validation, secret-free projections, one-time reveals and manager-error responses.
- Fleet, backup and native Ubuntu acceptance invoke the panel and installer binaries.
  The external backup controller copies SQLite online from the inspected data mount
  without requiring Python inside the panel container.
- Share JSON serialization and text/value primitives across Rust components while retaining
  each persisted format's ordering, escaping, spacing and historical number rendering.
- Panel self-updates refuse installed Fleet v1 systemd units, on-disk overlays and legacy Compose containers in either historical project before touching release files or the database. Existing certificates, journals and volumes require an explicit migration to Fleet v2.
- Pin Xray-core to [26.10.21](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21):
  upstream withdrew 26.10.17 for a certificate-trust security update. The installer,
  archive/member checks, prompts and seeded agent state use the same reviewed pin.

### Fixed
- Escape no longer discards the one-time access bundle behind its close confirmation;
  cancelling the confirmation keeps the original secrets available.
- Rotating an MTProxy key on its protocol page replaces the credential kept for client links and subscriptions. Deleting the account also removes its grant and revokes its kept credential, matching the other protocol pages.
- Request JSON deeper than 128 containers is rejected before validation. Previously, a deeply nested login body could exhaust a panel worker's stack and stop the process.
- Core installer lifecycle operations reject forged checkpoint ownership outside the planned
  generation before starting or stopping services or removing files.
- Recognized ingress upgrades update Core/Nginx ownership and the accepted plan together.
  Journal-write or reload failures restore both configurations and the previous journal.
- An explicit host-command `--version` no longer reads a missing source `VERSION` first;
  manager rebuilds refuse an empty running-image identity before changing containers.
- Router reinstall after a failed start verifies preserved private manager state instead
  of trying to initialize it as empty; credentials survive rollback and subsequent repair.
- Lab synchronization compares file contents without restoring workstation timestamps,
  avoiding stale Cargo binaries after cross-host clock skew. Root credentials stay excluded
  while frozen synthetic test fixtures are retained.
- Installing from a development checkout excludes Cargo `target` directories and linked
  build caches from both the deployed generation and its ownership inventory.

### Removed
- Fleet v1 node registration, certificate revocation and raw-command controls, including their OpenAPI operations. The Nodes screen and navigation badge use `/api/nodes` and linked panels.
- Fleet v1 agent and ingress Compose overlays, Dockerfiles, example environments and systemd units are no longer shipped; existing deployments are not automatically removed.
- Remove production Python implementations and their runtime dependencies. Python remains
  only in external release, development and acceptance tools, including the archived-3.3 oracle.

### Installer
- Rust service adapters manage WARP, MCP and the version-agent. The agent installs and owns its complete release tree and executes the prebuilt Rust binary; repair accepts pre-4.0 Python checkpoints and preserves operator environment values. MCP uses the panel binary CLI and version overrides. WARP downloads are removed after success or failure.
- Port NaiveProxy and Mieru host adapters and their private state/token preparers to the Rust installer. Preserve verified external Debian-package extraction and protocol acceptance, use the planned WARP endpoint and reviewed Mieru download URL, and retain version-agent Compose overrides during repair. Existing journal-owned Python helpers migrate to native dispatch without accepting unrelated drift; interrupted migration remains recoverable.
- The isolated official Mieru client uses a native Rust acceptance probe, without a Python interpreter. Fragmented SOCKS5 replies are read completely; client diagnostics cannot disclose the revealed configuration, and a partially started client is stopped on every error path.

## [3.3.0] - 2026-10-25

### Added
- **Deleting archived clients.** `DELETE /api/clients/{client_id}` (owner/admin, CSRF) and «Удалить навсегда» in the «⋯» menu of an archived client. Deletion is refused while the client has a grant not confirmed missing on its node, an unfinished operation or an operation in `manual_intervention_required`; it writes the `client.delete` audit event. The MCP tool `delete_clients_by_client_id` requires `confirm`.
- **«На чём клиент?» chooser.** The client window and the access bundle ask for the platform first and then offer the fitting apps: a deep link where one is verified, a download link otherwise. The app catalogue (`panel/subscriptions/apps.py`) is exposed by `GET /api/subscriptions/compatibility` as `platforms` and `apps`.
- **Overview.** A «Требует внимания» block lists clients with problems; «Выдать доступ» is a header button.
- **Center key.** «Создать ключ для центра» on the local node card issues a `node-sync` key and shows the address and the key once.

### Changed
- **Subscription page** `/s/{token}` is rebuilt: styled page, «Добавить в <app>» buttons, a download block, «Копировать ссылку подписки», a QR code on demand, collapsed accesses with copy buttons, `?lang=en`. A client with MTProxy only gets a `tg://` link instead of a subscription block. AmneziaWG stays out of subscriptions. The HTML renderer is version 5.
- Hiddify's TrustTunnel status in the compatibility report is `pending` instead of `unverified`.
- **Clients.** The list shows active clients by default and the navigation badge ignores archived ones; the card keeps «Открыть» and «Узлы и доступы», the rest is in the «⋯» menu (it opens upward on the last card on a phone). The matrix windows are wider, with a tag legend and one header for the AmneziaWG columns.
- «Ротировать URL» is «Выпустить новую ссылку». The TrustTunnel password in the access window is shown as is.
- Plain wording and one traffic-arrow convention across the panel; «Добавить узел» replaces «Панель», node registration v1 is under «Дополнительно»; the «Versions» legend is a single banner.

### Fixed
- The client dialog keeps button labels, proposes a free account name, reuses the created client after a partial failure, shows server errors in Russian, and archiving waits for the grants to be deleted.
- English labels for the app download links on the subscription page.

### Installer
- The wizard recognises an existing installation (`VERSION` or `ownership.json`), points at `bash install-release.sh --update` and quits by default; `--lang` skips the language question; review lines have human-readable labels in both languages; prompts are shorter with help lines; the profile help mentions AmneziaWG and TrustTunnel; root runs set `PYTHONDONTWRITEBYTECODE=1`. Components, ports, pins, configuration keys and host requirements are unchanged. The release build stamps `install-release.sh` with `3.3.0` and generates `install-release.sh.sha256`; the three-file `SHA256SUMS` is unchanged. No database migration or host configuration change.

## [3.2.1] - 2026-10-23

### Fixed
- **AmneziaWG and TrustTunnel node selection on their protocol screens.** Each access dialog loads the current node list when opened instead of relying on a previously visited screen. TrustTunnel submits the selected node rather than always using the local node; AmneziaWG takes the supported versions from the selected node's identity.
- Reopening either dialog ignores earlier load responses; AmneziaWG creation stays disabled until node capabilities arrive.
- Empty states on both protocol screens use the existing heading and paragraph layout, keeping the title and explanation on separate lines.
- English translations cover the two NekoBox subscription descriptions for supported and omitted protocols.

### Changed
- The NekoBox sing-box subscription variant carries NaiveProxy, Mieru and TrustTunnel together; TrustTunnel uses HTTP/2 over TCP with QUIC off. Support depends on the NekoBox/NyameBox build and is not claimed as verified in the app. MTProxy and Mieru port ranges remain unsupported; this variant is not for official sing-box.

### Security
- Pin `certifi` to `2026.10.19` in the panel and MCP server runtime requirements, replacing `2026.7.22` flagged by the dependency audit (`PYSEC-2026-4320`).
- Pin `opentelemetry-api` to `1.45.1` in both runtimes, addressing `CVE-2026-114603` reported by the release dependency audit.

### Installer
- Installer source and behavior are unchanged. The release build generates the published `install-release.sh` with version `3.2.1` and the new archive digest, plus `install-release.sh.sha256`; the three-file `SHA256SUMS` format and published asset set are unchanged. No API, wire format, database migration or host configuration change.

## [3.2.0] - 2026-10-20

### Added
- **AmneziaWG and TrustTunnel are version-agent components.** The «Versions» screen, the node's «Updates» window, `GET/POST /api/versions…`, the fleet routes and the MCP `versions_*` tools take `amneziawg` and `trusttunnel` next to `telemt`, `naive`, `mita`, `xray` and `panel`. A component is listed only on a host whose Compose model has its overlay (`compose.amneziawg.yaml`, `compose.trusttunnel.yaml`); its current version is read from the running manager's image env (`AWG_GO_VERSION`, `TT_VERSION`).
- Upstream candidates: `amneziawg` from the tags of `amnezia-vpn/amneziawg-go` (`kind: "build"`, `build: {commit, tag}`, a 40-hex commit); `trusttunnel` from the stable releases of `TrustTunnel/TrustTunnel` (`kind: "build"`, the `linux-x86_64` archive URL of that repository and the SHA-256 GitHub published for the asset; pre-releases are skipped, a release without a digest is visible but not installable). The installed version stays among the candidates, so a step back can be undone without another check. `versions.json` takes the same entries, validated the same way.
- An update writes the version into `version-overrides/compose.versions.yaml` as build args of the manager's service (`AWG_GO_VERSION` + `AWG_GO_COMMIT`, `TT_VERSION` + `TT_SHA256_X86_64`), tags the running image `<project>-<service>:rollback-<time>`, runs `compose up -d --build --no-deps <service>`, waits for health and reads the version back from the container. A failed build, start, health check or readback restores the previous override and image and proves the previous version runs again (`rollback_failed` otherwise). TrustTunnel refuses on a non-x86-64 host before any change.
- `awg_manager/Dockerfile` takes `AWG_GO_VERSION` and records it and `AWG_GO_COMMIT` in the image env.

### Changed
- The version override holds one block per service: Telemt's image update replaces only the `mtproxy` block and keeps the managers' build args, and the other way round.
- «Versions»: the «Proxy Control / панель» card comes first, then Telemt, Mieru, AmneziaWG, TrustTunnel, NaiveProxy, the Xray-router. The confirm text of a manager update says the image is rebuilt and the tunnels drop for seconds; a long component name wraps instead of running under the status pill.

### Installer
- The AmneziaWG and TrustTunnel adapters build with `version-overrides/compose.versions.yaml` when it exists, so `repair` keeps the agent's pins (Telemt's image included) instead of rebuilding the installer's own; the AmneziaWG adapter's model now includes the TrustTunnel overlay when it is installed. Removing either protocol drops its service's block from the override. Wizard questions, configuration keys and pins did not change.

### Maintenance
- Verification matrix: row `versions-protocol-managers`.

## [3.1.0] - 2026-10-20

### Changed
- **The overview's «Server resources» card is live.** It used to poll `GET /api/host` every 5 seconds and rebuild itself. It now subscribes to the monitor's own stream (`/api/metrics/stream`, the SSE feed of the «Monitoring» screen) and paints every snapshot in place — once per collector interval, 2 s by default: the percentages and the «used of total» lines change, the bars slide to the new width (CSS transition, off with `prefers-reduced-motion`), the status pill follows the load. The line under the title shows a pulsing «live» dot with the time of the snapshot.
- CPU on the card is now the agent's one-second average (the monitor's sample) instead of a 150 ms instantaneous reading; memory, swap and disk come from the same snapshot, so the card and the «Monitoring» screen always show the same numbers.
- **One shape for every protocol card.** MTProxy, Mieru, AmneziaWG, TrustTunnel and NaiveProxy are built by one function: the head with the status, the «Active accesses | Disabled» pair and one «Traffic» tile across the card — the value on one line (`↑ upload · ↓ download`, MTProxy `Σ total`, NaiveProxy with `Σ`), what the numbers count under it. The tile sits at the bottom of the card, so the cards of a row line up; its caption keeps two lines of room, so the tiles of a row have one height.
- What used to be extra tiles moved into the caption: MTProxy's current connections and active IPs, AmneziaWG's access versions, the NaiveProxy host and its «closed CONNECT tunnels only» note. NaiveProxy's «Accesses» is «Active accesses» like everywhere else; its dashed traffic box and footer line are gone.

### Fallback and compatibility
- A panel whose monitor is switched off (`PANEL_METRICS_ENABLED=0`) sends no snapshot; when the stream fails twice before the first one, the card closes it and polls `/api/host` every 5 seconds as before. The connection follows the overview: it closes when another screen opens and pauses in a hidden tab.
- `connectLive()` (`panel/static/js/live.js`) takes the screen it belongs to (`{ view }`, default `monitoring`); no API, database or configuration change. English strings for the new captions are in `i18n/en.json`.

### Maintenance
- CI: the shell step passes again (three `A && ok || bad` lines in `scripts/lab/awg-panel-e2e.sh` became `if … then … else`), and the notices step checks the Caddy builder pin of the Dockerfile (2.11.7) instead of the old 2.11.4.
- Verification matrix: row `ui-overview-live`.
- The installer did not change.

## [3.0.1] - 2026-10-20

- **The stack move takes the host's own model and checks it before stopping anything.** `scripts/migrate-compose-project.sh` read the Compose files from the running containers' labels; a label naming an overlay the host never installed (the Xray-router on two nodes) made `up` fail after the stop, and the way back failed the same way. It now uses `PROXY_CONTROL_COMPOSE_FILES`, the version overrides and the env files present — what update-host.sh and the version-agent use — and refuses before the stop when the model does not render, lacks a running service or bind-mounts a host path that does not exist (a short-syntax bind docker creates is fine). `--check` runs the checks only.
- No other change; the installer did not change.

## [3.0.0] - 2026-10-20

- **Faster and lighter.** The MTProxy ingress bridge (`xray-router-ingress`) is the static Go binary `mtproxy-bridge` (standard library only, built in the router image with the Go toolchain pinned for amneziawg-go) instead of a Python asyncio module; the protocol is unchanged (SOCKS5 login compared in constant time, VLESS over the router's socket, half-close, 4096 connections, a 10-second handshake), the kernel moves the bytes (splice) and its health check costs a millisecond.
- The panel's manager clients share one TLS context (`panel/local_http.py`): httpx built a new one, loading the whole CA bundle, for every request, and the monitor polls every manager once a second. The central's node clients share one context per TLS mode.
- The monitor reads the network-spike baseline (the p95 of a day of minute rollups) once a minute instead of on every tick.
- The Mieru manager hashes the pinned mita binary again only when the file changes (inode, size, mode, times), not on every status or traffic call; the NaiveProxy manager's cover probe uses one context without a CA store.
- Every Python image ships bytecode (`python -m compileall` right after `FROM`, a layer the images share): the base image has none and the containers' root is read-only, so each Python start — every health check — compiled the standard library again.
- **AmneziaWG through WARP.** Backend `amneziawg_native`: the AWG manager brings up its own WireGuard tunnel `awgwarp` to WARP (an account of its own, registered on the first apply), rules `from <subnet> lookup 51870` at priority 5150, a `blackhole` in the table for when the tunnel is gone and exceptions for private networks. Manager API `GET /v1/egress`, `POST /v1/egress/plan|apply|rollback`; an apply waits for the handshake and otherwise puts the previous exit back. Node capability `egress.amneziawg.v1`, migration 26. An AmneziaWG tab in «Routing» and an «Internet exit» card on the AmneziaWG screen.
- **AmneziaWG through the Xray-router (optional).** The AWG manager keeps a persistent TUN device `awgxr` (uid 10006) and with `{"provider": "router"}` steers the subnets into it; the router (service `amneziawg`, `XRAY_ROUTER_TUN_AMNEZIAWG`) opens the device and hands Xray the descriptor (`XRAY_TUN_FD`) for a sniffing `tun` inbound; that service's `warp` is a WireGuard outbound to WARP with the router's own account (`warp-wg.json`). The router gets the `/dev/net/tun` device.
- **The `tt://` link in the official TrustTunnel apps.** The panel writes the link in version 1 of the format: the official client (TrustTunnelClient 1.1.11, the AdGuard TrustTunnel apps) refused version 2 outright («Unsupported deep link version: 2»). The panel's decoder still reads version 2.
- **Subscription page: verified only.** For TrustTunnel — AdGuard TrustTunnel, the TrustTunnel CLI and mihomo-core apps; the compatibility table is replaced by a list of the apps verified to refresh the subscription, per protocol of this subscription; no Surge line. Long values wrap and the page is never wider than a phone screen.
- **Row actions on the AmneziaWG and TrustTunnel screens:** disable/enable, a new key (TrustTunnel: a new password) and delete through the grant API, after a confirmation; the list redraws at once. The access window opened from these screens also redraws the list behind it.
- **Compatibility:** TrustTunnel with mihomo verified on core v1.19.32; Hiddify is `unproven` (no app release has the outbound).
- No breaking changes: the API, the configuration and the data stay compatible; the major number marks the new bridge runtime and the rebuilt images. Installer: a report note on AmneziaWG's WARP exit; the bridge check it runs inside the container takes the Go binary (and the Python module of an older image).

## [2.2.1] - 2026-10-19

- **«Состояние сервисов» on the overview** lists every protocol that is switched on: Mieru, AmneziaWG and TrustTunnel join MTProxy and NaiveProxy (by their managers' state).
- No breaking changes; the installer did not change.

## [2.2.0] - 2026-10-19

- **Mieru in the clients table, live.** The Mieru manager serves cumulative per-user bytes (`GET /v1/traffic`, from `mita get metrics`; with lanes the running slots are added up) and the panel polls it every 5 seconds. The total rate stays with the kernel; without kernel counters it is computed from mita's counters (`source: "manager"`), and the `no_counters` reason is no longer reported.
- **NaiveProxy: per-client rows always.** The Naive manager used to be polled only when the kernel did not count the port. Now it is polled every 15 seconds always; the per-client rate is a 60-second average over finished connections (Caddy's log is written when a connection closes), and rows with `live: false` are marked «from finished».
- **The interface everywhere.** The MTProxy, Mieru, NaiveProxy, AmneziaWG and TrustTunnel pages show «Now ↓ ↑» beside a user (Naive: «Per minute»), `GET /api/metrics/clients?protocol=`; the Mieru page and the overview show the bytes since mita started instead of «Unavailable» (`traffic.available` in `/api/mieru/users` and `/api/dashboard`).
- Changes in the panel and the Mieru manager only; a manager older than 2.2.0 simply gives no Mieru rows. No breaking changes; the installer did not change.

## [2.1.0] - 2026-10-19

- **TrustTunnel for the client apps that actually take it.** The access window gains a «How to connect» table (AdGuard TrustTunnel for iOS/Android: link or QR; the TrustTunnel CLI: TOML; Throne: a profile created by hand; Surge: a policy line; Clash Verge Rev, FlClash, Mihomo Party, ClashMi: the Clash subscription; Hiddify and NekoBox: the sing-box subscription; Shadowrocket and the community GUIs: unverified, enter by hand) with store and project links, and a «Details for manual setup» card (server, port, username, password hidden until shown, SNI, protocol HTTP/2 with QUIC off, the certificate PEM, the Surge policy line) with a copy button per field. The subscription page carries the same list and card. Anything not run by us is marked «не проверено нами». Described in `TRUSTTUNNEL.en.md`, «Clients».
- **New artifact `trusttunnel_manual`** (`application/json`, no QR), built from the panel's store on request like the link and the TOML; also shown in the issue bundle.
- **TrustTunnel in the sing-box subscription for fork cores.** Upstream sing-box has no TrustTunnel outbound (SagerNet/sing-box#3723) and an official sing-box drops a whole config that has an unknown outbound, so the feed carries a `trusttunnel` outbound (`server`, `server_port`, `username`, `password`, `quic` false, `tls` with `server_name`; `insecure` only for an access with its own certificate) only for fork-core clients: a User-Agent with `Throne`, `NekoBox`, `NyameBox`, `NekoRay` or `Hiddify` on a request without `format` (or with `format=singbox`), or an explicit `client=throne|nekobox|nyamebox|hiddify`. Official sing-box, SFA, SFI, Karing and unknown agents keep the feed without it and the unsupported note; an explicit `client=singbox` or `client=karing` always does. `PANEL_SINGBOX_FORK_CLIENTS` adds extra User-Agent tokens without a release. `/s/{token}` now varies on `User-Agent`; the share variants gain `singbox-hiddify` and `singbox-nekobox`. Throne's `singbox` feed keeps naive and mieru.
- **Verified against a real core** (`scripts/lab/trusttunnel-fork-core-check.py`, lab host, 2026-10-19): `sing-box check` of hiddify-sing-box built from master `ae5cb1488` accepts the outbound, a request through it returns 200 with the traffic counted on the gate, and official sing-box 1.14.3 refuses the same JSON. `health_check` is not emitted because that build panics with it on. NekoBox's and Throne's cores could not be run, so their cells stay `unproven`.
- **Compatibility matrix, row `trusttunnel`:** `hiddify` supported (verified as above), `mihomo` supported (documented, not verified by us), `throne` and `nekobox` unproven with their steps in the note, `singbox` unsupported with the issue link.
- **Fixed: off-centre labels.** Text in filled and outlined buttons (for example the “Link” button on the MTProxy, Mieru and Naive screens) and the items of the phone's bottom bar were a pixel or several off the centre: a monitoring style (`.share`) also caught those buttons, and the bar did not centre its icon and label as a group. All buttons now centre their content on both axes; a browser test measures it.
- No breaking changes; the installer did not change.

## [2.0.1] - 2026-10-18

- **Connection counters in the monitor.** The protocol cards of «Сейчас» showed «Сессий» and «Клиентов» as 0 or «—» for TrustTunnel, NaiveProxy and Mieru while traffic was flowing, because those managers give no live count (TrustTunnel's `sessions` stays 0). The version-agent now counts **established TCP connections** on each protocol's ports from `/proc/net/tcp` and `/proc/net/tcp6` (no external tool) and serves it as `connections` in every `protocols.<name>` entry of `GET /v1/metrics` (`null` where the protocol has no TCP port, i.e. AmneziaWG). The card shows «Соединений N» and falls back to «Сессий» when there is no figure; AmneziaWG keeps its peer count. The panel carries `connections` in `GET /api/metrics/live`, records the series `<protocol>.connections` and reports `connections_peak` in `GET /api/metrics/summary`. Mieru counts its TCP ports only (UDP is not counted); behind the SNI router a loopback hop counts the tunnels to the backend. `sessions` stays the manager's or the peers' figure. Described in `MONITORING.en.md`.
- No breaking changes; the installer did not change.

## [2.0.0] - 2026-10-18

- **Monitoring.** A new «Мониторинг» screen (every role, read-only) shows the server and each protocol live: CPU, memory, swap, disk and its I/O, network, containers, and the ↑/↓ rate, sessions and busiest clients of MTProxy, NaiveProxy, Mieru, AmneziaWG and TrustTunnel. Three tabs: «Сейчас» (live, 5-minute chart), «Трафик» (history by protocol, 15 minutes to 90 days) and «Узлы» (comparison of nodes, alerts, per-node drill-down). Charts are drawn by the panel itself, work in the dark and light themes and respect reduced motion. Described in `MONITORING.en.md`.
- **How it is measured.** The version-agent samples the host once a second and serves it on `GET /v1/metrics`. Per-protocol bytes come from an own nftables table, `inet proxy_control_metrics`, that only counts and never decides a packet (ports are discovered by the agent; `/etc/proxy-control/metrics-ports.json` overrides them; `nft delete table inet proxy_control_metrics` removes it), AmneziaWG from its interfaces. Direction is the client's point of view and the bytes are network-layer bytes with headers. Without `nft` the panel falls back to the managers' counters (NaiveProxy then is not live). MTProxy's manager path has only a combined counter; NaiveProxy and Mieru have no live per-client rates.
- **History and alerts.** Rollups of 1 minute (3 days), 15 minutes (35 days) and 1 hour (400 days) in SQLite (migration 25, table `metric_rollups`); alerts for CPU, memory, disk, swap, a silent node and a traffic spike.
- **API and transport.** `GET /api/metrics/live`, `/stream` (Server-Sent Events with a polling fallback; 4 streams per session, 24 in total, 55 minutes each), `/history` and `/summary`, open to every signed-in role; `PANEL_METRICS_ENABLED=0` switches them off. On a central panel linked nodes are included through the new node routes `/api/fleet/v2/metrics[/history|/summary]` and the capability `metrics.v1`, polled only while someone watches; a node older than 2.0 shows as `unsupported`.
- **MCP.** The metrics routes become tools (`get_metrics_live`, `get_metrics_history`, `get_metrics_summary`); `/api/metrics/stream` is not exposed. `overview` gains a compact `metrics` section (per node: status, CPU/RAM/disk, network, per-protocol rates and sessions, alerts). The skills `proxy-control-morning-overview` and `proxy-control-diagnosing-access` use them.
- The «Versions» screen no longer tells you to rebuild managers when nothing needs doing. The version-agent now rebuilds the managers a panel update changed (`mieru-manager`, `naive-manager`, `xray-router`, `awg-manager`, `trusttunnel-manager`, `mcp`) itself, right after the panel is healthy, with one Compose call and a rollback image per service; a failure is recorded as `rebuild_error` and never rolls the panel back. Rebuilding the AmneziaWG and TrustTunnel managers briefly drops tunnels and sessions. Set `VERSION_AGENT_AUTO_REBUILD_MANAGERS=0` to keep the old behaviour.
- The card heals itself: a manager whose container already runs an image built after the panel update leaves `pending_rebuild`, also on hosts where it had got stuck. The card now reads «… — ещё не пересобраны» with an owner-only «Пересобрать менеджеры» button (`POST /api/versions/panel/rebuild-managers`, audit event `runtime.version.managers_rebuild`); the agent has `POST /v1/panel/managers/rebuild` and `/ack`, and the one-command update acknowledges what it rebuilt.
- The sidebar counters fill in when the panel starts, not only after a visit to the screen.
- No breaking changes to the API, the configuration or the installer TOML; the installer's only change is a fix for a fresh install with Mieru: the bootstrap config now sets `mtu` to 1400, because mita 3.38 reports an unset MTU as 0 and the Mieru manager refuses it. An updated host is unaffected. `scripts/update-host.sh` (the update helper) acknowledges the rebuilt managers.

## [1.6.0] - 2026-10-18

- A fifth protocol, **TrustTunnel** (AdGuard's VPN: HTTP/2 over TLS, TCP only; no QUIC and no UDP). It shares TCP/443 with the other services through the Nginx SNI route, so no new port is opened and no firewall rule is added. It is optional and needs a domain of its own (an A record to the server, DNS only, different from every other domain); its certificate comes from the installer. A new `trusttunnel-manager` container runs the pinned endpoint (TrustTunnel 1.1.0, Apache-2.0).
- An access is handed out as a `tt://` link with a QR code and as a client TOML (for the official AdGuard TrustTunnel apps for iOS and Android and the command-line client); the Clash/mihomo subscription carries a `type: trusttunnel` proxy. The sing-box feed leaves it out with a note, because sing-box has no TrustTunnel outbound. Surge's `trust-tunnel` policy is set up by hand. The compatibility matrix lists mihomo as supported; Karing, Shadowrocket, NekoBox and v2rayN as unproven.
- The endpoint reads its credentials only at start, so every new, changed or disabled access briefly restarts it (changes within about two seconds are merged); active sessions drop and the apps reconnect by themselves. Traffic counters survive restarts, and a renewed certificate is picked up without a restart. The manager reports `degraded` until the domain's certificate exists.
- A new «TrustTunnel» screen (where the protocol is enabled), a column in the «Nodes and access» matrix, the access window with the link, QR and TOML, and a card on the overview. Rotation issues a new password. Capture of an existing access and import of existing runtime users are not supported: the panel's store is the only copy of the password.
- Routing: TrustTunnel is a service in «Routing» with a policy for the whole service (presets, direct, WARP, your own exits, chains through other nodes). It has **no per-client lanes** (`lanes_unsupported`). Its own backend can only go direct; anything else attaches the service to the Xray-router, which opens a loopback-only SOCKS5 ingress without a password on `127.0.0.1:45104` — any local process or host-network container on the node can use that port as a proxy into the service's policy. Attaching and detaching restart the endpoint. A node without the capability is named in the routing screen (`node_lacks_trusttunnel_egress`, `router_lacks_trusttunnel`), and a central panel never sends a TrustTunnel access to a node that does not serve it. Update the nodes first, then the central panel.
- Installer: an optional `[trusttunnel]` section and `domains.trusttunnel` (the number of distinct names an installation can need is now twelve), two new wizard questions (enable? domain) in Russian and English, the example `examples/installer/core-trusttunnel.toml`, the `--requirements` text, and `scripts/enable-trusttunnel.sh` for a host the installer did not set up. The endpoint pin is in `release/external-artifacts.json`. The loopback ports `4453` (the endpoint, `listen_port`) and `1987` (the manager's metrics) join the reserved ports. Updating rebuilds `trusttunnel-manager` on a host that has it; `/var/lib/trusttunnel-manager` is never touched. Described in `TRUSTTUNNEL.en.md`.
- Database migration 24 (the access, routing and egress tables accept the new protocol).

## [1.5.1] - 2026-10-18

- The close cross is back in the «New AmneziaWG access» window.

## [1.5.0] - 2026-10-18

- AmneziaWG no longer uses the well-known ports 51820–51822: the installer picks a free random UDP port per version (10240–32000), stable for the server across plan, install and update. Ports can be set by hand: a wizard question (Enter accepts the picked ones), `ports` in the TOML, `--ports` of `scripts/enable-amneziawg.sh`.
- The «AmneziaWG» screen has a «+ AmneziaWG access» button: a name, versions (several allowed) and a node; after issuing, the window with the configs and QR opens.

## [1.4.0] - 2026-10-18

- A dedicated «AmneziaWG» screen in the panel (next to MTProxy, Mieru and NaiveProxy): cards for versions 1.5, 2.0 and 3.1 with the port, subnet and state, the list of this server's accesses with the client that holds each, the last connection and the traffic, and an «Open access» button (the access window with the config, QR, switch on/off, rotation and delete). The screen only reads: accesses are still given to clients («Clients» → «Nodes and accesses»). New route `GET /api/amneziawg/overview` (no keys and no obfuscation parameters); the menu item is shown only on a server that runs AmneziaWG.

## [1.3.4] - 2026-10-17

- Installer: files the version agent is meant to manage (the Caddy build and its pin, the mita binary and the digest in `.env.mieru`, the router's Xray files) are no longer read as foreign edits. Before, on a host set up by the installer, updating Caddy or mita from the panel made the next panel update refuse with «owned file drifted». Ownership still requires the file to exist and to be of the same kind; only its digest is not compared.
- The script `scripts/enable-amneziawg.sh` leaves the copied code owned by root even if the release was unpacked by an ordinary user.

## [1.3.3] - 2026-10-17

- The script `scripts/enable-amneziawg.sh` enables AmneziaWG on a host the installer did not set up: it copies the manager and the overlay, creates the token and the state directory, writes `.env.amneziawg`, turns on IPv4 forwarding, opens the ports and forwarding rules (`ufw` or `awg-forward.service`), adds the overlay to the version agent's list, rebuilds the manager and the panel and checks every version. It is safe to repeat and never touches the server keys. Described in `AMNEZIAWG.en.md`.

## [1.3.2] - 2026-10-17

- AmneziaWG on a server without `ufw`: the systemd service `deploy/awg-forward.service` adds forwarding allowances for the tunnel interfaces to Docker's `DOCKER-USER` chain after every start of Docker (Docker's forwarding policy is `DROP`). The case is described in `AMNEZIAWG.en.md`; with `ufw` the installer still adds the rules itself.

## [1.3.1] - 2026-10-17

- Telemt (MTProto) can be updated from the panel beyond the image: the Versions screen offers upstream releases (`telemt/telemt`) that the `mtproxymax-telemt` image does not carry yet. The version agent downloads the binary, checks the SHA-256 from the GitHub release metadata, builds an image on the host on top of the pinned base image and switches `mtproxy` to it; on a failure the previous state is restored. Version 3.5.14 is available this way now.

## [1.3.0] - 2026-10-17

- **AmneziaWG** protocol (optional): a VPN over UDP — WireGuard with traffic obfuscation. Versions **1.5, 2.0 and 3.1** run at the same time, each on its own interface, UDP port and subnet of the node (51820, 51821, 51822 by default), because the versions are not compatible with one another. The version is chosen per client: the «Nodes and accesses» matrix has «AmneziaWG 1.5 / 2.0 / 3.1» columns, and a client can hold several versions at once. The config is given as a `.conf` file and a QR from the access window and is not part of subscriptions. The panel keeps the client's private key, the node receives only the public one; rotation issues a new key pair. How it works, how to enable it and how to diagnose it: `AMNEZIAWG.en.md`.
- The node manager `awg-manager` (a container with `amneziawg-go` built from a pinned commit) and an `[amneziawg]` installer section: `enabled`, `versions`, `host`, ports, MTU, DNS. The installer turns on IPv4 forwarding, opens the UDP ports and allows forwarding for the tunnel interfaces in the firewall it manages. No new domain is needed: the panel's name works if it points straight at the server.
- Panel: an AmneziaWG card on the overview, its state in the node list, the MCP tools and the skill take the version (`options.version`), and the panel refuses at once if the node does not serve the chosen version.
- Database migration 23 widens the protocol list of `access_grants`; nodes get it with the same update. Nodes older than 1.3 receive no AmneziaWG resources (capability `protocol.amneziawg.v1`).
- Fixed: the version agent can update NaiveProxy (Caddy) again — its sandbox lacked write access to `/var/log/caddy`, so the configuration check and the rollback both failed.

## [1.2.1] - 2026-10-17

- Pinned components are updated: Xray 26.10.17 (the latest beta), Mieru/mita 3.38.1, Caddy 2.11.7 (the Naive build and the edge Caddy), 3x-ui 3.10.2 for `managed-new`, the MTProto (Telemt) image 3.5.9. The installer, `install-release.sh` and the examples use the same pins, so a fresh install and an update give the same set.
- The Xray-router can be updated to the latest beta from the panel (the Versions screen): the update check takes Xray pre-releases into account.

## [1.2.0] - 2026-10-17

- A client can be renamed (`POST /api/clients/{client_id}/rename`, the «Rename» button on the client card), and one access can carry its own name in subscriptions (`POST /api/clients/grants/{grant_id}/label`, access window → «Name in the subscription»; an empty name puts «node · protocol» back). The custom name applies to sing-box/Throne, Clash, HTML and `raw`; accounts, endpoints, credentials and the subscription URL do not change, and conditional fetches see the new names at once. Node renaming, already on the Nodes screen, is unchanged.
- Database migration 22 adds `access_grants.label`; nodes get it with the same update, and the Fleet protocol and the public manifest v1 are unchanged. Audit records `client.rename` and `grant.label`.

## [1.1.4] - 2026-10-12

- One request may issue any number of accesses: the cap of 8 grants per request is gone, so «all protocols on all nodes» no longer fails with 422 and leaves a client without accesses.
- The client list re-reads itself while any access waits for its node, so «ожидает узел» disappears once the node confirms instead of staying until the page is reloaded.

## [1.1.3] - 2026-10-11

- Subscriptions distinguish connections by node name and protocol instead of username alone. Duplicate names receive a stable suffix; Mieru retains transport and port distinctions. Shared naming applies to sing-box/Throne, Clash, HTML and Naive/Mieru raw labels. Node renames invalidate the ETag without changing subscription URLs or credentials.

## [1.1.2] - 2026-10-04

- `uninstall` without `--purge-data` removes the packages the installer installed with `apt-get remove` instead of `apt-get purge`: Docker's `/var/lib/docker` with every volume (the panel database included) and certbot's `/etc/letsencrypt` stay. A purge runs only on an explicit `uninstall --purge-data`; the rollback of a failed installation removes, never purges. The same rule applies to the `proxyctl` runtime.
- The package status reader accepts a purged package that dpkg keeps with an empty version; an uninstall used to fail right after purging.
- Routing refusals in the panel and the API name the missing node capability instead of an old version number; the update script and `install-release.sh --requirements` no longer refer to beta releases.
- The README is rewritten with separate installation sections for a person and for an AI agent; the documentation describes the current behaviour only, and the history before 1.0.0 is removed.

## [1.1.1] - 2026-10-03

- Includes the client lifecycle, bounded Fleet synchronization, update rollback and native installer fixes from the unpublished rc.1–rc.3 candidates below.
- The native installer pins 3x-ui 3.9.0 and its verified amd64 archive layout (bundled Xray 26.9.30). Managed installation removes its temporary acceptance accounts through the client API; 3x-ui 3.9 no longer changes clients through inbound updates. The wizard, release install script, examples and installation guides name the same pin.
- Managed Hysteria2 clients are explicitly enabled. Without this field, 3x-ui retains the account in its API but omits it from Xray's running configuration.
- Explicit managed 3x-ui purge also removes its SQLite sidecars and metrics cache after stopping the service, leaving unknown files untouched. Fresh installation refuses an orphan database directory.

## [1.1.1-rc.3] - 2026-10-03

Unpublished hardening candidate, checked with the stock installer on a native host.

- Panel updates transfer installer ownership for both Core and version-agent code under the installer lock; exact-archive reconciliation supports the first upgrade with an older agent. Installer-only changes also restart the agent to refresh imported Python modules.
- Updates refuse an incomplete Compose overlay scope before changing running services. Authenticated readiness diagnostics distinguish pending reconciliation from process liveness.
- Explicit installer purge removes an empty updater directory and verified optional-manager socket volumes, allowing a clean reinstall. Foreign files, symlinks and volumes remain protected.
- The release install script and bilingual installation guides describe old-agent reconciliation. Native update/repair, clean install/repair and idempotent install evidence is recorded separately; no public release was published.

## [1.1.1-rc.2] - 2026-10-02

Unpublished candidate with an additional fix found during installer validation.

- Installer command timeouts stop the command's process group and verify termination before returning control to rollback. If termination cannot be confirmed, automatic rollback does not start; remaining processes must be inspected before another operation.

## [1.1.1-rc.1] - 2026-10-02

Unpublished audit candidate; validation results are recorded separately from these changes.

- Client suspension and access validity windows now reach local protocol runtimes and remote nodes; reconciliation verifies the resulting state and retries failures. Stale Fleet reports cannot confirm a pending suspension.
- Client lists use batched reads and server-side pagination/search. Fleet pushes have bounded concurrency and connection-time DNS checks, preserving hostname verification and explicit private-address opt-in.
- Panel updates stop database writers before snapshot/restore, preserve the original WAL after a partial snapshot failure, and include the MCP service in synchronization and rebuilds.
- Request bodies are bounded while receiving; SQLite context managers close connections. Updated FastAPI, Starlette and related dependencies address dependency audit findings.
- Fresh installer ingress preserves client IP through a trusted Unix socket. Host updates migrate only recognized, owned Nginx templates with rollback and worker-generation verification; foreign coexistence frontends require an operator-managed bridge.
- CI validates all shipped Compose overlays, JavaScript syntax, pinned runtime dependencies and reproducible installer artifacts.

## [1.1.0] - 2026-10-01

- MTProxy routing: MTProxy attaches to the node's Xray-router and leaves through WARP, a custom exit or another node of the fleet (a chain); rules by CIDR, `geoip` and port, while rules by domain, `geosite` and protocol are `rule_kind_unsupported` (Telemt reaches Telegram's data centres by IP). Telemt's own policy (`mtproxy_native`) is direct only.
- Attach and detach change Telemt's upstream through its API (`PATCH /v1/config` + `POST /v1/system/reload`) without restarting the container; the rollback journal is the panel's `/data/telemt-egress.json`, secret-free.
- Xray-router: a third ingress `mtproxy` — VLESS on a Unix socket; the `xray-router-ingress` bridge (same image) on the Compose network takes Telemt's SOCKS5 on `:45103`; the router mints the credential; the only bypass exception, on that ingress alone — private networks on `:443` direct (the `mask` TLS front). `GET /v1/ingress/mtproxy`.
- Fleet: capability `egress.mtproxy.v1`, the generation's `egress.mtproxy` section; new codes `router_lacks_mtproxy`, `ingress_unreachable`, `node_lacks_mtproxy_egress`, `telemt_api_unsupported`, `egress_reload_failed`.
- Migration 21 (`routing-mtproxy`): `routing_policies` and `managed_egress` allow `mtproxy`/`mtproxy_native`.
- The installer starts, verifies and removes the bridge with the router; the wizard question and `--requirements` mention MTProxy.
- One-command updates: `bash install-release.sh --update` verifies the release, then `scripts/update-host.sh` (root) asks the version-agent to update the panel to exactly the verified digest and rebuilds the managers in `pending_rebuild` (and the router's bridge).

See [release notes](docs/releases/v1.1.0.md).

## [1.0.3] - 2026-10-01

- The release publishes `install-release.sh` and `install-release.sh.sha256`: the install script with its release's version and archive SHA-256 written in (a swapped archive does not pass even with a swapped `SHA256SUMS`), attested; `SHA256SUMS` still names three files.
- Installer wizard: explanations and defaults for the host mode, the profile and the 3x-ui mode; Mieru ports default to `46001`; the Xray version in the question comes from the external-artifact manifest; an invalid configuration says why; the review omits unused fields.
- Fix: with «apply» straight from the wizard, the typed panel and 3x-ui passwords were replaced by generated ones — they now reach the installation in a private temporary copy.
- Fix: the `initial_user` question says what it is (the first MTProxy and Mieru user; the panel login is always `owner`); «WARP domains» no longer promises «blank for none» and takes `geosite:`/`domain:`; `managed-new` is not offered in `coexist`; `existing` asks only for the VLESS domains (at least one); Mieru TCP ports are checked against the installer's own ports (8443, 8445, 8787, 4443, 8793, WARP, Xray-router, relay, lane slots, the managed 3x-ui); «No changes were made» is printed once; a 3x-ui username is kept with a generated password; the 3x-ui subscription domain joins the SNI uniqueness check.

The panel did not change. See [release notes](docs/releases/v1.0.3.md).

## [1.0.2] - 2026-10-01

- The access window: a click on an access row (client card or client window) opens its details (node, state and the node's report, route, limits, validity, subscription apps, secret, dates, ID), this access's own link with a QR on request («Открыть в Telegram» for MTProxy, «Профили для приложений» for NaiveProxy/Mieru on this server) and its actions: enable/disable, rotate, own lane, delete, adopt. The link does not stay in the window.
- Clients: search by name, account and node; state buttons with counts; filters by protocol, node and the state of accesses (problems, waiting for the node, error, no secret, disabled, own lane, no access); «Показано N из M» and «Сбросить». Filters survive list refreshes.
- API: `POST /api/clients/{id}/links?grant_id=…` reveals one access; links of all three protocols come with a QR.
- Client card and client window: compact clickable access rows, an access's buttons live in its window; one type size in the client window.
- Fix: text left its box (bubbles with vertical text in the client window, pills breaking mid-word); in-between widths — overview metrics, Mieru/NaiveProxy rows, the journal, the header on narrow phones.

Panel only: no migrations, no manager rebuild. See [release notes](docs/releases/v1.0.2.md).

## [1.0.1] - 2026-09-29

- Versions screen: each runtime's dropdown lists several recent releases both ways (newer / roll back, the agent's `newer` flag); the panel is only ever offered forward and the agent refuses a panel downgrade. The same on a node's Updates tab.
- Mieru takes any mita: no list of verified lines. The manager writes the whole config with the verb the binary offers (`replace config` from 3.38, `apply config` before), reads every write back and rolls back on a mismatch; a rollback that does not restore the snapshot is reported as needing recovery.
- Geodata: regional sources «runetfreedom» (Russia), «iran» (chocolate4u) and «v2fly» next to Loyalsoldier and the pin; a new router starts on Loyalsoldier with daily refreshes, an untouched pin moves there on upgrade. A daily refresh waits for `update_hour` (UTC, default 02:00); the line shows the last and next check. Files up to 128 MB (the Russian geosite is ~74 MB); a restart failure after the swap is recorded; the pin follows a new Xray seed; the download runs off the watchdog thread.
- Fix: the NaiveProxy upstream check asked for forwardproxy's `caddy2` branch, which no longer exists (422); it follows the `naive` branch now.
- Routing quick settings «Заблокированное в РФ → через WARP» (needs the runetfreedom source), «Китайские домены и IP → напрямую», «Иранские домены и IP → напрямую»; two new guide scenarios.

After the panel update rebuild `mieru-manager` and `xray-router`. See [release notes](docs/releases/v1.0.1.md).

## [1.0.0] - 2026-09-28

The first stable release: kept Mieru keys, a subscription for Throne, step-by-step routing with a built-in guide, and an English interface.

- Routing is step by step: for whom → where traffic goes → check → apply on the node, each step with a short explanation. A service's capabilities are named in words instead of codes; exits, the Xray-router, geosite/geoip lists and the relay sit in a folded «Возможности узла» block; the check's technical details fold under a plain summary of the draft.
- «Как это работает» (How it works) is a detailed guide inside the panel: the terms, what each service can do, eight step-by-step scenarios with a Start button (all traffic through WARP, some sites through WARP, ads, torrents, Russian sites direct, a chain through another node, your own exit, one client's own route), Save versus Apply, and what to do when the check says it cannot be applied. A scenario only prepares the draft — nothing reaches a node without Save and Apply.
- English interface: an RU/EN switch in the header and on the sign-in page, remembered per browser. Every screen, dialog and notification is translated; dates and numbers follow the chosen language.

- Mieru keys no longer need a rotation to be shown again: the panel keeps every key it issues in its encrypted store, and **Configuration** on the Mieru page shows the current key with no change on the node (`POST /api/mieru/users/{username}/access`). Users issued earlier are marked «Key not kept»; one **New key** keeps it from then on. «New link + QR» is renamed «New key».
- Fix: creating and rotating on the Mieru and NaiveProxy pages bypassed the panel's store, so a client's subscription kept serving the replaced password. The new password now reaches the subscription at once.
- Throne (formerly Nekoray), checked with Throne 1.3.1: it takes NaiveProxy and Mieru from the «sing-box JSON for Karing and Throne» variant and imports nothing from Clash YAML. The client window and the compatibility matrix say so, and grants carry a `throne` mark. Throne 1.3.1 limitation: Mieru over UDP connects only when the server is an IP address.
- Client card: grants line up as a table (protocol · account · state · route · actions) in one order, MTProxy → Naive → Mieru, with a coloured state dot; tidy stacked cards on a phone. Archived clients go last. The route button names the action.
- Overview: the loading placeholder has the real layout (server resources and three protocol cards), so the tiles no longer jump between 3 and 4. The RAM row shows swap (needs the host agent from this release).
- Accent colour: a palette button in the header, seven accents, remembered per browser.

See [release notes](docs/releases/v1.0.0.md).
