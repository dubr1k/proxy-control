# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Historical entries below are preserved as originally recorded.

## [Unreleased]

## [0.3.0-beta.1] - 2026-09-13

Fleet v2: one central panel manages linked panels over their own HTTPS domains with
scoped API keys — three UI actions, nothing installed on a host beyond the panel image
(`docs/adr/008-panel-to-panel-transport.md`, spec
`docs/superpowers/specs/2026-09-11-v0.3-central-panel-design.md`). Gated on the lab
host; the release note `docs/releases/v0.3.0-beta.1.md` tracks the gate and the live
check.

### Added

- Scoped API keys (`api_keys`, migration 9): name, scope `admin | monitor | node-sync`,
  optional expiry; SHA-256 at rest, the plaintext `pc_<prefix>_<secret>` shown once;
  enable/disable/delete take effect on the next request. `Authorization: Bearer` on the
  whole `/api/*` (`admin` → owner, `monitor` → viewer, `node-sync` → `/api/fleet/v2/*`
  only), 120 requests per minute per key, audit as `key:<name>`; `/api/keys*` for the
  owner and the section «API-ключи» on the «Администраторы» screen.
- A stable `panel_guid` per panel (`panel_settings`), minted on first start, and the
  release version reported from `VERSION` (`PANEL_VERSION_FILE`, bind-mounted by
  `compose.yaml`, copied into the project directory by the installer; `dev` when absent).
- Node side of Fleet v2 (migration 10, `panel/fleet_v2/{protocol,managed,reconcile,
  guard,node_routes}.py`): `/api/fleet/v2/identity|status|inventory|generation|observed|
  credentials/capture|versions/update|unlink`; typed, secret-free, digested
  `GenerationDocument` (≤ 64 KiB, ≤ 500 resources) with 409 codes `guid_mismatch`,
  `foreign_master`, `stale_generation`, `digest_conflict`, `secret_store_disabled`; a
  reconciler that creates, rotates, enables/disables and updates options through the
  protocol adapters, deletes orphans, reports collisions with local users as `failed`,
  adopts only explicitly imported users, re-applies an unfinished generation at start and
  answers 202 when an apply exceeds 25 s; one master per node; 409 `managed_by_central`
  for every local writer that touches a central-owned user; «Отвязать» on the card «Этот
  сервер» (`POST /api/nodes/local/unlink`).
- Central side of Fleet v2 (migration 11, `panel/fleet_v2/{client,links,generations,
  pusher,importing,central_routes}.py`): `NodeClient` with TLS `verify` or `pin` and an
  SSRF guard on the panel URL; «Добавить панель» (`/api/nodes/fingerprint|test|link`),
  pause/resume/probe/edit/delete (`DELETE` refused while grants remain); generations
  compiled from grants and published only when their content changes; a heartbeat and
  delivery loop (`PANEL_FLEET_HEARTBEAT_SECONDS`, default 15) with `node.up`/`node.down`
  events, 202 polling, resync on `stale_generation`/`digest_conflict` and a per-node
  backoff (30 s → 10 min) after a failed or rejected generation; import of a node's
  runtime users as clients and `origin=imported` grants with credential capture (Mieru
  without a credential until rotation); `GET /api/nodes/{id}/generations`; per-node
  public hosts in subscriptions and bundles.
- Grant lifecycle for linked panels (`panel/clients/lifecycle.py`, migration 12
  `pending_remote`): issue, enable, disable, rotate and delete are declarative — row,
  audit and generation in one transaction, «ожидает узел» until the node reports; a
  confirmed deletion purges the grant and revokes its credential versions so the name can
  be granted again; a manager-chosen credential returned by the node is escrowed under the
  version the document named.
- UI: «API-ключи» section, the «+ Панель» dialog with «Проверить», «Получить отпечаток»
  and the import list, the linked-panel card (Обзор / Пользователи / Обновления, Пауза /
  Проверить / Изменить / Удалить), GUID and «Отвязать» on «Этот сервер», linked panels in
  the node picker of «Выдать доступ».
- Telemt: the pinned fork accepts a caller-supplied `secret` on create and rotate
  (probed on the lab host, `scripts/lab/telemt-secret-probe.py`); a runtime that refuses
  falls back to a manager-generated secret and says so (`credential_origin`);
  `update_options` on all three adapters.
- ADR 008; `FLEET.*.md` rewritten for v2 with v1 as «Legacy transport v1»; `PANEL.*.md`
  (API keys), `docs/OPERATIONS.*.md` §11, `docs/UPGRADING*.md` («Upgrading to v0.3»),
  `docs/COMPATIBILITY.md` (frozen `panel_guid`, `/api/fleet/v2/*`, `pc_` keys, wire
  fields), `docs/VNEXT_ARCHITECTURE.md` (v0.3 section), `docs/releases/v0.3.0-beta.1.md`.

### Changed

- `compose.yaml` bind-mounts `./VERSION:/app/VERSION:ro` and the installer copies
  `VERSION` into the project directory; hosts updated by rsync must ship it with the code.
- `fleet_nodes` gained `transport` (`v1` for every existing node, `panel` for a linked
  one); a linked panel appears on the «Узлы» screen next to v1 nodes and the local node,
  and «Отключить» on it pauses the link instead of cutting a transport it does not have.
- `provisioning_operations` was rebuilt to admit the status `pending_remote` (rows, index
  and foreign key preserved).
- The `TelemtIndeterminate` outcome propagates raw through the caller-secret fallback so
  the saga resumes instead of compensating.

### Fixed

- A deleted grant no longer blocks re-granting the same `runtime_username` forever: the
  row is purged once the deletion is confirmed (locally right away, on a linked panel when
  the node reports `missing`).
- `read_panel_version` tolerates a missing, unreadable or empty `VERSION` (`dev`) instead
  of keeping the panel from starting.

### Not in this release

Routing (v0.4) and the Xray router (v0.5); transitive nodes, metric history and
panel-to-panel mTLS (ADR 008 non-goals); remote update of a node's panel itself (the
version-agent handles `telemt | naive | mita` only).

## [0.2.0-beta.1] - 2026-09-11

The local control plane (vNext v0.2): the panel owns clients, their accesses and the
credentials behind them, and hands each client one invalidatable subscription URL on a
dedicated domain. Everything below was gated on the disposable lab host, not in CI —
see `docs/superpowers/plans/2026-09-10-vnext-v0.2-local-control-plane.md`, Task 19A.

### Added

- One database boundary (`panel/database.py`) with versioned, checksummed migrations
  (`db-migrate`, `db-status`); the baseline migration adopts a v0.1.0 database in place.
  Audit rows are written inside the transaction of the change they describe and carry
  `X-Request-Id`, so a response and its trail can be matched.
- An encrypted secret store (AES-256-GCM, per-row AAD) behind a master keyring that the
  installer creates and preserves; the panel refuses to start when encrypted rows exist
  and the key is missing. `master-key-init|rotate|verify` in the CLI; backup guidance in
  `BACKUP_RESTORE.*`.
- Clients and access grants: import existing manager accounts read-only, adopt their
  credentials (MTProxy and NaiveProxy by capture, Mieru by explicit rotation), issue new
  accesses through a journaled saga that ends in exactly one of `succeeded`,
  `compensated` or `manual_intervention_required` (`operations-resume` in the CLI). Node
  lifecycle with a reserved `local` node; screens "Clients" and "Nodes" in the UI.
- Idempotent manager operations: NaiveProxy and Mieru accept a caller-supplied credential
  and an operation id and replay a lost reply; Telemt reads its live link back after an
  indeterminate call.
- `PANEL_VNEXT_WRITER=legacy|domain`: the protocol endpoints keep their v0.1.0 contract in
  both modes (the whole API suite runs twice); in `domain` the panel owns the credential.
- Client subscriptions: a bearer URL `https://<subscription domain>/s/<token>` (stored as a
  hash, revealed once), rendered from escrow as `raw`, `singbox` (Karing; `client=singbox`
  for the official core), `clash` (mihomo), `manifest` and `html`; ETag from the effective
  set of grants, `304` on `If-None-Match`, `Profile-Update-Interval`, a per-address rate
  limit, no access log anywhere on the path, and a compatibility matrix that names what a
  client cannot consume instead of shipping a link it cannot parse. Generation moves in
  the transaction of the change; `subscription.*` events and `GET /api/events`.
- `domains.subscription` in `install.toml` (asked by the wizard): a SAN on the core
  certificate, an SNI route and a dedicated Nginx `server` that serves only `/s/` with
  `access_log off`; the panel's own name refuses the path without logging it.
- Lab tooling that the gate relies on: `scripts/dev/remote-gate.sh`
  (`quick|full|compose|lab-container|lab-host`), `scripts/lab/host-teardown.sh` and
  `scripts/lab/subscription-acceptance.py` (the live subscription check, including the
  real sing-box and mihomo cores).
- ADR 001–007, `docs/VNEXT_ARCHITECTURE.md` and the capability matrix
  `docs/VNEXT_CAPABILITIES.md` / `tests/fixtures/vnext-capabilities.json`.

### Changed

- The release train: the lab host gates, CI confirms. `release.yml` rebuilds the tagged
  commit twice, refuses any archive whose digest differs from the one the lab accepted
  (`expected_sha256` input or a `lab-sha256:` tag annotation), attests and publishes after
  human confirmation; the QEMU `lab-amd64` job is gone. Pre-release tags
  (`vX.Y.Z-*`) build the same way.
- `panel/entrypoint.sh` runs uvicorn with `--no-access-log`; the subscription path is a
  bearer credential and an access line would be a copy of it.
- MTProxy links are rebuilt from the host and port Telemt itself reported (learned into
  the grant's options), not from the panel's domain.
- The `mierus://` link parser lives in `panel.protocols.mieru` and serves both the reveal
  and the subscription renderers.

### Fixed

- `full` profile installs ended with a panel that did not know NaiveProxy (`feature
  unavailable`): the Naive and Mieru adapters each started Compose with only their own
  overlay, and whichever applied last recreated the panel without the other's environment.
  Both now include the sibling overlay whenever its generation is present.
- `repair` on a `managed-new` 3x-ui host failed twice over: the route verify demanded that
  the 3x-ui panel and subscription listeners be Xray inbounds, and the runtime verify ran
  before the restarted panel had bound its port.
- A finished `uninstall` blocked the next `install` with "an installer transaction already
  exists", although the host owned nothing anymore; it is now cleared like a finished
  rollback, so `uninstall` → `install` re-renders owned files from a new release over the
  preserved data. `managed-new` 3x-ui still refuses a preserved `/etc/x-ui/x-ui.db`
  (documented in the installer reference).
- `db-status` on a v0.1.0 database crashed instead of reporting that nothing was applied.
- The release workflow read the lab digest from the local tag ref, which `actions/checkout`
  peels to the commit; the annotation is now read from the tag object through the API (the
  first `v0.2.0-beta.1` run built the exact lab bytes and stopped on "no lab digest").
- The one-time bundle dialog's "copy" buttons had no handler.
- `Database.__init__` retried `PRAGMA journal_mode=WAL` under contention (found by a 300-run
  stress of a test that failed once in a full run).

### Not in this release

Fleet v2, routing and the Xray router remain roadmap (`docs/VNEXT_ARCHITECTURE.md`).
Karing auto-refresh is verified for the feed formats it consumes but the on-device import
is the owner's manual check.

### Added (before the v0.2 work)

- A host resource card on the overview reporting CPU utilisation, memory and root-filesystem usage with warning thresholds, sourced from a new read-only `GET /v1/host` on the host version-agent. The panel runs read-only with all capabilities dropped and mounts nothing from the host but the agent socket, so the agent is the only component that can measure these; when it is unreachable the card degrades to a stated reason instead of guessing.
- NaiveProxy per-user traffic quotas: `quota_bytes` on create and a dedicated quota endpoint, with usage, remaining and exhaustion reported in the panel. A manager thread enforces quotas on an interval (`NAIVE_QUOTA_INTERVAL_SECONDS`, default 60 s) and transactionally removes an exhausted user's credentials from the managed Caddy block.
- A NekoBox client tab in the NaiveProxy one-time reveal that carries a `naive+https://USER:PASSWORD@HOST:443#NAME` link and a matching QR, the format NekoBox for Android and its forks parse.
- Standalone Proxy Control documentation, governance templates, screenshot policy, and third-party notices.
- CI coverage for the complete Python suite, Ruff, all tracked shell scripts, all Compose variants, project image builds, documentation links, and provenance notices.

### Changed (before the v0.2 work)

- Quota enforcement moved out of the manager's socket accept loop into its own thread with backoff, so a Caddy validate/reload can no longer stall the control socket. `GET /v1/health` and `GET /v1/traffic` are reads again and never rewrite the managed config.
- Managers tolerate a client that hangs up mid-response instead of logging a traceback per probe, and their health probes read the full response before closing.
- A refused enable now carries the reason code `quota_exhausted` through to the panel, which reports it as an actionable state instead of “manager unavailable”. Removing or raising a quota records `disabled_reason: manual` rather than leaving a stale quota block.
- Neutral product descriptions cover Telemt/MTProto, NaiveProxy/Caddy, Mieru/mita, panel, and fleet while preserving protocol-specific and migration-sensitive MTProxy identifiers.
- NaiveProxy now requires explicit `NAIVE_PUBLIC_HOST`; the personal fallback was removed.
- Documentation accurately describes persistent Telemt configuration and its authenticated private API.
- The panel backend is composed from protocol- and responsibility-specific route modules while preserving `panel.app:create_app`, existing API paths, RBAC, security headers, and one-time reveal behavior. Audit reads now support bounded cursor pagination and actor/action/target filters.
- Fleet v1 is Telemt-only; Mieru operations and Mieru capability advertisement were removed from its models, node execution path, and documentation.
- Naive and Mieru one-time reveals now expose client-specific Native, Karing, and verified manual variants. Karing receives a full profile through its documented deep link instead of a raw endpoint QR; unsupported Shadowrocket/Mieru and Mieru port-range combinations are reported without fabricated import formats.
- The Mieru manager, deployment guidance, and panel version metadata now admit pinned mita 3.36.x binaries while retaining 3.35.x compatibility.

### Fixed (before the v0.2 work)

- Added an opt-in, idempotent systemd-managed TCP MSS clamp for Mieru listeners. It addresses confirmed mobile return-path black holes without changing unrelated firewall rules and removes its exact rule on stop.
- Creating or rotating an MTProxy access now refreshes the list without a page reload. The reveal payload carried no QR while the access dialog requires one, so it threw after the modal closed and before the list was re-fetched, leaving the new profile invisible until F5. The QR now travels with the reveal, and a dialog that cannot render is reported without blocking the refresh.
- Busy buttons no longer stick on "Создаём…". Handlers read `event.currentTarget` in `finally`, which runs after dispatch has ended and yields null, so the button was never re-enabled; the target is now captured while it is still live.
- Mieru transactions no longer re-hash the blanked password mita returns for an already stored user, so creating, rotating, deleting or quota-editing an access after the first one succeeds instead of failing the readback check and rolling back with `manager operation failed`.
- Mieru Native reveals now provide a complete `mieru-client.json` with the required active profile, RPC port, and SOCKS5 port, so a brand-new official client can apply and start it. The human-readable `mierus://` link and QR are retained only for adding the profile to an already configured client.
- Rotated Mieru credentials now produce a generation-specific Karing profile name, so Karing imports the replacement instead of rejecting it as a duplicate and retaining the revoked password. The Mieru reveal also explicitly marks NekoBox+ as unsupported.
- Installer panel TLS vhosts now serve a neutral cover at `/` for unauthenticated requests while preserving the authenticated post-login landing.
- Public ACME roots are forced to `0755` even under restrictive operator umasks.
- Route repair/uninstall validates and removes only the marked Proxy Control block, preserving adjacent SNI routes added after core installation.
- Naive private-listener start/reload disables automatic HTTPS redirects, and Naive Karing reveals again provide a verified `karing://install-config` deep link with a matching QR pane.
- Client tabs without a verified QR format (NaiveProxy Native, Shadowrocket) now drop the QR pane instead of rendering an empty white placeholder that reads as a broken code.
- Toasts are raised into the top layer via a manual popover, so a confirmation such as “link copied” is no longer painted behind an open modal's blurred backdrop.

### Security

- Documented panel/RBAC, local managers, accounting, Mieru external-process, fleet mTLS, transactional host mutation, backup, and fail-closed boundaries.
- Removed the former host/systemd MTProxy install and uninstall scripts; supported deployments now use the Compose/Telemt installer path.
- Login attempts are atomically reserved in SQLite before Argon2 verification, each request can release only its own reservation after success, and password checks have bounded concurrency, preventing concurrent or cross-account batches from bypassing the configured rate limit.

### Validation status

- Ubuntu 24.04 QEMU lifecycle and production fleet enrollment remain pending; Telemt, NaiveProxy and Mieru have passed live operator-controlled protocol probes.

## [0.1.0]

The first packaged release: a transactional installer that takes a clean
Ubuntu 24.04 host from nothing to a verified deployment, and a release
acceptance lab that proves it on real hardware.

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

### Changed

- WARP is documented and wired as one loopback SOCKS5 endpoint at
  `127.0.0.1:45000`, with the per-protocol split stated explicitly: Xray routes
  only `warp_domains` through it, while NaiveProxy and Mieru route all traffic
  through it.
- The NaiveProxy site listens on a port-only address and enables probe
  resistance, so a tunnelled `CONNECT` reaches `forward_proxy` and an
  unauthenticated request is served the cover site instead of `407`.

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
