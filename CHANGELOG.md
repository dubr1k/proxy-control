# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Historical entries below are preserved as originally recorded.

## [Unreleased]

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
