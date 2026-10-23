# Proxy Control documentation

[Русский](#русский) · [English](#english)

This index separates **installation**, **protocols and the panel**, **operations**, and
**development**. Start with the README in your language, then follow the document for the
boundary you are changing.

## Русский

### Установка

1. [Обзор и установка: человеком и ИИ-агентом](../README.md)
2. [Установка на Ubuntu 24.04](../INSTALL.ru.md)
3. [Справочник установщика: команды, поля конфигурации, границы владения](INSTALLER_REFERENCE.ru.md)
4. [Установщик и проверка сервера](../INSTALLER_AUDITOR.ru.md)

### Протоколы и панель

- [Панель, роли, API-ключи, Telemt и NaiveProxy](../PANEL.ru.md)
- [MTProto за Nginx SNI](../DOCKER_DEPLOYMENT.ru.md)
- [Mieru/mita](../MIERU.ru.md) и [выдача ссылок, QR и конфигураций Mieru](MIERU_SHARING.ru.md)
- [AmneziaWG: версии 1.5, 2.0 и 3.1, конфиг и QR](../AMNEZIAWG.ru.md)
- [TrustTunnel: VPN поверх HTTP/2 и TLS, ссылка `tt://`, QR и конфиг](../TRUSTTUNNEL.ru.md)
- [Мониторинг: ресурсы и трафик по протоколам в прямом эфире, история, оповещения, API](../MONITORING.ru.md)
- [Связанные панели (Fleet v2) и транспорт mTLS (Fleet v1)](../FLEET.ru.md)
- [Маршрутизация: политики исходящего трафика, выходы, цепи и полосы](ROUTING.ru.md)
- [Xray-router](XRAY_ROUTER.ru.md)
- [MCP-сервер: панель как инструменты Claude Code и Claude Desktop](MCP.ru.md) и [навыки для ИИ](../skills/README.md)

### Эксплуатация

- [Ежедневная эксплуатация](OPERATIONS.ru.md)
- [Резервное копирование и восстановление](BACKUP_RESTORE.ru.md)
- [Обновление и откат](UPGRADING.ru.md)
- [Устранение проблем](TROUBLESHOOTING.ru.md)
- [Учёт трафика](ACCOUNTING.md)
- [Политика безопасности](../SECURITY.md)

### Разработка

- [Рабочий протокол для ИИ-агентов](../AGENTS.md) и [правила участия](../CONTRIBUTING.md)
- [Архитектура](ARCHITECTURE.md), [контракты совместимости](COMPATIBILITY.md),
  [архитектура панели и узлов](VNEXT_ARCHITECTURE.md), [матрица возможностей клиентов](VNEXT_CAPABILITIES.md)
- [Проверки выпуска](VALIDATION.md), [матрица сверки функций](VERIFICATION_MATRIX.md),
  [матрица проверок безопасности](SECURITY_TEST_MATRIX.md), [события аудита](AUDIT_EVENTS.md)
- Решения: [ADR 001](adr/001-pull-only-node-transport.md) — транспорт узлов только на опрос,
  [ADR 002](adr/002-declarative-generations.md) — декларативные поколения,
  [ADR 003](adr/003-one-writer-per-resource.md) — один писатель на ресурс,
  [ADR 004](adr/004-client-access-grant-subscription.md) — клиент, доступ и подписка,
  [ADR 005](adr/005-secret-references.md) — секреты по ссылкам,
  [ADR 006](adr/006-routing-policy-ir.md) — нейтральная модель маршрутизации,
  [ADR 007](adr/007-routing-enforcement-ownership.md) — кто исполняет маршрутизацию,
  [ADR 008](adr/008-panel-to-panel-transport.md) — транспорт панель→панель,
  [ADR 009](adr/009-lanes-and-chains.md) — полосы и цепи
- Исследования: [движок маршрутизации](spikes/VNEXT_ROUTING_ENGINE.md),
  [Xray как маршрутизатор исходящего трафика](spikes/XRAY_EGRESS_ROUTER.md),
  [цепи для отдельного клиента](spikes/CHAINS_PER_CLIENT.md)
- [Граф проекта](https://github.com/dubr1k/proxy-control/blob/main/graphify-out/GRAPH_REPORT.md) — в рабочей копии также `graphify-out/graph.html`; в архив установки граф не входит

### Выпуски

- [v3.2.1](releases/v3.2.1.md) — выбор узла и пустые состояния AmneziaWG/TrustTunnel, подписка NekoBox, обновление certifi
- [v3.2.0](releases/v3.2.0.md) — версии AmneziaWG и TrustTunnel с экрана «Версии»
- [v3.1.0](releases/v3.1.0.md) — обзор в прямом эфире, карточки протоколов одного вида
- [v3.0.1](releases/v3.0.1.md) — надёжный перевод стека в proxy_panel_by_dubr1k
- [v3.0.0](releases/v3.0.0.md) — быстрее и экономнее, стек proxy_panel_by_dubr1k, AmneziaWG через WARP
- [v2.2.1](releases/v2.2.1.md) — все протоколы в «Состоянии сервисов»
- [v2.2.0](releases/v2.2.0.md) — мониторинг по клиентам для Mieru и NaiveProxy
- [v2.1.0](releases/v2.1.0.md) — TrustTunnel: приложения-клиенты, подписка sing-box для форков ядра, данные для ручной настройки
- [v2.0.1](releases/v2.0.1.md) — счётчики соединений в мониторе
- [v2.0.0](releases/v2.0.0.md) — мониторинг в прямом эфире
- [v1.6.0](releases/v1.6.0.md) — протокол TrustTunnel
- [v1.5.1](releases/v1.5.1.md) — крестик в окне AmneziaWG
- [v1.5.0](releases/v1.5.0.md) — случайные порты AmneziaWG
- [v1.4.0](releases/v1.4.0.md) — отдельный экран AmneziaWG
- [v1.3.4](releases/v1.3.4.md) — обновление хоста после обновления компонентов из панели
- [v1.3.3](releases/v1.3.3.md) — включение AmneziaWG на хосте без установщика
- [v1.3.2](releases/v1.3.2.md) — AmneziaWG на сервере без ufw
- [v1.3.1](releases/v1.3.1.md) — Telemt из выпусков апстрима
- [v1.3.0](releases/v1.3.0.md) — протокол AmneziaWG: версии 1.5, 2.0 и 3.1
- [v1.2.1](releases/v1.2.1.md) — обновление Xray, Mieru, Caddy, 3x-ui и MTProto
- [v1.2.0](releases/v1.2.0.md) — переименование клиентов и названий доступов в подписке
- [v1.1.4](releases/v1.1.4.md) — выдача любого числа доступов за раз, список клиентов обновляет статус узлов
- [v1.1.3](releases/v1.1.3.md) — различимые имена подключений в подписках
- [v1.1.2](releases/v1.1.2.md) — удаление сохраняет данные Docker и сертификаты, новый README
- [v1.1.1](https://github.com/dubr1k/proxy-control/releases/tag/v1.1.1) — клиентский жизненный цикл, синхронизация Fleet, 3x-ui 3.9.0
- [v1.1.0](releases/v1.1.0.md) — маршрутизация MTProxy через Xray-router
- [v1.0.3](releases/v1.0.3.md) — сценарий установки в каждом выпуске, исправления мастера
- [v1.0.2](releases/v1.0.2.md) — окно доступа, поиск и фильтры клиентов
- [v1.0.1](releases/v1.0.1.md) — версии компонентов и региональные geodata
- [v1.0.0](releases/v1.0.0.md) — первый стабильный выпуск
- [Журнал изменений](../CHANGELOG.ru.md)

## English

### Installation

1. [Overview and installation: by a human and by an AI agent](../README.en.md)
2. [Installing on Ubuntu 24.04](../INSTALL.en.md)
3. [Installer reference: commands, configuration fields, ownership boundaries](INSTALLER_REFERENCE.en.md)
4. [The installer and the host audit](../INSTALLER_AUDITOR.md)

### Protocols and the panel

- [Panel, roles, API keys, Telemt and NaiveProxy](../PANEL.en.md)
- [MTProto behind Nginx SNI](../DOCKER_DEPLOYMENT.md)
- [Mieru/mita](../MIERU.en.md) and [sharing Mieru links, QR codes and configurations](MIERU_SHARING.en.md)
- [AmneziaWG: versions 1.5, 2.0 and 3.1, config and QR](../AMNEZIAWG.en.md)
- [TrustTunnel: a VPN over HTTP/2 and TLS, the `tt://` link, QR and config](../TRUSTTUNNEL.en.md)
- [Monitoring: live resources and per-protocol traffic, history, alerts, API](../MONITORING.en.md)
- [Linked panels (Fleet v2) and the mTLS transport (Fleet v1)](../FLEET.en.md)
- [Routing: outbound policies, exits, chains and lanes](ROUTING.en.md)
- [The Xray-router](XRAY_ROUTER.en.md)
- [The MCP server: the panel as tools for Claude Code and Claude Desktop](MCP.en.md) and [AI skills](../skills/README.md)

### Operations

- [Daily operations](OPERATIONS.en.md)
- [Backup and restore](BACKUP_RESTORE.en.md)
- [Upgrade and rollback](UPGRADING.md)
- [Troubleshooting](TROUBLESHOOTING.en.md)
- [Accounting semantics](ACCOUNTING.md)
- [Security policy](../SECURITY.md)

### Development

- [Development protocol for AI agents](../AGENTS.md) and [contribution rules](../CONTRIBUTING.md)
- [Architecture](ARCHITECTURE.md), [compatibility contracts](COMPATIBILITY.md),
  [panel and node architecture](VNEXT_ARCHITECTURE.md), [client capability matrix](VNEXT_CAPABILITIES.md)
- [Release validation](VALIDATION.md), [function verification matrix](VERIFICATION_MATRIX.md),
  [security test matrix](SECURITY_TEST_MATRIX.md), [audit events](AUDIT_EVENTS.md)
- Decisions: [ADR 001](adr/001-pull-only-node-transport.md) — pull-only node transport,
  [ADR 002](adr/002-declarative-generations.md) — declarative generations,
  [ADR 003](adr/003-one-writer-per-resource.md) — one writer per resource,
  [ADR 004](adr/004-client-access-grant-subscription.md) — client, access grant and subscription,
  [ADR 005](adr/005-secret-references.md) — secret references,
  [ADR 006](adr/006-routing-policy-ir.md) — engine-neutral routing model,
  [ADR 007](adr/007-routing-enforcement-ownership.md) — routing enforcement ownership,
  [ADR 008](adr/008-panel-to-panel-transport.md) — panel-to-panel transport,
  [ADR 009](adr/009-lanes-and-chains.md) — lanes and chains
- Spikes: [routing engine](spikes/VNEXT_ROUTING_ENGINE.md),
  [Xray as the egress router](spikes/XRAY_EGRESS_ROUTER.md),
  [chains per client](spikes/CHAINS_PER_CLIENT.md)
- [Project graph](https://github.com/dubr1k/proxy-control/blob/main/graphify-out/GRAPH_REPORT.md) — Git checkouts also include `graphify-out/graph.html`; the graph is excluded from installation archives

### Releases

- [v3.2.1](releases/v3.2.1.md) — AmneziaWG/TrustTunnel node selection and empty states, NekoBox subscription, certifi update
- [v3.2.0](releases/v3.2.0.md) — AmneziaWG and TrustTunnel versions from the «Versions» screen
- [v3.1.0](releases/v3.1.0.md) — a live overview, one shape for every protocol card
- [v3.0.1](releases/v3.0.1.md) — a safe move of the stack to proxy_panel_by_dubr1k
- [v3.0.0](releases/v3.0.0.md) — faster and lighter, the proxy_panel_by_dubr1k stack, AmneziaWG through WARP
- [v2.2.1](releases/v2.2.1.md) — every protocol in the services list
- [v2.2.0](releases/v2.2.0.md) — per-client monitoring for Mieru and NaiveProxy
- [v2.1.0](releases/v2.1.0.md) — TrustTunnel: client apps, a sing-box feed for fork cores, details for manual setup
- [v2.0.1](releases/v2.0.1.md) — connection counters in the monitor
- [v2.0.0](releases/v2.0.0.md) — live monitoring
- [v1.6.0](releases/v1.6.0.md) — the TrustTunnel protocol
- [v1.5.1](releases/v1.5.1.md) — close cross in the AmneziaWG window
- [v1.5.0](releases/v1.5.0.md) — random AmneziaWG ports
- [v1.4.0](releases/v1.4.0.md) — a dedicated AmneziaWG screen
- [v1.3.4](releases/v1.3.4.md) — updating a host after components were updated from the panel
- [v1.3.3](releases/v1.3.3.md) — enabling AmneziaWG on a host without the installer
- [v1.3.2](releases/v1.3.2.md) — AmneziaWG on a server without ufw
- [v1.3.1](releases/v1.3.1.md) — Telemt from upstream releases
- [v1.3.0](releases/v1.3.0.md) — the AmneziaWG protocol: versions 1.5, 2.0 and 3.1
- [v1.2.1](releases/v1.2.1.md) — Xray, Mieru, Caddy, 3x-ui and MTProto updates
- [v1.2.0](releases/v1.2.0.md) — rename clients and access names in the subscription
- [v1.1.4](releases/v1.1.4.md) — any number of accesses in one request, the client list refreshes node statuses
- [v1.1.3](releases/v1.1.3.md) — distinct connection names in subscriptions
- [v1.1.2](releases/v1.1.2.md) — uninstall keeps Docker data and certificates, a new README
- [v1.1.1](https://github.com/dubr1k/proxy-control/releases/tag/v1.1.1) — client lifecycle, Fleet synchronization, 3x-ui 3.9.0
- [v1.1.0](releases/v1.1.0.md) — MTProxy routing through the Xray-router
- [v1.0.3](releases/v1.0.3.md) — the install script in every release, wizard fixes
- [v1.0.2](releases/v1.0.2.md) — access windows, client search and filters
- [v1.0.1](releases/v1.0.1.md) — component versions and regional geodata
- [v1.0.0](releases/v1.0.0.md) — the first stable release
- [Changelog](../CHANGELOG.md)

## Common rules

- Keep public TCP/443 under the host Nginx `stream` router.
- Keep every node in the single Compose project `proxy_panel_by_dubr1k` (`mtproxy` before 3.0).
- Persist and reuse the exact full `COMPOSE_FILE` overlay list.
- Treat `.env`, `secrets/`, access URLs, QR codes, databases, journals and PKI as credentials.
- Back up a complete generation before changing runtime, state, identities, ports or routes.
- A healthy process is not a protocol test. Validate MTProto `resPQ`, Naive authenticated CONNECT and Mieru end-to-end transport.
- Never claim unavailable accounting precision.
- A linked panel (Fleet v2) is added by URL and a `node-sync` API key and is managed only after it accepted a generation; for Fleet v1, registry creation is not enrollment — enrollment requires certificate issuance, binding, mTLS authorization and a successful command/result cycle.
