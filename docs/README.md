# Proxy Control documentation

[Русский](#русский) · [English](#english)

This index separates **installation**, **protocol configuration**, **operations**, and **development**. Start with the language-specific README, then follow the runbook for the boundary you are changing.

## Русский

### Начало работы

1. [Обзор продукта и быстрый старт](../README.md)
2. [Автоматическая установка на Ubuntu 24.04](../INSTALL.ru.md)
3. [Справочник установщика релиза](INSTALLER_REFERENCE.ru.md)
4. [Полный installer/auditor](../INSTALLER_AUDITOR.ru.md)
5. [Архитектура](ARCHITECTURE.md) и [compatibility contracts](COMPATIBILITY.md)

### Протоколы и панель

- [Панель, роли, API-ключи, Telemt и NaiveProxy](../PANEL.ru.md)
- [MTProto за Nginx SNI](../DOCKER_DEPLOYMENT.ru.md)
- [Mieru/mita](../MIERU.ru.md)
- [Выдача Mieru URL, QR и client config](MIERU_SHARING.ru.md)
- [Связанные панели (Fleet v2) и legacy mTLS-транспорт v1](../FLEET.ru.md)
- [Маршрутизация: egress-политики NaiveProxy и Mieru (v0.4), Xray-router (v0.5), цепи и полосы (v0.7)](ROUTING.ru.md)

### Эксплуатация

- [Ежедневный операционный runbook](OPERATIONS.ru.md)
- [Backup и restore](BACKUP_RESTORE.ru.md)
- [Матрица сверки v0.2–v0.7](VERIFICATION_MATRIX.md)
- [Upgrade и rollback](UPGRADING.ru.md)
- [Troubleshooting](TROUBLESHOOTING.ru.md)
- [Accounting semantics](ACCOUNTING.md)
- [Validation gates](VALIDATION.md)
- [Security policy](../SECURITY.md)
- [Рабочий протокол для AI-агентов](../AGENTS.md)

### Архитектура vNext

- [Архитектура vNext](VNEXT_ARCHITECTURE.md)
- [Матрица возможностей vNext](VNEXT_CAPABILITIES.md)
- [ADR 001 — pull-only транспорт узлов](adr/001-pull-only-node-transport.md)
- [ADR 002 — декларативные поколения](adr/002-declarative-generations.md)
- [ADR 003 — один писатель на ресурс](adr/003-one-writer-per-resource.md)
- [ADR 004 — Client, AccessGrant и подписка](adr/004-client-access-grant-subscription.md)
- [ADR 005 — секреты по ссылкам](adr/005-secret-references.md)
- [ADR 006 — нейтральный routing IR (accepted, v0.4)](adr/006-routing-policy-ir.md)
- [ADR 007 — владение enforcement маршрутизации](adr/007-routing-enforcement-ownership.md)
- [ADR 008 — транспорт панель→панель со scoped API-ключами](adr/008-panel-to-panel-transport.md)
- [ADR 009 — полосы клиентов и цепи через relay парка (v0.7)](adr/009-lanes-and-chains.md)

### Выпуски

- [v0.7.0-beta.1](releases/v0.7.0-beta.1.md) — цепи и полосы: выход через узлы парка (relay), своя полоса у доступа, tier `chains`

- [CHANGELOG.ru.md](../CHANGELOG.ru.md) — журнал изменений по-русски (с v0.4); [CHANGELOG.md](../CHANGELOG.md) — основной, все выпуски; [scripts/install-release.sh](../scripts/install-release.sh) — скачать, проверить и поставить выпуск (`--requirements` — что нужно и что устанавливается)
- [Руководство оператора v0.6](releases/v0.6-operator-guide.ru.md) — архитектура, домены и их распределение по парку, автоматическое развёртывание, 3x-ui, привязка узлов, доступы из центра, маршрутизация и Xray-router — всё в одном месте; протокол для ИИ-агентов — в [AGENTS.md](../AGENTS.md)
- [v0.6.0-beta.1](releases/v0.6.0-beta.1.md) — выпуск-сверка v0.2–v0.5: матрица доказательств, tier `ui` в настоящем браузере, `managed-xui`, `backup-restore`
- [v0.5.0-beta.1](releases/v0.5.0-beta.1.md) — Xray-router: выделенный egress-роутер узла (вошёл в v0.6)
- [v0.4.0-beta.1](releases/v0.4.0-beta.1.md) — маршрутизация: egress-политики с предпросмотром
- [v0.3.0-beta.1](releases/v0.3.0-beta.1.md) — центральная панель и связанные панели
- [v0.2.0-beta.1](releases/v0.2.0-beta.1.md) — локальный control plane, подписки
- [v0.1.0](releases/v0.1.0.md)

## English

### Getting started

1. [Product overview and quick start](../README.en.md)
2. [Automated installation on Ubuntu 24.04](../INSTALL.en.md)
3. [Release installer reference](INSTALLER_REFERENCE.en.md)
4. [Complete installer/auditor](../INSTALLER_AUDITOR.md)
5. [Architecture](ARCHITECTURE.md) and [compatibility contracts](COMPATIBILITY.md)

### Protocols and panel

- [Panel, roles, API keys, Telemt, and NaiveProxy](../PANEL.en.md)
- [MTProto behind Nginx SNI](../DOCKER_DEPLOYMENT.md)
- [Mieru/mita](../MIERU.en.md)
- [Mieru URL, QR, and client config sharing](MIERU_SHARING.en.md)
- [Linked panels (Fleet v2) and the legacy mTLS transport v1](../FLEET.en.md)
- [Routing: egress policies of NaiveProxy and Mieru (v0.4), the Xray-router (v0.5), chains and lanes (v0.7)](ROUTING.en.md)

### Operations

- [Daily operations runbook](OPERATIONS.en.md)
- [Backup and restore](BACKUP_RESTORE.en.md)
- [Verification matrix v0.2–v0.7](VERIFICATION_MATRIX.md)
- [Upgrade and rollback](UPGRADING.md)
- [Troubleshooting](TROUBLESHOOTING.en.md)
- [Accounting semantics](ACCOUNTING.md)
- [Validation gates](VALIDATION.md)
- [Security policy](../SECURITY.md)
- [Operating protocol for AI agents](../AGENTS.md)

### vNext architecture

- [vNext architecture](VNEXT_ARCHITECTURE.md)
- [vNext capability matrix](VNEXT_CAPABILITIES.md)
- [ADR 001 — pull-only node transport](adr/001-pull-only-node-transport.md)
- [ADR 002 — declarative generations](adr/002-declarative-generations.md)
- [ADR 003 — one writer per resource](adr/003-one-writer-per-resource.md)
- [ADR 004 — Client, AccessGrant and subscription](adr/004-client-access-grant-subscription.md)
- [ADR 005 — secret references](adr/005-secret-references.md)
- [ADR 006 — engine-neutral routing IR (accepted, v0.4)](adr/006-routing-policy-ir.md)
- [ADR 007 — routing enforcement ownership](adr/007-routing-enforcement-ownership.md)
- [ADR 008 — panel-to-panel transport with scoped API keys](adr/008-panel-to-panel-transport.md)
- [ADR 009 — lanes per client and chains through the fleet's relays (v0.7)](adr/009-lanes-and-chains.md)

### Releases

- [v0.7.0-beta.1](releases/v0.7.0-beta.1.md) — chains and lanes: exits through the fleet's relays, a grant's own lane, the `chains` tier

- [CHANGELOG.md](../CHANGELOG.md) — the changelog, every release; [CHANGELOG.ru.md](../CHANGELOG.ru.md) — in Russian (from v0.4); [scripts/install-release.sh](../scripts/install-release.sh) — fetch, verify and install a release (`--requirements` — what is needed and what gets installed)
- [Operator guide v0.6 (Russian)](releases/v0.6-operator-guide.ru.md) — architecture, domains and how they spread over a fleet, unattended deployment, 3x-ui, linking nodes, grants from the central, routing and the Xray-router in one place; the AI-agent protocol is in [AGENTS.md](../AGENTS.md)
- [v0.6.0-beta.1](releases/v0.6.0-beta.1.md) — the verification release of v0.2–v0.5: the proof matrix, the `ui` tier in a real browser, `managed-xui`, `backup-restore`
- [v0.5.0-beta.1](releases/v0.5.0-beta.1.md) — Xray-router: the node's dedicated egress router (shipped inside v0.6)
- [v0.4.0-beta.1](releases/v0.4.0-beta.1.md) — routing: egress policies with a preview
- [v0.3.0-beta.1](releases/v0.3.0-beta.1.md) — central panel and linked panels
- [v0.2.0-beta.1](releases/v0.2.0-beta.1.md) — local control plane, subscriptions
- [v0.1.0](releases/v0.1.0.md)

## Common rules

- Keep public TCP/443 under the existing host Nginx `stream` router.
- Keep every node in the single Compose project `mtproxy`.
- Persist and reuse the exact full `COMPOSE_FILE` overlay list.
- Treat `.env`, `secrets/`, access URLs, QR codes, databases, journals, and PKI as credentials.
- Back up a complete generation before changing runtime, state, identities, ports, or routes.
- A healthy process is not a protocol test. Validate MTProto `resPQ`, Naive authenticated CONNECT, and Mieru end-to-end transport.
- Never claim unavailable accounting precision.
- A linked panel (Fleet v2) is added by URL and a `node-sync` API key and is managed only after it accepted a generation; for the legacy Fleet v1, registry creation is not enrollment — enrollment requires certificate issuance, binding, mTLS authorization, and a successful command/result cycle.
