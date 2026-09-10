# Proxy Control vNext (v0.2–v0.5): Nodes, Clients, Subscriptions and Pluggable Routing Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** последовательно превратить Proxy Control в единый безопасный control plane: v0.2 — локальная node identity, клиенты и подписки; v0.3 — Fleet v2 и удалённое provisioning; v0.4 — нейтральная routing policy с native/OS enforcement; v0.5 — опциональный выделенный Xray egress-router для проверенной DNS-aware/selective маршрутизации.

**Architecture:** сохранить проверенные границы текущего Fleet v1 — outbound-only mTLS, привязку сертификата к `node_id`, строгие типы, журнал и запрет секретов — но не расширять Telemt-командную очередь до универсального RPC. Сначала центральный host получает зарезервированную local Node identity и простой application-layer UX. Затем рядом появляется Fleet v2 с декларативными неизменяемыми поколениями desired state, observed state и node-local reconcile. Клиент панели становится отдельной доменной сущностью, доступы — `AccessGrant`, а subscription — стабильной проекцией текущих доступов. Маршрутизация хранится в нейтральном policy IR и компилируется в явный enforcement backend: `native`, `os-isolation` либо опциональный `xray-router`. Xray, которым владеет 3x-ui, не становится общим source of truth.

**Tech Stack:** Python 3, FastAPI, Pydantic, SQLite/WAL, httpx, existing mTLS ingress, existing Telemt/Naive/Mieru managers, vanilla JS UI, Nginx/shared-443, WARP SOCKS5; `cryptography` для AES-GCM secret storage; native/OS routing в v0.4; отдельно pinned Proxy-Control-owned Xray binary/config/geodata в опциональном v0.5 backend.

**Target baseline:** `main` at `8c787c52d10fa7f07269bc5972eea63c77f5a392`; updated `graphify-out` contains 4,638 nodes and 13,543 edges with no missing endpoints or self-loops.

---

## 1. Executive decisions

1. **Не копировать архитектуру 3x-ui целиком.** В 3x-ui v3.7.0 multi-node использует прямые вызовы административного HTTP API дочерней панели.[1][2][3]
   Конвергенция после offline достигается двунаправленным snapshot merge.[4] Для Proxy Control лучше сохранить отдельный минимальный агентский transport и сделать master authoritative для managed resources.
2. **Fleet v1 не расширять секретными и произвольными операциями.** Его Telemt-only command queue остаётся compatibility boundary. Fleet v2 передаёт типизированный desired intent, а не shell, URL, HTTP method/path, Compose YAML или готовые runtime-конфиги.
3. **Сложность Fleet убрать из UI, а не из гарантий.** Пользователь не вводит operation, idempotency key и revision вручную. Их строит application service.
4. **Один писатель на ресурс.** После adoption запись выполняет только vNext domain service/agent. Старые protocol endpoints временно становятся compatibility façade, затем read-only.
5. **Клиент не равен username.** `Client` — человек/абонент; `AccessGrant` — конкретный доступ MTProxy, Naive или Mieru на конкретной ноде; одинаковые username автоматически не объединяются.
6. **Subscription — pull, не push.** 3x-ui отдаёт один постоянный URL, который приложение перечитывает с рекомендуемым интервалом; это не уведомление и не принудительное обновление клиента.[5][6] Proxy Control реализует стабильный URL, generation/ETag и отдельно — опциональные операторские события. Нельзя обещать автоматическое применение там, где конкретный клиент (например Telegram MTProxy) не умеет подписки.
7. **Секреты — через references.** Desired/observed state, Fleet results, audit и логи остаются secret-free. Значения хранятся шифрованно и выдаются строго конкретной ноде или одноразовому reveal.
8. **Routing policy не зависит от движка.** 3x-ui фактически редактирует Xray JSON и строковые tags.[7][8] Мы заимствуем UX — ordered rules, preview, pools, health, fallback, client picker — но используем UUID и capability-aware compilers. Enforcement выбирается явно: `native`, `os-isolation` или `xray-router`; backend substitution без подтверждения запрещён.
9. **Никакой тихой деградации.** Если правило нельзя выполнить на Naive/Mieru, preview и API возвращают `unsupported`; selective routing нельзя молча заменить whole-protocol routing. MTProxy/Telemt полностью исключён из routing scope и не показывается как routing target.
10. **Центральный host — обычная зарезервированная local Node.** Это решение принимается до импорта клиентов: существующие локальные Telemt/Naive/Mieru ресурсы получают реальный `node_id`, а не `NULL` и не второй тип target.
11. **Разделить программу на релизы.** v0.2 ограничен local Node, Client/AccessGrant, безопасным локальным create и subscription. v0.3 добавляет Fleet v2 и remote provisioning. v0.4 добавляет routing preview и только проверенные native/OS compilers. v0.5 может добавить выделенный Xray egress-router после отдельного spike и gate. Pools и selective universal routing допускаются позднее.
12. **MVP без коммерческой модели.** `Product`, billing и автоматический placement отложить. Для v0.2 достаточно `Client`, `AccessGrant`, `ClientSubscription` и local `Node`; поколения появляются в v0.3, routing policy — в v0.4.
13. **Не делить Xray runtime с 3x-ui.** Для собственных VLESS/Hysteria inbounds 3x-ui сохраняет владение своим Xray template. Общий egress-router запускается отдельным service/config/state generation и не исполняется напрямую из `/usr/local/x-ui/bin`. Проверенный Xray из staged 3x-ui artifact можно скопировать как оптимизацию только в отдельный Proxy-Control-owned path с собственным digest/provenance; отсутствие 3x-ui не должно ломать базовую routing model.

---

## 2. Что показало исследование 3x-ui

### Полезно перенести как идею

- desired/observed поля узла, отдельные transport и daemon health;
- dirty/generation marker в одной транзакции с изменением;
- anti-entropy reconcile после offline;
- initial adoption без удаления неизвестных ресурсов;
- delayed orphan deletion;
- capability-aware mixed-version behavior;
- write-only credentials и scoped tokens;
- subscription URL, собираемый из текущего состояния;
- `Profile-Update-Interval`, last fetch, несколько renderer formats;
- stable identities и last-known-good для удалённых sources;
- ordered first-match rules, pools, health, override, fallback и cycle detection.[7][9][10]

### Не переносить

- административный API полной панели как node protocol;
- долгоживущий bearer token как основной enrollment;
- opt-in encryption secrets;
- CA-wide mTLS без binding cert → node identity;
- bidirectional merge без формального field ownership;
- DB IDs, email и mutable tags как межузловую identity;
- разбросанные 404-fallback вместо version/capability handshake;
- Xray JSON как доменную модель;
- совместную запись Proxy Control и 3x-ui в один Xray template;
- иллюзию, что subscription URL сам «уведомляет» или заставляет клиент обновиться.

### Как правильно использовать Xray

Xray действительно подходит как routing engine: правила проверяются сверху вниз до первого совпадения и могут выбирать outbound или balancer по domain/geosite, IP/geoip, CIDR, port, network и inbound tag.[11] Локальный SOCKS inbound предназначен для передачи трафика от других программ, но сам SOCKS не шифруется и не должен публиковаться наружу.[12] Xray также может отправлять трафик в SOCKS5 outbound — в нашем случае в принадлежащий Proxy Control WARP endpoint.[13]

Однако изменение routing template существующего 3x-ui само по себе не направит через Xray трафик Naive или Mieru. Для этого каждый участвующий data plane должен явно подключаться к отдельному Xray ingress либо к доказанному OS/TUN enforcement path. Поэтому:

- 3x-ui-owned Xray обслуживает только собственные inbounds и не используется как универсальный router;
- dedicated `xray-router` получает отдельные private/authenticated ingress tags для Naive и Mieru;
- Naive и Mieru сначала подключаются whole-service; per-grant routing остаётся unsupported без отдельной identity propagation;
- MTProxy/Telemt не участвует в маршрутизации ни через Xray, ни через native/OS backend;
- `direct`, `WARP` и `block` компилируются в явные outbounds/rules; настройки Freedom и DNS safety фиксируются в compiler contract, а не принимаются по умолчанию.[14]

### Важное ограничение по совместимости клиентов

Один стабильный Proxy Control URL может всегда возвращать актуальный bundle, но возможности потребителей различаются:

- Telegram понимает `tg://proxy`, но не опрашивает произвольный mixed-protocol feed;
- Naive-клиенты принимают `naive+https://`/native config в зависимости от приложения;
- Mieru часто требует native JSON либо клиент-специфический профиль;
- Karing/NekoBox/Shadowrocket имеют разные матрицы импорта.

Поэтому критерий v0.2.0: **одна страница/URL управления подпиской и поддержанные auto-refresh renderers**, а не ложное обещание единого автоматически применяемого формата для любого приложения.

---

## 3. Целевая модель

```text
Client
  id: UUID
  display_name
  state: active | suspended | archived
  metadata

AccessGrant
  id: UUID
  client_id
  protocol: mtproxy | naive | mieru
  node_id
  endpoint_id
  runtime_username
  secret_ref
  desired_state
  observed_state
  valid_from / valid_until
  protocol_options_json

ClientSubscription
  id: UUID
  client_id
  public_token_hash
  generation
  state: active | revoked
  update_interval_hours
  last_fetched_at

Node
  id: stable UUID/string
  enrollment_state
  connectivity_state
  daemon_health
  capability_manifest
  last_checked_at
  last_seen_at

DesiredGeneration
  node_id
  generation
  schema_version
  digest
  resources_json
  required_capabilities
  created_by / created_at
  previous_generation

ObservedGeneration
  node_id
  applied_generation
  bundle_digest
  reconcile_state
  resource_statuses
  safe_drift_summary

SecretVersion
  secret_id / version
  purpose / grant_id / permitted_node_id
  key_id
  encrypted_payload
  state: pending | active | retiring | revoked

RoutingPolicy
  id / revision / scope
  ordered rules
  default action
  management_bypass = required

EgressProvider
  id / type: direct | warp | socks | xray-router
  capability_manifest / health

EnforcementBackend
  id: native | os-isolation | xray-router
  supported_selectors / actions / protocols
  fallback: fail-closed | explicitly-approved-direct

CompiledRoutingGeneration
  node_id / policy_revision / backend_id
  compiler_version / runtime_version
  binary_digest / geodata_digest / config_digest
  previous_generation
```

### Fleet v2 exchange

```text
agent -> POST /agent/v2/nodes/{node_id}/heartbeat
agent -> GET  /agent/v2/nodes/{node_id}/desired?after=<generation>
agent -> POST /agent/v2/nodes/{node_id}/observed
agent -> POST /agent/v2/nodes/{node_id}/secrets/resolve
agent -> POST /agent/v2/nodes/{node_id}/secret-results
```

Every request uses existing outbound mTLS and exact certificate binding. Desired bundles contain references only. A node can resolve only references bound to its own `node_id` and assigned grants. `secret-results` is a separate bounded encrypted channel for manager-generated credentials; its envelope is forbidden in desired, observed, audit and telemetry payloads.

### Reconcile phases on node

```text
acquire -> discover -> plan -> resolve secrets -> prepare -> apply
        -> verify -> commit
                    \-> compensate -> verify previous generation
```

Rollback always creates a new higher control-plane generation; the agent never accepts a lower generation. Same generation + different digest is a security conflict.

---

## 4. Sequential implementation plan

## Phase 0 — Contract freeze and decision records

### Task 1: Add v0.2.0 architecture records

**Objective:** freeze terminology, ownership and non-goals before changing code.

**Files:**
- Create: `docs/adr/001-pull-only-node-transport.md`
- Create: `docs/adr/002-declarative-generations.md`
- Create: `docs/adr/003-one-writer-per-resource.md`
- Create: `docs/adr/004-client-access-grant-subscription.md`
- Create: `docs/adr/005-secret-references.md`
- Create: `docs/adr/006-routing-policy-ir.md`
- Create: `docs/adr/007-routing-enforcement-ownership.md`
- Create: `docs/VNEXT_ARCHITECTURE.md`
- Modify: `docs/README.md`

**Steps:**
1. Record the decisions from sections 1–3 of this plan.
2. Define `managed`, `adopted`, `foreign`, `drifted` and `tombstoned` resource ownership.
3. State that Fleet v1 remains unchanged and Telemt-only.
4. State that auto-refresh depends on client capability.
5. Link ADRs from the documentation index.
6. Run `python3 scripts/check-doc-links.py`; expected: `Markdown relative links: OK`.
7. Commit: `docs: зафиксировать архитектуру Proxy Control vNext`.

### Task 2: Write characterization tests for current boundaries

**Objective:** prove current Fleet, reveal and protocol behavior before refactoring.

**Files:**
- Modify: `panel/tests/test_fleet.py`
- Modify: `panel/tests/test_agent_transport.py`
- Modify: `panel/tests/test_users_adapter_ui.py`
- Modify: `panel/tests/test_naive_management.py`
- Modify: `panel/tests/test_mieru_management.py`
- Create: `panel/tests/test_vnext_characterization.py`

**Steps:**
1. Add tests proving Fleet v1 rejects non-Telemt operations and secret-bearing payload/results.
2. Add tests proving current UI/API paths and one-time reveal semantics.
3. Add tests documenting protocol-specific username/quota/revision differences.
4. Add a fixture with same username in all three managers and prove they are currently independent.
5. Run only the new tests and verify they pass before refactoring.
6. Commit: `test: зафиксировать текущие контракты fleet и клиентов`.

### Task 3: Publish a capability matrix and spike plan

**Objective:** prevent UI promises that adapters cannot enforce.

**Files:**
- Create: `docs/VNEXT_CAPABILITIES.md`
- Create: `tests/fixtures/vnext-capabilities.json`

**Matrix rows:** create, enable, disable, rotate, delete, quota, expiry, accounting, stable access artifact, whole-service SOCKS upstream, CIDR routing, domain routing, per-client routing, hot reload, rollback, DNS ownership/preservation, SOCKS hostname propagation, TCP/UDP upstream support, service/per-grant identity propagation, fail-closed behavior, binary/config hot-upgrade and exact geodata version.

**Required conclusions for initial matrix:**
- Fleet v1: Telemt mutations only.
- Naive: whole-service upstream is available; selective/per-client routing unproven.
- Mieru: native domain rules require a dedicated adapter test; per-client routing unproven.
- MTProxy: routing is explicitly out of scope; UI and compilers reject it as a routing target.
- Unsupported cells are explicit, not blank.

Commit: `docs: добавить матрицу возможностей vNext`.

---

## Phase 1 — Database and transactional substrate

### Task 4: Introduce one database boundary and migration runner

**Objective:** allow domain mutation + audit + generation publication in one SQLite transaction.

**Files:**
- Create: `panel/database.py`
- Create: `panel/migrations.py`
- Create: `panel/tests/test_migrations.py`
- Modify: `panel/store.py`
- Modify: `panel/fleet.py`
- Modify: `panel/app.py`

**Design:**
- shared connection factory applies `foreign_keys=ON`, WAL and explicit transaction helpers;
- `schema_migrations(version, applied_at, checksum)`;
- existing table creation becomes migration baseline without renaming current tables;
- migrations are idempotent and fail closed on checksum mismatch.

**TDD:**
1. Test migration from an exact pre-v0.2 fixture.
2. Test interrupted migration rollback.
3. Test current admins/sessions/audit/Fleet rows remain readable.
4. Implement minimal runner.
5. Run `pytest -q panel/tests/test_migrations.py panel/tests/test_store.py panel/tests/test_fleet.py`.
6. Commit: `refactor: ввести единый слой миграций панели`.

### Task 5: Make audit transactional and structured

**Objective:** record business change and audit event atomically.

**Files:**
- Create: `panel/audit.py`
- Create: `panel/tests/test_audit_transactions.py`
- Modify: `panel/store.py`
- Modify: `panel/web_context.py`
- Modify: `panel/auth_routes.py`

**Design:** add `request_id`, `correlation_id`, `before_digest`, `after_digest`, `generation`, typed reason code. Do not put secret/link/upstream text into `detail_json`. Hash chaining may be added, but external signed checkpoints are deferred.

**Acceptance:** injected failure after domain write but before audit produces neither row; successful mutation produces both.

Commit: `feat: связать аудит с бизнес-транзакциями`.

### Task 6: Add encrypted secret versions

**Objective:** support durable subscriptions and remote provisioning without plaintext in the DB.

**Files:**
- Create: `panel/secrets_store.py`
- Create: `panel/tests/test_secrets_store.py`
- Modify: `panel/settings.py`
- Modify: `panel/requirements.txt`
- Modify: `panel/requirements-dev.txt`
- Modify: `compose.yaml`
- Modify: installer/backup/restore docs and tests affected by the new key file.

**Design:**
- pin `cryptography`;
- AES-256-GCM envelope with AAD binding `secret_id`, version, purpose, grant and node;
- versioned keyring loaded from `PANEL_MASTER_KEY_FILE`, never the DB: `{active_key_id, keys[{key_id,state,created_at,key_material}]}` with `active|retiring` key states;
- every encrypted envelope stores `key_id`; new writes use only `active_key_id`;
- rotation is overlap-first: add new active key, rewrap rows atomically in bounded transactions, verify all rows and backups decrypt with expected key IDs, then retire/remove the old key; rollback keeps the old key until verification completes;
- plaintext lifetime bounded to one operation;
- version states `pending/active/retiring/revoked`;
- key absence with encrypted rows fails closed.

**Threat boundary:** это защищает от кражи только БД/backup и ограничивает последствия компрометации одной ноды. Компрометация работающего процесса control plane, имеющего БД и master key, раскрывает доступные панели секреты; v0.2 не заявляет обратного.

**Negative tests:** copied ciphertext under another grant/node fails; unknown/retired key IDs fail closed; interrupted rewrap leaves every row decryptable by the overlap keyring; DB backup without key does not contain recognizable test secret; logs/errors/repr remain redacted.

Commit: `feat: добавить версионируемое хранилище секретов`.

---

## Phase 2 — v0.2: Simplify local node management before replacing Fleet

### Task 7: Split Fleet responsibilities behind interfaces

**Objective:** stop `FleetStore` being registry, PKI, command queue and projection simultaneously without changing protocol v1.

**Files:**
- Create: `panel/nodes/models.py`
- Create: `panel/nodes/registry.py`
- Create: `panel/nodes/certificates.py`
- Create: `panel/nodes/read_model.py`
- Create: `panel/nodes/service.py`
- Create: `panel/tests/test_node_lifecycle.py`
- Modify: `panel/fleet.py`
- Modify: `panel/cli.py`

**Design:** wrappers initially delegate to existing tables/methods. Keep `TypedCommand`, sequence, outbox and mTLS behavior byte-compatible.

**Acceptance:** all existing Fleet tests pass unchanged; `NodeLifecycleService` exposes enrollment, connectivity, certificates and capabilities separately.

Commit: `refactor: разделить lifecycle узлов и fleet transport`.

### Task 8: Replace raw Fleet UI with node lifecycle views

**Objective:** operator sees enrollment, identity, connectivity and health без transport-level формы команд.

**Files:**
- Create: `panel/node_routes.py`
- Create: `panel/static/js/nodes.js`
- Modify: `panel/static/js/fleet.js`
- Modify: `panel/static/index.html`
- Modify: `panel/app.py`
- Create: `panel/tests/test_node_routes.py`
- Modify: `panel/tests/test_mobile_layout.py`

**UI:**
- add node wizard;
- enrollment checklist and certificate expiry;
- `last_checked_at`, `last_seen_at`, transport state and daemon state separately;
- capabilities and versions;
- transport history remains under an Advanced drawer;
- raw command form остаётся только в compatibility/Advanced режиме до появления Client/AccessGrant.

**Backend façade:** на этом этапе только registry/enrollment/status/certificate use cases. Client/grant actions появятся после Tasks 10–12.

Commit: `feat: упростить управление узлами в панели`.

### Task 9: Add the reserved local Node identity and basic lifecycle

**Objective:** дать текущему центральному host стабильный `node_id` до импорта локальных protocol resources.

**Files:**
- Modify: `panel/nodes/service.py`
- Modify: `panel/node_routes.py`
- Modify: `panel/static/js/nodes.js`
- Modify: `panel/tests/test_node_lifecycle.py`
- Modify: `panel/migrations.py`
- Modify: `panel/app.py`

**Rules:**
- migration creates exactly one reserved local Node identity idempotently;
- local Telemt/Naive/Mieru managers are associated with this identity;
- support rename, disable and certificate state without referencing grants that do not exist yet;
- revoke all active certificates only after explicit confirmation;
- retain command/audit history;
- drain/decommission guard is completed after Task 11 imports grants;
- physical deletion is deferred and not included in v0.2 UI.

Commit: `feat: добавить безопасный lifecycle вывода ноды`.

---

## Phase 3 — v0.2: Unified local clients without unsafe automatic merging

### Task 10: Add Client and AccessGrant tables

**Objective:** establish stable identities independent of protocol usernames.

**Files:**
- Create: `panel/clients/models.py`
- Create: `panel/clients/store.py`
- Create: `panel/clients/service.py`
- Create: `panel/tests/test_clients_domain.py`
- Modify: `panel/migrations.py`

**Invariants:**
- UUID primary identities;
- one grant belongs to one client and one node;
- every imported local grant references the reserved local Node from Task 9;
- `runtime_username` uniqueness is scoped by protocol + node + endpoint;
- protocol-specific options remain typed JSON validated by Pydantic;
- no secret value in grants;
- suspended client compiles every grant as disabled.

Commit: `feat: добавить доменную модель клиентов и доступов`.

### Task 11: Implement read-only import and explicit linking

**Objective:** bring existing Telemt/Naive/Mieru users into the new view without accidental identity merges.

**Files:**
- Create: `panel/clients/importer.py`
- Create: `panel/client_routes.py`
- Create: `panel/static/js/clients.js`
- Create: `panel/tests/test_client_import.py`
- Modify: `panel/app.py`
- Modify: `panel/static/index.html`

**Flow:** inventory → proposed matches → conflicts → operator confirmation → imported client/grant rows. Same username is only a suggestion. Credentials unavailable as plaintext require rotation before subscription enablement.

**Acceptance:** rerunning import is idempotent; conflicting same-name accounts remain separate by default; import makes no manager mutation. После импорта decommission блокируется при active grants или pending commands и разрешается только после drain/reassignment.

Commit: `feat: добавить безопасный импорт существующих клиентов`.

### Task 12: Define credential-origin and idempotency contracts, then one protocol adapter interface

**Objective:** сделать потерю ответа после manager commit восстановимой и только затем унифицировать Telemt/Naive/Mieru adapters.

**Files:**
- Create: `panel/protocols/base.py`
- Create: `panel/protocols/telemt.py`
- Create: `panel/protocols/naive.py`
- Create: `panel/protocols/mieru.py`
- Create: `panel/tests/test_protocol_adapter_contract.py`
- Modify: `naive_manager/service.py`
- Modify: `naive_manager/server.py`
- Modify: `mieru_manager/service.py`
- Modify: `mieru_manager/server.py`
- Modify: corresponding manager contract/recovery tests
- Modify: `panel/telemt.py`
- Modify: `panel/naive.py`
- Modify: `panel/mieru.py`

**Credential rules:**
- Naive and Mieru managers gain typed `operation_id` plus caller-supplied credential/version so create/rotate is idempotent and replayable.
- Telemt currently generates credentials upstream. Its adapter uses a durable operation-result record; after lost response it must either recover the current access artifact or perform one idempotently journaled rotation that invalidates the unknown credential.
- No adapter may report success before the generated/recovered secret is durably escrowed or explicitly marked `manual_intervention_required`.
- Tests inject response loss after manager commit for every protocol.

**Interface:**
```python
class ProtocolAdapter(Protocol):
    async def discover(self) -> ObservedInventory: ...
    async def preflight(self, intent: GrantIntent) -> Preflight: ...
    async def create(self, operation_id: UUID, intent: GrantIntent, credential: CredentialPlan) -> AppliedGrant: ...
    async def enable(self, grant: GrantRef) -> AppliedGrant: ...
    async def disable(self, grant: GrantRef) -> AppliedGrant: ...
    async def rotate(self, operation_id: UUID, grant: GrantRef, credential: CredentialPlan) -> AppliedGrant: ...
    async def delete(self, grant: GrantRef) -> None: ...
    async def render_artifacts(self, grant: GrantRef) -> list[AccessArtifact]: ...
```

Quota/accounting types remain protocol-qualified.

Commit: `refactor: унифицировать контракт protocol adapters`.

### Task 13: Implement durable local provisioning saga

**Objective:** create several grants from one panel form without pretending there is distributed ACID.

**Files:**
- Create: `panel/clients/provisioning.py`
- Create: `panel/tests/test_provisioning_saga.py`
- Modify: `panel/migrations.py`
- Modify: `panel/client_routes.py`
- Modify: `panel/static/js/clients.js`

**Flow:** validate all → reserve names → create pending secret versions where credentials are caller-supplied → persist operation IDs → sequential adapter apply → durably escrow caller- or manager-generated credentials → readback → activate grant/secrets → build one-time bundle. On failure compensate only resources created by this operation; pre-existing resources are never deleted.

**Fault tests:** fail before first apply, after each protocol apply, during compensation, after manager commit before response, and after response before central DB commit. Restart must resume by `operation_id`; every outcome is `succeeded`, `compensated`, or `manual_intervention_required`.

Commit: `feat: добавить журналируемое создание нескольких доступов`.

### Task 14: Route legacy protocol endpoints through the domain service

**Objective:** eliminate dual writers while preserving compatibility paths.

**Files:**
- Modify: `panel/telemt_routes.py`
- Modify: `panel/naive_routes.py`
- Modify: `panel/mieru_routes.py`
- Modify: `panel/tests/test_users_adapter_ui.py`
- Modify: `panel/tests/test_naive_management.py`
- Modify: `panel/tests/test_mieru_management.py`

**Rollout:** feature flag first; legacy request becomes domain intent; old response shape is rendered from the new operation result. Direct manager writes are forbidden after cutover.

Commit: `refactor: направить старые API клиентов через единый сервис`.

---

## Phase 4 — v0.2: Real subscription service

### Task 15: Add subscription token lifecycle and generation

**Objective:** give every Client one revocable stable URL with explicit generation.

**Files:**
- Create: `panel/subscriptions/models.py`
- Create: `panel/subscriptions/store.py`
- Create: `panel/subscriptions/service.py`
- Create: `panel/tests/test_subscription_lifecycle.py`
- Modify: `panel/migrations.py`

**Rules:** token plaintext shown once; DB stores hash; rotate revokes old URL; enable/disable/grant/artifact change increments generation in the same transaction; last fetch is audit metadata, not `Last-Modified` fiction. Generation describes persisted mutations, while HTTP validators use the canonical effective output digest so time-based expiry cannot leave a stale ETag.

Commit: `feat: добавить lifecycle клиентских подписок`.

### Task 16: Implement canonical manifest and protocol renderers

**Objective:** render current active grants without storing complete access URLs.

**Files:**
- Create: `panel/subscriptions/renderers/base.py`
- Create: `panel/subscriptions/renderers/manifest.py`
- Create: `panel/subscriptions/renderers/raw.py`
- Create: `panel/subscriptions/renderers/karing.py`
- Create: `panel/tests/test_subscription_renderers.py`
- Modify: `panel/static/js/access.js`

**Canonical media type:** `application/vnd.proxy-control.subscription+json;version=1`.

**Renderers:**
- MTProxy `tg://proxy` artifact;
- Naive native URI/config plus only verified client-specific variants;
- Mieru native config plus only verified variants;
- unsupported combinations are represented as instructions/status, not malformed links.

**Security:** response assembly resolves secrets in memory; no rendered URL in DB, logs, audit or exception messages; response size bounded.

Commit: `feat: добавить форматы подписки MTProxy Naive и Mieru`.

### Task 17: Add public subscription endpoint with correct HTTP semantics

**Objective:** support polling efficiently and safely.

**Files:**
- Create: `panel/subscription_routes.py`
- Create: `panel/tests/test_subscription_http.py`
- Modify: `panel/app.py`
- Modify: Nginx templates, installer ownership and access-log configuration for the public subscription location.
- Modify: application request logging/middleware to redact subscription paths.

**Contract:**
- `GET|HEAD /s/{opaque_token}`;
- explicit `format=manifest|raw|karing|html` and content negotiation;
- `ETag` derived on every request from canonical **effective** grant IDs, secret version IDs, endpoint/protocol options, active time boundaries and renderer version;
- `If-None-Match` → 304;
- `Cache-Control: private, no-cache` and no shared caching;
- `Profile-Update-Interval` as a hint, not a guarantee;
- generic 404 for absent/revoked tokens;
- rate and body bounds; mandatory redacted/off access logs for `/s/`; no token in application logs, audit, proxy logs or telemetry.

**Time-boundary test:** fetch before `valid_until`, advance the injected clock past expiry, repeat with the old `If-None-Match`; expected: new ETag/body, never 304 with the expired grant.

Commit: `feat: опубликовать обновляемый subscription endpoint`.

### Task 18: Build one subscription UI and compatibility matrix

**Objective:** make one understandable screen for create/copy/rotate/status.

**Files:**
- Create: `panel/static/js/subscriptions.js`
- Modify: `panel/static/index.html`
- Modify: `panel/static/css/*.css` as required
- Modify: `panel/tests/test_mobile_layout.py`
- Create: `panel/tests/test_subscription_ui_contract.py`

**UI:** current generation, last fetch, included grants, copy/QR, renderer/client compatibility, rotate/revoke, warning that Telegram and some native clients do not auto-refresh.

Commit: `feat: добавить единое окно подписки`.

### Task 19: Add subscription change events without claiming client push

**Objective:** separate feed update from notifications.

**Files:**
- Create: `panel/events.py`
- Create: `panel/tests/test_subscription_events.py`
- Modify: `panel/subscriptions/service.py`

Emit `subscription.generation.changed`, `subscription.fetched`, `subscription.revoked`. In v0.2.0 events feed audit/UI; Telegram/webhook delivery is a separate optional follow-up. No event claims that an end-user client applied the change.

Commit: `feat: добавить события изменений подписки`.

### Task 19A: Pass the v0.2 local control-plane release gate

**Scope:** Tasks 1–19 only. Fleet v2 and writable routing are neither required nor advertised.

**Required evidence:** full repository lint/unit suite; all Telemt/Naive/Mieru local manager contract tests; lost-response recovery for every credential mode; real local create/handshake/rotate/delete for all three protocols; subscription renderer compatibility; token-log canary scan; expiry + `If-None-Match`; DB-only secret inspection; master-key install/backup/restore/rotation and fail-closed recovery. Restore into an isolated environment and prove existing subscriptions render without printing credentials.

**Release rule:** `v0.2.0` cannot be tagged until this matrix, an independent security review and artifact verification pass. Failures in future Fleet/routing tests do not block v0.2 because those surfaces are absent/disabled.

---

## Phase 5 — v0.3: Fleet v2 declarative generations and remote provisioning

### Task 20: Define protocol v2 schemas and capability handshake

**Objective:** allow mixed v1/v2 nodes without ad hoc 404 fallbacks.

**Files:**
- Create: `panel/fleet_v2/protocol.py`
- Create: `panel/fleet_v2/capabilities.py`
- Create: `panel/tests/test_fleet_v2_protocol.py`
- Modify: `panel/schemas.py`

**Schemas:** exact fields, size limits, canonical JSON digest, min/max schema, known capability IDs, required/optional capabilities. Include backend/compiler/runtime/geodata versions and selector/action/protocol support in the capability manifest. Include `SecretResultUpload(operation_id,result_id,grant_id,secret_version,ingress_key_id,ephemeral_public_key,nonce,ciphertext,aad_digest)` and `SecretResultReceipt(operation_id,result_id,stored_secret_version,receipt_digest)`. Unknown required resource fails compilation.

**Negative tests:** lower generation, same generation/different digest, unknown resource, oversized bundle, secret-bearing value, cert for another node.

Commit: `feat: определить протокол поколений fleet v2`.

### Task 21: Add immutable desired/observed stores

**Objective:** persist generation history and node convergence state.

**Files:**
- Create: `panel/fleet_v2/store.py`
- Create: `panel/tests/test_fleet_v2_store.py`
- Modify: `panel/migrations.py`

**Tables:** desired generations, observed snapshots, resource statuses, capability manifests and secret-result receipts. Publish domain change + audit + generation atomically. Secret-result ingestion atomically inserts one encrypted `SecretVersion` and its operation receipt. Rollback copies old desired content into a new generation.

Commit: `feat: хранить desired и observed поколения нод`.

### Task 21A: Connect domain mutations to generation publication through one Unit of Work

**Objective:** гарантировать, что remote Client/AccessGrant mutation, audit, subscription projection change и desired generation появляются либо вместе, либо не появляются вовсе.

**Files:**
- Create: `panel/unit_of_work.py`
- Create: `panel/tests/test_domain_generation_atomicity.py`
- Modify: `panel/clients/service.py`
- Modify: `panel/clients/provisioning.py`
- Modify: `panel/subscriptions/service.py`
- Modify: `panel/fleet_v2/store.py`
- Later modify: `panel/routing/service.py` when Phase 6 exists.

**Tests:** create/disable/rotate/delete remote grant; inject failure before and after generation insert; verify no orphan domain row, audit row, subscription bump or desired generation. Local-only mutations do not publish remote generations.

Commit: `feat: связать доменные изменения с desired поколениями`.

### Task 22: Add v2 mTLS ingress endpoints

**Objective:** reuse proven identity boundary with a smaller declarative API.

**Files:**
- Create: `panel/fleet_v2/transport.py`
- Create: `panel/fleet_v2/routes.py`
- Create: `panel/tests/test_fleet_v2_transport.py`
- Modify: `panel/agent_transport.py`
- Modify: `panel/agent_ingress.py`
- Modify: `panel/settings.py`
- Modify: `deploy/mtproxy-fleet-ingress.service`
- Modify: `compose.fleet-central.yaml`
- Modify: fleet ingress environment generation, both supported deployment paths, installer/restore/deployment tests.

**Rules:** exact node cert binding; GET desired only for own node; resolve only own secrets; strict bounds/rate limits/timeouts; no generic manager proxy; responses no-store where secret-bearing. `POST .../secret-results` binds cert→node and grant→node, authenticates the envelope AAD, enforces payload/time bounds and anti-replay, then atomically stores the secret version plus receipt. Repeating the same `(operation_id,result_id,payload digest)` returns the same receipt; a different payload for either bound identifier returns conflict. Neither request bodies nor envelopes enter access/error/audit/observed/telemetry logs.

Provision the versioned at-rest keyring from `PANEL_MASTER_KEY_FILE` and the asymmetric ingress keyring from `PANEL_SECRET_INGRESS_KEYRING_FILE`, both with root-controlled creation and the minimum ACL needed by the dedicated `panel` ingress identity in both deployment paths. Define active-key selection, overlap-first rotation, bounded atomic rewrap, old-key retention until all-row verification, rollback and fail-closed missing/wrong-key recovery. The current ingress public key/key ID is distributed in the authenticated capability handshake; the private key remains central. The agent uses ephemeral X25519 + HKDF + AES-GCM to encrypt the result, and the central endpoint decrypts it only long enough to re-wrap it under the active at-rest master key. Rotation overlaps old/new ingress public keys until all journaled envelopes are acknowledged. Tests cover install/backup/restore, ingress restart during both overlaps and decryptability verification without printing plaintext. The acknowledged residual boundary is that a compromised central ingress/panel runtime can access panel secrets.

Commit: `feat: добавить mTLS transport fleet v2`.

### Task 23: Implement node-local generation journal and coordinator

**Objective:** replace indeterminate command outcomes with reconcile to desired or exact previous state.

**Files:**
- Create: `panel/fleet_v2/agent_journal.py`
- Create: `panel/fleet_v2/reconcile.py`
- Create: `panel/tests/test_generation_reconcile.py`
- Modify: `panel/agent_service.py`
- Modify: `compose.agent.yaml`

**Tests:** fault injection at each phase; reboot recovery; management-channel bypass; exact backup/readback; idempotent replay; rollback failure stops automatic mutation. The journal stores the exact previous compiled routing generation/backend digest before apply. The agent journals each manager-generated encrypted result until it receives a matching central receipt, then records acknowledgement before deleting local result material.

Commit: `feat: добавить node-local reconcile поколений`.

### Task 24: Add Telemt, Naive and Mieru node adapters

**Objective:** apply AccessGrants remotely through fixed local boundaries.

**Files:**
- Create: `panel/fleet_v2/adapters/base.py`
- Create: `panel/fleet_v2/adapters/telemt.py`
- Create: `panel/fleet_v2/adapters/naive.py`
- Create: `panel/fleet_v2/adapters/mieru.py`
- Create: `panel/tests/test_node_adapters.py`
- Modify: `deploy/Dockerfile.agent`
- Modify: `compose.agent.yaml`

Reuse existing manager transaction/revision semantics. Agent receives typed intent and secret references for caller-supplied credentials. Manager-generated credentials are persisted under the operation ID, encrypted to the authenticated current central secret-ingress public key and posted to `/agent/v2/nodes/{node_id}/secret-results`; the local journal/envelope remains replayable until the exact receipt is acknowledged. It never receives the at-rest master key and never accepts arbitrary path/URL/body.

**Lost-response contract:** manager commit → response loss resumes by `operation_id`; central secret insert → acknowledgement loss replays the identical envelope and receives the same receipt; same ID with a different payload conflicts; restart at either boundary cannot create a second active grant or lose the only subscription credential.

**Live acceptance per adapter:** create → handshake → disable → failed handshake → rotate → old credential fails/new succeeds → delete → reboot persistence.

Commit: `feat: подключить protocol adapters к fleet v2`.

### Task 25: Run shadow adoption and one-node canary cutover

**Objective:** migrate without two writers or destructive first sync.

**Files:**
- Create: `panel/fleet_v2/adoption.py`
- Create: `panel/tests/test_fleet_v2_adoption.py`
- Modify: `panel/static/js/nodes.js`
- Modify: operations/migration documentation.

**Sequence:**
1. report-only observed inventory;
2. explicit ownership decision for every resource;
3. baseline desired generation must compile to a no-op;
4. stop new v1 mutations for canary node;
5. drain v1 outbox and resolve `indeterminate` entries;
6. backup DB and node state;
7. activate v2 writer;
8. run real protocol probes;
9. retain tested rollback to v1.

Commit: `feat: добавить безопасное adoption fleet v2`.

### Task 25A: Pass the v0.3 Fleet v2 release gate

**Scope:** cumulative v0.2 plus Tasks 20–25. Routing remains preview-disabled and is not advertised.

**Required evidence:** v1/v2 compatibility suite; cert binding and cross-node denial; desired/observed digest/replay/downgrade tests; secret-result manager-commit/central-commit lost-response tests; at-rest and ingress key overlap/rotation/restart; DB + keyrings + node journal backup/restore; offline convergence; reboot during apply; shadow adoption no-op; one-node canary create/rotate/delete using real clients; verified rollback to v1 without dual writers.

**Release rule:** `v0.3.0` cannot be tagged until the isolated migration lab, per-adapter rollback, security review and artifact verification pass.

---

## Phase 6 — v0.4: Xray-independent policy with native/OS enforcement

### Task 26: Define neutral routing IR and preview API

**Objective:** deliver the convenient 3x-ui editing model without Xray types.

**Files:**
- Create: `panel/routing/models.py`
- Create: `panel/routing/store.py`
- Create: `panel/routing/compiler.py`
- Create: `panel/routing/routes.py`
- Create: `panel/tests/test_routing_ir.py`
- Modify: `panel/migrations.py`
- Modify: `panel/app.py`

**Objects:** immutable UUIDs for policies, rules, subjects, egress endpoints and pools; first-match priority; scopes `control_plane`, `service`, `access_grant`; actions `direct`, `block`, `egress`, `pool`; explicit `backend_id`; explicit default; `fallback=fail-closed|explicitly-approved-direct`; management bypass required. Compiler must never substitute another backend or direct egress silently.

**Preview response per target:** `supported`, `unsupported`, `warnings`, compiled diff, affected services/nodes, restart requirement, rollback plan. Preview performs no mutation.

Commit: `feat: добавить нейтральную модель маршрутизации`.

### Task 27: Build routing UI

**Objective:** provide 3x-ui-level usability while exposing real applicability.

**Files:**
- Create: `panel/static/js/routing.js`
- Modify: `panel/static/index.html`
- Modify: responsive styles
- Create: `panel/tests/test_routing_ui_contract.py`
- Modify: `panel/tests/test_mobile_layout.py`

**UI:** ordered drag/drop rules, enable/disable, client/grant/service picker, destination/CIDR/port selectors, egress picker, compiled preview per node and unsupported reason. Apply remains disabled until the target manager exposes a verified writable egress capability. Mutable names are labels only; references use UUIDs.

Commit: `feat: добавить редактор и preview маршрутизации`.

### Task 28: Extract egress provider lifecycle from `[three_xui]`

**Objective:** make WARP an independent provider and preserve existing TOML behavior.

**Files:**
- Create: `installer/model.py` top-level egress types or a dedicated `installer/egress_model.py`
- Modify: `installer/config.py`
- Modify: `installer/planner.py`
- Modify: `installer/adapters/warp.py`
- Modify: `installer/wizard.py`
- Create/modify: `tests/test_installer_warp_protocol_selection.py`
- Add migration tests for old `[three_xui].warp*`.

**Migration:** dual-read old keys; render/round-trip old configs unchanged; new `[egress]` becomes canonical only after explicit migration. Remove the accidental coupling that leaves Naive/Mieru direct whenever `[three_xui].warp_domains` is non-empty; selection is made per service/backend. Do not reinstall working WARP or change ownership.

Commit: `refactor: отделить WARP от конфигурации 3x-ui`.

### Task 29: Add typed transactional egress APIs to Naive and Mieru managers

**Objective:** create a real writable enforcement boundary before any routing compiler is allowed to apply.

**Files:**
- Modify: `naive_manager/service.py`
- Modify: `naive_manager/server.py`
- Modify: `naive_manager/tests/*`
- Modify: `mieru_manager/service.py`
- Modify: `mieru_manager/server.py`
- Modify: `mieru_manager/tests/*`
- Modify: `panel/naive.py`
- Modify: `panel/mieru.py`
- Modify: `compose.naive.yaml`
- Modify: `compose.mieru.yaml`
- Modify: `compose.agent.yaml`
- Create: `panel/tests/test_egress_manager_contract.py`

**Contract:** typed `get/plan/apply/rollback egress`, optimistic revision, exact readback hash, durable manager journal and bounded reason codes. Agent receives access only to fixed UDS/token endpoints; no generic config/file RPC. Verify WARP reachability from each service network namespace before apply. Do not add an egress API or routing adapter to Telemt.

**Acceptance:** failed validate/apply/readback/reload and process crash all restore exact previous egress or return `manual_intervention_required`; adjacent Caddy/mita state is unchanged. Routing UI/API reject MTProxy targets as `out_of_scope`.

Commit: `feat: добавить транзакционные egress API managers`.

### Task 30: Run an isolated routing-engine spike

**Objective:** decide how to support future selective routing while preserving engine-independent policy and single ownership.

**Artifacts:**
- Create: `docs/spikes/VNEXT_ROUTING_ENGINE.md`
- Create disposable lab only; no production changes.

**Compare:**
1. native manager/upstream support;
2. process/service isolation with netns/cgroup + WireGuard/TUN;
3. mutation of the 3x-ui-owned Xray template through its whole-document API — expected to be rejected as the universal backend if writer-collision tests fail;
4. dedicated Proxy-Control-owned Xray with separately pinned binary/geodata;
5. dedicated Xray seeded by copying an exact verified bundled artifact into a separate owned path — never direct execution from `/usr/local/x-ui/bin`;
6. another dedicated DNS-aware engine such as sing-box, only if it beats the same gates.

**Required probes:** TCP/UDP, SOCKS hostname vs pre-resolved IP, DNS semantics/leaks, shared CDN domains, separate ingress identity per service, management bypass, ACME/DNS/panel survival, reboot, crash, WARP loss, rollback, stale geodata, adjacent nftables/Nginx preservation, 3x-ui concurrent edits/restart/upgrade isolation and real Naive/Mieru clients. Add a negative contract test proving MTProxy cannot be selected.

**Decision gate:** choose a universal selective-routing adapter only if all failure and rollback tests pass. Otherwise v0.4 ships capability-limited routing honestly.

Commit: `docs: зафиксировать результаты routing spike`.

### Task 31: Implement only the routing compilers proven by Tasks 29–30

**Objective:** turn preview into apply only for verified v0.4 native/OS enforcement targets.

**Files:**
- Create: `panel/fleet_v2/adapters/routing.py`
- Create: `panel/routing/adapters/naive.py`
- Create: `panel/routing/adapters/mieru.py`
- Create: `panel/tests/test_routing_compilers.py`
- Modify: `panel/static/js/routing.js`

**Initial candidates, not promises:** direct; explicit block by CIDR/port where enforcement is clear; whole-Naive → WARP; whole-Mieru → WARP; native Mieru domain rules after live proof. Every compiled generation records backend/runtime/compiler versions and exact digests.

**Must fail compilation:** any MTProxy target; unsupported per-client routing; selective Naive domain routing without a proven adapter; SOCKS5 used as if it were a Linux route target.

**Deferred beyond v0.4:** pools, least-latency, fallback chains and remote routing sources. They require stable health semantics and are not part of the first writable routing release.

Commit: `feat: включить проверенные routing compilers`.

### Task 31A: Pass the v0.4 routing release gate

**Scope:** cumulative v0.2/v0.3 plus Tasks 26–31. Only capabilities with passing compilers are enabled; pools and unproven selective routing remain absent.

**Required evidence:** IR order/default/backend/fallback/capability tests; preview/apply parity; typed manager `get/plan/apply/rollback` contract tests; WARP reachability from each supported service namespace; real direct/WARP/block distinction; crash/reboot/failed-readback rollback; immutable management-channel survival for every accepted policy; adjacent Nginx/nftables snapshot/digest equality; unsupported per-client/selective rules and unavailable Xray backend fail closed without implicit substitution.

**Release rule:** `v0.4.0` cannot be tagged until each enabled compiler target has isolated-system evidence, independent network/security review and artifact verification. One unsupported backend does not lower semantics silently; it stays preview-only.

---

## Phase 7 — v0.5: Optional dedicated Xray egress-router

### Task 32: Freeze Xray-router topology and ownership after the spike

**Objective:** accept Xray only as an isolated enforcement backend, never as a second writer of 3x-ui runtime policy.

**Files:**
- Create: `docs/spikes/XRAY_EGRESS_ROUTER.md`
- Finalize: `docs/adr/007-routing-enforcement-ownership.md`
- Modify: `docs/VNEXT_CAPABILITIES.md`

**Decision contract:** dedicated service, config, state and lifecycle; no direct execution from `/usr/local/x-ui/bin`; no public SOCKS listener; one authenticated/private ingress identity and tag per source service; explicit fail-closed or operator-approved direct fallback; no per-client claim without identity propagation. Existing/foreign 3x-ui remains read-only. Managed-new 3x-ui may receive only a static, explicitly owned bridge to the dedicated router after concurrent-writer, upgrade and rollback tests pass; changing user policies never rewrites the 3x-ui template.

**Artifact decision:** independently pin Xray binary plus geoip/geosite and their digests in the Proxy Control release catalog. A staged 3x-ui bundle may seed a byte-identical copy into the Proxy-Control-owned path only when version and digest equal the router catalog; otherwise provision the independent artifact. Never couple router restart to x-ui restart.

Commit: `docs: зафиксировать ownership выделенного Xray router`.

### Task 33: Add the dedicated Xray-router runtime and typed manager

**Objective:** provide an isolated transactional runtime boundary before enabling an Xray compiler.

**Files:**
- Create: `installer/adapters/xray_router.py`
- Modify: `installer/egress_model.py`
- Modify: `installer/config.py`
- Modify: `installer/planner.py`
- Add: pinned Xray/geodata entries to the release catalog and manifest tests.
- Create: `deploy/proxy-control-xray-router.service`
- Create: `xray_router_manager/models.py`
- Create: `xray_router_manager/service.py`
- Create: `xray_router_manager/server.py`
- Create: `xray_router_manager/Dockerfile`
- Create: `xray_router_manager/tests/*`
- Create: `compose.xray-router.yaml`

**Boundary:** non-root Xray service, read-only binary/filesystem, dedicated owned config and generation directory, bounded redacted logs, no admin API, no shared config with x-ui. Runtime configs containing ingress credentials are minimum-ACL files readable only by the router identity; credentials originate from scoped `SecretVersion` references, never enter desired/observed/audit/logs and use an encrypted backup procedure. The manager accepts only typed `XrayRoutingIntent` plus expected deterministic digest, recompiles locally, runs `xray run -test`, atomically swaps the config, restarts/reloads, performs exact readback and probes, then commits or restores the last-known-good generation. Raw arbitrary Xray JSON/file paths/list URLs are rejected.

**Ingress security:** separate loopback port/tag and credential per supported service. If a client backend cannot authenticate to SOCKS, it remains unsupported until a UDS or network-namespace boundary with equivalent isolation is proven; unauthenticated host/bridge SOCKS is forbidden.

Commit: `feat: добавить выделенный Xray egress router`.

### Task 34: Compile neutral RoutingPolicy into Xray generations

**Objective:** reproduce the convenient Xray list/rule workflow without exposing Xray JSON in the panel domain model.

**Files:**
- Create: `panel/routing/adapters/xray_router.py`
- Create: `panel/tests/test_xray_routing_compiler.py`
- Modify: `panel/routing/compiler.py`
- Modify: `panel/fleet_v2/capabilities.py`
- Modify: `panel/static/js/routing.js`

**Compiler:** deterministic ordered rules keyed by dedicated `inboundTag`; selectors limited to proven domain/full/regexp/geosite, IP/CIDR/geoip, port and network semantics; explicit `direct`, `WARP SOCKS5`, `block` and later proven balancers. Output records policy/backend/compiler/Xray/geodata versions and digests. Same policy revision with another compiled digest is a conflict. Remote list updates are bounded, pinned and digested; a fetch failure keeps last-known-good and never substitutes an empty list.

**Safety:** preserve an immutable management/control bypass outside user-editable policy; prevent route loops to WARP, the router itself, DNS bootstrap, panel, Fleet mTLS, ACME, manager UDS/API and health probes. An unavailable required provider fails closed unless the policy explicitly chose direct fallback.

Commit: `feat: компилировать policy в Xray routing generation`.

### Task 35: Connect protocol data planes to dedicated Xray ingresses

**Objective:** enable only traffic paths proven end-to-end.

**Files:**
- Modify: `naive_manager/*` and `panel/naive.py`
- Modify: `mieru_manager/*` and `panel/mieru.py`
- Modify only for managed-new static bridge: `installer/three_xui_api.py`, `installer/adapters/three_xui.py` and exact contract tests.
- Create: `panel/tests/test_xray_protocol_bridges.py`

**Paths:**
- Naive → authenticated loopback SOCKS ingress tagged `naive` → Xray rule → direct/WARP/block;
- Mieru → its own authenticated/private SOCKS ingress tagged `mieru` → Xray rule → direct/WARP/block, with UDP capability disabled until SOCKS UDP ASSOCIATE is proven by a destination-level test;
- managed-new 3x-ui → optional static outbound/route bridge tagged `three-xui`; its scoped SOCKS credential is installed from `SecretVersion` through the bounded managed-new transaction, redacted from readback/logs and rotated overlap-first with an exact template snapshot. User policy mutations remain entirely in the dedicated router. `existing` is never mutated without a separate explicit adoption transaction.
- MTProxy/Telemt has no route, ingress, compiler or migration path in this phase.

**No claim:** separate service tags provide service-level, not per-client, identity. Per-grant routing stays unsupported until the source manager can map each grant to a distinct authenticated ingress/tag.

Commit: `feat: подключить сервисы к Xray router`.

### Task 36: Pass the v0.5 Xray-router release gate

**Scope:** cumulative v0.2–v0.4 plus Tasks 32–35. The router is optional; installations without it retain v0.4 native/OS behavior.

**Required evidence:** distinct authenticated ingress isolation; denial without/wrong cross-service credentials; Naive hostname propagation and real TCP egress; Mieru TCP and separate UDP proof; explicit MTProxy target rejection; domain/geosite/geoip/CIDR/port ordered-rule parity; direct/WARP/block distinction; DNS leak and shared-CDN tests; router/WARP/DNS kill; SIGKILL during config swap; reboot; stale/corrupt geodata; exact rollback of config/binary-compatible generation; ingress credential rotation and secret scans; 3x-ui restart/upgrade isolation; static bridge drift detection; no mutation of foreign 3x-ui; management/ACME/Fleet survival; no silent direct fallback; measured idle/load CPU and RSS budget for the second Xray process.

**Release rule:** `v0.5.0` cannot be tagged until every enabled protocol/backend cell passes its live matrix, independent network/security review and exact artifact verification. Failed cells remain `unsupported`; they do not block protocols not advertising that capability.

---

## Phase 8 — Cumulative migration, operations and release hardening

### Task 37: Update installer, backup and restore contracts

**Objective:** make vNext state fully recoverable without changing frozen runtime identifiers.

**Files likely to change:**
- `installer/*`
- `scripts/proxyctl.py`
- `docs/BACKUP_RESTORE.ru.md`
- `docs/BACKUP_RESTORE.en.md`
- `docs/COMPATIBILITY.md`
- `docs/OPERATIONS.ru.md`
- `docs/OPERATIONS.en.md`
- `tests/test_deploy.py`
- relevant installer tests.

**Preserve:** Compose project `mtproxy`, existing volumes, `/var/lib/mtproxy-panel`, `/etc/mtproxy-agent`, `/var/lib/mtproxy-agent`, existing unit names, URI SAN prefix and shared-443 ownership markers. The new `proxy-control-xray-router` identity, binary/config/generation paths and ports are separately frozen after v0.5 alpha and may not alias the 3x-ui tree or listeners.

**Backup:** central DB, separate master-key procedure, desired history, node journal, last applied generation and exact pre-cutover state. When v0.5 is enabled, include Xray-router config generations, compiler/runtime/geodata digests, owned ingress credentials and the previous binary-compatible generation; artifacts themselves remain restored from verified release pins. Restore must verify DB integrity and secret decryptability without printing values.

Commit: `feat: расширить backup и restore для vNext`.

### Task 38: Add staged rollout controls

**Objective:** prevent one bad generation from reaching the whole fleet.

**Files:**
- Create: `panel/rollouts.py`
- Create: `panel/tests/test_rollouts.py`
- Modify: nodes UI/API.

**Flow:** preview → explicit approval → one canary → observe → continue batch. Stop automatically on reconcile failure, rollback, capability drift or failed protocol health. Xray binary/geodata upgrade is a separate rollout from policy generation; both retain compatible last-known-good artifacts. Report per-node outcome.

Commit: `feat: добавить canary rollout поколений`.

### Task 39: Complete negative-path and security test matrix

**Objective:** prove that the public/control protocol is not a generic remote-execution surface, DB-only compromise does not reveal credentials, and one compromised node cannot fetch another node’s bundles/secrets. Explicitly do **not** claim resistance to compromise of the live central panel process holding DB access and the master key.

**Test targets:**
- unknown/missing/expired/revoked/wrong-node cert;
- node A requesting node B bundle/secret;
- replay/downgrade/digest conflict;
- oversized/compressed requests;
- secret scans across DB export, API, logs, audit, desired/observed;
- SSRF for any remote source;
- crash after every reconcile checkpoint;
- routing management lockout attempt;
- two-writer conflict;
- subscription token enumeration/rotation/cache behavior;
- malicious protocol manager response with secret-bearing text.
- unauthenticated/cross-service SOCKS access and backend substitution;
- concurrent/manual 3x-ui routing edit, static-bridge drift and Xray/geodata digest mismatch.

Commit: `test: закрыть негативные сценарии vNext`.

### Task 40: Run repository and isolated-system gates

**Objective:** establish release-grade evidence.

**Commands:**
```bash
.venv/bin/ruff check .
sudo .venv/bin/python -m pytest -q
.venv/bin/python -m unittest -v tests/test_deploy.py
python3 scripts/check-doc-links.py
node --check panel/static/app.js
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
shellcheck install-bootstrap
for unit in deploy/*.service; do systemd-analyze verify "$unit"; done
git diff --check
```

Then build all affected images and run the project’s isolated systemd-container/QEMU lifecycle. Add real client probes for all three protocols, subscription refresh, v1→v2 adoption, offline node recovery, reboot during apply, routing egress distinction and rollback. When Xray-router is enabled, include binary/geodata provenance, authenticated ingress isolation, DNS/UDP/no-leak probes and proof that x-ui restart/upgrade does not stop the dedicated router. Never run these destructive flows on production.

### Task 41: Release sequence

**Objective:** make migration observable and reversible.

**Release train:**
- `v0.2.0-alpha.1`: local Node identity, lifecycle façade and read-only client import;
- `v0.2.0-beta.1`: safe local unified create, credential recovery and subscriptions;
- `v0.2.0`: stable local control plane after independent spec/security review and full local protocol tests;
- `v0.3.0-alpha.1`: Fleet v2 shadow mode, desired/observed generations and secret transport;
- `v0.3.0-beta.1`: remote adapters, one-node canary and v1 compatibility façade;
- `v0.3.0`: stable remote provisioning after adoption/rollback lab;
- `v0.4.0-alpha.1`: routing IR and preview-only UI;
- `v0.4.0-beta.1`: typed manager egress APIs and only compilers proven by the isolated routing spike;
- `v0.4.0`: stable capability-limited native/OS routing;
- `v0.5.0-alpha.1`: optional dedicated Xray-router runtime, typed manager and preview compiler;
- `v0.5.0-beta.1`: proven Naive/Mieru bridges and optional managed-new 3x-ui static bridge;
- `v0.5.0`: stable DNS-aware Xray routing only for capability cells that passed Task 36. MTProxy remains outside routing scope.

Every stage keeps v1 readable and rollback-capable; v1 deletion is out of scope through v0.5.

---

## 5. Release-scoped acceptance criteria

### v0.2 — local Node, unified clients and subscriptions

- the panel host exists as one reserved local Node identity;
- one Client can own MTProxy, Naive and Mieru grants, while protocol credentials remain distinct;
- same username is never auto-merged;
- one form creates selected local grants via a durable resumable saga;
- partial failure compensates only newly created resources and lost-response tests do not lose the credential;
- protocol-specific quota/accounting semantics remain visible;
- one stable revocable URL reflects current active grants;
- persisted generation changes with mutations; ETag is derived from canonical effective output and changes across expiry boundaries;
- 304 works only when the effective manifest digest is unchanged;
- token and rendered credentials never appear in logs/audit/DB plaintext;
- client compatibility is explicit and UI does not claim push delivery or confirmed application.

### v0.3 — Fleet v2 and remote provisioning

- operator enrolls and monitors a remote node without writing protocol fields manually;
- transport health and daemon health are distinct;
- v1 and v2 coexist during the migration window;
- managed v2 resource changes converge after node reconnection;
- Fleet v2 introduces no generic remote command surface;
- manager-generated secret results survive loss at both acknowledgement boundaries;
- baseline adoption produces a no-op plan;
- migration gates reject activation when the same managed resource still has two configured writers;
- canary rollback is verified for each managed protocol adapter, not inferred.

### v0.4 — capability-limited routing

- policy is engine-independent and UUID-linked;
- first-match order and default action are deterministic;
- preview shows compiled effect per node/service;
- MTProxy is absent from routing targets and rejected by API contracts;
- unsupported semantics fail closed;
- management traffic bypass survives every policy accepted by a supported compiler target;
- rollback restores the previous managed egress; snapshot/digest comparisons prove adjacent Nginx/nftables state was not changed by that adapter;
- whole-service and selective/per-client routing are clearly distinguished;
- pools and unproven selective routing are absent rather than silently degraded.

### v0.5 — optional dedicated Xray routing

- Xray-router has a separately owned service, binary path, config and state generations;
- no policy edit rewrites the 3x-ui-owned Xray template;
- Naive and Mieru use distinct authenticated/private ingresses and service tags;
- domain/geosite/geoip/CIDR/port preview matches observed egress for every enabled cell;
- Mieru UDP remains disabled until destination-level UDP relay is proven;
- managed-new 3x-ui uses only an optional static bridge whose drift and upgrade behavior passed the gate; foreign/existing 3x-ui is not mutated;
- x-ui restart/upgrade does not restart or replace the dedicated router;
- router/provider failure follows the explicit fallback policy and never silently leaks direct;
- MTProxy remains outside routing scope.

### Cumulative operational criteria through v0.5

- each release passes its immediately preceding release-gate task independently;
- control-plane outage leaves existing data plane working;
- the DB, applicable keyrings and node generation/journal state can be restored for that release’s feature set;
- frozen runtime names/paths/volumes remain compatible;
- Graphify is rerun after each architecture-scale change and before final review.

---

## 6. Principal risks and mitigations

1. **Overengineering Fleet.** Mitigation: façade first; v2 is generations + typed adapters, not a workflow engine.
2. **Secret expansion.** Durable subscriptions introduce a new breach class. Mitigation: versioned encrypted secrets, separate key, node scoping, one-time reveal, exhaustive scans.
3. **Two writers.** Mitigation: feature-gated compatibility façade and explicit per-node cutover.
4. **False atomicity.** Mitigation: call it node-local saga; prove compensation and crash recovery.
5. **Routing lockout.** Mitigation: immutable management bypass, canary, out-of-band rollback and isolated live probes.
6. **False domain-routing claims.** Mitigation: compiler capability errors and dedicated spike before choosing a DNS-aware/TUN sidecar.
7. **False subscription expectations.** Mitigation: renderer-specific compatibility; distinguish pull refresh, operator events and actual client application.
8. **Username collisions.** Mitigation: UUID identities and explicit import decisions.
9. **Accounting ambiguity.** Mitigation: protocol/source/unit/completeness metadata; no billing-grade aggregate claim.
10. **Scope inflation.** Mitigation: defer Product/billing, automatic placement, Kubernetes, active-active panel, generic plugins and v1 removal.
11. **Xray ownership collision.** Mitigation: dedicated runtime; 3x-ui receives at most a static explicitly owned bridge, while policy generations are written only to the dedicated router.
12. **DNS/UDP semantic mismatch.** Mitigation: capability cells require hostname/IP, IPv4/IPv6, DNS leak and destination-level UDP tests; failed cells stay disabled.

---

## 7. Open product decisions to settle after the first spikes

The local Node identity is no longer open: it is required by Task 9. The remaining questions do not block v0.2 foundations, but some block later release gates:

> **Status 2026-09-10.** Question 1 is settled: the named client matrix, the renderer set (`manifest | singbox | clash | raw | html`), the dedicated subscription domain, the Mieru adopt-with-rotation flow, the master-key upgrade path and the `ams-test`-only release gate are recorded in section 5 of `docs/superpowers/plans/2026-09-10-vnext-v0.2-local-control-plane.md`, which is binding for v0.2. Questions 2-4 below remain open and are answered no earlier than v0.3.

1. Which client applications must receive true auto-refresh in v0.2? We need a named support matrix, not “all clients”.
2. Should v0.5 expose routing for managed-new 3x-ui inbounds through the tested static bridge, or initially limit Xray-router integration to Naive and Mieru? Recommendation: enable the bridge only after the exact upgrade/drift gate passes.
3. Should subscription-change events later go to Telegram, webhook, email, or only the operator UI? This is separate from polling the subscription URL.
4. How long should v1 remain writable after v0.3 canary success? Recommendation: one stable release cycle, then read-only; physical removal later.

---

## 8. Verification evidence used for this plan

- Local project inspected at exact commit `8c787c52d10fa7f07269bc5972eea63c77f5a392`.
- Current graph updated to 4,638 nodes / 13,543 edges / 194 communities; missing endpoint edges: 0; self-loops: 0.
- Focused current-state test matrix run by the read-only audit: 84 tests passed. This is not a full repository or production validation.
- 3x-ui analysis pinned to stable `v3.7.0`, commit `f727d04f6522bb94a8fb52e8352fdcafb51c11e1`.[1]
- 3x-ui conclusions are source-confirmed; its Go tests were not reproduced because Go was unavailable in the isolated research environment.

## Sources

[1] https://github.com/MHSanaei/3x-ui/releases/tag/v3.7.0
[2] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/internal/database/model/model.go
[3] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/internal/web/runtime/remote.go
[4] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/internal/web/service/inbound_node.go
[5] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/internal/sub/controller.go
[6] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/internal/sub/service.go
[7] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/frontend/src/schemas/routing.ts
[8] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/internal/web/service/xray.go
[9] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/internal/web/service/outbound_subscription.go
[10] https://github.com/MHSanaei/3x-ui/blob/v3.7.0/internal/sub/remote_routing.go
[11] https://xtls.github.io/en/config/routing.html
[12] https://xtls.github.io/en/config/inbounds/socks.html
[13] https://xtls.github.io/en/config/outbounds/socks.html
[14] https://xtls.github.io/en/config/outbounds/freedom.html
