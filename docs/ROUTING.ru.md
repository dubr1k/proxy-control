# Маршрутизация Proxy Control (v0.4): куда сервис выпускает трафик клиентов

[English](ROUTING.en.md) · **Русский**

## Обзор

С v0.4 оператор задаёт для каждого узла и каждого прокси-сервиса **политику egress**:
весь сервис идёт **напрямую** или **через WARP хоста**, а упорядоченные first-match
**правила** блокируют назначения или (где backend умеет) отправляют часть из них иначе.
Политика нейтральна к движку ([ADR 006](adr/006-routing-policy-ir.md)): в ней домены,
сети и цели `direct | block | egress: warp` — никогда адрес, путь к конфигу или сырая
директива. Панель **компилирует** её под backend, который на узле реально работает,
показывает результат и каждое ограничение как **предпросмотр** и применяет
**транзакционно** через менеджер сервиса, с откатом.

Что применимо — это то, что spike доказал на стенде (`spikes/VNEXT_ROUTING_ENGINE.md`),
а не то, что обещает документация движков. Где backend не может выполнить правило,
предпросмотр отвечает `unsupported` и называет правило; ничего не сужается до «весь
сервис» молча.

| Сервис | Backend | Умеет | Не умеет |
| --- | --- | --- | --- |
| NaiveProxy | `naive_native` — Caddy forwardproxy `upstream` + `acl` | весь сервис напрямую или через WARP; блокировка по домену (`example.com`, `*.example.com`) и по CIDR | выборочные правила `direct`/`egress` (один upstream на сервис); блокировку **рядом** с WARP по умолчанию — forwardproxy не применяет ACL при заданном upstream; блокировку по порту |
| Mieru | `mieru_native` — mita `egress` | весь сервис напрямую или через WARP; блокировку по домену и по CIDR; выборочные `direct`/`egress` по домену и по CIDR, по порядку | блокировку по порту; `*.example.com` и `example.com` — один селектор (mita матчит суффикс домена) |
| MTProxy (Telemt) | — | — | вне области: `protocol_out_of_scope` |

Приватные назначения — loopback, link-local, RFC 1918, CGNAT и их IPv6-аналоги, плюс
`localhost` — можно **блокировать**, но нельзя открыть правилом `direct` или `egress`
(`private_destination`). Caddy запрещает их по умолчанию; mita не должна давать клиенту
loopback узла.

## Политика

Одна политика на (узел, протокол), редактируется на экране «Маршрутизация» или через
`/api/routing/*`:

```text
default_action   direct | egress          default_egress  warp (при egress)
fallback         fail_closed | approved_direct
rules[]          enabled, action: direct | block | egress, egress: warp (при egress),
                 match: {domains[] ≤ 64, cidrs[] ≤ 64, ports[] ≤ 32}, note ≤ 120
```

- домены приводятся к нижнему регистру IDNA; `*.example.com` — «любой поддомен»,
  `example.com` — сам хост (у Mieru оба — суффикс `example.com`); CIDR нормализуются
  (`10.1.2.3` → `10.1.2.3/32`); правилу нужен хотя бы один домен или CIDR; `ports`
  принимаются, но ни один backend v0.4 их не применяет (`rule_kind_unsupported`);
- не больше 128 правил; скомпилированный документ — не больше 16 КиБ на протокол;
- `revision` растёт при каждом сохранении (`expected_revision` в `PUT` → 409
  `policy_conflict`, если кто-то сохранил параллельно); `applied_revision`/`applied_digest`
  говорят, что стоит на узле — `state = applied` **и** `applied_revision = revision` —
  «применено», иначе карточка показывает «есть неприменённые изменения».

`fallback` — единственный явный способ обменять fail-closed на доступность: при
`approved_direct` WARP, о котором узел сообщает «недоступен», заставляет компилятор
заменить `warp` на `direct` и сказать об этом в предпросмотре (`provider_unreachable` как
предупреждение). При `fail_closed` (по умолчанию) предпросмотр — `unsupported`, и ничего
не применяется.

## Предпросмотр и применение

`POST …/preview` (с черновиком в теле или без тела — для сохранённой политики) возвращает
скомпилированный документ, его digest, diff относительно того, что стоит на узле, нужен
ли перезапуск (mita — да; Caddy — reload), цель отката и — при `unsupported` — причины:

| Причина | Значение |
| --- | --- |
| `backend_capability_missing` | менеджер узла не объявляет возможность, нужную правилу (например, `selective_domain` у NaiveProxy) |
| `rule_kind_unsupported` | ни один backend v0.4 этого не применяет (блокировка по порту; блокировка рядом с WARP по умолчанию у NaiveProxy) |
| `private_destination` | правило `direct`/`egress` называет loopback или приватную сеть |
| `provider_unavailable` | на узле не настроен WARP (`NAIVE_EGRESS_WARP` / `MIERU_EGRESS_WARP` пусты) |
| `provider_unreachable` | WARP настроен, но не отвечает; `fallback = approved_direct` превращает это в предупреждение |
| `protocol_disabled_on_node` | сервис на узле выключен |
| `node_lacks_egress_v1` | связанная панель старше v0.4 |
| `protocol_out_of_scope` | MTProxy |
| `document_too_large` | больше 16 КиБ |
| `manager_unavailable` | локальный менеджер не ответил |

Предупреждения: `adopts_unmanaged_upstream` / `adopts_unmanaged_egress` (на узле есть
`upstream` или секция `egress`, написанные вручную — первое применение переносит их под
владение менеджера и сохраняет оригинал для отката), `policy_empty` (напрямую, без правил —
то, что применяет «Сбросить»).

`POST …/apply` с `expected_revision`:

- **локальный узел** — панель просит менеджер спланировать и применить
  (`POST /v1/egress/plan`, `POST /v1/egress/apply` на сокете менеджера, идемпотентно по
  `operation_id = routing:<policy>:<revision>`); менеджер проверяет доступность WARP,
  пишет конфиг, перезагружает или перезапускает сервис, читает работающую конфигурацию
  обратно и держит предыдущую запись в журнале. Исход, строка `routing_applies` и событие
  аудита `routing.policy.apply` пишутся одной транзакцией *после* ответа менеджера — I/O
  менеджера никогда не идёт под блокировкой базы;
- **связанная панель** — скомпилированный документ политики становится секцией `egress`
  следующего поколения Fleet v2 узла (`state = applying`); узел применяет его после
  ресурсов и отчитывается `converged | failed | unsupported` по протоколам, а центр
  переводит политику в `applied` или `failed` по этому отчёту (см. [FLEET](../FLEET.ru.md)).

Отказы — коды, а не тексты менеджера: 409 `policy_conflict`, 422 `unsupported` (в теле —
скомпилированный предпросмотр), собственные коды менеджера `egress_conflict`,
`egress_invalid`, `egress_unreachable` (409), `egress_readback_mismatch` (409 — менеджер
вернул прежний конфиг), `manual_intervention_required` (503 — менеджер не смог его вернуть;
путь к резервной копии — в журнале менеджера), `manager_unavailable` (502),
`managed_by_central` (409 — egress этого узла ведёт центральная панель; применяйте там).

`POST …/rollback` возвращает узел к предыдущей записи журнала менеджера (локально) или к
предыдущему применённому документу из собственной истории центра (связанная панель — один
шаг назад, не стек). `DELETE` допустим, только когда узел работает «напрямую, без правил»
(иначе 409 `policy_applied`): забытая политика никогда не меняет того, что узел применяет.

## Чем владеют менеджеры ([ADR 007](adr/007-routing-enforcement-ownership.md))

- **naive-manager** владеет ровно одним блоком внутри `forward_proxy` своего Caddyfile:

  ```text
  # BEGIN NAIVE-MANAGER EGRESS
  upstream socks5://127.0.0.1:45000
  acl {
      deny example.com *.example.com 10.0.0.0/8
  }
  # END NAIVE-MANAGER EGRESS
  ```

  Всё вне блока — блок пользователей, блок учёта, cover-сайт — остаётся байт в байт. URL
  провайдера берётся из `NAIVE_EGRESS_WARP`; панель никогда не присылает адрес. Revision =
  SHA-256 блока; журнал (`users.json`, `egress`) хранит последние десять записей и строки,
  которые первое применение переняло.
- **mieru-manager** владеет секцией `egress` конфига mita (`proxies` с эндпоинтом WARP из
  `MIERU_EGRESS_WARP`, `rules` с `domainNames`/`ipRanges`/`action`), применяемой той же
  транзакцией и журналом, что и изменения пользователей, в режиме **restart**: `mita
  reload` новый egress не подхватывает. Политика «напрямую» убирает секцию.
- Контейнер mieru-manager работает в сети хоста (своего слушателя нет, по-прежнему
  `read_only` и `cap_drop: ALL`), чтобы проверять эндпоинт WARP на loopback хоста перед
  применением.

Оба менеджера отказывают документу вне своей схемы (`egress_invalid`), документу с
провайдером, не настроенным на хосте, и — до записи чего-либо — провайдеру, который не
отвечает на TCP-connect и SOCKS5-приветствие (`egress_unreachable`). Сам эндпоинт WARP
отказывает loopback- и RFC 1918-назначениям (так делает proxy-режим Cloudflare) — ещё одна
причина, по которой компилятор отказывается их открывать.

## WARP на хосте

Секция установщика `[egress]` (`warp`, `warp_port`, `naive`, `mieru`) ставит Cloudflare
WARP в proxy-режиме и один раз сеет начальный egress каждого сервиса; обновление или repair
никогда не переписывают то, что панель применила позже
([INSTALLER_REFERENCE](INSTALLER_REFERENCE.ru.md)). Хост, собранный вручную, задаёт
`NAIVE_EGRESS_WARP=socks5://127.0.0.1:<port>` и `MIERU_EGRESS_WARP=…` в `.env` сам
([UPGRADING](UPGRADING.ru.md)); без них targets не показывают провайдера `warp`, и любая
WARP-политика в предпросмотре — `provider_unavailable`.

## Безопасность и аудит

- Политики, скомпилированные документы, `identity`, отчёты observed и строки аудита без
  секретов и без эндпоинта провайдера; `targets` отдаёт только `providers: {warp:
  {reachable}}`.
- Управляющий трафик не маршрутизируется: сокеты панель ↔ менеджеры, ACME, Fleet и
  heartbeat не проходят через `forward_proxy` или egress mita.
- Owner — для любых изменений; любая роль читает и делает предпросмотр. Аудит:
  `routing.policy.update | apply | rollback | delete` ([AUDIT_EVENTS](AUDIT_EVENTS.md)).

## Проверка

Unit: `panel/tests/test_routing_ir.py` (валидация, компилятор по матрице возможностей,
хранилище), `test_routing_service.py`, `test_routing_routes.py`, `test_routing_fleet.py`
(секция поколения, узел, pusher), `test_egress_adapters.py`, `tests/test_naive_egress.py`,
`tests/test_naive_manager_egress.py`, `tests/test_mieru_egress.py`. Стенд:
`scripts/dev/remote-gate.sh routing` — менеджеры узла смотрят на
`scripts/lab/socks5-stub.py` (SOCKS5, который журналирует каждую CONNECT-цель), а
`fleet-acceptance.py --routing` доказывает WARP на весь сервис, блокировки по домену и CIDR
при живом cover-сайте, выборочное правило Mieru, откат байт в байт, недоступный провайдер →
fail-closed и нетронутые nginx и nftables.
