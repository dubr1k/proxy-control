# Xray-router (v0.5): один выделенный egress-роутер на узел

[English](XRAY_ROUTER.en.md) · **Русский**

## Что это

С v0.5 на узле может работать выделенный процесс **Xray**, единственная задача которого —
выпускать трафик NaiveProxy и Mieru по политике маршрутизации панели
([ROUTING](ROUTING.ru.md)). Он необязателен (`[egress] router = true` в установщике,
[INSTALLER_REFERENCE](INSTALLER_REFERENCE.ru.md)); узел без него работает ровно как в v0.4.
Это не Xray из 3x-ui и он его не трогает ([ADR 007](adr/007-routing-enforcement-ownership.md)):
бинарь и geodata берутся из закреплённого upstream-архива, процесс живёт в своём контейнере
под своей identity, и ничего из него не лежит в `/usr/local/x-ui`.

```text
NaiveProxy (Caddy) ──upstream socks5://naive-…:key@127.0.0.1:45101──┐
                                                                    ├──> xray-router ──> direct | warp (127.0.0.1:40000) | block
Mieru (mita) ─────egress proxy "router" 127.0.0.1:45102 + auth ─────┘
```

У роутера два **ingress** — SOCKS5 на loopback хоста с аутентификацией по логину/паролю,
по одному на сервис: `naive` на `127.0.0.1:45101`, `mieru` на `45102`. Ключ ingress —
это идентичность сервиса: роутер принимает на этом порту только эту пару, поэтому процесс
на хосте не может воспользоваться чужим ingress, а без ключа не проходит ничего. На каждом
ingress роутер применяет **секцию** этого сервиса: правила политики, затем умолчание
(`direct` или `warp`).

Сервис **подключается** к роутеру явным действием владельца на экране «Маршрутизация»
(или `POST /api/routing/targets/{node}/{protocol}/attach`): сначала роутер получает
секцию-заглушку (pass-through) для сервиса, затем менеджер сервиса вписывает ingress
роутера в блок, которым владеет (`upstream` у Caddy, `egress` с `socks5Authentication`
у mita). **Отключение** — в обратном порядке. Политика никогда не подключает сервис сама;
семя `[egress] naive = "router"` при установке — то же подключение, сделанное один раз.

## Что он умеет

Каждая ячейка ниже доказана на стенде (`spikes/XRAY_EGRESS_ROUTER.md`, Xray-core 26.3.27,
Caddy 2.11.4 + forwardproxy, mita 3.36):

| Селектор / действие | `direct` | `block` | `egress: warp` |
| --- | --- | --- | --- |
| домен (`example.com`, `*.example.com`) | ✓ | ✓ | ✓ |
| `geosite:<код>` | ✓ | ✓ | ✓ |
| CIDR | ✓ | ✓ | ✓ |
| `geoip:<код>` | ✓ | ✓ | ✓ |
| порт (`443`, `1000-2000`) | ✓ | ✓ | ✓ |
| умолчание для всего сервиса | ✓ | — | ✓ |

Правила — first-match, в порядке политики; блокировка **рядом** с умолчанием WARP
работает (в отличие от собственного ACL NaiveProxy). Что **не** заявляется: UDP через
роутер (UDP mita остаётся напрямую; ingress не ретранслируют UDP), правила per-grant,
регулярные выражения, селектор `geoip:private` (см. ниже), MTProxy.

### DNS и приватные адреса

Роутер резолвит с `domainStrategy: IPOnDemand` (`dns` Xray использует резолвер хоста):
имя резолвится, когда правилу нужен адрес, и первое правило каждого ingress —
`geoip:private → block`. Поэтому назначение, которое является или резолвится в loopback,
link-local, RFC 1918, CGNAT или их IPv6-аналоги, отвергается раньше любого правила
политики, включая публичное имя, перепривязанное на `127.0.0.1` (spike использовал
`localtest.me`). Этот bypass не отключается, а `private` не принимается как код geoip в
политике. `localhost` и `full:localhost` блокируются и по имени. Sniffing работает с
`routeOnly: true`: подсмотренный host используется для решения о маршруте и никогда не
переписывает соединение.

## Рантайм

- **Контейнер** `proxy-control-xray-router` (Compose-сервис `xray-router`, оверлей
  `compose.xray-router.yaml`), сеть хоста, identity `10006:10006`, `read_only`,
  `cap_drop: ALL`, `pids_limit: 128`, tmpfs `/tmp`. Бинари примонтированы только для
  чтения из `/usr/local/lib/proxy-control/xray-router` (`xray`, `geoip.dat`,
  `geosite.dat`), состояние — из `/var/lib/xray-router` (0700,
  `prepare-xray-router-state.sh`), сокет менеджера — в tmpfs-томе `xray-router-run`
  (`/run/xray-router/manager.sock`, режим 660, панель входит в группу 10006).
- **Артефакты**: установщик скачивает закреплённый `Xray-linux-64.zip` по его HTTPS-URL в
  `/var/lib/proxy-control/`, если файла там нет (положенный вручную используется как есть),
  сверяет SHA-256 архива и извлекает ровно три члена
  (`release/external-artifacts.json`, у каждого свой SHA-256 и режим); менеджер
  перепроверяет все три дайджеста до любого запуска (`XRAY_ROUTER_*_SHA256` в
  `.env.xray-router`) и при несовпадении отвечает `artifact_mismatch` (503), а не
  запускает незакреплённый бинарь.
- **Менеджер** (`xray_router_manager`): супервизор над одним дочерним `xray run`. Его
  состояние — последовательность **поколений** (`generations/<n>/config.json`),
  `current.json` (запущенное), `journal.json` (по сервису: current, previous, history) и
  `state.json` (`phase: idle | swapping | broken`). Он рендерит один конфиг Xray из
  intent'ов обоих сервисов плюс ключей, которые читает из
  `/run/secrets/xray-router-ingress-*`.
- **API** на Unix-сокете, заголовок `X-Xray-Router-Token` (Docker-секрет
  `xray-router-manager-token`): `GET /v1/status`, `GET /v1/health`,
  `GET /v1/egress/{naive|mieru}`, `POST /v1/egress/{svc}/plan | apply | rollback`; с v0.7 —
  `GET | POST /v1/lanes/{svc}`, `DELETE /v1/lanes/{svc}/{lane}`, `GET | POST | DELETE /v1/relay`,
  `PUT /v1/relay/accounts` (см. ниже); с v0.8 — `GET /v1/geodata`, `GET /v1/geodata/codes`,
  `PUT /v1/geodata/settings`, `POST /v1/geodata/update | restore`, `POST /v1/exits/test`
  (см. «Geodata и свои выходы»). Панель — единственный клиент; `docker exec
  proxy-control-xray-router python -m xray_router_manager.healthcheck --status` печатает статус
  оператору или проверке установщика (`--relay`, `--relay-enable <server_name> <port>` — relay).

### Транзакция

`apply` для одного сервиса: проверить типизированный intent (schema 1: `default`,
`rules[]` с `domains/geosites/cidrs/geoips/ports`, `action`, `egress`; никогда не сырой
JSON Xray) → отрендерить поколение *n+1* из текущих intent'ов **всех** сервисов →
`xray run -test` на нём (неверный код geodata падает здесь: `geosite_unknown` /
`geoip_unknown`) → SIGTERM дочернему процессу → запустить новый → дождаться обоих портов
ingress → прочитать обратно → закоммитить `current.json` и журнал. Если новое поколение
не поднимается, снова запускается последнее известное хорошее, а вызывающий получает
`egress_readback_mismatch`; если не поднимается и оно, роутер `broken` и отвечает
`manual_intervention_required` (503), пока не посмотрит оператор
(`docs/OPERATIONS.ru.md`). Умолчание или правило `warp`, пока endpoint WARP не отвечает на
SOCKS5-приветствие, отвергается до любых изменений (`egress_unreachable`, fail-closed).
Apply идемпотентен по `operation_id`; устаревший `expected_revision` — `egress_conflict`;
swap занимает около 50 мс и прерывает открытые сессии *обоих* сервисов. **Watchdog**
перезапускает текущее поколение, если дочерний процесс умер (после трёх неудачных
стартов роутер `broken`).

`rollback` для одного сервиса снимает верх его журнала (предыдущий intent этого сервиса,
другой сервис не меняется) и применяет его как новое поколение.

## Ключи и ротация

- `secrets/xray-router-ingress-naive` и `-mieru` (`secrets/` проекта, root, 0600): одна
  строка `user:password`, user `<сервис>-<8 hex>`, пароль 43 URL-safe символа. Роутер
  монтирует их как Docker-секреты и перечитывает при старте; каждый менеджер держит
  собственную копию в своём каталоге состояния (`/var/lib/naive-manager/xray-router-ingress`,
  `/var/lib/mieru-manager/xray-router-ingress`, 0400) и читает её, когда рисует провайдер
  `router`.
- Ключ есть ровно в трёх местах на узле: файлы секретов, строка `upstream` Caddy и
  `socks5Authentication` mita — плюс отрендеренные поколения роутера. Каждое API-представление
  его маскирует (`socks5://***@…`, `socks5Authentication: ***`), diff в `plan` маскирует,
  identity и поколения Fleet его не несут, а secret-scan лаборатории падает на такой форме.
- **Ротация**: `sudo /usr/local/libexec/rotate-xray-router-ingress [naive] [mieru]` пишет
  новые ключи в `secrets/` и в копии менеджеров, пересоздаёт роутер (Docker-секреты из
  файлов читаются при создании контейнера), затем каждый менеджер; на старте менеджер,
  чей блок ещё несёт старый ключ, перерисовывает его (пока не перерисовал —
  `router_credential_stale`). Ротация один раз прерывает сессии ротируемых сервисов.

## Эксплуатация

- **Статус** на экране «Маршрутизация»: у цели видно `Xray-router: доступен / подключён /
  не установлен`, версию Xray и причины `router_unavailable`, `not_attached`,
  `artifact_mismatch`, `router_unreachable` (менеджер не достучался до ingress),
  `node_lacks_router` (связанная панель старше v0.5).
- **Логи**: `docker logs proxy-control-xray-router` (менеджер; access-лог дочернего
  процесса выключен, inbound'ов stats/api нет).
- **Сломанный роутер** (`phase: broken`): каждый apply отвечает 503
  `manual_intervention_required`; подключённые к нему сервисы сохраняют свой upstream и
  поэтому **fail closed**. Посмотрите лог, устраните причину (полный диск, чужой
  артефакт), затем `docker compose … restart xray-router` — bootstrap запустит последнее
  закоммиченное поколение; либо отключите сервисы на экране «Маршрутизация», чтобы они
  шли нативно, пока роутер лежит. Runbook — в `docs/OPERATIONS.ru.md`.
- **Удаление**: отключить каждый сервис, затем `uninstall` (откат установщика останавливает
  контейнер и удаляет бинари, helper'ы, env-оверлей; `--purge-data` — ещё состояние и
  секреты) — что сохранять, см. `docs/BACKUP_RESTORE.ru.md`.

## Полосы, цепи и relay (v0.7)

Intent **схемы 2** переносит роутер с «одной политики на сервис» на **полосы**: `{"schema": 2,
"lanes": {"svc:naive": {default, rules}, "grant:<id>": {…}}, "chains": {"c1": {"hops": [...],
"exit": "direct" | "warp"}}}`. Каждая полоса — учётка SOCKS на том же ingress сервиса; правила
рендерятся с селектором `user` (`grant-<id>` для полосы доступа, учётка установщика для полосы
сервиса, которая идёт последней), поэтому один ingress ведёт трафик разных пользователей по
разным политикам. Схема 1 рендерится байт в байт как в v0.5/v0.6.

- **Ключи полос**: `POST /v1/lanes/{svc}` `{"lane": "grant:<id>"}` чеканит (или перевыпускает)
  учётку полосы, тут же кладёт её на ingress новым поколением и возвращает **один раз** —
  панель отдаёт её менеджеру сервиса и не хранит. `lanes.json` (0600) в каталоге состояния;
  `GET /v1/lanes/{svc}` — только имена полос; `DELETE /v1/lanes/{svc}/{lane}` — забыть.
  Intent, называющий полосу без учётки, отвергается (`egress_invalid`).
- **Цепи**: у каждого хопа `guid`, `address`, `port`, `server_name`, `public_key`, `short_id`,
  `uuid`. Рендер — по одному outbound `vless` + `reality` на хоп (`chain:<svc>:<id>:<n>`),
  каждый следующий набирается через предыдущий (`proxySettings.tag`); правило полосы с
  `egress: chain:<id>` уходит на последний хоп. В `plan` и `apply` менеджер проверяет
  достижимость каждого хопа (TLS-hello к прикрытию с его `serverName`, 3 с) и отказывает
  `egress_unreachable` («chain c1 hop 1 is unreachable»), не меняя ничего. Представления
  intent'а (`GET /v1/egress/{svc}`) маскируют `uuid` хопов.
- **Relay**: `POST /v1/relay` `{"server_name", "port"}` включает inbound `vless` + `reality`
  на `0.0.0.0:<port>` с прикрытием `127.0.0.1:8443` (TLS панели узла); ключевая пара x25519
  чеканится `xray x25519` один раз и живёт только в `relay.json` (0600), `short_id` — тоже.
  `PUT /v1/relay/accounts` `[{"email": "relay:<guid источника>:<direct|warp>", "uuid"}]` —
  учётки, которые выдал центр; учётка `…:warp` ведёт в `warp` роутера (без WARP на узле —
  `egress_invalid`), остальные — `direct`; `geoip:private → block` действует и здесь.
  `DELETE /v1/relay` выключает inbound, пара сохраняется. `GET /v1/relay` и `status.relay` —
  только публичная часть (`enabled, port, server_name, public_key, short_ids, accounts` — число).
- Каждая из этих операций коммитит новое поколение с теми же intent'ами (`_rerender_current`)
  — та же транзакция «рендер → `xray run -test` → swap → readback», предыдущее поколение для
  отката; `capabilities` роутера дополняются `lanes`, `chains`, `relay`.

Пределы: ≤ 32 полос и ≤ 16 цепей на сервис, ≤ 3 хопов в цепи, intent схемы 2 ≤ 64 KiB.

## Geodata и свои выходы (v0.8)

**Geodata.** Xray читает `geosite.dat`/`geoip.dat` из `<state>/geodata` (`XRAY_LOCATION_ASSET`),
а не из каталога бинарей: при первом старте менеджер копирует туда закреплённую пару (её
дайджесты по-прежнему проверяются при старте), дальше файлы — выбор оператора: `xray` (пин),
`loyalsoldier` (`https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/…`) или
два своих HTTPS-URL. Обновление — транзакция: оба файла скачиваются во временные имена (≤ 64 MiB,
только HTTPS до конца редиректов, `<url>.sha256sum` сверяется, если издатель его отдаёт),
конфиг текущего поколения прогоняется через `xray run -test` против кандидатов (код, которого
новые списки не знают, падает здесь — `geodata_rejected`), затем атомарная подмена и перезапуск
текущего поколения. Неудача оставляет старые файлы и пишется в `last_error`
(`geodata_fetch_failed`, `geodata_digest_mismatch`, `geodata_too_large`, `geodata_corrupt`).
Автообновление — из потока watchdog по интервалу (`interval_hours` 1…336, по умолчанию 24);
`meta.json` рядом с файлами хранит источник, версию (тег релиза), дату и sha256. `restore`
возвращает пин и выключает автообновление. Коды списков менеджер читает из protobuf сам
(`/v1/geodata/codes`, кэш по sha256) — для подсказчика в правилах. Капабилити `geodata`.

**Свои выходы.** Intent схемы 2 несёт `exits: {<id>: {protocol, address, port, credential,
transport, security, method?, flow?}}` (≤ 16), а правило или default — `egress: exit:<id>`;
рендер даёт аутбаунд `exit:<svc>:<id>` (`socks`/`http` с `users`, `vless` с `vnext`, `trojan`,
`shadowsocks`; `streamSettings` по транспорту и `tls`/`reality`). Credential маскируется в
`redact_intent`, статусе и дифф. Правило может стоять на `protocols` (`http | tls | quic |
bittorrent`) — это `protocol` правила Xray по снифферу ingress'а (`routeOnly`). Капабилити
`custom_exits`, `block_protocol`, `selective_protocol`. `POST /v1/exits/test` `{exit}` поднимает
одноразовый `xray` с `dokodemo-door` на loopback к `www.cloudflare.com:443` через этот аутбаунд
и делает один TLS-запрос `/cdn-cgi/trace`: `{ok, ip, colo, latency_ms}` или `{ok: false, code:
exit_invalid | exit_test_failed | exit_unreachable}`; рабочий роутер не трогается, одна проба
в момент времени.

## Ограничения и что отложено

Правил ≤ 128 на политику, ≤ 64 селекторов каждого вида, ≤ 32 портов, ≤ 4 протоколов сниффера,
≤ 16 своих выходов на узел, скомпилированный intent ≤ 16 KiB на сервис (схема 2 — 64 KiB);
токен менеджера — 64 hex. WireGuard как выход не поддерживается намеренно (решение владельца,
2026-09-18). Отложено за v0.5
(спека §15): статический мост в Xray 3x-ui, canary-раскатка, ретрансляция UDP, регулярные
выражения; per-grant маршрутизация пришла в v0.7 полосами. Совместимость с узлами и центрами v0.4 — в [COMPATIBILITY](COMPATIBILITY.md) и
[FLEET](../FLEET.ru.md).
