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
- **Артефакты**: установщик извлекает ровно три члена закреплённого `Xray-linux-64.zip`
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
  `GET /v1/egress/{naive|mieru}`, `POST /v1/egress/{svc}/plan | apply | rollback`.
  Панель — единственный клиент; `docker exec proxy-control-xray-router python -m
  xray_router_manager.healthcheck --status` печатает статус оператору или проверке
  установщика.

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

## Ограничения и что отложено

Правил ≤ 128 на политику, ≤ 64 селекторов каждого вида, ≤ 32 портов, скомпилированный
intent ≤ 16 KiB на сервис; токен менеджера — 64 hex. Отложено за v0.5 (спека §15):
статический мост в Xray 3x-ui, canary-раскатка, per-grant, ретрансляция UDP, регулярные
выражения. Совместимость с узлами и центрами v0.4 — в [COMPATIBILITY](COMPATIBILITY.md) и
[FLEET](../FLEET.ru.md).
