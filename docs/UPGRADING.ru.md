# Обновление и откат

Процедура предназначена для работающей установки и для panel `version-agent`. Каждый runtime рассматривайте как отдельную границу изменения.

## Общий порядок

1. Прочитайте changelog, политику совместимости, лицензии upstream и сведения о pinned-артефактах.
2. Выполните полный набор проверок из [VALIDATION.md](VALIDATION.md).
3. Остановите новые изменения. Сделайте одну согласованную резервную генерацию: secrets, volumes, SQLite вместе с WAL/SHM, состояние менеджеров и journal keys, Nginx и ownership manifest.
4. Отрендерите Compose и план установщика без применения. Проверьте digest образов и бинарников, numeric identities, порты, mounts и SNI-маршруты.
5. Убедитесь, что работающие контейнеры имеют label проекта `com.docker.compose.project=mtproxy`; используйте точный сохранённый полный набор `COMPOSE_FILE`. Не применяйте `--remove-orphans` к неполной модели.
6. Меняйте только одну границу за раз. После изменения проверяйте конфигурацию, health, протокол, учёт трафика и соседние SNI.
7. При ошибке остановите изменённую службу и восстановите полную предыдущую генерацию с тем же project name и overlays. Не пересоздавайте journal keys и не копируйте состояние частично.

## Обновление до v0.2: мастер-ключ панели

В v0.2 учётные данные клиентов хранятся зашифрованными, поэтому сервис `panel`
монтирует ещё один Compose secret — `secrets/panel-master-key`.

- **Установка через `proxy-control`**: делать ничего не нужно. Установщик создаёт
  ключ и при установке, и при обновлении, сохраняет существующий и никогда не
  генерирует новый поверх (новый ключ сделал бы все сохранённые секреты
  нерасшифровываемыми).
- **Ручная сборка из `compose.yaml`**: создайте ключ один раз до
  `docker compose up`, иначе Compose откажется стартовать из-за отсутствующего
  файла секрета:

```bash
umask 077
docker run --rm -v "$PWD/secrets":/out --entrypoint python mtproxy-panel:latest \
  -m panel.cli master-key-init --path /out/panel-master-key
```

Потом положите копию **отдельно от БД** ([backup и
restore](BACKUP_RESTORE.ru.md)). Панель, которая ещё не сохранила ни одного
секрета, стартует и без ключа; как только зашифрованные строки появились, а ключ
пропал, панель отказывается стартовать вместо того, чтобы отдавать пустые
подписки.

Ротация — отдельная осознанная операция и никогда не часть обновления:

```bash
docker compose exec panel python -m panel.cli master-key-rotate --path /run/panel/master-key
```

Она добавляет новый активный ключ, перешифровывает все секреты батчами,
проверяет результат и только затем сужает keyring до нового ключа — прерванная
ротация оставляет всё читаемым.

## Обновление до v0.3: связанные панели

v0.3 позволяет одной панели (центру) управлять другими (узлами) по их HTTPS-доменам с
scoped API-ключами ([FLEET.ru.md](../FLEET.ru.md), [ADR
008](adr/008-panel-to-panel-transport.md)). Само обновление — обычное обновление панели,
`docker compose up -d --build --wait panel` с сохранённым набором overlays, — и не добавляет
ни службы, ни порта, ни файла секрета, ни компонента на хосте.

**Миграции 9–13** выполняются при первом старте (или `python -m panel.cli db-migrate`) и
аддитивны:

| № | Имя | Добавляет |
| --- | --- | --- |
| 9 | `panel-settings-and-api-keys` | `panel_settings` (`panel_guid` панели, позже её `fleet_master_guid`) и `api_keys` (префикс + SHA-256, scope, срок) |
| 10 | `fleet-v2-managed` | `managed_generations`, `managed_resources` — сторона узла: принятые поколения и учётные записи runtime, которыми узел владеет для центра |
| 11 | `fleet-v2-links` | `node_links`, `desired_generations`, `observed_generations` и `fleet_nodes.transport` (`v1` у всех существующих узлов) — сторона центра |
| 12 | `provisioning-pending-remote` | расширяет CHECK `provisioning_operations.status` значением `pending_remote`; SQLite не умеет менять CHECK на месте, поэтому таблица пересобирается с сохранением всех строк, индекса и внешнего ключа |
| 13 | `fleet-v2-learned-options` | `managed_resources.learned_json` — что runtime сообщил узлу о ресурсе, которым тот владеет для центра (хост и порт Telemt, share-шаблон mita); отдаётся с каждым наблюдаемым поколением |

`python -m panel.cli db-status` показывает все тринадцать как применённые. `panel_guid`
(uuid4) создаётся при первом старте и больше не меняется; `VERSION` панели сообщается
центру через `PANEL_VERSION_FILE` (по умолчанию `/app/VERSION`, монтируется из каталога
проекта `compose.yaml`; установщик копирует `VERSION` туда сам; отсутствующий файл читается
как `dev` и старту не мешает).

**Что появляется.** «Администраторы → API-ключи» (только владелец); карточка «Этот
сервер» на экране «Узлы» с GUID панели, URL для центра и — когда панелью управляют —
кнопкой «Отвязать»; кнопка «+ Панель» в шапке экрана «Узлы»; связанные панели в выборе
узла при «Выдать доступ»; `/api/fleet/v2/*` на каждой панели, отвечающий только на API-ключ
`node-sync` или `admin` (401 без ключа; 403 для сессии или ключа `monitor`);
`Authorization: Bearer` на всём `/api/*`; настройка `PANEL_FLEET_HEARTBEAT_SECONDS` (по
умолчанию 15) для центра; `compose.yaml` теперь передаёт контейнеру панели ещё и
`MTPROXY_DOMAIN` (он уже есть в `.env` для сервисов `mask` и `mtproxy`) — endpoint MTProxy,
который панель сообщает центру и подставляет в ссылку, пока не выучила его из Telemt;
настраивать ничего не нужно.

**Что не меняется.** Fleet v1 (mTLS-агент, `/api/fleet/nodes*`, `/agent/v1/*`) работает
байт-в-байт как прежде; protocol endpoints, `PANEL_VNEXT_WRITER`, подписки и требование
мастер-ключа — те же, что в v0.2; локальные пользователи не трогаются; панель ни с кем не
разговаривает, пока владелец не создаст ключ `node-sync`, а центр не добавит панель по
нему. Панель без мастер-ключа по-прежнему стартует и работает локально, но управляться
центром не может (push отвечает 409 `secret_store_disabled`).

**Одна сборка с обеих сторон.** Документ поколения проверяется на узле строго, поэтому
узел на более старой сборке отвергает документ с незнакомым полем (422), а центр уходит в
backoff; у панели v0.2 нет `/api/fleet/v2/*`, и добавить её нельзя. Обновляйте **сначала
узлы, затем центр**; держите все панели одного парка на одном выпуске.

**Хосты, обновляемые rsync,** должны получить `VERSION` вместе с кодом, иначе узел сообщает
`dev` ([OPERATIONS](OPERATIONS.ru.md), раздел 11).

**Откат** идёт по общему порядку выше — полная предыдущая генерация вместе с базой: образ
v0.2 отказывается стартовать на базе со схемой 13 («database schema 13 is newer than this
code»). На узле, который никто не подключал, обновление не тронуло ни одной учётной записи
runtime, так что база до обновления не теряет никакого fleet-состояния; узел, которым
управляли, сначала отвяжите («Отвязать»), затем откатывайте.

Проверка после обновления (health-check по-прежнему требует заголовок `Host`):

```bash
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 13
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: panel.example.com' http://127.0.0.1:8787/api/fleet/v2/identity   # 401: маршруты есть, нужен ключ
```

## Обновление до v0.4: маршрутизация

v0.4 добавляет egress-политики по узлам и сервисам ([ROUTING](ROUTING.ru.md)).
Обновление обычное — пересобираются панель **и оба менеджера**, потому что egress API
живёт в менеджерах: `docker compose up -d --build --wait panel naive-manager
mieru-manager` с сохранённым набором оверлеев после того, как в каталог проекта
(`/opt/mtproxy-shared443` у установщика) скопированы `panel/`, `naive_manager/`, `mieru_manager/`,
`compose*.yaml` и `VERSION` нового выпуска — так обновлён боевой узел при живой проверке v0.4.
Нового порта, файла секрета или компонента хоста нет.

**Миграция 14** (`routing-policies`) выполняется при первом старте и аддитивна:
`routing_policies`, `routing_rules`, `routing_applies` (политики центра и локальные с
историей) и `managed_egress` (какой egress узел применил для центра).
`python -m panel.cli db-status` показывает четырнадцать применённых.

**Что меняется на хосте.**

- `compose.mieru.yaml` переводит контейнер mieru-manager в **сеть хоста** (своей у него не
  было; по-прежнему `read_only`, `cap_drop: ALL`, слушающего сокета нет), чтобы проверять
  эндпоинт WARP на loopback хоста перед применением политики. `up -d` один раз пересоздаёт
  контейнер.
- В `.env` появляются `NAIVE_EGRESS_WARP` и `MIERU_EGRESS_WARP` — эндпоинт WARP в
  proxy-режиме, через который каждый менеджер может выпускать свой сервис
  (`socks5://127.0.0.1:<port>`), пусто — когда WARP на хосте нет. Установщик пишет их из
  новой секции `[egress]` (старые `[three_xui].warp` / `warp_port` по-прежнему читаются, с
  одним предупреждением); **хост, собранный или обновлённый вручную**, задаёт их сам до
  `up -d`, иначе экран маршрутизации не показывает провайдера `warp` для этого узла
  (`provider_unavailable`) — честное состояние, а не ошибка.
- Менеджеры ничего не сеют: `upstream`, который уже есть в рукописном Caddyfile, или
  секция `egress`, которая уже есть у mita, показываются как `custom` и остаются до первого
  применения политики; оно переносит их под владение менеджера и хранит исходные строки
  для отката. Ни один конфиг не меняется, пока owner не применит политику.

**Порядок в парке.** Сначала **узлы, потом центр**: центр v0.4 шлёт секцию `egress` только
узлу, объявившему `egress.v1`, а документ без неё сохраняет digest v0.3 в обе стороны —
смешанный парк продолжает работать, а экран маршрутизации помечает старый узел «узел нужно
обновить до v0.4» вместо ошибки. Центр v0.3 у узла v0.4 игнорирует его отчёт об egress.

**Откат** — по общему порядку: предыдущая генерация вместе с базой; образ v0.3 отказывается
от базы со схемой 14. Откат панели не отменяет применённую политику: сначала сбросьте её к
«напрямую» и примените, либо откатите блок менеджера вручную (`# BEGIN NAIVE-MANAGER
EGRESS … # END`; секция `egress` mita) из резервных копий менеджера
(`/var/lib/naive-manager/backups`, журнал mieru-manager).

Проверка после обновления:

```bash
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 14
curl -sS -H 'Host: panel.example.com' http://127.0.0.1:8787/api/routing/targets   # 401 без сессии: маршруты есть
docker inspect proxy-control-mieru-manager --format '{{.HostConfig.NetworkMode}}'   # host
```

## Обновление до v0.5: Xray-router

v0.5 добавляет необязательный выделенный egress-роутер ([XRAY_ROUTER](XRAY_ROUTER.ru.md)). Само
обновление — обычное и **роутер не ставит**: скопируйте из нового релиза `panel/`, `naive_manager/`,
`mieru_manager/`, `xray_router_manager/`, `compose*.yaml`, `scripts/` и `VERSION` в каталог проекта и
выполните `docker compose up -d --build --wait panel naive-manager mieru-manager` с сохранённым
набором оверлеев. Узел без роутера ведёт себя ровно как в v0.4: экран маршрутизации говорит
«Xray-router: не установлен», политики компилируются под нативные backend'ы.

**Миграция 15** (`routing-xray-router`) выполняется при первом старте и по эффекту аддитивна: она
перестраивает `routing_policies` / `routing_rules` / `routing_applies`, чтобы допустить backend
`xray_router` (каждая строка v0.4 сохраняется с историей), и добавляет
`managed_egress.router_revision` / `router_digest`. `python -m panel.cli db-status` покажет
пятнадцать применённых.

**Что меняется на хосте без роутера.** Менеджеры принимают две новые пустые переменные —
`NAIVE_EGRESS_ROUTER` / `NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE` и `MIERU_EGRESS_ROUTER` /
`MIERU_EGRESS_ROUTER_CREDENTIAL_FILE` (умолчания compose) — и отдают провайдер `router` только когда
они заданы. Модель политики принимает `geosites`, `geoips` и правила только с портами; на нативном
backend'е они дают в предпросмотре `rule_kind_unsupported` с упоминанием роутера.

**Добавление роутера на установленный узел.** Положите закреплённый архив как
`/var/lib/proxy-control/Xray-linux-64.zip` (URL и SHA-256 — в `release/external-artifacts.json`;
`scripts/install-release.sh --requirements` его перечисляет), добавьте `router = true` в `[egress]`
конфигурации установщика (и `naive = "router"` / `mieru = "router"` — только если сервис должен
стартовать подключённым) и запустите установщик снова: в плане появится одно действие
`xray_router.runtime` между `warp` и сервисами; apply создаст identity 10006, извлечёт три члена
архива, подготовит `/var/lib/xray-router`, запишет `secrets/xray-router-*` и `.env.xray-router` и
поднимет контейнер; `naive` и `mieru` затем применятся заново с env роутера и копиями ключей.
Обновление сервисы **не** подключает: подключите их на экране маршрутизации, когда будете готовы
(их сессии один раз прервутся). Хост, собранный вручную, проходит те же шаги из `INSTALLER_REFERENCE`
(«Xray-router») с `COMPOSE_FILE`, расширенным `compose.xray-router.yaml`, — именно так прошла живая
проверка v0.5 на продакшн-узле (`docs/releases/v0.5.0-beta.1.md`).

**Порядок в парке.** Сначала узлы, потом центр, как в v0.4: центр v0.5 шлёт секцию роутера,
`companion` или `passthrough` только узлу, объявившему `egress.router.v1`; узел v0.4 их не видит и
сохраняет свои дайджесты; центр v0.4 игнорирует `identity.router` и `router_attached`. Подключённый
сервис на узле, которым управляет центр v0.4, продолжает работать (центр просто не может менять
его политику, пока не обновится).

**Откат** — по общему порядку: предыдущее поколение вместе с базой: образ v0.4 отказывается от базы
на схеме 15. Отключите все сервисы от роутера **до** отката панели (отключение — это нативный
`direct` плюс pass-through роутера, оба применяют менеджеры, и старая панель находит понятные ей
нативные блоки); роутер, оставленный с подключёнными сервисами, продолжает их обслуживать
pass-through, но экран v0.4 покажет их upstream как `custom`.

Проверка после обновления:

```bash
docker compose exec panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 15
curl -sS -H 'Host: panel.example.com' http://127.0.0.1:8787/api/routing/targets   # 401 без сессии
# с роутером:
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -E 'verified|generation'
```

## Обновление из панели через version-agent

Панель не скачивает runtime-артефакты и не получает Docker socket. Отдельный root-owned `version-agent` читает `/etc/proxy-control/versions.json` и слушает только `/run/proxy-control/version-agent.sock`.

Установка:

```bash
sudo install -d -m 0750 /etc/proxy-control
sudo install -o root -g root -m 0644 deploy/version-agent.service /etc/systemd/system/version-agent.service
sudo install -o root -g root -m 0644 deploy/proxy-control-version-agent.tmpfiles.conf /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo install -o root -g root -m 0600 deploy/version-agent.env.example /etc/proxy-control/version-agent.env
sudo install -o root -g root -m 0600 deploy/version-catalog.example.json /etc/proxy-control/versions.json
sudo systemd-tmpfiles --create /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo systemctl daemon-reload
```

Замените все example entries на проверенные оператором артефакты. Для Telemt допустимы только immutable image references (`@sha256:...`). Для NaiveProxy/Caddy и mita — только HTTPS-артефакты с lowercase SHA-256. Каталог является allowlist, а не механизмом discovery; браузер не может его расширить.

В `/etc/proxy-control/version-agent.env` задайте путь deployment и полный список Compose overlays. Агент записывает только generated `version-overrides/compose.versions.yaml`, настроенные бинарники и собственные state/backup. Symlink targets и опасные относительные Compose paths отклоняются. Если настроенный контейнер pin-ит host binary, предварительный Docker inspect работает fail-closed: обновление разрешается только при точном ответе Docker `No such object`; ошибки daemon, permissions, timeout и любое другое неопределённое состояние блокируют операцию.

До первого обновления запишите установленные версии в `/var/lib/proxy-control/version-agent/state.json`. Панель отправляет `expected_current`; несовпадение возвращает `409` и не позволяет устаревшей вкладке изменить уже обновлённый runtime. Компонент в состоянии `rollback_failed` остаётся заблокированным, пока оператор не восстановит и не проверит полную generation, а затем не согласует root-owned state.

Включение и проверка:

```bash
sudo systemctl enable --now version-agent
sudo systemctl is-active version-agent
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/versions
```

Panel Compose должен монтировать `/run/proxy-control` и задавать `VERSION_AGENT_SOCKET=/run/proxy-control/version-agent.sock`. Socket создаётся с режимом `0660`; его numeric group должен быть доступен UID панели `10001`, но не должен быть world-writable.

### Telemt

Агент сначала считывает image работающего контейнера, скачивает выбранный immutable image, использует полный Compose-набор с `version-overrides/compose.versions.yaml`, пересоздаёт только `mtproxy` и проверяет как выбранный image reference, так и статус `healthy`. Ошибка pull, запуска, readback или health восстанавливает прежний override и запускает прежний image. Rollback считается успешным только после проверки прежнего image reference и container health теми же gates. `down -v` не вызывается.

### NaiveProxy/Caddy и Mieru/mita

Агент скачивает не более 256 MiB с HTTPS-host из каталога, проверяет SHA-256, размещает executable с mode `0755`, запускает checker и атомарно заменяет target. Для Caddy дополнительно проверяются Caddyfile и обязательный module checker. Version pin считывается обратно, служба перезапускается, после чего обязателен `systemctl is-active`.

При любой ошибке агент восстанавливает предыдущие binary и pin, проверяет hash восстановленного binary и readback pin, повторяет checker и Caddyfile validation, перезапускает службу и требует успешный `systemctl is-active`. Новая версия записывается в state только после успеха. Если любой restore, config/readback, restart или health gate отката не прошёл, состояние сохраняется и возвращается как `rollback_failed`; не повторяйте update endpoint, пока оператор не восстановит и не проверит полную предыдущую generation.

## Проверка после обновления

Минимальный набор:

```bash
docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml ps
curl --fail -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
sudo nginx -t
sudo systemctl is-active version-agent caddy-naive mita
sudo journalctl -u version-agent --since=-15min --no-pager
```

Затем выполните реальный protocol smoke-тест изменённой границы и проверьте соседние SNI-маршруты. Перед передачей вывода удалите URL, токены, QR payloads, cookies, сертификаты, закрытые ключи и содержимое journal.

`repair` и `uninstall` используют ownership manifest и намеренно отклоняют foreign drift; см. [COMPATIBILITY.md](COMPATIBILITY.md). Брендинг не является основанием для миграции runtime-path.
