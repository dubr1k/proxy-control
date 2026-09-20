# Операционный runbook Proxy Control

[English](OPERATIONS.en.md) · **Русский**

Это руководство — для уже развёрнутого узла. Оно не заменяет [installation guide](../INSTALL.ru.md), [backup contract](BACKUP_RESTORE.ru.md) или protocol-specific acceptance tests.

## 1. Перед началом смены

Зафиксируйте контекст, не выводя secret-bearing environment:

```bash
cd /opt/mtproxy-shared443   # либо фактический checkout/deployment path
git rev-parse HEAD 2>/dev/null || true
docker compose ps
systemctl is-active nginx docker
sudo nginx -t
ss -lntup
```

Проверьте, что используется полный deployment overlay set. Предпочтительный вариант — root-only `.env` с одной строкой:

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml:compose.mieru.yaml
```

Не печатайте полный `.env` в терминал, issue или CI. Не используйте `docker compose --remove-orphans`, если текущая модель не содержит все активные overlays.

## 2. Ежедневная проверка

```bash
docker compose ps
curl -fsS -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
sudo nginx -t
systemctl --no-pager --full status nginx
```

Если включены host runtimes:

```bash
systemctl is-active caddy-naive mita
sudo -u mita env MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

Для `mita` принимайте только точный anchored status output вида:

```text
mita server status is "RUNNING"
```

Не интерпретируйте произвольное слово `RUNNING` в stderr или соседней строке как успешный статус.

## 3. Protocol acceptance

### MTProxy / Telemt

1. Убедитесь, что public TCP/443 принадлежит Nginx, а Telemt слушает ожидаемый loopback backend.
2. Выполните внешний Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ` probe для каждого active secret.
3. Проверьте реальный Telegram client из целевой сети.
4. Regression-test соседние SNI routes.

HTTP health или открытый порт не подтверждают MTProto.

### NaiveProxy

1. Проверьте cover HTTPS без credentials.
2. Выполните authenticated CONNECT и передайте известный payload.
3. Закройте tunnel и только после этого проверьте accounting increment.
4. Убедитесь, что authorization не попал в access logs.
5. Проверьте соседние SNI routes.

### Mieru

1. Проверьте pinned `/usr/bin/mita` version/digest и exact status.
2. Выполните реальный client → server → Internet probe для TCP/UDP согласно active config.
3. Проверьте manager health и panel typed status.
4. Не ожидайте per-user traffic counters: безопасная typed boundary для них отсутствует, поэтому UI показывает `unavailable`.

## 4. Управление пользователями

### Роли

- `owner`: администраторы, пользователи, reveal/rotation, API-ключи, fleet registry и связанные панели;
- `admin`: protocol users и audit в разрешённых границах;
- `viewer`: read-only, без reveal, reset и mutations.

Все мутации через сессию требуют CSRF; Bearer-запрос не несёт cookie и ограничен scope своего ключа. Audit содержит action/actor/target/result, но не credentials, URLs, QR payloads или reveal tokens.

### One-time credentials

Naive и Mieru create/rotate возвращают credential только через one-time reveal с `Cache-Control: no-store`. После закрытия диалога frontend очищает URL, QR и config fields.

Существующий Mieru password нельзя восстановить из `hashedPassword`. Для повторной выдачи используйте **«Новая ссылка + QR»**; это rotation, после которой старая конфигурация недействительна.

## 5. Изменение конфигурации

Перед mutation:

1. Сделайте backup одной согласованной generation.
2. Зафиксируйте current revision, images/binary digests и service status.
3. Выполните config validation/read-only plan.
4. Меняйте одну protocol boundary.
5. Проверяйте health, real protocol path, accounting и adjacent SNI.
6. Только после этого удаляйте временные rollback artifacts по retention policy.

Naive manager и Mieru manager сами используют backup/journal/recovery. Это не отменяет host-level backup перед deployment change.

## 6. Логи

Используйте bounded запросы и сначала смотрите последние события:

```bash
docker compose logs --since=15m --tail=300 panel mtproxy
journalctl -u nginx -u caddy-naive -u mita --since=-15m --no-pager
```

Перед передачей логов удалите:

- passwords и complete access URLs;
- QR/reveal payloads;
- bearer/manager/fleet tokens и API-ключи (`pc_…`);
- cookies, CSRF values, certificate/private key data;
- public IP/hostname/node identity, если это не требуется для приватного incident channel.

### Подписки: логи и ротация

Ссылка подписки клиента (`https://<домен подписки>/s/<token>`) — bearer-секрет: тот, у кого
она есть, получает все доступы этого клиента. По конструкции она не попадает в логи: панель
запускает uvicorn без access log, блок `server` Nginx для домена подписки имеет `access_log off`,
а в базе панели хранится хэш токена и (с v0.10) его копия, зашифрованная мастер-ключом панели —
без ключа копии нет. Показ ссылки в панели («Показать» в окне клиента) доступен owner/admin,
идёт через одноразовый reveal и пишет в аудит `subscription.reveal`. Не добавляйте логирование
запросов на этот путь и не вставляйте ссылку подписки в тикеты.

Если ссылка утекла — ротируйте подписку клиента в панели: старый токен перестаёт отвечать (404,
как и неизвестный) в той же транзакции, где выдаётся новый, поэтому двух живых ссылок не бывает.
Отзыв без перевыпуска действует так же. Ротация credential доступа (Naive/Mieru/MTProxy) ссылку
подписки не меняет: клиенты заберут новую ссылку при следующем обновлении (`Profile-Update-Interval: 12`,
а `ETag`/`If-None-Match` оставляют неизменившиеся запросы на 304).

## 7. Accounting

- Telemt runtime counter и quota usage — разные величины.
- Naive bytes появляются после закрытия successful CONNECT.
- Mieru per-user traffic отображается как unavailable, а quota — rolling approximate session-admission check.
- Reset создаёт local baseline; он не превращает telemetry в billing record и не задаёт calendar period.

См. [ACCOUNTING.md](ACCOUNTING.md).

## 8. Restart и recovery

Restart выполняйте по одной boundary:

```bash
docker compose restart panel
systemctl restart caddy-naive
systemctl restart mita
```

После каждого restart повторите соответствующий acceptance test. Не удаляйте `journal.json`, `journal.key`, `transaction.json`, WAL/SHM или manager backups, чтобы «починить» startup: это разрушает recovery contract. Используйте documented repair/restore path.

Для installer-owned core:

```bash
sudo python3 scripts/proxyctl.py repair
```

`repair` читает private ownership manifest и намеренно не принимает arbitrary paths.

## 9. Incident sequence

1. Остановите новые mutations, но не уничтожайте process/state.
2. Снимите service status, exact revision, bounded logs и listener ownership.
3. Создайте forensic backup текущей generation.
4. Определите boundary: Nginx routing, panel, Telemt, Caddy/Naive, mita/Mieru, связь с центром или связанной панелью, либо fleet v1.
5. Выполните negative и positive probe этой boundary.
6. Repair или rollback делайте только после подтверждения root cause.
7. После восстановления выполните полный protocol regression, включая соседние SNI.

См. [Troubleshooting](TROUBLESHOOTING.ru.md).

## 10. Завершение смены

- `docker compose ps` показывает ожидаемые healthy services;
- `nginx -t` успешен;
- public listener ownership не изменился;
- MTProxy/Naive/Mieru acceptance выполнен для затронутых boundaries;
- SQLite integrity и backup checksums проверены;
- temporary configs, clients, worktrees, packages и caches удалены;
- production credentials не остались в shell history, logs или artifacts.

## 11. Центральная панель и связанные панели (Fleet v2)

С v0.3 панель может управлять другими панелями по HTTPS с API-ключом `node-sync`; модель
описана в [FLEET.ru.md](../FLEET.ru.md). Runbook добавляет к ней порядок действий на парке
хостов.

### Порядок раскатки

Центр и его узлы должны работать на **одной и той же сборке v0.3**. Узел проверяет документ
поколения строго (`extra = forbid`), поэтому узел на более старой сборке отвергает документ
с незнакомым полем (например, `origin`) с 422; центр тогда записывает для этого узла
`last_error: push 422: rejected` и уходит в backoff (30 с → 10 мин), пока что-нибудь не
изменится. У панели v0.2 нет `/api/fleet/v2/*` вообще, и добавить её нельзя («the node
answered 404»). Поэтому:

1. **Сначала обновите узлы, затем центр.** На каждом хосте в каталоге проекта:
   `docker compose up -d --build --wait panel` с сохранённым набором overlays. Миграции 9–13
   применяются при старте; `panel_guid` создаётся при первом старте
   ([UPGRADING](UPGRADING.ru.md)).
2. На каждом узле создайте ключ `node-sync` («Администраторы → API-ключи → Создать ключ»).
3. На центре добавьте панели («Узлы → + Панель → Проверить → Добавить») и импортируйте их
   пользователей. Первый heartbeat (≤ `PANEL_FLEET_HEARTBEAT_SECONDS`, по умолчанию 15 с)
   делает карточку `online`.

**Хосты, обновляемые rsync.** Панель сообщает версию из файла `VERSION`, который
`compose.yaml` монтирует read-only в `/app/VERSION`; установщик копирует этот файл в
каталог проекта сам. Хост, который вы обновляете rsync, должен получить `VERSION` **вместе с
кодом** — иначе узел сообщает центру `dev`, а его карточка показывает «панель dev».
Отсутствующий или нечитаемый файл никогда не мешает панели стартовать.

### Heartbeat и ежедневная проверка

`PANEL_FLEET_HEARTBEAT_SECONDS` в окружении центра задаёт период (по умолчанию 15, минимум
1; на стенде — 3). Один тик стоит два запроса на узел (`identity`, `status`) плюс push,
когда есть недоставленное поколение, — всё в пределах лимита 120/мин на ключ узла. На
экране «Узлы» центра каждая связанная карточка должна быть `online`, показывать `desired`
равным `applied` без пометки «есть недоставленные изменения» и не иметь `last_error`;
`GET /api/events` перечисляет переходы `node.up`/`node.down`. На узле карточка «Этот
сервер» называет центр, который им управляет; пользователи, принадлежащие центру, показаны
как «управляется центром» и отказывают локальной мутации с 409 `managed_by_central`.

### Пауза, отвязка, удаление

- **Пауза** («Пауза» или «Отключить» для связанной панели): heartbeat и доставка пропускают
  узел, связь и её доступы остаются, абоненты продолжают работать. Используйте её на время
  обслуживания узла.
- **Отвязка на узле** («Отвязать» в карточке «Этот сервер», только владелец, либо
  `POST /api/nodes/local/unlink`): узел забывает мастера, и каждая учётная запись, которую
  он держал для центра, снова становится локальной; runtime не трогается. Центр сохраняет
  связь и следующим опубликованным поколением снова сделал бы себя мастером — удалите узел
  и там.
- **Удаление на центре** («Удалить», `DELETE /api/nodes/{id}`): отказ (409), пока на панели
  остаются доступы не в состоянии `deleted` — сначала удалите доступы клиентов на этом узле
  и дождитесь отчёта `missing`; строка вычищается, учётная запись в runtime удалена.
  Удаление связи затем отвязывает узел best-effort и удаляет зашифрованный ключ.

### Ротация или отзыв ключа узла

Создайте новый ключ `node-sync` на узле, введите его на центре через «Изменить», затем
выключите или удалите старый ключ на узле — центр сохраняет новый ключ как новую строку
секрета и отзывает старую. Выключение ключа на узле без обновления центра переводит этот
узел в `offline` (`node.down`) на следующем heartbeat, и больше ничего не меняется;
абонентов это не затрагивает.

### Откат

Откат **узла** на предыдущий образ панели подчиняется общему правилу: восстанавливается
полная предыдущая генерация вместе с базой ([UPGRADING](UPGRADING.ru.md)). Образ v0.2
отказывается стартовать на базе со схемой 13 («database schema 13 is newer than this
code»), поэтому один предыдущий образ — это ещё не откат. На узле, который никто не
подключал, обновление не тронуло ни одной учётной записи runtime, а `managed_resources`
пуст, так что база до обновления не теряет никакого fleet-состояния. Узел, которым
управляли: сначала отвяжите (его пользователи становятся локальными и продолжают
работать), затем откатывайте. **Центр**: сначала поставьте на паузу или удалите его связи;
узлы продолжают обслуживать то поколение, которое применили последним.

## 12. Маршрутизация (v0.4)

Egress-политику применяет **менеджер** сервиса, а не правка конфига руками: naive-manager
владеет блоком `# BEGIN NAIVE-MANAGER EGRESS … # END` в
`/var/lib/naive-manager/Caddyfile` (reload, без перезапуска), mieru-manager — секцией
`egress` mita (перезапуск mita: каждая сессия Mieru переподключается один раз).
Рукописные `upstream` или `egress` не трогаются, пока первое применение их не перенимает,
а откат возвращает их байт в байт — [ROUTING](ROUTING.ru.md).

- **Перед применением WARP** предпросмотр должен показывать `warp: доступен`; WARP,
  который не отвечает, даёт fail-closed (`provider_unreachable` / `egress_unreachable`),
  и на узле ничего не меняется. Эндпоинт задают `NAIVE_EGRESS_WARP` / `MIERU_EGRESS_WARP`
  в `.env`.
- **Проверка после применения**: бейдж «применено (rev N)»; `curl --proxy https://<naive
  host>` с учётными данными клиента к заблокированной и к разрешённой цели; клиент Mieru —
  так же; cover-сайт `https://<naive host>/` по-прежнему отвечает 200; `nginx -T` и
  `nft list ruleset` не изменились (маршрутизация их не трогает).
- **Неудачное применение** оставляет работать последнюю применённую ревизию
  (`state = failed`, `last_error` называет код); «Откатить» возвращает предыдущую запись
  менеджера; `manual_intervention_required` значит, что менеджер не смог вернуть конфиг
  после расхождения readback — его резервные копии в `/var/lib/naive-manager/backups` и
  в журнале mieru-manager, а `docker compose logs naive-manager mieru-manager` называет
  файл.
- **Связанные панели**: центр применяет через следующее поколение; карточка узла и экран
  маршрутизации показывают «применяется…», пока не придёт отчёт узла (один heartbeat);
  собственный экран узла отказывает в применении, пока им управляет центр
  (`managed_by_central`). Отвязка оставляет egress как есть.
- Аудит: `routing.policy.update | apply | rollback | delete` на той панели, которая применяла.

## 13. Xray-router (v0.5)

Узел с `[egress] router = true` держит `proxy-control-xray-router`
([XRAY_ROUTER](XRAY_ROUTER.ru.md)). Его здоровье — часть ежедневной проверки:

```bash
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool
# artifacts.*.verified == true, phase == "idle", running.generation >= 1
ss -ltnp 'sport = :45101 or sport = :45102'   # только 127.0.0.1, владелец xray
```

- **Подключение / отключение** — действия owner на экране маршрутизации; каждое один раз
  прерывает сессии сервиса (reload Caddy, restart mita). Подключение при всё ещё применённой
  нативной политике отвергается (`policy_applied`): сначала сбросьте её. После подключения в
  Caddyfile стоит `upstream socks5://…@127.0.0.1:45101`, в `egress` mita — прокси `router`; не
  правьте их руками: ручная правка показывается как `attached: false`, а политика
  отказывается применяться (`not_attached`); повторное подключение чинит это.
- **Применение политики роутера** подменяет поколение Xray (≈ 50 мс) и прерывает открытые
  сессии **обоих** подключённых сервисов; сначала предпросмотр, применяйте один раз. WARP, который
  не отвечает, даёт fail-closed (`egress_unreachable`); неизвестный код geodata падает в
  собственном тестовом запуске роутера (`geosite_unknown` / `geoip_unknown`), и ничего не меняется.
- **`artifact_mismatch`**: роутер не стартует, потому что бинарь или geodata не совпадают с пином.
  Извлеките заново из закреплённого архива (`BACKUP_RESTORE`, «Xray-router generation») или
  выполните `proxyctl repair`; никогда не подменяйте файлы другой сборкой.
- **`manual_intervention_required` / `phase: broken`**: не поднялось и последнее хорошее
  поколение. Подключённые сервисы fail-closed, пока вы не вмешаетесь: читайте
  `docker logs proxy-control-xray-router`, устраните причину (диск, geodata), затем
  `docker compose … restart xray-router` (bootstrap запустит последнее закоммиченное поколение)
  либо отключите сервисы, чтобы они пока шли нативно.
- **Умерший дочерний процесс** watchdog перезапускает за секунды с тем же поколением; три
  неудачных старта подряд делают роутер `broken`.
- **Ротация ключей ingress**: `sudo /usr/local/libexec/rotate-xray-router-ingress` (оба сервиса)
  или с `naive` / `mieru`. Скрипт пересоздаёт роутер и менеджеры; менеджер, чей блок ещё несёт
  старый ключ, показывает `router_credential_stale`, пока не перерисует. Ротируйте после
  восстановления из резервной копии и при любом подозрении на утечку ключа.
- **Логи**: менеджера — `docker logs proxy-control-xray-router`; access-лог дочернего процесса
  выключен намеренно. Ни логи, ни API, ни аудит, ни отчёты не несут ключ ingress; secret-scan
  лаборатории падает на такой форме.
- Аудит: `routing.target.attach | detach` рядом с событиями политик.

