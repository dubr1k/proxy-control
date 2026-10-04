# Обновление и откат

Это руководство — для хоста, на котором уже работает Proxy Control 1.0.0 или новее: как его
обновить, что делает `version-agent` панели, как откатиться и как включить необязательные
компоненты на уже установленном узле. Каждый runtime — панель, каждый менеджер, Telemt,
NaiveProxy/Caddy, Mieru/mita и Xray-router — рассматривайте как отдельную границу изменения.

## Общий порядок

1. Прочитайте [changelog](../CHANGELOG.ru.md) и заметки о всех выпусках между установленным и
   целевым, [политику совместимости](COMPATIBILITY.md), лицензии upstream и сведения о
   pinned-артефактах (`release/external-artifacts.json`).
2. Сделайте одну согласованную резервную генерацию: файлы секретов, named volumes, SQLite вместе с
   WAL/SHM, состояние менеджеров и journal keys, файлы Nginx и ownership manifest. Мастер-ключ
   панели `secrets/panel-master-key` храните отдельно от базы ([backup и
   restore](BACKUP_RESTORE.ru.md)).
3. В парке сначала обновите связанные узлы, центральную панель — последней ([порядок в
   парке](#порядок-в-парке)).
4. Обновите [одной командой](#обновление-одной-командой) или с экрана «Версии» панели
   ([агент обновлений панели](#агент-обновлений-панели-version-agent)). Оба пути сверяют архив
   выпуска с `SHA256SUMS`, сохраняют копию для отката и при сбое возвращают её.
5. Для любого шага вручную отрендерите модель Compose и план установщика без применения и
   проверьте digest образов и бинарников, numeric identities, порты, mounts и SNI-маршруты.
   Убедитесь, что у всех работающих контейнеров проекта есть label
   `com.docker.compose.project=mtproxy`, и используйте точный сохранённый набор overlays
   `COMPOSE_FILE` на всё изменение. Не применяйте `--remove-orphans` к неполной модели.
6. Меняйте одну границу за раз внутри одного стека. После каждого изменения проверяйте
   конфигурацию, health служб, поведение протокола, учёт трафика и соседние SNI-маршруты
   ([проверка](#проверка-после-обновления)).
7. При ошибке остановите изменённую службу и восстановите полную предыдущую генерацию с тем же
   project name и набором overlays ([откат](#откат)). Не пересоздавайте journal keys и не копируйте
   состояние частично.

Если вы разворачиваете из дерева исходников, а не из опубликованного выпуска, сначала выполните
проверки репозитория из [VALIDATION.md](VALIDATION.md).

## Обновление одной командой

Установленный хост обновляется тем же скриптом, что ставит новый, в режиме `--update`. Сначала
сделайте резервную копию, затем выполните команды обычным пользователем с доступом к `sudo` в
каталоге, где нет прежнего `proxy-control-v<версия>/`:

```bash
curl -fsSLO https://github.com/dubr1k/proxy-control/releases/latest/download/install-release.sh
curl -fsSLO https://github.com/dubr1k/proxy-control/releases/latest/download/install-release.sh.sha256
sha256sum --check install-release.sh.sha256
bash install-release.sh --update
```

Скрипт скачивается, сверяется с собственной опубликованной контрольной суммой и читается до
запуска; в shell через конвейер он не передаётся никогда. В него записаны версия и SHA-256 архива
своего выпуска, на него тоже выпускается attestation:
`gh attestation verify install-release.sh --repo dubr1k/proxy-control`.

Что он делает:

1. **Без привилегий** скачивает четыре файла выпуска в `./proxy-control-v<версия>/` (`--dir` — другой
   новый каталог), сверяет `SHA256SUMS`, манифест и записанный в скрипт digest архива, при наличии
   `gh` проверяет attestation (`--attest` делает её обязательной) и распаковывает архив. Подменённый
   архив не проходит, даже если вместе с ним подменён и `SHA256SUMS`.
2. **Одним `sudo`** запускает `scripts/update-host.sh` из проверенного дерева. Тот просит
   version-agent хоста обновить панель — только если агент предлагает ровно тот digest архива, что
   проверен на шаге 1, — и ждёт, пока панель не ответит новой версией. Агент сохраняет копии
   дерева, образа и базы и при сбое откатывает всё обратно ([обновление самой
   панели](#обновление-самой-панели-из-ui)).
3. Пересобирает менеджеры, которые агент назвал в `pending_rebuild` (`mieru-manager`,
   `naive-manager`, `xray-router`), включённый MCP-сервер и, на хосте с Xray-router, мост
   `xray-router-ingress` — тем же вызовом Compose, что и агент. Образ каждой работающей службы
   сначала получает тег `mtproxy-<служба>:rollback-<время>`; неудачная пересборка возвращает
   прежние образы, проверяет их здоровье и всё равно сообщает об ошибке обновления.
4. Переводит владеемые шаблоны ingress Nginx (со своей резервной копией и откатом) и в конце
   требует, чтобы каждый контейнер `proxy-control-*` был healthy или running.

**Не трогаются:** Telemt и `mask`, сертификаты, `.env*` и `secrets/`. Если изменился `docker/`,
перезапустите Telemt и `mask` сами ([ниже](#перезапуск-telemt-и-mask-после-изменения-docker)).

**Отказы.** Обновление останавливается, ничего не изменив, если работающая необязательная служба
(MCP, менеджер, Xray-router или его мост, legacy-службы fleet) отсутствует в списке overlays агента
`PROXY_CONTROL_COMPOSE_FILES` в `/etc/proxy-control/version-agent.env` — иначе эта служба осталась
бы со старым кодом. Нужен version-agent, его ставит установщик; без него скрипт останавливается с
`version-agent не найден` ([установка version-agent вручную](#установка-version-agent-вручную)).

`--check-only` скачивает и проверяет без распаковки; `--requirements` печатает требования к хосту.
У хоста, агент которого из 1.1.0 или старше, после первого такого обновления есть ещё один шаг
([замечания при обновлении с 1.0.x и 1.1.0](#замечания-при-обновлении-с-10x-и-110)).

## Порядок в парке

Обновляйте **сначала связанные узлы, потом центральную панель** и держите все панели одного парка
на одном выпуске. Узел проверяет документ поколения строго и отвергает незнакомое поле (422), а
центр отправляет новую секцию только узлу, объявившему соответствующую возможность. Поэтому
смешанный парк продолжает работать во время обновления: узел, который ещё старше, сохраняет свои
digest, а экран маршрутизации называет его кодом вроде `node_lacks_mtproxy_egress` вместо ошибки.

Узел обновляется одной командой на самом хосте или из центра: «Узлы» → узел → «Обновления».

Хост, обновляемый копированием файлов (rsync), должен получить `VERSION` вместе с кодом. Панель
сообщает версию из файла `VERSION` каталога проекта, смонтированного в `/app/VERSION`; устаревший
файл сообщает центру прежний выпуск, отсутствующий — `dev` ([OPERATIONS](OPERATIONS.ru.md),
раздел 11).

## Пересборка изменившихся менеджеров вручную

Обновление панели с экрана «Версии» менеджеры не пересобирает. Если между двумя выпусками
изменились `mieru_manager/`, `naive_manager/`, `xray_router_manager/`, `mcp_server/` или `docker/`,
агент называет их в `pending_rebuild`, а карточка панели говорит «Изменились менеджеры: …».
Обновление одной командой пересобирает их само. После обновления из панели пересоберите их с
env-файлами и overlays самой установки — тем набором, что использует агент
(`PROXY_CONTROL_COMPOSE_DIR` и `PROXY_CONTROL_COMPOSE_FILES` в `/etc/proxy-control/version-agent.env`):

```bash
cd /opt/mtproxy-shared443
docker compose --env-file .env --env-file .env.mieru --env-file .env.xray-router --env-file .env.naive \
  -f compose.yaml -f compose.mieru.yaml -f compose.xray-router.yaml -f compose.naive.yaml \
  up -d --build --no-deps --wait mieru-manager xray-router
```

Оставьте только те `--env-file` и `-f`, что есть у вашей установки (добавьте
`--env-file .optional.env`, `--env-file .env.mcp` и `-f compose.mcp.yaml`, где они есть), и назовите
только изменившиеся службы: `mieru-manager`, `naive-manager`, `xray-router` вместе с
`xray-router-ingress`, `mcp`. Перед этим пометьте работающий образ каждой тегом, как это делает
обновление одной командой (`docker tag <ID образа> mtproxy-<служба>:rollback-<время>`, ID — из
`docker inspect --format '{{.Image}}' proxy-control-<служба>`).

Остальные шаги хоста, которые делает обновление одной командой, после обновления из панели тоже
остаются за вами: перезапуск Telemt и `mask` ([ниже](#перезапуск-telemt-и-mask-после-изменения-docker))
и перевод ingress Nginx ([замечания, 1.1.1](#замечания-при-обновлении-с-10x-и-110)).

## Перезапуск Telemt и mask после изменения `docker/`

В `docker/` лежат, среди прочего, entrypoint Telemt и Caddyfile сайта-прикрытия; они смонтированы
в контейнеры `mtproxy` и `mask`. Ни агент, ни обновление одной командой их не перезапускают. Если
`docker` есть в `pending_rebuild`, пересоздайте оба, когда удобно, — все сессии MTProxy один раз
переподключатся:

```bash
cd /opt/mtproxy-shared443
docker compose --env-file .env --env-file .env.mieru --env-file .env.xray-router --env-file .env.naive \
  -f compose.yaml -f compose.mieru.yaml -f compose.xray-router.yaml -f compose.naive.yaml \
  -f version-overrides/compose.versions.yaml \
  up -d --no-deps --force-recreate --wait mask mtproxy
```

Оставьте те `--env-file` и `-f`, что есть у вашей установки, как и для менеджеров.
`-f version-overrides/compose.versions.yaml` оставляйте всегда, когда файл существует (он появляется,
когда агент обновил Telemt): в нём образ Telemt, поставленный агентом, и без него `mtproxy` вернётся
к образу, закреплённому в `compose.yaml`. Конфигурация Telemt в volume `telemt-config` сохраняется:
entrypoint никогда не пересоздаёт существующую.

## Проверка после обновления

Минимальный набор (с набором overlays установки):

```bash
docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml ps
curl --fail -H 'Host: panel.example.com' http://127.0.0.1:8787/healthz
docker exec proxy-control-panel cat /app/VERSION
docker compose exec -T panel python -m panel.cli db-status | python3 -m json.tool | grep -c '"applied": true'   # 21 начиная с 1.1.0
sudo nginx -t
sudo systemctl is-active version-agent caddy-naive mita
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
sudo journalctl -u version-agent --since=-15min --no-pager
# с Xray-router:
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -E 'verified|generation'
```

Health-check требует заголовок `Host`: установщик разрешает только домен панели. Сводку
готовности для owner/admin даёт `GET /api/readiness` ([OPERATIONS](OPERATIONS.ru.md), раздел 2).

Затем выполните реальный protocol smoke-тест изменённой границы и проверьте соседние
SNI-маршруты. Перед передачей вывода удалите URL, токены, QR payloads, cookies, сертификаты,
закрытые ключи и содержимое journal.

`repair` и `uninstall` используют записанный ownership manifest и намеренно отклоняют foreign
drift; см. [COMPATIBILITY.md](COMPATIBILITY.md). Брендинг не является основанием для миграции
runtime-path.

## Откат

**Панель движется только вперёд.** Её база мигрирует при старте, а более старый образ отказывается
от более новой схемы («database schema N is newer than this code»). Поэтому агент предлагает
панель только вперёд и отказывает в понижении версии; возврат — это восстановление полной
предыдущей генерации вместе с базой ([backup и restore](BACKUP_RESTORE.ru.md), раздел об откате
обновления). Runtime — Telemt, NaiveProxy, Mieru, Xray-router — можно откатить с экрана «Версии»
(группа «Откат на прежнюю»); агент проверяет и сохраняет копию так же, как при обновлении.

**Неудачное обновление откатывается само.** Агент возвращает дерево, файлы базы и прежний образ;
обновление одной командой возвращает ещё и помеченные им образы менеджеров. Если даже
восстановленное состояние не проходит проверки, компонент получает `rollback_failed` и не
принимает следующих обновлений, пока оператор не восстановит и не проверит полную предыдущую
генерацию и не согласует root-owned state; всё нужное лежит в
`/var/lib/proxy-control/version-agent/backups/`.

**Вручную:**

1. Остановите изменённую границу и сохраните неудачную генерацию для разбора.
2. Восстановите полную предыдущую генерацию: образы (`mtproxy-panel:rollback-<время>`,
   `mtproxy-<служба>:rollback-<время>`), базу с её WAL/SHM, дерево, бинарники, units и набор
   overlays.
3. Проверьте конфигурацию до старта или reload, затем health и реальные protocol-пробы, соседние
   SNI-маршруты и непрерывность учёта. Без проверенного восстановления не объявляйте откат
   успешным и не удаляйте recovery journal.

**Чего не отменяет откат панели.** Политики и подключения, применённые менеджерами, остаются на
узле. Перед откатом панели через выпуск, который ввёл то, чем вы пользуетесь, сначала отмените это
в панели — например, отключите MTProxy от Xray-router перед возвратом на 1.0.x: Telemt тогда
снова ходит напрямую своим прежним upstream. Собственный блок менеджера можно восстановить и из его
резервных копий (`/var/lib/naive-manager/backups`, журнал mieru-manager).

**В парке.** Узел, которым управляет центр, сначала отвяжите («Отвязать» на карточке «Этот
сервер»): его пользователи станут локальными и продолжат работать. На центре сначала поставьте
связи на паузу или удалите их; узлы продолжают обслуживать последнее применённое поколение.

## Замечания при обновлении с 1.0.x и 1.1.0

- **Одна команда с 1.0.x.** `install-release.sh --update` выпуска 1.1.0 или новее обновляет и хост на
  1.0.x: ему нужен только version-agent, который поставил установщик. У скриптов выпусков до 1.1.0
  режима `--update` нет.
- **Первое обновление старым агентом.** Агент из 1.1.0 или старше не умеет передать новому выпуску
  владение установщика кодом Core и собственным кодом агента. Когда панель ответит новой версией,
  запустите установщик нового выпуска из его распакованного каталога с точным архивом и его
  проверенным SHA-256 (его печатает `install-release.sh`, он же — в строке архива в `SHA256SUMS`) —
  до следующего `repair`:

  ```bash installer-check
  cd proxy-control-vX.Y.Z/proxy-control
  sudo python3 -m installer.cli reconcile-panel-update --archive ../proxy-control-vX.Y.Z.tar.gz --sha256 '<64-символьный digest архива>'
  sudo python3 -m installer.cli repair --json
  ```

  Команда проверяет архив, версию работающей панели, заменённые файлы и все не связанные с этим
  владеемые файлы и отказывает при foreign drift ([справочник
  установщика](INSTALLER_REFERENCE.ru.md#команды)). Агенты начиная с 1.1.1 передают владение сами.
- **С 1.0.0: менеджеры.** В 1.0.1 изменились `mieru_manager` и `xray_router_manager`; если
  обновление шло из панели, пересоберите их ([пересборка
  менеджеров](#пересборка-изменившихся-менеджеров-вручную)). После этого менеджер Mieru принимает
  любую mita (3.38 и новее ставятся с «Версий»), а роутер, где geodata никто не настраивал,
  переходит на Loyalsoldier с ежедневным обновлением и сразу скачивает свежие списки (один
  перезапуск роутера).
- **1.0.2 и 1.0.3** меняют соответственно только панель и только установщик с файлами выпуска: без
  миграций и без пересборки менеджеров.
- **Переход на 1.1.0 и новее.** Миграция 21 (`routing-mtproxy`) перестраивает `routing_policies`,
  `routing_rules`, `routing_applies` и `managed_egress`, чтобы допустить `mtproxy` и
  `mtproxy_native`; каждая строка сохраняется с историей. На узле с Xray-router роутер
  пересобирается и поднимается мост `xray-router-ingress` (обновление одной командой делает оба
  шага; вручную — `up -d --build --no-deps --wait xray-router xray-router-ingress`). Роутер сам
  создаёт учётку входа `mtproxy` и перерисовывает генерацию: один перезапуск Xray, сессии NaiveProxy
  и Mieru через роутер один раз переподключатся. До этого экран маршрутизации показывает для MTProxy
  `router_lacks_mtproxy`, а NaiveProxy и Mieru работают как раньше. Образ 1.0.x отказывается от базы
  на схеме 21.
- **1.1.1: IP клиентов.** Обновление одной командой переводит владеемые шаблоны ingress Nginx
  установки `fresh` так, чтобы панель видела IP клиентов; изменённые вручную шаблоны отклоняются, а
  чужой frontend в режиме `coexist` остаётся как есть, и ему нужен PROXY-мост, настроенный
  оператором. После обновления только из панели выполните этот шаг хоста из распакованного выпуска —
  сначала без `--apply` (план только для чтения), затем от root с ним ([справочник
  установщика](INSTALLER_REFERENCE.ru.md)):

  ```bash
  python3 -m installer.ingress_upgrade --project-dir /opt/mtproxy-shared443
  sudo python3 -m installer.ingress_upgrade --project-dir /opt/mtproxy-shared443 --apply
  ```

- **1.1.1: 3x-ui.** Управляемая установка 3x-ui закрепляет 3x-ui 3.9.0. Существующий 3x-ui
  обновляется средствами самого 3x-ui; обновление Proxy Control его версию не меняет.

## Агент обновлений панели (version-agent)

Панель не скачивает runtime-артефакты и не получает Docker socket. Отдельный root-owned
`version-agent` читает `/etc/proxy-control/versions.json` и слушает только Unix socket
`/run/proxy-control/version-agent.sock`.

Агента настраивает установщик: адаптер `version_agent` работает последним, копирует код агента в
`/opt/proxy-control`, ставит unit и tmpfiles-фрагмент, пишет `version-agent.env` с полным списком
Compose-overlay профиля и флагом Xray-router, создаёт пустой `versions.json` и `state.json` с только
что поставленными версиями и ждёт `/v1/health`. `repair` переписывает владеемые файлы и не трогает
каталог и state.

Экран «Версии» показывает для каждого runtime — Telemt, NaiveProxy/Caddy, Mieru/mita и Xray-router,
если он установлен, — несколько последних выпусков в двух группах: «Новее установленной» и «Откат на
прежнюю»; карточка «Proxy Control / панель» предлагает только более новые выпуски. Установка —
действие роли `owner`. Интерфейс отправляет `expected_current`; несовпадение возвращает `409`, и устаревшая
вкладка не может изменить уже обновлённый runtime. Компонент в состоянии `rollback_failed` остаётся
заблокированным, пока оператор не восстановит и не проверит полную генерацию, а затем не согласует
root-owned state. Связанные узлы обновляются из центра так же: «Узлы» → узел → «Обновления».

### Telemt

Агент сначала считывает image работающего контейнера, скачивает выбранный immutable image,
использует полный Compose-набор с `version-overrides/compose.versions.yaml`, пересоздаёт только
`mtproxy` и проверяет как выбранный image reference, так и статус `healthy`. Ошибка pull, запуска,
readback или health восстанавливает прежний override и запускает прежний image. Rollback считается
успешным только после проверки прежнего image reference и container health теми же gates.
`down -v` не вызывается.

### NaiveProxy/Caddy и Mieru/mita

Агент скачивает не более 256 MiB с HTTPS-host, записанного для версии, проверяет SHA-256, размещает
executable с mode `0755`, запускает checker и атомарно заменяет target. Для Caddy дополнительно
проверяются Caddyfile и обязательный module checker. Version pin считывается обратно, служба
перезапускается, после чего обязателен `systemctl is-active`.

При любой ошибке агент восстанавливает предыдущие binary и pin, проверяет hash восстановленного
binary и readback pin, повторяет checker и Caddyfile validation, перезапускает службу и требует
успешный `systemctl is-active`. Новая версия записывается в state только после успеха. Если любой
restore, config/readback, restart или health gate отката не прошёл, состояние сохраняется и
возвращается как `rollback_failed`; не повторяйте update endpoint, пока оператор не восстановит и
не проверит полную предыдущую generation.

Обновление `mita` переписывает пин в `.env.mieru`, перезапускает `mita` и слоты полос `mita@<n>` и
пересоздаёт контейнер `mieru-manager` (`PROXY_CONTROL_CONSUMER_OVERLAYS`, ниже).

### Обновления из upstream

Кнопка «Проверить обновления» на экране «Версии» просит агента опросить источники самих проектов.
Каталог `versions.json` остаётся и имеет приоритет («каталог» в списке), а рядом появляются версии
из upstream («upstream»). Хосты опроса зашиты в агент: `api.github.com`, `github.com`,
`objects.githubusercontent.com`, `ghcr.io`, `registry-1.docker.io`, `auth.docker.io`; произвольный
URL невозможен ни из браузера, ни из конфигурации.

| Компонент | Источник | Что ставится | Хэш |
|---|---|---|---|
| Xray-router (`xray`) | GitHub Releases `XTLS/Xray-core` | `xray`, `geoip.dat`, `geosite.dat` из `Xray-linux-64.zip` | `.dgst` релиза |
| Mieru (`mita`) | GitHub Releases `enfein/mieru` | `mita` из `mita_<v>_linux_amd64.tar.gz` | `.sha256.txt` релиза |
| Telemt | реестр `ghcr.io/samnet-dev/mtproxymax-telemt` | образ по digest манифеста | digest реестра |
| NaiveProxy (`naive`) | GitHub Releases `caddyserver/caddy` + ветка `naive` `klzgrad/forwardproxy` | Caddy собирается на хосте (`docker build`, builder-образ по digest, до 15 минут) | пин собранного бинарника |
| Панель | GitHub Releases `dubr1k/proxy-control` | архив выпуска | строка архива в `SHA256SUMS` |

**Что подтверждает хэш из релиза и чего не подтверждает.** Совпадение с
`.dgst`/`.sha256.txt`/digest'ом реестра означает, что файл скачан без искажений и совпадает с тем,
что выложил автор проекта. Оно не означает, что версия проверена этим проектом, и интерфейс говорит
об этом рядом с каждой такой версией. Релиз без опубликованного хэша показывается, но не
устанавливается.

Результат проверки кэшируется в `state.json` (`upstream`), повторный опрос чаще раза в минуту отдаёт
кэш; при недоступном источнике остаётся прежний список и строка `last_error`. Переменные в
`version-agent.env`:

- `PROXY_CONTROL_UPSTREAM_CHECK=off` выключает опрос; остаётся только каталог;
- `PROXY_CONTROL_UPSTREAM_CHECK_INTERVAL` (секунды, по умолчанию `21600`) — агент сам опрашивает
  upstream с этим интервалом, и список версий узла приходит на центр с heartbeat'ом без нажатия
  «Проверить обновления»; `0` — только по запросу;
- `PROXY_CONTROL_XRAY_ROUTER=on` включает компонент `xray` (установщик пишет `on` вместе с
  роутером); `PROXY_CONTROL_XRAY_BIN_DIR`, `PROXY_CONTROL_XRAY_OVERLAY` — каталог бинарников и
  `.env.xray-router`;
- `PROXY_CONTROL_CONSUMER_OVERLAYS=mita=/opt/mtproxy-shared443/.env.mieru:MIERU_MITA_SHA256:mieru-manager`
  называет overlay, в котором закреплён бинарник для контейнера: обновление `mita` переписывает этот
  пин и пересоздаёт менеджер, а не отказывает из-за него.

`ReadWritePaths` unit'а включает `/usr/local/lib/proxy-control`, `/opt/proxy-control` и
`/var/lib/docker/volumes` — это нужно обновлению самой панели.

Обновление `xray` заменяет три файла в каталоге роутера, переписывает `XRAY_ROUTER_*_SHA256` в
`.env.xray-router`, пересоздаёт контейнер `xray-router` и сверяет `xray version` внутри него; любая
ошибка возвращает файлы, overlay и контейнер. Установщик после такого обновления знает о новой
версии из `state.json`: `verify`/`repair` принимают либо свой пин, либо версию, записанную агентом.

### Обновление самой панели из UI

Карточка «Proxy Control / панель» на экране «Версии» показывает выпуски самого проекта на GitHub
(`dubr1k/proxy-control`) со строкой архива из `SHA256SUMS`, и агент ставит выбранный только из
архива выпуска, никогда из ветки. Запрос отвечает сразу (`async: true`), потому что панель
посередине перезапускается: браузер опрашивает `GET /api/versions`, пока `status` компонента не
покинет `updating`, и перезагружает страницу, когда панель отвечает новой версией.

Что делает агент, по порядку:

1. скачивает `proxy-control-v<версия>.tar.gz`, сверяет SHA-256 со строкой `SHA256SUMS` и отказывает
   архиву, где есть член вне `proxy-control/`, с `..`, абсолютный или не обычный файл/каталог — на
   хосте к этому моменту ничего не тронуто;
2. переносит текущие копии в `/var/lib/proxy-control/version-agent/backups/panel.previous/` и
   копирует из архива в каталог проекта ровно этот набор: `panel/`, `installer/`, `scripts/`,
   `docker/`, `mieru_manager/`, `naive_manager/`, `xray_router_manager/`, `mcp_server/`, `release/`,
   `docs/`, файлы `compose*.yaml`, `VERSION`, `uninstall.sh`, `install.sh`, `install-bootstrap`,
   `CHANGELOG*`, `README*`, `THIRD_PARTY_NOTICES.md`, `LICENSE`. **Не трогает**: `secrets/`,
   `.env*`, `version-overrides/`, сертификаты и всё остальное в каталоге. `version_agent/` так же
   уходит в `/opt/proxy-control` (с резервной копией);
3. помечает неизменяемый ID образа работающего контейнера тегом `mtproxy-panel:rollback-<время>`
   (даже если отдельная сборка уже передвинула `mtproxy-panel:latest`), выполняет
   `docker compose … build panel`, останавливает панель и установленный legacy `fleet-ingress`,
   проверяет, что ни один работающий контейнер больше не монтирует том панели, копирует
   `panel.sqlite3`, `-wal` и `-shm` из volume `mtproxy_panel-data` в `backups/panel-db.previous/`
   (владелец и права сохраняются), поднимает панель `up -d --wait` (legacy ingress — после неё) и
   сверяет `docker exec proxy-control-panel cat /app/VERSION`.

**Текущая версия** — та, что сообщает работающий контейнер (`cat /app/VERSION`), а не файл в каталоге
проекта: файл может уйти вперёд, если дерево синхронизировали извне, а панель не пересобрали. Файл
читается, только если контейнер не отвечает.

**Откат.** Любая ошибка после шага 2 возвращает сохранённые записи на место, останавливает
неудачную новую панель, восстанавливает файлы базы в volume (старая панель отказывает более новой,
мигрированной базе, поэтому копия — часть отката), возвращает прежнему образу тег `latest`,
поднимает панель и проверяет, что она отвечает прежней версией. Ошибка остановки или оставшийся
writer запрещают восстановление, и резервная копия остаётся для оператора; неполный снимок никогда
не используется. Состояние тогда `ready` с `last_error`; если не прошла даже проверка
восстановленной панели — `rollback_failed`, и агент не примет следующее обновление панели, пока
оператор не разберётся.

**Менеджеры не пересобираются.** Если между двумя выпусками изменились `mieru_manager/`,
`naive_manager/`, `xray_router_manager/`, `mcp_server/` или `docker/`, агент называет их в
`pending_rebuild`, и карточка об этом говорит: пересоберите эти службы
([вручную](#пересборка-изменившихся-менеджеров-вручную)) или выполните [обновление одной
командой](#обновление-одной-командой) — оно ещё и приводит включённый MCP-сервер к проверенному
дереву выпуска, даже если старый агент пропустил его исходники (прежние исходники остаются в
`version-overrides/mcp-source-previous-*`). Код агента синхронизируется с выпуском; если он
изменился, агент планирует свой перезапуск (`systemd-run --on-active=5 … systemctl restart
version-agent`) самым последним шагом, после записи состояния.

Переменные в `version-agent.env` (значения по умолчанию совпадают с установщиком):
`PROXY_CONTROL_AGENT_DIR=/opt/proxy-control`, `PROXY_CONTROL_PANEL_IMAGE=mtproxy-panel`,
`PROXY_CONTROL_PANEL_CONTAINER=proxy-control-panel`,
`PROXY_CONTROL_PANEL_VOLUME=mtproxy_panel-data`.

### Установка version-agent вручную

Для хоста, собранного вручную, или хоста, где агента удалили. Установите файлы, не меняя
работающий стек:

```bash
sudo install -d -m 0750 /etc/proxy-control
sudo install -o root -g root -m 0644 deploy/version-agent.service /etc/systemd/system/version-agent.service
sudo install -o root -g root -m 0644 deploy/proxy-control-version-agent.tmpfiles.conf /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo install -o root -g root -m 0600 deploy/version-agent.env.example /etc/proxy-control/version-agent.env
sudo install -o root -g root -m 0600 deploy/version-catalog.example.json /etc/proxy-control/versions.json
sudo systemd-tmpfiles --create /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo systemctl daemon-reload
```

Замените все example entries на проверенные оператором артефакты. Для Telemt допустимы только
immutable image references (`@sha256:...`). Для NaiveProxy/Caddy и mita — только HTTPS-артефакты с
lowercase SHA-256. Каталог является allowlist, а не механизмом discovery; браузер не может его
расширить.

В `/etc/proxy-control/version-agent.env` задайте путь deployment и полный список Compose overlays
(`PROXY_CONTROL_COMPOSE_DIR`, `PROXY_CONTROL_COMPOSE_FILES`). Агент записывает только generated
`version-overrides/compose.versions.yaml`, настроенные бинарники и собственные state/backup. Symlink
targets и опасные относительные Compose paths отклоняются. Если настроенный контейнер pin-ит host
binary, предварительный Docker inspect работает fail-closed: обновление разрешается только при
точном ответе Docker `No such object`; ошибки daemon, permissions, timeout и любое другое
неопределённое состояние блокируют операцию.

До первого обновления запишите установленные версии в
`/var/lib/proxy-control/version-agent/state.json`. Затем включите и проверьте агента:

```bash
sudo systemctl enable --now version-agent
sudo systemctl is-active version-agent
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/versions
```

Panel Compose должен монтировать `/run/proxy-control` и задавать
`VERSION_AGENT_SOCKET=/run/proxy-control/version-agent.sock`. Socket создаётся с режимом `0660`; его
numeric group должен быть доступен UID панели `10001`, но не должен быть world-writable.

## Мастер-ключ панели

Учётные данные клиентов, сохранённые копии подписок и ключи узлов хранятся зашифрованными ключом
из `secrets/panel-master-key` — Compose secret сервиса `panel`.

- **Установка через установщик**: делать ничего не нужно. Установщик создаёт ключ при установке,
  сохраняет его при каждом обновлении и `repair` и никогда не генерирует новый поверх — новый ключ
  сделал бы все сохранённые секреты нерасшифровываемыми.
- **Ручная сборка из `compose.yaml`**: создайте ключ один раз до первого `docker compose up`, иначе
  Compose откажется стартовать из-за отсутствующего файла секрета:

```bash
umask 077
docker run --rm -v "$PWD/secrets":/out --entrypoint python mtproxy-panel:latest \
  -m panel.cli master-key-init --path /out/panel-master-key
```

Положите копию **отдельно от базы** ([backup и restore](BACKUP_RESTORE.ru.md)). Панель, которая ещё
не сохранила ни одного секрета, стартует и без ключа; как только зашифрованные строки появились, а
ключ пропал, панель отказывается стартовать вместо того, чтобы отдавать пустые подписки. Панель без
мастер-ключа не может показать подписку повторно и не может управляться центром (push отвечает 409
`secret_store_disabled`).

Ротация — отдельная осознанная операция и никогда не часть обновления:

```bash
docker compose exec panel python -m panel.cli master-key-rotate --path /run/panel/master-key
```

Она добавляет новый активный ключ, перешифровывает все секреты батчами, проверяет результат и только
затем сужает keyring до нового ключа — прерванная ротация оставляет всё читаемым.

## Включение Xray-router на установленном узле

Обновление никогда не ставит необязательный egress-роутер ([XRAY_ROUTER](XRAY_ROUTER.ru.md)). Узел
без него продолжает работать: экран маршрутизации говорит «Xray-router: не установлен», политики
компилируются под собственные backend'ы сервисов, а правила с `geosites`, `geoips` или только с
портами дают в предпросмотре `rule_kind_unsupported` с упоминанием роутера.

**Что делает с ним установщик.** Роутер — часть конфигурации установщика: `router = true` в
`[egress]` (в профиле нужен NaiveProxy или Mieru), а `naive = "router"` / `mieru = "router"` — только
если сервис должен стартовать подключённым. Закреплённый архив
`/var/lib/proxy-control/Xray-linux-64.zip` установщик скачает сам, если его нет (URL и SHA-256 — в
`release/external-artifacts.json`; хост без интернета кладёт файл заранее). В плане появляется одно
действие `xray_router.runtime` между `warp` и сервисами: оно создаёт identity 10006, извлекает три
закреплённых члена архива, готовит `/var/lib/xray-router`, пишет `secrets/xray-router-*` и
`.env.xray-router` и поднимает `xray-router` и мост `xray-router-ingress`; `naive` и `mieru` затем
применяются заново с env роутера и своими копиями ключей, а env агента получает
`PROXY_CONTROL_XRAY_ROUTER=on` и overlay роутера.

**На хосте, установленном установщиком.** Установщик применяет конфигурацию как одну установку: на
хосте с активной установкой план из изменённой конфигурации отклоняется
(`an installer transaction already exists`), а повторный запуск той же конфигурации ничего не
меняет. Завершённый `uninstall` без `--purge-data` не мешает следующему `install`, который
подхватывает сохранённые данные — мастер-ключ, базу панели, учётные данные, состояние менеджеров и
named volumes ([справочник установщика](INSTALLER_REFERENCE.ru.md), раздел о восстановлении,
repair, откате и удалении). Между этими шагами службы не работают: сделайте резервную копию и
выберите окно.

**На хосте, собранном вручную.** Пройдите те же шаги из справочника установщика (раздел
«Xray-router») с `COMPOSE_FILE`, расширенным `compose.xray-router.yaml`. Менеджеры узнают роутер из
`NAIVE_EGRESS_ROUTER` / `NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE` и `MIERU_EGRESS_ROUTER` /
`MIERU_EGRESS_ROUTER_CREDENTIAL_FILE` (по умолчанию пустые, и провайдер `router` появляется, только
когда они заданы). Добавьте `compose.xray-router.yaml` в `PROXY_CONTROL_COMPOSE_FILES` и
`PROXY_CONTROL_XRAY_ROUTER=on` в env агента; иначе следующее обновление одной командой откажется
стартовать.

**Подключение сервисов.** Включение роутера ничего не подключает: подключите NaiveProxy и Mieru на
экране маршрутизации, когда будете готовы («Подключить к Xray-router»; их сессии один раз
прервутся). Подключение при применённой нативной политике отклоняется (`policy_applied`): сначала
сбросьте её.

```bash
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -E 'verified|generation'
ss -ltnp 'sport = :45101 or sport = :45102'   # только 127.0.0.1, владелец — xray
```

## Включение relay и слотов полос

Relay позволяет другим узлам парка выходить через этот (цепи); слоты полос дают доступам Mieru
свои полосы ([ROUTING](ROUTING.ru.md), «Цепи и полосы»). Обоим нужен Xray-router.

В конфигурации установщика ими управляют `[egress].relay_port` (по умолчанию 45443 при
`router = true`; `0` — без relay) и `[mieru].lane_slots` (0…8, по умолчанию 4 при роутере):
действие `xray_router.runtime` включает relay через менеджер (пара Reality чеканится один раз и
хранится в `/var/lib/xray-router/relay.json`), `mieru.runtime` ставит шаблон `mita@.service`,
включает `mita@1…4` и записывает `MIERU_LANE_SLOTS` в `.env.mieru`; на управляемом свежем хосте UFW
открывает `45443/tcp` и `46101…46104/tcp`. `repair` включает relay повторно, идемпотентно.
Добавление их к активной установке подчиняется тому же правилу установщика, что и роутер выше.

Хост, собранный вручную:

```bash
# relay (домен панели — прикрытие Reality; порт — публичный)
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --relay-enable panel.example.com 45443
ufw allow 45443/tcp
# слоты Mieru: шаблон юнита, демоны, env менеджера
install -m 0644 deploy/mita@.service /etc/systemd/system/mita@.service && systemctl daemon-reload
for n in 1 2 3 4; do systemctl enable --now mita@$n; ufw allow $((46100+n))/tcp; done
printf 'MIERU_LANE_SLOTS=%s\n' "$(for n in 1 2 3 4; do printf '%s:%s:/run/mita/lane-%s.sock:/var/lib/mita/lanes/%s,' $n $((46100+n)) $n $n; done | sed 's/,$//')" >> .env.mieru
docker compose --env-file .env --env-file .env.mieru -f compose.yaml -f compose.mieru.yaml up -d --wait mieru-manager
```

Проверка:

```bash
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --relay | python3 -m json.tool   # enabled, public_key
systemctl is-active mita@1 mita@2 mita@3 mita@4; ss -lnt | grep -E ':45443|:4610[1-4]'
```

## Geodata роутера

Роутер читает списки geosite/geoip из `/var/lib/xray-router/geodata/` (каталог состояния, доступный
ему на запись). Источник выбирается на «Маршрутизации» → Geodata → «Источник…»: Loyalsoldier (с него
стартует новый роутер, с ежедневным обновлением), списки архива Xray-core (пин; следуют за
обновлением Xray), «Россия — runetfreedom» (`ru-blocked`, `ru-available-only-inside`), «Иран —
chocolate4u», «v2fly» или свои URL. Каждое скачивание сверяется с опубликованной контрольной суммой;
принимаются файлы до 128 МБ.

Новые списки перезапускают роутер и на секунды рвут его соединения, поэтому ежедневное обновление
ждёт выбранного часа — по умолчанию 02:00 UTC (05:00 по Москве), любой из 24 или «в любой час». В
строке geodata видно, когда списки проверялись последний раз, когда будет следующая проверка, и
ошибку перезапуска роутера, если она была.

```bash
docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status | python3 -m json.tool | grep -A3 '"geodata"'
```

Обновление `xray` с экрана «Версии» заменяет бинарник вместе со списками его архива; с источником
«архив Xray-core» роутер переходит на списки нового архива.

## Маршрутизация MTProxy через Xray-router

На узле с Xray-router MTProxy может выходить через WARP, свой выход или другой узел парка
([ROUTING](ROUTING.ru.md)). Он идёт через мост `xray-router-ingress`: Telemt работает в сети Docker,
роутер — в сети хоста, а мост (из того же образа, что и роутер) соединяет их без новых портов на
хосте и без правил firewall; учётку для своего входа `mtproxy` роутер создаёт сам.

1. Убедитесь, что роутер и мост работают на текущем выпуске (обновление одной командой делает это
   само; вручную — [пересборка изменившихся менеджеров](#пересборка-изменившихся-менеджеров-вручную)
   со службами `xray-router xray-router-ingress`).
2. «Маршрутизация» → MTProxy → «Подключить к Xray-router», затем выход: WARP, свой выход или
   другой узел. Подключение меняет upstream Telemt через его API без перезапуска контейнера;
   открытые сессии доживают на прежнем пути. «Отключить от Xray-router» возвращает тот upstream,
   что был у Telemt до подключения.

Правила по CIDR, `geoip` и порту работают; правила по домену, `geosite` и протоколу предпросмотр
отклоняет (`rule_kind_unsupported`), потому что Telemt ходит к дата-центрам Telegram по IP. Экран
маршрутизации называет, чего не хватает: `router_lacks_mtproxy` (роутер ещё не пересобран),
`ingress_unreachable` (мост не отвечает), `node_lacks_mtproxy_egress` (связанный узел старше 1.1).

```bash
docker inspect --format '{{.State.Health.Status}}' proxy-control-xray-router-ingress   # healthy
```
