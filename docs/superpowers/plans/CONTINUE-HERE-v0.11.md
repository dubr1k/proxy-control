# CONTINUE HERE — v0.11 (обновления из upstream), состояние на 2026-09-22

Спек: `docs/superpowers/specs/2026-09-21-v0.11-upstream-updates-design.md`; план:
`docs/superpowers/plans/2026-09-21-v0.11-upstream-updates.md`. Владелец остановил работу на
этапе раскатки («пока остановись, всё закоммить и запушить»); тег — только по его слову.

## Что сделано (всё в `main`)

- Обзор: ресурсы одной строкой, три карточки, без «Application bytes», Mieru подписан «TCP»,
  телефонная раскладка, бейдж «Клиенты»; карточка клиента получила «Узлы и доступы» (окно на матрице).
- version-agent: опрос upstream (`POST /v1/upstream/check`, кэш в `state.json` схема 2, хосты
  зашиты), компоненты `xray` (три файла роутера, пины в `.env.xray-router`) и `panel`
  (самообновление из архива релиза в фоне, откат дерева/базы/образа, `--no-deps`), `mita` с
  переписыванием пина `mieru-manager`, `naive` пересборкой Caddy (`docker build`, `DOCKER_CONFIG` в
  каталоге состояния), журнал причин неудач, `.optional.env`, откат копированием (EXDEV между
  bind-mount'ами `ReadWritePaths`).
- mieru-manager принимает mita 3.35–3.37; агент предлагает mita только в поддержанных линиях
  (`manager_unsupported`).
- Панель: `POST /api/versions/check`, компоненты `xray`/`panel`, relay `versions/check` на узлы,
  экран «Версии» (кнопка проверки, «каталог/upstream», риск, карточки Xray и панели).
- Установщик: адаптер `version_agent` (последний в каждом профиле: код, unit, tmpfiles, env по
  профилю, каталог, `state.json`), `verify` принимает версии из `state.json`, флаг
  `PROXY_CONTROL_XRAY_ROUTER=on` пишет установщик роутера.
- README ru/en: upstream, Mieru только TCP (UDP у клиентов не работает), протоколы и клиенты
  NaiveProxy; UPGRADING, CHANGELOG, заметка `docs/releases/v0.11.0-beta.1.md`, матрица проверок
  (76 строк), VERSION 0.11.0-beta.1.

## Проверено живьём на ams-test (настоящая установка `aurora.sky.dubr1kkk.uk`)

Гейт `remote-gate.sh full` зелёный четыре раза (последний — 2455 passed). Через агент: `xray`
26.3.27→26.9.9, `mita` 3.36.0→3.37.0 (пересобранный менеджер, пользователь через панель,
официальный клиент — `/root/mieru-live-v11.py`), `telemt` 3.5.5→3.5.7, `naive` пересборка по
каталожной записи `build`, панель 0.10→0.11 самообновлением (`/root/lab-release/…`,
временная nginx-location убрана). Браузерная проверка `ui-acceptance.py --views dashboard,versions`
20/20 (скриншоты в `/root/ui-v11`). Точка отката стенда `/root/v11-rollout/20260921T131610Z`.
**В момент остановки на стенде шёл tier `lab-host` (LAB_RESET=1, LAB_KEEP_INSTALL=1)** — лог
`/root/lab-host.log`, маркер `LAB_HOST_EXIT=`; он переустанавливает стенд с нуля и доказывает
адаптер `version_agent`. Результат не проверен — посмотреть первым делом.

## Раскатка на парк — СДЕЛАНА на всех четырёх (2026-09-21, вечер)

AMS_P (`/root/v11-rollout/20260921T150530Z`), AMS_R (`…150614Z`), ams-server (`…150743Z`,
drop-in `version-agent.service.d/project-dir.conf` с настоящим путём проекта) — тем же
`fleet-v11-host.sh`; AMS_Z — панель пересобрана ещё раз с последними коммитами. Везде: агент v0.11
активен, upstream отвечает (mita 3.37.0, telemt 3.5.7, xray 26.9.9 где роутер), менеджер Mieru
принимает 3.37, панель 0.11.0-beta.1. Компоненты на боевых хостах **не обновлялись**. По дороге
найдено и исправлено: unit агента не стартовал на узле без роутера (`ReadWritePaths` без «-» для
отсутствующих путей, коммит 2adb091). Стенд ams-test: `lab-host` упал на preflight (после
LAB_RESET остался `/etc/nginx/stream.d/proxy-control.conf` настоящей установки → два `listen 443`);
в `guest-runner.sh` добавлено удаление этого файла, tier перезапущен.

- **AMS_Z — сделано первым** (`/root/fleet-v11-host.sh`, точка отката `/root/v11-rollout/20260921T141435Z`,
  образы `*:rollback-v10-20260921T141435Z`): агент v0.11 с env (`COMPOSE_DIR`, четыре compose,
  роутер on, `CONSUMER_OVERLAYS`), state схема 2, mieru-manager и панель пересобраны, upstream
  виден (mita 3.37.0, telemt 3.5.7, xray 26.9.9). Компоненты **не обновлялись** — только панель.
- **AMS_P, AMS_R, ams-server — не сделано.** Скрипт `fleet-v11-host.sh` (в scratchpad сессии; копия
  на AMS_Z в `/root/`) параметризован: AMS_P — `/opt/mtproxy-shared443 … off compose.yaml:compose.naive.yaml:compose.mieru.yaml --env-file .env`;
  AMS_R — то же плюс `--env-file .optional.env`; ams-server — `COMPOSE_DIR`
  `/var/lib/docker/volumes/syncthing_data/_data/Development/proxy-control`, роутер on, четыре
  compose, `--env-file .env --env-file .env.xray-router` (скрипт добавит drop-in
  `ReadWritePaths` для чужого пути). Перед скриптом на AMS_P/AMS_R — rsync того же набора путей,
  что на AMS_Z (`--relative --delete`, включая `version_agent/` и `deploy/`); ams-server синхронизирован
  Syncthing. Найдено при инвентаризации: у AMS_P/AMS_R в env агента был чужой `COMPOSE_DIR`
  (путь ams-server) — скрипт исправляет.

## Стенд после раскатки

`lab-host` (LAB_RESET=1, LAB_KEEP_INSTALL=1) был зелёный целиком до MCP (см. ниже про прогон с MCP) (`REMOTE_GATE_LAB_HOST_OK`) после двух
правок LAB_RESET (stream-роутер и настоящий 3x-ui) и правки учения backup/restore под v0.10:
установщик с нуля поднял version-agent (env с четырьмя compose, роутер on, state со всеми
компонентами; Telemt записан как `sha256:ab27edbceb9f`). На ams-test теперь **лабораторный узел**
(`panel.lab.test`), настоящая установка `aurora…` снесена — следующая настоящая установка только
после `host-teardown.sh`.

## MCP-сервер (решение владельца: в v0.11, полный набор, с ноутбука через SNI, только на центре)

Спек §9a. Два агента в работе: `mcp_server/` + панель (OpenAPI-маршрут, CLI ключей) и установщик
(`domains.mcp` — одиннадцатый домен, nginx/core, адаптер `mcp`, version-agent, lab, docs). После
слияния: гейт full, `lab-host` с `mcp.lab.test`, живая проверка с ноутбука на ams-server — для
неё домен владельца на ams-server: **`mcp.panel-tga.unicorndubr1k.org`** (A/AAAA → 72.56.110.195,
проверено). ams-server ставился не установщиком: там свой nginx (`sites-available/sub-panel-tga.conf`,
SNI-карта `stream-conf.d/unicorndubr1k-sni.conf`, LE-сертификаты по доменам через webroot), поэтому
MCP на нём поднимается руками по образцу домена подписки: сертификат `certbot --webroot` для нового
имени, `server` на `127.0.0.1:8443` с `location /mcp → 127.0.0.1:8793`, строка в SNI-карте, `.env.mcp`,
секреты (`api-key-create` через панель, токен), `compose.mcp.yaml` в `COMPOSE_FILE`.

## MCP — СДЕЛАНО (2026-09-21, вечер)

Код влит в `main`. По дороге `lab-host` нашёл четыре падения установщика с MCP, все исправлены:
core не копировал `compose.mcp.yaml`/`mcp_server/` (dd74bc4); секреты MCP были root 0600, а контейнер
работает от uid 10007 → теперь root:10007 0440 (064fa79); `repair` не знал секреты MCP как «соседние»
и отказывал каталогу `secrets` (dbc6a4d); `repair` не знал сервис `mcp` в перекличке health и падал с
«Compose health checks» (8138422^). Кнопки `.ghost` («Проверить обновления», «Включить», «Ротировать»…)
выглядели как браузерные по умолчанию — класс задавал только прозрачный фон; дописан полный стиль
(8138422), после гейта — скриншот и раскатка панели на парк.

**ams-server: MCP поднят руками** (`/root/ams-server-mcp.sh`, точка отката `/root/v11-rollout/mcp-20260921T165734Z`):
LE-сертификат для `mcp.panel-tga.unicorndubr1k.org`, nginx-сайт `sites-available/mcp-panel-tga.conf`
(порт 80 ACME + редирект; `127.0.0.1:8443` TLS, только `/mcp → 127.0.0.1:8793`, остальное 404,
`access_log off`), строка в SNI-карте, `.env.mcp`, `secrets/mcp-token` + `secrets/mcp-panel-key`
(root:10007 0440, ключ панели `mcp` со scope admin), `compose.mcp.yaml` в `COMPOSE_FILE`. Проверено
снаружи: аноним 401, `initialize` 200, `tools/list` — 109 инструментов, `overview` отдаёт живые данные.
Токен — только в `secrets/mcp-token` на ams-server, в отчётах не печатать. На узлах MCP нет (решение владельца).

**Раскатка финального дерева на парк — СДЕЛАНА** (`fleet-v11-refresh.sh`, копия в `/root/` на каждом
хосте): agent-код и unit обновлены, панель пересобрана `--no-deps` (маршрут OpenAPI, CLI ключей, стили
чипов, текст «актуальная версия»); остальные контейнеры не трогались. Точки отката `/root/v11-rollout/20260921T1656*Z`
(образ `mtproxy-panel:rollback-final-<ts>`, копия `version_agent`). Тег — только по слову владельца.

## 2026-09-22 — окно клиента, гейт, раскатка

- Владелец показал окно клиента: радио «Вариант ссылки под клиента» растянуты до 36 px и стоят по
  центру строки, заголовок с описанием уехали вправо — общее правило `input{width:100%;min-height:36px}`
  доставалось и radio/checkbox. Правка e1923c5 (`input[type=radio],input[type=checkbox]` без ширины и
  высоты, вариант — сетка `16px 1fr`). Проверено скриншотом на лабораторном узле стенда после пересборки
  панели: точки 16 px, текст слева, на 1440 и на телефоне (390).
- Гейт на e1923c5: `ui` полностью — `UI_ACCEPTANCE_OK` (229 проверок); `full` — `REMOTE_GATE_FULL_OK`
  (прогон отсоединённый на стенде, `/root/gate-full-final.log`: SSH-сессия foreground-прогона рвётся
  на 25 %, как и раньше).
- **Панель пересобрана на всех четырёх хостах** из дерева e1923c5 (только `style.css` + `--no-deps panel`,
  compose/env-файлы — ровно те, что записаны в лейблах контейнера `com.docker.compose.project.*`).
  Точки отката `/root/v11-rollout/css-20260922T0753*Z` (образ `mtproxy-panel:rollback-css-<ts>`).
  Остальные контейнеры не трогались. Тег по-прежнему не сделан.
- Стенд: лабораторный узел `panel.lab.test` живёт, панель его пересобрана с новым CSS
  (`/root/panel-backup-<ts>`, образ `mtproxy-panel:rollback-radio-<ts>`); тестовый клиент
  `radio-check` заархивирован; скрипт скриншота — `/root/radio-shot.py`.

## ВЫПУЩЕНО 2026-09-22 (по слову владельца)

Тег `v0.11.0-beta.1` на e1c9dd8 (docs-коммит: заметка с полной инструкцией по установке и обновлению,
CHANGELOG, README, UPGRADING). Архив собран дважды из чистого клона на стенде (`/root/release-check-v11.sh`),
sha256 `8b42992fe5c7…`, workflow Release 35702763949 — все пять job'ов success, pre-release
опубликован, опубликованные суммы = стендовые; тело релиза на GitHub — заметка с абсолютными ссылками.
v0.10.0-beta.1 отдельно не публиковался и вошёл в этот архив. Парк уже на дереве e1923c5 (код тот же,
отличие тега — только документы).

## Скиллы для MCP (2026-09-22, после выпуска)

Пять скиллов в `skills/` (на английском — решение владельца): granting-access, morning-overview,
updating-components, diagnosing-access, changing-routing. Каждый проверен на боевой панели двумя
прогонами субагентов (без скилла / со скиллом, только читающие инструменты, изменяющие вызовы описаны,
не выполнены); замечания прогонов внесены. В архив релиза не входят (ставятся на машину клиента);
разделы «Скиллы»/«Skills» в docs/MCP, строка в README, запись в CHANGELOG [Unreleased].

## Обновление компонентов на парке (2026-09-22, по слову владельца «обнови»)

Через панель/MCP по скиллу `proxy-control-updating-components`: telemt 3.5.5→3.5.7 и mita 3.36.0→3.37.0
на всех хостах, Xray-router 26.3.27→26.9.9 на центре и AMS_Z. Найдено по дороге:

- **Гонка в `mita.service`**: `ExecStartPost` делал одну попытку `mita start`, как только появлялся файл
  сокета, а RPC ещё не отвечал → unit падал, агент откатывал mita (первая попытка на AMS_Z). Правка
  c3f29a0: `mita start` повторяется до успеха. Unit раскатан на все четыре хоста (`daemon-reload`, без
  перезапуска; резервные копии `/root/mita.service.bak-<ts>`), проверен тремя перезапусками на стенде.
- **Дрейф `.env.xray-router` на узлах**: `XRAY_ROUTER_EGRESS_WARP=socks5://127.0.0.1:40000` (порт центра)
  вместо `45000` на AMS_Z, AMS_P, AMS_R; контейнер роутера AMS_Z жил со старым env (45000), а обновление
  Xray пересоздало его из файла — `providers.warp.reachable: false`. Исправлено на всех трёх (резервные
  копии `/root/env.xray-router.bak-<ts>`), роутер AMS_Z пересоздан, WARP снова reachable. Откуда взялся
  40000 — не установлено (в снимках v0.9/v0.10 у контейнера было 45000).
- `restart_required: true` у Mieru — константа менеджера (см. ниже), не состояние.

## WARP на парке единообразно (2026-09-22, по слову владельца)

Стандарт — установщика: SOCKS5 `127.0.0.1:40000` (`warp_port`, по умолчанию 40000; так во всей документации).
Узлы AMS_P/AMS_R/AMS_Z переведены с ручного 45000 на 40000 без простоя (`warp-cli proxy port 40000`,
на время переключения loopback-NAT 45000→40000, затем `.env*`, privoxy, `server_config.json` mita с
переписанным `config_hash` в state менеджера, пересозданные менеджеры и роутер, шаблон 3x-ui; резервные
копии `/root/warp-port-<ts>/`). 3x-ui на AMS_P/AMS_R получил outbound `WARP` и правило доменов как на
центре (`/root/x-ui.db.bak-<ts>`); на AMS_Z свой список из 20 доменов сохранён. На AMS_P снесены
`naive-warp-bridge`/`naive-warp-redirect` (копии в `/root/naive-warp-bridge-removed-<ts>`); при этом
drop-in `caddy-naive.service.d/warp-redirect.conf` с `Requires=` уронил NaiveProxy на ~2 мин 15 с
(12:10–12:12 UTC) — drop-in убран. Файл `.env.xray-router` больше не в git (`.env.*` в .gitignore),
пример в ROUTING поправлен на 40000. Разобрано: `restart_required: true` у Mieru и роутера — константа менеджеров («применение перезапускает
демон»), не состояние; скиллы поправлены. privoxy на AMS_Z (никем не использовался) выключен; устаревшие
`MIERU_MITA_SHA256` в `.env`/`.optional.env` узлов приведены к бинарнику.

## Открытые мелочи

- На AMS_Z проверка `naive` ответила `upstream answered 422 for /repos/klzgrad/forwardproxy/commits/caddy2`
  — уточнить имя ветки forwardproxy в GitHub API (на ams-test тот же запрос проходил? проверить) и
  поправить `version_agent/upstream.py::_naive`.
- Версия Telemt в `state.json` свежей установки записывается как `sha256:<12 hex>` (репозиторий
  не называет версию); на старых хостах — `3.5.5`.
- Tier `ui` в `remote-gate.sh` всё ещё ставит агент руками (строки ~231–240) — теперь это делает
  установщик; блок можно убрать после `lab-host`.
