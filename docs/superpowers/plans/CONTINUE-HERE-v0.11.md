# CONTINUE HERE — v0.11 (обновления из upstream), состояние на 2026-09-21

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

`lab-host` (LAB_RESET=1, LAB_KEEP_INSTALL=1) зелёный целиком (`REMOTE_GATE_LAB_HOST_OK`) после двух
правок LAB_RESET (stream-роутер и настоящий 3x-ui) и правки учения backup/restore под v0.10:
установщик с нуля поднял version-agent (env с четырьмя compose, роутер on, state со всеми
компонентами; Telemt записан как `sha256:ab27edbceb9f`). На ams-test теперь **лабораторный узел**
(`panel.lab.test`), настоящая установка `aurora…` снесена — следующая настоящая установка только
после `host-teardown.sh`.

## MCP-сервер (решение владельца: в v0.11, полный набор, с ноутбука через SNI, только на центре)

Спек §9a. Два агента в работе: `mcp_server/` + панель (OpenAPI-маршрут, CLI ключей) и установщик
(`domains.mcp` — одиннадцатый домен, nginx/core, адаптер `mcp`, version-agent, lab, docs). После
слияния: гейт full, `lab-host` с `mcp.lab.test`, живая проверка с ноутбука на ams-server — для
неё владелец должен завести DNS-запись домена MCP на ams-server (домен пока не назван).

## Открытые мелочи

- На AMS_Z проверка `naive` ответила `upstream answered 422 for /repos/klzgrad/forwardproxy/commits/caddy2`
  — уточнить имя ветки forwardproxy в GitHub API (на ams-test тот же запрос проходил? проверить) и
  поправить `version_agent/upstream.py::_naive`.
- Версия Telemt в `state.json` свежей установки записывается как `sha256:<12 hex>` (репозиторий
  не называет версию); на старых хостах — `3.5.5`.
- Tier `ui` в `remote-gate.sh` всё ещё ставит агент руками (строки ~231–240) — теперь это делает
  установщик; блок можно убрать после `lab-host`.
