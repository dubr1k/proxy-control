# CONTINUE HERE — v0.9 (стык фронт/бэк, matches_node, мобильный UI, Xray-router на центре)

Состояние на 2026-09-19 (день UTC), ветка `main`, `VERSION = 0.9.0-beta.1`. Тег ещё **не** ставился.
Заметка о выпуске: `docs/releases/v0.9.0-beta.1.md` (для пользователей — без стендов, правило владельца).

## Сделано

- Причина «naive → WARP (не применено)» на ams-server: upstream WARP в Caddyfile был вписан вручную до
  политик, менеджер отдавал его как действующий документ, предпросмотр видел «изменений нет», политика ни
  разу не применялась. Ответ: `matches_node` у политик в `GET /api/routing/targets`
  (`RoutingService._matches_node`, компиляция против узла), слова на карточке узла / пилюле /
  предпросмотре (65bc8a0).
- Аудит контракта фронт/бэк (7 расхождений) исправлен там же: реестр `registerReasons` в api.js,
  `reasonText` ищет и в WARNING_TEXT, `_unsettle` (draft с сохранением applied_*), «Вернуть пин»,
  `policyError` закрывает редактор, relay `pending`, политика при backend=null.
- Кнопки Mieru «раздувались»: `.routing-layout{align-items:start}` + `.routing-editor{align-content:start}`
  (воспроизведено на стенде подстановкой ответов ams-server через fetch-override, скриншоты до/после).
- Мобильный аудит 360/390 px по всем экранам (скрипт `scratchpad/mobile-audit.py` сессии): переполнения и
  наложений нет; исправлено — нижняя панель без намёка на прокрутку (main.js `markMobileNavEdges` +
  mask-image `more-left/more-right`, активный раздел `scrollIntoView`), ghost-кнопки маршрутизации ≥ 32 px.
- v0.9: VERSION, CHANGELOG ru/en, заметка, UPGRADING «до v0.9», README (9733925 и далее).
- Гейт `full` на ams-test: 2342 passed / 2 skipped, REMOTE_GATE_FULL_OK (лог `/root/gate-v09-full.log`).
- Раскатка v0.9 на весь парк 12:37–12:39 UTC скриптами `/root/v09-rollout-{a,b,c}.sh` (sed из v08; драйвер
  `scratchpad/v09-deploy-host.sh <host> <a|b|c|sync|tail>`), только `panel`, PHASE_C_OK на всех четырёх;
  точки отката `/root/v09-rollout/<ts>/` (ams-server T122924Z, AMS_Z T122932Z, AMS_P T122940Z,
  AMS_R T122945Z), образы `mtproxy-panel:rollback-<ts>`. Панель настоящей установки ams-test
  пересобрана из `/root/dev/proxy-control/panel` (бэкап `/root/panel-backup-20260919T123839Z`).
- **Xray-router включён на ams-server** (`/root/v09/enable-router.py`, отчёт `/root/v09/router-report.json`,
  14/14): установлен адаптером установщика (project_dir — реальный путь тома
  `/var/lib/docker/volumes/syncthing_data/_data/Development/proxy-control`, `/var/syncthing` — симлинк,
  адаптер его отвергает), relay выключен (`relay_port=0`), WARP `socks5://127.0.0.1:40000`; `.env` центра
  получил `COMPOSE_FILE` с `compose.xray-router.yaml`, `XRAY_ROUTER_*`, `NAIVE/MIERU_EGRESS_ROUTER*`;
  копии ingress-ключей в `/var/lib/{naive,mieru}-manager/xray-router-ingress`; naive и mieru подключены к
  роутеру, политики `xray_router / egress warp` применены (applied, matches_node=true); клиент через
  NaiveProxy выходит с IP WARP (104.28.219.140, прямой 72.56.110.195).

## Что дальше

1. Тег `v0.9.0-beta.1` и Release — по слову владельца (ритуал v0.8: чистый клон на ams-test, две сборки,
   `lab-sha256` в аннотации, workflow Release, блок «Архив» в заметке — но без стендовых таблиц в теле).
2. Второй прогон раскатки (мобильные правки после первой волны) — см. журнал сессии: если PHASE_C второй
   волны не зафиксирован здесь, проверить `docker exec proxy-control-panel grep -c markMobileNavEdges
   /app/panel/static/js/main.js` на хостах.
3. Временный owner `v09-tmp` на ams-server (`/root/v09/tmp-owner.pass`) — удалить после проверок.
4. Открытые вопросы v0.8 владельца по geodata на узлах без роутера теперь неактуальны для ams-server
   (роутер есть); для AMS_P/AMS_R — по-прежнему решение владельца.
