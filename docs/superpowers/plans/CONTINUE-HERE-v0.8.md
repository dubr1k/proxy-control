# CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт)

Состояние на 2026-09-18 (вечер UTC), ветка `main`, `VERSION = 0.8.0-beta.1`, **не тегировано, не
опубликовано, парк на v0.7 (ams-server — на промежуточных коммитах v0.8 без автоимпорта)**.
Спека: `docs/superpowers/specs/2026-09-18-v0.8-exits-and-rules-design.md` (статус «утверждено и
реализовано», решения владельца в шапке). Заметка о выпуске: `docs/releases/v0.8.0-beta.1.md`
(разделы гейта, скриншотов и живой проверки — плейсхолдеры).

## Сделано (коммиты 8595133 … e904187, все на `main`)

- **UI-мелочи по замечаниям владельца**: одношаговый «Новый клиент» (имя + узел + протоколы),
  явное закрытие диалогов, отступ жёлтой плашки, бренд-терминал в боковой панели, поле «Узел» в
  диалогах MTProxy/Naive/Mieru (доступ на связанной панели — через клиента).
- **Подписки на центре**: домен `sub.panel-tga.unicorndubr1k.org` на ams-server (nginx только `/s/`,
  LE-сертификат, `.env` панели) — раскатано.
- **Автоимпорт** (миграция 17, `node_links.auto_import`, по умолчанию 1): pusher на каждом
  heartbeat принимает пользователей узла; одно имя — один клиент; аудит `node.import` с `auto`.
- **Geodata роутера** (`xray_router_manager/geodata.py`): `<state>/geodata` + `XRAY_LOCATION_ASSET`,
  источники xray/loyalsoldier/custom, транзакция обновления, автообновление, коды из protobuf;
  `/v1/geodata*`; панель `/api/routing/geodata*` (локально и через `/api/fleet/v2/geodata*`).
- **Свои выходы** (миграция 19, `egress_exits`, escrow `exit.credential`): `panel/routing/exits.py`
  (ExitInput, парсер ссылок), `/api/routing/exits*`, `exit:<id>` в политике, intent схемы 2 с
  `exits`, рендер аутбаундов, проба `/v1/exits/test` (`probe.py`), `/api/fleet/v2/exits/test`.
- **Пресеты и протокол сниффера** (миграция 18, `routing_rules.preset`, `match.protocols`),
  `/api/routing/presets`, компилятор версии 3.
- **UI «Маршрутизации»**: таблица правил + модалка, быстрые настройки, панель своих выходов
  с модалкой (форма/ссылка), блок Geodata с диалогом источника; tier `ui` расширен
  (`add_rule`, `routing_exits_and_geodata`).
- Документация: ROUTING/XRAY_ROUTER/UPGRADING ru+en, FLEET (автоимпорт), AUDIT_EVENTS, CHANGELOG
  en/ru, README RU/EN, docs/README.

## Проверено

- Юнит-тесты затронутых модулей зелёные на стенде (`remote-gate.sh quick …`), JS-синтаксис,
  контракт UI, route coverage, doc links; полный `gate-full.sh` на дереве e904187 запущен
  отсоединённо (`/root/gate-v08-full.log`, маркер `GATE_FULL_EXIT=`).
- На настоящей установке ams-test (v0.7 + статика/менеджер v0.8, пересобраны `panel` и
  `xray-router`): geodata посеялась (1 429 geosite, 260 geoip), экран «Маршрутизация» с таблицей,
  пресетами, выходами и geodata отрисован; скриншоты в scratchpad сессии.

## Что дальше (по порядку)

1. Дождаться `GATE_FULL_EXIT=0`; при красных тестах — чинить и повторять.
2. Tier-гейт: `setsid nohup env TIERS="compose lab-container lab-host-0 lab-host-1 fleet routing router chains ui managed-xui" bash /root/gate-v08.sh > /root/gate-v08.log 2>&1 &`
   (LAB_RESET сносит настоящую установку ams-test; LE-лимит — восстановить `/etc/letsencrypt` из
   `/root/le-backup-v07` перед переустановкой; после гейта — `node-live-chain.sh` для настоящей
   установки и связи с AMS_Z).
3. Заполнить заметку о выпуске (гейт, скриншоты tier'а `ui`, находки), обновить
   `docs/VERIFICATION_MATRIX.md` при необходимости.
4. Живая проверка AMS_Z → ams-test: выход socks через WARP-сокет AMS_Z, VLESS-выход на relay
   ams-test, пресет «реклама → блок», geodata → Loyalsoldier с обновлением, автоимпорт.
5. Тег `v0.8.0-beta.1` с `lab-sha256`, push, workflow Release, тело релиза.
6. Раскатка: узлы AMS_P, AMS_R, AMS_Z (rsync `panel/ xray_router_manager/ compose*.yaml scripts/
   VERSION`, `up -d --build --no-deps --wait panel xray-router`), потом центр ams-server; миграции
   17–19 при старте; автоимпорт включится сам — на ams-server ожидать появления клиентов AMS_P/R/Z.
