# CONTINUE HERE — v0.7 (цепи и полосы)

Состояние на 2026-09-18 13:40 UTC, ветка `main` (= `feature/vnext-v0.7-chains`). **v0.7.0-beta.1 выпущен, слит в `main`, парк раскатан.**
Спека: `docs/superpowers/specs/2026-09-17-v0.7-chains-design.md`, план:
`docs/superpowers/plans/2026-09-17-v0.7-chains.md` (Tasks 0–15 закрыты).

## Выпуск (сделано 2026-09-18 10:16–12:50 UTC)

- **Гейт на стенде** (`ams-test`), заметка `docs/releases/v0.7.0-beta.1.md`: на `0371c69` все tier'ы
  (full 2291, compose, lab-container, lab-host 20/20 без KEEP и 18 с KEEP, fleet 84/84, routing 154/154,
  router 242/242, chains 277/277, ui 197/197, managed-xui) — `lab-sha256` `ba5e9690…`; на финальном
  `644bea8` — full 2293, lab-host 18 с KEEP, chains 277/277 — `lab-sha256` `9bb30461…`. 14 скриншотов
  tier'а `ui` пересняты (новый знак бренда). Первый `chains` на `0371c69` дал 275/277 — обрывы проб
  (curl 55/35) в момент смены поколения роутера; повтор 277/277; проба получила повтор (`bed7f44`).
- **Живая проверка** (оба стенда параллельно): ams-test переустановлен по-настоящему из архива `9bb30461…`
  (`/root/node-live-chain.sh`: teardown → `ams-test-install-v07.sh` → `live-node-v07.py` **26/26**);
  AMS_Z обновлён v0.6 → v0.7 на месте (точки отката `/root/v07-live/20260918T101858Z`, миграция 16),
  роутер адаптером, два слота, naive+mieru через WARP, связь с ams-test, цепь через его relay —
  `live-v07.py` **41/41** (первый прогон 38/42 нашёл дефект: узел без WARP отказывал всему набору
  relay-учёток → `relay_credential_pending` навсегда; исправлено `644bea8`, тесты менеджера и узла).
- **Публикация**: две сборки из чистого клона `/root/release-check-v07` (дерево `a0a83d2`, байты совпали,
  `--verify` OK) → тег `v0.7.0-beta.1` на `a0a83d2` с `lab-sha256:
  9d5d22d899611bf53c9f5d9f0658e13aae9a4bdc8856f20485aae955f9642ab9` → push → workflow `Release` run
  `35346449946` (quality, build-twice-and-compare, attest, draft-release, publish — `success`) →
  pre-release <https://github.com/dubr1k/proxy-control/releases/tag/v0.7.0-beta.1> (4 файла, архив
  7 551 935 байт; опубликованные `SHA256SUMS` = стендовые; `gh attestation verify` — SLSA v1,
  `refs/tags/v0.7.0-beta.1`) → тело релиза из заметки с абсолютными ссылками (48 ссылок, все 200).
  Блок «Архив» заметки и шапка README (RU/EN: текущий выпуск v0.7, до него v0.6, v0.5 без своего
  релиза) — коммитом после тега.

## Что оставлено на хостах

- **AMS_Z** (v0.7.0-beta.1, дерево `644bea8` + заметка): Xray-router (`relay_port = 0`, входы на
  loopback), слоты `mita@1`/`mita@2` (46101/46102 в UFW), naive+mieru подключены к роутеру с политикой
  сервиса «через WARP», связь с ams-test и его relay включён. Откат — `/root/v07-live/20260918T101858Z`
  + образы `*:rollback-20260918T101858Z`. Скрипты: `/root/v07-live/live-v07.py`, `amsz-unlink-stale.py`.
- **ams-test**: настоящая установка v0.7 по `/root/install-v07.toml` (`active`, relay 45443, слоты
  `mita@1…4`, десятый домен подписки, 3x-ui с доменом подписки); один ключ `node-sync`
  (`AMS_Z-central-20260918T123839Z`) — он у AMS_Z. Лабораторный узел снесён (`host-teardown.sh`); перед
  следующим `lab-host` — `LAB_RESET=1`. Копия релиза `/tmp/proxy-control-release` = архив `9bb30461…`.
  Скрипты: `/root/gate-v07.sh` (все tier'ы одной цепочкой, `TIERS=…`), `/root/gate-compose.sh`,
  `/root/node-live-chain.sh`, `/root/live-node-v07.py`, `/root/node-keys-tidy.py`.

## Слияние и раскатка парка (сделано 2026-09-18 13:00–13:35 UTC, по решению владельца)

- **`main`** переведён fast-forward на `856e0f2` (цепочка веток v0.2 → … → v0.7 линейна, `main@8c787c5` —
  их общее основание; все теги v0.1.0…v0.7.0-beta.1 теперь на `main`). Перед push — гейт на стенде на
  этом дереве: `full` 2293 passed / 2 skipped, `compose` OK (от `644bea8` дерево отличается только
  документацией). Запушен в `origin/main`.
- **AMS_P, AMS_R, ams-server: v0.1.x → v0.7.0-beta.1 на месте**, по образцу обновления AMS_Z v0.1 → v0.3
  (`docs/releases/v0.3.0-beta.1.md`): снимок → резервные копии (онлайн-копия `panel.sqlite3` с
  `integrity_check`, tar кода и секретов, состояние менеджеров/mita/установщика, копия
  `traffic.sqlite3` naive, том `telemt-config`, дайджесты файлов пользователей, теги образов
  `*:rollback-<ts>`) → rsync `panel/ naive_manager/ mieru_manager/ xray_router_manager/ compose*.yaml
  deploy/ scripts/ VERSION .dockerignore` (сверено пофайлово с `main`; на ams-server дерево пришло
  через Syncthing) → `NAIVE_EGRESS_WARP`/`MIERU_EGRESS_WARP` в env (WARP-socks5 на loopback подтверждён
  `warp=on`; рукописные upstream'ы остались `custom`) → `compose config` → `build` → **пробная миграция в
  новом образе на копии базы этого же хоста** (16/16, 7 → 26 таблиц, строки на месте; единственное
  отличие — строка `local` в `fleet_nodes` от миграции 2) → `master-key-init` (0600, копия в
  `/root/v07-rollout/<ts>/`, на ams-server ключ не уходит в Syncthing — `secrets` в `.stignore`) →
  `up -d --wait --no-deps panel naive-manager mieru-manager`. Проверка на каждом: Telemt и mask не
  пересозданы, 16/16, `/healthz` 200, `/api/fleet/v2/identity` и `/api/routing/targets` 401,
  `/app/VERSION`, mieru-manager в сети хоста, журналы без ошибок, юниты активны, файлы пользователей
  байт-в-байт, списки через API как до обновления (AMS_P 3/2/1, AMS_R 3/3/2, ams-server 7/11/6
  MTProxy/Naive/Mieru). Точки отката и логи фаз — `/root/v07-rollout/` на каждом хосте (только root).
  На всех трёх та же особенность, что была на AMS_Z: рукописный `compose.yaml` без `expose: 9091` у
  `mtproxy` — `--no-deps` обязателен.
- **Парк**: ams-server — центр; AMS_P, AMS_R, AMS_Z связаны как узлы (`tls_verify=verify`, ключи
  `node-sync` `ams-server-central-20260918T132559Z` на каждом узле, на центре — 3 записи
  `node-api-key`), все `online` в первые секунды; инвентарь узлов виден центру, все учётные записи
  пока `ownership: local` (импорт не выполнялся — решение владельца). AMS_Z одновременно остаётся
  центром для ams-test. На ams-server для операций через API создавался временный владелец
  `rollout-tmp` (не трогая пароль `dubr1k`) — удалён; открытые копии ключей на хостах уничтожены.

## Что дальше (владелец)

1. Импорт существующих пользователей узлов в клиентов центра («Проверить» → галочки → «Добавить»
   или `POST /api/nodes/{id}/import`): узел пометит их `ownership=central`, `master_guid` появится с
   первым поколением; до импорта узлы связаны, но не заявлены.
2. Своя полоса владельца на AMS_Z → цепь через ams-test: `docs/releases/v0.6-operator-guide.ru.md` §8.8
   (relay ams-test уже включён, связь есть).
3. По желанию: `emails` в relay view роутера появляется только у включённого relay (у выключенного —
   старый вид без поля; узел тогда подтверждает `desired`, что для пустого набора одно и то же).
