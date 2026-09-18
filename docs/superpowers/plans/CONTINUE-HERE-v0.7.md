# CONTINUE HERE — v0.7 (цепи и полосы)

Состояние на 2026-09-18 12:55 UTC, ветка `feature/vnext-v0.7-chains`. **v0.7.0-beta.1 выпущен.**
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

## Что дальше (владелец)

1. Слияние `feature/vnext-v0.3-fleet-v2` → … → `v0.7-chains` в `main` (ни одна ветка ещё не слита) и
   раскатка `ams-server`/`AMS_P`/`AMS_R` — только владелец; порядок «узлы → центр» (`docs/UPGRADING.ru.md`).
2. Своя полоса владельца на AMS_Z → цепь через ams-test: `docs/releases/v0.6-operator-guide.ru.md` §8.8
   (relay ams-test уже включён, связь есть).
3. По желанию: `emails` в relay view роутера появляется только у включённого relay (у выключенного —
   старый вид без поля; узел тогда подтверждает `desired`, что для пустого набора одно и то же).
