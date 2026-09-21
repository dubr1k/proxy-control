# CONTINUE HERE — v0.10 (клиент на нескольких узлах, подписка под рукой)

Состояние на 2026-09-21 (день UTC), ветка `main` = `6bd5f08`, `VERSION = 0.10.0-beta.1`. **Раскатано на весь парк**
(панель, миграция 20): AMS_Z, ams-server, AMS_P, AMS_R — `PHASE_C_OK`, точки отката `/root/v10-rollout/<ts>/`
(AMS_Z T095941Z, ams-server T101507Z, AMS_P T102229Z, AMS_R T102330Z), образы `mtproxy-panel:rollback-<ts>`.
**Тег и заметка о выпуске не сделаны** — по слову владельца. Спека:
`docs/superpowers/specs/2026-09-20-v0.10-client-subscription-nodes-design.md`, план (11 задач + 9b):
`docs/superpowers/plans/2026-09-20-v0.10-client-subscription-nodes.md`.

## Сделано

- Токен подписки хранится дополнительно в escrow под мастер-ключом (`secret_versions`, purpose `subscription`,
  миграция 20 `subscription-escrow`); `POST /api/clients/{id}/subscription/reveal` показывает ссылку снова через
  одноразовый reveal с аудитом `subscription.reveal`; ротация/отзыв гасят копию в той же транзакции; без ключа —
  как раньше (один раз). Подписка выдаётся вместе с клиентом (`POST /api/clients` → `subscription_reveal_token`;
  сервисные экраны MTProxy/Naive/Mieru шлют `subscription: false`). Гранты без секрета подписку не блокируют.
- UI: `placement.js` (матрица узел × протокол, чистый модуль, контракт под Node через копию `.mjs`); окно клиента
  вместо диалога «Выдать доступ» (`#subscription-modal`: «Показать», ротация, отзыв, матрица с «Применить», крестик
  удаления, сброс при каждом открытии, защита от гонки close→open); «Новый клиент» с матрицей; блок подписки в
  «Доступы выданы»; `OPERATION_MESSAGE` в `common.js`; мобильный аудит окна (матрица прокручивается внутри блока).
- Лаборатория: `scripts/lab/ui-acceptance.py` под новые экраны (повтор клика после перерисовки, перечитывание
  матрицы, «Показать» с диагностикой), матрица верификации 73 строки (`subscription-reveal`,
  `client-placement-matrix`), `check-doc-links.py`/`remote-gate.sh` пропускают `.superpowers`.
- Гейт `full` на ams-test трижды, последний на `6bd5f08`: 2363 passed / 2 skipped, `REMOTE_GATE_FULL_OK`.
  Панель настоящей установки стенда пересобрана на v0.10 (бэкап `/root/panel-backup-20260921T085724Z`; `/app/VERSION`
  там смонтирован из `/opt/mtproxy-shared443/VERSION` — копировать отдельно; пароль owner — ключ `panel_password` в
  `/root/install-v08.credentials`); сценарий `--views login,clients`: всё новое v0.10 ok, 5 отказов — узел
  управляется центром AMS_Z (409 «managed by central», ADR 003), не дефект.
- Живая проверка AMS_Z → ams-test: клиент на двух узлах (naive@local + mieru@ams-test), выдача одной операцией,
  выключение/включение, доставка на узел, удаление, архив; на AMS_Z домена подписки нет (`sub_configured=false`),
  показ/ротация доказаны на стенде. Временные owner `v10-tmp` удалены. Отчёт раскатки — в ledger сессии
  (`.superpowers/sdd/…/rollout-report.md`, git-ignored).

## Что дальше

1. Тег `v0.10.0-beta.1` и заметка `docs/releases/v0.10.0-beta.1.md` (для пользователей, без стендов) — по слову
   владельца; сборка из чистого клона по образцу `/root/release-check-v09.sh` на ams-test; README-баннеры.
2. На ams-test в БД панели узла остались «сироты» после UI-сценария (клиенты `probe2-81654`, `ui-d340cd-client`,
   `ui-d340cd-imp` с грантами без аккаунтов; runtime-пользователи удалены через центр) — снимутся при следующем
   `lab-host` с `LAB_RESET=1`.
3. Отложенные мелочи финального ревью: частичное применение матрицы сообщает только первую ошибку; `cellStatus`
   прячет «выключен» за «ожидает узел»; ошибка бандла после успешной саги пишется в закрытый диалог; в
   «Доступы выданы» нет выбора формата (в окне клиента есть все четыре); дубль `client.create` в
   `create_with_client`/`create_client`.
4. Подписки, выданные до v0.10 (в парке их не было), показать нельзя — только ротировать (UPGRADING).
