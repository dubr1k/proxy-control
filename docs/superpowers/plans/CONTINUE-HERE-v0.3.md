# CONTINUE HERE — v0.3 центральная панель

Обновлено: 2026-09-14 (финальное whole-branch ревью закрыто, релизный гейт пройден на итоговом дереве кода
`ade7fcc`; **тег `v0.3.0-beta.1` поставлен на `a054489`, релиз опубликован** —
https://github.com/dubr1k/proxy-control/releases/tag/v0.3.0-beta.1).

## Точка продолжения

Разработка по плану завершена, релиз выпущен; из работ остались слияние ветки и раскатка на боевые хосты
(«Действия владельца» ниже).
Что было закрыто на финише: финальное whole-branch ревью (`bb0336b..ab9e841`, opus) → фикс-волна в три
раунда (`e89d2c9`…`ade7fcc`, каждый раунд с scoped re-review; третий чистый) → релизный гейт на `ade7fcc`
(таблица ниже). Триаж всех отложенных minor и out-of-scope наблюдений ревью — в
`2026-09-14-v0.3-post-merge-issues.md` (не блокируют релиз). Ledger SDD (`.superpowers/sdd/…`, gitignored)
удалён при закрытии ветки; история — в git и в этой заметке.

## Где мы

- Ветка: `feature/vnext-v0.3-fleet-v2` (от `feature/vnext-v0.2-local-control-plane`, `v0.2.0-beta.1`).
  Итоговое дерево кода — `ade7fcc`; поверх него только docs-коммиты (эта заметка, релизная заметка, CHANGELOG,
  список post-merge).
  **Фикс-волна финального ревью** (три раунда):
  - раунд 1 (`e89d2c9`…`4d61396`): C1 пин сертификата проверяется в TLS-рукопожатии, до отправки запроса;
    I2 повторный capture креда Telemt (re-PUT и 202/poll); I3 импортированные MTProxy-доступы несут host/port
    ссылки Telemt (+ `MTPROXY_DOMAIN` панели); I4 удаление узла отклоняется при неподтверждённом удалении гранта;
    I5 гейт ADR 003 до адаптера на локальных путях узла; I6 честная копия диалога отвязки; I7 отчёт `missing`
    переживает 202; I8 правдивость документации;
  - раунд 2 (`d6c4f57`, регрессии раунда 1): N1 регрант под новым ref не теряет строку владения (`missing`-строки
    с именем под другим ref снимаются до apply); N2 capture батчами по `CAPTURE_MAX_RESOURCES = 200`, ошибка
    capture не переводит узел в `offline`; N3 capture/escrow/confirm только по settled-отчёту (`converged|failed`),
    `applying` лишь записывается;
  - раунд 3 (`ade7fcc`, регрессия раунда 2): N4 сбой capture (ошибка транспорта, 4xx/5xx узла или `null` для
    manager-origin креда) не активирует несхваченный кред и не завершает операцию — версия остаётся `pending`,
    подтверждение поколения удерживается, центр повторяет PUT того же поколения на следующем тике;
    `TelemtAdapter.capture` оборачивает `TelemtError` (узел отвечает `null`, а не 500).
- Спека: `docs/superpowers/specs/2026-09-11-v0.3-central-panel-design.md` + `docs/adr/008-panel-to-panel-transport.md`.
- План (Tasks 0–16): `docs/superpowers/plans/2026-09-11-v0.3-central-panel.md`. **Все 17 задач закрыты** (0–15 —
  реализация и ревью, 16 — релизный гейт); протокол гейта — таблица ниже и релизная заметка.
- `VERSION` = `0.3.0-beta.1`; релизная заметка — `docs/releases/v0.3.0-beta.1.md` (двуязычная, гейт и живая
  проверка заполнены, скриншоты — `docs/releases/assets/v0.3.0-beta.1/`).
- Все проверки — только `scripts/dev/remote-gate.sh quick|full|compose|lab-host|fleet` на `ams-test`.
  На стенде оставлена установка `lab-host` с узлом v0.3 из дерева `ade7fcc` (`https://panel.lab.test`,
  `LAB_KEEP_INSTALL=1`); центр приёмки остановлен, узел отвязан, данных приёмки на узле нет.

## Гейт v0.3.0-beta.1 (2026-09-14 11:42–11:59 UTC, дерево `ade7fcc`, чистое — после трёх раундов фикс-волны)

| Tier | Маркер | Итог |
| --- | --- | --- |
| `remote-gate.sh full` | `REMOTE_GATE_FULL_OK` | 1762 passed / 2 skipped (pytest, 377 с), unittest `tests/test_deploy.py` 31 OK, ruff, doc-links, JS, shellcheck, systemd-analyze, `git diff --check`; ≈ 415 с |
| `remote-gate.sh compose` | `REMOTE_GATE_COMPOSE_OK` | 5 compose-моделей (core, +Naive, +Mieru, agent, fleet-central), образы agent/ingress, uid ingress 10001; ≈ 10 с |
| `LAB_RESET=1 LAB_KEEP_INSTALL=1 remote-gate.sh lab-host` | `REMOTE_GATE_LAB_HOST_OK` | `LAB_HOST_EXIT=0`, 17 сценариев passed (environment-preflight 37 с, release-artifact-integrity, audit, plan, nginx-multi-map, coexist-existing-xui, uninstall-foreign-identity, dns-tls-preflight, install 105 с, docker-build, repair 37 с, idempotence, reboot-recovery 61 с, crash-every-phase, report, `fleet` 169 с, secrets-scan), `uninstall`/`coexistence` skipped по `LAB_KEEP_INSTALL=1`; ≈ 400 с |
| `remote-gate.sh fleet` | `FLEET_ACCEPTANCE_OK` + `REMOTE_GATE_FLEET_OK` | 84 проверки, все пройдены, 170 с (link online 3,1 с, доступы enabled 4,1 с, offline-конвергенция < 0,1 с, 20 доступов при рестарте узла 11,2 с, purge 10,3 с; `lab-results/fleet/report.json` на стенде); ≈ 180 с |
| `lab-sha256` архива гейта | `e449b1d1eb40b0abd56a2713e288862408e8a9b21be250a91c51ae3e9ec417c5` | `/root/lab-host.sha` на `ams-test` = `dist/SHA256SUMS` в `/root/dev/proxy-control`; архив `proxy-control-v0.3.0-beta.1.tar.gz` из дерева `ade7fcc` |

Живая проверка (Task 15, 2026-09-13 14:02–14:22 UTC): боевой узел `AMS_Z` обновлён v0.1 → v0.3 на месте и
привязан к стендовому центру; импорт 12 учётных записей, тестовый клиент с тремя доступами (sing-box, mihomo,
resPQ — успех), ротация, удаление, отвязка — узел завершил ровно как был найден. Найденный баг (500 на «Удалить»
связанной панели в контейнере: tmpfs `/tmp` без прав для uid панели) исправлен в `67bda99` и покрыт тестами;
гейт выше прошёл уже на исправленном дереве. Подробно — раздел «Живая проверка» релизной заметки.

## Что дальше по ветке

Слияние ветки и раскатка — за владельцем («Действия владельца»). Работы после слияния —
`2026-09-14-v0.3-post-merge-issues.md`.

## Действия владельца

1. **Тег — сделано 2026-09-14.** `v0.3.0-beta.1` = `a054489` (код `ade7fcc` + документация), аннотация
   `lab-sha256: 5c78a48f2807d313faac20cf5d91c7da6903b0d833fe4362b305d3bb8e6f66fe` (архив собран дважды на стенде
   из чистого checkout `/root/release-check`, байты совпали); workflow `Release` прошёл (quality →
   build-twice-and-compare → attest → draft → publish), опубликованный `SHA256SUMS` совпадает с digest стенда,
   attestation есть; тело релиза — заметка `docs/releases/v0.3.0-beta.1.md` с абсолютными ссылками.
   Процедура на будущее (v0.3.0-beta.2 и далее): `git tag -a vX -m '<заголовок>' -m 'lab-sha256: <digest>'`.
   Важно: `release/build.py` кладёт в архив **все отслеживаемые файлы** (включая `docs/`) с mtime = время
   коммита, а релизный workflow (`build-twice-and-compare`) собирает архив из тегированного коммита и отказывается
   публиковать байты, отличные от `lab-sha256` в аннотации тега. Поэтому digest в аннотации должен быть digest'ом
   архива **именно тегируемого коммита**, и он не может лежать внутри дерева. Как получить: собрать архив
   этого коммита **на стенде** (`ams-test`, Ubuntu 24.04 — тот же zlib, что в CI; сборка на macOS даёт другой
   gzip при байт-идентичном tar — проверено на `9a4d80d`): либо `LAB_RESET=1 LAB_KEEP_INSTALL=1
   scripts/dev/remote-gate.sh lab-host` с дерева этого коммита (`/root/lab-host.sha`; заодно повторный гейт
   установки, ~8 мин), либо вручную на стенде из чистого checkout нужного SHA:
   `git clone <repo> /root/release-check && git -C /root/release-check checkout <sha> &&
   python3 /root/release-check/release/build.py --source /root/release-check --output /root/release-check/dist
   --version "$(cat /root/release-check/VERSION)"` → `dist/SHA256SUMS` (rsync-копия `/root/dev/proxy-control`
   тоже годится, но там нужен `--allow-dirty` из-за неотслеживаемых lab-файлов — сначала убедиться, что
   `git rev-parse HEAD` = тегируемый SHA и `git diff --stat` пуст).
   Digest в заметке не хранится и ни в каком отчёте не ищется: архив тегируемого коммита собирается на стенде
   (`python3 release/build.py …`, как это делает `remote-gate.sh lab-host`), и именно его `dist/SHA256SUMS`
   идёт в аннотацию тега. Любой новый коммит поверх (в т.ч. merge-коммит) меняет digest — пересобрать.
2. **Раскатка — сначала узлы, затем центр** (`docs/OPERATIONS.ru.md` §11, `docs/UPGRADING.ru.md` «до v0.3»).
   - `AMS_P`, `AMS_R` — путь v0.1 → v0.3, как на `AMS_Z` (Task 15): резервные копии (`panel.sqlite3` онлайн-бэкап,
     tar кода, теги образов `*:rollback-<ts>`) → `rsync panel/ naive_manager/ mieru_manager/ compose*.yaml VERSION`
     в `/opt/mtproxy-shared443/` → `docker compose build panel naive-manager mieru-manager` →
     `python -m panel.cli master-key-init` (файл `secrets/panel-master-key`, 0600) **до** `up` →
     `docker compose up -d --wait --no-deps panel naive-manager mieru-manager`. `--no-deps` обязателен, если
     лежащий на хосте `compose.yaml` правился руками и отстал от дерева (на `AMS_Z` у `mtproxy` не было
     `expose: 9091`) — иначе обычный `up -d` пересоздаст боевой Telemt; сравнить `compose.yaml` хоста с деревом
     до раскатки. `AMS_R` — с `--env-file .env --env-file .optional.env`. Сразу сохранить
     `secrets/panel-master-key` по `docs/BACKUP_RESTORE.ru.md` («Мастер-ключ панели»). Проверка: `db-status` →
     13 applied, `/app/VERSION` = `0.3.0-beta.1`, `GET /api/fleet/v2/identity` без ключа → 401, списки
     пользователей трёх протоколов не изменились.
   - `ams-server` — центр: git clone + Syncthing (`/var/syncthing/Development/proxy-control`, см.
     `docs/OPERATIONS.ru.md` и заметки о хостах), `git fetch && git reset --mixed` на тег (не `--hard`:
     локальные правки `probe/`, `scripts/caddy-naive-adapt`), `master-key-init`, `docker compose up -d --build --wait panel`
     с прежним набором overlays. Опционально `PANEL_FLEET_HEARTBEAT_SECONDS` (по умолчанию 15 с).
   - На каждом узле: «Администраторы → API-ключи → Создать ключ» (`node-sync`). На `ams-server`:
     «Узлы → + Панель → Проверить → Добавить» ×3 (`AMS_P`, `AMS_R`, `AMS_Z`; TLS `verify` при публичном
     сертификате панели, как у `AMS_Z`, иначе `pin` + «Получить отпечаток»), затем «Пользователи → Импортировать выбранных» на каждой карточке. Первый heartbeat делает
     карточку `online`.
3. **`AMS_Z` уже на v0.3 и отвязан** — только привязать его с `ams-server` (ключ `node-sync` создать заново, старый
   удалён при отвязке). Копия его мастер-ключа и набор для отката лежат в `/root/v03-live/` на `AMS_Z`
   (только root): `panel-master-key-20260913T140225Z.json`, `panel-pre-v0.3-20260913T140225Z.sqlite3`,
   `code-pre-v0.3-20260913T140225Z.tgz`, образы `*:rollback-20260913T140225Z`. Мастер-ключ сохранить по
   `docs/BACKUP_RESTORE.ru.md` (без него зашифрованные учётные данные центра не восстановить); имена
   `live-probe-*` в менеджерах NaiveProxy/Mieru узла tombstoned и не переиспользуются.
4. Стенд `ams-test` — одноразовый: установку `lab-host` можно снести следующим `LAB_RESET=1` или оставить как
   учебный узел; production-хосты гейт не трогал.

## Рулинги, принятые за владельца (в итоговый отчёт)

- Pre-flight: `_apply_one` не держит `BEGIN IMMEDIATE` через HTTP к менеджерам — adapter I/O вне транзакций.
- Pre-flight: `content_digest` (без номера/времени) рядом с `digest`; `publish` сравнивает `content_digest`.
- Pre-flight: `compile()` пропускает гранты `deleted` + `observed_state='missing'`.
- Pre-flight: фикстура `pair` в `panel/tests/conftest.py`; `ACTOR` — константа в тестах.
- Task 3: границы `generation ≥ 1`, `previous_generation ≥ 0`; тест поправлен, а не модель.
- Task 4: `TelemtIndeterminate` пробрасывается сырым (контракт resume).
- Task 5→9: центр эскроуит вернувшийся manager-секрет **под тем же `secret_id:version`**.
- Task 5→8: `compile()` не кладёт `MtproxyOptions.expiration` в документ.
- Task 5 fix: коллизия имени с локальным пользователем → `failed` («runtime user exists and is not managed»), не adoption;
  восстановление после падения между `create` и `_record` — через placeholder-строку до `create` + `rotate`.
- Task 6: `COPY VERSION` невозможен (build context `./panel`) → `Settings.panel_version_file` (`PANEL_VERSION_FILE`,
  default `/app/VERSION`) + bind-mount `./VERSION:/app/VERSION:ro` в `compose.yaml` + `VERSION` в `_COPY_FILES`
  установщика; нечитаемый/отсутствующий файл → `"dev"`.
- Task 6: трафик по протоколам в `GET status` реализован (спека §5.2/§7) best-effort: naive/mtproxy суммой,
  mieru `null`, ошибка менеджера → `null`; `SecretError` на push → 409 `secret_store_disabled`.
- Task 6: §5.3 backoff на узле не реализован — узел ретраит только при старте (`run_pending`); центр ведёт backoff.
- Task 8: после `add()` статус `unknown` (первый heartbeat даёт `node.up`); `delete()` глотает все ошибки клиента
  (audit `node_released:false`); `delete()` удаляет все-`deleted` гранты узла (FK RESTRICT); v1-строки получают
  `transport:"v1"`.
- Task 9: backoff **central-driven** — `_Backoff` per node 30 с → 600 с на `failed`/rejected текущего поколения, сброс
  при новом поколении или `converged`, heartbeat не откладывается. Миграция 12 (rebuild `provisioning_operations`
  ради `pending_remote`) принята как additive по духу (строки/индексы/FK сохранены).
- Task 10: disable до применения **не** отменяет операцию (узел создаёт аккаунт выключенным, `remote_applied`
  принимает `disabled` как завершение); purge гранта после подтверждённого удаления (local — сразу после `forget`
  в транзакции с audit; remote — в `FleetPusher._absorb` при observed `missing` для `deleted`), все `secret_versions`
  гранта → `revoked`.
- Task 14: observed-модели центра терпимы к незнакомым полям (`extra=ignore`), документ поколения и push — строгие;
  `learned` валидируется; `DELETE /api/nodes/{id}` освобождает imported-гранты и отказывает только при
  provisioned-гранте не в `deleted` (спека §6 дополнена).
- Task 15: живая проверка = обновление узла v0.1 → v0.3 на месте с резервными копиями; `--no-deps` при дрейфе
  `compose.yaml` хоста; фикс `temp_store=MEMORY` + tmpfs `/tmp` под uid панели (`67bda99`).
- Task 16: `lab-host` в релизном гейте — с `LAB_KEEP_INSTALL=1` (tier `fleet` нужна живая установка); скриншоты —
  только стендовые данные (центр запущен как в `fleet-acceptance.py`, узел — установка `lab-host`), не `AMS_Z`.
- Финальное ревью: одна фикс-волна = C1 + I2–I8 + docs-однострочники тех же файлов; FIX SOON-пункты триажа —
  задачи после слияния (`2026-09-14-v0.3-post-merge-issues.md`), не блокируют релиз.
- Финальное ревью: регрессии, внесённые самой фикс-волной (N1–N3 после раунда 1, N4 после раунда 2), закрыты
  отдельными целевыми раундами с scoped re-review каждого — осознанное отклонение от правила «второй волны нет»
  (иначе релиз ушёл бы с дефектами, внесёнными в последний день); гейт всех четырёх tier'ов повторён на итоговом
  дереве `ade7fcc`.
- Раунд 3 (N4): два наблюдения re-review вне диффа — `TelemtError` не оборачивался в `capture` (узел отвечал 500)
  и `null` для manager-origin креда всё равно подтверждал «голое» значение — включены в N4 как один дефект «сбой
  capture в любой форме не активирует несхваченный кред». Механизм повтора — удержание подтверждения поколения
  (`config_dirty` остаётся, центр повторяет PUT того же поколения), без нового планировщика.
- Пре-релизная проверка 2026-09-14 шла на `ams-test` параллельно с re-review (baseline на `d6c4f57` — все четыре
  tier'а зелёные, `lab-sha256` `e22c9263…`), затем повторена на `ade7fcc` — релизной считается только вторая.

## Отложенные minor и out-of-scope наблюдения

Триаж финального ревью (FIX SOON / ACCEPT) и наблюдения re-review трёх раундов сведены в
`2026-09-14-v0.3-post-merge-issues.md`; docs-однострочники того же триажа закрыты в `4d61396`.
