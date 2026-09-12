# CONTINUE HERE — v0.3 центральная панель

Обновлено: 2026-09-12 (вторая пауза владельца — после fix round 1 Task 10, до его scoped re-review).

## Где мы

- Ветка: `feature/vnext-v0.3-fleet-v2` (от `feature/vnext-v0.2-local-control-plane`, `v0.2.0-beta.1`).
- Спека: `docs/superpowers/specs/2026-09-11-v0.3-central-panel-design.md` + `docs/adr/008-panel-to-panel-transport.md`.
- План (Tasks 0–16): `docs/superpowers/plans/2026-09-11-v0.3-central-panel.md`.
- Исполнение — `superpowers:subagent-driven-development`: свежий субагент на задачу, ревью после каждой,
  ledger в `.superpowers/sdd/2026-09-11-v0.3-central-panel/progress.md` (gitignored — если каталога нет,
  восстановить из этого файла; brief'ы для Tasks 0–16 и report'ы там же; `scripts/task-brief` пересоздаст brief'ы).
- Все проверки — только `scripts/dev/remote-gate.sh quick|full|compose|lab-host` на `ams-test`.
  Живой стенд v0.2 на `ams-test` стоит (checkout `/root/dev/proxy-control`, rsync-копия).

## Сделано (коммиты в порядке)

| Task | Коммиты | Итог ревью |
| --- | --- | --- |
| 0 — probe Telemt caller-secret | `4fdcbbf`, `da33107` | `TELEMT_CALLER_SECRET = supported`; чисто |
| 1 — `panel_settings` + GUID + `api_keys` + `ApiKeyService` (миграция 9) | `a787459` | чисто |
| 2 — Bearer в `RequestContext.current`, scope-гейты, `KeyRateLimiter`, `/api/keys*` | `8be3d60` | чисто |
| 3 — `protocol.py` + `managed.py` (`ManagedStore`, миграция 10) | `fee90b5`, `8207bc6` | чисто |
| 4 — Telemt caller-secret + fallback, `update_options`, `credential_origin` | `02b9445`, `ac74a94` | чисто |
| 5 — `reconcile.py` (`Reconciler`) | `fbcbdec`, fix `6a8e90d` | fix round 1: 4/4 addressed; чисто |
| 6 — Fleet API v2 узла + гейт `managed_by_central` | `da9df48`, fix `4eb4e53` | fix round 1: 4/4 addressed; чисто |
| 7 — `client.py` (`NodeClient`, `fingerprint`, `validate_panel_url`) | `505f40e` | чисто |
| 8 — миграция 11, `links.py`, `generations.py`, `nodes/*` read model | `f285194` | чисто (12 minor в ledger) |
| 9 — `pusher.py` (heartbeat/push/backoff), events, provisioning `remote`, миграция 12 | `e68b187`, fix `83d206d` | fix round 1: 2/2 addressed; чисто |
| 10 — `clients/lifecycle.py` (enable/disable/rotate/delete local+remote), маршруты | `e8428c1`, fix `cf6b34a` | **fix round 1 закоммичен, scoped re-review не запущен** |

Полный suite на стенде после `cf6b34a`: `1713 passed, 2 skipped`, ruff чисто.

## Следующий шаг: Task 10, scoped re-review fix round 1

1. `scripts/review-package <plan> e8428c1 HEAD` → diff-файл.
2. Dispatch `re-review-prompt.md` (sonnet) с findings I1–I3 (ниже), brief `task-10-brief.md`, report `task-10-report.md`
   (секция `## Fix round 1`).
3. При «all addressed» → ledger `Task 10: fix round 1/5 (3 addressed, 0 open; commits e8428c1..cf6b34a)` +
   `Task 10: complete (commits 83d206d..cf6b34a, review clean)` → Task 11 (brief `task-11-brief.md` уже есть).

Findings Task 10 (из ревью, fix round 1 их закрыл по отчёту):
- I1 — идемпотентный remote enable/disable писал `observed_state='pending'`, а `publish` ничего не вставлял → грант
  застревал. Фикс: `set_enabled` — no-op (без audit/notify), если `desired_state` уже такой.
- I2 — `bundle()` рендерил креды удалённых/withdrawn грантов. Фикс: пропуск не-`active` шагов, `deleted` и purged
  грантов (`_live_grant`).
- I3 (plan-mandated) — tombstone `deleted/missing|pending` + `find_grant` + UNIQUE index блокировали повторную выдачу
  того же `runtime_username`. Рулинг: **purge** гранта после подтверждённого удаления (local — сразу после `forget`
  в транзакции с audit; remote — в `FleetPusher._absorb` при observed `missing` для `deleted`), все `secret_versions`
  гранта → `revoked` (строки остаются), шаги provisioning с purged-грантом терпимы; `find_grant`/index не трогали,
  миграции нет.

## Дальше по плану

- Task 11 — маршруты центра (`central_routes.py`, `importing.py`, схемы, `nodes/service.py` `set_disabled` → `links.set_enabled`,
  публичные хосты по узлу в подписках/бандлах). Факты для dispatch: `NodeLinkService` API в `links.py:34-214`;
  `importer.inventory` в `clients/importer.py:94`; панельные узлы уже попадают в v1 `/api/fleet/nodes` (решить —
  фильтровать или нет); два флага disabled (`fleet_nodes.disabled` vs `node_links.enabled`); `NodeView.last_seen_at`
  = None для panel-узлов.
- Task 12 — UI (`keys.js`, `nodes.js`, `clients.js`, `index.html`, `style.css`); карточка узла показывает
  `status_json.protocols[*].traffic` (реализовано в Task 6); ключевать observed по `(protocol, runtime_username)`.
- Task 13 — документация (двуязычная), CHANGELOG, VERSION; описать rsync `VERSION` для хостов, обновляемых rsync'ом
  (bind-mount `./VERSION:/app/VERSION:ro`), и `PANEL_FLEET_HEARTBEAT_SECONDS`.
- Task 14 — `scripts/lab/fleet-acceptance.py` + tier `fleet` в `remote-gate.sh`.
- Task 15 — живая проверка AMS_Z (узел) ↔ ams-test (центр): **обязательно rsync `VERSION`** на AMS_Z вместе с кодом;
  не удалять чужих пользователей; свой тестовый клиент удалить; «Отвязать от центра» в конце.
- Task 16 — релизный гейт `v0.3.0-beta.1` (`remote-gate.sh full` + `lab-host`), потом финальное whole-branch ревью
  (opus) с триажем всех `minor (deferred)` из ledger, `finishing-a-development-branch`.

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
  принимает `disabled` как завершение); purge гранта после подтверждённого удаления (см. I3 выше).

## Отложенные minor по задачам (для финального ревью ветки)

Полный список — в ledger (`Task N: minor (deferred)`); ключевые:
- T1: `authenticate()` коммитит `last_used_at` посреди итерации; ветка set/skip не покрыта.
- T2: rate-limit тест не доказывает порядок 429-до-403; нет тестов на пустой `Bearer ` / регистр.
- T3: `Resource.options` нетипизирован; `latest()` возвращает лишний `master_guid`; `remove_resource` без теста.
- T4: fallback 400/422 дублируется; контрактный тест skip'ает Telemt.
- T5: порядок `ObservedGeneration.resources` (коллизии в конце); last-write-wins дубликатов; нет теста rotate-failure.
- T6: `except KeyError` маскирует баги как `stale_generation`; `run_pending` блокирует старт; нет shutdown для
  `background`; `ClientConflict` без `X-Reason` на пути provisioning; `local_only` ×4; `adopt_credential` без гейта;
  `capture` без audit; `status` делает discover+health на каждый вызов; пробелы покрытия.
- T7: новый `AsyncClient` на вызов (нет keep-alive); IDN обходит private-check.
- T8: `delete()` оставляет ротированные ключи и сиротит секреты грантов; не проверяет `master_guid` перед `unlink`;
  `compile()` ValidationError может 500-нуть мутацию клиента через `on_change`; heartbeat JSON не ограничен;
  `record_observed` не сверяет digest; panel-узлы в v1-листинге; `last_seen_at` None; два флага disabled.
- T9: NodeRejected на identity/status флапает offline; `_in_flight` смешивает часы; `_secrets_for` молча глотает
  SecretError; SQLite+AES на event loop; гонка эскроу N vs N+1; миграция 12 без теста с данными; реальные sleep в тесте.
- T10: порядок ADR 003-гейта в локальном пути; façade re-resolve по имени с DEFAULT_ENDPOINT; гонка эскроу → две
  `active` версии; дубли audit-имён; inline `token_urlsafe` в façade; drifted local grant не удаляется при
  AdapterError; `compensated` шаг внутри `applying`; локальный грант после компенсации саги оставляет tombstone.

## Действия владельца

- Ничего до Task 16; production-хосты не трогались. `AMS_Z` разрешён только для живой проверки Task 15 после
  зелёного гейта (rsync кода **и `VERSION`**).
