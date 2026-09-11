# CONTINUE HERE — v0.3 центральная панель

Обновлено: 2026-09-12 (сессия прервана владельцем после ревью Task 5).

## Где мы

- Ветка: `feature/vnext-v0.3-fleet-v2` (от `feature/vnext-v0.2-local-control-plane`, `v0.2.0-beta.1`).
- Спека: `docs/superpowers/specs/2026-09-11-v0.3-central-panel-design.md` + `docs/adr/008-panel-to-panel-transport.md`.
- План (16 задач): `docs/superpowers/plans/2026-09-11-v0.3-central-panel.md`.
- Исполнение — `superpowers:subagent-driven-development`: свежий субагент на задачу, ревью после каждой,
  ledger в `.superpowers/sdd/2026-09-11-v0.3-central-panel/progress.md` (gitignored — если каталога нет,
  создать заново из этого файла; briefs/report'ы там же).
- Все проверки — только `scripts/dev/remote-gate.sh quick|full|compose|lab-host` на `ams-test`.
  Живой стенд v0.2 на `ams-test` стоит (Task 0 использовал его Telemt).

## Сделано (коммиты в порядке)

| Task | Коммиты | Итог ревью |
| --- | --- | --- |
| 0 — probe Telemt caller-secret | `4fdcbbf`, `da33107` | `TELEMT_CALLER_SECRET = supported` (пиннутый форк принимает `secret`); чисто |
| 1 — `panel_settings` + GUID + `api_keys` + `ApiKeyService` (миграция 9) | `a787459` | чисто |
| 2 — Bearer в `RequestContext.current`, scope-гейты, `KeyRateLimiter`, `/api/keys*`, stub `/api/fleet/v2/identity` | `8be3d60` | чисто |
| 3 — `panel/fleet_v2/protocol.py` (модели, digest, `GenerationConflict`) + `managed.py` (`ManagedStore`, миграция 10) | `fee90b5`, `8207bc6` | чисто |
| 4 — Telemt caller-secret + fallback, `update_options` у всех адаптеров, `AppliedGrant.credential_origin` | `02b9445`, `ac74a94` | чисто |
| 5 — `panel/fleet_v2/reconcile.py` (`Reconciler`) | `fbcbdec` | **Needs fixes — fix round 1 не запущен** |

Полный suite на стенде после Task 5: `399 passed, 1 skipped`, ruff чисто.

## Следующий шаг: Task 5, fix round 1 (из ревью)

Important:
1. Ресурс есть в runtime, но в `managed_resources` записи нет (`stored is None`): сейчас считается, что он уже несёт
   пушнутый секрет, и дальше управляется/удаляется как ресурс центра. Рулинг: коллизия имени с локальным
   пользователем → `failed` с ошибкой «runtime user exists and is not managed» (ADR 003); случай «упали между
   `adapter.create` и `_record`» → `rotate` (идемпотентно), чтобы runtime гарантированно держал escrow-секрет.
2. Дубликат `(protocol, runtime_username)` в одном документе обрабатывается в зависимости от порядка — добавить
   валидатор в `GenerationDocument` (`protocol.py`) и `failed` в reconciler.
3. Протокол, у которого в store есть только orphan-строки, а адаптера нет (или `discover()` падает), зависает
   навсегда без видимой причины — писать orphan-строки как `failed` с текстом ошибки.
4. Нет закоммиченных тестов на: drift опций → `drifted`; `run_pending()`; падение create/rotate одного ресурса при
   успехе соседей; `deleted` для неизвестного пользователя → не трогаем; идемпотентность `store_secrets` при
   повторном push.

Minor (в ledger, не блокируют): re-capture только для doc-`manager`; `applied.enabled` игнорируется после
rotate/update_options; задокументировать контракт `adapters` (только включённые протоколы, один `Reconciler` на
процесс); `run_pending` читает `latest` вне lock (Task 6 должен ловить `KeyError`); drift сравнивает сырые и
нормализованные опции; `clock` не используется.

После fix round → scoped re-review → `Task 5: complete` в ledger → Task 6 (brief уже сгенерирован:
`task-6-brief.md`, как и `task-4/5`).

## Рулинги, принятые за владельца (перенести в итоговый отчёт)

- Pre-flight: `_apply_one` не держит `BEGIN IMMEDIATE` через HTTP к менеджерам — adapter I/O вне транзакций.
- Pre-flight: `content_digest` (без номера/времени) рядом с `digest`; `publish` сравнивает `content_digest`.
- Pre-flight: `compile()` пропускает гранты `deleted` + `observed_state='missing'` (узел уже подтвердил).
- Pre-flight: фикстура `pair` живёт в `panel/tests/conftest.py`; `ACTOR` — константа в тестах.
- Task 3: границы `generation ≥ 1`, `previous_generation ≥ 0` по спеке; тест поправлен, а не модель.
- Task 4: `TelemtIndeterminate` пробрасывается сырым (контракт resume), а не превращается в `AdapterError`.
- Task 5→9: центр эскроуит вернувшийся manager-секрет **под тем же `secret_id:version`**, что назван в
  документе (иначе узел ротирует бесконечно).
- Task 5→8: `compile()` не кладёт `MtproxyOptions.expiration` в документ (ни один адаптер его не применяет).
- Task 5 fix: коллизия имени с локальным пользователем → `failed`, не adoption.

## Отложенные minor по задачам (для финального ревью ветки)

- T1: `authenticate()` коммитит `last_used_at` посреди итерации; ветка set/skip не покрыта тестом.
- T2: rate-limit тест не доказывает порядок 429-до-403; нет тестов на пустой `Bearer ` / регистр заголовка.
- T3: `Resource.options` — нетипизированный dict (не-JSON значение упадёт в `canonical_digest`); `latest()`
  возвращает лишний `master_guid`; `remove_resource` без теста; `assert` в `GenerationConflict`.
- T4: fallback 400/422 дублируется в create/rotate (частично убран helper'ом); контрактный тест skip'ает Telemt.

## Действия владельца

- Ничего, пока ветка не дойдёт до Task 16; production-хосты не трогались. `AMS_Z` разрешён только для
  живой проверки Task 15 после зелёного гейта.
