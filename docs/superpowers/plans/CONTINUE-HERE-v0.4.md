# CONTINUE HERE — v0.4 маршрутизация

Обновлено: 2026-09-14, вечер. **Tasks 0–13 сделаны: гейт зелёный, живая проверка на AMS_Z
пройдена, релизная заметка заполнена.** Осталось только действие владельца — тег (и решение о
merge/раскатке), см. «Что дальше».

## Где мы

- Ветка: `feature/vnext-v0.4-routing` (от `feature/vnext-v0.3-fleet-v2` = `v0.3.0-beta.1`, `ecfdcc3`).
  `VERSION` = `0.4.0-beta.1`. Гейт пройден на дереве `841a086` (`lab-sha256`
  `4d1e96d4dbf638fd846c8b43a86c78223571b25ebfcceb41df8a6034c27e6d24`); коммиты после него —
  только `scripts/dev/remote-gate.sh` (`e7c180c`, env-файлы tier `routing`), документация и план.
- Спека: `docs/superpowers/specs/2026-09-14-v0.4-routing-design.md` (§13 — решения за владельца, п. 8 —
  URL провайдера не покидает менеджер); план: `docs/superpowers/plans/2026-09-14-v0.4-routing.md` —
  все галочки Tasks 0–13 стоят; релизная заметка: `docs/releases/v0.4.0-beta.1.md` (таблица гейта +
  живая проверка AMS_Z, RU/EN).
- Поручение владельца (2026-09-14): «приступай к работе над версией 0.4, создай новую ветку, принимай
  решения автономно, всё проверяешь на ssh ams-test; также можешь тестить на AMS_Z».

## Коммиты ветки (по порядку)

| Коммит | Task | Что |
| --- | --- | --- |
| `1c88679` | 0 | спека + план |
| `3929da2`, `45703d7`, `013840f` | 1 | фикс-волна v0.3 (центр, узел, UI/стенд/compose tmpfs) |
| `751e93f` | 2 | spike: `socks5-stub.py`, `routing-spike.py`, `docs/spikes/VNEXT_ROUTING_ENGINE.md` |
| `0911494` | 3 | установщик `[egress]` (dual-read, `effective_egress`, мастер, compose env) |
| `6eff402` | 4 | naive-manager egress API |
| `a7e8283` | 5 | mieru-manager egress API (restart-транзакция, журнал, host network) |
| `11ac905` | 6 | клиенты панели + `EgressTarget/AppliedEgress` + `egress.v1` в identity; `panel/routing/document.py` |
| `ca98bee` | 7 | `panel/routing/` models/compiler/store + миграция 14 |
| `6371bb8` | 8 | `RoutingService` + `/api/routing/*` |
| `f2a685f` | 9 | Fleet v2: секция `egress`, узел, pusher, remote apply/rollback, `managed_by_central` |
| `e877fbb` | 10 | UI «Маршрутизация» |
| `b84414e`, `fcf452b`, `e7c180c` | 11 | лаборатория: `fleet-acceptance.py --routing`, tier `routing` |
| `4373edb`, `996352f` | 12 | VERSION/CHANGELOG, ROUTING.en/ru, ADR 006/007, PANEL/FLEET/UPGRADING/OPERATIONS/COMPATIBILITY/README |
| `d93b598`, `1b2eeed`, `efb568c` | гейт | preflight/nginx fixture; голый 5xx = offline; установщик пишет `*_EGRESS_WARP` в env-оверлеи |
| `841a086` + финальный docs-коммит | 13 | точка продолжения, гейт, живая проверка |

## Гейт (Task 13) — итог

`full` (1978 passed / 2 skipped, 427 с), `compose`, `lab-host` (17 сценариев, `fleet` 169 с),
`fleet` (84/84, 173 с), `routing` (154/154, 70 routing, 262 с) — все `REMOTE_GATE_*_OK`
2026-09-14. Живая проверка AMS_Z 17:20–17:41 UTC: обновление v0.3 → v0.4 на месте, naive «весь через
WARP» (`warp=on`, exit `104.28.219.140` ≠ прямой `194.87.220.7`) → откат байт-в-байт к privoxy-строке,
mieru «WARP + block example.com» → откат к снимку, всё удалено; Caddyfile/mita/пользователи = снимку.
Отчёт: `/root/v04-live/routing-live-report.json` на AMS_Z (root); точки отката `/root/v04-live/`.
AMS_Z **остался на v0.4** с `NAIVE_EGRESS_WARP`/`MIERU_EGRESS_WARP=socks5://127.0.0.1:45000` в `.env`.

## Что дальше (владелец)

1. Тег: `git tag -a v0.4.0-beta.1 -m 'Proxy Control v0.4.0-beta.1 — маршрутизация' -m 'lab-sha256: <digest архива тегируемого дерева>'`
   — архив пересобирается `release/build.py` из тегируемого дерева; `4d1e96d4…` относится к `841a086`.
2. Merge ветки (v0.3-ветка `feature/vnext-v0.3-fleet-v2` — по-прежнему не слита в `main`; см. память
   `proxy-control-vnext-v03-branch`) и раскатка `ams-server`/`AMS_P`/`AMS_R` — только владелец;
   порядок «узлы → центр» (`docs/UPGRADING.ru.md`, раздел v0.4); хосты, обновляемые rsync, задают
   `NAIVE_EGRESS_WARP`/`MIERU_EGRESS_WARP` в `.env` сами.
3. Стенд `ams-test`: узел v0.4 (`lab-host`, LAB_KEEP_INSTALL=1) оставлен установленным с провайдером-stub
   в `.env`/`.env.naive`/`.env.mieru` (`socks5://127.0.0.1:45000`, сам stub не запущен) — при следующем
   `lab-host` с `LAB_RESET=1` всё переустановится.

## Известные ограничения/решения (для ревью и v0.5)

- Удалённый rollback (связанная панель) — один шаг к предыдущему `applied`-документу из
  `routing_applies` центра, не стек; локальный — журнал менеджера (стек до «пола»).
- «Сбросить и применить» у naive оставляет пустой управляемый блок (маркеры); байт-в-байт к свежей
  установке возвращает только откат к «полу». Возможное улучшение: не писать маркеры для пустого документа.
- Предупреждение об adoption: у naive — от файла (каждый раз, пока строка не под маркерами), у mieru — от
  журнала (только до первого применения). Косметика, отмечено в release note.
- `providers` без URL везде (спека §13 п. 8); коды сверх спеки (`manager_unavailable`,
  `egress_no_previous`, `managed_by_central`, `backend_mismatch`, `node_not_found`) — в COMPATIBILITY.
- Reachability-проба провайдера при каждом heartbeat (identity) и каждом `targets` — на loopback мгновенна.
- `installer/planner.profile_environment` — мёртвый код (только тесты); env пишут адаптеры. Кандидат на
  удаление в v0.5.
- `/code-review high` в сессии недоступен; финальная самопроверка: RBAC маршрутов, отсутствие секретов в
  targets/identity/observed/audit (проверено на стенде и AMS_Z), FK-каскады миграции 14, wire/digest
  совместимость v0.3↔v0.4 (unit + lab).
