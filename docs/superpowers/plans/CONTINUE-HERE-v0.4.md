# CONTINUE HERE — v0.4 маршрутизация

Обновлено: 2026-09-14, поздний вечер. **Tasks 0–13 сделаны: гейт зелёный, живая проверка на AMS_Z
пройдена, релизная заметка заполнена, скриншоты и smoke экрана в браузере сняты; релиз опубликован по
поручению владельца («если всё ок, публикуй релиз…»).** Тег `v0.4.0-beta.1` стоит на `d5dc752`, релиз
опубликован — см. раздел «Публикация». Владельцу остаются
merge и раскатка, см. «Что дальше».

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
| `841a086`, `b960f04`, `442d9c6` | 13 | точка продолжения, гейт, живая проверка; check-doc-links/rsync без graphify-out |
| `0b1349e` | релиз | скриншоты `docs/releases/assets/v0.4.0-beta.1/` + smoke экрана в Chrome (`ROUTING_UI_OK`), `CHANGELOG.ru.md`, `scripts/install-release.sh` (`--requirements`: что нужно и что устанавливается), разделы «Установка» заметки, правка UPGRADING (у установщика нет команды `upgrade`) |

## Гейт (Task 13) — итог

`full` (1978 passed / 2 skipped, 427 с), `compose`, `lab-host` (17 сценариев, `fleet` 169 с),
`fleet` (84/84, 173 с), `routing` (154/154, 70 routing, 262 с) — все `REMOTE_GATE_*_OK`
2026-09-14. Живая проверка AMS_Z 17:20–17:41 UTC: обновление v0.3 → v0.4 на месте, naive «весь через
WARP» (`warp=on`, exit `104.28.219.140` ≠ прямой `194.87.220.7`) → откат байт-в-байт к privoxy-строке,
mieru «WARP + block example.com» → откат к снимку, всё удалено; Caddyfile/mita/пользователи = снимку.
Отчёт: `/root/v04-live/routing-live-report.json` на AMS_Z (root); точки отката `/root/v04-live/`.
AMS_Z **остался на v0.4** с `NAIVE_EGRESS_WARP`/`MIERU_EGRESS_WARP=socks5://127.0.0.1:45000` в `.env`.

## Публикация (по поручению владельца 2026-09-14)

Путь тот же, что у v0.3 (память `proxy-control-ci-only-on-ams-test`): `remote-gate.sh full` на финальном дереве →
архив дважды из чистого клона на ams-test (`/root/release-check-v04`, `release/build.py`, байты совпадают) →
аннотированный тег `v0.4.0-beta.1` с `lab-sha256: <digest>` → push ветки и тега → workflow `Release`
(собирает дважды, сверяет с аннотацией, attestation, публикует pre-release) → тело релиза из
`docs/releases/v0.4.0-beta.1.md` с абсолютными ссылками (`gh release edit --notes-file`). 
**Итог 2026-09-14 18:20–18:35 UTC.** `full` на `d5dc752` — `REMOTE_GATE_FULL_OK` (1978 passed / 2 skipped,
475 с); архив из `/root/release-check-v04` дважды — `fd837f021a096592aa61e876ad404c931a490b1a0672328dbb3e1f27a5bc5458`;
тег `v0.4.0-beta.1` на `d5dc752` (аннотация `lab-sha256: fd837f02…`); ветка и тег отправлены в origin
(ветка впервые); workflow `Release` run 34880569061 — quality, build-twice-and-compare, attest,
draft-release, publish — все success, без ручной остановки (у окружения `release-publish` нет
reviewer); опубликованные `SHA256SUMS` совпадают со стендовыми (архив, манифест, SBOM),
`gh attestation verify` проходит; тело релиза — заметка с абсолютными ссылками + блок «Архив» с digest;
заголовок «v0.4.0-beta.1 — маршрутизация / routing».
https://github.com/dubr1k/proxy-control/releases/tag/v0.4.0-beta.1. Этот коммит — после тега (в архив не входит).

## Что дальше (владелец)

1. Тег и публикация — см. «Публикация»; `4d1e96d4…` относится к дереву гейта `841a086`, digest тегируемого дерева — в аннотации тега и в `SHA256SUMS` релиза.
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
