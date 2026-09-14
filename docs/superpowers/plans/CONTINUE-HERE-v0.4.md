# CONTINUE HERE — v0.4 маршрутизация

Обновлено: 2026-09-14, вечер (Tasks 0–12 сделаны; идёт Task 13 — гейт релиза и живая проверка).

## Где мы

- Ветка: `feature/vnext-v0.4-routing` (от `feature/vnext-v0.3-fleet-v2` = `v0.3.0-beta.1`, `ecfdcc3`).
  `VERSION` = `0.4.0-beta.1`. Рабочее дерево чистое, кроме этой заметки/плана/release note.
- Спека: `docs/superpowers/specs/2026-09-14-v0.4-routing-design.md` (§13 — решения, принятые за
  владельца, п. 8 — URL провайдера не покидает менеджер); план (Tasks 0–13):
  `docs/superpowers/plans/2026-09-14-v0.4-routing.md` — галочки актуальны.
- Поручение владельца (2026-09-14): «приступай к работе над версией 0.4, создай новую ветку, принимай
  решения автономно, всё проверяешь на ssh ams-test; также можешь тестить на AMS_Z».

## Сделано (коммиты по порядку)

| Коммит | Task | Что |
| --- | --- | --- |
| `1c88679` | 0 | спека + план |
| `3929da2`, `45703d7`, `013840f` | 1 | фикс-волна v0.3 (центр, узел, UI/стенд/compose tmpfs) |
| `751e93f` | 2 | spike: `socks5-stub.py`, `routing-spike.py`, `docs/spikes/VNEXT_ROUTING_ENGINE.md` |
| `0911494` | 3 | установщик `[egress]` (dual-read, `effective_egress`, мастер, compose env) |
| `6eff402` | 4 | naive-manager egress API (`naive_manager/egress.py`, `/v1/egress*`) |
| `a7e8283` | 5 | mieru-manager egress API (restart-транзакция, журнал, host network) |
| `11ac905` | 6 | клиенты панели + `EgressTarget/AppliedEgress` адаптеров + `egress.v1` в identity; `panel/routing/document.py` |
| `ca98bee` | 7 | `panel/routing/` models/compiler/store + миграция 14 |
| `6371bb8` | 8 | `RoutingService` + `/api/routing/*` (локальный узел), `docs/AUDIT_EVENTS.md` |
| `f2a685f` | 9 | Fleet v2: `EgressDocument`, `GenerationDocument.egress` (wire/digest без поля при None), узел применяет egress после ресурсов, pusher переводит политику в applied/failed, remote apply/rollback, `managed_by_central` |
| `e877fbb` | 10 | UI «Маршрутизация» (`routing.js`), строка на карточке узла, контрактный тест, mobile-layout |
| `b84414e`, `fcf452b` | 11 | лаборатория: `fleet-acceptance.py --routing` (r01…r11), `remote-gate.sh routing`, `guest-runner LAB_ROUTING=1` |
| `4373edb`, `996352f` | 12 | VERSION 0.4.0-beta.1, CHANGELOG, `docs/ROUTING.en/ru.md`, ADR 006 accepted / ADR 007 (нативные backend), PANEL/FLEET/UPGRADING/OPERATIONS/COMPATIBILITY/README/матрица возможностей, черновик `docs/releases/v0.4.0-beta.1.md` |
| `d93b598` | lab | LAB_RESET убирает `lab-adjacent.conf` (иначе dpkg configure nginx падал в preflight) |
| `1b2eeed` | fix | голый 5xx от reverse proxy перед остановленной панелью = offline (`pusher._refusal`) — нашёл `lab-host fleet` |
| `efb568c` | fix | установщик пишет `NAIVE_EGRESS_WARP`/`MIERU_EGRESS_WARP` в `.env.naive`/`.env.mieru` (`warp-provider` действия); `planner.profile_environment` — мёртвый код, живут только тесты |

## Гейт (Task 13) — статус

| Гейт | Статус |
| --- | --- |
| `quick` (весь набор) | зелёный после Task 9 (EXIT=0); после `efb568c` — `tests/` зелёные, `panel/tests` частично |
| `compose` | `REMOTE_GATE_COMPOSE_OK` после Task 5 |
| `lab-host` (LAB_RESET=1 LAB_KEEP_INSTALL=1) | прогон 1 (дерево `4373edb`): установка/repair/reboot/crash — passed; сценарий `fleet` упал на s07/s09 offline-detection → фикс `1b2eeed`. **Повторить на финальном дереве** (архив = `git ls-files`, поэтому сначала всё закоммитить) |
| `routing` | `ROUTING_ACCEPTANCE_OK` 2026-09-14: 154/154 проверок (70 routing), 261 с — на узле первого lab-host |
| `fleet` | ещё не гонялся отдельно (внутри `routing` шаги 1–10 fleet проходят) |
| `full` | запущен после `fcf452b`; результат — в `scratchpad/full-gate.log` сессии или перезапустить |
| живая проверка AMS_Z | не начата |

## Как продолжать

1. `scripts/dev/remote-gate.sh full` → `REMOTE_GATE_FULL_OK`; `compose` → `REMOTE_GATE_COMPOSE_OK`.
2. `LAB_RESET=1 LAB_KEEP_INSTALL=1 scripts/dev/remote-gate.sh lab-host` (≈ 10 мин; runner отвязан от
   SSH, лог `/root/lab-host.log`); запомнить `/root/lab-host.sha` для аннотации тега.
3. `scripts/dev/remote-gate.sh fleet` → `REMOTE_GATE_FLEET_OK`; `scripts/dev/remote-gate.sh routing` →
   `REMOTE_GATE_ROUTING_OK` (ставит `NAIVE_EGRESS_WARP`/`MIERU_EGRESS_WARP=socks5://127.0.0.1:45000` в
   `.env` узла и пересоздаёт менеджеры; stub стартует сам скрипт; отчёт `lab-results/routing/report.json`).
4. Живая проверка `AMS_Z` (разрешение владельца 2026-09-14; хост на v0.3, rsync-раскатка,
   `/opt/mtproxy-shared443`, `.env` с `COMPOSE_FILE=…`, Caddyfile содержит рукописный
   `upstream http://127.0.0.1:8118` (privoxy) + `disable_insecure_upstreams_check`, mita — `egress`
   с warp `127.0.0.1:45000` и правилом `* → PROXY`; WARP proxy mode слушает `127.0.0.1:45000`):
   снимок (Caddyfile sha256, `mita describe config`, списки пользователей, `.env*`, db backup, теги
   образов `:rollback-<ts>`) → rsync `panel/ naive_manager/ mieru_manager/ compose*.yaml VERSION` →
   добавить `NAIVE_EGRESS_WARP=socks5://127.0.0.1:45000` и `MIERU_EGRESS_WARP=…` в `.env` →
   `docker compose build panel naive-manager mieru-manager` → `up -d --wait --no-deps panel
   naive-manager mieru-manager` (миграция 14; mieru-manager пересоздаётся в host network) → как owner
   через API узла: `GET /api/routing/targets` (naive `mode=custom`, `adopts_unmanaged_upstream`; mieru
   `mode=proxy`, `adopts_unmanaged_egress`) → политика naive «весь через WARP» → preview → apply →
   exit-IP через живой клиент = IP WARP (104.28.x) → rollback → Caddyfile sha256 = снимку → mieru:
   apply «весь через WARP» = no-op по digest? (секция уже warp — документ совпадёт, менеджер применит
   идемпотентно) + block тестового домена → rollback → `mita describe config` = снимку → удалить
   политики; пользователи не трогаются; хост остаётся на v0.4 (как в v0.3 живой проверке), `.env`
   с переменными провайдера — оставить (честное состояние хоста с WARP) или убрать — решить и записать.
5. Заполнить таблицу гейта и живую проверку в `docs/releases/v0.4.0-beta.1.md`, README «текущий
   выпуск» уже указывает на v0.4; обновить эту заметку; `graphify update .`; финальное ревью ветки;
   commit `docs: гейт v0.4.0-beta.1 и точка продолжения`. Тег — действие владельца
   (`git tag -a v0.4.0-beta.1 -m '…' -m 'lab-sha256: <digest>'`).

## Известные ограничения/решения (для ревью)

- Удалённый rollback (связанная панель) — один шаг к предыдущему `applied`-документу из
  `routing_applies` центра, не стек; локальный — журнал менеджера (стек до «пола» — перенятых строк).
- «Сбросить и применить» у naive оставляет пустой управляемый блок (маркеры) — файл не байт-в-байт
  равен свежей установке; откат к «полу» через журнал менеджера возвращает байты. Возможное улучшение:
  не писать маркеры для пустого документа.
- `providers` без URL везде (спека §13 п. 8); `manager_unavailable`, `egress_no_previous`,
  `managed_by_central`, `backend_mismatch`, `node_not_found` — коды сверх спеки, в COMPATIBILITY.
- Reachability-проба провайдера идёт при каждом heartbeat (identity) — на loopback это мгновенно.
