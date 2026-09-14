# CONTINUE HERE — v0.4 маршрутизация

Обновлено: 2026-09-14 (пауза по просьбе владельца после Task 4).

## Где мы

- Ветка: `feature/vnext-v0.4-routing` (от `feature/vnext-v0.3-fleet-v2` = `v0.3.0-beta.1`, `ecfdcc3`).
  Последний коммит: `6eff402` (naive-manager egress API). Рабочее дерево чистое, кроме этой заметки и
  галочек в плане.
- Спека: `docs/superpowers/specs/2026-09-14-v0.4-routing-design.md`; план (Tasks 0–13):
  `docs/superpowers/plans/2026-09-14-v0.4-routing.md` — галочки актуальны.
- Поручение владельца (2026-09-14): «приступай к работе над версией 0.4, создай новую ветку, принимай
  решения автономно, всё проверяешь на ssh ams-test; также можешь тестить на AMS_Z».

## Сделано (коммиты по порядку)

| Коммит | Task | Что |
| --- | --- | --- |
| `1c88679` | 0 | спека + план |
| `3929da2` | 1 | фикс-волна v0.3, центр (`panel/tests/test_fleet_v2_post_merge.py`) |
| `45703d7` | 1 | фикс-волна v0.3, узел (`test_fleet_v2_post_merge_node.py`, `docs/AUDIT_EVENTS.md`; capture получил `purpose: escrow|import`) |
| `013840f` | 1 | фикс-волна v0.3: UI, стенд, compose tmpfs, спека v0.3 |
| `751e93f` | 2 | spike: `scripts/lab/socks5-stub.py`, `scripts/lab/routing-spike.py`, `docs/spikes/VNEXT_ROUTING_ENGINE.md` |
| `0911494` | 3 | установщик `[egress]` (dual-read, `effective_egress`, мастер, `.env` + compose env, INSTALLER_REFERENCE) |
| `6eff402` | 4 | naive-manager egress API (`naive_manager/egress.py`, `service.py` `egress/egress_plan/egress_apply/egress_rollback` + `_commit`, маршруты `/v1/egress*`) |

Прогоны: `remote-gate.sh quick` (весь набор) — зелёный после Task 1 и после Task 3 (`tests/`); после
Task 4 гонялись `tests/test_naive_manager*.py` + `tests/test_naive_egress.py` (98 passed). **Полный `quick` и
`compose` после Task 4 не запускались** — первым делом при продолжении.

## Ключевые факты spike (влияют на Tasks 5–7)

- Caddy forwardproxy: `acl` **не применяется при заданном `upstream`** (и дефолтный deny loopback тоже
  выключается) → `naive_native` блокировки только при `default=direct`; менеджер уже отказывает документу
  с `upstream`+`acl` (422 `egress_invalid`). WARP proxy mode на AMS_Z сам не пускает loopback/RFC1918.
- mita: изменение `egress` применяется **только рестартом** (`mita reload` не подхватывает) →
  `TRANSACTION_MODES["egress.apply"] = "restart"`, `restart_required: true` в preview; доменные правила
  `REJECT`/`DIRECT` работают (suffix), CIDR — только по литеральным IP.
- capabilities: `naive_native = whole_direct, whole_warp, block_domain, block_cidr` (blocks only when
  direct); `mieru_native = + selective_domain, selective_cidr`.

## Следующий шаг — Task 5: mieru-manager egress API

1. `mieru_manager/egress.py`: `validate_document` (`{"schema":1,"proxies":[{"name":"warp","provider":"warp"}],
   "rules":[{"domains":[],"cidrs":[],"action":"DIRECT|PROXY|REJECT","proxy":"warp"|null}]}`), `to_mita(document,
   provider_url)` → секция `egress` mita, `from_mita(section)` (обратно; чужой прокси → `None` = custom),
   `CAPABILITIES`, копия `check_reachable`.
2. `mieru_manager/service.py`: `TRANSACTION_MODES["egress.apply"]="restart"`, `["egress.rollback"]="restart"`;
   `_transaction_mode` для этих операций; `egress()`, `egress_plan()`, `egress_apply(expected_revision,
   document, operation_id)`, `egress_rollback(expected_revision)`; журнал в state (`_OPTIONAL_STATE_KEYS` +
   `egress`); `provider_url` из `MIERU_EGRESS_WARP`.
3. `mieru_manager/server.py`: маршруты `/v1/egress*` (проверить префикс путей у mieru-сервера — там
   `_dispatch` со своими путями), коды как у naive.
4. `compose.mieru.yaml`: `network_mode: host` у mieru-manager (reachability к 127.0.0.1) — проверить
   `tests/test_mieru_deployment.py` (там утверждаются поля сервиса) и `remote-gate.sh compose`.
5. Тесты: `tests/test_mieru_egress.py` (чистые функции), `tests/test_mieru_manager.py` (сервис с fake mita:
   apply меняет только `egress`, users/portBindings/mtu равны; conflict; unreachable; readback mismatch;
   idempotent; rollback; recovery).

Дальше по плану: Task 6 (клиенты панели `NaiveClient/MieruClient`, `MemoryNaive/MemoryMieru`, адаптеры
`egress_target/apply_egress/rollback_egress`, `egress.v1` в identity) → Task 7 (IR + миграция 14 +
компилятор) → 8 (сервис/маршруты) → 9 (Fleet v2) → 10 (UI) → 11 (лаборатория) → 12 (docs; создать
`docs/ROUTING.en.md`/`.ru.md` — на них уже ссылается INSTALLER_REFERENCE, `check-doc-links` в `full` упадёт
без них) → 13 (гейт + живая проверка AMS_Z).

## Стенд

- `ams-test`: установка `lab-host` v0.3.0-beta.1 (узел `https://panel.lab.test`) — жива; spike вернул
  Caddy/mita в исходное состояние (проверено), throw-away пользователи `spike-*` удалены, stub снят,
  контейнер `pc-spike-mihomo` удалён. `/root/dev/proxy-control` — rsync-копия дерева на `6eff402`+.
- `AMS_Z`: не трогали (только read-only curl-пробы WARP/privoxy). Пользователи целы.
