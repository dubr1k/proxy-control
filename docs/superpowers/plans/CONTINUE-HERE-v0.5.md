# CONTINUE HERE — v0.5 Xray egress-router

Обновлено: 2026-09-17. **Tasks 1–15 сделаны: гейт зелёный на финальном дереве, живая проверка на
AMS_Z пройдена (53/53), smoke экрана в браузере (34/34), релизная заметка заполнена.** Это последняя стадия vNext. Тега и публикации
ещё нет — по поручению владельца (путь v0.4, см. «Что дальше»).

## Где мы

- Ветка: `feature/vnext-v0.5-xray-router` (от `feature/vnext-v0.4-routing` = `v0.4.0-beta.1`, `d5dc752`).
  `VERSION` = `0.5.0-beta.1`. Гейт пройден на дереве `90ff806` (`full`: 2149 passed / 2 skipped, 448,5 с), `6622208`
  (`routing`, `router`) и `ef400ff` (`compose`, `lab-host`, `lab-sha256` `5de24c49d322d42a2e3972dfa9f9b12a8b0a3792c31ea69e540e7188cc9dfbb5`;
  `fleet`); коммиты после — только документация.
- Спека: `docs/superpowers/specs/2026-09-16-v0.5-xray-router-design.md` (§13 — живая проверка, §15 —
  отложенное); план: `docs/superpowers/plans/2026-09-16-v0.5-xray-router.md` — все галочки Tasks 1–15
  стоят; релизная заметка: `docs/releases/v0.5.0-beta.1.md` (таблица гейта + живая проверка AMS_Z, RU/EN).
- Поручение владельца (2026-09-16): «/goal … переходить к разработке версии 0.5 и это последняя стадия …
  всё тестируй на локальных контурах»; «тесты на тех же стендах ssh AMS_Z и ssh ams-test».

## Коммиты ветки (по порядку)

| Коммит | Task | Что |
| --- | --- | --- |
| `be80370`, `2aafd47` | 0 | спека + план (ADR 007 accepted; без canary и 3x-ui bridge) |
| `4751d36` | 1 | фикс-волна v0.4 (userinfo custom-upstream не течёт в egress API; мёртвый `profile_environment` удалён) |
| `adf91ff` | 2 | закреплённый артефакт Xray-core 26.3.27 (`release.py`: архив + члены, `safe_extract_zip`), SBOM |
| `453ad12` | 3 | spike Xray на стенде: `docs/spikes/…`, все ячейки `xray_router` supported |
| `21b345a` | 4 | `xray_router_manager/`: рантайм, супервизор поколений (`-test → swap → LKG`, recovery, watchdog), egress API на UDS |
| `7f596da` | 5 | провайдер `router` у naive-manager и mieru-manager (ключ из state, перерисовка при ротации) |
| `fdb8fc9` | 6 | панель: клиент роутера, `RouterTarget/RouterAdapter`, attach-документы, wiring `XRAY_ROUTER_*` |
| `ada03b7` | 7 | backend `xray_router`, geosite/geoip/port в правилах, компилятор `XrayRoutingIntent`, миграция 15 |
| `2bf7be2` | 8 | attach/detach, политики `xray_router` локально (preview/apply/rollback через роутер), `targets.router` |
| `88a5420` | 9 | Fleet v2: `companion`/`passthrough` в секции egress, capability `egress.router.v1` |
| `3e1e111` | 10 | UI «Маршрутизация»: подключение к роутеру, geosite/geoip/порт |
| `cab8bfd`, `2785318`, `d796766` | 11 | установщик: `[egress] router`, адаптер `xray_router`, секреты `root:10006 0440`, Core «соседние» |
| `2ced210`, `f06874f`, `b870101` | 12 | лаборатория: staging Xray, `lab-host` с роутером, router-01…14, tier `router`; entrypoint панели держит группы всех оверлеев |
| `0e1ceaf` | 13 | backup/restore с роутером, `docs/SECURITY_TEST_MATRIX.md`, замороженные идентификаторы |
| `6d35e58`, `aaec4b4` | 14 | документация v0.5, VERSION/CHANGELOG, план Tasks 1–14 |
| `ef400ff`, `2f06770`, `6622208`, `7f9eaf7` | 15 | гейт: мастер ищет архив под `--root` (тесты не зависят от узла); реальный runner роутера видит свой Compose-сервис (найдено на AMS_Z); пробы лаборатории через Интернет получают вторую попытку при сетевом сбое; заметка и точка продолжения |
| `998b12d` | владелец | архив Xray скачивается сам по закреплённому URL (как пакет mita); мастер предлагает роутер каждому профилю; документация «положите сами» → «скачивается сам» |
| `90ff806` | smoke | attach/detach записывают pass-through узла (удаление после отключения без лишнего apply); карточка маршрутизации сбрасывает политику до первой отрисовки («загружается…»); скриншоты v0.5 + `ROUTER_UI_OK` 34/34 |

## Гейт (Task 15) — итог

`full` на `90ff806` (2149 passed / 2 skipped, 448,5 с), `compose`, `lab-host` (LAB_RESET=1, 17 сценариев,
install 115 с, repair 41 с, reboot-recovery 65 с, fleet 175 с, secrets-scan), `fleet` (84/84, 184,5 с),
`routing` (154/154, 296,6 с), `router` (242/242, 88 router, 471,2 с) — все `REMOTE_GATE_*_OK` 2026-09-16.
Первые прогоны `routing`/`router` на финальном дереве споткнулись на сетевых пробах стенда (потерянная
UDP-датаграмма DNS, curl 35 к контрольной цели) — лаборатория даёт таким пробам вторую попытку (`6622208`),
повтор зелёный.
Живая проверка AMS_Z 15:08–15:31 UTC: обновление v0.4 → v0.5 на месте (28 с, миграция 15), без роутера
v0.4-поведение цело → роутер шагами адаптера (7,4 с, verify зелёный) → attach naive → «весь через WARP +
block» через роутер (`warp=on`, exit `104.28.219.140` ≠ прямой `194.87.220.7`) → откат → detach → два
отката к полу → Caddyfile байт-в-байт (privoxy-строка на месте) → роутер удалён (`rollback(purge)`),
`.env` = снимку, всё удалено; Caddyfile/mita/пользователи = снимку. Отчёт `/root/v05-live/router-live-report.json`
(root), точки отката `/root/v05-live/`. AMS_Z **на v0.5 без роутера**; архив Xray оставлен в `/var/lib/proxy-control/`.

## Что дальше (владелец)

0. **Поручение 2026-09-17:** v0.6 — результат проверки всех функций бэкенда и фронта за v0.2–v0.5;
   выпустить её после подтверждения, что всё работает (спека/план v0.6 — следующие файлы в этом каталоге).

1. Тег и публикация — путь v0.4 (память `proxy-control-ci-only-on-ams-test`): `remote-gate.sh full` на
   финальном дереве → архив дважды из чистого клона на ams-test (`release/build.py`, байты совпадают) →
   аннотированный тег `v0.5.0-beta.1` с `lab-sha256: <digest>` → push ветки и тега → workflow `Release` →
   тело релиза из `docs/releases/v0.5.0-beta.1.md` (`gh release edit --notes-file`). Релизный архив
   Xray не содержит: установщик скачивает `Xray-linux-64.zip` (sha256 `23cd9af9…`) по закреплённому URL в
   `/var/lib/proxy-control/` сам, как пакет mita (решение владельца 2026-09-16: «пользователь вообще ничего
   не должен класть сам»); хост без интернета кладёт файл заранее.
2. Merge веток v0.3 → v0.4 → v0.5 в `main` и раскатка `ams-server`/`AMS_P`/`AMS_R` — только владелец;
   порядок «узлы → центр» (`docs/UPGRADING.ru.md`, раздел v0.5); узел v0.4 принимает поколение без
   `companion`, центр v0.4 игнорирует `router` в identity.
3. Стенд `ams-test`: узел v0.5 (`lab-host`, LAB_KEEP_INSTALL=1) оставлен установленным **с роутером** и
   stub-провайдером `socks5://127.0.0.1:45000` в `.env*` (stub не запущен) — следующий `lab-host` с
   `LAB_RESET=1` всё переустановит.

## Известные ограничения/решения (для ревью и после v0.5)

- Отложено спекой §15: 3x-ui bridge, canary, per-grant политики, UDP relay, regexp-правила.
- Ротация ключей ingress — root-скрипт `rotate-xray-router-ingress` (пересоздание роутера и менеджеров),
  не через API; naive перерисовывает блок при старте (adopts unmanaged seed как managed), mieru —
  seeded-секцию при пустом журнале.
- `LAB_KEEP_INSTALL=1` пропускает uninstall — именно поэтому отсутствие `compose_service_present` у
  реального runner'а роутера дожило до живой проверки; для следующих адаптеров: тест на реальный runner
  (`test_the_real_runner_sees_only_the_router_compose_service`) — образец.
- Мастер предлагает роутер каждому профилю с NaiveProxy или Mieru; архив — забота установщика
  (`_assert_archive` → `ensure_pinned_package` из mieru.py; runner без `fetch_artifact` не качает, и
  отказ называет путь, дайджест и URL).
- Секреты роутера — Docker file secrets с владельцем/режимом файла (`root:10006 0440`); менеджеры читают
  свою копию 0400 и принимают режим `& 0o027 == 0`.
- Entrypoint панели объединяет группы из `id -G` (все `group_add` оверлеев) и `PANEL_SUPPLEMENTARY_GROUPS`
  (allowlist 10001|10005|10006) — последний оверлей больше не теряет группу.
- Живая проверка: детач возвращает naive в `direct` (пустой управляемый блок), а privoxy-строку — только
  откаты к полу журнала (два шага); поведение по спеке, отмечено в заметке.
- `/code-review` в сессии недоступен; самопроверка: RBAC новых маршрутов (attach/detach/history/rollback —
  `owner`, preview/targets — `anyone`), secret-scan (лаборатория + AMS_Z: ключ ingress ни в `targets`, ни в
  аудите, ни в egress-виде), FK миграции 15 (`test_routing_v15_rebuilds_policies_keeping_rows_and_foreign_keys`,
  `test_delete_cascades_rules`), wire-совместимость v0.4↔v0.5 (`companion`/`passthrough` опускаются при
  отсутствии — `_Strict` узла v0.4 принимает; identity — `_Report` с `extra="ignore"`).
