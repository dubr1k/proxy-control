# Промпт для продолжения работы в новом контексте

Скопируйте всё, что ниже разделителя, в новую сессию Claude Code, запущенную
в каталоге проекта.

---

Проект: `~/Syncthing/development/proxy-control`. Отвечай по-русски.

Продолжаем vNext v0.2 — локальный control plane. Задачи 0–19 и релизный гейт 19A
(Steps 1–6) сделаны и проверены на стенде; остались действия владельца (коммиты, тег,
проверка Karing на устройстве). См. раздел «Состояние репозитория» в конце.

## Прочитай сначала

1. `docs/superpowers/plans/2026-09-10-vnext-v0.2-local-control-plane.md` — план.
   В нём отмечены галочками выполненные шаги, а под каждым выполненным шагом
   записан **факт**: что получилось, где черновик плана расходился с кодом и как
   это разрешено. Раздел 5 — решения владельца, они обязательны.
2. `AGENTS.md` — рабочий протокол: не заявляй «работает», не показав вывод
   команды; success-маркер только в успешной ветке.
3. `docs/VNEXT_ARCHITECTURE.md` и `docs/adr/001…007` — зафиксированная
   архитектура; `docs/VNEXT_CAPABILITIES.md` — матрица возможностей, где
   `unsupported` это явная ячейка, а не пробел.

## Как проверять (единственный способ)

Все проверки идут на одноразовом стенде `ssh ams-test`, локальный macOS
не авторитетен:

```
scripts/dev/remote-gate.sh quick <pytest args…>   # быстрый цикл TDD
scripts/dev/remote-gate.sh full                   # перед завершением задачи
scripts/dev/remote-gate.sh compose                # если трогал compose/Dockerfile/entrypoint
scripts/dev/remote-gate.sh lab-container          # если трогал installer/nginx/backup
```

Прогон `full` занимает ~7 минут (образы + 1300+ тестов). Запускай его в фоне и
не опрашивай статус чаще раза в минуту.

Базовая линия, с которой сравниваешь: до Tasks 0–8 было **1279 passed, 2 skipped**,
после Task 14 — **1494 passed, 2 skipped**; новых падений быть не должно. Production-хосты `ams-server`, `AMS_R`, `AMS_P`,
`GER` не трогаются ничем.

## Что уже сделано (Tasks 0–14)

- **0** — `scripts/dev/remote-gate.sh` и baseline. Попутно починен обязательный
  репозиторный гейт: `node --check panel/static/app.js` из `AGENTS.md` физически
  не мог пройти (ES-модуль против CommonJS в Node 18) — заменён на
  `scripts/dev/check-js-syntax.sh`, проверяющий все 14 модулей UI.
- **1** — ADR 001–007, `docs/VNEXT_ARCHITECTURE.md`, ссылки в `docs/README.md`.
- **2** — `panel/tests/test_vnext_characterization.py`: границы Fleet v1, три
  независимых аккаунта на один username, capture vs rotate по протоколам.
- **3** — матрица возможностей: `tests/fixtures/vnext-capabilities.json`
  (4×23 + 9 клиентов) и `docs/VNEXT_CAPABILITIES.md`.
- **4** — `panel/database.py` и `panel/migrations.py`: одна граница БД,
  версионированные миграции с checksum, `BEGIN IMMEDIATE`, fail-closed на более
  новой схеме, безопасный legacy-апгрейд. `Store._init`/`FleetStore._init`
  удалены; в CLI появились `db-migrate`/`db-status`.
- **5** — `panel/audit.py`: аудит пишется внутри транзакции вызывающего,
  рекурсивный скраббинг, `X-Request-Id` связывает ответ и строку журнала.
- **6** — `panel/keyring.py` + `panel/secrets_store.py`: AES-256-GCM,
  AAD-привязка к identity строки, overlap-first ротация; мастер-ключ создаётся
  установщиком автоматически (ручного шага при апгрейде нет), приходит в
  контейнер как Docker secret; документация в `BACKUP_RESTORE.*`, `UPGRADING*`,
  `PANEL.*`.
- **7** — `panel/nodes/`: lifecycle узлов поверх `FleetStore`, миграция 4
  (`kind`, `disabled`). Публичные сигнатуры `FleetStore` не менялись,
  `test_fleet.py` и `test_agent_transport.py` прошли без правок.
- **8** — `panel/node_routes.py` и экран «Узлы» (`panel/static/js/nodes.js`),
  сырые typed-команды Telemt v1 убраны в дравер «Advanced: транспорт v1»;
  старый экран списка удалён целиком.

- **9** — зарезервированный локальный узел: миграция 5 (`node_id='local'`,
  `kind='local'`, `INSERT OR IGNORE`), `LOCAL_NODE_ID` + `NodeLifecycleService.local()`,
  local всегда первый в списке, у него нет ни enrollment-действий, ни отключения, ни
  отзыва сертификатов, а id `local` закрыт для регистрации. В `GET /api/nodes`
  и `/api/nodes/{id}` у local появилось поле `services`
  (`ok|unavailable|disabled` по Telemt/Naive/Mieru); карточка в UI показывает их
  вместо сертификатов. `node-list` уже печатал `kind` — правки CLI не понадобились.

- **10** — `panel/clients/`: миграция 6 (`clients`, `access_grants`), типизированные
  `MtproxyOptions`/`NaiveOptions`/`MieruOptions`, `GrantIntent`/`AccessGrant`,
  `effective_enabled`, `ClientStore` (все методы принимают `db` вызывающего) и
  `ClientService` с `on_change`. Grant — это пара (протокол, узел, endpoint,
  runtime-username), она уникальна; credential в модели нет, только ссылка
  `SecretRef`. `app.state.clients` подключён.

- **11** — read-only импорт: `panel/clients/importer.py`, `panel/client_routes.py`,
  экран «Клиенты» (`panel/static/js/clients.js`). Инвентаризация только читает
  менеджеров, повторный импорт идемпотентен и не создаёт пустых клиентов, одинаковое
  имя — подсказка, а не объединение. Узел с неудалёнными grants нельзя отключить.
  Появился `RequestContext.read_roles()` — ролевой гейт для GET без CSRF.

- **12a** — Naive manager стал идемпотентным: `create`/`rotate` принимают
  `password` и `operation_id`, состояние хранит карту `operations` (обрезка 7 дней),
  повтор возвращает тот же credential с `"replayed": true`, а тот же id для другого
  запроса — `409 operation_conflict`. `MemoryNaive` получил тот же replay и
  `faults["create"] = "lose_response"`.

- **12b** — Mieru manager стал идемпотентным: `create_user`/`rotate_user` принимают
  `password` и `operation_id`, журнал хранит `operations` **без секретов**, повтор с
  caller-паролем возвращает `{username, revision, replayed}`, а повтор
  manager-generated пароля — честный отказ `result_unrecoverable` (панель обязана
  ротировать). Попутно найден и исправлен настоящий дефект `Database.__init__`:
  `PRAGMA journal_mode=WAL` без повтора (см. раздел 0 плана).

- **12c** — Telemt: `TelemtIndeterminate` поднимается только когда запрос уже ушёл
  (`ConnectError`/`ConnectTimeout` — обычная ошибка, повтор безопасен), плюс
  `TelemtClient.current_access(username)` и `access_from_user(row)`: живая ссылка и
  есть credential. `MemoryTelemt` получил `faults` и перестал отдавать живые ссылки на
  внутренние строки.

- **12d** — `panel/protocols/`: единый `ProtocolAdapter` с честно названными
  различиями (`credential_origin`, `capture_supported`) и три адаптера. Плюс
  `ClientService.capture_credential`/`adopt_credential`, маршруты
  `POST /api/clients/grants/{id}/adopt` и `.../adopt-batch`, рабочая кнопка «Принять»
  в UI. MTProxy и Naive принимаются чтением (ссылка клиента продолжает работать),
  Mieru — только с явным согласием на ротацию.

- **13** — журналируемая сага: миграция 7 (`provisioning_operations`),
  `panel/clients/provisioning.py`. Каждый переход шага — своя транзакция, поэтому
  перезапуск продолжает, а не повторяет. Любой исход — ровно один из трёх
  (`succeeded` / `compensated` / `manual_intervention_required`), компенсация трогает
  только созданное этой операцией. Маршруты `POST /api/clients/{id}/grants`,
  `GET|POST /api/operations/{id}[/resume|/bundle]`, CLI `operations-resume`, диалог
  выдачи и одноразовый bundle в UI.

- **14** — флаг `PANEL_VNEXT_WRITER=legacy|domain` и `panel/clients/facade.py`.
  Фикстура `client` параметризована, поэтому **весь API-набор идёт в обоих режимах** —
  это и есть доказательство неотличимости. В `domain` панель владеет credential;
  неизвестный ей пользователь записывается как `imported` без пересоздания и без
  слияния. Элевированные Mieru-флаги остаются на прямом вызове намеренно.

- **15** — `panel/subscriptions/` (миграция 8): bearer-токен хранится хэшем, generation
  движется в транзакции изменения через единственный `on_change.append(bump_generation)` в `create_app`,
  ETag — от эффективного набора. Переменная — `PANEL_SUBSCRIPTION_URL` (не `PANEL_PUBLIC_URL`, решение 1).
- **16** — `panel/subscriptions/renderers/` (`manifest|singbox|clash|raw|html`) и `compatibility.py`
  (копия секции `clients` фикстуры Task 3, сверяется тестом). Разбор `mierus://` вынесен в
  `panel.protocols.mieru.parse_share_url`, роут Mieru им пользуется. YAML пишется руками, без PyYAML.
- **17** — `panel/subscription_routes.py`: `GET|HEAD /s/{token}` только на `PANEL_SUBSCRIPTION_HOST`,
  один 404 на все отказы, rate limit до поиска токена, `--no-access-log` в entrypoint, своя CSP.
  Установщик: `domains.subscription` (мастер, config, SAN в lineage `proxy-control`, SNI-маршрут на
  8443, второй `server` с `access_log off`, env). Попутно: хост/порт MTProxy теперь учатся из ссылки
  Telemt в `MtproxyOptions.host/port` (раньше bundle подставлял домен панели).
- **18** — диалог «Подписка» (`panel/static/js/subscriptions.js`, `#subscription-modal`), API
  `GET|POST /api/clients/{id}/subscription[/rotate|/revoke]`, `GET /api/subscriptions/compatibility`;
  URL показывается один раз через reveal с вариантами `singbox|clash|raw` и QR каждого.
- **19** — `panel/events.py` (`EventBus`): `subscription.generation.changed|fetched|revoked` в `audit_log`
  в той же транзакции + кольцо; `GET /api/events?after&limit` для всех ролей.

## Task 19A — релизный гейт v0.2 на `ams-test` (пройден 2026-09-11)

Все шаги с фактами — в плане. Коротко: full/compose/lab-container/lab-host зелёные;
апгрейд-drill на данных v0.1.0 пройден; живая установка `full`+`managed-new`+`eclipse` стоит на
стенде (`/root/install.toml` с `subscription = "eclipse.sky.dubr1kkk.uk"`, бэкап в
`/root/install.toml.bak-20260911`); `scripts/lab/subscription-acceptance.py` —
`SUBSCRIPTION_ACCEPTANCE_OK` с настоящими sing-box 1.14.0 и mihomo 1.19.30 (образы запинены по
дайджесту в плане). По пути починены три дефекта установщика (overlay профиля `full`, verify
маршрутов 3x-ui, гонка repair 3x-ui), `db-status` на базе v0.1.0 и три дефекта самого гейта
(`lab-host` из dev-чекаута, неиндексированные файлы в релизе, обрыв SSH на install).

**Что осталось владельцу:** (1) коммиты по слоям (см. ниже), (2) аннотированный тег
`v0.2.0-beta.1` с `lab-sha256: <digest>` из `dist/SHA256SUMS` последнего зелёного `lab-host` на
стенде (собрать из закоммиченного чистого дерева — `--allow-dirty` даёт другой digest, чем CI),
(3) Karing на устройстве: импорт URL `?format=singbox`, автообновление, трафик naive и mieru —
результат в `tests/fixtures/vnext-capabilities.json`.

## Правила, добытые в этой серии

- **Черновик плана — не истина.** Уже трижды он расходился с кодом: `MemoryMieru`
  хранит `users`, а не `config`; Naive-`/access` отдаёт payload раскрытия, а не
  `reveal_token`; добавление мастер-ключа в `_PRESERVED_CREDENTIALS` ломало
  апгрейд с v0.1.0. Каждый раз правильным было поправить ожидание под факт и
  записать факт в раздел 0 плана, а не подгонять код.
- **Проверка канарейки должна читать и WAL.** `panel.sqlite3` без `-wal` —
  проверка вхолостую.
- **Утверждения должны быть точными.** `assert "p" not in str(...)` ловил букву
  в уцелевшем ключе `keep`; `schema.count("secret")` ловил колонку `secret_id`.
- **Мобильный тест-жгут понимает только форму карточки пользователя.** Новая
  карточка ломает его молча — тест зависает на «assertions did not finish».
  Новой раскладке нужна своя проверка стекинга.
- **Новая колонка ломает стража схемы так же, как новая строка — счётчики.**
  Миграция 6 добавила ссылку `secret_version`, и allowlist в двух тестах пришлось
  расширить ровно на неё. Расширять — можно, ослаблять (заменить множество на
  `"password" not in schema`) — нельзя.
- **Тест, считающий строки, ломается на честном изменении.** Аудит домен-писателя
  пишет строку саги рядом со строкой endpoint'а — обе с тем же `request_id`. Инвариант
  здесь корреляция, а не количество.
- **Что создано через API панели, импортировать уже нечего.** Тесты импорта обязаны
  сеять учётки прямо в менеджеры: импорт существует для того, что появилось до панели.
- **Общий тест по трём адаптерам ловит то, что поодиночке незаметно.** Именно он
  вскрыл, что у MTProxy «credential» неоднозначен: Telemt отдаёт `secret`, а в ссылке
  лежит `ee<secret>`, и в escrow обязан попасть тот, который воспроизводит ссылку.
- **Фейк, отдающий живую ссылку на своё состояние, врёт.** `MemoryTelemt.create_user`
  возвращал внутренний dict, и позднейшая ротация задним числом переписывала уже
  выданный ответ. Реальный HTTP-ответ — снимок; фейк обязан вести себя так же.
- **Одно падение в полном прогоне — не повод писать «флейк».** Упавший
  `test_two_processes_initialising_concurrently_are_safe` отдельно проходил 8/8, но
  стресс из 300 попыток дал 5% падений и вскрыл настоящий дефект WAL. Прежде чем
  списать тест на нестабильность, воспроизведи его под нагрузкой и покажи причину.
- **`remote-gate.sh quick` теряет кавычки в аргументах pytest.** Скрипт передаёт `$*`
  в удалённую оболочку, поэтому `-k "a or b"` превращается в путь `or`. Передавайте
  файл целиком или однословный `-k`.
- **Проверяй, фикстура ли это.** В `tests/test_naive_manager.py` `manager` — обычная
  функция-хелпер, а не pytest-фикстура; тесты сами делают `Hooks()` и `bootstrap()`,
  который к тому же импортирует двух пользователей из образцового Caddyfile.
- **`context.roles()` нельзя вешать на GET.** Он зависит от `mutation`, то есть требует
  `X-CSRF-Token`, которого у чтения нет, и отвечает `403` даже владельцу. Для
  ролевого чтения есть `RequestContext.read_roles()`.
- **Канарейка в мобильном жгуте должна быть вне потока.** `display:block` и
  отрицательный `margin-top` grid просто пересчитывает, а слишком широкий элемент
  роняет тест раньше — на проверке ширины вьюпорта. Перекрытие ловится только
  `position:relative; top:-80px`.
- **Проверяй новый инвариант канарейкой.** В Task 10 обе ключевые проверки —
  соответствие `protocol` ↔ `options` и предварительная проверка дубликата grant —
  были подтверждены временной поломкой кода: без них тесты падают. Без канарейки
  нельзя утверждать, что тест что-то проверяет.
- **Новая строка в базе ломает чужие «сколько всего» утверждения.** Миграция 5
  уронила четыре теста, считавших `count(*) FROM fleet_nodes` и `items == []` как
  «сколько создал этот тест». Правильный ответ — сузить утверждение до своей строки
  (`WHERE node_id='n1'`, `== ["local"]`), а не ослабить до `>= 1`.
- Не используй `pkill -f <строка>` по SSH: шаблон совпадает с командной строкой
  самой удалённой оболочки и обрывает сессию.
- **Не откатывай канарейку через `git checkout <файл>`** — вместе с ней уходит вся
  незакоммиченная работа в этом файле (так потерялись и были заново написаны правила
  `style.css`). Канарейка — это обратный `ctx_patch`, а не git.
- **Новый файл попадает в релиз только через индекс.** `release/build.py` пакует
  `git ls-files`; непроиндексированный `panel/events.py` дал `ModuleNotFoundError` только на
  `lab-host`. Новые файлы — `git add -N` сразу.
- **Длинные шаги на стенде — только детаченно.** `install`/`repair` роняют SSH (nginx/сеть
  пересобираются): `setsid nohup … > /root/x.log` и опрос лога; скрипты класть через rsync, а не
  heredoc внутри `ssh '…'` (зависает). `guest-runner.sh` в режиме библиотеки включает `set -e` —
  source его в подоболочке.
- **Переустановка `managed-new` 3x-ui без `--purge-data` невозможна по замыслу**: адаптер
  отказывается от любой существующей `/etc/x-ui/x-ui.db`, включая сохранённую своим же `uninstall`.
  На стенде — перенести базу в сторону; в проде — решение оператора.

## Состояние репозитория (2026-09-11)

Ветка **`feature/vnext-v0.2-local-control-plane`**. Коммиты ниже (Tasks 0–14) запушены в
`origin`; **Tasks 15–19 и Task 19A (фиксы установщика, `remote-gate.sh lab-host`, скрипты
`scripts/lab/host-teardown.sh` и `scripts/lab/subscription-acceptance.py`, релизный поезд,
`VERSION` = `0.2.0-beta.1`, `CHANGELOG.md`, `docs/releases/v0.2.0-beta.1.md`) лежат в рабочем
дереве незакоммиченными** (новые файлы — `git add -N`, чтобы попадать в релиз) — владелец
коммитит только по явной просьбе. Сообщения для них прописаны в плане под каждой задачей
(`feat: добавить lifecycle клиентских подписок` уже занят коммитом `1385a45` — для
Task 15 бери `feat: подключить подписки к приложению`). Гейтом проверена вершина
рабочего дерева: см. Task 19A в плане (финальный прогон — в Step 7).

Задачи 15–19 трогали одни и те же файлы (`panel/app.py`, `panel/subscription_routes.py`,
`test_subscription_http.py`), так что резать их на пять коммитов по номерам не стоит —
сгруппируй по слоям: (1) подписки + рендереры + `/s/` + события (`panel/`), (2) установщик +
лаборатория + релизный поезд + документация (`installer/`, `scripts/`, `.github/`, `docs/`,
`VERSION`, `CHANGELOG.md`), (3) UI (`panel/static/`, `test_mobile_layout.py`,
`test_subscription_ui_contract.py`). После коммитов — `remote-gate.sh lab-host` из чистого дерева
ради digest для аннотации тега.

Ранее запушенные коммиты, `main` не тронут:

```
f872e1c feat: добавить экраны клиентов и узлов в UI панели
8543f5f refactor: направить старые API клиентов через единый сервис под флагом
1385a45 feat: добавить lifecycle клиентских подписок
b319682 feat: добавить клиентов, безопасный импорт и журналируемую выдачу доступов
0453483 refactor: унифицировать контракт protocol adapters
aa69aae feat: сделать операции менеджеров восстановимыми после потери ответа
3b2607d refactor: разделить lifecycle узлов и transport, добавить локальный узел
26eb045 feat: добавить версионируемое хранилище секретов и мастер-ключ
640a264 refactor: ввести единый слой БД, миграции и транзакционный аудит
9f12a5c docs: зафиксировать архитектуру и матрицу возможностей vNext
afe9bae chore: добавить стенд ams-test, план и spec vNext v0.2
```

Коммиты сгруппированы по слоям, а не по номерам задач: задачи разрабатывались одним
потоком, и один файл трогали несколько задач подряд, поэтому «один коммит на задачу»
дал бы историю, в которой промежуточные состояния никогда не существовали. **Гейтом
проверена вершина ветки**, а не каждый коммит по отдельности: на `f872e1c` получен
`REMOTE_GATE_FULL_OK`, `1494 passed, 2 skipped`.

Trailer'ов (`Co-Authored-By`, `Claude-Session`) в сообщениях нет и быть не должно.

## Что делать первым делом

На стенде сейчас стоит живая установка итогового архива `de22f79d…` (свежий хост после
`lab-host`, `status: active`, домены `aurora`/`eclipse`, клиент «acceptance» в базе панели;
сертификаты LE выпущены 2026-09-11 дважды на каждый набор имён — лимит 5/неделя, считай
перед следующим teardown). Если нужен `lab-host` или новая живая установка — сначала
`LAB_RESET=1 scripts/lab/host-teardown.sh` (разрушительно; `install.toml` с `subscription` уже
лежит в `/root/`). Перед разрушительными шагами убедись, что стенд свободен: `ssh ams-test docker ps`.
Следующая инженерная работа — отдельный план v0.3 (раздел 4 плана), только после тега `v0.2.0`.

После задач, меняющих структуру кода, выполняй `graphify update .`.
