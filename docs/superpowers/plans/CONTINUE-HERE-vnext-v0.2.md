# Промпт для продолжения работы в новом контексте

Скопируйте всё, что ниже разделителя, в новую сессию Claude Code, запущенную
в каталоге проекта.

---

Проект: `~/Syncthing/development/proxy-control`. Отвечай по-русски.

Продолжаем vNext v0.2 — локальный control plane. Задачи 0–14 плана уже сделаны и
проверены; твоя задача — вести план дальше с **Task 15**, не ломая того, что уже
зелёное.

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

## Следующая задача: Task 15 — lifecycle токена подписки и generation

Читай раздел «Task 15» в плане: `panel/subscriptions/`, миграция 8, хук
`ClientService.on_change` уже готов и вызывается внутри транзакции.

После 12x идут Tasks 13–19A (saga, legacy endpoints, подписка). Task 19A — релизный
гейт: он целиком на `ams-test`, включая живую установку и проверку подписки на
домене `eclipse.sky.dubr1kkk.uk`.

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

## Состояние репозитория (2026-09-10, конец сессии)

Всё сделанное лежит в ветке **`feature/vnext-v0.2-local-control-plane`**, запушенной
в `origin`. Одиннадцать коммитов, `main` не тронут:

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

## Что делать первым делом завтра

**Дописать Task 15.** Сервис подписок (`panel/subscriptions/`) и миграция 8 готовы и
покрыты тестами (`8 passed`), но он **ещё не подключён к приложению**. Осталось:

1. `panel/settings.py` — `public_url: str = os.getenv("PANEL_PUBLIC_URL", "")`.
2. `panel/app.py` — `app.state.subscriptions = SubscriptionService(...)` и
   `app.state.clients.on_change.append(app.state.subscriptions.bump_generation)`.
3. Вызвать `bump_generation` там, где меняется grant: в `ProvisioningService` после
   `succeeded`, в `ClientService.capture_credential`/`adopt_credential` и в
   `DomainFacade.set_enabled/forget/rotate` — **в той же транзакции**, где меняется
   строка. Ради этого хук и сделан принимающим `db`.
4. `compose.yaml` — `PANEL_PUBLIC_URL: ${PANEL_PUBLIC_URL:-}`;
   `installer/adapters/core.py` — писать `PANEL_PUBLIC_URL=https://<panel_domain>`
   в `.env`.

Проверка: `scripts/dev/remote-gate.sh quick panel/tests/test_subscription_lifecycle.py
panel/tests/test_clients_domain.py panel/tests/test_provisioning_saga.py`, затем
`full`.

## Прежнее состояние репозитория

Задачи 0–14 **не закоммичены** — владелец коммитит только по явной просьбе.
В рабочем дереве ~30 изменённых файлов и новые каталоги `panel/nodes/`,
`docs/adr/`. Сообщения для семнадцати коммитов уже прописаны в плане под каждой
задачей. Спроси владельца, коммитить ли, прежде чем продолжать — иначе
следующая задача смешается с предыдущими в одном диффе.

После задач, меняющих структуру кода, выполняй `graphify update .`.
