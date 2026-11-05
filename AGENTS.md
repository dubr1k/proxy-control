[English](#for-ai-agents) · **Русский**

# Рабочий протокол для AI-агентов

Этот файл — обязательный протокол для AI-агентов, которые **разрабатывают** Proxy Control:
меняют код и документацию, проверяют их на стенде и выпускают. Людям он тоже полезен: это те
же правила безопасной работы, только записанные как алгоритм. В конце — эксплуатационный
протокол для работы с уже установленными узлами.

**Установить** Proxy Control агенту поможет не этот файл, а раздел README
[«Установка ИИ-агентом»](README.md#установка-ии-агентом). Обычному пользователю этот файл не
нужен — начните с [README](README.md).

## Codex и действующая архитектура

Основной агент разработки — **Codex**. Этот `AGENTS.md` — единый отслеживаемый Git
протокол проекта; правила владельца не должны зависеть от локального `CLAUDE.md`.
Локальный `CLAUDE.md` оставляется только указателем на этот файл. Старые рабочие копии
в `.claude/worktrees/` не являются текущими исходниками: не обходите их при поиске,
не меняйте и не удаляйте без задания. Проверяйте `pwd` и состояние выбранной рабочей копии.

Поставляемые компоненты написаны на **Rust**:

| Граница | Исходники |
| --- | --- |
| Панель, HTTP API, административный CLI | workspace `panel/`, сервер `panel/crates/web/`, предметные модули `panel/crates/` |
| Установщик, транзакции, адаптеры хоста | `installer/src/`, `installer/src/adapters/` |
| Конфигурация, план, мастер, переводы | `installer_core/src/config.rs`, `planner.rs`, `wizard.rs`, `i18n.rs` |
| Общие библиотеки и операции хоста | `pc_common/`, `pc_host/` |
| Обновления и метрики хоста | `version_agent/` |
| Менеджеры протоколов и роутера | `naive_manager/`, `mieru_manager/`, `awg_manager/`, `trusttunnel_manager/`, `xray_router_manager/` |
| MCP | `mcp_server/` |

Используйте закреплённый в CI Rust **1.99.0**, `Cargo.lock` и `--locked`.
Не возвращайте Python-реализации служб или установщика. Python 3.12 и `.venv` нужны
для внешних тестов, сборки выпуска и служебных сценариев на стенде; JavaScript остаётся
в интерфейсе, Go — в MTProxy bridge и сторонних компонентах. Это не зависимости Python
на установленном узле. Примеры API с `python3` ниже выполняются со стороны оператора,
где есть Python, и не требуют его установки на боевой сервер.

## Коммиты, теги и PR

- Сообщения коммитов — по сути изменения, на русском, как в `git log`.
- Не добавляйте подписи инструмента: `Co-Authored-By`, `Claude-Session`,
  `Generated with Claude Code`, `Generated with Codex` и аналогичные строки
  в коммиты, аменды, аннотации тегов или описания PR.
- Сообщение передавайте через `git commit -F -`, завершайте содержательным абзацем.
- Сохраняйте чужие изменения. Коммит, push, слияние и публикацию выполняйте в рамках
  поручения владельца; обновление документации само по себе не означает выпуск.

## Главное правило

Агент обязан выполнить алгоритм и приложить фактический вывод команд. Нельзя
ограничиваться описанием плана, изменением кода или фразой «выглядит рабочим».

Нельзя заявлять «установлено», «протестировано», «здорово», «закоммичено» или
«обновлено» без свежего подтверждения соответствующей командой. При любой
неопределённости остановитесь на безопасной границе и назовите недостающую
проверку.

## Перед изменением

1. Прочитайте [README](README.md), [CONTRIBUTING.md](CONTRIBUTING.md),
   [SECURITY.md](SECURITY.md), [политику совместимости](docs/COMPATIBILITY.md),
   затронутые документы и `.github/workflows/test.yml`.
2. Выполните и зафиксируйте вывод без секретов:

   ```bash
   pwd
   git status --short --branch
   git log -3 --oneline
   git diff --check
   ```

   Команды хоста выполняйте по SSH на `ams-test`, если проверяемая граница требует
   Docker, systemd или сети; для текстовой правки они не нужны:

   ```bash
   docker version
   docker compose version
   systemctl is-active docker nginx 2>/dev/null || true
   ss -lntup
   ```

3. Определите фактическую границу изменения и все связанные интерфейсы: README,
   Compose, Dockerfile, systemd, Rust HTTP API, UI, JavaScript, тесты,
   backup/restore и Fleet. Не меняйте чужие маршруты, контейнеры, тома, секреты
   и production-конфигурацию без явного задания.
4. При изменении кода сначала напишите узкий регрессионный тест, убедитесь, что
   он падает по ожидаемой причине, затем внесите минимальную реализацию и
   повторите проверку.

## Правила, которые уже спасали от ложных отчётов

- Ограничительный `umask 077` действует только внутри создания
  secrets/backups и сразу восстанавливается. Checkout/build context должен быть
  читаем runtime UID, APT keyring/source list — `_apt`, а public ACME roots —
  Nginx worker.
- Success marker печатается только в успешной ветке `if`. Конструкция
  `fallible-command; echo OK` запрещена: она уже приводила к ложным отчётам об
  установленном пакете, healthy manager и прошедшем repair.
- Secret-bearing browser dialogs проверяются безопасными агрегатами: булевыми
  признаками, подписями, длинами, совпадающими метаданными. Accessibility
  snapshot или DOM dump с паролем, ссылкой, subscription ID или скрытым путём
  запрещён; попавшее в tool output значение немедленно ротируется.

## Скрипт автоустановки обновляется вместе с каждым изменением

Строгое правило владельца (2026-10-01). «Скрипт автоустановки» — это всё, через что
новый сервер получает Proxy Control: `scripts/install-release.sh` (в каждом выпуске он
публикуется как `install-release.sh` с записанными версией и SHA-256 архива), установщик
`installer/` (движок и адаптеры) и `installer_core/` (мастер `wizard.rs`,
переводы `i18n.rs`, конфигурация `config.rs`),
`install.sh`, `install-bootstrap`, `release/external-artifacts.json` и примеры
`examples/installer/`. Изменение, которое его касается, без его обновления — незавершённая
работа, а не «потом догоним».

1. **Тот же коммит.** Новый или изменённый компонент, сервис, порт, домен, профиль, ключ
   конфигурации, пакет хоста, путь, имя службы, закреплённая версия внешнего артефакта или
   требование к хосту обновляют в том же коммите: адаптер; `installer_core/src/config.rs` с его проверками,
   включая `reserved_tcp_ports`; вопросы и подсказки мастера на обоих языках; текст
   `--requirements` в `scripts/install-release.sh`; примеры; README, INSTALL и
   INSTALLER_REFERENCE.
2. **Свежая установка = обновлённый узел.** Что приезжает на работающий узел обновлением
   через агента — компонент, настройка, значение по умолчанию, — то же самое ставит свежая
   установка этого выпуска. Иначе новый сервер и обновлённый расходятся.
3. **Закреплённые версии в текстах совпадают с `release/external-artifacts.json`.** Это
   `--requirements` и вопрос мастера про Xray-router; при смене пина — все тексты сразу. Тест
   `tests/test_release_build.py` это проверяет.
4. **Каждый выпуск публикует `install-release.sh` и `install-release.sh.sha256`.**
   - Их нельзя убирать из `release.yml`.
   - Формат `SHA256SUMS` не менять: три файла, их строго сверяют копии скрипта из прежних
     выпусков.
   - Проверка сборки выпуска: две сборки дают одинаковые архив и скрипт
     (`INSTALLER_IDENTICAL`), штампы скрипта = версия и digest архива.
5. **Гейт.** Полный гейт и tier `lab-host` в выпуск не входят (решение владельца,
   2026-10-12): перед выпуском — `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`
   и `cargo test --locked` затронутых Rust-крейтов на `ams-test`; `ruff` и выбранные
   внешние тесты — если затронуты их границы. Полный CI при этом не отключается.
6. **Живая проверка после публикации.**
   - На `ams-test` обычным пользователем (не root): `curl -fsSLO` для
     `releases/latest/download/install-release.sh` и `.sha256`, затем
     `sha256sum --check install-release.sh.sha256` и `bash install-release.sh`.
   - Дойти до мастера и выйти `quit`.
   - В отчёт приложить строки «the archive digest matches the pinned one» и «No changes were
     made».
   - Без этого выпуск не считается опубликованным.
7. **Мастер честен.**
   - Подсказка не обещает того, чего не принимает валидатор.
   - Каждое поле конфигурации, нужное обычной установке, мастер спрашивает или задаёт
     осознанно.
   - Новый вопрос — с переводом и тестом в `installer_core/src/wizard_tests.rs`.
   - Введённые пароли доходят до адаптеров на обоих путях: «apply» мастера и `install --config`.
8. **Отчёт о выпуске** называет, что изменилось в установщике и в скрипте, или прямо пишет
   «установщик не менялся», с доказательством (тесты, дифф).

## Документация

- **README.md и README.en.md** — для пользователей. В каждом два раздела установки:
  «Установка человеком» (мастер) и «Установка ИИ-агентом» — инструкция по установке для
  агентов, которым владелец дал доступ к серверу (TOML из `examples/installer/` → `plan --json`
  → digest подтверждает владелец → `install --accept-plan`). Этот файл (AGENTS.md) — протокол
  **разработки**, а не инструкция по установке. Изменение установщика, его флагов, путей,
  вопросов мастера или примеров обновляет оба раздела на двух языках в том же коммите; структуру
  сторожит нативный тест `installer/tests/documented_cli.rs`.
- **Мониторинг** — `docs/guides/MONITORING.ru.md` и `docs/guides/MONITORING.en.md`.
  Изменение рядов метрик, портов, порогов, сроков хранения, SSE или маршрутов обновляет
  оба документа; константы сверяются с кодом и затронутыми тестами. Таблица nftables
  `inet proxy_control_metrics` только считает: не добавляйте в неё сетевые запреты.
- Proxy Control — отдельная панель (MTProxy, NaiveProxy, Mieru, AmneziaWG, TrustTunnel), которую можно поставить рядом
  с 3x-ui. Не описывайте её как «панель для 3x-ui».
- **Истории до 1.0.0 нет.** Документы описывают текущее поведение: без «с v0.x», «since v0.x»,
  ссылок на бета-выпуски и их заметки. Журнал изменений начинается с 1.0.0; новые записи —
  в `CHANGELOG.md` и `CHANGELOG.ru.md`.
- **`docs/releases/vX.Y.Z.md`** — заметки о выпуске для пользователей: что изменилось и как
  обновиться. Таблицы гейта, имена стендов, счётчики живых проверок туда не пишутся.
- **Рабочие материалы агентов не коммитятся**: планы и спецификации, передачи
  (`CONTINUE-HERE`), протоколы приёмки на стендах держите в `.superpowers/` (игнорируется
  Git) или вне дерева. Ссылки из репозитория на них запрещены.
- После переноса или удаления документа — `python3 scripts/check-doc-links.py`.

## Стенд и выбор проверок

**Все тесты, сборки и гейты запускаются на `ams-test` по SSH**, не на рабочем Mac
и не на боевых узлах. `AMS_Z` не является вторым стендом: живые проверки на нём
допустимы только по отдельному явному поручению владельца. Локально допустимы чтение,
редактирование, `git diff --check` и статическая проверка ссылок документации.

Чтобы проверки не занимали лишнее время, сначала определите затронутые границы:

| Изменение | Проверки на `ams-test` |
| --- | --- |
| Только документация, без изменения поведения | Проверка ссылок и `git diff --check`; без Cargo, pytest и образов |
| Один Rust-крейт | `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, узкий регрессионный тест, затем тесты этого крейта |
| Общая библиотека или контракт | То же для изменённого крейта и зависимых компонентов, выбранные внешние тесты контракта |
| Мастер, конфигурация, установка | `installer_core`, `installer`, `installer/tests/documented_cli.rs`; реальные сценарии только затронутого пути |
| HTTP API, UI, менеджер | Затронутые Rust-пакеты и внешние файлы тестов; для UI — браузерная проверка затронутых экранов на телефоне и компьютере |
| Compose, Dockerfile, зависимости образа | Затронутые Compose-модели и образы, проверки соответствующего компонента |
| Сквозное изменение, неясная граница или прямое поручение | Полный набор из [VALIDATION](docs/VALIDATION.md) и CI |

Для Rust запускайте команды с `--manifest-path <crate>/Cargo.toml`; в workspace
панели выбирайте пакет через `-p <package>`. Узкий тест для цикла «падает → проходит»
можно выбирать фильтром Cargo; итоговая проверка компонента включает его полный набор.
Python — внешний контроллер Rust-бинарников, не альтернативный сервер.

На стенде один раз подготовьте `.venv` из `panel/requirements-dev.txt`; повторяйте установку
зависимостей при изменении этого файла. Сохраняйте Cargo target и Docker cache между
прогонами; не делайте `cargo clean` и не пересобирайте все образы для небольшой правки.
Не меняйте `CARGO_TARGET_DIR` между связанными командами, используйте фактические пути
полученных бинарников. Кэш сборки допустим, результат старого теста не заменяет новый.
После правки повторяйте упавшую и связанные проверки; успешно выполненное не повторяйте
без новых изменений, влияющих на него. Зависимые проверки выполняются последовательно.

Для внешних тестов по файлам предусмотрен `scripts/dev/remote-gate.sh quick <пути тестов>`:
он синхронизирует копию на `ams-test`, готовит нативные бинарники и запускает `ruff` и pytest.
Он готовит панель, установщик и version-agent, поэтому для чисто Rust-правки используйте
прямые Cargo-команды на стенде. Внешний гейт не допускает пропусков и исключённых тестов:
передавайте файлы, не `-k`/`-m`. Готовые бинарники через `PANEL_RUST_BIN`, `PC_INSTALLER_BIN`,
`PC_VERSION_AGENT_BIN` используйте только после сборки из текущей проверяемой копии.

Длинные прогоны запускайте на стенде отсоединённо с логом и отдельной фиксацией кода
завершения, затем опрашивайте результат; разрыв SSH не должен останавливать тесты.
Тесты, требующие root, запускайте с `sudo` на стенде, не подменяя боевые секреты.
Не запускайте несколько гейтов, меняющих одну рабочую копию или один стенд, одновременно.

## Полный набор проверок

Команды полного набора, сборки нативных бинарников, Python-окружения и образов —
в [VALIDATION](docs/VALIDATION.md); обязательные задания CI — в `.github/workflows/test.yml`.
Полный набор охватывает workspace панели, `pc_common`, `pc_host`, `installer_core`,
`installer`, `version_agent`, все менеджеры, MCP и `deploy/mieru-client`;
`cargo fmt`, `clippy`, тесты, аудит закреплённых зависимостей, внешние тесты,
ссылки, JavaScript, ShellCheck, systemd и Compose. Не подменяйте его одним `pytest`.
Для внешних тестов нужны Rust-панель с `test-hooks`, нативные установщик и version-agent,
`PANEL_IMPL=rust` и корректный `PANEL_RUST_BIN`.

Игнорируемый обычным `cargo test` интеграционный smoke настоящих бинарников
установщика и version-agent запускается отдельно по CI: root, приватный mount namespace,
временные `tmpfs` на `/etc`, `/var/lib`, `/run`, ровно один успешный тест.
Обычный Cargo-прогон не доказывает прохождение этого сценария.

В отчёте называйте выбранную границу, команды, результат и не запущенные проверки.
Успех узкого набора не означает прохождение полного. Недоступная команда, неверный
интерпретатор, пропуск или ошибка — незавершённая проверка, а не успех.

## Проверка всех Compose-моделей и образов

В изолированной копии с синтетическими значениями, а не в production. Сначала
задайте обязательные переменные — без них `compose config` падает по `:?`, как
и в CI:

```bash
export MTPROXY_DOMAIN=proxy.example.com MTPROXY_BACKEND_PORT=18445
export MTPROXY_COVER_ROOT=/tmp/cover MTPROXY_LETSENCRYPT_ROOT=/tmp/letsencrypt
export MIERU_MANAGER_TOKEN_FILE="$PWD/secrets/mieru-manager-token"
mkdir -p /tmp/cover /tmp/letsencrypt

docker compose -f compose.yaml config -q
NAIVE_PUBLIC_HOST=naive.example.com \
  docker compose -f compose.yaml -f compose.naive.yaml config -q
MIERU_PUBLIC_HOST=mieru.example.com MIERU_MITA_GID=321 \
MIERU_MITA_BIN=/bin/true \
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 \
  docker compose -f compose.yaml -f compose.mieru.yaml config -q
NAIVE_PUBLIC_HOST=naive.example.com MIERU_PUBLIC_HOST=mieru.example.com \
MIERU_MITA_GID=321 MIERU_MITA_BIN=/bin/true \
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 \
  docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml config -q
```

Fleet v1 (mTLS-контейнеры `fleet-agent`/`fleet-ingress`) снят с поставки.
Связанные панели Fleet v2 используют HTTPS API самой панели и не добавляют Compose-слой.

Перед этими командами создайте в изолированной копии только синтетические
`secrets/users.conf`, `secrets/telemt-api-token`, `secrets/naive-manager-token`,
`secrets/mieru-manager-token` и `.env` по примеру CI. Не подключайте настоящие
`.env`, Docker secrets, сертификаты или тома.

Затем соберите все затронутые образы. Панель запускает entrypoint от root только для
подготовки секретов и сбрасывает права до `panel` перед запуском бинарника;
`docker run --entrypoint id` обходит эту проверку. В одноразовом стенде проверьте UID
запущенного процесса панели отдельно.

```bash
docker build -f panel/Dockerfile -t proxy-control-panel:test .
docker build -f mieru_manager/Dockerfile -t proxy-control-mieru-manager:test .
```

Для Naive дополнительно соберите зафиксированный Caddy и проверьте не только
номер версии, но и обязательный модуль:

```bash
mkdir -p /tmp/proxy-control-caddy
timeout 10m docker buildx build \
  --file docker/Dockerfile.caddy-naive \
  --output type=local,dest=/tmp/proxy-control-caddy .
env CADDY_BIN=/tmp/proxy-control-caddy/caddy \
  scripts/check-naive-caddy-build.sh
if env CADDY_BIN=/bin/true scripts/check-naive-caddy-build.sh; then
  echo 'negative Caddy build check unexpectedly passed' >&2
  exit 1
fi
```

Вызов проверки с `/bin/true` обязан завершиться ошибкой; оборачивающий его `if`
завершается успешно только при ожидаемом отказе. Если проверка принимает `/bin/true`,
сборка небезопасна и агент должен остановиться.

## Изолированная установка и реальные проверки

Если меняется поведение установщика, Compose, Dockerfile, Nginx, systemd, резервного
копирования или восстановления, проверьте затронутые сценарии релизного стенда на
`ams-test` без боевых доступов. Текстовая правка не требует лаборатории; полный цикл
нужен при сквозном изменении или по поручению владельца.

Быстрее всего — одноразовый systemd-контейнер, он работает везде, где есть Docker:

```bash
python3 release/build.py --source . --output dist --version "$(cat VERSION)"
make lab-container \
  RELEASE_ARCHIVE=dist/proxy-control-v$(cat VERSION).tar.gz \
  RELEASE_SHA256=$(awk '/proxy-control-v.*\.tar\.gz$/ {print $1}' dist/SHA256SUMS)
```

Архив несёт готовые хостовые бинари (крейты из `release/host-binaries.list`): без флагов
`release/build.py` сам собирает их в закреплённом образе `release/Dockerfile.host-binaries`
(Docker buildx, статический musl, без кэша слоёв). `--build-binaries DIR` только собирает их и
печатает дайджест каждого, `--binaries-from DIR` вкладывает уже собранные после сверки
дайджестов, `--no-binaries` — для пробных сборок без Docker (такой архив хост не установит).

Полный цикл — установка, повторная установка, `repair`, восстановление после
перезагрузки, прерванная фаза, отчёт, удаление и сосуществование на общем 443 —
прогоняется на одноразовом сервере:

```bash
LAB_RESET=1 bash scripts/lab/guest-runner.sh host "$RELEASE_SHA256"
```

Эта команда переустанавливает сервер целиком. Запускайте её только на
одноразовой машине и никогда — на рабочей.

QEMU — только по отдельному поручению владельца: `make lab-prepare`, `make lab-full`,
`make lab-clean` на `ams-test`. В режиме TCG прогон может занять больше часа;
по умолчанию выбирайте затронутые сценарии на стенде. Начатый полный прогон нельзя
объявлять прошедшим по частичному результату. Подробности — в
[описании лаборатории](tests/lab/README.md).

В запущенном изолированном стенде проверьте:

- `docker compose ps` и фактический статус `healthy` каждого контейнера;
- `/healthz` панели с правильным `Host`;
- `nginx -t`, локальные слушатели и все соседние SNI;
- MTProxy: Fake-TLS → Obfuscated2 → `req_pq_multi` → `resPQ` → реальный клиент;
- NaiveProxy: cover HTTPS → authenticated `CONNECT` → payload → закрытие
  туннеля → учёт;
- Mieru: точный статус `RUNNING`, TCP/UDP-клиент, manager health и Unix-сокет;
- Fleet: связанная панель v2 должна принять поколение через HTTPS с ключом
  `node-sync`; установленный Fleet v1 требует отдельной миграции, а не проверки
  старого mTLS-входа в новой поставке;
- резервную копию, `PRAGMA integrity_check`, режимы файлов и отсутствие
  секретов в логах.

На живом сервере AI-агент не должен выполнять полный стенд, пересоздавать тома,
менять firewall, перевыпускать сертификаты или удалять orphan-контейнеры без
отдельного явного разрешения. Для production сначала сделайте backup и read-only
аудит, затем меняйте только одну границу и проверяйте откат.

## Правила отчёта

Агент обязан указать:

- какие файлы и границы изменены;
- какие команды реально выполнены и их результаты;
- какие проверки прошли, не прошли или не запускались;
- какие контейнеры и службы проверены и в каком состоянии;
- какие production-действия не выполнялись из-за риска;
- точный commit после проверки, если пользователь запросил commit.

---

# Эксплуатационный протокол для ИИ-агентов: развёртывание, узлы, доступы, маршрутизация, цепи и полосы

Часть выше — про **разработку** Proxy Control. Эта часть — про **эксплуатацию**: как агент
разворачивает узел, готовит его к центру, привязывает панели, выдаёт доступы клиентам и
настраивает маршрутизацию — неинтерактивно, с доказательством каждого шага и без единого
секрета в выводе. Человеческое описание тех же операций с примерами —
[docs/INSTALLER_REFERENCE.ru.md](docs/INSTALLER_REFERENCE.ru.md) (мастер установки и поля TOML, примеры — в
`examples/installer/`), [FLEET.ru.md](docs/guides/FLEET.ru.md) (привязка панелей и узлов, ключи node-sync, импорт),
[docs/ROUTING.ru.md](docs/ROUTING.ru.md) (политики маршрутизации, коды отказов, цепи и полосы),
[docs/XRAY_ROUTER.ru.md](docs/XRAY_ROUTER.ru.md) (подключение и отключение Xray-router),
[docs/UPGRADING.ru.md](docs/UPGRADING.ru.md) (version-agent и обновления),
[docs/BACKUP_RESTORE.ru.md](docs/BACKUP_RESTORE.ru.md) (резервные копии) и [docs/MCP.ru.md](docs/MCP.ru.md) (MCP);
агент обязан прочитать документ своей темы перед первым выполнением любого алгоритма ниже.

## 0. Режим работы и запреты

1. **Три класса хостов.** *Лабораторный* (одноразовый, можно переустанавливать целиком —
   `LAB_RESET=1`), *живой тестовый* (боевой узел, на котором владелец явно разрешил проверки),
   *боевой* (только чтение, любая мутация — по отдельному явному разрешению на конкретное
   действие). Если класс хоста не назван — считать боевым.
2. **Никогда без явного разрешения** на боевом хосте: `install`/`uninstall`/`repair`,
   пересоздание томов и контейнеров, firewall, сертификаты, `docker compose down`,
   `--remove-orphans`, `prune -a`, ротация ключей ingress, `LAB_RESET`, `pkill -f`.
3. **Секреты никогда не попадают в вывод, отчёт, лог, скриншот, commit**: пароли, `pc_…`
   ключи, ссылки `tg://`/`https://…/s/<token>`/`mierus://`, QR-payload'ы, `handoff.json`,
   `secrets/*`, `Set-Cookie`, отпечатки сертификатов в связке с URL боевых панелей. Значение,
   попавшее в вывод инструмента, считается скомпрометированным и ротируется.
4. **Маркер успеха печатается только из успешной ветки** реальной команды: `cmd && echo OK`,
   никогда `cmd; echo OK`. Утверждение «healthy/установлено/применено/привязано» — только
   после команды из соответствующего раздела «Проверка» ниже, выполненной *после* действия.
5. **Одна граница за раз**: одна установка, один узел, одна политика, один компонент; после
   каждой — проверка и запись результата; параллельные мутации на одном хосте запрещены.
6. **Перед любой мутацией на живом хосте** — точка отката: образ панели тегируется
   (`docker tag <image> <name>:rollback-<UTC>`), копия базы панели (online backup) и
   `secrets/`, копия `.env*` — по [BACKUP_RESTORE](docs/BACKUP_RESTORE.ru.md).
7. **Длинные прогоны** (гейты, лаборатория, приёмка) запускаются на хосте отсоединённо
   (`setsid nohup … > /root/<лог> 2>&1 < /dev/null &`) и опрашиваются по логу; SSH-сессия не
   держит процесс.
8. **Не догадываться**: если команда недоступна, ответ не разобран, статус неизвестен —
   остановиться и назвать недостающее доказательство.

## 1. Карта системы (что где лежит и чем проверяется)

| Что | Где / чем | Команда проверки |
| --- | --- | --- |
| Compose-проект узла | `/opt/mtproxy-shared443`, текущий проект `proxy_panel_by_dubr1k` (у ещё не перенесённого узла `mtproxy`), `.env` root-only с `COMPOSE_FILE=…` | `cd /opt/mtproxy-shared443 && sudo docker compose ps --format '{{.Name}} {{.Status}}'` — все `healthy` |
| Панель | контейнер `proxy-control-panel`, `127.0.0.1:8787`, том `panel-data` | `curl -fsS -H 'Host: <panel-domain>' http://127.0.0.1:8787/healthz` |
| Версия и схема базы | `VERSION` в каталоге проекта; `db-status` | `sudo docker exec proxy-control-panel panel cli db-status` |
| Мастер-ключ | `secrets/panel-master-key` | `sudo docker exec proxy-control-panel panel cli master-key-verify --path /run/panel/master-key` (печатает счётчики, не значения) |
| Nginx / 443 | stream-map `/etc/nginx/stream.d/proxy-control.conf` (fresh), TLS панели `127.0.0.1:8443` | `sudo nginx -t && ss -lntp 'sport = :443'` — владелец nginx |
| Сертификаты | `/etc/letsencrypt/live/{proxy-control,naive,three-xui-*}` | `sudo certbot certificates` (без вывода ключей) |
| NaiveProxy | `caddy-naive.service`, `/var/lib/naive-manager/Caddyfile`, `proxy-control-naive-manager` | `systemctl is-active caddy-naive` |
| Mieru | `mita.service`, `/run/mita/mita.sock`, `proxy-control-mieru-manager` | `sudo -u mita env MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status` → ровно `mita server status is "RUNNING"` |
| TrustTunnel (необязательно) | `proxy-control-trusttunnel-manager`, `/var/lib/trusttunnel-manager` (0700, пароли и счётчики), endpoint на `127.0.0.1:4453`, метрики `127.0.0.1:1987`, SNI-имя `domains.trusttunnel` на общем 443 | `sudo docker inspect --format '{{.State.Health.Status}}' proxy-control-trusttunnel-manager` → `healthy`; `ss -ltn 'sport = :4453'`; экран «TrustTunnel» не `degraded` (`certificate_missing` — нет сертификата домена) |
| Xray-router | `proxy-control-xray-router`, `/var/lib/xray-router`, ingress 45101/45102 | `sudo docker exec proxy-control-xray-router /usr/local/bin/xray-router-manager healthcheck --status` → `phase == "idle"`, `artifacts.*.verified == true` |
| WARP | `warp-svc`, SOCKS5 `127.0.0.1:40000` | `warp-cli status`; `curl -s --proxy socks5h://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace \| grep '^warp='` |
| 3x-ui (managed) | `x-ui.service`, панель `127.0.0.1:8451`, inbound 8449/8450, UDP/443 | `systemctl is-active x-ui && ss -lntup \| grep -E ':(8449\|8450\|8451)\b'` |
| version-agent | `version-agent.service`, `/run/proxy-control/version-agent.sock` | `sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health` |
| Мониторинг | сэмплер в `version-agent` (раз в секунду), таблица nftables `inet proxy_control_metrics` (только счётчики), опциональный `/etc/proxy-control/metrics-ports.json`, сборщик панели и таблица `metric_rollups`; описание — `docs/guides/MONITORING.ru.md` | `sudo curl --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/metrics` (`503 metrics_warming_up` — только что стартовал); `GET /api/metrics/live` → `status: ok`, `kernel_counters: ok`; `sudo nft list table inet proxy_control_metrics`; убрать — `sudo nft delete table inet proxy_control_metrics`; выключить сборщик — `PANEL_METRICS_ENABLED=0` |
| Установщик | журнал `/var/lib/proxy-control/installer/state.json`, отчёты `/var/lib/proxy-control/reports` | `sudo /opt/mtproxy-shared443/installer/bin/linux-amd64/proxy-control-installer status --json` |
| Аудит панели | таблица `audit`, экран «Журнал», `GET /api/audit` | `GET /api/audit?action=<код>&limit=50` |

API панели: сессия (`POST /api/auth/login` → cookie `panel_session` + `panel_csrf`; каждая
мутация с заголовком `X-CSRF-Token: <значение cookie panel_csrf>`) **или** `Authorization:
Bearer pc_…` (без CSRF; scope `admin` = владелец, `monitor` = чтение, `node-sync` = только
`/api/fleet/v2/*`). Ключ scope `admin` для агента выдаёт владелец; агент хранит его только в
переменной окружения процесса и никогда не печатает. Ниже `$PANEL` — `https://<panel-domain>`,
`$KEY` — ключ `admin`, `hdr=(-H "Authorization: Bearer $KEY" -H 'Content-Type: application/json')`.
Каждый ответ панели несёт `Cache-Control: no-store`; поля `reveal_token` разыменовываются
`GET /api/reveal/{token}` **один раз** и только человеком — агент никогда не вызывает
`/api/reveal/*`, а передаёт владельцу сам факт «ссылки готовы, id операции N».

## 2. Алгоритм A — развернуть узел неинтерактивно

Порядок установки — **только** по разделу README «Установка ИИ-агентом»
([README.md](README.md#установка-ии-агентом), [README.en.md](README.en.md#installation-by-an-ai-agent)):
скачать и проверить `install-release.sh`, `--no-wizard`, TOML из `examples/installer/`,
`plan --json`, digest подтверждает владелец, `install --accept-plan`. Здесь он не дублируется;
ниже — расширенная проверка после установки для отчёта.

Проверка (все команды обязаны пройти; иначе — `resume`/`repair` по [docs/INSTALLER_REFERENCE.ru.md](docs/INSTALLER_REFERENCE.ru.md) («Восстановление, repair, откат и удаление»), а не повтор `install` вслепую):

```bash
cd /opt/mtproxy-shared443 && sudo docker compose ps --format '{{.Name}} {{.Status}}' | grep -vc healthy   # ожидается 0
curl -fsS -H "Host: $PANEL_DOMAIN" http://127.0.0.1:8787/healthz && echo PANEL_OK
sudo nginx -t && ss -lntp 'sport = :443' | grep -q nginx && echo NGINX_443_OK
curl -sSI "https://$PANEL_DOMAIN/login" | head -1                       # HTTP/2 200
curl -sS -o /dev/null -w '%{http_code}\n' "https://$PANEL_DOMAIN/s/x"    # 404 на домене панели
systemctl is-active caddy-naive mita 2>/dev/null                          # по профилю
sudo /opt/mtproxy-shared443/installer/bin/linux-amd64/proxy-control-installer report --config /root/proxy-control.toml --output /var/lib/proxy-control/reports
sudo jq -r 'keys | .[]' /var/lib/proxy-control/reports/report.json  # только ключи фактов приёмки, не секреты
```

Отчёт владельцу: домены, профиль, digest плана, `VERSION`, статус контейнеров/служб,
где лежат учётные данные (пути `<конфиг>.credentials` / `secrets/panel-bootstrap-password`, не
содержимое; для managed 3x-ui — путь `/var/lib/proxy-control/three-xui/panel-access`, см. [README.md](README.md), «После установки»), какие ручные приёмки остались (реальный клиент
Telegram, вход в панель человеком).

## 3. Алгоритм B — подготовить узел к центру

```bash
# B1. Ключ node-sync (только владелец; через ключ admin узла или сессию владельца)
resp=$(curl -sS "${hdr[@]}" -X POST "$NODE/api/keys" -d '{"name":"central","scope":"node-sync"}')   # 201 {"key": {id, name, prefix, scope, …}, "plaintext": "pc_…"}
printf '%s' "$resp" | jq -r '.key | [.id, .prefix, .scope] | @tsv'    # только id/prefix/scope, НИКОГДА plaintext
NODE_SYNC_KEY=$(printf '%s' "$resp" | jq -er '.plaintext'); unset resp  # только в переменную, не в вывод
# B2. Идентичность узла, как её увидит центр
curl -sS -H "Authorization: Bearer $NODE_SYNC_KEY" "$NODE/api/fleet/v2/identity" | jq '{guid, panel_version, master_guid, capabilities}'
#   master_guid должен быть null (никем не управляется); panel_version — та же сборка, что у центра
# B3. (по желанию) version-agent — docs/UPGRADING.ru.md («Обновление из панели через version-agent»); проверка: /v1/health по сокету
```

## 4. Алгоритм C — привязать узел на центре

```bash
body=$(python3 - <<PY
import json,os;print(json.dumps({"display_name":os.environ["NODE_NAME"],"url":os.environ["NODE"],"api_key":os.environ["NODE_SYNC_KEY"],"tls_verify":"verify","allow_private_address":False}))
PY
)
# C1. Проверка без записи: identity/status/inventory узла этим ключом
curl -sS "${hdr[@]}" -X POST "$PANEL/api/nodes/test" -d "$body" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["identity"]["guid"],d["identity"]["panel_version"],d["latency_ms"],[(p,u["runtime_username"],u["ownership"]) for p,us in d["inventory"]["protocols"].items() for u in us])'
#   409/502 с code: node_unreachable | node_auth_failed | already_linked | foreign_master | same_panel → СТОП, причина владельцу
# C2. Привязка → 201 {"node_id": "<guid>"}
node_id=$(curl -sS "${hdr[@]}" -X POST "$PANEL/api/nodes/link" -d "$body" | python3 -c 'import json,sys;print(json.load(sys.stdin)["node_id"])')
unset NODE_SYNC_KEY
# C3. Дождаться первого heartbeat (≤ PANEL_FLEET_HEARTBEAT_SECONDS, по умолчанию 15 с) или запросить его
curl -sS "${hdr[@]}" -X POST "$PANEL/api/nodes/$node_id/probe" >/dev/null
for i in $(seq 1 20); do
  st=$(curl -sS "${hdr[@]}" "$PANEL/api/nodes/$node_id" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["link"]["status"],d["link"].get("last_error"))')
  case "$st" in online*) echo NODE_ONLINE; break;; esac; sleep 3; done
```

Импорт существующих пользователей (только после `NODE_ONLINE`, только те, кого назвал владелец):

```bash
curl -sS "${hdr[@]}" "$PANEL/api/nodes/$node_id/inventory" | python3 -c 'import json,sys;d=json.load(sys.stdin);print([(p,u["runtime_username"],u["ownership"],u.get("linked_grant_id")) for p,us in d["protocols"].items() for u in us])'
curl -sS "${hdr[@]}" -X POST "$PANEL/api/nodes/$node_id/import" -d '{"resources":[{"protocol":"naive","runtime_username":"alice","client":"new"}]}'
#   client: "new" — клиент с именем учётной записи; иначе id существующего клиента. Mieru вернётся unsupported (нет секрета) — это норма, не ошибка.
```

Проверка привязки: `GET /api/nodes/$node_id` → `link.status == "online"`, `connectivity_state == "online"`,
после первой доставки `link.desired_generation == link.acknowledged_generation` и `link.config_dirty == false`,
`link.last_error == null`; на узле `GET /api/fleet/v2/identity` → `master_guid` = GUID центра
**только после первого принятого поколения**; `GET /api/events?after=0` содержит `node.up`.

## 5. Алгоритм D — выдать доступ клиенту на узле

```bash
# D1. Клиент (или существующий id из GET /api/clients)
client=$(curl -sS "${hdr[@]}" -X POST "$PANEL/api/clients" -d '{"display_name":"Laptop"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
# D2. Доступы: до 8 за операцию; node_id = "local" или GUID связанного узла; options: {} = без квоты
op=$(curl -sS "${hdr[@]}" -X POST "$PANEL/api/clients/$client/grants" -d "{\"grants\":[
  {\"protocol\":\"naive\",\"node_id\":\"$node_id\",\"runtime_username\":\"laptop\",\"options\":{}},
  {\"protocol\":\"mieru\",\"node_id\":\"$node_id\",\"runtime_username\":\"laptop\",\"options\":{}}]}")
op_id=$(python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(d["operation_id"])' "$op"); python3 -c 'import json,sys;print(json.loads(sys.argv[1])["status"])' "$op"
#   локальный узел: succeeded | compensated | manual_intervention_required сразу
#   связанный узел: pending_remote → ждать доставки (heartbeat или POST /api/nodes/$node_id/probe)
for i in $(seq 1 40); do
  s=$(curl -sS "${hdr[@]}" "$PANEL/api/operations/$op_id" | python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])')
  case "$s" in succeeded) echo GRANT_OK; break;; compensated|manual_intervention_required|failed) echo "GRANT_$s"; break;; esac; sleep 3; done
# D3. Ссылки: агент получает только reveal_token и передаёт владельцу id операции; GET /api/reveal/<token> — человек, один раз
curl -sS "${hdr[@]}" -X POST "$PANEL/api/operations/$op_id/bundle" | python3 -c 'import json,sys;print("reveal issued" if json.load(sys.stdin).get("reveal_token") else "no reveal")'
# D4. Подписка (нужен PANEL_SUBSCRIPTION_URL на этой панели; иначе 409)
curl -sS "${hdr[@]}" "$PANEL/api/clients/$client/subscription" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["configured"],[(g["protocol"],g.get("state")) for g in d["grants"]])'
curl -sS "${hdr[@]}" -X POST "$PANEL/api/clients/$client/subscription" | python3 -c 'import json,sys;print("subscription reveal issued" if json.load(sys.stdin).get("reveal_token") else "?")'
```

Управление: `POST /api/clients/grants/{grant_id}/{enable|disable|rotate|delete}`; `POST /api/clients/{id}/state`
`{"state":"active|suspended|archived"}`; `POST …/subscription/rotate` и `…/revoke`; `POST /api/operations/{id}/resume` для
`manual_intervention_required` (после того как владелец посмотрел причину). Имена учётных записей NaiveProxy/Mieru после
удаления **не переиспользуются** (менеджеры тумбстонят их) — агент всегда берёт новое имя с суффиксом прогона.

Проверка: `GET /api/clients/{id}` → у каждого доступа `desired_state == enabled` и (на связанном узле)
`observed_state == enabled`; на узле `GET /api/fleet/v2/observed` → ресурс `grant:<id>` в `enabled`; в
`GET /api/audit?target=<runtime_username>` — строки создания без секретов; `GET /api/nodes/$node_id` →
`desired == applied`.

## 6. Алгоритм E — маршрутизация egress

```bash
# E1. Что умеет цель (backend, провайдеры, роутер)
curl -sS "${hdr[@]}" "$PANEL/api/routing/targets" | python3 -c 'import json,sys
for t in json.load(sys.stdin)["items"]: print(t["node_id"],t["protocol"],t["backend"],t["providers"],t["router"],t["reason"],(t["policy"] or {}).get("state"))'
# E2. Черновик → предпросмотр (ничего не меняет). Политика — по docs/ROUTING.ru.md; backend опускается (текущий цели)
policy='{"default_action":"egress","default_egress":"warp","fallback":"fail_closed","rules":[{"enabled":true,"action":"block","match":{"domains":["ads.example.com","*.ads.example.com"]},"note":"ads"}]}'
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/policies/$node_id/naive/preview" -d "$policy" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["status"],[(r["code"],r.get("rule_id")) for r in d["reasons"]],d["warnings"],d["restart_required"],d["backend"])'
#   status != supported → СТОП; коды и что делать — docs/ROUTING.ru.md, «Предпросмотр и применение» (provider_unavailable, rule_kind_unsupported, not_attached, …)
# E3. Сохранить (revision) → применить ровно эту revision (только owner)
rev=$(curl -sS "${hdr[@]}" -X PUT "$PANEL/api/routing/policies/$node_id/naive" -d "$policy" | python3 -c 'import json,sys;print(json.load(sys.stdin)["revision"])')
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/policies/$node_id/naive/apply" -d "{\"expected_revision\":$rev}" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["state"],d.get("applied_revision"),d.get("last_error"))'
#   локальный узел: applied сразу; связанный: applying → applied после отчёта узла (один heartbeat): опрашивать GET …/policies/$node_id/naive
# E4. Xray-router: подключить сервис ДО политики с geosite/geoip/портами (owner; сессии сервиса прервутся — согласовать с владельцем)
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/targets/$node_id/naive/attach" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["backend"],d["router"])'
#   отказ policy_applied → сначала PUT политики "напрямую без правил" + apply, затем attach
# E5. Откат — предыдущая запись менеджера/предыдущий документ: POST …/rollback {"expected_revision":<rev>}
# E6. Своя полоса доступа и цепь через другой узел (owner; docs/ROUTING.ru.md, «Цепи и полосы»). Предпосылки: сервис подключён к роутеру (E4),
#     у узла-выхода B relay включён: GET …/targets → exits[] с enabled && !pending; иначе POST $PANEL/api/routing/relay/$b/enable
#     (связанный узел: pending → ждать heartbeat с публичным ключом). Полоса: mode=own → у Mieru меняется ссылка (порт слота) — предупредить владельца
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/lanes/$grant_id" -d '{"mode":"own"}' | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["mode"],d["lane"],d.get("pending"))'
lane="grant:$grant_id"   # дальше — E2/E3 с ?lane=$lane; выход: "warp" | "node:$b" | "node:$b:warp" | "node:$b,$c"
policy='{"default_action":"egress","default_egress":"warp","fallback":"fail_closed","rules":[{"enabled":true,"action":"egress","egress":"node:'$b'","match":{"geosites":["youtube"]},"note":"via B"}]}'
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/policies/$node_id/naive/preview?lane=$lane" -d "$policy" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["status"],[r["code"] for r in d["reasons"]],d["document"] and d["document"].get("schema"))'
#   relay_credential_pending после apply → узел B ещё не подтвердил учётку relay: повторить apply после heartbeat; node_lacks_relay/relay_disabled/chain_loop — docs/ROUTING.ru.md, «Цепи и полосы»
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/policies/$node_id/naive/explain?lane=$lane" -d '{"host":"youtube.com","port":443}'   # {lane, rule_id, action, exit, hops, via, uncertain}
#   назад: POST …/lanes/$grant_id {"mode":"service"} — политика полосы удаляется, пользователь возвращается в сервис; удаление доступа снимает полосу само
```

Проверка после apply (на узле, по SSH): `docker compose logs --since=5m naive-manager` без ошибок; в
`/var/lib/naive-manager/Caddyfile` блок `# BEGIN NAIVE-MANAGER EGRESS … # END` с ожидаемым `upstream`
(ключи ingress роутера в выводе **маскировать**: `sed 's#socks5://[^@]*@#socks5://***@#'`); для Mieru —
`systemctl is-active mita` и секция `egress` в конфиге; `curl --proxy https://<naive-домен> --proxy-user
<тестовый пользователь>` к заблокированной цели → отказ, к разрешённой → 200 (тестовый пользователь создаётся
для проверки и удаляется). `GET /api/audit?action=routing.policy.apply` содержит строку с целью политики.
Для полосы: в Caddyfile блок `# BEGIN NAIVE-MANAGER LANES … # END` с `basic_auth <пользователь>` и
`upstream socks5://grant-<id>:***@127.0.0.1:45101` (ключ **маскировать**); у Mieru `systemctl is-active mita@1` и
`share_template` доступа с `port=4610N`; на узле-выходе `healthcheck --relay` → `enabled`, `accounts ≥ 1`; в отчёте
никогда не приводить `uuid` хопов, ключи полос, `relay.json`/`lanes.json`.

## 7. Алгоритм F — обновление, откат, резервная копия

- **Обновление узла** (после того как гейт релиза зелёный, а владелец разрешил): точка отката
  (образы `*:rollback-<UTC>`, online-backup базы, `secrets/`, `.env*`), затем
  `bash install-release.sh --update` по README «Обновление» и [docs/UPGRADING.ru.md](docs/UPGRADING.ru.md),
  `db-status`, `VERSION`, все проверки §2; порядок парка — **узлы, затем центр**. Панель на старой сборке отвергает
  документ поколения с новыми полями (422) — центр ждёт в backoff.
- **Обновление компонента** (Telemt/Caddy/mita/Xray/AmneziaWG/TrustTunnel) — только через version-agent:
  `GET /api/versions` → `POST /api/versions/{component}/update {"version":…, "expected_current":…}`
  (на центре для узла — `POST /api/nodes/{id}/versions/{component}`); `409` при несовпадении
  `expected_current`; `rollback_failed` блокирует компонент до вмешательства человека.
  Компоненты `amneziawg` и `trusttunnel` обновляются пересборкой образов менеджеров с выбранными
  закреплёнными версиями: version-agent сохраняет build args в `version-overrides/compose.versions.yaml`,
  проверяет `healthy` и версию, при ошибке возвращает прежние override и образ.
  Это отдельный путь от пересборки менеджеров после обновления панели: обновление одной
  командой пересобирает менеджеры; обновление панели из UI называет изменившиеся в `pending_rebuild`,
  а агент после успешного обновления сам пересобирает их одним вызовом Compose, если не задано
  `VERSION_AGENT_AUTO_REBUILD_MANAGERS=0`; доступны `POST /v1/panel/managers/{rebuild,ack}` и
  `POST /api/versions/panel/rebuild-managers`. Пересборка TrustTunnel перезапускает
  endpoint — сессии рвутся на секунды; `/var/lib/trusttunnel-manager` не трогается. Любое изменение учётных данных
  TrustTunnel (новый, изменённый, выключенный доступ, подключение/отключение роутера) тоже перезапускает endpoint;
  полос для отдельных клиентов у него нет (`lanes_unsupported`), вход роутера `127.0.0.1:45104` — SOCKS5 без пароля, только loopback.
- **Откат** — полная предыдущая генерация вместе с базой (образ старой версии не стартует на
  новой схеме); управляемый узел перед откатом отвязать (`POST /api/nodes/local/unlink` на узле,
  затем `DELETE /api/nodes/{id}` на центре после удаления его доступов).
- **Резервная копия** — `docs/BACKUP_RESTORE.ru.md`; образец сценария, который делает
  бэкап → разрушение → восстановление → сверку digest'ов: `scripts/lab/backup-restore-drill.py`
  (запускается сценарием `backup-restore` `lab-host`; на боевом хосте — только «бэкап» его
  части, никогда «разрушение»).

## 8. Изменение кода: что добавилось в гейт

По затронутой границе дополнительно выбирайте проверки ниже:

- `scripts/dev/route-coverage.py` запускает нативный тест
  `panel/crates/web/tests/route_gate_inventory.rs`: он берёт маршруты из реального
  `routes::all()`, проверяет HTTP-отказы по роли, CSRF и области ключа, сверяет OpenAPI.
  Публичных операций ровно 7; нарушение контракта ломает `full`. Эта проверка
  запускает Cargo и тоже выполняется только на `ams-test`.
- **Матрица сверки** `tests/fixtures/verification-matrix.json` ↔ `docs/VERIFICATION_MATRIX.md`
  (`scripts/dev/verification-matrix.py --render|--check`, тест `tests/test_verification_matrix.py`):
  каждый маршрут и каждый экран обязан иметь строку с существующим доказательством
  (`pytest::файл::тест`, `lab-host::сценарий`, `ui::экран.проверка`, `fleet::шаг`, …); на
  полном наборе `VERIFICATION_STRICT=1` запрещает статус `gap`. Новая функция = строка матрицы
  + доказательство, иначе тест-страж падает.
- **UI:** для локальной правки проверяйте затронутые экраны и состояния в настоящем браузере
  на телефоне и компьютере, отсутствие переполнений, пересечений, ошибок консоли/CSP и
  секретов в кадрах. Полный tier `ui` с обеими ролями и связанными панелями нужен только
  при изменении общей навигации, ролей или взаимодействия панелей. Скриншоты выпуска —
  только со стендовыми данными, ≤150 КБ, без метаданных; каждый кадр просматривается.
- **Tier `managed-xui`** — реальный 3x-ui на стенде; **сценарий `backup-restore`** в `lab-host`.
- Tier'ы (`full`, `compose`, `lab-container`, `lab-host`, `fleet`, `routing`, `router`, `chains`, `ui`,
  `managed-xui`) запускаются по необходимости, а не как обязательный релизный гейт.
- **Порядок выпуска, начиная с 4.0.2** (также применяется к подготовке самого 4.0.2):
  один успешный полный CI (`test.yml`, push в `main`) для точного коммита кандидата →
  тег `vX.Y.Z`, соответствующий `VERSION` и этому коммиту → `Release` один раз выполняет
  цикл двух независимых сборок бинарников и архива, сравнивает все файлы, создаёт
  подтверждение происхождения и **останавливается на черновике**.
- Скачайте `release-dist` выбранного запуска Release или файлы его черновика, проверьте
  суммы и происхождение; на `ams-test` проверьте **готовый архив**, выбирая сценарии по
  изменениям. Зафиксируйте SHA коммита, SHA-256 архива, команды, результат и ограничения.
  Не пересобирайте принятый кандидат. Для установки/обновления — затронутые сценарии
  в изолированном окружении; полный жизненный цикл нужен только при сквозных изменениях
  или по прямому заданию.
- По поручению владельца запустите `Publish accepted release` (`publish.yml`): номер
  успешного запуска Release, SHA-256 принятого архива и описание выполненной приёмки.
  Workflow сверяет источник, тег, attestation и **каждый файл** черновика с неизменяемым
  артефактом выбранной сборки и меняет только видимость выпуска. Повторных сборок,
  ручных `lab-sha256`/`lab-bin-sha256` в теге и повторного полного CI на теге нет.
  Обычный CI продолжает полностью проверять push веток и PR. После публикации обязательна
  проверка скачивания и входа в мастер с `quit`, описанная выше. Раскатка на узлы — отдельно.

## 9. Таблица «код отказа → действие агента»

| Откуда | Код | Действие |
| --- | --- | --- |
| установщик `plan` | `hard_stops` (DNS/CAA/443/порт/UID/x-ui) | стоп; владельцу — список, это его решения |
| установщик `install` | фаза не `done` | `status --json` → `resume`; не повторять `install` вслепую |
| `POST /api/nodes/test` | `node_unreachable` (502) | DNS/443/сертификат узла; `curl -sSI https://<узел>/login` |
| | `node_auth_failed` | ключ не `node-sync` этого узла или отозван — новый ключ (алгоритм B) |
| | `foreign_master` / `already_linked` / `same_panel` | стоп, владельцу |
| push поколения | `stale_generation` / `digest_conflict` | центр сам переиздаёт; ничего не делать, наблюдать `observed` |
| | `secret_store_disabled` | на узле нет мастер-ключа — `master-key-init` по [docs/UPGRADING.ru.md](docs/UPGRADING.ru.md) (владелец) |
| | 422 | узел на старой сборке — обновить узел до сборки центра |
| ресурс поколения | `failed: runtime user exists and is not managed` | коллизия с локальным пользователем — другое имя или импорт вместо выдачи |
| операция выдачи | `compensated` | причину в `GET /api/operations/{id}`; повторить с новым именем |
| | `manual_intervention_required` | стоп; владельцу id; `POST …/resume` только после его решения |
| протокол-API узла | 409 `managed_by_central` | ресурс принадлежит центру — менять на центре |
| маршрутизация | `unsupported` + причины | [docs/ROUTING.ru.md](docs/ROUTING.ru.md), «Предпросмотр и применение»; ничего не применять |
| | 409 `policy_conflict` | перечитать `revision`, повторить PUT |
| | 503 `manual_intervention_required` | стоп; резервные копии менеджера; владельцу |
| | `artifact_mismatch` | бинарь/geodata роутера не совпадают с пином — не чинить самому, владельцу |
| цепи и полосы | `relay_credential_pending` | узел-выход ещё не подтвердил учётку relay — повторить apply после heartbeat, не ротировать |
| | `node_lacks_relay` / `relay_disabled` / `node_lacks_lanes` | узел-выход без relay / relay выключен / узел без поддержки полос — включить relay (`POST …/relay/{node}/enable`) или обновить узел; вопрос владельцу, если это боевой узел |
| | `chain_loop` / `node_unknown` / `relay_no_warp` | политика называет сам узел / узел не в парке / у выхода нет WARP — исправить выход, не применять |
| | 409 `lane_slots_exhausted` / `lanes_invalid` / `lane_requires_router` / `lane_not_attached` | у Mieru кончились слоты (`[mieru] lane_slots`) / менеджер отверг полосы / нет роутера или сервис не подключён — сначала E4, затем повторить |
| version-agent | 409 `expected_current` | перечитать версии; не форсировать |
| | `rollback_failed` | стоп; компонент заблокирован до человека |

## 10. Шаблон отчёта об эксплуатационной операции

```text
Хост/класс: <alias>, <лабораторный|живой тестовый|боевой>, разрешение владельца: <цитата или «нет — только чтение»>
Операция: <A|B|C|D|E|F> <что именно>
Точка отката: <образы/бэкап/пути или «не требовалась (только чтение)»>
Выполнено (команды и ключевой вывод без секретов): …
Проверки после: <каждая команда из раздела «Проверка» и её результат>
Не выполнено / осталось человеку: <реальный клиент, reveal ссылок, ручной вход, hard stops>
Секреты: <«в вывод не попадали» | «попало X — ротировано так-то»>
Изменения в репозитории: <нет | commit …>
```


---

# For AI agents

This file is the mandatory protocol for AI agents that **develop** Proxy Control: change
its code and documentation, validate them on the lab host and release them. It is useful to
people too: the same safety rules, written as an algorithm. The Russian part ends with an
operations protocol for nodes that are already installed.

To **install** Proxy Control, an agent needs the README section
[«Installation by an AI agent»](README.en.md#installation-by-an-ai-agent), not this file. If
you are simply installing and operating Proxy Control, start with the [README](README.en.md).

The **operations protocol for agents** (preparing
and linking nodes, issuing grants, routing, upgrades, the gate additions and the
refusal-code table) is in the Russian part above, «Эксплуатационный протокол для
ИИ-агентов»; the human-facing documents are
[docs/INSTALLER_REFERENCE.en.md](docs/INSTALLER_REFERENCE.en.md) (the installer wizard and TOML),
[FLEET.en.md](docs/guides/FLEET.en.md) (linked panels), [docs/ROUTING.en.md](docs/ROUTING.en.md) (routing, chains and
lanes), [docs/XRAY_ROUTER.en.md](docs/XRAY_ROUTER.en.md), [docs/UPGRADING.md](docs/UPGRADING.md) (updates),
[docs/BACKUP_RESTORE.en.md](docs/BACKUP_RESTORE.en.md) and [docs/MCP.en.md](docs/MCP.en.md).

## Codex and the current architecture

The primary development agent is **Codex**. This tracked `AGENTS.md` is the single
project protocol; owner rules must not depend on a local `CLAUDE.md`. The local file
only points here. Old checkouts in `.claude/worktrees/` are not the current source:
exclude them from searches and do not edit or delete them without a request.
Verify `pwd` and the selected checkout's Git state.

Shipped components are implemented in **Rust**:

| Boundary | Source |
| --- | --- |
| Panel, HTTP API, administrative CLI | `panel/` workspace, `panel/crates/web/` server, domain modules in `panel/crates/` |
| Installer transactions and host adapters | `installer/src/`, `installer/src/adapters/` |
| Configuration, planner, wizard, translations | `installer_core/src/config.rs`, `planner.rs`, `wizard.rs`, `i18n.rs` |
| Shared libraries and host operations | `pc_common/`, `pc_host/` |
| Host updates and metrics | `version_agent/` |
| Protocol and router managers | `naive_manager/`, `mieru_manager/`, `awg_manager/`, `trusttunnel_manager/`, `xray_router_manager/` |
| MCP | `mcp_server/` |

Use CI's pinned Rust **1.99.0**, committed `Cargo.lock` files and `--locked`.
Do not reintroduce Python service or installer implementations. Python 3.12 and `.venv`
remain for external tests, release builds and development scripts on the test host;
JavaScript remains in the UI and Go in the MTProxy bridge and third-party components.
Installed nodes do not require Python. The API examples using `python3` below run on
an operator machine with Python, not as a production-host dependency.

## Commits, tags and PRs

- Write substantive commit messages in Russian, following `git log`.
- Do not add tool attribution such as `Co-Authored-By`, `Claude-Session`,
  `Generated with Claude Code`, `Generated with Codex` or equivalents to commits,
  amendments, tag annotations or PR descriptions.
- Pass messages through `git commit -F -` and end with a substantive paragraph.
- Preserve others' edits. Commit, push, merge and publish within the owner's request;
  a documentation update alone does not authorize a release.

## The rule that matters

An agent must follow the algorithm and provide factual command output. It must
not stop at a plan, a source edit, or a statement that the result "looks
correct".

It must not claim "installed", "tested", "healthy", "committed", or "updated"
without fresh evidence from the corresponding command. When anything is
uncertain, stop at a safe boundary and name the missing proof.

## Before making changes

1. Read the [README](README.en.md), [CONTRIBUTING.md](CONTRIBUTING.md),
   [SECURITY.md](SECURITY.md), the [compatibility policy](docs/COMPATIBILITY.md),
   the affected documents, and `.github/workflows/test.yml`.
2. Run and record the following without exposing secrets:

   ```bash
   pwd
   git status --short --branch
   git log -3 --oneline
   git diff --check
   ```

   Run host commands over SSH on `ams-test` when the changed boundary requires Docker,
   systemd or networking; text-only edits do not require them:

   ```bash
   docker version
   docker compose version
   systemctl is-active docker nginx 2>/dev/null || true
   ss -lntup
   ```

3. Identify the actual change boundary and every connected interface: README,
   Compose, Dockerfiles, systemd, Rust HTTP API, UI, JavaScript, tests,
   backup/restore, and Fleet. Do not change foreign routes, containers, volumes,
   secrets, or production configuration without an explicit request.
4. When code changes, write a narrow regression test first, verify that it fails
   for the expected reason, implement the smallest change, and run it again.

## Rules that have already prevented false reports

- Keep restrictive `umask 077` inside secret/backup creation only and restore it
  immediately. The checkout/build context must be readable by runtime UIDs, APT
  keyrings/source lists by `_apt`, and public ACME roots by the Nginx worker.
- Print a success marker only in a successful `if` branch.
  `fallible-command; echo OK` is forbidden: it has falsely reported a package
  installation, manager health, and a repair as successful.
- Verify secret-bearing browser dialogs through safe booleans, labels, lengths,
  and matching metadata. Never return an accessibility or DOM snapshot
  containing a password, link, subscription ID, or hidden path; rotate any value
  that reaches tool output.

## The auto-install script is updated with every change

A strict owner rule (2026-10-01). The «auto-install script» is everything a new server receives
Proxy Control through: `scripts/install-release.sh` (published with every release as
`install-release.sh` with its version and archive SHA-256 written in), the installer `installer/`
(engine and adapters) and `installer_core/` (wizard `wizard.rs`, translations `i18n.rs`,
configuration `config.rs`), `install.sh`,
`install-bootstrap`, `release/external-artifacts.json` and the examples in `examples/installer/`.
A change that touches it without updating it is unfinished work, not «we'll catch up later».

1. **The same commit.** A new or changed component, service, port, domain, profile, configuration
   key, host package, path, service name, pinned external artifact version or host requirement
   updates, in the same commit: the adapter; `installer_core/src/config.rs` and its checks, `reserved_tcp_ports`
   included; the wizard's questions and hints in both languages; the `--requirements` text in
   `scripts/install-release.sh`; the examples; README, INSTALL and INSTALLER_REFERENCE.
2. **A fresh install equals an upgraded node.** Whatever reaches a running node through an
   agent update — a component, a setting, a default — a fresh install of the same release sets
   up too. Otherwise new and upgraded servers drift apart.
3. **Pinned versions in texts match `release/external-artifacts.json`.** That covers
   `--requirements` and the wizard's Xray-router question; a pin change updates every text at
   once. `tests/test_release_build.py` checks it.
4. **Every release publishes `install-release.sh` and `install-release.sh.sha256`.**
   - Never remove them from `release.yml`.
   - Never change the `SHA256SUMS` format: three files, which copies of the script from earlier
     releases check strictly.
   - The release build check: two builds give identical archives and scripts
     (`INSTALLER_IDENTICAL`), and the script's stamps equal the version and the archive digest.
5. **The gate.** The full gate and the `lab-host` tier are not part of a release (owner's
   decision, 2026-10-12): before a release run `cargo fmt --check`,
   `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` for affected
   Rust crates on `ams-test`; run `ruff` and selected external tests when their boundaries
   are affected. This does not disable full CI.
6. **A live check after publishing.**
   - On `ams-test`, as a regular user (not root): `curl -fsSLO` for
     `releases/latest/download/install-release.sh` and its `.sha256`, then
     `sha256sum --check install-release.sh.sha256` and `bash install-release.sh`.
   - Reach the wizard and leave with `quit`.
   - Attach the lines «the archive digest matches the pinned one» and «No changes were made».
   - Until then the release is not published.
7. **The wizard is honest.**
   - A hint never promises what the validator refuses.
   - Every configuration field an ordinary install needs is asked or set deliberately.
   - A new question comes with its translation and a test in `installer_core/src/wizard_tests.rs`.
   - Typed passwords reach the adapters on both paths: the wizard's «apply» and `install --config`.
8. **The release report** names what changed in the installer and the script, or says plainly
   «the installer did not change», with the evidence (tests, diff).

## Documentation

- **README.md and README.en.md** are for users. Each has two installation sections:
  «Installation by a human» (the wizard) and «Installation by an AI agent» — the installation
  instruction for agents the owner gave access to a server (TOML from `examples/installer/` →
  `plan --json` → the owner confirms the digest → `install --accept-plan`). This file (AGENTS.md)
  is the **development** protocol, not an installation guide. A change to the installer, its
  flags, paths, wizard questions or examples updates both sections in both languages in the same
  commit; `installer/tests/documented_cli.rs` checks those examples with the native parser.
- **Monitoring (2.0)** is described in `docs/guides/MONITORING.ru.md` / `docs/guides/MONITORING.en.md`. A change to what is measured (series ids, ports the agent counts, thresholds, retention, SSE limits, routes) updates both files in the same commit; validate the quoted constants against the implementation and affected tests. The agent's nft table `inet proxy_control_metrics` only counts; never add a verdict to it.
- Proxy Control is a separate panel (MTProxy, NaiveProxy, Mieru, AmneziaWG, TrustTunnel) that can run next to 3x-ui. Do
  not describe it as «a panel for 3x-ui».
- **There is no history before 1.0.0.** Documents describe the current behaviour: no «since
  v0.x», no links to beta releases or their notes. The changelog starts at 1.0.0; new entries go
  to `CHANGELOG.md` and `CHANGELOG.ru.md`.
- **`docs/releases/vX.Y.Z.md`** are release notes for users: what changed and how to upgrade.
  Gate tables, lab host names and live-check counts do not belong there.
- **Agent working material is not committed**: plans and specs, handoffs (`CONTINUE-HERE`) and
  lab acceptance logs stay in `.superpowers/` (ignored by Git) or outside the tree, and nothing in
  the repository links to them.
- After moving or deleting a document, run `python3 scripts/check-doc-links.py`.

## Test host and check selection

**Run all tests, builds and gates on `ams-test` over SSH**, not on the workstation or
production nodes. `AMS_Z` is not a second test host; a live check there requires a separate
explicit owner request. Local reading, editing, `git diff --check` and static documentation
link checks are allowed.

Choose checks by the changed boundary to avoid unnecessary test time:

| Change | Checks on `ams-test` |
| --- | --- |
| Documentation only, no behaviour change | Links and `git diff --check`; no Cargo, pytest or image builds |
| One Rust crate | fmt, clippy with warnings denied, narrow regression test, then that crate's tests |
| Shared library or contract | Changed crate and dependent components, selected external contract tests |
| Wizard, configuration, installation | `installer_core`, `installer`, `installer/tests/documented_cli.rs`; real scenarios for the affected path |
| HTTP API, UI, manager | Affected Rust packages and external test files; browser checks of affected screens on phone and desktop for UI changes |
| Compose, Dockerfile, image dependencies | Affected models, images and component checks |
| Cross-cutting change, unclear scope or explicit request | Full [VALIDATION](docs/VALIDATION.md) and CI set |

Use `--manifest-path <crate>/Cargo.toml` for Cargo commands and `-p <package>` to select
panel workspace packages. Run `cargo fmt --check`,
`cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked`
for the selected crate/package. Cargo filters are
useful for the failing/passing regression cycle; final component validation includes its
whole suite. Python is the external controller of Rust executables, never a fallback server.

Prepare `.venv` from `panel/requirements-dev.txt` once on the host; refresh when that file
changes. Preserve Cargo target and Docker caches; do not run `cargo clean` or rebuild every
image for a small edit. Keep `CARGO_TARGET_DIR` consistent and use the actual binary paths.
Build caches are allowed; old test results do not replace a fresh run. Rerun failed and
related checks after edits, without repeating successful checks unless later changes affect
them. Run dependent checks sequentially.

`scripts/dev/remote-gate.sh quick <test file paths>` syncs to `ams-test`, prepares native
binaries, and runs ruff plus selected external files. It prepares the panel, installer and
version-agent, so use direct Cargo commands on the host for Rust-only changes. The external
gate rejects skips and deselection: pass files, not `-k`/`-m`. Reuse `PANEL_RUST_BIN`,
`PC_INSTALLER_BIN` and `PC_VERSION_AGENT_BIN` only when built from the current test checkout.

Run long checks detached on the host, with a log and recorded exit status, then poll them;
a disconnected SSH session must not stop them. Run root-only tests with `sudo` on the host,
without substituting production secrets. Do not run concurrent gates that mutate the same
checkout or host.

## Full validation set

[VALIDATION](docs/VALIDATION.md) contains the full commands for native binaries, Python
setup and images; `.github/workflows/test.yml` defines required CI jobs. The full set covers
the panel workspace, `pc_common`, `pc_host`, `installer_core`, `installer`, `version_agent`,
all managers, MCP and `deploy/mieru-client`: fmt, clippy, tests, locked dependency audits,
external tests, links, JavaScript, ShellCheck, systemd and Compose. A single pytest run is
not the full set. External tests require a Rust panel with `test-hooks`, native installer
and version-agent binaries, `PANEL_IMPL=rust` and the correct `PANEL_RUST_BIN`.

The real installer/version-agent smoke ignored by default Cargo tests is a separate CI
step: root, private mount namespace, temporary `tmpfs` on `/etc`, `/var/lib` and `/run`,
exactly one passing test. Ordinary Cargo success does not prove that scenario.

Report the selected boundary, commands, results and checks not run. A narrow suite does not
prove the full gate. An unavailable command, wrong interpreter, skip or failure is incomplete
validation, never a pass.

## Validate every Compose model and image

In an isolated checkout with synthetic values — not in production. Set the
required variables first; without them `compose config` fails on its `:?`
defaults, exactly as it would in CI:

```bash
export MTPROXY_DOMAIN=proxy.example.com MTPROXY_BACKEND_PORT=18445
export MTPROXY_COVER_ROOT=/tmp/cover MTPROXY_LETSENCRYPT_ROOT=/tmp/letsencrypt
export MIERU_MANAGER_TOKEN_FILE="$PWD/secrets/mieru-manager-token"
mkdir -p /tmp/cover /tmp/letsencrypt

docker compose -f compose.yaml config -q
NAIVE_PUBLIC_HOST=naive.example.com \
  docker compose -f compose.yaml -f compose.naive.yaml config -q
MIERU_PUBLIC_HOST=mieru.example.com MIERU_MITA_GID=321 \
MIERU_MITA_BIN=/bin/true \
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 \
  docker compose -f compose.yaml -f compose.mieru.yaml config -q
NAIVE_PUBLIC_HOST=naive.example.com MIERU_PUBLIC_HOST=mieru.example.com \
MIERU_MITA_GID=321 MIERU_MITA_BIN=/bin/true \
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 \
  docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml config -q
```

Fleet v1 (the mTLS `fleet-agent`/`fleet-ingress` containers) is retired.
Fleet v2 links panels through each panel's HTTPS API, without a Compose overlay.

Before these commands, create only synthetic `secrets/users.conf`,
`secrets/telemt-api-token`, `secrets/naive-manager-token`,
`secrets/mieru-manager-token`, and `.env` in the isolated checkout following the
CI example. Do not mount real `.env` files, Docker secrets, certificates, or
volumes.

Build all affected images. The panel entrypoint starts as root only to stage secrets,
then drops to `panel` before launching the binary; `docker run --entrypoint id` bypasses
that path. Verify the live panel process UID separately in the disposable lab.

```bash
docker build -f panel/Dockerfile -t proxy-control-panel:test .
docker build -f mieru_manager/Dockerfile -t proxy-control-mieru-manager:test .
```

For Naive, build the pinned Caddy and verify both the version and the required
module:

```bash
mkdir -p /tmp/proxy-control-caddy
timeout 10m docker buildx build \
  --file docker/Dockerfile.caddy-naive \
  --output type=local,dest=/tmp/proxy-control-caddy .
env CADDY_BIN=/tmp/proxy-control-caddy/caddy \
  scripts/check-naive-caddy-build.sh
if env CADDY_BIN=/bin/true scripts/check-naive-caddy-build.sh; then
  echo 'negative Caddy build check unexpectedly passed' >&2
  exit 1
fi
```

The checker invocation with `/bin/true` must fail; its enclosing `if` succeeds only
for that expected refusal. If the checker accepts `/bin/true`, the build is unsafe
and the agent must stop.

## Isolated installation and real acceptance checks

If installer, Compose, Dockerfile, Nginx, systemd, backup or restore behaviour changes,
run the affected release-lab scenarios on `ams-test` without production access. Text-only
edits do not require a release lab. Run a full lifecycle only when the change needs it
or the owner requests it.

The fastest lab is a disposable systemd container, which runs anywhere Docker
runs:

```bash
python3 release/build.py --source . --output dist --version "$(cat VERSION)"
make lab-container \
  RELEASE_ARCHIVE=dist/proxy-control-v$(cat VERSION).tar.gz \
  RELEASE_SHA256=$(awk '/proxy-control-v.*\.tar\.gz$/ {print $1}' dist/SHA256SUMS)
```

The archive carries prebuilt host binaries (the crates of `release/host-binaries.list`):
without a flag, `release/build.py` builds them itself in the pinned image of
`release/Dockerfile.host-binaries` (Docker buildx, static musl, no layer cache).
`--build-binaries DIR` only builds them and prints each digest, `--binaries-from DIR` injects
already-built ones after checking their digests, and `--no-binaries` is for dry runs without
Docker (a host cannot install such an archive). Starting with 4.0.2 (including its preparation), use one successful full main-push CI
for the exact candidate commit, then create the matching version tag. Release performs
the only pair of independent binary/archive builds, attests the files and stops at a draft.
Test those ready-built files on `ams-test`, selecting scenarios for the actual change;
record the source SHA, archive SHA-256, checks and limitations. Do not rebuild them.
Explicit publication uses `publish.yml` with the Release run ID, accepted archive digest
and acceptance evidence. It checks the tag, source, attestation and every draft asset
against that run's immutable artifact, then changes visibility without uploading new files.
No lab digests in tag annotations or repeated full CI on tag pushes are required.
Post-publication download/checksum/wizard-quit checks remain mandatory; deployment is separate.
For small UI edits, check affected screens/states on phone and desktop in a real browser.
The complete installed-stack UI tier is reserved for shared navigation, roles or panel links.

The complete lifecycle — install, a repeated install, `repair`, reboot recovery,
an interrupted phase, reporting, uninstall, and shared-443 coexistence — runs on
a disposable host:

```bash
LAB_RESET=1 bash scripts/lab/guest-runner.sh host "$RELEASE_SHA256"
```

That command reinstalls the whole machine. Run it only on a disposable server,
never on one you care about.

Run QEMU only on a separate owner request, on `ams-test`, through `make lab-prepare`,
`make lab-full` and `make lab-clean`. TCG can take over an hour; default to the affected
host scenarios. Never report a partial result as a successful full run. See the
[lab description](tests/lab/README.md).

In the running lab, check:

- `docker compose ps` and actual `healthy` status for every container;
- panel `/healthz` with the correct `Host`;
- `nginx -t`, local listeners, and every adjacent SNI route;
- MTProxy: Fake-TLS → Obfuscated2 → `req_pq_multi` → `resPQ` → a real client;
- NaiveProxy: cover HTTPS → authenticated `CONNECT` → payload → tunnel close →
  accounting;
- Mieru: exact `RUNNING` status, TCP/UDP client, manager health, and Unix socket;
- Fleet: a linked v2 panel accepts a generation through HTTPS using a `node-sync` key;
  installed Fleet v1 requires explicit migration, not testing its retired mTLS ingress;
- backup integrity, `PRAGMA integrity_check`, file modes, and absence of secrets
  in logs.

On a live server, an AI agent must not run the full lab, recreate volumes,
change the firewall, reissue certificates, or delete orphan containers without
separate explicit authorization. Production work starts with a backup and a
read-only audit, changes one boundary at a time, and verifies rollback.

## Reporting rules

The agent must state:

- which files and boundaries changed;
- which commands actually ran and their results;
- which checks passed, failed, or were not run;
- which containers and services were checked, and their states;
- which production actions were not performed because of risk;
- the exact commit after validation when a commit was requested.
