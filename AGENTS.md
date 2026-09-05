[English](#for-ai-agents) · **Русский**

# Рабочий протокол для AI-агентов

Этот файл — обязательный протокол для AI-агентов, которые ведут разработку,
проверку, развёртывание или обслуживание Proxy Control. Людям он тоже полезен:
это те же правила безопасной работы, только записанные как алгоритм.

Обычному пользователю, который просто ставит и эксплуатирует Proxy Control,
этот файл не нужен — начните с [README](README.md).

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
   docker version
   docker compose version
   systemctl is-active docker nginx 2>/dev/null || true
   ss -lntup
   ```

3. Определите фактическую границу изменения и все связанные интерфейсы: README,
   Compose, Dockerfile, systemd, Python API, UI, JavaScript, тесты,
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

## Установка зависимостей агента

В рабочей копии проекта:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r panel/requirements-dev.txt
```

Используйте именно этот `.venv`, а не случайный системный Python. Если тест
требует root для проверки прав, контейнеров, systemd или файловой системы,
запускайте именно тот тест с `sudo`, не подменяя production-секреты.

## Обязательные проверки репозитория

После каждого существенного изменения выполните весь набор:

```bash
.venv/bin/ruff check .
sudo .venv/bin/python -m pytest -q
.venv/bin/python -m unittest -v tests/test_deploy.py
python3 scripts/check-doc-links.py
node --check panel/static/app.js

git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
shellcheck install-bootstrap
for unit in deploy/*.service; do systemd-analyze verify "$unit"; done
git diff --check
```

Если команда недоступна, завершилась с ошибкой, тест был пропущен или проверка
выполнена не на том интерпретаторе — сообщите это как незавершённую проверку, а
не заменяйте догадкой.

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
FLEET_NODE_ID=node-ci FLEET_CENTRAL_URL=https://fleet.example.com:8790 \
FLEET_CLIENT_CERT=/tmp/client.crt FLEET_CLIENT_KEY=/tmp/client.key \
  docker compose -f compose.yaml -f compose.agent.yaml config -q
FLEET_SERVER_CERT=/tmp/server.crt FLEET_SERVER_KEY=/tmp/server.key \
FLEET_CLIENT_CA=/tmp/client-ca.crt \
  docker compose -f compose.yaml -f compose.fleet-central.yaml config -q
```

Перед этими командами создайте в изолированной копии только синтетические
`secrets/users.conf`, `secrets/telemt-api-token`, `secrets/naive-manager-token`,
`secrets/mieru-manager-token` и `.env` по примеру CI. Не подключайте настоящие
`.env`, Docker secrets, сертификаты или тома.

Затем соберите все затронутые образы и проверьте runtime identity:

```bash
docker build -f panel/Dockerfile -t proxy-control-panel:test panel
docker build -f mieru_manager/Dockerfile -t proxy-control-mieru-manager:test .
docker build -f deploy/Dockerfile.agent -t proxy-control-agent:test .
docker build -f deploy/Dockerfile.ingress -t proxy-control-ingress:test .

test "$(docker run --rm --entrypoint id proxy-control-ingress:test -u)" = 10001
test "$(docker run --rm --entrypoint id proxy-control-ingress:test -g)" = 10001
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

Последняя команда обязана завершиться ошибкой. Если проверка принимает
`/bin/true`, сборка небезопасна и агент должен остановиться.

## Изолированная установка и реальные проверки

Если затронуты установщик, Compose, Dockerfile, Nginx, systemd, резервное
копирование или восстановление, прогоните релизный стенд без production-доступов.

Быстрее всего — одноразовый systemd-контейнер, он работает везде, где есть Docker:

```bash
python3 release/build.py --source . --output dist --version "$(cat VERSION)"
make lab-container \
  RELEASE_ARCHIVE=dist/proxy-control-v$(cat VERSION).tar.gz \
  RELEASE_SHA256=$(awk '/proxy-control-v.*\.tar\.gz$/ {print $1}' dist/SHA256SUMS)
```

Полный цикл — установка, повторная установка, `repair`, восстановление после
перезагрузки, прерванная фаза, отчёт, удаление и сосуществование на общем 443 —
прогоняется на одноразовом сервере:

```bash
LAB_RESET=1 bash scripts/lab/guest-runner.sh host "$RELEASE_SHA256"
```

Эта команда переустанавливает сервер целиком. Запускайте её только на
одноразовой машине и никогда — на рабочей.

Под QEMU те же сценарии доступны через `make lab-prepare`, `make lab-full` и
`make lab-clean`; в режиме TCG прогон может занять больше часа. Отсутствие
времени не является основанием заменять его частичным тестом. Подробности — в
[описании лаборатории](tests/lab/README.md).

В запущенном изолированном стенде проверьте:

- `docker compose ps` и фактический статус `healthy` каждого контейнера;
- `/healthz` панели с правильным `Host`;
- `nginx -t`, локальные слушатели и все соседние SNI;
- MTProxy: Fake-TLS → Obfuscated2 → `req_pq_multi` → `resPQ` → реальный клиент;
- NaiveProxy: cover HTTPS → authenticated `CONNECT` → payload → закрытие
  туннеля → учёт;
- Mieru: точный статус `RUNNING`, TCP/UDP-клиент, manager health и Unix-сокет;
- Fleet: mTLS без клиентского сертификата должен отклоняться, зарегистрированный
  узел должен пройти inventory cycle;
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

# For AI agents

This file is the mandatory operating protocol for AI agents doing development,
validation, deployment, or maintenance on Proxy Control. It is useful to people
too: the same safety rules, written as an algorithm.

If you are simply installing and operating Proxy Control, you do not need this
file — start with the [README](README.en.md).

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
   docker version
   docker compose version
   systemctl is-active docker nginx 2>/dev/null || true
   ss -lntup
   ```

3. Identify the actual change boundary and every connected interface: README,
   Compose, Dockerfiles, systemd, Python API, UI, JavaScript, tests,
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

## Agent dependency setup

In the project checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r panel/requirements-dev.txt
```

Use this `.venv`, not an arbitrary system Python. If a test needs root for
permissions, containers, systemd, or filesystem contracts, run that exact test
with `sudo` without substituting production secrets.

## Mandatory repository checks

After every material change, run the complete gate set:

```bash
.venv/bin/ruff check .
sudo .venv/bin/python -m pytest -q
.venv/bin/python -m unittest -v tests/test_deploy.py
python3 scripts/check-doc-links.py
node --check panel/static/app.js

git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
shellcheck install-bootstrap
for unit in deploy/*.service; do systemd-analyze verify "$unit"; done
git diff --check
```

If a command is unavailable, fails, is skipped, or runs with the wrong
interpreter, report the check as incomplete. Do not replace evidence with an
assumption.

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
FLEET_NODE_ID=node-ci FLEET_CENTRAL_URL=https://fleet.example.com:8790 \
FLEET_CLIENT_CERT=/tmp/client.crt FLEET_CLIENT_KEY=/tmp/client.key \
  docker compose -f compose.yaml -f compose.agent.yaml config -q
FLEET_SERVER_CERT=/tmp/server.crt FLEET_SERVER_KEY=/tmp/server.key \
FLEET_CLIENT_CA=/tmp/client-ca.crt \
  docker compose -f compose.yaml -f compose.fleet-central.yaml config -q
```

Before these commands, create only synthetic `secrets/users.conf`,
`secrets/telemt-api-token`, `secrets/naive-manager-token`,
`secrets/mieru-manager-token`, and `.env` in the isolated checkout following the
CI example. Do not mount real `.env` files, Docker secrets, certificates, or
volumes.

Build all affected images and check runtime identity:

```bash
docker build -f panel/Dockerfile -t proxy-control-panel:test panel
docker build -f mieru_manager/Dockerfile -t proxy-control-mieru-manager:test .
docker build -f deploy/Dockerfile.agent -t proxy-control-agent:test .
docker build -f deploy/Dockerfile.ingress -t proxy-control-ingress:test .

test "$(docker run --rm --entrypoint id proxy-control-ingress:test -u)" = 10001
test "$(docker run --rm --entrypoint id proxy-control-ingress:test -g)" = 10001
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

The final command must fail. If the checker accepts `/bin/true`, the build is
unsafe and the agent must stop.

## Isolated installation and real acceptance checks

If the installer, Compose, Dockerfiles, Nginx, systemd, backup, or restore paths
are touched, run the release lab without production access.

The fastest lab is a disposable systemd container, which runs anywhere Docker
runs:

```bash
python3 release/build.py --source . --output dist --version "$(cat VERSION)"
make lab-container \
  RELEASE_ARCHIVE=dist/proxy-control-v$(cat VERSION).tar.gz \
  RELEASE_SHA256=$(awk '/proxy-control-v.*\.tar\.gz$/ {print $1}' dist/SHA256SUMS)
```

The complete lifecycle — install, a repeated install, `repair`, reboot recovery,
an interrupted phase, reporting, uninstall, and shared-443 coexistence — runs on
a disposable host:

```bash
LAB_RESET=1 bash scripts/lab/guest-runner.sh host "$RELEASE_SHA256"
```

That command reinstalls the whole machine. Run it only on a disposable server,
never on one you care about.

The same scenarios run under QEMU through `make lab-prepare`, `make lab-full`,
and `make lab-clean`; under TCG a run can take more than an hour. Lack of time
is not a reason to replace it with a partial test. See the
[lab description](tests/lab/README.md).

In the running lab, check:

- `docker compose ps` and actual `healthy` status for every container;
- panel `/healthz` with the correct `Host`;
- `nginx -t`, local listeners, and every adjacent SNI route;
- MTProxy: Fake-TLS → Obfuscated2 → `req_pq_multi` → `resPQ` → a real client;
- NaiveProxy: cover HTTPS → authenticated `CONNECT` → payload → tunnel close →
  accounting;
- Mieru: exact `RUNNING` status, TCP/UDP client, manager health, and Unix socket;
- Fleet: unauthenticated mTLS must be rejected, and an enrolled node must
  complete an inventory cycle;
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
