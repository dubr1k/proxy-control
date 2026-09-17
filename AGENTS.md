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
bash scripts/dev/check-js-syntax.sh

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

# Эксплуатационный протокол для ИИ-агентов (v0.6): развёртывание, узлы, доступы, маршрутизация

Часть выше — про **разработку** Proxy Control. Эта часть — про **эксплуатацию**: как агент
разворачивает узел, готовит его к центру, привязывает панели, выдаёт доступы клиентам и
настраивает маршрутизацию — неинтерактивно, с доказательством каждого шага и без единого
секрета в выводе. Человеческое описание тех же операций с картинками и примерами доменов —
[руководство оператора v0.6](docs/releases/v0.6-operator-guide.ru.md); агент обязан прочитать
его перед первым выполнением любого алгоритма ниже.

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
| Compose-проект узла | `/opt/mtproxy-shared443`, проект `mtproxy`, `.env` root-only с `COMPOSE_FILE=…` | `cd /opt/mtproxy-shared443 && sudo docker compose ps --format '{{.Name}} {{.Status}}'` — все `healthy` |
| Панель | контейнер `proxy-control-panel`, `127.0.0.1:8787`, том `panel-data` | `curl -fsS -H 'Host: <panel-domain>' http://127.0.0.1:8787/healthz` |
| Версия и схема базы | `VERSION` в каталоге проекта; `db-status` | `sudo docker exec proxy-control-panel python -m panel.cli db-status` |
| Мастер-ключ | `secrets/panel-master-key` | `sudo docker exec proxy-control-panel python -m panel.cli master-key-verify` (печатает счётчики, не значения) |
| Nginx / 443 | stream-map `/etc/nginx/stream.d/proxy-control.conf` (fresh), TLS панели `127.0.0.1:8443` | `sudo nginx -t && ss -lntp 'sport = :443'` — владелец nginx |
| Сертификаты | `/etc/letsencrypt/live/{proxy-control,naive,three-xui-*}` | `sudo certbot certificates` (без вывода ключей) |
| NaiveProxy | `caddy-naive.service`, `/var/lib/naive-manager/Caddyfile`, `proxy-control-naive-manager` | `systemctl is-active caddy-naive` |
| Mieru | `mita.service`, `/run/mita/mita.sock`, `proxy-control-mieru-manager` | `sudo -u mita env MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status` → ровно `mita server status is "RUNNING"` |
| Xray-router | `proxy-control-xray-router`, `/var/lib/xray-router`, ingress 45101/45102 | `sudo docker exec proxy-control-xray-router python -m xray_router_manager.healthcheck --status` → `phase == "idle"`, `artifacts.*.verified == true` |
| WARP | `warp-svc`, SOCKS5 `127.0.0.1:40000` | `warp-cli status`; `curl -s --proxy socks5h://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace \| grep '^warp='` |
| 3x-ui (managed) | `x-ui.service`, панель `127.0.0.1:8451`, inbound 8449/8450, UDP/443 | `systemctl is-active x-ui && ss -lntup \| grep -E ':(8449\|8450\|8451)\b'` |
| version-agent | `version-agent.service`, `/run/proxy-control/version-agent.sock` | `sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health` |
| Установщик | журнал `/var/lib/proxy-control/installer/state.json`, отчёты `/var/lib/proxy-control/reports` | `sudo python3 -m installer.cli status --json` (из распакованного релиза) |
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

Входные данные от владельца: класс хоста, домены (§3 руководства), профиль, нужны ли WARP /
Xray-router / 3x-ui, ACME-почта, имя владельца. Пароль владелец вводит сам или его генерирует
установщик — агент пароль не выбирает и не печатает.

```bash
# A1. Скачать и проверить без root (или scripts/install-release.sh --version … --sha256 … --no-wizard)
ver=0.6.0-beta.1; lab=<lab-sha256 из заметки о выпуске>
for f in proxy-control-v$ver.tar.gz SHA256SUMS release-manifest.json sbom.spdx.json; do
  curl -fsSLO "https://github.com/dubr1k/proxy-control/releases/download/v$ver/$f"; done
sha256sum --check SHA256SUMS && test "$(sha256sum proxy-control-v$ver.tar.gz | cut -d' ' -f1)" = "$lab" && echo ARCHIVE_OK
tar -xzf proxy-control-v$ver.tar.gz && cd proxy-control

# A2. Конфигурация — TOML по §4.3 руководства (пример полного узла там); пароль — НЕ в TOML.
#     Пароль владельца, если задан заранее: приватный файл рядом с TOML (installer.credentials), 0600.
cat > /root/proxy-control.toml <<'TOML'
… (см. руководство §4.3)
TOML
chmod 600 /root/proxy-control.toml

# A3. План: ничего не меняет; digest — из JSON, не из глаз. Жёсткая остановка аудита (DNS/CAA/443/порт/UID/x-ui)
#     = ненулевой код выхода и текст причины → СТОП, отчёт владельцу: это его решения.
if sudo python3 -m installer.cli plan --config /root/proxy-control.toml --json > /root/plan.json; then echo PLAN_OK; else echo PLAN_REFUSED; fi
digest=$(python3 -c 'import json;print(json.load(open("/root/plan.json"))["digest"])')
python3 -c 'import json;p=json.load(open("/root/plan.json"));print([a["id"] for a in p["actions"]])'   # какие адаптеры и что они сделают

# A4. Установка ровно этого плана; успешная транзакция оставляет поколение в статусе active
sudo python3 -m installer.cli install --config /root/proxy-control.toml --accept-plan "$digest" --json > /root/install.json
python3 -c 'import json;r=json.load(open("/root/install.json"));print(r["status"], r.get("error"))'   # ожидается: active None
sudo python3 -m installer.cli status --json | python3 -c 'import json,sys;s=json.load(sys.stdin);print(s["status"], s["plan_digest"][:12], sum(1 for c in s["checkpoints"] if not c["success"]))'   # active <digest> 0
```

Проверка (все команды обязаны пройти; иначе — `resume`/`repair` по §4.8 руководства, а не повтор `install` вслепую):

```bash
cd /opt/mtproxy-shared443 && sudo docker compose ps --format '{{.Name}} {{.Status}}' | grep -vc healthy   # ожидается 0
curl -fsS -H "Host: $PANEL_DOMAIN" http://127.0.0.1:8787/healthz && echo PANEL_OK
sudo nginx -t && ss -lntp 'sport = :443' | grep -q nginx && echo NGINX_443_OK
curl -sSI "https://$PANEL_DOMAIN/login" | head -1                       # HTTP/2 200
curl -sS -o /dev/null -w '%{http_code}\n' "https://$PANEL_DOMAIN/s/x"    # 404 на домене панели
systemctl is-active caddy-naive mita 2>/dev/null                          # по профилю
sudo python3 -m installer.cli report --config /root/proxy-control.toml --output /var/lib/proxy-control/reports
sudo python3 -c 'import json;r=json.load(open("/var/lib/proxy-control/reports/report.json"));print(sorted(r))'  # только факты приёмки; учётные данные в отчёте не бывают
```

Отчёт владельцу: домены, профиль, digest плана, `VERSION`, статус контейнеров/служб,
где лежат учётные данные (пути `<конфиг>.credentials` / `secrets/panel-bootstrap-password`, не
содержимое; для managed 3x-ui — напоминание, что пароль и web base path без явного ввода в
мастере не сохраняются, см. руководство §4.6), какие ручные приёмки остались (реальный клиент
Telegram, вход в панель человеком).

## 3. Алгоритм B — подготовить узел к центру

```bash
# B1. Ключ node-sync (только владелец; через ключ admin узла или сессию владельца)
resp=$(curl -sS "${hdr[@]}" -X POST "$NODE/api/keys" -d '{"name":"central","scope":"node-sync"}')   # 201 {"key": {id, name, prefix, scope, …}, "plaintext": "pc_…"}
python3 -c 'import json,sys;d=json.loads(sys.argv[1])["key"];print(d["id"],d["prefix"],d["scope"])' "$resp"   # печатать id/prefix/scope, НИКОГДА plaintext
NODE_SYNC_KEY=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["plaintext"])' "$resp"); unset resp   # только в переменную; передаётся центру в C2 и нигде не выводится
# B2. Идентичность узла, как её увидит центр
curl -sS -H "Authorization: Bearer $NODE_SYNC_KEY" "$NODE/api/fleet/v2/identity" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["guid"],d["panel_version"],d["master_guid"],sorted(d["capabilities"]))'
#   master_guid должен быть null (никем не управляется); panel_version — та же сборка, что у центра
# B3. (по желанию) version-agent — §6.2 руководства; проверка: /v1/health по сокету
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
# E2. Черновик → предпросмотр (ничего не меняет). Политика — по §8 руководства; backend опускается (текущий цели)
policy='{"default_action":"egress","default_egress":"warp","fallback":"fail_closed","rules":[{"enabled":true,"action":"block","match":{"domains":["ads.example.com","*.ads.example.com"]},"note":"ads"}]}'
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/policies/$node_id/naive/preview" -d "$policy" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["status"],[(r["code"],r.get("rule_id")) for r in d["reasons"]],d["warnings"],d["restart_required"],d["backend"])'
#   status != supported → СТОП; коды и что делать — §8.6 руководства (provider_unavailable, rule_kind_unsupported, not_attached, …)
# E3. Сохранить (revision) → применить ровно эту revision (только owner)
rev=$(curl -sS "${hdr[@]}" -X PUT "$PANEL/api/routing/policies/$node_id/naive" -d "$policy" | python3 -c 'import json,sys;print(json.load(sys.stdin)["revision"])')
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/policies/$node_id/naive/apply" -d "{\"expected_revision\":$rev}" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["state"],d.get("applied_revision"),d.get("last_error"))'
#   локальный узел: applied сразу; связанный: applying → applied после отчёта узла (один heartbeat): опрашивать GET …/policies/$node_id/naive
# E4. Xray-router: подключить сервис ДО политики с geosite/geoip/портами (owner; сессии сервиса прервутся — согласовать с владельцем)
curl -sS "${hdr[@]}" -X POST "$PANEL/api/routing/targets/$node_id/naive/attach" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["backend"],d["router"])'
#   отказ policy_applied → сначала PUT политики "напрямую без правил" + apply, затем attach
# E5. Откат — предыдущая запись менеджера/предыдущий документ: POST …/rollback {"expected_revision":<rev>}
```

Проверка после apply (на узле, по SSH): `docker compose logs --since=5m naive-manager` без ошибок; в
`/var/lib/naive-manager/Caddyfile` блок `# BEGIN NAIVE-MANAGER EGRESS … # END` с ожидаемым `upstream`
(ключи ingress роутера в выводе **маскировать**: `sed 's#socks5://[^@]*@#socks5://***@#'`); для Mieru —
`systemctl is-active mita` и секция `egress` в конфиге; `curl --proxy https://<naive-домен> --proxy-user
<тестовый пользователь>` к заблокированной цели → отказ, к разрешённой → 200 (тестовый пользователь создаётся
для проверки и удаляется). `GET /api/audit?action=routing.policy.apply` содержит строку с целью политики.

## 7. Алгоритм F — обновление, откат, резервная копия

- **Обновление узла** (после того как гейт релиза зелёный, а владелец разрешил): точка отката
  (образы `*:rollback-<UTC>`, online-backup базы, `secrets/`, `.env*`), затем новый релиз по алгоритму A
  на том же TOML (`install` перерисовывает своё, данные сохраняются), `db-status`, `VERSION`,
  все проверки §2; порядок парка — **узлы, затем центр**. Панель на старой сборке отвергает
  документ поколения с новыми полями (422) — центр ждёт в backoff.
- **Обновление компонента** (Telemt/Caddy/mita) — только через version-agent:
  `GET /api/versions` → `POST /api/versions/{component}/update {"version":…, "expected_current":…}`
  (на центре для узла — `POST /api/nodes/{id}/versions/{component}`); `409` при несовпадении
  `expected_current`; `rollback_failed` блокирует компонент до вмешательства человека.
- **Откат** — полная предыдущая генерация вместе с базой (образ старой версии не стартует на
  новой схеме); управляемый узел перед откатом отвязать (`POST /api/nodes/local/unlink` на узле,
  затем `DELETE /api/nodes/{id}` на центре после удаления его доступов).
- **Резервная копия** — `docs/BACKUP_RESTORE.ru.md`; образец сценария, который делает
  бэкап → разрушение → восстановление → сверку digest'ов: `scripts/lab/backup-restore-drill.py`
  (запускается сценарием `backup-restore` `lab-host`; на боевом хосте — только «бэкап» его
  части, никогда «разрушение»).

## 8. Изменение кода: что добавилось в гейт с v0.6

К набору из части «Обязательные проверки репозитория» добавились:

- `scripts/dev/route-coverage.py` — каждый маршрут панели имеет gate (роль/мутация/ключ),
  публичных ровно 7, каждый упомянут тестом; новый маршрут без теста ломает `full`.
- **Матрица сверки** `tests/fixtures/verification-matrix.json` ↔ `docs/VERIFICATION_MATRIX.md`
  (`scripts/dev/verification-matrix.py --render|--check`, тест `tests/test_verification_matrix.py`):
  каждый маршрут и каждый экран обязан иметь строку с существующим доказательством
  (`pytest::файл::тест`, `lab-host::сценарий`, `ui::экран.проверка`, `fleet::шаг`, …); на
  релизном гейте `VERIFICATION_STRICT=1` запрещает статус `gap`. Новая функция = строка матрицы
  + доказательство, иначе тест-страж падает.
- **Tier `ui`** (`scripts/dev/remote-gate.sh ui` → `scripts/lab/ui-acceptance.py`): настоящий
  headless Chrome по CDP на лабораторном узле — каждый экран, обе роли, центр во втором
  экземпляре панели, проверка секретов в кадрах (`SECRET_SHAPES`), пересечения ячеек
  (`cells_do_not_overlap`) и ошибок консоли. Правка UI без проверки в этом tier'е не считается
  проверенной; скриншоты выпуска — только из этого прогона, только стендовые данные, ≤150 КБ,
  без метаданных, и агент обязан **посмотреть каждый кадр** перед публикацией.
- **Tier `managed-xui`** — реальный 3x-ui на стенде; **сценарий `backup-restore`** в `lab-host`.
- Порядок tier'ов релизного гейта на лабораторном хосте (все `REMOTE_GATE_*_OK`): `full`
  (с `VERIFICATION_STRICT=1`) → `compose` → `lab-container` → `lab-host` без `KEEP_INSTALL`
  (uninstall, coexistence) → `lab-host` с `LAB_KEEP_INSTALL=1` → `fleet` → `routing` → `router` →
  `ui` → `managed-xui`; `compose` не запускать параллельно с `lab-host` (снапшоты Docker).
- Публикация (только по поручению владельца): архив дважды из чистого клона на лабораторном
  хосте (`release/build.py`, байты равны) → аннотированный тег с `lab-sha256: <digest>` →
  push ветки и тега → workflow `Release` → `SHA256SUMS` = стендовые, `gh attestation verify` →
  тело релиза из заметки с абсолютными ссылками. Merge в `main` и раскатка — решения владельца.

## 9. Таблица «код отказа → действие агента»

| Откуда | Код | Действие |
| --- | --- | --- |
| установщик `plan` | `hard_stops` (DNS/CAA/443/порт/UID/x-ui) | стоп; владельцу — список, это его решения |
| установщик `install` | фаза не `done` | `status --json` → `resume`; не повторять `install` вслепую |
| `POST /api/nodes/test` | `node_unreachable` (502) | DNS/443/сертификат узла; `curl -sSI https://<узел>/login` |
| | `node_auth_failed` | ключ не `node-sync` этого узла или отозван — новый ключ (алгоритм B) |
| | `foreign_master` / `already_linked` / `same_panel` | стоп, владельцу |
| push поколения | `stale_generation` / `digest_conflict` | центр сам переиздаёт; ничего не делать, наблюдать `observed` |
| | `secret_store_disabled` | на узле нет мастер-ключа — `master-key-init` по UPGRADING v0.2 (владелец) |
| | 422 | узел на старой сборке — обновить узел до сборки центра |
| ресурс поколения | `failed: runtime user exists and is not managed` | коллизия с локальным пользователем — другое имя или импорт вместо выдачи |
| операция выдачи | `compensated` | причину в `GET /api/operations/{id}`; повторить с новым именем |
| | `manual_intervention_required` | стоп; владельцу id; `POST …/resume` только после его решения |
| протокол-API узла | 409 `managed_by_central` | ресурс принадлежит центру — менять на центре |
| маршрутизация | `unsupported` + причины | §8.6 руководства; ничего не применять |
| | 409 `policy_conflict` | перечитать `revision`, повторить PUT |
| | 503 `manual_intervention_required` | стоп; резервные копии менеджера; владельцу |
| | `artifact_mismatch` | бинарь/geodata роутера не совпадают с пином — не чинить самому, владельцу |
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

This file is the mandatory operating protocol for AI agents doing development,
validation, deployment, or maintenance on Proxy Control. It is useful to people
too: the same safety rules, written as an algorithm.

If you are simply installing and operating Proxy Control, you do not need this
file — start with the [README](README.en.md).

The **operations protocol for agents** (deploying a node non-interactively, preparing
and linking nodes, issuing grants, routing, upgrades, the v0.6 gate additions and the
refusal-code table) is in the Russian part above, «Эксплуатационный протокол для
ИИ-агентов (v0.6)»; the human-facing walkthrough is
[docs/releases/v0.6-operator-guide.ru.md](docs/releases/v0.6-operator-guide.ru.md).

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
bash scripts/dev/check-js-syntax.sh

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
