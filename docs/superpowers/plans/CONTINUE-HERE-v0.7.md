# CONTINUE HERE — v0.7 (цепи и полосы)

Состояние на 2026-09-18 11:20 UTC, ветка `feature/vnext-v0.7-chains`, последний коммит `eaa37a5`.
Спека: `docs/superpowers/specs/2026-09-17-v0.7-chains-design.md`, план:
`docs/superpowers/plans/2026-09-17-v0.7-chains.md` (галочки актуальны, Tasks 0–13 закрыты).

## Что уже доказано

- **Гейт на стенде зелёный** (ams-test), по частям и на разных деревьях:
  - `bbcab08`: `fleet` 84/84 (198,9 с), `routing` 154/154 (302,1 с), `router` 242/242 (472,8 с),
    `chains` **277/277** (35 c01…c10, 531,3 с), `ui` 197/197, `managed-xui` OK,
    `full` 2283 passed/3 skipped, `compose`, `lab-container`, `lab-host` без и с KEEP;
    `lab-sha256` `a2dc937903b01ee61f613776c123f7de85b911dec34d08683d039c19a96ab0ee`.
  - `41ec41e`: `full` 2285 passed, `compose`, `lab-container`, `lab-host` без KEEP (20 `passed`)
    и с KEEP (18 `passed`), `ui` 197/197 (155,8 с) — `lab-sha256` `920be8f8c927f77d3…`.
  - `130a8a0`: `full` 2287 passed, `lab-host` без KEEP — `lab-sha256` `983dc49ab98f41fd2…`.
- **Заметка о выпуске** `docs/releases/v0.7.0-beta.1.md`: таблица гейта заполнена, 14 скриншотов
  tier'а `ui` лежат в `docs/releases/assets/v0.7.0-beta.1/` (≤150 КБ, без метаданных).
- **Настоящая установка ams-test по TOML владельца прошла** (`/root/install-v07.toml` =
  `/root/install.toml` + `[egress] warp=false, router=true, naive/mieru="router"` +
  `[three_xui] subscription_domain = "zenith.sky.dubr1kkk.uk"`): статус `active`, 14 действий,
  роутер с relay 45443 и четыре слота `mita@1…4` (46101…46104) в UFW, `VERSION` 0.7.0-beta.1.

## Что нашла настоящая установка (исправлено в ветке, доказательства — тесты)

1. `8fbf13d` — `plan` правил `nginx.conf` (контекст `stream` у стокового Nginx) **при
   планировании**, поэтому аудит в digest расходился с хостом и `install --accept-plan`
   отказывал собственному плану. Теперь план только называет шаг (`stream_context=create`),
   контекст добавляет `apply`. Там же: `host-teardown.sh` снимает юниты слотов `mita@<n>`.
2. `130a8a0` — пробное продление сертификата валило установку на `orderNotReady` (гонка
   certbot 2.9 ↔ Boulder); повторяется один раз, как и «authorization must be pending».
3. `eaa37a5` — **общий роутер 443 не нёс ни одного маршрута 3x-ui**: панель, сервер подписок и
   оба входа VLESS отвечали только на loopback, домены попадали на vhost нашей панели. Адаптер
   Nginx планирует их вместе с остальными (тесты `test_installer_nginx.py`).
4. `41ec41e` — системные события журнала (`subscription.fetched|revoked|generation.changed`,
   `node.up|down`) показывались кодами: подписи + `docs/AUDIT_EVENTS.md`.
5. `eaa37a5` — знак бренда: логотип продукта вместо эмодзи (вырезан из рамки, прозрачные углы),
   полоса «443 ♥» в боковой панели, картинка целиком на экране входа, favicon.

## Что осталось (по порядку)

### 1. Гейт на финальном дереве `eaa37a5`

Все tier'ы заново — менялись установщик (маршруты 3x-ui), панель (журнал, логотип) и лаборатория:

```
VERIFICATION_STRICT=1 scripts/dev/remote-gate.sh full
scripts/dev/remote-gate.sh compose
scripts/dev/remote-gate.sh lab-container
LAB_RESET=1 LAB_KEEP_INSTALL=0 scripts/dev/remote-gate.sh lab-host
LAB_RESET=1 LAB_KEEP_INSTALL=1 scripts/dev/remote-gate.sh lab-host
scripts/dev/remote-gate.sh fleet | routing | router | chains | ui | managed-xui
```

Длинные прогоны — отсоединённо, с опросом лога (память `proxy-control-ams-test-lab-host`).
После `ui` **переснять скриншоты**: знак бренда изменился на всех 14 кадрах
(`scp ams-test:/root/dev/proxy-control/lab-results/ui/*.png`, палитра ≤150 КБ, без метаданных,
каждый кадр просмотреть). Обновить таблицу гейта и `lab-sha256` в заметке.

### 2. Живая проверка узла (ams-test, настоящая установка владельца)

```
ssh ams-test 'LAB_RESET=1 bash /tmp/proxy-control-release/proxy-control/scripts/lab/host-teardown.sh'
ssh ams-test 'bash /root/ams-test-install-v07.sh'        # plan → digest → install, лог /root/v07-install.log
ssh ams-test 'python3 /root/live-node-v07.py aurora.sky.dubr1kkk.uk eclipse.sky.dubr1kkk.uk \
    zenith.sky.dubr1kkk.uk /root/install-v07.credentials /root/v07-live/node-sync.key \
    /root/v07-live/node-report.json'
```

`live-node-v07.py` (на хосте и в scratchpad сессии) проверяет: relay и четыре слота от
установщика, подписку нашей панели **на десятом домене** (`eclipse`, на панельном домене 404),
полосу Mieru (ссылка и подписка переезжают на порт слота 46101 и обратно), подписку 3x-ui на
`zenith`, и выдаёт ключ `node-sync` для центра. Свой клиент и полосу убирает за собой.

### 3. Живая проверка центра (AMS_Z → ams-test)

AMS_Z сейчас на v0.6.0-beta.1 без роутера; точки отката v0.6 — `/root/v06-live/`.

```
scp <scratchpad>/ams-z-prep-v07.sh AMS_Z:/root/ && ssh AMS_Z 'sudo bash /root/ams-z-prep-v07.sh'
# rsync panel/ naive_manager/ mieru_manager/ xray_router_manager/ installer/ compose*.yaml
#       deploy/ scripts/ VERSION release/  →  /opt/mtproxy-shared443 (см. память deploy-targets)
ssh AMS_Z 'sudo docker compose … up -d --build --wait panel naive-manager mieru-manager'
scp <scratchpad>/live-v07.py AMS_Z:/root/v07-live/ && ssh AMS_Z 'sudo python3 /root/v07-live/live-v07.py \
    api.dubr1k-kawai.uk edge.dubr1k-kawai.uk <файл пароля> https://aurora.sky.dubr1kkk.uk \
    <файл ключа node-sync с ams-test> /root/v07-live/report.json'
```

Скрипт ставит роутер адаптером (`relay_port=0`, `lane_slots=2`, UFW 46101/46102), подключает
naive+mieru с политикой сервиса `egress: warp` (как было), связывает ams-test, включает его relay,
создаёт временного клиента, включает полосы, применяет правило `api.ipify.org → node:<ams-test>`,
проверяет выходные IP и маскировку UUID, затем убирает своего клиента. Роутер, связь и relay
остаются владельцу. Заполнить «Живая проверка» в заметке (RU и EN).

### 4. Публикация

Две сборки из чистого клона на стенде (байты совпали) → аннотированный тег `v0.7.0-beta.1`
с `lab-sha256: <digest>` → push ветки и тега → workflow `Release` (собирает дважды, сверяет с
`lab-sha256`, attestation) → `gh attestation verify` → тело релиза из заметки →
**проверить описание релиза и README** (поручение владельца) → обновить `CONTINUE-HERE` и память
(`proxy-control-vnext-v07-branch`, `proxy-control-deploy-targets`, `proxy-control-ams-test-lab-host`).

Слияние в `main` и раскатка на остальные боевые хосты — решение владельца.

## Подводные камни стенда

Длинные прогоны — только отсоединённо (`setsid nohup`, опрос лога); `pgrep -f` по
`xray_router_manager` ловит менеджер **установленного** узла (cwd `/app`) — фильтровать по cwd;
`node-b.lab.test` должен быть в `/etc/hosts` до создания контейнеров; `host-teardown.sh` нужен
перед каждой настоящей установкой (`fresh` отказывает при живом лабораторном роутере).
