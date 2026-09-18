# CONTINUE HERE — v0.7 (цепи и полосы)

Состояние на 2026-09-18 00:xx UTC, ветка `feature/vnext-v0.7-chains`, последний коммит — см. `git log -1`.
Спека: `docs/superpowers/specs/2026-09-17-v0.7-chains-design.md`, план:
`docs/superpowers/plans/2026-09-17-v0.7-chains.md` (галочки актуальны).

## Сделано (Tasks 0–13 закрыты, всё на `ams-test`)

- Роутер: intent схемы 2 (полосы + цепи), relay-inbound (vless+reality), API полос/relay, проверка
  хопов, атомарное снятие полосы, старт/откат вычищают полосы без учётки.
- Менеджеры: naive — блок LANES (обработчик на полосу), mieru — слоты `mita@<n>` (свой
  `/var/lib/mita` через BindPaths), `service_share_template`.
- Панель: модель (выход `warp | node:<guid>[,…][:warp]`, `lane` в ключе политики, миграция 16),
  компилятор, `RelayRegistry`/`ChainResolver`/`LaneService`, API (`/api/routing/lanes/{grant}`,
  `?lane=`, `explain`, `relay/{node}/enable|rotate`), UUID хопов маскируются; Fleet v2 (секция
  `relay`, `lane` ресурса, отчёт `observed.relay`, узел строит полосы сам); UI («Выходы узла»,
  вкладки полос, «Куда», «Куда пойдёт…», переключатель на «Клиентах»).
- Установщик: `[egress] relay_port` (45443), `[mieru] lane_slots` (4), UFW, `mita@.service`.
- Лаборатория: tier `chains` (узел B из дерева, отсоединённый прогон) — **273/273**;
  `lab-host` KEEP — зелёный на дереве v0.7; `ui` — **197/197** (полосы в браузере, кадр
  `routing-lane-applied.png` просмотрен). Матрица 64 строки без `gap`.
- Документация: ROUTING (RU/EN) «Цепи и полосы», XRAY_ROUTER, INSTALLER_REFERENCE, UPGRADING
  v0.6→v0.7, ADR 009, руководство оператора §8.8, AGENTS E6 + коды, индекс docs.

## Где остановились (Task 14 — живая проверка AMS_Z → ams-test)

- **ams-test сейчас без установки**: лабораторная установка снесена `host-teardown.sh`
  (LAB_RESET=1) под настоящую установку по TOML владельца; настоящая установка **не выполнена**:
  `install --accept-plan <digest из plan --json>` отказал `BLOCKED: accepted plan digest does not
  match` (лог `/root/v07-install.log`, план `/root/v07-plan.json`, конфиг
  `/root/install-v07.toml` = `/root/install.toml` + `[egress] warp=false, router=true,
  naive="router", mieru="router"`, credentials `/root/install-v07.credentials`). Следующий шаг:
  проверить, стабилен ли digest плана между двумя `plan --json` подряд (если нет — найти
  недетерминизм в `audit_facts`/плане; если да — план мог измениться из-за состояния хоста после
  teardown, взять digest свежего `plan` непосредственно перед `install`). Релиз в
  `/tmp/proxy-control-release/proxy-control` собран из дерева (`dist/`, sha256 `eb43b167…`).
- **AMS_Z не тронут** (v0.6.0-beta.1 без роутера, `/root/v06-live/` — точки отката v0.6).
  Модель живой проверки — `/root/v05-live/router-live.py` (копия в scratchpad этой сессии не
  сохранилась; читать с хоста). Для v0.7: точки отката `/root/v07-live/<ts>/` (БД online-backup,
  tar кода, теги образов, Caddyfile, `mita describe config`, `.env`, `docker ps`) → rsync
  `panel/ naive_manager/ mieru_manager/ xray_router_manager/ installer/ compose*.yaml deploy/
  scripts/ VERSION release/` → `docker compose up -d --build --wait panel naive-manager
  mieru-manager` → миграция 16 → роутер через `XrayRouterAdapter` (relay_port=0 на AMS_Z как
  источнике, `lane_slots=2`; UFW 46101/46102 для Mieru-полос) → attach naive/mieru + политика
  сервиса `egress: warp` (сегодня весь трафик идёт через privoxy→WARP `http://127.0.0.1:8118` в
  Caddy и `warp` в mita — поведение сохранить) → ключ `node-sync` на ams-test → `POST
  /api/nodes/link` с AMS_Z → `POST /api/routing/relay/<ams-test>/enable` → тестовый клиент
  `live-lane-*` на AMS_Z (naive+mieru) → полоса → политика `warp` по умолчанию + правило
  `geosite:… → node:<ams-test>` → проверка curl через naive AMS_Z (IP выхода = ams-test / WARP
  AMS_Z) → подписка на **десятом домене** ams-test (`/s/{token}` только там, панельный домен
  404; ссылка/подписка Mieru с портом слота) → тестовые доступы снять, роутер/связь/relay
  **оставить** владельцу.
- Порядок с гейтом: финальный гейт (`full` с `VERIFICATION_STRICT=1`, `compose`, `lab-container`,
  `lab-host` без и с KEEP, `fleet`, `routing`, `router`, `chains`, `ui`, `managed-xui`) переустанавливает
  ams-test как лабораторный узел — делать его **до** настоящей установки ams-test для владельца,
  затем живую проверку, затем VERSION/CHANGELOG/заметку/тег (как в v0.6: дерево тега отличается
  от дерева гейта только документами).

## Task 15 — релиз (не начат)

`VERSION` 0.7.0-beta.1, CHANGELOG en/ru, `docs/releases/v0.7.0-beta.1.md` (RU/EN, по образцу v0.6:
чек-лист гейта, скриншоты из tier `ui` ≤150 КБ без метаданных, «Живая проверка»),
`COMPATIBILITY.md`, README, индекс; публикация по пути v0.4–v0.6 (два сборки из чистого клона на
стенде, `lab-sha256` в аннотации тега, workflow Release, `gh attestation verify`); после публикации —
проверить описание релиза и README (поручение владельца). Известное ограничение для заметки:
UUID relay в compiled-документах хранятся в БД панели открытым текстом (ADR 009).

## Подводные камни стенда (см. память `proxy-control-ams-test-lab-host`)

Длинные прогоны — только отсоединённо (`setsid nohup`, опрос лога); `pgrep -f` по
`xray_router_manager` ловит менеджер **установленного** узла (cwd `/app`) — фильтровать по cwd;
после прерванного прогона naive остаётся подключённым к роутеру — detach на узле со свежим CSRF
после логина; `node-b.lab.test` должен быть в `/etc/hosts` до создания контейнеров.
