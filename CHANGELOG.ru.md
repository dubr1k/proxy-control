# Журнал изменений

Русская версия журнала в формате [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/).
Ведётся с v0.4; записи о более ранних выпусках (v0.3.0-beta.1, v0.2.0-beta.1, v0.1.0 и
история до переписывания) — в английском [CHANGELOG.md](CHANGELOG.md), который остаётся
основным. Заметки о выпусках с чек-листом гейта и живой проверкой — `docs/releases/`.

## [Unreleased]

## [0.5.0-beta.1] - 2026-09-16

Xray-router: на узле может работать один выделенный закреплённый процесс Xray как egress-роутер
для NaiveProxy и Mieru. Сервис, который оператор к нему подключил, отправляет весь трафик через
приватный аутентифицированный loopback-ingress роутера, и его политику маршрутизации
применяет уже Xray — с селекторами `geosite`, `geoip` и портами и с блокировкой рядом с WARP по
умолчанию, чего нативные backend'ы не умеют. Он необязателен, не трогает Xray из 3x-ui, а узел
без него ведёт себя ровно как в v0.4. [ADR 007](docs/adr/007-routing-enforcement-ownership.md)
принят для роутера; спека — `docs/superpowers/specs/2026-09-16-v0.5-xray-router-design.md`, spike,
доказавший каждую ячейку на стенде, — `docs/spikes/XRAY_EGRESS_ROUTER.md`;
[XRAY_ROUTER](docs/XRAY_ROUTER.ru.md), [ROUTING](docs/ROUTING.ru.md),
[релизная заметка](docs/releases/v0.5.0-beta.1.md). Это последняя стадия vNext: фаза 8
(backup/restore, матрица негативных тестов, замороженные идентификаторы) закрывается здесь.

### Добавлено

- **Закреплённый артефакт `xray`** (Xray-core 26.3.27, `Xray-linux-64.zip`, MPL-2.0) в
  `release/external-artifacts.json` с дайджестом архива и каждого из трёх членов, которые
  извлекает установщик (`xray`, `geoip.dat`, `geosite.dat`); `installer.release.safe_extract_zip`
  пишет ровно проверенные члены через ту же подмену через приватный stage, что и tar-экстрактор,
  с границами и проверкой дайджестов; SBOM перечисляет члены. Архив оператор кладёт в
  `/var/lib/proxy-control/`; ничего не скачивается.
- **`xray_router_manager`** — рантайм роутера: контейнер `proxy-control-xray-router`
  (`compose.xray-router.yaml`, сеть хоста, identity 10006, read-only, `cap_drop: ALL`),
  супервизор над одним дочерним `xray run` с поколениями, посервисным журналом и типизированным
  egress API на собственном UDS (`/v1/status`, `/v1/health`, `/v1/egress/{naive|mieru}` и
  `plan | apply | rollback`; заголовок `X-Xray-Router-Token`). Применение рендерит один конфиг из
  intent'ов обоих сервисов, гоняет `xray run -test`, подменяет, читает обратно и коммитит; сбой
  возвращает последнее хорошее поколение, умерший дочерний процесс перезапускает watchdog, бинарь
  или geodata с неверным дайджестом держит роутер выключенным (`artifact_mismatch`). Два SOCKS5-ingress
  на loopback (`naive` 45101, `mieru` 45102) с посервисным ключом как идентичностью сервиса;
  `geoip:private → block` первым правилом каждого ingress и резолв `IPOnDemand`, чтобы
  перепривязанное имя не достало хост; UDP не ретранслируется.
- **Провайдер `router` у менеджеров**: naive-manager рисует `upstream
  socks5://user:password@127.0.0.1:45101` из `NAIVE_EGRESS_ROUTER` и файла ключа в своём каталоге
  состояния, mieru-manager — `egress` mita с `socks5Authentication` из `MIERU_EGRESS_ROUTER`; оба
  пробуют ingress методом username/password SOCKS5 до применения, маскируют ключ в каждом
  представлении и diff'е и перерисовывают свой блок на старте после ротации ключа
  (`router_credential_stale` до того), включая семя установщика.
- **Backend маршрутизации `xray_router`** (миграция 15): `RuleMatch` получает `geosites` и `geoips`
  (коды geodata Xray; `private` отвергается) и правила только с портами; компилятор строит для
  подключённого сервиса типизированный intent роутера — никогда не сырой JSON Xray — и называет
  роутер, когда нативный backend не может выполнить правило; `Compiled.compiler_version` — `"2"`.
- **Подключение и отключение** как явные действия owner (`POST
  /api/routing/targets/{node}/{protocol}/attach | detach`, аудит `routing.target.attach |
  detach`): сначала секция роутера (pass-through), затем нативный блок на ingress; отключение — в
  обратном порядке. Политика переносится черновиком; `targets[].router = {available, attached,
  xray_version, …}`. Отказы: `router_unavailable`, `router_unreachable`, `not_attached`,
  `node_lacks_router`, `artifact_mismatch`, `geosite_unknown`, `geoip_unknown`.
- **Fleet v2**: узел объявляет `egress.router.v1` и `identity.router`; секция `egress` поколения
  может нести `backend: xray_router`, `companion`-документ для другого менеджера и `passthrough` —
  всё опускается из проводной формы и digest при отсутствии, поэтому узел v0.4 и центр v0.4
  сохраняют каждый digest и игнорируют незнакомое; pusher записывает ревизию роутера рядом с
  нативной.
- **Установщик `[egress] router`** с выбором `router` для `naive` / `mieru`: адаптер `xray_router`
  (между `warp` и сервисами) проверяет положенный архив, извлекает члены, создаёт identity 10006,
  готовит `/var/lib/xray-router`, пишет токен менеджера и два ключа ingress (root:10006 0440),
  `.env.xray-router` и поднимает сервис; проверка читает статус менеджера, убеждается, что оба
  ingress только на loopback, и пропускает один аутентифицированный CONNECT через ingress NaiveProxy.
  `naive` и `mieru` узнают о роутере через свой env и держат собственные копии ключей; мастер
  спрашивает про роутер, только когда архив положен. `scripts/rotate-xray-router-ingress.sh`
  ротирует ключи и пересоздаёт роутер и менеджеры; `scripts/prepare-xray-router-state.sh` владеет
  каталогом состояния.
- **UI «Маршрутизация»**: бейдж backend (Caddy / mita / Xray-router), строка роутера с кнопками
  «Подключить к Xray-router» / «Отключить от Xray-router» и подтверждениями, поля geosite / geoip /
  порты в правиле, причины и предупреждения роутера в предпросмотре.
- **Tier лаборатории `router`** (`remote-gate.sh router`, `fleet-acceptance.py --router`):
  router-01…14 на узле, установленном с `[egress] router = true` — подключение, весь сервис через
  WARP и блокировка рядом через роутер, правила по порту / geosite / geoip, неизвестный код geodata,
  отвергнутый Xray, Mieru с выборочным правилом, отказ ingress без ключа и с чужим ключом, откат при
  нетронутом Caddyfile, watchdog после SIGKILL, fail-closed без провайдера, ни одного ключа в API,
  аудите, базе и логах, ротация ключей, отключение и нетронутый хост. `lab-host` ставит роутер по
  умолчанию.
- **Фаза 8**: `docs/SECURITY_TEST_MATRIX.md` сопоставляет каждую строку матрицы негативных тестов
  vNext с тестом или сценарием лаборатории; `BACKUP_RESTORE` получает состояние и секреты роутера;
  `tests/test_deploy.py` замораживает идентификаторы роутера и доказывает, что ничто в нём не
  называет пути 3x-ui; [COMPATIBILITY](docs/COMPATIBILITY.md) фиксирует, что v0.5 заморозил.

### Изменено

- **Фикс-волна замечаний v0.4**: naive-manager маскирует userinfo рукописного `upstream` в egress-
  представлениях и diff'ах `plan`; мёртвый `installer.planner.profile_environment` удалён.
- Список файлов состояния naive-manager (`prepare-naive-state.py`) допускает `xray-router-ingress`;
  restart-транзакция `egress.refresh` mieru-manager перерисовывает посеянную секцию роутера после
  ротации; Core считает секреты и Compose-сервис роутера соседними (repair, владение).
- Экран маршрутизации шлёт `backend` вместе с политикой, чтобы новая политика рождалась на том
  backend'е, который её применит.

### Безопасность

- Ключ ingress живёт только в файлах секретов, копиях менеджеров, `upstream` Caddy,
  `socks5Authentication` mita и отрендеренных поколениях роутера; каждое API-представление, diff
  плана, identity, поколение, строка аудита, отчёт и лог его не содержат, а secret-scan лаборатории
  падает на такой форме.
- Роутер — собственный рантайм: ни `/usr/local/x-ui`, ни `/etc/x-ui`, ни общего шаблона;
  несовпадение дайджеста члена отказывает в старте, а не запускает незакреплённый бинарь.
- Управляющий трафик никогда не входит в роутер; роутер блокирует приватные назначения раньше
  любого правила политики и отвергает `private` как селектор.

### Отложено (дорожная карта)

- Статический мост в Xray 3x-ui, canary-раскатка политики, per-grant, ретрансляция UDP через
  роутер, регулярные выражения в селекторах (спека §15).

## [0.4.0-beta.1] - 2026-09-14

Маршрутизация: оператор задаёт для каждого узла и каждого прокси-сервиса, куда выходит
трафик клиентов — напрямую, через WARP хоста или никуда, — как политику, не привязанную к
движку. Панель компилирует её под backend, который узел действительно запускает, и
применяет транзакционно с откатом — локально и на связанных панелях. Проект решения —
[ADR 006](docs/adr/006-routing-policy-ir.md) (принят) и
[ADR 007](docs/adr/007-routing-enforcement-ownership.md); спецификация —
`docs/superpowers/specs/2026-09-14-v0.4-routing-design.md`; spike, зафиксировавший, что
каждый backend умеет честно исполнять, — `docs/spikes/VNEXT_ROUTING_ENGINE.md`. Xray-роутер
(v0.5) остаётся дорожной картой: выпуск намеренно ограничен возможностями backend'ов, и
предпросмотр говорит об этом прямо, а не сужает правило молча —
[ROUTING](docs/ROUTING.ru.md), [заметка о выпуске](docs/releases/v0.4.0-beta.1.md).

### Добавлено

- **Политики маршрутизации** (миграция 14: `routing_policies`, `routing_rules`,
  `routing_applies`, `managed_egress`): одна политика на пару (узел, протокол) для
  NaiveProxy и Mieru — действие по умолчанию (`direct` | `egress: warp`), поведение при
  недоступном WARP (`fail_closed` | `approved_direct`) и упорядоченные first-match правила
  (`domains`, `cidrs`, `ports`; `direct` | `block` | `egress`) с оптимистичными ревизиями.
  MTProxy вне области (`protocol_out_of_scope`).
- **Компилятор и предпросмотр** (`panel/routing/compiler.py`): политика компилируется в
  документ, который проверяет менеджер узла, — `naive_native` (Caddy forwardproxy
  `upstream` + `acl`) или `mieru_native` (mita `egress`) — против возможностей, которые
  менеджер объявляет. Всё, что backend не может исполнить, возвращается как `unsupported`
  с именем правила: у NaiveProxy один upstream на сервис и нет выборочных правил, а
  forwardproxy не применяет ACL рядом с upstream, поэтому правило блокировки не держится
  при WARP по умолчанию; блокировка по порту — не запрет ни в одном движке; loopback,
  link-local и приватные сети можно только блокировать, но не открывать. Достижимый, но
  лежащий WARP — fail-closed, если политика не выбрала `approved_direct` (тогда это
  предупреждение).
- **Egress API менеджеров** (`/v1/egress`, `/v1/egress/plan|apply|rollback` на обоих UDS):
  naive-manager владеет размеченным блоком внутри `forward_proxy` (рукописный `upstream`
  перенимается как `custom` и восстанавливается байт в байт откатом), mieru-manager —
  секцией `egress` mita (применяется перезапуском — `mita reload` её не подхватывает). CAS
  по ревизии, проба достижимости провайдера перед применением, readback после reload,
  журнал последних десяти записей; коды `egress_conflict`, `egress_invalid`,
  `egress_unreachable`, `egress_readback_mismatch`, `manual_intervention_required`.
  Контейнер mieru-manager переходит в сеть хоста ради пробы (по-прежнему `read_only`,
  `cap_drop: ALL`, без слушателя).
- **Секция `[egress]` установщика** (`warp`, `warp_port`, `naive`, `mieru`): WARP вынесен
  из `[three_xui]` (старые ключи читаются с одним предупреждением), каждый сервис выбирает
  свой egress; `NAIVE_EGRESS_WARP` / `MIERU_EGRESS_WARP` доходят до менеджеров через
  `.env` и Compose. Начальный egress сеется один раз; upgrade и repair его не трогают —
  [INSTALLER_REFERENCE](docs/INSTALLER_REFERENCE.ru.md).
- **Маршрутизация через Fleet v2**: узел объявляет `egress.v1` и свои egress-цели в
  `identity`; поколение несёт необязательную секцию `egress` (опускается из проводной
  формы и digest, когда её нет, поэтому узел или центр v0.3 по-прежнему сходятся с v0.4 на
  любом документе без неё); узел применяет её после ресурсов, идемпотентно по digest, и
  отчитывается `converged | failed | unsupported` по каждому протоколу; центр переводит
  политику в `applied` / `failed` по этому отчёту. Локальное применение отклоняется, пока
  узлом управляет центр (`managed_by_central`).
- **`/api/routing/*`**: targets (узлы × протоколы с backend, возможностями, провайдерами —
  без адреса провайдера — и состоянием политики), `GET`/`PUT`/`DELETE` политики, `preview`
  черновика без сохранения, `apply`, `rollback`, `history`; аудит
  `routing.policy.update | apply | rollback | delete` — [PANEL](PANEL.ru.md),
  [AUDIT_EVENTS](docs/AUDIT_EVENTS.md).
- **Экран «Маршрутизация»**: вкладки узлов и протоколов, редактор политики (значения по
  умолчанию, правила с ↑/↓ и перетаскиванием), живой предпросмотр (статус, причины с
  привязкой к правилу, предупреждения, diff, цель отката), «Применить» только для
  сохранённой поддерживаемой политики, история; на карточке узла появляется строка
  «Маршрутизация: …».
- **Tier `routing` стенда** (`scripts/dev/remote-gate.sh routing`,
  `fleet-acceptance.py --routing`, `scripts/lab/socks5-stub.py`): WARP на весь сервис через
  журналирующий SOCKS5-stub, блокировки по домену и CIDR при живом cover-сайте, выборочное
  правило Mieru, откат байт в байт, лежащий провайдер → fail-closed, nginx и nftables не
  тронуты.
- **`scripts/install-release.sh`**: скачивает четыре файла выпуска, сверяет `SHA256SUMS`,
  манифест, при желании закреплённый digest (`--sha256`) и attestation GitHub, распаковывает
  и передаёт управление мастеру установщика через один `sudo`; `--requirements` печатает,
  что нужно хосту и что устанавливается. Тот же путь, что описан для бета-выпусков в README.

### Изменено

- **Фикс-волна замечаний post-merge v0.3**: узел, ответивший 429 или 5xx, который он написал
  сам (JSON `{detail, code}`), сохраняет статус связи (backoff, а не `offline`) — голая
  страница 502/503/504 от прокси перед остановленной панелью по-прежнему `offline`; эскроу
  только из отчёта о текущем поколении; неизменённый plaintext не эскроуится повторно; тело
  heartbeat ограничено 1 МиБ; `POST credentials/capture` принимает `purpose: escrow | import`
  и отказывает неуправляемым пользователям в эскроу; `DELETE /api/nodes/{id}?force=1`;
  «применено, ожидает учётные данные» на карточке узла; tmpfs `/tmp` у менеджеров и агента;
  имена событий аудита сведены в `docs/AUDIT_EVENTS.md`.
- `GenerationDocument.canonical_digest` считается по проводной форме (`egress` опускается,
  когда его нет); каждый документ без egress сохраняет digest, который имел в v0.3.

### Безопасность

- Документы маршрутизации, политики, `identity`, наблюдаемые отчёты и строки аудита не
  содержат ни секрета, ни адреса провайдера: URL WARP живёт только в окружении менеджеров.
  Правило `direct`/`egress` для loopback или приватной сети отклоняется при компиляции
  (`private_destination`); менеджер отклоняет то же в собственной валидации.
