# MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP

[English](MCP.en.md) · **Русский**

## Что это

С v0.11 рядом с центральной панелью может работать контейнер **`proxy-control-mcp`** —
сервер [Model Context Protocol](https://modelcontextprotocol.io) по Streamable HTTP. Он
превращает API панели в инструменты, которые вызывает модель: «создай клиента на двух узлах и
дай ссылку подписки», «проверь обновления», «покажи, что применит маршрутизация», «что было в
аудите за последний час». Сам сервер ничего не хранит и ничего не решает: каждый вызов — это
обычный запрос к панели с API-ключом области `admin`, поэтому действуют те же роли, лимиты и
аудит, что и в браузере. В журнале такие действия видны как `via: api-key`, имя ключа `mcp`.

Сервер нужен **только на центральной панели**: центр управляет узлами своим API
(`/api/nodes/{id}/…`), и инструменты центра покрывают весь парк. На узле домен MCP в мастере
установки оставляют пустым.

```text
Claude Code / Desktop ──https://<mcp-домен>/mcp (Bearer mcp-token)──> nginx SNI :8443
                                                                          │ location /mcp
                                                                          ▼
                                                     proxy-control-mcp 127.0.0.1:8793
                                                                          │ http://panel:8787 + Host панели
                                                                          │ Authorization: Bearer <admin API-ключ>
                                                                          ▼
                                                                proxy-control-panel
```

## Как включить

Установщик ставит сервер, когда в мастере задан **домен MCP** (одиннадцатый домен, после домена
подписки; `domains.mcp` в конфигурации, [INSTALLER_REFERENCE](INSTALLER_REFERENCE.ru.md)).
Он выпускает ключ панели (`python -m panel.cli api-key-create --name mcp --scope admin`),
кладёт секреты `secrets/mcp-panel-key` и `secrets/mcp-token` (0600), пишет `.env.mcp`
(`MCP_DOMAIN`, `MCP_PANEL_HOST`), добавляет vhost на SNI-роутере и поднимает overlay
`compose.mcp.yaml`. Токен и адрес `https://<домен>/mcp` попадают в root-only handoff установки.

Вручную (панель уже стоит, домен указывает на хост):

```bash
cd /opt/proxy-control            # каталог проекта
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > secrets/mcp-token
docker compose exec -T panel python -m panel.cli api-key-create --name mcp --scope admin \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["plaintext"])' > secrets/mcp-panel-key
chmod 0600 secrets/mcp-token secrets/mcp-panel-key
printf 'MCP_DOMAIN=mcp.example.com\nMCP_PANEL_HOST=panel.example.com\n' > .env.mcp
docker compose --env-file .env --env-file .env.mcp -f compose.yaml -f compose.mcp.yaml up -d --build --wait mcp
```

Сервер слушает `127.0.0.1:8793`; `GET /healthz` отвечает без токена (для healthcheck),
всё остальное — только с `Authorization: Bearer <содержимое secrets/mcp-token>`. Наружу его
публикует тот же nginx, что и панель: `location /mcp` → `127.0.0.1:8793`, всё остальное 404.

## Подключение

**Claude Code:**

```bash
claude mcp add --transport http proxy-control https://mcp.example.com/mcp \
  --header "Authorization: Bearer $(cat secrets/mcp-token)"
```

**Claude Desktop** — в настройках коннекторов добавьте удалённый сервер с адресом
`https://mcp.example.com/mcp` и заголовком `Authorization: Bearer <токен>` (или через
`mcp-remote` в `claude_desktop_config.json`, если версия клиента не умеет заголовки сама).

**Codex CLI** — в `~/.codex/config.toml` (файл с правами `0600`):

```toml
[mcp_servers.proxy-control]
url = "https://mcp.example.com/mcp"
http_headers = { Authorization = "Bearer <содержимое secrets/mcp-token>" }
startup_timeout_sec = 60
tool_timeout_sec = 120

# Читающие инструменты — без подтверждения; всё, что меняет состояние, Codex спрашивает.
[mcp_servers.proxy-control.tools.overview]
approval_mode = "approve"
[mcp_servers.proxy-control.tools.get_clients]
approval_mode = "approve"
```

Проверка: `codex mcp get proxy-control` показывает `enabled: true`, а `codex exec` с просьбой
вызвать `overview` отвечает статусом панели.

**OMP (oh-my-pi)** — в `~/.omp/agent/mcp.json` (права `0600`):

```json
{
  "mcpServers": {
    "proxy-control": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer <содержимое secrets/mcp-token>" },
      "timeout": 120000
    }
  }
}
```

Проверка без клиента: `curl -sS https://mcp.example.com/mcp` без токена отвечает `401`;
с токеном и телом `initialize` — `200`.

## Инструменты

**Из OpenAPI.** При старте (и по инструменту `reload_tools`) сервер берёт у панели
`GET /api/openapi.json` (доступен владельцу и администратору) и строит по одному инструменту на
операцию. Имя — `<метод>_<путь>` без `/api/`, `/` → `_`, `{параметр}` → `by_параметр`, не
длиннее 64 символов: `POST /api/clients/{client_id}/grants` → `post_clients_by_client_id_grants`,
`GET /api/audit` → `get_audit`. Описание — summary и docstring маршрута плюс сам путь. Входная
схема — path-параметры, query и поля тела запроса вместе. Не выдаются: `/api/openapi.json`,
`/healthz`, `/login`, `/api/auth/*`, `/api/reveal/{token}` (его используют curated-инструменты),
`/s/*` и узловой API `/api/fleet/*`.

**Curated** — с человеческими описаниями, по одному вызову на привычное действие:

| Инструмент | Что делает |
|---|---|
| `overview` | `GET /api/dashboard` + `/api/versions` + `/api/nodes` одним JSON |
| `create_client` | Создаёт клиента, выдаёт доступы по матрице узел×протокол (`placement`), возвращает ссылку подписки |
| `client_subscription` | Показывает ссылку подписки клиента ещё раз (одноразовый reveal, с записью в аудит) |
| `set_client_placement` | Приводит матрицу клиента к желаемой: недостающие доступы выдаёт, лишние выключает; без `confirm` только план |
| `versions_check` | Просит version-agent опросить upstream |
| `versions_update` | Ставит версию компонента (`confirm`) |
| `routing_preview` | Что применит backend узла для политики, ничего не сохраняя |
| `routing_apply` | Применяет сохранённую ревизию политики (`confirm`) |
| `audit_tail` | Последние строки аудита с фильтрами |
| `reload_tools` | Перечитать схему панели после её обновления |

**Ресурсы:** `proxy-control://overview`, `proxy-control://versions`, `proxy-control://nodes` —
те же данные как JSON-текст для чтения без вызова инструмента.

## Правило `confirm`

Действия, которые нельзя отменить, требуют параметр `confirm: true`: любой `DELETE`, а также
`POST`/`PUT` по путям с `/update`, `/rollback`, `/unlink`, `/revoke`, `/rotate`, `/delete`,
`/archive`, `/check`, `/exits/test`, `/reset-quota`, `/reset-metrics` и установка версии на узле
(`/nodes/{id}/versions/{component}`). Без `confirm` инструмент **не обращается к панели** и
отвечает описанием: `{"refused": true, "would": "POST /api/versions/telemt/update", "detail": …}`.
У инструментов с параметром пути вроде `{action}` (`enable|disable|rotate|delete`) `confirm`
необязателен в схеме, но `rotate` и `delete` без него тоже отказывают. Так модель сначала
показывает намерение, а владелец подтверждает его.

Отказ панели (409, 404, 422…) приходит клиенту как результат с ошибкой и текстом панели
`{"status": 409, "detail": "…", "code": "…"}` — сессия MCP не рвётся.

## Ротация токена и ключа

- **Токен клиентов:** запишите новый в `secrets/mcp-token` и пересоздайте контейнер —
  `docker compose --env-file .env --env-file .env.mcp -f compose.yaml -f compose.mcp.yaml up -d mcp`;
  затем обновите заголовок у клиентов (`claude mcp remove proxy-control` и `add` заново).
- **Ключ панели:** `api-key-revoke --name mcp`, затем `api-key-create --name mcp --scope admin`
  в `secrets/mcp-panel-key` и тот же `up -d mcp`. Ключ можно и просто выключить на экране
  «Администраторы» → «API-ключи» — сервер останется, но все инструменты будут отвечать 401 панели.

## Выключить

`docker compose … -f compose.mcp.yaml rm -sf mcp`, `api-key-revoke --name mcp`, удалить
`secrets/mcp-*`, `.env.mcp` и vhost домена; или очистить `domains.mcp` и перезапустить
установщик — его `rollback` делает то же.

## Проверка

- `tests/test_mcp_server.py` — сервер против фальшивой панели: построение инструментов из
  OpenAPI, `confirm`, 401 без токена, curated-последовательности.
- `panel/tests/test_openapi_routes.py`, `panel/tests/test_cli_api_keys.py` — маршрут схемы и
  команды ключей.
- Ярус `compose` гейта рендерит `compose.mcp.yaml` и собирает образ с проверкой uid 10007.
