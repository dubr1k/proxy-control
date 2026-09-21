# The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP

**English** · [Русский](MCP.ru.md)

## What it is

Since v0.11 the central panel may run a container **`proxy-control-mcp`** — a
[Model Context Protocol](https://modelcontextprotocol.io) server over Streamable HTTP. It turns
the panel's API into tools a model calls: "create a client on two nodes and give me the
subscription link", "check for updates", "show what routing would enforce", "what happened in
the audit log in the last hour". The server keeps nothing and decides nothing: every call is an
ordinary panel request with an `admin`-scoped API key, so the same roles, limits and audit apply
as in the browser. In the log such actions show as `via: api-key`, key name `mcp`.

The server belongs on **the central panel only**: the central manages nodes through its own API
(`/api/nodes/{id}/…`) and its tools cover the whole fleet. On a node the MCP domain is left empty
in the installer's wizard.

```text
Claude Code / Desktop ──https://<mcp-domain>/mcp (Bearer mcp-token)──> nginx SNI :8443
                                                                          │ location /mcp
                                                                          ▼
                                                     proxy-control-mcp 127.0.0.1:8793
                                                                          │ http://panel:8787 + the panel's Host
                                                                          │ Authorization: Bearer <admin API key>
                                                                          ▼
                                                                proxy-control-panel
```

## How to enable

The installer sets the server up when the wizard is given an **MCP domain** (the eleventh
domain, after the subscription one; `domains.mcp` in the configuration,
[INSTALLER_REFERENCE](INSTALLER_REFERENCE.en.md)). It issues the panel key
(`python -m panel.cli api-key-create --name mcp --scope admin`), writes the secrets
`secrets/mcp-panel-key` and `secrets/mcp-token` (0600) and `.env.mcp` (`MCP_DOMAIN`,
`MCP_PANEL_HOST`), adds the vhost on the SNI router and brings up the `compose.mcp.yaml`
overlay. The token and the address `https://<domain>/mcp` land in the root-only install handoff.

By hand (the panel is installed, the domain points at the host):

```bash
cd /opt/proxy-control            # the project directory
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > secrets/mcp-token
docker compose exec -T panel python -m panel.cli api-key-create --name mcp --scope admin \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["plaintext"])' > secrets/mcp-panel-key
chmod 0600 secrets/mcp-token secrets/mcp-panel-key
printf 'MCP_DOMAIN=mcp.example.com\nMCP_PANEL_HOST=panel.example.com\n' > .env.mcp
docker compose --env-file .env --env-file .env.mcp -f compose.yaml -f compose.mcp.yaml up -d --build --wait mcp
```

The server listens on `127.0.0.1:8793`; `GET /healthz` answers without a token (for the health
check), everything else only with `Authorization: Bearer <contents of secrets/mcp-token>`. The
same nginx that fronts the panel publishes it: `location /mcp` → `127.0.0.1:8793`, anything
else 404.

## Connecting

**Claude Code:**

```bash
claude mcp add --transport http proxy-control https://mcp.example.com/mcp \
  --header "Authorization: Bearer $(cat secrets/mcp-token)"
```

**Claude Desktop** — add a remote server in the connector settings with the address
`https://mcp.example.com/mcp` and the header `Authorization: Bearer <token>` (or through
`mcp-remote` in `claude_desktop_config.json` when the client version cannot send headers itself).

**Codex CLI** — in `~/.codex/config.toml` (mode `0600`):

```toml
[mcp_servers.proxy-control]
url = "https://mcp.example.com/mcp"
http_headers = { Authorization = "Bearer <contents of secrets/mcp-token>" }
startup_timeout_sec = 60
tool_timeout_sec = 120

# Read-only tools run without a prompt; anything that changes state still asks.
[mcp_servers.proxy-control.tools.overview]
approval_mode = "approve"
[mcp_servers.proxy-control.tools.get_clients]
approval_mode = "approve"
```

Check: `codex mcp get proxy-control` shows `enabled: true`, and a `codex exec` asked to call
`overview` answers with the panel's status.

**OMP (oh-my-pi)** — in `~/.omp/agent/mcp.json` (mode `0600`):

```json
{
  "mcpServers": {
    "proxy-control": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer <contents of secrets/mcp-token>" },
      "timeout": 120000
    }
  }
}
```

A check without a client: `curl -sS https://mcp.example.com/mcp` without the token answers
`401`; with the token and an `initialize` body — `200`.

## Tools

**From OpenAPI.** At start (and on the `reload_tools` tool) the server fetches
`GET /api/openapi.json` from the panel (owner and admin only) and builds one tool per operation.
The name is `<method>_<path>` without `/api/`, `/` → `_`, `{parameter}` → `by_parameter`, at most
64 characters: `POST /api/clients/{client_id}/grants` → `post_clients_by_client_id_grants`,
`GET /api/audit` → `get_audit`. The description is the route's summary and docstring plus the
path itself. The input schema merges path parameters, query parameters and the request body's
fields. Not exposed: `/api/openapi.json`, `/healthz`, `/login`, `/api/auth/*`,
`/api/reveal/{token}` (the curated tools consume it), `/s/*` and the node API `/api/fleet/*`.

**Curated** — with hand-written descriptions, one call per everyday move:

| Tool | What it does |
|---|---|
| `overview` | `GET /api/dashboard` + `/api/versions` + `/api/nodes` as one JSON |
| `create_client` | Creates a client, issues grants by the node×protocol matrix (`placement`), returns the subscription link |
| `client_subscription` | Shows a client's subscription link again (one-shot reveal, audited) |
| `set_client_placement` | Brings the client's matrix to the desired one: issues the missing grants, disables the extra ones; without `confirm` only the plan |
| `versions_check` | Asks the version-agent to poll upstream |
| `versions_update` | Installs a component version (`confirm`) |
| `routing_preview` | What the node's backend would enforce for a policy, saving nothing |
| `routing_apply` | Applies the saved policy revision (`confirm`) |
| `audit_tail` | The newest audit rows with filters |
| `reload_tools` | Re-read the panel's schema after a panel update |

**Resources:** `proxy-control://overview`, `proxy-control://versions`, `proxy-control://nodes` —
the same data as JSON text, readable without a tool call.

## The `confirm` rule

Actions that cannot be undone require `confirm: true`: any `DELETE`, and `POST`/`PUT` on paths
with `/update`, `/rollback`, `/unlink`, `/revoke`, `/rotate`, `/delete`, `/archive`, `/check`,
`/exits/test`, `/reset-quota`, `/reset-metrics`, and a version install on a node
(`/nodes/{id}/versions/{component}`). Without `confirm` the tool **does not call the panel** and
answers with a description: `{"refused": true, "would": "POST /api/versions/telemt/update", "detail": …}`.
Tools with a path parameter such as `{action}` (`enable|disable|rotate|delete`) carry an optional
`confirm` in their schema, but `rotate` and `delete` refuse without it too. The model shows its
intent first; the owner confirms it.

A refusal from the panel (409, 404, 422…) reaches the client as an error result with the
panel's own text, `{"status": 409, "detail": "…", "code": "…"}` — the MCP session survives.

## Rotating the token and the key

- **The clients' token:** write a new one into `secrets/mcp-token` and recreate the container —
  `docker compose --env-file .env --env-file .env.mcp -f compose.yaml -f compose.mcp.yaml up -d mcp`;
  then update the header on the clients (`claude mcp remove proxy-control` and `add` again).
- **The panel key:** `api-key-revoke --name mcp`, then `api-key-create --name mcp --scope admin`
  into `secrets/mcp-panel-key` and the same `up -d mcp`. The key can also simply be disabled on
  «Администраторы» → «API-ключи» — the server stays up, but every tool answers with the
  panel's 401.

## Turning it off

`docker compose … -f compose.mcp.yaml rm -sf mcp`, `api-key-revoke --name mcp`, remove
`secrets/mcp-*`, `.env.mcp` and the domain's vhost; or clear `domains.mcp` and rerun the
installer — its `rollback` does the same.

## Verification

- `tests/test_mcp_server.py` — the server against a fake panel: tools from OpenAPI, `confirm`,
  401 without a token, the curated sequences.
- `panel/tests/test_openapi_routes.py`, `panel/tests/test_cli_api_keys.py` — the schema route
  and the key commands.
- The gate's `compose` tier renders `compose.mcp.yaml` and builds the image, checking uid 10007.
