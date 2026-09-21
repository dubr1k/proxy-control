"""The MCP server (v0.11, spec §9a) against a fake panel: tools built from the OpenAPI
schema by the naming rule, `confirm` on irreversible operations, the curated tools, the
bearer gate on `/mcp` and the open `/healthz`."""
from __future__ import annotations

import json
from urllib.parse import parse_qs

import httpx
import pytest

from mcp_server.config import Config
from mcp_server.panel import PanelClient, PanelError
from mcp_server.server import create_app
from mcp_server.tools import ToolRegistry, build_operations, is_irreversible, tool_name

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"

TOKEN = "test-mcp-token-0123456789abcdef0123456789abcdef"
PANEL_KEY = "pc_deadbeef_test-panel-key"
PANEL_HOST = "panel.example.com"

OPENAPI = {
    "openapi": "3.1.0",
    "info": {"title": "Proxy Control API", "version": "0.1.0"},
    "paths": {
        "/api/openapi.json": {"get": {"summary": "Openapi Schema", "operationId": "openapi"}},
        "/healthz": {"get": {"summary": "Health", "operationId": "healthz"}},
        "/login": {"get": {"summary": "Login Page", "operationId": "login_page"}},
        "/api/auth/login": {"post": {"summary": "Login", "operationId": "login"}},
        "/api/reveal/{token}": {"get": {"summary": "Get Reveal", "operationId": "reveal",
                                        "parameters": [{"name": "token", "in": "path", "required": True, "schema": {"type": "string"}}]}},
        "/s/{token}": {"get": {"summary": "Subscription", "operationId": "sub",
                               "parameters": [{"name": "token", "in": "path", "required": True, "schema": {"type": "string"}}]}},
        "/api/fleet/v2/identity": {"get": {"summary": "Identity", "operationId": "identity"}},
        "/api/clients": {
            "get": {"summary": "Clients", "operationId": "clients"},
            "post": {"summary": "Create", "description": "Create a client.", "operationId": "create_client",
                     "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ClientCreate"}}}}},
        },
        "/api/clients/{client_id}/grants": {
            "post": {"summary": "Create Grants", "operationId": "create_grants",
                     "parameters": [{"name": "client_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                     "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GrantsCreate"}}}}},
        },
        "/api/clients/grants/{grant_id}/{action}": {
            "post": {"summary": "Grant Action", "operationId": "grant_action",
                     "parameters": [{"name": "grant_id", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "action", "in": "path", "required": True,
                                     "schema": {"type": "string", "enum": ["enable", "disable", "rotate", "delete"]}}]},
        },
        "/api/audit": {
            "get": {"summary": "Audit Log", "operationId": "audit",
                    "parameters": [{"name": "limit", "in": "query", "required": False, "schema": {"type": "integer", "default": 200}},
                                   {"name": "actor", "in": "query", "required": False, "schema": {"type": "string"}}]},
        },
        "/api/versions/{component}/update": {
            "post": {"summary": "Update Version", "operationId": "update_version",
                     "parameters": [{"name": "component", "in": "path", "required": True, "schema": {"type": "string"}}],
                     "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/VersionUpdate"}}}}},
        },
        "/api/keys/{key_id}": {
            "delete": {"summary": "Delete Key", "operationId": "delete_key",
                       "parameters": [{"name": "key_id", "in": "path", "required": True, "schema": {"type": "integer"}}]},
        },
        "/api/routing/policies/{node_id}/{protocol}/preview": {
            "post": {"summary": "Preview", "operationId": "preview",
                     "parameters": [{"name": "node_id", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "protocol", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "lane", "in": "query", "required": False, "schema": {"type": "string", "default": "svc"}}],
                     "requestBody": {"content": {"application/json": {"schema": {"anyOf": [{"$ref": "#/components/schemas/PolicyInput"}, {"type": "null"}]}}}}},
        },
    },
    "components": {"schemas": {
        "ClientCreate": {"type": "object", "properties": {"display_name": {"type": "string", "maxLength": 128},
                                                          "subscription": {"type": "boolean", "default": True}},
                         "required": ["display_name"]},
        "GrantRequest": {"type": "object", "properties": {"protocol": {"type": "string", "enum": ["mtproxy", "naive", "mieru"]},
                                                          "node_id": {"type": "string", "default": "local"},
                                                          "runtime_username": {"type": "string"}},
                         "required": ["protocol", "runtime_username"]},
        "GrantsCreate": {"type": "object", "properties": {"grants": {"type": "array", "items": {"$ref": "#/components/schemas/GrantRequest"}}},
                         "required": ["grants"]},
        "VersionUpdate": {"type": "object", "properties": {"version": {"type": "string"}, "expected_current": {"type": "string"}},
                          "required": ["version", "expected_current"]},
        "PolicyInput": {"type": "object", "properties": {"mode": {"type": "string"}}},
    }},
}


class FakePanel:
    """The routes the curated tools use, with a log of every request."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []
        self.grants: dict[str, list[dict]] = {}
        self.clients: dict[str, dict] = {}
        self.reveals: dict[str, dict] = {}
        self.next_id = 1

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["host"] == PANEL_HOST
        assert request.headers["authorization"] == f"Bearer {PANEL_KEY}"
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else None
        self.calls.append((method, request.url.raw_path.decode(), body))
        if path == "/api/openapi.json":
            return httpx.Response(200, json=OPENAPI)
        if path == "/api/dashboard":
            return httpx.Response(200, json={"users": 3})
        if path == "/api/versions":
            return httpx.Response(200, json={"enabled": True, "components": {"panel": {"current": "0.11.0"}}})
        if path == "/api/versions/check":
            return httpx.Response(200, json={"checked_at": 1})
        if path == "/api/versions/telemt/update":
            return httpx.Response(409, json={"detail": "expected_current does not match", "code": "stale"})
        if path == "/api/nodes":
            return httpx.Response(200, json={"items": [{"node_id": "local"}]})
        if path == "/api/audit":
            return httpx.Response(200, json={"items": [{"id": 1, "action": "api_key.create"}]})
        if path == "/api/clients" and method == "POST":
            client_id = f"c{self.next_id}"
            self.next_id += 1
            self.clients[client_id] = {"id": client_id, "display_name": body["display_name"]}
            self.grants[client_id] = []
            reveal = None
            if body.get("subscription", True):
                reveal = f"reveal-{client_id}"
                self.reveals[reveal] = {"url": f"https://sub.example.com/s/tok-{client_id}", "qr": "data:...",
                                        "variants": {"clash": {"url": f"https://sub.example.com/s/tok-{client_id}?format=clash", "qr": "x"}}}
            return httpx.Response(201, json={**self.clients[client_id], "subscription_reveal_token": reveal})
        if path.startswith("/api/clients/") and path.endswith("/grants") and method == "POST":
            client_id = path.split("/")[3]
            if client_id not in self.clients:
                return httpx.Response(404, json={"detail": "client not found"})
            for item in body["grants"]:
                self.grants[client_id].append({"id": f"g{len(self.grants[client_id]) + 1}", "client_id": client_id,
                                               "desired_state": "enabled", **item})
            return httpx.Response(200, json={"operation_id": "op1", "status": "succeeded"})
        if path.startswith("/api/clients/grants/") and method == "POST":
            grant_id, action = path.split("/")[4], path.split("/")[-1]
            for grants in self.grants.values():
                for grant in grants:
                    if grant["id"] == grant_id:
                        grant["desired_state"] = "enabled" if action == "enable" else "disabled"
                        return httpx.Response(200, json=grant)
            return httpx.Response(404, json={"detail": "grant not found"})
        if path.startswith("/api/clients/") and path.endswith("/subscription/reveal"):
            client_id = path.split("/")[3]
            if client_id not in self.clients:
                return httpx.Response(404, json={"detail": "client or subscription not found"})
            self.reveals["again"] = {"url": f"https://sub.example.com/s/tok-{client_id}", "qr": "x", "variants": {}}
            return httpx.Response(200, json={"reveal_token": "again"})
        if path.startswith("/api/reveal/"):
            payload = self.reveals.pop(path.split("/")[3], None)
            return httpx.Response(200, json=payload) if payload else httpx.Response(410, json={"detail": "reveal expired or consumed"})
        if path.startswith("/api/clients/") and method == "GET":
            client_id = path.split("/")[3]
            if client_id not in self.clients:
                return httpx.Response(404, json={"detail": "client not found"})
            return httpx.Response(200, json={"client": self.clients[client_id], "grants": self.grants[client_id]})
        if path.startswith("/api/routing/policies/") and path.endswith("/preview"):
            return httpx.Response(200, json={"node_id": path.split("/")[4], "body": body, "lane": parse_qs(request.url.query.decode()).get("lane")})
        if path.startswith("/api/routing/policies/") and path.endswith("/apply"):
            return httpx.Response(200, json={"applied": body})
        if path.startswith("/api/keys/") and method == "DELETE":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"detail": f"no fake route for {method} {path}"})


@pytest.fixture
def config(tmp_path):
    return Config(panel_url="http://panel:8787", panel_host=PANEL_HOST, panel_key=PANEL_KEY, token=TOKEN,
                  bind_host="0.0.0.0", bind_port=8793, allowed_hosts=("mcp.example.com", "127.0.0.1:8793"),
                  public_url="https://mcp.example.com/mcp")


@pytest.fixture
def fake():
    return FakePanel()


@pytest.fixture
def panel(config, fake):
    return PanelClient(config, transport=httpx.MockTransport(fake.handler))


@pytest.fixture
async def registry(panel):
    value = ToolRegistry(panel)
    await value.reload()
    return value


def _text(result) -> dict:
    assert len(result.content) == 1 and result.content[0].type == "text"
    return json.loads(result.content[0].text)


# --- config -------------------------------------------------------------------------


def test_config_reads_secrets_from_files_and_requires_allowed_hosts(tmp_path):
    (tmp_path / "key").write_text(f"{PANEL_KEY}\n")
    (tmp_path / "token").write_text(f"{TOKEN}\n")
    env = {"MCP_PANEL_HOST": PANEL_HOST, "MCP_PANEL_KEY_FILE": str(tmp_path / "key"), "MCP_TOKEN_FILE": str(tmp_path / "token"),
           "MCP_ALLOWED_HOSTS": "mcp.example.com, 127.0.0.1:8793"}
    config = Config.from_env(env)
    assert config.panel_url == "http://panel:8787" and config.panel_key == PANEL_KEY and config.token == TOKEN
    assert config.allowed_hosts == ("mcp.example.com", "127.0.0.1:8793")
    assert (config.bind_host, config.bind_port) == ("0.0.0.0", 8793)
    with pytest.raises(ValueError, match="MCP_ALLOWED_HOSTS"):
        Config.from_env({**env, "MCP_ALLOWED_HOSTS": ""})
    with pytest.raises(ValueError, match="MCP_PANEL_HOST"):
        Config.from_env({**env, "MCP_PANEL_HOST": ""})
    with pytest.raises(ValueError, match="MCP_BIND"):
        Config.from_env({**env, "MCP_BIND": "nonsense"})


# --- tools from OpenAPI --------------------------------------------------------------


def test_tool_names_follow_the_rule():
    assert tool_name("post", "/api/clients/{client_id}/grants") == "post_clients_by_client_id_grants"
    assert tool_name("get", "/api/audit") == "get_audit"
    assert tool_name("delete", "/api/routing/policies/{node_id}/{protocol}") == "delete_routing_policies_by_node_id_by_protocol"
    long = tool_name("post", "/api/" + "/".join(f"segment{i}" for i in range(12)))
    assert len(long) <= 64 and long.startswith("post_segment0_")


def test_operations_are_built_from_the_schema_and_the_excluded_paths_are_absent():
    operations = {op.name: op for op in build_operations(OPENAPI)}
    assert "get_openapi_json" not in operations and "get_healthz" not in operations
    assert not any(name.startswith(("get_login", "post_auth", "get_reveal", "get_s_", "get_fleet")) for name in operations)
    create = operations["post_clients"]
    assert create.method == "POST" and create.path == "/api/clients"
    assert "Create a client." in create.description and "POST /api/clients" in create.description
    assert create.input_schema["properties"]["display_name"]["type"] == "string"
    assert create.input_schema["required"] == ["display_name"]
    assert "confirm" not in create.input_schema["properties"]
    grants = operations["post_clients_by_client_id_grants"]
    assert set(grants.input_schema["properties"]) == {"client_id", "grants"}
    assert grants.input_schema["required"] == ["client_id", "grants"]
    # The body's `$ref` is resolved, nested refs included.
    assert grants.input_schema["properties"]["grants"]["items"]["properties"]["protocol"]["enum"] == ["mtproxy", "naive", "mieru"]
    audit = operations["get_audit"]
    assert set(audit.input_schema["properties"]) == {"limit", "actor"} and "required" not in audit.input_schema
    preview = operations["post_routing_policies_by_node_id_by_protocol_preview"]
    assert set(preview.input_schema["properties"]) == {"node_id", "protocol", "lane", "mode"}


def test_irreversible_operations_require_confirm():
    operations = {op.name: op for op in build_operations(OPENAPI)}
    update = operations["post_versions_by_component_update"]
    assert update.input_schema["properties"]["confirm"]["type"] == "boolean"
    assert "confirm" in update.input_schema["required"]
    delete = operations["delete_keys_by_key_id"]
    assert "confirm" in delete.input_schema["required"]
    # A path whose parameter may take an irreversible value gets an optional `confirm`.
    action = operations["post_clients_grants_by_grant_id_by_action"]
    assert "confirm" in action.input_schema["properties"] and "confirm" not in action.input_schema["required"]
    # Installing a version on a managed node is an update even though the path says `versions/{component}`.
    assert is_irreversible("POST", "/api/nodes/{node_id}/versions/{component}")
    assert is_irreversible("POST", "/api/nodes/{node_id}/versions/check")  # `/check` is on the list
    assert not is_irreversible("GET", "/api/versions")


async def test_confirm_false_refuses_without_calling_the_panel(registry, fake):
    calls_before = len(fake.calls)
    result = await registry.call("post_versions_by_component_update", {"component": "telemt", "version": "1", "expected_current": "0"})
    body = _text(result)
    assert body["refused"] is True and body["would"] == "POST /api/versions/telemt/update"
    result = await registry.call("post_clients_grants_by_grant_id_by_action", {"grant_id": "g1", "action": "delete"})
    assert _text(result)["would"] == "POST /api/clients/grants/g1/delete"
    assert len(fake.calls) == calls_before


async def test_a_confirmed_call_reaches_the_panel_and_its_error_comes_back_as_tool_text(registry, fake):
    result = await registry.call("post_versions_by_component_update",
                                 {"component": "telemt", "version": "1", "expected_current": "0", "confirm": True})
    assert result.is_error is True
    body = _text(result)
    assert body == {"status": 409, "detail": "expected_current does not match", "code": "stale"}
    assert fake.calls[-1] == ("POST", "/api/versions/telemt/update", {"version": "1", "expected_current": "0"})


async def test_path_params_are_encoded_and_get_params_travel_as_query(registry, fake):
    result = await registry.call("get_audit", {"limit": 5, "actor": "key:mcp"})
    assert result.is_error is False and _text(result)["items"][0]["action"] == "api_key.create"
    assert fake.calls[-1][1] == "/api/audit?limit=5&actor=key%3Amcp"
    await registry.call("post_clients_grants_by_grant_id_by_action", {"grant_id": "g/1", "action": "enable"})
    assert fake.calls[-1][1] == "/api/clients/grants/g%2F1/enable"


async def test_unknown_tool_is_an_error(registry):
    result = await registry.call("no_such_tool", {})
    assert result.is_error is True


async def test_listing_has_generated_and_curated_tools_and_reload_rebuilds(registry, fake):
    names = {tool.name for tool in registry.tools()}
    assert {"overview", "create_client", "client_subscription", "set_client_placement", "versions_check", "versions_update",
            "routing_preview", "routing_apply", "audit_tail", "reload_tools", "post_clients", "get_audit"} <= names
    assert all(len(tool.name) <= 64 for tool in registry.tools())
    schema_calls = len([call for call in fake.calls if call[1] == "/api/openapi.json"])
    result = await registry.call("reload_tools", {})
    assert _text(result)["tools"] == len(registry.tools())
    assert len([call for call in fake.calls if call[1] == "/api/openapi.json"]) == schema_calls + 1


# --- curated -------------------------------------------------------------------------


async def test_overview_joins_dashboard_versions_and_nodes(registry):
    body = _text(await registry.call("overview", {}))
    assert body["dashboard"] == {"users": 3}
    assert body["versions"]["components"]["panel"]["current"] == "0.11.0"
    assert body["nodes"] == [{"node_id": "local"}]


async def test_create_client_creates_places_and_returns_the_subscription_url(registry, fake):
    body = _text(await registry.call("create_client", {
        "display_name": "Alice Example", "subscription": True,
        "placement": [{"node_id": "local", "protocol": "naive"}, {"node_id": "node-1", "protocol": "mieru"}],
    }))
    assert body["client"]["id"] == "c1"
    assert body["subscription_url"] == "https://sub.example.com/s/tok-c1"
    assert body["grants"] == {"operation_id": "op1", "status": "succeeded"}
    sequence = [(method, path) for method, path, _ in fake.calls if path != "/api/openapi.json"]
    assert sequence == [("POST", "/api/clients"), ("POST", "/api/clients/c1/grants"), ("GET", "/api/reveal/reveal-c1")]
    grants = fake.calls[2][2]["grants"]
    assert [(g["node_id"], g["protocol"]) for g in grants] == [("local", "naive"), ("node-1", "mieru")]
    assert all(g["runtime_username"] == "alice-example" for g in grants)
    assert "qr" not in json.dumps(body)


async def test_create_client_without_subscription_or_placement(registry, fake):
    body = _text(await registry.call("create_client", {"display_name": "Bob", "subscription": False}))
    assert body["subscription_url"] is None and body["grants"] is None
    assert [(m, p) for m, p, _ in fake.calls if p != "/api/openapi.json"] == [("POST", "/api/clients")]


async def test_client_subscription_reveals_the_url_again(registry, fake):
    await registry.call("create_client", {"display_name": "Carol", "subscription": True, "placement": []})
    body = _text(await registry.call("client_subscription", {"client_id": "c1"}))
    assert body["url"] == "https://sub.example.com/s/tok-c1"
    missing = await registry.call("client_subscription", {"client_id": "nope"})
    assert missing.is_error is True and _text(missing)["status"] == 404


async def test_set_client_placement_plans_and_executes_only_with_confirm(registry, fake):
    await registry.call("create_client", {"display_name": "Dave", "subscription": False,
                                          "placement": [{"node_id": "local", "protocol": "naive"}, {"node_id": "local", "protocol": "mieru"}]})
    desired = [{"node_id": "local", "protocol": "naive"}, {"node_id": "node-2", "protocol": "mtproxy"}]
    plan = _text(await registry.call("set_client_placement", {"client_id": "c1", "placement": desired}))
    assert plan["refused"] is True
    assert plan["plan"]["issue"] == [{"node_id": "node-2", "protocol": "mtproxy"}]
    assert plan["plan"]["disable"] == [{"grant_id": "g2", "node_id": "local", "protocol": "mieru"}]
    assert plan["plan"]["keep"] == [{"grant_id": "g1", "node_id": "local", "protocol": "naive"}]
    mutations = [c for c in fake.calls if c[0] == "POST" and c[1] != "/api/clients"]
    assert len(mutations) == 1  # the original placement only
    done = _text(await registry.call("set_client_placement", {"client_id": "c1", "placement": desired, "confirm": True}))
    assert done["refused"] is False
    assert fake.grants["c1"][1]["desired_state"] == "disabled"
    assert (fake.grants["c1"][2]["node_id"], fake.grants["c1"][2]["protocol"]) == ("node-2", "mtproxy")
    assert fake.grants["c1"][2]["runtime_username"] == "dave"
    # Re-enabling a disabled grant instead of issuing a second one.
    again = _text(await registry.call("set_client_placement", {"client_id": "c1", "placement": [{"node_id": "local", "protocol": "mieru"}], "confirm": True}))
    assert again["plan"]["enable"] == [{"grant_id": "g2", "node_id": "local", "protocol": "mieru"}]
    assert fake.grants["c1"][1]["desired_state"] == "enabled"


async def test_versions_and_routing_and_audit_curated_tools(registry, fake):
    assert _text(await registry.call("versions_check", {}))["checked_at"] == 1
    refused = _text(await registry.call("versions_update", {"component": "telemt", "version": "1", "expected_current": "0"}))
    assert refused["refused"] is True and "telemt" in refused["would"]
    stale = await registry.call("versions_update", {"component": "telemt", "version": "1", "expected_current": "0", "confirm": True})
    assert stale.is_error and _text(stale)["code"] == "stale"
    preview = _text(await registry.call("routing_preview", {"node_id": "local", "protocol": "naive", "policy": {"mode": "direct"}}))
    assert preview["body"] == {"mode": "direct"} and preview["lane"] == ["svc"]
    assert fake.calls[-1][1] == "/api/routing/policies/local/naive/preview?lane=svc"
    refused = _text(await registry.call("routing_apply", {"node_id": "local", "protocol": "naive", "expected_revision": 3}))
    assert refused["refused"] is True
    applied = _text(await registry.call("routing_apply", {"node_id": "local", "protocol": "naive", "expected_revision": 3, "lane": "grant:g1", "confirm": True}))
    assert applied == {"applied": {"expected_revision": 3}}
    assert fake.calls[-1][1] == "/api/routing/policies/local/naive/apply?lane=grant%3Ag1"
    tail = _text(await registry.call("audit_tail", {"limit": 10}))
    assert tail["items"][0]["action"] == "api_key.create" and fake.calls[-1][1] == "/api/audit?limit=10"


async def test_resources_are_json_text(registry):
    uris = {resource.uri for resource in registry.resources()}
    assert uris == {"proxy-control://overview", "proxy-control://versions", "proxy-control://nodes"}
    versions = await registry.read_resource("proxy-control://versions")
    assert json.loads(versions)["enabled"] is True
    with pytest.raises(PanelError):
        await registry.read_resource("proxy-control://nothing")


# --- HTTP surface --------------------------------------------------------------------


@pytest.fixture
async def http(config, fake):
    app = create_app(config, transport=httpx.MockTransport(fake.handler))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://mcp.example.com") as client:
            yield client


def _rpc(method: str, params: dict | None = None, id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": id, "method": method, "params": params or {}}


MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = _rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})


async def test_healthz_is_open_and_mcp_needs_the_bearer(http):
    assert (await http.get("/healthz")).json() == {"status": "ok"}
    assert (await http.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)).status_code == 401
    wrong = {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN[:-1]}x"}
    assert (await http.post("/mcp", json=INITIALIZE, headers=wrong)).status_code == 401
    assert (await http.get("/mcp", headers={"Authorization": "Basic abc"})).status_code == 401


async def test_initialize_and_tool_calls_over_http(http):
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"}
    response = await http.post("/mcp", json=INITIALIZE, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["result"]["serverInfo"]["name"] == "proxy-control"
    listed = await http.post("/mcp", json=_rpc("tools/list", id=2), headers=headers)
    names = {tool["name"] for tool in listed.json()["result"]["tools"]}
    assert "overview" in names and "post_clients" in names
    called = await http.post("/mcp", json=_rpc("tools/call", {"name": "overview", "arguments": {}}, id=3), headers=headers)
    assert json.loads(called.json()["result"]["content"][0]["text"])["dashboard"] == {"users": 3}


async def test_a_host_outside_the_allowlist_is_refused(config, fake):
    app = create_app(config, transport=httpx.MockTransport(fake.handler))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://evil.example.com") as client:
            headers = {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"}
            assert (await client.post("/mcp", json=INITIALIZE, headers=headers)).status_code == 421
