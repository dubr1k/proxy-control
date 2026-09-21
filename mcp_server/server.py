"""The ASGI application: `/healthz` open for the container's health check, `/mcp` —
Streamable HTTP, stateless — behind a bearer token compared in constant time, with the
SDK's DNS-rebinding protection limited to the hosts the installer named."""
from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager
from typing import Any

import httpx
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import (
    CallToolRequestParams,
    CallToolResult,
    ListResourcesResult,
    ListToolsResult,
    PaginatedRequestParams,
    ReadResourceRequestParams,
    ReadResourceResult,
    TextResourceContents,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Config
from .panel import PanelClient, PanelError
from .tools import ToolRegistry

log = logging.getLogger("proxy-control-mcp")

SERVER_NAME = "proxy-control"
INSTRUCTIONS = (
    "Proxy Control panel over MCP. Curated tools (overview, create_client, client_subscription, "
    "set_client_placement, versions_check, versions_update, routing_preview, routing_apply, audit_tail) cover "
    "the everyday moves; every other panel operation is a generated tool named <method>_<path>. Operations "
    "that cannot be undone take `confirm: true` and only describe themselves without it. Errors from the panel "
    "come back as error results with the panel's own `detail`/`code`."
)


class BearerGate:
    """`Authorization: Bearer <token>` on everything but `/healthz`, compared in constant
    time; anything else is 401 before the transport sees the request."""

    def __init__(self, app: ASGIApp, token: str, open_paths: frozenset[str] = frozenset({"/healthz"})):
        self.app, self._token, self.open_paths = app, token.encode(), open_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in self.open_paths:
            await self.app(scope, receive, send)
            return
        header = Request(scope).headers.get("authorization", "")
        scheme, _, credential = header.partition(" ")
        presented = credential.strip().encode()
        if scheme.lower() != "bearer" or not presented or not hmac.compare_digest(presented, self._token):
            response = JSONResponse({"error": "unauthorized"}, 401, headers={"WWW-Authenticate": 'Bearer realm="proxy-control-mcp"'})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def build_server(registry: ToolRegistry) -> Server[Any]:
    async def list_tools(_ctx, _params: PaginatedRequestParams | None) -> ListToolsResult:
        return ListToolsResult(tools=registry.tools())

    async def call_tool(_ctx, params: CallToolRequestParams) -> CallToolResult:
        return await registry.call(params.name, params.arguments)

    async def list_resources(_ctx, _params: PaginatedRequestParams | None) -> ListResourcesResult:
        return ListResourcesResult(resources=registry.resources())

    async def read_resource(_ctx, params: ReadResourceRequestParams) -> ReadResourceResult:
        try:
            text = await registry.read_resource(str(params.uri))
        except PanelError as exc:
            raise ValueError(f"{exc.detail} ({exc.status})") from exc
        return ReadResourceResult(contents=[TextResourceContents(uri=str(params.uri), mime_type="application/json", text=text)])

    return Server(
        SERVER_NAME,
        version="0.11",
        instructions=INSTRUCTIONS,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
        on_list_resources=list_resources,
        on_read_resource=read_resource,
    )


def create_app(config: Config, transport: httpx.AsyncBaseTransport | None = None) -> Starlette:
    panel = PanelClient(config, transport=transport)
    registry = ToolRegistry(panel)
    server = build_server(registry)
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(config.allowed_hosts),
        allowed_origins=[f"https://{host}" for host in config.allowed_hosts] + [f"http://{host}" for host in config.allowed_hosts],
    )
    session_manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True, security_settings=security)

    async def healthz(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        try:
            count = await registry.reload()
            log.info("tools built from the panel's OpenAPI schema: %d generated + %d curated", count, len(registry.curated))
        except PanelError as exc:
            # The panel may still be starting; the curated tools work and `reload_tools` catches up.
            log.warning("could not load the panel's OpenAPI schema (%s): generated tools are empty until reload_tools",
                        exc.detail)
        async with session_manager.run():
            try:
                yield
            finally:
                await panel.aclose()

    app = Starlette(
        routes=[Route("/healthz", healthz, methods=["GET"]), Route("/mcp", endpoint=StreamableHTTPASGIApp(session_manager))],
        lifespan=lifespan,
    )
    app.add_middleware(BearerGate, token=config.token)
    app.state.registry = registry
    app.state.session_manager = session_manager
    app.state.panel = panel
    return app
