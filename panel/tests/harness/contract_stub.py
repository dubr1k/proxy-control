"""The Python panel behind the Rust binary's test contract — a stand-in `PANEL_RUST_BIN`.

It proves the `PANEL_IMPL=rust` half of the harness (a separate process on a Unix socket, the
doubles reached over their sockets, CLI seeding, the `/__test/*` hooks, `PANEL_TEST_NODE_ROUTES`)
before the Rust binary exists, and shows the contract in code (see `server.py` for the text):

    printf '#!/bin/sh\\nexec %s -m panel.tests.harness.contract_stub "$@"\\n' "$VENV/bin/python" > /tmp/panel-stub
    chmod +x /tmp/panel-stub
    PANEL_IMPL=rust PANEL_RUST_BIN=/tmp/panel-stub python -m pytest panel/tests -m blackbox

`<stub> cli …` runs `panel.cli`; `<stub>` alone serves on `PANEL_LISTEN=unix:<path>` with the
background loops paused (the pre-serve enforcement pass still runs, as the lifespan does).
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import sys

import httpx

KNOBS = {
    "login_attempts": "PANEL_TEST_LOGIN_ATTEMPTS",
    "login_window_seconds": "PANEL_TEST_LOGIN_WINDOW_SECONDS",
    "reveal_ttl_seconds": "PANEL_TEST_REVEAL_TTL_SECONDS",
    "session_ttl_seconds": "PANEL_TEST_SESSION_TTL_SECONDS",
    "body_limit_bytes": "PANEL_TEST_BODY_LIMIT_BYTES",
    "login_verify_concurrency": "PANEL_TEST_LOGIN_VERIFY_CONCURRENCY",
    "api_key_rate_per_minute": "PANEL_TEST_API_KEY_RATE_PER_MINUTE",
}
MONOTONIC_OFFSET = 1_700_000_000.0


class _Clock:
    def __init__(self):
        self.now: float | None = None

    def time(self) -> float:
        import time

        return time.time() if self.now is None else self.now

    def monotonic(self) -> float:
        import time

        return time.monotonic() if self.now is None else self.now - MONOTONIC_OFFSET


class _UnixRoutes(httpx.AsyncBaseTransport):
    """`PANEL_TEST_NODE_ROUTES`: `https://<host>` is dialled as plain HTTP on that host's socket."""

    def __init__(self, routes: dict[str, str]):
        self.routes = routes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = self.routes.get(request.url.host)
        if path is None:
            raise httpx.ConnectError(f"no route to {request.url.host}", request=request)
        forwarded = httpx.Request(request.method, request.url.copy_with(scheme="http"), headers=request.headers,
                                  content=request.content)
        async with httpx.AsyncHTTPTransport(uds=path) as transport:
            response = await transport.handle_async_request(forwarded)
            content = await response.aread()
        return httpx.Response(response.status_code, headers=response.headers, content=content, request=request)


def _routes(value: str) -> dict[str, str]:
    routes = {}
    for item in filter(None, value.split(",")):
        host, _, target = item.partition("=")
        if not target.startswith("unix:"):
            raise SystemExit(f"PANEL_TEST_NODE_ROUTES: {item!r} is not host=unix:<path>")
        routes[host] = target[len("unix:"):]
    return routes


def build_app():
    from fastapi import Body, HTTPException

    import panel.protocols.telemt as telemt_adapter
    from panel.app import create_app
    from panel.fleet_v2.client import NodeClient
    from panel.settings import Settings
    from panel.tests.harness.server import install_clock, settle_app, tick_app

    settings = Settings()
    overrides = {}
    for field, env in KNOBS.items():
        if env in os.environ:
            overrides[field] = int(os.environ[env])
    settings = dataclasses.replace(settings, **overrides)
    bridge = {"answer": True}

    async def probe(_ingress):
        return bridge["answer"]

    telemt_adapter._probe_bridge = probe
    app = create_app(settings)
    routes = _routes(os.environ.get("PANEL_TEST_NODE_ROUTES", ""))
    if routes:
        transport = _UnixRoutes(routes)
        app.state.links.client_factory = lambda url, key, **kw: NodeClient(url, key, transport=transport, **kw)
    clock = _Clock()

    @app.post("/__test/clock", include_in_schema=False)
    async def test_clock(body: dict = Body(...)):
        if clock.now is None:
            clock.now = clock.time()
            install_clock(app, clock)
        if "time" in body:
            clock.now = float(body["time"])
        elif "advance" in body:
            clock.now += float(body["advance"])
        else:
            raise HTTPException(422, "time or advance")
        return {"time": clock.now, "monotonic": clock.monotonic()}

    @app.post("/__test/tick/{loop}", include_in_schema=False)
    async def test_tick(loop: str, body: dict | None = Body(default=None)):
        if loop not in ("pusher", "enforcer", "metrics"):
            raise HTTPException(404, "unknown loop")
        await tick_app(app, loop, **(body or {}))
        return {"ok": True}

    @app.post("/__test/settle", include_in_schema=False)
    async def test_settle():
        await settle_app(app)
        return {"ok": True}

    @app.post("/__test/probe-bridge", include_in_schema=False)
    async def test_probe_bridge(body: dict = Body(...)):
        bridge["answer"] = bool(body.get("answer"))
        return {"answer": bridge["answer"]}

    return app


async def serve(path: str) -> None:
    import uvicorn

    app = build_app()
    await app.state.access_enforcer.tick(force=True)  # what the lifespan does before serving
    config = uvicorn.Config(app, uds=path, lifespan="off", access_log=False, log_level="warning")
    await uvicorn.Server(config).serve()


def main(argv: list[str]) -> int:
    if argv[:1] == ["cli"]:
        from panel import cli

        sys.argv = ["cli.py", *argv[1:]]
        cli.main()
        return 0
    listen = os.environ.get("PANEL_LISTEN", "")
    if not listen.startswith("unix:"):
        print(json.dumps({"error": "PANEL_LISTEN=unix:<path> is required"}), file=sys.stderr)
        return 64
    asyncio.run(serve(listen[len("unix:"):]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
