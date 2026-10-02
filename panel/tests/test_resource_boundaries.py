"""Observable resource limits, including transaction and streaming semantics."""
import asyncio
import sqlite3
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, Request
from starlette.staticfiles import StaticFiles

from panel.database import Database
from panel.web_context import install_security_middleware


def test_connection_context_commits_and_closes(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    with database.connect() as connection:
        connection.execute("CREATE TABLE sample (value INTEGER)")
        connection.execute("INSERT INTO sample VALUES (1)")
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    with database.connect() as reader:
        assert reader.execute("SELECT value FROM sample").fetchone()[0] == 1


def test_connection_context_rolls_back_and_closes(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    with database.connect() as connection:
        connection.execute("CREATE TABLE sample (value INTEGER)")
    with pytest.raises(ValueError, match="abort"):
        with database.connect() as failed:
            failed.execute("INSERT INTO sample VALUES (1)")
            raise ValueError("abort")
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        failed.execute("SELECT 1")
    with database.connect() as reader:
        assert reader.execute("SELECT count(*) FROM sample").fetchone()[0] == 0


@pytest.mark.anyio
@pytest.mark.parametrize("declared", [None, "1", "2048", "invalid", "-1"])
async def test_body_limit_stops_consuming_oversize_stream(declared):
    app = FastAPI()
    install_security_middleware(app, SimpleNamespace(body_limit_bytes=1024))
    invoked = False
    consumed = 0

    @app.post("/")
    async def endpoint(request: Request):
        nonlocal invoked
        invoked = True
        return {"size": len(await request.body())}

    async def content():
        nonlocal consumed
        for _ in range(10):
            consumed += 1
            yield b"x" * 1024

    headers = {"Content-Length": declared} if declared is not None else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/", content=content(), headers=headers)
    assert response.status_code == 413
    assert consumed <= 2
    assert not invoked
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]


@pytest.mark.anyio
@pytest.mark.parametrize("size", [0, 1023, 1024])
async def test_bounded_body_preserves_bytes_for_handler(size):
    app = FastAPI()
    install_security_middleware(app, SimpleNamespace(body_limit_bytes=1024))

    @app.post("/")
    async def endpoint(request: Request):
        return {"body": (await request.body()).decode()}

    async def content():
        yield b"x" * (size // 2)
        yield b"x" * (size - size // 2)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/", content=content())
    assert response.status_code == 200
    assert response.json() == {"body": "x" * size}


@pytest.mark.anyio
async def test_static_files_ignore_excessive_ranges(tmp_path):
    (tmp_path / "asset.txt").write_bytes(b"x" * 1000)
    app = FastAPI()
    app.mount("/static", StaticFiles(directory=tmp_path))
    ranges = "bytes=" + ",".join(f"{i * 3}-{i * 3}" for i in range(101))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/static/asset.txt", headers={"Range": ranges})
    # RFC 9110 permits ignoring Range; the fixed upstream caps parsing work.
    assert response.status_code == 200
    assert response.content == b"x" * 1000


@pytest.mark.anyio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_incomplete_body_never_dispatches_or_becomes_server_error(cancelled):
    app = FastAPI()
    install_security_middleware(app, SimpleNamespace(body_limit_bytes=1024))
    invoked = False
    messages = []
    received = 0

    @app.post("/")
    async def endpoint():
        nonlocal invoked
        invoked = True
        return {}

    async def receive():
        nonlocal received
        received += 1
        if received == 1:
            return {"type": "http.request", "body": b"partial", "more_body": True}
        if cancelled:
            raise asyncio.CancelledError()
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
             "http_version": "1.1", "method": "POST", "scheme": "http", "path": "/",
             "raw_path": b"/", "query_string": b"", "headers": [], "root_path": "",
             "server": ("test", 80), "client": ("127.0.0.1", 1234)}
    if cancelled:
        with pytest.raises(asyncio.CancelledError):
            await app(scope, receive, send)
        assert not messages
    else:
        await app(scope, receive, send)
        assert [message["status"] for message in messages if message["type"] == "http.response.start"] == [400]
    assert not invoked
