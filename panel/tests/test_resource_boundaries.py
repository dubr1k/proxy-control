"""Resource-boundary regressions through the actual panel's HTTP listener."""
from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.anyio


async def exchange(server, request: bytes, *, eof=False) -> bytes:
    reader, writer = await asyncio.open_unix_connection(server.socket)
    try:
        writer.write(request)
        await writer.drain()
        if eof:
            writer.write_eof()
        return await asyncio.wait_for(reader.read(), 5)
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.parametrize("declared", [False, True])
async def test_body_limit_stops_consuming_oversize_stream(panel_server, declared):
    server = panel_server(body_limit_bytes=64)
    if declared:
        framing = b"Content-Length: 65\r\n\r\n"
    else:
        framing = b"Transfer-Encoding: chunked\r\n\r\n41\r\n" + b"x" * 65 + b"\r\n"
    response = await exchange(server, b"POST /api/auth/login HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n" + framing)
    assert response.startswith(b"HTTP/1.1 413 "), response
    assert (await server.client.get("/healthz")).status_code == 200


@pytest.mark.parametrize("size", [32, 64])
async def test_bounded_body_preserves_bytes_for_handler(panel_server, size):
    server = panel_server(body_limit_bytes=64)
    body = b'{"time":1800000000}' + b" " * (size - len(b'{"time":1800000000}'))
    response = await server.client.post("/__test/clock", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 200, response.text
    assert response.json()["time"] == 1_800_000_000


async def test_static_files_ignore_excessive_ranges(panel_server):
    server = panel_server()
    plain = await server.client.get("/static/app.js")
    response = await server.client.get("/static/app.js", headers={"Range": "bytes=" + ",".join(f"{i * 2}-{i * 2}" for i in range(33))})
    assert response.status_code == plain.status_code == 200
    assert response.content == plain.content
    assert "content-range" not in response.headers


async def test_incomplete_body_never_dispatches_or_becomes_server_error(panel_server):
    server = panel_server()
    response = await exchange(server, b"POST /__test/clock HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\nContent-Length: 50\r\n\r\n{\"time\":1}", eof=True)
    assert not response or response.startswith(b"HTTP/1.1 400 "), response
    assert (await server.client.get("/healthz")).status_code == 200
    server.clock.set(1_800_000_000)
    assert server.clock.time() == 1_800_000_000
