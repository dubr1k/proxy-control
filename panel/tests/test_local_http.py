"""Manager clients share one TLS context: building httpx's default one loads the whole CA
bundle, and the monitor polls every manager once a second (3.0.0, profiled at 87 % of the
panel's busy CPU)."""
from __future__ import annotations

import asyncio
import contextlib
import ssl

import pytest

from panel import local_http
from panel.amneziawg import AmneziawgClient
from panel.mieru import MieruClient
from panel.naive import NaiveClient
from panel.telemt import TelemtClient, TelemtError
from panel.trusttunnel import TrusttunnelClient
from panel.versions import VersionClient
from panel.xray_router import XrayRouterClient

pytestmark = pytest.mark.anyio

REPLY = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'


async def _answer(reader, writer):
    while (await reader.readline()) not in (b"\r\n", b""):
        pass
    writer.write(REPLY)
    await writer.drain()
    writer.close()


@pytest.fixture
def counted(monkeypatch):
    calls = []
    original = ssl.create_default_context

    def counting(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(ssl, "create_default_context", counting)
    local_http.tls_context.cache_clear()
    yield calls
    local_http.tls_context.cache_clear()


async def test_every_manager_client_reuses_one_tls_context(tmp_path, counted):
    path = str(tmp_path / "manager.sock")
    server = await asyncio.start_unix_server(_answer, path)
    clients = [
        VersionClient(path), MieruClient(path, "t"), NaiveClient(path, "t"), AmneziawgClient(path, "t"),
        TrusttunnelClient(path, "t"), XrayRouterClient(path, "t"),
    ]
    async with server:
        for _ in range(3):
            for client in clients:
                assert await client._request("GET", "/v1/health") == {}
    assert len(counted) <= 1


async def test_the_telemt_client_reuses_it_over_tcp(counted):
    server = await asyncio.start_server(_answer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client = TelemtClient(f"http://127.0.0.1:{port}", "Bearer t")
    async with server:
        for _ in range(3):
            with contextlib.suppress(TelemtError):  # the body is not Telemt's envelope; the transport is the point
                await client._request("GET", "/v1/users")
    assert len(counted) <= 1


def test_the_shared_context_still_verifies_peers():
    context = local_http.tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert local_http.tls_context() is context
