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









