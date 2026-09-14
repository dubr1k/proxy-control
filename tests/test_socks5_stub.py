"""The lab's stand-in SOCKS5 egress (`scripts/lab/socks5-stub.py`): relays and logs."""
from __future__ import annotations

import asyncio
import importlib.util
import ipaddress
from pathlib import Path

STUB = Path(__file__).resolve().parents[1] / "scripts" / "lab" / "socks5-stub.py"


def _load():
    spec = importlib.util.spec_from_file_location("socks5_stub", STUB)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _echo(reader, writer):
    while data := await reader.read(1024):
        writer.write(data)
        await writer.drain()
    writer.close()


async def _connect_through(port: int, host: str, target_port: int, atyp: int) -> tuple[bytes, asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    address = bytes([len(host)]) + host.encode() if atyp == 3 else ipaddress.ip_address(host).packed
    writer.write(b"\x05\x01\x00" + bytes([atyp]) + address + target_port.to_bytes(2, "big"))
    await writer.drain()
    reply = await reader.readexactly(10)
    return reply, reader, writer


def test_stub_logs_connect_target_and_relays(tmp_path):
    asyncio.run(_relays(tmp_path))


async def _relays(tmp_path):
    module = _load()
    echo = await asyncio.start_server(_echo, "127.0.0.1", 0)
    echo_port = echo.sockets[0].getsockname()[1]
    log = tmp_path / "connects.log"
    stub = module.Stub(log)
    server = await stub.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reply, reader, writer = await _connect_through(port, "localhost", echo_port, atyp=3)
        assert reply[:2] == b"\x05\x00"
        writer.write(b"ping")
        await writer.drain()
        assert await reader.readexactly(4) == b"ping"
        writer.close()
        reply, _, writer2 = await _connect_through(port, "127.0.0.1", echo_port, atyp=1)
        assert reply[:2] == b"\x05\x00"
        writer2.close()
        await asyncio.sleep(0.05)
    finally:
        server.close()
        echo.close()
    lines = [line.split("\t") for line in log.read_text().splitlines()]
    assert [(host, int(p)) for _, host, p in lines] == [("localhost", echo_port), ("127.0.0.1", echo_port)]
    assert stub.connects == [("localhost", echo_port), ("127.0.0.1", echo_port)]


def test_stub_reports_a_refused_target_and_refuses_when_told_to():
    asyncio.run(_refuses())


async def _refuses():
    module = _load()
    stub = module.Stub(None)
    server = await stub.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        # A closed port on loopback: connection refused, reported as such (0x05), never a hang.
        probe = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        closed_port = probe.sockets[0].getsockname()[1]
        probe.close()
        await probe.wait_closed()
        reply, _, writer = await _connect_through(port, "127.0.0.1", closed_port, atyp=1)
        assert reply[1] == 0x05
        writer.close()
    finally:
        server.close()
    refusing = module.Stub(None, refuse=True)
    server = await refusing.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        try:
            assert await reader.read(2) == b""  # closed at once (EOF, or a reset of the unread greeting)
        except ConnectionResetError:
            pass
        writer.close()
    finally:
        server.close()
