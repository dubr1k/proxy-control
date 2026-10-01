"""The MTProxy ingress bridge (v1.1): SOCKS5 with a login in, a VLESS request over the router's
Unix socket out, bytes both ways — against a fake VLESS server on a socket."""
from __future__ import annotations

import asyncio
import json
import os
import struct
import uuid

import pytest

from xray_router_manager.bridge import Bridge, check, vless_request

UUID = "11111111-2222-4333-8444-555555555555"


def _credential(path, *, password="p" * 32):
    path.write_text(json.dumps({"uuid": UUID, "username": "telemt", "password": password}))


async def _fake_router(path, seen):
    """A VLESS server: records the request header, answers `\\x00\\x00` + the payload upper-cased."""

    async def handle(reader, writer):
        head = await reader.readexactly(1 + 16 + 1 + 1 + 2 + 1)
        version, user, addons, command, port, atyp = head[0], head[1:17], head[17], head[18], head[19:21], head[21]
        if atyp == 1:
            address = await reader.readexactly(4)
        elif atyp == 2:
            address = await reader.readexactly((await reader.readexactly(1))[0])
        else:
            address = await reader.readexactly(16)
        seen.append({"version": version, "uuid": str(uuid.UUID(bytes=user)), "addons": addons, "command": command,
                     "port": struct.unpack("!H", port)[0], "atyp": atyp, "address": address})
        data = await reader.read(1024)
        writer.write(b"\x00\x00" + data.upper())
        await writer.drain()
        writer.close()

    return await asyncio.start_unix_server(handle, path=str(path))


async def _socks(port, atyp, address, target_port, payload, *, user=b"telemt", password=b"p" * 32, methods=b"\x02", command=1):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05" + bytes([len(methods)]) + methods)
    choice = await reader.readexactly(2)
    if choice != b"\x05\x02":
        writer.close()
        return {"method": choice}
    writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
    auth = await reader.readexactly(2)
    if auth != b"\x01\x00":
        writer.close()
        return {"auth": auth}
    body = address if atyp != 3 else bytes([len(address)]) + address
    writer.write(b"\x05" + bytes([command]) + b"\x00" + bytes([atyp]) + body + struct.pack("!H", target_port))
    reply = await reader.readexactly(10)
    if reply[1] != 0:
        writer.close()
        return {"reply": reply[1]}
    writer.write(payload)
    await writer.drain()
    data = await reader.read(1024)
    writer.close()
    return {"reply": 0, "data": data}


@pytest.fixture
def bridge_env(tmp_path):
    socket_path = tmp_path / "ingress-mtproxy.sock"
    credential = tmp_path / "ingress-mtproxy.json"
    _credential(credential)
    return socket_path, credential


def _run(coroutine):
    return asyncio.run(coroutine)


def test_vless_request_header_for_each_address_kind():
    user = uuid.UUID(UUID).bytes
    assert vless_request(user, 1, bytes([149, 154, 167, 51]), 443) == b"\x00" + user + b"\x00\x01\x01\xbb\x01" + bytes([149, 154, 167, 51])
    assert vless_request(user, 3, b"t.me", 443) == b"\x00" + user + b"\x00\x01\x01\xbb\x02\x04t.me"
    assert vless_request(user, 4, bytes(16), 443)[21:22] == b"\x03"


@pytest.mark.parametrize(("atyp", "address", "vless_atyp"), [
    (1, bytes([149, 154, 167, 51]), 1), (3, b"telegram.org", 2), (4, bytes.fromhex("20010b28f23d8001" + "0" * 15 + "a"), 3)])
def test_a_connect_becomes_a_vless_request_and_bytes_flow_both_ways(bridge_env, atyp, address, vless_atyp):
    socket_path, credential = bridge_env

    async def scenario():
        seen = []
        router = await _fake_router(socket_path, seen)
        bridge = Bridge(socket_path, credential)
        server = await asyncio.start_server(bridge.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        result = await _socks(port, atyp, address, 443, b"hello")
        server.close()
        router.close()
        return seen, result

    seen, result = _run(scenario())
    assert result == {"reply": 0, "data": b"HELLO"}
    assert seen == [{"version": 0, "uuid": UUID, "addons": 0, "command": 1, "port": 443, "atyp": vless_atyp, "address": address}]


def test_a_wrong_password_or_no_login_is_refused_before_the_router(bridge_env):
    socket_path, credential = bridge_env

    async def scenario():
        seen = []
        router = await _fake_router(socket_path, seen)
        server = await asyncio.start_server(Bridge(socket_path, credential).handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        wrong = await _socks(port, 1, bytes(4), 443, b"x", password=b"q" * 32)
        anonymous = await _socks(port, 1, bytes(4), 443, b"x", methods=b"\x00")
        bind = await _socks(port, 1, bytes(4), 443, b"x", command=2)
        server.close()
        router.close()
        return seen, wrong, anonymous, bind

    seen, wrong, anonymous, bind = _run(scenario())
    assert wrong == {"auth": b"\x01\x01"} and anonymous == {"method": b"\x05\xff"} and bind == {"reply": 7}
    assert seen == []


def test_no_router_socket_is_a_general_failure(bridge_env):
    socket_path, credential = bridge_env

    async def scenario():
        server = await asyncio.start_server(Bridge(socket_path, credential).handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        result = await _socks(port, 1, bytes([1, 1, 1, 1]), 443, b"x")
        server.close()
        return result

    assert _run(scenario()) == {"reply": 1}


def test_a_new_credential_is_picked_up_without_a_restart(bridge_env):
    socket_path, credential = bridge_env

    async def scenario():
        seen = []
        router = await _fake_router(socket_path, seen)
        server = await asyncio.start_server(Bridge(socket_path, credential).handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        first = await _socks(port, 1, bytes([1, 1, 1, 1]), 443, b"a")
        _credential(credential, password="r" * 40)
        os.utime(credential, ns=(1, 1))
        old = await _socks(port, 1, bytes([1, 1, 1, 1]), 443, b"b")
        new = await _socks(port, 1, bytes([1, 1, 1, 1]), 443, b"c", password=b"r" * 40)
        server.close()
        router.close()
        return first, old, new

    first, old, new = _run(scenario())
    assert first["reply"] == 0 and old == {"auth": b"\x01\x01"} and new["data"] == b"C"


def test_check_answers_only_a_live_listener(bridge_env):
    socket_path, credential = bridge_env

    async def scenario():
        server = await asyncio.start_server(Bridge(socket_path, credential).handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        alive = await asyncio.get_running_loop().run_in_executor(None, check, "127.0.0.1", port)
        server.close()
        await server.wait_closed()
        return port, alive

    port, alive = _run(scenario())
    assert alive is True and check("127.0.0.1", port, timeout=0.5) is False
