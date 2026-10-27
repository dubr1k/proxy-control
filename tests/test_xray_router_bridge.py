"""The MTProxy ingress bridge (Go since 3.0): SOCKS5 with a login in, a VLESS request over the
router's Unix socket out, bytes both ways — the built binary against a fake VLESS server on a
socket, as the container runs it. The unit tests live next to the source (`go test`)."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import struct
import subprocess
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "xray_router_manager" / "mtproxy-bridge"
UUID = "11111111-2222-4333-8444-555555555555"
PASSWORD = "p" * 32


@pytest.fixture(scope="session")
def bridge_binary(tmp_path_factory):
    go = shutil.which("go") or ("/usr/local/go/bin/go" if Path("/usr/local/go/bin/go").exists() else None)
    assert go is not None, "the Go toolchain is required to exercise the MTProxy bridge"
    out = tmp_path_factory.mktemp("bridge") / "mtproxy-bridge"
    subprocess.run([go, "build", "-trimpath", "-o", str(out), "."], cwd=SOURCE, check=True,
                   env={**os.environ, "CGO_ENABLED": "0"})
    return out


def _credential(path, *, password=PASSWORD):
    path.write_text(json.dumps({"uuid": UUID, "username": "telemt", "password": password}))


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _environment(tmp_path, port):
    return {"PATH": os.environ.get("PATH", ""), "XRAY_ROUTER_BRIDGE_LISTEN": f"127.0.0.1:{port}",
            "XRAY_ROUTER_INGRESS_MTPROXY_SOCKET": str(tmp_path / "ingress-mtproxy.sock")}


def _check(binary, env) -> int:
    return subprocess.run([str(binary), "--check"], env=env, capture_output=True, timeout=10).returncode


@pytest.fixture
def bridge(bridge_binary, tmp_path):
    """The bridge as a process, with the credential next to the socket (its default path)."""
    _credential(tmp_path / "ingress-mtproxy.json")
    port = _free_port()
    env = _environment(tmp_path, port)
    process = subprocess.Popen([str(bridge_binary)], env=env, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 10
    while _check(bridge_binary, env) != 0:
        assert process.poll() is None and time.monotonic() < deadline, "the bridge did not come up"
        time.sleep(0.05)
    yield port
    process.terminate()
    process.wait(timeout=5)


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


async def _socks(port, atyp, address, target_port, payload, *, user=b"telemt", password=PASSWORD.encode(),
                 methods=b"\x02", command=1):
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


@pytest.mark.parametrize(("atyp", "address", "vless_atyp"), [
    (1, bytes([149, 154, 167, 51]), 1), (3, b"telegram.org", 2), (4, bytes.fromhex("20010b28f23d8001" + "0" * 15 + "a"), 3)])
def test_a_connect_becomes_a_vless_request_and_bytes_flow_both_ways(bridge, tmp_path, atyp, address, vless_atyp):
    async def scenario():
        seen = []
        router = await _fake_router(tmp_path / "ingress-mtproxy.sock", seen)
        result = await _socks(bridge, atyp, address, 443, b"hello")
        router.close()
        return seen, result

    seen, result = asyncio.run(scenario())
    assert result == {"reply": 0, "data": b"HELLO"}
    assert seen == [{"version": 0, "uuid": UUID, "addons": 0, "command": 1, "port": 443, "atyp": vless_atyp, "address": address}]


def test_a_wrong_password_or_no_login_is_refused_before_the_router(bridge, tmp_path):
    async def scenario():
        seen = []
        router = await _fake_router(tmp_path / "ingress-mtproxy.sock", seen)
        wrong = await _socks(bridge, 1, bytes(4), 443, b"x", password=b"q" * 32)
        anonymous = await _socks(bridge, 1, bytes(4), 443, b"x", methods=b"\x00")
        bind = await _socks(bridge, 1, bytes(4), 443, b"x", command=2)
        router.close()
        return seen, wrong, anonymous, bind

    seen, wrong, anonymous, bind = asyncio.run(scenario())
    assert wrong == {"auth": b"\x01\x01"} and anonymous == {"method": b"\x05\xff"} and bind == {"reply": 7}
    assert seen == []


def test_no_router_socket_is_a_general_failure(bridge):
    assert asyncio.run(_socks(bridge, 1, bytes([1, 1, 1, 1]), 443, b"x")) == {"reply": 1}


def test_a_new_credential_is_picked_up_without_a_restart(bridge, tmp_path):
    credential = tmp_path / "ingress-mtproxy.json"

    async def scenario():
        seen = []
        router = await _fake_router(tmp_path / "ingress-mtproxy.sock", seen)
        first = await _socks(bridge, 1, bytes([1, 1, 1, 1]), 443, b"a")
        _credential(credential, password="r" * 40)
        os.utime(credential, ns=(1, 1))
        old = await _socks(bridge, 1, bytes([1, 1, 1, 1]), 443, b"b")
        new = await _socks(bridge, 1, bytes([1, 1, 1, 1]), 443, b"c", password=b"r" * 40)
        router.close()
        return first, old, new

    first, old, new = asyncio.run(scenario())
    assert first["reply"] == 0 and old == {"auth": b"\x01\x01"} and new["data"] == b"C"


def test_check_answers_only_a_live_listener(bridge_binary, tmp_path):
    _credential(tmp_path / "ingress-mtproxy.json")
    env = _environment(tmp_path, _free_port())
    assert _check(bridge_binary, env) == 1
    process = subprocess.Popen([str(bridge_binary)], env=env)
    try:
        deadline = time.monotonic() + 10
        while _check(bridge_binary, env) != 0:
            assert time.monotonic() < deadline
            time.sleep(0.05)
    finally:
        process.terminate()
        process.wait(timeout=5)
    assert _check(bridge_binary, env) == 1


def test_a_bad_listen_address_or_argument_is_refused(bridge_binary, tmp_path):
    env = {**_environment(tmp_path, 1), "XRAY_ROUTER_BRIDGE_LISTEN": "bridge:45103"}
    assert subprocess.run([str(bridge_binary)], env=env, capture_output=True, timeout=10).returncode == 1
    usage = subprocess.run([str(bridge_binary), "--status"], env=_environment(tmp_path, 1), capture_output=True, timeout=10)
    assert usage.returncode == 1 and b"usage" in usage.stderr


def test_a_large_transfer_arrives_intact_in_both_directions(bridge, tmp_path):
    """Sixteen megabytes each way through the bridge, byte for byte (the pumps and half-close)."""
    blob = os.urandom(16 * 1024 * 1024)

    async def echo(reader, writer):
        await reader.readexactly(22 + 4)
        writer.write(b"\x00\x00")
        while chunk := await reader.read(1 << 16):
            writer.write(chunk)
            await writer.drain()
        writer.write_eof()
        writer.close()

    async def scenario():
        router = await asyncio.start_unix_server(echo, path=str(tmp_path / "ingress-mtproxy.sock"))
        reader, writer = await asyncio.open_connection("127.0.0.1", bridge)
        writer.write(b"\x05\x01\x02")
        assert await reader.readexactly(2) == b"\x05\x02"
        writer.write(b"\x01\x06telemt" + bytes([len(PASSWORD)]) + PASSWORD.encode())
        assert await reader.readexactly(2) == b"\x01\x00"
        writer.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x01\xbb")
        assert (await reader.readexactly(10))[1] == 0

        async def send():
            for offset in range(0, len(blob), 1 << 20):
                writer.write(blob[offset:offset + (1 << 20)])
                await writer.drain()
            writer.write_eof()

        sender = asyncio.create_task(send())
        received = bytearray()
        while chunk := await reader.read(1 << 20):
            received += chunk
        await sender
        writer.close()
        router.close()
        return bytes(received)

    assert asyncio.run(scenario()) == blob
