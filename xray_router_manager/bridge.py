"""The MTProxy ingress bridge (v1.1): SOCKS5 on the Compose network → VLESS on the router's
Unix socket.

Telemt runs on the Compose bridge network and the Xray-router on the host network, so Telemt
cannot reach the router's loopback ingresses, and a connection from the bridge to an address
of the host meets the host's firewall. A Unix socket in a volume both containers share crosses
the namespaces without one. Xray listens on a socket only with `vless` (its `socks` inbound
ignores a socket path, and its outbounds cannot dial one — proved on 26.3.27), and Telemt
dials only TCP SOCKS5: this process is the one piece between them.

    Telemt ── SOCKS5 CONNECT, username/password ──▶ bridge :45103
    bridge ── VLESS request (version 0, uuid, no addons, TCP, port, address) ──▶ router socket
    then bytes both ways; the VLESS response header (version, addons) is cut off the first reply

The credential (`{uuid, username, password}`) is the router manager's: it writes a copy next to
the socket and the bridge rereads it when the file changes. No routing happens here — the
router decides where the connection leaves by the `mtproxy` inbound's rules.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import secrets
import socket
import struct
import sys
import uuid as uuid_module
from pathlib import Path

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 45103
MAX_CONNECTIONS = 4096
HANDSHAKE_TIMEOUT = 10.0
BUFFER = 65536
log = logging.getLogger("xray_router_bridge")

# SOCKS5 replies (RFC 1928 §6).
REPLY_OK, REPLY_FAILURE, REPLY_NOT_ALLOWED, REPLY_COMMAND, REPLY_ADDRESS = 0, 1, 2, 7, 8


class BridgeRefused(Exception):
    def __init__(self, reply: int):
        super().__init__(reply)
        self.reply = reply


class Credential:
    """The router's credential file, reread whenever its mtime or size changes."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._stamp: tuple[int, int] | None = None
        self._value: tuple[bytes, bytes, bytes] | None = None

    def load(self) -> tuple[bytes, bytes, bytes]:
        """(uuid bytes, username, password), or `OSError`/`ValueError` while there is none."""
        info = self.path.stat()
        stamp = (info.st_mtime_ns, info.st_size)
        if stamp != self._stamp or self._value is None:
            record = json.loads(self.path.read_text())
            value = (uuid_module.UUID(record["uuid"]).bytes, record["username"].encode(), record["password"].encode())
            self._stamp, self._value = stamp, value
        return self._value


def vless_request(uuid: bytes, atyp: int, address: bytes, port: int) -> bytes:
    """The VLESS request header for a TCP CONNECT. `address` is what SOCKS5 carried: 4 bytes
    for IPv4, 16 for IPv6, the name for a domain (VLESS: 1 IPv4, 2 domain, 3 IPv6)."""
    if atyp == 1:
        target = b"\x01" + address
    elif atyp == 3:
        target = b"\x02" + bytes([len(address)]) + address
    elif atyp == 4:
        target = b"\x03" + address
    else:
        raise BridgeRefused(REPLY_ADDRESS)
    return b"\x00" + uuid + b"\x00" + b"\x01" + struct.pack("!H", port) + target


async def _socks_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                           credential: tuple[bytes, bytes, bytes]) -> tuple[int, bytes, int]:
    """Greeting, username/password (RFC 1929), the CONNECT request: (atyp, address, port)."""
    version, count = await reader.readexactly(2)
    methods = await reader.readexactly(count)
    if version != 5 or 2 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        raise BridgeRefused(REPLY_NOT_ALLOWED)
    writer.write(b"\x05\x02")
    await writer.drain()
    auth_version, user_length = await reader.readexactly(2)
    username = await reader.readexactly(user_length)
    password = await reader.readexactly((await reader.readexactly(1))[0])
    _uuid, expected_user, expected_password = credential
    allowed = auth_version == 1 and secrets.compare_digest(username, expected_user) and secrets.compare_digest(password, expected_password)
    writer.write(b"\x01" + (b"\x00" if allowed else b"\x01"))
    await writer.drain()
    if not allowed:
        raise BridgeRefused(REPLY_NOT_ALLOWED)
    version, command, _reserved, atyp = await reader.readexactly(4)
    if atyp == 1:
        address = await reader.readexactly(4)
    elif atyp == 3:
        address = await reader.readexactly((await reader.readexactly(1))[0])
    elif atyp == 4:
        address = await reader.readexactly(16)
    else:
        raise BridgeRefused(REPLY_ADDRESS)
    (port,) = struct.unpack("!H", await reader.readexactly(2))
    if version != 5 or command != 1:
        raise BridgeRefused(REPLY_COMMAND)
    return atyp, address, port


def _reply(code: int) -> bytes:
    return b"\x05" + bytes([code]) + b"\x00\x01" + b"\x00" * 6


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(BUFFER):
            writer.write(data)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except OSError:
            pass


async def _pump_response(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Router → client, the VLESS response header (version, addons length, addons) cut off."""
    try:
        _version, addons = await reader.readexactly(2)
        if addons:
            await reader.readexactly(addons)
    except (OSError, asyncio.IncompleteReadError):
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except OSError:
            pass
        return
    await _pump(reader, writer)


class Bridge:
    def __init__(self, socket_path: Path | str, credential_path: Path | str, *, max_connections: int = MAX_CONNECTIONS):
        self.socket_path = str(socket_path)
        self.credential = Credential(Path(credential_path))
        self.slots = asyncio.Semaphore(max_connections)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.slots.locked():
            writer.close()
            return
        async with self.slots:
            upstream_writer = None
            try:
                try:
                    credential = self.credential.load()
                except (OSError, ValueError, KeyError):
                    log.warning("no ingress credential yet: is the router up?")
                    return
                try:
                    atyp, address, port = await asyncio.wait_for(_socks_handshake(reader, writer, credential), HANDSHAKE_TIMEOUT)
                    request = vless_request(credential[0], atyp, address, port)
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_unix_connection(self.socket_path), HANDSHAKE_TIMEOUT)
                except BridgeRefused as exc:
                    if exc.reply != REPLY_NOT_ALLOWED:
                        writer.write(_reply(exc.reply))
                        await writer.drain()
                    return
                except (OSError, asyncio.TimeoutError):
                    writer.write(_reply(REPLY_FAILURE))
                    await writer.drain()
                    return
                upstream_writer.write(request)
                await upstream_writer.drain()
                writer.write(_reply(REPLY_OK))
                await writer.drain()
                await asyncio.gather(_pump(reader, upstream_writer), _pump_response(upstream_reader, writer))
            except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
            finally:
                for stream in (writer, upstream_writer):
                    if stream is not None:
                        stream.close()

    async def serve(self, host: str = LISTEN_HOST, port: int = LISTEN_PORT) -> None:
        server = await asyncio.start_server(self.handle, host, port, reuse_address=True)
        async with server:
            await server.serve_forever()


def check(host: str = "127.0.0.1", port: int = LISTEN_PORT, timeout: float = 2.0) -> bool:
    """The container's health: the listener accepts and answers a SOCKS5 greeting."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as probe:
            probe.sendall(b"\x05\x01\x02")
            return probe.recv(2) == b"\x05\x02"
    except OSError:
        return False


def _listen() -> tuple[str, int]:
    value = os.getenv("XRAY_ROUTER_BRIDGE_LISTEN", f"{LISTEN_HOST}:{LISTEN_PORT}").strip()
    host, _sep, port = value.rpartition(":")
    ipaddress.ip_address(host)
    return host, int(port)


def main(argv: list[str] | None = None) -> None:
    arguments = sys.argv[1:] if argv is None else argv
    host, port = _listen()
    if arguments == ["--check"]:
        raise SystemExit(0 if check("127.0.0.1" if host == LISTEN_HOST else host, port) else 1)
    if arguments:
        raise SystemExit("usage: python -m xray_router_manager.bridge [--check]")
    logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")
    socket_path = Path(os.getenv("XRAY_ROUTER_INGRESS_MTPROXY_SOCKET", "/run/xray-router/ingress-mtproxy.sock"))
    credential_path = Path(os.getenv("XRAY_ROUTER_INGRESS_MTPROXY_CREDENTIAL", str(socket_path.parent / "ingress-mtproxy.json")))
    asyncio.run(Bridge(socket_path, credential_path).serve(host, port))


if __name__ == "__main__":
    main()
