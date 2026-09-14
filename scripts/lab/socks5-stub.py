#!/usr/bin/env python3
"""A stand-in for the WARP SOCKS5 endpoint on the lab host (v0.4 routing spike and gate).

The lab has no WARP. What the routing gate must prove is *which path* a tunnelled
connection took — through the node's egress proxy or straight out — and this stub makes
that observable: every CONNECT it accepts is written as one line `<utc-iso>\t<host>\t<port>`
to the log, then relayed as-is. RFC 1928, `NO AUTHENTICATION` only, TCP CONNECT only
(a BIND or UDP ASSOCIATE is answered `command not supported`). Nothing is filtered: a
policy's `block` is the proxy server's job, never this stub's.

    socks5-stub.py --listen 127.0.0.1:45000 --log /run/socks5-stub/connects.log

`--refuse` binds the socket and closes every connection at once (the reachability check
of a manager must fail cleanly, not hang). Throwaway lab tooling; not part of a release.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import ipaddress
import socket
import sys
from pathlib import Path

VERSION = 5
NO_AUTH, NO_ACCEPTABLE = 0x00, 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6 = 0x01, 0x03, 0x04
REP_OK, REP_FAILURE, REP_HOST_UNREACHABLE, REP_REFUSED, REP_COMMAND, REP_ATYP = 0x00, 0x01, 0x04, 0x05, 0x07, 0x08
RELAY_CHUNK = 65536


def _reply(code: int) -> bytes:
    return bytes([VERSION, code, 0x00, ATYP_IPV4]) + ipaddress.IPv4Address("0.0.0.0").packed + b"\x00\x00"


async def _read_target(reader: asyncio.StreamReader) -> tuple[str, int]:
    version, command, _reserved, atyp = await reader.readexactly(4)
    if version != VERSION:
        raise ValueError("not SOCKS5")
    if command != CMD_CONNECT:
        raise LookupError(REP_COMMAND)
    if atyp == ATYP_IPV4:
        host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
    elif atyp == ATYP_IPV6:
        host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    elif atyp == ATYP_DOMAIN:
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode("ascii", errors="replace")  # punycode on the wire
    else:
        raise LookupError(REP_ATYP)
    port = int.from_bytes(await reader.readexactly(2), "big")
    return host, port


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(RELAY_CHUNK):
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.write_eof()


class Stub:
    def __init__(self, log_path: Path | None, *, refuse: bool = False):
        self.log_path, self.refuse = log_path, refuse
        self.connects: list[tuple[str, int]] = []

    def _log(self, host: str, port: int) -> None:
        self.connects.append((host, port))
        if self.log_path is not None:
            stamp = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(f"{stamp}\t{host}\t{port}\n")

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer = None
        try:
            if self.refuse:
                return
            version, count = await reader.readexactly(2)
            methods = await reader.readexactly(count)
            if version != VERSION or NO_AUTH not in methods:
                writer.write(bytes([VERSION, NO_ACCEPTABLE]))
                await writer.drain()
                return
            writer.write(bytes([VERSION, NO_AUTH]))
            await writer.drain()
            try:
                host, port = await _read_target(reader)
            except LookupError as unsupported:
                writer.write(_reply(int(unsupported.args[0])))
                await writer.drain()
                return
            self._log(host, port)
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 15)
            except (ConnectionRefusedError, TimeoutError, asyncio.TimeoutError):
                writer.write(_reply(REP_REFUSED))
                await writer.drain()
                return
            except (OSError, socket.gaierror):
                writer.write(_reply(REP_HOST_UNREACHABLE))
                await writer.drain()
                return
            writer.write(_reply(REP_OK))
            await writer.drain()
            await asyncio.gather(_pump(reader, upstream_writer), _pump(upstream_reader, writer))
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            with contextlib.suppress(Exception):
                writer.write(_reply(REP_FAILURE))
        finally:
            for stream in (writer, upstream_writer):
                if stream is not None:
                    stream.close()
                    with contextlib.suppress(Exception):
                        await stream.wait_closed()

    async def serve(self, host: str, port: int) -> asyncio.base_events.Server:
        return await asyncio.start_server(self.handle, host, port)


async def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--listen", default="127.0.0.1:45000", help="host:port to listen on")
    parser.add_argument("--log", type=Path, default=None, help="append one line per CONNECT here")
    parser.add_argument("--refuse", action="store_true", help="accept and close at once (an unreachable egress)")
    args = parser.parse_args(argv)
    host, _, port = args.listen.rpartition(":")
    if args.log is not None:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.touch()
    stub = Stub(args.log, refuse=args.refuse)
    server = await stub.serve(host or "127.0.0.1", int(port))
    print(f"socks5-stub: listening on {args.listen}{' (refusing)' if args.refuse else ''}", flush=True)
    async with server:
        await server.serve_forever()
    return 0


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        sys.exit(asyncio.run(_main()))
