"""Everything the manager does to the machine, behind one injectable seam."""
from __future__ import annotations

import json
import os
import socket
import subprocess
from typing import Protocol

AMNEZIAWG_BINARY = "/usr/local/bin/amneziawg-go"
UAPI_DIR = "/var/run/amneziawg"
NFT_TABLE = "awg_manager"


class HostError(RuntimeError):
    """An ip/nft command failed."""


class UapiError(RuntimeError):
    """The amneziawg-go control socket is unreachable or returned a non-zero errno."""


class Process(Protocol):
    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float) -> int: ...


class Host(Protocol):
    def start_process(self, iface: str, log_level: str) -> Process: ...
    def ip(self, *args: str) -> None: ...
    def ip_json(self, *args: str) -> list: ...
    def nft_apply(self, script: str) -> None: ...
    def nft_delete(self) -> None: ...
    def uapi_set(self, iface: str, body: str) -> None: ...
    def uapi_get(self, iface: str) -> str: ...
    def ip_forward_enabled(self) -> bool: ...


def _uapi_exchange(path: str, request: bytes, timeout: float = 5.0) -> str:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(path)
            sock.sendall(request)
            data = b""
            # The reply always ends with `errno=<n>\n\n`.
            while not (data.endswith(b"\n\n") and b"errno=" in data):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        raise UapiError(f"control socket unavailable: {exc}") from exc
    text = data.decode("utf-8", "replace")
    tail = text.rstrip("\n").rsplit("\n", 1)[-1]
    if not tail.startswith("errno="):
        raise UapiError("truncated control reply")
    if tail != "errno=0":
        raise UapiError(f"control socket replied {tail}")
    return text[: text.rindex("errno=")]


class RealHost:
    def start_process(self, iface: str, log_level: str) -> subprocess.Popen:
        env = {**os.environ, "LOG_LEVEL": log_level}
        return subprocess.Popen([AMNEZIAWG_BINARY, "-f", iface], env=env, stdin=subprocess.DEVNULL)

    def _run(self, argv: list[str], stdin: str | None = None) -> None:
        try:
            done = subprocess.run(
                argv, input=stdin, capture_output=True, text=True, timeout=15, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostError(f"{argv[0]} failed to run: {exc}") from exc
        if done.returncode != 0:
            raise HostError(f"{' '.join(argv[:3])} failed: {done.stderr.strip()[:300]}")

    def ip(self, *args: str) -> None:
        self._run(["ip", *args])

    def ip_json(self, *args: str) -> list:
        """`ip -j …` parsed (the WARP egress reads its own rules back this way)."""
        try:
            done = subprocess.run(["ip", "-j", *args], capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostError(f"ip failed to run: {exc}") from exc
        if done.returncode != 0:
            raise HostError(f"ip -j {' '.join(args[:3])} failed: {done.stderr.strip()[:300]}")
        try:
            value = json.loads(done.stdout or "[]")
        except ValueError as exc:
            raise HostError("ip -j answered something that is not JSON") from exc
        return value if isinstance(value, list) else []

    def nft_apply(self, script: str) -> None:
        self._run(["nft", "-f", "-"], script)

    def nft_delete(self) -> None:
        try:
            self._run(["nft", "delete", "table", "inet", NFT_TABLE])
        except HostError:
            pass  # already absent

    def uapi_set(self, iface: str, body: str) -> None:
        _uapi_exchange(f"{UAPI_DIR}/{iface}.sock", b"set=1\n" + body.encode() + b"\n")

    def uapi_get(self, iface: str) -> str:
        return _uapi_exchange(f"{UAPI_DIR}/{iface}.sock", b"get=1\n\n")

    def ip_forward_enabled(self) -> bool:
        try:
            with open("/proc/sys/net/ipv4/ip_forward") as handle:
                return handle.read().strip() == "1"
        except OSError:
            return False
