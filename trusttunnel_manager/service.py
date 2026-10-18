"""The manager core: client credentials, endpoint settings, restart coalescing, counters."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import ssl
import threading
import time
from pathlib import Path
from typing import Callable

from . import metrics as metrics_mod
from .config import Config
from .state import StateError, StateStore, atomic_write
from .supervisor import Supervisor

LOGGER = logging.getLogger("trusttunnel_manager")
USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
PASSWORD = re.compile(r"[\x21-\x7e]{8,128}")
OPERATION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
EGRESS_ADDRESS = re.compile(r"127\.0\.0\.1:([0-9]{4,5})")
MAX_BACKOFF_SECONDS = 30.0
CERT_CHECK_SECONDS = 60.0


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


def toml_string(value: str) -> str:
    """A TOML basic string: only backslash, quote and control characters need escaping."""
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def inspect_certificate(path: Path, *, now: Callable[[], float] = time.time) -> dict | None:
    """Fingerprint, trust heuristic and DER of the leaf; None when unreadable.

    `trusted` is true for a certificate that is not self-signed and not expired; a
    self-signed leaf must be pinned by the client, so its DER is exposed.
    """
    try:
        pem = Path(path).read_text()
        der = ssl.PEM_cert_to_DER_cert(pem[pem.index("-----BEGIN CERTIFICATE-----"):])
    except (OSError, ValueError):
        return None
    trusted = False
    try:
        info = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]  # noqa: SLF001
        expired = ssl.cert_time_to_seconds(info["notAfter"]) < now()
        trusted = not expired and info.get("issuer") != info.get("subject")
    except (OSError, ValueError, KeyError, AttributeError):
        trusted = False
    return {"der": der, "fingerprint": hashlib.sha256(der).hexdigest(), "trusted": trusted}


def egress_revision(document: dict) -> str:
    canonical = json.dumps(
        {"mode": document["mode"], "address": document["address"]}, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def normalize_egress(body: dict) -> dict:
    if set(body) - {"mode", "address"}:
        raise ApiError(422, "invalid_request", "invalid request fields")
    mode, address = body.get("mode"), body.get("address")
    if mode == "direct":
        if address not in (None, ""):
            raise ApiError(422, "invalid_request", "direct mode takes no address")
        return {"mode": "direct", "address": None}
    if mode == "socks5":
        match = EGRESS_ADDRESS.fullmatch(address) if isinstance(address, str) else None
        if not match or not 1024 <= int(match.group(1)) <= 65535:
            raise ApiError(422, "invalid_request", "address must be 127.0.0.1:PORT")
        return {"mode": "socks5", "address": address}
    raise ApiError(422, "invalid_request", "mode must be direct or socks5")


class TrusttunnelManager:
    def __init__(
        self,
        config: Config,
        supervisor: Supervisor,
        fetch: Callable[[], list[dict] | None] | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ):
        self.config = config
        self.supervisor = supervisor
        self.fetch = fetch or (lambda: metrics_mod.fetch_clients(config.metrics))
        self.clock, self.wall = clock, wall
        self.store = StateStore(config.state_dir)
        self.lock = threading.RLock()
        self.vpn_toml = config.state_dir / "vpn.toml"
        self.hosts_toml = config.state_dir / "hosts.toml"
        self.credentials_toml = config.state_dir / "credentials.toml"
        self._restart_at: float | None = None
        self._next_poll = 0.0
        self._failures = 0
        self._next_start = 0.0
        self._started_at = 0.0
        self._sessions: dict[str, int] = {}
        self._next_cert_check = 0.0
        self._applied_cert: tuple | None = None

    # ------------------------------------------------------------ lifecycle

    def bootstrap(self) -> None:
        with self.lock:
            self.store.load()
            self.store.directory.mkdir(parents=True, exist_ok=True)
            self._write_files()
            self._next_poll = self.clock() + self.config.poll_interval
            self._next_cert_check = self.clock() + CERT_CHECK_SECONDS
            self._maybe_start()

    def tick(self) -> None:
        with self.lock:
            now = self.clock()
            if self._restart_at is not None and now >= self._restart_at:
                self._restart_at = None
                self._restart()
                return
            if self.supervisor.running():
                if now - self._started_at >= 60:
                    self._failures = 0
                if now >= self._next_cert_check:
                    self._next_cert_check = now + CERT_CHECK_SECONDS
                    self._reload_certificate()
                if now >= self._next_poll:
                    self._next_poll = now + self.config.poll_interval
                    self._poll()
            else:
                self._maybe_start()

    def shutdown(self) -> None:
        with self.lock:
            if self.supervisor.running():
                self._poll()
            self.supervisor.stop()
            self.store.save()

    # ------------------------------------------------------------ files

    def _credentials_text(self) -> str:
        lines = []
        for name in sorted(self.store.clients):
            client = self.store.clients[name]
            if client["enabled"]:
                lines += [
                    "[[client]]",
                    f"username = {toml_string(name)}",
                    f"password = {toml_string(client['password'])}",
                    "",
                ]
        return "\n".join(lines)

    def _forward_text(self) -> str:
        document = self.store.egress["document"]
        if document["mode"] == "socks5":
            return (
                "[forward_protocol.socks5]\n"
                f"address = {toml_string(document['address'])}\n"
                # Plain no-auth SOCKS5: extended_auth offers method 0x80, which Xray's
                # socks inbound does not understand.
                "extended_auth = false\n"
            )
        return "[forward_protocol]\ndirect = {}\n"

    def _vpn_text(self) -> str:
        cfg = self.config
        return (
            f"listen_address = {toml_string(cfg.listen)}\n"
            "ipv6_available = false\n"
            "allow_private_network_connections = false\n"
            "tls_handshake_timeout_secs = 10\n"
            "client_listener_timeout_secs = 600\n"
            "connection_establishment_timeout_secs = 30\n"
            "tcp_connections_timeout_secs = 604800\n"
            "udp_connections_timeout_secs = 300\n"
            f"credentials_file = {toml_string(str(self.credentials_toml))}\n\n"
            # HTTP/1.1 and HTTP/2 over TLS only: no QUIC section, nothing listens on UDP.
            "[listen_protocols.http1]\nupload_buffer_size = 32768\n\n"
            "[listen_protocols.http2]\n"
            "initial_connection_window_size = 8388608\n"
            "initial_stream_window_size = 131072\n"
            "max_concurrent_streams = 1000\n"
            "max_frame_size = 16384\n"
            "header_table_size = 65536\n\n"
            f"{self._forward_text()}\n"
            f"[metrics]\naddress = {toml_string(cfg.metrics)}\nrequest_timeout_secs = 3\n"
            "per_client_metrics = true\n"
        )

    def _hosts_text(self) -> str:
        cfg = self.config
        return (
            "[[main_hosts]]\n"
            f"hostname = {toml_string(cfg.hostname)}\n"
            f"cert_chain_path = {toml_string(str(cfg.cert))}\n"
            f"private_key_path = {toml_string(str(cfg.key))}\n"
        )

    def _put(self, path: Path, text: str) -> bool:
        data = text.encode()
        try:
            if path.read_bytes() == data:
                return False
        except OSError:
            pass
        atomic_write(path, data)
        return True

    def _write_files(self) -> bool:
        """Write the three files; True when the credentials or the endpoint settings changed."""
        changed = self._put(self.credentials_toml, self._credentials_text())
        changed |= self._put(self.vpn_toml, self._vpn_text())
        changed |= self._put(self.hosts_toml, self._hosts_text())
        return changed

    def _mutated(self) -> None:
        self.store.save()
        if self._write_files():
            self.request_restart()

    # ------------------------------------------------------------ supervision

    def request_restart(self) -> None:
        if self._restart_at is None:
            self._restart_at = self.clock() + self.config.restart_delay

    def _certificate_ready(self) -> bool:
        return self.config.cert.is_file() and self.config.key.is_file()

    def _cert_identity(self) -> tuple | None:
        try:
            return tuple(
                hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in (self.config.cert, self.config.key)
            )
        except OSError:
            return None

    def _reload_certificate(self) -> None:
        identity = self._cert_identity()
        if identity is None or identity == self._applied_cert:
            return
        try:
            self.supervisor.reload()
        except OSError as exc:
            # Never include file content: only the failure class. Retried on the next check.
            LOGGER.warning("certificate reload failed (%s), will retry", type(exc).__name__)
            return
        LOGGER.info("certificate changed, endpoint reloaded")
        self._applied_cert = identity

    def _maybe_start(self) -> None:
        now = self.clock()
        if self.supervisor.running() or not self._certificate_ready() or now < self._next_start:
            return
        try:
            self.supervisor.start(self.vpn_toml, self.hosts_toml)
        except OSError:
            LOGGER.exception("cannot start the endpoint")
            self._failures += 1
        else:
            self._started_at = now
            self._applied_cert = self._cert_identity()
            self._failures += 1  # reset after a minute of uptime (see tick)
        self._next_start = now + min(MAX_BACKOFF_SECONDS, 2.0 ** min(self._failures, 5))

    def _restart(self) -> None:
        if self.supervisor.running():
            self._poll()  # the last reading before the counters reset
        self.supervisor.stop()
        for client in self.store.clients.values():
            client["last_in"] = client["last_out"] = 0
        self._sessions.clear()
        self.store.save()
        self._failures = 0
        self._next_start = 0.0
        self._maybe_start()

    def _poll(self) -> None:
        rows = self.fetch()
        if rows is None:
            return
        readings = metrics_mod.aggregate(rows)
        self._sessions = {name: value["sessions"] for name, value in readings.items()}
        changed = False
        for name, reading in readings.items():
            client = self.store.clients.get(name)
            if client is None:
                continue
            client["rx"], client["last_out"] = metrics_mod.fold(
                client["rx"], client["last_out"], reading["outbound"]
            )
            client["tx"], client["last_in"] = metrics_mod.fold(
                client["tx"], client["last_in"], reading["inbound"]
            )
            changed = True
        if changed:
            self.store.save()

    # ------------------------------------------------------------ reads

    def _view(self, name: str) -> dict:
        c = self.store.clients[name]
        return {
            "username": name,
            "enabled": c["enabled"],
            "revision": c["revision"],
            "rx": c["rx"],
            "tx": c["tx"],
            "sessions": self._sessions.get(name, 0),
        }

    def health(self) -> dict:
        with self.lock:
            running = self.supervisor.running()
            out: dict = {
                "status": "ok",
                "endpoint": {"running": running, "pid": self.supervisor.pid()},
                "clients": len(self.store.clients),
            }
            if not self._certificate_ready():
                out["status"], out["code"] = "degraded", "certificate_missing"
            elif not running:
                out["status"], out["code"] = "degraded", "endpoint_down"
            return out

    def endpoint(self) -> dict:
        cert = inspect_certificate(self.config.cert, now=self.wall)
        trusted = bool(cert and cert["trusted"])
        return {
            "hostname": self.config.hostname,
            "listen": self.config.listen,
            "public_port": self.config.public_port,
            "version": self.config.version,
            "certificate_trusted": trusted,
            "certificate_der_b64": (
                base64.b64encode(cert["der"]).decode() if cert and not trusted else None
            ),
            "fingerprint": cert["fingerprint"] if cert else None,
        }

    def list_clients(self) -> dict:
        with self.lock:
            return {"clients": [self._view(name) for name in sorted(self.store.clients)]}

    # ------------------------------------------------------------ client writes

    @staticmethod
    def _check_fields(body: dict, allowed: set[str]) -> None:
        if set(body) - allowed:
            raise ApiError(422, "invalid_request", "invalid request fields")

    @staticmethod
    def _operation_id(body: dict) -> str:
        op = body.get("operation_id")
        if not isinstance(op, str) or not OPERATION_ID.fullmatch(op):
            raise ApiError(422, "invalid_request", "invalid operation_id")
        return op

    @staticmethod
    def _password(body: dict) -> str:
        password = body.get("password")
        if not isinstance(password, str) or not PASSWORD.fullmatch(password):
            raise ApiError(422, "invalid_request", "invalid password")
        return password

    @staticmethod
    def _fingerprint(kind: str, username: str, password: str) -> str:
        return hashlib.sha256(f"{kind}\0{username}\0{password}".encode()).hexdigest()

    def _replay(self, op: str, fingerprint: str) -> str | None:
        known = self.store.operations.get(op)
        if known is None:
            return None
        if known["fingerprint"] != fingerprint:
            raise ApiError(409, "operation_conflict", "operation_id was used for another request")
        return known["username"]

    def create_client(self, body: dict) -> dict:
        self._check_fields(body, {"operation_id", "username", "password"})
        op = self._operation_id(body)
        username = body.get("username")
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ApiError(422, "invalid_request", "invalid username")
        password = self._password(body)
        fingerprint = self._fingerprint("create", username, password)
        with self.lock:
            replayed = self._replay(op, fingerprint)
            if replayed is not None:
                if replayed in self.store.clients:
                    return {"client": self._view(replayed)}
                raise ApiError(409, "operation_conflict", "the client of this operation was deleted")
            if username in self.store.clients:
                raise ApiError(409, "exists", "client already exists")
            self.store.clients[username] = {
                "password": password, "enabled": True, "revision": 1,
                "rx": 0, "tx": 0, "last_out": 0, "last_in": 0,
            }
            self.store.operations[op] = {"fingerprint": fingerprint, "username": username}
            self._mutated()
            return {"client": self._view(username)}

    def _existing(self, username: str) -> dict:
        client = self.store.clients.get(username)
        if client is None:
            raise ApiError(404, "not_found", "client not found")
        return client

    def set_enabled(self, username: str, enabled: bool) -> dict:
        with self.lock:
            client = self._existing(username)
            if client["enabled"] != enabled:
                client["enabled"] = enabled
                client["revision"] += 1
                self._mutated()
            return {"client": self._view(username)}

    def rotate(self, username: str, body: dict) -> dict:
        self._check_fields(body, {"operation_id", "password"})
        op = self._operation_id(body)
        password = self._password(body)
        fingerprint = self._fingerprint("rotate", username, password)
        with self.lock:
            client = self._existing(username)
            if self._replay(op, fingerprint) is not None:
                return {"client": self._view(username)}
            client["password"] = password
            client["revision"] += 1
            self.store.operations[op] = {"fingerprint": fingerprint, "username": username}
            self._mutated()
            return {"client": self._view(username)}

    def delete_client(self, username: str) -> None:
        with self.lock:
            if self.store.clients.pop(username, None) is not None:
                self._mutated()

    # ------------------------------------------------------------ egress

    def egress(self) -> dict:
        with self.lock:
            document = self.store.egress["document"]
            return {**document, "revision": egress_revision(document)}

    def egress_plan(self, body: dict) -> dict:
        proposed = normalize_egress(body)
        with self.lock:
            current = self.store.egress["document"]
            return {
                "changed": proposed != current,
                "current": {**current, "revision": egress_revision(current)},
                "proposed": {**proposed, "revision": egress_revision(proposed)},
            }

    def _set_egress(self, document: dict, previous: dict | None) -> None:
        self.store.egress["document"] = document
        self.store.egress["previous"] = previous
        self._mutated()

    def egress_apply(self, body: dict) -> dict:
        proposed = normalize_egress(body)
        with self.lock:
            current = self.store.egress["document"]
            if proposed != current:
                self._set_egress(proposed, current)
            return self.egress()

    def egress_rollback(self) -> dict:
        with self.lock:
            previous = self.store.egress.get("previous")
            if previous is None:
                raise ApiError(409, "no_previous", "nothing to roll back to")
            self._set_egress(previous, None)
            return self.egress()


__all__ = ["ApiError", "StateError", "TrusttunnelManager"]
