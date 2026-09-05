from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import socket
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from installer.adapters.core import (
    _DOMAIN,
    _decode_adjacent_routes,
    _encode_adjacent_routes,
    _DefaultCoreRunner,
    _file_sha256,
    _path_sha256,
    _valid_adjacent_backend,
)
from installer.model import InstallerConfig
from installer.planner import Action, AuditFacts, Evidence, PlanError
from installer.transaction import (
    atomic_write,
    durable_copy2,
    durable_mkdir,
    durable_remove,
    fsync_directory,
)

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_PROJECT = "/opt/mtproxy-shared443"
_DATA_DIR = "/var/lib/naive-manager"
_LOG_DIR = "/var/log/naive-proxy"
_CADDY_BINARY = "/usr/local/bin/caddy"
_CHECKER = "/usr/local/libexec/check-naive-caddy-build"
_ADAPT_SCRIPT = "/usr/local/libexec/caddy-naive-adapt"
_STATE_PREPARER = "/usr/local/libexec/prepare-naive-state"
_UNIT = "/etc/systemd/system/caddy-naive.service"
_PIN = "/etc/proxy-control/caddy-naive.pin"
_DEPLOY_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/proxy-control-naive-caddy"
# Caddy runs unprivileged and cannot traverse the root-only Certbot tree, so
# the renewal hook publishes just this one keypair for it.
_TLS_DIR = "/var/lib/naive-caddy/tls"
_COVER_INDEX = b"<!doctype html><title>Welcome</title><h1>Welcome</h1>\n"
_MARKER = "/etc/proxy-control/naive-owned"
_ACCEPTANCE_OWNER = "/etc/proxy-control/naive-acceptance-owner"
_ACCEPTANCE_PENDING = "/etc/proxy-control/naive-acceptance-pending"

_UNIT_NAME = "caddy-naive"
_CADDY_UID = 10003
_ACCOUNTING_GID = 10004
_MANAGER_UID = 10002
_MANAGER_GID = 101
_CADDY_USER = "naive-caddy"
_ACCOUNTING_GROUP = "naive-accounting"
_CADDY_VERSION = "v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0="
_CADDY_IMAGE = "proxy-control-caddy-naive:v2.11.4"
_FORWARD_PROXY_MODULE = "http.handlers.forward_proxy"
_ADMIN_PORT = 2019
_PRIVATE_PORT = 4443
_PUBLIC_PORT = 443
_ACCEPTANCE_PREFIX = "proxy-control-naive-"
_ACCEPTANCE_NAME = re.compile(r"proxy-control-naive-[0-9a-f]{16}\Z")
_HEX_16 = re.compile(r"[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MANAGED_MARKER = "NAIVE-MANAGER USERS"
_BOOTSTRAP_USERNAME = "__PROXY_CONTROL_BOOTSTRAP_USERNAME__"
_BOOTSTRAP_PASSWORD = "__PROXY_CONTROL_BOOTSTRAP_PASSWORD__"
# WARP is one loopback SOCKS5 endpoint. Unlike Xray, which routes only the
# selected domains through it, NaiveProxy sends every tunnelled connection
# through WARP once it is enabled.
_WARP_EGRESS = "socks5://127.0.0.1:45000"
_ACCOUNTING_TIMEOUT = 120.0
_ACCOUNTING_INTERVAL = 5.0

# Copied verbatim from the release into root-owned host locations.
_HELPERS: tuple[tuple[str, str, int], ...] = (
    ("scripts/check-naive-caddy-build.sh", _CHECKER, 0o755),
    ("scripts/caddy-naive-adapt", _ADAPT_SCRIPT, 0o755),
    ("scripts/prepare-naive-state.py", _STATE_PREPARER, 0o755),
    ("deploy/caddy-naive.service", _UNIT, 0o644),
)

def _sanitize_diagnostic(value: str, *, max_chars: int = 1200) -> str:
    """Keep a bounded diagnostic with any credential assignment redacted."""
    redacted = re.sub(
        r"(?i)((?:password|token|secret)[=:\s]+)\S+",
        r"\1[REDACTED]",
        value,
    )
    return redacted[-max_chars:].replace("\n", " ").strip()


def _command_failure(argv: Sequence[str]) -> str:
    """Name the failing program and subcommand without echoing any argument."""
    program = Path(str(argv[0])).name if argv else "command"
    subcommand = ""
    for value in list(argv)[1:3]:
        rendered = str(value)
        if rendered.startswith("-") or "/" in rendered:
            break
        subcommand += f" {rendered}"
    return f"Naive command failed: {program}{subcommand}"


class NaiveError(RuntimeError):
    """The NaiveProxy ownership boundary cannot be changed safely."""


class AcceptanceError(NaiveError):
    """NaiveProxy failed an end-to-end acceptance requirement."""


class _AcceptanceCollision(AcceptanceError):
    """A temporary acceptance username exists without installer ownership."""


def _deploy_hook_text(domain: str) -> str:
    """Root-owned Certbot deploy hook publishing one keypair for Caddy.

    The Certbot tree stays root-only. After every issuance and renewal this
    hook copies exactly the certificate and key this site needs into a
    directory the unprivileged Caddy identity can read, and nothing else.
    """
    return (
        "#!/bin/sh\n"
        "# Managed by proxy-control: publish the Naive keypair for the\n"
        "# unprivileged Caddy identity after every issuance and renewal.\n"
        "set -eu\n"
        f'lineage="/etc/letsencrypt/live/{domain}"\n'
        f'target="{_TLS_DIR}"\n'
        '[ "${RENEWED_LINEAGE:-$lineage}" = "$lineage" ] || exit 0\n'
        '[ -r "$lineage/fullchain.pem" ] || exit 1\n'
        '[ -r "$lineage/privkey.pem" ] || exit 1\n'
        'install -d -m 0750 -o root -g ' + _ACCOUNTING_GROUP + ' "$target"\n'
        'install -m 0640 -o root -g ' + _ACCOUNTING_GROUP
        + ' "$lineage/fullchain.pem" "$target/fullchain.pem"\n'
        'install -m 0640 -o root -g ' + _ACCOUNTING_GROUP
        + ' "$lineage/privkey.pem" "$target/privkey.pem"\n'
    )


def _identity_from_entry(output: str, identifier: int) -> str | None:
    """Parse one getent passwd/group line for the given numeric identifier."""
    for line in output.strip().splitlines():
        fields = line.split(":")
        if len(fields) < 3:
            continue
        name, _password, number = fields[0], fields[1], fields[2]
        if not name or number != str(identifier):
            continue
        if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name) is None:
            continue
        return name
    return None


class _DefaultNaiveRunner(_DefaultCoreRunner):
    """Real host commands and acceptance probes for the Naive boundary."""

    def identity_owner(self, kind: str, identifier: int) -> str | None:
        """Name the holder of a fixed identity, or None when it is free.

        `capture` reports a failed lookup as diagnostic text rather than
        raising, so only a well-formed database line for this exact identifier
        counts as a holder: anything else would invent a collision.
        """
        database = "passwd" if kind == "uid" else "group"
        try:
            output = self.capture(
                ("getent", database, str(identifier)),
                max_chars=512,
            )
        except Exception:
            return None
        return _identity_from_entry(output, identifier)

    def compose_service_present(self, service: str) -> bool:
        """Report only this protocol's own Compose service, not the project.

        Core owns the shared `mtproxy` project, so a project-wide check would
        see Core's containers and refuse a first install of this protocol.
        """
        output = self.capture(
            (
                "docker",
                "container",
                "ls",
                "--all",
                "--quiet",
                "--filter",
                "label=com.docker.compose.project=mtproxy",
                "--filter",
                f"label=com.docker.compose.service={service}",
            ),
            max_chars=512,
        )
        stripped = output.strip()
        if not stripped or stripped.startswith(("exit=", "diagnostic ")):
            return False
        return True

    def build_caddy(self, source_dir: str, destination: str) -> None:
        """Build the pinned forward-proxy Caddy and install it atomically."""
        self._run_checked(
            (
                "docker",
                "build",
                "-f",
                f"{source_dir}/docker/Dockerfile.caddy-naive",
                "-t",
                _CADDY_IMAGE,
                source_dir,
            ),
            "caddy build",
        )
        container = self._capture_checked(
            (
                "docker",
                "create",
                "--entrypoint",
                "/caddy",
                _CADDY_IMAGE,
                "version",
            )
        ).strip()
        if re.fullmatch(r"[0-9a-f]{12,64}", container) is None:
            raise NaiveError("pinned Caddy build produced no container")
        try:
            self._run_checked(
                ("docker", "cp", f"{container}:/caddy", destination),
                "caddy extract",
            )
        finally:
            self._run_checked(("docker", "rm", container), "caddy cleanup")

    def caddy_identity(self, binary: str) -> tuple[str, bool]:
        version = self._capture_checked((binary, "version")).strip()
        modules = self._capture_checked((binary, "list-modules"))
        present = any(
            line.strip() == _FORWARD_PROXY_MODULE
            for line in modules.splitlines()
        )
        return version, present

    def loopback_listener(self, port: int) -> bool:
        try:
            output = self.capture(
                ("ss", "-H", "-lnt", f"sport = :{port}"),
                max_chars=4096,
            )
        except Exception:
            return False
        addresses = {
            fields[3]
            for fields in (line.split() for line in output.splitlines())
            if len(fields) >= 4
        }
        return addresses == {f"127.0.0.1:{port}"}

    def naive_acceptance(
        self,
        *,
        panel_domain: str,
        naive_domain: str,
        log_dir: str,
        bootstrap_credential_file: str,
        acceptance_name: str,
        adjacent_sni: Sequence[tuple[str, str]],
        recover_existing: bool,
        state_preparer: str,
    ) -> Mapping[str, object]:
        admin_ok = self.loopback_listener(_ADMIN_PORT)
        private_ok = self.loopback_listener(_PRIVATE_PORT)
        cover_ok = self._cover_https(naive_domain)
        (
            connect_bytes,
            recorded_bytes,
            tunnel_closed,
            manager_ready,
            panel_ok,
        ) = self._connect_and_account(
            panel_domain=panel_domain,
            naive_domain=naive_domain,
            bootstrap_credential_file=bootstrap_credential_file,
            acceptance_name=acceptance_name,
            recover_existing=recover_existing,
        )
        adjacent_ok = True
        try:
            self._verify_adjacent_routes(adjacent_sni)
        except Exception:
            adjacent_ok = False
        self._run_checked(
            (state_preparer, "verify", "--log-dir", log_dir),
            "log boundary",
        )
        return {
            "admin_api_loopback": admin_ok,
            "private_listener_ok": private_ok,
            "cover_https_ok": cover_ok,
            "authenticated_connect_ok": connect_bytes > 0,
            "tunnel_closed_ok": tunnel_closed,
            "connect_bytes": connect_bytes,
            "recorded_bytes": recorded_bytes,
            "manager_health_ok": manager_ready,
            "panel_health_ok": panel_ok,
            "adjacent_sni_ok": adjacent_ok,
            "log_boundary_ok": True,
        }

    def cleanup_naive_acceptance(
        self,
        *,
        panel_domain: str,
        bootstrap_credential_file: str,
        acceptance_name: str,
        **_ignored: object,
    ) -> None:
        password = Path(bootstrap_credential_file).read_text().rstrip("\r\n")
        opener, csrf = self._login(panel_domain, "owner", password)
        try:
            if self._temporary_present(opener, panel_domain, acceptance_name):
                self._json_request(
                    opener,
                    panel_domain,
                    f"/api/naive/users/{acceptance_name}",
                    method="DELETE",
                    csrf=csrf,
                    expect_json=False,
                )
        finally:
            self._logout(opener, panel_domain, csrf)

    def _temporary_present(
        self,
        opener: urllib.request.OpenerDirector,
        panel_domain: str,
        acceptance_name: str,
    ) -> bool:
        listed = self._json_request(opener, panel_domain, "/api/naive/users")
        rows = listed.get("items", []) if isinstance(listed, Mapping) else []
        return any(
            isinstance(row, Mapping) and row.get("username") == acceptance_name
            for row in rows
        )

    def _cover_https(self, domain: str) -> bool:
        request = urllib.request.Request(f"https://{domain}/", method="GET")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return 200 <= response.status < 400
        except urllib.error.HTTPError as exc:
            return 200 <= exc.code < 500
        except Exception:
            return False

    @staticmethod
    def _native_proxy_url(revealed: object) -> str:
        """Read the proxy URL where the panel actually publishes it.

        A reveal carries one entry per client, and only the official-client
        Native configuration holds the plain `https://` proxy URL; the panel
        never exposes it as a top-level field.
        """
        clients = revealed.get("clients") if isinstance(revealed, Mapping) else None
        native = clients.get("native") if isinstance(clients, Mapping) else None
        config = native.get("config") if isinstance(native, Mapping) else None
        proxy_url = config.get("proxy") if isinstance(config, Mapping) else None
        if not isinstance(proxy_url, str) or not proxy_url:
            raise AcceptanceError("Naive acceptance failed: access")
        return proxy_url

    def _connect_and_account(
        self,
        *,
        panel_domain: str,
        naive_domain: str,
        bootstrap_credential_file: str,
        acceptance_name: str,
        recover_existing: bool,
    ) -> tuple[int, int, bool, bool, bool]:
        password = Path(bootstrap_credential_file).read_text().rstrip("\r\n")
        opener, csrf = self._login(panel_domain, "owner", password)
        created = False
        try:
            listed = self._json_request(opener, panel_domain, "/api/naive/users")
            if not isinstance(listed, Mapping):
                raise AcceptanceError("Naive acceptance failed: manager health")
            service = listed.get("service")
            manager_ready = (
                isinstance(service, Mapping) and service.get("ready") is True
            )
            rows = listed.get("items", [])
            collision = any(
                isinstance(row, Mapping)
                and row.get("username") == acceptance_name
                for row in rows
            )
            if collision and not recover_existing:
                raise _AcceptanceCollision(
                    "Naive acceptance failed: temporary-user collision"
                )
            if collision:
                self._json_request(
                    opener,
                    panel_domain,
                    f"/api/naive/users/{acceptance_name}",
                    method="DELETE",
                    csrf=csrf,
                    expect_json=False,
                )
            created_value = self._json_request(
                opener,
                panel_domain,
                "/api/naive/users",
                method="POST",
                payload={"username": acceptance_name},
                csrf=csrf,
            )
            created = True
            reveal = (
                created_value.get("reveal_token")
                if isinstance(created_value, Mapping)
                else None
            )
            if not isinstance(reveal, str) or not reveal:
                raise AcceptanceError("Naive acceptance failed: access")
            revealed = self._json_request(
                opener,
                panel_domain,
                f"/api/reveal/{reveal}",
            )
            proxy_url = self._native_proxy_url(revealed)
            connect_bytes, closed, panel_ok = self._authenticated_connect(
                proxy_url,
                naive_domain=naive_domain,
                panel_domain=panel_domain,
            )
            recorded = self._recorded_bytes(
                opener,
                panel_domain,
                acceptance_name,
                connect_bytes,
            )
            return connect_bytes, recorded, closed, manager_ready, panel_ok
        finally:
            failure: BaseException | None = None
            if created:
                try:
                    self._json_request(
                        opener,
                        panel_domain,
                        f"/api/naive/users/{acceptance_name}",
                        method="DELETE",
                        csrf=csrf,
                        expect_json=False,
                    )
                except BaseException as exc:
                    failure = exc
            try:
                self._logout(opener, panel_domain, csrf)
            except BaseException as exc:
                if failure is None:
                    failure = exc
            if failure is not None:
                raise failure

    def _authenticated_connect(
        self,
        proxy_url: str,
        *,
        naive_domain: str,
        panel_domain: str,
    ) -> tuple[int, bool, bool]:
        """Tunnel one known payload, then require a clean tunnel close."""
        parts = urllib.parse.urlsplit(proxy_url)
        username = urllib.parse.unquote(parts.username or "")
        password = urllib.parse.unquote(parts.password or "")
        if parts.scheme != "https" or parts.hostname != naive_domain:
            raise AcceptanceError("Naive acceptance failed: access")
        credential = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode("ascii")
        context = ssl.create_default_context()
        request = (
            f"GET /healthz HTTP/1.1\r\nHost: {panel_domain}\r\n"
            "Connection: close\r\nUser-Agent: proxy-control-acceptance\r\n\r\n"
        ).encode()
        raw = socket.create_connection((naive_domain, _PUBLIC_PORT), timeout=30)
        try:
            outer = context.wrap_socket(raw, server_hostname=naive_domain)
        except BaseException:
            raw.close()
            raise
        sent = 0
        received = 0
        panel_ok = False
        closed = False
        try:
            connect = (
                f"CONNECT {panel_domain}:443 HTTP/1.1\r\n"
                f"Host: {panel_domain}:443\r\n"
                f"Proxy-Authorization: Basic {credential}\r\n\r\n"
            ).encode()
            outer.sendall(connect)
            status = self._read_headers(outer)
            if not status.startswith(b"HTTP/1.1 200") and not status.startswith(
                b"HTTP/1.0 200"
            ):
                raise AcceptanceError(
                    "Naive acceptance failed: authenticated CONNECT"
                )
            # Python cannot wrap an SSLSocket in a second TLS layer: wrap_socket
            # reuses the raw descriptor, so the inner ClientHello would leave
            # outside the outer session and the peer would reject it. The inner
            # session runs on memory BIOs and its records are relayed by hand.
            incoming = ssl.MemoryBIO()
            outgoing = ssl.MemoryBIO()
            inner = context.wrap_bio(
                incoming, outgoing, server_hostname=panel_domain
            )

            def relay(operation):
                while True:
                    try:
                        result = operation()
                    except ssl.SSLWantReadError:
                        pending = outgoing.read()
                        if pending:
                            outer.sendall(pending)
                        chunk = outer.recv(65536)
                        if not chunk:
                            incoming.write_eof()
                            raise AcceptanceError(
                                "Naive acceptance failed: tunnel"
                            )
                        incoming.write(chunk)
                        continue
                    pending = outgoing.read()
                    if pending:
                        outer.sendall(pending)
                    return result

            relay(inner.do_handshake)
            sent = relay(lambda: inner.write(request))
            body = b""
            while True:
                try:
                    chunk = relay(lambda: inner.read(65536))
                except ssl.SSLZeroReturnError:
                    # close_notify: the tunnel ended cleanly, which is the
                    # only close that lets Caddy account the transfer.
                    closed = True
                    break
                except ssl.SSLEOFError:
                    break
                if not chunk:
                    closed = True
                    break
                received += len(chunk)
                body += chunk[: 65536 - len(body)]
            panel_ok = body.startswith(b"HTTP/1.1 200")
        finally:
            outer.close()
        return sent + received, closed, panel_ok

    @staticmethod
    def _read_headers(connection: ssl.SSLSocket) -> bytes:
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = connection.recv(1024)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > 8192:
                break
        return buffer

    def _recorded_bytes(
        self,
        opener: urllib.request.OpenerDirector,
        panel_domain: str,
        acceptance_name: str,
        expected: int,
    ) -> int:
        """Poll the closed-tunnel accounting the manager collects from Caddy."""
        deadline = time.monotonic() + _ACCOUNTING_TIMEOUT
        observed = 0
        while True:
            listed = self._json_request(opener, panel_domain, "/api/naive/users")
            rows = listed.get("items", []) if isinstance(listed, Mapping) else []
            for row in rows:
                if (
                    isinstance(row, Mapping)
                    and row.get("username") == acceptance_name
                    and isinstance(row.get("total_bytes"), int)
                ):
                    observed = max(observed, int(row["total_bytes"]))
            if observed >= expected or time.monotonic() >= deadline:
                return observed
            time.sleep(_ACCOUNTING_INTERVAL)


@dataclass(frozen=True)
class NaivePaths:
    """Fixed host paths owned by one NaiveProxy generation."""

    project_dir: str = _PROJECT
    data_dir: str = _DATA_DIR
    log_dir: str = _LOG_DIR
    caddy_binary: str = _CADDY_BINARY
    checker: str = _CHECKER
    adapt_script: str = _ADAPT_SCRIPT
    state_preparer: str = _STATE_PREPARER
    unit: str = _UNIT
    pin: str = _PIN
    deploy_hook: str = _DEPLOY_HOOK
    marker: str = _MARKER
    acceptance_owner: str = _ACCEPTANCE_OWNER
    acceptance_pending: str = _ACCEPTANCE_PENDING

    def __post_init__(self) -> None:
        for value in (
            self.project_dir,
            self.data_dir,
            self.log_dir,
            self.caddy_binary,
            self.checker,
            self.adapt_script,
            self.state_preparer,
            self.unit,
            self.pin,
            self.deploy_hook,
            self.marker,
            self.acceptance_owner,
            self.acceptance_pending,
        ):
            if not value.startswith("/") or ".." in Path(value).parts:
                raise ValueError("Naive path must be a normalized absolute path")
        if self.data_dir == self.log_dir:
            raise ValueError("Naive state and log directories must be distinct")

    @property
    def caddyfile(self) -> str:
        return f"{self.data_dir}/Caddyfile"

    @property
    def manager_token(self) -> str:
        return f"{self.data_dir}/manager-token"

    @property
    def secret_token(self) -> str:
        return f"{self.project_dir}/secrets/naive-manager-token"

    @property
    def env_overlay(self) -> str:
        return f"{self.project_dir}/.env.naive"

    @property
    def compose_overlay(self) -> str:
        return f"{self.project_dir}/compose.naive.yaml"

    @property
    def access_log(self) -> str:
        return f"{self.log_dir}/access.json"


@dataclass(frozen=True)
class RenderedNaive:
    """Deterministic, credential-free portion of a Naive generation."""

    caddyfile_template: str
    env_text: str
    unit_text: str
    pin_text: str
    file_modes: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "file_modes",
            MappingProxyType(dict(self.file_modes)),
        )

    def mode(self, host_path: str) -> int:
        return self.file_modes[host_path]


@dataclass(frozen=True)
class NaiveAcceptance:
    """Sanitized acceptance facts; values are only booleans and counts."""

    admin_api_loopback: bool
    private_listener_ok: bool
    cover_https_ok: bool
    authenticated_connect_ok: bool
    tunnel_closed_ok: bool
    connect_bytes: int
    recorded_bytes: int
    manager_health_ok: bool
    panel_health_ok: bool
    adjacent_sni_ok: bool
    log_boundary_ok: bool
    temporary_state_removed: bool = True

    def __post_init__(self) -> None:
        boolean_fields = (
            "admin_api_loopback",
            "private_listener_ok",
            "cover_https_ok",
            "authenticated_connect_ok",
            "tunnel_closed_ok",
            "manager_health_ok",
            "panel_health_ok",
            "adjacent_sni_ok",
            "log_boundary_ok",
            "temporary_state_removed",
        )
        if any(not isinstance(getattr(self, name), bool) for name in boolean_fields):
            raise TypeError("acceptance flags must be booleans")
        counts = (self.connect_bytes, self.recorded_bytes)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts
        ):
            raise ValueError("acceptance counts must be non-negative integers")

    def details(self) -> dict[str, bool | int]:
        return asdict(self)


class NaiveAdapter:
    """Own the pinned Caddy, split identities, manager state, and Naive route."""

    name = "naive"
    requires = frozenset({"core"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        source_dir: Path | None = None,
        paths: NaivePaths | None = None,
        adjacent_sni: Sequence[str] = (),
    ) -> None:
        if runner is None:
            runner = _DefaultNaiveRunner()
        self.root = Path(root)
        self.runner = runner
        self.source_dir = Path(source_dir or Path(__file__).resolve().parents[2])
        self.paths = paths or NaivePaths()
        normalized = tuple(sorted(set(adjacent_sni)))
        if any(_DOMAIN.fullmatch(value) is None for value in normalized):
            raise ValueError("adjacent SNI names must be valid domains")
        self.adjacent_sni = normalized

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if getattr(facts, "hard_stops", ()):
            raise NaiveError("host audit contains blocking findings")
        if not config.profile.includes_naive:
            return ()
        domain = config.domains.naive
        if domain is None or _DOMAIN.fullmatch(domain) is None:
            raise PlanError("Naive public domain is missing or invalid")
        self._assert_planned_identities(facts)
        adjacent = self._audited_adjacent_routes(config, facts)
        return (
            Action(
                id="naive.runtime",
                adapter=self.name,
                owner="proxy-control:naive",
                mutations=(
                    f"project={self.paths.project_dir}",
                    f"naive-domain={domain.lower()}",
                    f"panel-domain={config.domains.panel.lower()}",
                    f"data-dir={self.paths.data_dir}",
                    f"log-dir={self.paths.log_dir}",
                    f"caddy-binary={self.paths.caddy_binary}",
                    f"caddy-build={_CADDY_VERSION}",
                    f"unit={self.paths.unit}",
                    f"private-port={_PRIVATE_PORT}",
                    f"caddy-uid={_CADDY_UID}",
                    f"accounting-gid={_ACCOUNTING_GID}",
                    f"manager-uid={_MANAGER_UID}",
                    f"manager-gid={_MANAGER_GID}",
                    f"adjacent-sni={_encode_adjacent_routes(adjacent)}",
                    f"egress={'proxy' if config.three_xui.warp else 'direct'}",
                ),
                preconditions=(
                    "the Core runtime and the Naive certificate are verified",
                    "fixed Naive identities are free or already owned",
                    "the shared 443 route reaches the private Caddy listener",
                ),
                verification=(
                    "loopback Admin API and private Caddy listener are private",
                    "public cover HTTPS answers without credentials",
                    "one authenticated CONNECT carries a known payload and closes",
                    "closed-tunnel accounting observes at least the sent payload",
                    "manager, panel, adjacent SNI, and log boundary pass",
                ),
                inverse=(
                    "stop only the Caddy unit and the naive-manager service",
                    "preserve manager state and credentials unless purge is explicit",
                    "restore binary, unit, helper, hook, and identity ownership",
                ),
                credentials_required=True,
            ),
        )

    def _assert_planned_identities(self, facts: AuditFacts) -> None:
        ownership = facts.ownership if isinstance(facts.ownership, Mapping) else {}
        identities = ownership.get("identities")
        if identities is None:
            return
        if not isinstance(identities, Mapping):
            raise PlanError("audited identity facts are invalid")
        for kind, identifier, expected in (
            ("UID", _CADDY_UID, _CADDY_USER),
            ("GID", _ACCOUNTING_GID, _ACCOUNTING_GROUP),
            ("UID", _MANAGER_UID, None),
        ):
            group = identities.get(kind.lower())
            if not isinstance(group, Mapping):
                continue
            name = group.get(str(identifier))
            if name is None or name == "":
                continue
            if not isinstance(name, str):
                raise PlanError("audited identity facts are invalid")
            if expected is not None and name != expected:
                raise PlanError(f"{kind} {identifier} collision: {name}")

    def _audited_adjacent_routes(
        self,
        config: InstallerConfig,
        facts: AuditFacts,
    ) -> tuple[tuple[str, str], ...]:
        if self.adjacent_sni:
            return tuple((name, "audited") for name in self.adjacent_sni)
        topology = facts.topology if isinstance(facts.topology, Mapping) else {}
        nginx = topology.get("nginx", {})
        routes = nginx.get("sni_routes", {}) if isinstance(nginx, Mapping) else {}
        if not isinstance(routes, Mapping):
            raise NaiveError("audited adjacent SNI routes are invalid")
        owned = {
            config.domains.mtproxy.lower(),
            config.domains.panel.lower(),
            (config.domains.naive or "").lower(),
        }
        adjacent: list[tuple[str, str]] = []
        for domain, backend in routes.items():
            if not isinstance(domain, str) or not isinstance(backend, str):
                raise NaiveError("audited adjacent SNI routes are invalid")
            normalized = domain.lower()
            if normalized in owned:
                continue
            if (
                _DOMAIN.fullmatch(normalized) is None
                or not _valid_adjacent_backend(backend)
            ):
                raise NaiveError("audited adjacent SNI routes are invalid")
            adjacent.append((normalized, backend))
        return tuple(sorted(adjacent))

    # ------------------------------------------------------------------
    # rendering
    # ------------------------------------------------------------------

    def render(self, action: Action) -> RenderedNaive:
        selected = self._selection(action)
        domain = str(selected["naive_domain"])
        # Every tunnelled connection leaves through WARP when it is enabled.
        upstream = (
            f"            upstream {_WARP_EGRESS}\n"
            if selected["egress"] == "proxy"
            else ""
        )
        caddyfile = (
            "{\n"
            f"    admin 127.0.0.1:{_ADMIN_PORT}\n"
            "    auto_https disable_redirects\n"
            "}\n"
            # A named site address installs a Host matcher, and a tunnelled
            # CONNECT carries the *destination* as its Host: such a request
            # would miss the site, skip forward_proxy and be answered as an
            # ordinary page. The listener is therefore port-only, exactly as
            # the upstream NaiveProxy recipe publishes it, and the explicit
            # `tls` keypair below still pins the certificate this port serves.
            f"# NaiveProxy cover site and forward proxy for {domain}.\n"
            "https://:443 {\n"
            "    bind 127.0.0.1\n"
            "    tls /var/lib/naive-caddy/tls/fullchain.pem /var/lib/naive-caddy/tls/privkey.pem\n"
            # Caddy shares one file writer per filename, so this bootstrap log
            # must declare exactly the file options the manager's accounting
            # block uses. A bare block would create the log 0600 and gzip its
            # rotations, locking the accounting group out and hiding rotated
            # records from the manager's rotation matcher.
            "    log {\n"
            f"        output file {self.paths.access_log} {{\n"
            "            mode 0640\n"
            "            roll_size 10MiB\n"
            "            roll_keep 10\n"
            "            roll_keep_for 168h\n"
            "            roll_uncompressed\n"
            "        }\n"
            "        format json\n"
            "    }\n"
            f"    root * /var/www/{domain}\n"
            "    route {\n"
            "        forward_proxy {\n"
            f"            basic_auth {_BOOTSTRAP_USERNAME} {_BOOTSTRAP_PASSWORD}\n"
            "            hide_ip\n"
            "            hide_via\n"
            # Without probe resistance every unauthenticated request answers
            # 407, which both fingerprints the tunnel to a passive prober and
            # keeps the cover site unreachable. With it, such requests fall
            # through to file_server and the domain looks like a plain site.
            "            probe_resistance\n"
            f"{upstream}"
            "        }\n"
            "        file_server\n"
            "    }\n"
            "}\n"
        )
        if _MANAGED_MARKER in caddyfile:
            raise NaiveError("rendered Caddyfile must not pre-declare managed markers")
        env = (
            f"NAIVE_PUBLIC_HOST={domain}\n"
            f"NAIVE_DATA_DIR={self.paths.data_dir}\n"
        )
        unit_source = self.source_dir / "deploy" / "caddy-naive.service"
        try:
            unit_text = unit_source.read_text()
        except OSError as exc:
            raise NaiveError("Naive unit source is unavailable") from exc
        if f"User={_CADDY_USER}" not in unit_text or "User=root" in unit_text:
            raise NaiveError("Naive unit identity is invalid")
        return RenderedNaive(
            caddyfile_template=caddyfile,
            env_text=env,
            unit_text=unit_text,
            pin_text=_CADDY_VERSION + "\n",
            file_modes={
                self.paths.caddyfile: 0o640,
                self.paths.manager_token: 0o400,
                self.paths.secret_token: 0o600,
                self.paths.env_overlay: 0o600,
                self.paths.marker: 0o600,
                self.paths.pin: 0o644,
                self.paths.unit: 0o644,
                self.paths.checker: 0o755,
                self.paths.adapt_script: 0o755,
                self.paths.state_preparer: 0o755,
                self.paths.deploy_hook: 0o755,
                self.paths.acceptance_owner: 0o600,
                self.paths.acceptance_pending: 0o600,
            },
        )

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def prepare(self, action: Action) -> Mapping[str, object]:
        self._selection(action)
        self._assert_live_identities()
        marker = self._host(self.paths.marker)
        adoption = self._adoption_kind(marker)
        if adoption == "absent" and self._service_present():
            raise NaiveError(
                "active Naive resources require a proven owned recovery generation"
            )
        acceptance_name = self._existing_acceptance_name()
        if acceptance_name is None:
            acceptance_name = _ACCEPTANCE_PREFIX + secrets.token_hex(8)
        marker_value = secrets.token_hex(16) if adoption == "absent" else None
        marker_sha256 = (
            hashlib.sha256((marker_value + "\n").encode()).hexdigest()
            if marker_value is not None
            else self.marker_sha256()
        )
        caddy = self._host(self.paths.caddy_binary)
        caddy_preexisting = caddy.exists() or caddy.is_symlink()
        if caddy_preexisting:
            self._assert_pinned_caddy()
        state_dir = self._host(self.paths.data_dir)
        log_dir = self._host(self.paths.log_dir)
        return {
            "acceptance_name": acceptance_name,
            "adoption": adoption,
            "caddy_preexisting": caddy_preexisting,
            "identities_created": {},
            "log_dir_preexisting": log_dir.exists() or log_dir.is_symlink(),
            "marker_value": marker_value,
            "owner": action.owner,
            "ownership": {},
            "planned_ownership": self._planned_ownership(
                action,
                acceptance_name=acceptance_name,
                marker_sha256=marker_sha256,
            ),
            "state_dir_preexisting": state_dir.exists() or state_dir.is_symlink(),
            "unit_preexisting": self._unit_present(),
        }

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action)
        # 1. Pinned artifact before anything else claims the fixed identities.
        self._install_caddy(prepared)
        # 2. Split identities.
        identities = self._ensure_identities()
        # 3. Directories, credentials, staged Caddyfile, helpers, and unit.
        self._install_helpers()
        self._prepare_state()
        self._write_generation(selected, prepared)
        self._install_deploy_hook(selected)
        self._install_cover_site(selected)
        # 4. Host Caddy with a proven private listener.
        self._run("systemctl", "daemon-reload")
        self._run("systemctl", "enable", "--now", _UNIT_NAME)
        self._assert_private_listeners()
        # 5. Manager bootstrap, reload, then the long-running overlay.
        self._compose("run", "--rm", "--build", "naive-manager", "--bootstrap-only")
        self._run("systemctl", "reload", _UNIT_NAME)
        self._compose("up", "-d", "--build", "--wait")
        return {
            **prepared,
            "identities_created": identities,
            "ownership": self._ownership(prepared),
        }

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self.apply(action, checkpoint)

    def verify(self, action: Action) -> Evidence:
        selected = self._selection(action)
        acceptance_name = self._read_acceptance_owner()
        pending = self._host(self.paths.acceptance_pending)
        recover_existing = pending.exists() or pending.is_symlink()
        if recover_existing:
            self._assert_pending(pending, acceptance_name)
        else:
            self._atomic(pending, (acceptance_name + "\n").encode(), 0o600)
        result: NaiveAcceptance | None = None
        cleanup_ok = False
        failure: Exception | None = None
        try:
            raw = self.runner.naive_acceptance(
                panel_domain=str(selected["panel_domain"]),
                naive_domain=str(selected["naive_domain"]),
                log_dir=self.paths.log_dir,
                bootstrap_credential_file=(
                    f"{self.paths.project_dir}/secrets/panel-bootstrap-password"
                ),
                acceptance_name=acceptance_name,
                adjacent_sni=selected["adjacent_sni"],
                recover_existing=recover_existing,
                state_preparer=self.paths.state_preparer,
            )
            result = _acceptance_value(raw)
            _require_acceptance(result)
        except Exception as exc:
            failure = exc
        finally:
            try:
                if isinstance(failure, _AcceptanceCollision) and not recover_existing:
                    cleanup_ok = True
                else:
                    self._cleanup_acceptance(selected, acceptance_name)
                    cleanup_ok = True
            except Exception as exc:
                if failure is None:
                    failure = AcceptanceError(
                        "temporary-user and session cleanup failed"
                    )
                    failure.__cause__ = exc
            if cleanup_ok:
                durable_remove(pending, missing_ok=True)
        if failure is not None:
            if isinstance(failure, AcceptanceError):
                raise failure
            raise AcceptanceError("Naive acceptance execution failed") from failure
        if result is None or not cleanup_ok:
            raise AcceptanceError("temporary-user and session cleanup failed")
        result = NaiveAcceptance(
            **{**result.details(), "temporary_state_removed": True}
        )
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "Naive listener, cover, authenticated CONNECT, and accounting passed",
                "temporary acceptance state was removed",
            ),
            details=result.details(),
        )

    def repair(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._assert_checkpoint_ownership(prepared)
        self._assert_live_identities()
        self._assert_pinned_caddy()
        self._run(
            self.paths.state_preparer,
            "verify",
            "--state-dir",
            self.paths.data_dir,
            "--log-dir",
            self.paths.log_dir,
        )
        self._run("systemctl", "restart", _UNIT_NAME)
        self._assert_private_listeners()
        self._compose("up", "-d", "--wait")
        return prepared

    def rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        if rollback_target not in {"rolled_back", "uninstalled"}:
            raise ValueError("invalid rollback target")
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action, applied=True)
        destructive_purge = rollback_target == "uninstalled" and purge_data
        cleanup_pending = False
        pending = self._host(self.paths.acceptance_pending)
        if pending.exists() or pending.is_symlink():
            try:
                self._cleanup_acceptance(
                    selected,
                    str(prepared["acceptance_name"]),
                )
            except Exception:
                # A rollback is never blocked by an unreachable runtime: the
                # pending temporary user stays recorded in the tombstone so a
                # later repair or uninstall retries it.
                cleanup_pending = not destructive_purge
                if cleanup_pending:
                    self._write_acceptance_owner(str(prepared["acceptance_name"]))
            durable_remove(pending, missing_ok=True)
        if self._unit_present():
            self._run_best_effort("systemctl", "disable", "--now", _UNIT_NAME)
        if self._compose_service_present():
            self._compose("rm", "--stop", "--force", "naive-manager")
        self._remove_generation(
            prepared,
            preserve_credentials=not destructive_purge,
            preserve_acceptance=cleanup_pending,
        )
        self._remove_owned_caddy(prepared)
        self._run_best_effort("systemctl", "daemon-reload")
        if destructive_purge:
            self._purge_state()
            self._remove_identities(prepared)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the Naive runtime was removed",
                (
                    "manager state and credentials were purged"
                    if destructive_purge
                    else "manager state and credentials were preserved"
                ),
            ),
            details={
                "persistent_data_preserved": not destructive_purge,
                "identities_removed": destructive_purge,
                "temporary_cleanup_pending": cleanup_pending,
            },
        )

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        return self.rollback(
            action,
            checkpoint,
            purge_data=purge_data,
            rollback_target=rollback_target,
        )

    def marker_sha256(self, expected: str | None = None) -> str:
        marker = self._host(self.paths.marker)
        if (
            marker.is_symlink()
            or not marker.is_file()
            or stat.S_IMODE(marker.stat().st_mode) != 0o600
            or (
                self.root == Path("/")
                and (marker.stat().st_uid, marker.stat().st_gid) != (0, 0)
            )
        ):
            raise NaiveError("Naive generation ownership has drifted")
        actual = _file_sha256(marker)
        if expected is not None and actual != expected:
            raise NaiveError("Naive generation ownership has drifted")
        return actual

    # ------------------------------------------------------------------
    # action and checkpoint validation
    # ------------------------------------------------------------------

    def _selection(self, action: Action) -> dict[str, object]:
        if (
            action.adapter != self.name
            or action.id != "naive.runtime"
            or action.owner != "proxy-control:naive"
        ):
            raise NaiveError("Naive action is invalid")
        values: dict[str, str] = {}
        for mutation in action.mutations:
            key, separator, value = mutation.partition("=")
            if not separator or not key or key in values:
                raise NaiveError("Naive action is invalid")
            values[key] = value
        required = {
            "project",
            "naive-domain",
            "panel-domain",
            "data-dir",
            "log-dir",
            "caddy-binary",
            "caddy-build",
            "unit",
            "private-port",
            "caddy-uid",
            "accounting-gid",
            "manager-uid",
            "manager-gid",
            "adjacent-sni",
            "egress",
        }
        if set(values) != required:
            raise NaiveError("Naive action is invalid")
        if (
            values["project"] != self.paths.project_dir
            or values["data-dir"] != self.paths.data_dir
            or values["log-dir"] != self.paths.log_dir
            or values["caddy-binary"] != self.paths.caddy_binary
            or values["unit"] != self.paths.unit
            or values["caddy-build"] != _CADDY_VERSION
            or values["private-port"] != str(_PRIVATE_PORT)
            or values["caddy-uid"] != str(_CADDY_UID)
            or values["accounting-gid"] != str(_ACCOUNTING_GID)
            or values["manager-uid"] != str(_MANAGER_UID)
            or values["manager-gid"] != str(_MANAGER_GID)
            or _DOMAIN.fullmatch(values["naive-domain"]) is None
            or _DOMAIN.fullmatch(values["panel-domain"]) is None
            or values["naive-domain"] == values["panel-domain"]
            or values["egress"] not in {"proxy", "direct"}
        ):
            raise NaiveError("Naive action is invalid")
        return {
            "naive_domain": values["naive-domain"].lower(),
            "panel_domain": values["panel-domain"].lower(),
            "adjacent_sni": _decode_adjacent_routes(values["adjacent-sni"]),
            "egress": values["egress"],
        }

    def _checkpoint(
        self,
        checkpoint: Mapping[str, object],
        action: Action,
        *,
        applied: bool = False,
    ) -> dict[str, object]:
        required = {
            "acceptance_name",
            "adoption",
            "caddy_preexisting",
            "identities_created",
            "log_dir_preexisting",
            "marker_value",
            "owner",
            "ownership",
            "planned_ownership",
            "state_dir_preexisting",
            "unit_preexisting",
        }
        if set(checkpoint) != required:
            raise NaiveError("Naive checkpoint is invalid")
        acceptance_name = checkpoint["acceptance_name"]
        adoption = checkpoint["adoption"]
        marker_value = checkpoint["marker_value"]
        ownership = checkpoint["ownership"]
        planned = checkpoint["planned_ownership"]
        identities = checkpoint["identities_created"]
        if (
            not isinstance(acceptance_name, str)
            or _ACCEPTANCE_NAME.fullmatch(acceptance_name) is None
            or adoption not in {"absent", "recovery"}
            or checkpoint["owner"] != action.owner
            or (
                adoption == "absent"
                and (
                    not isinstance(marker_value, str)
                    or _HEX_16.fullmatch(marker_value) is None
                )
            )
            or (adoption == "recovery" and marker_value is not None)
            or not isinstance(planned, Mapping)
            or not planned
            or not isinstance(ownership, Mapping)
            or (not applied and ownership)
            or not isinstance(identities, Mapping)
            or any(
                not isinstance(key, str) or not isinstance(value, bool)
                for key, value in identities.items()
            )
            or any(
                not isinstance(checkpoint[name], bool)
                for name in (
                    "caddy_preexisting",
                    "log_dir_preexisting",
                    "state_dir_preexisting",
                    "unit_preexisting",
                )
            )
        ):
            raise NaiveError("Naive checkpoint is invalid")
        _validate_ownership_mapping(planned)
        if applied:
            _validate_ownership_mapping(ownership)
        return {name: checkpoint[name] for name in required}

    # ------------------------------------------------------------------
    # ownership
    # ------------------------------------------------------------------

    def _owned_paths(self) -> tuple[tuple[str, bool], ...]:
        """Every host path one generation may own, with its preserve flag."""
        return (
            (self.paths.marker, True),
            (self.paths.pin, False),
            (self.paths.unit, False),
            (self.paths.checker, False),
            (self.paths.adapt_script, False),
            (self.paths.state_preparer, False),
            (self.paths.deploy_hook, False),
            (self.paths.env_overlay, False),
            (self.paths.acceptance_owner, False),
            (_TLS_DIR + "/fullchain.pem", False),
            (_TLS_DIR + "/privkey.pem", False),
            (self.paths.secret_token, True),
            (self.paths.manager_token, True),
            (self.paths.caddyfile, True),
        )

    def _planned_ownership(
        self,
        action: Action,
        *,
        acceptance_name: str,
        marker_sha256: str,
    ) -> dict[str, dict[str, object]]:
        rendered = self.render(action)
        planned: dict[str, dict[str, object]] = {
            self.paths.marker: {"preserve": True, "sha256": marker_sha256},
            self.paths.acceptance_owner: {
                "preserve": False,
                "sha256": hashlib.sha256(
                    (acceptance_name + "\n").encode()
                ).hexdigest(),
            },
            self.paths.env_overlay: {
                "preserve": False,
                "sha256": hashlib.sha256(rendered.env_text.encode()).hexdigest(),
            },
            self.paths.pin: {
                "preserve": False,
                "sha256": hashlib.sha256(rendered.pin_text.encode()).hexdigest(),
            },
        }
        for relative, host_path, _mode in _HELPERS:
            source = self.source_dir / relative
            if not source.is_file():
                raise NaiveError("installer source generation is incomplete")
            planned[host_path] = {
                "preserve": False,
                "sha256": _path_sha256(source),
            }
        selected = self._selection(action)
        planned[self.paths.deploy_hook] = {
            "preserve": False,
            "sha256": hashlib.sha256(
                _deploy_hook_text(str(selected["naive_domain"])).encode()
            ).hexdigest(),
        }
        return planned

    def _ownership(
        self,
        checkpoint: Mapping[str, object],
    ) -> dict[str, dict[str, object]]:
        ownership: dict[str, dict[str, object]] = {}
        for host_path, preserve in self._owned_paths():
            path = self._host(host_path)
            if path.exists() or path.is_symlink():
                ownership[host_path] = {
                    "preserve": preserve,
                    # The manager rewrites the Caddyfile on every credential
                    # change, so its digest is never foreign drift.
                    "mutable": host_path == self.paths.caddyfile,
                    "sha256": _path_sha256(path),
                }
        caddy = self._host(self.paths.caddy_binary)
        if caddy.exists() or caddy.is_symlink():
            ownership[self.paths.caddy_binary] = {
                "preserve": bool(checkpoint["caddy_preexisting"]),
                "sha256": _path_sha256(caddy),
            }
        if not ownership:
            raise NaiveError("Naive generation has no owned files")
        return ownership

    def _assert_checkpoint_ownership(self, checkpoint: Mapping[str, object]) -> None:
        ownership = checkpoint["ownership"]
        if not isinstance(ownership, Mapping):
            raise NaiveError("Naive checkpoint is invalid")
        for host_path, entry in ownership.items():
            if not isinstance(host_path, str) or not isinstance(entry, Mapping):
                raise NaiveError("Naive checkpoint is invalid")
            path = self._host(host_path)
            if (
                not (path.exists() or path.is_symlink())
                or _path_sha256(path) != entry["sha256"]
            ):
                raise NaiveError(f"Naive owned file has drifted: {host_path}")

    def _remove_generation(
        self,
        checkpoint: Mapping[str, object],
        *,
        preserve_credentials: bool,
        preserve_acceptance: bool = False,
    ) -> None:
        ownership = checkpoint.get("ownership", {})
        planned = checkpoint.get("planned_ownership", {})
        if not isinstance(ownership, Mapping) or not isinstance(planned, Mapping):
            raise NaiveError("Naive checkpoint is invalid")
        using_planned = not ownership
        entries = planned if using_planned else ownership
        allowed = {host_path for host_path, _preserve in self._owned_paths()}
        allowed.add(self.paths.caddy_binary)
        directories: set[Path] = set()
        for host_path, entry in sorted(entries.items(), reverse=True):
            if host_path == self.paths.caddy_binary:
                continue
            if not isinstance(entry, Mapping) or host_path not in allowed:
                raise NaiveError("Naive checkpoint ownership escapes the boundary")
            if preserve_credentials and entry.get("preserve") is True:
                continue
            if preserve_acceptance and host_path == self.paths.acceptance_owner:
                continue
            path = self._host(host_path)
            directories.add(path.parent)
            if not (path.exists() or path.is_symlink()):
                continue
            if _path_sha256(path) != entry.get("sha256"):
                if using_planned:
                    continue
                raise NaiveError(f"Naive owned file has drifted: {host_path}")
            durable_remove(path)
        for directory in sorted(
            directories,
            key=lambda value: len(value.parts),
            reverse=True,
        ):
            if directory.is_symlink() or not directory.is_dir():
                continue
            try:
                directory.rmdir()
            except OSError:
                continue
            fsync_directory(directory.parent)

    def _remove_owned_caddy(self, checkpoint: Mapping[str, object]) -> None:
        if checkpoint.get("caddy_preexisting") is True:
            return
        caddy = self._host(self.paths.caddy_binary)
        if not (caddy.exists() or caddy.is_symlink()):
            return
        ownership = checkpoint.get("ownership", {})
        expected = (
            ownership.get(self.paths.caddy_binary, {}).get("sha256")
            if isinstance(ownership, Mapping)
            else None
        )
        if expected is not None and _path_sha256(caddy) != expected:
            raise NaiveError("Naive owned Caddy binary has drifted")
        durable_remove(caddy)

    def _purge_state(self) -> None:
        for host_path in (
            self.paths.secret_token,
            self.paths.manager_token,
            self.paths.caddyfile,
        ):
            path = self._host(host_path)
            if path.exists() or path.is_symlink():
                durable_remove(path)
        state = self._host(self.paths.data_dir)
        if state.is_dir() and not state.is_symlink():
            for entry in sorted(state.rglob("*"), reverse=True):
                if entry.is_dir() and not entry.is_symlink():
                    entry.rmdir()
                else:
                    durable_remove(entry)

    def _remove_identities(self, checkpoint: Mapping[str, object]) -> None:
        created = checkpoint.get("identities_created", {})
        if not isinstance(created, Mapping):
            return
        if created.get("user") is True:
            self._run_best_effort("userdel", _CADDY_USER)
        if created.get("group") is True:
            self._run_best_effort("groupdel", _ACCOUNTING_GROUP)

    # ------------------------------------------------------------------
    # apply helpers
    # ------------------------------------------------------------------

    def _install_caddy(self, checkpoint: Mapping[str, object]) -> None:
        if checkpoint["caddy_preexisting"] is True:
            self._assert_pinned_caddy()
            return
        destination = self._host(self.paths.caddy_binary)
        durable_mkdir(destination.parent)
        builder = getattr(self.runner, "build_caddy", None)
        if not callable(builder):
            raise NaiveError("pinned Caddy build is unavailable")
        builder(str(self.source_dir), str(destination))
        if not destination.is_file() or destination.is_symlink():
            raise NaiveError("pinned Caddy build produced no binary")
        os.chmod(destination, 0o755)
        if self.root == Path("/") and os.geteuid() == 0:
            os.chown(destination, 0, 0)
        self._assert_pinned_caddy()

    def _assert_pinned_caddy(self) -> None:
        identity = getattr(self.runner, "caddy_identity", None)
        if not callable(identity):
            raise NaiveError("pinned Caddy verification is unavailable")
        version, forward_proxy = identity(str(self._host(self.paths.caddy_binary)))
        if version.strip() != _CADDY_VERSION or not forward_proxy:
            raise NaiveError("refusing an unpinned Caddy build")

    def _ensure_identities(self) -> dict[str, bool]:
        self._assert_live_identities()
        created = {"group": False, "user": False}
        if self._identity_owner("gid", _ACCOUNTING_GID) is None:
            self._run(
                "groupadd",
                "--system",
                "--gid",
                str(_ACCOUNTING_GID),
                _ACCOUNTING_GROUP,
            )
            created["group"] = True
        if self._identity_owner("uid", _CADDY_UID) is None:
            self._run(
                "useradd",
                "--system",
                "--uid",
                str(_CADDY_UID),
                "--gid",
                str(_ACCOUNTING_GID),
                "--home",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                _CADDY_USER,
            )
            created["user"] = True
        self._assert_live_identities()
        return created

    def _assert_live_identities(self) -> None:
        for kind, identifier, expected in (
            ("uid", _CADDY_UID, _CADDY_USER),
            ("gid", _ACCOUNTING_GID, _ACCOUNTING_GROUP),
        ):
            name = self._identity_owner(kind, identifier)
            if name is not None and name != expected:
                raise NaiveError(f"{kind.upper()} {identifier} collision: {name}")

    def _identity_owner(self, kind: str, identifier: int) -> str | None:
        lookup = getattr(self.runner, "identity_owner", None)
        if not callable(lookup):
            return None
        value = lookup(kind, identifier)
        return str(value) if value else None

    def _install_helpers(self) -> None:
        for relative, host_path, mode in _HELPERS:
            source = self.source_dir / relative
            if not source.is_file():
                raise NaiveError("installer source generation is incomplete")
            destination = self._host(host_path)
            durable_mkdir(destination.parent)
            self._atomic(destination, source.read_bytes(), mode)

    def _install_deploy_hook(self, selected: Mapping[str, object]) -> None:
        hook = self._host(self.paths.deploy_hook)
        durable_mkdir(hook.parent)
        self._atomic(
            hook,
            _deploy_hook_text(str(selected["naive_domain"])).encode(),
            0o755,
        )
        # Publish immediately: the unit cannot start without the keypair.
        self._run(str(hook))

    def _install_cover_site(self, selected: Mapping[str, object]) -> None:
        """Seed the cover root so an unauthenticated request answers 200.

        The root belongs to the operator, so an existing page is never
        replaced and uninstall never removes what is written here.
        """
        domain = str(selected["naive_domain"])
        cover = self._host(f"/var/www/{domain}/index.html")
        if cover.exists() or cover.is_symlink():
            return
        durable_mkdir(cover.parent)
        self._atomic(cover, _COVER_INDEX, 0o644)

    def _prepare_state(self) -> None:
        self._run(
            self.paths.state_preparer,
            "prepare",
            "--state-dir",
            self.paths.data_dir,
            "--log-dir",
            self.paths.log_dir,
        )

    def _write_generation(
        self,
        selected: Mapping[str, object],
        checkpoint: Mapping[str, object],
    ) -> None:
        rendered = self.render(self._action_from_selection(selected))
        marker_value = checkpoint["marker_value"]
        if isinstance(marker_value, str):
            self._atomic(
                self._host(self.paths.marker),
                (marker_value + "\n").encode(),
                0o600,
            )
        self._atomic(
            self._host(self.paths.pin),
            rendered.pin_text.encode(),
            0o644,
        )
        self._atomic(
            self._host(self.paths.env_overlay),
            rendered.env_text.encode(),
            0o600,
        )
        self._write_acceptance_owner(str(checkpoint["acceptance_name"]))
        self._write_credentials(rendered)

    def _write_credentials(self, rendered: RenderedNaive) -> None:
        secret = self._host(self.paths.secret_token)
        token_copy = self._host(self.paths.manager_token)
        caddyfile = self._host(self.paths.caddyfile)
        if not (secret.exists() or secret.is_symlink()):
            durable_mkdir(secret.parent, mode=0o700)
            self._atomic(secret, (secrets.token_hex(32) + "\n").encode(), 0o600)
        self._assert_owned_credential(secret, 0o600, owner=(0, 0))
        if not (token_copy.exists() or token_copy.is_symlink()):
            durable_copy2(secret, token_copy)
        self._chown(token_copy, _MANAGER_UID, _MANAGER_GID, 0o400)
        if not (caddyfile.exists() or caddyfile.is_symlink()):
            body = rendered.caddyfile_template.replace(
                _BOOTSTRAP_USERNAME,
                f"bootstrap-{secrets.token_hex(4)}",
            ).replace(_BOOTSTRAP_PASSWORD, secrets.token_urlsafe(24))
            self._atomic(caddyfile, body.encode(), 0o640)
        self._chown(caddyfile, _MANAGER_UID, _MANAGER_GID, 0o640)

    def _assert_owned_credential(
        self,
        path: Path,
        mode: int,
        *,
        owner: tuple[int, int],
    ) -> None:
        if path.is_symlink() or not path.is_file():
            raise NaiveError("pre-existing Naive credentials are unsafe")
        metadata = path.stat()
        if stat.S_IMODE(metadata.st_mode) != mode or (
            self.root == Path("/")
            and (metadata.st_uid, metadata.st_gid) != owner
        ):
            raise NaiveError("pre-existing Naive credentials are unsafe")

    def _chown(self, path: Path, uid: int, gid: int, mode: int) -> None:
        if path.is_symlink() or not path.is_file():
            raise NaiveError("pre-existing Naive credentials are unsafe")
        os.chmod(path, mode)
        if self.root == Path("/") and os.geteuid() == 0:
            os.chown(path, uid, gid)

    def _action_from_selection(self, selected: Mapping[str, object]) -> Action:
        return Action(
            id="naive.runtime",
            adapter=self.name,
            owner="proxy-control:naive",
            mutations=(
                f"project={self.paths.project_dir}",
                f"naive-domain={selected['naive_domain']}",
                f"panel-domain={selected['panel_domain']}",
                f"data-dir={self.paths.data_dir}",
                f"log-dir={self.paths.log_dir}",
                f"caddy-binary={self.paths.caddy_binary}",
                f"caddy-build={_CADDY_VERSION}",
                f"unit={self.paths.unit}",
                f"private-port={_PRIVATE_PORT}",
                f"caddy-uid={_CADDY_UID}",
                f"accounting-gid={_ACCOUNTING_GID}",
                f"manager-uid={_MANAGER_UID}",
                f"manager-gid={_MANAGER_GID}",
                "adjacent-sni="
                + _encode_adjacent_routes(
                    tuple(selected.get("adjacent_sni", ()))  # type: ignore[arg-type]
                ),
                f"egress={selected.get('egress', 'direct')}",
            ),
            preconditions=("owned Naive generation",),
            verification=("Naive acceptance",),
            inverse=("remove owned Naive generation",),
            credentials_required=True,
        )

    # ------------------------------------------------------------------
    # acceptance ownership
    # ------------------------------------------------------------------

    def _existing_acceptance_name(self) -> str | None:
        owner = self._host(self.paths.acceptance_owner)
        pending = self._host(self.paths.acceptance_pending)
        if not (owner.exists() or owner.is_symlink()):
            if pending.exists() or pending.is_symlink():
                raise NaiveError("temporary-user ownership has drifted")
            return None
        if (
            owner.is_symlink()
            or not owner.is_file()
            or stat.S_IMODE(owner.stat().st_mode) != 0o600
        ):
            raise NaiveError("temporary-user ownership has drifted")
        value = owner.read_text().strip()
        if _ACCEPTANCE_NAME.fullmatch(value) is None:
            raise NaiveError("temporary-user ownership has drifted")
        if pending.exists() or pending.is_symlink():
            self._assert_pending(pending, value)
        return value

    def _assert_pending(self, pending: Path, acceptance_name: str) -> None:
        if (
            pending.is_symlink()
            or not pending.is_file()
            or stat.S_IMODE(pending.stat().st_mode) != 0o600
            or pending.read_text().strip() != acceptance_name
        ):
            raise AcceptanceError("temporary-user ownership has drifted")

    def _write_acceptance_owner(self, acceptance_name: str) -> None:
        if _ACCEPTANCE_NAME.fullmatch(acceptance_name) is None:
            raise NaiveError("temporary-user ownership has drifted")
        self._atomic(
            self._host(self.paths.acceptance_owner),
            (acceptance_name + "\n").encode(),
            0o600,
        )

    def _read_acceptance_owner(self) -> str:
        value = self._existing_acceptance_name()
        if value is None:
            raise NaiveError("temporary-user ownership has drifted")
        return value

    def _cleanup_acceptance(
        self,
        selected: Mapping[str, object],
        acceptance_name: str,
    ) -> None:
        cleanup = getattr(self.runner, "cleanup_naive_acceptance", None)
        if not callable(cleanup):
            raise AcceptanceError("temporary-user cleanup is unavailable")
        cleanup(
            panel_domain=str(selected["panel_domain"]),
            bootstrap_credential_file=(
                f"{self.paths.project_dir}/secrets/panel-bootstrap-password"
            ),
            acceptance_name=acceptance_name,
        )

    # ------------------------------------------------------------------
    # host state
    # ------------------------------------------------------------------

    def _adoption_kind(self, marker: Path) -> str:
        if not (marker.exists() or marker.is_symlink()):
            return "absent"
        self.marker_sha256()
        return "recovery"

    def _unit_present(self) -> bool:
        unit = self._host(self.paths.unit)
        return unit.exists() or unit.is_symlink()

    def _compose_service_present(self) -> bool:
        """Only the Naive manager counts; Core owns the shared project."""
        method = getattr(self.runner, "compose_service_present", None)
        if callable(method):
            return bool(method("naive-manager"))
        method = getattr(self.runner, "compose_project_present", None)
        return bool(method(self.paths.project_dir)) if callable(method) else False

    def _service_present(self) -> bool:
        return self._unit_present() or self._compose_service_present()

    def _assert_private_listeners(self) -> None:
        listener = getattr(self.runner, "loopback_listener", None)
        if not callable(listener):
            raise NaiveError("listener verification is unavailable")
        if not listener(_ADMIN_PORT) or not listener(_PRIVATE_PORT):
            raise NaiveError("Caddy Admin API and private listener must stay loopback")

    def _compose(self, *args: str) -> None:
        """Run one Compose command and keep its diagnostic on failure.

        A Compose failure is otherwise invisible: the runner discards output,
        and the operator is left with a bare "command failed".
        """
        argv = (
            "docker",
            "compose",
            "--project-directory",
            self.paths.project_dir,
            "--env-file",
            f"{self.paths.project_dir}/.env",
            "--env-file",
            self.paths.env_overlay,
            "-f",
            f"{self.paths.project_dir}/compose.yaml",
            "-f",
            self.paths.compose_overlay,
            *args,
        )
        capture = getattr(self.runner, "capture", None)
        if callable(capture):
            try:
                output = str(capture(argv, max_chars=1200))
            except Exception as exc:
                raise NaiveError(_command_failure(argv)) from exc
            if output.startswith("exit="):
                raise NaiveError(
                    f"{_command_failure(argv)}; {_sanitize_diagnostic(output)}"
                )
            return
        self._run_compose(*args)

    def _run_compose(self, *args: str) -> None:
        self._run(
            "docker",
            "compose",
            "--project-directory",
            self.paths.project_dir,
            "--env-file",
            f"{self.paths.project_dir}/.env",
            "--env-file",
            self.paths.env_overlay,
            "-f",
            f"{self.paths.project_dir}/compose.yaml",
            "-f",
            self.paths.compose_overlay,
            *args,
        )

    def _run(self, *argv: str, stdin_path: Path | None = None) -> None:
        try:
            try:
                result = self.runner.run(argv, stdin_path=stdin_path)
            except TypeError:
                result = self.runner.run(argv)
        except NaiveError:
            raise
        except Exception as exc:
            raise NaiveError(_command_failure(argv)) from exc
        if getattr(result, "returncode", 0):
            raise NaiveError(_command_failure(argv))

    def _run_best_effort(self, *argv: str) -> None:
        try:
            self._run(*argv)
        except Exception:
            return

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise NaiveError("Naive host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise NaiveError("Naive root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise NaiveError("Naive host path crosses an unsafe parent")
        return self.root / relative

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        durable_mkdir(path.parent)
        atomic_write(path, data, mode=mode, owner=owner)


def _acceptance_value(value: object) -> NaiveAcceptance:
    if isinstance(value, NaiveAcceptance):
        return value
    if isinstance(value, Mapping):
        allowed = set(NaiveAcceptance.__dataclass_fields__)
        if not set(value) <= allowed:
            raise AcceptanceError("Naive acceptance result is invalid")
        try:
            return NaiveAcceptance(**dict(value))
        except (TypeError, ValueError) as exc:
            raise AcceptanceError("Naive acceptance result is invalid") from exc
    raise AcceptanceError("Naive acceptance result is invalid")


def _require_acceptance(result: NaiveAcceptance) -> None:
    if not result.admin_api_loopback or not result.private_listener_ok:
        raise AcceptanceError("Naive acceptance failed: loopback listeners")
    if not result.cover_https_ok:
        raise AcceptanceError("Naive acceptance failed: cover HTTPS")
    if not result.authenticated_connect_ok or result.connect_bytes <= 0:
        raise AcceptanceError("Naive acceptance failed: authenticated CONNECT")
    if not result.tunnel_closed_ok:
        raise AcceptanceError("Naive acceptance failed: tunnel close")
    if result.recorded_bytes < result.connect_bytes:
        raise AcceptanceError("Naive acceptance failed: closed-tunnel accounting")
    if not result.manager_health_ok or not result.panel_health_ok:
        raise AcceptanceError("Naive acceptance failed: manager and panel health")
    if not result.adjacent_sni_ok:
        raise AcceptanceError("Naive acceptance failed: adjacent SNI")
    if not result.log_boundary_ok:
        raise AcceptanceError("Naive acceptance failed: accounting log boundary")


def _validate_ownership_mapping(value: Mapping[object, object]) -> None:
    for host_path, entry in value.items():
        if (
            not isinstance(host_path, str)
            or not host_path.startswith("/")
            or not isinstance(entry, Mapping)
            or not {"preserve", "sha256"} <= set(entry) <= {
                "preserve",
                "mutable",
                "sha256",
            }
            or not isinstance(entry["preserve"], bool)
            or not isinstance(entry.get("mutable", False), bool)
            or not isinstance(entry["sha256"], str)
            or _SHA256.fullmatch(entry["sha256"]) is None
        ):
            raise NaiveError("Naive ownership record is invalid")
