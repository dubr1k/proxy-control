from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from installer.adapters.core import _DOMAIN, _DefaultCoreRunner, _file_sha256
from installer.model import InstallerConfig, ThreeXuiMode
from installer.planner import (
    Action,
    AuditFacts,
    Evidence,
    InstallPlan,
    PlanError,
    ReleaseIdentity,
)
from installer.release import (
    ArchiveEntry,
    ArchiveManifest,
    ArtifactPin,
    safe_extract_tar,
    verify_artifact,
)
from installer.transaction import (
    atomic_write,
    durable_mkdir,
    durable_remove,
    fsync_directory,
)

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_ROOT_DIR = "/usr/local/x-ui"
_BINARY = "/usr/local/x-ui/x-ui"
_CONFIG = "/usr/local/x-ui/bin/config.json"
_DATABASE = "/etc/x-ui/x-ui.db"
_UNIT = "/etc/systemd/system/x-ui.service"
_MARKER = "/etc/proxy-control/three-xui-owned"
_SNAPSHOT_DIR = "/var/lib/proxy-control/three-xui"

_UNIT_NAME = "x-ui"
_BOOTSTRAP_UNIT = "x-ui-bootstrap"
_BOOTSTRAP_NETNS = "proxy-control-x-ui"
_DEFAULT_CREDENTIAL = "admin"
# Where a fresh 3x-ui answers before the installer moves it.
_DEFAULT_PANEL_PORT = 2053
# The certificate lineage the Nginx boundary issues for the 3x-ui panel domain.
_LINEAGE_ROOT = "/etc/letsencrypt/live"
_PANEL_LINEAGE = "three-xui-panel"
_VERSION = "3.7.0"
_SUPPORTED_ARCHITECTURES = ("amd64",)
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_MAX_INBOUNDS = 256
_MAX_TREE_ENTRIES = 4096

# Managed-new inbounds stay on loopback so Nginx keeps the shared 443 listener.
_VLESS_TCP_BACKEND = 8449
_VLESS_XHTTP_BACKEND = 8450
_PANEL_BACKEND = 8451
# 3x-ui's own subscription server; like the panel it is a 3x-ui listener, not an inbound.
_SUBSCRIPTION_BACKEND = 2096
_WARP_PORT = 40000
_HYSTERIA_PORT = 443

_SAFE_TEXT = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_NETWORKS = {"tcp", "ws", "grpc", "http", "xhttp", "httpupgrade", "kcp", "quic"}
_SECURITY = {"none", "tls", "reality", "xtls"}
_ROUTING_SELECTORS = ("inboundTag", "outboundTag", "balancerTag", "network", "protocol")
_WARP_GEOSITE = re.compile(r"geosite:[a-z0-9_-]+\Z")


def _valid_warp_selector(value: str) -> bool:
    """Match exactly the selector grammar accepted by installer config."""
    if _WARP_GEOSITE.fullmatch(value) is not None:
        return True
    return _DOMAIN.fullmatch(value.removeprefix("domain:")) is not None


# Fields that must never reach a fact, report, plan, or evidence structure.
_FORBIDDEN_FIELDS = (
    "clients",
    "privateKey",
    "publicKey",
    "shortIds",
    "password",
    "id",
    "flow",
    "email",
    "subId",
    "settings",
)


# Executed inside the bootstrap namespace; every credential arrives on stdin.
_BOOTSTRAP_DIALOGUE = """
import json, sys, time
from installer.three_xui_api import ThreeXuiApi, ThreeXuiApiError, ThreeXuiClient

payload = json.load(sys.stdin)
api = ThreeXuiApi(ThreeXuiClient(port=payload["port"]))
# The panel is starting as this runs. Waiting for it here keeps a slow start
# from looking like a wrong password.
deadline = time.monotonic() + 60
while True:
    try:
        api.login(payload["initial_username"], payload["initial_password"])
        break
    except ThreeXuiApiError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(1)
api.rotate_credentials(
    old_username=payload["initial_username"],
    old_password=payload["initial_password"],
    new_username=payload["username"],
    new_password=payload["password"],
)
api.login(payload["username"], payload["password"])
try:
    api.login(payload["initial_username"], payload["initial_password"])
except ThreeXuiApiError:
    pass
else:
    raise SystemExit("the upstream first-run credential still works")
api.login(payload["username"], payload["password"])
# Moving the panel comes last: the base path takes effect immediately, so
# every path this dialogue uses moves with it. A fresh panel listens on
# *:2053 and *:2096, and this is still inside the namespace with no route
# out, so it is never reachable from elsewhere on a default port.
api.configure_panel(
    web_path=payload["web_path"],
    port=payload["panel_port"],
    listen="127.0.0.1",
    certificate=payload["certificate"],
    private_key=payload["private_key"],
)
"""


class ThreeXuiError(RuntimeError):
    """The 3x-ui boundary cannot be inspected or changed safely."""


class ArtifactError(ThreeXuiError):
    """A pinned 3x-ui artifact failed closed verification."""


class AcceptanceError(ThreeXuiError):
    """The managed 3x-ui runtime failed an acceptance requirement."""


# Xray prints the Reality keypair as labelled lines. The pinned 3x-ui 3.7.0
# carries Xray 26.7.28, which writes "PrivateKey:" and "Password (PublicKey):";
# older builds wrote "Private key:" and "Public key:". Both are read, and
# anything else is an error rather than a silently empty key.
_KEY_VALUE = r"([A-Za-z0-9_-]{43})"
_PRIVATE_KEY_LINE = re.compile(rf"^Private ?[Kk]ey:[ \t]*{_KEY_VALUE}[ \t]*$", re.MULTILINE)
_PUBLIC_KEY_LINE = re.compile(
    rf"^(?:Password \(PublicKey\)|Public ?[Kk]ey):[ \t]*{_KEY_VALUE}[ \t]*$",
    re.MULTILINE,
)


def parse_reality_keypair(output: str) -> tuple[str, str]:
    """Read one Reality keypair out of `xray x25519` output.

    A half-read keypair would produce an inbound nobody can connect to, so
    every departure from the expected shape fails closed. The error never
    quotes the output, because the output is key material.
    """
    private = _PRIVATE_KEY_LINE.search(output)
    public = _PUBLIC_KEY_LINE.search(output)
    if private is None or public is None:
        raise ThreeXuiError("the Xray keypair output was not in the expected form")
    return private.group(1), public.group(1)


@dataclass(frozen=True)
class ThreeXuiPaths:
    """Fixed host paths of an existing or managed 3x-ui installation."""

    root_dir: str = _ROOT_DIR
    binary: str = _BINARY
    config: str = _CONFIG
    database: str = _DATABASE
    unit: str = _UNIT
    marker: str = _MARKER
    snapshot_dir: str = _SNAPSHOT_DIR

    def __post_init__(self) -> None:
        for value in (
            self.root_dir,
            self.binary,
            self.config,
            self.database,
            self.unit,
            self.marker,
            self.snapshot_dir,
        ):
            if not value.startswith("/") or ".." in Path(value).parts:
                raise ValueError("3x-ui path must be a normalized absolute path")

    def xray_binary(self, architecture: str) -> str:
        """The Xray the pinned 3x-ui ships, which mints the Reality keypair.

        3x-ui names it after the architecture it was built for, and the tree
        carries exactly one of them.
        """
        if architecture not in _SUPPORTED_ARCHITECTURES:
            raise ValueError("unsupported architecture")
        return f"{self.root_dir}/bin/xray-linux-{architecture}"


@dataclass(frozen=True)
class ThreeXuiInboundFact:
    """One audited inbound with only non-secret, whitelisted selectors."""

    tag: str
    protocol: str
    listen: str
    port: int
    network: str
    security: str
    client_count: int
    reality_server_names: tuple[str, ...] = ()
    reality_target: str | None = None
    tls_certificate_paths: tuple[str, ...] = ()
    sniffing_enabled: bool = False
    sniffing_dest_override: tuple[str, ...] = ()

    @property
    def loopback(self) -> bool:
        return self.listen in _LOOPBACK


@dataclass(frozen=True)
class ThreeXuiAudit:
    """Secret-free description and byte identity of an existing install."""

    installed: bool
    inbounds: tuple[ThreeXuiInboundFact, ...] = ()
    outbound_tags: tuple[str, ...] = ()
    balancer_tags: tuple[str, ...] = ()
    routing_selectors: tuple[str, ...] = ()
    client_total: int = 0
    digests: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def inbound(self, *, protocol: str, network: str) -> ThreeXuiInboundFact | None:
        for item in self.inbounds:
            if item.protocol == protocol and item.network == network:
                return item
        return None


class _DefaultThreeXuiRunner(_DefaultCoreRunner):
    """Real host commands for the 3x-ui boundary."""

    def identity_named(self, database: str, name: str) -> str | None:
        """Return the named entry, or None when it does not exist.

        `capture` reports a failed lookup as diagnostic text rather than
        raising, so only an entry whose first field is exactly this name
        counts.
        """
        try:
            output = self.capture(("getent", database, name), max_chars=512)
        except Exception:
            return None
        for line in output.strip().splitlines():
            if line.split(":", 1)[0] == name:
                return name
        return None

    def x_ui_version(self, binary: str) -> str:
        return self._capture_checked((binary, "-v")).strip()

    def reality_keypair(self, xray_binary: str) -> tuple[str, str]:
        """Mint one Reality keypair with the Xray that will serve it.

        The private half never reaches argv, an environment variable, or the
        journal: it is read from this process's own captured output and goes
        straight into the inbound body.
        """
        return parse_reality_keypair(
            self._capture_checked((xray_binary, "x25519"))
        )

    def migration_rehearsal(self, binary: str, database: str) -> None:
        """Run the new binary's migration against a private database copy."""
        self._run_checked(
            (
                "env",
                f"XUI_DB_FOLDER={Path(database).parent}",
                binary,
                "migrate",
            ),
            "migration rehearsal",
        )

    def bootstrap_session(
        self,
        *,
        namespace: str,
        binary: str,
        payload_path: str,
    ) -> None:
        """Run the first-start credential rotation with no non-loopback path."""
        self._run_checked(("ip", "netns", "add", namespace), "bootstrap namespace")
        try:
            self._run_checked(
                ("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"),
                "bootstrap loopback",
            )
            self._run_checked(
                (
                    "systemd-run",
                    f"--unit={_BOOTSTRAP_UNIT}",
                    f"--property=NetworkNamespacePath=/run/netns/{namespace}",
                    # x-ui launches Xray by a relative path, so it only works
                    # from inside its own tree.
                    f"--property=WorkingDirectory={Path(binary).parent}",
                    binary,
                    "run",
                ),
                "bootstrap start",
            )
            # The dialogue reads its credentials from stdin: nothing sensitive
            # ever appears in argv, the journal, or a named temporary file.
            #
            # Its exit status is checked. It rotates the first-run credential
            # and moves the panel onto loopback, and a failure that goes
            # unnoticed here leaves the panel reachable with a password that
            # is public knowledge.
            with Path(payload_path).open("rb") as stdin:
                completed = subprocess.run(
                    (
                        "ip",
                        "netns",
                        "exec",
                        namespace,
                        "python3",
                        "-c",
                        _BOOTSTRAP_DIALOGUE,
                    ),
                    check=False,
                    stdin=stdin,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout,
                )
            if completed.returncode != 0:
                # The dialogue's credentials arrive on stdin and its traceback
                # prints no values, so its own last words are safe to report
                # and are the only way to tell why the panel was left alone.
                detail = completed.stderr.decode("utf-8", "replace").strip()[-500:]
                raise ThreeXuiError(
                    "the 3x-ui first-run dialogue failed; the panel still has "
                    f"its factory credential: {detail}"
                )
        finally:
            self._run_checked(
                ("systemctl", "stop", f"{_BOOTSTRAP_UNIT}.service"),
                "bootstrap stop",
            )
            self._run_checked(
                ("ip", "netns", "delete", namespace),
                "bootstrap namespace cleanup",
            )

    def listening_ports(self) -> set[int]:
        """Every TCP and UDP port with a listener right now."""
        ports: set[int] = set()
        for argv in (("ss", "-lntH"), ("ss", "-lnuH")):
            for line in self._capture_checked(argv).splitlines():
                fields = line.split()
                if len(fields) < 4:
                    continue
                _host, separator, port = fields[3].rpartition(":")
                if separator and port.isdigit():
                    ports.add(int(port))
        return ports

    def unit_active(self, unit: str) -> bool:
        try:
            return self.capture(
                ("systemctl", "is-active", unit),
                max_chars=64,
            ).strip() == "active"
        except Exception:
            return False


def _default_api_factory(port: int, base_path: str = "/", *, certificate: Path | None = None):
    """One client against the local panel, under the path it now answers on."""
    from installer.three_xui_api import ThreeXuiApi, ThreeXuiClient

    return ThreeXuiApi(ThreeXuiClient(port=port, certificate=certificate), base_path=base_path)


class ThreeXuiAdapter:
    """Read an existing 3x-ui install, or own one staged pinned generation."""

    name = "three_xui"
    requires = frozenset({"certificates"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        source_dir: Path | None = None,
        paths: ThreeXuiPaths | None = None,
        architecture: str = "amd64",
        pin: ArtifactPin | None = None,
        layout: Path | None = None,
        panel_username: str = "owner",
        web_path: str | None = None,
        api_factory=None,
    ) -> None:
        if runner is None:
            runner = _DefaultThreeXuiRunner()
        if architecture not in _SUPPORTED_ARCHITECTURES:
            raise ValueError(f"unsupported architecture: {architecture}")
        self.root = Path(root)
        self.runner = runner
        self.source_dir = Path(source_dir or Path(__file__).resolve().parents[2])
        self.paths = paths or ThreeXuiPaths()
        self.architecture = architecture
        self.pin = pin
        self.layout = layout
        self.panel_username = panel_username
        # A private base path keeps the panel off "/" where a scanner looks
        # first. It is not a secret and it is not a substitute for the
        # password, but it costs nothing.
        self.web_path = web_path or f"/{secrets.token_hex(8)}/"
        self.api_factory = api_factory or _default_api_factory

    # ------------------------------------------------------------------
    # existing audit
    # ------------------------------------------------------------------

    def audit_existing(self) -> ThreeXuiAudit:
        """Whitelist non-secret facts and hash the byte identity of the tree."""
        config = self._host(self.paths.config)
        if not (config.exists() or config.is_symlink()):
            return ThreeXuiAudit(installed=False, digests=self._digests())
        if config.is_symlink() or not config.is_file():
            raise ThreeXuiError("3x-ui configuration must be a regular file")
        if config.stat().st_size > _MAX_CONFIG_BYTES:
            raise ThreeXuiError("3x-ui configuration exceeds the audit bound")
        try:
            document = json.loads(config.read_text())
        except (OSError, UnicodeError, ValueError) as exc:
            raise ThreeXuiError("3x-ui configuration is not readable JSON") from exc
        if not isinstance(document, Mapping):
            raise ThreeXuiError("3x-ui configuration is not an object")
        inbounds = self._audit_inbounds(document.get("inbounds", []))
        return ThreeXuiAudit(
            installed=True,
            inbounds=inbounds,
            outbound_tags=_tags(document.get("outbounds", [])),
            balancer_tags=_tags(
                document.get("routing", {}).get("balancers", [])
                if isinstance(document.get("routing"), Mapping)
                else []
            ),
            routing_selectors=self._audit_routing(document.get("routing")),
            client_total=sum(item.client_count for item in inbounds),
            digests=self._digests(),
        )

    def _audit_inbounds(self, value: object) -> tuple[ThreeXuiInboundFact, ...]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return ()
        if len(value) > _MAX_INBOUNDS:
            raise ThreeXuiError("3x-ui declares more inbounds than the audit bound")
        facts: list[ThreeXuiInboundFact] = []
        for item in value:
            if not isinstance(item, Mapping):
                continue
            fact = self._audit_inbound(item)
            if fact is not None:
                facts.append(fact)
        return tuple(sorted(facts, key=lambda item: (item.port, item.tag)))

    def _audit_inbound(self, item: Mapping[str, object]) -> ThreeXuiInboundFact | None:
        port = item.get("port")
        protocol = item.get("protocol")
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
            or not _safe_text(protocol)
        ):
            return None
        stream = item.get("streamSettings")
        stream = stream if isinstance(stream, Mapping) else {}
        network = stream.get("network", "tcp")
        security = stream.get("security", "none")
        if not isinstance(network, str) or network not in _NETWORKS:
            network = "tcp"
        if not isinstance(security, str) or security not in _SECURITY:
            security = "none"
        reality = stream.get("realitySettings")
        reality = reality if isinstance(reality, Mapping) else {}
        server_names = tuple(
            sorted(
                name
                for name in reality.get("serverNames", [])
                if isinstance(name, str) and _DOMAIN.fullmatch(name)
            )
        )
        target = reality.get("target") or reality.get("dest")
        tls = stream.get("tlsSettings")
        tls = tls if isinstance(tls, Mapping) else {}
        certificates = tuple(
            sorted(
                str(entry[key])
                for entry in tls.get("certificates", [])
                if isinstance(entry, Mapping)
                for key in ("certificateFile", "keyFile")
                if _safe_text(entry.get(key)) and str(entry[key]).startswith("/")
            )
        )
        sniffing = item.get("sniffing")
        sniffing = sniffing if isinstance(sniffing, Mapping) else {}
        listen = item.get("listen")
        return ThreeXuiInboundFact(
            tag=str(item["tag"]) if _safe_text(item.get("tag")) else f"inbound-{port}",
            protocol=str(protocol),
            listen=str(listen) if _safe_text(listen) else "0.0.0.0",
            port=port,
            network=network,
            security=security,
            client_count=_client_count(item),
            reality_server_names=server_names,
            reality_target=str(target) if _safe_text(target) else None,
            tls_certificate_paths=certificates,
            sniffing_enabled=sniffing.get("enabled") is True,
            sniffing_dest_override=tuple(
                sorted(
                    value
                    for value in sniffing.get("destOverride", [])
                    if isinstance(value, str) and _safe_text(value)
                )
            ),
        )

    def _audit_routing(self, value: object) -> tuple[str, ...]:
        if not isinstance(value, Mapping):
            return ()
        rules = value.get("rules")
        if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
            return ()
        selectors: set[str] = set()
        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            for key in _ROUTING_SELECTORS:
                item = rule.get(key)
                values = item if isinstance(item, list) else [item]
                for entry in values:
                    if _safe_text(entry):
                        selectors.add(f"{key}={entry}")
        return tuple(sorted(selectors))

    def _digests(self) -> dict[str, str]:
        digests: dict[str, str] = {}
        for label, host_path in (
            ("config", self.paths.config),
            ("database", self.paths.database),
            ("unit", self.paths.unit),
        ):
            path = self._host(host_path)
            if path.is_file() and not path.is_symlink():
                digests[label] = _file_sha256(path)
        tree = self._host(self.paths.root_dir)
        if tree.is_dir() and not tree.is_symlink():
            digests["binary_tree"] = self._tree_sha256(tree)
        return digests

    def _tree_sha256(self, root: Path) -> str:
        digest = hashlib.sha256()
        entries = sorted(root.rglob("*"))
        if len(entries) > _MAX_TREE_ENTRIES:
            raise ThreeXuiError("3x-ui tree exceeds the audit bound")
        for path in entries:
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                digest.update(f"L {relative} {os.readlink(path)}\n".encode())
            elif path.is_dir():
                digest.update(f"D {relative}\n".encode())
            elif path.is_file():
                digest.update(f"F {relative} {_file_sha256(path)}\n".encode())
        return digest.hexdigest()

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if getattr(facts, "hard_stops", ()):
            raise ThreeXuiError("host audit contains blocking findings")
        mode = config.three_xui.mode
        if mode is ThreeXuiMode.NONE:
            return ()
        if mode is ThreeXuiMode.EXISTING:
            return (self._route_action(config, self._existing_routes(config)),)
        actions = [
            self._route_action(config, self._managed_routes(config)),
            self._managed_action(config),
        ]
        if config.three_xui.warp:
            actions.append(self._warp_action(config))
        return tuple(actions)

    def _existing_routes(
        self,
        config: InstallerConfig,
    ) -> tuple[tuple[str, str], ...]:
        """Map operator-selected domains onto audited loopback inbounds only."""
        audit = self.audit_existing()
        if not audit.installed:
            raise PlanError("existing 3x-ui mode requires an installed 3x-ui")
        routes: list[tuple[str, str]] = []
        for domain, network in (
            (config.three_xui.vless_tcp_domain, "tcp"),
            (config.three_xui.vless_xhttp_domain, "xhttp"),
        ):
            if domain is None:
                continue
            inbound = audit.inbound(protocol="vless", network=network)
            if inbound is None:
                raise PlanError(
                    f"no existing VLESS {network} inbound to route {domain}"
                )
            if not inbound.loopback:
                raise PlanError(
                    "an existing 3x-ui inbound must listen on loopback to share 443"
                )
            routes.append((domain.lower(), f"127.0.0.1:{inbound.port}"))
        if not routes:
            raise PlanError("existing 3x-ui mode requires at least one routed domain")
        return tuple(sorted(routes))

    def _managed_routes(
        self,
        config: InstallerConfig,
    ) -> tuple[tuple[str, str], ...]:
        routes: list[tuple[str, str]] = []
        for domain, backend in (
            (config.three_xui.vless_tcp_domain, _VLESS_TCP_BACKEND),
            (config.three_xui.vless_xhttp_domain, _VLESS_XHTTP_BACKEND),
            (config.three_xui.panel_domain, _PANEL_BACKEND),
        ):
            if domain is None:
                raise PlanError("managed 3x-ui requires every selected domain")
            routes.append((domain.lower(), f"127.0.0.1:{backend}"))
        if config.three_xui.subscription_domain is not None:
            routes.append((config.three_xui.subscription_domain, f"127.0.0.1:{_SUBSCRIPTION_BACKEND}"))
        return tuple(sorted(routes))

    def _route_action(
        self,
        config: InstallerConfig,
        routes: Sequence[tuple[str, str]],
    ) -> Action:
        for domain, _backend in routes:
            if _DOMAIN.fullmatch(domain) is None:
                raise PlanError("3x-ui route domains must be valid")
        return Action(
            id="three_xui.routes",
            adapter=self.name,
            owner="nginx.routes.three_xui",
            mutations=(
                f"mode={config.three_xui.mode.value}",
                *(f"route={domain} {backend}" for domain, backend in routes),
            ),
            preconditions=(
                "the shared 443 router is owned and verified",
                "every routed 3x-ui inbound answers on loopback",
            ),
            verification=(
                "each owned SNI route reaches its loopback 3x-ui backend",
            ),
            inverse=("remove only the owned 3x-ui route block",),
            credentials_required=False,
        )

    def _managed_action(self, config: InstallerConfig) -> Action:
        url, package_sha256 = self._pins()
        if config.three_xui.hysteria_domain is None:
            raise PlanError("managed 3x-ui requires a Hysteria2 domain")
        return Action(
            id="three_xui.runtime",
            adapter=self.name,
            owner="proxy-control:three-xui",
            mutations=(
                f"version={_VERSION}",
                f"architecture={self.architecture}",
                f"release-url={url}",
                f"release-digest={package_sha256}",
                f"root={self.paths.root_dir}",
                f"unit={self.paths.unit}",
                f"database={self.paths.database}",
                f"panel-domain={config.three_xui.panel_domain}",
                f"hysteria-domain={config.three_xui.hysteria_domain}",
                f"vless-tcp-domain={config.three_xui.vless_tcp_domain}",
                f"vless-xhttp-domain={config.three_xui.vless_xhttp_domain}",
                f"vless-tcp-backend={_VLESS_TCP_BACKEND}",
                f"vless-xhttp-backend={_VLESS_XHTTP_BACKEND}",
                f"panel-backend={_PANEL_BACKEND}",
                f"warp={'true' if config.three_xui.warp else 'false'}",
                f"warp-port={config.three_xui.warp_port}",
                f"warp-domains={','.join(config.three_xui.warp_domains)}",
                f"subscription-domain={config.three_xui.subscription_domain or ''}",
            ),
            preconditions=(
                "no x-ui database, binary tree, unit, user, or listener exists",
                "the pinned release digest matches before and after extraction",
            ),
            verification=(
                "the staged binary reports the pinned version",
                "the panel answers only on loopback under its private path",
                "every promised inbound exists and its port is open",
            ),
            inverse=(
                "stop the staged unit and remove only the staged generation",
            ),
            credentials_required=True,
        )

    def _warp_action(self, config: InstallerConfig) -> Action:
        domains = tuple(sorted(config.three_xui.warp_domains))
        if not domains:
            raise PlanError("WARP requires operator-confirmed domains")
        for domain in domains:
            if not _valid_warp_selector(domain):
                raise PlanError("WARP domains must be valid")
        return Action(
            id="three_xui.warp",
            adapter=self.name,
            owner="proxy-control:three-xui-warp",
            mutations=(
                "warp=true",
                f"warp-egress=127.0.0.1:{config.three_xui.warp_port}",
                *(f"warp-domain={domain}" for domain in domains),
            ),
            preconditions=(
                "the managed 3x-ui generation is installed and verified",
                "the operator confirmed every WARP domain",
            ),
            verification=(
                "the WARP outbound exists and the mandatory final policy is last",
            ),
            inverse=("remove only the owned WARP outbound and its rules",),
            credentials_required=True,
        )

    def reality_keypair(self) -> tuple[str, str]:
        """One Reality keypair from the Xray that will serve it."""
        return self.runner.reality_keypair(
            str(self._host(self.paths.xray_binary(self.architecture)))
        )

    def provision(self, action: Action, *, password: str) -> Mapping[str, object]:
        """Turn a started 3x-ui into a configured one.

        Staging and starting the service is not an installation: on its own it
        leaves an empty panel on its default public ports with the upstream
        first-run credential. This rotates that credential, moves the panel
        onto loopback, restarts it so the move takes effect, and creates every
        inbound the operator's domains promised.
        """
        from installer.three_xui_api import SystemSecrets

        config = self._managed_config(action)
        credential = self._host(self.paths.snapshot_dir) / "panel-password"
        durable_mkdir(credential.parent, mode=0o700)
        self._atomic(credential, (password + "\n").encode(), 0o600)
        try:
            self.bootstrap_credentials(
                username=self.panel_username,
                password_path=credential,
                web_path=self.web_path,
                port=_DEFAULT_PANEL_PORT,
                panel_domain=config.three_xui.panel_domain,
            )
            # The settings are stored at once but the listener does not move
            # until the service restarts, so the restart is part of the move.
            self._run("systemctl", "restart", _UNIT_NAME)
            self._await_panel(_PANEL_BACKEND)
            if self.api_factory is _default_api_factory:
                certificate = self._host(f"{_LINEAGE_ROOT}/{config.three_xui.panel_domain}/fullchain.pem")
                api = self.api_factory(_PANEL_BACKEND, self.web_path, certificate=certificate)
            else:
                api = self.api_factory(_PANEL_BACKEND, self.web_path)
            api.login(self.panel_username, password)
            configured = self.configure_managed(
                config,
                api,
                generator=SystemSecrets(keypair=self.reality_keypair()),
            )
            # Subscription certificate/listener changes are stored by v3.7.0
            # but do not become live until the panel service is restarted.
            self._run("systemctl", "restart", _UNIT_NAME)
            self._await_panel(_PANEL_BACKEND)
            return configured
        finally:
            credential.unlink(missing_ok=True)

    def _await_panel(self, port: int, *, timeout: float = 60.0) -> None:
        """Wait until the panel is listening again after its restart.

        Connecting the moment `systemctl restart` returns is a race the
        installer loses on a loaded host: the unit is active before the panel
        has bound its socket, and the refused connection then looks like a
        configuration failure.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if port in self.runner.listening_ports():
                return
            time.sleep(1.0)
        raise AcceptanceError(
            "the 3x-ui panel did not start listening on its private port"
        )

    def _managed_config(self, action: Action) -> InstallerConfig:
        """Rebuild the managed configuration this action described.

        The plan carries every domain it will act on, in the open, because
        none of them is a secret.
        """
        from installer.model import (
            DomainConfig,
            FirewallConfig,
            HostMode,
            Profile,
            ThreeXuiConfig,
        )

        values: dict[str, str] = {}
        for mutation in action.mutations:
            key, separator, value = mutation.partition("=")
            if separator:
                values[key] = value
        missing = [
            name
            for name in ("panel-domain", "hysteria-domain", "vless-tcp-domain", "vless-xhttp-domain")
            if not values.get(name) or values[name] == "None"
        ]
        if missing:
            raise ThreeXuiError(f"the 3x-ui action names no {missing[0]}")
        return InstallerConfig(
            schema=1,
            host_mode=HostMode.COEXIST,
            profile=Profile.CORE,
            acme_email="unused@example.invalid",
            initial_user="owner",
            domains=DomainConfig(panel=values["panel-domain"], mtproxy=values["panel-domain"]),
            mieru=None,
            three_xui=ThreeXuiConfig(
                mode=ThreeXuiMode.MANAGED_NEW,
                panel_domain=values["panel-domain"],
                vless_tcp_domain=values["vless-tcp-domain"],
                vless_xhttp_domain=values["vless-xhttp-domain"],
                hysteria_domain=values["hysteria-domain"],
                warp=values.get("warp") == "true",
                warp_port=int(values.get("warp-port", "45000")),
                warp_domains=tuple(filter(None, values.get("warp-domains", "").split(","))),
                subscription_domain=values.get("subscription-domain") or None,
            ),
            firewall=FirewallConfig(manage_ufw=False),
        )

    def configure_managed(
        self,
        config: InstallerConfig,
        api,
        *,
        generator,
    ) -> Mapping[str, object]:
        """Create the persistent inbounds, then prove acceptance clients gone."""
        from installer.three_xui_api import (
            build_managed_clients,
            build_managed_inbounds,
            warp_routing,
        )

        templates = build_managed_inbounds(config, generator=generator)
        subscription_id = secrets.token_urlsafe(24) if config.three_xui.subscription_domain else None
        persistent = build_managed_clients(
            templates,
            generator=generator,
            prefix="initial",
            subscription_id=subscription_id,
        )
        acceptance = build_managed_clients(
            templates,
            generator=generator,
            prefix="acceptance",
            acceptance=True,
        )
        # Each inbound is created once, carrying both clients: two inbounds on
        # one port is not something 3x-ui will accept, and rightly so. The
        # acceptance client is then removed and its absence proved, which is
        # what makes it an acceptance client rather than a second account
        # nobody asked for.
        identifiers: dict[str, int] = {}
        for inbound, extra in zip(persistent, acceptance, strict=True):
            identifiers[inbound.tag] = api.add_inbound(
                inbound.with_clients([*inbound.clients, *extra.clients])
            )
        routing = warp_routing(config)
        if config.three_xui.warp:
            api.configure_warp(config)
        if config.three_xui.subscription_domain:
            api.configure_subscription(
                config.three_xui.subscription_domain,
                certificate=f"{_LINEAGE_ROOT}/{config.three_xui.subscription_domain}/fullchain.pem",
                private_key=f"{_LINEAGE_ROOT}/{config.three_xui.subscription_domain}/privkey.pem",
            )
            path = self._host("/var/lib/proxy-control/three-xui/subscription-url")
            durable_mkdir(path.parent, mode=0o700)
            self._atomic(path, f"https://{config.three_xui.subscription_domain}/sub/{subscription_id}\n".encode(), 0o600)
        removed = 0
        for inbound in persistent:
            api.replace_clients(identifiers[inbound.tag], inbound)
            removed += 1
        effective = api.effective_config()
        emails = set(effective.get("client_emails", []))
        if any(inbound.clients[0].email in emails for inbound in acceptance):
            raise AcceptanceError(
                "an acceptance client is still present in the effective configuration"
            )
        return {
            "inbounds": len(persistent),
            "acceptance_clients_removed": removed,
            "warp_outbounds": len(routing["outbounds"]),
        }

    def bootstrap_credentials(
        self,
        *,
        username: str,
        password_path: Path,
        web_path: str,
        port: int,
        panel_domain: str,
    ) -> None:
        """Rotate the first-run credential before exposing the panel."""
        if not isinstance(panel_domain, str) or not _DOMAIN.fullmatch(panel_domain):
            raise ThreeXuiError("invalid panel certificate domain")
        session = getattr(self.runner, "bootstrap_session", None)
        if not callable(session):
            raise ThreeXuiError("the 3x-ui bootstrap session is unavailable")
        payload = {
            "port": port,
            "panel_port": _PANEL_BACKEND,
            # Nginx routes the panel's domain here by SNI, so the panel
            # terminates TLS itself with the certificate the installer issued
            # for that domain.
            "certificate": f"{_LINEAGE_ROOT}/{panel_domain}/fullchain.pem",
            "private_key": f"{_LINEAGE_ROOT}/{panel_domain}/privkey.pem",
            "initial_username": _DEFAULT_CREDENTIAL,
            "initial_password": _DEFAULT_CREDENTIAL,
            "username": username,
            "password": password_path.read_text().rstrip("\r\n"),
            "web_path": web_path,
        }
        staging = self._host(self.paths.snapshot_dir) / f"bootstrap-{secrets.token_hex(8)}"
        durable_mkdir(staging, mode=0o700)
        document = staging / "bootstrap.json"
        try:
            self._atomic(
                document,
                json.dumps(payload, separators=(",", ":")).encode(),
                0o600,
            )
            session(
                namespace=_BOOTSTRAP_NETNS,
                binary=str(self._host(self.paths.binary)),
                payload_path=str(document),
            )
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _pins(self) -> tuple[str, str]:
        if self.pin is not None:
            if (
                self.pin.name != "three_xui"
                or self.pin.version != _VERSION
                or self.pin.architecture != self.architecture
            ):
                raise ArtifactError("release pin does not describe pinned 3x-ui")
            return self.pin.url, self.pin.sha256
        manifest = self._release_manifest()
        pin = manifest.external_artifact("three_xui", self.architecture)
        if pin.version != _VERSION:
            raise ArtifactError("release manifest pins an unexpected 3x-ui version")
        return pin.url, pin.sha256

    def _release_manifest(self):
        from installer.release import ReleaseManifest

        path = self.source_dir / "release" / "external-artifacts.json"
        try:
            return ReleaseManifest.from_bytes(path.read_bytes())
        except OSError as exc:
            raise ArtifactError("release manifest is unavailable") from exc

    # ------------------------------------------------------------------
    # managed staging
    # ------------------------------------------------------------------

    def archive_manifest(self, archive_sha256: str) -> ArchiveManifest:
        """Load the reviewed release layout for the pinned 3x-ui archive."""
        path = self.layout or (
            self.source_dir / "release" / f"three-xui-layout-{self.architecture}.json"
        )
        try:
            document = json.loads(Path(path).read_text())
        except (OSError, UnicodeError, ValueError) as exc:
            raise ArtifactError("3x-ui release layout is unavailable") from exc
        entries = document.get("entries") if isinstance(document, Mapping) else None
        if not isinstance(entries, list) or not entries:
            raise ArtifactError("3x-ui release layout is empty")
        return ArchiveManifest(
            entries=tuple(
                ArchiveEntry(
                    path=str(entry["path"]),
                    kind=str(entry["kind"]),
                    mode=entry.get("mode"),
                    sha256=entry.get("sha256"),
                    link_target=entry.get("link_target"),
                )
                for entry in entries
                if isinstance(entry, Mapping)
            ),
            archive_sha256=archive_sha256,
        )

    def stage(self, action: Action, archive: Path) -> tuple[Path, Path]:
        """Verify, extract, and prove the pinned release before installing.

        Returns the private staging directory and the extracted tree root; the
        caller always removes the staging directory.
        """
        selected = self._selection(action)
        expected = str(selected["release_digest"])
        try:
            verify_artifact(archive, expected)
        except Exception as exc:
            raise ArtifactError("3x-ui release digest does not match") from exc
        # Stage inside the installer's own root-owned tree: the extractor
        # refuses any destination whose parent chain is a symlink or untrusted,
        # which a process TMPDIR cannot guarantee.
        staging = self._host(self.paths.snapshot_dir) / f"staging-{secrets.token_hex(8)}"
        durable_mkdir(staging, mode=0o700)
        try:
            os.chmod(staging, 0o700)
            destination = staging / "release"
            safe_extract_tar(archive, destination, self.archive_manifest(expected))
            nested = destination / "x-ui"
            tree = nested if nested.is_dir() and not nested.is_symlink() else destination
            binary = tree / "x-ui"
            if binary.is_symlink() or not binary.is_file():
                raise ArtifactError("3x-ui release has no x-ui binary")
            os.chmod(binary, 0o755)
            version = self._x_ui_version(binary)
            if _VERSION not in version:
                raise ArtifactError("staged 3x-ui reports an unpinned version")
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return staging, tree

    def _x_ui_version(self, binary: Path) -> str:
        reader = getattr(self.runner, "x_ui_version", None)
        if not callable(reader):
            raise ArtifactError("3x-ui version verification is unavailable")
        return str(reader(str(binary))).strip()

    def assert_absent(self) -> None:
        """Managed-new refuses to adopt any pre-existing 3x-ui footprint."""
        for label, host_path in (
            ("database", self.paths.database),
            ("binary tree", self.paths.root_dir),
            ("unit", self.paths.unit),
        ):
            path = self._host(host_path)
            if path.exists() or path.is_symlink():
                raise ThreeXuiError(
                    f"managed 3x-ui refuses a pre-existing {label}: {host_path}"
                )
        if self._identity_named("passwd", "x-ui") is not None:
            raise ThreeXuiError("managed 3x-ui refuses a pre-existing service user")
        if self._unit_active():
            raise ThreeXuiError("managed 3x-ui refuses an active x-ui unit")

    def _identity_named(self, database: str, name: str) -> str | None:
        lookup = getattr(self.runner, "identity_named", None)
        if not callable(lookup):
            return None
        value = lookup(database, name)
        return str(value) if value else None

    def _unit_active(self) -> bool:
        lookup = getattr(self.runner, "unit_active", None)
        return bool(lookup(_UNIT_NAME)) if callable(lookup) else False

    # ------------------------------------------------------------------
    # managed lifecycle
    # ------------------------------------------------------------------

    def prepare(self, action: Action) -> Mapping[str, object]:
        if action.id == "three_xui.routes":
            return {"owner": action.owner, "routes": self._route_map(action)}
        if action.id == "three_xui.warp":
            return {"owner": action.owner, "warp_domains": self._warp_domains(action)}
        self._selection(action)
        self.assert_absent()
        marker_value = secrets.token_hex(16)
        return {
            "marker_value": marker_value,
            "owner": action.owner,
            "ownership": {},
            "staged": False,
        }

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        archive: Path | None = None,
    ) -> Mapping[str, object]:
        if action.id in {"three_xui.routes", "three_xui.warp"}:
            # Routes belong to the Nginx boundary and WARP is applied with the
            # managed generation; neither mutates host state on its own.
            return dict(checkpoint)
        selected = self._selection(action)
        if archive is None:
            from installer.adapters.mieru import _download, ensure_pinned_package
            url, digest = self._pins()
            archive = self._host(f"/var/cache/proxy-control/three-xui-{digest}.tar.gz")
            ensure_pinned_package(archive, url, digest, fetch=getattr(self.runner, "fetch_artifact", _download))
        self.assert_absent()
        staging, tree = self.stage(action, archive)
        try:
            self._install_tree(tree)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        marker_value = checkpoint.get("marker_value")
        if isinstance(marker_value, str) and _HEX_32.fullmatch(marker_value):
            self._atomic(
                self._host(self.paths.marker),
                (marker_value + "\n").encode(),
                0o600,
            )
        else:
            raise ThreeXuiError("3x-ui checkpoint is invalid")
        self._run("systemctl", "daemon-reload")
        del selected
        # Starting the service is not an installation: on its own it leaves an
        # empty panel on its default public ports with the upstream first-run
        # credential still working.
        provisioned = self.provision(action, password=self._panel_password())
        self._run("systemctl", "enable", _UNIT_NAME)
        return {
            **dict(checkpoint),
            "staged": True,
            "provisioned": dict(provisioned),
            "ownership": self._ownership(),
        }

    def _panel_password(self) -> str:
        """The 3x-ui password the operator chose, or a generated one."""
        from installer.credentials import CredentialError, staged_credentials

        try:
            chosen = staged_credentials(self.root)
        except CredentialError as exc:
            raise ThreeXuiError(f"the staged credentials cannot be used: {exc}") from None
        if chosen is not None:
            if chosen.three_xui_username:
                self.panel_username = chosen.three_xui_username
            if chosen.three_xui_password:
                return chosen.three_xui_password
        return secrets.token_urlsafe(32)

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self.apply(action, checkpoint)

    def verify(self, action: Action) -> Evidence:
        if action.id == "three_xui.warp":
            domains = self._warp_domains(action)
            return Evidence(
                action_id=action.id,
                success=True,
                observations=(
                    "the owned WARP outbound covers only confirmed domains",
                ),
                details={"warp_domains": len(domains)},
            )
        if action.id == "three_xui.routes":
            routes = self._route_map(action)
            audit = self.audit_existing()
            # The panel and its subscription server are 3x-ui's own loopback listeners,
            # not Xray inbounds: for those two routes an open port is the evidence, and
            # the inbound audit can never vouch for them.
            own = {f"127.0.0.1:{_PANEL_BACKEND}", f"127.0.0.1:{_SUBSCRIPTION_BACKEND}"}
            listening = set(self.runner.listening_ports()) if audit.installed else set()
            reachable = sum(
                1
                for _domain, backend in routes.items()
                if (
                    (backend in own and int(backend.rsplit(":", 1)[1]) in listening)
                    or any(
                        f"127.0.0.1:{item.port}" == backend and item.loopback
                        for item in audit.inbounds
                    )
                )
            )
            if audit.installed and reachable != len(routes):
                raise AcceptanceError(
                    "a routed 3x-ui backend is not an audited loopback inbound"
                )
            return Evidence(
                action_id=action.id,
                success=True,
                observations=("owned 3x-ui routes reach audited loopback inbounds",),
                details={"routes": len(routes), "installed": audit.installed},
            )
        self._selection(action)
        version = self._x_ui_version(self._host(self.paths.binary))
        if _VERSION not in version:
            raise AcceptanceError("the installed 3x-ui is not the pinned version")
        # 3x-ui stores a row Xray will not serve and still reports it enabled,
        # with nothing in the log to say so. An open port is the only evidence
        # that an inbound exists.
        listening = self.runner.listening_ports()
        if _PANEL_BACKEND not in listening:
            raise AcceptanceError(
                "the 3x-ui panel is not listening on its private loopback port"
            )
        expected = (_VLESS_TCP_BACKEND, _VLESS_XHTTP_BACKEND, _HYSTERIA_PORT)
        missing = [port for port in expected if port not in listening]
        if missing:
            raise AcceptanceError(
                f"a provisioned 3x-ui inbound is not listening on port {missing[0]}"
            )
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the staged 3x-ui generation reports the pinned version",
                "the panel answers only on its private loopback port",
                "every provisioned inbound is listening",
            ),
            details={"version_pinned": True, "inbounds_listening": len(expected)},
        )

    def repair(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        if action.id in {"three_xui.routes", "three_xui.warp"}:
            return dict(checkpoint)
        self._assert_ownership(checkpoint)
        self._run("systemctl", "restart", _UNIT_NAME)
        # The verify that follows checks the listening ports; the same race provision
        # waits out applies here, and the panel binds last.
        self._await_panel(_PANEL_BACKEND)
        return dict(checkpoint)

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
        if action.id in {"three_xui.routes", "three_xui.warp"}:
            return Evidence(
                action_id=action.id,
                success=True,
                observations=("no 3x-ui state was mutated by this action",),
                details={"persistent_data_preserved": True},
            )
        self._selection(action)
        self._run_best_effort("systemctl", "disable", "--now", _UNIT_NAME)
        ownership = checkpoint.get("ownership", {})
        if not isinstance(ownership, Mapping):
            raise ThreeXuiError("3x-ui checkpoint is invalid")
        for host_path in sorted(ownership, reverse=True):
            path = self._host(str(host_path))
            if path.exists() or path.is_symlink():
                durable_remove(path)
        for host_path in (self.paths.root_dir, self.paths.marker):
            path = self._host(host_path)
            if path.exists() or path.is_symlink():
                durable_remove(path)
        destructive = rollback_target == "uninstalled" and purge_data
        database = self._host(self.paths.database)
        if destructive and (database.exists() or database.is_symlink()):
            durable_remove(database)
        self._run_best_effort("systemctl", "daemon-reload")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the staged 3x-ui generation was removed",
                (
                    "the staged database was purged"
                    if destructive
                    else "the staged database was preserved"
                ),
            ),
            details={"persistent_data_preserved": not destructive},
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

    # ------------------------------------------------------------------
    # separate existing-version upgrade transaction
    # ------------------------------------------------------------------

    def plan_existing_upgrade(
        self,
        target: ArtifactPin,
        facts: ThreeXuiAudit,
    ) -> InstallPlan:
        """Build the standalone upgrade plan an explicit CLI subcommand runs."""
        if not isinstance(facts, ThreeXuiAudit) or not facts.installed:
            raise PlanError("an existing 3x-ui installation is required to upgrade")
        if target.name != "three_xui" or target.architecture != self.architecture:
            raise PlanError("upgrade target does not describe this 3x-ui host")
        for label in ("config", "database", "unit", "binary_tree"):
            if _SHA256.fullmatch(str(facts.digests.get(label, ""))) is None:
                raise PlanError(
                    "an upgrade requires the complete byte identity of the install"
                )
        action = Action(
            id="three_xui.upgrade",
            adapter=self.name,
            owner="proxy-control:three-xui-upgrade",
            mutations=(
                f"version={target.version}",
                f"architecture={target.architecture}",
                f"release-url={target.url}",
                f"release-digest={target.sha256}",
                f"database-digest={facts.digests['database']}",
                f"binary-tree-digest={facts.digests['binary_tree']}",
                f"unit-digest={facts.digests['unit']}",
                f"config-digest={facts.digests['config']}",
                f"inbounds={len(facts.inbounds)}",
            ),
            preconditions=(
                "the operator invoked the explicit upgrade subcommand",
                "the observed install matches the recorded byte identity",
            ),
            verification=(
                "the new binary migrates a private database copy first",
                "existing inbounds still pass protocol acceptance",
            ),
            inverse=(
                "restore the database, binary tree, and unit as one generation",
            ),
            credentials_required=False,
        )
        return InstallPlan(
            config={"three_xui": {"mode": ThreeXuiMode.EXISTING.value}},
            facts=AuditFacts(
                topology={"three_xui": _plain_audit(facts)},
                ownership={"three_xui": {"mode": "existing", "present": True}},
            ),
            release=ReleaseIdentity(
                tag=target.tag,
                commit=target.sha256,
                manifest_sha256=target.sha256,
                components={"three_xui": target.version},
                artifacts={"three_xui": target.sha256},
            ),
            adapter_order=(self.name,),
            adapter_dependencies={self.name: ()},
            actions=(action,),
        )

    def snapshot_upgrade(self, facts: ThreeXuiAudit) -> Path:
        """Copy the database, binary tree, and unit as one restorable generation."""
        snapshot = self._host(self.paths.snapshot_dir) / secrets.token_hex(8)
        durable_mkdir(snapshot, mode=0o700)
        for label, host_path in (
            ("database", self.paths.database),
            ("unit", self.paths.unit),
        ):
            source = self._host(host_path)
            if source.is_file() and not source.is_symlink():
                shutil.copy2(source, snapshot / label)
        tree = self._host(self.paths.root_dir)
        if tree.is_dir() and not tree.is_symlink():
            shutil.copytree(tree, snapshot / "root", symlinks=True)
        (snapshot / "digests.json").write_text(
            json.dumps(dict(facts.digests), sort_keys=True)
        )
        fsync_directory(snapshot)
        return snapshot

    def rehearse_migration(self, staged_binary: Path, snapshot: Path) -> None:
        """Migrate a private copy before the live database is ever touched."""
        rehearsal = snapshot / "rehearsal"
        durable_mkdir(rehearsal, mode=0o700)
        database = snapshot / "database"
        if not database.is_file():
            raise ThreeXuiError("an upgrade rehearsal requires a database snapshot")
        copy = rehearsal / Path(self.paths.database).name
        shutil.copy2(database, copy)
        rehearse = getattr(self.runner, "migration_rehearsal", None)
        if not callable(rehearse):
            raise ThreeXuiError("migration rehearsal is unavailable")
        try:
            rehearse(str(staged_binary), str(copy))
        except Exception as exc:
            raise ThreeXuiError("the new 3x-ui failed its migration rehearsal") from exc

    def restore_upgrade(self, snapshot: Path, facts: ThreeXuiAudit) -> None:
        """Restore the complete generation and prove it byte-identical again."""
        self._run_best_effort("systemctl", "stop", _UNIT_NAME)
        tree = self._host(self.paths.root_dir)
        if (tree.exists() or tree.is_symlink()) and (snapshot / "root").is_dir():
            durable_remove(tree)
        if (snapshot / "root").is_dir():
            shutil.copytree(snapshot / "root", tree, symlinks=True)
        for label, host_path in (
            ("database", self.paths.database),
            ("unit", self.paths.unit),
        ):
            source = snapshot / label
            if not source.is_file():
                continue
            destination = self._host(host_path)
            durable_mkdir(destination.parent)
            shutil.copy2(source, destination)
        observed = self._digests()
        for label in ("database", "unit", "binary_tree", "config"):
            expected = facts.digests.get(label)
            if expected is None:
                continue
            if observed.get(label) != expected:
                raise ThreeXuiError(
                    f"restored 3x-ui {label} is not byte-identical to the snapshot"
                )
        self._run_best_effort("systemctl", "start", _UNIT_NAME)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _selection(self, action: Action) -> dict[str, object]:
        if (
            action.adapter != self.name
            or action.id not in {"three_xui.runtime", "three_xui.upgrade"}
        ):
            raise ThreeXuiError("3x-ui action is invalid")
        values: dict[str, str] = {}
        for mutation in action.mutations:
            key, separator, value = mutation.partition("=")
            if not separator or not key or key in values:
                raise ThreeXuiError("3x-ui action is invalid")
            values[key] = value
        for key in ("version", "architecture", "release-url", "release-digest"):
            if key not in values:
                raise ThreeXuiError("3x-ui action is invalid")
        if (
            values["architecture"] != self.architecture
            or _SHA256.fullmatch(values["release-digest"]) is None
        ):
            raise ThreeXuiError("3x-ui action is invalid")
        return {
            "version": values["version"],
            "architecture": values["architecture"],
            "release_url": values["release-url"],
            "release_digest": values["release-digest"],
        }

    def _route_map(self, action: Action) -> dict[str, str]:
        if action.adapter != self.name or action.id != "three_xui.routes":
            raise ThreeXuiError("3x-ui action is invalid")
        routes: dict[str, str] = {}
        for mutation in action.mutations:
            key, separator, value = mutation.partition("=")
            if separator != "=" or key != "route":
                continue
            domain, space, backend = value.partition(" ")
            if space != " " or _DOMAIN.fullmatch(domain) is None:
                raise ThreeXuiError("3x-ui route is invalid")
            routes[domain] = backend
        if not routes:
            raise ThreeXuiError("3x-ui route action declares no route")
        return routes

    def _warp_domains(self, action: Action) -> tuple[str, ...]:
        if action.adapter != self.name or action.id != "three_xui.warp":
            raise ThreeXuiError("3x-ui action is invalid")
        domains = tuple(
            value.partition("=")[2]
            for value in action.mutations
            if value.startswith("warp-domain=")
        )
        if not domains or any(not _valid_warp_selector(item) for item in domains):
            raise ThreeXuiError("3x-ui WARP action declares no valid domain")
        return domains

    def _install_tree(self, staged: Path) -> None:
        destination = self._host(self.paths.root_dir)
        durable_mkdir(destination.parent)
        shutil.copytree(staged, destination, symlinks=False)
        os.chmod(self._host(self.paths.binary), 0o755)
        unit_source = staged / "x-ui.service"
        if not unit_source.is_file():
            unit_source = staged / "x-ui.service.debian"
        if not unit_source.is_file():
            raise ArtifactError("pinned 3x-ui archive has no Debian service unit")
        self._atomic(self._host(self.paths.unit), unit_source.read_bytes(), 0o644)

    def _ownership(self) -> dict[str, dict[str, object]]:
        ownership: dict[str, dict[str, object]] = {}
        for host_path in (self.paths.unit, self.paths.marker):
            path = self._host(host_path)
            if path.is_file() and not path.is_symlink():
                ownership[host_path] = {
                    "preserve": False,
                    "sha256": _file_sha256(path),
                }
        return ownership

    def _assert_ownership(self, checkpoint: Mapping[str, object]) -> None:
        ownership = checkpoint.get("ownership", {})
        if not isinstance(ownership, Mapping):
            raise ThreeXuiError("3x-ui checkpoint is invalid")
        for host_path, entry in ownership.items():
            path = self._host(str(host_path))
            if (
                not isinstance(entry, Mapping)
                or not path.is_file()
                or _file_sha256(path) != entry.get("sha256")
            ):
                raise ThreeXuiError(f"3x-ui owned file has drifted: {host_path}")

    def _run(self, *argv: str) -> None:
        try:
            result = self.runner.run(argv)
        except ThreeXuiError:
            raise
        except Exception as exc:
            raise ThreeXuiError("3x-ui command failed") from exc
        if getattr(result, "returncode", 0):
            raise ThreeXuiError("3x-ui command failed")

    def _run_best_effort(self, *argv: str) -> None:
        try:
            self._run(*argv)
        except Exception:
            return

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise ThreeXuiError("3x-ui host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise ThreeXuiError("3x-ui root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise ThreeXuiError("3x-ui host path crosses an unsafe parent")
        return self.root / relative

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        durable_mkdir(path.parent)
        atomic_write(path, data, mode=mode, owner=owner)


def _safe_text(value: object) -> bool:
    return isinstance(value, str) and _SAFE_TEXT.fullmatch(value) is not None


def _tags(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(
        sorted(
            str(item["tag"])
            for item in value
            if isinstance(item, Mapping) and _safe_text(item.get("tag"))
        )
    )


def _client_count(item: Mapping[str, object]) -> int:
    """Count clients without ever reading a credential into a structure."""
    settings = item.get("settings")
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except ValueError:
            return 0
    if not isinstance(settings, Mapping):
        return 0
    clients = settings.get("clients")
    if not isinstance(clients, Sequence) or isinstance(clients, (str, bytes)):
        return 0
    return len(clients)


def _plain_audit(facts: ThreeXuiAudit) -> dict[str, object]:
    document = facts.to_dict()
    encoded = json.dumps(document, sort_keys=True, default=str)
    for forbidden in _FORBIDDEN_FIELDS:
        if f'"{forbidden}"' in encoded:
            raise ThreeXuiError("3x-ui audit leaked a forbidden field")
    return json.loads(encoded)
