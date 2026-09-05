from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from installer.adapters.core import (
    _DOMAIN,
    _DefaultCoreRunner,
    _file_sha256,
    _path_sha256,
)
from installer.adapters.naive import _identity_from_entry
from installer.model import InstallerConfig
from installer.planner import Action, AuditFacts, Evidence, PlanError
from installer.release import ArtifactPin, verify_artifact
from installer.transaction import (
    atomic_write,
    durable_mkdir,
    durable_remove,
    fsync_directory,
)

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_PROJECT = "/opt/mtproxy-shared443"
_MITA_BINARY = "/usr/bin/mita"
_MITA_LICENSE = "/usr/share/doc/mita/copyright"
_MITA_LICENSE_NOTICE = (
    b"Upstream-Name: mieru / mita\n"
    b"Source: https://github.com/enfein/mieru\n"
    b"License: GPL-3.0-or-later\n"
    b"\n"
    b"The mita executable installed next to this notice is unmodified upstream\n"
    b"software distributed under the GNU General Public License version 3 or\n"
    b"later. Its complete source and licence text are published at the address\n"
    b"above. Proxy Control installs only the executable and this notice; the\n"
    b"package itself is never installed.\n"
)
_MITA_STATE = "/var/lib/mita"
_MITA_CONFIG = "/var/lib/mita/server_config.json"
# Files a service rewrites after the installer creates them.
_MUTABLE_PATHS = frozenset({_MITA_CONFIG})
_MITA_BOOTSTRAP = "/var/lib/mita/bootstrap-input.json"
_MITA_UNIT = "/etc/systemd/system/mita.service"
_MITA_TMPFILES = "/etc/tmpfiles.d/mita.conf"
_MITA_SOCKET = "/run/mita/mita.sock"
_MANAGER_TOKEN = "/etc/mieru-manager/token"
_MANAGER_STATE = "/var/lib/mieru-manager"
_STATE_PREPARER = "/usr/local/libexec/prepare-mieru-state"
_TOKEN_PREPARER = "/usr/local/libexec/prepare-mieru-token"
_MARKER = "/etc/proxy-control/mieru-owned"
_ACCEPTANCE_OWNER = "/etc/proxy-control/mieru-acceptance-owner"
_ACCEPTANCE_PENDING = "/etc/proxy-control/mieru-acceptance-pending"

_MITA_UNIT_NAME = "mita"
_MITA_BOOTSTRAP_UNIT = "mita-bootstrap"
_MITA_USER = "mita"
_MITA_GROUP = "mita"
_MANAGER_UID = 10005
_MANAGER_GID = 10005
_WARP_EGRESS = ("127.0.0.1", 45000)
_WARP_PROXY_NAME = "warp"
_RUNNING = 'mita server status is "RUNNING"'
_MITA_VERSION = "3.36.0"
_SUPPORTED_ARCHITECTURES = ("amd64", "arm64")

# Pinned upstream mita 3.36.0 packages and the executable each one must carry.
# mita stays an external GPLv3+ artifact: only the binary and its license text
# are installed, never the package itself.
_MITA_PINS: Mapping[str, tuple[str, str, str]] = MappingProxyType(
    {
        "amd64": (
            "https://github.com/enfein/mieru/releases/download/v3.36.0/"
            "mita_3.36.0_amd64.deb",
            "44622bea7fac732984ac6cf1189e555fd9add1969001e9b2d7cdea9416b5919a",
            "38835a88e9b7fb09de0a3b6b5110e3a98719bffd9471aa07ddb7e03dc678a170",
        ),
        "arm64": (
            "https://github.com/enfein/mieru/releases/download/v3.36.0/"
            "mita_3.36.0_arm64.deb",
            "a43dbc4d75dcb18978ea79b924ce859e2485af8b776dfc981b29a7b60644157c",
            "5105cf47ae85cfa885922fe8384f53f1977ea230259eb066130b7232ce0847b0",
        ),
    }
)

_ACCEPTANCE_PREFIX = "proxy-control-mieru-"
_ACCEPTANCE_NAME = re.compile(r"proxy-control-mieru-[0-9a-f]{16}\Z")
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")

_HELPERS: tuple[tuple[str, str, int], ...] = (
    ("scripts/prepare-mieru-state.sh", _STATE_PREPARER, 0o755),
    ("scripts/prepare_mieru_token.py", _TOKEN_PREPARER, 0o755),
    ("deploy/mita.service", _MITA_UNIT, 0o644),
    ("deploy/mita.tmpfiles.conf", _MITA_TMPFILES, 0o644),
)

def _command_failure(argv: Sequence[str]) -> str:
    """Name the failing program and subcommand without echoing any argument."""
    program = Path(str(argv[0])).name if argv else "command"
    subcommand = ""
    for value in list(argv)[1:3]:
        rendered = str(value)
        if rendered.startswith("-") or "/" in rendered:
            break
        subcommand += f" {rendered}"
    return f"Mieru command failed: {program}{subcommand}"


class MieruError(RuntimeError):
    """The Mieru ownership boundary cannot be changed safely."""


class ArtifactError(MieruError):
    """A pinned mita artifact failed closed verification."""


class AcceptanceError(MieruError):
    """Mieru failed an end-to-end acceptance requirement."""


class _AcceptanceCollision(AcceptanceError):
    """A temporary acceptance username exists without installer ownership."""


class _DefaultMieruRunner(_DefaultCoreRunner):
    """Real host commands and acceptance probes for the Mieru boundary."""

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

    def service_identity(self, name: str) -> tuple[int, int] | None:
        """Return the numeric (uid, gid) of one service account, if it exists."""
        try:
            output = self.capture(("getent", "passwd", name), max_chars=512)
        except Exception:
            return None
        for line in output.strip().splitlines():
            fields = line.split(":")
            if len(fields) < 4 or fields[0] != name:
                continue
            if fields[2].isdigit() and fields[3].isdigit():
                return int(fields[2]), int(fields[3])
        return None

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

    def dpkg_extract(self, package: str, destination: str) -> None:
        self._run_checked(
            ("dpkg-deb", "-x", package, destination),
            "package extraction",
        )

    def mita_version(self, binary: str) -> str:
        return self._capture_checked((binary, "version")).strip()

    def mita_status(self) -> str:
        return self._capture_checked(
            (
                "env",
                f"MITA_UDS_PATH={_MITA_SOCKET}",
                _MITA_BINARY,
                "status",
            )
        ).strip()

    def socket_group(self, path: str) -> int:
        return os.stat(path).st_gid

    def mieru_acceptance(
        self,
        *,
        panel_domain: str,
        public_host: str,
        transports: Sequence[tuple[str, int]],
        bootstrap_credential_file: str,
        acceptance_name: str,
        adjacent_listeners: Sequence[int],
        recover_existing: bool,
    ) -> Mapping[str, object]:
        status = self.mita_status()
        verified = 0
        send_q_empty = True
        password = Path(bootstrap_credential_file).read_text().rstrip("\r\n")
        opener, csrf = self._login(panel_domain, "owner", password)
        created = False
        try:
            listed = self._json_request(opener, panel_domain, "/api/mieru/users")
            manager_ready = (
                isinstance(listed, Mapping)
                and isinstance(listed.get("service"), Mapping)
                and listed["service"].get("ready") is True
            )
            rows = listed.get("items", []) if isinstance(listed, Mapping) else []
            collision = any(
                isinstance(row, Mapping)
                and row.get("username") == acceptance_name
                for row in rows
            )
            if collision and not recover_existing:
                raise _AcceptanceCollision(
                    "Mieru acceptance failed: temporary-user collision"
                )
            revision = self._service_revision(listed)
            if collision:
                # Every mutation is a compare-and-set, so a delete carries the
                # revision the manager last reported and re-reads the new one.
                self._delete_acceptance_user(
                    opener, panel_domain, acceptance_name, csrf, revision
                )
                listed = self._json_request(
                    opener, panel_domain, "/api/mieru/users"
                )
                revision = self._service_revision(listed)
            # The managed create is a compare-and-set against the revision the
            # manager just reported.
            created_value = self._json_request(
                opener,
                panel_domain,
                "/api/mieru/users",
                method="POST",
                payload={
                    "username": acceptance_name,
                    "quotas": [],
                    "expected_revision": revision,
                },
                csrf=csrf,
            )
            created = True
            revision = self._revision_value(
                created_value.get("revision")
                if isinstance(created_value, Mapping)
                else None
            )
            reveal = (
                created_value.get("reveal_token")
                if isinstance(created_value, Mapping)
                else None
            )
            if not isinstance(reveal, str) or not reveal:
                raise AcceptanceError("Mieru acceptance failed: access")
            revealed = self._json_request(
                opener,
                panel_domain,
                f"/api/reveal/{reveal}",
            )
            native = self._native_client_config(revealed)
            for protocol, port in transports:
                if self._client_probe(native, protocol, port):
                    verified += 1
                if not self._send_queue_empty(port):
                    send_q_empty = False
            panel_ok = True
        finally:
            failure: BaseException | None = None
            if created:
                try:
                    self._delete_acceptance_user(
                        opener, panel_domain, acceptance_name, csrf, revision
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
        return {
            "package_digest_ok": True,
            "executable_digest_ok": True,
            "mita_status_running": status == _RUNNING,
            "uds_boundary_ok": self._uds_boundary_ok(),
            "manager_health_ok": manager_ready,
            "panel_health_ok": panel_ok,
            "transports_verified": verified,
            "transports_expected": len(transports),
            "send_queue_drained": send_q_empty,
            "adjacent_listeners_ok": self._adjacent_listeners_ok(adjacent_listeners),
            "public_host_ok": bool(_DOMAIN.fullmatch(public_host)),
        }

    def cleanup_mieru_acceptance(
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
            listed = self._json_request(opener, panel_domain, "/api/mieru/users")
            rows = listed.get("items", []) if isinstance(listed, Mapping) else []
            if any(
                isinstance(row, Mapping)
                and row.get("username") == acceptance_name
                for row in rows
            ):
                self._json_request(
                    opener,
                    panel_domain,
                    f"/api/mieru/users/{acceptance_name}",
                    method="DELETE",
                    csrf=csrf,
                    expect_json=False,
                )
        finally:
            self._logout(opener, panel_domain, csrf)

    def _service_revision(self, listed: object) -> str:
        service = listed.get("service") if isinstance(listed, Mapping) else None
        return self._revision_value(
            service.get("revision") if isinstance(service, Mapping) else None
        )

    @staticmethod
    def _revision_value(value: object) -> str:
        if not isinstance(value, str) or not value:
            raise AcceptanceError("Mieru acceptance failed: manager health")
        return value

    def _delete_acceptance_user(
        self,
        opener,
        panel_domain: str,
        acceptance_name: str,
        csrf: str,
        revision: str,
    ) -> None:
        """Remove the temporary user with the compare-and-set the panel requires."""
        self._json_request(
            opener,
            panel_domain,
            f"/api/mieru/users/{acceptance_name}",
            method="DELETE",
            payload={"expected_revision": revision},
            csrf=csrf,
            expect_json=False,
        )

    @staticmethod
    def _native_client_config(revealed: object) -> Mapping[str, object]:
        """Extract the full official-client Native configuration once."""
        clients = revealed.get("clients") if isinstance(revealed, Mapping) else None
        native = clients.get("native") if isinstance(clients, Mapping) else None
        config = native.get("config") if isinstance(native, Mapping) else None
        if not isinstance(config, Mapping) or "profiles" not in config:
            raise AcceptanceError("Mieru acceptance failed: access")
        return config

    def _client_probe(
        self,
        native: Mapping[str, object],
        protocol: str,
        port: int,
    ) -> bool:
        """Run the pinned official client and require one HTTP 204 over SOCKS."""
        document = json.dumps(
            _client_config_for(native, protocol, port),
            separators=(",", ":"),
        )
        descriptor, name = tempfile.mkstemp(prefix="proxy-control-mieru-client-")
        configuration = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(document)
                handle.flush()
                os.fsync(handle.fileno())
            self._run_checked(
                (
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "host",
                    "--volume",
                    f"{configuration}:/etc/mieru/client.json:ro",
                    f"proxy-control-mieru-client:{_MITA_VERSION}",
                ),
                "client probe",
            )
        except Exception:
            return False
        finally:
            configuration.unlink(missing_ok=True)
        return True

    def _send_queue_empty(self, port: int) -> bool:
        try:
            output = self.capture(
                ("ss", "-H", "-tin", f"sport = :{port}"),
                max_chars=8192,
            )
        except Exception:
            return False
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0].isdigit() and fields[1].isdigit():
                if int(fields[1]):
                    return False
        return True

    def _uds_boundary_ok(self) -> bool:
        try:
            metadata = os.stat(_MITA_SOCKET)
        except OSError:
            return False
        return stat.S_ISSOCK(metadata.st_mode) and (
            stat.S_IMODE(metadata.st_mode) == 0o770
        )

    def _adjacent_listeners_ok(self, expected: Sequence[int]) -> bool:
        if not expected:
            return True
        try:
            output = self.capture(("ss", "-H", "-lntup"), max_chars=65536)
        except Exception:
            return False
        observed = {
            int(match.group(1))
            for match in re.finditer(r"[:.](\d{1,5})\s", output)
            if match.group(1).isdigit()
        }
        return set(expected) <= observed


@dataclass(frozen=True)
class MieruPaths:
    """Fixed host paths owned by one Mieru generation."""

    project_dir: str = _PROJECT
    binary: str = _MITA_BINARY
    license: str = _MITA_LICENSE
    state_dir: str = _MITA_STATE
    config: str = _MITA_CONFIG
    bootstrap_input: str = _MITA_BOOTSTRAP
    unit: str = _MITA_UNIT
    tmpfiles: str = _MITA_TMPFILES
    socket: str = _MITA_SOCKET
    manager_token: str = _MANAGER_TOKEN
    manager_state: str = _MANAGER_STATE
    state_preparer: str = _STATE_PREPARER
    token_preparer: str = _TOKEN_PREPARER
    marker: str = _MARKER
    acceptance_owner: str = _ACCEPTANCE_OWNER
    acceptance_pending: str = _ACCEPTANCE_PENDING

    def __post_init__(self) -> None:
        for value in (
            self.project_dir,
            self.binary,
            self.license,
            self.state_dir,
            self.config,
            self.bootstrap_input,
            self.unit,
            self.tmpfiles,
            self.socket,
            self.manager_token,
            self.manager_state,
            self.state_preparer,
            self.token_preparer,
            self.marker,
            self.acceptance_owner,
            self.acceptance_pending,
        ):
            if not value.startswith("/") or ".." in Path(value).parts:
                raise ValueError("Mieru path must be a normalized absolute path")

    @property
    def env_overlay(self) -> str:
        return f"{self.project_dir}/.env.mieru"

    @property
    def compose_overlay(self) -> str:
        return f"{self.project_dir}/compose.mieru.yaml"


@dataclass(frozen=True)
class StagedMita:
    """A verified mita executable and its license, outside their final home."""

    binary: Path
    license: Path
    version: str
    package_sha256: str
    executable_sha256: str


@dataclass(frozen=True)
class MieruAcceptance:
    """Sanitized acceptance facts; values are only booleans and counts."""

    package_digest_ok: bool
    executable_digest_ok: bool
    mita_status_running: bool
    uds_boundary_ok: bool
    manager_health_ok: bool
    panel_health_ok: bool
    transports_verified: int
    transports_expected: int
    send_queue_drained: bool
    adjacent_listeners_ok: bool
    public_host_ok: bool
    temporary_state_removed: bool = True

    def __post_init__(self) -> None:
        boolean_fields = (
            "package_digest_ok",
            "executable_digest_ok",
            "mita_status_running",
            "uds_boundary_ok",
            "manager_health_ok",
            "panel_health_ok",
            "send_queue_drained",
            "adjacent_listeners_ok",
            "public_host_ok",
            "temporary_state_removed",
        )
        if any(not isinstance(getattr(self, name), bool) for name in boolean_fields):
            raise TypeError("acceptance flags must be booleans")
        counts = (self.transports_verified, self.transports_expected)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts
        ):
            raise ValueError("acceptance counts must be non-negative integers")
        if self.transports_expected == 0 or (
            self.transports_verified > self.transports_expected
        ):
            raise ValueError("acceptance counts are inconsistent")

    def details(self) -> dict[str, bool | int]:
        return asdict(self)


class MieruAdapter:
    """Own the pinned mita runtime, manager boundary, and Mieru listeners."""

    name = "mieru"
    requires = frozenset({"core"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        source_dir: Path | None = None,
        paths: MieruPaths | None = None,
        architecture: str = "amd64",
        pin: ArtifactPin | None = None,
    ) -> None:
        if runner is None:
            runner = _DefaultMieruRunner()
        if architecture not in _SUPPORTED_ARCHITECTURES:
            raise ValueError(f"unsupported architecture: {architecture}")
        self.root = Path(root)
        self.runner = runner
        self.source_dir = Path(source_dir or Path(__file__).resolve().parents[2])
        self.paths = paths or MieruPaths()
        self.architecture = architecture
        self.pin = pin

    # ------------------------------------------------------------------
    # pins
    # ------------------------------------------------------------------

    def _pins(self) -> tuple[str, str, str]:
        """Return the release url, package digest, and executable digest."""
        if self.pin is not None:
            if (
                self.pin.name != "mita"
                or self.pin.version != _MITA_VERSION
                or self.pin.architecture != self.architecture
                or self.pin.executable_path != "usr/bin/mita"
                or self.pin.executable_sha256 is None
            ):
                raise ArtifactError("release pin does not describe pinned mita")
            return self.pin.url, self.pin.sha256, self.pin.executable_sha256
        return _MITA_PINS[self.architecture]

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if getattr(facts, "hard_stops", ()):
            raise MieruError("host audit contains blocking findings")
        if not config.profile.includes_mieru:
            return ()
        if not config.initial_user or _SAFE_NAME.fullmatch(config.initial_user) is None:
            raise PlanError("a valid bootstrap user is required")
        domain = config.domains.mieru
        if domain is None or _DOMAIN.fullmatch(domain) is None:
            raise PlanError("Mieru public host is missing or invalid")
        transports = self._planned_transports(config)
        self._assert_planned_identities(facts)
        self._assert_free_listeners(facts, transports)
        url, package_sha256, executable_sha256 = self._pins()
        egress = "proxy" if config.three_xui.warp else "direct"
        return (
            Action(
                id="mieru.runtime",
                adapter=self.name,
                owner="proxy-control:mieru",
                mutations=(
                    f"project={self.paths.project_dir}",
                    f"mieru-host={domain.lower()}",
                    f"panel-domain={config.domains.panel.lower()}",
                    f"mita-version={_MITA_VERSION}",
                    f"architecture={self.architecture}",
                    f"package-url={url}",
                    f"package-digest={package_sha256}",
                    f"executable-digest={executable_sha256}",
                    f"binary={self.paths.binary}",
                    f"unit={self.paths.unit}",
                    f"socket={self.paths.socket}",
                    f"manager-uid={_MANAGER_UID}",
                    f"manager-gid={_MANAGER_GID}",
                    f"bootstrap-user={config.initial_user}",
                    "transports=" + _encode_transports(transports),
                    f"egress={egress}",
                ),
                preconditions=(
                    "the Core runtime is verified",
                    "the selected Mieru listeners are free",
                    "fixed manager identity 10005 is free or already owned",
                ),
                verification=(
                    "package and executable digests match the pinned release",
                    'mita reports the exact status "RUNNING"',
                    "the management UDS keeps its owner and 0770 mode",
                    "the official client reaches the Internet over every transport",
                    "manager and panel health pass and adjacent listeners are intact",
                ),
                inverse=(
                    "stop only the mita unit and the mieru-manager service",
                    "preserve manager state, token, and mita config unless purge",
                    "remove only the owned binary, unit, tmpfiles, and helpers",
                ),
                credentials_required=True,
            ),
        )

    def _planned_transports(
        self,
        config: InstallerConfig,
    ) -> tuple[tuple[str, int], ...]:
        if config.mieru is None:
            raise PlanError("Mieru listener selection is missing")
        transports = tuple(
            [("TCP", port) for port in config.mieru.tcp_ports]
            + [("UDP", port) for port in config.mieru.udp_ports]
        )
        if not transports:
            raise PlanError("at least one Mieru listener is required")
        for protocol, port in transports:
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise PlanError("Mieru listener ports must be valid")
            if port == 443:
                raise PlanError("Mieru must not claim the shared 443 listener")
            del protocol
        if len(set(transports)) != len(transports):
            raise PlanError("Mieru listeners must be unique")
        return tuple(sorted(transports))

    def _assert_planned_identities(self, facts: AuditFacts) -> None:
        ownership = facts.ownership if isinstance(facts.ownership, Mapping) else {}
        identities = ownership.get("identities")
        if identities is None:
            return
        if not isinstance(identities, Mapping):
            raise PlanError("audited identity facts are invalid")
        for kind, identifier in (("uid", _MANAGER_UID), ("gid", _MANAGER_GID)):
            group = identities.get(kind)
            if not isinstance(group, Mapping):
                continue
            name = group.get(str(identifier))
            if name in (None, "", "mieru-manager"):
                continue
            if not isinstance(name, str):
                raise PlanError("audited identity facts are invalid")
            raise PlanError(f"{kind.upper()} {identifier} collision: {name}")

    def _assert_free_listeners(
        self,
        facts: AuditFacts,
        transports: Sequence[tuple[str, int]],
    ) -> None:
        listeners = facts.listeners if isinstance(facts.listeners, Mapping) else {}
        for protocol, port in transports:
            observed = listeners.get(protocol.lower())
            if not isinstance(observed, Sequence) or isinstance(observed, (str, bytes)):
                continue
            if port in {int(value) for value in observed if isinstance(value, int)}:
                raise PlanError(
                    f"{protocol} port {port} is already claimed by another listener"
                )

    # ------------------------------------------------------------------
    # artifact staging
    # ------------------------------------------------------------------

    def stage(self, action: Action) -> StagedMita:
        """Verify the package, extract it privately, and verify the binary."""
        selected = self._selection(action)
        package = Path(str(selected["package"]))
        expected_package = str(selected["package_digest"])
        expected_executable = str(selected["executable_digest"])
        try:
            verify_artifact(package, expected_package)
        except Exception as exc:
            raise ArtifactError("mita package digest does not match") from exc
        staging = Path(tempfile.mkdtemp(prefix="proxy-control-mita-"))
        try:
            os.chmod(staging, 0o700)
            extract = getattr(self.runner, "dpkg_extract", None)
            if not callable(extract):
                raise ArtifactError("package extraction is unavailable")
            extract(str(package), str(staging))
            binary = staging / "usr/bin/mita"
            if binary.is_symlink() or not binary.is_file():
                raise ArtifactError("mita executable is missing from the package")
            if _file_sha256(binary) != expected_executable:
                raise ArtifactError("mita executable digest does not match")
            os.chmod(binary, 0o755)
            version = self._mita_version(binary)
            if version.split()[-1] != _MITA_VERSION:
                raise ArtifactError("mita executable reports an unpinned version")
            license_path = staging / "usr/share/doc/mita/copyright"
            if license_path.is_symlink():
                raise ArtifactError("mita license material is unsafe")
            if not license_path.is_file():
                # Upstream publishes mita without a Debian copyright file, so
                # the installer records the attribution itself: the binary is
                # external GPL-3.0-or-later code and must stay attributed on
                # the host next to the executable it belongs to.
                license_path.parent.mkdir(parents=True, exist_ok=True)
                license_path.write_bytes(_MITA_LICENSE_NOTICE)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return StagedMita(
            binary=binary,
            license=license_path,
            version=version,
            package_sha256=expected_package,
            executable_sha256=expected_executable,
        )

    def _mita_version(self, binary: Path) -> str:
        reader = getattr(self.runner, "mita_version", None)
        if not callable(reader):
            raise ArtifactError("mita version verification is unavailable")
        return str(reader(str(binary))).strip()

    # ------------------------------------------------------------------
    # rendering
    # ------------------------------------------------------------------

    def bootstrap_config(
        self,
        selected: Mapping[str, object],
        *,
        password: str,
    ) -> dict[str, object]:
        """One valid generation: bindings, one bootstrap user, and egress."""
        transports = selected["transports"]
        if not isinstance(transports, tuple) or not transports:
            raise MieruError("Mieru action is invalid")
        proxy_action = "PROXY" if selected["egress"] == "proxy" else "DIRECT"
        return {
            "portBindings": [
                {"port": port, "protocol": protocol}
                for protocol, port in transports
            ],
            "users": [
                {
                    "name": str(selected["bootstrap_user"]),
                    "password": password,
                }
            ],
            "loggingLevel": "INFO",
            "egress": {
                "proxies": [
                    {
                        "name": _WARP_PROXY_NAME,
                        "protocol": "SOCKS5_PROXY_PROTOCOL",
                        "host": _WARP_EGRESS[0],
                        "port": _WARP_EGRESS[1],
                    }
                ],
                "rules": [
                    {
                        "ipRanges": ["0.0.0.0/0", "::/0"],
                        "domainNames": [],
                        "action": proxy_action,
                        "proxyNames": (
                            [_WARP_PROXY_NAME] if proxy_action == "PROXY" else []
                        ),
                    }
                ],
            },
        }

    def env_text(self, selected: Mapping[str, object], *, mita_gid: int) -> str:
        return (
            f"MIERU_PUBLIC_HOST={selected['mieru_host']}\n"
            f"MIERU_MITA_BIN={self.paths.binary}\n"
            f"MIERU_MITA_SHA256={selected['executable_digest']}\n"
            f"MIERU_MITA_GID={mita_gid}\n"
            f"MIERU_MANAGER_STATE_DIR={self.paths.manager_state}\n"
            f"MIERU_MANAGER_TOKEN_FILE={self.paths.manager_token}\n"
        )

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def prepare(self, action: Action) -> Mapping[str, object]:
        self._selection(action)
        self._assert_live_identities()
        marker = self._host(self.paths.marker)
        adoption = "recovery" if self._marker_present(marker) else "absent"
        if adoption == "absent" and self._service_present():
            raise MieruError(
                "active Mieru resources require a proven owned recovery generation"
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
        binary = self._host(self.paths.binary)
        return {
            "acceptance_name": acceptance_name,
            "adoption": adoption,
            "binary_preexisting": binary.exists() or binary.is_symlink(),
            "identities_created": {},
            "marker_value": marker_value,
            "owner": action.owner,
            "ownership": {},
            "planned_ownership": self._planned_ownership(
                action,
                acceptance_name=acceptance_name,
                marker_sha256=marker_sha256,
            ),
            "state_preexisting": self._host(self.paths.manager_state).is_dir(),
            "token_preexisting": self._host(self.paths.manager_token).is_file(),
        }

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action)
        # 1. Verified artifact first: nothing else may run an unpinned binary.
        staged = self.stage(action)
        try:
            self._install_binary(staged, prepared)
        finally:
            shutil.rmtree(staged.binary.parents[2], ignore_errors=True)
        # 2. Service identity and the stable socket boundary.
        identities = self._ensure_identities()
        self._install_helpers()
        self._run("systemd-tmpfiles", "--create", self.paths.tmpfiles)
        self._prepare_mita_state()
        self._run("systemctl", "daemon-reload")
        # 3. One valid generation applied through the local UDS.
        self._bootstrap_generation(selected, prepared)
        # 4. Long-running service and the proven RUNNING status.
        self._run("systemctl", "enable", "--now", _MITA_UNIT_NAME)
        self._assert_running()
        # 5. Manager identity, token, state, and the Compose overlay.
        mita_gid = self._socket_group()
        self._prepare_manager(selected, mita_gid)
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
        result: MieruAcceptance | None = None
        cleanup_ok = False
        failure: Exception | None = None
        try:
            probe = getattr(self.runner, "mieru_acceptance", None)
            if not callable(probe):
                raise AcceptanceError("Mieru acceptance is unavailable")
            raw = probe(
                panel_domain=str(selected["panel_domain"]),
                public_host=str(selected["mieru_host"]),
                transports=selected["transports"],
                bootstrap_credential_file=(
                    f"{self.paths.project_dir}/secrets/panel-bootstrap-password"
                ),
                acceptance_name=acceptance_name,
                adjacent_listeners=(),
                recover_existing=recover_existing,
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
            raise AcceptanceError("Mieru acceptance execution failed") from failure
        if result is None or not cleanup_ok:
            raise AcceptanceError("temporary-user and session cleanup failed")
        result = MieruAcceptance(
            **{**result.details(), "temporary_state_removed": True}
        )
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "pinned mita, UDS boundary, and official-client acceptance passed",
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
        self._run(self.paths.token_preparer, "verify", self.paths.manager_token)
        self._run(self.paths.state_preparer, "verify", self.paths.manager_state)
        self._run("systemctl", "restart", _MITA_UNIT_NAME)
        self._assert_running()
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
            self._run_best_effort("systemctl", "disable", "--now", _MITA_UNIT_NAME)
        if self._compose_service_present():
            self._compose("rm", "--stop", "--force", "mieru-manager")
        self._remove_generation(
            prepared,
            preserve_credentials=not destructive_purge,
            preserve_acceptance=cleanup_pending,
        )
        self._remove_owned_binary(prepared)
        self._run_best_effort("systemctl", "daemon-reload")
        if destructive_purge:
            self._purge_state()
            self._remove_identities(prepared)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the Mieru runtime was removed",
                (
                    "manager state, token, and mita config were purged"
                    if destructive_purge
                    else "manager state, token, and mita config were preserved"
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
            raise MieruError("Mieru generation ownership has drifted")
        actual = _file_sha256(marker)
        if expected is not None and actual != expected:
            raise MieruError("Mieru generation ownership has drifted")
        return actual

    # ------------------------------------------------------------------
    # action and checkpoint validation
    # ------------------------------------------------------------------

    def _selection(self, action: Action) -> dict[str, object]:
        if (
            action.adapter != self.name
            or action.id != "mieru.runtime"
            or action.owner != "proxy-control:mieru"
        ):
            raise MieruError("Mieru action is invalid")
        values: dict[str, str] = {}
        for mutation in action.mutations:
            key, separator, value = mutation.partition("=")
            if not separator or not key or key in values:
                raise MieruError("Mieru action is invalid")
            values[key] = value
        required = {
            "project",
            "mieru-host",
            "panel-domain",
            "mita-version",
            "architecture",
            "package-url",
            "package-digest",
            "executable-digest",
            "binary",
            "unit",
            "socket",
            "manager-uid",
            "manager-gid",
            "bootstrap-user",
            "transports",
            "egress",
        }
        optional = {"package"}
        if not required <= set(values) or set(values) - required - optional:
            raise MieruError("Mieru action is invalid")
        if (
            values["project"] != self.paths.project_dir
            or values["binary"] != self.paths.binary
            or values["unit"] != self.paths.unit
            or values["socket"] != self.paths.socket
            or values["mita-version"] != _MITA_VERSION
            or values["architecture"] not in _SUPPORTED_ARCHITECTURES
            or values["manager-uid"] != str(_MANAGER_UID)
            or values["manager-gid"] != str(_MANAGER_GID)
            or values["egress"] not in {"proxy", "direct"}
            or _SHA256.fullmatch(values["package-digest"]) is None
            or _SHA256.fullmatch(values["executable-digest"]) is None
            or _SAFE_NAME.fullmatch(values["bootstrap-user"]) is None
            or _DOMAIN.fullmatch(values["mieru-host"]) is None
            or _DOMAIN.fullmatch(values["panel-domain"]) is None
        ):
            raise MieruError("Mieru action is invalid")
        package = values.get("package", self._default_package(values["architecture"]))
        if not package.startswith("/") or ".." in Path(package).parts:
            raise MieruError("Mieru action is invalid")
        return {
            "mieru_host": values["mieru-host"].lower(),
            "panel_domain": values["panel-domain"].lower(),
            "architecture": values["architecture"],
            "package": package,
            "package_digest": values["package-digest"],
            "executable_digest": values["executable-digest"],
            "bootstrap_user": values["bootstrap-user"],
            "transports": _decode_transports(values["transports"]),
            "egress": values["egress"],
        }

    def _default_package(self, architecture: str) -> str:
        return f"/var/lib/proxy-control/mita_{_MITA_VERSION}_{architecture}.deb"

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
            "binary_preexisting",
            "identities_created",
            "marker_value",
            "owner",
            "ownership",
            "planned_ownership",
            "state_preexisting",
            "token_preexisting",
        }
        if set(checkpoint) != required:
            raise MieruError("Mieru checkpoint is invalid")
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
                    or _HEX_32.fullmatch(marker_value) is None
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
                    "binary_preexisting",
                    "state_preexisting",
                    "token_preexisting",
                )
            )
        ):
            raise MieruError("Mieru checkpoint is invalid")
        _validate_ownership_mapping(planned)
        if applied:
            _validate_ownership_mapping(ownership)
        return {name: checkpoint[name] for name in required}

    # ------------------------------------------------------------------
    # ownership
    # ------------------------------------------------------------------

    def _owned_paths(self) -> tuple[tuple[str, bool], ...]:
        return (
            (self.paths.marker, True),
            (self.paths.unit, False),
            (self.paths.tmpfiles, False),
            (self.paths.state_preparer, False),
            (self.paths.token_preparer, False),
            (self.paths.license, False),
            (self.paths.env_overlay, False),
            (self.paths.acceptance_owner, False),
            (self.paths.manager_token, True),
            (self.paths.config, True),
        )

    def _planned_ownership(
        self,
        action: Action,
        *,
        acceptance_name: str,
        marker_sha256: str,
    ) -> dict[str, dict[str, object]]:
        planned: dict[str, dict[str, object]] = {
            self.paths.marker: {"preserve": True, "sha256": marker_sha256},
            self.paths.acceptance_owner: {
                "preserve": False,
                "sha256": hashlib.sha256(
                    (acceptance_name + "\n").encode()
                ).hexdigest(),
            },
        }
        for relative, host_path, _mode in _HELPERS:
            source = self.source_dir / relative
            if not source.is_file():
                raise MieruError("installer source generation is incomplete")
            planned[host_path] = {
                "preserve": False,
                "sha256": _path_sha256(source),
            }
        del action
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
                    # mita rewrites its own server config whenever a user
                    # changes, so its digest is never foreign drift.
                    "mutable": host_path in _MUTABLE_PATHS,
                    "sha256": _path_sha256(path),
                }
        binary = self._host(self.paths.binary)
        if binary.exists() or binary.is_symlink():
            ownership[self.paths.binary] = {
                "preserve": bool(checkpoint["binary_preexisting"]),
                "sha256": _path_sha256(binary),
            }
        if not ownership:
            raise MieruError("Mieru generation has no owned files")
        return ownership

    def _assert_checkpoint_ownership(self, checkpoint: Mapping[str, object]) -> None:
        ownership = checkpoint["ownership"]
        if not isinstance(ownership, Mapping):
            raise MieruError("Mieru checkpoint is invalid")
        for host_path, entry in ownership.items():
            if not isinstance(host_path, str) or not isinstance(entry, Mapping):
                raise MieruError("Mieru checkpoint is invalid")
            path = self._host(host_path)
            if (
                not (path.exists() or path.is_symlink())
                or _path_sha256(path) != entry["sha256"]
            ):
                raise MieruError(f"Mieru owned file has drifted: {host_path}")

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
            raise MieruError("Mieru checkpoint is invalid")
        using_planned = not ownership
        entries = planned if using_planned else ownership
        allowed = {host_path for host_path, _preserve in self._owned_paths()}
        allowed.add(self.paths.binary)
        directories: set[Path] = set()
        for host_path, entry in sorted(entries.items(), reverse=True):
            if host_path == self.paths.binary:
                continue
            if not isinstance(entry, Mapping) or host_path not in allowed:
                raise MieruError("Mieru checkpoint ownership escapes the boundary")
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
                raise MieruError(f"Mieru owned file has drifted: {host_path}")
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

    def _remove_owned_binary(self, checkpoint: Mapping[str, object]) -> None:
        if checkpoint.get("binary_preexisting") is True:
            return
        binary = self._host(self.paths.binary)
        if not (binary.exists() or binary.is_symlink()):
            return
        ownership = checkpoint.get("ownership", {})
        expected = (
            ownership.get(self.paths.binary, {}).get("sha256")
            if isinstance(ownership, Mapping)
            else None
        )
        if expected is not None and _path_sha256(binary) != expected:
            raise MieruError("Mieru owned mita binary has drifted")
        durable_remove(binary)

    def _purge_state(self) -> None:
        for host_path in (
            self.paths.manager_token,
            self.paths.config,
            self.paths.bootstrap_input,
        ):
            path = self._host(host_path)
            if path.exists() or path.is_symlink():
                durable_remove(path)
        state = self._host(self.paths.manager_state)
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
            self._run_best_effort("userdel", _MITA_USER)
        if created.get("group") is True:
            self._run_best_effort("groupdel", _MITA_GROUP)

    # ------------------------------------------------------------------
    # apply helpers
    # ------------------------------------------------------------------

    def _install_binary(
        self,
        staged: StagedMita,
        checkpoint: Mapping[str, object],
    ) -> None:
        binary = self._host(self.paths.binary)
        if checkpoint["binary_preexisting"] is True:
            if _file_sha256(binary) != staged.executable_sha256:
                raise ArtifactError(
                    "a pre-existing mita binary does not match the pinned digest"
                )
            return
        self._atomic(binary, staged.binary.read_bytes(), 0o755)
        self._atomic(
            self._host(self.paths.license),
            staged.license.read_bytes(),
            0o644,
        )

    def _ensure_identities(self) -> dict[str, bool]:
        created = {"group": False, "user": False}
        if self._identity_named("group", _MITA_GROUP) is None:
            self._run("groupadd", "--system", _MITA_GROUP)
            created["group"] = True
        if self._identity_named("passwd", _MITA_USER) is None:
            self._run(
                "useradd",
                "--system",
                "--gid",
                _MITA_GROUP,
                "--home",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                _MITA_USER,
            )
            created["user"] = True
        return created

    def _identity_named(self, database: str, name: str) -> str | None:
        lookup = getattr(self.runner, "identity_named", None)
        if callable(lookup):
            value = lookup(database, name)
            return str(value) if value else None
        return None

    def _assert_live_identities(self) -> None:
        for kind, identifier in (("uid", _MANAGER_UID), ("gid", _MANAGER_GID)):
            name = self._identity_owner(kind, identifier)
            if name is not None and name not in {"mieru-manager", _MITA_USER}:
                raise MieruError(f"{kind.upper()} {identifier} collision: {name}")

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
                raise MieruError("installer source generation is incomplete")
            destination = self._host(host_path)
            durable_mkdir(destination.parent)
            self._atomic(destination, source.read_bytes(), mode)

    def _bootstrap_generation(
        self,
        selected: Mapping[str, object],
        checkpoint: Mapping[str, object],
    ) -> None:
        """Apply one valid generation through a transient local mita run."""
        marker_value = checkpoint["marker_value"]
        if isinstance(marker_value, str):
            self._atomic(
                self._host(self.paths.marker),
                (marker_value + "\n").encode(),
                0o600,
            )
        self._write_acceptance_owner(str(checkpoint["acceptance_name"]))
        config = self._host(self.paths.config)
        if config.exists() or config.is_symlink():
            # A restored generation is authoritative: never rewrite live users.
            return
        bootstrap = self._host(self.paths.bootstrap_input)
        document = self.bootstrap_config(
            selected,
            password=secrets.token_urlsafe(24),
        )
        self._atomic(
            bootstrap,
            json.dumps(document, separators=(",", ":")).encode() + b"\n",
            0o600,
        )
        # mita reads its own bootstrap input as the service user.
        if self.root == Path("/") and os.geteuid() == 0:
            os.chown(bootstrap, *self._mita_identity())
        # A transient unit left in the failed state by an interrupted attempt
        # makes systemd-run refuse the name, so resume would never start.
        self._run_best_effort(
            "systemctl", "reset-failed", f"{_MITA_BOOTSTRAP_UNIT}.service"
        )
        try:
            self._run(
                "systemd-run",
                f"--unit={_MITA_BOOTSTRAP_UNIT}",
                f"--property=User={_MITA_USER}",
                f"--property=Group={_MITA_GROUP}",
                f"--setenv=MITA_CONFIG_JSON_FILE={self.paths.config}",
                f"--setenv=MITA_UDS_PATH={self.paths.socket}",
                self.paths.binary,
                "run",
            )
            for argument in ("apply", "start", "stop"):
                if argument == "apply":
                    self._mita("apply", "config", self.paths.bootstrap_input)
                else:
                    self._mita(argument)
        finally:
            self._run_best_effort(
                "systemctl",
                "stop",
                f"{_MITA_BOOTSTRAP_UNIT}.service",
            )
            self._run_best_effort(
                "systemctl",
                "reset-failed",
                f"{_MITA_BOOTSTRAP_UNIT}.service",
            )
            durable_remove(bootstrap, missing_ok=True)

    def _mita(self, *arguments: str) -> None:
        self._run(
            "sudo",
            "-u",
            _MITA_USER,
            "env",
            f"MITA_UDS_PATH={self.paths.socket}",
            self.paths.binary,
            *arguments,
        )

    def _assert_running(self) -> None:
        status = getattr(self.runner, "mita_status", None)
        if not callable(status):
            raise MieruError("mita status verification is unavailable")
        if str(status()).strip() != _RUNNING:
            raise MieruError("mita did not reach the exact RUNNING status")

    def _mita_identity(self) -> tuple[int, int]:
        lookup = getattr(self.runner, "service_identity", None)
        identity = lookup(_MITA_USER) if callable(lookup) else None
        if (
            not isinstance(identity, tuple)
            or len(identity) != 2
            or not all(isinstance(value, int) and value > 0 for value in identity)
        ):
            raise MieruError("mita service identity is unavailable")
        return identity

    def _prepare_mita_state(self) -> None:
        """Own the state directory the upstream package postinst would create.

        Only the executable is installed, never the package, so nothing else
        creates this directory and mita cannot write its own server config.
        """
        state = self._host(self.paths.state_dir)
        if state.is_symlink() or (state.exists() and not state.is_dir()):
            raise MieruError("mita state path is occupied")
        durable_mkdir(state, mode=0o700)
        os.chmod(state, 0o700)
        if self.root == Path("/") and os.geteuid() == 0:
            os.chown(state, *self._mita_identity())

    def _socket_group(self) -> int:
        lookup = getattr(self.runner, "socket_group", None)
        if not callable(lookup):
            raise MieruError("management socket group is unavailable")
        value = lookup(self.paths.socket)
        if not isinstance(value, int) or value <= 0:
            raise MieruError("management socket group is unavailable")
        return value

    def _prepare_manager(
        self,
        selected: Mapping[str, object],
        mita_gid: int,
    ) -> None:
        token = self._host(self.paths.manager_token)
        if not (token.exists() or token.is_symlink()):
            self._atomic(token, (secrets.token_hex(32) + "\n").encode(), 0o600)
        self._run(self.paths.token_preparer, "prepare", self.paths.manager_token)
        self._run(self.paths.state_preparer, "prepare", self.paths.manager_state)
        self._atomic(
            self._host(self.paths.env_overlay),
            self.env_text(selected, mita_gid=mita_gid).encode(),
            0o600,
        )

    # ------------------------------------------------------------------
    # acceptance ownership
    # ------------------------------------------------------------------

    def _existing_acceptance_name(self) -> str | None:
        owner = self._host(self.paths.acceptance_owner)
        pending = self._host(self.paths.acceptance_pending)
        if not (owner.exists() or owner.is_symlink()):
            if pending.exists() or pending.is_symlink():
                raise MieruError("temporary-user ownership has drifted")
            return None
        if (
            owner.is_symlink()
            or not owner.is_file()
            or stat.S_IMODE(owner.stat().st_mode) != 0o600
        ):
            raise MieruError("temporary-user ownership has drifted")
        value = owner.read_text().strip()
        if _ACCEPTANCE_NAME.fullmatch(value) is None:
            raise MieruError("temporary-user ownership has drifted")
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
            raise MieruError("temporary-user ownership has drifted")
        self._atomic(
            self._host(self.paths.acceptance_owner),
            (acceptance_name + "\n").encode(),
            0o600,
        )

    def _read_acceptance_owner(self) -> str:
        value = self._existing_acceptance_name()
        if value is None:
            raise MieruError("temporary-user ownership has drifted")
        return value

    def _cleanup_acceptance(
        self,
        selected: Mapping[str, object],
        acceptance_name: str,
    ) -> None:
        cleanup = getattr(self.runner, "cleanup_mieru_acceptance", None)
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

    def _marker_present(self, marker: Path) -> bool:
        if not (marker.exists() or marker.is_symlink()):
            return False
        self.marker_sha256()
        return True

    def _unit_present(self) -> bool:
        unit = self._host(self.paths.unit)
        return unit.exists() or unit.is_symlink()

    def _compose_service_present(self) -> bool:
        """Only the Mieru manager counts; Core owns the shared project."""
        method = getattr(self.runner, "compose_service_present", None)
        if callable(method):
            return bool(method("mieru-manager"))
        method = getattr(self.runner, "compose_project_present", None)
        return bool(method(self.paths.project_dir)) if callable(method) else False

    def _service_present(self) -> bool:
        return self._unit_present() or self._compose_service_present()

    def _compose(self, *args: str) -> None:
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
        except MieruError:
            raise
        except Exception as exc:
            raise MieruError(_command_failure(argv)) from exc
        if getattr(result, "returncode", 0):
            raise MieruError(_command_failure(argv))

    def _run_best_effort(self, *argv: str) -> None:
        try:
            self._run(*argv)
        except Exception:
            return

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise MieruError("Mieru host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise MieruError("Mieru root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise MieruError("Mieru host path crosses an unsafe parent")
        return self.root / relative

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        durable_mkdir(path.parent)
        atomic_write(path, data, mode=mode, owner=owner)


def _client_config_for(
    native: Mapping[str, object],
    protocol: str,
    port: int,
) -> dict[str, object]:
    """Keep only the transport under test so one probe proves one path."""
    document = json.loads(json.dumps(native))
    for profile in document.get("profiles", []):
        for server in profile.get("servers", []):
            server["portBindings"] = [
                binding
                for binding in server.get("portBindings", [])
                if binding.get("protocol") == protocol
                and binding.get("port") == port
            ]
    return document


def _encode_transports(transports: Sequence[tuple[str, int]]) -> str:
    return ";".join(f"{protocol}:{port}" for protocol, port in transports)


def _decode_transports(value: str) -> tuple[tuple[str, int], ...]:
    transports: list[tuple[str, int]] = []
    for encoded in value.split(";"):
        protocol, separator, port = encoded.partition(":")
        if separator != ":" or protocol not in {"TCP", "UDP"} or not port.isdigit():
            raise MieruError("Mieru action has invalid transports")
        number = int(port)
        if not 1 <= number <= 65535 or number == 443:
            raise MieruError("Mieru action has invalid transports")
        transports.append((protocol, number))
    if not transports or len(set(transports)) != len(transports):
        raise MieruError("Mieru action has invalid transports")
    return tuple(sorted(transports))


def _acceptance_value(value: object) -> MieruAcceptance:
    if isinstance(value, MieruAcceptance):
        return value
    if isinstance(value, Mapping):
        allowed = set(MieruAcceptance.__dataclass_fields__)
        if not set(value) <= allowed:
            raise AcceptanceError("Mieru acceptance result is invalid")
        try:
            return MieruAcceptance(**dict(value))
        except (TypeError, ValueError) as exc:
            raise AcceptanceError("Mieru acceptance result is invalid") from exc
    raise AcceptanceError("Mieru acceptance result is invalid")


def _require_acceptance(result: MieruAcceptance) -> None:
    if not result.package_digest_ok or not result.executable_digest_ok:
        raise AcceptanceError("Mieru acceptance failed: pinned artifact digests")
    if not result.mita_status_running:
        raise AcceptanceError("Mieru acceptance failed: exact RUNNING status")
    if not result.uds_boundary_ok:
        raise AcceptanceError("Mieru acceptance failed: management UDS boundary")
    if result.transports_verified != result.transports_expected:
        raise AcceptanceError("Mieru acceptance failed: official client probe")
    if not result.send_queue_drained:
        raise AcceptanceError("Mieru acceptance failed: send queue")
    if not result.manager_health_ok or not result.panel_health_ok:
        raise AcceptanceError("Mieru acceptance failed: manager and panel health")
    if not result.adjacent_listeners_ok:
        raise AcceptanceError("Mieru acceptance failed: adjacent listeners")
    if not result.public_host_ok:
        raise AcceptanceError("Mieru acceptance failed: public host")


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
            raise MieruError("Mieru ownership record is invalid")
