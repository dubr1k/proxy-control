"""Installer-owned Xray egress-router (v0.5, ADR 007).

The operator stages the pinned `Xray-linux-64.zip` in `/var/lib/proxy-control/`; the
installer proves its digest, extracts exactly the three reviewed members into the host
directory the container reads, creates the manager identity 10006, its state directory,
the manager token and the two per-service ingress credentials, writes `.env.xray-router`
with the members' digests and starts the `xray-router` Compose service. Nothing is
downloaded: an absent archive is a refusal with the pinned URL in it.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from installer.adapters.core import _DefaultCoreRunner, _file_sha256
from installer.model import ROUTER_PORTS, InstallerConfig
from installer.planner import Action, AuditFacts, Evidence, PlanError
from installer.release import ArtifactPin, MemberPin, ReleaseError, safe_extract_zip, verify_artifact
from installer.transaction import atomic_write, durable_mkdir, durable_remove, fsync_directory

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_PROJECT = "/opt/mtproxy-shared443"
_BIN_DIR = "/usr/local/lib/proxy-control/xray-router"
_STATE_DIR = "/var/lib/xray-router"
_ARTIFACT_DIR = "/var/lib/proxy-control"
_STATE_PREPARER = "/usr/local/libexec/prepare-xray-router-state"
_ROTATOR = "/usr/local/libexec/rotate-xray-router-ingress"
_MARKER = "/etc/proxy-control/xray-router-owned"
_ROUTER_USER = "xray-router"
_ROUTER_GROUP = "xray-router"
_ROUTER_UID = 10006
_ROUTER_GID = 10006
_SERVICE = "xray-router"
_CONTAINER = "proxy-control-xray-router"
_XRAY_VERSION = "26.3.27"
_ARCHIVE = "Xray-linux-64.zip"
_MEMBERS = ("xray", "geoip.dat", "geosite.dat")
_SERVICES = ("naive", "mieru")
_SUPPORTED_ARCHITECTURES = ("amd64",)
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
# Secrets the router container (10006) and the panel (group 10006) read as Docker file
# secrets: root-owned, group 10006, never world-readable.
_SECRET_MODE = 0o440
# An ingress credential is `user:password` — the shapes the managers and the router accept.
_CREDENTIAL = re.compile(r"[A-Za-z0-9._-]{1,64}:[A-Za-z0-9._~-]{16,128}\Z")
_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"

# Pinned upstream Xray-core 26.3.27: the archive and the only members the installer
# writes. The same numbers live in `release/external-artifacts.json`; a test keeps them equal.
_XRAY_PINS: Mapping[str, tuple[str, str, Mapping[str, MemberPin]]] = MappingProxyType(
    {
        "amd64": (
            "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip",
            "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
            MappingProxyType(
                {
                    "xray": MemberPin("8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed", 36577406, 0o755),
                    "geoip.dat": MemberPin("744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354", 19768301, 0o644),
                    "geosite.dat": MemberPin("adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9", 10491954, 0o644),
                }
            ),
        ),
    }
)

_HELPERS: tuple[tuple[str, str, int], ...] = (
    ("scripts/prepare-xray-router-state.sh", _STATE_PREPARER, 0o755),
    ("scripts/rotate-xray-router-ingress.sh", _ROTATOR, 0o755),
)


class XrayRouterError(RuntimeError):
    """The Xray-router ownership boundary cannot be changed safely."""


class ArtifactError(XrayRouterError):
    """The staged Xray archive failed closed verification."""


def _command_failure(argv: Sequence[str]) -> str:
    program = Path(str(argv[0])).name if argv else "command"
    subcommand = ""
    for value in list(argv)[1:3]:
        rendered = str(value)
        if rendered.startswith("-") or "/" in rendered:
            break
        subcommand += f" {rendered}"
    return f"Xray-router command failed: {program}{subcommand}"


class _DefaultXrayRouterRunner(_DefaultCoreRunner):
    """Real host commands and probes for the router boundary."""

    def identity_named(self, database: str, name: str) -> str | None:
        if database not in {"passwd", "group"}:
            raise XrayRouterError("unsupported identity database")
        output = self.capture(("getent", database, name), max_chars=512)
        fields = output.strip().split(":")
        if len(fields) >= 4 and fields[0] == name and fields[2].isdigit():
            return name
        return None

    def router_status(self) -> Mapping[str, object]:
        """The manager's `/v1/status`, asked from inside the container over its own UDS."""
        output = self._capture_checked(
            ("docker", "exec", _CONTAINER, "python", "-m", "xray_router_manager.healthcheck", "--status")
        )
        try:
            value = json.loads(output)
        except ValueError as exc:
            raise XrayRouterError("Xray-router status is not JSON") from exc
        if not isinstance(value, Mapping):
            raise XrayRouterError("Xray-router status is not an object")
        return value

    def loopback_listener(self, port: int) -> bool:
        try:
            output = self.capture(("ss", "-H", "-lnt", f"sport = :{port}"), max_chars=4096)
        except Exception:
            return False
        addresses = {fields[3] for fields in (line.split() for line in output.splitlines()) if len(fields) >= 4}
        return addresses == {f"127.0.0.1:{port}"}

    def ingress_probe(self, port: int, credential_file: str) -> bool:
        """One authenticated SOCKS5 CONNECT through the ingress reaches the Internet.

        The credential travels in a private curl config file, never in the argument list."""
        credential = Path(credential_file).read_text().strip()
        if _CREDENTIAL.fullmatch(credential) is None:
            return False
        with tempfile.TemporaryDirectory(prefix="proxy-control-router-") as directory:
            config = Path(directory) / "curl.conf"
            config.write_text(f'proxy-user = "{credential}"\n')
            os.chmod(config, 0o600)
            output = self.capture(
                ("curl", "--config", str(config), "--fail", "--silent", "--show-error", "--noproxy", "",
                 "--socks5-hostname", f"127.0.0.1:{port}", "--max-time", "20", _TRACE),
                max_chars=4096,
            )
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        return bool(values.get("ip")) and not output.startswith(("exit=", "diagnostic "))


@dataclass(frozen=True)
class XrayRouterPaths:
    """Fixed host paths owned by one Xray-router generation."""

    project_dir: str = _PROJECT
    bin_dir: str = _BIN_DIR
    state_dir: str = _STATE_DIR
    artifact_dir: str = _ARTIFACT_DIR
    state_preparer: str = _STATE_PREPARER
    rotator: str = _ROTATOR
    marker: str = _MARKER

    def __post_init__(self) -> None:
        for value in (self.project_dir, self.bin_dir, self.state_dir, self.artifact_dir,
                      self.state_preparer, self.rotator, self.marker):
            if not value.startswith("/") or ".." in Path(value).parts:
                raise ValueError("Xray-router path must be a normalized absolute path")

    @property
    def archive(self) -> str:
        return f"{self.artifact_dir}/{_ARCHIVE}"

    @property
    def env_overlay(self) -> str:
        return f"{self.project_dir}/.env.xray-router"

    @property
    def compose_overlay(self) -> str:
        return f"{self.project_dir}/compose.xray-router.yaml"

    @property
    def manager_token(self) -> str:
        return f"{self.project_dir}/secrets/xray-router-manager-token"

    def ingress(self, service: str) -> str:
        if service not in _SERVICES:
            raise ValueError(f"unknown router service: {service}")
        return f"{self.project_dir}/secrets/xray-router-ingress-{service}"


def ingress_credential(service: str) -> str:
    """A fresh `user:password` for one service's ingress: the user names the service."""
    return f"{service}-{secrets.token_hex(4)}:{secrets.token_urlsafe(32)}"


class XrayRouterAdapter:
    """Own the pinned Xray runtime, its manager and the two loopback ingresses."""

    name = "xray_router"
    requires = frozenset({"core"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        source_dir: Path | None = None,
        paths: XrayRouterPaths | None = None,
        architecture: str = "amd64",
        pin: ArtifactPin | None = None,
    ) -> None:
        if runner is None:
            runner = _DefaultXrayRouterRunner()
        if architecture not in _SUPPORTED_ARCHITECTURES:
            raise ValueError(f"unsupported architecture: {architecture}")
        self.root = Path(root)
        self.runner = runner
        self.source_dir = Path(source_dir or Path(__file__).resolve().parents[2])
        self.paths = paths or XrayRouterPaths()
        self.architecture = architecture
        self.pin = pin

    # ------------------------------------------------------------------
    # pins
    # ------------------------------------------------------------------

    def _pins(self) -> tuple[str, str, Mapping[str, MemberPin]]:
        """The release url, the archive digest and the reviewed members."""
        if self.pin is not None:
            if (
                self.pin.name != "xray"
                or self.pin.version != _XRAY_VERSION
                or self.pin.architecture != self.architecture
                or not self.pin.members
                or set(self.pin.members) != set(_MEMBERS)
            ):
                raise ArtifactError("release pin does not describe pinned Xray")
            return self.pin.url, self.pin.sha256, self.pin.members
        return _XRAY_PINS[self.architecture]

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if not config.effective_egress.router:
            return ()
        if getattr(facts, "hard_stops", ()):
            raise XrayRouterError("host audit contains blocking findings")
        if not (config.profile.includes_naive or config.profile.includes_mieru):
            raise PlanError("the Xray-router needs NaiveProxy or Mieru to feed")
        self._assert_planned_identities(facts)
        self._assert_free_listeners(facts)
        url, archive_sha256, members = self._pins()
        return (
            Action(
                id="xray_router.runtime",
                adapter=self.name,
                owner="proxy-control:xray-router",
                mutations=(
                    f"project={self.paths.project_dir}",
                    f"xray-version={_XRAY_VERSION}",
                    f"architecture={self.architecture}",
                    f"archive={self.paths.archive}",
                    f"archive-url={url}",
                    f"archive-digest={archive_sha256}",
                    *(f"{member}-digest={members[member].sha256}" for member in _MEMBERS),
                    f"bin-dir={self.paths.bin_dir}",
                    f"state-dir={self.paths.state_dir}",
                    f"router-uid={_ROUTER_UID}",
                    f"router-gid={_ROUTER_GID}",
                    *(f"port-{service}={ROUTER_PORTS[service]}" for service in _SERVICES),
                    # The WARP endpoint the router may send traffic through (v0.4 provider).
                    f"warp-provider={config.effective_egress.provider_url() or ''}",
                ),
                preconditions=(
                    "the Core runtime is verified",
                    f"the pinned archive is staged in {self.paths.artifact_dir}",
                    "loopback ports 45101 and 45102 are free or held by the owned router",
                    "fixed router identity 10006 is free or already owned",
                ),
                verification=(
                    "archive and member digests match the pinned release",
                    "the manager reports verified artifacts and a running generation",
                    "both ingresses listen on the loopback only",
                    "one authenticated CONNECT through the NaiveProxy ingress reaches the Internet",
                ),
                inverse=(
                    "stop and remove only the xray-router Compose service",
                    "remove only the owned binaries, helpers and env overlay",
                    "preserve manager state and secrets unless purge is explicit",
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
        for kind, identifier in (("uid", _ROUTER_UID), ("gid", _ROUTER_GID)):
            group = identities.get(kind)
            if not isinstance(group, Mapping):
                continue
            holder = group.get(str(identifier))
            if holder in (None, "", _ROUTER_USER):
                continue
            if not isinstance(holder, str):
                raise PlanError("audited identity facts are invalid")
            raise PlanError(f"{kind.upper()} {identifier} collision: {holder}")

    def _assert_free_listeners(self, facts: AuditFacts) -> None:
        listeners = facts.listeners if isinstance(facts.listeners, Mapping) else {}
        observed = listeners.get("tcp")
        if not isinstance(observed, Sequence) or isinstance(observed, (str, bytes)):
            return
        held = {int(value) for value in observed if isinstance(value, int)}
        owners = listeners.get("owners")
        for service in _SERVICES:
            port = ROUTER_PORTS[service]
            if port not in held:
                continue
            holders = owners.get(str(port)) if isinstance(owners, Mapping) else None
            if isinstance(holders, Sequence) and not isinstance(holders, (str, bytes)) and holders and set(holders) <= {"xray"}:
                continue
            raise PlanError(f"router ingress port {port} is already claimed by another listener")

    def _selection(self, action: Action) -> dict[str, object]:
        if action.id != "xray_router.runtime" or action.adapter != self.name or action.owner != "proxy-control:xray-router":
            raise XrayRouterError("Xray-router action is invalid")
        values: dict[str, str] = {}
        for item in action.mutations:
            key, separator, value = item.partition("=")
            if not separator or key in values:
                raise XrayRouterError("Xray-router action is invalid")
            values[key] = value
        required = {"project", "xray-version", "architecture", "archive", "archive-url", "archive-digest", "bin-dir",
                    "state-dir", "router-uid", "router-gid", "warp-provider",
                    *(f"{member}-digest" for member in _MEMBERS), *(f"port-{service}" for service in _SERVICES)}
        if set(values) != required:
            raise XrayRouterError("Xray-router action is invalid")
        url, archive_sha256, members = self._pins()
        if (
            values["project"] != self.paths.project_dir
            or values["xray-version"] != _XRAY_VERSION
            or values["architecture"] != self.architecture
            or values["archive"] != self.paths.archive
            or values["archive-url"] != url
            or values["archive-digest"] != archive_sha256
            or values["bin-dir"] != self.paths.bin_dir
            or values["state-dir"] != self.paths.state_dir
            or values["router-uid"] != str(_ROUTER_UID)
            or values["router-gid"] != str(_ROUTER_GID)
            or any(values[f"{member}-digest"] != members[member].sha256 for member in _MEMBERS)
            or any(values[f"port-{service}"] != str(ROUTER_PORTS[service]) for service in _SERVICES)
        ):
            raise XrayRouterError("Xray-router action is invalid")
        provider = values["warp-provider"]
        if provider and re.fullmatch(r"socks5://127\.0\.0\.1:[0-9]{4,5}", provider) is None:
            raise XrayRouterError("invalid WARP provider")
        return {"url": url, "archive_sha256": archive_sha256, "members": members, "warp_provider": provider}

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def prepare(self, action: Action) -> Mapping[str, object]:
        selected = self._selection(action)
        self._assert_live_identities()
        self._assert_archive(selected)
        marker = self._host(self.paths.marker)
        adoption = "recovery" if self._marker_present(marker) else "absent"
        if adoption == "absent" and self._compose_service_present():
            raise XrayRouterError("an active xray-router service requires a proven owned recovery generation")
        return {
            "owner": action.owner,
            "adoption": adoption,
            "marker_value": secrets.token_hex(16) if adoption == "absent" else None,
            "identities_created": {},
            "bin_preexisting": self._host(self.paths.bin_dir).is_dir(),
            "state_preexisting": self._host(self.paths.state_dir).is_dir(),
            "secrets_preexisting": {
                name: self._host(path).is_file()
                for name, path in (("manager_token", self.paths.manager_token),
                                   *((f"ingress_{service}", self.paths.ingress(service)) for service in _SERVICES))
            },
            "ownership": {},
        }

    def _assert_archive(self, selected: Mapping[str, object]) -> None:
        archive = self._host(self.paths.archive)
        if archive.is_symlink() or not archive.is_file():
            raise ArtifactError(
                f"stage the pinned Xray archive as {self.paths.archive} first (sha256 {selected['archive_sha256']}, "
                f"published at {selected['url']})"
            )
        try:
            verify_artifact(archive, str(selected["archive_sha256"]))
        except ReleaseError as exc:
            raise ArtifactError("Xray archive digest does not match the pinned release") from exc

    def apply(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action)
        # 1. Verified artifact first: nothing else may run an unpinned binary.
        self._assert_archive(selected)
        self._install_members(selected)
        # 2. Identity, helpers, state and secrets the container is started with.
        identities = self._ensure_identities()
        self._install_helpers()
        self._prepare_state()
        self._write_secrets()
        self._atomic(self._host(self.paths.env_overlay), self.env_text(selected).encode(), 0o600)
        marker_value = prepared["marker_value"]
        if isinstance(marker_value, str):
            self._atomic(self._host(self.paths.marker), (marker_value + "\n").encode(), 0o600)
        # 3. The service, healthy (the manager bootstraps generation 1 before it answers).
        self._compose("up", "-d", "--build", "--wait", _SERVICE)
        return {**prepared, "identities_created": identities, "ownership": self._ownership()}

    reconcile_apply = apply

    def env_text(self, selected: Mapping[str, object]) -> str:
        members = selected["members"]
        assert isinstance(members, Mapping)
        return (
            f"XRAY_ROUTER_BIN_DIR={self.paths.bin_dir}\n"
            f"XRAY_ROUTER_STATE_DIR={self.paths.state_dir}\n"
            f"XRAY_ROUTER_XRAY_SHA256={members['xray'].sha256}\n"
            f"XRAY_ROUTER_GEOIP_SHA256={members['geoip.dat'].sha256}\n"
            f"XRAY_ROUTER_GEOSITE_SHA256={members['geosite.dat'].sha256}\n"
            # The WARP endpoint the router's `warp` provider points at; empty on a host
            # without WARP, and the routing preview then says so.
            f"XRAY_ROUTER_EGRESS_WARP={selected['warp_provider']}\n"
        )

    def verify(self, action: Action) -> Evidence:
        selected = self._selection(action)
        members = selected["members"]
        assert isinstance(members, Mapping)
        bin_dir = self._host(self.paths.bin_dir)
        for member in _MEMBERS:
            path = bin_dir / member
            if path.is_symlink() or not path.is_file() or _file_sha256(path) != members[member].sha256:
                raise ArtifactError(f"installed Xray member does not match its pin: {member}")
        status = self._status()
        artifacts = status.get("artifacts")
        if not isinstance(artifacts, Mapping) or any(
            not isinstance(artifacts.get(name), Mapping) or artifacts[name].get("verified") is not True
            for name in ("xray", "geoip", "geosite")
        ):
            raise XrayRouterError("the Xray-router manager has not verified its artifacts")
        running = status.get("running")
        generation = running.get("generation") if isinstance(running, Mapping) else None
        if not isinstance(generation, int) or generation < 1 or status.get("phase") != "idle":
            raise XrayRouterError("the Xray-router is not running a committed generation")
        listener = getattr(self.runner, "loopback_listener", None)
        if not callable(listener):
            raise XrayRouterError("listener verification is unavailable")
        for service in _SERVICES:
            if not listener(ROUTER_PORTS[service]):
                raise XrayRouterError(f"the {service} ingress must listen on the loopback only")
        probe = getattr(self.runner, "ingress_probe", None)
        if not callable(probe):
            raise XrayRouterError("ingress verification is unavailable")
        if not probe(ROUTER_PORTS["naive"], str(self._host(self.paths.ingress("naive")))):
            raise XrayRouterError("an authenticated CONNECT through the NaiveProxy ingress did not reach the Internet")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "pinned Xray members, verified artifacts and a running generation",
                "both ingresses are loopback-only and the NaiveProxy ingress relays",
            ),
            details={"generation": generation, "xray_version": str(status.get("xray_version") or ""),
                     "ports": {service: ROUTER_PORTS[service] for service in _SERVICES}},
        )

    def repair(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._assert_live_identities()
        self._run(self.paths.state_preparer, "verify", self.paths.state_dir)
        self._atomic(self._host(self.paths.env_overlay), self.env_text(selected).encode(), 0o600)
        self._compose("up", "-d", "--wait", _SERVICE)
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
        self._selection(action)
        prepared = self._checkpoint(checkpoint, action, applied=True)
        destructive_purge = rollback_target == "uninstalled" and purge_data
        if self._compose_service_present():
            self._compose("rm", "--stop", "--force", _SERVICE)
        for relative in (self.paths.env_overlay, self.paths.marker, *(host for _source, host, _mode in _HELPERS)):
            durable_remove(self._host(relative), missing_ok=True)
        bin_dir = self._host(self.paths.bin_dir)
        if bin_dir.is_dir() and not bin_dir.is_symlink():
            for member in _MEMBERS:
                durable_remove(bin_dir / member, missing_ok=True)
            if not any(bin_dir.iterdir()):
                durable_remove(bin_dir)
        if destructive_purge:
            state = self._host(self.paths.state_dir)
            if state.is_dir() and not state.is_symlink():
                for child in sorted(state.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                    durable_remove(child)
                durable_remove(state)
            for relative in (self.paths.manager_token, *(self.paths.ingress(service) for service in _SERVICES)):
                durable_remove(self._host(relative), missing_ok=True)
            self._remove_identities(prepared)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the Xray-router runtime was removed",
                "manager state and secrets were purged" if destructive_purge else "manager state and secrets were preserved",
            ),
            details={"persistent_data_preserved": not destructive_purge, "identities_removed": destructive_purge},
        )

    reconcile_rollback = rollback

    # ------------------------------------------------------------------
    # checkpoint
    # ------------------------------------------------------------------

    def _checkpoint(self, checkpoint: Mapping[str, object], action: Action, *, applied: bool = False) -> dict[str, object]:
        required = {"owner", "adoption", "marker_value", "identities_created", "bin_preexisting", "state_preexisting",
                    "secrets_preexisting", "ownership"}
        if set(checkpoint) != required:
            raise XrayRouterError("Xray-router checkpoint is invalid")
        adoption = checkpoint["adoption"]
        marker_value = checkpoint["marker_value"]
        identities = checkpoint["identities_created"]
        secrets_preexisting = checkpoint["secrets_preexisting"]
        ownership = checkpoint["ownership"]
        if (
            checkpoint["owner"] != action.owner
            or adoption not in {"absent", "recovery"}
            or (adoption == "absent" and (not isinstance(marker_value, str) or _HEX_32.fullmatch(marker_value) is None))
            or (adoption == "recovery" and marker_value is not None)
            or not isinstance(identities, Mapping)
            or any(not isinstance(key, str) or not isinstance(value, bool) for key, value in identities.items())
            or not isinstance(secrets_preexisting, Mapping)
            or any(not isinstance(key, str) or not isinstance(value, bool) for key, value in secrets_preexisting.items())
            or not isinstance(ownership, Mapping)
            or (not applied and ownership)
            or any(not isinstance(checkpoint[name], bool) for name in ("bin_preexisting", "state_preexisting"))
        ):
            raise XrayRouterError("Xray-router checkpoint is invalid")
        return {name: checkpoint[name] for name in required}

    def _ownership(self) -> dict[str, str]:
        """Digests of what this generation wrote and rollback may remove: never a secret."""
        owned: dict[str, str] = {}
        for relative in (self.paths.env_overlay, self.paths.marker, *(host for _source, host, _mode in _HELPERS)):
            path = self._host(relative)
            if path.is_file():
                owned[relative] = _file_sha256(path)
        bin_dir = self._host(self.paths.bin_dir)
        for member in _MEMBERS:
            path = bin_dir / member
            if path.is_file():
                owned[f"{self.paths.bin_dir}/{member}"] = _file_sha256(path)
        return owned

    # ------------------------------------------------------------------
    # steps
    # ------------------------------------------------------------------

    def _install_members(self, selected: Mapping[str, object]) -> None:
        """Exactly the reviewed members, through the private-stage swap of the extractor;
        the directory ends world-readable for the container's identity."""
        members = selected["members"]
        assert isinstance(members, Mapping)
        bin_dir = self._host(self.paths.bin_dir)
        if bin_dir.is_symlink() or (bin_dir.exists() and not bin_dir.is_dir()):
            raise XrayRouterError("Xray-router binary path is occupied")
        durable_mkdir(bin_dir.parent, mode=0o755)
        try:
            safe_extract_zip(self._host(self.paths.archive), bin_dir, members)
        except ReleaseError as exc:
            raise ArtifactError(f"Xray archive extraction failed: {exc}") from exc
        os.chmod(bin_dir, 0o755)
        os.chmod(bin_dir.parent, 0o755)
        fsync_directory(bin_dir.parent)

    def _ensure_identities(self) -> dict[str, bool]:
        created = {"group": False, "user": False}
        if self._identity_named("group", _ROUTER_GROUP) is None:
            self._run("groupadd", "--system", "--gid", str(_ROUTER_GID), _ROUTER_GROUP)
            created["group"] = True
        if self._identity_named("passwd", _ROUTER_USER) is None:
            self._run("useradd", "--system", "--uid", str(_ROUTER_UID), "--gid", _ROUTER_GROUP, "--home", "/nonexistent",
                      "--shell", "/usr/sbin/nologin", _ROUTER_USER)
            created["user"] = True
        return created

    def _remove_identities(self, checkpoint: Mapping[str, object]) -> None:
        created = checkpoint["identities_created"]
        assert isinstance(created, Mapping)
        if created.get("user") and self._identity_named("passwd", _ROUTER_USER) is not None:
            self._run_best_effort("userdel", _ROUTER_USER)
        if created.get("group") and self._identity_named("group", _ROUTER_GROUP) is not None:
            self._run_best_effort("groupdel", _ROUTER_GROUP)

    def _identity_named(self, database: str, name: str) -> str | None:
        lookup = getattr(self.runner, "identity_named", None)
        if callable(lookup):
            value = lookup(database, name)
            return str(value) if value else None
        return None

    def _assert_live_identities(self) -> None:
        owner = getattr(self.runner, "identity_owner", None)
        if not callable(owner):
            return
        for kind, identifier in (("uid", _ROUTER_UID), ("gid", _ROUTER_GID)):
            holder = owner(kind, identifier)
            if holder not in (None, "", _ROUTER_USER):
                raise XrayRouterError(f"{kind.upper()} {identifier} collision: {holder}")

    def _install_helpers(self) -> None:
        for relative, host_path, mode in _HELPERS:
            source = self.source_dir / relative
            if not source.is_file():
                raise XrayRouterError("installer source generation is incomplete")
            self._atomic(self._host(host_path), source.read_bytes(), mode)

    def _prepare_state(self) -> None:
        state = self._host(self.paths.state_dir)
        if state.is_symlink() or (state.exists() and not state.is_dir()):
            raise XrayRouterError("Xray-router state path is occupied")
        mode = "verify" if state.is_dir() and any(state.iterdir()) else "prepare"
        self._run(self.paths.state_preparer, mode, self.paths.state_dir)

    def _write_secrets(self) -> None:
        """The manager token and one credential per ingress; an existing secret is kept, so
        a re-run never breaks the managers' copies (rotation is the operator's script).
        Docker mounts a file secret with the file's own owner and mode, and the container
        runs as 10006: root-owned, group 10006, mode 0440 — the shape mieru's token has."""
        token = self._host(self.paths.manager_token)
        durable_mkdir(token.parent, mode=0o700)
        if not (token.exists() or token.is_symlink()):
            self._atomic(token, (secrets.token_hex(32) + "\n").encode("ascii"), _SECRET_MODE)
        self._own_secret(token)
        for service in _SERVICES:
            path = self._host(self.paths.ingress(service))
            if not (path.exists() or path.is_symlink()):
                self._atomic(path, (ingress_credential(service) + "\n").encode("ascii"), _SECRET_MODE)
            self._own_secret(path)
            if _CREDENTIAL.fullmatch(path.read_text().strip()) is None:
                raise XrayRouterError(f"the {service} ingress credential is malformed")

    def _own_secret(self, path: Path) -> None:
        """A regular, non-world-readable file becomes root:10006 0440; anything else is refused."""
        if path.is_symlink() or not path.is_file():
            raise XrayRouterError("pre-existing Xray-router secrets are unsafe")
        metadata = path.stat()
        if metadata.st_mode & 0o007 or (self.root == Path("/") and metadata.st_uid != 0):
            raise XrayRouterError("pre-existing Xray-router secrets are unsafe")
        os.chmod(path, _SECRET_MODE)
        if self.root == Path("/") and os.geteuid() == 0:
            os.chown(path, 0, _ROUTER_GID)

    def _status(self) -> Mapping[str, object]:
        reader = getattr(self.runner, "router_status", None)
        if not callable(reader):
            raise XrayRouterError("Xray-router status is unavailable")
        value = reader()
        if not isinstance(value, Mapping):
            raise XrayRouterError("Xray-router status is unavailable")
        return value

    # ------------------------------------------------------------------
    # host boundary
    # ------------------------------------------------------------------

    def _marker_present(self, marker: Path) -> bool:
        return marker.is_file() and not marker.is_symlink()

    def _compose_service_present(self) -> bool:
        method = getattr(self.runner, "compose_service_present", None)
        return bool(method(_SERVICE)) if callable(method) else False

    def _compose_argv(self, *args: str) -> tuple[str, ...]:
        """One Compose invocation over every overlay the project currently runs with: the
        protocol overlays extend the same `panel` service this overlay extends, so they
        ride along whenever their env files exist on the host."""
        project = self.paths.project_dir
        env_files = [f"{project}/.env"]
        compose_files = [f"{project}/compose.yaml"]
        for sibling in ("naive", "mieru"):
            env = f"{project}/.env.{sibling}"
            if self._host(env).is_file():
                env_files.append(env)
                compose_files.append(f"{project}/compose.{sibling}.yaml")
        env_files.append(self.paths.env_overlay)
        compose_files.append(self.paths.compose_overlay)
        argv: list[str] = ["docker", "compose", "--project-directory", project]
        for path in env_files:
            argv += ["--env-file", path]
        for path in compose_files:
            argv += ["-f", path]
        return (*argv, *args)

    def _compose(self, *args: str) -> None:
        self._run(*self._compose_argv(*args))

    def _run(self, *argv: str) -> None:
        try:
            result = self.runner.run(argv)
        except XrayRouterError:
            raise
        except Exception as exc:
            raise XrayRouterError(_command_failure(argv)) from exc
        if getattr(result, "returncode", 0):
            from installer.adapters.nginx import _sanitize_diagnostic
            stderr = getattr(result, "stderr", "") or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            raise XrayRouterError(f"{_command_failure(argv)}; {_sanitize_diagnostic(str(stderr))}")

    def _run_best_effort(self, *argv: str) -> None:
        try:
            self._run(*argv)
        except Exception:
            pass

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise XrayRouterError("Xray-router host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise XrayRouterError("Xray-router root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise XrayRouterError("Xray-router host path crosses an unsafe parent")
        return self.root / relative

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        durable_mkdir(path.parent)
        atomic_write(path, data, mode=mode, owner=owner)
