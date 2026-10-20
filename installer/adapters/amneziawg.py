"""Installer-owned AmneziaWG add-on (the optional `[amneziawg]` section, any profile).

The `awg-manager` Compose service (overlay `compose.amneziawg.yaml`, sources in
`awg_manager/`) runs one `amneziawg-go` process per enabled version on the host network.
The installer owns exactly what the container cannot create for itself:

* the host sysctl file `/etc/sysctl.d/99-proxy-control-amneziawg.conf` (IPv4 forwarding),
* the state directory `/var/lib/awg-manager` (mode 0700; it holds the server keys),
* the manager token `secrets/awg-manager-token` (0600 root) and `.env.amneziawg` (0600),
* the ownership marker, and the Compose service itself.

The UDP ports and the per-interface forwarding rules in UFW belong to the firewall adapter.
The manager's token is never printed, logged or put into a plan.
"""
from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from installer.adapters.core import _DOMAIN, _DefaultCoreRunner, _file_sha256
from installer.model import (
    AWG_DEFAULT_SUBNETS,
    AWG_VERSIONS,
    InstallerConfig,
    awg_interface,
)
from installer.planner import Action, AuditFacts, Evidence, PlanError
from installer.transaction import atomic_write, durable_mkdir, durable_remove
from installer.compose_project import COMPOSE_PROJECTS, VERSION_OVERRIDE, without_override_service

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_PROJECT = "/opt/mtproxy-shared443"
_STATE_DIR = "/var/lib/awg-manager"
_SYSCTL_FILE = "/etc/sysctl.d/99-proxy-control-amneziawg.conf"
_MARKER = "/etc/proxy-control/amneziawg-owned"
_TUN_DEVICE = "/dev/net/tun"
_SERVICE = "awg-manager"
_CONTAINER = "proxy-control-awg-manager"
# The group of the manager's Unix socket (the run volume is a setgid tmpfs directory); the
# panel joins it through the overlay's `group_add`.
_SOCKET_GID = 10007
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_IPV4 = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}\Z")
_SYSCTL_TEXT = (
    "# Managed by Proxy Control (AmneziaWG): the tunnels forward clients' packets to the Internet.\n"
    "net.ipv4.ip_forward = 1\n"
)
# Run inside the manager container: asks `GET /v1/health` over its own Unix socket with its own
# token file and prints the answer's body only. The token never leaves the container.
_HEALTH_SCRIPT = (
    "import os, socket\n"
    "from pathlib import Path\n"
    "token = Path(os.environ['AWG_MANAGER_TOKEN_FILE']).read_text().strip()\n"
    "request = ('GET /v1/health HTTP/1.1\\r\\nHost: awg-manager\\r\\nX-Awg-Token: ' + token\n"
    "           + '\\r\\nConnection: close\\r\\n\\r\\n').encode('ascii')\n"
    "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:\n"
    "    client.settimeout(5)\n"
    "    client.connect(os.environ.get('AWG_MANAGER_SOCKET', '/run/awg-manager/manager.sock'))\n"
    "    client.sendall(request)\n"
    "    chunks = []\n"
    "    while True:\n"
    "        chunk = client.recv(4096)\n"
    "        if not chunk:\n"
    "            break\n"
    "        chunks.append(chunk)\n"
    "head, _, body = b''.join(chunks).partition(b'\\r\\n\\r\\n')\n"
    "if head.split(b'\\r\\n', 1)[0] not in (b'HTTP/1.0 200 OK', b'HTTP/1.1 200 OK'):\n"
    "    raise SystemExit(1)\n"
    "print(body.decode())\n"
)


class AmneziaWgError(RuntimeError):
    """The AmneziaWG ownership boundary cannot be changed safely."""


def _command_failure(argv: Sequence[str]) -> str:
    program = Path(str(argv[0])).name if argv else "command"
    subcommand = ""
    for value in list(argv)[1:3]:
        rendered = str(value)
        if rendered.startswith("-") or "/" in rendered:
            break
        subcommand += f" {rendered}"
    return f"AmneziaWG command failed: {program}{subcommand}"


class _DefaultAmneziaWgRunner(_DefaultCoreRunner):
    """Real host commands and probes for the AmneziaWG boundary."""

    def compose_service_present(self, service: str) -> bool:
        for project in COMPOSE_PROJECTS:
            output = self.capture(
                ("docker", "container", "ls", "--all", "--quiet",
                 "--filter", f"label=com.docker.compose.project={project}",
                 "--filter", f"label=com.docker.compose.service={service}"),
                max_chars=512,
            )
            stripped = output.strip()
            if stripped and not stripped.startswith(("exit=", "diagnostic ")):
                return True
        return False

    def container_health(self) -> str:
        output = self.capture(
            ("docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
             _CONTAINER),
            max_chars=64,
        )
        return output.strip()

    def manager_health(self) -> Mapping[str, object]:
        output = self._capture_checked(("docker", "exec", _CONTAINER, "python", "-c", _HEALTH_SCRIPT))
        try:
            value = json.loads(output)
        except ValueError as exc:
            raise AmneziaWgError("AmneziaWG manager health is not JSON") from exc
        if not isinstance(value, Mapping):
            raise AmneziaWgError("AmneziaWG manager health is not an object")
        return value

    def udp_listener(self, port: int) -> bool:
        try:
            output = self.capture(("ss", "-H", "-lun", f"sport = :{port}"), max_chars=4096)
        except Exception:
            return False
        if output.startswith(("exit=", "diagnostic ")):
            return False
        return any(len(fields) >= 4 for fields in (line.split() for line in output.splitlines()))


@dataclass(frozen=True)
class AmneziaWgPaths:
    """Fixed host paths owned by one AmneziaWG generation."""

    project_dir: str = _PROJECT
    state_dir: str = _STATE_DIR
    sysctl_file: str = _SYSCTL_FILE
    marker: str = _MARKER
    tun_device: str = _TUN_DEVICE

    def __post_init__(self) -> None:
        for value in (self.project_dir, self.state_dir, self.sysctl_file, self.marker, self.tun_device):
            if not value.startswith("/") or ".." in Path(value).parts:
                raise ValueError("AmneziaWG path must be a normalized absolute path")

    @property
    def env_overlay(self) -> str:
        return f"{self.project_dir}/.env.amneziawg"

    @property
    def compose_overlay(self) -> str:
        return f"{self.project_dir}/compose.amneziawg.yaml"

    @property
    def manager_token(self) -> str:
        return f"{self.project_dir}/secrets/awg-manager-token"


class AmneziaWgAdapter:
    """Own the AmneziaWG manager container, its token, state directory and forwarding sysctl."""

    name = "amneziawg"
    requires = frozenset({"core"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        paths: AmneziaWgPaths | None = None,
    ) -> None:
        if runner is None:
            runner = _DefaultAmneziaWgRunner()
        self.root = Path(root)
        self.runner = runner
        self.paths = paths or AmneziaWgPaths()

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        awg = config.amneziawg
        if awg is None:
            return ()
        if getattr(facts, "hard_stops", ()):
            raise AmneziaWgError("host audit contains blocking findings")
        if not self._tun_present():
            raise PlanError(
                f"AmneziaWG needs {self.paths.tun_device} on the host (load the kernel module: modprobe tun) "
                "or a kernel/container platform that provides it"
            )
        if not all(awg.ports):
            raise AmneziaWgError("AmneziaWG ports are not assigned (resolve them with installer.awg_ports first)")
        self._assert_free_udp(facts, awg.ports)
        ports = ",".join(f"{version}:{port}" for version, port in awg.port_map().items())
        ufw_managed = config.host_mode.value == "fresh" and config.firewall.manage_ufw
        return (
            Action(
                id="amneziawg.runtime",
                adapter=self.name,
                owner="proxy-control:amneziawg",
                mutations=(
                    f"project={self.paths.project_dir}",
                    f"state-dir={self.paths.state_dir}",
                    f"sysctl-file={self.paths.sysctl_file}",
                    "ip-forward=1",
                    f"versions={','.join(awg.versions)}",
                    f"ports={ports}",
                    f"interfaces={','.join(awg.interfaces())}",
                    f"host={awg.host}",
                    f"mtu={awg.mtu}",
                    f"dns={','.join(awg.dns)}",
                    f"socket-gid={_SOCKET_GID}",
                    f"container={_CONTAINER}",
                ),
                preconditions=(
                    "the Core runtime is verified",
                    f"{self.paths.tun_device} exists on the host",
                    "the selected UDP ports are free or held by the owned manager",
                    *(
                        ("the host firewall allows the selected UDP ports and forwarding on the awg interfaces "
                         "(managed by this installer through UFW)",)
                        if ufw_managed
                        else ("the operator opens the selected UDP ports and allows forwarding on the awg "
                              "interfaces in the host firewall (the installer does not manage it here)",)
                    ),
                    "the host name clients dial points straight at this server and is not proxied",
                ),
                verification=(
                    "the awg-manager container is healthy",
                    "the manager answers /v1/health over its Unix socket and every enabled version is running",
                    "every selected UDP port is bound on the host",
                    "IPv4 forwarding is enabled",
                ),
                inverse=(
                    "stop and remove only the awg-manager Compose service",
                    "remove only the owned env overlay, sysctl file and marker",
                    "preserve the state directory (server keys) and the manager secret unless purge is explicit",
                ),
                credentials_required=True,
            ),
        )

    def _tun_present(self) -> bool:
        probe = getattr(self.runner, "device_present", None)
        if callable(probe):
            return bool(probe(self.paths.tun_device))
        return self._host(self.paths.tun_device).exists()

    def _assert_free_udp(self, facts: AuditFacts, ports: Sequence[int]) -> None:
        listeners = facts.listeners if isinstance(facts.listeners, Mapping) else {}
        observed = listeners.get("udp")
        if not isinstance(observed, Sequence) or isinstance(observed, (str, bytes)):
            return
        held = {int(value) for value in observed if isinstance(value, int)}
        owners = listeners.get("owners")
        for port in ports:
            if port not in held:
                continue
            holders = owners.get(str(port)) if isinstance(owners, Mapping) else None
            if isinstance(holders, Sequence) and not isinstance(holders, (str, bytes)) and holders \
                    and set(holders) <= {"amneziawg-go"}:
                continue
            raise PlanError(f"AmneziaWG port {port}/udp is already claimed by another listener")

    def _selection(self, action: Action) -> dict[str, object]:
        if action.id != "amneziawg.runtime" or action.adapter != self.name or action.owner != "proxy-control:amneziawg":
            raise AmneziaWgError("AmneziaWG action is invalid")
        values: dict[str, str] = {}
        for item in action.mutations:
            key, separator, value = item.partition("=")
            if not separator or key in values:
                raise AmneziaWgError("AmneziaWG action is invalid")
            values[key] = value
        required = {"project", "state-dir", "sysctl-file", "ip-forward", "versions", "ports", "interfaces", "host",
                    "mtu", "dns", "socket-gid", "container"}
        if set(values) != required:
            raise AmneziaWgError("AmneziaWG action is invalid")
        if (
            values["project"] != self.paths.project_dir
            or values["state-dir"] != self.paths.state_dir
            or values["sysctl-file"] != self.paths.sysctl_file
            or values["ip-forward"] != "1"
            or values["socket-gid"] != str(_SOCKET_GID)
            or values["container"] != _CONTAINER
        ):
            raise AmneziaWgError("AmneziaWG action is invalid")
        versions = tuple(values["versions"].split(","))
        if not versions or len(set(versions)) != len(versions) or any(v not in AWG_VERSIONS for v in versions):
            raise AmneziaWgError("AmneziaWG action is invalid")
        ports: dict[str, int] = {}
        for entry in values["ports"].split(","):
            version, separator, port = entry.partition(":")
            if not separator or version in ports or not port.isdigit() or not 1024 <= int(port) <= 65535:
                raise AmneziaWgError("AmneziaWG action is invalid")
            ports[version] = int(port)
        if tuple(ports) != versions or len(set(ports.values())) != len(ports):
            raise AmneziaWgError("AmneziaWG action is invalid")
        if values["interfaces"] != ",".join(awg_interface(v) for v in versions):
            raise AmneziaWgError("AmneziaWG action is invalid")
        host = values["host"]
        if not (_IPV4.fullmatch(host) or _DOMAIN.fullmatch(host)):
            raise AmneziaWgError("invalid AmneziaWG public host")
        mtu = values["mtu"]
        if not mtu.isdigit() or not 1280 <= int(mtu) <= 1420:
            raise AmneziaWgError("invalid AmneziaWG MTU")
        dns = tuple(values["dns"].split(","))
        if not 1 <= len(dns) <= 4 or any(re.fullmatch(r"[0-9A-Fa-f:.]{2,45}", item) is None for item in dns):
            raise AmneziaWgError("invalid AmneziaWG DNS list")
        return {"versions": versions, "ports": ports, "host": host, "mtu": int(mtu), "dns": dns}

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def prepare(self, action: Action) -> Mapping[str, object]:
        self._selection(action)
        if not self._tun_present():
            raise AmneziaWgError(f"{self.paths.tun_device} is missing on the host")
        marker = self._host(self.paths.marker)
        adoption = "recovery" if marker.is_file() and not marker.is_symlink() else "absent"
        if adoption == "absent":
            if self._compose_service_present():
                raise AmneziaWgError("an active awg-manager service requires a proven owned recovery generation")
            sysctl = self._host(self.paths.sysctl_file)
            if (sysctl.exists() or sysctl.is_symlink()) and (
                sysctl.is_symlink() or not sysctl.is_file() or sysctl.read_text(encoding="utf-8") != _SYSCTL_TEXT
            ):
                raise AmneziaWgError(f"a foreign file occupies {self.paths.sysctl_file}")
        return {
            "owner": action.owner,
            "adoption": adoption,
            "marker_value": secrets.token_hex(16) if adoption == "absent" else None,
            "state_preexisting": self._host(self.paths.state_dir).is_dir(),
            "token_preexisting": self._host(self.paths.manager_token).is_file(),
            "sysctl_preexisting": self._host(self.paths.sysctl_file).is_file(),
            "ownership": {},
        }

    def apply(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action)
        if not self._tun_present():
            raise AmneziaWgError(f"{self.paths.tun_device} is missing on the host")
        # 1. Host prerequisites the container cannot create: forwarding and the key directory.
        self._write_sysctl()
        self._prepare_state()
        # 2. The manager token (an existing one is kept) and the Compose env overlay.
        self._write_token()
        self._atomic(self._host(self.paths.env_overlay), self.env_text(selected).encode(), 0o600)
        marker_value = prepared["marker_value"]
        if isinstance(marker_value, str):
            self._atomic(self._host(self.paths.marker), (marker_value + "\n").encode(), 0o600)
        # 3. The service, healthy; the panel is recreated by the same call to join the socket group.
        self._compose("up", "-d", "--build", "--wait")
        return {**prepared, "ownership": self._ownership()}

    reconcile_apply = apply

    def env_text(self, selected: Mapping[str, object]) -> str:
        versions = selected["versions"]
        ports = selected["ports"]
        assert isinstance(versions, tuple) and isinstance(ports, Mapping)
        return (
            f"AWG_MANAGER_TOKEN_FILE={self.paths.manager_token}\n"
            f"AWG_MANAGER_STATE_DIR={self.paths.state_dir}\n"
            f"AWG_VERSIONS={','.join(versions)}\n"
            f"AWG_PORTS={','.join(f'{version}={ports[version]}' for version in versions)}\n"
            f"AWG_SUBNETS={','.join(f'{version}={AWG_DEFAULT_SUBNETS[version]}' for version in versions)}\n"
            f"AWG_MTU={selected['mtu']}\n"
            f"AWG_DNS={','.join(selected['dns'])}\n"  # type: ignore[arg-type]
            f"AWG_MANAGER_SOCKET_GID={_SOCKET_GID}\n"
            f"AMNEZIAWG_PUBLIC_HOST={selected['host']}\n"
        )

    def verify(self, action: Action) -> Evidence:
        selected = self._selection(action)
        versions, ports = selected["versions"], selected["ports"]
        assert isinstance(versions, tuple) and isinstance(ports, Mapping)
        sysctl = self._host(self.paths.sysctl_file)
        if sysctl.is_symlink() or not sysctl.is_file() or sysctl.read_text(encoding="utf-8") != _SYSCTL_TEXT:
            raise AmneziaWgError("the AmneziaWG sysctl file is missing or changed")
        state = self._host(self.paths.state_dir)
        if state.is_symlink() or not state.is_dir():
            raise AmneziaWgError("the AmneziaWG state directory is missing")
        health = getattr(self.runner, "container_health", None)
        if not callable(health) or health() != "healthy":
            raise AmneziaWgError("the awg-manager container is not healthy")
        reader = getattr(self.runner, "manager_health", None)
        if not callable(reader):
            raise AmneziaWgError("AmneziaWG manager health is unavailable")
        report = reader()
        instances = report.get("instances") if isinstance(report, Mapping) else None
        if (
            not isinstance(report, Mapping)
            or report.get("status") != "ok"
            or report.get("ip_forward") is not True
            or not isinstance(instances, Mapping)
            or set(instances) != set(versions)
        ):
            raise AmneziaWgError("the AmneziaWG manager does not report a healthy state")
        for version in versions:
            instance = instances[version]
            if not isinstance(instance, Mapping) or instance.get("running") is not True:
                raise AmneziaWgError(f"AmneziaWG {version} is not running")
            if instance.get("port") != ports[version]:
                raise AmneziaWgError(f"AmneziaWG {version} does not run on its planned port")
        listener = getattr(self.runner, "udp_listener", None)
        if not callable(listener):
            raise AmneziaWgError("UDP listener verification is unavailable")
        for version in versions:
            if not listener(ports[version]):
                raise AmneziaWgError(f"AmneziaWG {version} does not listen on {ports[version]}/udp")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the awg-manager container is healthy and answers over its Unix socket",
                "every enabled AmneziaWG version is running and bound to its UDP port",
                "IPv4 forwarding is enabled",
                "the operator must keep the UDP ports open and forwarding allowed on the awg interfaces "
                "in any firewall the installer does not manage",
            ),
            details={
                "versions": list(versions),
                "ports": {version: ports[version] for version in versions},
                "interfaces": [awg_interface(version) for version in versions],
            },
        )

    def repair(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._write_sysctl()
        self._prepare_state()
        self._write_token()
        self._atomic(self._host(self.paths.env_overlay), self.env_text(selected).encode(), 0o600)
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
        self._selection(action)
        prepared = self._checkpoint(checkpoint, action, applied=True)
        destructive_purge = rollback_target == "uninstalled" and purge_data
        if self._compose_service_present():
            self._compose("rm", "--stop", "--force", _SERVICE)
        for absolute in (self.paths.env_overlay, self.paths.marker, self.paths.sysctl_file):
            durable_remove(self._host(absolute), missing_ok=True)
        override = self._host(f"{self.paths.project_dir}/{VERSION_OVERRIDE}")
        if override.is_file() and not override.is_symlink():
            text = override.read_text(encoding="utf-8")
            if text != without_override_service(text, _SERVICE):
                self._atomic(override, without_override_service(text, _SERVICE).encode(), 0o640)
        state = self._host(self.paths.state_dir)
        if state.is_dir() and not state.is_symlink():
            if destructive_purge:
                for child in sorted(state.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                    durable_remove(child)
                durable_remove(state)
            elif not prepared["state_preexisting"] and not any(state.iterdir()):
                # A directory this attempt created and never filled: nothing to preserve.
                durable_remove(state)
        if destructive_purge:
            durable_remove(self._host(self.paths.manager_token), missing_ok=True)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the AmneziaWG runtime was removed",
                "the state directory and the manager secret were purged"
                if destructive_purge
                else "the state directory (server keys) and the manager secret were preserved",
            ),
            details={"persistent_data_preserved": not destructive_purge},
        )

    reconcile_rollback = rollback

    # ------------------------------------------------------------------
    # checkpoint
    # ------------------------------------------------------------------

    def _checkpoint(self, checkpoint: Mapping[str, object], action: Action, *, applied: bool = False) -> dict[str, object]:
        required = {"owner", "adoption", "marker_value", "state_preexisting", "token_preexisting",
                    "sysctl_preexisting", "ownership"}
        if set(checkpoint) != required:
            raise AmneziaWgError("AmneziaWG checkpoint is invalid")
        adoption = checkpoint["adoption"]
        marker_value = checkpoint["marker_value"]
        ownership = checkpoint["ownership"]
        if (
            checkpoint["owner"] != action.owner
            or adoption not in {"absent", "recovery"}
            or (adoption == "absent" and (not isinstance(marker_value, str) or _HEX_32.fullmatch(marker_value) is None))
            or (adoption == "recovery" and marker_value is not None)
            or not isinstance(ownership, Mapping)
            or (not applied and ownership)
            or any(not isinstance(checkpoint[name], bool)
                   for name in ("state_preexisting", "token_preexisting", "sysctl_preexisting"))
        ):
            raise AmneziaWgError("AmneziaWG checkpoint is invalid")
        return {name: checkpoint[name] for name in required}

    def _ownership(self) -> dict[str, str]:
        """Digests of what this generation wrote and rollback may remove: never a secret."""
        owned: dict[str, str] = {}
        for absolute in (self.paths.env_overlay, self.paths.marker, self.paths.sysctl_file):
            path = self._host(absolute)
            if path.is_file():
                owned[absolute] = _file_sha256(path)
        return owned

    # ------------------------------------------------------------------
    # steps
    # ------------------------------------------------------------------

    def _write_sysctl(self) -> None:
        path = self._host(self.paths.sysctl_file)
        self._atomic(path, _SYSCTL_TEXT.encode(), 0o644)
        self._run("sysctl", "-p", self.paths.sysctl_file)

    def _prepare_state(self) -> None:
        state = self._host(self.paths.state_dir)
        if state.is_symlink() or (state.exists() and not state.is_dir()):
            raise AmneziaWgError("AmneziaWG state path is occupied")
        durable_mkdir(state.parent, mode=0o755)
        durable_mkdir(state, mode=0o700)
        os.chmod(state, 0o700)
        if self.root == Path("/") and os.geteuid() == 0:
            os.chown(state, 0, 0)

    def _write_token(self) -> None:
        """The manager token; an existing one is kept so the panel's copy never breaks."""
        token = self._host(self.paths.manager_token)
        durable_mkdir(token.parent, mode=0o700)
        if not (token.exists() or token.is_symlink()):
            self._atomic(token, (secrets.token_hex(32) + "\n").encode("ascii"), 0o600)
        if token.is_symlink() or not token.is_file():
            raise AmneziaWgError("pre-existing AmneziaWG secret is unsafe")
        metadata = token.stat()
        if metadata.st_mode & 0o077 or (self.root == Path("/") and metadata.st_uid != 0):
            raise AmneziaWgError("pre-existing AmneziaWG secret is unsafe")
        if not 32 <= len(token.read_text().strip()) <= 512:
            raise AmneziaWgError("the AmneziaWG manager secret is malformed")

    # ------------------------------------------------------------------
    # host boundary
    # ------------------------------------------------------------------

    def _compose_service_present(self) -> bool:
        method = getattr(self.runner, "compose_service_present", None)
        return bool(method(_SERVICE)) if callable(method) else False

    def _compose_argv(self, *args: str) -> tuple[str, ...]:
        """One Compose invocation over every overlay the project currently runs with: the
        other overlays extend the same `panel` service, so they ride along whenever their env
        files exist on the host."""
        project = self.paths.project_dir
        env_files = [f"{project}/.env"]
        compose_files = [f"{project}/compose.yaml"]
        for sibling in ("naive", "mieru", "xray-router", "trusttunnel"):
            env = f"{project}/.env.{sibling}"
            if self._host(env).is_file():
                env_files.append(env)
                compose_files.append(f"{project}/compose.{sibling}.yaml")
        env_files.append(self.paths.env_overlay)
        compose_files.append(self.paths.compose_overlay)
        # The version-agent's pins ride along (3.2), or a repair would rebuild the old version.
        if self._host(f"{project}/{VERSION_OVERRIDE}").is_file():
            compose_files.append(f"{project}/{VERSION_OVERRIDE}")
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
        except AmneziaWgError:
            raise
        except Exception as exc:
            raise AmneziaWgError(_command_failure(argv)) from exc
        if getattr(result, "returncode", 0):
            from installer.adapters.nginx import _sanitize_diagnostic
            stderr = getattr(result, "stderr", "") or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            raise AmneziaWgError(f"{_command_failure(argv)}; {_sanitize_diagnostic(str(stderr))}")

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise AmneziaWgError("AmneziaWG host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise AmneziaWgError("AmneziaWG root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise AmneziaWgError("AmneziaWG host path crosses an unsafe parent")
        return self.root / relative

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        durable_mkdir(path.parent)
        atomic_write(path, data, mode=mode, owner=owner)
