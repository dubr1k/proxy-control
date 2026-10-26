"""Installer-owned TrustTunnel add-on (the optional `[trusttunnel]` section, any profile).

The `trusttunnel-manager` Compose service (overlay `compose.trusttunnel.yaml`, sources in
`trusttunnel_manager/`) supervises the pinned `trusttunnel_endpoint` binary on the host
network. The endpoint listens on loopback only; the Nginx SNI router already on TCP/443 sends
`domains.trusttunnel` to it. Nothing is UDP and no firewall rule is added.
The installer owns exactly what the container cannot create for itself:

* the state directory `/var/lib/trusttunnel-manager` (mode 0700; credentials, totals),
* the manager token `secrets/trusttunnel-manager-token` (0600 root) and `.env.trusttunnel` (0600),
* the ownership marker, and the Compose service itself.

The manager mounts the host's `/etc/letsencrypt` read-only and reads its own host name's lineage
from there, so renewals reach the endpoint without a hook.
The certificate itself is obtained by the installer's `certificates` step (its own lineage,
named after the host). The manager's token is never printed, logged or put into a plan.
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
from installer.model import TT_METRICS_PORT, InstallerConfig
from installer.planner import Action, AuditFacts, Evidence, PlanError
from installer.transaction import atomic_write, durable_mkdir, durable_remove
from installer.compose_project import COMPOSE_PROJECTS, VERSION_OVERRIDE, without_override_service

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_PROJECT = "/opt/mtproxy-shared443"
_STATE_DIR = "/var/lib/trusttunnel-manager"
_LETSENCRYPT = "/etc/letsencrypt"
_LINEAGE_ROOT = "/etc/letsencrypt/live"
_MARKER = "/etc/proxy-control/trusttunnel-owned"
_SERVICE = "trusttunnel-manager"
_CONTAINER = "proxy-control-trusttunnel-manager"
# The group of the manager's Unix socket (the run volume is a setgid tmpfs directory); the
# panel joins it through the overlay's `group_add`.
_SOCKET_GID = 10008
# The pinned endpoint (release/external-artifacts.json, artifact `trusttunnel`): the manager
# image downloads this exact archive and checks the digest. A test keeps the numbers equal.
TT_VERSION = "1.1.0"
TT_SHA256 = "91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7"
# The aarch64 archive: the image builds for both, the installer itself supports amd64 hosts only.
TT_SHA256_AARCH64 = "c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686"
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_LOOPBACK = re.compile(r"127\.0\.0\.1:([0-9]{1,5})\Z")
# Run inside the manager container: the manager's own binary asks `GET /v1/health` over its Unix
# socket with its own token file and prints the answer's body only. The token never leaves the
# container.
_HEALTH_COMMAND = ("/usr/local/bin/trusttunnel-manager", "health")


class TrustTunnelError(RuntimeError):
    """The TrustTunnel ownership boundary cannot be changed safely."""


def _command_failure(argv: Sequence[str]) -> str:
    program = Path(str(argv[0])).name if argv else "command"
    subcommand = ""
    for value in list(argv)[1:3]:
        rendered = str(value)
        if rendered.startswith("-") or "/" in rendered:
            break
        subcommand += f" {rendered}"
    return f"TrustTunnel command failed: {program}{subcommand}"


class _DefaultTrustTunnelRunner(_DefaultCoreRunner):
    """Real host commands and probes for the TrustTunnel boundary."""

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
        output = self._capture_checked(("docker", "exec", _CONTAINER, *_HEALTH_COMMAND))
        try:
            value = json.loads(output)
        except ValueError as exc:
            raise TrustTunnelError("TrustTunnel manager health is not JSON") from exc
        if not isinstance(value, Mapping):
            raise TrustTunnelError("TrustTunnel manager health is not an object")
        return value

    def tcp_listener(self, port: int) -> bool:
        try:
            output = self.capture(("ss", "-H", "-ltn", f"sport = :{port}"), max_chars=4096)
        except Exception:
            return False
        if output.startswith(("exit=", "diagnostic ")):
            return False
        return any(len(fields) >= 4 for fields in (line.split() for line in output.splitlines()))


@dataclass(frozen=True)
class TrustTunnelPaths:
    """Fixed host paths owned by one TrustTunnel generation."""

    project_dir: str = _PROJECT
    state_dir: str = _STATE_DIR
    letsencrypt_dir: str = _LETSENCRYPT
    lineage_root: str = _LINEAGE_ROOT
    marker: str = _MARKER

    def __post_init__(self) -> None:
        for value in (self.project_dir, self.state_dir, self.letsencrypt_dir, self.lineage_root,
                      self.marker):
            if not value.startswith("/") or ".." in Path(value).parts:
                raise ValueError("TrustTunnel path must be a normalized absolute path")

    @property
    def env_overlay(self) -> str:
        return f"{self.project_dir}/.env.trusttunnel"

    @property
    def compose_overlay(self) -> str:
        return f"{self.project_dir}/compose.trusttunnel.yaml"

    @property
    def manager_token(self) -> str:
        return f"{self.project_dir}/secrets/trusttunnel-manager-token"


class TrustTunnelAdapter:
    """Own the TrustTunnel manager container, its token, state and certificate directories."""

    name = "trusttunnel"
    requires = frozenset({"core"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        paths: TrustTunnelPaths | None = None,
    ) -> None:
        if runner is None:
            runner = _DefaultTrustTunnelRunner()
        self.root = Path(root)
        self.runner = runner
        self.paths = paths or TrustTunnelPaths()

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        tt = config.trusttunnel
        if tt is None:
            return ()
        if getattr(facts, "hard_stops", ()):
            raise TrustTunnelError("host audit contains blocking findings")
        self._assert_free_tcp(facts, tt.listen_port)
        return (
            Action(
                id="trusttunnel.runtime",
                adapter=self.name,
                owner="proxy-control:trusttunnel",
                mutations=(
                    f"project={self.paths.project_dir}",
                    f"state-dir={self.paths.state_dir}",
                    f"letsencrypt-dir={self.paths.letsencrypt_dir}",
                    f"hostname={tt.hostname}",
                    f"listen=127.0.0.1:{tt.listen_port}",
                    f"metrics=127.0.0.1:{TT_METRICS_PORT}",
                    f"version={TT_VERSION}",
                    f"sha256={TT_SHA256}",
                    f"socket-gid={_SOCKET_GID}",
                    f"container={_CONTAINER}",
                ),
                preconditions=(
                    "the Core runtime is verified",
                    "the certificate of the TrustTunnel host name is issued by the certificates step and mounted read-only",
                    "the TrustTunnel host name has an A record to this server and is not proxied by a CDN",
                    "TCP/443 is shared with the other services through the Nginx SNI router "
                    "(TCP only: no UDP port and no firewall rule are added)",
                ),
                verification=(
                    "the trusttunnel-manager container is healthy",
                    "the manager answers /v1/health over its Unix socket and the endpoint is running",
                    "the endpoint listens on its loopback TCP port",
                    "the host name's certificate lineage is present and readable",
                ),
                inverse=(
                    "stop and remove only the trusttunnel-manager Compose service",
                    "remove only the owned env overlay and marker",
                    "preserve the state directory (credentials) and the manager secret unless purge is explicit",
                ),
                credentials_required=True,
            ),
        )

    @staticmethod
    def _assert_free_tcp(facts: AuditFacts, port: int) -> None:
        listeners = facts.listeners if isinstance(facts.listeners, Mapping) else {}
        observed = listeners.get("tcp")
        if not isinstance(observed, Sequence) or isinstance(observed, (str, bytes)):
            return
        if port not in {int(value) for value in observed if isinstance(value, int)}:
            return
        owners = listeners.get("owners")
        holders = owners.get(str(port)) if isinstance(owners, Mapping) else None
        if isinstance(holders, Sequence) and not isinstance(holders, (str, bytes)) and holders \
                and set(holders) <= {"trusttunnel_endpoint", "trusttunnel_end"}:
            return
        raise PlanError(f"TrustTunnel port {port}/tcp is already claimed by another listener")

    def _selection(self, action: Action) -> dict[str, object]:
        if action.id != "trusttunnel.runtime" or action.adapter != self.name or action.owner != "proxy-control:trusttunnel":
            raise TrustTunnelError("TrustTunnel action is invalid")
        values: dict[str, str] = {}
        for item in action.mutations:
            key, separator, value = item.partition("=")
            if not separator or key in values:
                raise TrustTunnelError("TrustTunnel action is invalid")
            values[key] = value
        required = {"project", "state-dir", "letsencrypt-dir", "hostname", "listen", "metrics", "version",
                    "sha256", "socket-gid", "container"}
        if set(values) != required:
            raise TrustTunnelError("TrustTunnel action is invalid")
        if (
            values["project"] != self.paths.project_dir
            or values["state-dir"] != self.paths.state_dir
            or values["letsencrypt-dir"] != self.paths.letsencrypt_dir
            or values["socket-gid"] != str(_SOCKET_GID)
            or values["container"] != _CONTAINER
            or values["metrics"] != f"127.0.0.1:{TT_METRICS_PORT}"
            or _VERSION.fullmatch(values["version"]) is None
            or _HEX_64.fullmatch(values["sha256"]) is None
        ):
            raise TrustTunnelError("TrustTunnel action is invalid")
        hostname = values["hostname"]
        if not _DOMAIN.fullmatch(hostname):
            raise TrustTunnelError("invalid TrustTunnel host name")
        match = _LOOPBACK.fullmatch(values["listen"])
        if match is None or not 1024 <= int(match.group(1)) <= 65535 or int(match.group(1)) == TT_METRICS_PORT:
            raise TrustTunnelError("invalid TrustTunnel listen address")
        return {
            "hostname": hostname,
            "listen": values["listen"],
            "port": int(match.group(1)),
            "version": values["version"],
            "sha256": values["sha256"],
        }

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def prepare(self, action: Action) -> Mapping[str, object]:
        self._selection(action)
        marker = self._host(self.paths.marker)
        adoption = "recovery" if marker.is_file() and not marker.is_symlink() else "absent"
        if adoption == "absent" and self._compose_service_present():
            raise TrustTunnelError("an active trusttunnel-manager service requires a proven owned recovery generation")
        return {
            "owner": action.owner,
            "adoption": adoption,
            "marker_value": secrets.token_hex(16) if adoption == "absent" else None,
            "state_preexisting": self._host(self.paths.state_dir).is_dir(),
            "token_preexisting": self._host(self.paths.manager_token).is_file(),
            "ownership": {},
        }

    def apply(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action)
        # 1. Host prerequisites the container cannot create: the state directory; the lineage
        #    must exist (the certificates step issued it).
        self._prepare_dir(self.paths.state_dir)
        self._require_certificate(str(selected["hostname"]))
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
        return (
            f"TRUSTTUNNEL_MANAGER_TOKEN_FILE={self.paths.manager_token}\n"
            f"TT_MANAGER_STATE_DIR={self.paths.state_dir}\n"
            f"TT_CERT_DIR={self.paths.letsencrypt_dir}\n"
            f"TT_HOSTNAME={selected['hostname']}\n"
            f"TT_LISTEN={selected['listen']}\n"
            f"TT_VERSION=v{selected['version']}\n"
            f"TT_SHA256_X86_64={selected['sha256']}\n"
            f"TT_SHA256_AARCH64={TT_SHA256_AARCH64}\n"
            f"TRUSTTUNNEL_MANAGER_SOCKET_GID={_SOCKET_GID}\n"
            f"TRUSTTUNNEL_PUBLIC_HOST={selected['hostname']}\n"
        )

    def verify(self, action: Action) -> Evidence:
        selected = self._selection(action)
        hostname, port = str(selected["hostname"]), int(selected["port"])  # type: ignore[call-overload]
        state = self._host(self.paths.state_dir)
        if state.is_symlink() or not state.is_dir():
            raise TrustTunnelError("the TrustTunnel state directory is missing")
        self._require_certificate(hostname)
        health = getattr(self.runner, "container_health", None)
        if not callable(health) or health() != "healthy":
            raise TrustTunnelError("the trusttunnel-manager container is not healthy")
        reader = getattr(self.runner, "manager_health", None)
        if not callable(reader):
            raise TrustTunnelError("TrustTunnel manager health is unavailable")
        report = reader()
        endpoint = report.get("endpoint") if isinstance(report, Mapping) else None
        if (
            not isinstance(report, Mapping)
            or report.get("status") != "ok"
            or not isinstance(endpoint, Mapping)
            or endpoint.get("running") is not True
        ):
            raise TrustTunnelError("the TrustTunnel manager does not report a healthy endpoint")
        listener = getattr(self.runner, "tcp_listener", None)
        if not callable(listener):
            raise TrustTunnelError("TCP listener verification is unavailable")
        if not listener(port):
            raise TrustTunnelError(f"the TrustTunnel endpoint does not listen on 127.0.0.1:{port}")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the trusttunnel-manager container is healthy and answers over its Unix socket",
                "the TrustTunnel endpoint is running and bound to its loopback TCP port",
                "TrustTunnel shares TCP/443 through the SNI router: no UDP port was opened and no firewall rule added",
                "the host name needs an A record to this server and must not be proxied by a CDN",
            ),
            details={"hostname": hostname, "listen": f"127.0.0.1:{port}", "version": str(selected["version"])},
        )

    def repair(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._prepare_dir(self.paths.state_dir)
        self._require_certificate(str(selected["hostname"]))
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
        for absolute in (self.paths.env_overlay, self.paths.marker):
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
                "the TrustTunnel runtime was removed",
                "the state directory and the manager secret were purged"
                if destructive_purge
                else "the state directory (credentials) and the manager secret were preserved",
            ),
            details={"persistent_data_preserved": not destructive_purge},
        )

    reconcile_rollback = rollback

    # ------------------------------------------------------------------
    # checkpoint
    # ------------------------------------------------------------------

    def _checkpoint(self, checkpoint: Mapping[str, object], action: Action, *, applied: bool = False) -> dict[str, object]:
        required = {"owner", "adoption", "marker_value", "state_preexisting", "token_preexisting", "ownership"}
        if set(checkpoint) != required:
            raise TrustTunnelError("TrustTunnel checkpoint is invalid")
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
            or any(not isinstance(checkpoint[name], bool) for name in ("state_preexisting", "token_preexisting"))
        ):
            raise TrustTunnelError("TrustTunnel checkpoint is invalid")
        return {name: checkpoint[name] for name in required}

    def _ownership(self) -> dict[str, str]:
        """Digests of what this generation wrote and rollback may remove: never a secret's content."""
        owned: dict[str, str] = {}
        for absolute in (self.paths.env_overlay, self.paths.marker):
            path = self._host(absolute)
            if path.is_file():
                owned[absolute] = _file_sha256(path)
        return owned

    # ------------------------------------------------------------------
    # steps
    # ------------------------------------------------------------------

    def _prepare_dir(self, absolute: str, *, mode: int = 0o700) -> None:
        path = self._host(absolute)
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise TrustTunnelError("TrustTunnel directory path is occupied")
        durable_mkdir(path.parent, mode=0o755)
        durable_mkdir(path, mode=mode)
        os.chmod(path, mode)
        if self.root == Path("/") and os.geteuid() == 0:
            os.chown(path, 0, 0)

    def _require_certificate(self, hostname: str) -> None:
        """The host name's lineage (the `certificates` step issues it); the manager reads it
        through its read-only mount of /etc/letsencrypt."""
        lineage = self._host(f"{self.paths.lineage_root}/{hostname}")
        if not (lineage / "fullchain.pem").is_file() or not (lineage / "privkey.pem").is_file():
            raise TrustTunnelError(
                f"the certificate for {hostname} is missing: the certificates step must issue it first"
            )

    def _write_token(self) -> None:
        """The manager token; an existing one is kept so the panel's copy never breaks."""
        token = self._host(self.paths.manager_token)
        durable_mkdir(token.parent, mode=0o700)
        if not (token.exists() or token.is_symlink()):
            self._atomic(token, (secrets.token_hex(32) + "\n").encode("ascii"), 0o600)
        if token.is_symlink() or not token.is_file():
            raise TrustTunnelError("pre-existing TrustTunnel secret is unsafe")
        metadata = token.stat()
        if metadata.st_mode & 0o077 or (self.root == Path("/") and metadata.st_uid != 0):
            raise TrustTunnelError("pre-existing TrustTunnel secret is unsafe")
        if not 32 <= len(token.read_text().strip()) <= 512:
            raise TrustTunnelError("the TrustTunnel manager secret is malformed")

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
        for sibling in ("naive", "mieru", "xray-router", "amneziawg"):
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
        except TrustTunnelError:
            raise
        except Exception as exc:
            raise TrustTunnelError(_command_failure(argv)) from exc
        if getattr(result, "returncode", 0):
            from installer.adapters.nginx import _sanitize_diagnostic
            stderr = getattr(result, "stderr", "") or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            raise TrustTunnelError(f"{_command_failure(argv)}; {_sanitize_diagnostic(str(stderr))}")

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise TrustTunnelError("TrustTunnel host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise TrustTunnelError("TrustTunnel root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise TrustTunnelError("TrustTunnel host path crosses an unsafe parent")
        return self.root / relative

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        durable_mkdir(path.parent)
        atomic_write(path, data, mode=mode, owner=owner)
