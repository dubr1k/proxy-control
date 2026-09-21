"""Installer-owned version-agent (v0.11).

Before v0.11 the agent was a manual step from UPGRADING; a real install then had no env,
no catalog and no state, and the «Версии» screen stayed empty. This adapter runs last: it
copies the agent's code out of the release tree, installs its unit and tmpfiles fragment,
writes the env from the shipped example with the profile's Compose overlays and the router
flag, seeds an empty catalog and a state that records exactly what the installer just
installed (the agent's `current`), starts the unit and waits for `/v1/health`.

The catalog and the state are the operator's and the agent's: written only when absent,
never owned, kept on rollback unless the purge is explicit.
"""
from __future__ import annotations

import json
import re
import secrets
import stat
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from installer.adapters import mieru as _mieru
from installer.adapters import naive as _naive
from installer.adapters import xray_router as _xray
from installer.adapters.core import _DefaultCoreRunner, _file_sha256
from installer.model import InstallerConfig
from installer.planner import Action, AuditFacts, Evidence, compose_file_list
from installer.transaction import atomic_write, durable_mkdir, durable_remove, fsync_directory

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_PROJECT = "/opt/mtproxy-shared443"
_AGENT_DIR = "/opt/proxy-control"
_UNIT = "/etc/systemd/system/version-agent.service"
_TMPFILES = "/etc/tmpfiles.d/proxy-control-version-agent.conf"
_ENV = "/etc/proxy-control/version-agent.env"
_CATALOG = "/etc/proxy-control/versions.json"
_STATE_DIR = "/var/lib/proxy-control/version-agent"
_SOCKET = "/run/proxy-control/version-agent.sock"
_MARKER = "/etc/proxy-control/version-agent-owned"
_UNIT_NAME = "version-agent"
_SOCKET_GID = 10001
_CODE_PACKAGE = "version_agent"
_UNIT_SOURCE = "deploy/version-agent.service"
_TMPFILES_SOURCE = "deploy/proxy-control-version-agent.tmpfiles.conf"
_ENV_EXAMPLE = "deploy/version-agent.env.example"
_COMPOSE_SOURCE = "compose.yaml"
_TELEMT_SERVICE = "mtproxy"
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_IMAGE_DIGEST = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:([0-9a-f]{64})\Z")
_COMPOSE_FILE = re.compile(r"\Acompose(\.[a-z-]+)?\.yaml\Z")
_HEALTH_DEADLINE_SECONDS = 30.0
_HEALTH_RETRY_SECONDS = 1.0
# `/v1/versions` with cached upstream candidates outgrows the Core runner's 4 KiB
# diagnostic bound; one megabyte is far above any answer the agent gives.
_JSON_LIMIT = 1_048_576
_ROUTER_KEY = _xray._AGENT_ROUTER_KEY


class VersionAgentError(RuntimeError):
    """The version-agent ownership boundary cannot be changed safely."""


class _DefaultVersionAgentRunner(_DefaultCoreRunner):
    """The Core runner, with a capture wide enough for the agent's JSON."""

    def capture(self, argv, *, max_chars: int) -> str:
        limit = min(max(max_chars, 0), _JSON_LIMIT)
        try:
            completed = subprocess.run(
                [str(value) for value in argv], check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=min(self.timeout, 15.0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"diagnostic unavailable: {type(exc).__name__}"[:limit]
        output = completed.stdout or ""
        if completed.returncode:
            output = f"exit={completed.returncode} {output}"
        return output[-limit:]


@dataclass(frozen=True)
class VersionAgentPaths:
    """Fixed host paths of one version-agent generation."""

    agent_dir: str = _AGENT_DIR
    unit: str = _UNIT
    tmpfiles: str = _TMPFILES
    env: str = _ENV
    catalog: str = _CATALOG
    state_dir: str = _STATE_DIR
    socket: str = _SOCKET
    project_dir: str = _PROJECT
    marker: str = _MARKER

    def __post_init__(self) -> None:
        for value in (self.agent_dir, self.unit, self.tmpfiles, self.env, self.catalog, self.state_dir,
                      self.socket, self.project_dir, self.marker):
            if not value.startswith("/") or ".." in Path(value).parts or value == "/":
                raise ValueError("version-agent path must be a normalized absolute path")

    @property
    def code_dir(self) -> str:
        return f"{self.agent_dir}/{_CODE_PACKAGE}"

    @property
    def state(self) -> str:
        return f"{self.state_dir}/state.json"


class VersionAgentAdapter:
    """Own the agent's code, unit, tmpfiles, env and ownership marker — never its data."""

    name = "version_agent"
    requires = frozenset({"core"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        source_dir: Path | None = None,
        paths: VersionAgentPaths | None = None,
    ) -> None:
        self.root = Path(root)
        self.runner = runner if runner is not None else _DefaultVersionAgentRunner()
        self.source_dir = Path(source_dir or Path(__file__).resolve().parents[2])
        self.paths = paths or VersionAgentPaths()

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        del facts  # nothing on the host decides this boundary; the profile does
        egress = config.effective_egress
        flag = {True: "on", False: "off"}
        return (
            Action(
                id="version_agent.runtime",
                adapter=self.name,
                owner="proxy-control:version-agent",
                mutations=(
                    f"project={self.paths.project_dir}",
                    f"agent-dir={self.paths.agent_dir}",
                    f"socket={self.paths.socket}",
                    f"socket-gid={_SOCKET_GID}",
                    f"compose-files={':'.join(compose_file_list(config))}",
                    f"router={flag[bool(egress.router)]}",
                    f"naive={flag[bool(config.profile.includes_naive)]}",
                    f"mieru={flag[bool(config.profile.includes_mieru)]}",
                    "upstream=on",
                ),
                preconditions=(
                    "the Core runtime is verified",
                    "no foreign version-agent unit, env or code directory exists without the ownership marker",
                ),
                verification=(
                    "the version-agent unit is active and enabled",
                    "/v1/health answers ok over the group-10001 socket",
                    "/v1/versions lists the profile's components at the versions the installer recorded",
                    "the env names the profile's Compose overlays and the router flag",
                ),
                inverse=(
                    "disable the unit and remove only the owned unit, tmpfiles, env, code and marker",
                    "preserve the catalog and the agent state unless purge is explicit",
                ),
                credentials_required=False,
            ),
        )

    def _selection(self, action: Action) -> dict[str, object]:
        if action.id != "version_agent.runtime" or action.adapter != self.name or action.owner != "proxy-control:version-agent":
            raise VersionAgentError("version-agent action is invalid")
        values: dict[str, str] = {}
        for item in action.mutations:
            key, separator, value = item.partition("=")
            if not separator or key in values:
                raise VersionAgentError("version-agent action is invalid")
            values[key] = value
        required = {"project", "agent-dir", "socket", "socket-gid", "compose-files", "router", "naive", "mieru", "upstream"}
        if set(values) != required:
            raise VersionAgentError("version-agent action is invalid")
        flags = {name: values[name] for name in ("router", "naive", "mieru", "upstream")}
        compose_files = tuple(values["compose-files"].split(":"))
        if (
            values["project"] != self.paths.project_dir
            or values["agent-dir"] != self.paths.agent_dir
            or values["socket"] != self.paths.socket
            or values["socket-gid"] != str(_SOCKET_GID)
            or any(flag not in {"on", "off"} for flag in flags.values())
            or flags["upstream"] != "on"
            or not compose_files
            or compose_files[0] != "compose.yaml"
            or any(_COMPOSE_FILE.fullmatch(name) is None for name in compose_files)
            or len(set(compose_files)) != len(compose_files)
            or ("compose.naive.yaml" in compose_files) != (flags["naive"] == "on")
            or ("compose.mieru.yaml" in compose_files) != (flags["mieru"] == "on")
            or ("compose.xray-router.yaml" in compose_files) != (flags["router"] == "on")
        ):
            raise VersionAgentError("version-agent action is invalid")
        return {"compose_files": compose_files, **{name: flag == "on" for name, flag in flags.items()}}

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def prepare(self, action: Action) -> Mapping[str, object]:
        self._selection(action)
        marker = self._host(self.paths.marker)
        if marker.is_file() and not marker.is_symlink():
            value = marker.read_text(encoding="utf-8").strip()
            if _HEX_32.fullmatch(value) is None:
                raise VersionAgentError("version-agent ownership marker is invalid")
            return {"owner": action.owner, "adoption": "recovery", "marker_value": value, "ownership": {}}
        # The env is not a foreign sign: the Xray-router adapter writes its flag there first.
        for absolute in (self.paths.unit, self.paths.code_dir):
            path = self._host(absolute)
            if path.exists() or path.is_symlink():
                raise VersionAgentError(f"foreign version-agent installation ({absolute}) requires explicit migration")
        return {"owner": action.owner, "adoption": "absent", "marker_value": secrets.token_hex(16), "ownership": {}}

    def apply(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action)
        self._assert_marker(prepared, missing_ok=True)
        was_active = self._unit_active()
        self._install_code()
        self._install_deploy_files()
        self._write_env(selected)
        self._seed_catalog()
        self._seed_state(selected)
        self._run("systemctl", "daemon-reload")
        self._run("systemd-tmpfiles", "--create", self.paths.tmpfiles)
        self._run("systemctl", "enable", "--now", _UNIT_NAME)
        if was_active:
            # `enable --now` leaves a running unit alone; a repair must load the new code and env.
            self._run("systemctl", "restart", _UNIT_NAME)
        self._wait_healthy()
        self._atomic(self._host(self.paths.marker), (str(prepared["marker_value"]) + "\n").encode(), 0o600)
        return {**prepared, "ownership": self._ownership()}

    reconcile_apply = apply

    def repair(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._assert_marker(prepared, missing_ok=False)
        return self.apply(action, {**prepared, "ownership": {}})

    def verify(self, action: Action) -> Evidence:
        selected = self._selection(action)
        for check, expected in (("is-active", "active"), ("is-enabled", "enabled")):
            if self._capture("systemctl", check, _UNIT_NAME, max_chars=64).strip() != expected:
                raise VersionAgentError("the version-agent unit is not active and enabled")
        self._assert_socket()
        health = self._agent_json("/v1/health")
        if health != {"status": "ok"}:
            raise VersionAgentError("the version-agent did not answer /v1/health with ok")
        versions = self._agent_json("/v1/versions")
        if versions.get("enabled") is not True:
            raise VersionAgentError("the version-agent reports itself not enabled")
        listed = versions.get("components")
        if not isinstance(listed, Mapping):
            raise VersionAgentError("the version-agent lists no components")
        recorded = self._recorded_versions()
        current: dict[str, str | None] = {}
        for component in self._profile_components(selected):
            entry = listed.get(component)
            if not isinstance(entry, Mapping):
                raise VersionAgentError(f"the version-agent does not list the {component} component")
            if entry.get("current") != recorded.get(component):
                raise VersionAgentError(f"the version-agent reports {component} at a version the state does not record")
            current[component] = entry.get("current")
        self._assert_env(selected)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the version-agent is active, enabled and healthy over its socket",
                "it lists the profile's components at the recorded versions",
            ),
            details={"components": current},
        )

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
        self._assert_marker(prepared, missing_ok=False)
        if self._host(self.paths.unit).exists():
            self._run("systemctl", "disable", "--now", _UNIT_NAME)
        for absolute in (self.paths.unit, self.paths.tmpfiles, self.paths.env, self.paths.socket):
            durable_remove(self._host(absolute), missing_ok=True)
        code = self._host(self.paths.code_dir)
        if code.is_symlink():
            raise VersionAgentError("version-agent code directory is a symlink")
        durable_remove(code, missing_ok=True)
        agent_dir = self._host(self.paths.agent_dir)
        if agent_dir.is_dir() and not agent_dir.is_symlink() and not any(agent_dir.iterdir()):
            durable_remove(agent_dir)
        if purge_data:
            state_dir = self._host(self.paths.state_dir)
            if state_dir.is_symlink():
                raise VersionAgentError("version-agent state directory is a symlink")
            durable_remove(state_dir, missing_ok=True)
            durable_remove(self._host(self.paths.catalog), missing_ok=True)
        durable_remove(self._host(self.paths.marker))
        self._run("systemctl", "daemon-reload")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the version-agent unit, code, env and marker were removed",
                "the catalog and the agent state were purged" if purge_data else "the catalog and the agent state were preserved",
            ),
            details={"persistent_data_preserved": not purge_data},
        )

    reconcile_rollback = rollback

    # ------------------------------------------------------------------
    # checkpoint and ownership
    # ------------------------------------------------------------------

    def _checkpoint(self, checkpoint: Mapping[str, object], action: Action, *, applied: bool = False) -> dict[str, object]:
        required = {"owner", "adoption", "marker_value", "ownership"}
        if set(checkpoint) != required:
            raise VersionAgentError("version-agent checkpoint is invalid")
        marker_value = checkpoint["marker_value"]
        ownership = checkpoint["ownership"]
        if (
            checkpoint["owner"] != action.owner
            or checkpoint["adoption"] not in {"absent", "recovery"}
            or not isinstance(marker_value, str)
            or _HEX_32.fullmatch(marker_value) is None
            or not isinstance(ownership, Mapping)
            or (not applied and ownership)
        ):
            raise VersionAgentError("version-agent checkpoint is invalid")
        return {name: checkpoint[name] for name in required}

    def _assert_marker(self, prepared: Mapping[str, object], *, missing_ok: bool) -> None:
        marker = self._host(self.paths.marker)
        if marker.is_symlink() or (marker.exists() and not marker.is_file()):
            raise VersionAgentError("version-agent ownership marker is unsafe")
        if not marker.exists():
            if missing_ok:
                return
            raise VersionAgentError("version-agent ownership marker is missing")
        if marker.read_text(encoding="utf-8").strip() != prepared["marker_value"]:
            raise VersionAgentError("version-agent ownership marker drifted")

    def _ownership(self) -> dict[str, object]:
        """Digests of what this generation wrote and rollback removes: never the data."""
        owned: dict[str, object] = {}
        for absolute in (self.paths.unit, self.paths.tmpfiles, self.paths.marker):
            owned[absolute] = _file_sha256(self._host(absolute))
        # UPGRADING tells the operator to edit the env (the upstream switch), so its
        # digest is recorded but never treated as foreign drift.
        owned[self.paths.env] = {"sha256": _file_sha256(self._host(self.paths.env)), "mutable": True}
        code = self._host(self.paths.code_dir)
        for path in sorted(code.glob("*.py")):
            owned[f"{self.paths.code_dir}/{path.name}"] = _file_sha256(path)
        return owned

    # ------------------------------------------------------------------
    # steps
    # ------------------------------------------------------------------

    def _install_code(self) -> None:
        source = self.source_dir / _CODE_PACKAGE
        if not source.is_dir() or source.is_symlink():
            raise VersionAgentError("installer source generation is incomplete")
        files = sorted(path for path in source.iterdir() if path.suffix == ".py")
        if not files or any(path.is_symlink() or not path.is_file() for path in files):
            raise VersionAgentError("installer source generation is incomplete")
        agent_dir = self._host(self.paths.agent_dir)
        code = self._host(self.paths.code_dir)
        for directory in (agent_dir, code):
            if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                raise VersionAgentError("version-agent code path is occupied")
            durable_mkdir(directory, mode=0o755)
            directory.chmod(0o755)
        names = {path.name for path in files}
        for stale in sorted(code.iterdir()):
            if stale.suffix == ".py" and stale.name not in names:
                durable_remove(stale)
        for path in files:
            self._atomic(code / path.name, path.read_bytes(), 0o644)
        fsync_directory(code)

    def _install_deploy_files(self) -> None:
        for relative, absolute in ((_UNIT_SOURCE, self.paths.unit), (_TMPFILES_SOURCE, self.paths.tmpfiles)):
            source = self.source_dir / relative
            if source.is_symlink() or not source.is_file():
                raise VersionAgentError("installer source generation is incomplete")
            self._atomic(self._host(absolute), source.read_bytes(), 0o644)

    def env_text(self, selected: Mapping[str, object], existing: str) -> str:
        """The shipped example with the profile's values; extra keys of an existing file survive."""
        example = self.source_dir / _ENV_EXAMPLE
        if example.is_symlink() or not example.is_file():
            raise VersionAgentError("installer source generation is incomplete")
        example_lines = example.read_text(encoding="utf-8").splitlines()
        example_values = _env_values(example_lines)
        compose_files = selected["compose_files"]
        assert isinstance(compose_files, tuple)
        overrides = {
            "PROXY_CONTROL_COMPOSE_DIR": self.paths.project_dir,
            "PROXY_CONTROL_COMPOSE_FILES": ":".join(compose_files),
            _ROUTER_KEY: "on" if selected["router"] else "off",
            "PROXY_CONTROL_UPSTREAM_CHECK": "on",
            "PROXY_CONTROL_CONSUMER_OVERLAYS": example_values.get("PROXY_CONTROL_CONSUMER_OVERLAYS", "") if selected["mieru"] else "",
            "PROXY_CONTROL_VERSION_SOCKET": self.paths.socket,
            "PROXY_CONTROL_VERSION_SOCKET_GID": str(_SOCKET_GID),
            "PROXY_CONTROL_VERSION_CATALOG": self.paths.catalog,
            "PROXY_CONTROL_VERSION_STATE": self.paths.state,
        }
        rendered: list[str] = []
        seen: set[str] = set()
        for line in example_lines:
            key = _env_key(line)
            if key is None:
                rendered.append(line)
                continue
            seen.add(key)
            rendered.append(f"{key}={overrides[key]}" if key in overrides else line)
        for key in overrides:
            if key not in seen:
                rendered.append(f"{key}={overrides[key]}")
                seen.add(key)
        for line in existing.splitlines():
            key = _env_key(line)
            if key is not None and key not in seen:
                rendered.append(line)
                seen.add(key)
        return "".join(f"{line}\n" for line in rendered)

    def _write_env(self, selected: Mapping[str, object]) -> None:
        path = self._host(self.paths.env)
        if path.is_symlink():
            raise VersionAgentError("version-agent env file is a symlink")
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        self._atomic(path, self.env_text(selected, existing).encode(), 0o600)

    def _seed_catalog(self) -> None:
        path = self._host(self.paths.catalog)
        if path.exists() or path.is_symlink():
            return
        self._atomic(path, (json.dumps({"schema": 1, "components": {}}, indent=2) + "\n").encode(), 0o600)

    def _seed_state(self, selected: Mapping[str, object]) -> None:
        path = self._host(self.paths.state)
        if path.exists() or path.is_symlink():
            return
        state_dir = self._host(self.paths.state_dir)
        if state_dir.is_symlink() or (state_dir.exists() and not state_dir.is_dir()):
            raise VersionAgentError("version-agent state path is occupied")
        durable_mkdir(state_dir, mode=0o700)
        state_dir.chmod(0o700)
        state = {"schema": 2, "components": self.installed_components(selected)}
        self._atomic(path, (json.dumps(state, indent=2, sort_keys=True) + "\n").encode(), 0o600)

    def installed_components(self, selected: Mapping[str, object]) -> dict[str, dict[str, object]]:
        """What the installer's own adapters put on the host, in the agent's state shape."""
        now = int(time.time())
        components: dict[str, dict[str, object]] = {
            "telemt": {"version": None, "kind": "image", "source": "catalog", "image": None, "updated_at": now},
        }
        image = self._telemt_image()
        digest = _IMAGE_DIGEST.fullmatch(image)
        if digest is None:
            raise VersionAgentError("compose.yaml does not pin the Telemt image by digest")
        components["telemt"]["image"] = image
        # The repository does not name the Telemt version; the digest prefix is a valid
        # catalog version and is what a later catalog or upstream entry compares against.
        components["telemt"]["version"] = f"sha256:{digest.group(1)[:12]}"
        if selected["naive"]:
            caddy = self._host(_naive._CADDY_BINARY)
            pin = self._host(_naive._PIN)
            runtime = pin.read_text(encoding="utf-8").strip() if pin.is_file() and not pin.is_symlink() else ""
            components["naive"] = {
                "version": _naive._CADDY_VERSION.split()[0].lstrip("v"),
                "kind": "build",
                "source": "catalog",
                "sha256": self._binary_sha256(caddy, "caddy"),
                "runtime_version": runtime or _naive._CADDY_VERSION,
                "updated_at": now,
            }
        if selected["mieru"]:
            components["mita"] = {
                "version": _mieru._MITA_VERSION,
                "kind": "binary",
                "source": "catalog",
                "sha256": self._binary_sha256(self._host(_mieru._MITA_BINARY), "mita"),
                "updated_at": now,
            }
        if selected["router"]:
            _url, archive_sha256, _members = _xray._XRAY_PINS["amd64"]
            bin_dir = self._host(_xray._BIN_DIR)
            components["xray"] = {
                "version": _xray._XRAY_VERSION,
                "kind": "binary",
                "source": "catalog",
                "sha256": archive_sha256,
                "members": {member: self._binary_sha256(bin_dir / member, member) for member in _xray._MEMBERS},
                "updated_at": now,
            }
        return components

    def _telemt_image(self) -> str:
        compose = self.source_dir / _COMPOSE_SOURCE
        if compose.is_symlink() or not compose.is_file():
            raise VersionAgentError("installer source generation is incomplete")
        inside = False
        for line in compose.read_text(encoding="utf-8").splitlines():
            if line.startswith("  ") and not line.startswith("   ") and line.strip().endswith(":"):
                inside = line.strip() == f"{_TELEMT_SERVICE}:"
                continue
            if inside:
                key, separator, value = line.strip().partition(":")
                if separator and key == "image":
                    return value.strip().strip("'\"")
        raise VersionAgentError("compose.yaml names no Telemt image")

    @staticmethod
    def _binary_sha256(path: Path, label: str) -> str:
        if path.is_symlink() or not path.is_file():
            raise VersionAgentError(f"the installed {label} is missing; the version-agent state cannot record it")
        return _file_sha256(path)

    def _recorded_versions(self) -> dict[str, str | None]:
        path = self._host(self.paths.state)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VersionAgentError("the version-agent state is unreadable") from exc
        components = raw.get("components") if isinstance(raw, Mapping) else None
        if not isinstance(components, Mapping):
            raise VersionAgentError("the version-agent state is invalid")
        return {name: entry.get("version") if isinstance(entry, Mapping) else None for name, entry in components.items()}

    @staticmethod
    def _profile_components(selected: Mapping[str, object]) -> tuple[str, ...]:
        return ("telemt", *(("naive",) if selected["naive"] else ()), *(("mita",) if selected["mieru"] else ()),
                *(("xray",) if selected["router"] else ()))

    def _assert_env(self, selected: Mapping[str, object]) -> None:
        path = self._host(self.paths.env)
        if path.is_symlink() or not path.is_file():
            raise VersionAgentError("the version-agent env file is missing")
        values = _env_values(path.read_text(encoding="utf-8").splitlines())
        compose_files = selected["compose_files"]
        assert isinstance(compose_files, tuple)
        expected = {_ROUTER_KEY: "on" if selected["router"] else "off", "PROXY_CONTROL_COMPOSE_FILES": ":".join(compose_files)}
        for key, value in expected.items():
            if values.get(key) != value:
                raise VersionAgentError(f"the version-agent env does not set {key} as planned")

    def _assert_socket(self) -> None:
        path = self._host(self.paths.socket)
        try:
            info = path.lstat()
        except OSError as exc:
            raise VersionAgentError("the version-agent socket is absent") from exc
        if not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o660:
            raise VersionAgentError("the version-agent socket is not a 0660 socket")
        if self.root == Path("/") and info.st_gid != _SOCKET_GID:
            raise VersionAgentError(f"the version-agent socket is not group {_SOCKET_GID}")

    def _wait_healthy(self) -> None:
        deadline = time.monotonic() + _HEALTH_DEADLINE_SECONDS
        while True:
            try:
                if self._agent_json("/v1/health") == {"status": "ok"}:
                    return
            except VersionAgentError:
                pass
            if time.monotonic() >= deadline:
                raise VersionAgentError(f"the version-agent did not answer /v1/health within {_HEALTH_DEADLINE_SECONDS:.0f} seconds")
            time.sleep(_HEALTH_RETRY_SECONDS)

    def _agent_json(self, path: str) -> Mapping[str, object]:
        output = self._capture(
            "curl", "--fail", "--silent", "--show-error", "--max-time", "5",
            "--unix-socket", self.paths.socket, f"http://{_UNIT_NAME}{path}", max_chars=_JSON_LIMIT,
        )
        if output.startswith(("exit=", "diagnostic ")):
            raise VersionAgentError(f"the version-agent did not answer {path}")
        try:
            value = json.loads(output)
        except ValueError as exc:
            raise VersionAgentError(f"the version-agent answer to {path} is not JSON") from exc
        if not isinstance(value, Mapping):
            raise VersionAgentError(f"the version-agent answer to {path} is not an object")
        return value

    def _unit_active(self) -> bool:
        return self._capture("systemctl", "is-active", _UNIT_NAME, max_chars=64).strip() == "active"

    # ------------------------------------------------------------------
    # host boundary
    # ------------------------------------------------------------------

    def _capture(self, *argv: str, max_chars: int) -> str:
        capture = getattr(self.runner, "capture", None)
        if not callable(capture):
            raise VersionAgentError("version-agent runner cannot capture output")
        try:
            return str(capture(argv, max_chars=max_chars))
        except VersionAgentError:
            raise
        except Exception as exc:
            raise VersionAgentError(_command_failure(argv)) from exc

    def _run(self, *argv: str) -> None:
        try:
            result = self.runner.run(argv)
        except VersionAgentError:
            raise
        except Exception as exc:
            raise VersionAgentError(_command_failure(argv)) from exc
        if getattr(result, "returncode", 0):
            from installer.adapters.nginx import _sanitize_diagnostic
            stderr = getattr(result, "stderr", "") or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            raise VersionAgentError(f"{_command_failure(argv)}; {_sanitize_diagnostic(str(stderr))}")

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise VersionAgentError("version-agent host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise VersionAgentError("version-agent root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise VersionAgentError("version-agent host path crosses an unsafe parent")
        return self.root / relative

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        import os

        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        durable_mkdir(path.parent)
        atomic_write(path, data, mode=mode, owner=owner)


def _env_key(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    return stripped.split("=", 1)[0].strip()


def _env_values(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        key = _env_key(line)
        if key is not None and key not in values:
            values[key] = line.strip().split("=", 1)[1]
    return values


def _command_failure(argv: tuple[str, ...]) -> str:
    program = Path(str(argv[0])).name if argv else "command"
    subcommand = ""
    for value in list(argv)[1:3]:
        rendered = str(value)
        if rendered.startswith("-") or "/" in rendered:
            break
        subcommand += f" {rendered}"
    return f"version-agent command failed: {program}{subcommand}"
