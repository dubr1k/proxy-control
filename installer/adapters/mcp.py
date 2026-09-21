"""Installer-owned MCP server (v0.11 §9a).

The `proxy-control-mcp` container (Compose service `mcp`, overlay `compose.mcp.yaml`)
speaks the Model Context Protocol over Streamable HTTP on `127.0.0.1:8793/mcp`. The
outside reaches it through the SNI router on the eleventh name, `domains.mcp`, whose
vhost the Core adapter renders into the panel's file. This adapter owns what the
container needs and nothing else: `.env.mcp` (the two names), the bearer token clients
present, the panel API key of scope `admin` the panel issues for it, the container, and
the ownership marker.

Only the central panel runs it: a node leaves `domains.mcp` empty and this adapter is
never selected there.
"""
from __future__ import annotations

import json
import re
import secrets
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from installer.adapters.core import _DefaultCoreRunner, _file_sha256
from installer.model import InstallerConfig
from installer.planner import Action, AuditFacts, Evidence, compose_file_list
from installer.transaction import atomic_write, durable_mkdir, durable_remove

if TYPE_CHECKING:
    from installer.audit import CommandRunner


_PROJECT = "/opt/mtproxy-shared443"
_MARKER = "/etc/proxy-control/mcp-owned"
_COMPOSE_PROJECT = "mtproxy"
_SERVICE = "mcp"
_CONTAINER = "proxy-control-mcp"
_COMPOSE_OVERLAY = "compose.mcp.yaml"
_PORT = 8793
_TLS_PORT = 8443
_KEY_NAME = "mcp"
_KEY_SCOPE = "admin"
# The protocol overlays extend the same project; their env files ride along whenever
# they exist on the host, in the installer's order (version_agent/service.py agrees).
_ENV_SIBLINGS = ("naive", "mieru", "xray-router", "mcp")
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_COMPOSE_FILE = re.compile(r"\Acompose(\.[a-z-]+)?\.yaml\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,64}\Z")
_KEY_OUTPUT_LIMIT = 4096
_CURL_TIMEOUT = "15"
_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "installer", "version": "0"},
    },
}


class McpError(RuntimeError):
    """The MCP ownership boundary cannot be changed safely."""


class _DefaultMcpRunner(_DefaultCoreRunner):
    """The Core runner, with a capture patient enough for `compose exec`."""

    def capture(self, argv, *, max_chars: int) -> str:
        limit = min(max(max_chars, 0), _KEY_OUTPUT_LIMIT)
        try:
            completed = subprocess.run(
                [str(value) for value in argv], check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=min(self.timeout, 120.0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"diagnostic unavailable: {type(exc).__name__}"[:limit]
        output = completed.stdout or ""
        if completed.returncode:
            output = f"exit={completed.returncode} {output}"
        return output[-limit:]


@dataclass(frozen=True)
class McpPaths:
    """Fixed host paths of one MCP generation."""

    project_dir: str = _PROJECT
    marker: str = _MARKER

    def __post_init__(self) -> None:
        for value in (self.project_dir, self.marker):
            if not value.startswith("/") or ".." in Path(value).parts or value == "/":
                raise ValueError("MCP path must be a normalized absolute path")

    @property
    def env_overlay(self) -> str:
        return f"{self.project_dir}/.env.mcp"

    @property
    def token(self) -> str:
        return f"{self.project_dir}/secrets/mcp-token"

    @property
    def panel_key(self) -> str:
        return f"{self.project_dir}/secrets/mcp-panel-key"


class McpAdapter:
    """Own the MCP env, token, panel key, container and marker — never the panel's data."""

    name = "mcp"
    requires = frozenset({"core"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | object | None = None,
        paths: McpPaths | None = None,
    ) -> None:
        self.root = Path(root)
        self.runner = runner if runner is not None else _DefaultMcpRunner()
        self.paths = paths or McpPaths()

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        del facts  # the configuration alone decides this boundary
        if config.domains.mcp is None:
            raise McpError("the MCP adapter requires domains.mcp")
        return (
            Action(
                id="mcp.runtime",
                adapter=self.name,
                owner="proxy-control:mcp",
                mutations=(
                    f"project={self.paths.project_dir}",
                    f"domain={config.domains.mcp}",
                    f"panel-domain={config.domains.panel}",
                    f"port={_PORT}",
                    f"compose-files={':'.join(compose_file_list(config))}",
                ),
                preconditions=(
                    "the Core runtime is verified",
                    "no foreign MCP env or secrets exist without the ownership marker",
                ),
                verification=(
                    "the proxy-control-mcp container is healthy",
                    "the MCP name answers 401 without a token and 200 to initialize with it",
                ),
                inverse=(
                    "remove the mcp service, revoke its panel API key, remove only the owned env, secrets and marker",
                ),
                credentials_required=True,
            ),
        )

    def _selection(self, action: Action) -> dict[str, object]:
        if action.id != "mcp.runtime" or action.adapter != self.name or action.owner != "proxy-control:mcp":
            raise McpError("MCP action is invalid")
        values: dict[str, str] = {}
        for item in action.mutations:
            key, separator, value = item.partition("=")
            if not separator or key in values:
                raise McpError("MCP action is invalid")
            values[key] = value
        if set(values) != {"project", "domain", "panel-domain", "port", "compose-files"}:
            raise McpError("MCP action is invalid")
        domain = values["domain"].lower()
        panel_domain = values["panel-domain"].lower()
        compose_files = tuple(values["compose-files"].split(":"))
        if (
            values["project"] != self.paths.project_dir
            or values["port"] != str(_PORT)
            or _DOMAIN.fullmatch(domain) is None
            or _DOMAIN.fullmatch(panel_domain) is None
            or domain == panel_domain
            or not compose_files
            or compose_files[0] != "compose.yaml"
            or _COMPOSE_OVERLAY not in compose_files
            or any(_COMPOSE_FILE.fullmatch(name) is None for name in compose_files)
            or len(set(compose_files)) != len(compose_files)
        ):
            raise McpError("MCP action is invalid")
        return {"domain": domain, "panel_domain": panel_domain, "port": _PORT, "compose_files": compose_files}

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def prepare(self, action: Action) -> Mapping[str, object]:
        self._selection(action)
        marker = self._host(self.paths.marker)
        if marker.is_file() and not marker.is_symlink():
            value = marker.read_text(encoding="utf-8").strip()
            if _HEX_32.fullmatch(value) is None:
                raise McpError("MCP ownership marker is invalid")
            return {"owner": action.owner, "adoption": "recovery", "marker_value": value, "ownership": {}}
        foreign = [self.paths.env_overlay]
        secret_dir = self._host(f"{self.paths.project_dir}/secrets")
        if secret_dir.is_dir() and not secret_dir.is_symlink():
            foreign.extend(f"{self.paths.project_dir}/secrets/{path.name}" for path in sorted(secret_dir.glob("mcp-*")))
        for absolute in foreign:
            path = self._host(absolute)
            if path.exists() or path.is_symlink():
                raise McpError(f"foreign MCP installation ({absolute}) requires explicit migration")
        return {"owner": action.owner, "adoption": "absent", "marker_value": secrets.token_hex(16), "ownership": {}}

    def apply(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action)
        self._assert_marker(prepared, missing_ok=True)
        self._write_env(selected)
        self._write_token()
        self._issue_panel_key(selected)
        self._compose(selected, "up", "-d", "--build", "--no-deps", "--wait", _SERVICE)
        self._atomic(self._host(self.paths.marker), (str(prepared["marker_value"]) + "\n").encode(), 0o600)
        return {**prepared, "ownership": self._ownership()}

    reconcile_apply = apply

    def repair(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._assert_marker(prepared, missing_ok=False)
        return self.apply(action, {**prepared, "ownership": {}})

    def verify(self, action: Action) -> Evidence:
        selected = self._selection(action)
        health = self._capture("docker", "inspect", "--format", "{{.State.Health.Status}}", _CONTAINER, max_chars=64).strip()
        if health != "healthy":
            raise McpError(f"the {_CONTAINER} container is not healthy")
        domain = str(selected["domain"])
        anonymous = self._status(domain)
        if anonymous != "401":
            raise McpError(f"the MCP name answered {anonymous or 'nothing'} without a token instead of 401")
        token = self._read_token()
        authenticated = self._status(
            domain,
            "--request", "POST",
            "--header", "Accept: application/json, text/event-stream",
            "--header", "Content-Type: application/json",
            "--header", f"Authorization: Bearer {token}",
            "--data", json.dumps(_INITIALIZE, separators=(",", ":")),
        )
        if authenticated != "200":
            raise McpError(f"the MCP name answered {authenticated or 'nothing'} to initialize instead of 200")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the proxy-control-mcp container is healthy",
                "the MCP name refuses an anonymous request and answers initialize with a bearer",
            ),
            details={"response_status": 200, "public_host_ok": True},
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
        selected = self._selection(action)
        prepared = self._checkpoint(checkpoint, action, applied=True)
        self._assert_marker(prepared, missing_ok=False)
        self._compose(selected, "rm", "-sf", _SERVICE)
        # Best effort: the panel may already be gone when the whole generation unwinds.
        self._capture(
            *self._compose_argv(selected, "exec", "-T", "panel", "python", "-m", "panel.cli", "api-key-revoke", "--name", _KEY_NAME),
            max_chars=256,
        )
        for absolute in (self.paths.env_overlay, self.paths.panel_key, self.paths.token):
            durable_remove(self._host(absolute), missing_ok=True)
        durable_remove(self._host(self.paths.marker))
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "the mcp service, its env, secrets and marker were removed",
                "the panel API key of the MCP server was revoked",
            ),
            details={"persistent_data_preserved": True},
        )

    reconcile_rollback = rollback

    # ------------------------------------------------------------------
    # checkpoint and ownership
    # ------------------------------------------------------------------

    def _checkpoint(self, checkpoint: Mapping[str, object], action: Action, *, applied: bool = False) -> dict[str, object]:
        required = {"owner", "adoption", "marker_value", "ownership"}
        if set(checkpoint) != required:
            raise McpError("MCP checkpoint is invalid")
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
            raise McpError("MCP checkpoint is invalid")
        return {name: checkpoint[name] for name in required}

    def _assert_marker(self, prepared: Mapping[str, object], *, missing_ok: bool) -> None:
        marker = self._host(self.paths.marker)
        if marker.is_symlink() or (marker.exists() and not marker.is_file()):
            raise McpError("MCP ownership marker is unsafe")
        if not marker.exists():
            if missing_ok:
                return
            raise McpError("MCP ownership marker is missing")
        if marker.read_text(encoding="utf-8").strip() != prepared["marker_value"]:
            raise McpError("MCP ownership marker drifted")

    def _ownership(self) -> dict[str, object]:
        """Digests of what this generation wrote and rollback removes."""
        return {
            absolute: _file_sha256(self._host(absolute))
            for absolute in (self.paths.env_overlay, self.paths.token, self.paths.panel_key, self.paths.marker)
        }

    # ------------------------------------------------------------------
    # steps
    # ------------------------------------------------------------------

    def _write_env(self, selected: Mapping[str, object]) -> None:
        path = self._host(self.paths.env_overlay)
        if path.is_symlink():
            raise McpError("MCP env file is a symlink")
        text = f"MCP_DOMAIN={selected['domain']}\nMCP_PANEL_HOST={selected['panel_domain']}\n"
        self._atomic(path, text.encode(), 0o600)

    def _write_token(self) -> None:
        """A bearer for MCP clients; a valid existing one survives a re-apply, so the
        laptop's configuration keeps working across repairs."""
        path = self._host(self.paths.token)
        if path.is_symlink():
            raise McpError("MCP token file is a symlink")
        if path.is_file() and _TOKEN.fullmatch(path.read_text(encoding="utf-8").strip()):
            path.chmod(0o600)
            return
        self._atomic(path, (secrets.token_urlsafe(32) + "\n").encode(), 0o600)

    def _issue_panel_key(self, selected: Mapping[str, object]) -> None:
        """Ask the panel for an `admin` API key named `mcp` once; the plaintext lands in
        the secret file and nowhere else — not in a log, not in an error."""
        path = self._host(self.paths.panel_key)
        if path.is_symlink():
            raise McpError("MCP panel key file is a symlink")
        if path.is_file():
            path.chmod(0o600)
            return
        output = self._capture(
            *self._compose_argv(
                selected, "exec", "-T", "panel", "python", "-m", "panel.cli",
                "api-key-create", "--name", _KEY_NAME, "--scope", _KEY_SCOPE,
            ),
            max_chars=_KEY_OUTPUT_LIMIT,
        )
        if output.startswith(("exit=", "diagnostic ")):
            raise McpError("the panel did not issue the MCP API key")
        plaintext = _plaintext_of(output)
        if plaintext is None:
            raise McpError("the panel's answer to api-key-create carries no key")
        self._atomic(path, (plaintext + "\n").encode(), 0o600)

    def _read_token(self) -> str:
        path = self._host(self.paths.token)
        if path.is_symlink() or not path.is_file():
            raise McpError("the MCP token is missing")
        value = path.read_text(encoding="utf-8").strip()
        if _TOKEN.fullmatch(value) is None:
            raise McpError("the MCP token is invalid")
        return value

    def _status(self, domain: str, *extra: str) -> str:
        """The HTTP status the MCP name answers on the panel's TLS listener, via SNI."""
        output = self._capture(
            "curl", "--silent", "--output", "/dev/null", "--write-out", "%{http_code}",
            "--max-time", _CURL_TIMEOUT, "--resolve", f"{domain}:{_TLS_PORT}:127.0.0.1",
            *extra, f"https://{domain}:{_TLS_PORT}/mcp", max_chars=64,
        )
        if output.startswith(("exit=", "diagnostic ")):
            return ""
        return output.strip()

    def _compose_argv(self, selected: Mapping[str, object], *args: str) -> tuple[str, ...]:
        """One Compose invocation over the profile's files and every env overlay present."""
        project = self.paths.project_dir
        argv: list[str] = ["docker", "compose", "--project-name", _COMPOSE_PROJECT, "--project-directory", project,
                           "--env-file", f"{project}/.env"]
        for sibling in _ENV_SIBLINGS:
            env = f"{project}/.env.{sibling}"
            if self._host(env).is_file():
                argv += ["--env-file", env]
        compose_files = selected["compose_files"]
        assert isinstance(compose_files, tuple)
        for name in compose_files:
            argv += ["-f", f"{project}/{name}"]
        return (*argv, *args)

    def _compose(self, selected: Mapping[str, object], *args: str) -> None:
        self._run(*self._compose_argv(selected, *args))

    # ------------------------------------------------------------------
    # host boundary
    # ------------------------------------------------------------------

    def _capture(self, *argv: str, max_chars: int) -> str:
        capture = getattr(self.runner, "capture", None)
        if not callable(capture):
            raise McpError("MCP runner cannot capture output")
        try:
            return str(capture(argv, max_chars=max_chars))
        except McpError:
            raise
        except Exception as exc:
            raise McpError(_command_failure(argv)) from exc

    def _run(self, *argv: str) -> None:
        try:
            result = self.runner.run(argv)
        except McpError:
            raise
        except Exception as exc:
            raise McpError(_command_failure(argv)) from exc
        if getattr(result, "returncode", 0):
            from installer.adapters.nginx import _sanitize_diagnostic
            stderr = getattr(result, "stderr", "") or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            raise McpError(f"{_command_failure(argv)}; {_sanitize_diagnostic(str(stderr))}")

    def _host(self, absolute: str) -> Path:
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise McpError("MCP host path is unsafe")
        if self.root.is_symlink() or not self.root.is_dir():
            raise McpError("MCP root is unsafe")
        relative = Path(absolute.lstrip("/"))
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor /= part
            if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
                raise McpError("MCP host path crosses an unsafe parent")
        return self.root / relative

    def _atomic(self, path: Path, data: bytes, mode: int) -> None:
        import os

        owner = (0, 0) if self.root == Path("/") and os.geteuid() == 0 else None
        durable_mkdir(path.parent)
        atomic_write(path, data, mode=mode, owner=owner)


def mcp_url(domain: str) -> str:
    """Where a client connects: the eleventh name, `/mcp`, over the public 443 router."""
    return f"https://{domain}/mcp"


def mcp_handoff(root: Path, config: InstallerConfig, *, paths: McpPaths | None = None) -> dict[str, str]:
    """What the root-only handoff carries for MCP: the address and the bearer token.

    Empty when MCP is off. The token is read from the secret the adapter wrote; the
    public report never sees either entry (installer/report.py keeps the schemas apart).
    """
    if config.domains.mcp is None:
        return {}
    adapter = McpAdapter(root=root, paths=paths)
    return {"mcp_url": mcp_url(config.domains.mcp), "mcp_token": adapter._read_token()}


def _plaintext_of(output: str) -> str | None:
    """The `plaintext` of the one JSON line `api-key-create` prints, or None."""
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            document = json.loads(line)
        except ValueError:
            continue
        value = document.get("plaintext") if isinstance(document, Mapping) else None
        if isinstance(value, str) and value and "\n" not in value:
            return value
    return None


def _command_failure(argv: tuple[str, ...]) -> str:
    program = Path(str(argv[0])).name if argv else "command"
    subcommand = ""
    for value in list(argv)[1:3]:
        rendered = str(value)
        if rendered.startswith("-") or "/" in rendered:
            break
        subcommand += f" {rendered}"
    return f"MCP command failed: {program}{subcommand}"
