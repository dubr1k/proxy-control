from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from installer.model import HostMode, InstallerConfig
from installer.planner import Action, AuditFacts, Evidence
from installer.transaction import atomic_write, durable_remove

if TYPE_CHECKING:
    from installer.audit import CommandRunner


OWNERSHIP_BEGIN = "# BEGIN PROXY-CONTROL ROUTES"
OWNERSHIP_END = "# END PROXY-CONTROL ROUTES"
GENERATED_BEGIN = "# BEGIN PROXY-CONTROL GENERATED STREAM ROUTER"
GENERATED_END = "# END PROXY-CONTROL GENERATED STREAM ROUTER"
_DEFAULT_FRESH_PATH = "/etc/nginx/stream.d/proxy-control.conf"
_VARIABLE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\Z")
_SOURCE_MARKER = re.compile(r"# configuration file (/[^:\r\n]+):(?:\r?\n|\Z)")


class TopologyError(RuntimeError):
    """The effective Nginx stream route cannot be selected safely."""


@dataclass(frozen=True)
class MapRoute:
    key: str
    value: str
    start: int


@dataclass(frozen=True)
class NginxMap:
    source_variable: str
    variable: str
    source_file: str
    routes: tuple[MapRoute, ...]
    start: int
    end: int


@dataclass(frozen=True)
class StreamServer:
    source_file: str
    listener_ports: tuple[int, ...]
    ssl_preread: str | None
    proxy_passes: tuple[str, ...]


@dataclass(frozen=True)
class NginxTopology:
    maps: tuple[NginxMap, ...]
    servers: tuple[StreamServer, ...]
    stream_enabled: bool


@dataclass(frozen=True)
class RouteTarget:
    variable: str
    source_variable: str
    source_file: str
    routes: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _Token:
    value: str
    source_file: str
    start: int
    end: int


def parse_effective_nginx(text: str) -> NginxTopology:
    """Parse the effective ``nginx -T`` stream grammar needed for route ownership."""
    if not isinstance(text, str):
        raise TypeError("effective Nginx configuration must be text")
    tokens = _tokenize(text)
    maps: list[NginxMap] = []
    servers: list[StreamServer] = []
    stream_enabled = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.value == "stream" and index + 1 < len(tokens) and tokens[index + 1].value == "{":
            stream_enabled = True
        if token.value == "map" and index + 3 < len(tokens):
            parsed = _parse_map(tokens, index)
            if parsed is not None:
                mapping, index = parsed
                maps.append(mapping)
                continue
        if token.value == "server" and index + 1 < len(tokens) and tokens[index + 1].value == "{":
            server, index = _parse_server(tokens, index)
            servers.append(server)
            continue
        index += 1
    return NginxTopology(tuple(maps), tuple(servers), stream_enabled)


def select_route_target(topology: NginxTopology, listener_port: int = 443) -> RouteTarget:
    """Trace an active SSL-preread listener to its one effective map."""
    if not isinstance(listener_port, int) or isinstance(listener_port, bool) or not 1 <= listener_port <= 65535:
        raise ValueError("listener port must be in 1..65535")
    active = [server for server in topology.servers if listener_port in server.listener_ports]
    if not active:
        raise TopologyError(f"no effective stream listener on port {listener_port}")
    variables: set[str] = set()
    for server in active:
        if server.ssl_preread != "on" or len(server.proxy_passes) != 1:
            raise TopologyError("active stream route is dynamic or unresolved")
        proxy_pass = server.proxy_passes[0]
        if _VARIABLE.fullmatch(proxy_pass) is None:
            raise TopologyError("active stream route is dynamic or unresolved")
        variables.add(proxy_pass)
    if len(variables) != 1:
        raise TopologyError("more than one effective map feeds the active listener")
    variable = next(iter(variables))
    matches = [mapping for mapping in topology.maps if mapping.variable == variable]
    if len(matches) != 1:
        if len(matches) > 1:
            raise TopologyError("more than one effective map feeds the active listener")
        raise TopologyError("active stream route is dynamic or unresolved")
    mapping = matches[0]
    if mapping.source_variable != "$ssl_preread_server_name":
        raise TopologyError("active stream route is dynamic or unresolved")
    return RouteTarget(
        variable=mapping.variable,
        source_variable=mapping.source_variable,
        source_file=mapping.source_file,
        routes=tuple((route.key, route.value) for route in mapping.routes),
    )


def patch_owned_map(
    text: str,
    *,
    variable: str,
    routes: Sequence[tuple[str, str]],
    ownership_id: str,
) -> str:
    """Insert or verify one exact owned block in a selected map destination."""
    topology = parse_effective_nginx(text)
    matches = [mapping for mapping in topology.maps if mapping.variable == variable]
    if len(matches) != 1:
        raise TopologyError("selected route file does not contain exactly one effective map")
    mapping = matches[0]
    wanted = tuple(routes)
    if not wanted or any(not key or not value for key, value in wanted):
        raise ValueError("owned routes must be non-empty")
    existing: dict[str, str] = {}
    for route in mapping.routes:
        if route.key in existing:
            raise TopologyError("duplicate routes make the selected map ambiguous")
        existing[route.key] = route.value
    for domain, backend in wanted:
        if domain in existing and existing[domain] != backend:
            raise TopologyError(f"domain already routed: {domain}")

    begin = f"{OWNERSHIP_BEGIN} {ownership_id}"
    end = f"{OWNERSHIP_END} {ownership_id}"
    managed_lines = [begin, *(f"{domain} {backend};" for domain, backend in wanted), end]
    if OWNERSHIP_BEGIN in text or OWNERSHIP_END in text:
        lines = text.splitlines()
        begins = [i for i, line in enumerate(lines) if line.strip() == begin]
        ends = [i for i, line in enumerate(lines) if line.strip() == end]
        if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
            raise TopologyError("malformed or foreign route ownership markers")
        if [line.strip() for line in lines[begins[0] : ends[0] + 1]] != managed_lines:
            raise TopologyError("owned route block differs from requested configuration")
        return text

    defaults = [route for route in mapping.routes if route.key == "default"]
    if len(defaults) != 1:
        raise TopologyError("selected SNI map must contain exactly one default route")
    insertion = defaults[0].start
    line_start = text.rfind("\n", 0, insertion) + 1
    indent = text[line_start:insertion]
    if indent.strip():
        indent = "    "
    managed = "".join(f"{indent}{line}\n" for line in managed_lines)
    return text[:line_start] + managed + text[line_start:]


def remove_owned_map_block(
    content: bytes,
    *,
    routes: Sequence[tuple[str, str]],
    ownership_id: str,
) -> bytes:
    try:
        text = content.decode()
    except UnicodeDecodeError as exc:
        raise TopologyError("owned route file has drifted") from exc
    lines = text.splitlines(keepends=True)
    begin = f"{OWNERSHIP_BEGIN} {ownership_id}"
    end = f"{OWNERSHIP_END} {ownership_id}"
    begins = [i for i, line in enumerate(lines) if line.strip() == begin]
    ends = [i for i, line in enumerate(lines) if line.strip() == end]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise TopologyError("owned route file has drifted")
    expected = [begin, *(f"{domain} {backend};" for domain, backend in routes), end]
    if [line.strip() for line in lines[begins[0] : ends[0] + 1]] != expected:
        raise TopologyError("owned route file has drifted")
    return "".join(lines[: begins[0]] + lines[ends[0] + 1 :]).encode()


class NginxAdapter:
    """Transactional owner of the generated router or one selected map block."""

    name = "nginx"
    requires = frozenset({"packages"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | None = None,
        fresh_path: str = _DEFAULT_FRESH_PATH,
    ) -> None:
        if runner is None:
            from installer.audit import CommandRunner

            runner = CommandRunner()
        self.root = root.resolve()
        self.runner = runner
        self.fresh_path = _safe_host_path(fresh_path)

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if getattr(facts, "hard_stops", ()):
            raise TopologyError("host audit contains blocking findings")
        nginx = facts.topology.get("nginx")
        if not isinstance(nginx, Mapping):
            raise TopologyError("Nginx observation is missing")
        observation = nginx.get("observation")
        if observation == "unknown":
            raise TopologyError("Nginx topology is unknown")
        routes = (
            (config.domains.mtproxy, "127.0.0.1:8445"),
            (config.domains.panel, "127.0.0.1:8787"),
        )
        known_domains: set[str] = set()
        observed_routes = nginx.get("sni_routes", {})
        if isinstance(observed_routes, Mapping):
            known_domains.update(
                key for key in observed_routes if isinstance(key, str)
            )
        http_domains = nginx.get("http_domains", ())
        if isinstance(http_domains, Sequence) and not isinstance(
            http_domains, (str, bytes, bytearray)
        ):
            known_domains.update(
                domain for domain in http_domains if isinstance(domain, str)
            )
        for domain, _backend in routes:
            if domain in known_domains:
                raise TopologyError(f"domain already routed: {domain}")
        if config.host_mode is HostMode.FRESH:
            if observation not in {"observed", "unavailable"}:
                raise TopologyError("Nginx observation is invalid")
            mode = "fresh"
            target_path = self.fresh_path
            variable = "$proxy_control_backend"
        else:
            if observation != "observed":
                raise TopologyError("Nginx is unavailable in coexist mode")
            effective = self.runner.capture(("nginx", "-T"))
            target = select_route_target(parse_effective_nginx(effective))
            mode = "coexist"
            target_path = _safe_host_path(target.source_file)
            variable = target.variable
            existing = dict(target.routes)
            for domain, backend in routes:
                if domain in existing and existing[domain] != backend:
                    raise TopologyError(f"domain already routed: {domain}")
        mutations = (
            f"mode={mode}",
            f"target={target_path}",
            f"variable={variable}",
            *(f"route={domain} {backend}" for domain, backend in routes),
        )
        return (
            Action(
                id="nginx.routes",
                adapter=self.name,
                owner="proxy-control:nginx",
                mutations=mutations,
                preconditions=("effective Nginx topology is observed and unambiguous",),
                verification=("Nginx configuration test passes before reload",),
                inverse=("restore content, owner, group, mode, and symlink identity",),
                credentials_required=False,
            ),
        )

    def prepare(self, action: Action) -> Mapping[str, object]:
        specification = _action_specification(action)
        host_path = specification["target"]
        path = self._root_path(host_path)
        exists = path.exists() or path.is_symlink()
        if specification["mode"] == "coexist" and not exists:
            raise TopologyError("selected route file does not exist")
        if specification["mode"] == "fresh" and exists:
            raise TopologyError("fresh router path is already occupied")
        if exists:
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise TopologyError("selected route file cannot be resolved") from exc
            self._assert_contained(resolved)
            if not resolved.is_file():
                raise TopologyError("selected route path is not a regular file")
            metadata = resolved.stat()
            content = resolved.read_bytes()
            identity: dict[str, object] = {
                "exists": True,
                "resolved_path": self._host_path(resolved),
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "original_sha256": _sha256(content),
                "symlink_target": os.readlink(path) if path.is_symlink() else None,
            }
        else:
            identity = {
                "exists": False,
                "resolved_path": host_path,
                "mode": 0o640,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "original_sha256": None,
                "symlink_target": None,
            }
        return {"owner": action.owner, "ownership": {}, "route_identity": identity}

    def apply(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        specification = _action_specification(action)
        identity = _checkpoint_identity(checkpoint, specification["target"])
        path = self._root_path(str(identity["resolved_path"]))
        original = path.read_bytes() if bool(identity["exists"]) else b""
        original_hash = identity["original_sha256"]
        if bool(identity["exists"]) and _sha256(original) != original_hash:
            raise TopologyError("selected route file changed after planning")
        desired = _desired_content(specification, original)
        backup = self._backup_path(action, identity)
        if bool(identity["exists"]):
            atomic_write(backup, original, mode=0o600)
        atomic_write(
            path,
            desired,
            mode=int(identity["mode"]),
            owner=(int(identity["uid"]), int(identity["gid"])),
        )
        try:
            self._run_checked(("nginx", "-t"), "nginx configuration test failed")
            self._run_checked(("systemctl", "reload", "nginx"), "nginx reload failed")
        except BaseException:
            if bool(identity["exists"]):
                atomic_write(
                    path,
                    original,
                    mode=int(identity["mode"]),
                    owner=(int(identity["uid"]), int(identity["gid"])),
                )
            else:
                durable_remove(path, missing_ok=True)
            raise
        result = _copy_checkpoint(checkpoint)
        result["owned_sha256"] = _sha256(desired)
        if bool(identity["exists"]):
            backup_host = self._host_path(backup)
            result["backup_path"] = backup_host
            result["ownership"] = {
                backup_host: {"preserve": False, "sha256": original_hash}
            }
        else:
            result["backup_path"] = ""
            result["ownership"] = {
                str(specification["target"]): {
                    "preserve": False,
                    "sha256": _sha256(desired),
                }
            }
        return result

    def reconcile_apply(self, action: Action, checkpoint: Mapping[str, object]) -> Mapping[str, object]:
        specification = _action_specification(action)
        identity = _checkpoint_identity(checkpoint, specification["target"])
        path = self._root_path(str(identity["resolved_path"]))
        if path.is_file():
            current = path.read_bytes()
            owned_hash = checkpoint.get("owned_sha256")
            if isinstance(owned_hash, str) and _sha256(current) == owned_hash:
                return checkpoint
            if specification["mode"] == "coexist" and _owned_block_is_exact(current, specification, action.id):
                return checkpoint
        return self.apply(action, checkpoint)

    def verify(self, action: Action) -> Evidence:
        specification = _action_specification(action)
        path = self._root_path(specification["target"])
        success = path.is_file()
        if success and specification["mode"] == "coexist":
            success = _owned_block_is_exact(path.read_bytes(), specification, action.id)
        if success and specification["mode"] == "fresh":
            success = path.read_bytes() == _render_fresh(specification)
        return Evidence(
            action_id=action.id,
            success=success,
            observations=("owned Nginx route verified" if success else "owned Nginx route is absent or drifted",),
        )

    def rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        del purge_data
        if rollback_target not in {"rolled_back", "uninstalled"}:
            raise ValueError("invalid rollback target")
        specification = _action_specification(action)
        identity = _checkpoint_identity(checkpoint, specification["target"])
        path = self._root_path(str(identity["resolved_path"]))
        current = path.read_bytes() if path.is_file() else b""
        if specification["mode"] == "fresh":
            if current and current != _render_fresh(specification):
                raise TopologyError("owned route file has drifted")
            durable_remove(path, missing_ok=True)
        else:
            if not path.is_file():
                raise TopologyError("owned route file is missing")
            restored = remove_owned_map_block(
                current,
                routes=specification["routes"],
                ownership_id=action.id,
            )
            atomic_write(
                path,
                restored,
                mode=int(identity["mode"]),
                owner=(int(identity["uid"]), int(identity["gid"])),
            )
        try:
            self._run_checked(("nginx", "-t"), "nginx configuration test failed")
            self._run_checked(("systemctl", "reload", "nginx"), "nginx reload failed")
        except BaseException:
            if current:
                atomic_write(
                    path,
                    current,
                    mode=int(identity["mode"]),
                    owner=(int(identity["uid"]), int(identity["gid"])),
                )
            raise
        backup = self._backup_path(action, identity)
        durable_remove(backup, missing_ok=True)
        return Evidence(action_id=action.id, success=True, observations=("owned Nginx route rolled back",))

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        specification = _action_specification(action)
        identity = _checkpoint_identity(checkpoint, specification["target"])
        path = self._root_path(str(identity["resolved_path"]))
        if specification["mode"] == "fresh" and not path.exists():
            return Evidence(action_id=action.id, success=True, observations=("Nginx rollback already committed",))
        if specification["mode"] == "coexist" and path.is_file() and OWNERSHIP_BEGIN.encode() not in path.read_bytes():
            return Evidence(action_id=action.id, success=True, observations=("Nginx rollback already committed",))
        return self.rollback(
            action,
            checkpoint,
            purge_data=purge_data,
            rollback_target=rollback_target,
        )

    def _run_checked(self, argv: tuple[str, ...], message: str) -> None:
        result = self.runner.run(argv)
        if result.returncode != 0:
            raise RuntimeError(message)

    def _root_path(self, host_path: str) -> Path:
        normalized = _safe_host_path(host_path)
        path = self.root / normalized.lstrip("/")
        self._assert_contained(path)
        return path

    def _host_path(self, path: Path) -> str:
        self._assert_contained(path)
        return "/" + str(path.relative_to(self.root))

    def _assert_contained(self, path: Path) -> None:
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise TopologyError("selected route path escapes the supplied root") from exc

    def _backup_path(self, action: Action, identity: Mapping[str, object]) -> Path:
        digest = identity.get("original_sha256")
        suffix = digest if isinstance(digest, str) else _sha256(action.id.encode())
        return self._root_path(f"/var/lib/proxy-control/installer/nginx/{suffix}.backup")


def _tokenize(text: str) -> tuple[_Token, ...]:
    tokens: list[_Token] = []
    source_file = "<effective>"
    index = 0
    line_start = True
    while index < len(text):
        if line_start and text.startswith("# configuration file ", index):
            marker = _SOURCE_MARKER.match(text, index)
            if marker is not None:
                source_file = marker.group(1)
                index = marker.end()
                line_start = True
                continue
        character = text[index]
        if character in " \t\r":
            index += 1
            continue
        if character == "\n":
            index += 1
            line_start = True
            continue
        if character == "#":
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline + 1
            line_start = True
            continue
        line_start = False
        if character in "{};":
            tokens.append(_Token(character, source_file, index, index + 1))
            index += 1
            continue
        if character in {'"', "'"}:
            quote = character
            start = index
            index += 1
            value: list[str] = []
            while index < len(text):
                character = text[index]
                if character == "\\" and index + 1 < len(text):
                    value.append(text[index + 1])
                    index += 2
                    continue
                if character == quote:
                    index += 1
                    break
                value.append(character)
                index += 1
            else:
                raise TopologyError("unterminated quoted Nginx token")
            tokens.append(_Token("".join(value), source_file, start, index))
            continue
        start = index
        while index < len(text) and text[index] not in " \t\r\n{};#'\"":
            index += 1
        tokens.append(_Token(text[start:index], source_file, start, index))
    return tuple(tokens)


def _parse_map(tokens: tuple[_Token, ...], start: int) -> tuple[NginxMap, int] | None:
    if tokens[start + 3].value != "{":
        return None
    source_variable = tokens[start + 1].value
    variable = tokens[start + 2].value
    if _VARIABLE.fullmatch(source_variable) is None or _VARIABLE.fullmatch(variable) is None:
        return None
    close = _matching_close(tokens, start + 3)
    routes: list[MapRoute] = []
    current: list[_Token] = []
    depth = 1
    for token in tokens[start + 4 : close]:
        if token.value == "{":
            depth += 1
        elif token.value == "}":
            depth -= 1
        elif token.value == ";" and depth == 1:
            if len(current) >= 2:
                routes.append(MapRoute(current[0].value, " ".join(item.value for item in current[1:]), current[0].start))
            current = []
        elif depth == 1:
            current.append(token)
    if current:
        raise TopologyError("unterminated directive in Nginx map")
    return (
        NginxMap(
            source_variable=source_variable,
            variable=variable,
            source_file=tokens[start].source_file,
            routes=tuple(routes),
            start=tokens[start].start,
            end=tokens[close].end,
        ),
        close + 1,
    )


def _parse_server(tokens: tuple[_Token, ...], start: int) -> tuple[StreamServer, int]:
    close = _matching_close(tokens, start + 1)
    directives: list[tuple[str, ...]] = []
    current: list[str] = []
    depth = 1
    for token in tokens[start + 2 : close]:
        if token.value == "{":
            depth += 1
        elif token.value == "}":
            depth -= 1
        elif token.value == ";" and depth == 1:
            if current:
                directives.append(tuple(current))
            current = []
        elif depth == 1:
            current.append(token.value)
    listeners: set[int] = set()
    ssl_preread: str | None = None
    proxy_passes: list[str] = []
    for directive in directives:
        if directive[0] == "listen" and len(directive) >= 2:
            port = _listen_port(directive[1])
            if port is not None:
                listeners.add(port)
        elif directive[0] == "ssl_preread" and len(directive) == 2:
            ssl_preread = directive[1]
        elif directive[0] == "proxy_pass" and len(directive) >= 2:
            proxy_passes.append(" ".join(directive[1:]))
    return (
        StreamServer(
            source_file=tokens[start].source_file,
            listener_ports=tuple(sorted(listeners)),
            ssl_preread=ssl_preread,
            proxy_passes=tuple(proxy_passes),
        ),
        close + 1,
    )


def _matching_close(tokens: tuple[_Token, ...], opening: int) -> int:
    depth = 0
    for index in range(opening, len(tokens)):
        if tokens[index].value == "{":
            depth += 1
        elif tokens[index].value == "}":
            depth -= 1
            if depth == 0:
                return index
    raise TopologyError("unterminated Nginx block")


def _listen_port(value: str) -> int | None:
    if value.startswith("unix:"):
        return None
    if value.isdigit():
        port = int(value)
    else:
        match = re.search(r":(\d+)\Z", value)
        if match is None:
            return None
        port = int(match.group(1))
    return port if 1 <= port <= 65535 else None


def _safe_host_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or ".." in Path(path).parts or "\x00" in path:
        raise TopologyError("Nginx route path must be a normalized absolute path")
    return str(Path(path))


def _action_specification(action: Action) -> dict[str, object]:
    if action.adapter != "nginx" or action.id != "nginx.routes":
        raise TopologyError("Nginx action identity is invalid")
    values: dict[str, str] = {}
    routes: list[tuple[str, str]] = []
    for mutation in action.mutations:
        key, separator, value = mutation.partition("=")
        if not separator:
            raise TopologyError("Nginx action is malformed")
        if key == "route":
            domain, separator, backend = value.partition(" ")
            if not separator:
                raise TopologyError("Nginx action is malformed")
            routes.append((domain, backend))
        elif key in values:
            raise TopologyError("Nginx action is malformed")
        else:
            values[key] = value
    if set(values) != {"mode", "target", "variable"} or values["mode"] not in {"fresh", "coexist"} or len(routes) != 2:
        raise TopologyError("Nginx action is malformed")
    _safe_host_path(values["target"])
    if _VARIABLE.fullmatch(values["variable"]) is None:
        raise TopologyError("Nginx action is malformed")
    return {"mode": values["mode"], "target": values["target"], "variable": values["variable"], "routes": tuple(routes)}


def _desired_content(specification: Mapping[str, object], original: bytes) -> bytes:
    if specification["mode"] == "fresh":
        if original and original != _render_fresh(specification):
            raise TopologyError("fresh router path is already occupied")
        return _render_fresh(specification)
    try:
        text = original.decode()
    except UnicodeDecodeError as exc:
        raise TopologyError("selected route file is not UTF-8") from exc
    return patch_owned_map(
        text,
        variable=str(specification["variable"]),
        routes=specification["routes"],
        ownership_id="nginx.routes",
    ).encode()


def _render_fresh(specification: Mapping[str, object]) -> bytes:
    routes = specification["routes"]
    assert isinstance(routes, tuple)
    lines = [
        GENERATED_BEGIN,
        "map $ssl_preread_server_name $proxy_control_backend {",
        *(f"    {domain} {backend};" for domain, backend in routes),
        "    default 127.0.0.1:8443;",
        "}",
        "server {",
        "    listen 443;",
        "    ssl_preread on;",
        "    proxy_pass $proxy_control_backend;",
        "}",
        GENERATED_END,
        "",
    ]
    return "\n".join(lines).encode()


def _checkpoint_identity(
    checkpoint: Mapping[str, object],
    host_path: object,
) -> Mapping[str, object]:
    del host_path
    identity = checkpoint.get("route_identity")
    if not isinstance(identity, Mapping):
        raise TopologyError("Nginx checkpoint is invalid")
    required = {
        "exists",
        "resolved_path",
        "mode",
        "uid",
        "gid",
        "original_sha256",
        "symlink_target",
    }
    if set(identity) != required:
        raise TopologyError("Nginx checkpoint is invalid")
    return identity


def _copy_checkpoint(checkpoint: Mapping[str, object]) -> dict[str, object]:
    identity = checkpoint.get("route_identity")
    if not isinstance(identity, Mapping):
        raise TopologyError("Nginx checkpoint is invalid")
    return {
        "owner": checkpoint.get("owner"),
        "ownership": {},
        "route_identity": dict(identity),
    }


def _owned_block_is_exact(content: bytes, specification: Mapping[str, object], ownership_id: str) -> bool:
    try:
        remove_owned_map_block(content, routes=specification["routes"], ownership_id=ownership_id)
    except TopologyError:
        return False
    return True


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


__all__ = [
    "NginxAdapter",
    "NginxTopology",
    "RouteTarget",
    "TopologyError",
    "parse_effective_nginx",
    "patch_owned_map",
    "remove_owned_map_block",
    "select_route_target",
]
