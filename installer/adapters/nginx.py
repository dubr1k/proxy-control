from __future__ import annotations

import hashlib
import fnmatch
import ipaddress
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
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
_SOURCE_SECTION_MARKER = re.compile(
    r"^# configuration file (/[^:\r\n]+):(?:\r?\n|\Z)",
    re.MULTILINE,
)
_NGINX_PREFIX_ARG = re.compile(
    r"(?:^|\s)--prefix=(?:\"([^\"\r\n]+)\"|'([^'\r\n]+)'|([^\s]+))"
)


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
    stream_includes: tuple[str, ...]


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
    """Parse effective ``nginx -T`` stream contexts and expanded includes."""
    if not isinstance(text, str):
        raise TypeError("effective Nginx configuration must be text")
    tokens = _tokenize(text)
    ranges, included_sources, include_patterns = _stream_context(tokens)

    def accepted(index: int) -> bool:
        return any(start <= index < end for start, end in ranges) or (
            tokens[index].source_file in included_sources
        )

    parsed = _parse_tokens(
        tokens,
        accepted=accepted,
        stream_enabled=bool(ranges),
    )
    return NginxTopology(
        parsed.maps,
        parsed.servers,
        parsed.stream_enabled,
        include_patterns,
    )


def _parse_file_nginx(text: str) -> NginxTopology:
    tokens = _tokenize(text)
    return _parse_tokens(
        tokens,
        accepted=lambda _index: True,
        stream_enabled=False,
    )


def _parse_tokens(
    tokens: tuple[_Token, ...],
    *,
    accepted: object,
    stream_enabled: bool,
) -> NginxTopology:
    accepts = accepted
    if not callable(accepts):
        raise TypeError("token predicate must be callable")
    maps: list[NginxMap] = []
    servers: list[StreamServer] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if accepts(index) and token.value == "map" and index + 3 < len(tokens):
            parsed = _parse_map(tokens, index)
            if parsed is not None:
                mapping, index = parsed
                maps.append(mapping)
                continue
        if (
            accepts(index)
            and token.value == "server"
            and index + 1 < len(tokens)
            and tokens[index + 1].value == "{"
        ):
            server, index = _parse_server(tokens, index)
            servers.append(server)
            continue
        index += 1
    return NginxTopology(tuple(maps), tuple(servers), stream_enabled, ())


def _stream_context(
    tokens: tuple[_Token, ...],
) -> tuple[
    tuple[tuple[int, int], ...],
    frozenset[str],
    tuple[str, ...],
]:
    ranges: list[tuple[int, int]] = []
    patterns: set[str] = set()
    stream_sources: set[str] = set()
    for index, token in enumerate(tokens[:-1]):
        if token.value != "stream" or tokens[index + 1].value != "{":
            continue
        stream_sources.add(token.source_file)
        close = _matching_close(tokens, index + 1)
        ranges.append((index + 2, close))
        cursor = index + 2
        while cursor < close:
            if (
                tokens[cursor].value == "include"
                and cursor + 2 < close
                and tokens[cursor + 2].value == ";"
            ):
                patterns.add(
                    _normalize_include_pattern(tokens[cursor + 1].value)
                )
                cursor += 3
                continue
            cursor += 1
    sources = {
        token.source_file
        for token in tokens
        if token.source_file != "<effective>"
    }
    included: set[str] = set()
    while True:
        relative_prefix = _relative_include_prefix(
            sources - stream_sources,
            patterns,
        )
        expanded = {
            source
            for source in sources
            if any(
                _source_matches_include(
                    source,
                    pattern,
                    relative_prefix=relative_prefix,
                )
                for pattern in patterns
            )
        }
        new_sources = expanded - included
        if not new_sources:
            break
        included.update(new_sources)
        for index, token in enumerate(tokens[:-2]):
            if (
                token.source_file in new_sources
                and tokens[index + 1].source_file == token.source_file
                and tokens[index + 2].source_file == token.source_file
                and token.value == "include"
                and tokens[index + 2].value == ";"
            ):
                patterns.add(
                    _normalize_include_pattern(tokens[index + 1].value)
                )
    return tuple(ranges), frozenset(included), tuple(sorted(patterns))


def _normalize_include_pattern(pattern: str) -> str:
    absolute = pattern.startswith("/")
    parts: list[str] = []
    for part in PurePosixPath(pattern).parts:
        if part in {"", "/", "."}:
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif absolute:
                raise TopologyError("Nginx include escapes its prefix")
            else:
                parts.append(part)
            continue
        parts.append(part)
    normalized = "/".join(parts)
    return f"/{normalized}" if absolute else normalized


def _resolve_include(pattern: str, prefix: str) -> str:
    if pattern.startswith("/"):
        return _normalize_include_pattern(pattern)
    if not prefix.startswith("/"):
        raise TopologyError("Nginx prefix is not absolute")
    return _normalize_include_pattern(f"{prefix.rstrip('/')}/{pattern}")


def _nginx_runtime_prefix(version_output: str) -> str:
    prefixes = {
        next(value for value in match.groups() if value is not None)
        for match in _NGINX_PREFIX_ARG.finditer(version_output)
    }
    if len(prefixes) != 1:
        raise TopologyError(
            "fresh router path is not proven included by Nginx"
        )
    prefix = _normalize_include_pattern(next(iter(prefixes)))
    if not prefix.startswith("/"):
        raise TopologyError(
            "fresh router path is not proven included by Nginx"
        )
    return prefix


def _glob_path_matches(path: str, pattern: str) -> bool:
    path_parts = PurePosixPath(path).parts
    pattern_parts = PurePosixPath(pattern).parts
    return len(path_parts) == len(pattern_parts) and all(
        fnmatch.fnmatchcase(path_part, pattern_part)
        for path_part, pattern_part in zip(path_parts, pattern_parts, strict=True)
    )


def _relative_include_prefix(
    sources: set[str],
    patterns: set[str],
) -> str | None:
    candidates = {
        candidate
        for pattern in patterns
        if not pattern.startswith("/")
        for source in sources
        if (candidate := _relative_prefix_candidate(source, pattern)) is not None
    }
    if len(candidates) > 1:
        raise TopologyError("relative Nginx include prefix is ambiguous")
    return next(iter(candidates), None)


def _relative_prefix_candidate(source: str, pattern: str) -> str | None:
    pattern_parts = PurePosixPath(pattern).parts
    if not pattern_parts or ".." in pattern_parts:
        return None
    source_parts = PurePosixPath(source).parts
    if len(source_parts) <= len(pattern_parts):
        return None
    suffix = source_parts[-len(pattern_parts):]
    if not all(
        fnmatch.fnmatchcase(source_part, pattern_part)
        for source_part, pattern_part in zip(
            suffix,
            pattern_parts,
            strict=True,
        )
    ):
        return None
    return str(PurePosixPath(*source_parts[:-len(pattern_parts)]))


def _source_matches_include(
    source: str,
    pattern: str,
    *,
    relative_prefix: str | None,
) -> bool:
    if pattern.startswith("/"):
        return _glob_path_matches(source, pattern)
    if relative_prefix is None:
        return False
    return _glob_path_matches(
        source,
        _resolve_include(pattern, relative_prefix),
    )


def select_route_target(
    topology: NginxTopology,
    listener_port: int = 443,
) -> RouteTarget:
    """Trace an active SSL-preread listener to its one effective map."""
    if (
        not isinstance(listener_port, int)
        or isinstance(listener_port, bool)
        or not 1 <= listener_port <= 65535
    ):
        raise ValueError("listener port must be in 1..65535")
    active = [
        server
        for server in topology.servers
        if listener_port in server.listener_ports
    ]
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
    matches = [
        mapping for mapping in topology.maps if mapping.variable == variable
    ]
    if len(matches) != 1:
        if len(matches) > 1:
            raise TopologyError(
                "more than one effective map feeds the active listener"
            )
        raise TopologyError("active stream route is dynamic or unresolved")
    mapping = matches[0]
    if mapping.source_variable != "$ssl_preread_server_name":
        raise TopologyError("active stream route is dynamic or unresolved")
    if any(not _literal_backend(route.value) for route in mapping.routes):
        raise TopologyError("active stream route is dynamic or unresolved")
    return RouteTarget(
        variable=mapping.variable,
        source_variable=mapping.source_variable,
        source_file=mapping.source_file,
        routes=tuple((route.key, route.value) for route in mapping.routes),
    )
def derive_owned_route_variable(
    text: str,
    *,
    routes: Sequence[tuple[str, str]],
    ownership_id: str,
) -> str:
    """Derive a legacy route variable from one owned or unique SNI map."""
    topology = _parse_file_nginx(text)
    sni_maps = [
        mapping
        for mapping in topology.maps
        if mapping.source_variable == "$ssl_preread_server_name"
    ]
    exact: list[NginxMap] = []
    for mapping in sni_maps:
        block = text[mapping.start : mapping.end].encode()
        try:
            remove_owned_map_block(
                block,
                routes=routes,
                ownership_id=ownership_id,
            )
        except TopologyError:
            continue
        exact.append(mapping)
    if len(exact) == 1:
        return exact[0].variable
    marker = f"{OWNERSHIP_BEGIN} {ownership_id}"
    if marker in text or len(sni_maps) != 1:
        raise TopologyError("legacy owned route topology is ambiguous")
    return sni_maps[0].variable




def patch_owned_map(
    text: str,
    *,
    variable: str,
    routes: Sequence[tuple[str, str]],
    ownership_id: str,
) -> str:
    """Insert or verify one exact owned block in a selected map destination."""
    topology = _parse_file_nginx(text)
    matches = [
        mapping
        for mapping in topology.maps
        if mapping.variable == variable
        and mapping.source_variable == "$ssl_preread_server_name"
    ]
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
            # The panel application speaks plain HTTP; the Core adapter owns an
            # Nginx TLS listener on 8443 that terminates for it, so the raw TLS
            # this router forwards reaches a TLS server.
            (config.domains.panel, "127.0.0.1:8443"),
        )
        if config.profile.includes_naive:
            if config.domains.naive is None:
                raise TopologyError("Naive route domain is missing")
            # The private Caddy listener never competes for TCP/443 itself.
            routes += ((config.domains.naive, "127.0.0.1:4443"),)
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
        # A second install of the same generation observes the router this
        # adapter itself generated. That is this installation, not a foreign
        # one, so its own routes and its own listener are not conflicts.
        route_target = nginx.get("route_target")
        owned_router = (
            isinstance(route_target, Mapping)
            and route_target.get("source_file") == self.fresh_path
        )
        observed_backends = (
            dict(observed_routes) if isinstance(observed_routes, Mapping) else {}
        )
        for domain, backend in routes:
            if domain not in known_domains:
                continue
            # A domain already routed to exactly the backend this generation
            # installs is this installation, so a repeated install stays a
            # no-op. Anything else - a different backend, or an HTTP server
            # name with no route of ours behind it - is foreign.
            if observed_backends.get(domain) == backend:
                continue
            raise TopologyError(f"domain already routed: {domain}")
        if config.host_mode is HostMode.FRESH:
            if observation != "observed":
                raise TopologyError(
                    "fresh router path is not proven included by Nginx"
                )
            effective = self.runner.capture(("nginx", "-T"))
            topology = parse_effective_nginx(effective)
            if not owned_router and any(
                443 in server.listener_ports for server in topology.servers
            ):
                raise TopologyError(
                    "fresh mode cannot replace an active stream router"
                )
            if not self._fresh_path_is_included(topology):
                raise TopologyError(
                    "fresh router path is not included by the stream context"
                )
            mode = "fresh"
            target_path = self.fresh_path
            variable = "$proxy_control_backend"
        else:
            if observation != "observed":
                raise TopologyError("Nginx is unavailable in coexist mode")
            effective = self.runner.capture(("nginx", "-T"))
            target = select_route_target(parse_effective_nginx(effective))
            self._authenticate_source(effective, target.source_file)
            mode = "coexist"
            target_path = _safe_host_path(target.source_file)
            variable = target.variable
            existing = dict(target.routes)
            for domain, backend in routes:
                if domain in existing and existing[domain] != backend:
                    raise TopologyError(f"domain already routed: {domain}")
        planned_identity = self._planned_path_identity(
            target_path,
            must_be_missing=mode == "fresh" and not owned_router,
        )
        mutations = (
            f"mode={mode}",
            f"target={target_path}",
            f"variable={variable}",
            f"path_kind={planned_identity['kind']}",
            f"resolved_path={planned_identity['resolved_path']}",
            f"symlink_target={planned_identity['symlink_target'] or '-'}",
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
        path = self._validate_planned_path(specification, allow_created=False)
        exists = specification["path_kind"] != "missing"
        if exists:
            metadata = path.stat()
            content = path.read_bytes()
            original_hash: str | None = _sha256(content)
            mode = stat.S_IMODE(metadata.st_mode)
            uid = metadata.st_uid
            gid = metadata.st_gid
        else:
            original_hash = None
            mode = 0o640
            uid = os.getuid()
            gid = os.getgid()
        identity: dict[str, object] = {
            "exists": exists,
            "original_path": specification["target"],
            "path_kind": specification["path_kind"],
            "resolved_path": specification["resolved_path"],
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "original_sha256": original_hash,
            "symlink_target": specification["symlink_target"],
        }
        return {"owner": action.owner, "ownership": {}, "route_identity": identity}

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        specification = _action_specification(action)
        identity = _checkpoint_identity(checkpoint, specification)
        path = self._validate_planned_path(specification, allow_created=False)
        original = path.read_bytes() if bool(identity["exists"]) else b""
        original_hash = identity["original_sha256"]
        desired = _desired_content(specification, original)
        # A resume can re-enter apply after the write already landed. The file
        # then holds exactly this action's own output - patching it again is a
        # no-op - which is this transaction's work, not foreign drift.
        reentered = bool(identity["exists"]) and _sha256(original) != original_hash
        if reentered and desired != original:
            raise TopologyError("selected route file changed after planning")
        backup = self._backup_path(action, identity)
        if bool(identity["exists"]) and not reentered:
            # Only the first apply sees the content rollback must restore.
            atomic_write(backup, original, mode=0o600)
        self._validate_planned_path(specification, allow_created=False)
        atomic_write(
            path,
            desired,
            mode=int(identity["mode"]),
            owner=(int(identity["uid"]), int(identity["gid"])),
        )
        try:
            self._assert_active_route(
                action,
                specification,
                require_owned=True,
            )
            self._run_checked(("nginx", "-t"), "nginx configuration test failed")
            self._run_checked(
                ("systemctl", "reload", "nginx"),
                "nginx reload failed",
            )
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
        return self._applied_checkpoint(action, checkpoint, identity, desired)

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        specification = _action_specification(action)
        identity = _checkpoint_identity(checkpoint, specification)
        target = self._root_path(str(identity["resolved_path"]))
        if target.is_file():
            current = target.read_bytes()
            if specification["mode"] == "fresh":
                recognized = current == _render_fresh(specification)
            else:
                recognized = _owned_block_in_selected_map(
                    current,
                    specification,
                    action.id,
                )
            if recognized:
                self._assert_active_route(
                    action,
                    specification,
                    require_owned=True,
                )
                backup = self._backup_path(action, identity)
                if bool(identity["exists"]) and (
                    not backup.is_file()
                    or _sha256(backup.read_bytes()) != identity["original_sha256"]
                ):
                    raise TopologyError("Nginx rollback backup is missing or drifted")
                self._run_checked(
                    ("nginx", "-t"),
                    "nginx configuration test failed",
                )
                self._run_checked(
                    ("systemctl", "reload", "nginx"),
                    "nginx reload failed",
                )
                return self._applied_checkpoint(
                    action,
                    checkpoint,
                    identity,
                    current,
                )
        return self.apply(action, checkpoint)

    def repair(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self.reconcile_apply(action, checkpoint)

    def verify(self, action: Action) -> Evidence:
        specification = _action_specification(action)
        try:
            path = self._validate_planned_path(
                specification,
                allow_created=True,
            )
            self._assert_active_route(
                action,
                specification,
                require_owned=True,
            )
            if specification["mode"] == "coexist":
                success = _owned_block_in_selected_map(
                    path.read_bytes(),
                    specification,
                    action.id,
                )
            else:
                success = path.read_bytes() == _render_fresh(specification)
        except (OSError, TopologyError):
            success = False
        return Evidence(
            action_id=action.id,
            success=success,
            observations=(
                "owned Nginx route verified"
                if success
                else "owned Nginx route is absent or drifted",
            ),
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
        identity = _checkpoint_identity(checkpoint, specification)
        path = self._validate_planned_path(specification, allow_created=True)
        current = path.read_bytes()
        self._assert_active_route(
            action,
            specification,
            require_owned=True,
        )
        if specification["mode"] == "fresh":
            if current != _render_fresh(specification):
                raise TopologyError("owned route file has drifted")
            durable_remove(path, missing_ok=True)
        else:
            restored = remove_owned_map_block(
                current,
                routes=specification["routes"],
                ownership_id=action.id,
            )
            self._validate_planned_path(specification, allow_created=True)
            atomic_write(
                path,
                restored,
                mode=int(identity["mode"]),
                owner=(int(identity["uid"]), int(identity["gid"])),
            )
        try:
            self._run_checked(("nginx", "-t"), "nginx configuration test failed")
            self._run_checked(
                ("systemctl", "reload", "nginx"),
                "nginx reload failed",
            )
        except BaseException:
            atomic_write(
                path,
                current,
                mode=int(identity["mode"]),
                owner=(int(identity["uid"]), int(identity["gid"])),
            )
            raise
        durable_remove(self._backup_path(action, identity), missing_ok=True)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("owned Nginx route rolled back",),
        )

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        del purge_data, rollback_target
        specification = _action_specification(action)
        identity = _checkpoint_identity(checkpoint, specification)
        original = self._root_path(str(specification["target"]))
        exact_marker = f"{OWNERSHIP_BEGIN} {action.id}".encode()
        if specification["mode"] == "fresh" and not (
            original.exists() or original.is_symlink()
        ):
            self._root_path(str(specification["resolved_path"]))
            committed = True
        elif specification["mode"] == "coexist":
            path = self._validate_planned_path(
                specification,
                allow_created=True,
            )
            current = path.read_bytes()
            committed = exact_marker not in current
            if committed:
                self._assert_active_route(
                    action,
                    specification,
                    require_owned=False,
                )
        else:
            committed = False
        if not committed:
            return self.rollback(action, checkpoint)
        self._run_checked(("nginx", "-t"), "nginx configuration test failed")
        self._run_checked(
            ("systemctl", "reload", "nginx"),
            "nginx reload failed",
        )
        durable_remove(self._backup_path(action, identity), missing_ok=True)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("Nginx rollback side effects reconciled",),
        )

    def _applied_checkpoint(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        identity: Mapping[str, object],
        desired: bytes,
    ) -> dict[str, object]:
        result = _copy_checkpoint(checkpoint)
        result["owned_sha256"] = _sha256(desired)
        if bool(identity["exists"]):
            backup = self._backup_path(action, identity)
            backup_host = self._host_path(backup)
            result["backup_path"] = backup_host
            result["ownership"] = {
                backup_host: {
                    "preserve": False,
                    "sha256": identity["original_sha256"],
                }
            }
        else:
            result["backup_path"] = ""
            specification = _action_specification(action)
            result["ownership"] = {
                str(specification["target"]): {
                    "preserve": False,
                    "sha256": _sha256(desired),
                }
            }
        return result

    def _assert_active_route(
        self,
        action: Action,
        specification: Mapping[str, object],
        *,
        require_owned: bool,
    ) -> None:
        try:
            effective = self.runner.capture(("nginx", "-T"))
            target = select_route_target(parse_effective_nginx(effective))
            self._authenticate_source(effective, target.source_file)
        except Exception:
            raise TopologyError(
                "owned route is not on the active 443 path"
            ) from None
        if (
            target.source_file != specification["target"]
            or target.variable != specification["variable"]
        ):
            raise TopologyError("owned route is not on the active 443 path")
        path = self._validate_planned_path(
            specification,
            allow_created=True,
        )
        if specification["mode"] == "fresh":
            owned = path.read_bytes() == _render_fresh(specification)
        else:
            owned = _owned_block_in_selected_map(
                path.read_bytes(),
                specification,
                action.id,
            )
        if require_owned and not owned:
            raise TopologyError("owned route is not on the active 443 path")

    def _fresh_path_is_included(self, topology: NginxTopology) -> bool:
        relative: list[str] = []
        for pattern in topology.stream_includes:
            if pattern.startswith("/"):
                if _glob_path_matches(self.fresh_path, pattern):
                    return True
            else:
                relative.append(pattern)
        if not relative:
            return False
        result = self.runner.run(("nginx", "-V"))
        if result.returncode != 0:
            raise TopologyError(
                "fresh router path is not proven included by Nginx"
            )
        prefix = _nginx_runtime_prefix(f"{result.stdout}\n{result.stderr}")
        return any(
            _glob_path_matches(
                self.fresh_path,
                _resolve_include(pattern, prefix),
            )
            for pattern in relative
        )


    def _authenticate_source(self, effective: str, source_file: str) -> None:
        sections = _effective_source_sections(effective).get(source_file, ())
        if len(sections) != 1:
            raise TopologyError(
                "effective Nginx source marker is not authenticated"
            )
        path = self._root_path(_safe_host_path(source_file))
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise TopologyError(
                "effective Nginx source marker is not authenticated"
            ) from exc
        self._assert_contained(resolved)
        if not resolved.is_file():
            raise TopologyError(
                "effective Nginx source marker is not authenticated"
            )
        try:
            content = resolved.read_bytes().decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise TopologyError(
                "effective Nginx source marker is not authenticated"
            ) from exc
        # `nginx -T` prints the file verbatim and then one blank line before
        # the next marker, so the separator it adds is the only difference the
        # comparison tolerates; everything else must be byte-identical.
        if sections[0] not in {content, content + "\n"}:
            raise TopologyError(
                "effective Nginx source marker is not authenticated"
            )

    def _planned_path_identity(
        self,
        host_path: str,
        *,
        must_be_missing: bool,
    ) -> dict[str, str | None]:
        path = self._root_path(host_path)
        exists = path.exists() or path.is_symlink()
        if must_be_missing:
            if exists:
                raise TopologyError("fresh router path is already occupied")
            return {
                "kind": "missing",
                "resolved_path": host_path,
                "symlink_target": None,
            }
        if not exists:
            raise TopologyError("selected route file does not exist")
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise TopologyError("selected route file cannot be resolved") from exc
        self._assert_contained(resolved)
        if not resolved.is_file():
            raise TopologyError("selected route path is not a regular file")
        return {
            "kind": "symlink" if path.is_symlink() else "file",
            "resolved_path": self._host_path(resolved),
            "symlink_target": os.readlink(path) if path.is_symlink() else None,
        }

    def _validate_planned_path(
        self,
        specification: Mapping[str, object],
        *,
        allow_created: bool,
    ) -> Path:
        original = self._root_path(str(specification["target"]))
        expected_kind = specification["path_kind"]
        expected_resolved = str(specification["resolved_path"])
        if expected_kind == "missing":
            if not allow_created:
                if original.exists() or original.is_symlink():
                    raise TopologyError("Nginx route path identity changed")
                return self._root_path(expected_resolved)
            if original.is_symlink() or not original.is_file():
                raise TopologyError("Nginx route path identity changed")
        elif expected_kind == "symlink":
            if (
                not original.is_symlink()
                or os.readlink(original) != specification["symlink_target"]
            ):
                raise TopologyError("Nginx route path identity changed")
        elif expected_kind == "file":
            if original.is_symlink() or not original.is_file():
                raise TopologyError("Nginx route path identity changed")
        else:
            raise TopologyError("Nginx action path identity is invalid")
        try:
            resolved = original.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise TopologyError("Nginx route path identity changed") from exc
        if self._host_path(resolved) != expected_resolved:
            raise TopologyError("Nginx route path identity changed")
        return resolved

    def _run_checked(self, argv: tuple[str, ...], message: str) -> None:
        result = self.runner.run(argv)
        if result.returncode != 0:
            raise RuntimeError(message)

    def _root_path(self, host_path: str) -> Path:
        normalized = _safe_host_path(host_path)
        path = self.root / normalized.lstrip("/")
        nearest = path
        while not (nearest.exists() or nearest.is_symlink()):
            if nearest == self.root:
                return path
            nearest = nearest.parent
        try:
            resolved = nearest.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise TopologyError("selected route parent cannot be resolved") from exc
        self._assert_contained(resolved)
        return path

    def _host_path(self, path: Path) -> str:
        self._assert_contained(path)
        return "/" + str(path.relative_to(self.root))

    def _assert_contained(self, path: Path) -> None:
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise TopologyError(
                "selected route path escapes the supplied root"
            ) from exc

    def _backup_path(self, action: Action, identity: Mapping[str, object]) -> Path:
        digest = identity.get("original_sha256")
        suffix = digest if isinstance(digest, str) else _sha256(action.id.encode())
        return self._root_path(
            f"/var/lib/proxy-control/installer/nginx/{suffix}.backup"
        )


def _effective_source_sections(text: str) -> dict[str, tuple[str, ...]]:
    markers = tuple(_SOURCE_SECTION_MARKER.finditer(text))
    sections: dict[str, list[str]] = {}
    for index, marker in enumerate(markers):
        end = (
            markers[index + 1].start()
            if index + 1 < len(markers)
            else len(text)
        )
        sections.setdefault(marker.group(1), []).append(
            text[marker.end():end]
        )
    return {path: tuple(contents) for path, contents in sections.items()}


def _tokenize(text: str) -> tuple[_Token, ...]:
    tokens: list[_Token] = []
    source_file = "<effective>"
    index = 0
    line_start = True
    brace_depth = 0
    while index < len(text):
        if line_start and text.startswith("# configuration file ", index):
            marker = _SOURCE_MARKER.match(text, index)
            if marker is not None:
                if brace_depth != 0:
                    raise TopologyError(
                        "Nginx source marker is embedded within a configuration block"
                    )
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
            if character == "{":
                brace_depth += 1
            elif character == "}":
                brace_depth -= 1
                if brace_depth < 0:
                    raise TopologyError("unbalanced Nginx configuration block")
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
    if brace_depth != 0:
        raise TopologyError("unbalanced Nginx configuration block")
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


def _literal_backend(value: str) -> bool:
    if "$" in value or any(character.isspace() for character in value):
        return False
    if value.startswith("unix:/"):
        return "\x00" not in value and len(value) > len("unix:/")
    match = re.fullmatch(
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\]):(\d+)",
        value,
    )
    return match is not None and 1 <= int(match.group(1)) <= 65535


def _sanitize_diagnostic(value: str, *, max_chars: int = 800) -> str:
    """Keep a bounded diagnostic with any credential assignment redacted."""
    redacted = re.sub(
        r"(?i)((?:password|token|secret)[=:\s]+)\S+",
        r"\1[REDACTED]",
        value,
    )
    return redacted[-max_chars:].replace("\n", " ").strip()


def _safe_host_path(path: str) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or ".." in Path(path).parts
        or "\x00" in path
        or any(character.isspace() for character in path)
    ):
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
    required_values = {
        "mode",
        "target",
        "variable",
        "path_kind",
        "resolved_path",
        "symlink_target",
    }
    # The router always owns the MTProto and panel routes, and one more per
    # protocol the profile selected; every domain appears exactly once.
    if (
        set(values) != required_values
        or values["mode"] not in {"fresh", "coexist"}
        or values["path_kind"] not in {"missing", "file", "symlink"}
        or not 2 <= len(routes) <= 8
        or len({domain for domain, _backend in routes}) != len(routes)
    ):
        raise TopologyError("Nginx action is malformed")
    target = _safe_host_path(values["target"])
    resolved_path = _safe_host_path(values["resolved_path"])
    if _VARIABLE.fullmatch(values["variable"]) is None:
        raise TopologyError("Nginx action is malformed")
    symlink_target = (
        None if values["symlink_target"] == "-" else values["symlink_target"]
    )
    if (values["path_kind"] == "symlink") != isinstance(symlink_target, str):
        raise TopologyError("Nginx action is malformed")
    if isinstance(symlink_target, str) and (
        not symlink_target or "\x00" in symlink_target
    ):
        raise TopologyError("Nginx action is malformed")
    if values["path_kind"] == "missing" and resolved_path != target:
        raise TopologyError("Nginx action is malformed")
    if any(
        not re.fullmatch(
            r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?",
            domain,
        )
        or not _literal_backend(backend)
        for domain, backend in routes
    ):
        raise TopologyError("Nginx action is malformed")
    return {
        "mode": values["mode"],
        "target": target,
        "variable": values["variable"],
        "path_kind": values["path_kind"],
        "resolved_path": resolved_path,
        "symlink_target": symlink_target,
        "routes": tuple(routes),
    }


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
    specification: Mapping[str, object],
) -> Mapping[str, object]:
    identity = checkpoint.get("route_identity")
    if not isinstance(identity, Mapping):
        raise TopologyError("Nginx checkpoint is invalid")
    required = {
        "exists",
        "original_path",
        "path_kind",
        "resolved_path",
        "mode",
        "uid",
        "gid",
        "original_sha256",
        "symlink_target",
    }
    if set(identity) != required:
        raise TopologyError("Nginx checkpoint is invalid")
    exists = identity["exists"]
    mode = identity["mode"]
    uid = identity["uid"]
    gid = identity["gid"]
    original_hash = identity["original_sha256"]
    if (
        not isinstance(exists, bool)
        or isinstance(mode, bool)
        or not isinstance(mode, int)
        or not 0 <= mode <= 0o7777
        or isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 0
        or isinstance(gid, bool)
        or not isinstance(gid, int)
        or gid < 0
    ):
        raise TopologyError("Nginx checkpoint is invalid")
    expected_exists = specification["path_kind"] != "missing"
    if (
        exists != expected_exists
        or identity["original_path"] != specification["target"]
        or identity["path_kind"] != specification["path_kind"]
        or identity["resolved_path"] != specification["resolved_path"]
        or identity["symlink_target"] != specification["symlink_target"]
        or (
            exists
            and (
                not isinstance(original_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", original_hash) is None
            )
        )
        or (not exists and original_hash is not None)
    ):
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


def _owned_block_in_selected_map(
    content: bytes,
    specification: Mapping[str, object],
    ownership_id: str,
) -> bool:
    try:
        text = content.decode()
        topology = _parse_file_nginx(text)
        matches = [
            mapping
            for mapping in topology.maps
            if mapping.variable == specification["variable"]
            and mapping.source_variable == "$ssl_preread_server_name"
        ]
        if len(matches) != 1:
            return False
        mapping = matches[0]
        block = text[mapping.start : mapping.end].encode()
        remove_owned_map_block(
            block,
            routes=specification["routes"],
            ownership_id=ownership_id,
        )
    except (UnicodeDecodeError, TopologyError):
        return False
    return True


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()



class CertificatePlan:
    """Own HTTP-01 routing and verify service-scoped Certbot lineages."""

    name = "certificates"
    requires = frozenset({"nginx", "packages"})

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: CommandRunner | None = None,
        expected_key_owner: tuple[int, int] | None = None,
    ) -> None:
        if runner is None:
            from installer.audit import CommandRunner

            runner = CommandRunner(timeout=600.0)
        self.root = root.resolve()
        self.runner = runner
        self.expected_key_owner = expected_key_owner or (os.getuid(), os.getgid())
        if (
            len(self.expected_key_owner) != 2
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in self.expected_key_owner
            )
        ):
            raise ValueError("certificate key owner must be a uid/gid pair")

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]:
        if getattr(facts, "hard_stops", ()):
            raise TopologyError("host audit contains blocking findings")
        groups = _certificate_groups(config)
        for _service, _certificate, names in groups:
            _validate_certificate_facts(names, facts)
        return tuple(
            Action(
                id=f"certificate.{service}",
                adapter=self.name,
                owner=f"proxy-control:certificate:{service}",
                mutations=(
                    f"service={service}",
                    f"certificate={certificate}",
                    f"email={config.acme_email}",
                    *(f"name={name}" for name in names),
                    *(f"webroot=/var/www/{name}" for name in names),
                ),
                preconditions=(
                    "strict local A, handled AAAA, and HTTP-01 CAA facts pass",
                ),
                verification=(
                    "owned port-80 HTTP-01 vhosts are active",
                    "certificate validity, trust, exact SANs, and key pair pass",
                    "Certbot renewal dry run succeeds for the exact lineage",
                ),
                inverse=(
                    "remove only the exact owned HTTP-01 vhost and preserve ACME data",
                ),
                credentials_required=False,
            )
            for service, certificate, names in groups
        )

    def prepare(self, action: Action) -> Mapping[str, object]:
        specification = _certificate_action(action)
        vhost_name = _certificate_vhost_path(specification)
        vhost = self._contained_path(vhost_name, allow_missing=True)
        if vhost.exists() or vhost.is_symlink():
            raise TopologyError("certificate HTTP-01 vhost path is already occupied")
        lineage_state = self._lineage_state(specification)
        if lineage_state == "incomplete":
            raise TopologyError("pre-existing certificate lineage is incomplete")
        return {
            "certificate": specification["certificate"],
            "created_webroots": (),
            "lineage_preexisting": lineage_state == "complete",
            "names": specification["names"],
            "owner": action.owner,
            "ownership": {},
            "vhost": vhost_name,
            "vhost_sha256": None,
        }

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self._activate(action, checkpoint, repair_renewal=False)

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self.apply(action, checkpoint)

    def repair(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self._activate(action, checkpoint, repair_renewal=True)

    def verify(self, action: Action) -> Evidence:
        try:
            specification = _certificate_action(action)
            vhost_name = _certificate_vhost_path(specification)
            desired = _render_certificate_vhost(action, specification)
            if not self._vhost_valid(action, specification):
                raise TopologyError("owned HTTP-01 vhost is invalid")
            self._assert_vhost_effective(vhost_name, desired)
            if self._lineage_state(specification) != "complete":
                raise TopologyError("certificate lineage is incomplete")
            if not self._certificate_valid(specification):
                raise TopologyError("certificate lineage is invalid")
            self._run_renewal(specification)
            success = True
        except Exception:
            success = False
            specification = _certificate_action(action)
        return Evidence(
            action_id=action.id,
            success=success,
            observations=(
                "owned HTTP-01 vhost and service certificate are valid"
                if success
                else "owned HTTP-01 vhost or service certificate is invalid",
            ),
            details={
                "certificate": specification["certificate"],
                "names": specification["names"],
            },
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
        specification = _certificate_action(action)
        saved = _certificate_checkpoint(checkpoint, specification)
        vhost = self._contained_path(str(saved["vhost"]), allow_missing=True)
        desired = _render_certificate_vhost(action, specification)
        removed = False
        if vhost.exists() or vhost.is_symlink():
            if (
                vhost.is_symlink()
                or not vhost.is_file()
                or vhost.read_bytes() != desired
            ):
                raise TopologyError("owned certificate HTTP-01 vhost has drifted")
            durable_remove(vhost)
            removed = True
        try:
            self._run_checked(
                ("nginx", "-t"),
                "Nginx HTTP-01 rollback test failed",
            )
            self._run_checked(
                ("systemctl", "reload", "nginx"),
                "Nginx HTTP-01 rollback reload failed",
            )
            self._assert_vhost_absent(str(saved["vhost"]))
        except BaseException:
            if removed:
                atomic_write(
                    vhost,
                    desired,
                    mode=0o644,
                    owner=(os.getuid(), os.getgid()),
                )
            raise
        if not saved["lineage_preexisting"]:
            lineage_state = self._lineage_state(specification)
            if lineage_state == "incomplete" or (
                lineage_state == "complete"
                and not self._certificate_valid(specification)
            ):
                self._remove_action_lineage(specification)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=(
                "owned HTTP-01 vhost removed; valid certificates and webroots preserved",
            ),
            details={"certificate": specification["certificate"]},
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

    def _activate(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        repair_renewal: bool,
    ) -> Mapping[str, object]:
        specification = _certificate_action(action)
        saved = _certificate_checkpoint(checkpoint, specification)
        vhost_name = str(saved["vhost"])
        desired_vhost = _render_certificate_vhost(action, specification)
        if (
            not saved["lineage_preexisting"]
            and saved["vhost_sha256"] is None
            and self._lineage_state(specification) != "absent"
            and not self._vhost_valid(action, specification)
        ):
            raise TopologyError("certificate lineage appeared after prepare")
        created = set(saved["created_webroots"])
        for webroot in specification["webroots"]:
            created.update(self._ensure_webroot(webroot))
        desired_hash = _sha256(desired_vhost)
        self._ensure_vhost(vhost_name, desired_vhost)
        self._run_checked(
            ("nginx", "-t"),
            "Nginx HTTP-01 vhost test failed",
            include_output=True,
        )
        self._run_checked(
            ("systemctl", "reload", "nginx"),
            "Nginx HTTP-01 vhost reload failed",
            include_output=True,
        )
        self._assert_vhost_effective(vhost_name, desired_vhost)
        self._ensure_lineage(
            specification,
            preexisting=bool(saved["lineage_preexisting"]),
            repair_renewal=repair_renewal,
        )
        return {
            "certificate": specification["certificate"],
            "created_webroots": tuple(sorted(created)),
            "lineage_preexisting": saved["lineage_preexisting"],
            "names": specification["names"],
            "owner": action.owner,
            "ownership": {vhost_name: {"sha256": desired_hash}},
            "vhost": vhost_name,
            "vhost_sha256": desired_hash,
        }

    def _ensure_vhost(self, host_path: str, desired: bytes) -> None:
        vhost = self._contained_path(host_path, allow_missing=True)
        if vhost.exists() or vhost.is_symlink():
            if (
                vhost.is_symlink()
                or not vhost.is_file()
                or vhost.read_bytes() != desired
            ):
                raise TopologyError("owned certificate HTTP-01 vhost has drifted")
            return
        atomic_write(
            vhost,
            desired,
            mode=0o644,
            owner=(os.getuid(), os.getgid()),
        )

    def _ensure_lineage(
        self,
        specification: Mapping[str, object],
        *,
        preexisting: bool,
        repair_renewal: bool,
    ) -> None:
        lineage_state = self._lineage_state(specification)
        if preexisting:
            if lineage_state != "complete" or not self._certificate_valid(
                specification
            ):
                raise TopologyError(
                    "pre-existing certificate lineage identity changed or is invalid"
                )
        elif lineage_state != "complete" or not self._certificate_valid(
            specification
        ):
            if lineage_state != "absent":
                self._remove_action_lineage(specification)
            self._issue_certificate(specification)
            if self._lineage_state(specification) != "complete" or not (
                self._certificate_valid(specification)
            ):
                raise TopologyError(
                    "certificate validity, trust, SANs, or private key are invalid"
                )
        try:
            self._run_renewal(specification)
        except TopologyError:
            if preexisting or not repair_renewal:
                raise
            self._remove_action_lineage(specification)
            self._issue_certificate(specification)
            if self._lineage_state(specification) != "complete" or not (
                self._certificate_valid(specification)
            ):
                raise TopologyError(
                    "certificate validity, trust, SANs, or private key are invalid"
                )
            self._run_renewal(specification)

    def _issue_certificate(self, specification: Mapping[str, object]) -> None:
        argv: list[str] = [
            "certbot",
            "certonly",
            "--non-interactive",
            "--agree-tos",
            "--email",
            str(specification["email"]),
            "--cert-name",
            str(specification["certificate"]),
            "--webroot",
        ]
        for name, webroot in zip(
            specification["names"],
            specification["webroots"],
            strict=True,
        ):
            argv.extend(("-w", webroot, "-d", name))
        self._run_checked(tuple(argv), "certificate issuance failed")

    def _run_renewal(self, specification: Mapping[str, object]) -> None:
        self._run_checked(
            (
                "certbot",
                "renew",
                "--cert-name",
                str(specification["certificate"]),
                "--dry-run",
                "--no-random-sleep-on-renew",
            ),
            "certificate renewal dry run failed",
        )

    def _lineage_state(self, specification: Mapping[str, object]) -> str:
        certificate = str(specification["certificate"])
        live = self._contained_path(
            f"/etc/letsencrypt/live/{certificate}",
            allow_missing=True,
        )
        archive = self._contained_path(
            f"/etc/letsencrypt/archive/{certificate}",
            allow_missing=True,
        )
        renewal = self._contained_path(
            f"/etc/letsencrypt/renewal/{certificate}.conf",
            allow_missing=True,
        )
        paths = (live, archive, renewal)
        present = tuple(path.exists() or path.is_symlink() for path in paths)
        if not any(present):
            return "absent"
        if not all(present):
            return "incomplete"
        if (
            live.is_symlink()
            or not live.is_dir()
            or archive.is_symlink()
            or not archive.is_dir()
            or renewal.is_symlink()
            or not renewal.is_file()
        ):
            return "incomplete"
        return "complete"

    def _remove_action_lineage(
        self,
        specification: Mapping[str, object],
    ) -> None:
        certificate = str(specification["certificate"])
        paths = (
            (
                self._contained_path(
                    f"/etc/letsencrypt/renewal/{certificate}.conf",
                    allow_missing=True,
                ),
                "file",
            ),
            (
                self._contained_path(
                    f"/etc/letsencrypt/live/{certificate}",
                    allow_missing=True,
                ),
                "directory",
            ),
            (
                self._contained_path(
                    f"/etc/letsencrypt/archive/{certificate}",
                    allow_missing=True,
                ),
                "directory",
            ),
        )
        for path, kind in paths:
            if not (path.exists() or path.is_symlink()):
                continue
            if path.is_symlink() or (
                kind == "file" and not path.is_file()
            ) or (
                kind == "directory" and not path.is_dir()
            ):
                raise TopologyError(
                    "action-created certificate lineage has unsafe path types"
                )
        for path, _kind in paths:
            durable_remove(path, missing_ok=True)

    def _ensure_webroot(self, host_path: str) -> tuple[str, ...]:
        challenge = f"{host_path}/.well-known/acme-challenge"
        path = self._contained_path(challenge, allow_missing=True)
        created: list[str] = []
        cursor = self.root
        for part in path.relative_to(self.root).parts:
            cursor = cursor / part
            if cursor.exists() or cursor.is_symlink():
                if cursor.is_symlink() or not cursor.is_dir():
                    raise TopologyError("certificate webroot is not a real directory")
                continue
            cursor.mkdir(mode=0o755)
            cursor.chmod(0o755)
            created.append("/" + str(cursor.relative_to(self.root)))
        for required in (
            self._contained_path(host_path, allow_missing=False),
            self._contained_path(f"{host_path}/.well-known", allow_missing=False),
            path,
        ):
            if stat.S_IMODE(required.stat().st_mode) != 0o755:
                raise TopologyError("certificate webroot permissions are invalid")
        return tuple(created)

    def _certificate_valid(self, specification: Mapping[str, object]) -> bool:
        certificate = str(specification["certificate"])
        live = self._contained_path(
            f"/etc/letsencrypt/live/{certificate}",
            allow_missing=True,
        )
        paths = {
            name: live / name
            for name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem")
        }
        try:
            resolved = {
                name: path.resolve(strict=True) for name, path in paths.items()
            }
            for path in resolved.values():
                self._assert_contained(path)
                if not path.is_file():
                    return False
            metadata = resolved["privkey.pem"].stat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or (metadata.st_uid, metadata.st_gid) != self.expected_key_owner
            ):
                return False
            key_public = self.runner.run(
                (
                    "openssl",
                    "pkey",
                    "-in",
                    str(paths["privkey.pem"]),
                    "-pubout",
                )
            )
            leaf_public = self.runner.run(
                (
                    "openssl",
                    "x509",
                    "-in",
                    str(paths["cert.pem"]),
                    "-pubkey",
                    "-noout",
                )
            )
            if (
                key_public.returncode != 0
                or leaf_public.returncode != 0
                or not key_public.stdout.strip()
                or key_public.stdout.strip() != leaf_public.stdout.strip()
            ):
                return False
            checkend = self.runner.run(
                (
                    "openssl",
                    "x509",
                    "-in",
                    str(paths["cert.pem"]),
                    "-noout",
                    "-checkend",
                    "0",
                )
            )
            if checkend.returncode != 0:
                return False
            trust = self.runner.run(
                (
                    "openssl",
                    "verify",
                    "-CApath",
                    "/etc/ssl/certs",
                    "-untrusted",
                    str(paths["chain.pem"]),
                    str(paths["cert.pem"]),
                )
            )
            if trust.returncode != 0:
                return False
            sans = self.runner.run(
                (
                    "openssl",
                    "x509",
                    "-in",
                    str(paths["cert.pem"]),
                    "-noout",
                    "-ext",
                    "subjectAltName",
                )
            )
        except (OSError, RuntimeError, TopologyError):
            return False
        return sans.returncode == 0 and _certificate_sans(sans.stdout) == set(
            specification["names"]
        )

    def _vhost_valid(
        self,
        action: Action,
        specification: Mapping[str, object],
    ) -> bool:
        path = self._contained_path(
            _certificate_vhost_path(specification),
            allow_missing=True,
        )
        try:
            return (
                not path.is_symlink()
                and path.is_file()
                and path.read_bytes()
                == _render_certificate_vhost(action, specification)
            )
        except OSError:
            return False

    def _assert_vhost_effective(
        self,
        host_path: str,
        desired: bytes,
    ) -> None:
        result = self.runner.run(("nginx", "-T"))
        if result.returncode != 0:
            raise TopologyError("effective Nginx HTTP-01 inspection failed")
        try:
            rendered = desired.decode()
        except UnicodeDecodeError as exc:
            raise TopologyError("owned HTTP-01 vhost is not UTF-8") from exc
        # `nginx -T` prints one blank line after each file; that separator is
        # the only difference tolerated here, exactly as in source
        # authentication.
        sections = _effective_source_sections(result.stdout).get(host_path, ())
        if len(sections) != 1 or sections[0] not in {rendered, rendered + "\n"}:
            raise TopologyError(
                "owned HTTP-01 vhost is absent from effective Nginx"
            )

    def _assert_vhost_absent(self, host_path: str) -> None:
        result = self.runner.run(("nginx", "-T"))
        if result.returncode != 0:
            raise TopologyError("effective Nginx HTTP-01 inspection failed")
        if host_path in _effective_source_sections(result.stdout):
            raise TopologyError(
                "owned HTTP-01 vhost remains in effective Nginx"
            )

    def _contained_path(self, host_path: str, *, allow_missing: bool) -> Path:
        normalized = _safe_host_path(host_path)
        path = self.root / normalized.lstrip("/")
        nearest = path
        while not (nearest.exists() or nearest.is_symlink()):
            if nearest == self.root:
                return path
            nearest = nearest.parent
        try:
            resolved = nearest.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise TopologyError("certificate path cannot be resolved") from exc
        self._assert_contained(resolved)
        if not allow_missing and not path.exists():
            raise TopologyError("certificate path is missing")
        return path

    def _assert_contained(self, path: Path) -> None:
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise TopologyError("certificate path escapes the supplied root") from exc

    def _run_checked(
        self,
        argv: tuple[str, ...],
        message: str,
        *,
        include_output: bool = False,
    ) -> None:
        """Run one command; `include_output` is opt-in and never set for ACME.

        Certbot's output can carry credentials, so it stays suppressed. Nginx's
        own test and reload say only why the configuration was rejected, and
        without that an operator is told a reload failed and nothing about why.
        """
        result = self.runner.run(argv)
        if result.returncode != 0:
            detail = (
                _sanitize_diagnostic(f"{result.stderr}\n{result.stdout}")
                if include_output
                else ""
            )
            raise TopologyError(f"{message}: {detail}" if detail else message)


def _certificate_groups(
    config: InstallerConfig,
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    groups: list[tuple[str, str, tuple[str, ...]]] = [
        (
            "proxy-control",
            config.domains.mtproxy,
            tuple(sorted((config.domains.mtproxy, config.domains.panel))),
        )
    ]
    if config.profile.includes_naive:
        if config.domains.naive is None:
            raise TopologyError("Naive certificate domain is missing")
        groups.append(("naive", config.domains.naive, (config.domains.naive,)))
    if config.three_xui.mode.value == "managed-new":
        if config.three_xui.panel_domain is not None:
            groups.append(
                (
                    "three-xui-panel",
                    config.three_xui.panel_domain,
                    (config.three_xui.panel_domain,),
                )
            )
        if config.three_xui.hysteria_domain is not None:
            groups.append(
                (
                    "three-xui-hysteria",
                    config.three_xui.hysteria_domain,
                    (config.three_xui.hysteria_domain,),
                )
            )
    return tuple(sorted(groups))


def _validate_certificate_facts(
    names: tuple[str, ...],
    facts: AuditFacts,
) -> None:
    dns = facts.topology.get("dns")
    certificates = facts.topology.get("certificates")
    if not isinstance(dns, Mapping) or not isinstance(certificates, Mapping):
        raise TopologyError("certificate domain preflight facts are missing")
    for name in names:
        observation = dns.get(name)
        certificate = certificates.get(name)
        if not isinstance(observation, Mapping) or not isinstance(
            certificate,
            Mapping,
        ):
            raise TopologyError(f"certificate domain preflight failed: {name}")
        ipv4 = observation.get("a")
        ipv6 = observation.get("aaaa")
        caa = observation.get("caa")
        caa_source = observation.get("caa_source")
        if (
            not _address_facts(ipv4, version=4, require_one=True)
            or not _address_facts(ipv6, version=6, require_one=False)
            or not isinstance(caa, (tuple, list))
            or not (
                caa_source is None
                or isinstance(caa_source, str) and caa_source
            )
            or observation.get("a_matches_local") is not True
            or observation.get("aaaa_handled") is not True
            or observation.get("caa_compatible") is not True
            or not isinstance(certificate.get("present"), bool)
            or not isinstance(certificate.get("covers_domain"), bool)
            or (
                certificate["present"] is True
                and certificate["covers_domain"] is not True
            )
        ):
            raise TopologyError(f"certificate domain preflight failed: {name}")


def _address_facts(
    value: object,
    *,
    version: int,
    require_one: bool,
) -> bool:
    if (
        not isinstance(value, (tuple, list))
        or require_one and not value
        or any(not isinstance(address, str) for address in value)
    ):
        return False
    try:
        parsed = tuple(ipaddress.ip_address(address) for address in value)
    except ValueError:
        return False
    return all(address.version == version for address in parsed)


def _certificate_action(action: Action) -> dict[str, object]:
    if action.adapter != "certificates" or not action.id.startswith("certificate."):
        raise TopologyError("certificate action identity is invalid")
    singular: dict[str, str] = {}
    names: list[str] = []
    webroots: list[str] = []
    for mutation in action.mutations:
        key, separator, value = mutation.partition("=")
        if not separator:
            raise TopologyError("certificate action is malformed")
        if key == "name":
            names.append(value)
        elif key == "webroot":
            webroots.append(value)
        elif key in singular:
            raise TopologyError("certificate action is malformed")
        else:
            singular[key] = value
    if set(singular) != {"certificate", "email", "service"}:
        raise TopologyError("certificate action is malformed")
    service = singular["service"]
    if (
        action.id != f"certificate.{service}"
        or action.owner != f"proxy-control:certificate:{service}"
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", service) is None
        or not names
        or tuple(names) != tuple(sorted(set(names)))
        or len(webroots) != len(names)
        or tuple(webroots) != tuple(f"/var/www/{name}" for name in names)
        or singular["certificate"] not in names
        or re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",
            singular["email"],
        )
        is None
        or any(
            re.fullmatch(
                r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
                name,
            )
            is None
            for name in names
        )
    ):
        raise TopologyError("certificate action is malformed")
    return {
        "certificate": singular["certificate"],
        "email": singular["email"],
        "names": tuple(names),
        "service": service,
        "webroots": tuple(webroots),
    }


def _certificate_vhost_path(specification: Mapping[str, object]) -> str:
    return (
        "/etc/nginx/conf.d/proxy-control-acme-"
        f"{specification['service']}.conf"
    )


def _render_certificate_vhost(
    action: Action,
    specification: Mapping[str, object],
) -> bytes:
    lines = [f"# BEGIN PROXY-CONTROL ACME {action.id}"]
    for name, webroot in zip(
        specification["names"],
        specification["webroots"],
        strict=True,
    ):
        lines.extend(
            (
                "server {",
                "    listen 80;",
                "    listen [::]:80;",
                f"    server_name {name};",
                "    location ^~ /.well-known/acme-challenge/ {",
                f"        root {webroot};",
                "        try_files $uri =404;",
                "    }",
                "    location / { return 404; }",
                "}",
            )
        )
    lines.extend((f"# END PROXY-CONTROL ACME {action.id}", ""))
    return "\n".join(lines).encode()


def _certificate_checkpoint(
    checkpoint: Mapping[str, object],
    specification: Mapping[str, object],
) -> dict[str, object]:
    required = {
        "certificate",
        "created_webroots",
        "lineage_preexisting",
        "names",
        "owner",
        "ownership",
        "vhost",
        "vhost_sha256",
    }
    expected_vhost = _certificate_vhost_path(specification)
    names = checkpoint.get("names")
    if (
        set(checkpoint) != required
        or checkpoint["certificate"] != specification["certificate"]
        or not isinstance(names, (tuple, list))
        or tuple(names) != specification["names"]
        or checkpoint["owner"]
        != f"proxy-control:certificate:{specification['service']}"
        or checkpoint["vhost"] != expected_vhost
        or not isinstance(checkpoint["lineage_preexisting"], bool)
    ):
        raise TopologyError("certificate checkpoint is invalid")
    created = checkpoint["created_webroots"]
    if not isinstance(created, (tuple, list)) or any(
        not isinstance(path, str)
        or not path.startswith("/")
        or ".." in Path(path).parts
        for path in created
    ):
        raise TopologyError("certificate checkpoint is invalid")
    created_paths = tuple(sorted(set(created)))
    if tuple(created) != created_paths:
        raise TopologyError("certificate checkpoint is invalid")
    vhost_hash = checkpoint["vhost_sha256"]
    if vhost_hash is not None and (
        not isinstance(vhost_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", vhost_hash) is None
    ):
        raise TopologyError("certificate checkpoint is invalid")
    ownership = checkpoint["ownership"]
    if not isinstance(ownership, Mapping):
        raise TopologyError("certificate checkpoint is invalid")
    expected_ownership: Mapping[str, object] = (
        {}
        if vhost_hash is None
        else {expected_vhost: {"sha256": vhost_hash}}
    )
    if dict(ownership) != expected_ownership:
        raise TopologyError("certificate checkpoint is invalid")
    return {
        "created_webroots": created_paths,
        "lineage_preexisting": checkpoint["lineage_preexisting"],
        "vhost": expected_vhost,
        "vhost_sha256": vhost_hash,
    }


def _certificate_sans(text: str) -> set[str]:
    if re.search(r"(?:IP Address|URI|email|othername):", text, re.IGNORECASE):
        return set()
    names: set[str] = set()
    raw_names = re.findall(r"DNS:([^,\s]+)", text)
    for raw in raw_names:
        normalized = raw.lower().rstrip(".")
        if re.fullmatch(
            r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
            normalized,
        ) is None:
            return set()
        names.add(normalized)
    return names


__all__ = [
    "CertificatePlan",
    "NginxAdapter",
    "derive_owned_route_variable",
    "NginxTopology",
    "RouteTarget",
    "TopologyError",
    "parse_effective_nginx",
    "patch_owned_map",
    "remove_owned_map_block",
    "select_route_target",
]
