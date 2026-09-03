#!/usr/bin/env python3
"""Proxy Control fail-closed host lifecycle and Nginx transaction manager."""
from __future__ import annotations

import json
import os
import re
import secrets
import signal
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from functools import partial
from pathlib import Path
from typing import Callable, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from installer.transaction import (
    atomic_write as _atomic_write,
    durable_copy2 as _durable_copy2,
    durable_mkdir as _durable_mkdir,
    durable_remove as _durable_remove,
    durable_symlink as _durable_symlink,
    fsync_directory as _fsync_dir,
    fsync_tree as _fsync_tree,
    operation_lock,
    sha256 as _sha256,
)

OWNERSHIP_BEGIN = "# BEGIN PROXY-CONTROL ROUTES"
OWNERSHIP_END = "# END PROXY-CONTROL ROUTES"
STATE_PATH = "/var/lib/proxy-control/ownership.json"
STATE_SCHEMA = 1
DOMAIN_RE = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class InstallerConflict(RuntimeError):
    """A condition that cannot be changed safely or unambiguously."""


_operation_lock = partial(operation_lock, error_type=InstallerConflict)


def validate_domain(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(normalized):
        raise ValueError("a plain fully-qualified domain name is required")
    return normalized


@dataclass(frozen=True)
class DomainAudit:
    domain: str
    a_records: list[str]
    aaaa_records: list[str]
    dns_matches_host: bool
    unhandled_aaaa: bool
    tls_certificate_present: bool


@dataclass(frozen=True)
class NginxAudit:
    installed: bool
    stream_enabled: bool
    sni_routes: dict[str, str]
    http_domains: list[str]
    config_files: list[str]
    sni_map_count: int = 0
    sni_map_files: dict[str, int] = field(default_factory=dict)
    duplicate_sni_domains: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class XrayAudit:
    installed: bool
    inbounds: list[dict]
    outbound_tags: list[str]


@dataclass(frozen=True)
class AuditReport:
    nginx: NginxAudit
    xray: XrayAudit
    docker_available: bool
    listening_ports: list[int]
    listener_owners: dict[int, list[str]] = field(default_factory=dict)
    domains: list[DomainAudit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _root_path(root: Path, absolute: str) -> Path:
    if not absolute.startswith("/"):
        raise InstallerConflict("host paths must be absolute")
    return root / absolute.lstrip("/")


def _host_path(root: Path, path: Path) -> str:
    try:
        return "/" + str(path.relative_to(root))
    except ValueError as exc:
        raise InstallerConflict("resolved path escapes the selected root") from exc


def _read_text(path: Path) -> str:
    try:
        return path.read_text()
    except (FileNotFoundError, PermissionError, OSError, UnicodeError):
        return ""


def _nginx_files(root: Path) -> list[Path]:
    candidates = [_root_path(root, "/etc/nginx/nginx.conf")]
    for directory in (
        "/etc/nginx/stream.d",
        "/etc/nginx/stream-conf.d",
        "/etc/nginx/conf.d",
        "/etc/nginx/sites-enabled",
    ):
        folder = _root_path(root, directory)
        if folder.is_dir():
            candidates.extend(sorted(path for path in folder.iterdir() if path.is_file()))
    unique: list[Path] = []
    seen: set[tuple[int, int]] = set()
    for path in candidates:
        if not path.is_file():
            continue
        metadata = path.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        if identity not in seen:
            seen.add(identity)
            unique.append(path)
    return unique


def _parse_sni_entries(text: str) -> list[tuple[str, str]]:
    return [
        (domain.lower(), backend)
        for domain, backend in re.findall(
            r"(?<![A-Za-z0-9_.-])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\s+"
            r"((?:127\.0\.0\.1|\[?::1\]?):\d+)\s*;",
            text,
        )
    ]


def _parse_sni_routes(text: str) -> dict[str, str]:
    return dict(_parse_sni_entries(text))


def _parse_http_domains(text: str) -> set[str]:
    domains: set[str] = set()
    for match in re.finditer(r"(?m)^\s*server_name\s+([^;]+);", text):
        for value in match.group(1).split():
            try:
                domains.add(validate_domain(value))
            except ValueError:
                continue
    return domains


def _xray_audit(root: Path) -> XrayAudit:
    path = _root_path(root, "/usr/local/x-ui/bin/config.json")
    if not path.is_file():
        return XrayAudit(False, [], [])
    try:
        config = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return XrayAudit(True, [], [])
    inbounds = []
    for inbound in config.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        stream = inbound.get("streamSettings") if isinstance(inbound.get("streamSettings"), dict) else {}
        reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
        names = reality.get("serverNames") if isinstance(reality.get("serverNames"), list) else []
        inbounds.append({
            "tag": inbound.get("tag"),
            "protocol": inbound.get("protocol"),
            "listen": inbound.get("listen"),
            "port": inbound.get("port"),
            "security": stream.get("security"),
            "server_names": sorted(name for name in names if isinstance(name, str)),
        })
    tags = [item.get("tag") for item in config.get("outbounds", []) if isinstance(item, dict)]
    return XrayAudit(True, inbounds, sorted(tag for tag in tags if isinstance(tag, str)))


def _resolve_domain(domain: str) -> dict[str, list[str]]:
    records = {"A": set(), "AAAA": set()}
    try:
        answers = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        answers = []
    for family, _kind, _proto, _canon, address in answers:
        if family == socket.AF_INET:
            records["A"].add(address[0])
        elif family == socket.AF_INET6:
            records["AAAA"].add(address[0])
    return {key: sorted(value) for key, value in records.items()}


def _local_addresses() -> set[str]:
    addresses: set[str] = set()
    result = subprocess.run(["ip", "-j", "address"], capture_output=True, text=True, check=False)
    try:
        links = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return addresses
    for link in links:
        for item in link.get("addr_info", []):
            if item.get("scope") in {"global", "host"} and isinstance(item.get("local"), str):
                addresses.add(item["local"])
    return addresses


def _certificate_names(root: Path, domains: set[str]) -> set[str]:
    present = set()
    for domain in domains:
        cert = _root_path(root, f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        if not cert.is_file():
            continue
        try:
            decoded = ssl._ssl._test_decode_cert(str(cert))  # noqa: SLF001
        except (OSError, ssl.SSLError, ValueError):
            continue
        names = {value.lower() for kind, value in decoded.get("subjectAltName", []) if kind == "DNS"}
        if domain in names:
            present.add(domain)
    return present


def audit_host(
    *,
    root: Path = Path("/"),
    listening_ports: set[int] | None = None,
    listener_owners: dict[int, list[str]] | None = None,
    docker_available: bool | None = None,
    dns_records: dict[str, dict[str, list[str]]] | None = None,
    local_addresses: set[str] | None = None,
    tls_names: set[str] | None = None,
    domains: set[str] | None = None,
) -> AuditReport:
    """Collect facts only. No file, service, package, firewall, or DNS mutation occurs."""
    files = _nginx_files(root)
    texts = {path: _read_text(path) for path in files}
    nginx_main = _read_text(_root_path(root, "/etc/nginx/nginx.conf"))
    route_values: dict[str, set[str]] = {}
    route_counts: dict[str, int] = {}
    http_domains: set[str] = set()
    map_files: dict[str, int] = {}
    for path, text in texts.items():
        count = len(_map_blocks(text))
        if count:
            map_files[_host_path(root, path)] = count
        for domain, backend in _parse_sni_entries(text):
            route_values.setdefault(domain, set()).add(backend)
            route_counts[domain] = route_counts.get(domain, 0) + 1
        http_domains.update(_parse_http_domains(text))
    routes = {domain: sorted(backends)[0] for domain, backends in route_values.items()}
    duplicates = sorted(domain for domain, count in route_counts.items() if count > 1)
    if listening_ports is None or listener_owners is None:
        detected_ports, detected_owners = _listener_inventory()
        if listening_ports is None:
            listening_ports = detected_ports
        if listener_owners is None:
            listener_owners = detected_owners
    if docker_available is None:
        docker_available = shutil.which("docker") is not None

    requested = set(domains or ()) | set((dns_records or {}).keys())
    records = dns_records if dns_records is not None else {name: _resolve_domain(name) for name in requested}
    local = _local_addresses() if local_addresses is None else local_addresses
    cert_names = _certificate_names(root, requested) if tls_names is None else tls_names
    domain_audits = []
    for domain in sorted(validate_domain(name) for name in requested):
        record = records.get(domain, {})
        a_records = sorted(set(record.get("A", [])))
        aaaa_records = sorted(set(record.get("AAAA", [])))
        domain_audits.append(DomainAudit(
            domain=domain,
            a_records=a_records,
            aaaa_records=aaaa_records,
            dns_matches_host=bool(set(a_records) & local),
            unhandled_aaaa=bool(aaaa_records and not set(aaaa_records) <= local),
            tls_certificate_present=domain in cert_names,
        ))

    return AuditReport(
        nginx=NginxAudit(
            installed=bool(files),
            stream_enabled=bool(re.search(r"(?m)^\s*stream\s*\{", nginx_main)),
            sni_routes=dict(sorted(routes.items())),
            http_domains=sorted(http_domains),
            config_files=[_host_path(root, path) for path in files],
            sni_map_count=sum(map_files.values()),
            sni_map_files=dict(sorted(map_files.items())),
            duplicate_sni_domains=duplicates,
        ),
        xray=_xray_audit(root),
        docker_available=docker_available,
        listening_ports=sorted(listening_ports),
        listener_owners={port: sorted(set(names)) for port, names in sorted(listener_owners.items())},
        domains=domain_audits,
    )


def _listener_inventory() -> tuple[set[int], dict[int, list[str]]]:
    result = subprocess.run(["ss", "-H", "-lntp"], capture_output=True, text=True, check=False)
    ports: set[int] = set()
    owners: dict[int, list[str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        endpoint = fields[3] if len(fields) > 3 else ""
        match = re.search(r":(\d+)$", endpoint)
        if match:
            port = int(match.group(1))
            ports.add(port)
            names = re.findall(r'users:\(\("([^"\\]+)"', line)
            if names:
                owners.setdefault(port, []).extend(names)
    return ports, owners


def _listening_ports() -> set[int]:
    return _listener_inventory()[0]


def _map_blocks(text: str) -> list[tuple[int, int]]:
    blocks = []
    pattern = re.compile(r"map\s+\$ssl_preread_server_name\s+\$[A-Za-z0-9_]+\s*\{")
    for match in pattern.finditer(text):
        depth = 0
        for index in range(match.end() - 1, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((match.start(), index + 1))
                    break
        else:
            raise InstallerConflict("unterminated SNI map")
    return blocks


def patch_stream_map(
    text: str,
    *,
    proxy_domain: str,
    panel_domain: str,
    proxy_backend: str,
    panel_backend: str,
    ownership_id: str | None = None,
) -> str:
    proxy_domain, panel_domain = validate_domain(proxy_domain), validate_domain(panel_domain)
    if proxy_domain == panel_domain:
        raise InstallerConflict("proxy and panel domains must differ")
    blocks = _map_blocks(text)
    if len(blocks) != 1:
        raise InstallerConflict("exactly one SNI map is required")
    start, end = blocks[0]
    block = text[start:end]
    wanted = {proxy_domain: proxy_backend, panel_domain: panel_backend}
    existing = _parse_sni_routes(block)
    for domain, backend in wanted.items():
        if domain in existing and backend != existing[domain]:
            raise InstallerConflict(f"domain already routed: {domain}")
    suffix = f" {ownership_id}" if ownership_id else ""
    begin, finish = OWNERSHIP_BEGIN + suffix, OWNERSHIP_END + suffix
    managed = (
        f"    {begin}\n"
        f"    {proxy_domain} {proxy_backend};\n"
        f"    {panel_domain} {panel_backend};\n"
        f"    {finish}\n"
    )
    begins, ends = block.count(OWNERSHIP_BEGIN), block.count(OWNERSHIP_END)
    if (begins, ends) == (1, 1):
        marker_start = block.index(OWNERSHIP_BEGIN)
        marker_end = block.index("\n", block.index(OWNERSHIP_END, marker_start))
        current = block[marker_start:marker_end]
        expected = managed.strip()
        def normalize(value: str) -> str:
            return "\n".join(line.strip() for line in value.splitlines())

        if normalize(current) != normalize(expected):
            raise InstallerConflict("owned route block differs from requested configuration")
        return text
    if (begins, ends) != (0, 0):
        raise InstallerConflict("malformed ownership markers")
    default_match = re.search(r"(?m)^\s*default\s+[^;]+;", block)
    if default_match is None:
        raise InstallerConflict("SNI map has no default route")
    insert_at = start + default_match.start()
    return text[:insert_at] + managed + text[insert_at:]

def _owned_route_marker(state: dict, *, end: bool = False) -> str:
    prefix = OWNERSHIP_END if end else OWNERSHIP_BEGIN
    return f"{prefix} {state['install_id']}"


def _remove_owned_route_block(current: bytes, state: dict) -> bytes:
    try:
        text = current.decode()
    except UnicodeDecodeError as exc:
        raise InstallerConflict("owned route file has drifted") from exc
    lines = text.splitlines(keepends=True)
    begin = _owned_route_marker(state)
    end = _owned_route_marker(state, end=True)
    begins = [index for index, line in enumerate(lines) if line.strip() == begin]
    ends = [index for index, line in enumerate(lines) if line.strip() == end]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise InstallerConflict("owned route file has drifted")
    start, finish = begins[0], ends[0]
    plan = state["plan"]
    expected = [
        begin,
        f"{plan['proxy_domain']} {plan['proxy_backend']};",
        f"{plan['panel_domain']} {plan['panel_backend']};",
        end,
    ]
    if [line.strip() for line in lines[start:finish + 1]] != expected:
        raise InstallerConflict("owned route file has drifted")
    return "".join(lines[:start] + lines[finish + 1:]).encode()


@dataclass(frozen=True)
class InstallPlan:
    proxy_domain: str
    panel_domain: str
    route_file: str = "/etc/nginx/stream.d/routes.conf"
    proxy_backend_port: int = 8445
    panel_backend_port: int = 8787
    schema: int = 1

    @property
    def proxy_backend(self) -> str:
        return f"127.0.0.1:{self.proxy_backend_port}"

    @property
    def panel_backend(self) -> str:
        return f"127.0.0.1:{self.panel_backend_port}"

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "proxy_domain": self.proxy_domain,
            "panel_domain": self.panel_domain,
            "proxy_backend": self.proxy_backend,
            "panel_backend": self.panel_backend,
            "route_file": self.route_file,
            "actions": [
                {"kind": "nginx_route", "target": self.route_file},
                {"kind": "ownership_manifest", "target": STATE_PATH},
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_audit(
        cls,
        report: AuditReport,
        *,
        proxy_domain: str,
        panel_domain: str,
        route_file: str = "/etc/nginx/stream.d/routes.conf",
        proxy_backend_port: int = 8445,
        panel_backend_port: int = 8787,
        require_domain_preflight: bool = True,
    ) -> "InstallPlan":
        proxy_domain, panel_domain = validate_domain(proxy_domain), validate_domain(panel_domain)
        if proxy_domain == panel_domain:
            raise InstallerConflict("proxy and panel domains must differ")
        if not route_file.startswith("/") or ".." in Path(route_file).parts:
            raise InstallerConflict("route file must be a normalized absolute path")
        known = set(report.nginx.sni_routes) | set(report.nginx.http_domains)
        for domain in (proxy_domain, panel_domain):
            if domain in known:
                raise InstallerConflict(f"domain already routed: {domain}")
        if report.nginx.duplicate_sni_domains:
            raise InstallerConflict("duplicate SNI routes make the topology ambiguous")
        if report.nginx.stream_enabled and report.nginx.sni_map_count != 1:
            raise InstallerConflict("exactly one SNI map is required")
        for port in (proxy_backend_port, panel_backend_port):
            if not 1024 <= port <= 65535:
                raise InstallerConflict(f"backend port {port} is outside 1024..65535")
            if port in report.listening_ports:
                raise InstallerConflict(f"backend port {port} is already listening")
        if not report.nginx.stream_enabled and 443 in report.listening_ports:
            raise InstallerConflict("public 443 is occupied without an Nginx stream router")
        owners_443 = report.listener_owners.get(443, [])
        if report.nginx.stream_enabled and owners_443 and not any("nginx" in name.lower() for name in owners_443):
            raise InstallerConflict("public 443 is not owned by Nginx despite a stream configuration")
        if not report.docker_available:
            raise InstallerConflict("Docker is unavailable")
        if report.nginx.stream_enabled and report.nginx.sni_map_files.get(route_file) != 1:
            raise InstallerConflict("route file is not the single audited SNI map file")
        if require_domain_preflight:
            checks = {item.domain: item for item in report.domains}
            if set(checks) != {proxy_domain, panel_domain}:
                raise InstallerConflict("domain preflight evidence is incomplete")
            for domain in (proxy_domain, panel_domain):
                check = checks.get(domain)
                if check is None or not check.dns_matches_host:
                    raise InstallerConflict(f"DNS does not resolve to this host: {domain}")
                if check.unhandled_aaaa:
                    raise InstallerConflict(f"unhandled AAAA record: {domain}")
                if not check.tls_certificate_present:
                    raise InstallerConflict(f"TLS certificate is missing or does not cover: {domain}")
        return cls(proxy_domain, panel_domain, route_file, proxy_backend_port, panel_backend_port)




def _state_path(root: Path) -> Path:
    return _root_path(root, STATE_PATH)


def _write_state(path: Path, state: dict) -> None:
    _atomic_write(path, (json.dumps(state, indent=2, sort_keys=True) + "\n").encode(), mode=0o600)


def _validate_manifest_plan(plan: object) -> None:
    if not isinstance(plan, dict):
        raise InstallerConflict("ownership manifest plan is invalid")
    required = {
        "schema", "proxy_domain", "panel_domain", "proxy_backend", "panel_backend",
        "route_file", "actions",
    }
    if set(plan) != required or plan.get("schema") != 1:
        raise InstallerConflict("ownership manifest plan is invalid")
    try:
        proxy_domain = validate_domain(plan["proxy_domain"])
        panel_domain = validate_domain(plan["panel_domain"])
    except (TypeError, ValueError) as exc:
        raise InstallerConflict("ownership manifest plan is invalid") from exc
    if proxy_domain == panel_domain:
        raise InstallerConflict("ownership manifest plan is invalid")
    route_file = plan["route_file"]
    if not isinstance(route_file, str) or not route_file.startswith("/") or ".." in Path(route_file).parts:
        raise InstallerConflict("ownership manifest plan is invalid")
    for key in ("proxy_backend", "panel_backend"):
        if not isinstance(plan[key], str) or not re.fullmatch(r"127\.0\.0\.1:(\d{4,5})", plan[key]):
            raise InstallerConflict("ownership manifest plan is invalid")
        port = int(plan[key].rsplit(":", 1)[1])
        if not 1024 <= port <= 65535:
            raise InstallerConflict("ownership manifest plan is invalid")
    expected_actions = [
        {"kind": "nginx_route", "target": route_file},
        {"kind": "ownership_manifest", "target": STATE_PATH},
    ]
    if plan["actions"] != expected_actions:
        raise InstallerConflict("ownership manifest plan is invalid")


def _load_state(root: Path) -> tuple[Path, dict] | None:
    path = _state_path(root)
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallerConflict("ownership manifest is unreadable") from exc
    required = {
        "schema", "install_id", "status", "route_file", "backup_file", "route_mode",
        "route_uid", "route_gid", "route_sha256_before", "route_sha256_owned", "plan",
    }
    if set(state) != required or state.get("schema") != STATE_SCHEMA:
        raise InstallerConflict("ownership manifest schema is invalid")
    if state["status"] not in {"applying", "active", "uninstalling"}:
        raise InstallerConflict("ownership manifest status is invalid")
    install_id = state.get("install_id")
    if not isinstance(install_id, str) or not re.fullmatch(r"[0-9a-f]{32}", install_id):
        raise InstallerConflict("ownership manifest generation is invalid")
    for key in ("route_file", "backup_file"):
        if not isinstance(state[key], str) or not state[key].startswith("/") or ".." in Path(state[key]).parts:
            raise InstallerConflict("ownership manifest contains an unsafe path")
    expected_backup = f"/var/lib/proxy-control/backups/{install_id}.route"
    if state["backup_file"] != expected_backup:
        raise InstallerConflict("ownership manifest generation does not match its backup")
    for key in ("route_mode", "route_uid", "route_gid"):
        if isinstance(state[key], bool) or not isinstance(state[key], int) or state[key] < 0:
            raise InstallerConflict("ownership manifest metadata is invalid")
    if state["route_mode"] > 0o7777:
        raise InstallerConflict("ownership manifest metadata is invalid")
    _validate_manifest_plan(state["plan"])
    for key, label in (
        ("route_sha256_before", "original"),
        ("route_sha256_owned", "owned"),
    ):
        if not isinstance(state[key], str) or not re.fullmatch(r"[0-9a-f]{64}", state[key]):
            raise InstallerConflict(f"ownership manifest has an invalid {label} hash")
    return path, state


def _canonical_route(root: Path, route_file: str) -> tuple[Path, str]:
    supplied = _root_path(root, route_file)
    try:
        resolved = supplied.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise InstallerConflict(f"route file does not exist: {route_file}") from exc
    if not resolved.is_file():
        raise InstallerConflict(f"route file is not regular: {route_file}")
    return resolved, _host_path(root.resolve(), resolved)


def _run_nginx_validate() -> None:
    subprocess.run(["nginx", "-t"], check=True)


def _run_nginx_reload() -> None:
    subprocess.run(["systemctl", "reload", "nginx"], check=True)



def _apply_plan_unlocked(
    plan: InstallPlan,
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> Path:
    loaded = _load_state(root)
    if loaded is not None:
        _path, state = loaded
        if state["status"] == "active" and state["plan"] == plan.to_dict():
            _repair_installation_unlocked(root=root, validate=validate, reload=reload)
            return _state_path(root)
        raise InstallerConflict("another owned installation or interrupted transaction exists")
    route, route_host_path = _canonical_route(root, plan.route_file)
    original = route.read_bytes()
    metadata = route.stat()
    install_id = uuid.uuid4().hex
    changed = patch_stream_map(
        original.decode(),
        proxy_domain=plan.proxy_domain,
        panel_domain=plan.panel_domain,
        proxy_backend=plan.proxy_backend,
        panel_backend=plan.panel_backend,
        ownership_id=install_id,
    ).encode()
    backup_host = f"/var/lib/proxy-control/backups/{install_id}.route"
    backup = _root_path(root, backup_host)
    _atomic_write(backup, original, mode=0o600)
    state = {
        "schema": STATE_SCHEMA,
        "install_id": install_id,
        "status": "applying",
        "route_file": route_host_path,
        "backup_file": backup_host,
        "route_mode": stat.S_IMODE(metadata.st_mode),
        "route_uid": metadata.st_uid,
        "route_gid": metadata.st_gid,
        "route_sha256_before": _sha256(original),
        "route_sha256_owned": _sha256(changed),
        "plan": plan.to_dict(),
    }
    manifest = _state_path(root)
    _write_state(manifest, state)
    try:
        _atomic_write(
            route,
            changed,
            mode=state["route_mode"],
            owner=(state["route_uid"], state["route_gid"]),
        )
        validate()
        reload()
        state["status"] = "active"
        _write_state(manifest, state)
    except BaseException:
        _atomic_write(
            route,
            original,
            mode=state["route_mode"],
            owner=(state["route_uid"], state["route_gid"]),
        )
        try:
            validate()
            reload()
        except BaseException:
            # Keep the durable applying journal and backup: repair can retry.
            raise
        manifest.unlink(missing_ok=True)
        _fsync_dir(manifest.parent)
        raise
    return manifest


def _repair_installation_unlocked(
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> None:
    loaded = _load_state(root)
    if loaded is None:
        return
    manifest, state = loaded
    route = _root_path(root, state["route_file"])
    backup = _root_path(root, state["backup_file"])
    if not route.is_file():
        raise InstallerConflict("owned route or backup is missing")
    current = route.read_bytes()
    if not backup.is_file():
        if state["status"] == "uninstalling" and _owned_route_marker(state) not in current.decode(errors="ignore"):
            validate()
            reload()
            manifest.unlink()
            _fsync_dir(manifest.parent)
            return
        raise InstallerConflict("owned route or backup is missing")
    original = backup.read_bytes()
    if _sha256(original) != state["route_sha256_before"]:
        raise InstallerConflict("owned backup has drifted")
    if state["status"] == "active":
        _remove_owned_route_block(current, state)
        validate()
        return
    if state["status"] == "applying":
        if _sha256(current) not in {state["route_sha256_before"], state["route_sha256_owned"]}:
            raise InstallerConflict("owned route file has drifted")
        _atomic_write(
            route,
            original,
            mode=state["route_mode"],
            owner=(state["route_uid"], state["route_gid"]),
        )
        validate()
        reload()
        manifest.unlink()
        _fsync_dir(manifest.parent)
        return
    if state["status"] == "uninstalling":
        _uninstall_installation_unlocked(root=root, validate=validate, reload=reload)
        return
    raise InstallerConflict("owned route file has drifted")


def _uninstall_installation_unlocked(
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> None:
    loaded = _load_state(root)
    if loaded is None:
        return
    manifest, state = loaded
    if state["status"] not in {"active", "uninstalling"}:
        raise InstallerConflict("repair the interrupted transaction before uninstall")
    route = _root_path(root, state["route_file"])
    backup = _root_path(root, state["backup_file"])
    if not route.is_file():
        raise InstallerConflict("owned route or backup is missing")
    current = route.read_bytes()
    marker_present = _owned_route_marker(state) in current.decode(errors="ignore")
    if not backup.is_file():
        if state["status"] == "uninstalling" and not marker_present:
            validate()
            reload()
            manifest.unlink()
            _fsync_dir(manifest.parent)
            return
        raise InstallerConflict("owned route or backup is missing")
    original = backup.read_bytes()
    if _sha256(original) != state["route_sha256_before"]:
        raise InstallerConflict("owned backup has drifted")
    updated = _remove_owned_route_block(current, state) if marker_present else current
    was_active = state["status"] == "active"
    if was_active:
        state["status"] = "uninstalling"
        _write_state(manifest, state)
    try:
        if updated != current:
            _atomic_write(
                route,
                updated,
                mode=state["route_mode"],
                owner=(state["route_uid"], state["route_gid"]),
            )
        validate()
        reload()
    except BaseException:
        if updated != current:
            _atomic_write(
                route,
                current,
                mode=state["route_mode"],
                owner=(state["route_uid"], state["route_gid"]),
            )
        if was_active:
            state["status"] = "active"
            _write_state(manifest, state)
        validate()
        reload()
        raise
    backup.unlink()
    _fsync_dir(backup.parent)
    manifest.unlink()
    _fsync_dir(manifest.parent)


def apply_plan(
    plan: InstallPlan,
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> Path:
    with _operation_lock(root):
        return _apply_plan_unlocked(plan, root=root, validate=validate, reload=reload)


def repair_installation(
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> None:
    with _operation_lock(root):
        _repair_installation_unlocked(root=root, validate=validate, reload=reload)


def uninstall_installation(
    *,
    root: Path = Path("/"),
    validate: Callable[[], None] = _run_nginx_validate,
    reload: Callable[[], None] = _run_nginx_reload,
) -> None:
    with _operation_lock(root):
        _uninstall_installation_unlocked(root=root, validate=validate, reload=reload)


RUNTIME_STATE_PATH = "/var/lib/proxy-control/runtime.json"
RUNTIME_STATE_SCHEMA = 2
RUNTIME_CORE_PACKAGES = ("ca-certificates", "certbot", "curl", "openssl", "python3")
INSTALL_PHASES = {
    "initialized", "packages_installed", "project_rendered", "sites_installed",
    "compose_started", "route_installed", "rollback_routes", "rollback_compose",
    "rollback_sites", "rollback_project", "rollback_packages", "rollback_complete",
}
UNINSTALL_PHASES = {
    "started", "compose_stopping", "compose_down", "data_purging",
    "data_purged", "route_removing", "route_removed", "sites_removing",
    "sites_removed", "project_cleaning", "project_cleaned",
    "packages_purging", "packages_purged",
}


@dataclass(frozen=True)
class RuntimePlan:
    """Complete, deterministic host-runtime installation contract."""

    proxy_domain: str
    panel_domain: str
    email: str
    route_file: str
    source_dir: str
    project_dir: str = "/opt/mtproxy-shared443"
    users: tuple[str, ...] = ("default",)
    proxy_backend_port: int = 8445
    panel_app_port: int = 8787
    panel_tls_port: int = 8443
    protocol_probe: str = ""
    schema: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "proxy_domain", validate_domain(self.proxy_domain))
        object.__setattr__(self, "panel_domain", validate_domain(self.panel_domain))
        if self.proxy_domain == self.panel_domain:
            raise InstallerConflict("proxy and panel domains must differ")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", self.email):
            raise InstallerConflict("a valid ACME email is required")
        for value, label in ((self.route_file, "route file"), (self.project_dir, "project directory")):
            if not value.startswith("/") or ".." in Path(value).parts:
                raise InstallerConflict(f"{label} must be a normalized absolute path")
        if not self.protocol_probe.startswith("/"):
            raise InstallerConflict("an absolute protocol verification hook is required")
        if not self.users or len(set(self.users)) != len(self.users) or any(
            not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) for name in self.users
        ):
            raise InstallerConflict("users must be unique safe names")
        for port in (self.proxy_backend_port, self.panel_app_port, self.panel_tls_port):
            if not 1024 <= port <= 65535:
                raise InstallerConflict("runtime ports must be in 1024..65535")

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "proxy_domain": self.proxy_domain,
            "panel_domain": self.panel_domain,
            "email": self.email,
            "route_file": self.route_file,
            "source_dir": self.source_dir,
            "project_dir": self.project_dir,
            "users": list(self.users),
            "proxy_backend_port": self.proxy_backend_port,
            "panel_app_port": self.panel_app_port,
            "panel_tls_port": self.panel_tls_port,
            "protocol_probe": self.protocol_probe,
            "actions": [
                "install_missing_packages", "create_two_domain_acme_vhosts", "issue_certificate",
                "render_compose_and_secrets", "bootstrap_panel_from_password_file",
                "start_and_healthcheck_compose", "install_panel_tls_vhost",
                "transactionally_install_sni_routes", "run_respq_protocol_hook",
            ],
        }


class CommandRunner:
    """Small injectable host-command boundary; suppresses all command output."""

    def package_installed(self, name: str) -> bool:
        return subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", name],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False,
        ).stdout == "install ok installed"

    def command_available(self, name: str) -> bool:
        return shutil.which(name) is not None

    def compose_available(self) -> bool:
        try:
            return subprocess.run(
                ["docker", "compose", "version"], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False,
            ).returncode == 0
        except OSError:
            return False

    @staticmethod
    def _query(argv: Sequence[str]) -> str:
        command = [str(value) for value in argv]
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallerConflict(
                f"command query failed: {' '.join(command)}"
            ) from exc
        if completed.returncode:
            detail = " ".join((completed.stderr or "").split())[-2000:]
            suffix = f": {detail}" if detail else ""
            raise InstallerConflict(
                f"command query failed ({completed.returncode}): "
                f"{' '.join(command)}{suffix}"
            )
        return completed.stdout or ""

    def _compose_project_name(self, project_dir: str) -> str:
        command = (
            "docker",
            "compose",
            "--project-directory",
            project_dir,
            "config",
            "--format",
            "json",
        )
        try:
            value = json.loads(self._query(command))
        except json.JSONDecodeError as exc:
            raise InstallerConflict(
                "compose project identity is unreadable"
            ) from exc
        name = value.get("name") if isinstance(value, dict) else None
        if not isinstance(name, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9_-]*",
            name,
        ):
            raise InstallerConflict("compose project identity is invalid")
        return name

    def compose_project_present(self, project_dir: str) -> bool:
        compose = (
            "docker",
            "compose",
            "--project-directory",
            project_dir,
            "ps",
            "-a",
            "-q",
        )
        project = self._compose_project_name(project_dir)
        networks = (
            "docker",
            "network",
            "ls",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
        )
        return bool(
            self._query(compose).strip()
            or self._query(networks).strip()
        )

    def compose_project_volumes_present(self, project_dir: str) -> bool:
        project = self._compose_project_name(project_dir)
        command = (
            "docker",
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
        )
        return bool(self._query(command).strip())

    def run(self, argv, *, stdin_path: Path | None = None, env: dict[str, str] | None = None) -> None:
        stdin = stdin_path.open("rb") if stdin_path else subprocess.DEVNULL
        try:
            command = [str(value) for value in argv]
            completed = subprocess.run(
                command, check=False, stdin=stdin, text=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
            )
            if completed.returncode:
                detail = " ".join((completed.stderr or "").split())[-2000:]
                suffix = f": {detail}" if detail else ""
                raise InstallerConflict(
                    f"command failed ({completed.returncode}): {' '.join(command)}{suffix}"
                )
        finally:
            if stdin_path:
                stdin.close()

    def capture(self, argv, *, max_chars: int) -> str:
        """Capture a bounded diagnostic command without inheriting a terminal."""
        command = [str(value) for value in argv]
        limit = max(0, min(max_chars, 4096))
        try:
            completed = subprocess.run(
                command, check=False, stdin=subprocess.DEVNULL, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"diagnostic unavailable: {type(exc).__name__}"[:limit]
        output = completed.stdout or ""
        if completed.returncode:
            output = f"exit={completed.returncode} {output}"
        return output[-limit:]


class RuntimeInstaller:
    """Transactional full-runtime manager, testable against a fake root and runner."""

    def __init__(self, plan: RuntimePlan, *, root: Path = Path("/"), runner=None):
        self.plan = plan
        self.root = root
        self.runner = runner or CommandRunner()
        self.state_path = _root_path(root, RUNTIME_STATE_PATH)

    def _run(self, *argv: str, stdin_path: Path | None = None) -> None:
        self.runner.run(argv, stdin_path=stdin_path)

    def _compose(self, *args: str) -> None:
        self._run("docker", "compose", "--project-directory", self.plan.project_dir, *args)

    @staticmethod
    def _sanitize_diagnostic(value: str, *, max_chars: int = 4096) -> str:
        clean = " ".join(value.split())
        clean = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", clean)
        clean = re.sub(
            r"(?i)\b(password|secret|token|authorization)(\s*[=:]\s*|\s+)\S+",
            lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
            clean,
        )
        return clean[-max_chars:]

    def _compose_start(self) -> None:
        try:
            self._compose("up", "-d", "--wait")
        except InstallerConflict as original:
            compose = ("docker", "compose", "--project-directory", self.plan.project_dir)

            def capture(command: tuple[str, ...], limit: int) -> str:
                try:
                    value = self.runner.capture(command, max_chars=limit)
                except Exception as exc:
                    value = f"diagnostic unavailable: {type(exc).__name__}"
                return self._sanitize_diagnostic(value, max_chars=limit)

            container = capture(compose + ("ps", "-q", "panel"), 256).strip().splitlines()
            if container and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", container[-1]):
                health = capture(
                    ("docker", "inspect", "--format", "{{json .State.Health}}", container[-1]),
                    2400,
                )
            else:
                health = "container id unavailable"
            diagnostics = (
                ("panel health", health),
                ("panel logs", capture(compose + ("logs", "--no-color", "--tail", "80", "panel"), 600)),
                ("compose ps", capture(compose + ("ps",), 400)),
            )
            summary = self._sanitize_diagnostic(str(original), max_chars=300)
            detail = "; ".join(f"{label}: {value or '(empty)'}" for label, value in diagnostics)
            raise InstallerConflict(f"compose startup failed: {summary}; startup diagnostics: {detail}") from original

    def _managed_paths(self) -> list[str]:
        return [
            "/etc/nginx/sites-available/proxy-control-acme.conf",
            "/etc/nginx/sites-available/proxy-control-panel.conf",
            "/etc/nginx/sites-enabled/proxy-control-acme.conf",
            "/etc/nginx/sites-enabled/proxy-control-panel.conf",
        ]

    @staticmethod
    def _path_hash(path: Path) -> str:
        if path.is_symlink():
            return _sha256(("symlink:" + os.readlink(path)).encode())
        return _sha256(path.read_bytes())

    def _check_unowned_paths(self) -> None:
        for host_path in self._managed_paths():
            if _root_path(self.root, host_path).exists() or _root_path(self.root, host_path).is_symlink():
                raise InstallerConflict(f"refusing to replace unowned Nginx file: {host_path}")

    def _acme_site_content(self) -> bytes:
        return (
            f"server {{ listen 80; server_name {self.plan.proxy_domain}; "
            f"location ^~ /.well-known/acme-challenge/ {{ root /var/www/{self.plan.proxy_domain}; }} "
            "location / { return 301 https://$host$request_uri; } }\n"
            f"server {{ listen 80; server_name {self.plan.panel_domain}; "
            f"location ^~ /.well-known/acme-challenge/ {{ root /var/www/{self.plan.panel_domain}; }} "
            "location / { return 301 https://$host$request_uri; } }\n"
        ).encode()

    def _panel_site_content(self) -> bytes:
        proxy = (
            f"proxy_pass http://127.0.0.1:{self.plan.panel_app_port}; "
            "proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; "
            "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; "
        )
        return (
            f"server {{ listen 127.0.0.1:{self.plan.panel_tls_port} ssl; "
            f"server_name {self.plan.panel_domain}; "
            f"ssl_certificate /etc/letsencrypt/live/{self.plan.proxy_domain}/fullchain.pem; "
            f"ssl_certificate_key /etc/letsencrypt/live/{self.plan.proxy_domain}/privkey.pem; "
            f"location = / {{ error_page 418 = @panel_root; "
            f"if ($cookie_panel_session != \"\") {{ return 418; }} "
            f"root /var/www/{self.plan.panel_domain}; try_files /index.html =404; }} "
            f"location @panel_root {{ {proxy}}} "
            f"location / {{ {proxy}}} }}\n"
        ).encode()

    def _expected_managed_hashes(self) -> dict[str, str]:
        return {
            self._managed_paths()[0]: _sha256(self._acme_site_content()),
            self._managed_paths()[1]: _sha256(self._panel_site_content()),
            self._managed_paths()[2]: _sha256(b"symlink:../sites-available/proxy-control-acme.conf"),
            self._managed_paths()[3]: _sha256(b"symlink:../sites-available/proxy-control-panel.conf"),
        }

    def _write_acme_site(self) -> None:
        for domain in (self.plan.proxy_domain, self.plan.panel_domain):
            webroot = _root_path(self.root, f"/var/www/{domain}")
            well_known = webroot / ".well-known"
            challenge = well_known / "acme-challenge"
            _durable_mkdir(challenge)
            for directory in (webroot, well_known, challenge):
                os.chmod(directory, 0o755)
                _fsync_dir(directory)
        available = _root_path(self.root, "/etc/nginx/sites-available")
        enabled = _root_path(self.root, "/etc/nginx/sites-enabled")
        _atomic_write(available / "proxy-control-acme.conf", self._acme_site_content(), mode=0o644)
        _durable_symlink("../sites-available/proxy-control-acme.conf", enabled / "proxy-control-acme.conf")

    def _write_panel_site(self) -> None:
        available = _root_path(self.root, "/etc/nginx/sites-available")
        enabled = _root_path(self.root, "/etc/nginx/sites-enabled")
        _atomic_write(available / "proxy-control-panel.conf", self._panel_site_content(), mode=0o640)
        _durable_symlink("../sites-available/proxy-control-panel.conf", enabled / "proxy-control-panel.conf")

    def _render_project(self, *, recovery: bool = False) -> bool:
        project = _root_path(self.root, self.plan.project_dir)
        marker = project / ".mtproxy-owned"
        created = not project.exists()
        if project.exists() and any(project.iterdir()):
            names = {entry.name for entry in project.iterdir()}
            if not recovery or ".mtproxy-owned" not in names or not names <= {".mtproxy-owned", "secrets"}:
                raise InstallerConflict("pre-existing project requires explicit migration; refusing overwrite")
        _durable_mkdir(project)
        if not marker.exists():
            _atomic_write(marker, (uuid.uuid4().hex + "\n").encode(), mode=0o600)
        source = Path(self.plan.source_dir)
        if not source.is_dir():
            raise InstallerConflict("installer source directory does not exist")
        for name in ("compose.yaml", "uninstall.sh"):
            _durable_copy2(source / name, project / name)
        target_scripts = project / "scripts"
        _durable_mkdir(target_scripts)
        _durable_copy2(source / "scripts/proxyctl.py", target_scripts / "proxyctl.py")
        for directory in ("docker", "installer", "panel"):
            shutil.copytree(
                source / directory, project / directory, dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("tests", "__pycache__", "*.pyc", "*.sqlite3*"),
            )
            _fsync_tree(project / directory)
        secret_dir = project / "secrets"
        _durable_mkdir(secret_dir, mode=0o700)
        users_file = secret_dir / "users.conf"
        existing: dict[str, str] = {}
        if users_file.is_file():
            for line in users_file.read_text().splitlines():
                if "=" in line:
                    name, value = line.split("=", 1)
                    if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) and re.fullmatch(r"[0-9a-f]{32}", value):
                        existing[name] = value
        _atomic_write(users_file, "".join(
            f"{name}={existing.get(name, secrets.token_hex(16))}\n" for name in self.plan.users
        ).encode(), mode=0o600)
        token = secret_dir / "telemt-api-token"
        if not token.exists():
            _atomic_write(token, ("Bearer " + secrets.token_urlsafe(48) + "\n").encode(), mode=0o600)
        password = secret_dir / "panel-bootstrap-password"
        if not password.exists():
            _atomic_write(password, (secrets.token_urlsafe(32) + "\n").encode(), mode=0o600)
        env = (
            f"MTPROXY_DOMAIN={self.plan.proxy_domain}\n"
            f"MTPROXY_BACKEND_PORT={self.plan.proxy_backend_port}\n"
            f"MTPROXY_COVER_ROOT=/var/www/{self.plan.proxy_domain}\n"
            "MTPROXY_LETSENCRYPT_ROOT=/etc/letsencrypt\n"
            f"PANEL_ALLOWED_HOSTS={self.plan.panel_domain}\n"
            f"PANEL_HEALTHCHECK_HOST={self.plan.panel_domain}\n"
        )
        _atomic_write(project / ".env", env.encode(), mode=0o600)
        cover = _root_path(self.root, f"/var/www/{self.plan.proxy_domain}/index.html")
        if not cover.exists():
            _atomic_write(cover, b"<!doctype html><title>Welcome</title><h1>Welcome</h1>\n", mode=0o644)
        panel_cover = _root_path(self.root, f"/var/www/{self.plan.panel_domain}/index.html")
        if not panel_cover.exists():
            _atomic_write(panel_cover, b"<!doctype html><title>Workspace</title><h1>Secure workspace</h1>\n", mode=0o644)
        return created

    def _remove_managed_files(self, state: dict, *, check_hashes: bool, allow_missing: bool = False) -> None:
        hashes = state.get("managed_hashes", {})
        paths = [(host_path, _root_path(self.root, host_path)) for host_path in state.get("managed_files", [])]
        if check_hashes:
            for host_path, path in paths:
                exists = path.exists() or path.is_symlink()
                if not exists and allow_missing:
                    continue
                if not exists or host_path not in hashes or self._path_hash(path) != hashes[host_path]:
                    raise InstallerConflict(f"managed file has drifted: {host_path}")
        for _host_path, path in reversed(paths):
            if path.exists() or path.is_symlink():
                _durable_remove(path)

    def _snapshot_managed_files(self, state: dict) -> dict[str, tuple]:
        snapshots = {}
        for host_path in state.get("managed_files", []):
            path = _root_path(self.root, host_path)
            if path.is_symlink():
                snapshots[host_path] = ("symlink", os.readlink(path))
            elif path.is_file():
                snapshots[host_path] = ("file", path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
            else:
                raise InstallerConflict(f"managed file is missing: {host_path}")
        return snapshots

    def _restore_managed_files(self, snapshots: dict[str, tuple]) -> None:
        for host_path, snapshot in snapshots.items():
            path = _root_path(self.root, host_path)
            _durable_remove(path, missing_ok=True)
            if snapshot[0] == "symlink":
                _durable_symlink(snapshot[1], path)
            else:
                _atomic_write(path, snapshot[1], mode=snapshot[2])

    def _read_runtime_state(self) -> dict:
        try:
            state = json.loads(self.state_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise InstallerConflict("runtime manifest is unreadable") from exc
        required = {
            "schema", "status", "phase", "plan", "owned_packages", "managed_files",
            "managed_hashes", "project_created",
        }
        keys = frozenset(state)
        uninstall_ownership = {"purge_data", "project_marker_sha256"}
        allowed_keys = {
            frozenset(required),
            frozenset(required | {"rollback_error"}),
            frozenset(required | uninstall_ownership),
        }
        if keys not in allowed_keys:
            raise InstallerConflict("runtime manifest schema is invalid")
        if state.get("schema") != RUNTIME_STATE_SCHEMA:
            raise InstallerConflict("runtime manifest schema is invalid")
        status, phase = state.get("status"), state.get("phase")
        if status == "active" and phase != "route_installed":
            raise InstallerConflict("runtime manifest phase is invalid")
        if status in {"installing", "rollback_failed"} and phase not in INSTALL_PHASES:
            raise InstallerConflict("runtime manifest phase is invalid")
        if status == "uninstalling" and phase not in UNINSTALL_PHASES:
            raise InstallerConflict("runtime manifest phase is invalid")
        if status not in {"installing", "rollback_failed", "active", "uninstalling"}:
            raise InstallerConflict("runtime manifest status is invalid")
        if status == "uninstalling":
            if not isinstance(state.get("purge_data"), bool):
                raise InstallerConflict("runtime uninstall data policy is invalid")
            marker_sha256 = state.get("project_marker_sha256")
            if (
                not isinstance(marker_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", marker_sha256)
            ):
                raise InstallerConflict(
                    "runtime project ownership checkpoint is invalid"
                )
        elif uninstall_ownership & set(state):
            raise InstallerConflict("runtime uninstall ownership is invalid")
        if state.get("plan") != self.plan.to_dict():
            raise InstallerConflict("runtime transaction belongs to another plan")
        packages = state.get("owned_packages")
        if not isinstance(packages, list) or packages != sorted(set(packages)) or any(
            not isinstance(item, str) for item in packages
        ):
            raise InstallerConflict("runtime package ownership is invalid")
        if state.get("managed_files") != self._managed_paths():
            raise InstallerConflict("runtime managed-file ownership is invalid")
        if state.get("managed_hashes") != self._expected_managed_hashes():
            raise InstallerConflict("runtime managed-file ownership is invalid")
        if not isinstance(state.get("project_created"), bool):
            raise InstallerConflict("runtime project ownership is invalid")
        return state

    def _checkpoint(self, state: dict, *, status: str | None = None, phase: str | None = None) -> None:
        if status is not None:
            state["status"] = status
        if phase is not None:
            state["phase"] = phase
        state.pop("rollback_error", None)
        _write_state(self.state_path, state)
        if phase is not None and os.environ.get("PROXYCTL_TEST_CRASH_AFTER_PHASE") == phase:
            os.kill(os.getpid(), signal.SIGKILL)

    def _clean_project_preserving_credentials(self) -> None:
        project = _root_path(self.root, self.plan.project_dir)
        if project.is_dir():
            for child in list(project.iterdir()):
                if child.name not in {"secrets", ".mtproxy-owned"}:
                    _durable_remove(child)

    def _validate_owned_project(
        self,
        expected_marker_sha256: str | None = None,
    ) -> str:
        project = _root_path(self.root, self.plan.project_dir)
        current = self.root
        for part in Path(self.plan.project_dir).parts[1:]:
            current /= part
            if current.is_symlink():
                raise InstallerConflict("runtime project ownership has drifted")
        marker = project / ".mtproxy-owned"
        if (
            not project.is_dir()
            or marker.is_symlink()
            or not marker.is_file()
        ):
            raise InstallerConflict("runtime project ownership has drifted")
        actual = self._path_hash(marker)
        if (
            expected_marker_sha256 is not None
            and actual != expected_marker_sha256
        ):
            raise InstallerConflict("runtime project ownership has drifted")
        return actual

    def _require_owned_packages(self, state: dict, *, installed: bool) -> None:
        mismatched = [
            name
            for name in state["owned_packages"]
            if bool(self.runner.package_installed(name)) != installed
        ]
        if mismatched:
            condition = "missing" if installed else "still installed"
            raise InstallerConflict(
                f"runtime owned packages are {condition}: {', '.join(mismatched)}"
            )

    def _validate_uninstall_ownership(
        self,
        state: dict,
        *,
        packages_installed: bool | None = True,
    ) -> None:
        self._validate_owned_project(state["project_marker_sha256"])
        if packages_installed is not None:
            self._require_owned_packages(
                state,
                installed=packages_installed,
            )

    def _compose_project_present(self) -> bool:
        return bool(
            self.runner.compose_project_present(self.plan.project_dir)
        )

    def _compose_project_volumes_present(self) -> bool:
        return bool(
            self.runner.compose_project_volumes_present(
                self.plan.project_dir
            )
        )

    def _rollback_runtime(self, state: dict) -> None:
        """Idempotently restore host routing while retaining generated credentials."""
        try:
            self._checkpoint(state, status="rollback_failed", phase="rollback_routes")
            if _load_state(self.root) is not None:
                _repair_installation_unlocked(
                    root=self.root,
                    validate=lambda: self._run("nginx", "-t"),
                    reload=lambda: self._run("systemctl", "reload", "nginx"),
                )
                if _load_state(self.root) is not None:
                    _uninstall_installation_unlocked(
                        root=self.root,
                        validate=lambda: self._run("nginx", "-t"),
                        reload=lambda: self._run("systemctl", "reload", "nginx"),
                    )
            self._checkpoint(state, status="rollback_failed", phase="rollback_compose")
            self._compose("down", "--remove-orphans", "--volumes")
            self._checkpoint(state, status="rollback_failed", phase="rollback_sites")
            self._remove_managed_files(state, check_hashes=True, allow_missing=True)
            self._validate_reload()
            self._checkpoint(state, status="rollback_failed", phase="rollback_project")
            self._clean_project_preserving_credentials()
            self._checkpoint(state, status="rollback_failed", phase="rollback_packages")
            if state["owned_packages"]:
                self._run("apt-get", "purge", "-y", *state["owned_packages"])
            self._checkpoint(state, status="installing", phase="rollback_complete")
        except BaseException as exc:
            state["status"] = "rollback_failed"
            state["rollback_error"] = type(exc).__name__
            _write_state(self.state_path, state)
            raise

    def _validate_reload(self) -> None:
        self._run("nginx", "-t")
        self._run("systemctl", "reload", "nginx")

    def _health_and_protocol(self) -> None:
        self._compose("config", "-q")
        self._compose("ps", "--status", "running")
        self._run(
            "curl", "-fsS", "-H", f"Host: {self.plan.panel_domain}",
            f"http://127.0.0.1:{self.plan.panel_app_port}/healthz",
        )
        self._run(
            self.plan.protocol_probe, "--domain", self.plan.proxy_domain,
            "--secrets-file", f"{self.plan.project_dir}/secrets/users.conf",
        )

    def install(self) -> Path:
        with _operation_lock(self.root):
            recovering = False
            if self.state_path.exists():
                state = self._read_runtime_state()
                if state["status"] == "active":
                    self.repair(_locked=True)
                    return self.state_path
                if state["status"] == "uninstalling":
                    raise InstallerConflict("runtime uninstall is incomplete; retry uninstall")
                self._rollback_runtime(state)
                recovering = True
            else:
                project = _root_path(self.root, self.plan.project_dir)
                if project.exists() and any(project.iterdir()):
                    raise InstallerConflict("pre-existing project requires explicit migration; refusing overwrite")
                missing = {name for name in RUNTIME_CORE_PACKAGES if not self.runner.package_installed(name)}
                command_available = getattr(self.runner, "command_available", None)
                compose_available = getattr(self.runner, "compose_available", None)
                if not (command_available("nginx") if command_available else self.runner.package_installed("nginx-full")):
                    missing.add("nginx-full")
                if not (command_available("docker") if command_available else self.runner.package_installed("docker.io")):
                    missing.add("docker.io")
                if not (compose_available() if compose_available else self.runner.package_installed("docker-compose-v2")):
                    missing.add("docker-compose-v2")
                state = {
                    "schema": RUNTIME_STATE_SCHEMA, "status": "installing", "phase": "initialized",
                    "plan": self.plan.to_dict(), "owned_packages": sorted(missing),
                    "managed_files": self._managed_paths(),
                    "managed_hashes": self._expected_managed_hashes(),
                    "project_created": not project.exists(),
                }
                _write_state(self.state_path, state)
            route_plan = InstallPlan(
                self.plan.proxy_domain, self.plan.panel_domain, self.plan.route_file,
                self.plan.proxy_backend_port, self.plan.panel_tls_port,
            )
            try:
                if state["owned_packages"]:
                    self._run("apt-get", "update")
                    self._run("apt-get", "install", "-y", *state["owned_packages"])
                self._checkpoint(state, status="installing", phase="packages_installed")
                self._run("systemctl", "enable", "--now", "docker", "nginx")
                self._render_project(recovery=recovering)
                self._checkpoint(state, status="installing", phase="project_rendered")
                self._check_unowned_paths()
                self._write_acme_site()
                self._validate_reload()
                self._run(
                    "certbot", "certonly", "--webroot",
                    "-w", f"/var/www/{self.plan.proxy_domain}", "-d", self.plan.proxy_domain,
                    "-w", f"/var/www/{self.plan.panel_domain}", "-d", self.plan.panel_domain,
                    "--cert-name", self.plan.proxy_domain, "-m", self.plan.email,
                    "--agree-tos", "--non-interactive",
                )
                self._write_panel_site()
                state["managed_hashes"] = {
                    path: self._path_hash(_root_path(self.root, path)) for path in state["managed_files"]
                }
                self._checkpoint(state, status="installing", phase="sites_installed")
                self._validate_reload()
                self._compose("config", "-q")
                self._compose("pull", "-q")
                self._compose_start()
                password = _root_path(self.root, f"{self.plan.project_dir}/secrets/panel-bootstrap-password")
                self._run(
                    "docker", "compose", "--project-directory", self.plan.project_dir,
                    "exec", "-T", "panel", "python", "-m", "panel.cli", "create-admin",
                    "--username", "owner", "--role", "owner", "--password-stdin",
                    stdin_path=password,
                )
                self._checkpoint(state, status="installing", phase="compose_started")
                _apply_plan_unlocked(
                    route_plan, root=self.root,
                    validate=lambda: self._run("nginx", "-t"),
                    reload=lambda: self._run("systemctl", "reload", "nginx"),
                )
                self._checkpoint(state, status="installing", phase="route_installed")
                self._health_and_protocol()
                self._checkpoint(state, status="active", phase="route_installed")
                return self.state_path
            except Exception:
                try:
                    self._rollback_runtime(state)
                except BaseException:
                    pass
                raise

    def repair(self, *, _locked: bool = False) -> None:
        def operation() -> None:
            if not self.state_path.exists():
                return
            state = self._read_runtime_state()
            if state["status"] in {"installing", "rollback_failed"}:
                self._rollback_runtime(state)
                return
            if state["status"] == "uninstalling":
                raise InstallerConflict("runtime uninstall is incomplete; retry uninstall")
            for host_path, expected in state["managed_hashes"].items():
                path = _root_path(self.root, host_path)
                if (not path.exists() and not path.is_symlink()) or self._path_hash(path) != expected:
                    raise InstallerConflict(f"managed file has drifted: {host_path}")
            _repair_installation_unlocked(
                root=self.root,
                validate=lambda: self._run("nginx", "-t"),
                reload=lambda: self._run("systemctl", "reload", "nginx"),
            )
            self._compose_start()
            self._health_and_protocol()
        if _locked:
            operation()
        else:
            with _operation_lock(self.root):
                operation()

    def uninstall(
        self,
        *,
        purge_data: bool = False,
        _locked: bool = False,
    ) -> None:
        def operation() -> None:
            if not self.state_path.exists():
                return
            state = self._read_runtime_state()
            if state["status"] in {"installing", "rollback_failed"}:
                self._rollback_runtime(state)
                return
            if state["status"] == "active":
                marker_sha256 = self._validate_owned_project()
                self._require_owned_packages(state, installed=True)
                state["purge_data"] = purge_data
                state["project_marker_sha256"] = marker_sha256
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="started",
                )
            elif state["purge_data"] != purge_data:
                required_flag = (
                    "with --purge-data"
                    if state["purge_data"]
                    else "without --purge-data"
                )
                raise InstallerConflict(
                    f"retry the interrupted uninstall {required_flag}"
                )

            phase = state["phase"]
            if phase == "packages_purged":
                expected_packages: bool | None = False
            elif phase == "packages_purging":
                expected_packages = None
            else:
                expected_packages = True
            self._validate_uninstall_ownership(
                state,
                packages_installed=expected_packages,
            )

            if phase == "started":
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="compose_stopping",
                )
                phase = "compose_stopping"
            if phase == "compose_stopping":
                self._validate_uninstall_ownership(state)
                if self._compose_project_present():
                    self._compose("down", "--remove-orphans")
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="compose_down",
                )
                phase = "compose_down"
            if phase == "compose_down" and state["purge_data"]:
                self._validate_uninstall_ownership(state)
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="data_purging",
                )
                phase = "data_purging"
            if phase == "data_purging":
                self._validate_uninstall_ownership(state)
                if self._compose_project_volumes_present():
                    self._compose(
                        "down",
                        "--remove-orphans",
                        "--volumes",
                    )
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="data_purged",
                )
                phase = "data_purged"
            if phase in {"compose_down", "data_purged"}:
                self._validate_uninstall_ownership(state)
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="route_removing",
                )
                phase = "route_removing"
            if phase == "route_removing":
                self._validate_uninstall_ownership(state)
                _uninstall_installation_unlocked(
                    root=self.root,
                    validate=lambda: self._run("nginx", "-t"),
                    reload=lambda: self._run("systemctl", "reload", "nginx"),
                )
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="route_removed",
                )
                phase = "route_removed"
            if phase == "route_removed":
                self._validate_uninstall_ownership(state)
                # Validate the complete owned generation before making removal retryable.
                for host_path, expected in state["managed_hashes"].items():
                    path = _root_path(self.root, host_path)
                    if (
                        (not path.exists() and not path.is_symlink())
                        or self._path_hash(path) != expected
                    ):
                        raise InstallerConflict(
                            f"managed file has drifted: {host_path}"
                        )
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="sites_removing",
                )
                phase = "sites_removing"
            if phase == "sites_removing":
                self._validate_uninstall_ownership(state)
                self._remove_managed_files(
                    state,
                    check_hashes=True,
                    allow_missing=True,
                )
                self._validate_reload()
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="sites_removed",
                )
                phase = "sites_removed"
            if phase == "sites_removed":
                self._validate_uninstall_ownership(state)
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="project_cleaning",
                )
                phase = "project_cleaning"
            if phase == "project_cleaning":
                self._validate_uninstall_ownership(state)
                self._clean_project_preserving_credentials()
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="project_cleaned",
                )
                phase = "project_cleaned"
            if phase == "project_cleaned":
                self._validate_uninstall_ownership(state)
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="packages_purging",
                )
                phase = "packages_purging"
            if phase == "packages_purging":
                self._validate_uninstall_ownership(
                    state,
                    packages_installed=None,
                )
                remaining = [
                    package
                    for package in state["owned_packages"]
                    if self.runner.package_installed(package)
                ]
                if remaining:
                    self._run("apt-get", "purge", "-y", *remaining)
                self._checkpoint(
                    state,
                    status="uninstalling",
                    phase="packages_purged",
                )
                phase = "packages_purged"
            if phase == "packages_purged":
                self._validate_uninstall_ownership(
                    state,
                    packages_installed=False,
                )
            self.state_path.unlink()
            _fsync_dir(self.state_path.parent)

        if _locked:
            operation()
        else:
            with _operation_lock(self.root):
                operation()


def main(argv: Sequence[str] | None = None) -> int:
    """Delegate command dispatch to the typed installer CLI."""
    from installer.cli import main as installer_main

    return installer_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
