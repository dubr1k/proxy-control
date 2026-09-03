from __future__ import annotations

import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from installer.model import HostMode, InstallerConfig
from installer.planner import AuditFacts as PlannerAuditFacts

DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_OUTPUT = 1024 * 1024
_XRAY_CONFIG = "/usr/local/x-ui/bin/config.json"
_INSTALLER_STATE = "/var/lib/proxy-control/ownership.json"
_DOMAIN_RE = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9_.:@+-]{1,128}\Z")
_SAFE_ARCHITECTURES = {
    "aarch64": "arm64",
    "amd64": "amd64",
    "arm64": "arm64",
    "x86_64": "amd64",
}
_SENSITIVE_KEY = re.compile(
    r"(?:authorization|auth|cookie|credential|password|passwd|secret|token|"
    r"private[_-]?key|short[_-]?ids?|panel(?:path|_path)|webbasepath|"
    r"api[_-]?key|access[_-]?key|session|dsn|database[_-]?url)",
    re.IGNORECASE,
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(authorization\s*:\s*(?:bearer\s+)?|cookie\s*:\s*|"
    r"(?:password|passwd|secret|token|private[_-]?key|short[_-]?ids?|"
    r"panel(?:path|_path)|webbasepath|api[_-]?key|session(?:id)?)\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,}\]]+)"
)
_UUID = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?"
    r"-----END [^-\r\n]*PRIVATE KEY-----",
    re.DOTALL,
)


class AuditError(RuntimeError):
    """An audit failed without exposing command input or captured content."""


@dataclass(frozen=True, order=True)
class HardStop:
    code: str
    message: str
    domains: tuple[str, ...] = ()


@dataclass(frozen=True, order=True)
class OperatorPrerequisite:
    code: str
    status: str
    message: str


@dataclass(frozen=True)
class AuditFacts(PlannerAuditFacts):
    hard_stops: tuple[HardStop, ...] = field(default_factory=tuple)
    operator_prerequisites: tuple[OperatorPrerequisite, ...] = field(
        default_factory=tuple
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        object.__setattr__(self, "hard_stops", tuple(sorted(self.hard_stops)))
        object.__setattr__(
            self,
            "operator_prerequisites",
            tuple(sorted(self.operator_prerequisites)),
        )


class Executor(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_output: int,
    ) -> subprocess.CompletedProcess[str]: ...


Resolver = Callable[..., list[tuple[int, int, int, str, tuple[object, ...]]]]


class CommandRunner:
    """Shell-free, bounded command and DNS observation boundary."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_output: int = DEFAULT_MAX_OUTPUT,
        executor: Executor | None = None,
        resolver: Resolver = socket.getaddrinfo,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_output <= 0:
            raise ValueError("max_output must be positive")
        self.timeout = timeout
        self.max_output = max_output
        self._executor = executor or _bounded_execute
        self._resolver = resolver

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = _validated_argv(argv)
        try:
            result = self._executor(
                command,
                timeout=self.timeout,
                max_output=self.max_output,
            )
        except AuditError as exc:
            message = str(exc)
            if message in {
                "command could not be executed",
                "command output limit exceeded",
                "command timed out",
            }:
                raise AuditError(message) from None
            raise AuditError("command could not be executed") from None
        except subprocess.TimeoutExpired:
            raise AuditError("command timed out") from None
        except Exception:
            raise AuditError("command could not be executed") from None
        if (
            not isinstance(result, subprocess.CompletedProcess)
            or not isinstance(result.returncode, int)
            or not isinstance(result.stdout, str)
            or not isinstance(result.stderr, str)
        ):
            raise AuditError("command returned an invalid response")
        if _output_size(result.stdout, result.stderr) > self.max_output:
            raise AuditError("command output limit exceeded")
        return result

    def capture(self, argv: Sequence[str]) -> str:
        result = self.run(argv)
        if result.returncode != 0:
            raise AuditError(f"command failed with exit status {result.returncode}")
        return result.stdout

    def json(self, argv: Sequence[str]) -> object:
        text = self.capture(argv)
        try:
            return json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            raise AuditError("command returned malformed JSON") from None

    def resolve(self, domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        try:
            answers = self._resolver(domain, 443, type=socket.SOCK_STREAM)
        except socket.gaierror:
            answers = []
        except Exception as exc:
            raise AuditError(_sanitize_error(str(exc))) from None
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        for family, _kind, _proto, _canon, address in answers:
            if not address:
                continue
            value = _canonical_ip(address[0])
            if value is None:
                continue
            if family == socket.AF_INET and ":" not in value:
                ipv4.add(value)
            elif family == socket.AF_INET6 and ":" in value:
                ipv6.add(value)
        return tuple(sorted(ipv4)), tuple(sorted(ipv6))


def _validated_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes, bytearray)) or not argv:
        raise AuditError("command argv must be a non-empty sequence")
    if any(not isinstance(part, str) or "\x00" in part for part in argv):
        raise AuditError("command argv contains an invalid argument")
    return tuple(argv)


def _output_size(stdout: object, stderr: object) -> int:
    def size(value: object) -> int:
        if isinstance(value, bytes):
            return len(value)
        if isinstance(value, str):
            return len(value.encode("utf-8", errors="replace"))
        return 0

    return size(stdout) + size(stderr)


def _bounded_execute(
    argv: Sequence[str],
    *,
    timeout: float,
    max_output: int,
) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        raise AuditError("command could not be executed") from None
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    captured = 0
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process(process)
                raise AuditError("command timed out")
            events = selector.select(remaining)
            if not events and process.poll() is None:
                continue
            for key, _mask in events:
                data = os.read(key.fileobj.fileno(), min(65536, max_output - captured + 1))
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                captured += len(data)
                if captured > max_output:
                    _terminate_process(process)
                    raise AuditError("command output limit exceeded")
                chunks[key.data].append(data)
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        _terminate_process(process)
        raise AuditError("command timed out") from None
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    stdout = b"".join(chunks["stdout"]).decode("utf-8", errors="replace")
    stderr = b"".join(chunks["stderr"]).decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(tuple(argv), returncode, stdout, stderr)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _environment_secret_values() -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value
                for key, value in os.environ.items()
                if len(value) >= 4 and _SENSITIVE_KEY.search(key)
            },
            key=len,
            reverse=True,
        )
    )


def _sanitize_error(text: str) -> str:
    redactions = sum(1 for _ in _SENSITIVE_ASSIGNMENT.finditer(text))
    redactions += sum(1 for _ in _UUID.finditer(text))
    redactions += sum(1 for _ in _PRIVATE_KEY_BLOCK.finditer(text))
    redactions += sum(text.count(value) for value in _environment_secret_values())
    suffix = " " + " ".join("[REDACTED]" for _ in range(redactions)) if redactions else ""
    return "audit observation failed" + suffix


def _safe_audit_error(text: str) -> str:
    if text in {
        "command could not be executed",
        "command output limit exceeded",
        "command returned an invalid response",
        "command returned malformed JSON",
        "command timed out",
    } or re.fullmatch(r"command failed with exit status -?\d+", text):
        return text
    return _sanitize_error(text)


def validate_domain(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(normalized):
        raise ValueError("a plain fully-qualified domain name is required")
    return normalized


def parse_sni_entries(text: str) -> list[tuple[str, str]]:
    return [
        (domain.lower(), backend)
        for domain, backend in re.findall(
            r"(?<![A-Za-z0-9_.-])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\s+"
            r"((?:127\.0\.0\.1|\[?::1\]?):\d+)\s*;",
            text,
        )
    ]


def parse_sni_routes(text: str) -> dict[str, str]:
    return dict(parse_sni_entries(text))


def parse_http_domains(text: str) -> set[str]:
    domains: set[str] = set()
    for match in re.finditer(r"(?m)^\s*server_name\s+([^;]+);", text):
        for value in match.group(1).split():
            try:
                domains.add(validate_domain(value))
            except ValueError:
                continue
    return domains


def parse_xray_inbounds(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, Mapping):
        return ()
    raw_inbounds = value.get("inbounds")
    if not isinstance(raw_inbounds, list):
        return ()
    observations: list[dict[str, object]] = []
    for raw in raw_inbounds:
        if not isinstance(raw, Mapping):
            continue
        stream = raw.get("streamSettings")
        if not isinstance(stream, Mapping):
            stream = {}
        reality = stream.get("realitySettings")
        if not isinstance(reality, Mapping):
            reality = {}
        raw_names = reality.get("serverNames")
        names: list[str] = []
        if isinstance(raw_names, list):
            for name in raw_names:
                if not isinstance(name, str):
                    continue
                try:
                    names.append(validate_domain(name))
                except ValueError:
                    continue
        observation: dict[str, object] = {}
        for source, target in (
            ("tag", "tag"),
            ("protocol", "protocol"),
            ("listen", "listen"),
        ):
            candidate = raw.get(source)
            if (
                isinstance(candidate, str)
                and _SAFE_NAME_RE.fullmatch(candidate)
                and _safe_text(candidate, 128)
            ):
                observation[target] = candidate
        port = raw.get("port")
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            observation["port"] = port
        security = stream.get("security")
        if (
            isinstance(security, str)
            and _SAFE_NAME_RE.fullmatch(security)
            and _safe_text(security, 128)
        ):
            observation["transport_security"] = security
        observation["reality_server_names"] = tuple(sorted(set(names)))
        observations.append(dict(sorted(observation.items())))
    return tuple(sorted(observations, key=lambda item: json.dumps(item, sort_keys=True)))


def audit_host(config: InstallerConfig, runner: CommandRunner) -> AuditFacts:
    """Collect a deterministic, secret-free, read-only host snapshot."""
    try:
        return _audit_host(config, runner)
    except AuditError as exc:
        raise AuditError(_safe_audit_error(str(exc))) from None
    except Exception as exc:
        raise AuditError(_sanitize_error(str(exc))) from None


def _audit_host(config: InstallerConfig, runner: CommandRunner) -> AuditFacts:
    domains = tuple(validate_domain(domain) for domain in config.required_domains())

    architecture = _SAFE_ARCHITECTURES.get(runner.capture(("uname", "-m")).strip(), "unknown")
    disks = _parse_disks(runner.capture(("df", "-Pk")))
    memory = _parse_memory(runner.capture(("free", "-b")))
    addresses = _parse_addresses(runner.json(("ip", "-j", "address")))
    local_addresses = {item["address"] for item in addresses}
    listeners = _parse_listeners(runner.capture(("ss", "-H", "-lntup")))

    nginx_result = runner.run(("nginx", "-T"))
    nginx = _parse_nginx(nginx_result.stdout) if nginx_result.returncode == 0 else _empty_nginx()

    docker_result = runner.run(("docker", "--version"))
    compose_result = runner.run(("docker", "compose", "version", "--short"))
    systemd_result = runner.run(
        (
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--no-pager",
        )
    )
    ufw_result = runner.run(("ufw", "status", "verbose"))

    xray_present = runner.run(("test", "-f", _XRAY_CONFIG)).returncode == 0
    xray = {
        "installed": xray_present,
        "inbounds": parse_xray_inbounds(runner.json(("cat", _XRAY_CONFIG)))
        if xray_present
        else (),
    }
    installer_present = runner.run(("test", "-f", _INSTALLER_STATE)).returncode == 0

    dns: dict[str, object] = {}
    certificates: dict[str, object] = {}
    unhandled_aaaa: list[str] = []
    caa_mismatch: list[str] = []
    for domain in domains:
        ipv4, ipv6 = runner.resolve(domain)
        caa_result = runner.run(("dig", "+short", "CAA", domain))
        caa = _parse_caa(caa_result.stdout) if caa_result.returncode == 0 else ()
        caa_compatible = _caa_compatible(caa)
        aaaa_handled = not ipv6 or set(ipv6) <= local_addresses
        if not aaaa_handled:
            unhandled_aaaa.append(domain)
        if not caa_compatible:
            caa_mismatch.append(domain)
        dns[domain] = {
            "a": ipv4,
            "aaaa": ipv6,
            "a_matches_local": bool(set(ipv4) & local_addresses),
            "aaaa_handled": aaaa_handled,
            "caa": caa,
            "caa_compatible": caa_compatible,
        }
        certificates[domain] = _certificate_fact(domain, runner)

    hard_stops: list[HardStop] = []
    if unhandled_aaaa:
        hard_stops.append(
            HardStop(
                "dns.unhandled_aaaa",
                "AAAA records point outside addresses handled by this host",
                tuple(unhandled_aaaa),
            )
        )
    if caa_mismatch:
        hard_stops.append(
            HardStop(
                "dns.caa_mismatch",
                "CAA records do not authorize Let's Encrypt",
                tuple(caa_mismatch),
            )
        )
    cloud_prerequisite = OperatorPrerequisite(
        "cloud_firewall.reachability",
        "operator_required",
        "Verify required inbound ports in the external cloud firewall",
    )
    prerequisite_facts = {
        "hard_stops": tuple(_hard_stop_dict(item) for item in hard_stops),
        "operator_prerequisites": (_operator_prerequisite_dict(cloud_prerequisite),),
    }

    return AuditFacts(
        platform={
            "addresses": addresses,
            "architecture": architecture,
            "disks": disks,
            "memory": memory,
            "os": sys.platform,
        },
        listeners=listeners,
        topology={
            "certificates": certificates,
            "dns": dns,
            "nginx": nginx,
            "three_xui": xray,
        },
        ownership={
            "compose": _version_fact(compose_result, bare=True),
            "docker": _version_fact(docker_result),
            "installer": {"present": installer_present},
            "systemd": _systemd_fact(systemd_result),
            "three_xui": {"mode": config.three_xui.mode.value, "present": xray_present},
            "ufw": _ufw_fact(config, ufw_result),
        },
        prerequisites=prerequisite_facts,
        hard_stops=tuple(hard_stops),
        operator_prerequisites=(cloud_prerequisite,),
    )


def _parse_disks(text: str) -> tuple[dict[str, object], ...]:
    observations: list[dict[str, object]] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6 or not all(value.isdigit() for value in fields[1:4]):
            continue
        filesystem, mount = fields[0], fields[-1]
        if not _safe_text(filesystem, 256) or not _safe_text(mount, 256):
            continue
        observations.append(
            {
                "available_kib": int(fields[3]),
                "filesystem": filesystem,
                "mount": mount,
                "total_kib": int(fields[1]),
                "used_kib": int(fields[2]),
            }
        )
    return tuple(sorted(observations, key=lambda item: str(item["mount"])))


def _parse_memory(text: str) -> dict[str, int]:
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0].rstrip(":") == "Mem" and len(fields) >= 7:
            numbers = fields[1:7]
            if all(value.isdigit() for value in numbers):
                return {"available_bytes": int(numbers[5]), "total_bytes": int(numbers[0])}
    return {"available_bytes": 0, "total_bytes": 0}


def _parse_addresses(value: object) -> tuple[dict[str, str], ...]:
    observations: set[tuple[str, str, str]] = set()
    if not isinstance(value, list):
        return ()
    for link in value:
        if not isinstance(link, Mapping):
            continue
        interface = link.get("ifname")
        if not isinstance(interface, str) or not _SAFE_NAME_RE.fullmatch(interface):
            continue
        items = link.get("addr_info")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, Mapping) or item.get("scope") not in {"global", "host"}:
                continue
            address = _canonical_ip(item.get("local"))
            if address is None:
                continue
            family = "inet6" if ":" in address else "inet"
            observations.add((address, family, interface))
    return tuple(
        {"address": address, "family": family, "interface": interface}
        for address, family, interface in sorted(observations)
    )


def _parse_listeners(text: str) -> dict[str, object]:
    tcp: set[int] = set()
    udp: set[int] = set()
    owners: dict[int, set[str]] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        protocol = fields[0].lower()
        endpoint = next((field for field in fields if re.search(r":\d+$", field)), "")
        port_match = re.search(r":(\d+)$", endpoint)
        if not port_match:
            continue
        port = int(port_match.group(1))
        if not 1 <= port <= 65535:
            continue
        target = tcp if protocol.startswith("tcp") else udp if protocol.startswith("udp") else None
        if target is None:
            continue
        target.add(port)
        for owner in re.findall(r'users:\(\(\"([^\"\\]+)\"', line):
            if _SAFE_NAME_RE.fullmatch(owner):
                owners.setdefault(port, set()).add(owner)
    ports = tcp | udp
    return {
        "owners": {str(port): tuple(sorted(names)) for port, names in sorted(owners.items())},
        "ports": tuple(sorted(ports)),
        "tcp": tuple(sorted(tcp)),
        "udp": tuple(sorted(udp)),
    }


def _empty_nginx() -> dict[str, object]:
    return {"available": False, "http_domains": (), "sni_routes": {}, "stream_enabled": False}


def _parse_nginx(text: str) -> dict[str, object]:
    routes = parse_sni_routes(text)
    return {
        "available": True,
        "http_domains": tuple(sorted(parse_http_domains(text))),
        "sni_routes": dict(sorted(routes.items())),
        "stream_enabled": bool(re.search(r"(?m)^\s*stream\s*\{", text)),
    }


def _parse_caa(text: str) -> tuple[str, ...]:
    records: set[str] = set()
    pattern = re.compile(r'^\s*(\d{1,3})\s+(issue|issuewild|iodef)\s+"([^"\r\n]{0,255})"\s*$', re.I)
    for line in text.splitlines():
        match = pattern.fullmatch(line)
        if match:
            records.add(f'{int(match.group(1))} {match.group(2).lower()} "{match.group(3)}"')
    return tuple(sorted(records))


def _caa_compatible(records: Sequence[str]) -> bool:
    authorities: list[str] = []
    for record in records:
        match = re.fullmatch(r'\d+ issue "([^";\s]+)(?:;[^\"]*)?"', record, re.I)
        if match:
            authorities.append(match.group(1).lower().rstrip("."))
    return not authorities or "letsencrypt.org" in authorities


def _certificate_fact(domain: str, runner: CommandRunner) -> dict[str, object]:
    path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    result = runner.run(
        (
            "openssl",
            "x509",
            "-in",
            path,
            "-noout",
            "-dates",
            "-ext",
            "subjectAltName",
        )
    )
    if result.returncode != 0:
        return {"covers_domain": False, "present": False}
    names: set[str] = set()
    for name in re.findall(r"DNS:([^,\s]+)", result.stdout):
        try:
            names.add(validate_domain(name))
        except ValueError:
            continue
    fact: dict[str, object] = {
        "covers_domain": domain in names,
        "names": tuple(sorted(names)),
        "present": True,
    }
    for key, label in (("notBefore", "not_before"), ("notAfter", "not_after")):
        match = re.search(rf"(?m)^{key}=([A-Za-z0-9 :]+(?:GMT)?)$", result.stdout)
        if match:
            fact[label] = match.group(1)
    return fact


def _version_fact(result: subprocess.CompletedProcess[str], *, bare: bool = False) -> dict[str, object]:
    if result.returncode != 0:
        return {"available": False}
    pattern = r"^\s*(\d+(?:\.\d+){1,3})\s*$" if bare else r"\bversion\s+(\d+(?:\.\d+){1,3})\b"
    match = re.search(pattern, result.stdout, re.I)
    fact: dict[str, object] = {"available": True}
    if match:
        fact["version"] = match.group(1)
    return fact


def _systemd_fact(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    if result.returncode != 0:
        return {"available": False, "services": ()}
    services = {
        fields[0]
        for line in result.stdout.splitlines()
        if (fields := line.split()) and re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", fields[0])
    }
    return {"available": True, "services": tuple(sorted(services))}


def _ufw_fact(config: InstallerConfig, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    active = result.returncode == 0 and bool(re.search(r"(?im)^Status:\s+active\s*$", result.stdout))
    return {
        "active": active,
        "available": result.returncode == 0,
        "mode": "managed" if config.host_mode is HostMode.FRESH and config.firewall.manage_ufw else "read_only",
    }


def _hard_stop_dict(value: HardStop) -> dict[str, object]:
    return {"code": value.code, "domains": value.domains, "message": value.message}


def _operator_prerequisite_dict(value: OperatorPrerequisite) -> dict[str, str]:
    return {"code": value.code, "message": value.message, "status": value.status}


def _safe_text(value: str, maximum: int) -> bool:
    return (
        0 < len(value) <= maximum
        and not _SENSITIVE_ASSIGNMENT.search(value)
        and not _UUID.search(value)
        and not any(secret in value for secret in _environment_secret_values())
    )


def _canonical_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


# Legacy rooted audit compatibility lives here so proxyctl has no parallel parsers.
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
    inbounds: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class AuditReport:
    nginx: NginxAudit
    xray: XrayAudit
    docker_available: bool
    listening_ports: list[int]
    listener_owners: dict[int, list[str]] = field(default_factory=dict)
    domains: list[DomainAudit] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "docker_available": self.docker_available,
            "domains": [vars(item) for item in self.domains],
            "listener_owners": self.listener_owners,
            "listening_ports": self.listening_ports,
            "nginx": vars(self.nginx),
            "xray": vars(self.xray),
        }


def legacy_audit_host(
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
    files = _legacy_nginx_files(root)
    texts = {path: _legacy_read_text(path) for path in files}
    nginx_main = _legacy_read_text(_legacy_root_path(root, "/etc/nginx/nginx.conf"))
    route_values: dict[str, set[str]] = {}
    route_counts: dict[str, int] = {}
    http_domains: set[str] = set()
    map_files: dict[str, int] = {}
    for path, text in texts.items():
        count = _sni_map_count(text)
        if count:
            map_files[_legacy_host_path(root, path)] = count
        for domain, backend in parse_sni_entries(text):
            route_values.setdefault(domain, set()).add(backend)
            route_counts[domain] = route_counts.get(domain, 0) + 1
        http_domains.update(parse_http_domains(text))
    routes = {domain: sorted(backends)[0] for domain, backends in route_values.items()}
    duplicates = sorted(domain for domain, count in route_counts.items() if count > 1)
    if listening_ports is None:
        listening_ports, detected_owners = legacy_listener_inventory()
        if listener_owners is None:
            listener_owners = detected_owners
    if listener_owners is None:
        listener_owners = {}
    if docker_available is None:
        docker_available = _command_available("docker")

    requested = set(domains or ()) | set((dns_records or {}).keys())
    records = dns_records if dns_records is not None else {
        name: _legacy_resolve_domain(name) for name in requested
    }
    local = _legacy_local_addresses() if local_addresses is None else local_addresses
    cert_names = _legacy_certificate_names(root, requested) if tls_names is None else tls_names
    domain_audits = []
    for domain in sorted(validate_domain(name) for name in requested):
        record = records.get(domain, {})
        a_records = sorted(set(record.get("A", [])))
        aaaa_records = sorted(set(record.get("AAAA", [])))
        domain_audits.append(
            DomainAudit(
                domain=domain,
                a_records=a_records,
                aaaa_records=aaaa_records,
                dns_matches_host=bool(set(a_records) & local),
                unhandled_aaaa=bool(aaaa_records and not set(aaaa_records) <= local),
                tls_certificate_present=domain in cert_names,
            )
        )
    xray_path = _legacy_root_path(root, _XRAY_CONFIG)
    xray_installed = xray_path.is_file()
    xray_inbounds: tuple[dict[str, object], ...] = ()
    if xray_installed:
        try:
            xray_inbounds = parse_xray_inbounds(json.loads(xray_path.read_text()))
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
            xray_inbounds = ()
    return AuditReport(
        nginx=NginxAudit(
            installed=bool(files),
            stream_enabled=bool(re.search(r"(?m)^\s*stream\s*\{", nginx_main)),
            sni_routes=dict(sorted(routes.items())),
            http_domains=sorted(http_domains),
            config_files=[_legacy_host_path(root, path) for path in files],
            sni_map_count=sum(map_files.values()),
            sni_map_files=dict(sorted(map_files.items())),
            duplicate_sni_domains=duplicates,
        ),
        xray=XrayAudit(xray_installed, xray_inbounds),
        docker_available=docker_available,
        listening_ports=sorted(listening_ports),
        listener_owners={
            port: sorted(set(names)) for port, names in sorted(listener_owners.items())
        },
        domains=domain_audits,
    )


def legacy_listener_inventory() -> tuple[set[int], dict[int, list[str]]]:
    try:
        result = subprocess.run(
            ["ss", "-H", "-lntp"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return set(), {}
    parsed = _parse_listeners(result.stdout)
    owners = {
        int(port): list(names)
        for port, names in parsed["owners"].items()  # type: ignore[union-attr]
    }
    return set(parsed["ports"]), owners  # type: ignore[arg-type]


def _legacy_root_path(root: Path, absolute: str) -> Path:
    if not absolute.startswith("/"):
        raise ValueError("host paths must be absolute")
    return root / absolute.lstrip("/")


def _legacy_host_path(root: Path, path: Path) -> str:
    return "/" + str(path.relative_to(root))


def _legacy_read_text(path: Path) -> str:
    try:
        return path.read_text()
    except (FileNotFoundError, PermissionError, OSError, UnicodeError):
        return ""


def _legacy_nginx_files(root: Path) -> list[Path]:
    candidates = [_legacy_root_path(root, "/etc/nginx/nginx.conf")]
    for directory in (
        "/etc/nginx/stream.d",
        "/etc/nginx/stream-conf.d",
        "/etc/nginx/conf.d",
        "/etc/nginx/sites-enabled",
    ):
        folder = _legacy_root_path(root, directory)
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


def _legacy_resolve_domain(domain: str) -> dict[str, list[str]]:
    records: dict[str, set[str]] = {"A": set(), "AAAA": set()}
    try:
        answers = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        answers = []
    for family, _kind, _proto, _canon, address in answers:
        value = _canonical_ip(address[0])
        if value is not None and family == socket.AF_INET:
            records["A"].add(value)
        elif value is not None and family == socket.AF_INET6:
            records["AAAA"].add(value)
    return {key: sorted(value) for key, value in records.items()}


def _legacy_local_addresses() -> set[str]:
    try:
        result = subprocess.run(
            ["ip", "-j", "address"], capture_output=True, text=True, check=False
        )
        value = json.loads(result.stdout or "[]")
    except (OSError, json.JSONDecodeError, RecursionError):
        return set()
    return {item["address"] for item in _parse_addresses(value)}


def _legacy_certificate_names(root: Path, domains: set[str]) -> set[str]:
    present = set()
    for domain in domains:
        cert = _legacy_root_path(root, f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        if not cert.is_file():
            continue
        try:
            decoded = ssl._ssl._test_decode_cert(str(cert))  # noqa: SLF001
        except (OSError, ssl.SSLError, ValueError):
            continue
        names = {
            value.lower()
            for kind, value in decoded.get("subjectAltName", [])
            if kind == "DNS"
        }
        if domain in names:
            present.add(domain)
    return present


def _sni_map_count(text: str) -> int:
    return len(re.findall(r"map\s+\$ssl_preread_server_name\s+\$[A-Za-z0-9_]+\s*\{", text))


def _command_available(name: str) -> bool:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return True
    return False
