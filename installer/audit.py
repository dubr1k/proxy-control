from __future__ import annotations

import ipaddress
import json
import multiprocessing
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from installer.model import HostMode, InstallerConfig
from installer.planner import AuditFacts as PlannerAuditFacts

DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_OUTPUT = 1024 * 1024
_XRAY_CONFIG = "/usr/local/x-ui/bin/config.json"
UFW_IPV6_CONFIG_COMMAND = (
    "grep",
    "-E",
    "^IPV6=(yes|no)$",
    "/etc/default/ufw",
)
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
_CAA_VALIDATION_METHODS = frozenset({"dns-01", "http-01", "tls-alpn-01"})
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


class CommandUnavailable(AuditError):
    """The requested executable does not exist on this host."""


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
        except CommandUnavailable:
            raise
        except AuditError as exc:
            message = str(exc)
            if message in {
                "command could not be executed",
                "command output limit exceeded",
                "command timed out",
            }:
                raise AuditError(message) from None
            raise AuditError("command could not be executed") from None
        except FileNotFoundError:
            raise CommandUnavailable("command is unavailable") from None
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
        absolute_name = validate_domain(domain) + "."
        return _bounded_resolve(self._resolver, absolute_name, self.timeout)


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
    except FileNotFoundError:
        raise CommandUnavailable("command is unavailable") from None
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
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _resolver_worker(connection, resolver: Resolver, domain: str) -> None:
    try:
        answers = resolver(domain, 443, type=socket.SOCK_STREAM)
        observations: list[tuple[int, str]] = []
        for family, _kind, _proto, _canon, address in answers:
            if family not in {socket.AF_INET, socket.AF_INET6} or not address:
                continue
            value = _canonical_ip(address[0])
            if value is None:
                continue
            if len(observations) >= 256:
                connection.send(("result_limit", []))
                return
            observations.append((family, value))
        connection.send(("ok", observations))
    except socket.gaierror:
        connection.send(("resolver_error", []))
    except BaseException:
        connection.send(("resolver_error", []))
    finally:
        connection.close()


def _bounded_resolve(
    resolver: Resolver,
    domain: str,
    timeout: float,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_resolver_worker, args=(sender, resolver, domain))
    process.daemon = True
    process.start()
    sender.close()
    try:
        if not receiver.poll(timeout):
            _stop_worker(process)
            raise AuditError("DNS resolution timed out")
        try:
            status, observations = receiver.recv()
        except EOFError:
            _stop_worker(process)
            raise AuditError("DNS resolution failed") from None
        process.join(timeout=0.2)
        if process.is_alive():
            _stop_worker(process)
            raise AuditError("DNS resolution failed")
        if status == "result_limit":
            raise AuditError("DNS resolution result limit exceeded")
        if status != "ok":
            raise AuditError("DNS resolution failed")
    finally:
        receiver.close()
        if process.is_alive():
            _stop_worker(process)
        process.close()
    ipv4 = {value for family, value in observations if family == socket.AF_INET}
    ipv6 = {value for family, value in observations if family == socket.AF_INET6}
    return tuple(sorted(ipv4)), tuple(sorted(ipv6))


def _stop_worker(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=0.2)
    if process.is_alive():
        process.kill()
        process.join()


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
        "CAA alias loop detected",
        "CAA issuer is malformed",
        "CAA issuer parameter is duplicated",
        "CAA issuer parameter is malformed",
        "CAA issuer parameter is unsupported",
        "CAA query failed",
        "CAA query limit exceeded",
        "CAA response was malformed",
        "DNS resolution failed",
        "DNS resolution result limit exceeded",
        "DNS resolution timed out",
        "Nginx observation is malformed",
        "command could not be executed",
        "command output limit exceeded",
        "command returned an invalid response",
        "command returned malformed JSON",
        "command timed out",
        "required audit command is unavailable",
    } or re.fullmatch(
        r"(?:command failed|required audit command failed) with exit status -?\d+",
        text,
    ):
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

    architecture = _SAFE_ARCHITECTURES.get(
        _required_capture(runner, ("uname", "-m")).strip(),
        "unknown",
    )
    disks = _parse_disks(_required_capture(runner, ("df", "-Pk")))
    memory = _parse_memory(_required_capture(runner, ("free", "-b")))
    addresses = _parse_addresses(_required_json(runner, ("ip", "-j", "address")))
    local_addresses = {item["address"] for item in addresses}
    listeners = _parse_listeners(_required_capture(runner, ("ss", "-H", "-lntup")))
    ssh_socket_result, _ssh_socket_observation = _optional_run(
        runner,
        (
            "systemctl",
            "show",
            "ssh.socket",
            "--property=Listen",
            "--value",
            "--no-pager",
        ),
    )
    listeners["ssh_socket_tcp"] = (
        _parse_ssh_socket_ports(ssh_socket_result.stdout)
        if ssh_socket_result is not None
        else ()
    )

    nginx_result, nginx_observation = _optional_run(runner, ("nginx", "-T"))
    nginx = (
        parse_nginx_observation(nginx_result.stdout)
        if nginx_result is not None
        else _empty_nginx(nginx_observation)
    )

    docker_result, docker_observation = _optional_run(runner, ("docker", "--version"))
    compose_result, compose_observation = _optional_run(
        runner,
        ("docker", "compose", "version", "--short"),
    )
    systemd_result, systemd_observation = _optional_run(
        runner,
        (
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--no-pager",
        ),
    )
    ufw_result, ufw_observation = _optional_run(runner, ("ufw", "status", "verbose"))
    ufw_config_result, _ = _optional_run(runner, UFW_IPV6_CONFIG_COMMAND)

    xray_present = _required_run(runner, ("test", "-f", _XRAY_CONFIG)).returncode == 0
    xray = {
        "installed": xray_present,
        "inbounds": parse_xray_inbounds(
            _required_json(runner, ("cat", _XRAY_CONFIG))
        )
        if xray_present
        else (),
    }
    installer_present = (
        _required_run(runner, ("test", "-f", _INSTALLER_STATE)).returncode == 0
    )

    dns: dict[str, object] = {}
    certificates: dict[str, object] = {}
    unhandled_aaaa: list[str] = []
    caa_mismatch: list[str] = []
    caa_cache: dict[
        str,
        tuple[tuple[dict[str, object], ...], tuple[str, ...]],
    ] = {}
    caa_queries = [0]
    for domain in domains:
        ipv4, ipv6 = runner.resolve(domain)
        caa, caa_source = _applicable_caa(
            domain,
            runner,
            caa_cache,
            caa_queries,
        )
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
            "caa_source": caa_source,
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
            "compose": _version_fact(
                compose_result,
                compose_observation,
                bare=True,
            ),
            "docker": _version_fact(docker_result, docker_observation),
            "installer": {"present": installer_present},
            "systemd": _systemd_fact(systemd_result, systemd_observation),
            "three_xui": {"mode": config.three_xui.mode.value, "present": xray_present},
            "ufw": _ufw_fact(
                config,
                ufw_result,
                ufw_observation,
                _parse_ufw_ipv6_enabled(ufw_config_result),
            ),
        },
        prerequisites=prerequisite_facts,
        hard_stops=tuple(hard_stops),
        operator_prerequisites=(cloud_prerequisite,),
    )


def _required_run(
    runner: CommandRunner,
    argv: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    try:
        return runner.run(argv)
    except CommandUnavailable:
        raise AuditError("required audit command is unavailable") from None


def _required_capture(runner: CommandRunner, argv: Sequence[str]) -> str:
    result = _required_run(runner, argv)
    if result.returncode != 0:
        raise AuditError(f"required audit command failed with exit status {result.returncode}")
    return result.stdout


def _required_json(runner: CommandRunner, argv: Sequence[str]) -> object:
    text = _required_capture(runner, argv)
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        raise AuditError("command returned malformed JSON") from None


def _optional_run(
    runner: CommandRunner,
    argv: Sequence[str],
) -> tuple[subprocess.CompletedProcess[str] | None, str]:
    try:
        result = runner.run(argv)
    except CommandUnavailable:
        return None, "unavailable"
    except AuditError:
        return None, "unknown"
    if result.returncode != 0:
        return None, "unknown"
    return result, "observed"


def listener_inventory(runner: CommandRunner) -> tuple[set[int], dict[int, list[str]]]:
    parsed = _parse_listeners(_required_capture(runner, ("ss", "-H", "-lntup")))
    owners = {
        int(port): list(names)
        for port, names in parsed["owners"].items()  # type: ignore[union-attr]
    }
    return set(parsed["ports"]), owners  # type: ignore[arg-type]


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

def _parse_ssh_socket_ports(text: str) -> tuple[int, ...]:
    ports: set[int] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.fullmatch(
            r"(?:(?:0\.0\.0\.0|\[::\]|\*):)?([1-9][0-9]{0,4}) \(Stream\)",
            line,
        )
        if match is not None and 1 <= int(match.group(1)) <= 65535:
            ports.add(int(match.group(1)))
            continue
        if re.fullmatch(r"/[^\x00\r\n ]+ \(Stream\)", line) is not None:
            continue
        return ()
    return tuple(sorted(ports))


def _empty_nginx(observation: str) -> dict[str, object]:
    return {
        "available": False,
        "duplicate_sni_domains": (),
        "http_domains": (),
        "observation": observation,
        "route_target": None,
        "sni_map_count": 0,
        "sni_map_files": {},
        "sni_routes": {},
        "stream_enabled": False,
        "topology_error": None,
    }


def parse_nginx_observation(text: str) -> dict[str, object]:
    from installer.adapters.nginx import (
        TopologyError,
        parse_effective_nginx,
        select_route_target,
    )

    try:
        topology = parse_effective_nginx(text)
    except TopologyError:
        raise AuditError("Nginx observation is malformed") from None
    sections = _nginx_sections(text)
    route_values: dict[str, set[str]] = {}
    route_counts: dict[str, int] = {}
    map_files: dict[str, int] = {}
    http_domains: set[str] = set()
    sni_maps = [
        mapping
        for mapping in topology.maps
        if mapping.source_variable == "$ssl_preread_server_name"
    ]
    for mapping in sni_maps:
        if mapping.source_file != "<effective>":
            map_files[mapping.source_file] = map_files.get(mapping.source_file, 0) + 1
    for section in sections.values():
        http_domains.update(parse_http_domains(section))
    route_target: dict[str, str] | None = None
    topology_error: str | None = None
    try:
        selected = select_route_target(topology)
    except TopologyError as exc:
        topology_error = str(exc)
    else:
        route_target = {
            "source_file": selected.source_file,
            "source_variable": selected.source_variable,
            "variable": selected.variable,
        }
        for key, backend in selected.routes:
            domain = key.lower()
            if _DOMAIN_RE.fullmatch(domain) is None:
                continue
            route_values.setdefault(domain, set()).add(backend)
            route_counts[domain] = route_counts.get(domain, 0) + 1
    routes = {
        domain: sorted(backends)[0]
        for domain, backends in sorted(route_values.items())
    }
    return {
        "available": True,
        "duplicate_sni_domains": tuple(
            sorted(domain for domain, count in route_counts.items() if count > 1)
        ),
        "http_domains": tuple(sorted(http_domains)),
        "observation": "observed",
        "route_target": route_target,
        "sni_map_count": len(sni_maps),
        "sni_map_files": dict(sorted(map_files.items())),
        "sni_routes": routes,
        "stream_enabled": topology.stream_enabled,
        "topology_error": topology_error,
    }


def _nginx_sections(text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {"<effective>": []}
    current = "<effective>"
    for line in text.splitlines(keepends=True):
        marker = re.fullmatch(r"# configuration file (/[^:\r\n]+):\r?\n?", line)
        if marker and _safe_text(marker.group(1), 512):
            current = marker.group(1)
            sections.setdefault(current, [])
            continue
        sections[current].append(line)
    return {
        path: "".join(lines)
        for path, lines in sections.items()
        if lines
    }




def _parse_caa_answer(
    text: str,
) -> tuple[tuple[dict[str, object], ...], tuple[str, ...]]:
    records: dict[str, dict[str, object]] = {}
    aliases: list[str] = []
    pattern = re.compile(
        r'^\s*(\d{1,3})\s+(issue|issuewild|iodef)\s+"([^"\r\n]{0,255})"\s*$',
        re.I,
    )
    for line in text.splitlines():
        if not line.strip():
            continue
        match = pattern.fullmatch(line)
        if match:
            record = _canonical_caa_record(
                int(match.group(1)),
                match.group(2).lower(),
                match.group(3),
            )
            records[json.dumps(record, sort_keys=True)] = record
            continue
        try:
            alias = validate_domain(line)
        except ValueError:
            raise AuditError("CAA response was malformed") from None
        if alias not in aliases:
            aliases.append(alias)
    return tuple(records[key] for key in sorted(records)), tuple(aliases)


def _canonical_caa_record(flags: int, tag: str, value: str) -> dict[str, object]:
    if not 0 <= flags <= 255:
        raise AuditError("CAA response was malformed")
    if tag == "iodef":
        return {"configured": bool(value), "flags": flags, "tag": "iodef"}
    parts = value.split(";")
    raw_issuer = parts[0].strip()
    if raw_issuer:
        try:
            issuer: str | None = validate_domain(raw_issuer)
        except ValueError:
            raise AuditError("CAA issuer is malformed") from None
    else:
        issuer = None
    record: dict[str, object] = {"flags": flags, "issuer": issuer, "tag": tag}
    parameters: set[str] = set()
    for raw_parameter in parts[1:]:
        parameter = raw_parameter.strip()
        if not parameter:
            continue
        if parameter.count("=") != 1:
            raise AuditError("CAA issuer parameter is malformed")
        key, parameter_value = (item.strip() for item in parameter.split("=", 1))
        key = key.lower()
        if key in parameters:
            raise AuditError("CAA issuer parameter is duplicated")
        parameters.add(key)
        if key == "validationmethods":
            methods = tuple(
                sorted(set(item.strip().lower() for item in parameter_value.split(",")))
            )
            if not methods:
                raise AuditError("CAA issuer parameter is malformed")
            if any(method not in _CAA_VALIDATION_METHODS for method in methods):
                raise AuditError("CAA issuer parameter is unsupported")
            record["validation_methods"] = methods
        elif key == "accounturi":
            if (
                not parameter_value.startswith(("http://", "https://"))
                or len(parameter_value) > 255
                or any(character.isspace() for character in parameter_value)
            ):
                raise AuditError("CAA issuer parameter is malformed")
            record["account_restricted"] = True
        else:
            raise AuditError("CAA issuer parameter is unsupported")
    return record


def _applicable_caa(
    domain: str,
    runner: CommandRunner,
    cache: dict[str, tuple[tuple[dict[str, object], ...], tuple[str, ...]]],
    query_count: list[int],
) -> tuple[tuple[dict[str, object], ...], str | None]:
    current = domain
    visited: set[str] = set()
    while current not in visited:
        visited.add(current)
        if current not in cache:
            query_count[0] += 1
            if query_count[0] > 64:
                raise AuditError("CAA query limit exceeded")
            result = _required_run(runner, ("dig", "+short", "CAA", current))
            if result.returncode != 0:
                raise AuditError("CAA query failed")
            cache[current] = _parse_caa_answer(result.stdout)
        records, aliases = cache[current]
        if records:
            source = aliases[-1] if aliases else current
            return records, source
        if aliases:
            current = aliases[-1]
            continue
        labels = current.split(".")
        if len(labels) == 1:
            return (), None
        current = ".".join(labels[1:])
    raise AuditError("CAA alias loop detected")


def _caa_compatible(records: Sequence[Mapping[str, object]]) -> bool:
    issue_records = [record for record in records if record.get("tag") == "issue"]
    if not issue_records:
        return True
    for record in issue_records:
        methods = record.get("validation_methods")
        if (
            record.get("issuer") == "letsencrypt.org"
            and record.get("account_restricted") is not True
            and (methods is None or "http-01" in methods)
        ):
            return True
    return False


def _certificate_fact(domain: str, runner: CommandRunner) -> dict[str, object]:
    path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    result = _required_run(
        runner,
        (
            "openssl",
            "x509",
            "-in",
            path,
            "-noout",
            "-dates",
            "-ext",
            "subjectAltName",
        ),
    )
    if result.returncode != 0:
        return {"covers_domain": False, "present": False}
    names: set[str] = set()
    for raw_name in re.findall(r"DNS:([^,\s]+)", result.stdout):
        try:
            if raw_name.startswith("*."):
                names.add("*." + validate_domain(raw_name[2:]))
            else:
                names.add(validate_domain(raw_name))
        except ValueError:
            continue
    fact: dict[str, object] = {
        "covers_domain": any(_san_covers(name, domain) for name in names),
        "names": tuple(sorted(names)),
        "present": True,
    }
    for key, label in (("notBefore", "not_before"), ("notAfter", "not_after")):
        match = re.search(rf"(?m)^{key}=([A-Za-z0-9 :]+(?:GMT)?)$", result.stdout)
        if match:
            fact[label] = match.group(1)
    return fact


def _san_covers(name: str, domain: str) -> bool:
    if not name.startswith("*."):
        return name == domain
    suffix = name[2:]
    return domain.endswith("." + suffix) and len(domain.split(".")) == len(suffix.split(".")) + 1


def _version_fact(
    result: subprocess.CompletedProcess[str] | None,
    observation: str,
    *,
    bare: bool = False,
) -> dict[str, object]:
    if result is None:
        return {"available": False, "observation": observation}
    pattern = (
        r"^\s*(\d+(?:\.\d+){1,3})\s*$"
        if bare
        else r"\bversion\s+(\d+(?:\.\d+){1,3})\b"
    )
    match = re.search(pattern, result.stdout, re.I)
    fact: dict[str, object] = {"available": True, "observation": observation}
    if match:
        fact["version"] = match.group(1)
    return fact


def _systemd_fact(
    result: subprocess.CompletedProcess[str] | None,
    observation: str,
) -> dict[str, object]:
    if result is None:
        return {"available": False, "observation": observation, "services": ()}
    services = {
        fields[0]
        for line in result.stdout.splitlines()
        if (fields := line.split())
        and re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", fields[0])
    }
    return {
        "available": True,
        "observation": observation,
        "services": tuple(sorted(services)),
    }


def parse_ufw_ipv6_config(text: str) -> bool | None:
    assignments = [line.strip() for line in text.splitlines() if line.strip()]
    if len(assignments) != 1:
        return None
    match = re.fullmatch(r"IPV6=(yes|no)", assignments[0])
    if match is None:
        return None
    return match.group(1) == "yes"


def _parse_ufw_ipv6_enabled(
    result: subprocess.CompletedProcess[str] | None,
) -> bool | None:
    if result is None:
        return None
    return parse_ufw_ipv6_config(result.stdout)


def _ufw_fact(
    config: InstallerConfig,
    result: subprocess.CompletedProcess[str] | None,
    observation: str,
    ipv6_enabled: bool | None,
) -> dict[str, object]:
    active = result is not None and bool(
        re.search(r"(?im)^Status:\s+active\s*$", result.stdout)
    )
    return {
        "active": active,
        "available": result is not None,
        "ipv6_enabled": ipv6_enabled,
        "mode": "managed"
        if config.host_mode is HostMode.FRESH and config.firewall.manage_ufw
        else "read_only",
        "observation": observation,
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


