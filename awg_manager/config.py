"""Environment configuration, validated fail-closed at startup."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
from typing import Mapping

KNOWN_VERSIONS = ("1.5", "2.0", "3.1")
DEFAULT_PORTS = {"1.5": 51820, "2.0": 51821, "3.1": 51822}
DEFAULT_SUBNETS = {"1.5": "10.66.15.0/24", "2.0": "10.66.20.0/24", "3.1": "10.66.31.0/24"}
LOG_LEVELS = ("verbose", "error", "silent")
_PRIVATE = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class ConfigError(ValueError):
    """Startup configuration is invalid; the manager refuses to run."""


def interface_name(version: str) -> str:
    return "awg" + version.replace(".", "")


@dataclass(frozen=True)
class Config:
    token_file: Path
    socket: Path
    socket_mode: int
    state_dir: Path
    versions: tuple[str, ...]
    ports: dict[str, int]
    subnets: dict[str, ipaddress.IPv4Network]
    mtu: int
    dns: tuple[str, ...]
    nat: bool
    log_level: str
    obfuscation_file: Path | None


def _pairs(raw: str, name: str, defaults: Mapping[str, object]) -> dict[str, str]:
    out: dict[str, str] = {k: str(v) for k, v in defaults.items()}
    seen: set[str] = set()
    for item in (p.strip() for p in raw.split(",")):
        if not item:
            continue
        key, sep, value = item.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or key not in KNOWN_VERSIONS or not value or key in seen:
            raise ConfigError(f"{name}: bad entry {item!r}")
        seen.add(key)
        out[key] = value
    return out


def _bool(raw: str, name: str) -> bool:
    low = raw.strip().lower()
    if low in {"1", "true", "yes", "on"}:
        return True
    if low in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name}: expected true or false")


def _int(raw: str, name: str, base: int = 10) -> int:
    try:
        return int(raw.strip(), base)
    except ValueError as exc:
        raise ConfigError(f"{name}: not a number") from exc


def from_env(env: Mapping[str, str]) -> Config:
    get = lambda k, d="": env.get(k, d).strip()  # noqa: E731
    if not get("AWG_MANAGER_TOKEN_FILE"):
        raise ConfigError("AWG_MANAGER_TOKEN_FILE is required")

    versions = tuple(v.strip() for v in get("AWG_VERSIONS", "1.5,2.0,3.1").split(",") if v.strip())
    if not versions or len(set(versions)) != len(versions):
        raise ConfigError("AWG_VERSIONS: empty or duplicated")
    unknown = [v for v in versions if v not in KNOWN_VERSIONS]
    if unknown:
        raise ConfigError(f"AWG_VERSIONS: unknown version {unknown[0]!r}")

    ports_raw = _pairs(get("AWG_PORTS"), "AWG_PORTS", DEFAULT_PORTS)
    ports = {v: _int(ports_raw[v], f"AWG_PORTS[{v}]") for v in versions}
    for v, port in ports.items():
        if not 1024 <= port <= 65535:
            raise ConfigError(f"AWG_PORTS[{v}]: must be 1024-65535")
    if len(set(ports.values())) != len(ports):
        raise ConfigError("AWG_PORTS: ports must be distinct")

    subnets_raw = _pairs(get("AWG_SUBNETS"), "AWG_SUBNETS", DEFAULT_SUBNETS)
    subnets: dict[str, ipaddress.IPv4Network] = {}
    for v in versions:
        try:
            net = ipaddress.ip_network(subnets_raw[v], strict=True)
        except ValueError as exc:
            raise ConfigError(f"AWG_SUBNETS[{v}]: invalid network") from exc
        if net.version != 4 or not 24 <= net.prefixlen <= 28:
            raise ConfigError(f"AWG_SUBNETS[{v}]: must be an IPv4 /24 to /28")
        if not any(net.subnet_of(p) for p in _PRIVATE):
            raise ConfigError(f"AWG_SUBNETS[{v}]: must be inside a private range")
        subnets[v] = net  # type: ignore[assignment]
    nets = list(subnets.values())
    for i, a in enumerate(nets):
        if any(a.overlaps(b) for b in nets[i + 1 :]):
            raise ConfigError("AWG_SUBNETS: subnets overlap")

    mtu = _int(get("AWG_MTU", "1280"), "AWG_MTU")
    if not 1280 <= mtu <= 1420:
        raise ConfigError("AWG_MTU: must be 1280-1420")

    dns = tuple(d.strip() for d in get("AWG_DNS", "1.1.1.1,1.0.0.1").split(",") if d.strip())
    if not 1 <= len(dns) <= 4:
        raise ConfigError("AWG_DNS: 1 to 4 addresses")
    for d in dns:
        try:
            ipaddress.ip_address(d)
        except ValueError as exc:
            raise ConfigError(f"AWG_DNS: invalid address {d!r}") from exc

    log_level = get("AWG_LOG_LEVEL", "error").lower()
    if log_level not in LOG_LEVELS:
        raise ConfigError("AWG_LOG_LEVEL: verbose, error or silent")

    mode = _int(get("AWG_MANAGER_SOCKET_MODE", "660"), "AWG_MANAGER_SOCKET_MODE", 8)
    if not 0 < mode <= 0o777 or mode & 0o007:
        raise ConfigError("AWG_MANAGER_SOCKET_MODE: must not grant access to others")

    sock = Path(get("AWG_MANAGER_SOCKET", "/run/awg-manager/manager.sock"))
    state_dir = Path(get("AWG_STATE_DIR", "/var/lib/awg-manager"))
    if not sock.is_absolute() or not state_dir.is_absolute():
        raise ConfigError("AWG_MANAGER_SOCKET and AWG_STATE_DIR must be absolute")
    obf = get("AWG_OBFUSCATION_FILE")
    return Config(
        token_file=Path(get("AWG_MANAGER_TOKEN_FILE")),
        socket=sock,
        socket_mode=mode,
        state_dir=state_dir,
        versions=versions,
        ports=ports,
        subnets=subnets,
        mtu=mtu,
        dns=dns,
        nat=_bool(get("AWG_NAT", "true"), "AWG_NAT"),
        log_level=log_level,
        obfuscation_file=Path(obf) if obf else None,
    )
