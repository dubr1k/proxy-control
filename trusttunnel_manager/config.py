"""Environment configuration, validated fail-closed at startup."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from typing import Mapping

HOSTNAME = re.compile(
    r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?"
)


class ConfigError(ValueError):
    """Startup configuration is invalid; the manager refuses to run."""


@dataclass(frozen=True)
class Config:
    token_file: Path
    socket: Path
    socket_mode: int
    state_dir: Path
    hostname: str
    listen: str
    metrics: str
    cert: Path
    key: Path
    binary: Path
    version: str
    public_port: int
    restart_delay: float
    poll_interval: float


def loopback_address(raw: str, name: str) -> str:
    host, sep, port = raw.rpartition(":")
    try:
        ok = bool(sep) and ipaddress.ip_address(host).is_loopback and 1024 <= int(port) <= 65535
    except ValueError:
        ok = False
    if not ok:
        raise ConfigError(f"{name}: must be a loopback address with a port 1024-65535")
    return raw


def _int(raw: str, name: str, base: int = 10) -> int:
    try:
        return int(raw.strip(), base)
    except ValueError as exc:
        raise ConfigError(f"{name}: not a number") from exc


def from_env(env: Mapping[str, str]) -> Config:
    get = lambda k, d="": env.get(k, d).strip()  # noqa: E731
    if not get("TT_MANAGER_TOKEN_FILE"):
        raise ConfigError("TT_MANAGER_TOKEN_FILE is required")
    hostname = get("TT_HOSTNAME").lower()
    if not HOSTNAME.fullmatch(hostname):
        raise ConfigError("TT_HOSTNAME: a DNS name is required")
    listen = loopback_address(get("TT_LISTEN", "127.0.0.1:4453"), "TT_LISTEN")
    metrics = loopback_address(get("TT_METRICS", "127.0.0.1:1987"), "TT_METRICS")
    if listen == metrics:
        raise ConfigError("TT_LISTEN and TT_METRICS must differ")
    mode = _int(get("TT_MANAGER_SOCKET_MODE", "660"), "TT_MANAGER_SOCKET_MODE", 8)
    if not 0 < mode <= 0o777 or mode & 0o007:
        raise ConfigError("TT_MANAGER_SOCKET_MODE: must not grant access to others")
    paths = {
        "TT_MANAGER_SOCKET": get("TT_MANAGER_SOCKET", "/run/trusttunnel-manager/manager.sock"),
        "TT_STATE_DIR": get("TT_STATE_DIR", "/var/lib/trusttunnel-manager"),
        "TT_CERT": get("TT_CERT", f"/etc/letsencrypt/live/{hostname}/fullchain.pem"),
        "TT_KEY": get("TT_KEY", f"/etc/letsencrypt/live/{hostname}/privkey.pem"),
        "TT_BINARY": get("TT_BINARY", "/usr/local/bin/trusttunnel_endpoint"),
    }
    for name, value in paths.items():
        if not Path(value).is_absolute():
            raise ConfigError(f"{name}: must be an absolute path")
    return Config(
        token_file=Path(get("TT_MANAGER_TOKEN_FILE")),
        socket=Path(paths["TT_MANAGER_SOCKET"]),
        socket_mode=mode,
        state_dir=Path(paths["TT_STATE_DIR"]),
        hostname=hostname,
        listen=listen,
        metrics=metrics,
        cert=Path(paths["TT_CERT"]),
        key=Path(paths["TT_KEY"]),
        binary=Path(paths["TT_BINARY"]),
        version=get("TT_VERSION"),
        public_port=_int(get("TT_PUBLIC_PORT", "443"), "TT_PUBLIC_PORT"),
        restart_delay=2.0,
        poll_interval=5.0,  # per-client rows of the live monitor follow the endpoint within seconds
    )
