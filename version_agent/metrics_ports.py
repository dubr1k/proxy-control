"""Which listening ports carry each protocol's client traffic, for the kernel byte counters.

The agent never asks the operator for a port map: it derives it from the files the installer
already wrote (the Compose overlay list, `.env*`, the mita server config) and an optional
override file. A protocol that is not enabled on the host is simply absent from the result, so
the panel shows it as unavailable instead of as zero traffic.
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

LOG = logging.getLogger("version_agent.metrics")

OVERRIDE_FILE = Path("/etc/proxy-control/metrics-ports.json")
MITA_CONFIG = Path("/var/lib/mita/server_config.json")
KNOWN_PROTOCOLS = ("mtproxy", "naive", "mieru", "trusttunnel")
DEFAULT_MTPROXY_PORT = 8445
DEFAULT_NAIVE_PORT = 4443
DEFAULT_TRUSTTUNNEL_PORT = 4453
# A port range of a Mieru binding is expanded into one counter per port; a sane config stays far
# below this, and an absurd one must not turn into thousands of firewall rules.
MAX_PORTS_PER_PROTOCOL = 64

PortMap = dict[str, dict[str, list[int]]]
EnvReader = Callable[[Path], Mapping[str, str]]

_warned: set[str] = set()


def _warn_once(key: str, message: str, *args) -> None:
    if key not in _warned:
        _warned.add(key)
        LOG.warning(message, *args)


def read_env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE lines of an env file. A missing or unreadable file is an empty mapping."""
    try:
        text = Path(path).read_text()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _valid_port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= 65535 else None


def _port_from_listen(value: str | None, default: int) -> int:
    """`127.0.0.1:4453`, `[::1]:4453` or `4453` -> 4453; anything else -> the default."""
    if value:
        match = re.fullmatch(r"(?:.*:)?([0-9]{1,5})", value.strip())
        if match and (port := _valid_port(int(match.group(1)))):
            return port
    return default


def _mieru_ports(config_path: Path) -> dict[str, list[int]]:
    """TCP/UDP ports from the mita server config's `portBindings` (`port` or `portRange`)."""
    found: dict[str, list[int]] = {"tcp": [], "udp": []}
    try:
        config = json.loads(Path(config_path).read_text())
        bindings = config.get("portBindings") or []
    except (OSError, ValueError, AttributeError):
        return found
    for binding in bindings if isinstance(bindings, list) else []:
        if not isinstance(binding, dict):
            continue
        transport = str(binding.get("protocol", "")).lower()
        if transport not in found:
            continue
        if "port" in binding:
            ports: Iterable[int] = [binding["port"]]
        else:
            match = re.fullmatch(r"([0-9]{1,5})-([0-9]{1,5})", str(binding.get("portRange", "")))
            ports = range(int(match.group(1)), int(match.group(2)) + 1) if match else []
        for port in ports:
            if (valid := _valid_port(port)) and valid not in found[transport]:
                found[transport].append(valid)
    return found


def _lane_slot_ports(value: str | None) -> list[int]:
    """`MIERU_LANE_SLOTS=1:46101:/sock:/state,2:46102:...` -> [46101, 46102]."""
    ports = []
    for entry in (value or "").split(","):
        parts = entry.split(":")
        if len(parts) >= 2 and parts[1].isdigit() and (port := _valid_port(int(parts[1]))):
            ports.append(port)
    return ports


def load_override(path: Path = OVERRIDE_FILE) -> PortMap:
    """The validated override file. Malformed content is ignored as a whole, with one log line."""
    try:
        raw = Path(path).read_text()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        _warn_once("override-read", "metrics port override unreadable: %s", type(exc).__name__)
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("top level must be an object")
        result: PortMap = {}
        for protocol, transports in data.items():
            if protocol not in KNOWN_PROTOCOLS:
                raise ValueError(f"unknown protocol {protocol!r}")
            if not isinstance(transports, dict) or not transports:
                raise ValueError(f"{protocol}: expected an object with tcp/udp lists")
            entry: dict[str, list[int]] = {"tcp": [], "udp": []}
            for transport, ports in transports.items():
                if transport not in entry or not isinstance(ports, list):
                    raise ValueError(f"{protocol}: bad transport {transport!r}")
                for port in ports:
                    if _valid_port(port) is None:
                        raise ValueError(f"{protocol}: port out of range")
                    if port not in entry[transport]:
                        entry[transport].append(port)
            result[protocol] = entry
        return result
    except ValueError as exc:
        _warn_once("override-invalid", "metrics port override ignored: %s", exc)
        return {}


def discover_ports(
    compose_dir: Path | str,
    compose_files: Iterable[str],
    runner=None,  # noqa: ARG001 - reserved: discovery reads files only, never runs a command
    env_reader: EnvReader = read_env_file,
    *,
    override_path: Path = OVERRIDE_FILE,
    mita_config: Path = MITA_CONFIG,
) -> PortMap:
    """`{protocol: {"tcp": [...], "udp": [...]}}` for the protocols enabled on this host."""
    directory = Path(compose_dir)
    files = set(compose_files)
    base = env_reader(directory / ".env")
    result: PortMap = {}

    backend = base.get("MTPROXY_BACKEND_PORT", "")
    mtproxy = int(backend) if backend.isdigit() and _valid_port(int(backend)) else DEFAULT_MTPROXY_PORT
    result["mtproxy"] = {"tcp": [mtproxy], "udp": []}

    if "compose.naive.yaml" in files:
        result["naive"] = {"tcp": [DEFAULT_NAIVE_PORT], "udp": []}

    if "compose.trusttunnel.yaml" in files:
        port = _port_from_listen(env_reader(directory / ".env.trusttunnel").get("TT_LISTEN"), DEFAULT_TRUSTTUNNEL_PORT)
        result["trusttunnel"] = {"tcp": [port], "udp": []}

    if "compose.mieru.yaml" in files:
        mieru = _mieru_ports(mita_config)
        lanes = {**env_reader(directory / ".env"), **env_reader(directory / ".env.mieru")}.get("MIERU_LANE_SLOTS")
        for port in _lane_slot_ports(lanes):
            if port not in mieru["tcp"]:
                mieru["tcp"].append(port)
        if mieru["tcp"] or mieru["udp"]:
            result["mieru"] = mieru

    for protocol, transports in load_override(override_path).items():
        result[protocol] = transports

    for protocol, transports in result.items():
        budget = MAX_PORTS_PER_PROTOCOL
        for transport in ("tcp", "udp"):
            transports[transport] = sorted(transports[transport])[:budget]
            budget -= len(transports[transport])
    return result
