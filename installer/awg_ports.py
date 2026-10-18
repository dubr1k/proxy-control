"""Pseudo-random, host-stable UDP ports for the AmneziaWG add-on.

The well-known 51820-51822 are fingerprinted by censors, so the installer never defaults to
them. A version without an explicit `[amneziawg] ports` entry gets a free port derived from
the host, so the plan digest is the same for `plan`, `install --accept-plan` and every re-run:

    candidate = 10240 + int(sha256(f"{machine_id}:{version}:{attempt}")) % 21761      # 10240..32000

`machine_id` is `/etc/machine-id` under the installer's root (the host name when it is absent).
A candidate that is planned for another purpose, bound on the host or already picked for
another version is skipped by raising `attempt`. Ports an installed host already runs
(`.env.amneziawg`, or a socket held by `amneziawg-go`) are kept as they are.
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
import socket
from collections.abc import Collection, Mapping, Sequence
from pathlib import Path

from installer.config import ConfigError, planned_ports
from installer.model import AWG_VERSIONS, InstallerConfig

PORT_LOW = 10240
PORT_HIGH = 32000  # below the Linux ephemeral range (32768-60999)
_MAX_ATTEMPTS = 4096
_OWN_PROCESS = "amneziawg-go"
_ENV_OVERLAY = "opt/mtproxy-shared443/.env.amneziawg"


def machine_id(root: Path) -> str:
    """The host identity the derivation hashes: `/etc/machine-id`, else the host name."""
    try:
        value = (Path(root) / "etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    return value or socket.gethostname()


def derive_port(identity: str, version: str, attempt: int) -> int:
    digest = hashlib.sha256(f"{identity}:{version}:{attempt}".encode()).digest()
    return PORT_LOW + int.from_bytes(digest, "big") % (PORT_HIGH - PORT_LOW + 1)


def bound_ports(listeners: object) -> set[int]:
    """Ports the audit saw bound, except UDP ports held only by our own `amneziawg-go`."""
    if not isinstance(listeners, Mapping):
        return set()

    def numbers(key: str) -> set[int]:
        value = listeners.get(key)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return set()
        return {int(item) for item in value if isinstance(item, int)}

    owners = listeners.get("owners")
    own = {
        port
        for port in numbers("udp")
        if isinstance(owners, Mapping)
        and isinstance(owners.get(str(port)), Sequence)
        and not isinstance(owners.get(str(port)), (str, bytes))
        and owners.get(str(port))
        and set(owners.get(str(port))) <= {_OWN_PROCESS}  # type: ignore[arg-type]
    }
    return (numbers("udp") - own) | numbers("tcp")


def installed_ports(root: Path) -> dict[str, int]:
    """The ports of an installed add-on (`AWG_PORTS` in its env overlay); {} when absent."""
    try:
        text = (Path(root) / _ENV_OVERLAY).read_text(encoding="utf-8")
    except OSError:
        return {}
    match = re.search(r"^AWG_PORTS=(.*)$", text, re.MULTILINE)
    found: dict[str, int] = {}
    for entry in (match.group(1).split(",") if match else ()):
        version, _, port = entry.strip().partition("=")
        if version in AWG_VERSIONS and port.isdigit() and 1024 <= int(port) <= 65535:
            found[version] = int(port)
    return found if len(set(found.values())) == len(found) else {}


def pick_ports(
    versions: Sequence[str],
    *,
    identity: str,
    taken: Collection[int],
    fixed: Mapping[str, int] | None = None,
) -> dict[str, int]:
    """A distinct free port for every version in `versions` that `fixed` does not name."""
    result = dict(fixed or {})
    used = set(taken) | set(result.values())
    for version in versions:
        if version in result:
            continue
        for attempt in range(_MAX_ATTEMPTS):
            candidate = derive_port(identity, version, attempt)
            if candidate not in used:
                result[version] = candidate
                used.add(candidate)
                break
        else:
            raise ConfigError(f"no free AmneziaWG port was found for version {version}")
    return {version: result[version] for version in versions}


def resolve_awg_ports(
    config: InstallerConfig,
    *,
    root: Path,
    listeners: object = None,
    identity: str | None = None,
) -> InstallerConfig:
    """Fill every unassigned AmneziaWG port (0) of `config`; a config with all ports is returned as is."""
    awg = config.amneziawg
    if awg is None or all(awg.ports):
        return config
    fixed = {v: p for v, p in zip(awg.versions, awg.ports, strict=True) if p}
    taken = set(planned_ports(config)) | bound_ports(listeners)
    for version, port in installed_ports(root).items():
        if version in awg.versions and version not in fixed and port not in fixed.values() \
                and port not in planned_ports(config):
            fixed[version] = port
    picks = pick_ports(
        awg.versions, identity=identity or machine_id(root), taken=taken - set(fixed.values()), fixed=fixed
    )
    return dataclasses.replace(
        config, amneziawg=dataclasses.replace(awg, ports=tuple(picks[v] for v in awg.versions))
    )
