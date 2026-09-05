from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum, StrEnum
from typing import Any


class HostMode(StrEnum):
    FRESH = "fresh"
    COEXIST = "coexist"


class Profile(StrEnum):
    CORE = "core"
    CORE_NAIVE = "core-naive"
    CORE_MIERU = "core-mieru"
    FULL = "full"

    @property
    def includes_naive(self) -> bool:
        return self in {Profile.CORE_NAIVE, Profile.FULL}

    @property
    def includes_mieru(self) -> bool:
        return self in {Profile.CORE_MIERU, Profile.FULL}


class ThreeXuiMode(StrEnum):
    NONE = "none"
    EXISTING = "existing"
    MANAGED_NEW = "managed-new"


@dataclass(frozen=True)
class DomainConfig:
    panel: str
    mtproxy: str
    naive: str | None = None
    mieru: str | None = None


@dataclass(frozen=True)
class MieruConfig:
    tcp_ports: tuple[int, ...]
    udp_ports: tuple[int, ...]


@dataclass(frozen=True)
class ThreeXuiConfig:
    mode: ThreeXuiMode
    panel_domain: str | None = None
    vless_tcp_domain: str | None = None
    vless_xhttp_domain: str | None = None
    hysteria_domain: str | None = None
    warp: bool = False
    warp_domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class FirewallConfig:
    manage_ufw: bool


@dataclass(frozen=True)
class InstallerConfig:
    schema: int
    host_mode: HostMode
    profile: Profile
    acme_email: str
    initial_user: str
    domains: DomainConfig
    mieru: MieruConfig | None
    three_xui: ThreeXuiConfig
    firewall: FirewallConfig

    def required_domains(self) -> tuple[str, ...]:
        values = (
            self.domains.panel,
            self.domains.mtproxy,
            self.domains.naive,
            self.domains.mieru,
            self.three_xui.panel_domain,
            self.three_xui.vless_tcp_domain,
            self.three_xui.vless_xhttp_domain,
            self.three_xui.hysteria_domain,
        )
        return tuple(sorted({value for value in values if value is not None}))

    def canonical_dict(self) -> dict[str, object]:
        return _canonical_dataclass(self)


def _canonical_dataclass(value: object) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _canonical_dataclass(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, tuple):
        return [_canonical_dataclass(item) for item in value]
    return value
