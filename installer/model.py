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
    # The client subscription URL lives on its own name so that a subscriber never
    # learns the panel's; absent means the public `/s/` endpoint stays switched off.
    subscription: str | None = None
    # The MCP server (v0.11 §9a) rides on its own name too, and only on the central
    # panel: nodes leave it empty and the MCP container never starts there.
    mcp: str | None = None


# Lane slots (v0.7): extra mita daemons for clients' own lanes, one TCP port each from
# this base — `mita@1` on 46101, `mita@2` on 46102, … (spec §5.2).
LANE_SLOT_BASE_PORT = 46100
MAX_LANE_SLOTS = 8
DEFAULT_LANE_SLOTS = 4


def lane_slot_port(index: int) -> int:
    return LANE_SLOT_BASE_PORT + index


@dataclass(frozen=True)
class MieruConfig:
    tcp_ports: tuple[int, ...]
    udp_ports: tuple[int, ...]
    # How many lane slots the host runs (v0.7); 0 without a router.
    lane_slots: int = 0

    def slot_ports(self) -> tuple[int, ...]:
        return tuple(lane_slot_port(index) for index in range(1, self.lane_slots + 1))


@dataclass(frozen=True)
class ThreeXuiConfig:
    mode: ThreeXuiMode
    panel_domain: str | None = None
    vless_tcp_domain: str | None = None
    vless_xhttp_domain: str | None = None
    hysteria_domain: str | None = None
    warp: bool = False
    warp_domains: tuple[str, ...] = ()
    warp_port: int = 40000
    subscription_domain: str | None = None


class EgressChoice(StrEnum):
    DIRECT = "direct"
    WARP = "warp"
    # v0.5: the service is handed to the node's Xray egress-router (ADR 007).
    ROUTER = "router"


# The router's per-service SOCKS5 ingress on the host loopback (v0.5, frozen identifiers):
# the same numbers `xray_router_manager.intent.PORTS` listens on.
ROUTER_PORTS: dict[str, int] = {"naive": 45101, "mieru": 45102}
# The relay inbound's public port (v0.7): vless+reality for chains from other nodes.
DEFAULT_RELAY_PORT = 45443


@dataclass(frozen=True)
class EgressConfig:
    """Where NaiveProxy and Mieru send their clients' traffic when installed (v0.4, `[egress]`).

    The installer seeds this once; afterwards the managers own it (ADR 007) and the
    panel's routing changes it. `InstallerConfig.egress` holds the section only when it
    was written (wizard or by hand); `InstallerConfig.effective_egress` derives it from
    the pre-v0.4 `[three_xui].warp*` keys otherwise. `router` (v0.5) installs the Xray
    egress-router; a service set to `router` starts attached to it."""

    warp: bool = False
    warp_port: int = 40000
    naive: EgressChoice = EgressChoice.DIRECT
    mieru: EgressChoice = EgressChoice.DIRECT
    router: bool = False
    # The router's relay inbound for chains from other nodes (v0.7): a public TCP port,
    # opened with the router; 0 keeps the relay off.
    relay_port: int = 0

    def provider_url(self) -> str | None:
        """The WARP proxy-mode endpoint the managers are told about, or None without WARP."""
        return f"socks5://127.0.0.1:{self.warp_port}" if self.warp else None

    def router_url(self, service: str) -> str | None:
        """The router ingress a manager may send its service through, or None without a router."""
        return f"socks5://127.0.0.1:{ROUTER_PORTS[service]}" if self.router else None

    @classmethod
    def derived(cls, three_xui: ThreeXuiConfig) -> EgressConfig:
        """Exactly what the pre-v0.4 keys meant — including the v0.1 coupling that left
        NaiveProxy and Mieru direct whenever the managed 3x-ui had domain-scoped WARP — so
        an old configuration plans unchanged."""
        whole = three_xui.warp and not three_xui.warp_domains
        choice = EgressChoice.WARP if whole else EgressChoice.DIRECT
        return cls(warp=three_xui.warp, warp_port=three_xui.warp_port, naive=choice, mieru=choice)


@dataclass(frozen=True)
class FirewallConfig:
    manage_ufw: bool


@dataclass(frozen=True)
class IngressConfig:
    """Optional local bridge for a foreign stream frontend that emits PROXY."""

    proxy_protocol_bridge: str | None = None
    # The Core TLS vhost normally owns 8443. A foreign vhost already bound there
    # can reserve another private listener for Core without touching its socket.
    panel_tls_port: int = 8443
    # Explicit operator acknowledgement: use locally verified existing certificates
    # without making a new ACME renewal simulation during this install.
    skip_renewal_dry_run: bool = False


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
    # The written `[egress]` section, or None for a configuration from before it existed.
    egress: EgressConfig | None = None
    # An opt-in loopback bridge is required only when a foreign shared-443 frontend
    # emits PROXY protocol but the selected private backends do not consume it.
    ingress: IngressConfig | None = None

    @property
    def effective_egress(self) -> EgressConfig:
        return self.egress if self.egress is not None else EgressConfig.derived(self.three_xui)

    @property
    def panel_tls_port(self) -> int:
        """The private Nginx TLS listener that terminates the Core panel."""
        return self.ingress.panel_tls_port if self.ingress is not None else 8443

    def required_domains(self) -> tuple[str, ...]:
        values = (
            self.domains.panel,
            self.domains.mtproxy,
            self.domains.naive,
            self.domains.mieru,
            self.domains.subscription,
            self.domains.mcp,
            self.three_xui.panel_domain,
            self.three_xui.vless_tcp_domain,
            self.three_xui.vless_xhttp_domain,
            self.three_xui.hysteria_domain,
            self.three_xui.subscription_domain,
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
