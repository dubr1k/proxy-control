from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar

from installer.model import (
    DEFAULT_LANE_SLOTS,
    DEFAULT_RELAY_PORT,
    MAX_LANE_SLOTS,
    ROUTER_PORTS,
    DomainConfig,
    EgressChoice,
    EgressConfig,
    FirewallConfig,
    HostMode,
    IngressConfig,
    InstallerConfig,
    MieruConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
    lane_slot_port,
)

_DOMAIN_RE = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+\Z")
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_ENUM = TypeVar("_ENUM", bound=object)


class ConfigError(ValueError):
    """The installer configuration is malformed or internally inconsistent."""


def load_config(path: Path) -> InstallerConfig:
    return parse_config(path.read_text(encoding="utf-8"))


def parse_config(text: str) -> InstallerConfig:
    try:
        raw = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, TypeError) as exc:
        raise ConfigError(f"invalid TOML: {exc}") from exc

    root = _table(raw, "config")
    _keys(
        root,
        path="",
        required={
            "schema",
            "host_mode",
            "profile",
            "acme_email",
            "initial_user",
            "domains",
            "three_xui",
            "firewall",
        },
        optional={"mieru", "egress", "ingress"},
    )

    schema = _integer(root["schema"], "schema")
    if schema != 1:
        raise ConfigError(f"unsupported schema: {schema}")
    host_mode = _enum(root["host_mode"], HostMode, "host_mode")
    profile = _enum(root["profile"], Profile, "profile")
    acme_email = _string(root["acme_email"], "acme_email")
    if not _EMAIL_RE.fullmatch(acme_email):
        raise ConfigError("invalid ACME email")
    initial_user = _string(root["initial_user"], "initial_user")
    if not _SAFE_NAME_RE.fullmatch(initial_user):
        raise ConfigError("unsafe initial user")

    domains = _parse_domains(root["domains"], profile)
    mieru = _parse_mieru(root.get("mieru"), profile)
    three_xui = _parse_three_xui(root["three_xui"], explicit_egress="egress" in root)
    egress = _parse_egress(root.get("egress"), three_xui, profile, three_xui_raw=_table(root["three_xui"], "three_xui"))
    if mieru is not None:
        # Lane slots (v0.7) need the router; absent, a router host gets the default set.
        router = egress is not None and egress.router
        if mieru.lane_slots == -1:
            mieru = MieruConfig(tcp_ports=mieru.tcp_ports, udp_ports=mieru.udp_ports,
                                lane_slots=DEFAULT_LANE_SLOTS if router else 0)
        elif mieru.lane_slots > 0 and not router:
            raise ConfigError("mieru.lane_slots requires egress.router = true")
    if egress is not None:
        # The old keys mirror the section: everything that still reads them sees one truth.
        three_xui = ThreeXuiConfig(**{**_as_dict(three_xui), "warp": egress.warp, "warp_port": egress.warp_port})
    firewall = _parse_firewall(root["firewall"])
    ingress = _parse_ingress(root.get("ingress"))

    if host_mode is HostMode.COEXIST and firewall.manage_ufw:
        raise ConfigError("UFW can be managed only in fresh mode")
    if ingress is not None and host_mode is not HostMode.COEXIST:
        raise ConfigError("ingress.proxy_protocol_bridge requires coexist mode")

    config = InstallerConfig(
        schema=schema,
        host_mode=host_mode,
        profile=profile,
        acme_email=acme_email,
        initial_user=initial_user,
        domains=domains,
        mieru=mieru,
        three_xui=three_xui,
        firewall=firewall,
        egress=egress,
        ingress=ingress,
    )
    _reject_duplicate_tcp_sni_domains(config)
    return config


def render_config(config: InstallerConfig) -> str:
    lines = [
        f"schema = {config.schema}",
        f"host_mode = {_toml_string(config.host_mode.value)}",
        f"profile = {_toml_string(config.profile.value)}",
        f"acme_email = {_toml_string(config.acme_email)}",
        f"initial_user = {_toml_string(config.initial_user)}",
        "",
        "[domains]",
        f"panel = {_toml_string(config.domains.panel)}",
        f"mtproxy = {_toml_string(config.domains.mtproxy)}",
    ]
    if config.domains.naive is not None:
        lines.append(f"naive = {_toml_string(config.domains.naive)}")
    if config.domains.mieru is not None:
        lines.append(f"mieru = {_toml_string(config.domains.mieru)}")
    if config.domains.subscription is not None:
        lines.append(f"subscription = {_toml_string(config.domains.subscription)}")
    if config.domains.mcp is not None:
        lines.append(f"mcp = {_toml_string(config.domains.mcp)}")

    if config.mieru is not None:
        lines.extend(
            [
                "",
                "[mieru]",
                f"tcp_ports = {_toml_array(config.mieru.tcp_ports)}",
                f"udp_ports = {_toml_array(config.mieru.udp_ports)}",
            ]
        )
        if config.egress is not None and config.egress.router:
            lines.append(f"lane_slots = {config.mieru.lane_slots}")

    if config.egress is not None:
        lines.extend(["", "[egress]", f"warp = {_toml_boolean(config.egress.warp)}"])
        if config.egress.warp_port != 40000:
            lines.append(f"warp_port = {config.egress.warp_port}")
        if config.egress.router:
            lines.append("router = true")
            lines.append(f"relay_port = {config.egress.relay_port}")
        if config.profile.includes_naive:
            lines.append(f"naive = {_toml_string(config.egress.naive.value)}")
        if config.profile.includes_mieru:
            lines.append(f"mieru = {_toml_string(config.egress.mieru.value)}")

    if config.ingress is not None:
        lines.extend([
            "",
            "[ingress]",
            f"proxy_protocol_bridge = {_toml_string(config.ingress.proxy_protocol_bridge or '')}",
            f"panel_tls_port = {config.ingress.panel_tls_port}",
            f"skip_renewal_dry_run = {'true' if config.ingress.skip_renewal_dry_run else 'false'}",
        ])

    lines.extend(["", "[three_xui]", f"mode = {_toml_string(config.three_xui.mode.value)}"])
    for name in (
        "panel_domain",
        "vless_tcp_domain",
        "vless_xhttp_domain",
        "hysteria_domain",
    ):
        # Subscription is emitted below only when explicitly enabled.
        value = getattr(config.three_xui, name)
        if value is not None:
            lines.append(f"{name} = {_toml_string(value)}")
    # Round-tripping must reproduce exactly what the parser accepts in this
    if config.three_xui.subscription_domain is not None:
        lines.append(f"subscription_domain = {_toml_string(config.three_xui.subscription_domain)}")
    # mode, so `warp_domains` is written only where it is allowed.
    if config.three_xui.warp or config.three_xui.mode is ThreeXuiMode.MANAGED_NEW:
        lines.append(f"warp = {_toml_boolean(config.three_xui.warp)}")
    if config.three_xui.warp_port != 40000:
        lines.append(f"warp_port = {config.three_xui.warp_port}")
    if config.three_xui.mode is ThreeXuiMode.MANAGED_NEW:
        lines.append(f"warp_domains = {_toml_array(config.three_xui.warp_domains)}")

    lines.extend(
        [
            "",
            "[firewall]",
            f"manage_ufw = {_toml_boolean(config.firewall.manage_ufw)}",
        ]
    )
    return "\n".join(lines) + "\n"


def _parse_domains(value: object, profile: Profile) -> DomainConfig:
    raw = _table(value, "domains")
    if profile.includes_naive and "naive" not in raw:
        raise ConfigError(f"domains.naive is required for profile {profile.value}")
    if profile.includes_mieru and "mieru" not in raw:
        raise ConfigError(f"domains.mieru is required for profile {profile.value}")
    required = {"panel", "mtproxy"}
    optional: set[str] = {"subscription", "mcp"}
    if profile.includes_naive:
        required.add("naive")
    if profile.includes_mieru:
        required.add("mieru")
    _keys(raw, path="domains", required=required, optional=optional)
    return DomainConfig(
        panel=_domain(raw["panel"], "domains.panel"),
        mtproxy=_domain(raw["mtproxy"], "domains.mtproxy"),
        naive=_domain(raw["naive"], "domains.naive") if "naive" in raw else None,
        mieru=_domain(raw["mieru"], "domains.mieru") if "mieru" in raw else None,
        subscription=(
            _domain(raw["subscription"], "domains.subscription") if "subscription" in raw else None
        ),
        mcp=_domain(raw["mcp"], "domains.mcp") if "mcp" in raw else None,
    )


def _parse_mieru(value: object, profile: Profile) -> MieruConfig | None:
    if not profile.includes_mieru:
        if value is not None:
            raise ConfigError("unknown key: mieru")
        return None
    if value is None:
        raise ConfigError(f"mieru section is required for profile {profile.value}")
    raw = _table(value, "mieru")
    _keys(raw, path="mieru", required={"tcp_ports", "udp_ports"}, optional={"lane_slots"})
    tcp_ports = _ports(raw["tcp_ports"], "mieru.tcp_ports")
    udp_ports = _ports(raw["udp_ports"], "mieru.udp_ports")
    if not tcp_ports and not udp_ports:
        raise ConfigError("mieru requires at least one TCP or UDP port")
    lane_slots = None
    if "lane_slots" in raw:
        lane_slots = _integer(raw["lane_slots"], "mieru.lane_slots")
        if not 0 <= lane_slots <= MAX_LANE_SLOTS:
            raise ConfigError(f"mieru.lane_slots must be between 0 and {MAX_LANE_SLOTS}")
        if set(tcp_ports) & set(lane_slot_port(i) for i in range(1, lane_slots + 1)):
            raise ConfigError("mieru.tcp_ports collide with the lane slot ports")
    return MieruConfig(tcp_ports=tcp_ports, udp_ports=udp_ports, lane_slots=-1 if lane_slots is None else lane_slots)


def _parse_three_xui(value: object, *, explicit_egress: bool = False) -> ThreeXuiConfig:
    raw = _table(value, "three_xui")
    if "mode" not in raw:
        raise ConfigError("missing key: three_xui.mode")
    mode = _enum(raw["mode"], ThreeXuiMode, "three_xui.mode")
    domain_names = {
        "panel_domain",
        "vless_tcp_domain",
        "vless_xhttp_domain",
        "hysteria_domain",
    }
    # `warp` is not a 3x-ui setting despite living here: NaiveProxy and Mieru
    # read it to decide their own egress, and neither depends on 3x-ui. It is
    # therefore accepted in every mode. `warp_domains` really is Xray-only, so
    # it stays confined to the managed mode.
    if mode is ThreeXuiMode.NONE:
        _keys(raw, path="three_xui", required={"mode"}, optional={"warp", "warp_port"})
    elif mode is ThreeXuiMode.EXISTING:
        _keys(
            raw,
            path="three_xui",
            required={"mode"},
            optional={*domain_names, "warp", "warp_port"},
        )
    else:
        # With an explicit [egress] the managed mode need not repeat `warp` here.
        _keys(
            raw,
            path="three_xui",
            required={"mode", "warp_domains", *domain_names} | (set() if explicit_egress else {"warp"}),
            optional={"warp_port", "subscription_domain"} | ({"warp"} if explicit_egress else set()),
        )

    parsed_domains = {
        name: _domain(raw[name], f"three_xui.{name}") if name in raw else None
        for name in domain_names
    }
    warp = _boolean(raw["warp"], "three_xui.warp") if "warp" in raw else False
    warp_domains = (
        _warp_domains(raw["warp_domains"])
        if "warp_domains" in raw
        else ()
    )
    if not warp and warp_domains and not (explicit_egress and "warp" not in raw):
        raise ConfigError("three_xui.warp_domains requires warp = true")  # or egress.warp, checked there
    warp_port = _integer(raw.get("warp_port", 40000), "three_xui.warp_port")
    if not 1024 <= warp_port <= 65535:
        raise ConfigError("three_xui.warp_port must be between 1024 and 65535")
    return ThreeXuiConfig(
        mode=mode,
        panel_domain=parsed_domains["panel_domain"],
        vless_tcp_domain=parsed_domains["vless_tcp_domain"],
        vless_xhttp_domain=parsed_domains["vless_xhttp_domain"],
        hysteria_domain=parsed_domains["hysteria_domain"],
        warp=warp,
        warp_domains=warp_domains,
        warp_port=warp_port,
        subscription_domain=_domain(raw["subscription_domain"], "three_xui.subscription_domain") if "subscription_domain" in raw else None,
    )


def _parse_egress(value: object, three_xui: ThreeXuiConfig, profile: Profile, *, three_xui_raw: Mapping[str, Any]) -> EgressConfig | None:
    """`[egress]` when written, None otherwise (`InstallerConfig.effective_egress` then
    derives it from the pre-v0.4 `[three_xui].warp*` keys, so an old configuration plans
    unchanged). Both spellings present must agree."""
    if value is None:
        return None
    raw = _table(value, "egress")
    _keys(raw, path="egress", required=set(), optional={"warp", "warp_port", "naive", "mieru", "router", "relay_port"})
    warp = _boolean(raw["warp"], "egress.warp") if "warp" in raw else False
    # v0.5: the Xray egress-router is worth installing only with a service to feed it.
    router = _boolean(raw["router"], "egress.router") if "router" in raw else False
    if router and not (profile.includes_naive or profile.includes_mieru):
        raise ConfigError("egress.router requires NaiveProxy or Mieru in the profile")
    # v0.7: the relay inbound comes with the router; a router host gets it on the default port.
    relay_port = _integer(raw.get("relay_port", DEFAULT_RELAY_PORT if router else 0), "egress.relay_port")
    if relay_port and not router:
        raise ConfigError("egress.relay_port requires router = true")
    if relay_port and not 1024 <= relay_port <= 65535:
        raise ConfigError("egress.relay_port must be between 1024 and 65535")
    if relay_port in (443, 80, *ROUTER_PORTS.values()):
        raise ConfigError("egress.relay_port collides with a listener the host already runs")
    warp_port = _integer(raw.get("warp_port", 40000), "egress.warp_port")
    if not 1024 <= warp_port <= 65535:
        raise ConfigError("egress.warp_port must be between 1024 and 65535")
    if "warp" in three_xui_raw and three_xui.warp != warp:
        raise ConfigError("three_xui.warp disagrees with egress.warp")
    if "warp_port" in three_xui_raw and three_xui.warp_port != warp_port:
        raise ConfigError("three_xui.warp_port disagrees with egress.warp_port")
    if three_xui.warp_domains and not warp:
        raise ConfigError("three_xui.warp_domains requires egress.warp = true")
    default = EgressChoice.WARP if warp else EgressChoice.DIRECT
    choices = {}
    for service, present in (("naive", profile.includes_naive), ("mieru", profile.includes_mieru)):
        if service not in raw:
            choices[service] = default if present else EgressChoice.DIRECT
            continue
        if not present:
            raise ConfigError(f"egress.{service} is not part of profile {profile.value}")
        choices[service] = _enum(raw[service], EgressChoice, f"egress.{service}")
        if choices[service] is EgressChoice.WARP and not warp:
            raise ConfigError(f"egress.{service} requires warp = true")
        if choices[service] is EgressChoice.ROUTER and not router:
            raise ConfigError(f"egress.{service} requires router = true")
    return EgressConfig(warp=warp, warp_port=warp_port, naive=choices["naive"], mieru=choices["mieru"], router=router,
                        relay_port=relay_port)


def _as_dict(config: ThreeXuiConfig) -> dict[str, Any]:
    return {name: getattr(config, name) for name in ThreeXuiConfig.__dataclass_fields__}


def _warp_domains(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError("three_xui.warp_domains must be an array")
    result = []
    for item in value:
        item = _string(item, "three_xui.warp_domains")
        if item.startswith("geosite:"):
            if re.fullmatch(r"geosite:[a-z0-9_-]+", item) is None:
                raise ConfigError("invalid WARP geosite selector")
        else:
            domain = item.removeprefix("domain:")
            _domain(domain, "three_xui.warp_domains")
        result.append(item)
    return tuple(sorted(set(result)))


def _parse_ingress(value: object) -> IngressConfig | None:
    if value is None:
        return None
    raw = _table(value, "ingress")
    _keys(
        raw,
        path="ingress",
        required={"proxy_protocol_bridge"},
        optional={"panel_tls_port", "skip_renewal_dry_run"},
    )
    bridge = _string(raw["proxy_protocol_bridge"], "ingress.proxy_protocol_bridge")
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", bridge)
    if match is None or not 1024 <= int(match.group(1)) <= 65535:
        raise ConfigError("ingress.proxy_protocol_bridge must be a loopback TCP endpoint")
    bridge_port = int(match.group(1))
    panel_tls_port = _integer(raw.get("panel_tls_port", 8443), "ingress.panel_tls_port")
    if not 1024 <= panel_tls_port <= 65535 or panel_tls_port == bridge_port:
        raise ConfigError("ingress.panel_tls_port must be a distinct unprivileged TCP port")
    return IngressConfig(
        proxy_protocol_bridge=bridge,
        panel_tls_port=panel_tls_port,
        skip_renewal_dry_run=_boolean(
            raw.get("skip_renewal_dry_run", False),
            "ingress.skip_renewal_dry_run",
        ),
    )


def _parse_firewall(value: object) -> FirewallConfig:
    raw = _table(value, "firewall")
    _keys(raw, path="firewall", required={"manage_ufw"})
    return FirewallConfig(manage_ufw=_boolean(raw["manage_ufw"], "firewall.manage_ufw"))


def _reject_duplicate_tcp_sni_domains(config: InstallerConfig) -> None:
    domains = (
        config.domains.panel,
        config.domains.mtproxy,
        config.domains.naive,
        config.domains.subscription,
        config.domains.mcp,
        config.three_xui.panel_domain,
        config.three_xui.vless_tcp_domain,
        config.three_xui.vless_xhttp_domain,
    )
    seen: set[str] = set()
    for domain in (item for item in domains if item is not None):
        if domain in seen:
            raise ConfigError(f"duplicate TCP SNI domain: {domain}")
        seen.add(domain)


def _keys(
    value: Mapping[str, Any],
    *,
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    allowed = required | (optional or set())
    for key in value:
        if key not in allowed:
            raise ConfigError(f"unknown key: {_qualified(path, key)}")
    for key in sorted(required):
        if key not in value:
            raise ConfigError(f"missing key: {_qualified(path, key)}")


def _table(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{path} must be a table")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{path} must be a string")
    return value


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{path} must be an integer")
    return value


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{path} must be a boolean")
    return value


def _enum(value: object, enum_type: type[_ENUM], path: str) -> _ENUM:
    raw = _string(value, path)
    try:
        return enum_type(raw)  # type: ignore[call-arg]
    except ValueError as exc:
        raise ConfigError(f"invalid {path}: {raw}") from exc


def _domain(value: object, path: str) -> str:
    normalized = _string(value, path).strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(normalized):
        raise ConfigError(f"invalid domain: {path}")
    return normalized


def _domains(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{path} must be an array")
    domains = tuple(_domain(item, f"{path}[{index}]") for index, item in enumerate(value))
    if len(domains) != len(set(domains)):
        raise ConfigError(f"{path} must not contain duplicates")
    return domains


def _ports(value: object, path: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{path} must be an array")
    ports: list[int] = []
    for item in value:
        port = _integer(item, path)
        if not 1024 <= port <= 65535:
            raise ConfigError(f"{path} contains invalid port: {port}")
        ports.append(port)
    if len(ports) != len(set(ports)):
        raise ConfigError(f"{path} must not contain duplicates")
    return tuple(ports)


def _qualified(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_boolean(value: bool) -> str:
    return "true" if value else "false"


def _toml_array(values: tuple[object, ...]) -> str:
    rendered = [str(item) if isinstance(item, int) else _toml_string(str(item)) for item in values]
    return f"[{', '.join(rendered)}]"
