from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar

from installer.model import (
    DomainConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    MieruConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
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
        optional={"mieru"},
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
    three_xui = _parse_three_xui(root["three_xui"])
    firewall = _parse_firewall(root["firewall"])

    if host_mode is HostMode.COEXIST and firewall.manage_ufw:
        raise ConfigError("UFW can be managed only in fresh mode")

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

    if config.mieru is not None:
        lines.extend(
            [
                "",
                "[mieru]",
                f"tcp_ports = {_toml_array(config.mieru.tcp_ports)}",
                f"udp_ports = {_toml_array(config.mieru.udp_ports)}",
            ]
        )

    lines.extend(["", "[three_xui]", f"mode = {_toml_string(config.three_xui.mode.value)}"])
    for name in (
        "panel_domain",
        "vless_tcp_domain",
        "vless_xhttp_domain",
        "hysteria_domain",
    ):
        value = getattr(config.three_xui, name)
        if value is not None:
            lines.append(f"{name} = {_toml_string(value)}")
    if config.three_xui.mode is ThreeXuiMode.MANAGED_NEW:
        lines.extend(
            [
                f"warp = {_toml_boolean(config.three_xui.warp)}",
                f"warp_domains = {_toml_array(config.three_xui.warp_domains)}",
            ]
        )

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
    optional: set[str] = set()
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
    )


def _parse_mieru(value: object, profile: Profile) -> MieruConfig | None:
    if not profile.includes_mieru:
        if value is not None:
            raise ConfigError("unknown key: mieru")
        return None
    if value is None:
        raise ConfigError(f"mieru section is required for profile {profile.value}")
    raw = _table(value, "mieru")
    _keys(raw, path="mieru", required={"tcp_ports", "udp_ports"})
    tcp_ports = _ports(raw["tcp_ports"], "mieru.tcp_ports")
    udp_ports = _ports(raw["udp_ports"], "mieru.udp_ports")
    if not tcp_ports and not udp_ports:
        raise ConfigError("mieru requires at least one TCP or UDP port")
    return MieruConfig(tcp_ports=tcp_ports, udp_ports=udp_ports)


def _parse_three_xui(value: object) -> ThreeXuiConfig:
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
    if mode is ThreeXuiMode.NONE:
        _keys(raw, path="three_xui", required={"mode"})
    elif mode is ThreeXuiMode.EXISTING:
        _keys(raw, path="three_xui", required={"mode"}, optional=domain_names)
    else:
        _keys(
            raw,
            path="three_xui",
            required={"mode", "warp", "warp_domains", *domain_names},
        )

    parsed_domains = {
        name: _domain(raw[name], f"three_xui.{name}") if name in raw else None
        for name in domain_names
    }
    warp = _boolean(raw["warp"], "three_xui.warp") if "warp" in raw else False
    warp_domains = (
        _domains(raw["warp_domains"], "three_xui.warp_domains")
        if "warp_domains" in raw
        else ()
    )
    if not warp and warp_domains:
        raise ConfigError("three_xui.warp_domains requires warp = true")
    return ThreeXuiConfig(
        mode=mode,
        panel_domain=parsed_domains["panel_domain"],
        vless_tcp_domain=parsed_domains["vless_tcp_domain"],
        vless_xhttp_domain=parsed_domains["vless_xhttp_domain"],
        hysteria_domain=parsed_domains["hysteria_domain"],
        warp=warp,
        warp_domains=warp_domains,
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
