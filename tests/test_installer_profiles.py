from __future__ import annotations

import pytest

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
from installer.planner import PlanError, adapters_for


BASE = ("packages", "nginx", "certificates")


def config_for(
    *,
    profile: Profile = Profile.CORE,
    three_xui: ThreeXuiMode = ThreeXuiMode.NONE,
    host_mode: HostMode = HostMode.FRESH,
    manage_ufw: bool = True,
    naive_domain: str | None = None,
    mieru_domain: str | None = None,
    mieru: MieruConfig | None = None,
) -> InstallerConfig:
    if profile.includes_naive and naive_domain is None:
        naive_domain = "naive.example.com"
    if profile.includes_mieru:
        mieru_domain = mieru_domain or "mieru.example.com"
        mieru = mieru or MieruConfig(tcp_ports=(46001,), udp_ports=(46002,))
    three_xui_config = ThreeXuiConfig(mode=three_xui)
    if three_xui is ThreeXuiMode.MANAGED_NEW:
        three_xui_config = ThreeXuiConfig(
            mode=three_xui,
            panel_domain="xui.example.com",
            vless_tcp_domain="vless.example.com",
            vless_xhttp_domain="xhttp.example.com",
            hysteria_domain="hysteria.example.com",
        )
    elif three_xui is ThreeXuiMode.EXISTING:
        three_xui_config = ThreeXuiConfig(
            mode=three_xui,
            vless_tcp_domain="vless.example.com",
        )
    return InstallerConfig(
        schema=1,
        host_mode=host_mode,
        profile=profile,
        acme_email="ops@example.com",
        initial_user="owner",
        domains=DomainConfig(
            panel="panel.example.com",
            mtproxy="proxy.example.com",
            naive=naive_domain,
            mieru=mieru_domain,
        ),
        mieru=mieru,
        three_xui=three_xui_config,
        firewall=FirewallConfig(manage_ufw=manage_ufw),
    )


PROFILE_MATRIX = (
    (Profile.CORE, ThreeXuiMode.NONE, BASE + ("firewall", "core")),
    (
        Profile.CORE_NAIVE,
        ThreeXuiMode.NONE,
        BASE + ("firewall", "core", "naive"),
    ),
    (
        Profile.CORE_MIERU,
        ThreeXuiMode.NONE,
        BASE + ("firewall", "core", "mieru"),
    ),
    (
        Profile.FULL,
        ThreeXuiMode.NONE,
        BASE + ("firewall", "core", "naive", "mieru"),
    ),
    (
        Profile.CORE,
        ThreeXuiMode.EXISTING,
        BASE + ("firewall", "core", "three_xui"),
    ),
    (
        Profile.FULL,
        ThreeXuiMode.MANAGED_NEW,
        BASE + ("firewall", "core", "naive", "mieru", "three_xui"),
    ),
)


@pytest.mark.parametrize("profile,xui,expected", PROFILE_MATRIX)
def test_profile_selects_exact_adapters(profile, xui, expected):
    config = config_for(profile=profile, three_xui=xui)
    assert tuple(adapter.name for adapter in adapters_for(config)) == expected


def test_firewall_is_selected_only_for_a_managed_fresh_host():
    fresh = adapters_for(config_for())
    assert "firewall" in {adapter.name for adapter in fresh}

    coexist = adapters_for(config_for(host_mode=HostMode.COEXIST))
    assert "firewall" not in {adapter.name for adapter in coexist}

    unmanaged = adapters_for(config_for(manage_ufw=False))
    assert "firewall" not in {adapter.name for adapter in unmanaged}


def test_profile_order_is_the_documented_installation_order():
    names = tuple(
        adapter.name
        for adapter in adapters_for(
            config_for(profile=Profile.FULL, three_xui=ThreeXuiMode.MANAGED_NEW)
        )
    )
    assert names == (
        "packages",
        "nginx",
        "certificates",
        "firewall",
        "core",
        "naive",
        "mieru",
        "three_xui",
    )


def test_selection_rejects_a_naive_profile_without_a_domain():
    config = config_for(profile=Profile.CORE_NAIVE, naive_domain=None)
    broken = InstallerConfig(
        **{
            **{name: getattr(config, name) for name in config.__dataclass_fields__},
            "domains": DomainConfig(
                panel="panel.example.com",
                mtproxy="proxy.example.com",
            ),
        }
    )
    with pytest.raises(PlanError, match="NaiveProxy domain"):
        adapters_for(broken)


def test_selection_rejects_a_mieru_profile_without_listeners():
    config = config_for(profile=Profile.CORE_MIERU)
    broken = InstallerConfig(
        **{
            **{name: getattr(config, name) for name in config.__dataclass_fields__},
            "mieru": None,
        }
    )
    with pytest.raises(PlanError, match="Mieru listeners"):
        adapters_for(broken)


def test_selection_rejects_mieru_listeners_outside_a_mieru_profile():
    broken = config_for(
        profile=Profile.CORE,
        mieru=MieruConfig(tcp_ports=(46001,), udp_ports=()),
    )
    with pytest.raises(PlanError, match="outside a Mieru profile"):
        adapters_for(broken)


def test_selection_rejects_managed_three_xui_on_a_coexisting_host():
    broken = config_for(
        three_xui=ThreeXuiMode.MANAGED_NEW,
        host_mode=HostMode.COEXIST,
    )
    with pytest.raises(PlanError, match="fresh host"):
        adapters_for(broken)


def test_every_selected_adapter_declares_satisfiable_dependencies():
    adapters = adapters_for(
        config_for(profile=Profile.FULL, three_xui=ThreeXuiMode.MANAGED_NEW)
    )
    available: set[str] = set()
    for adapter in adapters:
        assert adapter.requires <= available, adapter.name
        available.add(adapter.name)


def test_compose_file_list_is_canonical_per_profile():
    from installer.planner import compose_file_list

    assert compose_file_list(config_for()) == ("compose.yaml",)
    assert compose_file_list(config_for(profile=Profile.CORE_NAIVE)) == (
        "compose.yaml",
        "compose.naive.yaml",
    )
    assert compose_file_list(config_for(profile=Profile.FULL)) == (
        "compose.yaml",
        "compose.naive.yaml",
        "compose.mieru.yaml",
    )


def test_profile_environment_is_non_secret_and_self_contained():
    from installer.planner import profile_environment

    rendered = profile_environment(config_for(profile=Profile.FULL))
    keys = {line.split("=", 1)[0] for line in rendered.strip().splitlines()}
    assert keys == {
        "COMPOSE_FILE",
        "PROXY_CONTROL_PROFILE",
        "PANEL_ALLOWED_HOSTS",
        "MTPROXY_DOMAIN",
        "NAIVE_PUBLIC_HOST",
        "MIERU_PUBLIC_HOST",
    }
    assert "compose.yaml:compose.naive.yaml:compose.mieru.yaml" in rendered
    assert "password" not in rendered.lower()
    assert "token" not in rendered.lower()
