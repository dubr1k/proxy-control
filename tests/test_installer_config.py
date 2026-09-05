from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

from installer.config import ConfigError, load_config, parse_config, render_config
from installer.model import HostMode, InstallerConfig, Profile, ThreeXuiMode


EXAMPLES = Path(__file__).parents[1] / "examples" / "installer"

FULL_MANAGED_TOML = """
schema = 1
host_mode = "fresh"
profile = "full"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"
naive = "edge.example.com"
mieru = "mieru.example.com"

[mieru]
tcp_ports = [46001]
udp_ports = [46001]

[three_xui]
mode = "managed-new"
panel_domain = "xui.example.com"
vless_tcp_domain = "vless.example.com"
vless_xhttp_domain = "xhttp.example.com"
hysteria_domain = "hy2.example.com"
warp = false
warp_domains = []

[firewall]
manage_ufw = true
"""

COEXIST_WITH_UFW_TOML = """
schema = 1
host_mode = "coexist"
profile = "core"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"

[three_xui]
mode = "none"

[firewall]
manage_ufw = true
"""

CONFIG_WITH_SECRET_FIELD = FULL_MANAGED_TOML.replace(
    'mode = "managed-new"',
    'mode = "managed-new"\nprivate_key = "do-not-store-secrets"',
)

CORE_TOML = """
schema = 1
host_mode = "fresh"
profile = "core"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"

[three_xui]
mode = "none"

[firewall]
manage_ufw = false
"""


def test_full_managed_config_collects_every_domain():
    config = parse_config(FULL_MANAGED_TOML)
    assert config.host_mode is HostMode.FRESH
    assert config.profile is Profile.FULL
    assert config.three_xui.mode is ThreeXuiMode.MANAGED_NEW
    assert config.required_domains() == (
        "edge.example.com",
        "hy2.example.com",
        "mieru.example.com",
        "panel.example.com",
        "relay.example.com",
        "vless.example.com",
        "xhttp.example.com",
        "xui.example.com",
    )
    assert parse_config(render_config(config)) == config


def test_coexist_rejects_ufw_mutation():
    with pytest.raises(ConfigError, match="UFW can be managed only in fresh mode"):
        parse_config(COEXIST_WITH_UFW_TOML)


def test_config_rejects_irrelevant_and_unknown_fields():
    with pytest.raises(ConfigError, match=r"unknown key: three_xui\.private_key"):
        parse_config(CONFIG_WITH_SECRET_FIELD)


@pytest.mark.parametrize(
    "name",
    [
        "core.toml",
        "core-naive.toml",
        "core-mieru.toml",
        "full-three-xui.toml",
        "existing-three-xui.toml",
    ],
)
def test_example_configs_load_and_round_trip(name: str):
    config = load_config(EXAMPLES / name)
    assert parse_config(render_config(config)) == config


def test_config_model_is_deeply_immutable():
    config = parse_config(FULL_MANAGED_TOML)
    with pytest.raises(FrozenInstanceError):
        config.initial_user = "other"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        config.domains.panel = "other.example.com"  # type: ignore[misc]
    assert isinstance(config.mieru.tcp_ports, tuple)
    assert isinstance(config.three_xui.warp_domains, tuple)


def test_generated_model_and_canonical_form_have_no_secret_fields():
    config = parse_config(FULL_MANAGED_TOML)
    canonical = config.canonical_dict()
    rendered = render_config(config)
    forbidden = ("password", "secret", "private_key", "token", "credential")
    assert not any(word in repr(canonical).lower() for word in forbidden)
    assert not any(word in rendered.lower() for word in forbidden)
    assert {field.name for field in fields(InstallerConfig)} == {
        "schema",
        "host_mode",
        "profile",
        "acme_email",
        "initial_user",
        "domains",
        "mieru",
        "three_xui",
        "firewall",
    }


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (CORE_TOML.replace("schema = 1", "schema = 2"), "unsupported schema: 2"),
        (CORE_TOML.replace('profile = "core"', 'profile = "unknown"'), "invalid profile"),
        (CORE_TOML.replace('panel = "panel.example.com"', 'panel = "not a domain"'), "invalid domain"),
        (CORE_TOML.replace('initial_user = "owner"', 'initial_user = "bad user"'), "unsafe initial user"),
        (CORE_TOML.replace('manage_ufw = false', 'manage_ufw = "false"'), "firewall.manage_ufw must be a boolean"),
        (CORE_TOML + "\nunexpected = true\n", "unknown key: firewall.unexpected"),
    ],
)
def test_config_rejects_invalid_scalar_values(text: str, message: str):
    with pytest.raises(ConfigError, match=message):
        parse_config(text)


def test_profile_requires_and_rejects_conditional_sections_and_domains():
    with pytest.raises(ConfigError, match="domains.naive is required for profile core-naive"):
        parse_config(CORE_TOML.replace('profile = "core"', 'profile = "core-naive"'))
    with pytest.raises(ConfigError, match="unknown key: domains.naive"):
        parse_config(CORE_TOML.replace('mtproxy = "relay.example.com"', 'mtproxy = "relay.example.com"\nnaive = "edge.example.com"'))
    with pytest.raises(ConfigError, match="mieru section is required for profile core-mieru"):
        parse_config(
            CORE_TOML.replace('profile = "core"', 'profile = "core-mieru"').replace(
                'mtproxy = "relay.example.com"',
                'mtproxy = "relay.example.com"\nmieru = "mieru.example.com"',
            )
        )


def test_mieru_ports_are_validated_and_immutable():
    invalid = FULL_MANAGED_TOML.replace("tcp_ports = [46001]", "tcp_ports = [0, 46001]")
    with pytest.raises(ConfigError, match="mieru.tcp_ports contains invalid port: 0"):
        parse_config(invalid)


def test_managed_three_xui_requires_all_fields():
    missing = FULL_MANAGED_TOML.replace('panel_domain = "xui.example.com"\n', "")
    with pytest.raises(ConfigError, match="missing key: three_xui.panel_domain"):
        parse_config(missing)


def test_none_three_xui_rejects_irrelevant_fields():
    invalid = CORE_TOML.replace('mode = "none"', 'mode = "none"\npanel_domain = "xui.example.com"')
    with pytest.raises(ConfigError, match=r"unknown key: three_xui\.panel_domain"):
        parse_config(invalid)


def test_duplicate_tcp_sni_domains_are_rejected():
    duplicate = FULL_MANAGED_TOML.replace("xui.example.com", "panel.example.com")
    with pytest.raises(ConfigError, match="duplicate TCP SNI domain: panel.example.com"):
        parse_config(duplicate)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("hysteria_domain", "panel.example.com"),
        ("domains.mieru", "panel.example.com"),
    ],
)
def test_udp_or_dedicated_port_domains_may_reuse_tcp_dns(field: str, replacement: str):
    if field == "hysteria_domain":
        text = FULL_MANAGED_TOML.replace("hy2.example.com", replacement)
    else:
        text = FULL_MANAGED_TOML.replace("mieru.example.com", replacement)
    config = parse_config(text)
    assert "panel.example.com" in config.required_domains()


def test_domains_are_normalized_before_duplicate_checks():
    text = FULL_MANAGED_TOML.replace("panel.example.com", "Panel.Example.COM.")
    config = parse_config(text)
    assert config.domains.panel == "panel.example.com"


def test_invalid_toml_is_reported_as_config_error():
    with pytest.raises(ConfigError, match="invalid TOML"):
        parse_config("schema = [")
