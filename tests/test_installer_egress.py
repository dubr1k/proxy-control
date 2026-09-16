"""`[egress]` (v0.4, Task 28): WARP as its own provider, with the old `[three_xui].warp*`
keys still read exactly as before so an existing configuration renders and plans unchanged."""
from __future__ import annotations

import pytest

from installer.config import ConfigError, parse_config, render_config
from installer.model import EgressChoice

HEAD = (
    "schema = 1\n"
    'host_mode = "fresh"\n'
    'profile = "full"\n'
    'acme_email = "ops@example.com"\n'
    'initial_user = "owner"\n'
    "\n[domains]\n"
    'panel = "panel.example.com"\n'
    'mtproxy = "proxy.example.com"\n'
    'naive = "edge.example.com"\n'
    'mieru = "mieru.example.com"\n'
    "\n[mieru]\n"
    "tcp_ports = [46001]\n"
    "udp_ports = [46002]\n"
)
TAIL = "\n[firewall]\nmanage_ufw = false\n"


def _document(three_xui: str, egress: str = "") -> str:
    return HEAD + egress + "\n[three_xui]\n" + three_xui + TAIL


@pytest.mark.parametrize("three_xui, naive, mieru", [
    ('mode = "none"\n', EgressChoice.DIRECT, EgressChoice.DIRECT),
    ('mode = "none"\nwarp = true\n', EgressChoice.WARP, EgressChoice.WARP),
    ('mode = "none"\nwarp = true\nwarp_port = 45000\n', EgressChoice.WARP, EgressChoice.WARP),
    # The v0.1 coupling, kept for configurations written before [egress] existed: a
    # domain-scoped WARP for managed 3x-ui left NaiveProxy and Mieru direct.
    ('mode = "managed-new"\npanel_domain = "xui.example.com"\nvless_tcp_domain = "vless.example.com"\n'
     'vless_xhttp_domain = "xhttp.example.com"\nhysteria_domain = "hy2.example.com"\nwarp = true\n'
     'warp_domains = ["example.org"]\n', EgressChoice.DIRECT, EgressChoice.DIRECT),
])
def test_egress_is_derived_from_three_xui_when_the_section_is_absent(three_xui, naive, mieru):
    config = parse_config(_document(three_xui))
    assert config.egress is None
    egress = config.effective_egress
    assert (egress.warp, egress.naive, egress.mieru) == ("warp = true" in three_xui, naive, mieru)
    assert egress.warp_port == (45000 if "45000" in three_xui else 40000)
    assert egress.provider_url() == (f"socks5://127.0.0.1:{egress.warp_port}" if egress.warp else None)


def test_an_old_configuration_round_trips_without_an_egress_section():
    text = _document('mode = "none"\nwarp = true\n')
    config = parse_config(text)
    rendered = render_config(config)
    assert "[egress]" not in rendered
    assert parse_config(rendered) == config


def test_the_egress_section_is_canonical_and_round_trips():
    egress = "\n[egress]\nwarp = true\nwarp_port = 45000\nnaive = \"direct\"\nmieru = \"warp\"\n"
    config = parse_config(_document('mode = "none"\n', egress))
    assert config.egress is not None and config.effective_egress == config.egress
    assert (config.egress.warp, config.egress.warp_port) == (True, 45000)
    assert (config.egress.naive, config.egress.mieru) == (EgressChoice.DIRECT, EgressChoice.WARP)
    # The old keys mirror the section so that everything reading them keeps working.
    assert (config.three_xui.warp, config.three_xui.warp_port) == (True, 45000)
    rendered = render_config(config)
    assert "[egress]" in rendered and 'naive = "direct"' in rendered and "warp_port = 45000" in rendered
    assert parse_config(rendered) == config


def test_egress_defaults_follow_warp_when_services_are_not_named():
    config = parse_config(_document('mode = "none"\n', "\n[egress]\nwarp = true\n"))
    assert (config.egress.naive, config.egress.mieru) == (EgressChoice.WARP, EgressChoice.WARP)
    config = parse_config(_document('mode = "none"\n', "\n[egress]\nwarp = false\n"))
    assert (config.egress.naive, config.egress.mieru) == (EgressChoice.DIRECT, EgressChoice.DIRECT)


@pytest.mark.parametrize("three_xui, egress, message", [
    ('mode = "none"\nwarp = false\n', "\n[egress]\nwarp = true\n", "three_xui.warp disagrees with egress.warp"),
    ('mode = "none"\nwarp = true\nwarp_port = 40001\n', "\n[egress]\nwarp = true\nwarp_port = 40002\n",
     "three_xui.warp_port disagrees with egress.warp_port"),
    ('mode = "none"\n', "\n[egress]\nwarp = false\nnaive = \"warp\"\n", "egress.naive requires warp = true"),
    ('mode = "none"\n', "\n[egress]\nwarp = true\nnaive = \"socks\"\n", "invalid egress.naive"),
    ('mode = "none"\n', "\n[egress]\nwarp = true\nwarp_port = 80\n", "egress.warp_port must be between 1024 and 65535"),
    ('mode = "none"\n', "\n[egress]\nwarp = true\nxray = \"warp\"\n", "unknown key: egress.xray"),
])
def test_egress_values_are_validated(three_xui, egress, message):
    with pytest.raises(ConfigError, match=message):
        parse_config(_document(three_xui, egress))


def test_naming_a_service_the_profile_lacks_is_an_error():
    document = (HEAD.replace('profile = "full"', 'profile = "core-naive"').replace('mieru = "mieru.example.com"\n', "")
                .replace("\n[mieru]\ntcp_ports = [46001]\nudp_ports = [46002]\n", "")
                + "\n[egress]\nwarp = true\nmieru = \"warp\"\n" + '\n[three_xui]\nmode = "none"\n' + TAIL)
    with pytest.raises(ConfigError, match="egress.mieru is not part of profile core-naive"):
        parse_config(document)


