from installer.config import parse_config, render_config
from tests.test_installer_config import FULL_MANAGED_TOML


def test_warp_port_and_geosite_selectors_round_trip_to_routing():
    from installer.three_xui_api import warp_routing

    text = FULL_MANAGED_TOML.replace("warp = false", "warp = true\nwarp_port = 41000").replace(
        "warp_domains = []", 'warp_domains = ["geosite:openai", "domain:2ip.ru", "claude.ai"]'
    )
    config = parse_config(text)
    assert parse_config(render_config(config)) == config
    policy = warp_routing(
        config, existing_rules=[{"ip": ["geoip:private"], "outboundTag": "blocked"}]
    )
    assert policy["outbounds"][0]["tag"] == "WARP"
    assert policy["outbounds"][0]["settings"]["servers"][0]["port"] == 41000
    assert policy["rules"][0]["outboundTag"] == "blocked"
    assert policy["rules"][-2]["domain"] == [
        "domain:claude.ai",
        "domain:2ip.ru",
        "geosite:openai",
    ]
    assert policy["rules"][-1]["outboundTag"] == "direct"


def test_three_xui_warp_action_records_the_explicit_egress_port():
    from installer.adapters.three_xui import ThreeXuiAdapter
    from installer.planner import AuditFacts

    config = parse_config(
        FULL_MANAGED_TOML.replace("warp = false", "warp = true\nwarp_port = 41000").replace(
            "warp_domains = []", 'warp_domains = ["example.org"]'
        )
    )
    action = next(
        item for item in ThreeXuiAdapter().plan(config, AuditFacts()) if item.id == "three_xui.warp"
    )
    assert "warp-egress=127.0.0.1:41000" in action.mutations


def test_three_xui_warp_action_accepts_a_valid_geosite_selector():
    from installer.adapters.three_xui import ThreeXuiAdapter
    from installer.planner import AuditFacts

    config = parse_config(
        FULL_MANAGED_TOML.replace("warp = false", "warp = true").replace(
            "warp_domains = []", 'warp_domains = ["geosite:openai"]'
        )
    )
    adapter = ThreeXuiAdapter()
    action = next(item for item in adapter.plan(config, AuditFacts()) if item.id == "three_xui.warp")
    assert "warp-domain=geosite:openai" in action.mutations
    assert adapter._warp_domains(action) == ("geosite:openai",)


def test_three_xui_warp_action_accepts_a_valid_domain_selector():
    from installer.adapters.three_xui import ThreeXuiAdapter
    from installer.planner import AuditFacts

    config = parse_config(
        FULL_MANAGED_TOML.replace("warp = false", "warp = true").replace(
            "warp_domains = []", 'warp_domains = ["domain:example.org"]'
        )
    )
    adapter = ThreeXuiAdapter()
    action = next(item for item in adapter.plan(config, AuditFacts()) if item.id == "three_xui.warp")
    assert "warp-domain=domain:example.org" in action.mutations
    assert adapter._warp_domains(action) == ("domain:example.org",)
