from installer.config import parse_config, render_config
from tests.test_installer_config import FULL_MANAGED_TOML


def test_warp_port_and_geosite_selectors_round_trip_to_routing():
    from installer.three_xui_api import warp_routing
    text = FULL_MANAGED_TOML.replace('warp = false', 'warp = true\nwarp_port = 41000').replace(
        'warp_domains = []', 'warp_domains = ["geosite:openai", "domain:2ip.ru", "claude.ai"]'
    )
    config = parse_config(text)
    assert parse_config(render_config(config)) == config
    policy = warp_routing(config, existing_rules=[{'ip': ['geoip:private'], 'outboundTag': 'blocked'}])
    assert policy['outbounds'][0]['tag'] == 'WARP'
    assert policy['outbounds'][0]['settings']['servers'][0]['port'] == 41000
    assert policy['rules'][0]['outboundTag'] == 'blocked'
    assert policy['rules'][-2]['domain'] == ['domain:claude.ai', 'domain:2ip.ru', 'geosite:openai']
    assert policy['rules'][-1]['outboundTag'] == 'direct'
