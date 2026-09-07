from installer.config import parse_config
from installer.planner import AuditFacts
from installer.adapters.naive import NaiveAdapter
from installer.adapters.mieru import MieruAdapter
from tests.test_installer_config import FULL_MANAGED_TOML


def test_domain_selective_warp_keeps_non_xray_protocols_direct():
    cfg=parse_config(FULL_MANAGED_TOML.replace('warp = false','warp = true\nwarp_port = 41000').replace('warp_domains = []','warp_domains = ["example.org"]'))
    for adapter in (NaiveAdapter(), MieruAdapter()):
        action=adapter.plan(cfg, AuditFacts())[0]
        assert 'egress=direct' in action.mutations


def test_whole_protocol_warp_port_reaches_rendered_config():
    cfg=parse_config(FULL_MANAGED_TOML.replace('warp = false','warp = true\nwarp_port = 41000'))
    for adapter in (NaiveAdapter(), MieruAdapter()):
        action=adapter.plan(cfg, AuditFacts())[0]
        selected=adapter._selection(action)
        assert selected['warp_port']==41000
