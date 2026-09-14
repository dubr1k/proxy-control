from dataclasses import replace
from pathlib import Path

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


def test_the_provider_endpoint_reaches_the_managers_env_only_when_the_host_has_warp():
    """[v0.4] the managers learn the WARP endpoint through their env overlays — the
    routing policy may route through it later, whatever the seed says — and nothing
    when the host has no WARP; an old action without the parameter still selects."""
    with_warp = parse_config(FULL_MANAGED_TOML.replace('warp = false', 'warp = true\nwarp_port = 41000').replace(
        'warp_domains = []', 'warp_domains = ["example.org"]'))
    without = parse_config(FULL_MANAGED_TOML)
    for adapter, key in ((NaiveAdapter(), "NAIVE_EGRESS_WARP"), (MieruAdapter(), "MIERU_EGRESS_WARP")):
        action = adapter.plan(with_warp, AuditFacts())[0]
        assert "egress=direct" in action.mutations and "warp-provider=socks5://127.0.0.1:41000" in action.mutations
        selected = adapter._selection(action)
        assert selected["warp_provider"] == "socks5://127.0.0.1:41000"
        action = adapter.plan(without, AuditFacts())[0]
        assert "warp-provider=" in action.mutations and adapter._selection(action)["warp_provider"] == ""
        legacy = replace(action, mutations=tuple(m for m in action.mutations if not m.startswith("warp-provider=")))
        assert adapter._selection(legacy)["warp_provider"] == ""
    naive = NaiveAdapter(source_dir=Path(__file__).resolve().parents[1])
    selected = naive._selection(naive.plan(with_warp, AuditFacts())[0])
    rendered = naive.render(naive.plan(with_warp, AuditFacts())[0])
    assert "NAIVE_EGRESS_WARP=socks5://127.0.0.1:41000\n" in rendered.env_text and selected["egress"] == "direct"
    assert "NAIVE_EGRESS_WARP=\n" in naive.render(naive.plan(without, AuditFacts())[0]).env_text
    mieru = MieruAdapter()
    assert "MIERU_EGRESS_WARP=socks5://127.0.0.1:41000\n" in mieru.env_text(
        mieru._selection(mieru.plan(with_warp, AuditFacts())[0]), mita_gid=321)


def test_an_explicit_egress_section_selects_per_service():
    """[egress] (v0.4): the same 3x-ui with a domain list, but NaiveProxy through WARP and
    Mieru direct — the v0.1 coupling no longer decides for the other data planes."""
    text = FULL_MANAGED_TOML.replace('warp = false', 'warp = true\nwarp_port = 41000').replace(
        'warp_domains = []', 'warp_domains = ["example.org"]').replace(
        "[three_xui]", '[egress]\nwarp = true\nwarp_port = 41000\nnaive = "warp"\nmieru = "direct"\n\n[three_xui]')
    cfg = parse_config(text)
    naive = NaiveAdapter().plan(cfg, AuditFacts())[0]
    mieru = MieruAdapter().plan(cfg, AuditFacts())[0]
    assert "egress=proxy" in naive.mutations and "warp-port=41000" in naive.mutations
    assert "egress=direct" in mieru.mutations


def test_legacy_mutations_are_byte_identical_with_and_without_the_derived_section():
    """A configuration written before [egress] existed plans exactly as it did: the
    derived section reproduces the old keys, so nothing in the plan digest moves."""
    legacy = parse_config(FULL_MANAGED_TOML.replace('warp = false', 'warp = true\nwarp_port = 41000'))
    for adapter in (NaiveAdapter(), MieruAdapter()):
        action = adapter.plan(legacy, AuditFacts())[0]
        assert "egress=proxy" in action.mutations and "warp-port=41000" in action.mutations
    assert legacy.egress is None and legacy.canonical_dict()["egress"] is None
    assert legacy.effective_egress.naive.value == "warp" and legacy.effective_egress.warp_port == 41000
