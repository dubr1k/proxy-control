"""The Xray config a generation runs: a pure function of intents, ingresses and provider."""
from __future__ import annotations

import json

import pytest

from xray_router_manager.intent import EgressInvalid, direct_document, validate_document
from xray_router_manager.render import Ingress, config_bytes, generation_digest, redact, render_config

INGRESSES = [Ingress("naive", 45101, "naive-abc", "p" * 32), Ingress("mieru", 45102, "mieru-def", "q" * 32)]
WARP = "socks5://127.0.0.1:45000"


def _intent(rules=(), default=None):
    return validate_document({"schema": 1, "default": default or {"action": "direct", "egress": None}, "rules": list(rules)})


def test_render_is_deterministic_and_block_is_first_outbound():
    intents = {"naive": _intent(default={"action": "egress", "egress": "warp"}), "mieru": direct_document()}
    first = render_config(intents, INGRESSES, warp_url=WARP)
    second = render_config(json.loads(json.dumps(intents)), list(reversed(INGRESSES)), warp_url=WARP)
    assert config_bytes(first) == config_bytes(second)
    assert generation_digest(first) == generation_digest(second)
    assert [item["tag"] for item in first["outbounds"]] == ["block", "direct", "warp"]
    assert first["outbounds"][1]["settings"] == {"domainStrategy": "UseIP"}
    assert first["outbounds"][2] == {"tag": "warp", "protocol": "socks",
                                     "settings": {"servers": [{"address": "127.0.0.1", "port": 45000}]}}
    assert first["routing"]["domainStrategy"] == "IPOnDemand"
    assert first["dns"] == {"servers": ["localhost"]}
    assert first["log"] == {"access": "none", "loglevel": "warning"}
    assert "api" not in first and "stats" not in first


def test_render_bypass_private_precedes_every_rule_per_tag():
    intents = {"naive": _intent([{"domains": ["example.com"], "action": "block"}], default={"action": "egress", "egress": "warp"}),
               "mieru": _intent([{"geoips": ["cn"], "action": "direct"}])}
    rules = render_config(intents, INGRESSES, warp_url=WARP)["routing"]["rules"]
    naive = [rule for rule in rules if rule["inboundTag"] == ["naive"]]
    mieru = [rule for rule in rules if rule["inboundTag"] == ["mieru"]]
    assert naive[0] == {"inboundTag": ["naive"], "ip": ["geoip:private"], "outboundTag": "block"}
    assert naive[1] == {"inboundTag": ["naive"], "domain": ["domain:localhost", "full:localhost"], "outboundTag": "block"}
    assert naive[2] == {"inboundTag": ["naive"], "domain": ["domain:example.com"], "outboundTag": "block"}
    assert naive[-1] == {"inboundTag": ["naive"], "outboundTag": "warp"}
    assert mieru[0]["ip"] == ["geoip:private"] and mieru[2]["ip"] == ["geoip:cn"] and mieru[-1]["outboundTag"] == "direct"
    assert all("inboundTag" in rule for rule in rules)


def test_render_rule_matchers_domain_geosite_cidr_geoip_port():
    rule = {"domains": ["*.example.com", "exact.example"], "geosites": ["category-ads-all"], "cidrs": ["10.0.0.0/8"],
            "geoips": ["cloudflare"], "ports": [80, "1000-2000"], "action": "egress", "egress": "warp"}
    rendered = render_config({"naive": _intent([rule])}, INGRESSES, warp_url=WARP)["routing"]["rules"][2]
    assert rendered == {"inboundTag": ["naive"], "domain": ["domain:example.com", "domain:exact.example", "geosite:category-ads-all"],
                        "ip": ["10.0.0.0/8", "geoip:cloudflare"], "port": "80,1000-2000", "outboundTag": "warp"}


def test_render_default_egress_warp_needs_warp_url():
    intents = {"naive": _intent(default={"action": "egress", "egress": "warp"})}
    with pytest.raises(EgressInvalid, match="warp"):
        render_config(intents, INGRESSES, warp_url=None)
    with pytest.raises(EgressInvalid):
        render_config(intents, INGRESSES, warp_url="http://127.0.0.1:8118")


def test_render_omits_warp_outbound_when_unused():
    config = render_config({"naive": direct_document(), "mieru": direct_document()}, INGRESSES, warp_url=WARP)
    assert [item["tag"] for item in config["outbounds"]] == ["block", "direct"]
    config = render_config({}, INGRESSES, warp_url=None)
    assert [rule["outboundTag"] for rule in config["routing"]["rules"] if "ip" not in rule and "domain" not in rule] == ["direct", "direct"]


def test_render_inbounds_have_password_auth_no_udp_and_sniffing_route_only():
    config = render_config({}, INGRESSES, warp_url=None, ports={"naive": 1, "mieru": 2})
    naive, mieru = config["inbounds"]
    assert (naive["tag"], naive["listen"], naive["port"], naive["protocol"]) == ("naive", "127.0.0.1", 1, "socks")
    assert naive["settings"] == {"auth": "password", "accounts": [{"user": "naive-abc", "pass": "p" * 32}], "udp": False}
    assert naive["sniffing"] == {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    assert mieru["port"] == 2 and mieru["settings"]["accounts"] == [{"user": "mieru-def", "pass": "q" * 32}]


def test_generation_digest_changes_with_credentials_and_redact_hides_accounts():
    plain = render_config({}, INGRESSES, warp_url=None)
    rotated = render_config({}, [Ingress("naive", 45101, "naive-abc", "r" * 32), INGRESSES[1]], warp_url=None)
    assert generation_digest(plain) != generation_digest(rotated)
    masked = json.dumps(redact(plain))
    assert "p" * 32 not in masked and "naive-abc" not in masked and '"user": "***"' in masked
    assert "p" * 32 in json.dumps(plain)  # redact returns a copy
