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


# --- schema 2 (v0.7): lanes, chains, relay --------------------------------------------------

from xray_router_manager.render import LaneAccount, Relay  # noqa: E402

HOP_B = {"guid": "b" * 32, "address": "panel.node-b.example.org", "port": 45443, "server_name": "panel.node-b.example.org",
         "public_key": "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s", "short_id": "0123abcd",
         "uuid": "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10"}
HOP_C = HOP_B | {"guid": "c" * 32, "address": "203.0.113.7", "server_name": "panel.node-c.example.org",
                 "uuid": "9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e"}
LANES = {"naive": [LaneAccount("grant:7f3a", "grant-7f3a", "x" * 32)]}


def _v2(lanes, chains=None):
    return validate_document({"schema": 2, "lanes": lanes, "chains": chains or {}})


def test_render_lanes_are_accounts_on_the_service_ingress_and_rules_carry_the_user():
    intent = _v2({
        "grant:7f3a": {"default": {"action": "egress", "egress": "warp"},
                       "rules": [{"geosites": ["category-ads-all"], "action": "block"}, {"geoips": ["ru"], "action": "direct"}]},
        "svc:naive": {"default": {"action": "direct", "egress": None}, "rules": [{"domains": ["example.com"], "action": "block"}]},
    })
    config = render_config({"naive": intent}, INGRESSES, warp_url=WARP, lanes=LANES)
    naive = config["inbounds"][0]
    assert naive["settings"]["accounts"] == [{"user": "naive-abc", "pass": "p" * 32}, {"user": "grant-7f3a", "pass": "x" * 32}]
    rules = [rule for rule in config["routing"]["rules"] if rule["inboundTag"] == ["naive"]]
    assert rules[0]["ip"] == ["geoip:private"] and "user" not in rules[0] and "user" not in rules[1]
    # the grant lane's rules and catch-all, then the service lane's — the service lane last
    assert rules[2] == {"inboundTag": ["naive"], "user": ["grant-7f3a"], "domain": ["geosite:category-ads-all"], "outboundTag": "block"}
    assert rules[3] == {"inboundTag": ["naive"], "user": ["grant-7f3a"], "ip": ["geoip:ru"], "outboundTag": "direct"}
    assert rules[4] == {"inboundTag": ["naive"], "user": ["grant-7f3a"], "outboundTag": "warp"}
    assert rules[5] == {"inboundTag": ["naive"], "user": ["naive-abc"], "domain": ["domain:example.com"], "outboundTag": "block"}
    assert rules[6] == {"inboundTag": ["naive"], "user": ["naive-abc"], "outboundTag": "direct"}
    assert len(rules) == 7
    # a lane the intent names but the service has no account for is refused, and the reverse is ignored
    with pytest.raises(EgressInvalid, match="lane"):
        render_config({"naive": intent}, INGRESSES, warp_url=WARP, lanes={})


def test_render_chain_is_a_vless_reality_outbound_per_hop_dialled_through_the_previous():
    intent = _v2({"svc:naive": {"default": {"action": "egress", "egress": "chain:c1"},
                                "rules": [{"domains": ["a.example"], "action": "egress", "egress": "chain:c2"}]}},
                 chains={"c1": {"hops": [HOP_B], "exit": "warp"}, "c2": {"hops": [HOP_B, HOP_C], "exit": "direct"}})
    config = render_config({"naive": intent}, INGRESSES, warp_url=None)
    tags = [item["tag"] for item in config["outbounds"]]
    assert tags == ["block", "direct", "chain:naive:c1:1", "chain:naive:c2:1", "chain:naive:c2:2"]
    first = config["outbounds"][2]
    assert first["protocol"] == "vless" and first["settings"]["vnext"] == [
        {"address": "panel.node-b.example.org", "port": 45443, "users": [{"id": HOP_B["uuid"], "encryption": "none", "flow": ""}]}]
    assert first["streamSettings"] == {"network": "tcp", "security": "reality", "realitySettings": {
        "serverName": "panel.node-b.example.org", "fingerprint": "chrome", "publicKey": HOP_B["public_key"], "shortId": "0123abcd"}}
    assert "proxySettings" not in first
    second_hop = config["outbounds"][4]
    assert second_hop["proxySettings"] == {"tag": "chain:naive:c2:1"} and second_hop["settings"]["vnext"][0]["address"] == "203.0.113.7"
    rules = [rule for rule in config["routing"]["rules"] if rule["inboundTag"] == ["naive"]]
    assert rules[2]["outboundTag"] == "chain:naive:c2:2" and rules[-1]["outboundTag"] == "chain:naive:c1:1"
    # a chain's exit is the hop's business (its relay account decides) — no warp outbound is needed here
    assert "warp" not in tags


def test_render_relay_inbound_and_its_rules():
    relay = Relay(port=45443, server_name="panel.node-a.example.org", private_key="k" * 43, short_ids=["0123abcd"],
                  accounts=[("relay:" + "b" * 32 + ":direct", HOP_B["uuid"]), ("relay:" + "b" * 32 + ":warp", HOP_C["uuid"])])
    config = render_config({}, INGRESSES, warp_url=WARP, relay=relay)
    inbound = config["inbounds"][2]
    assert inbound["tag"] == "relay" and inbound["listen"] == "0.0.0.0" and inbound["port"] == 45443 and inbound["protocol"] == "vless"
    assert inbound["settings"] == {"clients": [{"id": HOP_B["uuid"], "email": "relay:" + "b" * 32 + ":direct", "flow": ""},
                                               {"id": HOP_C["uuid"], "email": "relay:" + "b" * 32 + ":warp", "flow": ""}], "decryption": "none"}
    assert inbound["streamSettings"] == {"network": "tcp", "security": "reality", "realitySettings": {
        "dest": "127.0.0.1:8443", "serverNames": ["panel.node-a.example.org"], "privateKey": "k" * 43, "shortIds": ["0123abcd"]}}
    assert inbound["sniffing"] == {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    rules = [rule for rule in config["routing"]["rules"] if rule["inboundTag"] == ["relay"]]
    assert rules[0] == {"inboundTag": ["relay"], "ip": ["geoip:private"], "outboundTag": "block"}
    assert rules[1]["domain"] == ["domain:localhost", "full:localhost"]
    assert rules[2] == {"inboundTag": ["relay"], "user": ["relay:" + "b" * 32 + ":warp"], "outboundTag": "warp"}
    assert rules[3] == {"inboundTag": ["relay"], "outboundTag": "direct"}
    assert [item["tag"] for item in config["outbounds"]] == ["block", "direct", "warp"]
    # a warp account without a warp endpoint on this node is a contradiction, not a silent direct
    with pytest.raises(EgressInvalid, match="warp"):
        render_config({}, INGRESSES, warp_url=None, relay=relay)
    # an enabled relay with no accounts still listens (accounts arrive with the next generation)
    empty = render_config({}, INGRESSES, warp_url=None, relay=Relay(45443, "panel.node-a.example.org", "k" * 43, ["0123abcd"], []))
    assert empty["inbounds"][2]["settings"]["clients"] == []


def test_render_schema_1_bytes_are_unchanged_by_the_new_parameters():
    intents = {"naive": _intent(default={"action": "egress", "egress": "warp"}), "mieru": direct_document()}
    before = config_bytes(render_config(intents, INGRESSES, warp_url=WARP))
    after = config_bytes(render_config(intents, INGRESSES, warp_url=WARP, lanes={}, relay=None))
    assert before == after


def test_redact_masks_relay_and_chain_secrets_too():
    intent = _v2({"svc:naive": {"default": {"action": "egress", "egress": "chain:c1"}, "rules": []}},
                 chains={"c1": {"hops": [HOP_B], "exit": "direct"}})
    relay = Relay(45443, "panel.node-a.example.org", "k" * 43, ["0123abcd"], [("relay:x:direct", HOP_C["uuid"])])
    config = render_config({"naive": intent}, INGRESSES, warp_url=None, lanes=LANES, relay=relay)
    masked = json.dumps(redact(config))
    for secret in (HOP_B["uuid"], HOP_C["uuid"], "k" * 43, "x" * 32, "grant-7f3a"):
        assert secret not in masked
    assert HOP_B["public_key"] in masked and "panel.node-a.example.org" in masked
