"""The TrustTunnel ingress of the Xray-router (v1.6): a no-auth SOCKS5 inbound on the host
loopback (the endpoint's `[forward_protocol.socks5]` with `extended_auth = false` offers no
credentials), enabled by the router's environment, per service only — no client lanes."""
from __future__ import annotations

import pytest

from tests.test_xray_router_manager import BLOCK_DOC, WARP_DOC, manager as base_manager
from xray_router_manager.intent import PORTS, TRUSTTUNNEL_PORT, EgressInvalid, direct_document, validate_document
from xray_router_manager.render import Ingress, render_config
from xray_router_manager.service import ValidationError, XrayRouterManager


def manager(tmp_path, runner=None, **kwargs):
    instance, runner = base_manager(tmp_path, runner, **kwargs)
    instance.ports["trusttunnel"] = TRUSTTUNNEL_PORT
    instance.services = ("naive", "mieru", "trusttunnel")
    return instance, runner


def _inbound(config: dict, tag: str) -> dict:
    return next(item for item in config["inbounds"] if item["tag"] == tag)


def test_the_port_is_a_frozen_identifier_and_the_authenticated_ports_are_unchanged():
    assert TRUSTTUNNEL_PORT == 45104 and PORTS == {"naive": 45101, "mieru": 45102}


def test_bootstrap_opens_a_noauth_socks_inbound_on_the_loopback(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    inbound = _inbound(runner.running["config"], "trusttunnel")
    assert inbound["listen"] == "127.0.0.1" and inbound["port"] == 45104 and inbound["protocol"] == "socks"
    assert inbound["settings"] == {"auth": "noauth", "udp": False}
    assert inbound["sniffing"]["routeOnly"] is True
    assert ("ready", (45101, 45102, 45104)) in runner.calls
    assert instance.status()["services"]["trusttunnel"]["document"] == direct_document()
    # the other ingresses keep their accounts
    assert _inbound(runner.running["config"], "naive")["settings"]["auth"] == "password"


def test_without_the_port_the_router_serves_what_it_served_before(tmp_path):
    instance, runner = base_manager(tmp_path)
    instance.bootstrap()
    assert [item["tag"] for item in runner.running["config"]["inbounds"]] == ["naive", "mieru"]
    with pytest.raises(ValidationError):
        instance.egress("trusttunnel")


def test_a_policy_for_trusttunnel_routes_only_its_own_inbound(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    revision = instance.egress("trusttunnel")["revision"]
    instance.egress_apply("trusttunnel", revision, BLOCK_DOC, "op-1")
    rules = runner.running["config"]["routing"]["rules"]
    mine = [rule for rule in rules if rule["inboundTag"] == ["trusttunnel"] and rule.get("outboundTag") == "block"]
    assert any(rule.get("domain") == ["domain:example.com"] for rule in mine)
    assert instance.egress("naive")["document"] == direct_document()


def test_warp_for_trusttunnel_needs_the_warp_provider_like_any_service(tmp_path):
    instance, _runner = manager(tmp_path, warp=None)
    instance.bootstrap()
    revision = instance.egress("trusttunnel")["revision"]
    with pytest.raises(EgressInvalid):
        instance.egress_plan("trusttunnel", revision, WARP_DOC)


def test_trusttunnel_has_no_lanes(tmp_path):
    instance, _runner = manager(tmp_path)
    instance.bootstrap()
    with pytest.raises(ValidationError):
        instance.lane_issue("trusttunnel", "grant:abc")


def test_a_schema_two_document_may_name_the_trusttunnel_service_lane():
    document = {"schema": 2, "lanes": {"svc:trusttunnel": {"default": {"action": "direct", "egress": None}, "rules": []}},
                "chains": {}}
    assert validate_document(document)["lanes"].keys() == {"svc:trusttunnel"}


def test_render_config_without_an_account_for_trusttunnel():
    config = render_config({}, [Ingress(tag="trusttunnel", port=45104, user="", password="")], warp_url=None,
                           ports={"trusttunnel": 45104})
    inbound = _inbound(config, "trusttunnel")
    assert inbound["settings"] == {"auth": "noauth", "udp": False}
    assert {"inboundTag": ["trusttunnel"], "outboundTag": "direct"} in config["routing"]["rules"]


def test_the_environment_enables_the_ingress(monkeypatch, tmp_path):
    from xray_router_manager import __main__ as entry

    for name, value in (("XRAY_ROUTER_BIN_DIR", str(tmp_path)), ("XRAY_ROUTER_XRAY_SHA256", "0" * 64),
                        ("XRAY_ROUTER_GEOIP_SHA256", "0" * 64), ("XRAY_ROUTER_GEOSITE_SHA256", "0" * 64),
                        ("XRAY_ROUTER_STATE_DIR", str(tmp_path / "state"))):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("XRAY_ROUTER_PORT_TRUSTTUNNEL", raising=False)
    off: XrayRouterManager = entry.build_manager()
    assert "trusttunnel" not in off.services
    monkeypatch.setenv("XRAY_ROUTER_PORT_TRUSTTUNNEL", "45104")
    on: XrayRouterManager = entry.build_manager()
    assert "trusttunnel" in on.services and on.ports["trusttunnel"] == 45104
