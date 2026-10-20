"""The AmneziaWG ingress of the Xray-router (v2.3.0, variant 2): a `tun` inbound on the device the AWG
manager makes (the router passes Xray its descriptor), rendered only while the device exists, a WARP
WireGuard outbound for the service's `warp` (TCP and UDP) registered on first use, no client lanes."""
from __future__ import annotations

import json

import pytest

from tests.test_xray_router_manager import BLOCK_DOC, WARP_DOC, FakeRunner
from tests.test_xray_router_manager import manager as base_manager
from xray_router_manager import warp as warp_module
from xray_router_manager.intent import (
    NO_LANE_SERVICES,
    TUN_SERVICES,
    WARP_WG_TAG,
    EgressInvalid,
    direct_document,
    validate_document,
)
from xray_router_manager.render import Ingress, redact, render_config, warp_wg_outbound
from xray_router_manager.service import EgressUnreachable

PEER = "A" * 43 + "="
ACCOUNT = {"id": "d1", "token": "t1", "private_key": "B" * 43 + "=", "address": "172.16.0.2",
           "peer_public_key": PEER, "endpoint": "162.159.192.5:2408"}
MIXED_DOC = {"schema": 1, "default": {"action": "egress", "egress": "warp"},
             "rules": [{"domains": ["cloudflare.com"], "action": "direct"}]}


class TunRunner(FakeRunner):
    def start(self, config_path, tun=None):
        handle = super().start(config_path)
        handle["tun"] = tun
        return handle


def registrar(calls):
    def opener(method, url, headers, body):
        calls.append(method)
        return 200, {"id": "d1", "token": "t1", "account": {"account_type": "free"}, "config": {
            "interface": {"addresses": {"v4": "172.16.0.2"}},
            "peers": [{"public_key": PEER, "endpoint": {"v4": "162.159.192.5:0"}}]}}
    return opener


def manager(tmp_path, *, device=True, calls=None):
    instance, runner = base_manager(tmp_path, TunRunner())
    net = tmp_path / "net"
    net.mkdir(exist_ok=True)
    if device:
        (net / "awgxr").mkdir(exist_ok=True)
        (net / "awgxr" / "ifindex").write_text("41\n")
    instance.amneziawg_tun, instance.net_root = "awgxr", net
    instance.services = ("naive", "mieru", "amneziawg")
    instance.warp_opener = registrar(calls if calls is not None else [])
    return instance, runner


def _inbound(config, tag):
    return next((item for item in config["inbounds"] if item["tag"] == tag), None)


def test_amneziawg_is_a_tun_service_without_lanes():
    assert "amneziawg" in TUN_SERVICES and "amneziawg" in NO_LANE_SERVICES


def test_the_tun_inbound_and_the_warp_wireguard_outbound_render_and_redact():
    intents = {"amneziawg": validate_document(MIXED_DOC)}
    config = render_config(intents, [Ingress(tag="amneziawg", port=0, user="", password="", tun="awgxr")],
                           warp_url=None, warp_wg=ACCOUNT)
    inbound = _inbound(config, "amneziawg")
    assert inbound == {"tag": "amneziawg", "port": 0, "protocol": "tun", "settings": {"name": "awgxr", "mtu": 1280},
                       "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}}
    outbound = next(item for item in config["outbounds"] if item["tag"] == WARP_WG_TAG)
    assert outbound == warp_wg_outbound(ACCOUNT) and outbound["settings"]["noKernelTun"] is True
    assert not any(item["tag"] == "warp" for item in config["outbounds"])  # no SOCKS warp needed here
    rules = [rule for rule in config["routing"]["rules"] if rule["inboundTag"] == ["amneziawg"]]
    assert rules[-1] == {"inboundTag": ["amneziawg"], "outboundTag": WARP_WG_TAG}
    assert any(rule.get("domain") == ["domain:cloudflare.com"] and rule["outboundTag"] == "direct" for rule in rules)
    assert redact(config)["outbounds"][-1]["settings"]["secretKey"] == "***"
    with pytest.raises(EgressInvalid) as exc:
        render_config(intents, [Ingress(tag="amneziawg", port=0, user="", password="", tun="awgxr")], warp_url=None)
    assert exc.value.code == "egress_unreachable"


def test_bootstrap_passes_the_device_and_registers_warp_only_when_used(tmp_path):
    calls = []
    instance, runner = manager(tmp_path, calls=calls)
    instance.bootstrap()
    assert runner.running["tun"] == "awgxr" and _inbound(runner.running["config"], "amneziawg")["protocol"] == "tun"
    view = instance.egress("amneziawg")
    assert view["document"] == direct_document() and view["tun"] == {
        "device": "awgxr", "present": True, "attached": True, "warp_registered": False}
    instance.egress_apply("amneziawg", view["revision"], BLOCK_DOC, "op-1")
    assert calls == []  # no warp in the document: nothing registered
    instance.egress_apply("amneziawg", instance.egress("amneziawg")["revision"], WARP_DOC, "op-2")
    assert calls == ["POST"] and instance.egress("amneziawg")["tun"]["warp_registered"] is True
    config = runner.running["config"]
    assert any(item["tag"] == WARP_WG_TAG for item in config["outbounds"])
    stored = json.loads((instance.state_dir / "warp-wg.json").read_text())
    assert warp_module.valid_account(stored) and stored["private_key"] != runner.private_key  # standard base64
    # another service's apply re-renders AmneziaWG with the same account, no second registration
    instance.egress_apply("naive", instance.egress("naive")["revision"], BLOCK_DOC, "op-3")
    assert calls == ["POST"] and any(item["tag"] == WARP_WG_TAG for item in runner.running["config"]["outbounds"])


def test_a_failed_registration_refuses_the_apply_and_changes_nothing(tmp_path):
    instance, runner = manager(tmp_path)
    instance.warp_opener = lambda *args: (403, None)
    instance.bootstrap()
    revision = instance.egress("amneziawg")["revision"]
    with pytest.raises(EgressUnreachable):
        instance.egress_apply("amneziawg", revision, WARP_DOC, "op-1")
    assert instance.egress("amneziawg")["revision"] == revision


def test_the_plan_works_before_any_registration(tmp_path):
    calls = []
    instance, _ = manager(tmp_path, calls=calls)
    instance.bootstrap()
    plan = instance.egress_plan("amneziawg", instance.egress("amneziawg")["revision"], WARP_DOC)
    assert plan["reachability"] == {"warp": None} and calls == []


def test_without_the_device_nothing_of_it_renders_and_its_arrival_re_renders(tmp_path):
    instance, runner = manager(tmp_path, device=False)
    instance.bootstrap()
    assert _inbound(runner.running["config"], "amneziawg") is None and runner.running["tun"] is None
    (instance.net_root / "awgxr").mkdir()
    (instance.net_root / "awgxr" / "ifindex").write_text("7\n")
    instance.watchdog_tick()
    assert runner.running["tun"] == "awgxr" and _inbound(runner.running["config"], "amneziawg") is not None
    # a device made anew (another ifindex) restarts Xray on it
    (instance.net_root / "awgxr" / "ifindex").write_text("8\n")
    starts = len(runner.handles)
    instance.watchdog_tick()
    assert len(runner.handles) == starts + 1 and runner.running["tun"] == "awgxr"
    instance.watchdog_tick()
    assert len(runner.handles) == starts + 1  # settled


def test_the_router_without_the_device_name_serves_what_it_served_before(tmp_path):
    instance, runner = base_manager(tmp_path)
    instance.bootstrap()
    assert "amneziawg" not in instance.status()["services"]


def test_registration_turns_the_xray_key_pair_into_standard_base64():
    calls = []
    account = warp_module.register(("kPrivate_" + "k" * 34, "Public_" + "p" * 36), registrar(calls))
    assert warp_module.valid_account(account) and account["endpoint"] == "162.159.192.5:2408"
    with pytest.raises(warp_module.WarpError):
        warp_module.register(("short", "short"), registrar(calls))
    with pytest.raises(warp_module.WarpError):
        warp_module.register(("kPrivate_" + "k" * 34, "Public_" + "p" * 36), lambda *a: (200, {"id": "x"}))
