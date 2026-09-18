"""Custom exits of the router (v0.8): the intent's `exits`, their Xray outbounds, the
credentials masked everywhere, and the throwaway probe an exit is tested with."""
from __future__ import annotations

import json
import threading

import httpx
import pytest

from tests.test_xray_router_manager import manager
from xray_router_manager.intent import (
    CAPABILITIES,
    EgressInvalid,
    redact_intent,
    validate_document,
    validate_exit,
)
from xray_router_manager.render import exit_outbound, render_config
from xray_router_manager.server import ManagerHTTPServer
from xray_router_manager.service import Ingress

UUID = "9d3b6b2c-1e6a-4b2a-9f0e-3c2f8a1d5e77"
PUBLIC_KEY = "a" * 43
SOCKS = {"protocol": "socks", "address": "10.0.0.2", "port": 1080, "credential": {"username": "u", "password": "p"}}
VLESS = {"protocol": "vless", "address": "vpn.example.org", "port": 443, "credential": {"uuid": UUID}, "flow": "xtls-rprx-vision",
         "transport": {"network": "tcp"}, "security": {"kind": "reality", "server_name": "www.example.com", "public_key": PUBLIC_KEY,
                                                       "short_id": "0123abcd", "fingerprint": "chrome"}}
TROJAN_WS = {"protocol": "trojan", "address": "t.example.org", "port": 8443, "credential": {"password": "pw"},
             "transport": {"network": "ws", "path": "/ws", "host": "t.example.org"}, "security": {"kind": "tls", "server_name": "t.example.org"}}
SS = {"protocol": "shadowsocks", "address": "203.0.113.5", "port": 8388, "credential": {"password": "pw"}, "method": "aes-256-gcm"}
DEFAULT_DIRECT = {"action": "direct", "egress": None}


def _v2(exits, egress="exit:e1"):
    return {"schema": 2, "chains": {}, "exits": exits,
            "lanes": {"svc:naive": {"default": {"action": "egress", "egress": egress},
                                    "rules": [{"domains": ["example.com"], "action": "direct"}]}}}


def test_validate_exit_normalises_every_protocol_and_refuses_the_impossible():
    socks = validate_exit(SOCKS)
    assert socks["transport"] == {"network": "tcp"} and socks["security"] == {"kind": "none"}
    vless = validate_exit(VLESS)
    assert vless["security"]["public_key"] == PUBLIC_KEY and vless["flow"] == "xtls-rprx-vision"
    assert validate_exit(TROJAN_WS)["transport"] == {"network": "ws", "path": "/ws", "host": "t.example.org"}
    assert validate_exit(SS)["method"] == "aes-256-gcm"
    assert validate_exit({**SOCKS, "credential": {}})["credential"] == {}
    for broken, message in (
        ({**SOCKS, "protocol": "wireguard"}, "exit protocol"),
        ({**SOCKS, "port": 70000}, "exit port"),
        ({**SOCKS, "credential": {"username": "u"}}, "both username and password"),
        ({**VLESS, "credential": {"uuid": "nope"}}, "exit uuid"),
        ({**VLESS, "security": {"kind": "reality", "public_key": PUBLIC_KEY}}, "server name"),
        ({**SS, "method": "rc4-md5"}, "shadowsocks method"),
        ({**SS, "transport": {"network": "ws"}}, "tcp only"),
        ({**SOCKS, "security": {"kind": "reality", "server_name": "x.com", "public_key": PUBLIC_KEY}}, "vless or trojan"),
        ({**VLESS, "transport": {"network": "ws"}}, "xtls-rprx-vision needs tcp"),
        ({**SOCKS, "extra": 1}, "invalid exit"),
        ({**SOCKS, "address": "*.example.com"}, "exit address"),
    ):
        with pytest.raises(EgressInvalid, match=message):
            validate_exit(broken)


def test_the_intent_names_exits_and_a_rule_may_leave_through_one():
    document = validate_document(_v2({"e1": SOCKS}))
    assert document["exits"]["e1"]["protocol"] == "socks" and document["lanes"]["svc:naive"]["default"]["egress"] == "exit:e1"
    with pytest.raises(EgressInvalid, match="egress provider"):
        validate_document(_v2({"e1": SOCKS}, egress="exit:e2"))
    with pytest.raises(EgressInvalid, match="exit id"):
        validate_document(_v2({"bad id!": SOCKS}, egress="exit:bad id!"))
    with pytest.raises(EgressInvalid, match="exits list"):
        validate_document(_v2({f"e{i}": SOCKS for i in range(17)}, egress="exit:e1"))
    # Without exits the document is byte-for-byte what v0.7 produced.
    plain = validate_document({"schema": 2, "chains": {}, "lanes": {"svc:naive": {"default": DEFAULT_DIRECT, "rules": []}}})
    assert "exits" not in plain
    assert "custom_exits" in CAPABILITIES


def test_credentials_are_masked_in_the_redacted_intent():
    masked = redact_intent(validate_document(_v2({"e1": VLESS, "e2": SOCKS})))
    assert masked["exits"]["e1"]["credential"] == {"uuid": "***"} and masked["exits"]["e2"]["credential"] == {"username": "***", "password": "***"}
    assert UUID not in json.dumps(masked) and '"p"' not in json.dumps(masked)


def test_exit_outbounds_render_the_way_xray_dials_them():
    socks = exit_outbound("x", validate_exit(SOCKS))
    assert socks["protocol"] == "socks" and socks["settings"]["servers"][0]["users"] == [{"user": "u", "pass": "p"}]
    vless = exit_outbound("x", validate_exit(VLESS))
    assert vless["settings"]["vnext"][0]["users"][0] == {"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}
    assert vless["streamSettings"]["security"] == "reality" and vless["streamSettings"]["realitySettings"]["publicKey"] == PUBLIC_KEY
    trojan = exit_outbound("x", validate_exit(TROJAN_WS))
    assert trojan["streamSettings"]["network"] == "ws" and trojan["streamSettings"]["wsSettings"] == {"path": "/ws", "host": "t.example.org"}
    assert trojan["streamSettings"]["tlsSettings"]["serverName"] == "t.example.org"
    ss = exit_outbound("x", validate_exit(SS))
    assert ss["settings"]["servers"][0]["method"] == "aes-256-gcm"
    ingresses = [Ingress("naive", 45101, "naive-a", "N" * 40), Ingress("mieru", 45102, "mieru-b", "M" * 40)]
    config = render_config({"naive": validate_document(_v2({"e1": SOCKS}))}, ingresses, warp_url=None)
    tags = [item["tag"] for item in config["outbounds"]]
    assert "exit:naive:e1" in tags
    catch_all = [rule for rule in config["routing"]["rules"] if rule.get("inboundTag") == ["naive"] and "outboundTag" in rule and "domain" not in rule and "ip" not in rule]
    assert catch_all[-1]["outboundTag"] == "exit:naive:e1"


def test_exit_test_runs_a_throwaway_xray_and_reports_what_the_far_end_saw(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    seen = {}

    def prober(port, host, timeout):
        seen["port"], seen["host"] = port, host
        return {"ip": "203.0.113.9", "colo": "AMS"}

    instance.exit_prober = prober
    before = len(runner.calls)
    result = instance.exit_test(SOCKS)
    assert result["ok"] is True and result["ip"] == "203.0.113.9" and result["colo"] == "AMS" and result["latency_ms"] >= 0
    tail = runner.calls[before:]
    assert [call[0] for call in tail] == ["test", "start", "ready", "stop"] and tail[0][1] == "exit-test.json"
    assert seen["host"] == "www.cloudflare.com" and seen["port"] == tail[2][1][0]
    assert not (instance.state_dir / "exit-test.json").exists()
    # The running router was never stopped.
    assert runner.running is not None and runner.running["path"].name == "1.json"
    probe_config = [handle for handle in runner.handles if handle["path"].name == "exit-test.json"][0]["config"]
    assert probe_config["inbounds"][0]["protocol"] == "dokodemo-door" and probe_config["outbounds"][0]["tag"] == "probe-exit"

    def failing(port, host, timeout):
        raise OSError("connection refused")

    instance.exit_prober = failing
    refused = instance.exit_test(VLESS)
    assert refused["ok"] is False and refused["code"] == "exit_unreachable"
    runner.fail_test = "invalid outbound"
    assert instance.exit_test(SS)["code"] == "exit_invalid"
    with pytest.raises(EgressInvalid):
        instance.exit_test({"protocol": "socks"})


def test_unix_api_exit_test_route(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    instance.exit_prober = lambda port, host, timeout: {"ip": "198.51.100.1", "colo": "FRA"}
    socket_path = tmp_path / "manager.sock"
    server = ManagerHTTPServer(socket_path, instance, "t" * 40)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        headers = {"X-Xray-Router-Token": "t" * 40}
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(socket_path)), base_url="http://router") as client:
            ok = client.post("/v1/exits/test", json={"exit": SOCKS}, headers=headers)
            assert ok.status_code == 200 and ok.json()["ip"] == "198.51.100.1"
            bad = client.post("/v1/exits/test", json={"exit": {"protocol": "socks"}}, headers=headers)
            assert bad.status_code == 422 and bad.json()["code"] == "egress_invalid"
            assert client.post("/v1/exits/test", json={"outbound": SOCKS}, headers=headers).status_code == 422
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
