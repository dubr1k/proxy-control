"""The MTProxy ingress of the Xray-router (v1.1): a `vless` inbound on a Unix socket the
`xray-router-ingress` bridge shares, its credential minted by the manager, the one fixed
exception to the bypass, and a node updated from a router without the service."""
from __future__ import annotations

import json
import stat

import pytest

from tests.test_xray_router_manager import FakeRunner, WARP_DOC, manager as base_manager
from xray_router_manager.intent import MTPROXY_BRIDGE_ADDRESS, direct_document
from xray_router_manager.render import MTPROXY_PRIVATE_EXCEPTION, Ingress, render_config
from xray_router_manager.service import ManualInterventionRequired, ValidationError, XrayRouterManager

CHAIN_DOC = {
    "schema": 2,
    "lanes": {"svc:mtproxy": {"default": {"action": "egress", "egress": "chain:b"}, "rules": []}},
    "chains": {"b": {"exit": "direct", "hops": [{
        "guid": "node-b", "address": "203.0.113.7", "port": 45443, "server_name": "panel.example.com",
        "public_key": "A" * 43, "short_id": "ab12", "uuid": "11111111-2222-4333-8444-555555555555"}]}},
}


class SocketRunner(FakeRunner):
    """The fake runner, accepting the socket the manager waits for."""

    def wait_ready(self, ports, timeout, sockets=()) -> None:
        self.calls.append(("ready", tuple(ports), tuple(sockets)))
        if self.fail_ready:
            self.fail_ready -= 1
            self.handles[-1]["alive"] = False
            from xray_router_manager.service import XrayError
            raise XrayError("the ingress ports did not open in time")


def manager(tmp_path, runner=None, **kwargs):
    instance, runner = base_manager(tmp_path, runner or SocketRunner(), **kwargs)
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    instance.mtproxy_socket = run_dir / "ingress-mtproxy.sock"
    instance.services = ("naive", "mieru", "mtproxy")
    return instance, runner


def _inbound(config: dict, tag: str) -> dict:
    return next(item for item in config["inbounds"] if item["tag"] == tag)


def test_bootstrap_mints_the_credential_and_listens_on_the_socket(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    record = json.loads((instance.state_dir / "ingress-mtproxy.json").read_text())
    assert set(record) == {"uuid", "username", "password"} and len(record["password"]) >= 32
    assert stat.S_IMODE((instance.state_dir / "ingress-mtproxy.json").stat().st_mode) == 0o600
    bridge_copy = instance.mtproxy_socket.parent / "ingress-mtproxy.json"
    assert json.loads(bridge_copy.read_text()) == record
    assert stat.S_IMODE(bridge_copy.stat().st_mode) == 0o600
    assert ("ready", (45101, 45102), (str(instance.mtproxy_socket),)) in runner.calls
    inbound = _inbound(runner.running["config"], "mtproxy")
    assert inbound["listen"] == str(instance.mtproxy_socket) and inbound["port"] == 0
    assert inbound["protocol"] == "vless" and inbound["streamSettings"] == {"network": "raw"}
    assert inbound["settings"]["clients"] == [{"id": record["uuid"], "email": "mtproxy", "flow": ""}]
    assert instance.status()["services"]["mtproxy"]["document"] == direct_document()


def test_the_credential_survives_a_restart_and_the_panel_reads_the_bridge_address(tmp_path):
    instance, _runner = manager(tmp_path)
    instance.bootstrap()
    first = instance.ingress("mtproxy")
    again, _ = manager(tmp_path)
    again.bootstrap()
    assert again.ingress("mtproxy") == first
    assert first["address"] == MTPROXY_BRIDGE_ADDRESS and set(first) == {"address", "username", "password"}
    with pytest.raises(ValidationError):
        instance.ingress("naive")


def test_a_malformed_credential_is_a_manual_intervention_not_a_new_one(tmp_path):
    instance, _runner = manager(tmp_path)
    instance.state_dir.mkdir(parents=True, exist_ok=True)
    (instance.state_dir / "ingress-mtproxy.json").write_text('{"uuid": "x", "username": "telemt", "password": "short"}')
    with pytest.raises(ManualInterventionRequired):
        instance.bootstrap()


def test_a_stale_socket_is_removed_before_xray_starts(tmp_path):
    instance, runner = manager(tmp_path)
    instance.mtproxy_socket.write_text("left behind")
    instance.bootstrap()
    assert not instance.mtproxy_socket.exists()  # the fake never creates it; the manager removed it
    assert ("start", "1.json") in runner.calls


def test_rules_start_with_the_mask_exception_then_the_bypass(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    current = instance.egress("mtproxy")
    instance.egress_apply("mtproxy", current["revision"], WARP_DOC, "routing:p:1")
    rules = [rule for rule in runner.running["config"]["routing"]["rules"] if rule["inboundTag"] == ["mtproxy"]]
    assert rules[0] == {"inboundTag": ["mtproxy"], "ip": list(MTPROXY_PRIVATE_EXCEPTION), "port": "443",
                        "outboundTag": "direct"}
    assert rules[1] == {"inboundTag": ["mtproxy"], "ip": ["geoip:private"], "outboundTag": "block"}
    assert rules[-1] == {"inboundTag": ["mtproxy"], "outboundTag": "warp"}
    assert "127.0.0.0/8" not in MTPROXY_PRIVATE_EXCEPTION


def test_a_chain_for_mtproxy_renders_like_any_service(tmp_path):
    instance, runner = manager(tmp_path)
    instance.hop_reachability = lambda *args: True
    instance.bootstrap()
    current = instance.egress("mtproxy")
    instance.egress_apply("mtproxy", current["revision"], CHAIN_DOC, "routing:p:2")
    config = runner.running["config"]
    assert any(outbound["tag"] == "chain:mtproxy:b:1" for outbound in config["outbounds"])
    assert config["routing"]["rules"][-1] == {"inboundTag": ["mtproxy"], "outboundTag": "chain:mtproxy:b:1"}


def test_mtproxy_has_no_lanes(tmp_path):
    instance, _runner = manager(tmp_path)
    instance.bootstrap()
    with pytest.raises(ValidationError):
        instance.lane_issue("mtproxy", "grant:abc")


def test_a_node_updated_from_a_router_without_mtproxy_rerenders_it_pass_through(tmp_path):
    old, runner = base_manager(tmp_path, SocketRunner())
    old.bootstrap()
    current = json.loads((old.state_dir / "current.json").read_text())
    assert set(current["services"]) == {"naive", "mieru"}
    old.close()  # the container is recreated with the new image
    updated, runner = manager(tmp_path, runner)
    updated.bootstrap()
    current = json.loads((updated.state_dir / "current.json").read_text())
    assert current["generation"] == 2 and set(current["services"]) == {"naive", "mieru", "mtproxy"}
    assert current["services"]["mtproxy"]["document"] == direct_document()
    assert _inbound(runner.running["config"], "mtproxy")["protocol"] == "vless"
    view = updated.egress("mtproxy")
    updated.egress_apply("mtproxy", view["revision"], WARP_DOC, "routing:p:3")


def test_a_manager_without_the_socket_does_not_know_mtproxy(tmp_path):
    instance, _runner = base_manager(tmp_path)
    instance.bootstrap()
    assert "mtproxy" not in instance.status()["services"]
    with pytest.raises(ValidationError):
        instance.egress("mtproxy")


def test_render_without_an_mtproxy_ingress_is_unchanged():
    ingresses = [Ingress("naive", 45101, "naive-a", "N" * 20), Ingress("mieru", 45102, "mieru-a", "M" * 20)]
    config = render_config({}, ingresses, warp_url=None)
    assert [inbound["tag"] for inbound in config["inbounds"]] == ["naive", "mieru"]
    assert not any(rule.get("port") == "443" for rule in config["routing"]["rules"])


def test_the_constructor_switch(tmp_path):
    with_socket = XrayRouterManager(state_dir=tmp_path / "a", runner=SocketRunner(), ingress_files={}, warp_url=None,
                                    artifacts={}, mtproxy_socket=tmp_path / "s.sock")
    without = XrayRouterManager(state_dir=tmp_path / "b", runner=SocketRunner(), ingress_files={}, warp_url=None, artifacts={})
    assert with_socket.services == ("naive", "mieru", "mtproxy") and without.services == ("naive", "mieru")
