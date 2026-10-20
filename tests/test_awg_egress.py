"""AmneziaWG egress through a WARP tunnel of its own (v2.3.0): the document, the registration, the
`awgwarp` device, the source rules and the fail-closed table, the handshake gate and the rollback."""
from __future__ import annotations

import ipaddress
import json
import random

import pytest

from awg_manager import egress as egress_mod
from awg_manager import keys, warp
from awg_manager.config import from_env
from awg_manager.egress import IFACE, PRIORITY, TABLE, EgressError, validate_document
from awg_manager.service import AwgManager
from awg_manager.state import StateError
from tests.test_awg_manager import Clock, FakeHost, make_env

WARP_DOC = {"schema": 1, "upstream": {"provider": "warp"}}
DIRECT_DOC = {"schema": 1, "upstream": None}
PEER_KEY = keys.b64(keys.public_key(bytes(range(2, 34))))


class RoutingHost(FakeHost):
    """FakeHost plus `ip rule` and the handshake of the WARP device."""

    def __init__(self):
        super().__init__()
        self.rules: set[str] = set()
        self.warp_handshake = 0
        self.links: dict[str, list[str]] = {}
        self.router_reads = True  # the router opens the device as soon as it exists

    def ip(self, *args):
        super().ip(*args)
        if args[:2] == ("tuntap", "add"):
            self.links[args[3]] = ["POINTOPOINT", "UP", "LOWER_UP"] if self.router_reads else ["NO-CARRIER", "POINTOPOINT", "UP"]
        if args[:2] == ("rule", "add"):
            self.rules.add(str(ipaddress.ip_network(args[3])))
        elif args[:2] == ("rule", "del"):
            self.rules.discard(str(ipaddress.ip_network(args[3])))

    def ip_json(self, *args):
        if args[:3] == ("link", "show", "dev"):
            from awg_manager.host import HostError
            if args[3] not in self.links:
                raise HostError("no such device")
            return [{"ifname": args[3], "flags": list(self.links[args[3]])}]
        assert args == ("-4", "rule", "show", "table", TABLE)
        out = []
        for source in sorted(self.rules):
            net = ipaddress.ip_network(source)
            out.append({"priority": int(PRIORITY), "src": str(net.network_address), "srclen": net.prefixlen, "table": TABLE})
        return out

    def uapi_get(self, iface):
        if iface == IFACE:
            self._alive(iface)
            return f"private_key=x\npublic_key=y\nlast_handshake_time_sec={self.warp_handshake}\nrx_bytes=10\ntx_bytes=20\n"
        return super().uapi_get(iface)


class Registrar:
    def __init__(self, status=200):
        self.status, self.calls = status, []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        if method == "DELETE":
            return 204, None
        if self.status != 200:
            return self.status, None
        sent = json.loads(body)
        assert keys.unb64(sent["key"]) and headers["CF-Client-Version"]
        return 200, {"id": "dev-1", "token": "tok-1", "account": {"account_type": "free"}, "config": {
            "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700::1"}},
            "peers": [{"public_key": PEER_KEY, "endpoint": {"v4": "162.159.192.9:0", "host": "engage.cloudflareclient.com:2408"}}]}}


def make(tmp_path, *, status=200, handshake=True, router=False, router_reads=True):
    host, clock = RoutingHost(), Clock()
    host.router_reads = router_reads
    registrar = Registrar(status)

    def sleep(_seconds):
        if handshake:
            host.warp_handshake = 1_700_000_000

    extra = {"AWG_EGRESS_ROUTER_TUN": "awgxr"} if router else {}
    manager = AwgManager(from_env(make_env(tmp_path, **extra)), host, clock=clock, wall=lambda: 1_700_000_000,
                         rng=random.Random(3), warp_opener=registrar, sleep=sleep)
    manager.bootstrap()
    return manager, host, clock, registrar


def apply(manager, document, op="op-1"):
    return manager.egress_apply({"expected_revision": manager.egress_view()["revision"], "document": document,
                                 "operation_id": op})


def test_the_document_is_direct_warp_or_router_and_nothing_else():
    assert validate_document(DIRECT_DOC) == DIRECT_DOC and validate_document(WARP_DOC) == WARP_DOC
    assert validate_document({"schema": 1, "upstream": {"provider": "router"}})["upstream"] == {"provider": "router"}
    for bad in ({}, {"schema": 2, "upstream": None}, {"schema": 1, "upstream": {"provider": "socks"}},
                {"schema": 1, "upstream": None, "acl": []}, None):
        with pytest.raises(EgressError) as exc:
            validate_document(bad)
        assert exc.value.code == "egress_invalid"


def test_a_fresh_node_is_direct_with_both_capabilities_and_no_tunnel(tmp_path):
    manager, host, _, registrar = make(tmp_path)
    view = manager.egress_view()
    assert view["mode"] == "direct" and view["document"] == DIRECT_DOC and view["managed"] is False
    assert view["capabilities"] == ["whole_direct", "whole_warp"] and view["providers"] == {"warp": {"reachable": None}}
    assert view["warp"]["registered"] is False and view["warp"]["tunnel"] == "off"
    assert IFACE not in host.procs and host.rules == set() and registrar.calls == []
    assert manager.health()["egress"] == {"mode": "direct", "tunnel": "off"} and manager.health()["status"] == "ok"


def test_warp_registers_once_starts_the_device_and_steers_every_subnet(tmp_path):
    manager, host, _, registrar = make(tmp_path)
    result = apply(manager, WARP_DOC)
    assert result["applied"] == WARP_DOC and result["replayed"] is False
    assert [c[0] for c in registrar.calls] == ["POST"]
    config = dict(line.split("=", 1) for _, body in host.sets if _ == IFACE for line in body.splitlines())
    assert config["endpoint"] == "162.159.192.9:2408" and config["allowed_ip"] == "0.0.0.0/0"
    assert config["public_key"] == keys.unb64(PEER_KEY).hex() and config["persistent_keepalive_interval"] == "25"
    assert "jc" not in config and "h1" not in config  # a plain WireGuard device: WARP knows no obfuscation
    assert ("addr", "replace", "172.16.0.2/32", "dev", IFACE) in host.ip_calls
    assert ("route", "replace", "blackhole", "default", "table", TABLE, "metric", "1024") in host.ip_calls
    assert ("route", "replace", "default", "dev", IFACE, "table", TABLE) in host.ip_calls
    assert ("route", "replace", "throw", "10.0.0.0/8", "table", TABLE) in host.ip_calls
    assert host.rules == {"10.66.15.0/24", "10.66.20.0/24", "10.66.31.0/24"}
    view = manager.egress_view()
    assert view["mode"] == "proxy" and view["providers"]["warp"]["reachable"] is True
    assert view["warp"] == {"registered": True, "address": "172.16.0.2", "endpoint": "162.159.192.9:2408",
                            "account_type": "free", "tunnel": "up", "latest_handshake": 1_700_000_000, "rx": 10, "tx": 20}
    assert "tok-1" not in json.dumps(view) and "private" not in json.dumps(view)
    assert manager.health()["egress"] == {"mode": "proxy", "tunnel": "up"}
    # direct again: the registration stays, the rules and the device go
    apply(manager, DIRECT_DOC, op="op-2")
    assert host.rules == set() and manager.egress.proc is None and ("route", "flush", "table", TABLE) in host.ip_calls
    apply(manager, WARP_DOC, op="op-3")
    assert [c[0] for c in registrar.calls] == ["POST"]  # no second registration


def test_a_control_socket_that_is_not_ready_at_first_is_configured_while_waiting(tmp_path):
    """The live bug of the first lab run: the device's socket was not ready when the apply first tried to
    configure it, and nothing tried again while the apply held the lock waiting for the handshake."""
    manager, host, _, _ = make(tmp_path)
    original = host.uapi_set
    refusals = {"left": 2}

    def flaky(iface, body):
        if iface == IFACE and refusals["left"]:
            refusals["left"] -= 1
            from awg_manager.host import UapiError
            raise UapiError("no control socket yet")
        return original(iface, body)

    host.uapi_set = flaky
    apply(manager, WARP_DOC)
    assert manager.egress_view()["warp"]["tunnel"] == "up" and host.rules


def test_no_handshake_puts_the_previous_document_back_and_fails(tmp_path):
    manager, host, _, registrar = make(tmp_path, handshake=False)
    before = manager.egress_view()["revision"]
    with pytest.raises(Exception) as exc:
        apply(manager, WARP_DOC)
    assert getattr(exc.value, "code", None) == "egress_unreachable"
    view = manager.egress_view()
    assert view["mode"] == "direct" and view["revision"] != before
    assert host.rules == set() and manager.egress.proc is None
    assert view["warp"]["registered"] is True  # kept for the next attempt


def test_a_refused_registration_changes_nothing(tmp_path):
    manager, host, _, _ = make(tmp_path, status=429)
    with pytest.raises(Exception) as exc:
        apply(manager, WARP_DOC)
    assert getattr(exc.value, "code", None) == "egress_unreachable"
    view = manager.egress_view()
    assert view["mode"] == "direct" and view["revision"] == "0" and view["warp"]["registered"] is False
    assert host.rules == set()


def test_revision_replay_and_rollback(tmp_path):
    manager, host, _, _ = make(tmp_path)
    with pytest.raises(Exception) as exc:
        manager.egress_apply({"expected_revision": "7", "document": WARP_DOC, "operation_id": "x"})
    assert exc.value.code == "egress_conflict"
    apply(manager, WARP_DOC, op="same")
    replay = manager.egress_apply({"expected_revision": "0", "document": WARP_DOC, "operation_id": "same"})
    assert replay["replayed"] is True
    with pytest.raises(Exception) as exc:
        manager.egress_apply({"expected_revision": "1", "document": DIRECT_DOC, "operation_id": "same"})
    assert exc.value.code == "egress_conflict"
    rolled = manager.egress_rollback({"expected_revision": manager.egress_view()["revision"]})
    assert rolled["applied"] == DIRECT_DOC and host.rules == set()
    with pytest.raises(Exception) as exc:
        manager.egress_rollback({"expected_revision": manager.egress_view()["revision"]})
    assert exc.value.code == "egress_no_previous"


def test_the_tunnel_comes_back_after_a_crash_and_the_table_stays_fail_closed(tmp_path):
    manager, host, clock, _ = make(tmp_path)
    apply(manager, WARP_DOC)
    host.crash(IFACE)
    clock.now += 1
    manager.tick()  # the dead device is noticed; restart waits for the backoff
    assert host.rules  # rules stay: with the device gone the blackhole route drops the traffic
    assert manager.egress_view()["warp"]["tunnel"] == "down"
    clock.now += 2
    manager.tick()
    assert host.procs[IFACE].poll() is None and manager.egress.configured


def test_restart_keeps_warp_and_shutdown_removes_the_rules(tmp_path):
    manager, host, _, registrar = make(tmp_path)
    apply(manager, WARP_DOC)
    manager.shutdown()
    assert host.rules == set() and manager.egress.proc is None
    again = AwgManager(from_env(make_env(tmp_path)), host, clock=Clock(), wall=lambda: 1_700_000_000,
                       rng=random.Random(3), warp_opener=registrar, sleep=lambda _s: None)
    again.bootstrap()
    assert again.egress_view()["mode"] == "proxy" and host.rules
    assert [c[0] for c in registrar.calls] == ["POST"]


def test_stale_rules_are_swept_when_direct(tmp_path):
    manager, host, clock, _ = make(tmp_path)
    host.rules.add("10.66.20.0/24")  # left by a manager that was killed while on WARP
    clock.now += egress_mod.NETWORK_RECHECK + 1
    manager.tick()
    assert host.rules == set()


def test_a_malformed_egress_section_is_refused(tmp_path):
    manager, _, _, _ = make(tmp_path)
    manager.store.doc["egress"] = {"revision": "x", "history": [], "warp": None}
    manager.store.save()
    with pytest.raises(StateError):
        AwgManager(from_env(make_env(tmp_path)), RoutingHost(), clock=Clock()).bootstrap()


def test_api_routes_and_field_checks(tmp_path):
    manager, _, _, _ = make(tmp_path)
    with pytest.raises(Exception) as exc:
        manager.egress_apply({"expected_revision": "0", "document": WARP_DOC})
    assert exc.value.code == "invalid_request"
    plan = manager.egress_plan({"expected_revision": "0", "document": WARP_DOC})
    assert plan["target"] == WARP_DOC and plan["diff"] and plan["restart_required"] is False


def test_registration_parses_only_what_it_needs_and_refuses_odd_answers():
    account = warp.register(Registrar())
    assert warp.valid_account(account) and account["endpoint"] == "162.159.192.9:2408"
    assert set(account) == {"id", "token", "private_key", "address", "peer_public_key", "endpoint",
                            "account_type", "registered_at"}
    with pytest.raises(warp.WarpError):
        warp.register(lambda *a: (200, {"id": "x", "config": {}}))
    with pytest.raises(warp.WarpError):
        warp.register(Registrar(status=403))
    calls = []
    warp.deregister(account, lambda m, u, h, b: (calls.append((m, u, h["Authorization"])) or (204, None)))
    assert calls == [("DELETE", f"{warp.API}/reg/dev-1", "Bearer tok-1")]


# ---------------------------------------------------------------- through the Xray-router (variant 2)

ROUTER_DOC = {"schema": 1, "upstream": {"provider": "router"}}


def test_the_router_device_is_made_for_the_routers_uid_and_offered_as_a_provider(tmp_path):
    manager, host, _, _ = make(tmp_path, router=True)
    assert ("tuntap", "add", "dev", "awgxr", "mode", "tun", "user", "10006", "group", "10006") in host.ip_calls
    assert ("addr", "replace", "198.18.0.1/30", "dev", "awgxr") in host.ip_calls
    view = manager.egress_view()
    assert view["providers"]["router"] == {"reachable": True}
    assert view["router"] == {"device": "awgxr", "present": True, "attached": True}
    assert host.rules == set()  # made, not routed: the panel attaches


def test_attach_steers_every_subnet_into_the_router_device_and_stops_the_warp_tunnel(tmp_path):
    manager, host, _, registrar = make(tmp_path, router=True)
    apply(manager, WARP_DOC)
    assert IFACE in host.procs and host.procs[IFACE].poll() is None
    apply(manager, ROUTER_DOC, op="op-2")
    assert ("route", "replace", "default", "dev", "awgxr", "table", TABLE) in host.ip_calls
    assert host.rules == {"10.66.15.0/24", "10.66.20.0/24", "10.66.31.0/24"}
    assert manager.egress.proc is None
    assert manager.health()["egress"] == {"mode": "router", "tunnel": "up"}
    assert manager.egress_view()["mode"] == "proxy" and manager.egress_view()["document"] == ROUTER_DOC
    apply(manager, DIRECT_DOC, op="op-3")
    assert host.rules == set() and "awgxr" in host.links  # the device stays for the router


def test_attach_waits_for_the_router_to_read_the_device_or_goes_back(tmp_path):
    manager, host, _, _ = make(tmp_path, router=True, router_reads=False)
    with pytest.raises(Exception) as exc:
        apply(manager, ROUTER_DOC)
    assert getattr(exc.value, "code", None) == "egress_unreachable"
    assert manager.egress_view()["document"] == DIRECT_DOC and host.rules == set()


def test_a_node_without_the_router_device_refuses_the_router_provider(tmp_path):
    manager, host, _, _ = make(tmp_path)
    assert "router" not in manager.egress_view()["providers"] and manager.egress_view()["router"] is None
    with pytest.raises(Exception) as exc:
        apply(manager, ROUTER_DOC)
    assert getattr(exc.value, "code", None) == "egress_invalid" and host.links == {}
