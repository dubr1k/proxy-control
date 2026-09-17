"""The mieru-manager's lanes (v0.7, spike S3): mita has one egress per daemon, so a lane is
one of the slot daemons the installer keeps running (`mita@<n>`, its own port and UDS).
The main daemon stays the source of truth for users; a slot mirrors its lane's users with
an egress that sends everything to the lane's account on the router ingress."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mieru_manager.egress import EgressInvalid
from mieru_manager.lanes import LanesInvalid, Slot, parse_slots
from mieru_manager.service import ConfigConflict, MieruManager
from tests.test_mieru_manager import BASE, FakeMita

ROUTER = "socks5://127.0.0.1:45102"
ROUTER_SECRET = "mieru-e5f6a7b8:" + "K" * 40
SLOTS = "1:46101:/run/mita/lane-1.sock:/var/lib/mita/lanes/1,2:46102:/run/mita/lane-2.sock:/var/lib/mita/lanes/2"
TWO_USERS = {**BASE, "users": [{"name": "alice", "hashedPassword": "a" * 64}, {"name": "bob", "hashedPassword": "b" * 64, "quotas": [{"days": 30, "megabytes": 1024}]},
                              {"name": "carol", "hashedPassword": "c" * 64}]}
LANE_A = {"lane": "grant:7f3a", "users": ["alice"], "upstream": {"user": "grant-7f3a", "password": "A" * 43}}
LANE_B = {"lane": "grant:b2c4", "users": ["bob"], "upstream": {"user": "grant-b2c4", "password": "B" * 43}}


class FakeSlot(FakeMita):
    """A slot daemon: starts empty and idle (nothing listens), like the installer leaves it."""

    def __init__(self, port: int):
        super().__init__({"portBindings": [{"port": port, "protocol": "TCP"}], "loggingLevel": "INFO"})
        self.running = False


def lane_manager(tmp_path: Path, *, mita: FakeMita | None = None, router: str | None = ROUTER,
                 slots: str | None = SLOTS) -> tuple[MieruManager, FakeMita, dict[int, FakeSlot]]:
    credential = tmp_path / "xray-router-ingress"
    credential.write_text(ROUTER_SECRET + "\n")
    main = mita or FakeMita(TWO_USERS)
    parsed = parse_slots(slots) if slots else []
    fakes = {slot.index: FakeSlot(slot.port) for slot in parsed}
    instance = MieruManager(mita=main, state_dir=tmp_path / "state", public_host="proxy.example.com",
                            router_url=router, router_credential_file=credential if router else None,
                            lane_slots=parsed, slot_factory=lambda slot: fakes[slot.index])
    instance.reachability = lambda url, timeout=3.0, auth=False: True
    instance.bootstrap()
    return instance, main, fakes


def test_parse_slots_reads_the_installer_list():
    assert parse_slots(SLOTS) == [Slot(1, 46101, "/run/mita/lane-1.sock", "/var/lib/mita/lanes/1"),
                                  Slot(2, 46102, "/run/mita/lane-2.sock", "/var/lib/mita/lanes/2")]
    assert parse_slots("") == [] and parse_slots(None) == []
    for bad in ("x:46101:/s:/d", "1:70000:/s:/d", "1:46101:/s", "1:46101:/s:/d,1:46102:/t:/e", "1:46101:/s:/d,2:46101:/t:/e"):
        with pytest.raises(LanesInvalid):
            parse_slots(bad)


def test_set_lanes_mirrors_the_lane_users_into_a_slot_with_the_router_egress(tmp_path):
    instance, main, slots = lane_manager(tmp_path)
    view = instance.set_lanes({"lanes": [LANE_A]})
    slot = slots[1]
    config = slot.observe()
    assert config["portBindings"] == [{"port": 46101, "protocol": "TCP"}]
    assert config["users"] == [{"name": "alice", "hashedPassword": "a" * 64}]
    assert config["egress"] == {"proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102,
                                              "socks5Authentication": {"user": "grant-7f3a", "password": "A" * 43}}],
                                "rules": [{"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["router"]}]}
    assert slot.running and ("start",) in slot.calls
    assert slots[2].running is False and slots[2].calls == []
    # the main daemon is untouched: users stay there (the slot mirrors), no restart
    assert main.observe() == TWO_USERS and ("stop",) not in main.calls
    assert view == {"lanes": [{"lane": "grant:7f3a", "slot": 1, "port": 46101, "users": ["alice"], "upstream": "socks5://***@127.0.0.1:45102",
                               "status": "running", "share_templates": {"alice": "mierus://{username}:{password}@proxy.example.com?profile=alice&port=46101&protocol=TCP&mtu=1400"}}],
                    "free_slots": 1, "service_share_template": "mierus://{username}:{password}@proxy.example.com?profile={profile}&port=8443&protocol=TCP&mtu=1400"}
    assert "A" * 43 not in json.dumps(view)
    state = json.loads(instance.state_file.read_text())
    assert state["lanes"] == {"grant:7f3a": {"slot": 1, "users": ["alice"], "upstream": {"user": "grant-7f3a", "password": "A" * 43}}}
    assert [row.get("lane") for row in instance.list_users()] == ["grant:7f3a", None, None]


def test_lanes_keep_their_slot_move_users_and_run_out_of_slots(tmp_path):
    instance, main, slots = lane_manager(tmp_path)
    instance.set_lanes({"lanes": [LANE_A, LANE_B]})
    assert slots[1].observe()["users"][0]["name"] == "alice" and slots[2].observe()["users"][0]["name"] == "bob"
    # a lane keeps its slot across requests; a dropped lane frees its slot (empty config, stopped)
    instance.set_lanes({"lanes": [LANE_B]})
    assert slots[2].observe()["users"][0]["name"] == "bob" and instance.lanes()["lanes"][0]["slot"] == 2
    assert slots[1].observe().get("users", []) == [] and slots[1].running is False and "egress" not in slots[1].observe()
    assert instance.lanes()["free_slots"] == 1
    moved = {"lane": "grant:b2c4", "users": ["alice", "bob"], "upstream": LANE_B["upstream"]}
    instance.set_lanes({"lanes": [moved]})
    assert [user["name"] for user in slots[2].observe()["users"]] == ["alice", "bob"]
    assert slots[2].observe()["users"][1]["quotas"] == [{"days": 30, "megabytes": 1024}]
    third = {"lane": "grant:c3", "users": ["carol"], "upstream": {"user": "grant-c3", "password": "C" * 43}}
    with pytest.raises(ConfigConflict, match="lane_slots_exhausted"):
        instance.set_lanes({"lanes": [LANE_A, LANE_B, third]})
    instance.set_lanes({"lanes": []})
    assert instance.lanes() == {"lanes": [], "free_slots": 2, "service_share_template": "mierus://{username}:{password}@proxy.example.com?profile={profile}&port=8443&protocol=TCP&mtu=1400"}
    assert all(not slot.running for slot in slots.values())


def test_user_changes_on_the_main_daemon_are_mirrored_into_the_slot(tmp_path):
    instance, main, slots = lane_manager(tmp_path)
    instance.set_lanes({"lanes": [LANE_A]})
    revision = instance.inspect()["revision"]
    rotated = instance.rotate_user("alice", expected_revision=revision)
    assert slots[1].observe()["users"][0]["hashedPassword"] == main.observe()["users"][0]["hashedPassword"] != "a" * 64
    # the rotated link names the lane's port, not the main one
    assert "port=46101" in rotated["share_url"] and "port=8443" not in rotated["share_url"]
    instance.disable_user("alice", expected_revision=rotated["revision"])
    assert slots[1].observe().get("users", []) == [] and slots[1].running is False
    assert instance.lanes()["lanes"][0]["users"] == ["alice"]  # the lane remembers a disabled member
    revision = instance.inspect()["revision"]
    instance.enable_user("alice", expected_revision=revision)
    assert slots[1].observe()["users"][0]["name"] == "alice" and slots[1].running
    revision = instance.inspect()["revision"]
    instance.delete_user("alice", expected_revision=revision)
    assert slots[1].observe().get("users", []) == []
    assert instance.lanes()["lanes"][0]["users"] == []  # gone from the lane too (the name is tombstoned)


@pytest.mark.parametrize("body", [
    {"lanes": [{"lane": "svc:mieru", "users": ["alice"], "upstream": LANE_A["upstream"]}]},
    {"lanes": [{"lane": "grant:7f3a", "users": ["nobody"], "upstream": LANE_A["upstream"]}]},
    {"lanes": [LANE_A, {"lane": "grant:x", "users": ["alice"], "upstream": LANE_B["upstream"]}]},
    {"lanes": [{"lane": "grant:7f3a", "users": [], "upstream": LANE_A["upstream"]}]},
    {"lanes": [{"lane": "grant:7f3a", "users": ["alice"], "upstream": {"user": "grant-7f3a"}}]},
    {"lanes": "nope"},
])
def test_set_lanes_refuses_bad_requests_without_touching_a_slot(tmp_path, body):
    instance, main, slots = lane_manager(tmp_path)
    with pytest.raises((LanesInvalid, ConfigConflict)):
        instance.set_lanes(body)
    assert all(slot.calls == [] for slot in slots.values())


def test_lanes_need_the_router_and_slots(tmp_path):
    (tmp_path / "a").mkdir()
    without_router, _main, _slots = lane_manager(tmp_path / "a", router=None)
    with pytest.raises(EgressInvalid, match="router"):
        without_router.set_lanes({"lanes": [LANE_A]})
    (tmp_path / "b").mkdir()
    without_slots, _main, _slots = lane_manager(tmp_path / "b", slots=None)
    with pytest.raises(ConfigConflict, match="lane_slots_exhausted"):
        without_slots.set_lanes({"lanes": [LANE_A]})
    assert without_slots.lanes() == {"lanes": [], "free_slots": 0, "service_share_template": "mierus://{username}:{password}@proxy.example.com?profile={profile}&port=8443&protocol=TCP&mtu=1400"}


def test_a_failed_slot_probe_restores_the_slot_and_keeps_the_state(tmp_path):
    instance, main, slots = lane_manager(tmp_path)
    slots[1].fail_probe = True
    state_before = instance.state_file.read_text()
    with pytest.raises(Exception):
        instance.set_lanes({"lanes": [LANE_A]})
    assert instance.state_file.read_text() == state_before
    assert slots[1].observe().get("users", []) == [] and slots[1].running is False
    assert instance.lanes() == {"lanes": [], "free_slots": 2, "service_share_template": "mierus://{username}:{password}@proxy.example.com?profile={profile}&port=8443&protocol=TCP&mtu=1400"}


def test_bootstrap_resyncs_the_slots_from_the_state(tmp_path):
    instance, main, slots = lane_manager(tmp_path)
    instance.set_lanes({"lanes": [LANE_A]})
    # the slot lost its config (a reboot of a slot daemon without persisted config, or a crash mid-apply)
    slots[1].config = {"portBindings": [{"port": 46101, "protocol": "TCP"}], "loggingLevel": "INFO"}
    slots[1].running = False
    again = MieruManager(mita=main, state_dir=tmp_path / "state", public_host="proxy.example.com", router_url=ROUTER,
                         router_credential_file=tmp_path / "xray-router-ingress", lane_slots=parse_slots(SLOTS),
                         slot_factory=lambda slot: slots[slot.index])
    again.reachability = lambda url, timeout=3.0, auth=False: True
    again.bootstrap()
    assert slots[1].observe()["users"][0]["name"] == "alice" and slots[1].running
    assert again.lanes()["lanes"][0]["lane"] == "grant:7f3a"


def test_unix_api_lanes_routes(tmp_path):
    import threading

    import httpx

    from mieru_manager.server import ManagerHTTPServer

    instance, _main, _slots = lane_manager(tmp_path)
    socket_path = tmp_path / "manager.sock"
    server = ManagerHTTPServer(socket_path, instance, "t" * 40)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        headers = {"X-Mieru-Token": "t" * 40}
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(socket_path)), base_url="http://manager") as client:
            assert client.get("/v1/lanes").status_code == 401
            assert client.get("/v1/lanes", headers=headers).json() == {"lanes": [], "free_slots": 2, "service_share_template": "mierus://{username}:{password}@proxy.example.com?profile={profile}&port=8443&protocol=TCP&mtu=1400"}
            put = client.put("/v1/lanes", json={"lanes": [LANE_A]}, headers=headers)
            assert put.status_code == 200 and put.json()["lanes"][0]["port"] == 46101 and "A" * 43 not in put.text
            bad = client.put("/v1/lanes", json={"lanes": [{"lane": "svc:mieru", "users": ["alice"], "upstream": LANE_A["upstream"]}]}, headers=headers)
            assert (bad.status_code, bad.json()["code"]) == (409, "lanes_invalid")
            assert client.get("/v1/users", headers=headers).json()[0]["lane"] == "grant:7f3a"
            assert client.put("/v1/lanes", json={"lanes": []}, headers=headers).json() == {"lanes": [], "free_slots": 2, "service_share_template": "mierus://{username}:{password}@proxy.example.com?profile={profile}&port=8443&protocol=TCP&mtu=1400"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_the_slot_unit_template_mirrors_the_main_unit_with_its_own_socket_and_state():
    """`mita@<n>.service` (v0.7): the same hardening as `mita.service`, the slot's own config,
    socket and state directory, and no `mita start` — an idle slot listens on nothing."""
    root = Path(__file__).resolve().parents[1] / "deploy"
    main, template = (root / "mita.service").read_text(), (root / "mita@.service").read_text()
    # the slot's own state directory is bound over /var/lib/mita: mita's fixed metrics.pb and
    # the config stay per daemon, never shared with the main one
    assert "BindPaths=/var/lib/mita/lanes/%i:/var/lib/mita" in template
    assert "MITA_CONFIG_JSON_FILE=/var/lib/mita/server_config.json" in template
    assert "MITA_UDS_PATH=/run/mita/lane-%i.sock" in template and "StateDirectory=mita/lanes/%i" in template
    assert "ExecStart=/usr/bin/mita run" in template and "mita start" not in template
    for line in ("NoNewPrivileges=true", "ProtectSystem=strict", "ReadOnlyPaths=/usr/bin/mita", "ReadWritePaths=/run/mita /var/lib/mita", "User=mita"):
        assert line in main and line in template
