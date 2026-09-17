"""The installer's side of v0.7 (spec §8): `[egress] relay_port` and `[mieru] lane_slots` in
the configuration, the firewall opening them, the router's relay enabled on apply and
proven on verify, the Mieru lane slots (`mita@<n>`) started, verified, repaired and
rolled back — and a v0.6 action without the new keys still valid."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from installer.adapters import mieru as mieru_module
from installer.adapters import xray_router as router_module
from installer.adapters.firewall import _selected_ports
from installer.adapters.mieru import MieruError
from installer.adapters.xray_router import XrayRouterError
from installer.config import ConfigError, parse_config, render_config
from installer.model import DEFAULT_RELAY_PORT, EgressChoice, EgressConfig, MieruConfig, Profile
from installer.planner import Action, AuditFacts, PlanError
from tests.test_installer_mieru import FakeMieruRunner, artifact_action, fake_deb, full_config, host
from tests.test_installer_mieru import adapter as mieru_adapter
from tests.test_installer_mieru import pinned_client  # noqa: F401 — the autouse fixture of that module
from tests.test_installer_xray_router import FakeRunner, config, stage_archive
from tests.test_installer_xray_router import adapter as router_adapter
from tests.test_installer_xray_router import pinned_archive  # noqa: F401 — the autouse fixture of that module

ROOT = Path(__file__).resolve().parents[1]
TOML = """schema = 1
host_mode = "fresh"
profile = "full"
acme_email = "ops@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "proxy.example.com"
naive = "edge.example.com"
mieru = "mieru.example.com"

[mieru]
tcp_ports = [46001]
udp_ports = [46002]
{mieru_extra}
[egress]
warp = true
router = {router}
{egress_extra}
[three_xui]
mode = "none"

[firewall]
manage_ufw = true
"""


def _toml(*, router="true", mieru_extra="", egress_extra=""):
    return TOML.format(router=router, mieru_extra=mieru_extra, egress_extra=egress_extra)


# -- configuration ----------------------------------------------------------------------


def test_a_router_host_gets_the_relay_and_the_default_slots_and_writes_them_back():
    parsed = parse_config(_toml())
    assert parsed.egress.relay_port == DEFAULT_RELAY_PORT and parsed.mieru.lane_slots == 4
    assert parsed.mieru.slot_ports() == (46101, 46102, 46103, 46104)
    rendered = render_config(parsed)
    assert "relay_port = 45443" in rendered and "lane_slots = 4" in rendered
    assert parse_config(rendered) == parsed
    explicit = parse_config(_toml(mieru_extra="lane_slots = 2\n", egress_extra="relay_port = 45444\n"))
    assert explicit.egress.relay_port == 45444 and explicit.mieru.lane_slots == 2
    # without a router: no relay, no slots — and the keys refuse to stand alone
    plain = parse_config(_toml(router="false"))
    assert plain.egress.relay_port == 0 and plain.mieru.lane_slots == 0
    assert "relay_port" not in render_config(plain) and "lane_slots" not in render_config(plain)
    with pytest.raises(ConfigError, match="relay_port requires router"):
        parse_config(_toml(router="false", egress_extra="relay_port = 45443\n"))
    with pytest.raises(ConfigError, match="lane_slots requires egress.router"):
        parse_config(_toml(router="false", mieru_extra="lane_slots = 2\n"))
    with pytest.raises(ConfigError, match="lane_slots must be between"):
        parse_config(_toml(mieru_extra="lane_slots = 9\n"))
    with pytest.raises(ConfigError, match="collides"):
        parse_config(_toml(egress_extra="relay_port = 45101\n"))
    with pytest.raises(ConfigError, match="collide with the lane slot ports"):
        parse_config(_toml(mieru_extra="lane_slots = 2\n").replace("tcp_ports = [46001]", "tcp_ports = [46102]"))
    # slots switched off by hand on a router host stay off
    assert parse_config(_toml(mieru_extra="lane_slots = 0\n")).mieru.lane_slots == 0


def test_the_firewall_opens_the_relay_and_the_slot_ports():
    parsed = parse_config(_toml())
    assert set(_selected_ports(parsed)) >= {"tcp:45443", "tcp:46101", "tcp:46104", "tcp:46001", "udp:46002"}
    plain = parse_config(_toml(router="false"))
    assert not {port for port in _selected_ports(plain) if port in ("tcp:45443", "tcp:46101")}


# -- the router's relay ------------------------------------------------------------------


class RelayRunner(FakeRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.relay = {"enabled": False, "port": None, "server_name": None, "public_key": None, "short_ids": [], "accounts": 0}
        self.public = True
        self.enabled: list[tuple[str, int]] = []

    def router_relay_enable(self, server_name, port):
        self.enabled.append((server_name, port))
        if not self.relay["public_key"]:
            self.relay.update({"public_key": "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s", "short_ids": ["0123abcd"]})
        self.relay.update({"enabled": True, "port": port, "server_name": server_name})
        return dict(self.relay)

    def router_relay(self):
        return dict(self.relay)

    def public_listener(self, port):
        return self.public and port == self.relay["port"]


def _relay_config():
    base = config(warp=True)
    return replace(base, egress=replace(base.egress, relay_port=DEFAULT_RELAY_PORT))


def test_router_plan_carries_the_relay_and_refuses_a_claimed_relay_port(tmp_path):
    (action,) = router_adapter(tmp_path).plan(_relay_config(), AuditFacts())
    values = dict(item.split("=", 1) for item in action.mutations)
    assert values["relay-port"] == "45443" and values["relay-server-name"] == "panel.example.com"
    assert any("relay" in item for item in action.verification)
    (plain,) = router_adapter(tmp_path).plan(config(), AuditFacts())
    plain_values = dict(item.split("=", 1) for item in plain.mutations)
    assert plain_values["relay-port"] == "0" and plain_values["relay-server-name"] == ""
    facts = AuditFacts(listeners={"tcp": [45443], "owners": {"45443": ["nginx"]}})
    with pytest.raises(PlanError, match="45443 is already claimed"):
        router_adapter(tmp_path).plan(_relay_config(), facts)


def test_router_apply_enables_the_relay_and_verify_proves_its_public_part(tmp_path):
    stage_archive(tmp_path)
    runner = RelayRunner()
    instance = router_adapter(tmp_path, runner)
    (action,) = instance.plan(_relay_config(), AuditFacts())
    checkpoint = instance.apply(action, instance.prepare(action))
    assert runner.enabled == [("panel.example.com", 45443)]
    evidence = instance.verify(action)
    assert evidence.success and dict(evidence.details["relay"]) == {
        "port": 45443, "server_name": "panel.example.com", "public_key": "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s"}
    assert "private" not in repr(evidence.details)
    # repair asks again — the manager keeps its keypair, nothing is minted twice
    instance.repair(action, checkpoint)
    assert len(runner.enabled) == 2 and runner.relay["public_key"] == "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s"
    # a relay that does not listen, or is off, fails the verification
    runner.public = False
    with pytest.raises(XrayRouterError, match="does not listen on its public port"):
        instance.verify(action)
    runner.public, runner.relay["enabled"] = True, False
    with pytest.raises(XrayRouterError, match="not enabled on its port"):
        instance.verify(action)


def test_a_router_action_without_relay_keys_still_applies_and_verifies(tmp_path):
    """A v0.5/v0.6 action from a saved plan: no relay, no relay calls."""
    stage_archive(tmp_path)
    runner = RelayRunner()
    instance = router_adapter(tmp_path, runner)
    (action,) = instance.plan(config(), AuditFacts())
    stripped = Action(id=action.id, adapter=action.adapter, owner=action.owner,
                      mutations=tuple(item for item in action.mutations if not item.startswith("relay-")),
                      preconditions=action.preconditions, verification=action.verification, inverse=action.inverse,
                      credentials_required=action.credentials_required)
    instance.apply(stripped, instance.prepare(stripped))
    assert runner.enabled == []
    assert instance.verify(stripped).details["relay"] is None
    with pytest.raises(XrayRouterError, match="invalid relay server name"):
        instance._selection(Action(id=action.id, adapter=action.adapter, owner=action.owner,
                                   mutations=(*stripped.mutations, "relay-port=45443", "relay-server-name="),
                                   preconditions=action.preconditions, verification=action.verification,
                                   inverse=action.inverse, credentials_required=True))


def test_healthcheck_relay_flags_post_and_get(tmp_path, monkeypatch):
    import io
    import socket
    import sys
    import threading

    from xray_router_manager import healthcheck

    sock, token = tmp_path / "manager.sock", tmp_path / "token"
    token.write_text("t" * 40 + "\n")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock))
    server.listen(2)
    seen: list[bytes] = []

    def serve(count):
        with server:
            for _ in range(count):
                client, _ = server.accept()
                with client:
                    seen.append(client.recv(4096))
                    client.sendall(b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{"enabled": true, "port": 45443}')

    thread = threading.Thread(target=serve, args=(2,))
    thread.start()
    monkeypatch.setenv("XRAY_ROUTER_SOCKET", str(sock))
    monkeypatch.setenv("XRAY_ROUTER_MANAGER_TOKEN_FILE", str(token))
    buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buffer))
    with pytest.raises(SystemExit) as raised:
        healthcheck.main(["--relay-enable", "panel.example.com", "45443"])
    assert raised.value.code == 0
    with pytest.raises(SystemExit) as raised:
        healthcheck.main(["--relay"])
    thread.join(timeout=5)
    assert raised.value.code == 0
    assert seen[0].startswith(b"POST /v1/relay ") and b'{"server_name": "panel.example.com", "port": 45443}' in seen[0]
    assert seen[1].startswith(b"GET /v1/relay ")
    with pytest.raises(SystemExit):
        healthcheck.main(["--relay-enable", "panel.example.com"])


# -- Mieru lane slots ---------------------------------------------------------------------


class SlotRunner(FakeMieruRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.slot_status = mieru_module._IDLE
        self.slots_asked: list[str] = []

    def mita_slot_status(self, socket_path):
        self.slots_asked.append(socket_path)
        return self.slot_status


def _slot_config(slots: int = 2):
    base = full_config(profile=Profile.FULL)
    return replace(base, mieru=MieruConfig(tcp_ports=(46001,), udp_ports=(46002,), lane_slots=slots),
                   egress=EgressConfig(warp=True, router=True, mieru=EgressChoice.ROUTER, relay_port=DEFAULT_RELAY_PORT))


def _slot_action(tmp_path, slots: int = 2) -> Action:
    base = artifact_action(fake_deb(tmp_path))
    planned = mieru_module.MieruAdapter(source_dir=ROOT).plan(_slot_config(slots), AuditFacts())[0]
    keep = {"package-digest", "executable-digest", "package"}
    mutations = tuple(item for item in base.mutations if item.split("=", 1)[0] in keep)
    mutations += tuple(item for item in planned.mutations if item.split("=", 1)[0] not in keep)
    return Action(id=planned.id, adapter=planned.adapter, owner=planned.owner, mutations=mutations,
                  preconditions=planned.preconditions, verification=planned.verification, inverse=planned.inverse,
                  credentials_required=planned.credentials_required)


def _stage_router(tmp_path):
    secret = host(tmp_path, f"{mieru_module.MieruPaths().project_dir}/secrets/xray-router-ingress-mieru")
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_text("mieru-cafe0001:" + "k" * 43 + "\n")
    secret.chmod(0o600)
    host(tmp_path, f"{mieru_module.MieruPaths().project_dir}/.env.xray-router").write_text("XRAY_ROUTER_BIN_DIR=/x\n")


def test_mieru_plan_carries_the_slots_and_refuses_a_collision():
    action = mieru_module.MieruAdapter(source_dir=ROOT).plan(_slot_config(3), AuditFacts())[0]
    assert "lane-slots=3" in action.mutations and any("lane slot" in item for item in action.verification)
    plain = mieru_module.MieruAdapter(source_dir=ROOT).plan(full_config(), AuditFacts())[0]
    assert "lane-slots=0" in plain.mutations
    facts = AuditFacts(listeners={"tcp": [46102], "owners": {"46102": ["nginx"]}})
    with pytest.raises(PlanError):
        mieru_module.MieruAdapter(source_dir=ROOT).plan(_slot_config(3), facts)
    collision = replace(_slot_config(2), mieru=MieruConfig(tcp_ports=(46101,), udp_ports=(), lane_slots=2))
    with pytest.raises(PlanError, match="collide"):
        mieru_module.MieruAdapter(source_dir=ROOT).plan(collision, AuditFacts())


def test_mieru_apply_starts_the_slot_units_and_verify_and_repair_check_them(tmp_path):
    _stage_router(tmp_path)
    runner = SlotRunner()
    instance = mieru_adapter(tmp_path, runner)
    action = _slot_action(tmp_path, 2)
    checkpoint = instance.apply(action, instance.prepare(action))
    assert ("systemctl", "enable", "--now", "mita@1") in runner.calls and ("systemctl", "enable", "--now", "mita@2") in runner.calls
    assert runner.slots_asked == ["/run/mita/lane-1.sock", "/run/mita/lane-2.sock"]
    unit = host(tmp_path, mieru_module.MieruPaths().slot_unit)
    assert unit.is_file() and "MITA_UDS_PATH=/run/mita/lane-%i.sock" in unit.read_text()
    env = host(tmp_path, mieru_module.MieruPaths().env_overlay).read_text()
    assert "MIERU_LANE_SLOTS=1:46101:/run/mita/lane-1.sock:/var/lib/mita/lanes/1,2:46102:/run/mita/lane-2.sock:/var/lib/mita/lanes/2\n" in env
    evidence = instance.verify(action)
    assert [dict(slot) for slot in evidence.details["lane_slots"]] == [{"index": 1, "port": 46101}, {"index": 2, "port": 46102}]
    # a slot already running a lane is as good as an idle one; a silent one is not
    runner.slot_status = mieru_module._RUNNING
    assert instance.verify(action).success
    runner.slot_status = "exit=1"
    with pytest.raises(MieruError, match="lane slot 1 did not answer"):
        instance._assert_slots(instance._selection(action), patience=0.6)
    # a daemon whose RPC server is still coming up answers on the second ask
    answers = iter(["exit=1", mieru_module._IDLE, mieru_module._IDLE])
    runner.mita_slot_status = lambda socket_path: next(answers)
    instance._assert_slots(instance._selection(action), patience=5)
    del runner.mita_slot_status  # back to the class method
    runner.slot_status = mieru_module._IDLE
    runner.calls.clear()
    instance.repair(action, checkpoint)
    assert ("systemctl", "enable", "--now", "mita@2") in runner.calls
    # rollback stops the slot units; purge removes the slot state with the rest
    slot_state = host(tmp_path, "/var/lib/mita/lanes/1")
    slot_state.mkdir(parents=True)
    (slot_state / "server_config.json").write_text("{}")
    evidence = instance.rollback(action, checkpoint)
    assert ("systemctl", "disable", "--now", "mita@1") in runner.calls and slot_state.exists()
    assert not unit.exists()
    instance.rollback(action, checkpoint, purge_data=True, rollback_target="uninstalled")
    assert not slot_state.exists()


def test_mieru_without_slots_starts_none_and_a_slotted_action_needs_the_router(tmp_path):
    runner = SlotRunner()
    instance = mieru_adapter(tmp_path, runner)
    action = artifact_action(fake_deb(tmp_path))
    instance.apply(action, instance.prepare(action))
    assert not any(call[-1].startswith("mita@") for call in runner.calls if call[:2] == ("systemctl", "enable"))
    assert runner.slots_asked == []
    assert "MIERU_LANE_SLOTS=\n" in host(tmp_path, mieru_module.MieruPaths().env_overlay).read_text()
    bad = Action(id=action.id, adapter=action.adapter, owner=action.owner,
                 mutations=tuple("lane-slots=2" if item.startswith("lane-slots=") else item for item in action.mutations),
                 preconditions=action.preconditions, verification=action.verification, inverse=action.inverse,
                 credentials_required=True)
    with pytest.raises(MieruError, match="need the node's Xray-router"):
        instance._selection(bad)


def test_the_compose_overlay_passes_the_slots_to_the_manager():
    text = (ROOT / "compose.mieru.yaml").read_text()
    assert "MIERU_LANE_SLOTS: ${MIERU_LANE_SLOTS:-}" in text
    assert (ROOT / "deploy/mita@.service").read_text().count("%i") >= 3
    assert router_module._DOMAIN.fullmatch("panel.example.com")
