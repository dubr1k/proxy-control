"""The optional AmneziaWG add-on in the installer: configuration, plan, firewall rules, the
adapter's lifecycle with a fake host, and the places that must know the new overlay."""
from __future__ import annotations

import dataclasses
import json
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from installer.adapters.amneziawg import (
    _HEALTH_SCRIPT,
    AmneziaWgAdapter,
    AmneziaWgError,
    AmneziaWgPaths,
    _DefaultAmneziaWgRunner,
)
from installer.adapters.firewall import (
    _HEADER,
    FirewallAdapter,
    FirewallError,
    _selected_ports,
    parse_ufw_status,
)
from installer.config import ConfigError, parse_config, render_config
from installer.model import AWG_VERSIONS, HostMode
from installer.planner import (
    Action,
    AuditFacts,
    PlanError,
    adapters_for,
    compose_file_list,
)

ROOT = Path(__file__).resolve().parents[1]

BASE = """
schema = 1
host_mode = "fresh"
profile = "core"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"

{extra}

[three_xui]
mode = "none"

[firewall]
manage_ufw = {ufw}
"""

MIERU_BASE = """
schema = 1
host_mode = "fresh"
profile = "core-mieru"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"
mieru = "mieru.example.com"

[mieru]
tcp_ports = [46001]
udp_ports = [46002]

{extra}

[three_xui]
mode = "none"

[firewall]
manage_ufw = true
"""


# Fixture ports (the installer itself never defaults to these well-known ones): the adapter tests
# below need a resolved configuration, so `cfg` assigns them to the versions the TOML leaves open.
TEST_PORTS = {"1.5": 51820, "2.0": 51821, "3.1": 51822}


def assign_test_ports(config):
    awg = config.amneziawg
    if awg is None or all(awg.ports):
        return config
    ports = tuple(port or TEST_PORTS[version] for version, port in zip(awg.versions, awg.ports, strict=True))
    return dataclasses.replace(config, amneziawg=dataclasses.replace(awg, ports=ports))


def cfg(extra: str = "[amneziawg]\nenabled = true\n", *, ufw: str = "true"):
    return assign_test_ports(parse_config(BASE.format(extra=extra, ufw=ufw)))


# -- configuration ---------------------------------------------------------------------


def test_the_defaults_cover_all_three_versions_and_the_panel_name():
    awg = cfg().amneziawg
    assert awg is not None
    assert awg.versions == AWG_VERSIONS == ("1.5", "2.0", "3.1")
    assert awg.port_map() == TEST_PORTS
    assert awg.host == "panel.example.com"
    assert awg.mtu == 1280 and awg.dns == ("1.1.1.1", "1.0.0.1")
    assert awg.interfaces() == ("awg15", "awg20", "awg31")


def test_absent_or_disabled_section_means_no_amneziawg():
    assert cfg("").amneziawg is None
    assert cfg("[amneziawg]\nenabled = false\n").amneziawg is None
    assert cfg("[amneziawg]\n").amneziawg is None


def test_a_disabled_section_refuses_settings():
    with pytest.raises(ConfigError, match="enabled is false"):
        cfg('[amneziawg]\nenabled = false\nversions = ["2.0"]\n')


def test_every_key_can_be_set_and_the_order_is_canonical():
    awg = cfg(
        '[amneziawg]\nenabled = true\nversions = ["3.1", "1.5"]\nhost = "198.51.100.7"\n'
        'ports = { "1.5" = 40000, "3.1" = 40001 }\nmtu = 1380\ndns = ["9.9.9.9", "2620:fe::fe"]\n'
    ).amneziawg
    assert awg is not None
    assert awg.versions == ("1.5", "3.1")
    assert awg.port_map() == {"1.5": 40000, "3.1": 40001}
    assert awg.host == "198.51.100.7" and awg.mtu == 1380
    assert awg.dns == ("9.9.9.9", "2620:fe::fe")
    assert awg.interfaces() == ("awg15", "awg31")


def test_the_host_is_normalised_dns_name_or_ipv4():
    assert cfg('[amneziawg]\nenabled = true\nhost = "VPN.Example.COM."\n').amneziawg.host == "vpn.example.com"


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ('[amneziawg]\nenabled = true\nbogus = 1\n', "unknown key: amneziawg.bogus"),
        ('[amneziawg]\nenabled = "yes"\n', "amneziawg.enabled must be a boolean"),
        ('[amneziawg]\nenabled = true\nversions = []\n', "non-empty array"),
        ('[amneziawg]\nenabled = true\nversions = ["4.0"]\n', "unknown amneziawg version"),
        ('[amneziawg]\nenabled = true\nversions = ["2.0", "2.0"]\n', "duplicates"),
        ('[amneziawg]\nenabled = true\nversions = [2.0]\n', "must be a string"),
        ('[amneziawg]\nenabled = true\nhost = "not_a_host"\n', "DNS name or an IPv4"),
        ('[amneziawg]\nenabled = true\nhost = "2001:db8::1"\n', "DNS name or an IPv4"),
        ('[amneziawg]\nenabled = true\nhost = "localhost"\n', "DNS name or an IPv4"),
        ('[amneziawg]\nenabled = true\nports = { "1.5" = 80 }\n', "between 1024 and 65535"),
        ('[amneziawg]\nenabled = true\nports = { "1.5" = 70000 }\n', "between 1024 and 65535"),
        ('[amneziawg]\nenabled = true\nports = { "1.5" = 51821, "2.0" = 51821 }\n', "distinct"),
        ('[amneziawg]\nenabled = true\nports = { "9.9" = 51821 }\n', "unknown amneziawg version"),
        ('[amneziawg]\nenabled = true\nversions = ["1.5"]\nports = { "2.0" = 51821 }\n', "not enabled"),
        ('[amneziawg]\nenabled = true\nports = { "1.5" = "x" }\n', "must be an integer"),
        ('[amneziawg]\nenabled = true\nports = [51820]\n', "must be a table"),
        ('[amneziawg]\nenabled = true\nmtu = 1200\n', "between 1280 and 1420"),
        ('[amneziawg]\nenabled = true\nmtu = 1500\n', "between 1280 and 1420"),
        ('[amneziawg]\nenabled = true\ndns = []\n', "one to four"),
        ('[amneziawg]\nenabled = true\ndns = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]\n', "one to four"),
        ('[amneziawg]\nenabled = true\ndns = ["dns.example.com"]\n', "invalid address"),
        ('[amneziawg]\nenabled = true\ndns = ["1.1.1.1", "1.1.1.1"]\n', "duplicates"),
    ],
)
def test_configuration_rejections(extra: str, message: str):
    with pytest.raises(ConfigError, match=message):
        cfg(extra)


@pytest.mark.parametrize(
    ("port", "owner"),
    [(8443, "private TLS"), (8445, "MTProxy backend"), (8787, "panel application"), (1024, None)],
)
def test_ports_colliding_with_the_installers_own_are_refused(port: int, owner: str | None):
    extra = f'[amneziawg]\nenabled = true\nversions = ["2.0"]\nports = {{ "2.0" = {port} }}\n'
    if owner is None:
        assert cfg(extra).amneziawg.port_map() == {"2.0": 1024}
        return
    with pytest.raises(ConfigError, match=f"amneziawg.ports.2.0: {port} is taken by .*{owner}"):
        cfg(extra)


def test_ports_colliding_with_mieru_tcp_or_udp_are_refused():
    for port in (46001, 46002):
        extra = f'[amneziawg]\nenabled = true\nversions = ["1.5"]\nports = {{ "1.5" = {port} }}\n'
        with pytest.raises(ConfigError, match="Mieru"):
            parse_config(MIERU_BASE.format(extra=extra))


def test_ports_colliding_with_the_router_ports_are_refused():
    extra = '[amneziawg]\nenabled = true\nversions = ["1.5"]\nports = { "1.5" = 45101 }\n'
    text = MIERU_BASE.format(extra=extra + '\n[egress]\nrouter = true\nmieru = "router"\n')
    with pytest.raises(ConfigError, match="Xray-router"):
        parse_config(text)


def test_the_section_round_trips_through_render_config():
    config = cfg(
        '[amneziawg]\nenabled = true\nversions = ["2.0", "3.1"]\nhost = "vpn.example.com"\n'
        'ports = { "2.0" = 41000, "3.1" = 41001 }\nmtu = 1400\ndns = ["9.9.9.9"]\n'
    )
    rendered = render_config(config)
    assert "[amneziawg]" in rendered and "enabled = true" in rendered
    assert parse_config(rendered) == config
    assert "[amneziawg]" not in render_config(cfg(""))


def test_amneziawg_needs_no_domain_and_no_new_profile():
    plain = cfg("")
    awg = cfg()
    assert awg.required_domains() == plain.required_domains()
    assert awg.profile == plain.profile
    assert dataclasses.replace(awg, amneziawg=None) == plain


def test_the_canonical_form_carries_the_section_without_secrets():
    canonical = cfg().canonical_dict()
    assert canonical["amneziawg"]["versions"] == ["1.5", "2.0", "3.1"]
    assert "token" not in json.dumps(canonical).lower()


def test_the_shipped_example_loads_and_enables_the_add_on():
    from installer.config import load_config

    config = load_config(ROOT / "examples" / "installer" / "core-amneziawg.toml")
    assert config.amneziawg is not None and config.amneziawg.versions == AWG_VERSIONS


# -- the planner -----------------------------------------------------------------------


def test_the_adapter_and_the_overlay_are_selected_exactly_when_enabled():
    names = [adapter.name for adapter in adapters_for(cfg())]
    assert "amneziawg" in names
    assert names.index("amneziawg") > names.index("core")
    assert names.index("amneziawg") < names.index("version_agent")
    assert "amneziawg" not in [adapter.name for adapter in adapters_for(cfg(""))]
    assert compose_file_list(cfg()) == ("compose.yaml", "compose.amneziawg.yaml")
    assert compose_file_list(cfg("")) == ("compose.yaml",)


def test_the_overlay_follows_the_other_overlays_in_the_file_list():
    config = parse_config(MIERU_BASE.format(extra='[amneziawg]\nenabled = true\n'))
    files = compose_file_list(config)
    assert files == ("compose.yaml", "compose.mieru.yaml", "compose.amneziawg.yaml")


# -- the adapter -----------------------------------------------------------------------


class FakeRunner:
    def __init__(self, *, health: str = "healthy", report: dict | None = None, listening: bool | set | None = True):
        self.health = health
        self.report = report
        self.listening = listening
        self.calls: list[tuple[str, ...]] = []
        self.present = False
        self.fail_on: tuple[str, ...] | None = None

    def run(self, argv: Sequence[str], *, stdin_path=None):
        del stdin_path
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        if self.fail_on and command[: len(self.fail_on)] == self.fail_on:
            return subprocess.CompletedProcess(command, 1, "", "boom token=SECRET123")
        if "up" in command:
            self.present = True
        if "rm" in command and "--stop" in command:
            self.present = False
        return subprocess.CompletedProcess(command, 0, "", "")

    def compose_service_present(self, service: str) -> bool:
        return self.present and service == "awg-manager"

    def container_health(self) -> str:
        return self.health

    def manager_health(self) -> dict:
        if self.report is not None:
            return self.report
        return {
            "status": "ok",
            "ip_forward": True,
            "instances": {
                "1.5": {"interface": "awg15", "running": True, "port": 51820, "peers": 0},
                "2.0": {"interface": "awg20", "running": True, "port": 51821, "peers": 0},
                "3.1": {"interface": "awg31", "running": True, "port": 51822, "peers": 0},
            },
        }

    def udp_listener(self, port: int) -> bool:
        if isinstance(self.listening, set):
            return port in self.listening
        return bool(self.listening)


def make_root(tmp_path: Path) -> Path:
    tun = tmp_path / "dev" / "net" / "tun"
    tun.parent.mkdir(parents=True)
    tun.write_text("")
    return tmp_path


def adapter_for(tmp_path: Path, runner: FakeRunner | None = None) -> AmneziaWgAdapter:
    return AmneziaWgAdapter(root=make_root(tmp_path) if not (tmp_path / "dev").exists() else tmp_path,
                            runner=runner or FakeRunner())


def host(tmp_path: Path, absolute: str) -> Path:
    return tmp_path / absolute.lstrip("/")


def planned(tmp_path: Path, config=None, runner=None) -> tuple[AmneziaWgAdapter, Action]:
    adapter = adapter_for(tmp_path, runner)
    (action,) = adapter.plan(config or cfg(), AuditFacts())
    return adapter, action


def test_the_plan_is_deterministic_secret_free_and_complete(tmp_path):
    adapter, action = planned(tmp_path)
    again = adapter.plan(cfg(), AuditFacts())
    assert (action,) == again
    values = dict(item.split("=", 1) for item in action.mutations)
    assert action.id == "amneziawg.runtime" and action.owner == "proxy-control:amneziawg"
    assert values["versions"] == "1.5,2.0,3.1"
    assert values["ports"] == "1.5:51820,2.0:51821,3.1:51822"
    assert values["interfaces"] == "awg15,awg20,awg31"
    assert values["state-dir"] == "/var/lib/awg-manager"
    assert values["sysctl-file"] == "/etc/sysctl.d/99-proxy-control-amneziawg.conf"
    assert values["host"] == "panel.example.com" and values["socket-gid"] == "10007"
    assert not any("secret" in item.lower() or "password" in item.lower() for item in action.mutations)
    assert adapter.plan(cfg(""), AuditFacts()) == ()
    assert any("UFW" in item for item in action.preconditions)


def test_without_a_managed_ufw_the_plan_tells_the_operator_to_open_the_ports(tmp_path):
    _, action = planned(tmp_path, cfg(ufw="false"))
    assert any("operator opens the selected UDP ports" in item for item in action.preconditions)
    coexist = parse_config(BASE.format(extra="[amneziawg]\nenabled = true\n", ufw="false").replace(
        'host_mode = "fresh"', 'host_mode = "coexist"'))
    coexist = assign_test_ports(coexist)
    assert coexist.host_mode is HostMode.COEXIST
    _, action = planned(tmp_path, coexist)
    assert any("operator opens the selected UDP ports" in item for item in action.preconditions)


def test_the_plan_fails_clearly_without_dev_net_tun(tmp_path):
    adapter = AmneziaWgAdapter(root=tmp_path, runner=FakeRunner())
    with pytest.raises(PlanError, match=r"/dev/net/tun.*modprobe tun"):
        adapter.plan(cfg(), AuditFacts())


def test_the_plan_refuses_a_claimed_udp_port_but_accepts_its_own_listener(tmp_path):
    adapter = adapter_for(tmp_path)
    foreign = AuditFacts(listeners={"udp": [51821], "owners": {"51821": ["wireguard"]}})
    with pytest.raises(PlanError, match="51821/udp is already claimed"):
        adapter.plan(cfg(), foreign)
    own = AuditFacts(listeners={"udp": [51820, 51821], "owners": {"51820": ["amneziawg-go"], "51821": ["amneziawg-go"]}})
    assert adapter.plan(cfg(), own)
    unknown_owner = AuditFacts(listeners={"udp": [51820]})
    with pytest.raises(PlanError, match="51820/udp"):
        adapter.plan(cfg(), unknown_owner)


def test_apply_writes_every_owned_file_and_starts_the_service(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    checkpoint = adapter.prepare(action)
    result = adapter.apply(action, checkpoint)

    sysctl = host(tmp_path, "/etc/sysctl.d/99-proxy-control-amneziawg.conf")
    assert sysctl.read_text() == (
        "# Managed by Proxy Control (AmneziaWG): the tunnels forward clients' packets to the Internet.\n"
        "net.ipv4.ip_forward = 1\n"
    )
    assert ("sysctl", "-p", "/etc/sysctl.d/99-proxy-control-amneziawg.conf") in runner.calls
    state = host(tmp_path, "/var/lib/awg-manager")
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    token = host(tmp_path, "/opt/mtproxy-shared443/secrets/awg-manager-token")
    assert stat.S_IMODE(token.stat().st_mode) == 0o600 and len(token.read_text().strip()) == 64
    env = host(tmp_path, "/opt/mtproxy-shared443/.env.amneziawg")
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert env.read_text() == (
        "AWG_MANAGER_TOKEN_FILE=/opt/mtproxy-shared443/secrets/awg-manager-token\n"
        "AWG_MANAGER_STATE_DIR=/var/lib/awg-manager\n"
        "AWG_VERSIONS=1.5,2.0,3.1\n"
        "AWG_PORTS=1.5=51820,2.0=51821,3.1=51822\n"
        "AWG_SUBNETS=1.5=10.66.15.0/24,2.0=10.66.20.0/24,3.1=10.66.31.0/24\n"
        "AWG_MTU=1280\n"
        "AWG_DNS=1.1.1.1,1.0.0.1\n"
        "AWG_MANAGER_SOCKET_GID=10007\n"
        "AMNEZIAWG_PUBLIC_HOST=panel.example.com\n"
    )
    assert token.read_text().strip() not in env.read_text()
    marker = host(tmp_path, "/etc/proxy-control/amneziawg-owned")
    assert marker.is_file() and stat.S_IMODE(marker.stat().st_mode) == 0o600
    up = next(call for call in runner.calls if "up" in call)
    assert up[:2] == ("docker", "compose") and up[-4:] == ("up", "-d", "--build", "--wait")
    assert "/opt/mtproxy-shared443/.env.amneziawg" in up and "/opt/mtproxy-shared443/compose.amneziawg.yaml" in up
    assert str(env) not in " ".join(up)
    assert set(result["ownership"]) == {
        "/opt/mtproxy-shared443/.env.amneziawg", "/etc/proxy-control/amneziawg-owned",
        "/etc/sysctl.d/99-proxy-control-amneziawg.conf",
    }
    assert token.read_text().strip() not in json.dumps(result)


def test_a_subset_with_custom_values_reaches_the_env_overlay(tmp_path):
    config = cfg('[amneziawg]\nenabled = true\nversions = ["2.0"]\nhost = "198.51.100.9"\n'
                 'ports = { "2.0" = 41000 }\nmtu = 1400\ndns = ["9.9.9.9"]\n')
    adapter, action = planned(tmp_path, config)
    adapter.apply(action, adapter.prepare(action))
    text = host(tmp_path, "/opt/mtproxy-shared443/.env.amneziawg").read_text()
    assert "AWG_VERSIONS=2.0\n" in text and "AWG_PORTS=2.0=41000\n" in text
    assert "AWG_SUBNETS=2.0=10.66.20.0/24\n" in text and "AWG_MTU=1400\n" in text
    assert "AWG_DNS=9.9.9.9\n" in text and "AMNEZIAWG_PUBLIC_HOST=198.51.100.9\n" in text


def test_the_compose_call_carries_the_sibling_overlays_present(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    project = host(tmp_path, "/opt/mtproxy-shared443")
    project.mkdir(parents=True)
    (project / ".env.mieru").write_text("X=1\n")
    adapter.apply(action, adapter.prepare(action))
    up = next(call for call in runner.calls if "up" in call)
    assert "/opt/mtproxy-shared443/compose.mieru.yaml" in up and "/opt/mtproxy-shared443/compose.naive.yaml" not in up


def test_an_existing_token_is_kept_and_a_world_readable_one_is_refused(tmp_path):
    adapter, action = planned(tmp_path)
    token = host(tmp_path, "/opt/mtproxy-shared443/secrets/awg-manager-token")
    token.parent.mkdir(parents=True)
    token.write_text("a" * 64 + "\n")
    token.chmod(0o600)
    checkpoint = adapter.apply(action, adapter.prepare(action))
    assert token.read_text() == "a" * 64 + "\n"
    token.chmod(0o644)
    with pytest.raises(AmneziaWgError, match="unsafe"):
        adapter.repair(action, checkpoint)
    token.chmod(0o600)
    token.write_text("short\n")
    with pytest.raises(AmneziaWgError, match="malformed"):
        adapter.repair(action, checkpoint)


def test_apply_refuses_a_missing_tun_device_and_a_failing_command_hides_stderr_secrets(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    runner.fail_on = ("docker", "compose")
    with pytest.raises(AmneziaWgError) as caught:
        adapter.apply(action, adapter.prepare(action))
    assert "SECRET123" not in str(caught.value) and "AmneziaWG command failed: docker compose" in str(caught.value)
    host(tmp_path, "/dev/net/tun").unlink()
    with pytest.raises(AmneziaWgError, match="tun"):
        adapter.prepare(action)


def test_prepare_refuses_a_foreign_sysctl_file_and_an_unowned_running_service(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    sysctl = host(tmp_path, "/etc/sysctl.d/99-proxy-control-amneziawg.conf")
    sysctl.parent.mkdir(parents=True)
    sysctl.write_text("net.ipv4.ip_forward = 0\n")
    with pytest.raises(AmneziaWgError, match="foreign file"):
        adapter.prepare(action)
    sysctl.unlink()
    runner.present = True
    with pytest.raises(AmneziaWgError, match="owned recovery"):
        adapter.prepare(action)


def test_a_foreign_or_malformed_checkpoint_is_refused(tmp_path):
    adapter, action = planned(tmp_path)
    good = dict(adapter.prepare(action))
    for bad in ({**good, "owner": "x"}, {**good, "adoption": "weird"}, {**good, "marker_value": "zz"},
                {k: v for k, v in good.items() if k != "ownership"}, {**good, "ownership": {"a": "b"}},
                {**good, "state_preexisting": "yes"}):
        with pytest.raises(AmneziaWgError, match="checkpoint"):
            adapter.apply(action, bad)


def test_a_tampered_action_is_refused(tmp_path):
    adapter, action = planned(tmp_path)
    for index, replacement in (
        (0, "project=/elsewhere"),
        (3, "ip-forward=0"),
        (5, "ports=1.5:80,2.0:51821,3.1:51822"),
        (5, "ports=1.5:51820,2.0:51820,3.1:51822"),
        (7, "host=bad_host"),
        (8, "mtu=9000"),
        (9, "dns="),
    ):
        mutations = list(action.mutations)
        mutations[index] = replacement
        with pytest.raises(AmneziaWgError):
            adapter.prepare(dataclasses.replace(action, mutations=tuple(mutations)))


def applied(tmp_path: Path, runner: FakeRunner | None = None):
    runner = runner or FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    checkpoint = adapter.apply(action, adapter.prepare(action))
    return adapter, action, checkpoint, runner


def test_verify_accepts_a_healthy_manager_and_reports_ports(tmp_path):
    adapter, action, _, _ = applied(tmp_path)
    evidence = adapter.verify(action)
    assert evidence.success and evidence.details["ports"] == {"1.5": 51820, "2.0": 51821, "3.1": 51822}
    assert list(evidence.details["interfaces"]) == ["awg15", "awg20", "awg31"]
    assert any("keep the UDP ports open" in item for item in evidence.observations)


def _degraded(report):
    report["status"] = "degraded"
    return report


@pytest.mark.parametrize(
    ("runner_kwargs", "mutate", "message"),
    [
        ({"health": "unhealthy"}, None, "not healthy"),
        ({"health": "starting"}, None, "not healthy"),
        ({"listening": False}, None, "does not listen"),
        ({"listening": {51820, 51821}}, None, "3.1 does not listen on 51822"),
        (None, lambda r: _degraded(r), "healthy state"),
        (None, lambda r: {**r, "ip_forward": False}, "healthy state"),
        (None, lambda r: {**r, "instances": {k: v for k, v in r["instances"].items() if k != "3.1"}}, "healthy state"),
        (None, lambda r: {**r, "instances": {**r["instances"], "2.0": {**r["instances"]["2.0"], "running": False}}},
         "2.0 is not running"),
        (None, lambda r: {**r, "instances": {**r["instances"], "1.5": {**r["instances"]["1.5"], "port": 1}}},
         "planned port"),
    ],
)
def test_verify_failure_paths(tmp_path, runner_kwargs, mutate, message):
    runner = FakeRunner(**(runner_kwargs or {}))
    adapter, action, _, _ = applied(tmp_path, runner)
    if mutate is not None:
        runner.report = mutate(FakeRunner().manager_health())
    with pytest.raises(AmneziaWgError, match=message):
        adapter.verify(action)


def test_verify_notices_a_drifted_sysctl_file_and_a_lost_state_directory(tmp_path):
    adapter, action, _, _ = applied(tmp_path)
    sysctl = host(tmp_path, "/etc/sysctl.d/99-proxy-control-amneziawg.conf")
    original = sysctl.read_text()
    sysctl.write_text("net.ipv4.ip_forward = 0\n")
    with pytest.raises(AmneziaWgError, match="sysctl"):
        adapter.verify(action)
    sysctl.write_text(original)
    host(tmp_path, "/var/lib/awg-manager").rmdir()
    with pytest.raises(AmneziaWgError, match="state directory"):
        adapter.verify(action)


def test_repair_rewrites_the_overlay_and_restarts_without_a_rebuild(tmp_path):
    adapter, action, checkpoint, runner = applied(tmp_path)
    host(tmp_path, "/opt/mtproxy-shared443/.env.amneziawg").unlink()
    runner.calls.clear()
    adapter.repair(action, checkpoint)
    assert host(tmp_path, "/opt/mtproxy-shared443/.env.amneziawg").is_file()
    up = next(call for call in runner.calls if "up" in call)
    assert up[-3:] == ("up", "-d", "--wait") and "--build" not in up


def test_uninstall_keeps_the_state_and_the_token_unless_purged(tmp_path):
    adapter, action, checkpoint, runner = applied(tmp_path)
    key = host(tmp_path, "/var/lib/awg-manager/server.json")
    key.write_text("{}")
    evidence = adapter.rollback(action, checkpoint, rollback_target="uninstalled")
    assert evidence.details["persistent_data_preserved"] is True
    assert key.is_file()
    assert host(tmp_path, "/opt/mtproxy-shared443/secrets/awg-manager-token").is_file()
    for removed in ("/opt/mtproxy-shared443/.env.amneziawg", "/etc/proxy-control/amneziawg-owned",
                    "/etc/sysctl.d/99-proxy-control-amneziawg.conf"):
        assert not host(tmp_path, removed).exists(), removed
    assert any(call[-4:] == ("rm", "--stop", "--force", "awg-manager") for call in runner.calls)


def test_uninstall_with_purge_removes_the_state_and_the_token(tmp_path):
    adapter, action, checkpoint, _ = applied(tmp_path)
    (host(tmp_path, "/var/lib/awg-manager") / "server.json").write_text("{}")
    evidence = adapter.rollback(action, checkpoint, purge_data=True, rollback_target="uninstalled")
    assert evidence.details["persistent_data_preserved"] is False
    assert not host(tmp_path, "/var/lib/awg-manager").exists()
    assert not host(tmp_path, "/opt/mtproxy-shared443/secrets/awg-manager-token").exists()


def test_a_purge_flag_alone_does_not_destroy_data_on_a_plain_rollback(tmp_path):
    adapter, action, checkpoint, _ = applied(tmp_path)
    (host(tmp_path, "/var/lib/awg-manager") / "server.json").write_text("{}")
    adapter.rollback(action, checkpoint, purge_data=True, rollback_target="rolled_back")
    assert host(tmp_path, "/var/lib/awg-manager/server.json").is_file()


def test_a_rollback_removes_a_state_directory_it_created_and_left_empty(tmp_path):
    adapter, action, checkpoint, _ = applied(tmp_path)
    adapter.rollback(action, checkpoint)
    assert not host(tmp_path, "/var/lib/awg-manager").exists()
    adapter2, action2, checkpoint2, _ = applied(tmp_path / "second")
    assert checkpoint2["state_preexisting"] is False


def test_a_preexisting_state_directory_survives_a_plain_rollback(tmp_path):
    state = host(tmp_path, "/var/lib/awg-manager")
    state.mkdir(parents=True)
    adapter, action, checkpoint, _ = applied(tmp_path)
    assert checkpoint["state_preexisting"] is True
    adapter.rollback(action, checkpoint)
    assert state.is_dir()


def test_rollback_rejects_an_unknown_target(tmp_path):
    adapter, action, checkpoint, _ = applied(tmp_path)
    with pytest.raises(ValueError):
        adapter.rollback(action, checkpoint, rollback_target="bogus")


def test_the_default_runner_asks_health_inside_the_container_without_the_token(monkeypatch):
    runner = _DefaultAmneziaWgRunner()
    seen: list[tuple[str, ...]] = []
    monkeypatch.setattr(_DefaultAmneziaWgRunner, "_capture_checked",
                        lambda self, argv: seen.append(tuple(argv)) or '{"status": "ok", "instances": {}}')
    assert runner.manager_health() == {"status": "ok", "instances": {}}
    argv = seen[0]
    assert argv[:5] == ("docker", "exec", "proxy-control-awg-manager", "python", "-c")
    assert "AWG_MANAGER_TOKEN_FILE" in argv[5] and "X-Awg-Token" in argv[5]
    assert argv[5] == _HEALTH_SCRIPT
    compile(_HEALTH_SCRIPT, "<health>", "exec")


def test_the_default_runner_rejects_a_non_object_health(monkeypatch):
    monkeypatch.setattr(_DefaultAmneziaWgRunner, "_capture_checked", lambda self, argv: "[1]")
    with pytest.raises(AmneziaWgError, match="not an object"):
        _DefaultAmneziaWgRunner().manager_health()
    monkeypatch.setattr(_DefaultAmneziaWgRunner, "_capture_checked", lambda self, argv: "no json")
    with pytest.raises(AmneziaWgError, match="not JSON"):
        _DefaultAmneziaWgRunner().manager_health()


def test_the_default_runner_reads_udp_listeners_from_ss(monkeypatch):
    runner = _DefaultAmneziaWgRunner()
    monkeypatch.setattr(_DefaultAmneziaWgRunner, "capture",
                        lambda self, argv, max_chars: "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n")
    assert runner.udp_listener(51820) is True
    monkeypatch.setattr(_DefaultAmneziaWgRunner, "capture", lambda self, argv, max_chars: "")
    assert runner.udp_listener(51820) is False
    monkeypatch.setattr(_DefaultAmneziaWgRunner, "capture", lambda self, argv, max_chars: "exit=1")
    assert runner.udp_listener(51820) is False


def test_paths_must_be_absolute_and_normalised():
    with pytest.raises(ValueError):
        AmneziaWgPaths(state_dir="relative")
    with pytest.raises(ValueError):
        AmneziaWgPaths(marker="/etc/../x")


# -- the firewall ----------------------------------------------------------------------


def test_the_firewall_opens_udp_ports_and_the_forwarding_of_each_interface():
    keys = _selected_ports(cfg())
    assert "udp:51820" in keys and "udp:51821" in keys and "udp:51822" in keys
    assert [key for key in keys if key.startswith("route:")] == ["route:awg15", "route:awg20", "route:awg31"]
    subset = _selected_ports(cfg('[amneziawg]\nenabled = true\nversions = ["3.1"]\nports = { "3.1" = 41000 }\n'))
    assert "udp:41000" in subset and "route:awg31" in subset and "route:awg15" not in subset
    assert "udp:51820" not in subset


class FakeUfw:
    def __init__(self, rules: list[str], *, ipv6: bool = False):
        self.rules = list(rules)
        self.ipv6 = ipv6
        self.calls: list[tuple[str, ...]] = []

    def _status(self) -> str:
        lines = ["Status: active", "", *_HEADER]
        lines += [f"[{index:2}] {rule}" for index, rule in enumerate(self.rules, 1)]
        return "\n".join(lines) + "\n"

    def run(self, argv):
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        done = lambda out="": subprocess.CompletedProcess(command, 0, out, "")  # noqa: E731
        if command[:2] == ("grep", "-E"):
            return done(f"IPV6={'yes' if self.ipv6 else 'no'}\n")
        if command == ("ufw", "status", "numbered"):
            return done(self._status())
        if command[:3] == ("ufw", "route", "allow"):
            interface, comment = command[command.index("on") + 1], command[command.index("comment") + 1]
            self.rules.append(f"Anywhere                   ALLOW FWD   Anywhere on {interface}        # {comment}")
            if self.ipv6:
                self.rules.append(f"Anywhere (v6)              ALLOW FWD   Anywhere (v6) on {interface}   # {comment}")
            return done("Rule added")
        if command[:4] == ("ufw", "--force", "route", "delete"):
            interface, comment = command[command.index("on") + 1], command[command.index("comment") + 1]
            self.rules = [rule for rule in self.rules if not (f"on {interface}" in rule and rule.endswith(f"# {comment}"))]
            return done("Rule deleted")
        if command[:2] == ("ufw", "allow"):
            protocol, port = command[command.index("proto") + 1], command[command.index("port") + 1]
            comment = command[command.index("comment") + 1]
            self.rules.append(f"{port}/{protocol} ALLOW IN Anywhere # {comment}")
            if self.ipv6:
                self.rules.append(f"{port}/{protocol} (v6) ALLOW IN Anywhere (v6) # {comment}")
            return done("Rule added")
        if command[:4] == ("ufw", "--force", "delete", "allow"):
            protocol, port = command[command.index("proto") + 1], command[command.index("port") + 1]
            comment = command[command.index("comment") + 1]
            self.rules = [rule for rule in self.rules
                          if not (rule.startswith(f"{port}/{protocol}") and rule.endswith(f"# {comment}"))]
            return done("Rule deleted")
        raise AssertionError(command)


def firewall_facts(*, ipv6: bool = False) -> AuditFacts:
    return AuditFacts(
        listeners={"tcp": (22,), "udp": (), "ports": (22,), "owners": {"22": ("sshd",)}, "ssh_socket_tcp": ()},
        ownership={"ufw": {"active": True, "available": True, "ipv6_enabled": ipv6, "mode": "managed",
                           "observation": "observed"}},
    )


SSH_RULE = "22/tcp ALLOW IN Anywhere # operator:ssh"


def test_ufw_gets_the_udp_ports_and_route_rules_and_loses_them_again():
    ufw = FakeUfw([SSH_RULE])
    adapter = FirewallAdapter(runner=ufw, ssh_ports={22})
    (action,) = adapter.plan(cfg(), firewall_facts())
    assert "rule=route:awg15" in action.mutations and "rule=udp:51822" in action.mutations
    original = list(ufw.rules)

    applied_checkpoint = adapter.apply(action, adapter.prepare(action))

    assert "udp:51820" in applied_checkpoint["installer_added"] and "route:awg20" in applied_checkpoint["installer_added"]
    assert "51821/udp ALLOW IN Anywhere # proxy-control:firewall:udp:51821" in ufw.rules
    assert any(rule.startswith("Anywhere ") and "ALLOW FWD" in rule and "awg31" in rule for rule in ufw.rules)
    assert ("ufw", "route", "allow", "in", "on", "awg15", "comment", "proxy-control:firewall:route:awg15") in ufw.calls
    assert adapter.verify(action).success is True

    # Idempotent: a second apply over the same host adds nothing.
    ufw.calls.clear()
    again = adapter.apply(action, adapter.prepare(action))
    assert not [call for call in ufw.calls if call[:2] in {("ufw", "allow"), ("ufw", "route")}]
    assert again["preexisting"] and not again["installer_added"]

    adapter.rollback(action, applied_checkpoint)
    assert ufw.rules == original
    assert ("ufw", "--force", "route", "delete", "allow", "in", "on", "awg15", "comment",
            "proxy-control:firewall:route:awg15") in ufw.calls


def test_ufw_covers_both_families_for_the_route_rules_when_ipv6_is_on():
    ufw = FakeUfw([SSH_RULE, "22/tcp (v6) ALLOW IN Anywhere (v6) # operator:ssh"], ipv6=True)
    adapter = FirewallAdapter(runner=ufw, ssh_ports={22})
    (action,) = adapter.plan(cfg(), firewall_facts(ipv6=True))
    original = list(ufw.rules)
    result = adapter.apply(action, adapter.prepare(action))
    assert sum("ALLOW FWD" in rule for rule in ufw.rules) == 6
    assert adapter.verify(action).success
    adapter.rollback(action, result)
    assert ufw.rules == original


def test_a_foreign_route_rule_is_neither_adopted_nor_removed():
    foreign = "Anywhere                   ALLOW FWD   Anywhere on awg15        # operator:forward"
    ufw = FakeUfw([SSH_RULE, foreign])
    adapter = FirewallAdapter(runner=ufw, ssh_ports={22})
    (action,) = adapter.plan(cfg(), firewall_facts())
    checkpoint = adapter.prepare(action)
    assert "route:awg15" in checkpoint["preexisting"]
    result = adapter.apply(action, checkpoint)
    assert "route:awg15" not in result["installer_added"]
    adapter.rollback(action, result)
    assert foreign in ufw.rules


def test_repair_restores_a_deleted_owned_route_rule():
    ufw = FakeUfw([SSH_RULE])
    adapter = FirewallAdapter(runner=ufw, ssh_ports={22})
    (action,) = adapter.plan(cfg(), firewall_facts())
    result = adapter.apply(action, adapter.prepare(action))
    ufw.rules = [rule for rule in ufw.rules if "awg20" not in rule]
    assert adapter.verify(action).success is False
    adapter.repair(action, result)
    assert adapter.verify(action).success is True


def test_a_drifted_owned_route_rule_is_refused():
    drifted = "Anywhere                   ALLOW FWD   Anywhere on awg20        # proxy-control:firewall:route:awg15"
    ufw = FakeUfw([SSH_RULE, drifted])
    adapter = FirewallAdapter(runner=ufw, ssh_ports={22})
    (action,) = adapter.plan(cfg(), firewall_facts())
    with pytest.raises(FirewallError, match="drifted"):
        adapter.apply(action, adapter.prepare(action))


def test_the_status_parser_reads_forward_rules_and_rejects_malformed_ones():
    text = (
        "Status: active\n\n     To                         Action      From\n"
        "     --                         ------      ----\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere                   # keep\n"
        "[ 2] Anywhere                   ALLOW FWD   Anywhere on awg15          # proxy-control:firewall:route:awg15\n"
        "[ 3] Anywhere (v6)              ALLOW FWD   Anywhere (v6) on awg15     # proxy-control:firewall:route:awg15\n"
    )
    rules = parse_ufw_status(text)
    assert [rule.interface for rule in rules] == ["", "awg15", "awg15"]
    assert [rule.ipv6 for rule in rules] == [False, False, True]
    assert rules[1].action == "ALLOW FWD" and rules[1].port == 0
    head = text.split("[ 2]")[0]
    for bad in (
        "[ 2] Anywhere                   ALLOW FWD   Anywhere (v6) on awg15\n",
        "[ 2] Anywhere                   ALLOW FWD   Anywhere on eth0\n",
        "[ 3] Anywhere                   ALLOW FWD   Anywhere on awg15\n",
    ):
        with pytest.raises(FirewallError, match="nonstandard"):
            parse_ufw_status(head + bad)


def test_older_rule_fingerprints_do_not_change():
    from installer.adapters.firewall import UfwRule, _rule_fingerprint

    rule = UfwRule(port=443, protocol="tcp", action="ALLOW IN", source="Anywhere", ipv6=False, comment="c")
    forward = dataclasses.replace(rule, port=0, protocol="", action="ALLOW FWD", interface="awg15")
    assert _rule_fingerprint(rule) == _rule_fingerprint(dataclasses.replace(rule, interface=""))
    assert _rule_fingerprint(forward) != _rule_fingerprint(dataclasses.replace(forward, interface="awg20"))


def test_a_plan_without_amneziawg_adds_no_route_rules_or_udp_ports():
    keys = _selected_ports(cfg(""))
    assert not [key for key in keys if key.startswith(("route:", "udp:"))]


# -- everything that has to know the new overlay ---------------------------------------


def test_core_copies_the_overlay_the_sources_and_leaves_the_secret_and_service_alone():
    from installer.adapters import core

    assert "compose.amneziawg.yaml" in core._COPY_FILES
    assert "awg_manager" in core._COPY_DIRECTORIES
    assert "secrets/awg-manager-token" in core._ADJACENT_CREDENTIALS
    assert "awg-manager" in core._ADJACENT_SERVICES


def test_the_panel_sync_scope_knows_the_new_names():
    from version_agent import service

    assert {"awg_manager", "compose.amneziawg.yaml"} <= set(service.PANEL_SYNC)
    assert "awg_manager" in service.PANEL_MANAGERS
    assert service.OPTIONAL_COMPOSE_SERVICES["awg-manager"] == "compose.amneziawg.yaml"
    source = (ROOT / "installer" / "transaction.py").read_text()
    assert "'awg_manager'" in source and "'compose.amneziawg.yaml'" in source


def test_every_adapter_compose_call_rides_the_amneziawg_overlay_when_its_env_exists(tmp_path):
    from installer.adapters.mcp import _ENV_SIBLINGS
    from installer.adapters.mieru import MieruAdapter
    from installer.adapters.naive import NaiveAdapter
    from installer.adapters.xray_router import XrayRouterAdapter

    assert "amneziawg" in _ENV_SIBLINGS
    project = tmp_path / "opt" / "mtproxy-shared443"
    project.mkdir(parents=True)
    (project / ".env.amneziawg").write_text("AWG=1\n")
    for adapter_type in (NaiveAdapter, MieruAdapter):
        adapter = adapter_type(root=tmp_path)
        argv = adapter._compose_argv("up")
        assert "/opt/mtproxy-shared443/compose.amneziawg.yaml" in argv, adapter_type.__name__
        assert "/opt/mtproxy-shared443/.env.amneziawg" in argv, adapter_type.__name__
    router = XrayRouterAdapter(root=tmp_path)
    assert "/opt/mtproxy-shared443/compose.amneziawg.yaml" in router._compose_argv("up")


def test_the_version_agent_env_and_service_carry_the_overlay(tmp_path):
    from version_agent import service

    source = (ROOT / "version_agent" / "service.py").read_text()
    assert '"amneziawg"' in source
    assert service.PANEL_SYNC.count("compose.amneziawg.yaml") == 1


def test_update_host_rebuilds_the_manager_with_the_overlay_and_env():
    script = (ROOT / "scripts" / "update-host.sh").read_text()
    assert "awg-manager) required=compose.amneziawg.yaml" in script
    assert "awg_manager) has compose.amneziawg.yaml && services+=(awg-manager)" in script
    assert "for sibling in naive mieru xray-router amneziawg trusttunnel mcp; do" in script


def test_the_install_script_describes_the_add_on_in_both_languages():
    script = (ROOT / "scripts" / "install-release.sh").read_text()
    assert script.count("AmneziaWG") >= 8
    for needle in ("amneziawg-go", "/var/lib/awg-manager", "/dev/net/tun", "99-proxy-control-amneziawg.conf",
                   "awg15, awg20, awg31", "awg15, awg20 and", "[amneziawg]", "random free UDP port"):
        assert needle in script, needle


def test_the_release_carries_the_manager_sources_and_the_overlay():
    for relative in ("awg_manager/Dockerfile", "awg_manager/service.py", "compose.amneziawg.yaml",
                     "examples/installer/core-amneziawg.toml", "installer/adapters/amneziawg.py"):
        assert (ROOT / relative).is_file(), relative
        ignored = subprocess.run(("git", "-C", str(ROOT), "check-ignore", "-q", relative), check=False)
        assert ignored.returncode == 1, f"{relative} is git-ignored and would not ship"


def test_third_party_notices_name_the_amneziawg_licence():
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    assert "amneziawg-go" in notices and "MIT" in notices and "WireGuard LLC" in notices


def test_the_overlay_and_the_manager_defaults_agree_with_the_installer_model():
    from awg_manager.config import DEFAULT_PORTS, DEFAULT_SUBNETS, KNOWN_VERSIONS, interface_name
    from installer.model import AWG_DEFAULT_SUBNETS, awg_interface

    assert tuple(KNOWN_VERSIONS) == AWG_VERSIONS
    # the manager's and the overlay's fallback ports are lab-only; the installer has no such default
    assert DEFAULT_PORTS == TEST_PORTS and DEFAULT_SUBNETS == AWG_DEFAULT_SUBNETS
    assert all(interface_name(v) == awg_interface(v) for v in AWG_VERSIONS)
    overlay = (ROOT / "compose.amneziawg.yaml").read_text()
    for version, port in TEST_PORTS.items():
        assert f"{version}={port}" in overlay
    assert "lab acceptance scripts only" in overlay
    for name in ("AWG_MANAGER_TOKEN_FILE", "AWG_MANAGER_STATE_DIR", "AWG_VERSIONS", "AWG_PORTS", "AWG_SUBNETS",
                 "AWG_MTU", "AWG_DNS", "AWG_MANAGER_SOCKET_GID", "AMNEZIAWG_PUBLIC_HOST"):
        assert name in overlay, name


# -- random free ports (installer.awg_ports) --------------------------------------------

from installer.awg_ports import (  # noqa: E402
    PORT_HIGH,
    PORT_LOW,
    derive_port,
    installed_ports,
    machine_id,
    pick_ports,
    resolve_awg_ports,
)


def raw(extra: str = "[amneziawg]\nenabled = true\n"):
    """The configuration as parsed: ports the TOML does not name are 0 (unassigned)."""
    return parse_config(BASE.format(extra=extra, ufw="true"))


def host_root(tmp_path: Path, identity: str | None = "host-a") -> Path:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True, exist_ok=True)
    if identity is not None:
        (root / "etc/machine-id").write_text(identity + "\n")
    return root


def test_an_unnamed_port_is_left_unassigned_by_the_parser_and_never_a_well_known_default():
    awg = raw().amneziawg
    assert awg.ports == (0, 0, 0)
    assert "ports" not in render_config(raw())
    partial = raw('[amneziawg]\nenabled = true\nports = { "2.0" = 40000 }\n').amneziawg
    assert partial.ports == (0, 40000, 0)
    assert parse_config(render_config(raw('[amneziawg]\nenabled = true\nports = { "2.0" = 40000 }\n'))) == raw(
        '[amneziawg]\nenabled = true\nports = { "2.0" = 40000 }\n')


def test_the_derivation_is_sha256_of_machine_id_version_and_attempt():
    import hashlib

    digest = hashlib.sha256(b"abc:2.0:0").digest()
    assert derive_port("abc", "2.0", 0) == 10240 + int.from_bytes(digest, "big") % 21761
    assert PORT_LOW == 10240 and PORT_HIGH == 32000


def test_same_root_same_ports_and_a_different_machine_id_other_ports(tmp_path: Path):
    root = host_root(tmp_path)
    first = resolve_awg_ports(raw(), root=root).amneziawg.ports
    assert resolve_awg_ports(raw(), root=root).amneziawg.ports == first
    other = resolve_awg_ports(raw(), root=host_root(tmp_path / "b", "host-b")).amneziawg.ports
    assert other != first
    assert len(set(first)) == 3 and all(PORT_LOW <= port <= PORT_HIGH for port in first)
    assert not set(first) & {51820, 51821, 51822}


def test_without_a_machine_id_the_host_name_is_used(tmp_path: Path, monkeypatch):
    import socket

    monkeypatch.setattr(socket, "gethostname", lambda: "lab-host")
    assert machine_id(host_root(tmp_path, None)) == "lab-host"
    assert resolve_awg_ports(raw(), root=host_root(tmp_path, None)).amneziawg.ports == \
        resolve_awg_ports(raw(), root=host_root(tmp_path / "x", None)).amneziawg.ports


def test_planned_and_bound_ports_are_skipped_and_the_picks_stay_distinct(tmp_path: Path):
    root = host_root(tmp_path)
    plain = resolve_awg_ports(raw(), root=root).amneziawg.port_map()
    # the first candidate of 1.5 is bound (TCP or UDP, a foreign program): the next attempt is used
    for kind in ("udp", "tcp"):
        listeners = {kind: [plain["1.5"]]}
        moved = resolve_awg_ports(raw(), root=root, listeners=listeners).amneziawg.port_map()
        assert moved["1.5"] == derive_port("host-a", "1.5", 1) and moved["1.5"] != plain["1.5"]
        assert moved["2.0"] == plain["2.0"] and len(set(moved.values())) == 3
    # a planned Mieru port is skipped too
    mieru = parse_config(MIERU_BASE.format(extra="[amneziawg]\nenabled = true\n").replace(
        "tcp_ports = [46001]", f"tcp_ports = [{plain['3.1']}]"))
    assert resolve_awg_ports(mieru, root=root).amneziawg.port_map()["3.1"] != plain["3.1"]
    # two candidates colliding with each other: the later version moves on
    assert pick_ports(("1.5", "2.0"), identity="x", taken={derive_port("x", "2.0", 0)})["2.0"] == derive_port("x", "2.0", 1)


def test_pick_ports_never_returns_a_taken_port_even_after_many_collisions():
    taken = {derive_port("busy", "1.5", attempt) for attempt in range(40)}
    port = pick_ports(("1.5",), identity="busy", taken=taken)["1.5"]
    assert port == derive_port("busy", "1.5", 40) and port not in taken


def test_a_partial_ports_table_fills_only_the_rest(tmp_path: Path):
    root = host_root(tmp_path)
    config = resolve_awg_ports(raw('[amneziawg]\nenabled = true\nports = { "2.0" = 40000 }\n'), root=root)
    ports = config.amneziawg.port_map()
    assert ports["2.0"] == 40000 and ports["1.5"] != 40000 and ports["3.1"] != 40000
    assert PORT_LOW <= ports["1.5"] <= PORT_HIGH and len({*ports.values()}) == 3


def test_manual_ports_are_validated_as_before_and_untouched_by_the_resolver(tmp_path: Path):
    manual = raw('[amneziawg]\nenabled = true\nports = { "1.5" = 23456, "2.0" = 23457, "3.1" = 23458 }\n')
    assert resolve_awg_ports(manual, root=host_root(tmp_path)) is manual
    with pytest.raises(ConfigError, match="distinct"):
        raw('[amneziawg]\nenabled = true\nports = { "1.5" = 23456, "2.0" = 23456 }\n')
    with pytest.raises(ConfigError, match="between 1024 and 65535"):
        raw('[amneziawg]\nenabled = true\nports = { "3.1" = 80 }\n')


def test_the_plan_is_stable_across_two_plan_calls_and_refuses_unassigned_ports(tmp_path: Path):
    root = host_root(tmp_path)
    make_root(tmp_path)
    plans = []
    for _ in range(2):
        config = resolve_awg_ports(raw(), root=root, listeners={"udp": [], "tcp": [22]})
        (action,) = AmneziaWgAdapter(root=tmp_path, runner=FakeRunner()).plan(config, AuditFacts())
        plans.append(action)
    assert plans[0] == plans[1]
    ports = ",".join(f"{v}:{p}" for v, p in resolve_awg_ports(raw(), root=root).amneziawg.port_map().items())
    assert f"ports={ports}" in plans[0].mutations
    with pytest.raises(AmneziaWgError, match="not assigned"):
        AmneziaWgAdapter(root=tmp_path, runner=FakeRunner()).plan(raw(), AuditFacts())


def test_the_installers_own_running_manager_keeps_its_ports(tmp_path: Path):
    root = host_root(tmp_path)
    first = resolve_awg_ports(raw(), root=root).amneziawg.port_map()
    # replanned on an installed host: the ports are UDP listeners of our own amneziawg-go
    own = {"udp": list(first.values()),
           "owners": {str(port): ["amneziawg-go"] for port in first.values()}}
    assert resolve_awg_ports(raw(), root=root, listeners=own).amneziawg.port_map() == first
    # a foreign owner is not accepted: the pick moves away
    foreign = {"udp": [first["1.5"]], "owners": {str(first["1.5"]): ["wireguard"]}}
    assert resolve_awg_ports(raw(), root=root, listeners=foreign).amneziawg.port_map()["1.5"] != first["1.5"]
    # and the adapter accepts the held ports exactly like before
    facts = AuditFacts(listeners=own)
    make_root(tmp_path)
    assert AmneziaWgAdapter(root=tmp_path, runner=FakeRunner()).plan(resolve_awg_ports(raw(), root=root, listeners=own), facts)


def test_an_installed_hosts_env_overlay_wins_over_the_derivation(tmp_path: Path):
    root = host_root(tmp_path)
    project = root / "opt/mtproxy-shared443"
    project.mkdir(parents=True)
    (project / ".env.amneziawg").write_text("AWG_VERSIONS=1.5,2.0,3.1\nAWG_PORTS=1.5=20001,2.0=20002,3.1=20003\n")
    assert installed_ports(root) == {"1.5": 20001, "2.0": 20002, "3.1": 20003}
    assert resolve_awg_ports(raw(), root=root).amneziawg.ports == (20001, 20002, 20003)
    # an explicit TOML entry still beats the installed one
    mixed = resolve_awg_ports(raw('[amneziawg]\nenabled = true\nports = { "2.0" = 30000 }\n'), root=root)
    assert mixed.amneziawg.ports == (20001, 30000, 20003)
    (project / ".env.amneziawg").write_text("AWG_PORTS=1.5=20001,2.0=20001\n")
    assert installed_ports(root) == {}


def test_the_cli_plan_digest_is_identical_between_plan_and_install_and_the_report_shows_the_ports(tmp_path: Path):
    from installer import cli

    root = host_root(tmp_path)
    toml = tmp_path / "proxy-control.toml"
    toml.write_text(BASE.format(extra="[amneziawg]\nenabled = true\n", ufw="true"))
    seen = []

    class Services:
        def audit(self, config):
            return AuditFacts(listeners={"udp": [], "tcp": [22]})

        def plan(self, config, facts):
            seen.append(config)
            raise cli.CliError("stop")

    for _ in range(2):
        with pytest.raises(cli.CliError):
            cli._plan_from_path(toml, Services(), root)
    assert seen[0] == seen[1] and all(seen[0].amneziawg.ports)
    assert seen[0].amneziawg.port_map() == resolve_awg_ports(raw(), root=root).amneziawg.port_map()
