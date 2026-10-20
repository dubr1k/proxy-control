"""The optional TrustTunnel add-on in the installer: configuration, plan, nginx route, the
adapter's lifecycle with a fake host, the absence of any firewall change, and the places that
must know the new overlay."""
from __future__ import annotations

import dataclasses
import json
import re
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from installer.adapters.firewall import _selected_ports
from installer.adapters.trusttunnel import (
    _HEALTH_SCRIPT,
    TT_SHA256,
    TT_VERSION,
    TrustTunnelAdapter,
    TrustTunnelError,
    TrustTunnelPaths,
    TT_SHA256_AARCH64,
    _DefaultTrustTunnelRunner,
)
from installer.config import ConfigError, load_config, parse_config, render_config, reserved_tcp_ports
from installer.model import TT_METRICS_PORT
from installer.planner import (
    Action,
    AuditFacts,
    PlanError,
    adapters_for,
    compose_file_list,
)

ROOT = Path(__file__).resolve().parents[1]
HOST = "gate.example.org"

BASE = """
schema = 1
host_mode = "fresh"
profile = "core"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"
{domain}

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
{domain}

[mieru]
tcp_ports = [{tcp}]
udp_ports = [46002]

{extra}

[three_xui]
mode = "none"

[firewall]
manage_ufw = true
"""

DOMAIN = f'trusttunnel = "{HOST}"'
SECTION = "[trusttunnel]\nenabled = true\n"


def cfg(extra: str = SECTION, *, domain: str = DOMAIN, ufw: str = "true"):
    return parse_config(BASE.format(domain=domain, extra=extra, ufw=ufw))


# -- configuration ---------------------------------------------------------------------


def test_defaults_name_the_domain_and_the_loopback_port():
    tt = cfg().trusttunnel
    assert tt is not None and tt.hostname == HOST and tt.listen_port == 4453
    assert cfg().domains.trusttunnel == HOST


def test_absent_section_without_a_domain_means_no_trusttunnel():
    assert cfg("", domain="").trusttunnel is None
    assert cfg("[trusttunnel]\nenabled = false\n", domain="").trusttunnel is None
    assert cfg("", domain="").domains.trusttunnel is None


def test_the_domain_and_the_section_go_together():
    with pytest.raises(ConfigError, match="domains.trusttunnel is required"):
        cfg(SECTION, domain="")
    with pytest.raises(ConfigError, match="domains.trusttunnel is set but"):
        cfg("", domain=DOMAIN)
    with pytest.raises(ConfigError, match="domains.trusttunnel is set but"):
        cfg("[trusttunnel]\nenabled = false\n", domain=DOMAIN)
    with pytest.raises(ConfigError, match="enabled is false"):
        cfg("[trusttunnel]\nenabled = false\nlisten_port = 4500\n", domain="")


def test_the_listen_port_can_be_set():
    assert cfg(SECTION + "listen_port = 4500\n").trusttunnel.listen_port == 4500


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("[trusttunnel]\nenabled = true\nbogus = 1\n", "unknown key: trusttunnel.bogus"),
        ('[trusttunnel]\nenabled = "yes"\n', "trusttunnel.enabled must be a boolean"),
        ("[trusttunnel]\nenabled = true\nlisten_port = 80\n", "between 1024 and 65535"),
        ("[trusttunnel]\nenabled = true\nlisten_port = 70000\n", "between 1024 and 65535"),
        ('[trusttunnel]\nenabled = true\nlisten_port = "x"\n', "must be an integer"),
        ("[trusttunnel]\nenabled = true\nlisten_port = 1987\n", "metrics"),
        ("[trusttunnel]\nenabled = true\nlisten_port = 4443\n", "is taken by .*"),
        ("[trusttunnel]\nenabled = true\nlisten_port = 8443\n", "taken by .*private TLS"),
        ("[trusttunnel]\nenabled = true\nlisten_port = 8445\n", "taken by .*MTProxy backend"),
        ("[trusttunnel]\nenabled = true\nlisten_port = 8787\n", "taken by .*panel application"),
        ("[trusttunnel]\nenabled = true\nlisten_port = 8793\n", "taken by .*"),
    ],
)
def test_configuration_rejections(extra: str, message: str):
    # 8793 and 4443 are only reserved with the MCP server / NaiveProxy: give them to the config
    domain = DOMAIN + '\nmcp = "mcp.example.com"'
    with pytest.raises(ConfigError, match=message):
        if "4443" in extra:
            parse_config(BASE.format(domain=DOMAIN + '\nnaive = "naive.example.com"', extra=extra, ufw="true")
                         .replace('profile = "core"', 'profile = "core-naive"'))
        else:
            cfg(extra, domain=domain)


def test_the_name_must_differ_from_every_other_name():
    for key in ("panel", "mtproxy"):
        text = BASE.format(domain=DOMAIN, extra=SECTION, ufw="true").replace(f'{key} = "', f'{key} = "{HOST}" #')
        with pytest.raises(ConfigError, match=f"domains.trusttunnel duplicates domains.{key}"):
            parse_config(text)
    with pytest.raises(ConfigError, match="duplicates domains.mieru"):
        parse_config(MIERU_BASE.format(domain='trusttunnel = "mieru.example.com"', extra=SECTION, tcp=46001))
    with pytest.raises(ConfigError, match="duplicates domains.subscription"):
        cfg(SECTION, domain=DOMAIN + f'\nsubscription = "{HOST}"')


def test_the_loopback_port_is_reserved_and_refused_to_mieru_and_amneziawg():
    reserved = reserved_tcp_ports(cfg())
    assert "TrustTunnel" in reserved[4453] and "TrustTunnel" in reserved[TT_METRICS_PORT]
    assert 4453 not in reserved_tcp_ports(cfg("", domain=""))
    with pytest.raises(ConfigError, match="trusttunnel.listen_port: 4453 is taken by a Mieru TCP port"):
        parse_config(MIERU_BASE.format(domain=DOMAIN, extra=SECTION, tcp=4453))
    with pytest.raises(ConfigError, match="trusttunnel.listen_port: 46001 is taken by a Mieru"):
        parse_config(MIERU_BASE.format(domain=DOMAIN, extra=SECTION + "listen_port = 46001\n", tcp=46001))
    with pytest.raises(ConfigError, match="amneziawg.ports.2.0: 4453 is taken by TrustTunnel"):
        cfg(SECTION + '\n[amneziawg]\nenabled = true\nversions = ["2.0"]\nports = { "2.0" = 4453 }\n')


def test_the_section_round_trips_through_render_config():
    config = cfg(SECTION + "listen_port = 4500\n")
    rendered = render_config(config)
    assert "[trusttunnel]" in rendered and "enabled = true" in rendered and "listen_port = 4500" in rendered
    assert f'trusttunnel = "{HOST}"' in rendered
    assert parse_config(rendered) == config
    plain = render_config(cfg("", domain=""))
    assert "[trusttunnel]" not in plain and "domains.trusttunnel" not in plain


def test_the_new_name_is_a_required_domain_and_the_canonical_form_has_no_secrets():
    assert HOST in cfg().required_domains()
    assert HOST not in cfg("", domain="").required_domains()
    canonical = cfg().canonical_dict()
    assert canonical["trusttunnel"] == {"hostname": HOST, "listen_port": 4453}
    assert "token" not in json.dumps(canonical).lower() and "password" not in json.dumps(canonical).lower()


def test_the_shipped_example_loads_and_enables_the_add_on():
    config = load_config(ROOT / "examples" / "installer" / "core-trusttunnel.toml")
    assert config.trusttunnel is not None and config.trusttunnel.hostname == "gate.example.org"


# -- the planner, nginx and the firewall -----------------------------------------------


def test_the_adapter_and_the_overlay_are_selected_exactly_when_enabled():
    names = [adapter.name for adapter in adapters_for(cfg())]
    assert "trusttunnel" in names
    assert names.index("trusttunnel") > names.index("core") and names.index("trusttunnel") > names.index("certificates")
    assert names.index("trusttunnel") < names.index("version_agent")
    assert "trusttunnel" not in [adapter.name for adapter in adapters_for(cfg("", domain=""))]
    assert compose_file_list(cfg()) == ("compose.yaml", "compose.trusttunnel.yaml")
    assert compose_file_list(cfg("", domain="")) == ("compose.yaml",)
    both = cfg(SECTION + "\n[amneziawg]\nenabled = true\n")
    assert compose_file_list(both) == ("compose.yaml", "compose.amneziawg.yaml", "compose.trusttunnel.yaml")


def test_the_certificate_step_issues_the_hosts_own_lineage():
    from installer.adapters.nginx import _certificate_groups

    groups = {service: (lineage, names) for service, lineage, names in _certificate_groups(cfg())}
    assert groups["trusttunnel"] == (HOST, (HOST,))
    assert "trusttunnel" not in {service for service, *_ in _certificate_groups(cfg("", domain=""))}


def test_nginx_routes_the_name_to_the_loopback_listener():
    from installer.adapters.nginx import NginxAdapter

    source = (ROOT / "installer" / "adapters" / "nginx.py").read_text()
    assert "config.trusttunnel.hostname" in source and "config.trusttunnel.listen_port" in source
    assert NginxAdapter.name == "nginx"


def test_no_firewall_rule_is_added_and_nothing_is_udp():
    plain = _selected_ports(cfg("", domain=""))
    assert _selected_ports(cfg()) == plain
    assert not [key for key in _selected_ports(cfg()) if key.startswith(("udp:", "route:"))]
    assert not any(str(port) in {key.split(":")[-1] for key in _selected_ports(cfg())} for port in (4453, 1987))


# -- the adapter -----------------------------------------------------------------------


class FakeRunner:
    def __init__(self, *, health: str = "healthy", report: dict | None = None, listening: bool = True):
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
        return self.present and service == "trusttunnel-manager"

    def container_health(self) -> str:
        return self.health

    def manager_health(self) -> dict:
        if self.report is not None:
            return self.report
        return {"status": "ok", "endpoint": {"running": True, "pid": 7}, "clients": 0}

    def tcp_listener(self, port: int) -> bool:
        return self.listening and port == 4453


def host(tmp_path: Path, absolute: str) -> Path:
    return tmp_path / absolute.lstrip("/")


def make_root(tmp_path: Path) -> Path:
    lineage = host(tmp_path, f"/etc/letsencrypt/live/{HOST}")
    lineage.mkdir(parents=True, exist_ok=True)
    (lineage / "fullchain.pem").write_text("CERT\n")
    (lineage / "privkey.pem").write_text("KEY-SECRET\n")
    return tmp_path


def planned(tmp_path: Path, config=None, runner=None) -> tuple[TrustTunnelAdapter, Action]:
    make_root(tmp_path)
    adapter = TrustTunnelAdapter(root=tmp_path, runner=runner or FakeRunner())
    (action,) = adapter.plan(config or cfg(), AuditFacts())
    return adapter, action


def applied(tmp_path: Path, runner: FakeRunner | None = None):
    runner = runner or FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    checkpoint = adapter.apply(action, adapter.prepare(action))
    return adapter, action, checkpoint, runner


def test_the_plan_is_deterministic_secret_free_and_complete(tmp_path):
    adapter, action = planned(tmp_path)
    assert (action,) == adapter.plan(cfg(), AuditFacts())
    values = dict(item.split("=", 1) for item in action.mutations)
    assert action.id == "trusttunnel.runtime" and action.owner == "proxy-control:trusttunnel"
    assert values["hostname"] == HOST and values["listen"] == "127.0.0.1:4453"
    assert values["metrics"] == "127.0.0.1:1987" and values["socket-gid"] == "10008"
    assert values["state-dir"] == "/var/lib/trusttunnel-manager" and values["letsencrypt-dir"] == "/etc/letsencrypt"
    assert values["version"] == TT_VERSION and values["sha256"] == TT_SHA256
    assert not any("secret" in item.lower() or "password" in item.lower() for item in action.mutations)
    assert adapter.plan(cfg("", domain=""), AuditFacts()) == ()
    assert any("A record" in item and "CDN" in item for item in action.preconditions)
    assert any("TCP only" in item and "no firewall rule" in item for item in action.preconditions)


def test_the_plan_refuses_a_claimed_loopback_port_but_accepts_its_own_listener(tmp_path):
    adapter, _ = planned(tmp_path)
    with pytest.raises(PlanError, match="4453/tcp is already claimed"):
        adapter.plan(cfg(), AuditFacts(listeners={"tcp": [4453], "owners": {"4453": ["nginx"]}}))
    with pytest.raises(PlanError, match="4453/tcp"):
        adapter.plan(cfg(), AuditFacts(listeners={"tcp": [4453]}))
    own = AuditFacts(listeners={"tcp": [4453], "owners": {"4453": ["trusttunnel_end"]}})
    assert adapter.plan(cfg(), own)


def test_apply_writes_every_owned_file_and_starts_the_service(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    result = adapter.apply(action, adapter.prepare(action))

    state = host(tmp_path, "/var/lib/trusttunnel-manager")
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert not host(tmp_path, "/var/lib/trusttunnel-tls").exists()  # no copy of the key: the manager mounts /etc/letsencrypt
    token = host(tmp_path, "/opt/mtproxy-shared443/secrets/trusttunnel-manager-token")
    assert stat.S_IMODE(token.stat().st_mode) == 0o600 and len(token.read_text().strip()) == 64
    env = host(tmp_path, "/opt/mtproxy-shared443/.env.trusttunnel")
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert env.read_text() == (
        "TRUSTTUNNEL_MANAGER_TOKEN_FILE=/opt/mtproxy-shared443/secrets/trusttunnel-manager-token\n"
        "TT_MANAGER_STATE_DIR=/var/lib/trusttunnel-manager\n"
        "TT_CERT_DIR=/etc/letsencrypt\n"
        f"TT_HOSTNAME={HOST}\n"
        "TT_LISTEN=127.0.0.1:4453\n"
        f"TT_VERSION=v{TT_VERSION}\n"
        f"TT_SHA256_X86_64={TT_SHA256}\n"
        f"TT_SHA256_AARCH64={TT_SHA256_AARCH64}\n"
        "TRUSTTUNNEL_MANAGER_SOCKET_GID=10008\n"
        f"TRUSTTUNNEL_PUBLIC_HOST={HOST}\n"
    )
    assert token.read_text().strip() not in env.read_text() and "KEY-SECRET" not in env.read_text()
    marker = host(tmp_path, "/etc/proxy-control/trusttunnel-owned")
    assert marker.is_file() and stat.S_IMODE(marker.stat().st_mode) == 0o600
    up = next(call for call in runner.calls if "up" in call)
    assert up[:2] == ("docker", "compose") and up[-4:] == ("up", "-d", "--build", "--wait")
    assert "/opt/mtproxy-shared443/.env.trusttunnel" in up and "/opt/mtproxy-shared443/compose.trusttunnel.yaml" in up
    assert set(result["ownership"]) == {
        "/opt/mtproxy-shared443/.env.trusttunnel", "/etc/proxy-control/trusttunnel-owned",
    }
    dumped = json.dumps(result)
    assert token.read_text().strip() not in dumped and "KEY-SECRET" not in dumped


def test_a_missing_certificate_stops_before_anything_starts(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    (host(tmp_path, f"/etc/letsencrypt/live/{HOST}") / "privkey.pem").unlink()
    with pytest.raises(TrustTunnelError, match="certificate for gate.example.org is missing"):
        adapter.apply(action, adapter.prepare(action))
    assert not any("up" in call for call in runner.calls)


def test_the_compose_call_carries_the_sibling_overlays_present(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    project = host(tmp_path, "/opt/mtproxy-shared443")
    project.mkdir(parents=True)
    (project / ".env.amneziawg").write_text("X=1\n")
    adapter.apply(action, adapter.prepare(action))
    up = next(call for call in runner.calls if "up" in call)
    assert "/opt/mtproxy-shared443/compose.amneziawg.yaml" in up and "/opt/mtproxy-shared443/compose.naive.yaml" not in up


def test_an_existing_token_is_kept_and_a_world_readable_one_is_refused(tmp_path):
    adapter, action = planned(tmp_path)
    token = host(tmp_path, "/opt/mtproxy-shared443/secrets/trusttunnel-manager-token")
    token.parent.mkdir(parents=True)
    token.write_text("a" * 64 + "\n")
    token.chmod(0o600)
    checkpoint = adapter.apply(action, adapter.prepare(action))
    assert token.read_text() == "a" * 64 + "\n"
    token.chmod(0o644)
    with pytest.raises(TrustTunnelError, match="unsafe"):
        adapter.repair(action, checkpoint)
    token.chmod(0o600)
    token.write_text("short\n")
    with pytest.raises(TrustTunnelError, match="malformed"):
        adapter.repair(action, checkpoint)


def test_a_failing_command_hides_stderr_secrets(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    runner.fail_on = ("docker", "compose")
    with pytest.raises(TrustTunnelError) as caught:
        adapter.apply(action, adapter.prepare(action))
    assert "SECRET123" not in str(caught.value) and "TrustTunnel command failed: docker compose" in str(caught.value)


def test_prepare_refuses_an_unowned_running_service(tmp_path):
    runner = FakeRunner()
    adapter, action = planned(tmp_path, runner=runner)
    runner.present = True
    with pytest.raises(TrustTunnelError, match="owned recovery"):
        adapter.prepare(action)


def test_a_foreign_or_malformed_checkpoint_is_refused(tmp_path):
    adapter, action = planned(tmp_path)
    good = dict(adapter.prepare(action))
    for bad in ({**good, "owner": "x"}, {**good, "adoption": "weird"}, {**good, "marker_value": "zz"},
                {k: v for k, v in good.items() if k != "ownership"}, {**good, "ownership": {"a": "b"}},
                {**good, "state_preexisting": "yes"}):
        with pytest.raises(TrustTunnelError, match="checkpoint"):
            adapter.apply(action, bad)


def test_a_tampered_action_is_refused(tmp_path):
    adapter, action = planned(tmp_path)
    keys = [item.split("=", 1)[0] for item in action.mutations]
    for key, replacement in (
        ("project", "project=/elsewhere"),
        ("letsencrypt-dir", "letsencrypt-dir=/elsewhere"),
        ("hostname", "hostname=bad_host"),
        ("listen", "listen=0.0.0.0:4453"),
        ("listen", "listen=127.0.0.1:80"),
        ("listen", "listen=127.0.0.1:1987"),
        ("metrics", "metrics=127.0.0.1:1"),
        ("sha256", "sha256=zz"),
        ("socket-gid", "socket-gid=0"),
    ):
        mutations = list(action.mutations)
        mutations[keys.index(key)] = replacement
        with pytest.raises(TrustTunnelError):
            adapter.prepare(dataclasses.replace(action, mutations=tuple(mutations)))


def test_verify_accepts_a_healthy_manager_and_states_that_nothing_is_udp(tmp_path):
    adapter, action, _, _ = applied(tmp_path)
    evidence = adapter.verify(action)
    assert evidence.success and evidence.details["listen"] == "127.0.0.1:4453"
    assert any("no UDP port was opened" in item for item in evidence.observations)
    assert any("A record" in item and "CDN" in item for item in evidence.observations)


@pytest.mark.parametrize(
    ("runner_kwargs", "message"),
    [
        ({"health": "unhealthy"}, "not healthy"),
        ({"listening": False}, "does not listen on 127.0.0.1:4453"),
        ({"report": {"status": "degraded", "endpoint": {"running": True}}}, "healthy endpoint"),
        ({"report": {"status": "ok", "endpoint": {"running": False}}}, "healthy endpoint"),
        ({"report": {"status": "ok"}}, "healthy endpoint"),
    ],
)
def test_verify_failure_paths(tmp_path, runner_kwargs, message):
    adapter, action, _, _ = applied(tmp_path, FakeRunner(**runner_kwargs))
    with pytest.raises(TrustTunnelError, match=message):
        adapter.verify(action)


def test_verify_notices_a_lost_certificate_and_a_lost_state_directory(tmp_path):
    adapter, action, _, _ = applied(tmp_path)
    key = host(tmp_path, f"/etc/letsencrypt/live/{HOST}/privkey.pem")
    key.rename(key.with_name("gone"))
    with pytest.raises(TrustTunnelError, match="certificate for gate.example.org is missing"):
        adapter.verify(action)
    key.with_name("gone").rename(key)
    host(tmp_path, "/var/lib/trusttunnel-manager").rmdir()
    with pytest.raises(TrustTunnelError, match="state directory"):
        adapter.verify(action)


def test_repair_rewrites_the_overlay_without_a_rebuild(tmp_path):
    adapter, action, checkpoint, runner = applied(tmp_path)
    host(tmp_path, "/opt/mtproxy-shared443/.env.trusttunnel").unlink()
    runner.calls.clear()
    adapter.repair(action, checkpoint)
    assert host(tmp_path, "/opt/mtproxy-shared443/.env.trusttunnel").is_file()
    up = next(call for call in runner.calls if "up" in call)
    assert up[-3:] == ("up", "-d", "--wait") and "--build" not in up


def test_uninstall_keeps_the_state_and_the_token_unless_purged(tmp_path):
    adapter, action, checkpoint, runner = applied(tmp_path)
    clients = host(tmp_path, "/var/lib/trusttunnel-manager/state.json")
    clients.write_text("{}")
    evidence = adapter.rollback(action, checkpoint, rollback_target="uninstalled")
    assert evidence.details["persistent_data_preserved"] is True
    assert clients.is_file() and host(tmp_path, "/opt/mtproxy-shared443/secrets/trusttunnel-manager-token").is_file()
    for removed in ("/opt/mtproxy-shared443/.env.trusttunnel", "/etc/proxy-control/trusttunnel-owned"):
        assert not host(tmp_path, removed).exists(), removed
    assert any(call[-4:] == ("rm", "--stop", "--force", "trusttunnel-manager") for call in runner.calls)


def test_uninstall_with_purge_removes_the_state_and_the_token(tmp_path):
    adapter, action, checkpoint, _ = applied(tmp_path)
    (host(tmp_path, "/var/lib/trusttunnel-manager") / "state.json").write_text("{}")
    evidence = adapter.rollback(action, checkpoint, purge_data=True, rollback_target="uninstalled")
    assert evidence.details["persistent_data_preserved"] is False
    assert not host(tmp_path, "/var/lib/trusttunnel-manager").exists()
    assert not host(tmp_path, "/opt/mtproxy-shared443/secrets/trusttunnel-manager-token").exists()


def test_a_purge_flag_alone_does_not_destroy_data_on_a_plain_rollback(tmp_path):
    adapter, action, checkpoint, _ = applied(tmp_path)
    (host(tmp_path, "/var/lib/trusttunnel-manager") / "state.json").write_text("{}")
    adapter.rollback(action, checkpoint, purge_data=True, rollback_target="rolled_back")
    assert host(tmp_path, "/var/lib/trusttunnel-manager/state.json").is_file()
    with pytest.raises(ValueError):
        adapter.rollback(action, checkpoint, rollback_target="bogus")


def test_the_default_runner_asks_health_inside_the_container_without_the_token(monkeypatch):
    seen: list[tuple[str, ...]] = []
    monkeypatch.setattr(_DefaultTrustTunnelRunner, "_capture_checked",
                        lambda self, argv: seen.append(tuple(argv)) or '{"status": "ok", "clients": 0}')
    assert _DefaultTrustTunnelRunner().manager_health() == {"status": "ok", "clients": 0}
    argv = seen[0]
    assert argv[:5] == ("docker", "exec", "proxy-control-trusttunnel-manager", "python", "-c")
    assert argv[5] == _HEALTH_SCRIPT and "X-Trusttunnel-Token" in argv[5] and "TT_MANAGER_TOKEN_FILE" in argv[5]
    compile(_HEALTH_SCRIPT, "<health>", "exec")
    monkeypatch.setattr(_DefaultTrustTunnelRunner, "_capture_checked", lambda self, argv: "[1]")
    with pytest.raises(TrustTunnelError, match="not an object"):
        _DefaultTrustTunnelRunner().manager_health()
    monkeypatch.setattr(_DefaultTrustTunnelRunner, "_capture_checked", lambda self, argv: "no json")
    with pytest.raises(TrustTunnelError, match="not JSON"):
        _DefaultTrustTunnelRunner().manager_health()


def test_the_default_runner_reads_tcp_listeners_from_ss(monkeypatch):
    runner = _DefaultTrustTunnelRunner()
    monkeypatch.setattr(_DefaultTrustTunnelRunner, "capture",
                        lambda self, argv, max_chars: "LISTEN 0 4096 127.0.0.1:4453 0.0.0.0:*\n")
    assert runner.tcp_listener(4453) is True
    monkeypatch.setattr(_DefaultTrustTunnelRunner, "capture", lambda self, argv, max_chars: "")
    assert runner.tcp_listener(4453) is False
    monkeypatch.setattr(_DefaultTrustTunnelRunner, "capture", lambda self, argv, max_chars: "exit=1")
    assert runner.tcp_listener(4453) is False


def test_paths_must_be_absolute_and_normalised():
    with pytest.raises(ValueError):
        TrustTunnelPaths(state_dir="relative")
    with pytest.raises(ValueError):
        TrustTunnelPaths(letsencrypt_dir="/var/../x")


def test_the_overlay_and_the_installer_agree_on_the_contract():
    overlay = (ROOT / "compose.trusttunnel.yaml").read_text()
    text = TrustTunnelAdapter(root=Path("/nonexistent")).env_text(
        {"hostname": HOST, "listen": "127.0.0.1:4453", "version": TT_VERSION, "sha256": TT_SHA256}
    )
    for line in text.splitlines():
        name = line.split("=", 1)[0]
        assert name in overlay, name
    assert "TT_SHA256_AARCH64" in overlay and TT_SHA256_AARCH64 in overlay
    assert "10008" in overlay


# -- everything that has to know the new overlay ---------------------------------------


def test_core_copies_the_overlay_the_sources_and_leaves_the_secret_and_service_alone():
    from installer.adapters import core

    assert "compose.trusttunnel.yaml" in core._COPY_FILES
    assert "trusttunnel_manager" in core._COPY_DIRECTORIES
    assert "secrets/trusttunnel-manager-token" in core._ADJACENT_CREDENTIALS
    assert "trusttunnel-manager" in core._ADJACENT_SERVICES


def test_the_panel_sync_scope_and_the_service_map_know_the_new_names():
    from version_agent import service

    assert {"trusttunnel_manager", "compose.trusttunnel.yaml"} <= set(service.PANEL_SYNC)
    assert "trusttunnel_manager" in service.PANEL_MANAGERS
    assert service.OPTIONAL_COMPOSE_SERVICES["trusttunnel-manager"] == "compose.trusttunnel.yaml"
    assert service.PANEL_SYNC.count("compose.trusttunnel.yaml") == 1
    source = (ROOT / "installer" / "transaction.py").read_text()
    assert "'trusttunnel_manager'" in source and "'compose.trusttunnel.yaml'" in source
    assert '"trusttunnel"' in (ROOT / "version_agent" / "service.py").read_text()


def test_every_adapter_compose_call_rides_the_trusttunnel_overlay_when_its_env_exists(tmp_path):
    from installer.adapters.amneziawg import AmneziaWgAdapter
    from installer.adapters.mcp import _ENV_SIBLINGS
    from installer.adapters.mieru import MieruAdapter
    from installer.adapters.naive import NaiveAdapter
    from installer.adapters.xray_router import XrayRouterAdapter

    assert "trusttunnel" in _ENV_SIBLINGS
    project = tmp_path / "opt" / "mtproxy-shared443"
    project.mkdir(parents=True)
    (project / ".env.trusttunnel").write_text("TT=1\n")
    for adapter_type in (NaiveAdapter, MieruAdapter, XrayRouterAdapter):
        argv = adapter_type(root=tmp_path)._compose_argv("up")
        assert "/opt/mtproxy-shared443/compose.trusttunnel.yaml" in argv, adapter_type.__name__
        assert "/opt/mtproxy-shared443/.env.trusttunnel" in argv, adapter_type.__name__
    argv = AmneziaWgAdapter(root=tmp_path)._compose_argv("up")  # 3.2: the AWG adapter rides it too
    assert "/opt/mtproxy-shared443/compose.trusttunnel.yaml" in argv


def test_update_host_rebuilds_the_manager_with_the_overlay_and_env():
    script = (ROOT / "scripts" / "update-host.sh").read_text()
    assert "trusttunnel-manager) required=compose.trusttunnel.yaml" in script
    assert "trusttunnel_manager) has compose.trusttunnel.yaml && services+=(trusttunnel-manager)" in script
    assert "for sibling in naive mieru xray-router amneziawg trusttunnel mcp; do" in script


def test_the_install_script_describes_the_add_on_in_both_languages():
    script = (ROOT / "scripts" / "install-release.sh").read_text()
    assert script.count("TrustTunnel") >= 12
    for needle in ("trusttunnel-manager", "/var/lib/trusttunnel-manager", "/etc/letsencrypt",
                   "[trusttunnel]", "domains.trusttunnel", "127.0.0.1:4453", "A-запись", "A record",
                   "ничего UDP", "nothing UDP", "no UFW rule is added", "правила UFW не добавляются",
                   "Apache-2.0", "TrustTunnel endpoint "):
        assert needle in script, needle


def test_the_pin_in_the_adapter_equals_the_release_manifest():
    pins = {item["name"]: item for item in json.loads((ROOT / "release" / "external-artifacts.json").read_text())["artifacts"]}
    entry = pins["trusttunnel"]
    amd64 = entry["platforms"]["amd64"]
    assert entry["version"] == TT_VERSION and amd64["sha256"] == TT_SHA256
    assert entry["spdx_license"] == "Apache-2.0" and entry["repository"] == "TrustTunnel/TrustTunnel"
    assert amd64["url"].endswith(f"/v{TT_VERSION}/trusttunnel-v{TT_VERSION}-linux-x86_64.tar.gz")
    assert re.fullmatch(r"[0-9a-f]{64}", amd64["executable_sha256"])


def test_the_manifest_parses_and_the_notices_name_the_licence():
    from installer.release import ReleaseManifest

    manifest = ReleaseManifest.from_bytes((ROOT / "release" / "external-artifacts.json").read_bytes())
    assert manifest.external_artifact("trusttunnel", "amd64").sha256 == TT_SHA256
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    assert "trusttunnel_endpoint" in notices and "Apache-2.0" in notices and TT_SHA256 in notices


def test_the_release_carries_the_example_and_the_enable_script():
    for relative in ("examples/installer/core-trusttunnel.toml", "installer/adapters/trusttunnel.py",
                     "scripts/enable-trusttunnel.sh"):
        assert (ROOT / relative).is_file(), relative
        ignored = subprocess.run(("git", "-C", str(ROOT), "check-ignore", "-q", relative), check=False)
        assert ignored.returncode == 1, f"{relative} is git-ignored and would not ship"
