"""The installer's version-agent adapter (v0.11): the agent's code, unit, tmpfiles, env,
an empty catalog and a state that records what the installer just installed — so the
«Версии» screen is not empty after a real install."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
from pathlib import Path

import pytest

from installer.adapters import version_agent as module
from installer.adapters.mieru import _MITA_VERSION
from installer.adapters.naive import _CADDY_VERSION
from installer.adapters.version_agent import (
    VersionAgentAdapter,
    VersionAgentError,
    VersionAgentPaths,
)
from installer.adapters.xray_router import _XRAY_PINS, _XRAY_VERSION
from installer.model import (
    DomainConfig,
    EgressChoice,
    EgressConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    MieruConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
)
from installer.planner import Action, AuditFacts

ROOT = Path(__file__).resolve().parents[1]
PATHS = VersionAgentPaths()
MEMBER_BYTES = {"xray": b"#!/bin/sh\nexit 0\n", "geoip.dat": b"geoip\n", "geosite.dat": b"geosite\n"}
CADDY_BYTES = b"#!/bin/sh\necho caddy\n"
MITA_BYTES = b"#!/bin/sh\necho mita\n"
TELEMT_DIGEST = "ab27edbceb9f8c042911a7d9a44835318d1db5943ff50f276792fa29601ff856"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def config(*, profile: Profile = Profile.FULL, router: bool = True) -> InstallerConfig:
    return InstallerConfig(
        schema=1, host_mode=HostMode.FRESH, profile=profile, acme_email="ops@example.com", initial_user="owner",
        domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com",
                             naive="edge.example.com" if profile.includes_naive else None,
                             mieru="mieru.example.com" if profile.includes_mieru else None),
        mieru=MieruConfig(tcp_ports=(46001,), udp_ports=(46002,)) if profile.includes_mieru else None,
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE), firewall=FirewallConfig(manage_ufw=False),
        egress=EgressConfig(router=router, naive=EgressChoice.ROUTER if router and profile.includes_naive else EgressChoice.DIRECT),
    )


def host(tmp_path: Path, absolute: str) -> Path:
    return tmp_path / absolute.lstrip("/")


class FakeRunner:
    """Records every command; answers `systemctl is-*` and the agent's two GET endpoints."""

    def __init__(self, *, active: bool = True, enabled: bool = True, health_after: int | None = 0):
        self.calls: list[tuple[str, ...]] = []
        self.active = active
        self.enabled = enabled
        self.health_after = health_after  # None: the agent never answers
        self.versions: dict = {"enabled": True, "upstream_enabled": True, "checked_at": None, "components": {}}
        self.health_asked = 0

    def run(self, argv, *, stdin_path=None):
        del stdin_path
        self.calls.append(tuple(str(value) for value in argv))

    def capture(self, argv, *, max_chars):
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        if command[:2] == ("systemctl", "is-active"):
            return "active\n" if self.active else "exit=3 inactive\n"
        if command[:2] == ("systemctl", "is-enabled"):
            return "enabled\n" if self.enabled else "exit=1 disabled\n"
        if command[0] == "curl":
            url = command[-1]
            if url.endswith("/v1/health"):
                self.health_asked += 1
                if self.health_after is None or self.health_asked <= self.health_after:
                    return "exit=7 curl: (7) Couldn't connect to server"
                return json.dumps({"status": "ok"})
            if url.endswith("/v1/versions"):
                return json.dumps(self.versions)
        raise AssertionError(f"unexpected capture: {command}")


def stage_host(tmp_path: Path, *, naive: bool = True, mieru: bool = True, router: bool = True) -> None:
    """What the earlier adapters left on the host: the binaries the state records."""
    if naive:
        caddy = host(tmp_path, "/usr/local/bin/caddy")
        caddy.parent.mkdir(parents=True, exist_ok=True)
        caddy.write_bytes(CADDY_BYTES)
        pin = host(tmp_path, "/etc/proxy-control/caddy-naive.pin")
        pin.parent.mkdir(parents=True, exist_ok=True)
        pin.write_text(_CADDY_VERSION + "\n")
    if mieru:
        mita = host(tmp_path, "/usr/bin/mita")
        mita.parent.mkdir(parents=True, exist_ok=True)
        mita.write_bytes(MITA_BYTES)
    if router:
        bin_dir = host(tmp_path, "/usr/local/lib/proxy-control/xray-router")
        bin_dir.mkdir(parents=True, exist_ok=True)
        for name, data in MEMBER_BYTES.items():
            (bin_dir / name).write_bytes(data)
        env = host(tmp_path, PATHS.env)  # the router adapter wrote its flag first
        env.parent.mkdir(parents=True, exist_ok=True)
        env.write_text("PROXY_CONTROL_XRAY_ROUTER=on\n")
    run_dir = host(tmp_path, PATHS.socket).parent
    run_dir.mkdir(parents=True, exist_ok=True)


def bind_socket(tmp_path: Path) -> socket.socket:
    path = host(tmp_path, PATHS.socket)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o660)
    return listener


@pytest.fixture(autouse=True)
def fast_polls(monkeypatch):
    monkeypatch.setattr(module, "_HEALTH_RETRY_SECONDS", 0)


@pytest.fixture
def short_root():
    """A root short enough for `sun_path` (104 bytes on macOS): the socket tests bind one."""
    import shutil
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="pcva-", dir=tempfile.gettempdir()))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def adapter(tmp_path: Path, runner: FakeRunner | None = None) -> VersionAgentAdapter:
    return VersionAgentAdapter(root=tmp_path, source_dir=ROOT, runner=runner or FakeRunner())


def action_for(tmp_path: Path, **kwargs) -> Action:
    (action,) = adapter(tmp_path).plan(config(**kwargs), AuditFacts())
    return action


def recorded_versions(tmp_path: Path) -> dict[str, str]:
    state = json.loads(host(tmp_path, PATHS.state).read_text())
    return {name: entry["version"] for name, entry in state["components"].items()}


def _installed(tmp_path: Path, runner: FakeRunner | None = None, **kwargs) -> tuple[VersionAgentAdapter, Action, dict]:
    stage_host(tmp_path, naive=kwargs.get("profile", Profile.FULL).includes_naive,
               mieru=kwargs.get("profile", Profile.FULL).includes_mieru, router=kwargs.get("router", True))
    runner = runner or FakeRunner()
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path, **kwargs)
    checkpoint = instance.apply(action, instance.prepare(action))
    for name, version in recorded_versions(tmp_path).items():
        runner.versions["components"][name] = {"current": version, "status": "ready", "available": []}
    return instance, action, dict(checkpoint)


# -- planning ------------------------------------------------------------------


def test_plan_reflects_the_profile_and_is_secret_free(tmp_path):
    first = adapter(tmp_path).plan(config(), AuditFacts())
    assert first == adapter(tmp_path).plan(config(), AuditFacts()) and len(first) == 1
    action = first[0]
    assert action.id == "version_agent.runtime" and action.adapter == "version_agent"
    assert action.owner == "proxy-control:version-agent" and action.credentials_required is False
    values = dict(item.split("=", 1) for item in action.mutations)
    assert values["project"] == "/opt/mtproxy-shared443" and values["agent-dir"] == "/opt/proxy-control"
    assert values["socket"] == "/run/proxy-control/version-agent.sock" and values["socket-gid"] == "10001"
    assert values["compose-files"] == "compose.yaml:compose.naive.yaml:compose.mieru.yaml:compose.xray-router.yaml"
    assert values["router"] == "on" and values["naive"] == "on" and values["mieru"] == "on" and values["upstream"] == "on"

    (core,) = adapter(tmp_path).plan(config(profile=Profile.CORE, router=False), AuditFacts())
    values = dict(item.split("=", 1) for item in core.mutations)
    assert values["compose-files"] == "compose.yaml"
    assert values["router"] == "off" and values["naive"] == "off" and values["mieru"] == "off"


# -- prepare -------------------------------------------------------------------


def test_prepare_refuses_a_foreign_unit_without_the_marker(tmp_path):
    stage_host(tmp_path, router=False)
    unit = host(tmp_path, PATHS.unit)
    unit.parent.mkdir(parents=True)
    unit.write_text("[Unit]\nDescription=someone else's agent\n")
    with pytest.raises(VersionAgentError, match="foreign version-agent .* requires explicit migration"):
        adapter(tmp_path).prepare(action_for(tmp_path))


def test_prepare_returns_a_fresh_nonce_and_no_ownership(tmp_path):
    stage_host(tmp_path)
    checkpoint = adapter(tmp_path).prepare(action_for(tmp_path))
    assert checkpoint["owner"] == "proxy-control:version-agent" and checkpoint["adoption"] == "absent"
    assert len(checkpoint["marker_value"]) == 32 and checkpoint["ownership"] == {}


# -- apply ---------------------------------------------------------------------


def test_apply_installs_code_unit_env_catalog_state_and_starts_the_agent(tmp_path):
    stage_host(tmp_path)
    runner = FakeRunner(health_after=2)
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path)
    checkpoint = instance.prepare(action)
    applied = instance.apply(action, checkpoint)

    code = host(tmp_path, PATHS.code_dir)
    sources = sorted(path.name for path in (ROOT / "version_agent").glob("*.py"))
    assert sorted(path.name for path in code.glob("*.py")) == sources
    assert (code / "service.py").read_bytes() == (ROOT / "version_agent/service.py").read_bytes()
    assert stat.S_IMODE((code / "service.py").stat().st_mode) == 0o644
    assert stat.S_IMODE(code.stat().st_mode) == 0o755 and stat.S_IMODE(host(tmp_path, PATHS.agent_dir).stat().st_mode) == 0o755

    unit = host(tmp_path, PATHS.unit)
    assert unit.read_bytes() == (ROOT / "deploy/version-agent.service").read_bytes()
    assert stat.S_IMODE(unit.stat().st_mode) == 0o644
    tmpfiles = host(tmp_path, PATHS.tmpfiles)
    assert tmpfiles.read_bytes() == (ROOT / "deploy/proxy-control-version-agent.tmpfiles.conf").read_bytes()

    env = host(tmp_path, PATHS.env)
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    lines = dict(line.split("=", 1) for line in env.read_text().splitlines() if line and not line.startswith("#"))
    assert lines["PROXY_CONTROL_COMPOSE_DIR"] == "/opt/mtproxy-shared443"
    assert lines["PROXY_CONTROL_COMPOSE_FILES"] == "compose.yaml:compose.naive.yaml:compose.mieru.yaml:compose.xray-router.yaml"
    assert lines["PROXY_CONTROL_XRAY_ROUTER"] == "on" and lines["PROXY_CONTROL_UPSTREAM_CHECK"] == "on"
    assert lines["PROXY_CONTROL_CONSUMER_OVERLAYS"] == "mita=/opt/mtproxy-shared443/.env.mieru:MIERU_MITA_SHA256:mieru-manager"
    assert lines["PROXY_CONTROL_VERSION_SOCKET"] == PATHS.socket and lines["PROXY_CONTROL_VERSION_SOCKET_GID"] == "10001"
    assert lines["PROXY_CONTROL_CADDY_BUILD_DIR"] == "/var/lib/proxy-control/version-agent/caddy-build"  # kept from the example
    assert env.read_text().count("PROXY_CONTROL_XRAY_ROUTER=") == 1

    catalog = host(tmp_path, PATHS.catalog)
    assert json.loads(catalog.read_text()) == {"schema": 1, "components": {}}
    assert stat.S_IMODE(catalog.stat().st_mode) == 0o600

    state_path = host(tmp_path, PATHS.state)
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(state_path.parent.stat().st_mode) == 0o700
    state = json.loads(state_path.read_text())
    assert state["schema"] == 2 and set(state["components"]) == {"telemt", "naive", "mita", "xray"}
    xray = state["components"]["xray"]
    assert xray["version"] == _XRAY_VERSION and xray["kind"] == "binary" and xray["source"] == "catalog"
    assert xray["sha256"] == _XRAY_PINS["amd64"][1]
    assert xray["members"] == {name: _sha(data) for name, data in MEMBER_BYTES.items()}
    mita = state["components"]["mita"]
    assert mita == {**mita, "version": _MITA_VERSION, "kind": "binary", "sha256": _sha(MITA_BYTES)}
    naive = state["components"]["naive"]
    assert naive["version"] == "2.11.4" and naive["kind"] == "build" and naive["sha256"] == _sha(CADDY_BYTES)
    assert naive["runtime_version"] == _CADDY_VERSION
    telemt = state["components"]["telemt"]
    assert telemt["kind"] == "image" and telemt["image"] == f"ghcr.io/samnet-dev/mtproxymax-telemt@sha256:{TELEMT_DIGEST}"
    assert telemt["version"] == f"sha256:{TELEMT_DIGEST[:12]}"
    assert all(isinstance(entry["updated_at"], int) for entry in state["components"].values())

    assert ("systemctl", "daemon-reload") in runner.calls
    assert ("systemd-tmpfiles", "--create", PATHS.tmpfiles) in runner.calls
    assert ("systemctl", "enable", "--now", "version-agent") in runner.calls
    assert runner.health_asked == 3
    health = [call for call in runner.calls if call[0] == "curl" and call[-1].endswith("/v1/health")][0]
    assert "--fail" in health and "--unix-socket" in health and PATHS.socket in health
    assert health[-1] == "http://version-agent/v1/health"

    marker = host(tmp_path, PATHS.marker)
    assert marker.read_text().strip() == checkpoint["marker_value"] and stat.S_IMODE(marker.stat().st_mode) == 0o600
    ownership = applied["ownership"]
    assert set(ownership) >= {PATHS.unit, PATHS.tmpfiles, PATHS.env, PATHS.marker, f"{PATHS.code_dir}/service.py"}
    assert PATHS.catalog not in ownership and PATHS.state not in ownership
    assert ownership[PATHS.unit] == _sha(unit.read_bytes())
    assert ownership[PATHS.env] == {"sha256": _sha(env.read_bytes()), "mutable": True}


def test_env_names_the_mcp_overlay_when_the_central_panel_runs_it(tmp_path):
    """v0.11 §9a: with `domains.mcp` the profile's Compose list carries `compose.mcp.yaml`
    and the agent's env says so; the agent then recreates the panel with that overlay."""
    from dataclasses import replace

    stage_host(tmp_path, naive=False, mieru=False, router=False)
    central = replace(config(profile=Profile.CORE, router=False),
                      domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com", mcp="mcp.example.com"))
    instance = adapter(tmp_path)
    (action,) = instance.plan(central, AuditFacts())
    assert dict(item.split("=", 1) for item in action.mutations)["compose-files"] == "compose.yaml:compose.mcp.yaml"
    instance.apply(action, instance.prepare(action))
    lines = dict(line.split("=", 1) for line in host(tmp_path, PATHS.env).read_text().splitlines() if line and not line.startswith("#"))
    assert lines["PROXY_CONTROL_COMPOSE_FILES"] == "compose.yaml:compose.mcp.yaml"
    instance._assert_env(instance._selection(action))


def test_apply_records_only_the_components_of_the_profile(tmp_path):
    stage_host(tmp_path, naive=False, mieru=False, router=False)
    instance = adapter(tmp_path)
    action = action_for(tmp_path, profile=Profile.CORE, router=False)
    instance.apply(action, instance.prepare(action))
    state = json.loads(host(tmp_path, PATHS.state).read_text())
    assert set(state["components"]) == {"telemt"}
    lines = dict(line.split("=", 1) for line in host(tmp_path, PATHS.env).read_text().splitlines() if line and not line.startswith("#"))
    assert lines["PROXY_CONTROL_COMPOSE_FILES"] == "compose.yaml"
    assert lines["PROXY_CONTROL_XRAY_ROUTER"] == "off" and lines["PROXY_CONTROL_CONSUMER_OVERLAYS"] == ""


def test_apply_keeps_an_existing_catalog_and_state(tmp_path):
    stage_host(tmp_path)
    catalog = host(tmp_path, PATHS.catalog)
    catalog.write_text('{"schema": 1, "components": {"mita": []}}\n')
    state_path = host(tmp_path, PATHS.state)
    state_path.parent.mkdir(parents=True)
    state_path.write_text('{"schema": 2, "components": {"mita": {"version": "3.35.0"}}}\n')
    instance = adapter(tmp_path)
    action = action_for(tmp_path)
    instance.apply(action, instance.prepare(action))
    assert catalog.read_text() == '{"schema": 1, "components": {"mita": []}}\n'
    assert state_path.read_text() == '{"schema": 2, "components": {"mita": {"version": "3.35.0"}}}\n'


def test_apply_removes_stale_code_and_keeps_extra_env_keys(tmp_path):
    stage_host(tmp_path)
    code = host(tmp_path, PATHS.code_dir)
    instance = adapter(tmp_path)
    action = action_for(tmp_path)
    instance.apply(action, instance.prepare(action))
    (code / "obsolete.py").write_text("gone\n")
    env = host(tmp_path, PATHS.env)
    env.write_text(env.read_text() + "PROXY_CONTROL_EXTRA=kept\n")
    instance.apply(action, instance.prepare(action))
    assert not (code / "obsolete.py").exists()
    assert "PROXY_CONTROL_EXTRA=kept\n" in env.read_text()


def test_apply_refuses_a_health_that_never_comes(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_HEALTH_DEADLINE_SECONDS", 0.01)
    stage_host(tmp_path)
    instance = adapter(tmp_path, FakeRunner(health_after=None))
    action = action_for(tmp_path)
    with pytest.raises(VersionAgentError, match="did not answer /v1/health"):
        instance.apply(action, instance.prepare(action))


def test_apply_rejects_a_foreign_checkpoint(tmp_path):
    stage_host(tmp_path)
    instance = adapter(tmp_path)
    action = action_for(tmp_path)
    checkpoint = dict(instance.prepare(action))
    with pytest.raises(VersionAgentError, match="checkpoint is invalid"):
        instance.apply(action, {**checkpoint, "marker_value": "not-hex"})
    with pytest.raises(VersionAgentError, match="checkpoint is invalid"):
        instance.apply(action, {**checkpoint, "extra": True})


# -- verify --------------------------------------------------------------------


def test_verify_passes_on_a_healthy_agent_that_lists_the_profile(short_root):
    runner = FakeRunner()
    instance, action, _ = _installed(short_root, runner)
    listener = bind_socket(short_root)
    try:
        evidence = instance.verify(action)
    finally:
        listener.close()
    assert evidence.success
    assert evidence.details["components"] == {"telemt": f"sha256:{TELEMT_DIGEST[:12]}", "naive": "2.11.4",
                                               "mita": _MITA_VERSION, "xray": _XRAY_VERSION}
    assert ("systemctl", "is-active", "version-agent") in runner.calls
    assert ("systemctl", "is-enabled", "version-agent") in runner.calls


def test_verify_refuses_a_wrong_current_a_missing_component_or_a_dead_unit(short_root):
    runner = FakeRunner()
    instance, action, _ = _installed(short_root, runner)
    listener = bind_socket(short_root)
    try:
        runner.versions["components"]["mita"]["current"] = "3.35.0"
        with pytest.raises(VersionAgentError, match="mita"):
            instance.verify(action)
        runner.versions["components"]["mita"]["current"] = _MITA_VERSION
        del runner.versions["components"]["xray"]
        with pytest.raises(VersionAgentError, match="xray"):
            instance.verify(action)
        runner.versions["components"]["xray"] = {"current": _XRAY_VERSION}
        runner.versions["enabled"] = False
        with pytest.raises(VersionAgentError, match="not enabled"):
            instance.verify(action)
        runner.versions["enabled"] = True
        runner.active = False
        with pytest.raises(VersionAgentError, match="active and enabled"):
            instance.verify(action)
    finally:
        listener.close()


def test_verify_refuses_a_missing_or_open_socket_and_a_drifted_env(short_root):
    runner = FakeRunner()
    instance, action, _ = _installed(short_root, runner)
    with pytest.raises(VersionAgentError, match="socket"):
        instance.verify(action)
    listener = bind_socket(short_root)
    try:
        os.chmod(host(short_root, PATHS.socket), 0o666)
        with pytest.raises(VersionAgentError, match="socket"):
            instance.verify(action)
        os.chmod(host(short_root, PATHS.socket), 0o660)
        env = host(short_root, PATHS.env)
        env.write_text(env.read_text().replace("PROXY_CONTROL_XRAY_ROUTER=on", "PROXY_CONTROL_XRAY_ROUTER=off"))
        with pytest.raises(VersionAgentError, match="PROXY_CONTROL_XRAY_ROUTER"):
            instance.verify(action)
    finally:
        listener.close()


# -- rollback / repair ---------------------------------------------------------


def test_rollback_removes_owned_files_and_keeps_the_state_unless_purged(short_root):
    runner = FakeRunner()
    instance, action, checkpoint = _installed(short_root, runner)
    listener = bind_socket(short_root)
    listener.close()
    foreign = host(short_root, "/etc/proxy-control/caddy-naive.pin")

    evidence = instance.rollback(action, checkpoint)
    assert evidence.success and evidence.details["persistent_data_preserved"] is True
    assert ("systemctl", "disable", "--now", "version-agent") in runner.calls
    assert runner.calls[-1] == ("systemctl", "daemon-reload")
    for absolute in (PATHS.unit, PATHS.tmpfiles, PATHS.env, PATHS.marker, PATHS.agent_dir, PATHS.socket):
        assert not host(short_root, absolute).exists(), absolute
    assert host(short_root, PATHS.state).exists() and host(short_root, PATHS.catalog).exists()
    assert foreign.exists()

    instance, action, checkpoint = _installed(short_root, runner)
    evidence = instance.rollback(action, checkpoint, purge_data=True, rollback_target="uninstalled")
    assert evidence.details["persistent_data_preserved"] is False
    assert not host(short_root, PATHS.state_dir).exists() and not host(short_root, PATHS.catalog).exists()
    assert foreign.exists()


def test_rollback_refuses_a_missing_or_drifted_marker(tmp_path):
    instance, action, checkpoint = _installed(tmp_path)
    marker = host(tmp_path, PATHS.marker)
    marker.write_text("0" * 32 + "\n")
    with pytest.raises(VersionAgentError, match="marker"):
        instance.rollback(action, checkpoint)
    marker.unlink()
    with pytest.raises(VersionAgentError, match="marker"):
        instance.rollback(action, checkpoint)
    assert host(tmp_path, PATHS.unit).exists()


def test_repair_reapplies_restarts_and_keeps_the_operator_catalog(tmp_path):
    runner = FakeRunner()
    instance, action, checkpoint = _installed(tmp_path, runner)
    catalog = host(tmp_path, PATHS.catalog)
    catalog.write_text('{"schema": 1, "components": {"mita": [{"version": "3.37.0", "kind": "binary", '
                       '"url": "https://artifacts.example.com/mita", "sha256": "' + "a" * 64 + '"}]}}\n')
    host(tmp_path, PATHS.unit).write_text("tampered\n")
    runner.calls.clear()
    repaired = instance.repair(action, checkpoint)
    assert host(tmp_path, PATHS.unit).read_bytes() == (ROOT / "deploy/version-agent.service").read_bytes()
    assert '"3.37.0"' in catalog.read_text()
    assert ("systemctl", "restart", "version-agent") in runner.calls
    assert repaired["marker_value"] == checkpoint["marker_value"]
    assert host(tmp_path, PATHS.marker).read_text().strip() == checkpoint["marker_value"]


def test_the_real_runner_reads_curl_output_beyond_the_core_bound():
    """`/v1/versions` with cached upstream candidates is longer than the Core runner's
    4 KiB diagnostic bound; the agent runner returns the whole body."""
    runner = module._DefaultVersionAgentRunner()
    output = runner.capture(("python3", "-c", "print('x' * 10000)"), max_chars=module._JSON_LIMIT)
    assert len(output.strip()) == 10000
    assert runner.capture(("false",), max_chars=64).startswith("exit=1")
