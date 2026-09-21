"""The installer's MCP adapter (v0.11 §9a): env, bearer token, the panel API key it asks
the panel for, the `mcp` Compose service, and the ownership marker — on the central
panel only, and never a secret in a log or an error."""
from __future__ import annotations

import json
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from installer.adapters.mcp import McpAdapter, McpError, McpPaths, mcp_handoff, mcp_url
from installer.model import (
    DomainConfig,
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

PATHS = McpPaths()
PLAINTEXT = "pc_" + "k" * 40
INITIALIZE_BODY = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "installer", "version": "0"}},
    },
    separators=(",", ":"),
)


def config(*, profile: Profile = Profile.CORE, mcp: str | None = "mcp.example.com", router: bool = False) -> InstallerConfig:
    return InstallerConfig(
        schema=1, host_mode=HostMode.FRESH, profile=profile, acme_email="ops@example.com", initial_user="owner",
        domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com",
                             naive="edge.example.com" if profile.includes_naive else None,
                             mieru="mieru.example.com" if profile.includes_mieru else None, mcp=mcp),
        mieru=MieruConfig(tcp_ports=(46001,), udp_ports=(46002,)) if profile.includes_mieru else None,
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE), firewall=FirewallConfig(manage_ufw=False),
        egress=EgressConfig(router=router),
    )


def host(tmp_path: Path, absolute: str) -> Path:
    return tmp_path / absolute.lstrip("/")


class FakeRunner:
    """Records every command; answers `api-key-create`, `docker inspect` and the two curls."""

    def __init__(self, *, healthy: bool = True, anonymous: str = "401", authenticated: str = "200",
                 key_output: str | None = None):
        self.calls: list[tuple[str, ...]] = []
        self.healthy = healthy
        self.anonymous = anonymous
        self.authenticated = authenticated
        self.key_output = key_output if key_output is not None else (
            "created\n" + json.dumps({"name": "mcp", "scope": "admin", "plaintext": PLAINTEXT}) + "\n"
        )
        self.keys_created = 0
        self.keys_revoked = 0
        self.bearers: list[str] = []

    def run(self, argv, *, stdin_path=None):
        del stdin_path
        self.calls.append(tuple(str(value) for value in argv))

    def capture(self, argv, *, max_chars):
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        if "api-key-create" in command:
            self.keys_created += 1
            return self.key_output
        if "api-key-revoke" in command:
            self.keys_revoked += 1
            return "exit=1 panel is gone\n" if self.healthy is None else "revoked\n"
        if command[:2] == ("docker", "inspect"):
            return "healthy\n" if self.healthy else "starting\n"
        if command[0] == "curl":
            bearer = [value for value in command if value.startswith("Authorization: Bearer ")]
            if bearer:
                self.bearers.append(bearer[0].split(" ", 2)[2])
                return self.authenticated
            return self.anonymous
        raise AssertionError(f"unexpected capture: {command}")


def adapter(tmp_path: Path, runner: FakeRunner | None = None) -> McpAdapter:
    return McpAdapter(root=tmp_path, runner=runner or FakeRunner())


def action_for(tmp_path: Path, **kwargs) -> Action:
    (action,) = adapter(tmp_path).plan(config(**kwargs), AuditFacts())
    return action


def stage_host(tmp_path: Path, *, naive_env: bool = False) -> None:
    """What Core left behind: the project env and its secrets directory."""
    env = host(tmp_path, f"{PATHS.project_dir}/.env")
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text("MTPROXY_DOMAIN=proxy.example.com\n")
    host(tmp_path, f"{PATHS.project_dir}/secrets").mkdir(mode=0o700, exist_ok=True)
    if naive_env:
        host(tmp_path, f"{PATHS.project_dir}/.env.naive").write_text("NAIVE_PUBLIC_HOST=edge.example.com\n")


def _installed(tmp_path: Path, runner: FakeRunner | None = None, **kwargs) -> tuple[McpAdapter, Action, dict]:
    stage_host(tmp_path)
    runner = runner or FakeRunner()
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path, **kwargs)
    checkpoint = instance.apply(action, instance.prepare(action))
    return instance, action, dict(checkpoint)


# -- planning ------------------------------------------------------------------


def test_plan_names_the_two_domains_the_port_and_the_compose_files(tmp_path):
    first = adapter(tmp_path).plan(config(), AuditFacts())
    assert first == adapter(tmp_path).plan(config(), AuditFacts()) and len(first) == 1
    action = first[0]
    assert action.id == "mcp.runtime" and action.adapter == "mcp" and action.owner == "proxy-control:mcp"
    assert action.credentials_required is True
    values = dict(item.split("=", 1) for item in action.mutations)
    assert values == {
        "project": "/opt/mtproxy-shared443",
        "domain": "mcp.example.com",
        "panel-domain": "panel.example.com",
        "port": "8793",
        "compose-files": "compose.yaml:compose.mcp.yaml",
    }
    full = adapter(tmp_path).plan(config(profile=Profile.FULL, router=True), AuditFacts())[0]
    assert dict(item.split("=", 1) for item in full.mutations)["compose-files"] == (
        "compose.yaml:compose.naive.yaml:compose.mieru.yaml:compose.xray-router.yaml:compose.mcp.yaml"
    )
    with pytest.raises(McpError, match="domains.mcp"):
        adapter(tmp_path).plan(config(mcp=None), AuditFacts())
    assert mcp_url("mcp.example.com") == "https://mcp.example.com/mcp"


def test_selection_refuses_a_tampered_action(tmp_path):
    action = action_for(tmp_path)
    instance = adapter(tmp_path)
    for broken in (
        ("domain=panel.example.com",),
        ("port=8794",),
        ("compose-files=compose.yaml",),
        ("compose-files=compose.mcp.yaml:compose.yaml",),
        ("domain=not a domain",),
    ):
        mutations = tuple(broken[0] if item.split("=", 1)[0] == broken[0].split("=", 1)[0] else item for item in action.mutations)
        with pytest.raises(McpError, match="MCP action is invalid"):
            instance._selection(replace(action, mutations=mutations))
    with pytest.raises(McpError, match="MCP action is invalid"):
        instance._selection(replace(action, owner="proxy-control:core"))


# -- prepare -------------------------------------------------------------------


def test_prepare_refuses_foreign_env_or_secrets_without_the_marker(tmp_path):
    stage_host(tmp_path)
    key = host(tmp_path, PATHS.panel_key)
    key.write_text("someone else's key\n")
    with pytest.raises(McpError, match=r"foreign MCP installation \(.*secrets/mcp-panel-key\) requires explicit migration"):
        adapter(tmp_path).prepare(action_for(tmp_path))
    key.unlink()
    host(tmp_path, PATHS.env_overlay).write_text("MCP_DOMAIN=other.example.com\n")
    with pytest.raises(McpError, match=r"foreign MCP installation \(.*\.env\.mcp\)"):
        adapter(tmp_path).prepare(action_for(tmp_path))


def test_prepare_returns_a_fresh_nonce_or_recovers_the_marker(tmp_path):
    stage_host(tmp_path)
    checkpoint = adapter(tmp_path).prepare(action_for(tmp_path))
    assert checkpoint["owner"] == "proxy-control:mcp" and checkpoint["adoption"] == "absent"
    assert len(checkpoint["marker_value"]) == 32 and checkpoint["ownership"] == {}
    marker = host(tmp_path, PATHS.marker)
    marker.parent.mkdir(parents=True)
    marker.write_text("a" * 32 + "\n")
    host(tmp_path, PATHS.env_overlay).write_text("MCP_DOMAIN=mcp.example.com\n")  # ours: the marker says so
    recovered = adapter(tmp_path).prepare(action_for(tmp_path))
    assert recovered["adoption"] == "recovery" and recovered["marker_value"] == "a" * 32


# -- apply ---------------------------------------------------------------------


def test_apply_writes_env_token_key_starts_the_service_and_marks_ownership(tmp_path):
    stage_host(tmp_path, naive_env=True)
    runner = FakeRunner()
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path)
    checkpoint = instance.prepare(action)
    applied = instance.apply(action, checkpoint)

    env = host(tmp_path, PATHS.env_overlay)
    assert env.read_text() == "MCP_DOMAIN=mcp.example.com\nMCP_PANEL_HOST=panel.example.com\n"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600

    token = host(tmp_path, PATHS.token)
    value = token.read_text().strip()
    assert len(value) >= 40 and value.replace("-", "").replace("_", "").isalnum()
    assert stat.S_IMODE(token.stat().st_mode) == 0o600

    key = host(tmp_path, PATHS.panel_key)
    assert key.read_text() == PLAINTEXT + "\n" and stat.S_IMODE(key.stat().st_mode) == 0o600
    assert runner.keys_created == 1

    create = next(call for call in runner.calls if "api-key-create" in call)
    project = PATHS.project_dir
    assert create[:6] == ("docker", "compose", "--project-name", "mtproxy", "--project-directory", project)
    env_files = [create[index + 1] for index, item in enumerate(create) if item == "--env-file"]
    assert env_files == [f"{project}/.env", f"{project}/.env.naive", f"{project}/.env.mcp"]
    compose_files = [create[index + 1] for index, item in enumerate(create) if item == "-f"]
    assert compose_files == [f"{project}/compose.yaml", f"{project}/compose.mcp.yaml"]
    assert create[-11:] == ("exec", "-T", "panel", "python", "-m", "panel.cli", "api-key-create", "--name", "mcp", "--scope", "admin")

    up = next(call for call in runner.calls if call[-1] == "mcp" and "up" in call)
    assert up[-6:] == ("up", "-d", "--build", "--no-deps", "--wait", "mcp")
    assert up[:6] == create[:6]
    # The env overlay is written before Compose runs, so the service sees its names.
    assert f"{project}/.env.mcp" in up

    marker = host(tmp_path, PATHS.marker)
    assert marker.read_text().strip() == checkpoint["marker_value"] and stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert set(applied["ownership"]) == {PATHS.env_overlay, PATHS.token, PATHS.panel_key, PATHS.marker}
    # Nothing recorded carries a secret: the runner saw the key only in its own answer.
    assert PLAINTEXT not in json.dumps(applied) and value not in json.dumps(applied)
    assert all(PLAINTEXT not in " ".join(call) and value not in " ".join(call) for call in runner.calls)


def test_apply_keeps_the_token_and_the_key_on_a_re_apply(tmp_path):
    runner = FakeRunner()
    instance, action, _ = _installed(tmp_path, runner)
    token = host(tmp_path, PATHS.token).read_text()
    instance.apply(action, instance.prepare(action))
    assert host(tmp_path, PATHS.token).read_text() == token
    assert host(tmp_path, PATHS.panel_key).read_text() == PLAINTEXT + "\n"
    assert runner.keys_created == 1


def test_apply_refuses_a_key_answer_without_plaintext_and_never_quotes_it(tmp_path):
    for index, output in enumerate(("exit=1 panel: no such command\n", "created\n{\"name\": \"mcp\"}\n", "not json at all\n")):
        root = tmp_path / str(index)
        root.mkdir()
        stage_host(root)
        instance = adapter(root, FakeRunner(key_output=output))
        action = action_for(root)
        with pytest.raises(McpError) as failure:
            instance.apply(action, instance.prepare(action))
        assert "panel" in str(failure.value) and output.strip() not in str(failure.value)
        assert not host(root, PATHS.panel_key).exists()
        assert not host(root, PATHS.marker).exists()


def test_apply_rejects_a_foreign_checkpoint(tmp_path):
    stage_host(tmp_path)
    instance = adapter(tmp_path)
    action = action_for(tmp_path)
    checkpoint = dict(instance.prepare(action))
    with pytest.raises(McpError, match="checkpoint is invalid"):
        instance.apply(action, {**checkpoint, "marker_value": "not-hex"})
    with pytest.raises(McpError, match="checkpoint is invalid"):
        instance.apply(action, {**checkpoint, "extra": True})


# -- verify --------------------------------------------------------------------


def test_verify_checks_health_then_401_without_and_200_with_the_token(tmp_path):
    runner = FakeRunner()
    instance, action, _ = _installed(tmp_path, runner)
    runner.calls.clear()
    evidence = instance.verify(action)
    assert evidence.success and evidence.details == {"response_status": 200, "public_host_ok": True}
    inspect, anonymous, authenticated = runner.calls
    assert inspect == ("docker", "inspect", "--format", "{{.State.Health.Status}}", "proxy-control-mcp")
    assert anonymous[0] == "curl" and "--resolve" in anonymous
    assert anonymous[anonymous.index("--resolve") + 1] == "mcp.example.com:8443:127.0.0.1"
    assert anonymous[-1] == "https://mcp.example.com:8443/mcp"
    assert not any(value.startswith("Authorization") for value in anonymous)
    assert "--request" in authenticated and authenticated[authenticated.index("--request") + 1] == "POST"
    headers = [authenticated[index + 1] for index, item in enumerate(authenticated) if item == "--header"]
    assert "Accept: application/json, text/event-stream" in headers and "Content-Type: application/json" in headers
    assert authenticated[authenticated.index("--data") + 1] == INITIALIZE_BODY
    assert runner.bearers == [host(tmp_path, PATHS.token).read_text().strip()]


def test_verify_refuses_an_unhealthy_container_an_open_endpoint_or_a_refused_initialize(tmp_path):
    runner = FakeRunner(healthy=False)
    instance, action, _ = _installed(tmp_path, runner)
    with pytest.raises(McpError, match="not healthy"):
        instance.verify(action)
    runner.healthy = True
    runner.anonymous = "200"
    with pytest.raises(McpError, match="without a token instead of 401"):
        instance.verify(action)
    runner.anonymous = "401"
    runner.authenticated = "401"
    with pytest.raises(McpError, match="initialize instead of 200"):
        instance.verify(action)
    runner.authenticated = "200"
    host(tmp_path, PATHS.token).unlink()
    with pytest.raises(McpError, match="token is missing"):
        instance.verify(action)


# -- handoff -------------------------------------------------------------------


def test_handoff_carries_the_address_and_the_token_only_when_mcp_is_on(tmp_path):
    assert mcp_handoff(tmp_path, config(mcp=None)) == {}
    with pytest.raises(McpError, match="token is missing"):
        mcp_handoff(tmp_path, config())
    _installed(tmp_path)
    token = host(tmp_path, PATHS.token).read_text().strip()
    assert mcp_handoff(tmp_path, config()) == {"mcp_url": "https://mcp.example.com/mcp", "mcp_token": token}


# -- rollback / repair ---------------------------------------------------------


def test_rollback_removes_the_service_the_key_the_secrets_and_the_marker(tmp_path):
    runner = FakeRunner()
    instance, action, checkpoint = _installed(tmp_path, runner)
    runner.calls.clear()
    evidence = instance.rollback(action, checkpoint)
    assert evidence.success and evidence.details == {"persistent_data_preserved": True}
    remove = runner.calls[0]
    assert remove[-3:] == ("rm", "-sf", "mcp") and remove[:4] == ("docker", "compose", "--project-name", "mtproxy")
    assert runner.keys_revoked == 1
    revoke = runner.calls[1]
    assert revoke[-9:] == ("exec", "-T", "panel", "python", "-m", "panel.cli", "api-key-revoke", "--name", "mcp")
    for absolute in (PATHS.env_overlay, PATHS.token, PATHS.panel_key, PATHS.marker):
        assert not host(tmp_path, absolute).exists(), absolute
    assert host(tmp_path, f"{PATHS.project_dir}/.env").exists()

    # A panel that is already gone does not stop the unwind.
    runner = FakeRunner()
    instance, action, checkpoint = _installed(tmp_path, runner)
    runner.healthy = None  # the fake answers api-key-revoke with a failure
    instance.rollback(action, checkpoint, rollback_target="uninstalled")
    assert not host(tmp_path, PATHS.marker).exists()


def test_rollback_refuses_a_missing_or_drifted_marker(tmp_path):
    instance, action, checkpoint = _installed(tmp_path)
    marker = host(tmp_path, PATHS.marker)
    marker.write_text("0" * 32 + "\n")
    with pytest.raises(McpError, match="marker"):
        instance.rollback(action, checkpoint)
    marker.unlink()
    with pytest.raises(McpError, match="marker"):
        instance.rollback(action, checkpoint)
    assert host(tmp_path, PATHS.token).exists()


def test_repair_reapplies_and_keeps_the_marker_and_the_token(tmp_path):
    runner = FakeRunner()
    instance, action, checkpoint = _installed(tmp_path, runner)
    token = host(tmp_path, PATHS.token).read_text()
    host(tmp_path, PATHS.env_overlay).write_text("tampered\n")
    runner.calls.clear()
    repaired = instance.repair(action, checkpoint)
    assert host(tmp_path, PATHS.env_overlay).read_text() == "MCP_DOMAIN=mcp.example.com\nMCP_PANEL_HOST=panel.example.com\n"
    assert host(tmp_path, PATHS.token).read_text() == token
    assert any(call[-6:] == ("up", "-d", "--build", "--no-deps", "--wait", "mcp") for call in runner.calls)
    assert repaired["marker_value"] == checkpoint["marker_value"]
    assert runner.keys_created == 1
