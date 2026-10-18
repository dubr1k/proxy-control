"""Managers the panel update does not rebuild (`pending_rebuild`): the card heals itself, the
agent rebuilds them after a panel update, and `rebuild`/`ack` work by hand."""
from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

from tests.test_version_agent_panel import (
    NEW_PANEL, OLD_PANEL, _PanelHost, _panel_archive, _release_tar, _state,
)
from version_agent import server as server_module
from version_agent.service import ConflictError, VersionAgent

FILES = ("compose.yaml", "compose.naive.yaml", "compose.xray-router.yaml", "compose.mcp.yaml")
ROUTER_OVERLAY = "services:\n  xray-router:\n    image: x\n  xray-router-ingress:\n    image: x\n"
OLD = "2020-01-01T00:00:00.123456789Z"


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch)) + ".000000001Z"


def _id(service: str) -> str:
    return (service.encode().hex() * 64)[:64]


class ManagerHost(_PanelHost):
    """The panel host plus containers per Compose service: id, image id, image creation time."""

    def __init__(self, tmp_path, services=("naive-manager",), created=OLD, **kw):
        super().__init__(tmp_path, **kw)
        (self.compose / "compose.xray-router.yaml").write_text(ROUTER_OVERLAY)
        self.created = {service: created for service in services}
        self.health = {}
        self.fail_up = False
        self.sleeps: list[float] = []

    def run(self, command, *, env=None, cwd=None, timeout=None):
        if command[:3] == ["docker", "ps", "-a"]:
            service = command[command.index("--filter", 5) + 1].rsplit("=", 1)[1]
            self.commands.append(list(command))
            return _id(service) if service in self.created else ""
        if command[:2] == ["docker", "inspect"] and command[-1] != "proxy-control-panel" \
                and not command[-1].startswith("sha256"):
            self.commands.append(list(command))
            service = next(s for s in self.created if _id(s) == command[-1])
            if "{{.Image}}" in command:
                return "sha256:" + _id(service)
            return self.health.get(service, "healthy")
        if command[:3] == ["docker", "image", "inspect"]:
            self.commands.append(list(command))
            service = next(s for s in self.created if "sha256:" + _id(s) == command[-1])
            return self.created[service]
        if command[:2] == ["docker", "compose"] and "--build" in command:
            self.commands.append(list(command))
            if self.fail_up:
                raise RuntimeError("build failed")
            for service in self.created:
                if service in command:
                    self.created[service] = _iso(time.time())
            return ""
        return super().run(command, env=env, cwd=cwd, timeout=timeout)

    def agent(self, payload: bytes, **extra) -> VersionAgent:
        extra.setdefault("sleep", self.sleeps.append)
        agent = super().agent(payload, **extra)
        agent.compose_files = FILES
        return agent


def _update(host, auto=False, **kw):
    agent = host.agent(_panel_archive(), auto_rebuild_managers=auto, **kw)
    agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    return agent


def test_card_drops_managers_whose_container_image_is_newer_than_the_panel_update(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager", "xray-router", "mcp"))
    agent = _update(host)
    updated = _state(tmp_path)["updated_at"]
    assert _state(tmp_path)["pending_rebuild"] == ["naive_manager"]
    host.created.update({"naive-manager": OLD, "xray-router": _iso(updated + 60), "mcp": _iso(updated + 60)})
    state = _state(tmp_path)
    state["pending_rebuild"] = ["naive_manager", "xray_router_manager", "mcp_server", "docker"]
    _write_panel(tmp_path, state)
    listed = agent.list_versions()["components"]["panel"]
    # naive is still old; the router (both services) and mcp were rebuilt; docker is untouched.
    assert listed["pending_rebuild"] == ["naive_manager", "docker"]
    assert _state(tmp_path)["pending_rebuild"] == ["naive_manager", "docker"]  # persisted


def test_slack_and_missing_services_and_absent_overlays(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager",))
    agent = _update(host)
    updated = _state(tmp_path)["updated_at"]
    host.created["naive-manager"] = _iso(updated - 5)  # inside the slack: rebuilt
    _write_panel(tmp_path, {**_state(tmp_path), "pending_rebuild": ["naive_manager", "mcp_server", "awg_manager"]})
    # mcp has no container, awg has no overlay: nothing to rebuild for either
    assert agent.list_versions()["components"]["panel"]["pending_rebuild"] == []
    host.created["naive-manager"] = _iso(updated - 60)
    _write_panel(tmp_path, {**_state(tmp_path), "pending_rebuild": ["naive_manager"]})
    assert agent.list_versions()["components"]["panel"]["pending_rebuild"] == ["naive_manager"]


def test_docker_error_leaves_the_list_unchanged_and_nothing_runs_for_an_empty_list(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager",), created=_iso(time.time() + 3600))
    agent = _update(host)
    _write_panel(tmp_path, {**_state(tmp_path), "pending_rebuild": ["naive_manager"]})
    good = agent.runner

    def broken(command, **kwargs):
        if command[:3] == ["docker", "image", "inspect"]:
            raise OSError("docker down")
        return good(command, **kwargs)

    agent.runner = broken
    assert agent.list_versions()["components"]["panel"]["pending_rebuild"] == ["naive_manager"]
    agent.runner = good
    agent.list_versions()
    _write_panel(tmp_path, {**_state(tmp_path), "pending_rebuild": []})
    host.commands.clear()
    agent.list_versions()
    assert not any(c[:2] == ["docker", "ps"] and "-a" in c for c in host.commands)


def _write_panel(tmp_path: Path, panel: dict) -> None:
    path = tmp_path / "state.json"
    data = json.loads(path.read_text())
    data["components"]["panel"] = panel
    path.write_text(json.dumps(data))


def test_successful_panel_update_rebuilds_managers_in_one_compose_call_before_the_agent_restart(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager", "xray-router", "xray-router-ingress"))
    agent = host.agent(_release_tar({
        "proxy-control/VERSION": NEW_PANEL.encode(),
        "proxy-control/naive_manager/app.py": b"changed",
        "proxy-control/xray_router_manager/app.py": b"changed",
        "proxy-control/version_agent/service.py": b"new agent",
    }), auto_rebuild_managers=True)
    agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    builds = [c for c in host.commands if c[:2] == ["docker", "compose"] and "--build" in c]
    assert len(builds) == 1
    assert builds[0][-4:] == ["--no-deps", "naive-manager", "xray-router", "xray-router-ingress"]
    assert "--env-file" in builds[0] and "up" in builds[0]
    tags = [c for c in host.commands if c[:2] == ["docker", "tag"] and c[3].startswith("mtproxy-") and not c[3].startswith("mtproxy-panel")]
    assert {c[3].split(":")[0] for c in tags} == {"mtproxy-naive-manager", "mtproxy-xray-router",
                                                  "mtproxy-xray-router-ingress"}
    panel = _state(tmp_path)
    assert panel["status"] == "ready" and panel["pending_rebuild"] == []
    assert isinstance(panel["managers_rebuilt_at"], int) and "rebuilding_managers" not in panel
    assert host.commands[-1][0] == "systemd-run"  # the agent restart is the very last step


def test_failed_manager_rebuild_keeps_the_panel_pending_and_records_the_error(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager",))
    host.fail_up = True
    _update(host, auto=True)
    panel = _state(tmp_path)
    assert panel["status"] == "ready" and panel["version"] == NEW_PANEL  # panel never rolled back
    assert panel["pending_rebuild"] == ["naive_manager"] and "build failed" in panel["rebuild_error"]
    assert "rebuilding_managers" not in panel
    restored = [c for c in host.commands if c[:2] == ["docker", "tag"] and c[-1] == "mtproxy-naive-manager:latest"]
    assert restored and host.commands[-1][0] == "systemd-run"


def test_unhealthy_managers_time_out_without_dropping_the_pending_list(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager",))
    host.health["naive-manager"] = "starting"
    _update(host, auto=True, manager_health_timeout=6)
    panel = _state(tmp_path)
    assert panel["pending_rebuild"] == ["naive_manager"] and "not healthy: naive-manager=starting" in panel["rebuild_error"]
    assert host.sleeps == [2, 2, 2]


def test_auto_rebuild_can_be_switched_off(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager",))
    _update(host, auto=False)
    assert not any("--build" in c for c in host.commands)
    assert _state(tmp_path)["pending_rebuild"] == ["naive_manager"]


def test_manual_rebuild_refuses_while_updating_and_ack_is_idempotent(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager", "mcp"))
    agent = _update(host)
    _write_panel(tmp_path, {**_state(tmp_path), "pending_rebuild": ["naive_manager", "mcp_server", "docker"]})
    with pytest.raises(ValueError):
        agent.ack_managers([])
    with pytest.raises(ValueError):
        agent.ack_managers(["nope"])
    assert agent.ack_managers(["mcp_server"])["pending_rebuild"] == ["naive_manager", "docker"]
    assert agent.ack_managers(["mcp_server"])["pending_rebuild"] == ["naive_manager", "docker"]
    _write_panel(tmp_path, {**_state(tmp_path), "status": "updating"})
    with pytest.raises(ConflictError):
        agent.rebuild_managers()
    _write_panel(tmp_path, {**_state(tmp_path), "status": "ready"})
    result = agent.rebuild_managers()
    assert result["pending_rebuild"] == ["docker"] and not result["rebuilding"]
    assert "managers_rebuilt_at" in result


def test_http_endpoints(tmp_path):
    host = ManagerHost(tmp_path, services=("naive-manager",))
    agent = _update(host)

    class Request(server_module.Handler):
        def __init__(self, path, body, agent):
            self.path, self.agent_ = path, agent
            self.headers = {"Content-Length": str(len(body))}
            self.rfile = io.BytesIO(body)
            self.wfile = io.BytesIO()
            self.server = type("S", (), {"agent": agent})()
            self.sent = None

        def _send(self, status, value):
            self.sent = (status, value)

    def post(path, payload):
        request = Request(path, json.dumps(payload).encode(), agent)
        request.do_POST()
        return request.sent

    assert post("/v1/panel/managers/ack", {"names": []})[0] == 422
    assert post("/v1/panel/managers/ack", {"names": ["x"]})[0] == 422
    assert post("/v1/panel/managers/ack", {"other": 1})[0] == 422
    status, body = post("/v1/panel/managers/ack", {"names": ["naive_manager"]})
    assert status == 200 and body["pending_rebuild"] == []
    _write_panel(tmp_path, {**_state(tmp_path), "status": "updating"})
    assert post("/v1/panel/managers/rebuild", {})[0] == 409
