from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import httpx

from version_agent.server import Handler, UnixHTTPServer
from version_agent.service import RollbackFailedError, UpdateError


class FakeAgent:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure

    def list_versions(self):
        return {
            "enabled": True,
            "components": {"telemt": {"current": "old", "available": []}},
        }

    def update(self, component, version, expected_current):
        self.calls.append((component, version, expected_current))
        if self.failure is not None:
            raise self.failure
        if component == "panel":
            # v0.11: the panel's own update runs in the agent's background thread.
            return {"component": component, "version": version, "changed": True, "async": True}
        return {"component": component, "version": version, "changed": True}


def test_unix_socket_server_preserves_update_contract(tmp_path: Path):
    socket_path = tmp_path / "version-agent.sock"
    server = UnixHTTPServer(str(socket_path), Handler, gid=os.getgid())
    agent = FakeAgent()
    server.agent = agent
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(base_url="http://version-agent", transport=transport) as client:
            listed = client.get("/v1/versions")
            assert listed.status_code == 200
            assert listed.json()["components"]["telemt"]["current"] == "old"
            # Deliberately use a different JSON key order: the handler must not
            # rely on dict insertion order when parsing a privileged request.
            response = client.post(
                "/v1/update",
                content=json.dumps(
                    {
                        "expected_current": "old",
                        "version": "new",
                        "component": "telemt",
                    }
                ),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 200
            assert agent.calls == [("telemt", "new", "old")]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unix_socket_server_answers_a_panel_update_as_accepted_and_async(tmp_path: Path):
    socket_path = tmp_path / "version-agent.sock"
    server = UnixHTTPServer(str(socket_path), Handler, gid=os.getgid())
    agent = FakeAgent()
    server.agent = agent
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(base_url="http://version-agent", transport=transport) as client:
            response = client.post(
                "/v1/update",
                json={"component": "panel", "version": "0.11.0-beta.1", "expected_current": "0.10.0-beta.1"},
            )
            assert response.status_code == 200
            assert response.json() == {"component": "panel", "version": "0.11.0-beta.1", "changed": True, "async": True}
            assert agent.calls == [("panel", "0.11.0-beta.1", "0.10.0-beta.1")]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unix_socket_server_checks_upstream_on_post(tmp_path: Path):
    class Agent:
        def __init__(self):
            self.checked = 0

        def list_versions(self):
            return {"enabled": True, "components": {}}

        def check_upstream(self, force=False):
            self.checked += 1
            return {"enabled": True, "components": {}, "checked_at": 1}

    socket_path = tmp_path / "version-agent.sock"
    server = UnixHTTPServer(str(socket_path), Handler, gid=os.getgid())
    agent = Agent()
    server.agent = agent
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(base_url="http://version-agent", transport=transport) as client:
            response = client.post("/v1/upstream/check")
            assert response.status_code == 200
            assert response.json()["checked_at"] == 1 and agent.checked == 1
            # A body is tolerated but never read as input: the check takes no parameters.
            response = client.post("/v1/upstream/check", content=b"{}", headers={"Content-Type": "application/json"})
            assert response.status_code == 200 and agent.checked == 2
            assert client.get("/v1/upstream/check").status_code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unix_socket_server_reports_a_failed_or_disabled_upstream_check(tmp_path: Path):
    class Agent:
        def list_versions(self):
            return {"enabled": True, "components": {}}

        def check_upstream(self, force=False):
            raise UpdateError("upstream check is disabled on this host")

    socket_path = tmp_path / "version-agent.sock"
    server = UnixHTTPServer(str(socket_path), Handler, gid=os.getgid())
    server.agent = Agent()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(base_url="http://version-agent", transport=transport) as client:
            response = client.post("/v1/upstream/check")
            assert response.status_code == 502
            assert response.json() == {
                "detail": "upstream check is disabled on this host",
                "state": "update_failed",
            }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unix_socket_server_returns_distinct_rollback_failed_state(tmp_path: Path):
    socket_path = tmp_path / "version-agent.sock"
    server = UnixHTTPServer(str(socket_path), Handler, gid=os.getgid())
    server.agent = FakeAgent(RollbackFailedError("restored generation is unhealthy"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(base_url="http://version-agent", transport=transport) as client:
            response = client.post(
                "/v1/update",
                json={
                    "component": "telemt",
                    "version": "new",
                    "expected_current": "old",
                },
            )

            assert response.status_code == 502
            assert response.json() == {
                "detail": "update failed and the previous generation could not be verified",
                "state": "rollback_failed",
            }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
