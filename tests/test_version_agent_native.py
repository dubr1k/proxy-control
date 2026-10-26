"""The real Rust agent's Unix HTTP service in an entirely private host tree."""
from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import time

import pytest


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


@pytest.fixture
def agent(agent_binary, tmp_path):
    assert os.geteuid() == 0, "Run numeric ownership integration tests as root on ams-test"
    socket_path = tmp_path / "agent.sock"
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {}}))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n")
    docker.chmod(0o755)
    environment = {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin", "PROXY_CONTROL_VERSION_SOCKET": str(socket_path), "PROXY_CONTROL_VERSION_SOCKET_GID": "0", "PROXY_CONTROL_VERSION_STATE": str(tmp_path / "state/state.json"), "PROXY_CONTROL_VERSION_CATALOG": str(catalog), "PROXY_CONTROL_COMPOSE_DIR": str(tmp_path / "project"), "PROXY_CONTROL_UPSTREAM_CHECK": "off"}
    process = subprocess.Popen([str(agent_binary)], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while not socket_path.exists():
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline, "native agent did not bind its socket"
            time.sleep(0.02)
        yield socket_path
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        assert process.returncode == 0


def request(agent, method, path, body=None):
    connection = UnixConnection(agent)
    try:
        connection.request(method, path, body=body)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_native_agent_health_and_socket_permissions(agent):
    info = agent.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777) == (0, 0, 0o660)
    status, health = request(agent, "GET", "/v1/health")
    assert status == 200
    assert health["status"] == "ok" and health["implementation"] == "rust"
    assert health["version"]


@pytest.mark.parametrize("method,path,body", [("POST", "/v1/host", "{}"), ("POST", "/v1/update", "[]"), ("POST", "/v1/update", "not-json"), ("POST", "/v1/update", '{}'), ("GET", "/not-a-route", None)])
def test_invalid_requests_are_refused_and_agent_stays_healthy(agent, method, path, body):
    status, _ = request(agent, method, path, body)
    assert status in (400, 404, 405)
    assert request(agent, "GET", "/v1/health")[0] == 200
