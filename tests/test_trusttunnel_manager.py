from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import tomllib

import pytest

from trusttunnel_manager import healthcheck
from trusttunnel_manager.config import ConfigError, from_env
from trusttunnel_manager.metrics import aggregate, fold
from trusttunnel_manager.server import MAX_BODY, ManagerHTTPServer
from trusttunnel_manager.service import (
    ApiError,
    TrusttunnelManager,
    inspect_certificate,
    toml_string,
)
from trusttunnel_manager.state import StateError, StateStore

TOKEN = "t" * 40
PASSWORD = "p" * 32


class FakeSupervisor:
    """Stands in for the endpoint process; its counters reset on every start."""

    def __init__(self):
        self.is_running = False
        self.starts = 0
        self.stops = 0
        self.reloads = 0
        self.reload_error: Exception | None = None
        self.credentials_at_start: list[list[str]] = []
        self.vpn_at_start: list[dict] = []
        self.counters: dict[str, dict[str, int]] = {}

    def start(self, vpn_toml, hosts_toml):
        self.is_running = True
        self.starts += 1
        self.counters = {}
        creds = tomllib.loads((vpn_toml.parent / "credentials.toml").read_text())
        self.credentials_at_start.append(
            [c["username"] for c in creds["client"] if c["username"] != "proxy-control-idle"]
        )
        self.vpn_at_start.append(tomllib.loads(vpn_toml.read_text()))

    def stop(self):
        if self.is_running:
            self.stops += 1
        self.is_running = False

    def reload(self):
        if self.reload_error:
            raise self.reload_error
        self.reloads += 1

    def running(self):
        return self.is_running

    def pid(self):
        return 4242 if self.is_running else None

    def traffic(self, name, inbound, outbound, sessions=1):
        self.counters[name] = {"username": name, "ip": "1.2.3.4", "sessions": sessions,
                               "inbound": inbound, "outbound": outbound}

    def fetch(self):
        return list(self.counters.values()) if self.is_running else None


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_env(tmp_path, **extra):
    env = {
        "TT_MANAGER_TOKEN_FILE": str(tmp_path / "token"),
        "TT_MANAGER_SOCKET": str(tmp_path / "run" / "m.sock"),
        "TT_STATE_DIR": str(tmp_path / "state"),
        "TT_HOSTNAME": "gate.example.com",
        "TT_CERT": str(tmp_path / "cert.pem"),
        "TT_KEY": str(tmp_path / "key.pem"),
        "TT_BINARY": str(tmp_path / "trusttunnel_endpoint"),
    }
    env.update(extra)
    return env


def make_manager(tmp_path, *, cert=True, **env_extra):
    if cert:
        (tmp_path / "cert.pem").write_text("cert")
        (tmp_path / "key.pem").write_text("key")
    sup, clock = FakeSupervisor(), Clock()
    manager = TrusttunnelManager(
        from_env(make_env(tmp_path, **env_extra)), sup, sup.fetch, clock=clock, wall=lambda: 1_700_000_000
    )
    manager.bootstrap()
    return manager, sup, clock


def create_body(name="alice", password=PASSWORD, op="op-1"):
    return {"operation_id": op, "username": name, "password": password}


def settle(manager, clock):
    clock.now += 3
    manager.tick()


def raw_credentials(tmp_path):
    return tomllib.loads((tmp_path / "state" / "credentials.toml").read_text())["client"]


def credentials(tmp_path):
    return [c for c in raw_credentials(tmp_path) if c["username"] != "proxy-control-idle"]


# ---------------------------------------------------------------- config


def test_config_defaults_and_required_values(tmp_path):
    config = from_env(make_env(tmp_path))
    assert config.listen == "127.0.0.1:4453" and config.metrics == "127.0.0.1:1987"
    assert config.public_port == 443 and config.socket_mode == 0o660
    with pytest.raises(ConfigError, match="TT_MANAGER_TOKEN_FILE"):
        from_env({"TT_HOSTNAME": "gate.example.com"})


@pytest.mark.parametrize(
    "extra",
    [
        {"TT_HOSTNAME": "10.0.0.1"},
        {"TT_HOSTNAME": ""},
        {"TT_LISTEN": "0.0.0.0:4453"},
        {"TT_LISTEN": "127.0.0.1:80"},
        {"TT_METRICS": "127.0.0.1:4453"},
        {"TT_MANAGER_SOCKET_MODE": "666"},
        {"TT_STATE_DIR": "relative"},
        {"TT_CERT": "cert.pem"},
    ],
)
def test_config_rejects_unsafe_values(tmp_path, extra):
    with pytest.raises(ConfigError):
        from_env(make_env(tmp_path, **extra))


# ---------------------------------------------------------------- toml


def test_toml_string_round_trips_hostile_characters():
    for value in ['a"b', "back\\slash", "new\nline", "tab\t", 'ends\\"', "ünï"]:
        assert tomllib.loads(f"v = {toml_string(value)}")["v"] == value


def test_generated_settings_are_tcp_only_and_loopback(tmp_path):
    manager, sup, _ = make_manager(tmp_path)
    vpn = tomllib.loads((tmp_path / "state" / "vpn.toml").read_text())
    assert vpn["listen_address"] == "127.0.0.1:4453"
    assert set(vpn["listen_protocols"]) == {"http1", "http2"}
    assert vpn["forward_protocol"] == {"direct": {}}
    assert vpn["metrics"] == {"address": "127.0.0.1:1987", "request_timeout_secs": 3, "per_client_metrics": True}
    assert vpn["credentials_file"] == str(tmp_path / "state" / "credentials.toml")
    assert "quic" not in (tmp_path / "state" / "vpn.toml").read_text()
    hosts = tomllib.loads((tmp_path / "state" / "hosts.toml").read_text())
    assert hosts["main_hosts"] == [
        {"hostname": "gate.example.com", "cert_chain_path": str(tmp_path / "cert.pem"),
         "private_key_path": str(tmp_path / "key.pem")}
    ]
    assert sup.starts == 1


def test_files_are_private(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    manager.create_client(create_body())
    state = tmp_path / "state"
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    for name in ("credentials.toml", "vpn.toml", "hosts.toml", "state.json"):
        assert stat.S_IMODE((state / name).stat().st_mode) == 0o600


# ---------------------------------------------------------------- clients


def test_create_is_idempotent_per_operation_and_hides_the_password(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    first = manager.create_client(create_body())
    again = manager.create_client(create_body())
    assert first == again
    assert first["client"] == {"username": "alice", "enabled": True, "revision": 1, "rx": 0, "tx": 0, "sessions": 0}
    assert PASSWORD not in json.dumps(first)
    assert credentials(tmp_path) == [{"username": "alice", "password": PASSWORD}]


def test_create_conflicts_and_validation(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    manager.create_client(create_body())
    with pytest.raises(ApiError) as exists:
        manager.create_client(create_body(op="op-2"))
    assert (exists.value.status, exists.value.code) == (409, "exists")
    with pytest.raises(ApiError) as conflict:
        manager.create_client(create_body(name="bob"))
    assert (conflict.value.status, conflict.value.code) == (409, "operation_conflict")
    for bad in (
        create_body(name="bad name"), create_body(name=""), create_body(name="x" * 65),
        create_body(password="short"), create_body(password="has space in it 123"),
        {**create_body(), "extra": 1}, {"username": "a", "password": PASSWORD},
    ):
        with pytest.raises(ApiError) as exc:
            manager.create_client(bad)
        assert (exc.value.status, exc.value.code) == (422, "invalid_request")


def test_disable_removes_from_credentials_and_enable_restores_the_same_password(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    manager.create_client(create_body())
    manager.create_client(create_body(name="bob", op="op-2", password="q" * 32))
    manager.set_enabled("alice", False)
    assert [c["username"] for c in credentials(tmp_path)] == ["bob"]
    assert manager.list_clients()["clients"][0]["enabled"] is False
    settle(manager, clock)
    assert sup.credentials_at_start[-1] == ["bob"]
    manager.set_enabled("alice", True)
    assert {c["username"]: c["password"] for c in credentials(tmp_path)}["alice"] == PASSWORD
    assert manager.list_clients()["clients"][0]["revision"] == 3


def test_rotate_changes_the_password_and_is_idempotent(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    manager.create_client(create_body())
    new = "n" * 32
    body = {"operation_id": "rot-1", "password": new}
    first = manager.rotate("alice", body)
    assert first["client"]["revision"] == 2
    assert credentials(tmp_path) == [{"username": "alice", "password": new}]
    assert manager.rotate("alice", body)["client"]["revision"] == 2
    with pytest.raises(ApiError) as conflict:
        manager.rotate("alice", {"operation_id": "rot-1", "password": "z" * 32})
    assert conflict.value.code == "operation_conflict"
    with pytest.raises(ApiError) as missing:
        manager.rotate("nobody", {"operation_id": "rot-2", "password": new})
    assert missing.value.status == 404


def test_rotating_a_disabled_client_keeps_it_out_and_does_not_restart(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    manager.create_client(create_body())
    settle(manager, clock)
    manager.set_enabled("alice", False)
    settle(manager, clock)
    starts = sup.starts
    manager.rotate("alice", {"operation_id": "r", "password": "n" * 32})
    settle(manager, clock)
    assert sup.starts == starts and credentials(tmp_path) == []
    manager.set_enabled("alice", True)
    assert credentials(tmp_path) == [{"username": "alice", "password": "n" * 32}]


def test_delete_is_idempotent(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    manager.create_client(create_body())
    manager.delete_client("alice")
    manager.delete_client("alice")
    assert manager.list_clients() == {"clients": []} and credentials(tmp_path) == []
    with pytest.raises(ApiError) as missing:
        manager.set_enabled("alice", True)
    assert missing.value.status == 404


def test_state_survives_a_manager_restart(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    manager.create_client(create_body())
    manager.set_enabled("alice", False)
    again, _, _ = make_manager(tmp_path)
    assert again.list_clients()["clients"][0]["enabled"] is False
    assert again.create_client(create_body())["client"]["username"] == "alice"


def test_corrupt_or_foreign_state_is_refused(tmp_path):
    store = StateStore(tmp_path / "state")
    store.directory.mkdir()
    store.path.write_text('{"schema": 99}')
    with pytest.raises(StateError):
        store.load()
    store.path.write_text("not json")
    with pytest.raises(StateError):
        store.load()


# ---------------------------------------------------------------- restarts and counters


def test_credential_changes_coalesce_into_one_restart(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    assert sup.starts == 1
    for i in range(5):
        manager.create_client(create_body(name=f"u{i}", op=f"op-{i}"))
    clock.now += 1
    manager.tick()
    assert sup.starts == 1  # still inside the coalescing window
    clock.now += 2
    manager.tick()
    assert sup.starts == 2 and sup.stops == 1
    assert sup.credentials_at_start[-1] == [f"u{i}" for i in range(5)]
    clock.now += 10
    manager.tick()
    assert sup.starts == 2


def test_totals_survive_restarts_and_use_a_final_poll(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    manager.create_client(create_body())
    settle(manager, clock)  # first restart picks up alice
    sup.traffic("alice", inbound=100, outbound=1000, sessions=2)
    clock.now += 15
    manager.tick()
    view = manager.list_clients()["clients"][0]
    # rx = endpoint `outbound` = what the client uploaded; tx = endpoint `inbound` = what it downloaded (measured)
    assert (view["rx"], view["tx"], view["sessions"]) == (1000, 100, 2)
    sup.traffic("alice", inbound=150, outbound=1500)  # traffic after the last poll
    manager.create_client(create_body(name="bob", op="op-2"))
    settle(manager, clock)  # restart: a final poll runs before the stop
    assert sup.starts == 3
    view = manager.list_clients()["clients"][0]
    assert (view["rx"], view["tx"], view["sessions"]) == (1500, 150, 0)
    sup.traffic("alice", inbound=10, outbound=20)  # counters restarted from zero
    clock.now += 15
    manager.tick()
    view = manager.list_clients()["clients"][0]
    assert (view["rx"], view["tx"]) == (1520, 160)


def test_a_lower_reading_without_restart_is_a_counter_reset():
    assert fold(500, 300, 350) == (550, 350)
    assert fold(500, 300, 40) == (540, 40)
    rows = [
        {"username": "a", "inbound": 1, "outbound": 2, "sessions": 1},
        {"username": "a", "inbound": 3, "outbound": 4, "sessions": 1},
        {"username": 7, "inbound": 1}, "junk",
    ]
    assert aggregate(rows) == {"a": {"inbound": 4, "outbound": 6, "sessions": 2}}


def test_totals_persist_in_state(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    manager.create_client(create_body())
    settle(manager, clock)
    sup.traffic("alice", inbound=5, outbound=9)
    clock.now += 15
    manager.tick()
    again, _, _ = make_manager(tmp_path)
    view = again.list_clients()["clients"][0]
    assert (view["rx"], view["tx"]) == (9, 5)


def test_unreachable_metrics_do_not_disturb_totals(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    manager.create_client(create_body())
    settle(manager, clock)
    sup.traffic("alice", inbound=5, outbound=9)
    manager.fetch = lambda: None
    clock.now += 15
    manager.tick()
    assert manager.list_clients()["clients"][0]["rx"] == 0


def test_a_crashed_endpoint_is_started_again_with_backoff(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    sup.is_running = False
    manager.tick()  # inside the backoff window of the first start
    assert sup.starts == 1
    clock.now += 3
    manager.tick()
    assert sup.starts == 2
    sup.is_running = False
    manager.tick()
    assert sup.starts == 2
    clock.now += 10
    manager.tick()
    assert sup.starts == 3


# ---------------------------------------------------------------- health, endpoint


def test_missing_certificate_is_degraded_not_a_crash(tmp_path):
    manager, sup, clock = make_manager(tmp_path, cert=False)
    health = manager.health()
    assert health["status"] == "degraded" and health["code"] == "certificate_missing"
    assert sup.starts == 0
    manager.create_client(create_body())  # the API keeps working
    (tmp_path / "cert.pem").write_text("cert")
    (tmp_path / "key.pem").write_text("key")
    clock.now += 5
    manager.tick()
    assert sup.starts == 1 and manager.health()["status"] == "ok"
    assert manager.health()["clients"] == 1 and manager.health()["endpoint"] == {"running": True, "pid": 4242}


def test_health_reports_a_dead_endpoint(tmp_path):
    manager, sup, _ = make_manager(tmp_path)
    sup.is_running = False
    assert manager.health()["code"] == "endpoint_down"


def test_endpoint_info_without_a_readable_certificate(tmp_path):
    manager, _, _ = make_manager(tmp_path, TT_VERSION="v1.1.0")
    info = manager.endpoint()
    assert info["hostname"] == "gate.example.com" and info["listen"] == "127.0.0.1:4453"
    assert info["public_port"] == 443 and info["version"] == "v1.1.0"
    assert info["certificate_trusted"] is False and info["certificate_der_b64"] is None
    assert info["fingerprint"] is None


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_self_signed_certificate_is_exposed_for_pinning(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", "30", "-subj", "/CN=gate.example.com"],
        check=True, capture_output=True,
    )
    found = inspect_certificate(cert)
    assert found and found["trusted"] is False and len(found["fingerprint"]) == 64
    manager, _, _ = make_manager(tmp_path, cert=False)
    info = manager.endpoint()
    assert info["certificate_trusted"] is False
    assert info["certificate_der_b64"] and info["fingerprint"] == found["fingerprint"]
    assert inspect_certificate(tmp_path / "missing.pem") is None


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_a_fullchain_file_is_read_by_its_leaf_and_counts_as_trusted(tmp_path):
    """Let's Encrypt's fullchain.pem is the leaf plus an intermediate: the leaf is the first block."""
    def run(*argv):
        subprocess.run(["openssl", *argv], check=True, capture_output=True, cwd=tmp_path)

    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-days", "30", "-subj", "/CN=Test Intermediate")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr",
        "-subj", "/CN=gate.example.com")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "leaf.pem", "-days", "30")
    run("x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der")
    chain = tmp_path / "fullchain.pem"
    chain.write_text((tmp_path / "leaf.pem").read_text() + (tmp_path / "ca.pem").read_text())
    found = inspect_certificate(chain)
    assert found is not None, "a two-certificate chain must still be readable"
    assert found["trusted"] is True
    assert found["der"] == (tmp_path / "leaf.der").read_bytes()


# ---------------------------------------------------------------- egress


def test_egress_default_apply_and_rollback(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    direct = manager.egress()
    assert (direct["mode"], direct["address"]) == ("direct", None) and len(direct["revision"]) == 64
    plan = manager.egress_plan({"mode": "socks5", "address": "127.0.0.1:41080"})
    assert plan["changed"] is True and plan["current"]["revision"] == direct["revision"]
    assert manager.egress()["mode"] == "direct"  # planning changes nothing
    applied = manager.egress_apply({"mode": "socks5", "address": "127.0.0.1:41080"})
    assert applied["mode"] == "socks5" and applied["revision"] == plan["proposed"]["revision"]
    vpn = tomllib.loads((tmp_path / "state" / "vpn.toml").read_text())
    assert vpn["forward_protocol"] == {"socks5": {"address": "127.0.0.1:41080", "extended_auth": False}}
    settle(manager, clock)
    assert sup.vpn_at_start[-1]["forward_protocol"]["socks5"]["extended_auth"] is False
    starts = sup.starts
    assert manager.egress_apply({"mode": "socks5", "address": "127.0.0.1:41080"}) == applied
    settle(manager, clock)
    assert sup.starts == starts  # same document: no restart
    back = manager.egress_rollback()
    assert back == direct
    assert tomllib.loads((tmp_path / "state" / "vpn.toml").read_text())["forward_protocol"] == {"direct": {}}
    with pytest.raises(ApiError) as nothing:
        manager.egress_rollback()
    assert nothing.value.code == "no_previous"


@pytest.mark.parametrize(
    "body",
    [
        {"mode": "http"}, {"mode": "socks5"}, {"mode": "socks5", "address": "10.0.0.1:1080"},
        {"mode": "socks5", "address": "127.0.0.1:80"}, {"mode": "direct", "address": "127.0.0.1:41080"},
        {"mode": "socks5", "address": "127.0.0.1:41080", "x": 1}, {},
    ],
)
def test_egress_rejects_bad_documents(tmp_path, body):
    manager, _, _ = make_manager(tmp_path)
    with pytest.raises(ApiError) as exc:
        manager.egress_apply(body)
    assert exc.value.status == 422


def test_egress_survives_a_manager_restart(tmp_path):
    manager, _, _ = make_manager(tmp_path)
    manager.egress_apply({"mode": "socks5", "address": "127.0.0.1:41080"})
    again, _, _ = make_manager(tmp_path)
    assert again.egress()["address"] == "127.0.0.1:41080"
    assert "socks5" in (tmp_path / "state" / "vpn.toml").read_text()


# ---------------------------------------------------------------- HTTP


@pytest.fixture
def api():
    tmp = Path(tempfile.mkdtemp(prefix="tt"))
    manager, sup, clock = make_manager(tmp)
    server = ManagerHTTPServer(tmp / "m.sock", manager, TOKEN)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield tmp, manager, server
    server.shutdown()
    server.server_close()
    shutil.rmtree(tmp, ignore_errors=True)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)


def call(server, method, path, body=None, token=TOKEN, raw=None):
    conn = UnixConnection(server.socket_path)
    headers = {"X-Trusttunnel-Token": token} if token else {}
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    if data is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    return response.status, (json.loads(payload) if payload else None)


def test_socket_is_private_and_token_is_required(api):
    tmp, _, server = api
    assert stat.S_IMODE(os.stat(server.socket_path).st_mode) == 0o660
    for token in (None, "wrong" * 10):
        status, body = call(server, "GET", "/v1/health", token=token)
        assert status == 401 and body == {"detail": "unauthorized", "code": "unauthorized"}
    assert call(server, "POST", "/v1/clients", create_body(), token=None)[0] == 401
    with pytest.raises(ValueError):
        ManagerHTTPServer(tmp / "x.sock", None, "short")


def test_http_client_lifecycle(api):
    _, _, server = api
    status, body = call(server, "POST", "/v1/clients", create_body())
    assert status == 200 and body["client"]["username"] == "alice"
    assert call(server, "POST", "/v1/clients", create_body()) == (200, body)
    assert call(server, "POST", "/v1/clients", create_body(op="o2"))[1]["code"] == "exists"
    assert call(server, "GET", "/v1/clients")[1]["clients"][0]["username"] == "alice"
    assert call(server, "POST", "/v1/clients/alice/disable")[1]["client"]["enabled"] is False
    assert call(server, "POST", "/v1/clients/alice/enable")[1]["client"]["enabled"] is True
    assert call(server, "POST", "/v1/clients/alice/enable", {"x": 1})[0] == 422
    status, body = call(server, "POST", "/v1/clients/alice/rotate", {"operation_id": "r", "password": "n" * 32})
    assert status == 200 and body["client"]["revision"] == 4
    assert call(server, "DELETE", "/v1/clients/alice") == (204, None)
    assert call(server, "POST", "/v1/clients/alice/enable")[0] == 404
    assert call(server, "GET", "/v1/nope")[0] == 404


def test_http_health_endpoint_and_egress(api):
    _, _, server = api
    assert call(server, "GET", "/v1/health")[1]["status"] == "ok"
    assert call(server, "GET", "/v1/endpoint")[1]["hostname"] == "gate.example.com"
    assert call(server, "GET", "/v1/egress")[1]["mode"] == "direct"
    doc = {"mode": "socks5", "address": "127.0.0.1:41080"}
    assert call(server, "POST", "/v1/egress/plan", doc)[1]["changed"] is True
    assert call(server, "POST", "/v1/egress/apply", doc)[1]["mode"] == "socks5"
    assert call(server, "POST", "/v1/egress/rollback")[1]["mode"] == "direct"
    assert call(server, "POST", "/v1/egress/apply", {"mode": "x"})[1]["code"] == "invalid_request"


def test_body_cap_and_malformed_bodies(api):
    _, _, server = api
    assert call(server, "POST", "/v1/clients", raw=b"x" * (MAX_BODY + 1))[0] == 422
    assert call(server, "POST", "/v1/clients", raw=b"[1]")[0] == 422
    assert call(server, "POST", "/v1/clients", raw=b"{nope")[0] == 422


def test_internal_errors_do_not_leak(api):
    _, manager, server = api
    manager.list_clients = lambda: 1 / 0
    status, body = call(server, "GET", "/v1/clients")
    assert status == 500 and body == {"detail": "manager operation failed", "code": "internal_error"}


def test_healthcheck_probe(api):
    tmp, manager, server = api
    token_file = tmp / "tok"
    token_file.write_text(TOKEN)
    assert healthcheck.check(server.socket_path, token_file) is True
    token_file.write_text("w" * 40)
    assert healthcheck.check(server.socket_path, token_file) is False
    token_file.write_text("short")
    assert healthcheck.check(server.socket_path, token_file) is False
    assert healthcheck.check(tmp / "none.sock", token_file) is False


def test_healthcheck_tolerates_only_a_missing_certificate(tmp_path):
    manager, sup, _ = make_manager(tmp_path, cert=False)
    server = ManagerHTTPServer(tmp_path / "m.sock", manager, TOKEN)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token_file = tmp_path / "tok"
    token_file.write_text(TOKEN)
    try:
        assert healthcheck.check(server.socket_path, token_file) is True
        (tmp_path / "cert.pem").write_text("c")
        (tmp_path / "key.pem").write_text("k")  # certificate there, endpoint not started yet
        assert healthcheck.check(server.socket_path, token_file) is False
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------- certificate renewal


def test_renewed_certificate_triggers_one_reload_and_no_restart(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    clock.now += 61
    manager.tick()
    assert sup.reloads == 0  # unchanged since start
    (tmp_path / "cert.pem").write_text("renewed")
    clock.now += 61
    manager.tick()
    assert (sup.reloads, sup.starts, sup.stops) == (1, 1, 0)
    clock.now += 61
    manager.tick()
    assert sup.reloads == 1


def test_reload_failure_is_logged_without_content_and_retried(tmp_path, caplog):
    manager, sup, clock = make_manager(tmp_path)
    (tmp_path / "key.pem").write_text("SECRET-KEY-BYTES")
    sup.reload_error = OSError("SECRET-KEY-BYTES")
    clock.now += 61
    with caplog.at_level("INFO"):
        manager.tick()
    assert "SECRET-KEY-BYTES" not in caplog.text and "reload failed" in caplog.text
    sup.reload_error = None
    clock.now += 61
    manager.tick()
    assert sup.reloads == 1


def test_endpoint_info_follows_the_renewed_certificate(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("needs openssl")
    manager, _, _ = make_manager(tmp_path, cert=False)
    seen = []
    for cn in ("a.example.com", "b.example.com"):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "key.pem"),
             "-out", str(tmp_path / "cert.pem"), "-days", "30", "-subj", f"/CN={cn}"],
            check=True, capture_output=True,
        )
        seen.append(manager.endpoint()["fingerprint"])
    assert seen[0] != seen[1]


# ---------------------------------------------------------------- idle placeholder client


def test_zero_client_credentials_file_is_valid_and_non_empty(tmp_path):
    """The real endpoint panics on a credentials file without clients."""
    manager, _, _ = make_manager(tmp_path)
    text = (tmp_path / "state" / "credentials.toml").read_text()
    clients = tomllib.loads(text)["client"]
    assert len(clients) >= 1 and clients[0]["username"] == "proxy-control-idle"
    assert len(clients[0]["password"]) >= 32
    manager.create_client(create_body())
    manager.set_enabled("alice", False)
    assert len(raw_credentials(tmp_path)) == 1  # the last real client is disabled: still valid
    manager.delete_client("alice")
    assert len(raw_credentials(tmp_path)) == 1


def test_placeholder_is_stable_private_and_never_toggles_a_restart(tmp_path):
    manager, sup, clock = make_manager(tmp_path)
    password = raw_credentials(tmp_path)[0]["password"]
    again, _, _ = make_manager(tmp_path)
    assert raw_credentials(tmp_path)[0]["password"] == password
    assert json.loads((tmp_path / "state" / "state.json").read_text())["placeholder"] == password
    assert stat.S_IMODE((tmp_path / "state" / "state.json").stat().st_mode) == 0o600
    settle(manager, clock)
    starts = sup.starts
    manager.create_client(create_body())
    settle(manager, clock)
    assert sup.starts == starts + 1  # one restart for the real change only


def test_placeholder_username_is_reserved_and_invisible(tmp_path, caplog):
    manager, sup, clock = make_manager(tmp_path)
    password = raw_credentials(tmp_path)[0]["password"]
    with pytest.raises(ApiError) as exc:
        manager.create_client(create_body(name="proxy-control-idle"))
    assert (exc.value.status, exc.value.code) == (422, "reserved_username")
    manager.create_client(create_body())
    sup.traffic("proxy-control-idle", inbound=7, outbound=7)
    sup.traffic("alice", inbound=1, outbound=2)
    settle(manager, clock)
    clock.now += 15
    with caplog.at_level("DEBUG"):
        manager.tick()
    shown = json.dumps([manager.list_clients(), manager.health(), manager.endpoint(), manager.egress()])
    assert "proxy-control-idle" not in shown and password not in shown
    assert manager.health()["clients"] == 1
    assert [c["username"] for c in manager.list_clients()["clients"]] == ["alice"]
    assert password not in caplog.text and "proxy-control-idle" not in json.dumps(
        json.loads((tmp_path / "state" / "state.json").read_text())["clients"]
    )
