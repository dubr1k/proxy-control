from __future__ import annotations

import http.server
import json
import ssl
import socket
import threading

import anyio
import httpcore
import httpx
import pytest

from panel.agent_transport import CertificateAuthority
from panel.fleet_v2.client import (
    NodeAuthFailed,
    NodeClient,
    NodeRejected,
    NodeUnreachable,
    fingerprint,
    validate_panel_url,
)
from panel.fleet_v2.protocol import GenerationDocument, PushRequest

pytestmark = pytest.mark.anyio


def _client(handler, **kw):
    return NodeClient("https://node.example", "pc_k", transport=httpx.MockTransport(handler), **kw)


async def test_identity_sends_bearer_and_parses_json():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers["authorization"]
        seen["path"] = request.url.path
        return httpx.Response(200, json={"guid": "g", "api_version": 2})

    body = await _client(handler).identity()
    assert body["guid"] == "g" and seen == {"auth": "Bearer pc_k", "path": "/api/fleet/v2/identity"}


async def test_status_codes_map_to_typed_errors():
    async def expect(status, exc, **json):
        with pytest.raises(exc):
            await _client(lambda r: httpx.Response(status, json=json)).identity()

    await expect(401, NodeAuthFailed)
    await expect(403, NodeAuthFailed)
    await expect(409, NodeRejected, code="stale_generation")
    await expect(500, NodeRejected)
    with pytest.raises(NodeUnreachable):
        def boom(_request):
            raise httpx.ConnectError("refused")
        await _client(boom).identity()


async def test_push_returns_status_and_typed_response():
    doc = GenerationDocument(node_guid="n", master_guid="m", generation=1, previous_generation=0,
                             created_at=1, created_by="c", resources=[])

    def handler(request):
        assert request.method == "PUT" and request.url.path == "/api/fleet/v2/generation"
        return httpx.Response(202, json={"observed": {"applied_generation": 1, "digest": "d", "reconcile_state": "applying",
                                                      "resources": [], "reported_at": 1}, "credentials": {}})

    status, response = await _client(handler).push(PushRequest(expected_guid="n", generation=doc))
    assert status == 202 and response.observed.reconcile_state == "applying"


def test_url_validation_refuses_http_query_and_private_hosts():
    assert validate_panel_url("https://panel.example.com/", allow_private=False) == "https://panel.example.com"
    for bad in ("http://panel.example.com", "https://panel.example.com/?x=1", "https://10.0.0.1", "https://localhost",
                "https://@panel.example.com", "https://:synthetic@panel.example.com"):
        with pytest.raises(ValueError):
            validate_panel_url(bad, allow_private=False)
    assert validate_panel_url("https://10.0.0.1:8443", allow_private=True) == "https://10.0.0.1:8443"


def test_pin_mode_requires_a_fingerprint():
    with pytest.raises(ValueError):
        NodeClient("https://node.example", "k", tls_verify="pin")
    with pytest.raises(ValueError):
        NodeClient("https://node.example", "k", tls_verify="skip")


# --- additional coverage beyond the brief's Step 1 tests ---

async def test_nodereject_exposes_status_code_and_detail_when_present():
    def handler(request):
        return httpx.Response(409, json={"detail": "generation is stale", "code": "stale_generation"})

    with pytest.raises(NodeRejected) as excinfo:
        await _client(handler).identity()
    assert (excinfo.value.status, excinfo.value.code, excinfo.value.detail) == (409, "stale_generation", "generation is stale")


async def test_nodereject_tolerates_a_body_without_code_or_json():
    def handler(request):
        return httpx.Response(500, content=b"internal error", headers={"content-type": "text/plain"})

    with pytest.raises(NodeRejected) as excinfo:
        await _client(handler).identity()
    assert excinfo.value.status == 500 and excinfo.value.code is None


async def test_observed_defaults_to_idle_shape():
    def handler(request):
        assert request.url.path == "/api/fleet/v2/observed"
        return httpx.Response(200, json={"applied_generation": 0, "digest": "", "reconcile_state": "idle",
                                         "resources": [], "reported_at": 0})

    observed = await _client(handler).observed()
    assert observed.applied_generation == 0 and observed.reconcile_state == "idle"


async def test_capture_sends_bounded_resource_list_and_returns_body_verbatim():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"credentials": {"naive:alice": "s3cr3t", "mieru:bob": None},
                                         "unsupported": ["mieru:bob"]})

    body = await _client(handler).capture([{"protocol": "naive", "runtime_username": "alice"}])
    assert seen["body"] == {"resources": [{"protocol": "naive", "runtime_username": "alice"}]}
    assert body["credentials"]["naive:alice"] == "s3cr3t"


async def test_update_version_posts_component_version_and_expected_current():
    seen = {}

    def handler(request):
        assert request.url.path == "/api/fleet/v2/versions/update"
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"component": "telemt", "version": "1.2.3"})

    await _client(handler).update_version("telemt", "1.2.3", "1.2.2")
    assert seen["body"] == {"component": "telemt", "version": "1.2.3", "expected_current": "1.2.2"}


async def test_unlink_posts_and_returns_dict():
    def handler(request):
        assert request.method == "POST" and request.url.path == "/api/fleet/v2/unlink"
        return httpx.Response(200, json={"released": 3})

    assert await _client(handler).unlink() == {"released": 3}


async def test_status_and_inventory_use_expected_paths():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={})

    client = _client(handler)
    await client.status()
    await client.inventory()
    assert seen == ["/api/fleet/v2/status", "/api/fleet/v2/inventory"]


async def test_api_key_never_appears_in_the_unreachable_exception():
    def boom(_request):
        raise httpx.ConnectTimeout("timed out")

    client = NodeClient("https://node.example", "super-secret-key", transport=httpx.MockTransport(boom))
    with pytest.raises(NodeUnreachable) as excinfo:
        await client.identity()
    assert "super-secret-key" not in str(excinfo.value)


class _OneShotTLSServer(http.server.HTTPServer):
    allow_reuse_address = True


class _EmptyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def do_GET(self):
        self.server.requests.append(self.path)
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()


def _start_tls_server(cert, key):
    server = _OneShotTLSServer(("127.0.0.1", 0), _EmptyHandler)
    server.requests = []  # every HTTP request the handler saw; a pin mismatch must leave it empty
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_fingerprint_matches_the_real_leaf_certificate(tmp_path):
    ca = CertificateAuthority(tmp_path / "ca")
    ca.initialize("test fleet CA")
    key, cert = ca.issue_server("127.0.0.1", ["127.0.0.1"])
    expected = ca.certificate_metadata(cert)["fingerprint_sha256"]
    server, thread = _start_tls_server(cert, key)
    try:
        digest = fingerprint(f"https://127.0.0.1:{server.server_port}", allow_private=True)
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert digest == expected


async def test_pinned_transport_accepts_matching_and_rejects_mismatched_pin(tmp_path):
    ca = CertificateAuthority(tmp_path / "ca")
    ca.initialize("test fleet CA")
    key, cert = ca.issue_server("127.0.0.1", ["127.0.0.1"])
    expected = ca.certificate_metadata(cert)["fingerprint_sha256"]
    server, thread = _start_tls_server(cert, key)
    try:
        base_url = f"https://127.0.0.1:{server.server_port}"
        good = NodeClient(base_url, "k", tls_verify="pin", pinned_sha256=expected, allow_private_address=True)
        assert (await good.identity()) == {}
        assert server.requests == ["/api/fleet/v2/identity"]

        # A pin mismatch is an active MITM by definition: the handshake must fail before a
        # single byte of HTTP (the bearer key, the credentials of a push) reaches the peer.
        bad = NodeClient(base_url, "k", tls_verify="pin", pinned_sha256="0" * 64, allow_private_address=True)
        with pytest.raises(NodeUnreachable):
            await bad.identity()
        assert server.requests == ["/api/fleet/v2/identity"], "the mismatched server must not see a request"
    finally:
        server.shutdown()
        thread.join(timeout=2)


@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["::1"], ["169.254.169.254"], ["224.0.0.1"],
                                      ["::ffff:127.0.0.1"], ["8.8.8.8", "10.0.0.1"]])
@pytest.mark.parametrize("mode", ["verify", "pin"])
async def test_dns_private_addresses_are_refused_before_connect(monkeypatch, addresses, mode):
    connected = []

    async def resolve(*args, **kwargs):
        return [(0, 0, 0, "", (ip, 443)) for ip in addresses]

    async def connect(self, host, port, **kwargs):
        connected.append(host)
        raise httpcore.ConnectError("test connection")

    monkeypatch.setattr(anyio, "getaddrinfo", resolve)
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect)
    client = NodeClient("https://node.example", "synthetic-key", tls_verify=mode, pinned_sha256="0" * 64)
    with pytest.raises(NodeUnreachable):
        await client.identity()
    assert connected == []


async def test_dns_is_checked_again_for_each_connection_and_only_numeric_ip_is_dialed(monkeypatch):
    connected, names, hosts = [], [], []
    addresses = iter(["8.8.8.8", "127.0.0.1"])

    async def resolve(*args, **kwargs):
        return [(0, 0, 0, "", (next(addresses), 443))]

    class Stream(httpcore.AsyncMockStream):
        async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            names.append(server_hostname)
            return self

        async def write(self, buffer, timeout=None):
            if b"Host:" in buffer:
                hosts.append(b"Host: node.example" in buffer)

    async def connect(self, host, port, **kwargs):
        connected.append(host)
        return Stream([b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"])

    monkeypatch.setattr(anyio, "getaddrinfo", resolve)
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect)
    client = NodeClient("https://node.example", "synthetic-key")
    assert await client.identity() == {}
    with pytest.raises(NodeUnreachable):
        await client.identity()
    assert connected == ["8.8.8.8"]
    assert names == ["node.example"] and hosts == [True]


async def test_explicit_private_opt_in_reaches_loopback(monkeypatch):
    connected = []

    async def connect(self, host, port, **kwargs):
        connected.append(host)
        raise httpcore.ConnectError("test connection")

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect)
    client = NodeClient("https://127.0.0.1", "synthetic-key", allow_private_address=True)
    with pytest.raises(NodeUnreachable):
        await client.identity()
    assert connected == ["127.0.0.1"]


def test_fingerprint_dns_private_answer_is_refused_before_connect(monkeypatch):
    connected = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(0, 0, 0, "", ("127.0.0.1", 443))])

    def connect(*args, **kwargs):
        connected.append(args)
        raise OSError("test connection")

    monkeypatch.setattr(socket, "create_connection", connect)
    with pytest.raises(OSError):
        fingerprint("https://node.example")
    assert connected == []


async def test_dns_timeout_is_bounded_and_typed(monkeypatch):
    async def resolve(*args, **kwargs):
        await anyio.sleep_forever()

    monkeypatch.setattr(anyio, "getaddrinfo", resolve)
    with pytest.raises(NodeUnreachable, match="ConnectTimeout"):
        await NodeClient("https://node.example", "key", connect_timeout=0.01).identity()


async def test_public_ipv6_failure_falls_back_to_validated_ipv4(monkeypatch):
    connected = []

    async def resolve(*args, **kwargs):
        return [(0, 0, 0, "", (ip, 443)) for ip in ("2001:4860:4860::8888", "8.8.8.8")]

    async def connect(self, host, port, **kwargs):
        connected.append(host)
        raise httpcore.ConnectError("test connection")

    monkeypatch.setattr(anyio, "getaddrinfo", resolve)
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect)
    with pytest.raises(NodeUnreachable):
        await NodeClient("https://node.example", "key").identity()
    assert connected == ["2001:4860:4860::8888", "8.8.8.8"]


async def test_redirect_never_sends_the_bearer_key_to_another_origin():
    seen = []

    def redirect(request):
        seen.append(request.url.host)
        return httpx.Response(302, headers={"Location": "https://127.0.0.1/internal"})

    await _client(redirect).identity()
    assert seen == ["node.example"]


async def test_explicit_client_scope_reuses_http_client_and_closes_once(monkeypatch):
    created, closed = [], []
    original = httpx.AsyncClient

    class TrackedClient(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

        async def aclose(self):
            closed.append(self)
            await super().aclose()

    monkeypatch.setattr(httpx, "AsyncClient", TrackedClient)
    client = _client(lambda request: httpx.Response(200, json={}))
    async with client:
        await client.identity()
        await client.status()
        await client.inventory()
        assert len(created) == 1 and closed == []
    assert len(closed) == 1
    assert client._http_client is None


async def test_client_scope_closes_after_transport_failure():
    closed = []

    class Transport(httpx.MockTransport):
        async def aclose(self):
            closed.append(True)

    def fail(request):
        raise httpx.ConnectError("synthetic failure")

    client = NodeClient("https://node.example", "key", transport=Transport(fail))
    with pytest.raises(NodeUnreachable):
        async with client:
            await client.identity()
    assert closed == [True]
