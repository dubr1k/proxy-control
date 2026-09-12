from __future__ import annotations

import http.server
import json
import ssl
import threading

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
    for bad in ("http://panel.example.com", "https://panel.example.com/?x=1", "https://10.0.0.1", "https://localhost"):
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
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()


def _start_tls_server(cert, key):
    server = _OneShotTLSServer(("127.0.0.1", 0), _EmptyHandler)
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
        digest = fingerprint(f"https://127.0.0.1:{server.server_port}")
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
        good = NodeClient(base_url, "k", tls_verify="pin", pinned_sha256=expected)
        assert (await good.identity()) == {}

        bad = NodeClient(base_url, "k", tls_verify="pin", pinned_sha256="0" * 64)
        with pytest.raises(NodeUnreachable):
            await bad.identity()
    finally:
        server.shutdown()
        thread.join(timeout=2)
