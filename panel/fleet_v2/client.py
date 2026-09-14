"""The central panel's typed HTTP client to one node panel (spec §6, ADR 008)."""
from __future__ import annotations

import hashlib
import ipaddress
import json as json_module
import socket
import ssl
from urllib.parse import urlsplit

import httpcore
import httpx

from .protocol import ObservedGeneration, PushRequest, PushResponse

TLS_MODES = ("verify", "pin")
# A node's answer is read at most this far (spec §5.2 bounds the push at 64 KiB; the
# inventory of a node with `MAX_RESOURCES` users per protocol is well under this). A
# longer body is a misbehaving node, refused before a byte of it is parsed.
MAX_RESPONSE_BYTES = 1_048_576


class NodeUnreachable(Exception):
    """Transport-level failure: DNS, connect, TLS handshake, timeout, or a pin mismatch."""


class NodeAuthFailed(Exception):
    """401 (bad/disabled key) or 403 (wrong scope)."""


class NodeRejected(Exception):
    """Any other >=400 response, with the node's `{detail, code}` body preserved."""

    def __init__(self, status: int, code: str | None, detail: str):
        super().__init__(detail or code or str(status))
        self.status, self.code, self.detail = status, code, detail


def validate_panel_url(url: str, *, allow_private: bool) -> str:
    """https:// only, no query/fragment/userinfo, and no private/loopback/link-local
    host unless the caller opts in (linking a node on a lab or LAN)."""
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment or parts.username:
        raise ValueError("panel URL must be https://host[:port][/base-path]")
    host = parts.hostname
    try:
        address = ipaddress.ip_address(host)
        private = not address.is_global
    except ValueError:
        private = host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local")
    if private and not allow_private:
        raise ValueError("private or local addresses need allow_private_address")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


def fingerprint(url: str, *, timeout: float = 5.0) -> str:
    """SHA-256 of the leaf certificate presented at `url`, hex-encoded, chain unverified.
    Used to capture a pin when a node is linked (spec §4: pin-on-trust for lab/self-signed certs)."""
    parts = urlsplit(url)
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((parts.hostname, parts.port or 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=parts.hostname) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


class _PinningStream(httpcore.AsyncNetworkStream):
    """A plaintext stream whose `start_tls` refuses to return until the peer's leaf certificate
    matches the pin — so no HTTP byte (the bearer key, a generation's credentials) is ever
    written to an unpinned peer. httpcore calls `start_tls` once per connection, before
    `handle_async_request` writes the first request line."""

    def __init__(self, inner: httpcore.AsyncNetworkStream, expected: str):
        self._inner, self._expected = inner, expected

    async def read(self, max_bytes, timeout=None):
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer, timeout=None):
        await self._inner.write(buffer, timeout)

    async def aclose(self):
        await self._inner.aclose()

    def get_extra_info(self, info):
        return self._inner.get_extra_info(info)

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        tls = await self._inner.start_tls(ssl_context, server_hostname=server_hostname, timeout=timeout)
        ssl_object = tls.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if certificate is None or hashlib.sha256(certificate).hexdigest() != self._expected:
            await tls.aclose()
            raise httpcore.ConnectError("pinned certificate mismatch")
        return tls


class _PinningBackend(httpcore.AsyncNetworkBackend):
    """Wrap the anyio backend so every TCP connection's TLS handshake is pinned (see `_PinningStream`)."""

    def __init__(self, expected: str):
        self._inner, self._expected = httpcore.AnyIOBackend(), expected

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        stream = await self._inner.connect_tcp(host, port, timeout=timeout, local_address=local_address,
                                               socket_options=socket_options)
        return _PinningStream(stream, self._expected)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
        raise httpcore.ConnectError("pinned transport is TCP-only")

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


class _PinnedTransport(httpx.AsyncHTTPTransport):
    """Verify the leaf certificate by SHA-256 instead of by chain (self-signed/lab certs).
    Chain verification is off (`CERT_NONE`), so the pin is the only trust anchor — it is
    checked inside the handshake (`_PinningStream.start_tls`), never after a response."""

    def __init__(self, expected: str, **kw):
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        super().__init__(verify=context, **kw)
        self.expected = expected.lower()
        # Replace httpx's pool with one whose network backend pins the handshake (httpx exposes no hook
        # for the backend); the pool limits are httpx's defaults (100 / 20 / 5 s), HTTP/1.1 only.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context, network_backend=_PinningBackend(self.expected),
            max_connections=100, max_keepalive_connections=20, keepalive_expiry=5.0, http1=True, http2=False)


class NodeClient:
    """Bearer-authenticated client to one node's `/api/fleet/v2/*` routes (spec §5.2)."""

    def __init__(self, base_url: str, api_key: str, *, tls_verify: str = "verify", pinned_sha256: str | None = None,
                 timeout: float = 30.0, connect_timeout: float = 5.0, transport=None):
        if tls_verify not in TLS_MODES:
            raise ValueError("tls_verify must be verify or pin")
        if tls_verify == "pin" and not pinned_sha256:
            raise ValueError("pin mode needs pinned_sha256")
        self.base_url = base_url.rstrip("/")
        # The key never lands in an attribute we might log or repr elsewhere; only the header dict holds it.
        self.headers = {"Authorization": f"Bearer {api_key}"}
        self.timeout = httpx.Timeout(timeout, connect=connect_timeout)
        self.transport = transport or (_PinnedTransport(pinned_sha256) if tls_verify == "pin" else None)

    async def _call(self, method: str, path: str, json=None) -> tuple[int, dict]:
        content = bytearray()
        try:
            async with httpx.AsyncClient(base_url=self.base_url, headers=self.headers, timeout=self.timeout,
                                         transport=self.transport) as client:
                async with client.stream(method, path, json=json) as response:
                    status = response.status_code
                    if status in (401, 403):
                        raise NodeAuthFailed()
                    async for chunk in response.aiter_bytes():
                        content += chunk
                        if len(content) > MAX_RESPONSE_BYTES:
                            raise NodeRejected(status, "response_too_large", "")
        except (httpx.TransportError, ssl.SSLError) as exc:
            # Never include the exception's str() with the API key: httpx transport errors
            # never carry it (it only ever appears in the Authorization header we sent).
            raise NodeUnreachable(type(exc).__name__) from exc
        try:
            body = json_module.loads(content) if content else {}
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        if status >= 400:
            raise NodeRejected(status, body.get("code"), str(body.get("detail", "")))
        return status, body

    async def identity(self) -> dict:
        return (await self._call("GET", "/api/fleet/v2/identity"))[1]

    async def status(self) -> dict:
        return (await self._call("GET", "/api/fleet/v2/status"))[1]

    async def inventory(self) -> dict:
        return (await self._call("GET", "/api/fleet/v2/inventory"))[1]

    async def push(self, request: PushRequest) -> tuple[int, PushResponse]:
        status, body = await self._call("PUT", "/api/fleet/v2/generation", json=request.wire())
        return status, PushResponse.model_validate(body)

    async def observed(self) -> ObservedGeneration:
        return ObservedGeneration.model_validate((await self._call("GET", "/api/fleet/v2/observed"))[1])

    async def capture(self, resources: list[dict], *, purpose: str = "escrow") -> dict:
        """`escrow` reads back the credentials of users this central owns on the node;
        `import` is the operator's adoption of the node's own users (the only purpose the
        node answers for a local user). The default travels implicitly: a v0.3 node
        (`extra="forbid"`) still answers an escrow read during a nodes-first upgrade."""
        body = {"resources": resources}
        if purpose != "escrow":
            body["purpose"] = purpose
        return (await self._call("POST", "/api/fleet/v2/credentials/capture", json=body))[1]

    async def update_version(self, component: str, version: str, expected_current: str | None) -> dict:
        return (await self._call("POST", "/api/fleet/v2/versions/update",
                                 json={"component": component, "version": version,
                                       "expected_current": expected_current}))[1]

    async def unlink(self) -> dict:
        return (await self._call("POST", "/api/fleet/v2/unlink"))[1]
