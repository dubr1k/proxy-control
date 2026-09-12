"""The central panel's typed HTTP client to one node panel (spec §6, ADR 008)."""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit

import httpx

from .protocol import ObservedGeneration, PushRequest, PushResponse

TLS_MODES = ("verify", "pin")


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


class _PinnedTransport(httpx.AsyncHTTPTransport):
    """Verify the leaf certificate by SHA-256 instead of by chain (self-signed/lab certs)."""

    def __init__(self, expected: str, **kw):
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        super().__init__(verify=context, **kw)
        self.expected = expected.lower()

    async def handle_async_request(self, request):
        response = await super().handle_async_request(request)
        stream = response.extensions.get("network_stream")
        certificate = stream.get_extra_info("ssl_object").getpeercert(binary_form=True) if stream else None
        if certificate is None or hashlib.sha256(certificate).hexdigest() != self.expected:
            await response.aclose()
            raise ssl.SSLCertVerificationError("pinned certificate mismatch")
        return response


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
        try:
            async with httpx.AsyncClient(base_url=self.base_url, headers=self.headers, timeout=self.timeout,
                                         transport=self.transport) as client:
                response = await client.request(method, path, json=json)
        except (httpx.TransportError, ssl.SSLError) as exc:
            # Never include the exception's str() with the API key: httpx transport errors
            # never carry it (it only ever appears in the Authorization header we sent).
            raise NodeUnreachable(type(exc).__name__) from exc
        if response.status_code in (401, 403):
            raise NodeAuthFailed()
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = {}
        if response.status_code >= 400:
            raise NodeRejected(response.status_code, body.get("code"), str(body.get("detail", "")))
        return response.status_code, body

    async def identity(self) -> dict:
        return (await self._call("GET", "/api/fleet/v2/identity"))[1]

    async def status(self) -> dict:
        return (await self._call("GET", "/api/fleet/v2/status"))[1]

    async def inventory(self) -> dict:
        return (await self._call("GET", "/api/fleet/v2/inventory"))[1]

    async def push(self, request: PushRequest) -> tuple[int, PushResponse]:
        status, body = await self._call("PUT", "/api/fleet/v2/generation", json=request.model_dump())
        return status, PushResponse.model_validate(body)

    async def observed(self) -> ObservedGeneration:
        return ObservedGeneration.model_validate((await self._call("GET", "/api/fleet/v2/observed"))[1])

    async def capture(self, resources: list[dict]) -> dict:
        return (await self._call("POST", "/api/fleet/v2/credentials/capture", json={"resources": resources}))[1]

    async def update_version(self, component: str, version: str, expected_current: str | None) -> dict:
        return (await self._call("POST", "/api/fleet/v2/versions/update",
                                 json={"component": component, "version": version,
                                       "expected_current": expected_current}))[1]

    async def unlink(self) -> dict:
        return (await self._call("POST", "/api/fleet/v2/unlink"))[1]
