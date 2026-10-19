"""TrustTunnel: the panel chooses the password, the node's manager keeps the endpoint's account list.

The credential is the password itself (UTF-8, `token_urlsafe(24)`), generated and escrowed by the
panel. The manager receives it too — the endpoint authenticates by Basic credentials from a file —
so unlike AmneziaWG a node holds a working secret; it does not hold anything a lost node could
not re-issue by rotation. What a client needs besides the account (the domain the TLS endpoint
answers to, the public port, a certificate the system store does not trust) is learned at issue
time into the grant's options and rendered from there: the deep link and the client config are
built from escrow alone, with no call to the node.

TCP only (`upstream_protocol = http2`): there is no UDP rule and no QUIC anywhere.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import secrets

from ..clients.models import AccessGrant, GrantIntent
from ..trusttunnel import TrusttunnelError
from ..trusttunnel_link import encode_deeplink
from .base import (
    AccessArtifact,
    AdapterError,
    AppliedEgress,
    AppliedGrant,
    CredentialPlan,
    EgressTarget,
    GrantRef,
    ObservedGrant,
    ObservedInventory,
    Preflight,
    applied_egress_from_view,
    egress_error,
    egress_target_from_view,
)

LINK_KIND, TOML_KIND, MANUAL_KIND = "trusttunnel_link", "trusttunnel_toml", "trusttunnel_manual"
LINK_MEDIA_TYPE, TOML_MEDIA_TYPE, MANUAL_MEDIA_TYPE = "text/uri-list", "application/toml", "application/json"
EGRESS_CAPABILITIES = ("whole_direct",)
PASSWORD = re.compile(r"[\x21-\x7e]{8,128}")


def new_credential() -> bytes:
    """A fresh password, as the escrowed secret."""
    return secrets.token_urlsafe(24).encode()


def parse_credential(plaintext: bytes) -> str:
    """The manager's rule: printable ASCII without spaces, 8 to 128 characters."""
    try:
        password = plaintext.decode("ascii")
    except (UnicodeDecodeError, AttributeError) as exc:
        raise AdapterError("the TrustTunnel credential is malformed") from exc
    if not PASSWORD.fullmatch(password):
        raise AdapterError("the TrustTunnel credential is malformed")
    return password


def learned_options(endpoint: dict) -> dict:
    """The option fields the deep link and the client config are built from, as the manager's
    endpoint reported them. A certificate the system store trusts is not stored."""
    certificate = None if endpoint.get("certificate_trusted") is True else endpoint.get("certificate_der_b64")
    return {"hostname": endpoint.get("hostname"), "port": endpoint.get("public_port") or 443,
            "certificate_der_b64": certificate or None}


def split_der(chain: bytes) -> list[bytes]:
    """The certificates of a concatenated DER chain (each is a DER SEQUENCE)."""
    certificates, offset = [], 0
    while offset < len(chain):
        if chain[offset] != 0x30 or offset + 2 > len(chain):
            raise AdapterError("the endpoint certificate is not DER")
        first = chain[offset + 1]
        if first < 0x80:
            header, length = 2, first
        else:
            count = first & 0x7F
            if count == 0 or count > 4 or offset + 2 + count > len(chain):
                raise AdapterError("the endpoint certificate is not DER")
            header, length = 2 + count, int.from_bytes(chain[offset + 2:offset + 2 + count], "big")
        end = offset + header + length
        if end > len(chain):
            raise AdapterError("the endpoint certificate is not DER")
        certificates.append(chain[offset:end])
        offset = end
    return certificates


def certificate_pem(certificate_der_b64: str) -> str:
    try:
        chain = base64.b64decode(certificate_der_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AdapterError("the endpoint certificate is malformed") from exc
    blocks = []
    for der in split_der(chain):
        body = base64.b64encode(der).decode()
        lines = [body[i:i + 64] for i in range(0, len(body), 64)]
        blocks.append("\n".join(["-----BEGIN CERTIFICATE-----", *lines, "-----END CERTIFICATE-----"]))
    return "\n".join(blocks) + "\n"


def _toml_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch in '"\\':
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _host(options, public_host: str) -> str:
    """The name the client dials and puts in its TLS handshake: the endpoint's own domain, as the
    manager reported it (`public_host` only stands in for an access that predates that)."""
    host = options.hostname or public_host
    if not host:
        raise AdapterError("this TrustTunnel access has not learned its endpoint yet")
    return host


def render_toml(grant: AccessGrant, credential: bytes, *, public_host: str) -> str:
    """The client's `trusttunnel_client.toml`, with the keys the vendor documents for the CLI client."""
    options, password = grant.options, parse_credential(credential)
    host = _host(options, public_host)
    port = options.port or 443
    endpoint = [
        f"hostname = {_toml_string(host)}",
        f"addresses = [{_toml_string(f'{host}:{port}')}]",
        f"username = {_toml_string(grant.runtime_username)}",
        f"password = {_toml_string(password)}",
        "skip_verification = false",
    ]
    if options.certificate_der_b64:
        endpoint.append(f"certificate = {_toml_string(certificate_pem(options.certificate_der_b64))}")
    endpoint.append('upstream_protocol = "http2"')
    if options.name:
        endpoint.append(f"name = {_toml_string(options.name)}")
    return "\n".join([
        'loglevel = "info"', 'vpn_mode = "general"', "killswitch_enabled = true", "",
        "[endpoint]", *endpoint, "",
        "[listener.tun]", 'included_routes = ["0.0.0.0/0", "2000::/3"]', "mtu_size = 1350", "",
    ])


def render_link(grant: AccessGrant, credential: bytes, *, public_host: str) -> str:
    options, password = grant.options, parse_credential(credential)
    host = _host(options, public_host)
    certificate = None
    if options.certificate_der_b64:
        certificate = base64.b64decode(options.certificate_der_b64)
    return encode_deeplink(hostname=host, addresses=[f"{host}:{options.port or 443}"], username=grant.runtime_username,
                           password=password, certificate_der=certificate, name=options.name)


def render_manual(grant: AccessGrant, credential: bytes, *, public_host: str) -> str:
    """The fields a person types into a client that imports neither the `tt://` link nor the TOML
    (Throne, Surge, Shadowrocket…), as one JSON object. TCP only: HTTP/2, QUIC off. The Surge policy
    line is the vendor's documented form; it carries no certificate, so for an endpoint whose
    certificate the system store does not trust the PEM below has to be trusted by the client."""
    options, password = grant.options, parse_credential(credential)
    host = _host(options, public_host)
    port = options.port or 443
    certificate = certificate_pem(options.certificate_der_b64) if options.certificate_der_b64 else None
    return json.dumps({
        "server": host, "port": port, "username": grant.runtime_username, "password": password, "sni": host,
        "protocol": "HTTP/2", "quic": False, "certificate_pem": certificate,
        "surge": f"trust-tunnel, {host}, {port}, username={grant.runtime_username}, password={password}",
    }, ensure_ascii=False, indent=2)


class TrusttunnelAdapter:
    protocol = "trusttunnel"
    credential_origin = "caller"
    # The manager's account list is write-only for the panel: a password is never read back.
    capture_supported = False
    accepts_caller_credential = True

    def __init__(self, client, *, public_host: str = "", router=None):
        self.client = client
        self.public_host = public_host
        # The node's Xray-router adapter (v1.6): the endpoint's SOCKS5 upstream is its loopback ingress,
        # so the target offers it only while the router serves the `trusttunnel` section.
        self.router = router

    async def _clients(self) -> list[dict]:
        try:
            return await self.client.clients()
        except TrusttunnelError as exc:
            raise AdapterError("TrustTunnel manager unavailable") from exc

    async def endpoint(self) -> dict:
        try:
            return await self.client.endpoint()
        except TrusttunnelError as exc:
            raise AdapterError("TrustTunnel manager unavailable") from exc

    async def discover(self) -> ObservedInventory:
        return ObservedInventory(tuple(
            ObservedGrant(runtime_username=row["username"], enabled=row.get("enabled") is not False,
                          options={}, revision=str(row.get("revision")))
            for row in await self._clients() if isinstance(row, dict) and isinstance(row.get("username"), str)))

    async def preflight(self, intent: GrantIntent) -> Preflight:
        endpoint = await self.endpoint()
        if not endpoint.get("hostname"):
            return Preflight(False, "TrustTunnel has no hostname on this node")
        if any(row.get("username") == intent.runtime_username for row in await self._clients()):
            return Preflight(False, "runtime username already exists")
        return Preflight(True)

    @staticmethod
    def _password(credential: CredentialPlan) -> str:
        if credential.origin != "caller":
            raise AdapterError("TrustTunnel needs a caller-supplied password so the panel can escrow it")
        return parse_credential(credential.plaintext)

    async def create(self, operation_id: str, intent: GrantIntent, credential: CredentialPlan) -> AppliedGrant:
        password = self._password(credential)
        # Learned before anything is written: a node without a usable endpoint refuses cleanly.
        endpoint = await self.endpoint()
        if not endpoint.get("hostname"):
            raise AdapterError("TrustTunnel has no hostname on this node")
        payload = {"operation_id": operation_id, "username": intent.runtime_username, "password": password}
        recovered = False
        try:
            result = await self.client.create_client(payload)
        except TrusttunnelError as exc:
            if exc.status_code in (404, 409, 422) and exc.code != "operation_conflict":
                raise AdapterError("TrustTunnel manager refused the request") from exc
            recovered = True  # the reply may have been lost: the same operation id replays safely
            try:
                result = await self.client.create_client(payload)
            except TrusttunnelError as again:
                raise AdapterError("TrustTunnel manager refused the request") from again
        client = result["client"]
        return AppliedGrant(runtime_username=client["username"], enabled=client.get("enabled") is not False,
                            credential=credential.plaintext, revision=str(client.get("revision")),
                            artifact_template=learned_options(endpoint), recovered=recovered)

    async def _state(self, grant: GrantRef, action: str) -> AppliedGrant:
        try:
            result = await self.client.client_state(grant.runtime_username, action)
        except TrusttunnelError as exc:
            raise AdapterError("TrustTunnel manager refused the request") from exc
        return AppliedGrant(runtime_username=grant.runtime_username, enabled=action == "enable",
                            revision=str(result["client"].get("revision")))

    async def enable(self, grant: GrantRef) -> AppliedGrant:
        return await self._state(grant, "enable")

    async def disable(self, grant: GrantRef) -> AppliedGrant:
        return await self._state(grant, "disable")

    async def rotate(self, operation_id: str, grant: GrantRef, credential: CredentialPlan) -> AppliedGrant:
        payload = {"operation_id": operation_id, "password": self._password(credential)}
        recovered = False
        try:
            result = await self.client.rotate_client(grant.runtime_username, payload)
        except TrusttunnelError as exc:
            if exc.status_code in (404, 409, 422):
                raise AdapterError("TrustTunnel manager refused the request") from exc
            recovered = True
            try:
                result = await self.client.rotate_client(grant.runtime_username, payload)
            except TrusttunnelError as again:
                raise AdapterError("TrustTunnel manager refused the request") from again
        client = result["client"]
        return AppliedGrant(runtime_username=grant.runtime_username, enabled=client.get("enabled") is not False,
                            credential=credential.plaintext, revision=str(client.get("revision")), recovered=recovered)

    async def delete(self, grant: GrantRef) -> None:
        try:
            await self.client.delete_client(grant.runtime_username)
        except TrusttunnelError as exc:
            raise AdapterError("TrustTunnel manager refused the request", already_gone=exc.status_code == 404) from exc

    async def capture(self, grant: GrantRef) -> bytes | None:
        return None

    async def update_options(self, grant: GrantRef, options: dict) -> AppliedGrant | None:
        # Hostname, port and certificate are the manager's to say, never an input; the display
        # name is presentation only and changes the rendered artifacts, not the node.
        return None

    def render_artifacts(self, grant: AccessGrant, credential: bytes, *, public_host: str) -> list[AccessArtifact]:
        return [
            AccessArtifact(kind=LINK_KIND, label="Ссылка TrustTunnel", media_type=LINK_MEDIA_TYPE,
                           value=render_link(grant, credential, public_host=public_host)),
            AccessArtifact(kind=TOML_KIND, label="Конфиг TrustTunnel (TOML)", media_type=TOML_MEDIA_TYPE,
                           value=render_toml(grant, credential, public_host=public_host)),
            AccessArtifact(kind=MANUAL_KIND, label="Данные для ручной настройки", media_type=MANUAL_MEDIA_TYPE,
                           value=render_manual(grant, credential, public_host=public_host)),
        ]

    # ------------------------------------------------------------------
    # egress (service level): the manager's own document, `{mode: direct|socks5, address}`. The
    # manager takes no revision or operation id: the adapter checks the revision against what the
    # manager runs now (an apply of the document it already runs is a no-op there). The routing
    # service integration (the router ingress, the compiler) is separate.
    # ------------------------------------------------------------------

    @staticmethod
    def _document(view: dict) -> dict:
        return {"mode": "direct"} if view.get("mode") == "direct" else {"mode": view.get("mode"), "address": view.get("address")}

    @staticmethod
    def _egress_failure(exc: TrusttunnelError) -> AdapterError:
        code = "egress_no_previous" if exc.code == "no_previous" else exc.code
        return egress_error("TrustTunnel", exc.status_code, code)

    async def _egress_view(self) -> dict:
        try:
            return await self.client.egress()
        except TrusttunnelError as exc:
            raise self._egress_failure(exc) from exc

    async def _egress_current(self, expected_revision: str) -> dict:
        view = await self._egress_view()
        if view.get("revision") != expected_revision:
            raise AdapterError("TrustTunnel egress revision does not match", code="egress_conflict")
        return view

    async def egress_target(self) -> EgressTarget | None:
        view = await self._egress_view()
        providers = {}
        if self.router is not None and (await self.router.target(self.protocol)).available:
            providers["router"] = {"reachable": True}
        # `socks5` is the manager's word for an upstream; the compiler's vocabulary calls it `proxy`.
        return egress_target_from_view(self.protocol, "trusttunnel_native", {
            "revision": view.get("revision"), "mode": "proxy" if view.get("mode") == "socks5" else "direct",
            "document": self._document(view), "providers": providers, "capabilities": list(EGRESS_CAPABILITIES)})

    async def plan_egress(self, document: dict, *, expected_revision: str) -> dict:
        await self._egress_current(expected_revision)
        try:
            plan = await self.client.egress_plan(document)
        except TrusttunnelError as exc:
            raise self._egress_failure(exc) from exc
        target = plan["proposed"]["revision"]
        return {"revision": expected_revision, "target_revision": target, "rendered_sha256": target,
                "diff": ["-current", "+planned"] if plan.get("changed") else [], "warnings": [],
                "reachability": {}, "restart_required": False}

    @staticmethod
    def _applied(view: dict) -> AppliedEgress:
        document = TrusttunnelAdapter._document(view)
        return applied_egress_from_view({"revision": view.get("revision"), "applied": document})

    async def apply_egress(self, document: dict, *, expected_revision: str, operation_id: str) -> AppliedEgress:
        await self._egress_current(expected_revision)
        try:
            view = await self.client.egress_apply(document)
        except TrusttunnelError as exc:
            raise self._egress_failure(exc) from exc
        return self._applied(view)

    async def rollback_egress(self, *, expected_revision: str) -> AppliedEgress:
        await self._egress_current(expected_revision)
        try:
            view = await self.client.egress_rollback()
        except TrusttunnelError as exc:
            raise self._egress_failure(exc) from exc
        return self._applied(view)
