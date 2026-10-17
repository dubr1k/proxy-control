"""AmneziaWG: the panel chooses the client's keys, the node's manager owns the server side.

The credential is a small JSON document (`private_key` and `preshared_key`, base64) the panel
generates and escrows. The manager receives only the public key and the preshared key, so a
node never holds a client's private key and a lost node loses no access. The config a client
needs — its address, the interface port of its protocol version, the server key and the
obfuscation parameters it must repeat — is learned at issue time into the grant's options and
rendered from there, with no call to the node.

Versions 1.5, 2.0 and 3.1 differ in server-side parameters, so each runs on its own interface
and port; a grant names one version and the manager puts the peer on that interface.
"""
from __future__ import annotations

import base64
import binascii
import json
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..amneziawg import AmneziawgError
from ..clients.models import AWG_VERSIONS, AccessGrant, GrantIntent
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
)

CONF_MEDIA_TYPE = "text/x-amneziawg-conf"
# Client-config key order: the interface keys the apps expect first, parameters as the docs list them.
_OBFUSCATION_ORDER = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
                      "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition")


def new_credential() -> bytes:
    """A fresh client key pair's private half and a preshared key, as the escrowed secret."""
    private = X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return json.dumps({"private_key": base64.b64encode(private).decode(),
                       "preshared_key": base64.b64encode(secrets.token_bytes(32)).decode()},
                      separators=(",", ":")).encode()


def parse_credential(plaintext: bytes) -> tuple[str, str]:
    try:
        document = json.loads(plaintext)
        private, preshared = document["private_key"], document["preshared_key"]
        for value in (private, preshared):
            if len(base64.b64decode(value, validate=True)) != 32:
                raise ValueError("a key must be 32 bytes")
    except (ValueError, KeyError, TypeError, binascii.Error) as exc:
        raise AdapterError("the AmneziaWG credential is malformed") from exc
    return private, preshared


def public_key_of(private_b64: str) -> str:
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    return base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def learned_options(peer: dict, instance: dict) -> dict:
    """The option fields the client's config is built from, as the manager reported them."""
    return {
        "version": instance["version"], "address": peer["address"], "port": instance["port"],
        "server_public_key": instance["server_public_key"], "mtu": instance.get("mtu"),
        "dns": list(instance.get("dns") or []), "obfuscation": dict(instance.get("obfuscation") or {}),
    }


def render_conf(grant: AccessGrant, credential: bytes, *, public_host: str) -> str:
    options = grant.options
    private, preshared = parse_credential(credential)
    if not (options.address and options.port and options.server_public_key):
        raise AdapterError("this AmneziaWG access has not learned its server details yet")
    if not public_host:
        raise AdapterError("no public host is known for this node")
    interface = [f"PrivateKey = {private}", f"Address = {options.address}/32"]
    if options.dns:
        interface.append("DNS = " + ", ".join(options.dns))
    if options.mtu:
        interface.append(f"MTU = {options.mtu}")
    interface += [f"{key} = {options.obfuscation[key]}" for key in _OBFUSCATION_ORDER if key in options.obfuscation]
    peer = [f"PublicKey = {options.server_public_key}", f"PresharedKey = {preshared}",
            "AllowedIPs = 0.0.0.0/0, ::/0", f"Endpoint = {public_host}:{options.port}", "PersistentKeepalive = 25"]
    return "\n".join(["[Interface]", *interface, "", "[Peer]", *peer, ""])


class AmneziawgAdapter:
    protocol = "amneziawg"
    credential_origin = "caller"
    # The manager keeps public keys only, so a client's private key cannot be read back.
    capture_supported = False
    accepts_caller_credential = True

    def __init__(self, client, *, public_host: str = ""):
        self.client = client
        self.public_host = public_host

    async def _peers(self) -> list[dict]:
        try:
            return await self.client.peers()
        except AmneziawgError as exc:
            raise AdapterError("AmneziaWG manager unavailable") from exc

    async def _instances(self) -> dict[str, dict]:
        try:
            return {item["version"]: item for item in await self.client.instances()}
        except AmneziawgError as exc:
            raise AdapterError("AmneziaWG manager unavailable") from exc

    async def versions(self) -> list[str]:
        return sorted(await self._instances(), key=AWG_VERSIONS.index)

    async def discover(self) -> ObservedInventory:
        return ObservedInventory(tuple(
            ObservedGrant(runtime_username=row["username"], enabled=row.get("enabled") is not False,
                          options={"version": row.get("version"), "address": row.get("address")},
                          revision=str(row.get("revision")))
            for row in await self._peers() if isinstance(row, dict) and isinstance(row.get("username"), str)))

    async def preflight(self, intent: GrantIntent) -> Preflight:
        version = intent.options.version
        if version not in await self._instances():
            return Preflight(False, f"AmneziaWG {version} is not enabled on this node")
        if any(row.get("username") == intent.runtime_username for row in await self._peers()):
            return Preflight(False, "runtime username already exists")
        return Preflight(True)

    @staticmethod
    def _keys(credential: CredentialPlan) -> tuple[str, str]:
        if credential.origin != "caller":
            raise AdapterError("AmneziaWG needs a caller-supplied key pair so the panel can escrow it")
        private, preshared = parse_credential(credential.plaintext)
        return public_key_of(private), preshared

    def _applied(self, result: dict, credential: bytes | None, *, recovered: bool = False) -> AppliedGrant:
        peer, instance = result["peer"], result.get("instance") or {}
        template = learned_options(peer, instance) if instance else {"address": peer["address"]}
        return AppliedGrant(runtime_username=peer["username"], enabled=peer.get("enabled") is not False,
                            credential=credential, revision=str(peer.get("revision")),
                            artifact_template=template, recovered=recovered)

    async def create(self, operation_id: str, intent: GrantIntent, credential: CredentialPlan) -> AppliedGrant:
        public, preshared = self._keys(credential)
        payload = {"operation_id": operation_id, "username": intent.runtime_username,
                   "version": intent.options.version, "public_key": public, "preshared_key": preshared}
        recovered = False
        try:
            result = await self.client.create_peer(payload)
        except AmneziawgError as exc:
            if exc.status_code in (404, 409, 422) and exc.code != "operation_conflict":
                raise AdapterError("AmneziaWG manager refused the request") from exc
            recovered = True  # the reply may have been lost: the same operation id replays safely
            try:
                result = await self.client.create_peer(payload)
            except AmneziawgError as again:
                raise AdapterError("AmneziaWG manager refused the request") from again
        return self._applied(result, credential.plaintext, recovered=recovered)

    async def _state(self, grant: GrantRef, action: str) -> AppliedGrant:
        try:
            result = await self.client.peer_state(grant.runtime_username, action)
        except AmneziawgError as exc:
            raise AdapterError("AmneziaWG manager refused the request") from exc
        return AppliedGrant(runtime_username=grant.runtime_username, enabled=action == "enable",
                            revision=str(result["peer"].get("revision")))

    async def enable(self, grant: GrantRef) -> AppliedGrant:
        return await self._state(grant, "enable")

    async def disable(self, grant: GrantRef) -> AppliedGrant:
        return await self._state(grant, "disable")

    async def rotate(self, operation_id: str, grant: GrantRef, credential: CredentialPlan) -> AppliedGrant:
        public, preshared = self._keys(credential)
        payload = {"operation_id": operation_id, "public_key": public, "preshared_key": preshared}
        recovered = False
        try:
            result = await self.client.rotate_peer(grant.runtime_username, payload)
        except AmneziawgError as exc:
            if exc.status_code in (404, 409, 422):
                raise AdapterError("AmneziaWG manager refused the request") from exc
            recovered = True
            try:
                result = await self.client.rotate_peer(grant.runtime_username, payload)
            except AmneziawgError as again:
                raise AdapterError("AmneziaWG manager refused the request") from again
        peer = result["peer"]
        return AppliedGrant(runtime_username=grant.runtime_username, enabled=peer.get("enabled") is not False,
                            credential=credential.plaintext, revision=str(peer.get("revision")), recovered=recovered)

    async def delete(self, grant: GrantRef) -> None:
        try:
            await self.client.delete_peer(grant.runtime_username)
        except AmneziawgError as exc:
            raise AdapterError("AmneziaWG manager refused the request", already_gone=exc.status_code == 404) from exc

    async def capture(self, grant: GrantRef) -> bytes | None:
        return None

    async def update_options(self, grant: GrantRef, options: dict) -> AppliedGrant | None:
        # The version cannot change in place: a peer lives on one interface. Anything the panel
        # learned (address, port, keys) is the manager's to say, never an input.
        return None

    def render_artifacts(self, grant: AccessGrant, credential: bytes, *, public_host: str) -> list[AccessArtifact]:
        return [AccessArtifact(kind="awg_conf", label=f"AmneziaWG {grant.options.version}",
                               media_type=CONF_MEDIA_TYPE,
                               value=render_conf(grant, credential, public_host=public_host))]

    # No egress: the tunnel leaves through the host's own route.
    async def egress_target(self) -> EgressTarget | None:
        return None

    async def plan_egress(self, document: dict, *, expected_revision: str) -> dict:
        raise AdapterError("AmneziaWG has no egress control", code="egress_unsupported")

    async def apply_egress(self, document: dict, *, expected_revision: str, operation_id: str) -> AppliedEgress:
        raise AdapterError("AmneziaWG has no egress control", code="egress_unsupported")

    async def rollback_egress(self, *, expected_revision: str) -> AppliedEgress:
        raise AdapterError("AmneziaWG has no egress control", code="egress_unsupported")

