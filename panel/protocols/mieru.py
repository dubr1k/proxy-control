"""Mieru: the caller chooses the password, but the manager keeps no copy of one it made.

That asymmetry is the whole reason `capture_supported` is False here. A grant imported
from a running mita cannot be adopted by reading it back — the only honest way to make
it renderable is to rotate, which invalidates the old `mierus://` link. The adapter
says so rather than inventing a link it cannot produce.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from ..clients.models import AccessGrant, GrantIntent
from ..mieru import MieruError
from .base import (
    AccessArtifact,
    AdapterError,
    AppliedGrant,
    CredentialPlan,
    GrantRef,
    ManualInterventionRequired,
    ObservedGrant,
    ObservedInventory,
    Preflight,
)

SHARE_TEMPLATE = "mierus://{username}:{password}@{host}?profile={profile}&port={port}&protocol=TCP"


def share_url(username: str, password: str, host: str, *, port: int = 8443) -> str:
    return SHARE_TEMPLATE.format(
        username=quote(username, safe=""),
        password=quote(password, safe=""),
        host=host,
        profile=quote(username),
        port=port,
    )


@dataclass(frozen=True)
class MieruShare:
    """A `mierus://` link taken apart: what every client config is built from."""

    username: str
    password: str
    host: str
    is_ip: bool
    profile: str
    # Each binding is {"port": int} or {"portRange": "a-b"} plus {"protocol": TCP|UDP},
    # in mita's own `portBindings` shape.
    bindings: tuple[dict, ...]
    mtu: int = 1400

    @property
    def exact_ports(self) -> list[int] | None:
        """Ports as integers, or None when any binding is a range."""
        ports = [binding["port"] for binding in self.bindings if "port" in binding]
        return ports if len(ports) == len(self.bindings) else None


def parse_share_url(value) -> MieruShare:
    """Validate a `mierus://` link strictly; anything odd is a ValueError, never a guess."""
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("share url is not a string of sane length")
    parts = urlsplit(value)
    query = parse_qsl(parts.query, keep_blank_values=True)
    authority_port = parts.port  # raises ValueError on a malformed authority
    values: dict[str, list[str]] = {}
    for key, item in query:
        values.setdefault(key, []).append(item)
    ports = values.get("port", [])
    protocols = values.get("protocol", [])
    if (
        parts.scheme != "mierus"
        or not parts.username
        or not parts.password
        or not parts.hostname
        or authority_port is not None
        or parts.path not in ("", "/")
        or parts.fragment
        or len(values.get("profile", [])) != 1
        or not values["profile"][0]
        or not ports
        or len(ports) != len(protocols)
        or any(protocol not in {"TCP", "UDP"} for protocol in protocols)
    ):
        raise ValueError("share url has an unexpected shape")

    bindings = []
    for port, protocol in zip(ports, protocols, strict=True):
        if re.fullmatch(r"[0-9]{1,5}", port) and 1 <= int(port) <= 65535:
            bindings.append({"port": int(port), "protocol": protocol})
            continue
        match = re.fullmatch(r"([0-9]{1,5})-([0-9]{1,5})", port)
        if not match or not 1 <= int(match[1]) <= int(match[2]) <= 65535:
            raise ValueError("share url carries an invalid port")
        bindings.append({"portRange": port, "protocol": protocol})

    mtu_values = values.get("mtu", [])
    if len(mtu_values) > 1 or (mtu_values and not re.fullmatch(r"[0-9]{4,5}", mtu_values[0])):
        raise ValueError("share url carries an invalid mtu")
    mtu = int(mtu_values[0]) if mtu_values else 1400
    if not 1280 <= mtu <= 1500:
        raise ValueError("share url carries an mtu out of range")

    try:
        host, is_ip = str(ipaddress.ip_address(parts.hostname)), True
    except ValueError:
        host, is_ip = parts.hostname, False
    return MieruShare(
        username=unquote(parts.username),
        password=unquote(parts.password),
        host=host,
        is_ip=is_ip,
        profile=values["profile"][0],
        bindings=tuple(bindings),
        mtu=mtu,
    )


def singbox_outbounds(share: MieruShare, *, tag) -> list[dict] | None:
    """The `mieru` outbound Karing's sing-box core takes: one per exact port.

    A port range has no place in that shape, so the answer is None rather than a
    profile that silently drops bindings.
    """
    ports = share.exact_ports
    if ports is None:
        return None
    return [
        {
            "type": "mieru",
            "tag": tag(port, binding["protocol"]),
            "server": share.host,
            "server_port": port,
            "transport": binding["protocol"],
            "username": share.username,
            "password": share.password,
        }
        for port, binding in zip(ports, share.bindings, strict=True)
    ]


def template_from(share_url_value: str, username: str, password: str) -> str | None:
    """Turn the manager's real share URL into a template the panel can re-render.

    mita owns the public host and the port, so the shape has to be learned from what it
    returns rather than configured twice. Only the credential is replaced, and the
    result must still parse as a template, or it is discarded.
    """
    if not isinstance(share_url_value, str):
        return None
    credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    if credentials not in share_url_value:
        return None
    return share_url_value.replace(credentials, "{username}:{password}@", 1)


class MieruAdapter:
    protocol = "mieru"
    credential_origin = "caller"
    # mita stores only a hash, so a credential it generated cannot be read back.
    capture_supported = False

    def __init__(self, client, *, public_host: str = "", port: int = 8443):
        # mita owns the public host; it arrives inside the share URL.
        self.client = client
        self.public_host = public_host
        self.port = port

    async def _revision(self) -> str | None:
        try:
            return (await self.client.health()).get("revision")
        except MieruError as exc:
            raise AdapterError("Mieru manager unavailable") from exc

    async def _row(self, username: str) -> dict | None:
        for row in await self.client.list_users():
            if isinstance(row, dict) and row.get("username") == username:
                return row
        return None

    async def discover(self) -> ObservedInventory:
        revision = await self._revision()
        rows = await self.client.list_users()
        return ObservedInventory(
            tuple(
                ObservedGrant(
                    runtime_username=row["username"],
                    enabled=row.get("enabled") is not False,
                    options={"quotas": row.get("quotas", [])},
                    revision=revision,
                )
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("username"), str)
            )
        )

    async def preflight(self, intent: GrantIntent) -> Preflight:
        if await self._row(intent.runtime_username) is not None:
            return Preflight(False, "runtime username already exists")
        return Preflight(True)

    def _applied(
        self, username: str, password: str, revision, *, enabled: bool, recovered: bool, share=None
    ) -> AppliedGrant:
        template = template_from(share, username, password) if share else None
        return AppliedGrant(
            runtime_username=username,
            enabled=enabled,
            credential=password.encode(),
            revision=revision,
            artifact_template={
                "share_template": template or SHARE_TEMPLATE,
                "host": self.public_host,
                "port": self.port,
            },
            recovered=recovered,
        )

    @staticmethod
    def _unrecoverable(exc: MieruError) -> AdapterError:
        if getattr(exc, "code", None) in {"result_unrecoverable", "operation_conflict"}:
            return ManualInterventionRequired("the Mieru credential must be rotated")
        return AdapterError("Mieru manager refused the request")

    async def create(
        self, operation_id: str, intent: GrantIntent, credential: CredentialPlan
    ) -> AppliedGrant:
        if credential.origin != "caller":
            raise AdapterError("Mieru needs a caller-supplied password so the panel can escrow it")
        password = credential.plaintext.decode()
        quotas = [item.model_dump() for item in getattr(intent.options, "quotas", [])]
        payload = {
            "username": intent.runtime_username,
            "quotas": quotas,
            "expected_revision": await self._revision(),
            "password": password,
            "operation_id": operation_id,
        }
        try:
            result = await self.client.create(payload)
            recovered = False
        except MieruError:
            recovered = True
            try:
                result = await self.client.create({**payload, "expected_revision": await self._revision()})
            except MieruError as exc:
                raise self._unrecoverable(exc) from exc
        return self._applied(
            intent.runtime_username, password, result.get("revision"),
            enabled=True, recovered=recovered, share=result.get("share_url"),
        )

    async def _operation(self, grant: GrantRef, operation: str) -> AppliedGrant:
        revision = grant.revision or await self._revision()
        try:
            result = await self.client.operation(grant.runtime_username, operation, revision)
        except MieruError as exc:
            raise AdapterError("Mieru manager refused the request") from exc
        # Enabling and disabling never touch the credential, so none is reported.
        return AppliedGrant(
            runtime_username=grant.runtime_username,
            enabled=operation == "enable",
            revision=result.get("revision"),
            artifact_template={"share_template": SHARE_TEMPLATE, "host": self.public_host, "port": self.port},
        )

    async def enable(self, grant: GrantRef) -> AppliedGrant:
        return await self._operation(grant, "enable")

    async def disable(self, grant: GrantRef) -> AppliedGrant:
        return await self._operation(grant, "disable")

    async def rotate(
        self, operation_id: str, grant: GrantRef, credential: CredentialPlan
    ) -> AppliedGrant:
        if credential.origin != "caller":
            raise AdapterError("Mieru needs a caller-supplied password so the panel can escrow it")
        password = credential.plaintext.decode()
        revision = grant.revision or await self._revision()
        try:
            result = await self.client.rotate(
                grant.runtime_username, revision, password=password, operation_id=operation_id
            )
            recovered = False
        except MieruError:
            recovered = True
            try:
                result = await self.client.rotate(
                    grant.runtime_username, await self._revision(),
                    password=password, operation_id=operation_id,
                )
            except MieruError as exc:
                raise self._unrecoverable(exc) from exc
        return self._applied(
            grant.runtime_username, password, result.get("revision"),
            enabled=True, recovered=recovered, share=result.get("share_url"),
        )

    async def delete(self, grant: GrantRef) -> None:
        revision = grant.revision or await self._revision()
        try:
            await self.client.delete(grant.runtime_username, revision)
        except MieruError as exc:
            raise AdapterError("Mieru manager refused the request") from exc

    def share(self, username: str, password: str) -> str:
        """The `mierus://` link for a credential the panel already holds."""
        return share_url(username, password, self.public_host, port=self.port)

    async def capture(self, grant: GrantRef) -> bytes | None:
        """Always None: mita keeps a hash, so the credential cannot be read back."""
        return None

    def render_artifacts(
        self, grant: AccessGrant, credential: bytes, *, public_host: str
    ) -> list[AccessArtifact]:
        options = grant.options.model_dump() if hasattr(grant.options, "model_dump") else {}
        template = options.get("share_template") or SHARE_TEMPLATE
        # A learned template already carries mita's own host and port; the default one
        # still has placeholders. Passing every field suits both.
        value = template.format(
            username=quote(grant.runtime_username, safe=""),
            password=quote(credential.decode(), safe=""),
            host=public_host,
            profile=quote(grant.runtime_username),
            port=self.port,
        )
        return [
            AccessArtifact(
                kind="share_url",
                label="Ссылка Mieru",
                media_type="text/uri-list",
                value=value,
            )
        ]
