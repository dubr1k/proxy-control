"""MTProxy through Telemt: the manager owns the secret, and the live link carries it.

Telemt has no operation id, so a lost reply cannot be replayed. What saves the grant is
that the credential is readable back: after an indeterminate call the adapter asks what
the runtime holds now rather than guessing or creating a second account.
"""
from __future__ import annotations

from urllib.parse import quote

from ..clients.models import AccessGrant, GrantIntent
from ..telemt import TelemtError, TelemtIndeterminate, access_from_user
from .base import (
    AccessArtifact,
    AdapterError,
    AppliedGrant,
    CredentialPlan,
    GrantRef,
    ObservedGrant,
    ObservedInventory,
    Preflight,
)

OPTION_FIELDS = (
    "data_quota_bytes",
    "rate_limit_up_bps",
    "rate_limit_down_bps",
    "max_tcp_conns",
    "max_unique_ips",
)


def _link(host: str, port: int, secret: str) -> str:
    return f"tg://proxy?server={quote(host, safe='')}&port={port}&secret={quote(secret, safe='')}"


class TelemtAdapter:
    protocol = "mtproxy"
    credential_origin = "manager"
    capture_supported = True

    def __init__(self, client, *, public_host: str = "", public_port: int = 443):
        # Telemt owns the public host: it comes back inside the connection link, so the
        # panel has no configured value to insist on here.
        self.client = client
        self.public_host = public_host
        self.public_port = public_port

    async def _row(self, username: str) -> dict | None:
        for row in await self.client.list_users():
            if isinstance(row, dict) and row.get("username") == username:
                return row
        return None

    async def discover(self) -> ObservedInventory:
        rows = await self.client.list_users()
        return ObservedInventory(
            tuple(
                ObservedGrant(
                    runtime_username=row["username"],
                    enabled=row.get("enabled") is not False,
                    options={key: row[key] for key in OPTION_FIELDS if key in row},
                )
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("username"), str)
            )
        )

    async def preflight(self, intent: GrantIntent) -> Preflight:
        if await self._row(intent.runtime_username) is not None:
            return Preflight(False, "runtime username already exists")
        return Preflight(True)

    def _applied(self, username: str, access: dict, *, enabled: bool, recovered: bool) -> AppliedGrant:
        """Everything a link needs comes out of the link Telemt returned.

        The host and port are learned the same way Mieru's share template is: Telemt
        owns them, the panel is not configured with them, and a subscription rebuilt
        from escrow must point where the runtime actually listens.
        """
        return AppliedGrant(
            runtime_username=username,
            enabled=enabled,
            credential=(access.get("secret") or "").encode(),
            artifact_template={
                "host": access.get("server") or self.public_host,
                "port": access.get("port") or self.public_port,
            },
            recovered=recovered,
        )

    @staticmethod
    def _link_access(result: dict) -> dict | None:
        """The credential is what the link carries, not the bare `secret` field.

        Telemt reports the raw secret while the Fake-TLS link prefixes it with `ee`.
        Escrowing the bare value would store something that cannot rebuild the link,
        so the adapter always takes the secret out of the link itself.
        """
        access = access_from_user(result.get("user") if isinstance(result, dict) else None)
        return None if access is None or not access.get("secret") else access

    async def _recover(self, username: str) -> AppliedGrant | None:
        access = await self.client.current_access(username)
        if access is None or not access.get("secret"):
            return None
        return self._applied(username, access, enabled=True, recovered=True)

    async def create(
        self, operation_id: str, intent: GrantIntent, credential: CredentialPlan
    ) -> AppliedGrant:
        if credential.origin != "manager":
            raise AdapterError("Telemt generates the MTProxy secret itself")
        try:
            created = await self.client.create_user(intent.runtime_username)
        except TelemtIndeterminate:
            recovered = await self._recover(intent.runtime_username)
            if recovered is not None:
                return recovered
            # Nothing was created, so a single retry is safe rather than a guess.
            created = await self.client.create_user(intent.runtime_username)
        except TelemtError as exc:
            raise AdapterError("Telemt refused the request") from exc
        access = self._link_access(created)
        if access is None:
            raise AdapterError("Telemt returned a user without a connection link")
        return self._applied(intent.runtime_username, access, enabled=True, recovered=False)

    async def _set_enabled(self, grant: GrantRef, enabled: bool) -> AppliedGrant:
        try:
            await self.client.set_enabled(grant.runtime_username, enabled)
        except TelemtError as exc:
            raise AdapterError("Telemt refused the request") from exc
        access = await self.client.current_access(grant.runtime_username)
        return self._applied(grant.runtime_username, access or {}, enabled=enabled, recovered=False)

    async def enable(self, grant: GrantRef) -> AppliedGrant:
        return await self._set_enabled(grant, True)

    async def disable(self, grant: GrantRef) -> AppliedGrant:
        return await self._set_enabled(grant, False)

    async def rotate(
        self, operation_id: str, grant: GrantRef, credential: CredentialPlan
    ) -> AppliedGrant:
        if credential.origin != "manager":
            raise AdapterError("Telemt generates the MTProxy secret itself")
        try:
            rotated = await self.client.rotate(grant.runtime_username)
        except TelemtIndeterminate:
            recovered = await self._recover(grant.runtime_username)
            if recovered is None:
                raise
            return recovered
        except TelemtError as exc:
            raise AdapterError("Telemt refused the request") from exc
        access = self._link_access(rotated)
        if access is None:
            raise AdapterError("Telemt returned a user without a connection link")
        return self._applied(grant.runtime_username, access, enabled=True, recovered=False)

    async def delete(self, grant: GrantRef) -> None:
        try:
            await self.client.delete_user(grant.runtime_username)
        except TelemtError as exc:
            raise AdapterError("Telemt refused the request") from exc

    async def capture(self, grant: GrantRef) -> bytes | None:
        """The live link is the credential, so an existing account needs no rotation."""
        access = await self.client.current_access(grant.runtime_username)
        secret = (access or {}).get("secret")
        return None if not secret else secret.encode()

    def render_artifacts(
        self, grant: AccessGrant, credential: bytes, *, public_host: str
    ) -> list[AccessArtifact]:
        options = grant.options.model_dump() if hasattr(grant.options, "model_dump") else {}
        # What the saga learned from Telemt's own link wins over any configured fallback.
        host = options.get("host") or public_host
        port = options.get("port") or self.public_port
        link = _link(host, port, credential.decode())
        return [
            AccessArtifact(
                kind="link",
                label="Ссылка Telegram",
                media_type="text/uri-list",
                value=link,
            )
        ]
