"""NaiveProxy: the caller chooses the password, so a lost reply is replayed, not guessed."""
from __future__ import annotations

from urllib.parse import quote, urlsplit

from ..clients.models import AccessGrant, GrantIntent
from ..naive import NaiveError
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


def _password(proxy_url: str) -> str | None:
    parts = urlsplit(proxy_url)
    return parts.password


def proxy_url(username: str, password: str, host: str) -> str:
    return f"https://{quote(username, safe='')}:{quote(password, safe='')}@{host}"


class NaiveAdapter:
    protocol = "naive"
    credential_origin = "caller"
    capture_supported = True

    def __init__(self, client, *, public_host: str):
        self.client = client
        self.public_host = public_host

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
                    enabled=row.get("enabled") is True,
                    options={"quota_bytes": row.get("quota_bytes")},
                )
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("username"), str)
            )
        )

    async def preflight(self, intent: GrantIntent) -> Preflight:
        if await self._row(intent.runtime_username) is not None:
            return Preflight(False, "runtime username already exists")
        return Preflight(True)

    def _applied(self, username: str, password: str, *, enabled: bool, recovered: bool) -> AppliedGrant:
        return AppliedGrant(
            runtime_username=username,
            enabled=enabled,
            credential=password.encode(),
            artifact_template={"host": self.public_host},
            recovered=recovered,
        )

    async def create(
        self, operation_id: str, intent: GrantIntent, credential: CredentialPlan
    ) -> AppliedGrant:
        if credential.origin != "caller":
            raise AdapterError("NaiveProxy needs a caller-supplied password")
        password = credential.plaintext.decode()
        quota = getattr(intent.options, "quota_bytes", None)
        try:
            await self.client.create(
                intent.runtime_username, quota, password=password, operation_id=operation_id
            )
            recovered = False
        except NaiveError:
            # The manager may have committed before the reply was lost: the same
            # operation id either replays that result or creates the account once.
            recovered = True
            try:
                await self.client.create(
                    intent.runtime_username, quota, password=password, operation_id=operation_id
                )
            except NaiveError as exc:
                raise self._unrecoverable(exc) from exc
        return self._applied(intent.runtime_username, password, enabled=True, recovered=recovered)

    @staticmethod
    def _unrecoverable(exc: NaiveError) -> AdapterError:
        if getattr(exc, "code", None) in {"result_unrecoverable", "operation_conflict"}:
            return ManualInterventionRequired("the NaiveProxy credential must be rotated")
        return AdapterError("NaiveProxy refused the request")

    async def _set_enabled(self, grant: GrantRef, enabled: bool) -> AppliedGrant:
        try:
            await self.client.set_enabled(grant.runtime_username, enabled)
            revealed = await self.client.reveal(grant.runtime_username)
        except NaiveError as exc:
            raise AdapterError("NaiveProxy refused the request") from exc
        return self._applied(
            grant.runtime_username, _password(revealed["proxy_url"]) or "", enabled=enabled, recovered=False
        )

    async def enable(self, grant: GrantRef) -> AppliedGrant:
        return await self._set_enabled(grant, True)

    async def disable(self, grant: GrantRef) -> AppliedGrant:
        return await self._set_enabled(grant, False)

    async def rotate(
        self, operation_id: str, grant: GrantRef, credential: CredentialPlan
    ) -> AppliedGrant:
        if credential.origin != "caller":
            raise AdapterError("NaiveProxy needs a caller-supplied password")
        password = credential.plaintext.decode()
        try:
            await self.client.rotate(
                grant.runtime_username, password=password, operation_id=operation_id
            )
            recovered = False
        except NaiveError:
            recovered = True
            try:
                await self.client.rotate(
                    grant.runtime_username, password=password, operation_id=operation_id
                )
            except NaiveError as exc:
                raise self._unrecoverable(exc) from exc
        return self._applied(grant.runtime_username, password, enabled=True, recovered=recovered)

    async def delete(self, grant: GrantRef) -> None:
        try:
            await self.client.delete(grant.runtime_username)
        except NaiveError as exc:
            raise AdapterError("NaiveProxy refused the request") from exc

    async def capture(self, grant: GrantRef) -> bytes | None:
        """The manager reveals the stored password, so adoption needs no rotation."""
        try:
            revealed = await self.client.reveal(grant.runtime_username)
        except NaiveError as exc:
            raise AdapterError("NaiveProxy refused the request") from exc
        password = _password(revealed.get("proxy_url", ""))
        return None if not password else password.encode()

    def render_artifacts(
        self, grant: AccessGrant, credential: bytes, *, public_host: str
    ) -> list[AccessArtifact]:
        url = proxy_url(grant.runtime_username, credential.decode(), public_host)
        return [
            AccessArtifact(
                kind="proxy_url",
                label="Адрес прокси",
                media_type="text/uri-list",
                value=url,
            )
        ]
