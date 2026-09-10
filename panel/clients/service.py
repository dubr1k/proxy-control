"""Clients as an application service: one transaction per change, audit included.

Task 15 hangs subscription generation off `on_change`, which is why the hooks run
inside the same transaction as the change that triggered them: a rolled-back state
change must not leave a bumped generation behind.
"""
from __future__ import annotations

import secrets
import time
import uuid
from collections.abc import Callable

from ..audit import digest, record
from ..database import Database
from ..secrets_store import SecretStore
from .models import AccessGrant, Client
from .store import ClientConflict, ClientStore

STATES = ("active", "suspended", "archived")
CREDENTIAL_PURPOSE = "grant.credential"


class ClientService:
    def __init__(self, database: Database, secret_store: SecretStore, clock=time):
        self.database = database
        self.secrets = secret_store
        self.clock = clock
        self.store = ClientStore(database)
        self.on_change: list[Callable[[object, str], None]] = []
        # Filled in by create_app; adoption needs the protocol adapters.
        self.adapters: dict = {}

    def notify(self, db, client_id: str) -> None:
        """Run inside the caller's transaction: a rolled-back change bumps nothing."""
        for hook in self.on_change:
            hook(db, client_id)

    def new_client(self, db, display_name: str, *, now: int) -> Client:
        """Insert a client into the caller's transaction; import composes several of these."""
        client = Client(
            id=str(uuid.uuid4()),
            display_name=display_name,
            state="active",
            metadata={},
            created_at=now,
            updated_at=now,
        )
        self.store.insert_client(db, client)
        return client

    def create_client(self, display_name: str, *, actor: dict, ip: str, request_id: str | None = None) -> Client:
        now = int(self.clock.time())
        with self.database.transaction() as db:
            client = self.new_client(db, display_name, now=now)
            record(
                db,
                actor=actor,
                action="client.create",
                target=client.id,
                ip=ip,
                request_id=request_id,
                after_digest=digest(client.model_dump()),
            )
            self.notify(db, client.id)
        return client

    def set_state(self, client_id: str, state: str, *, actor: dict, ip: str, request_id: str | None = None) -> Client:
        if state not in STATES:
            raise ClientConflict(f"state must be one of {STATES}")
        now = int(self.clock.time())
        with self.database.transaction() as db:
            before = self.store.client(db, client_id)
            if state == "archived" and self.store.grants(db, client_id=client_id):
                # Archiving is the end of the client's life, so nothing may still be
                # provisioned in its name on any node.
                raise ClientConflict("client still has grants that are not deleted")
            self.store.set_client_state(db, client_id, state, updated_at=now)
            after = self.store.client(db, client_id)
            record(
                db,
                actor=actor,
                action=f"client.{state}",
                target=client_id,
                ip=ip,
                request_id=request_id,
                before_digest=digest(before.model_dump()),
                after_digest=digest(after.model_dump()),
            )
            self.notify(db, client_id)
            return after

    def _adapter(self, protocol: str):
        adapter = self.adapters.get(protocol)
        if adapter is None:
            raise ClientConflict(f"no adapter is configured for {protocol}")
        return adapter

    def _escrow(self, grant: AccessGrant, plaintext: bytes, *, rotated: bool, actor, ip, request_id):
        """Store the credential and point the grant at it — one transaction, no plaintext logged."""
        with self.database.transaction() as db:
            current = self.store.grant(db, grant.id)
            if current.secret_ref is not None:
                raise ClientConflict("the grant already has a stored credential")
            reference = self.secrets.store(
                db,
                secret_id=f"grant:{grant.id}",
                version=1,
                purpose=CREDENTIAL_PURPOSE,
                grant_id=grant.id,
                permitted_node_id=grant.node_id,
                plaintext=plaintext,
                state="active",
            )
            self.store.update_grant(
                db,
                grant.id,
                secret_id=reference.secret_id,
                secret_version=reference.version,
                updated_at=int(self.clock.time()),
            )
            record(
                db,
                actor=actor,
                action="grant.credential.adopt" if rotated else "grant.credential.capture",
                target=grant.id,
                ip=ip,
                request_id=request_id,
                # `rotated` is the fact an operator must see; the value never appears.
                detail={"protocol": grant.protocol, "rotated": rotated},
            )
            self.notify(db, current.client_id)
            return self.store.grant(db, grant.id)

    async def capture_credential(self, grant_id: str, *, actor: dict, ip: str, request_id: str | None = None):
        """Read the live credential and escrow it, without touching the runtime."""
        with self.database.connect() as db:
            grant = self.store.grant(db, grant_id)
        adapter = self._adapter(grant.protocol)
        if not adapter.capture_supported:
            raise ClientConflict(f"{grant.protocol} credential requires rotation: it cannot be read back")
        from ..protocols.base import GrantRef  # noqa: PLC0415 - avoids a cycle at import time

        plaintext = await adapter.capture(GrantRef(grant.protocol, grant.runtime_username))
        if not plaintext:
            raise ClientConflict("the runtime returned no credential to capture")
        return self._escrow(grant, plaintext, rotated=False, actor=actor, ip=ip, request_id=request_id)

    async def adopt_credential(
        self, grant_id: str, *, allow_rotation: bool, actor: dict, ip: str, request_id: str | None = None
    ):
        """Make an imported grant renderable, rotating only when the operator allowed it."""
        with self.database.connect() as db:
            grant = self.store.grant(db, grant_id)
        if grant.secret_ref is not None:
            raise ClientConflict("the grant already has a stored credential")
        adapter = self._adapter(grant.protocol)
        if adapter.capture_supported:
            return await self.capture_credential(grant_id, actor=actor, ip=ip, request_id=request_id)
        if not allow_rotation:
            # Rotation invalidates the link the subscriber holds today, so it is never
            # done implicitly.
            raise ClientConflict(
                f"{grant.protocol} credential requires rotation: the current link will stop working"
            )
        from ..protocols.base import CredentialPlan, GrantRef  # noqa: PLC0415

        password = secrets.token_urlsafe(24).encode()
        applied = await adapter.rotate(
            f"adopt:{grant_id}",
            GrantRef(grant.protocol, grant.runtime_username),
            CredentialPlan("caller", password),
        )
        return self._escrow(
            grant, applied.credential or password, rotated=True, actor=actor, ip=ip, request_id=request_id
        )

    def client_with_grants(self, client_id: str) -> tuple[Client, list[AccessGrant]]:
        with self.database.connect() as db:
            return self.store.client(db, client_id), self.store.grants(db, client_id=client_id)

    def list_clients(self) -> list[Client]:
        with self.database.connect() as db:
            return self.store.clients(db)
