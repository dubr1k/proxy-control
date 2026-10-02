"""Clients as an application service: one transaction per change, audit included.

Task 15 hangs subscription generation off `on_change`, which is why the hooks run
inside the same transaction as the change that triggered them: a rolled-back state
change must not leave a bumped generation behind.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
import uuid
from collections.abc import Callable

from ..audit import digest, record
from ..database import Database
from ..fleet_v2.guard import require_unmanaged
from ..fleet_v2.managed import ManagedStore
from ..nodes.models import LOCAL_NODE_ID
from ..secrets_store import SecretRef, SecretStore
from .models import AccessGrant, Client, effective_enabled
from .store import ClientConflict, ClientStore

STATES = ("active", "suspended", "archived")
CREDENTIAL_PURPOSE = "grant.credential"
log = logging.getLogger(__name__)


class ClientService:
    def __init__(self, database: Database, secret_store: SecretStore, clock=time):
        self.database = database
        self.secrets = secret_store
        self.clock = clock
        self.store = ClientStore(database)
        # Resources the central panel owns (ADR 003); capture/adopt ask here before the adapter.
        self.managed = ManagedStore(database)
        self.on_change: list[Callable[[object, str], None]] = []
        # Filled in by create_app; adoption needs the protocol adapters.
        self.adapters: dict = {}
        self._access_lock = asyncio.Lock()

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
            if before.state != state:
                for grant in self.store.grants(db, client_id=client_id):
                    if effective_enabled(grant, before, now) != effective_enabled(grant, after, now):
                        self.store.update_grant(db, grant.id, observed_state="pending")
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

    async def reconcile_access(self, client_id: str | None = None, *, force: bool = False) -> None:
        """Confirm local access after state/time changes; failed writes stay pending.

        Administrative intent stays intact: suspending a client must not erase which
        of its grants were manually disabled. No manager I/O holds a DB transaction.
        """
        async with self._access_lock:
            with self.database.connect() as db:
                grants = self.store.grants(db, client_id=client_id, node_id=LOCAL_NODE_ID)
                clients = {client.id: client for client in self.store.clients(db)}
            now = int(self.clock.time())
            candidates = [grant for grant in grants if force or grant.observed_state != (
                "enabled" if effective_enabled(grant, clients[grant.client_id], now) else "disabled")]
            for protocol in sorted({grant.protocol for grant in candidates}):
                try:
                    await self._reconcile_protocol(protocol, [grant for grant in candidates if grant.protocol == protocol])
                except Exception:  # noqa: BLE001 — one unavailable manager must not skip other protocols
                    # Deliberately omit manager exception text: it can contain a credential.
                    log.warning("access enforcement pending for protocol %s", protocol)

    async def _reconcile_protocol(self, protocol: str, grants: list[AccessGrant]) -> None:
        from ..protocols.base import GrantRef  # noqa: PLC0415

        planned = []
        with self.database.transaction() as db:
            for grant in grants:
                try:
                    current = self.store.grant(db, grant.id)
                except KeyError:
                    continue
                if current.desired_state == "deleted" or self.managed.is_managed(db, protocol, current.runtime_username):
                    continue
                client = self.store.client(db, current.client_id)
                planned.append((current, effective_enabled(current, client, int(self.clock.time()))))
                self.store.update_grant(db, grant.id, observed_state="pending")
        if not planned:
            return
        adapter = self._adapter(protocol)
        inventory = {item.runtime_username: item for item in (await adapter.discover()).items}
        for grant, wanted in planned:
            item = inventory.get(grant.runtime_username)
            if item is None:
                continue  # provisioning owns creation; a missing account stays pending
            if item.enabled != wanted:
                try:
                    ref = GrantRef(protocol, grant.runtime_username)
                    await (adapter.enable(ref) if wanted else adapter.disable(ref))
                except Exception:  # noqa: BLE001 — readback decides even after a lost reply
                    log.warning("access mutation pending for grant %s", grant.id)
        confirmed = {item.runtime_username: item for item in (await adapter.discover()).items}
        with self.database.transaction() as db:
            for grant, _ in planned:
                try:
                    fresh = self.store.grant(db, grant.id)
                except KeyError:
                    continue
                client = self.store.client(db, fresh.client_id)
                wanted = effective_enabled(fresh, client, int(self.clock.time()))
                item = confirmed.get(fresh.runtime_username)
                if fresh.desired_state != "deleted" and item is not None and item.enabled == wanted:
                    self.store.update_grant(db, grant.id, observed_state="enabled" if wanted else "disabled")

    def _adapter(self, protocol: str):
        adapter = self.adapters.get(protocol)
        if adapter is None:
            raise ClientConflict(f"no adapter is configured for {protocol}")
        return adapter

    def purge_grant(self, db, grant_id: str) -> None:
        """The runtime account is confirmed gone: the row goes too, so the name can be
        granted again, and every version of its credential is revoked. The secret rows
        stay as an audit trail nothing renders; the provisioning journal keeps naming the
        id, and its readers tolerate a grant that is no longer there. In the caller's
        transaction, next to whatever confirmed the removal."""
        secret_id = f"grant:{grant_id}"
        live = db.execute(
            "SELECT version FROM secret_versions WHERE secret_id=? AND state<>'revoked'", (secret_id,)
        ).fetchall()
        for row in live:
            self.secrets.transition(db, SecretRef(secret_id, row["version"]), "revoked")
        self.store.delete_grant(db, grant_id)

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

    def _local_writable(self, grant_id: str) -> AccessGrant:
        """The grant, if this panel may write its account (ADR 003): one the central panel
        owns is refused before any adapter I/O, with the same 409 the routes use; one
        that lives on another node has no manager here at all — the local adapter would
        read (or rotate!) an unrelated account of the same name."""
        with self.database.connect() as db:
            grant = self.store.grant(db, grant_id)
            if grant.node_id != LOCAL_NODE_ID:
                raise ClientConflict(f"the grant lives on another node ({grant.node_id}); use its lifecycle")
            require_unmanaged(db, self.managed, grant.protocol, grant.runtime_username)
        return grant

    async def capture_credential(self, grant_id: str, *, actor: dict, ip: str, request_id: str | None = None):
        """Read the live credential and escrow it, without touching the runtime."""
        grant = self._local_writable(grant_id)
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
        grant = self._local_writable(grant_id)
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
