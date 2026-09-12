"""The old protocol endpoints, served by the domain instead of the managers directly.

The contract of this module is negative: from outside, `domain` mode must be
indistinguishable from `legacy`. Same status codes, same response shapes, same audit
actions. What changes is who owns the record — the panel now keeps a client, a grant and
an escrowed credential for every account it touches, which is what makes a subscription
possible at all.

A username the panel has never seen is *adopted*, never recreated and never merged with
a same-named account of another protocol: one row is written that says "this exists and
it is not ours", with no credential, because we do not have one.
"""
from __future__ import annotations

import time
import uuid

from ..audit import record
from ..fleet_v2.guard import require_unmanaged
from ..fleet_v2.managed import ManagedStore
from ..protocols.base import GrantRef
from .models import PROTOCOL_OPTIONS, AccessGrant, GrantIntent
from .store import ClientConflict

LOCAL_NODE_ID = "local"
DEFAULT_ENDPOINT = "default"


class DomainFacade:
    def __init__(self, clients, provisioning, adapters: dict, clock=time, managed: ManagedStore | None = None):
        self.clients = clients
        self.provisioning = provisioning
        self.adapters = adapters
        self.clock = clock
        self.managed = managed or ManagedStore(clients.database)

    # --- lookups ------------------------------------------------------------------

    def grant(self, protocol: str, username: str):
        with self.clients.database.connect() as db:
            return self.clients.store.find_grant(db, protocol, LOCAL_NODE_ID, DEFAULT_ENDPOINT, username)

    def _local_only(self, protocol: str, username: str) -> None:
        """An account the central panel owns is not this façade's to write (ADR 003)."""
        with self.clients.database.connect() as db:
            require_unmanaged(db, self.managed, protocol, username)

    def _client_for(self, db, display_name: str) -> str:
        for existing in self.clients.store.clients(db):
            if existing.display_name == display_name:
                return existing.id
        return self.clients.new_client(db, display_name, now=int(self.clock.time())).id

    def touch_import(self, protocol: str, username: str, *, enabled: bool, options: dict, actor, ip, request_id=None):
        """Record an account the panel did not create — one row, no credential, no merge."""
        self._local_only(protocol, username)
        existing = self.grant(protocol, username)
        if existing is not None:
            return existing
        now = int(self.clock.time())
        state = "enabled" if enabled else "disabled"
        with self.clients.database.transaction() as db:
            client_id = self._client_for(db, username)
            grant = AccessGrant(
                id=str(uuid.uuid4()),
                client_id=client_id,
                protocol=protocol,
                node_id=LOCAL_NODE_ID,
                endpoint_id=DEFAULT_ENDPOINT,
                runtime_username=username,
                desired_state=state,
                observed_state=state,
                options=PROTOCOL_OPTIONS[protocol].model_validate(options),
                origin="imported",
                created_at=now,
                updated_at=now,
            )
            self.clients.store.insert_grant(db, grant)
            record(
                db,
                actor=actor,
                action="grant.adopt_on_write",
                target=grant.id,
                ip=ip,
                request_id=request_id,
                reason_code="domain",
                detail={"protocol": protocol, "runtime_username": username},
            )
            self.clients.notify(db, client_id)
        return grant

    # --- writes -------------------------------------------------------------------

    async def create(self, protocol: str, username: str, options: dict, *, actor, ip, request_id=None) -> bytes:
        """Provision one account through the saga and return its credential once."""
        intent = GrantIntent(
            protocol=protocol,
            runtime_username=username,
            options=PROTOCOL_OPTIONS[protocol].model_validate(options),
        )
        with self.clients.database.transaction() as db:
            client_id = self._client_for(db, username)
        operation_id = await self.provisioning.start(
            client_id, [intent], actor=actor, ip=ip, request_id=request_id
        )
        result = await self.provisioning.run(operation_id)
        if result.status != "succeeded":
            raise ClientConflict(
                f"provisioning {result.status}: operation {operation_id}"
            )
        return self.credential(protocol, username)

    def credential(self, protocol: str, username: str) -> bytes:
        grant = self.grant(protocol, username)
        if grant is None or grant.secret_ref is None:
            raise ClientConflict("the panel has no stored credential for this account")
        with self.clients.database.connect() as db:
            return self.clients.secrets.reveal(
                db,
                grant.secret_ref,
                purpose="grant.credential",
                grant_id=grant.id,
                permitted_node_id=grant.node_id,
            )

    async def set_enabled(
        self, protocol: str, username: str, enabled: bool, *, observed: dict, actor, ip, request_id=None
    ):
        """Mirror a runtime state change into the grant, adopting the row if needed."""
        self._local_only(protocol, username)
        grant = self.grant(protocol, username) or self.touch_import(
            protocol, username, enabled=enabled, options=observed,
            actor=actor, ip=ip, request_id=request_id,
        )
        state = "enabled" if enabled else "disabled"
        with self.clients.database.transaction() as db:
            self.clients.store.update_grant(
                db, grant.id, desired_state=state, observed_state=state,
                updated_at=int(self.clock.time()),
            )
            record(
                db,
                actor=actor,
                action=f"grant.{state}",
                target=grant.id,
                ip=ip,
                request_id=request_id,
                reason_code="domain",
                detail={"protocol": protocol, "runtime_username": username},
            )
            self.clients.notify(db, grant.client_id)

    async def forget(self, protocol: str, username: str, *, actor, ip, request_id=None):
        """The runtime account is gone; the grant follows it instead of dangling."""
        self._local_only(protocol, username)
        grant = self.grant(protocol, username)
        if grant is None:
            return
        with self.clients.database.transaction() as db:
            self.clients.store.update_grant(
                db, grant.id, desired_state="deleted", observed_state="missing",
                updated_at=int(self.clock.time()),
            )
            record(
                db,
                actor=actor,
                action="grant.deleted",
                target=grant.id,
                ip=ip,
                request_id=request_id,
                reason_code="domain",
                detail={"protocol": protocol, "runtime_username": username},
            )
            self.clients.notify(db, grant.client_id)

    async def rotate(self, protocol: str, username: str, *, observed: dict, actor, ip, request_id=None) -> bytes:
        """Rotate through the adapter so the new credential lands in escrow, not a reply."""
        self._local_only(protocol, username)
        grant = self.grant(protocol, username) or self.touch_import(
            protocol, username, enabled=True, options=observed,
            actor=actor, ip=ip, request_id=request_id,
        )
        adapter = self.adapters[protocol]
        from ..protocols.base import CredentialPlan  # noqa: PLC0415 - avoids an import cycle
        import secrets as secret_tokens  # noqa: PLC0415

        plan = (
            CredentialPlan("manager", None)
            if adapter.credential_origin == "manager"
            else CredentialPlan("caller", secret_tokens.token_urlsafe(24).encode())
        )
        applied = await adapter.rotate(
            f"rotate:{grant.id}:{int(self.clock.time())}",
            GrantRef(protocol, username, None),
            plan,
        )
        self._store_credential(grant, applied.credential or b"", actor=actor, ip=ip, request_id=request_id)
        return applied.credential or b""

    def _store_credential(self, grant, plaintext: bytes, *, actor, ip, request_id=None) -> None:
        reference_id = f"grant:{grant.id}"
        with self.clients.database.transaction() as db:
            version = db.execute(
                "SELECT max(version) FROM secret_versions WHERE secret_id=?", (reference_id,)
            ).fetchone()[0]
            reference = self.clients.secrets.store(
                db,
                secret_id=reference_id,
                version=(version or 0) + 1,
                purpose="grant.credential",
                grant_id=grant.id,
                permitted_node_id=grant.node_id,
                plaintext=plaintext,
                state="active",
            )
            self.clients.store.update_grant(
                db, grant.id, secret_id=reference.secret_id, secret_version=reference.version,
                observed_state="enabled", desired_state="enabled",
                updated_at=int(self.clock.time()),
            )
            record(
                db,
                actor=actor,
                action="grant.credential.rotate",
                target=grant.id,
                ip=ip,
                request_id=request_id,
                reason_code="domain",
                detail={"protocol": grant.protocol, "runtime_username": grant.runtime_username},
            )
            self.clients.notify(db, grant.client_id)
