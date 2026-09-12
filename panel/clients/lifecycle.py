"""Enable, disable, rotate and delete one grant, wherever its account lives (spec §7).

A grant on this panel's own runtime reaches the manager first and the `DomainFacade`
second, exactly as the protocol routes do: the façade mirrors the runtime into the row
and escrows a rotated credential. A grant on a linked panel (`fleet_nodes.transport =
'panel'`) is declarative — only `access_grants` and, for a rotation, `secret_versions`
change here, in one transaction with the audit row and `ClientService.notify`; the
generation compiled from that change is what the pusher delivers, and the node's report
is what moves `observed_state` afterwards. No manager is called for a remote grant and
nothing is pushed from here.
"""
from __future__ import annotations

import time

from ..audit import record
from ..protocols.base import GrantRef
from .facade import LOCAL_NODE_ID, DomainFacade
from .models import AccessGrant
from .provisioning import is_remote_node, new_credential
from .service import CREDENTIAL_PURPOSE
from .store import ClientConflict

WITHDRAWN = "the grant was deleted before the node applied it"


class GrantLifecycle:
    def __init__(self, database, clients, secrets, facade: DomainFacade, clock=time):
        self.database = database
        self.clients = clients
        self.secrets = secrets
        self.facade = facade
        self.clock = clock
        # The journal of the operation that provisioned a remote grant lives there.
        self.provisioning = facade.provisioning

    # --- lookups ------------------------------------------------------------------

    @staticmethod
    def is_remote(db, grant: AccessGrant) -> bool:
        """The grant's account is on a linked panel: that panel's reconcile applies it."""
        return is_remote_node(db, grant.node_id)

    def _live(self, db, grant_id: str) -> AccessGrant:
        grant = self.clients.store.grant(db, grant_id)  # KeyError: no such grant
        if grant.desired_state == "deleted":
            raise ClientConflict("the grant is deleted")
        return grant

    def _load(self, grant_id: str) -> tuple[AccessGrant, bool]:
        """The grant and where it lives. A node this panel has no writer for is refused
        here: the façade looks accounts up by name on the local runtime and would adopt
        an unrelated one."""
        with self.database.connect() as db:
            grant = self._live(db, grant_id)
            remote = self.is_remote(db, grant)
        if not remote and grant.node_id != LOCAL_NODE_ID:
            raise ClientConflict(f"node {grant.node_id} has no writer on this panel")
        return grant, remote

    @staticmethod
    def _ref(grant: AccessGrant) -> GrantRef:
        return GrantRef(grant.protocol, grant.runtime_username)

    @staticmethod
    def _observed(grant: AccessGrant) -> dict:
        """What the façade would adopt the account with; the grant exists, so it never does."""
        return grant.options.model_dump(exclude_none=True)

    # --- writes -------------------------------------------------------------------

    def _audit(self, db, grant: AccessGrant, action: str, *, actor, ip, request_id) -> None:
        record(
            db,
            actor=actor,
            action=f"grant.{action}",
            target=grant.id,
            ip=ip,
            request_id=request_id,
            detail={"protocol": grant.protocol, "runtime_username": grant.runtime_username, "node_id": grant.node_id},
        )

    def _audited(self, grant: AccessGrant, action: str, *, actor, ip, request_id) -> AccessGrant:
        """The operator's action on a local grant, once the façade has mirrored the runtime."""
        with self.database.transaction() as db:
            self._audit(db, grant, action, actor=actor, ip=ip, request_id=request_id)
            return self.clients.store.grant(db, grant.id)

    def _declare(self, db, grant: AccessGrant, action: str, *, actor, ip, request_id, **fields) -> AccessGrant:
        """What the central now wants of a remote grant, in the caller's transaction: the
        row, the audit row and the generation (`notify`) commit together or not at all.
        `observed_state` is `pending` until the node reports what it made of it."""
        self.clients.store.update_grant(
            db, grant.id, observed_state="pending", updated_at=int(self.clock.time()), **fields
        )
        self._audit(db, grant, action, actor=actor, ip=ip, request_id=request_id)
        self.clients.notify(db, grant.client_id)
        return self.clients.store.grant(db, grant.id)

    async def set_enabled(self, grant_id: str, enabled: bool, *, actor, ip, request_id=None) -> AccessGrant:
        action, state = ("enable", "enabled") if enabled else ("disable", "disabled")
        grant, remote = self._load(grant_id)
        if not remote:
            adapter = self.facade.adapters[grant.protocol]
            await (adapter.enable if enabled else adapter.disable)(self._ref(grant))
            await self.facade.set_enabled(
                grant.protocol, grant.runtime_username, enabled, observed=self._observed(grant),
                actor=actor, ip=ip, request_id=request_id,
            )
            return self._audited(grant, action, actor=actor, ip=ip, request_id=request_id)
        with self.database.transaction() as db:
            grant = self._live(db, grant_id)
            return self._declare(
                db, grant, action, actor=actor, ip=ip, request_id=request_id, desired_state=state
            )

    async def rotate(self, grant_id: str, *, actor, ip, request_id=None) -> AccessGrant:
        """A new credential: applied through the adapter for a local grant; for a remote
        one a `pending` version the next generation names, the current one `retiring`
        until the node confirms the new one (`ProvisioningService.confirm_credential`)."""
        grant, remote = self._load(grant_id)
        if not remote:
            await self.facade.rotate(
                grant.protocol, grant.runtime_username, observed=self._observed(grant),
                actor=actor, ip=ip, request_id=request_id,
            )
            return self._audited(grant, "rotate", actor=actor, ip=ip, request_id=request_id)
        with self.database.transaction() as db:
            grant = self._live(db, grant_id)
            secret_id = f"grant:{grant.id}"
            # A grant without a credential travels as version 1 by reference (see
            # `generations.compile`), so its first rotation is version 2; `max()` keeps the
            # numbering monotonic whatever the grant currently points at.
            top = db.execute("SELECT max(version) FROM secret_versions WHERE secret_id=?", (secret_id,)).fetchone()[0]
            version = max(top or 0, grant.secret_ref.version if grant.secret_ref else 1) + 1
            self.secrets.store(
                db,
                secret_id=secret_id,
                version=version,
                purpose=CREDENTIAL_PURPOSE,
                grant_id=grant.id,
                permitted_node_id=grant.node_id,
                plaintext=new_credential(grant.protocol),
                state="pending",
            )
            if grant.secret_ref is not None:
                self.secrets.transition(db, grant.secret_ref, "retiring")
            return self._declare(
                db, grant, "rotate", actor=actor, ip=ip, request_id=request_id,
                secret_id=secret_id, secret_version=version,
            )

    async def delete(self, grant_id: str, *, actor, ip, request_id=None) -> None:
        """Local: the account is removed and the grant follows it (`forget`). Remote: the
        grant is `deleted` for the next generation, `missing` once the node confirms; an
        operation still waiting for the node to apply this grant is settled now."""
        grant, remote = self._load(grant_id)
        if not remote:
            await self.facade.adapters[grant.protocol].delete(self._ref(grant))
            await self.facade.forget(
                grant.protocol, grant.runtime_username, actor=actor, ip=ip, request_id=request_id
            )
            with self.database.transaction() as db:
                self._audit(db, grant, "delete", actor=actor, ip=ip, request_id=request_id)
            return
        with self.database.transaction() as db:
            grant = self._live(db, grant_id)
            self.provisioning.withdraw_remote(db, grant.id, reason=WITHDRAWN)
            self._declare(db, grant, "delete", actor=actor, ip=ip, request_id=request_id, desired_state="deleted")
