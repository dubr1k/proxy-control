"""Node-local reconcile: make the runtime match the latest accepted generation (spec §5.3).

No compensation lives here on purpose: a resource that fails is reported as `failed`
and retried; a rollback is a new, higher generation from the central panel (ADR 002).

Adapter calls never run inside a database transaction. A manager round-trip can take
seconds, and a `BEGIN IMMEDIATE` held across it would stall every other writer on the
node. Each resource is planned and applied with no connection open, then recorded in
one short transaction of its own.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter

from ..clients.models import PROTOCOL_OPTIONS, GrantIntent
from ..protocols.base import AdapterError, AppliedGrant, CredentialPlan, GrantRef, ObservedGrant
from ..secrets_store import SecretRef
from .managed import ManagedStore
from .protocol import ObservedGeneration, ObservedResource, PushRequest, Resource


class _RuntimeCollision(AdapterError):
    """A pushed resource names a runtime user this node never recorded as its own.

    Never persisted to `managed_resources` (see `_apply_resource`'s docstring): a stored
    row — in *any* state — would make the next `apply()` treat the collision as the
    crash-recovery case and rotate a credential onto an account that was never ours.
    """


MANAGED_PURPOSE = "fleet-managed"
# Options the runtime teaches the panel (Telemt's endpoint, mita's share link): they are
# never pushed back, so they never count as drift.
LEARNED_OPTIONS = frozenset({"host", "port", "share_template"})
log = logging.getLogger(__name__)


def _secret_ref(credential_ref: str) -> SecretRef:
    secret_id, _, version = credential_ref.rpartition(":")
    if not secret_id or not version.isdigit():
        raise ValueError("credential_ref must look like <secret_id>:<version>")
    return SecretRef(secret_id, int(version))


def _state(enabled: bool) -> str:
    return "enabled" if enabled else "disabled"


class Reconciler:
    def __init__(self, database, secrets, adapters: dict, managed: ManagedStore, *, guid: str, clock=time):
        self.database, self.secrets, self.adapters, self.managed = database, secrets, adapters, managed
        self.guid, self.clock = guid, clock
        # A push and the startup retry may overlap; two interleaved applies would race
        # the same runtime users.
        self._lock = asyncio.Lock()

    async def store_secrets(self, db, request: PushRequest) -> None:
        """Escrow the secrets a push carried, once per version, inside the caller's transaction."""
        for credential_ref, plaintext in request.secrets.items():
            ref = _secret_ref(credential_ref)
            exists = db.execute("SELECT 1 FROM secret_versions WHERE secret_id=? AND version=?",
                                (ref.secret_id, ref.version)).fetchone()
            if exists is None:
                self.secrets.store(db, secret_id=ref.secret_id, version=ref.version, purpose=MANAGED_PURPOSE,
                                   grant_id=None, permitted_node_id="local", plaintext=plaintext.encode(),
                                   state="active")

    async def apply(self, generation: int) -> tuple[ObservedGeneration, dict[str, str]]:
        """Apply the latest generation; returns what the node observed and the credentials
        the runtime chose itself (manager-origin), which the central panel must escrow."""
        async with self._lock:
            return await self._apply(generation)

    async def run_pending(self) -> None:
        """At startup: an accepted generation that never converged is applied again."""
        with self.database.connect() as db:
            latest = self.managed.latest(db)
        if latest is not None and latest["state"] != "converged":
            await self.apply(latest["generation"])

    # ---- planning ------------------------------------------------------------------

    def _plan(self, resource: Resource) -> CredentialPlan:
        if resource.credential_origin == "manager":
            return CredentialPlan("manager", None)
        with self.database.connect() as db:
            plaintext = self.secrets.reveal(db, _secret_ref(resource.credential_ref), purpose=MANAGED_PURPOSE,
                                            grant_id=None, permitted_node_id="local")
        return CredentialPlan("caller", plaintext)

    @staticmethod
    def _intent(resource: Resource) -> GrantIntent:
        return GrantIntent(protocol=resource.protocol, runtime_username=resource.runtime_username,
                           options=PROTOCOL_OPTIONS[resource.protocol].model_validate(resource.options),
                           valid_from=resource.valid_from, valid_until=resource.valid_until)

    @staticmethod
    def _collect(credentials: dict[str, str], resource: Resource, applied: AppliedGrant) -> None:
        """A credential the manager chose is unknown to the central until the node hands it back."""
        manager_chose = applied.credential_origin == "manager" or resource.credential_origin == "manager"
        if manager_chose and applied.credential:
            credentials[resource.credential_ref] = applied.credential.decode()

    # ---- applying (adapter I/O only, no database connection open) -------------------

    async def _apply_resource(self, adapter, resource: Resource, item: ObservedGrant | None, record: dict | None,
                              generation: int, credentials: dict[str, str]) -> tuple[str, str | None]:
        """Bring one runtime user to the resource's desired state; returns (state, revision).

        Ownership rule (ADR 003, ruling on finding I1): a runtime user this node did not
        record as ours is never touched, managed or deleted just because its name matches
        a pushed resource — that would silently adopt a local (or someone else's) account.
        `record` is `None` exactly when `managed_resources` holds no row for this
        (protocol, runtime_username); in that case `item is not None` is a name collision
        and this call always raises `_RuntimeCollision` instead of acting — a collision is
        never written to the store (see that class's docstring), so it stays a permanent,
        stable "no" rather than becoming an accidental adoption after a retry.

        The one case that legitimately needs recovery is a crash between `adapter.create`
        succeeding and `_record` persisting its row: that would otherwise look identical to
        a collision on the next `apply()`. To make it distinguishable, a "create" always
        writes a placeholder row *before* calling the adapter (see below), so a resource
        this node itself started always leaves `record` non-`None` even if the process dies
        right after `adapter.create` returns. Recovery there is `rotate` — idempotent, and
        it proves the runtime now holds the credential the placeholder could not confirm.
        """
        ref = GrantRef(resource.protocol, resource.runtime_username)
        operation_id = f"{self.guid}:{generation}:{resource.ref}"
        if item is not None and record is None:
            raise _RuntimeCollision("runtime user exists and is not managed")
        if resource.desired_state == "deleted":
            if item is not None:
                await adapter.delete(ref)
            return "missing", None
        if item is None:
            # Placeholder written before the call: see the docstring above.
            self._record(generation, resource, "failed", error="create in flight; will retry on the next apply")
            applied = await adapter.create(operation_id, self._intent(resource), self._plan(resource))
            self._collect(credentials, resource, applied)
            state, revision, current = _state(applied.enabled), applied.revision, None
        else:
            state, revision, current = _state(item.enabled), item.revision, item.options or {}
            stored = record.get("credential_ref")
            if stored != resource.credential_ref and (stored is not None or adapter.accepts_caller_credential):
                applied = await adapter.rotate(f"{operation_id}:rotate", ref, self._plan(resource))
                self._collect(credentials, resource, applied)
                revision = applied.revision or revision
            elif resource.credential_origin == "manager" and adapter.capture_supported:
                captured = await adapter.capture(ref)
                if captured:
                    credentials[resource.credential_ref] = captured.decode()
        wanted = resource.desired_state == "enabled"
        if wanted != (state == "enabled"):
            applied = await (adapter.enable(ref) if wanted else adapter.disable(ref))
            state, revision = _state(applied.enabled), applied.revision or revision
        if current is not None:  # a user created just now already carries the intent's options
            desired = {k: v for k, v in resource.options.items() if v is not None and k not in LEARNED_OPTIONS}
            if desired and desired != {k: v for k, v in current.items() if k in desired}:
                applied = await adapter.update_options(ref, desired)
                if applied is None:
                    state = "drifted"
                else:
                    revision = applied.revision or revision
        return state, revision

    async def _apply_protocol(self, protocol: str, resources: list[Resource], orphans: list[str],
                              known: dict, generation: int, credentials: dict[str, str],
                              collisions: list[ObservedResource]) -> bool:
        """Apply one protocol's resources and drop its orphans; True when anything failed."""
        adapter = self.adapters.get(protocol)
        try:
            if adapter is None:
                raise AdapterError(f"protocol {protocol} is not enabled on this node")
            inventory = await adapter.discover()
        except Exception as exc:  # noqa: BLE001 — every failure is reported, none is fatal
            log.warning("fleet: discover on %s failed: %s", protocol, exc)
            error = str(exc)[:200]
            for resource in resources:
                self._record(generation, resource, "failed", error=error)
            # Orphans exist only in the store (no adapter, or discover() is broken): without
            # this they would never be reported and `apply()` would hang on them forever
            # (finding I3) — mark them `failed` too, using what the store already knows.
            for username in orphans:
                stored = known.get((protocol, username), {})
                with self.database.transaction() as db:
                    self.managed.upsert_resource(db, protocol=protocol, username=username,
                                                 ref=stored.get("ref", username), generation=generation,
                                                 state="failed", error=error,
                                                 credential_ref=stored.get("credential_ref"))
            return True
        observed = {item.runtime_username: item for item in inventory.items}
        failed = False
        for resource in resources:
            record = known.get((protocol, resource.runtime_username))
            try:
                state, revision = await self._apply_resource(adapter, resource, observed.get(resource.runtime_username),
                                                             record, generation, credentials)
            except _RuntimeCollision as exc:
                failed = True
                log.warning("fleet: %s/%s (%s) failed: %s", protocol, resource.runtime_username, resource.ref, exc)
                # Reported, never persisted — see `_RuntimeCollision`'s docstring.
                collisions.append(ObservedResource(ref=resource.ref, protocol=protocol,
                                                   runtime_username=resource.runtime_username,
                                                   state="failed", error=str(exc)[:200]))
            except Exception as exc:  # noqa: BLE001
                failed = True
                log.warning("fleet: %s/%s (%s) failed: %s", protocol, resource.runtime_username, resource.ref, exc)
                self._record(generation, resource, "failed", error=str(exc)[:200])
            else:
                self._record(generation, resource, state, revision=revision, credential_ref=resource.credential_ref)
        # Orphans: central-owned users this generation no longer names (spec §5.3).
        for username in orphans:
            try:
                if username in observed:
                    await adapter.delete(GrantRef(protocol, username))
                with self.database.transaction() as db:
                    self.managed.remove_resource(db, protocol, username)
            except Exception as exc:  # noqa: BLE001
                failed = True
                log.warning("fleet: orphan %s/%s not removed: %s", protocol, username, exc)
        return failed

    # ---- recording (the one place that writes managed_resources) --------------------

    def _record(self, generation: int, resource: Resource, state: str, *, error: str | None = None,
                revision: str | None = None, credential_ref: str | None = None) -> None:
        with self.database.transaction() as db:
            self.managed.upsert_resource(db, protocol=resource.protocol, username=resource.runtime_username,
                                         ref=resource.ref, generation=generation, state=state, error=error,
                                         revision=revision, credential_ref=credential_ref)

    async def _apply(self, generation: int) -> tuple[ObservedGeneration, dict[str, str]]:
        with self.database.connect() as db:
            latest = self.managed.latest(db)
        if latest is None or latest["generation"] != generation:
            raise KeyError(generation)
        document = latest["document"]
        with self.database.transaction() as db:
            self.managed.set_state(db, generation, "applying")
            known = self.managed.resources(db)
        wanted = {(r.protocol, r.runtime_username) for r in document.resources}
        credentials: dict[str, str] = {}
        unmanaged: list[ObservedResource] = []  # I1 collisions: reported, never persisted
        failed = False
        # Defence in depth (finding I2): `GenerationDocument` already rejects two resources
        # naming the same (protocol, runtime_username), but a document built without going
        # through that validator (e.g. internally) must not let the two race one runtime
        # user — neither is applied; both are reported `failed`. Their shared username still
        # counts as `wanted` above so it is never swept up as an orphan.
        counts = Counter((r.protocol, r.runtime_username) for r in document.resources)
        colliding = {key for key, n in counts.items() if n > 1}
        applicable = []
        for resource in document.resources:
            if (resource.protocol, resource.runtime_username) in colliding:
                failed = True
                self._record(generation, resource, "failed",
                             error="duplicate protocol/runtime_username in this generation")
            else:
                applicable.append(resource)
        for protocol in sorted({r.protocol for r in applicable} | {key[0] for key in known}):
            resources = [r for r in applicable if r.protocol == protocol]
            orphans = [key[1] for key in known if key[0] == protocol and key not in wanted]
            failed |= await self._apply_protocol(protocol, resources, orphans, known, generation, credentials,
                                                 unmanaged)
        with self.database.transaction() as db:
            self.managed.set_state(db, generation, "failed" if failed else "converged")
            observed = self.managed.observed(db)
            if unmanaged:
                observed = observed.model_copy(update={"resources": [*observed.resources, *unmanaged]})
            # A deleted resource is reported once as `missing`, then forgotten; one whose
            # delete failed stays known, so the retry still recognises it as the central's.
            missing = {(r.protocol, r.runtime_username) for r in observed.resources if r.state == "missing"}
            for resource in document.resources:
                if resource.desired_state == "deleted" and (resource.protocol, resource.runtime_username) in missing:
                    self.managed.remove_resource(db, resource.protocol, resource.runtime_username)
        return observed, credentials
