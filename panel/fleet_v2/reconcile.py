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
import contextlib
import logging
import time
from collections import Counter

from ..clients.models import PROTOCOL_OPTIONS, GrantIntent
from ..protocols.base import AdapterError, AppliedGrant, CredentialPlan, GrantRef, ObservedGrant
from ..secrets_store import SecretRef
from .managed import ManagedStore
from .protocol import EgressDocument, ObservedGeneration, ObservedResource, PushRequest, Resource


class GenerationSuperseded(KeyError):
    """`apply(n)` found a newer generation accepted meanwhile: nothing was applied for `n`."""


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

    async def unlink(self) -> int:
        """Forget the master under the same lock `apply()` holds: a reconcile in flight would
        otherwise re-register the rows this releases (and then crash on the generation it
        no longer finds). Returns how many resources became local."""
        async with self._lock:
            with self.database.transaction() as db:
                return self.managed.unlink(db)

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
    def _collect(credentials: dict[str, str], resource: Resource, applied: AppliedGrant, plan: CredentialPlan) -> None:
        """A credential the central does not hold in the form the runtime serves is handed
        back: one the manager chose, or the runtime's own framing of the caller's (Telemt
        turns a bare 32-hex secret into the Fake-TLS `ee` + secret + domain the link needs)."""
        manager_chose = applied.credential_origin == "manager" or resource.credential_origin == "manager"
        reframed = plan.plaintext is not None and applied.credential not in (None, plan.plaintext)
        if applied.credential and (manager_chose or reframed):
            credentials[resource.credential_ref] = applied.credential.decode()

    @staticmethod
    def _learned(resource: Resource, applied: AppliedGrant) -> dict:
        """The facts the runtime taught about the link — only those the protocol's options
        model has a field for (Telemt: host, port; mita: share_template), never a credential."""
        return Reconciler._learned_from(resource, applied.artifact_template)

    @staticmethod
    def _learned_from_inventory(resource: Resource, item: ObservedGrant) -> dict | None:
        """The same facts read off the inventory row an adoption is based on, or None."""
        return Reconciler._learned_from(resource, item.options or {}) or None

    @staticmethod
    def _learned_from(resource: Resource, reported: dict) -> dict:
        fields = PROTOCOL_OPTIONS[resource.protocol].model_fields
        return {key: value for key, value in reported.items()
                if key in fields and key in LEARNED_OPTIONS and value not in (None, "")}

    # ---- applying (adapter I/O only, no database connection open) -------------------

    async def _apply_resource(self, adapter, resource: Resource, item: ObservedGrant | None, record: dict | None,
                              generation: int, credentials: dict[str, str]) -> tuple[str, str | None, dict | None]:
        """Bring one runtime user to the resource's desired state; returns (state, revision,
        learned) — `learned` is what create/rotate taught about the link, None otherwise.

        Ownership rule (ADR 003, ruling on finding I1): a runtime user this node did not
        record as ours is never touched, managed or deleted just because its name matches
        a pushed resource — that would silently adopt a local (or someone else's) account.
        `record` is `None` exactly when `managed_resources` holds no row for this
        (protocol, runtime_username); in that case `item is not None` is a name collision
        and this call raises `_RuntimeCollision` instead of acting — a collision is
        never written to the store (see that class's docstring), so it stays a permanent,
        stable "no" rather than becoming an accidental adoption after a retry. The one
        deliberate adoption is an `imported` resource (spec §6): the operator chose that
        user from this node's inventory, and the row is written without touching it.

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
        if record is not None and record.get("state") == "missing":
            # The account was deleted for the central; the row only lingers so the one-time
            # `missing` report survives a 202 (see `_apply`). It owns nothing: whatever now
            # lives under that name is someone else's, exactly as if no row existed.
            record = None
        if item is not None and record is None:
            if resource.origin != "imported" or resource.desired_state == "deleted":
                raise _RuntimeCollision("runtime user exists and is not managed")
            # Explicit adoption (ADR 003 `adopted`, spec §6): the operator imported this user
            # from the node's own inventory, so it is the central's from here on — with the
            # credential it holds today, which the pushed `credential_ref` now names. No
            # adapter call: nothing is created, rotated or deleted by adopting. A `deleted`
            # resource never adopts — adopting and deleting are two separate decisions.
            # What the inventory knows about the link (Telemt's host/port, mita's share
            # template) is recorded as `learned` — the same facts create/rotate teach.
            learned = self._learned_from_inventory(resource, item)
            self._record(generation, resource, _state(item.enabled), revision=item.revision,
                         credential_ref=resource.credential_ref, learned=learned)
            record = {"credential_ref": resource.credential_ref}
        else:
            learned = None
        if resource.desired_state == "deleted":
            if item is not None:
                await adapter.delete(ref)
            return "missing", None, None
        if item is None:
            # Placeholder written before the call: see the docstring above.
            self._record(generation, resource, "failed", error="create in flight; will retry on the next apply")
            plan = self._plan(resource)
            applied = await adapter.create(operation_id, self._intent(resource), plan)
            self._collect(credentials, resource, applied, plan)
            learned = self._learned(resource, applied)
            state, revision, current = _state(applied.enabled), applied.revision, None
        else:
            state, revision, current = _state(item.enabled), item.revision, item.options or {}
            # A row adopted before the inventory carried the endpoint learns it now (no I/O:
            # the inventory is already in hand); create/rotate below may refine it.
            learned = learned or self._learned_from_inventory(resource, item)
            stored = record.get("credential_ref")
            if stored != resource.credential_ref and (stored is not None or adapter.accepts_caller_credential):
                plan = self._plan(resource)
                applied = await adapter.rotate(f"{operation_id}:rotate", ref, plan)
                self._collect(credentials, resource, applied, plan)
                learned = self._learned(resource, applied)
                revision = applied.revision or revision
            elif adapter.capture_supported and "manager" in (resource.credential_origin, adapter.credential_origin):
                # The runtime holds the credential in its own form (Telemt reframes a caller's
                # bare secret as the Fake-TLS `ee…` link secret): hand it back on every apply, so
                # a re-PUT after a lost reply still gives the central the form the link needs.
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
        return state, revision, learned

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
                state, revision, learned = await self._apply_resource(
                    adapter, resource, observed.get(resource.runtime_username), record, generation, credentials)
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
                self._record(generation, resource, state, revision=revision, credential_ref=resource.credential_ref,
                             learned=learned)
        # Orphans: central-owned users this generation no longer names (spec §5.3). A row
        # left `missing` owned nothing any more: a same-named user present now is local.
        for username in orphans:
            try:
                if username in observed and known.get((protocol, username), {}).get("state") != "missing":
                    await adapter.delete(GrantRef(protocol, username))
                with self.database.transaction() as db:
                    self.managed.remove_resource(db, protocol, username)
            except Exception as exc:  # noqa: BLE001
                failed = True
                log.warning("fleet: orphan %s/%s not removed: %s", protocol, username, exc)
        return failed

    # ---- recording (the one place that writes managed_resources) --------------------

    def _record(self, generation: int, resource: Resource, state: str, *, error: str | None = None,
                revision: str | None = None, credential_ref: str | None = None, learned: dict | None = None) -> None:
        with self.database.transaction() as db:
            self.managed.upsert_resource(db, protocol=resource.protocol, username=resource.runtime_username,
                                         ref=resource.ref, generation=generation, state=state, error=error,
                                         revision=revision, credential_ref=credential_ref, learned=learned)

    # ---- egress (v0.4, spec §8.3): after the resources, one section per protocol ------

    def _record_egress(self, protocol: str, generation: int, state: str, *, revision: str | None = None,
                       digest: str | None = None, error: str | None = None) -> None:
        with self.database.transaction() as db:
            self.managed.upsert_egress(db, protocol=protocol, generation=generation, state=state, revision=revision,
                                       digest=digest, error=error)

    async def _apply_egress_section(self, protocol: str, entry: EgressDocument, generation: int) -> None:
        adapter = self.adapters.get(protocol)
        target = None if adapter is None else await adapter.egress_target()
        if target is None:
            raise AdapterError(f"{protocol} has no egress on this node", code="egress_unsupported")
        if target.backend != entry.backend:
            raise AdapterError(f"{protocol} runs {target.backend}, not {entry.backend}", code="egress_unsupported")
        if target.applied is not None and target.applied["digest"] == entry.digest:
            # Already what the runtime runs: a re-PUT or a restart re-applies nothing.
            self._record_egress(protocol, generation, "converged", revision=target.revision, digest=entry.digest)
            return
        applied = await adapter.apply_egress(entry.document, expected_revision=target.revision,
                                             operation_id=f"{self.guid}:{generation}:egress:{protocol}")
        self._record_egress(protocol, generation, "converged", revision=applied.revision, digest=applied.digest)

    async def _apply_egress(self, egress: dict[str, EgressDocument] | None, generation: int) -> bool:
        """Apply each protocol's egress section; True when any failed. No section at all
        means the central has nothing to say about egress: the node leaves it as it is."""
        if not egress:
            return False
        failed = False
        for protocol, entry in egress.items():
            try:
                await self._apply_egress_section(protocol, entry, generation)
            except AdapterError as exc:
                failed = True
                code = exc.code or "manager_unavailable"
                log.warning("fleet: egress for %s failed: %s", protocol, code)
                self._record_egress(protocol, generation, "unsupported" if code == "egress_unsupported" else "failed",
                                    error=code)
            except Exception as exc:  # noqa: BLE001 — reported, never fatal
                failed = True
                log.warning("fleet: egress for %s failed: %s", protocol, exc)
                self._record_egress(protocol, generation, "failed", error=str(exc)[:200])
        return failed

    async def _apply(self, generation: int) -> tuple[ObservedGeneration, dict[str, str]]:
        with self.database.connect() as db:
            latest = self.managed.latest(db)
        if latest is None or latest["generation"] != generation:
            raise GenerationSuperseded(generation)
        document = latest["document"]
        refs = {(r.protocol, r.runtime_username): r.ref for r in document.resources}
        with self.database.transaction() as db:
            self.managed.set_state(db, generation, "applying")
            known = self.managed.resources(db)
            # A `missing` row lingers so the one-time report survives a 202 (see the tail of this
            # method). A generation naming that user under ANOTHER ref proves the central saw the
            # report (the name is UNIQUE there until the deleted grant is purged): the row is
            # retired here, before the apply — never afterwards, when `_record` may already have
            # rewritten the same (protocol, username) row for the regrant.
            for key, row in list(known.items()):
                if row["state"] == "missing" and refs.get(key, row["ref"]) != row["ref"]:
                    self.managed.remove_resource(db, *key)
                    del known[key]
        wanted = set(refs)
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
            # An adapter that can batch its inventory reads (Telemt reads the whole user table
            # per look-up) does so for the protocol's whole pass.
            batch = getattr(self.adapters.get(protocol), "batch", None)
            async with (batch() if batch is not None else contextlib.nullcontext()):
                failed |= await self._apply_protocol(protocol, resources, orphans, known, generation, credentials,
                                                     unmanaged)
        # Egress after the resources (spec §8.3): the users are provisioned whatever the
        # routing outcome; a failed section fails the generation the way a resource does.
        failed |= await self._apply_egress(document.egress, generation)
        with self.database.transaction() as db:
            self.managed.set_state(db, generation, "failed" if failed else "converged")
            observed = self.managed.observed(db)
            if unmanaged:
                observed = observed.model_copy(update={"resources": [*observed.resources, *unmanaged]})
            # A deleted resource stays in the store as `missing` until a generation omits its
            # name (the orphan pass above drops it then) or names it under another ref (retired
            # before the apply, above): the central may only learn of the deletion from a later
            # `GET observed` (a push answered 202), and a report that vanished after one apply
            # would leave the grant `deleted/pending` there forever. The row owns nothing
            # meanwhile — see `_apply_resource` and `ManagedStore.is_managed`.
        return observed, credentials
