"""Heartbeat and delivery loop of the central panel (spec §6): poll, push, absorb the report.

One tick visits every enabled link: `identity` + `status` decide online/offline (a
transition is one `node.up`/`node.down` event); when the node owes the central a
generation, the latest one goes out with its credentials revealed for that node only,
and what the node reports lands in `observed_generations`, in the grants'
`observed_state`, and in the operations that were waiting for it.

The heartbeat runs every tick regardless. A push is deferred with a per-node exponential
backoff (30 s doubling to a 10 min cap) after the node reported the generation `failed`
or rejected the push with a code the central cannot answer; the backoff is dropped as
soon as a new generation exists for that node or the node reports converged (spec §6:
«Ошибки → last_error, backoff»). An unreachable node simply waits for the next heartbeat.
Network calls never run inside a database transaction; one node's failure never stalls
the others; a node is synced by one coroutine at a time.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from ..secrets_store import SecretError, SecretRef
from .client import NodeAuthFailed, NodeRejected, NodeUnreachable
from .generations import compile, content_digest
from .protocol import ObservedGeneration, PushRequest, canonical_digest

log = logging.getLogger(__name__)
CREDENTIAL_PURPOSE = "grant.credential"
CLIENT_ERRORS = (NodeUnreachable, NodeAuthFailed, NodeRejected)
# The node numbers its own truth: these mean "the node holds something newer or
# different under this number" and are answered by republishing above it.
RESYNC_CODES = ("stale_generation", "digest_conflict")
# A push answered 202 is polled, not repeated — until the node has been `applying` the
# same generation for this long, when the apply is presumed dead and the push goes again
# (the node's accept is idempotent, and its reconcile is a no-op where it already converged).
STALE_APPLY_SECONDS = 600
# Re-push slots after a failed reconcile or a rejected push: 30 s, 60 s, …, capped at 10 min.
BACKOFF_FIRST_SECONDS = 30.0
BACKOFF_CAP_SECONDS = 600.0
# Observed states a grant row can carry; `failed` and `drifted` are folded in `_absorb`.
GRANT_STATES = ("enabled", "disabled", "missing")


@dataclass
class _Backoff:
    """Why the next push of `generation` to one node waits until `until` (monotonic)."""
    generation: int
    failures: int
    until: float


def _describe(exc: Exception) -> str:
    """What `last_error` may say about a node's answer: the class of failure and the
    node's code, never its detail (a 422 detail echoes the request, secrets included)."""
    code = f"{exc.code or exc.status}" if isinstance(exc, NodeRejected) else str(exc)
    return f"{type(exc).__name__}: {code}"[:200]


class FleetPusher:
    def __init__(self, database, links, desired, secrets, clients, provisioning, events, *, interval=15.0, clock=time):
        self.database, self.links, self.desired, self.secrets = database, links, desired, secrets
        self.clients, self.provisioning, self.events = clients, provisioning, events
        self.interval, self.clock, self._stop = interval, clock, asyncio.Event()
        self._locks: dict[str, asyncio.Lock] = {}
        # In memory on purpose: a restart is a fresh attempt, and nothing here is worth a column.
        self._backoff: dict[str, _Backoff] = {}

    # --- loop -------------------------------------------------------------------

    async def run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 — the loop must outlive any single tick
                log.exception("fleet: tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()

    async def tick(self) -> None:
        """One pass over every enabled link, the nodes in parallel and each one isolated."""
        with self.database.connect() as db:
            node_ids = [link["node_id"] for link in self.links.links(db) if link["enabled"]]
        await asyncio.gather(*(self._guarded(node_id) for node_id in node_ids))

    async def _guarded(self, node_id: str) -> None:
        try:
            await self.sync_node(node_id)
        except Exception:  # noqa: BLE001 — one node's failure never stalls the others
            log.exception("fleet: sync of node %s failed", node_id)

    # --- one node ---------------------------------------------------------------

    async def sync_node(self, node_id: str) -> None:
        """Heartbeat, then deliver or poll — whichever the node owes; serialised per node
        so an operator's "probe now" cannot interleave with the loop."""
        async with self._locks.setdefault(node_id, asyncio.Lock()):
            await self._sync(node_id)

    async def _sync(self, node_id: str) -> None:
        client = self.links.client_for(node_id)
        started = self.clock.monotonic()
        try:
            identity = await client.identity()
            status = await client.status()
        except CLIENT_ERRORS as exc:
            self._offline(node_id, exc)
            return
        latency = int((self.clock.monotonic() - started) * 1000)
        with self.database.transaction() as db:
            self._emit(db, self.links.record_heartbeat(db, node_id, online=True, identity=identity, status=status,
                                                       latency_ms=latency), node_id)
            link = self.links.link(db, node_id)
            latest = self.desired.latest(db, node_id)
            observed = self.desired.observed(db, node_id)
        if latest is None:
            return
        if self._in_flight(latest, observed):
            await self._poll_observed(client, node_id)
        elif self._deferred(node_id, latest["generation"]):
            return  # heartbeat done; the re-push waits for its slot
        elif link["config_dirty"] or link["acknowledged_generation"] < latest["generation"]:
            await self._push(client, node_id, latest)

    def _in_flight(self, latest: dict, observed: ObservedGeneration | None) -> bool:
        """The node answered 202 for this very generation and is still applying it."""
        if observed is None or latest["pushed_at"] is None:
            return False
        return (observed.applied_generation == latest["generation"] and observed.reconcile_state == "applying"
                and self.clock.time() - latest["pushed_at"] < STALE_APPLY_SECONDS)

    # --- backoff ----------------------------------------------------------------

    def _defer(self, node_id: str, generation: int) -> None:
        """One more failure of `generation` on this node: the next slot doubles, from 30 s to the cap."""
        current = self._backoff.get(node_id)
        failures = current.failures + 1 if current and current.generation == generation else 1
        wait = min(BACKOFF_FIRST_SECONDS * 2 ** (failures - 1), BACKOFF_CAP_SECONDS)
        self._backoff[node_id] = _Backoff(generation, failures, self.clock.monotonic() + wait)
        log.info("fleet: node %s: generation %s deferred for %.0f s (failure %s)", node_id, generation, wait, failures)

    def _deferred(self, node_id: str, generation: int) -> bool:
        """True while the slot for this very generation has not come; a different (newer)
        generation forgets the backoff outright — something changed for this node."""
        current = self._backoff.get(node_id)
        if current is None:
            return False
        if current.generation != generation:
            del self._backoff[node_id]
            return False
        return self.clock.monotonic() < current.until

    def _emit(self, db, name: str | None, node_id: str) -> None:
        if name:
            self.events.emit(db, name, {"node_id": node_id})

    def _offline(self, node_id: str, exc: Exception) -> None:
        with self.database.transaction() as db:
            self._emit(db, self.links.record_heartbeat(db, node_id, online=False, error=_describe(exc)), node_id)

    # --- push -------------------------------------------------------------------

    def _secrets_for(self, node_id: str, document) -> dict[str, str]:
        """Every credential the document names, revealed for this node only. A grant
        without one (imported, not yet captured) travels by reference alone."""
        secrets: dict[str, str] = {}
        with self.database.connect() as db:
            for resource in document.resources:
                if resource.desired_state == "deleted":
                    continue
                secret_id, _, version = resource.credential_ref.rpartition(":")
                try:
                    secrets[resource.credential_ref] = self.secrets.reveal(
                        db, SecretRef(secret_id, int(version)), purpose=CREDENTIAL_PURPOSE,
                        grant_id=resource.ref.removeprefix("grant:"), permitted_node_id=node_id).decode()
                except SecretError:
                    continue
        return secrets

    async def _push(self, client, node_id: str, latest: dict) -> None:
        document = latest["document"]
        request = PushRequest(expected_guid=node_id, generation=document, secrets=self._secrets_for(node_id, document))
        try:
            _, response = await client.push(request)
        except NodeRejected as exc:
            with self.database.transaction() as db:
                db.execute("UPDATE node_links SET last_error=?, updated_at=? WHERE node_id=?",
                           (f"push {exc.status}: {exc.code or 'rejected'}"[:200], int(self.clock.time()), node_id))
            if exc.code in RESYNC_CODES:
                await self._resync(client, node_id, latest)
            else:
                self._defer(node_id, document.generation)
            return
        except (NodeUnreachable, NodeAuthFailed) as exc:
            self._offline(node_id, exc)
            return
        with self.database.transaction() as db:
            self.desired.mark_pushed(db, node_id, document.generation)
        self._absorb(node_id, response.observed, response.credentials)

    async def _resync(self, client, node_id: str, latest: dict) -> None:
        """The node holds a generation the central never numbered (a database restored
        from a backup, a link cut and re-made): the same resources are republished above
        what the node reports, and the next tick delivers them. Never a retry of the
        rejected number — that would be the same answer every tick."""
        try:
            observed = await client.observed()
        except CLIENT_ERRORS:
            return
        with self.database.transaction() as db:
            current = self.desired.latest(db, node_id)
            if current is None or current["generation"] != latest["generation"]:
                return  # something newer was published meanwhile; it goes out on the next tick
            if observed.applied_generation < current["generation"]:
                return
            document = compile(db, self.clients.store, node_id=node_id, node_guid=node_id, master_guid=self.links.own_guid,
                               previous=observed.applied_generation, generation=observed.applied_generation + 1,
                               now=int(self.clock.time()), created_by="system")
            self.desired.insert(db, node_id, document, canonical_digest(document), content_digest(document))
        log.warning("fleet: node %s holds generation %s; republished as %s", node_id, observed.applied_generation,
                    document.generation)

    # --- absorbing what the node reported ---------------------------------------

    async def _poll_observed(self, client, node_id: str) -> None:
        try:
            observed = await client.observed()
        except CLIENT_ERRORS as exc:
            self._offline(node_id, exc)
            return
        self._absorb(node_id, observed, {})

    def _absorb(self, node_id: str, observed: ObservedGeneration, credentials: dict[str, str]) -> None:
        """One transaction: the report itself, each grant's observed state, credentials
        the runtime chose, and the operations that waited for this node.

        Only a report about the generation the central currently wants confirms a
        credential version or finishes an operation: a report about an older one says
        nothing about the version the grant names now.
        """
        now = int(self.clock.time())
        with self.database.transaction() as db:
            self.desired.record_observed(db, node_id, observed)
            latest = self.desired.latest(db, node_id)
            current = latest is not None and observed.applied_generation == latest["generation"]
            if observed.reconcile_state == "converged":
                self._backoff.pop(node_id, None)
            elif current and observed.reconcile_state == "failed":
                self._defer(node_id, latest["generation"])
            grants = {grant.id: grant for grant in self.clients.store.grants(db, node_id=node_id, include_deleted=True)}
            for item in observed.resources:
                grant = grants.get(item.ref.removeprefix("grant:"))
                if grant is None:
                    continue  # a collision on a name the central never granted, or a grant since purged
                # `drifted`: the runtime holds the desired on/off state, only an option
                # could not be applied. `failed`: the last known state stands; the node's
                # error is in observed_generations and on the operation's step.
                state = grant.desired_state if item.state == "drifted" else item.state
                if state not in GRANT_STATES:
                    continue
                returned = next((ref for ref in credentials if ref.startswith(item.ref + ":")), None)
                if returned is not None:
                    self.provisioning.escrow_returned_credential(db, grant.id, returned, credentials[returned])
                if current and state != "missing":
                    self.provisioning.confirm_credential(db, grant.id)
                self.clients.store.update_grant(db, grant.id, observed_state=state, updated_at=now)
            if current:
                self.provisioning.remote_applied(db, observed)
