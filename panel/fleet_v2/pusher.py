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
import hashlib
import json
import logging
import time
from dataclasses import dataclass

from ..routing.store import PolicyNotFound
from ..routing.lanes import RELAY_PURPOSE, RelayRegistry
from ..secrets_store import SecretError, SecretRef
from .client import NodeAuthFailed, NodeRejected, NodeUnreachable
from .generations import compile, content_digest
from .importing import auto_import
from .protocol import CAPTURE_MAX_RESOURCES, ObservedGeneration, PushRequest, canonical_digest


def _inventory_digest(inventory: dict) -> str:
    return hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

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
# A report about a finished apply. An `applying` one is provisional: rows the apply has not
# reached yet still carry the previous generation's state, so nothing is captured, escrowed
# or confirmed from it — `_in_flight` polls again on the next tick.
SETTLED_STATES = ("converged", "failed")
# A converged report whose credentials the node still cannot hand over (`_uncaptured`) is
# delivered again on the next tick; after this many such ticks in a row the re-push is
# deferred with the usual backoff instead of hammering the node every 15 s.
WITHHELD_TICKS_BEFORE_BACKOFF = 4
# What the waiting operation step says while a manager-origin credential is not in escrow.
NOT_CAPTURED = "credential not captured yet"
# A node that answers the heartbeat with these is up but refusing — rate limit, a manager
# hiccup behind a 5xx: the link keeps its status, the error is recorded, and nothing is pushed
# until it answers again. Any other refusal (a 404: no Fleet v2 at that URL) is `offline`.
# A 5xx counts only when the panel wrote it (its JSON `{detail, code}`): a bare 502/503/504
# page is the reverse proxy in front of a dead panel, and that node is down (lab finding,
# v0.4 gate: a stopped panel container behind nginx must go `offline` within the deadline).
REFUSING_STATUSES = frozenset({429}) | frozenset(range(500, 600))


def _refusal(exc: NodeRejected) -> bool:
    if exc.status == 429:
        return True
    return exc.status in REFUSING_STATUSES and bool(exc.detail or exc.code)


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


class _ImportState:
    """What `importing` needs of `app.state`, from the pusher's own references."""

    def __init__(self, pusher):
        self.database, self.links, self.secrets, self.clients = pusher.database, pusher.links, pusher.secrets, pusher.clients


class FleetPusher:
    def __init__(self, database, links, desired, secrets, clients, provisioning, events, *, interval=15.0, clock=time,
                 routing=None):
        self.database, self.links, self.desired, self.secrets = database, links, desired, secrets
        self.clients, self.provisioning, self.events = clients, provisioning, events
        # The routing store (v0.4): a republish carries the node's egress section, and the
        # node's report moves each policy to `applied`/`failed`. None on a central without it.
        self.routing = routing
        self.interval, self.clock, self._stop = interval, clock, asyncio.Event()
        self._locks: dict[str, asyncio.Lock] = {}
        # Per node: the inventory the last auto-import saw, so an unchanged node costs one
        # `inventory` read per tick and no capture.
        self._adopted: dict[str, str] = {}
        # In memory on purpose: a restart is a fresh attempt, and nothing here is worth a column.
        self._backoff: dict[str, _Backoff] = {}
        # (generation, consecutive converged reports with a credential still withheld) per node.
        self._withheld: dict[str, tuple[int, int]] = {}

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
        except NodeRejected as exc:
            if _refusal(exc):
                self._refusing(node_id, exc)
            else:
                self._offline(node_id, exc)
            return
        except CLIENT_ERRORS as exc:
            self._offline(node_id, exc)
            return
        latency = int((self.clock.monotonic() - started) * 1000)
        try:
            with self.database.transaction() as db:
                self._emit(db, self.links.record_heartbeat(db, node_id, online=True, identity=identity, status=status,
                                                           latency_ms=latency), node_id)
                link = self.links.link(db, node_id)
                latest = self.desired.latest(db, node_id)
                observed = self.desired.observed(db, node_id)
        except KeyError:
            # The node was unlinked while its heartbeat was in flight: nothing to record.
            log.info("fleet: node %s was unlinked during its heartbeat", node_id)
            return
        if link["enabled"] and link.get("auto_import"):
            # Adoption publishes a generation of its own, so what the node owes is re-read.
            if await self._adopt(client, node_id):
                with self.database.connect() as db:
                    latest = self.desired.latest(db, node_id)
                    observed = self.desired.observed(db, node_id)
        if latest is None or not link["enabled"]:
            return  # a paused link is probed dry: the heartbeat above, nothing delivered
        if self._in_flight(latest, observed):
            await self._poll_observed(client, node_id)
        elif self._deferred(node_id, latest["generation"]):
            return  # heartbeat done; the re-push waits for its slot
        elif link["config_dirty"] or link["acknowledged_generation"] < latest["generation"]:
            await self._push(client, node_id, latest)

    async def _adopt(self, client, node_id: str) -> bool:
        """The node's own users become clients here (auto-import). A failure is this tick's
        business only: logged, never a `node.down`, never a stall. True when something was
        imported."""
        read = getattr(client, "inventory", None)
        if read is None:
            return False  # a transport that only heartbeats (test doubles) has nothing to adopt
        try:
            inventory = (await read()).get("protocols") or {}
        except CLIENT_ERRORS as exc:
            log.info("fleet: node %s: inventory unavailable for auto-import (%s)", node_id, _describe(exc))
            return False
        digest = _inventory_digest(inventory)
        if self._adopted.get(node_id) == digest:
            return False
        try:
            result = await auto_import(_ImportState(self), node_id, inventory=inventory)
        except (ValueError, KeyError, *CLIENT_ERRORS) as exc:
            log.warning("fleet: node %s: auto-import failed: %s", node_id, _describe(exc))
            return False
        self._adopted[node_id] = digest
        if result and result["imported"]:
            log.info("fleet: node %s: adopted %d account(s), %d without credential", node_id,
                     len(result["imported"]), len(result["without_credential"]))
            return True
        return False

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

    def _refusing(self, node_id: str, exc: NodeRejected) -> None:
        """The node is up but refused the heartbeat (429, 5xx): recorded, not a transition."""
        with self.database.transaction() as db:
            db.execute("UPDATE node_links SET last_error=?, updated_at=? WHERE node_id=?",
                       (_describe(exc), int(self.clock.time()), node_id))

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
            # The relay accounts other nodes dial this node with (v0.7): issued for this node.
            if document.relay is not None:
                for account in document.relay.accounts:
                    secret_id, _, version = account.credential_ref.rpartition(":")
                    try:
                        secrets[account.credential_ref] = self.secrets.reveal(
                            db, SecretRef(secret_id, int(version)), purpose=RELAY_PURPOSE, grant_id=None,
                            permitted_node_id=node_id).decode()
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
                               now=int(self.clock.time()), created_by="system", routing=self.routing)
            self.desired.insert(db, node_id, document, canonical_digest(document), content_digest(document))
        log.warning("fleet: node %s holds generation %s; republished as %s", node_id, observed.applied_generation,
                    document.generation)

    # --- absorbing what the node reported ---------------------------------------

    async def _poll_observed(self, client, node_id: str) -> None:
        """A push answered 202 carried no credentials: once the node's report is settled, what
        its runtime chose (or reframed — Telemt's `ee…` form of a caller secret) is captured
        here before the report is absorbed, so `confirm_credential` never activates the bare
        value. A capture the node refuses or cannot answer is not a heartbeat failure: the
        report is absorbed with whatever was captured, and `_absorb` withholds the rest —
        those versions stay `pending`, their operation steps keep waiting, and the generation
        is not acknowledged, so the next tick delivers it again (an idempotent re-PUT: the
        node hands the runtime's form back in its reply) until every credential is in escrow
        or the node reports the generation `failed` (backoff, as for any failed apply)."""
        try:
            observed = await client.observed()
        except CLIENT_ERRORS as exc:
            self._offline(node_id, exc)
            return
        credentials: dict[str, str] = {}
        if observed.reconcile_state in SETTLED_STATES:
            credentials = await self._capture_pending(client, node_id, observed)
        self._absorb(node_id, observed, credentials)

    async def _capture_pending(self, client, node_id: str, observed: ObservedGeneration) -> dict[str, str]:
        """The runtime's credential for every grant the report shows present whose version
        the in-flight document names is still `pending`, keyed by that `credential_ref`;
        asked in batches of at most `CAPTURE_MAX_RESOURCES` (the node's cap per call). A
        batch the node cannot answer (unreachable, 4xx/5xx) ends the asking: what earlier
        batches returned is kept, the rest is asked again on a later tick."""
        present = {item.ref for item in observed.resources if item.state in ("enabled", "disabled", "drifted")}
        wanted: dict[str, dict] = {}
        with self.database.connect() as db:
            latest = self.desired.latest(db, node_id)
            if latest is None or observed.applied_generation != latest["generation"]:
                return {}
            for resource in latest["document"].resources:
                if resource.ref not in present or resource.desired_state == "deleted":
                    continue
                secret_id, _, version = resource.credential_ref.rpartition(":")
                row = db.execute("SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
                                 (secret_id, int(version))).fetchone()
                # No row at all: an imported grant the node could not reveal at import time
                # (`secret_ref is None`); the version the document names is asked for now, so
                # a 202 on its generation does not leave it without a credential until a re-PUT.
                if row is None or row["state"] == "pending":
                    wanted[f"{resource.protocol}:{resource.runtime_username}"] = {
                        "credential_ref": resource.credential_ref,
                        "resource": {"protocol": resource.protocol, "runtime_username": resource.runtime_username}}
        returned: dict = {}
        labels = list(wanted)
        for start in range(0, len(labels), CAPTURE_MAX_RESOURCES):
            batch = labels[start:start + CAPTURE_MAX_RESOURCES]
            try:
                answer = await client.capture([wanted[label]["resource"] for label in batch])
            except CLIENT_ERRORS as exc:
                log.warning("fleet: node %s: credential capture failed (%s); %s of %s answered, the rest is asked again",
                            node_id, _describe(exc), start, len(labels))
                break
            returned.update(answer.get("credentials") or {})
        return {entry["credential_ref"]: returned[label] for label, entry in wanted.items()
                if isinstance(returned.get(label), str) and returned[label]}

    @staticmethod
    def _names(grant, credential_ref: str) -> bool:
        """The grant still points at the version the node answered for. A rotation published
        meanwhile moved it on: escrowing the old value would resurrect a `retiring` version
        as `active`, and the node rotates to the new one on the next generation anyway."""
        return grant.secret_ref is None or credential_ref == f"{grant.secret_ref.secret_id}:{grant.secret_ref.version}"

    def _uncaptured(self, db, grant) -> bool:
        """The version the grant names is still `pending` while its runtime owns the
        credential's form (`credential_origin == "manager"`: Telemt reframes even a caller's
        secret as the `ee…` link secret). Confirming it now would activate the bare value the
        central generated; only the node's answer — captured or returned in a push reply and
        escrowed just before — may activate it."""
        adapter = self.provisioning.adapters.get(grant.protocol)
        if grant.secret_ref is None or adapter is None or adapter.credential_origin != "manager":
            return False
        row = db.execute("SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
                         (grant.secret_ref.secret_id, grant.secret_ref.version)).fetchone()
        return row is not None and row["state"] == "pending"

    def _absorb_egress(self, db, latest: dict, observed: ObservedGeneration, now: int) -> None:
        """The node's word on each egress section of the generation the central wants (v0.4,
        spec §8.3): `converged` makes the policy `applied` at the revision the section named,
        anything else `failed` with the node's code. Recorded once per outcome, not per tick."""
        egress = latest["document"].egress
        if self.routing is None or not egress:
            return
        for protocol, entry in egress.items():
            report = observed.egress.get(protocol)
            if report is None:
                continue
            try:
                policy = self.routing.get_by_id(db, entry.policy_id)
            except PolicyNotFound:
                continue
            detail = {"generation": latest["generation"], "manager_revision": report.revision}
            if report.router is not None:
                detail["router"] = report.router
            if report.state == "converged":
                # An attach/detach generation (v0.5) runs the backend's pass-through while the
                # policy itself still has rules: the node did what was asked, the policy is
                # not applied — it waits as a draft on its new backend.
                policy_empty = policy.default_action == "direct" and not any(rule.enabled for rule in policy.rules)
                if entry.passthrough and not policy_empty:
                    if policy.state == "draft" and policy.applied_digest == entry.digest and policy.backend == entry.backend:
                        continue
                    self.routing.mark(db, policy.id, state="draft", applied_revision=None, applied_digest=entry.digest, now=now)
                    self.routing.record_apply(db, policy.id, revision=entry.policy_revision, digest=entry.digest,
                                              backend=entry.backend, outcome="applied",
                                              detail=json.dumps({**detail, "passthrough": True}, sort_keys=True),
                                              actor="node", document=entry.document, now=now)
                    continue
                if (policy.state, policy.applied_revision, policy.applied_digest) == ("applied", entry.policy_revision,
                                                                                      entry.digest):
                    continue
                self.routing.mark(db, policy.id, state="applied", applied_revision=entry.policy_revision,
                                  applied_digest=entry.digest, now=now)
                self.routing.record_apply(db, policy.id, revision=entry.policy_revision, digest=entry.digest,
                                          backend=entry.backend, outcome="applied", detail=json.dumps(detail, sort_keys=True),
                                          actor="node", document=entry.document, now=now)
                if entry.document.get("schema") == 2:
                    # The router runs every lane of the service as one intent (v0.7): they all
                    # stand applied at this digest now.
                    for other in self.routing.lanes_of(db, policy.node_id, policy.protocol):
                        if other.id != policy.id:
                            self.routing.mark(db, other.id, state="applied", applied_revision=other.revision,
                                              applied_digest=entry.digest, now=now)
            else:
                error = report.error or report.state
                if policy.state == "failed" and policy.last_error == error:
                    continue
                self.routing.mark(db, policy.id, state="failed", last_error=error, now=now)
                self.routing.record_apply(db, policy.id, revision=entry.policy_revision, digest=entry.digest,
                                          backend=entry.backend, outcome="failed",
                                          detail=json.dumps({**detail, "error": error}, sort_keys=True), actor="node", now=now)

    def _absorb(self, node_id: str, observed: ObservedGeneration, credentials: dict[str, str]) -> None:
        """One transaction: the report itself, each grant's observed state, credentials
        the runtime chose, and the operations that waited for this node.

        Only a settled report (`SETTLED_STATES`) about the generation the central currently
        wants escrows or confirms a credential version or finishes an operation: a report
        about an older generation says nothing about the version the grant names now, and
        an `applying` one still shows rows the apply has not reached with their previous
        state — a rotation not yet applied would otherwise be confirmed with the old secret.
        A deletion the node confirms (`missing` for a grant the central wants `deleted`)
        purges the row, whatever the generation: the account is gone, and the name is free
        to grant again.

        A grant whose runtime owns the credential's form (`_uncaptured`) is confirmed only
        once that form is in escrow: without it the version stays `pending`, the operation
        step keeps waiting, and the generation is recorded but not acknowledged — the link
        stays `config_dirty`, so the next tick delivers it again and the node's reply carries
        the credential. The rest of the report is absorbed as usual.
        """
        now = int(self.clock.time())
        withheld: set[str] = set()
        with self.database.transaction() as db:
            latest = self.desired.latest(db, node_id)
            settled = observed.reconcile_state in SETTLED_STATES
            current = settled and latest is not None and observed.applied_generation == latest["generation"]
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
                if state == "missing" and grant.desired_state == "deleted":
                    self.clients.purge_grant(db, grant.id)
                    continue
                returned = next((ref for ref in credentials if ref.startswith(item.ref + ":")), None)
                # Only the generation the central wants now may escrow: a late answer about an
                # older one could otherwise overwrite what the newer generation's report put
                # in escrow — the newer generation's re-PUT returns the value again anyway.
                if current and returned is not None and self._names(grant, returned):
                    self.provisioning.escrow_returned_credential(db, grant.id, returned, credentials[returned])
                if item.learned and state != "missing":
                    # Telemt's host/port, mita's share template: the link renders from these.
                    self.provisioning.remember_template(db, grant, item.learned)
                if current and state != "missing":
                    if self._uncaptured(db, grant):
                        withheld.add(grant.id)
                    else:
                        self.provisioning.confirm_credential(db, grant.id)
                self.clients.store.update_grant(db, grant.id, observed_state=state, updated_at=now)
            if current:
                self.provisioning.remote_applied(db, observed, withheld=withheld, withheld_error=NOT_CAPTURED)
                self._absorb_egress(db, latest, observed, now)
            self.desired.record_observed(db, node_id, observed, acknowledge=not withheld)
            if observed.relay is not None:
                # The node's relay (v0.7): its public part for the chains of other nodes, the
                # accounts it confirmed for the applies that wait on them.
                self.desired.record_relay(db, node_id, observed.relay.model_dump())
                RelayRegistry.observe(db, node_id, observed.relay.model_dump(), now=now)
        if not (current and withheld):
            self._withheld.pop(node_id, None)
            return
        generation = observed.applied_generation
        previous = self._withheld.get(node_id)
        ticks = previous[1] + 1 if previous and previous[0] == generation else 1
        self._withheld[node_id] = (generation, ticks)
        log.warning("fleet: node %s: %s credential(s) not captured yet (%s tick(s)); generation %s is delivered again",
                    node_id, len(withheld), ticks, generation)
        if ticks >= WITHHELD_TICKS_BEFORE_BACKOFF:
            # The node converges every time but never hands the credential over: keep asking,
            # at the failed-apply cadence rather than every tick.
            self._defer(node_id, generation)
