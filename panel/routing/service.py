"""Routing policies end to end: targets, preview, save, apply, rollback (spec §8).

The local node is applied through its manager adapters; a linked panel through a Fleet
v2 generation (`publisher`, spec §8.3). Manager I/O never runs inside a `BEGIN
IMMEDIATE`: the policy is read, the manager is asked, and only then the outcome is
written with its audit row in one transaction — the same rule the grant saga follows.
"""
from __future__ import annotations

import json
import time
from typing import Callable

from .. import audit
from ..database import Database
from ..nodes.registry import NodeRegistry
from ..protocols.base import AdapterError, AppliedEgress, EgressTarget
from .compiler import compile as compile_policy
from .compiler import direct_document
from .document import document_digest
from .models import BACKEND_FOR, Compiled, PolicyInput, Reason, RoutingPolicy
from .store import PolicyConflict, RoutingStore

PROTOCOLS = ("mtproxy", "naive", "mieru")
# What an apply failure costs the caller: the manager's own refusals are conflicts, an
# unrecoverable runtime is a 503, a manager that does not answer a 502.
ERROR_STATUS = {"manual_intervention_required": 503, "manager_unavailable": 502}


class RoutingError(Exception):
    def __init__(self, status: int, code: str, detail: str = "", *, compiled: Compiled | None = None):
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.compiled = compiled


def target_from_identity(protocol: str, entry: dict | None) -> EgressTarget | None:
    """A linked panel's `identity.protocols[p].egress` as the compiler's target. The node
    reports its applied document's digest, not the document; the diff is then against
    that digest only."""
    if not isinstance(entry, dict) or entry.get("backend") not in BACKEND_FOR.values():
        return None
    providers = {name: {"reachable": value.get("reachable")} for name, value in (entry.get("providers") or {}).items()
                 if isinstance(value, dict)}
    revision = str(entry.get("revision") or "")
    digest = entry.get("applied_digest")
    mode = entry.get("mode") if entry.get("mode") in ("direct", "proxy", "custom") else "custom"
    return EgressTarget(
        protocol=protocol, backend=entry["backend"],
        capabilities=frozenset(item for item in entry.get("capabilities", []) if isinstance(item, str)),
        providers=providers, revision=revision,
        applied=None if not isinstance(digest, str) else {"revision": revision, "digest": digest, "document": None},
        mode=mode, restart_required=entry.get("restart_required") is True,
        warnings=tuple(item for item in entry.get("warnings", []) if isinstance(item, str)),
    )


class RoutingService:
    def __init__(self, database: Database, store: RoutingStore, adapters: dict, nodes: NodeRegistry, *,
                 enabled: Callable[[str], bool] = lambda protocol: True, publisher=None, managed=None, clock=time):
        self.database = database
        self.store = store
        self.adapters = adapters
        self.nodes = nodes
        self.enabled = enabled
        # The remote path (spec §8.3): `publisher(db, node_id)` publishes a generation carrying
        # the node's desired egress sections; None means this panel applies locally only.
        self.publisher = publisher
        # The node side of a link (ADR 003): while a central manages this panel, its egress is
        # the central's to set — a local apply would race the next generation.
        self.managed = managed
        self.clock = clock

    def _master(self, db) -> str | None:
        return None if self.managed is None else self.managed.master_guid(db)

    # -- targets -----------------------------------------------------------------------

    @staticmethod
    def _kind(row: dict) -> str:
        if row["kind"] == "local":
            return "local"
        return "remote" if row.get("link") else "v1"

    async def _local_target(self, protocol: str) -> EgressTarget | None:
        adapter = self.adapters.get(protocol)
        if adapter is None or not self.enabled(protocol):
            return None
        return await adapter.egress_target()

    async def _target(self, row: dict, protocol: str) -> tuple[EgressTarget | None, bool]:
        """(target, node has egress.v1). A manager that does not answer raises AdapterError."""
        kind = self._kind(row)
        if kind == "local":
            return await self._local_target(protocol), True
        if kind != "remote":
            return None, False
        identity = row["link"].get("identity") or {}
        if "egress.v1" not in (identity.get("capabilities") or []):
            return None, False
        return target_from_identity(protocol, (identity.get("protocols") or {}).get(protocol, {}).get("egress")), True

    async def targets(self) -> list[dict]:
        """Nodes × protocols, with the policy each has (spec §8.1)."""
        with self.database.connect() as db:
            rows = [row for row in self.nodes.rows(db) if self._kind(row) != "v1"]
            policies = {(policy.node_id, policy.protocol): policy for policy in self.store.list(db)}
            master = self._master(db)
        items = []
        for row in rows:
            node_id, kind = row["node_id"], self._kind(row)
            for protocol in PROTOCOLS:
                item = {"node_id": node_id, "node_name": row["display_name"], "kind": kind, "protocol": protocol,
                        "backend": None, "capabilities": [], "providers": {}, "egress_v1": kind == "local",
                        "mode": None, "policy": None, "reason": None}
                policy = policies.get((node_id, protocol))
                if policy is not None:
                    enabled_rules = [rule for rule in policy.rules if rule.enabled]
                    item["policy"] = {"id": policy.id, "revision": policy.revision, "state": policy.state,
                                      "applied_revision": policy.applied_revision, "applied_current": policy.applied_current,
                                      "last_error": policy.last_error, "default_action": policy.default_action,
                                      "default_egress": policy.default_egress,
                                      "rules": {action: sum(rule.action == action for rule in enabled_rules)
                                                for action in ("block", "direct", "egress")}}
                if protocol not in BACKEND_FOR:
                    item["reason"] = "protocol_out_of_scope"
                    items.append(item)
                    continue
                if kind == "remote" and row["link"].get("status") != "online":
                    item["reason"] = "node_offline"
                elif kind == "local" and master is not None:
                    item["reason"] = "managed_by_central"
                try:
                    target, egress_v1 = await self._target(row, protocol)
                except AdapterError as exc:
                    target, egress_v1, item["reason"] = None, True, exc.code or "manager_unavailable"
                item["egress_v1"] = egress_v1
                if target is None:
                    item["reason"] = item["reason"] or ("protocol_disabled_on_node" if egress_v1 else "node_lacks_egress_v1")
                else:
                    item.update({"backend": target.backend, "capabilities": sorted(target.capabilities),
                                 "providers": target.providers, "mode": target.mode})
                items.append(item)
        return items

    # -- policies ----------------------------------------------------------------------

    @staticmethod
    def _protocol(protocol: str) -> None:
        if protocol not in BACKEND_FOR:
            raise RoutingError(422, "protocol_out_of_scope", f"{protocol} is outside routing")

    def _node(self, db, node_id: str) -> dict:
        try:
            return self.nodes.row(db, node_id)
        except KeyError as exc:
            raise RoutingError(404, "node_not_found", "node not found") from exc

    def _policy(self, db, node_id: str, protocol: str) -> RoutingPolicy:
        self._protocol(protocol)
        self._node(db, node_id)
        policy = self.store.get(db, node_id, protocol)
        if policy is None:
            raise RoutingError(404, "policy_not_found", "no routing policy for this node and protocol")
        return policy

    def get(self, node_id: str, protocol: str) -> RoutingPolicy:
        with self.database.connect() as db:
            return self._policy(db, node_id, protocol)

    def history(self, node_id: str, protocol: str) -> list[dict]:
        with self.database.connect() as db:
            policy = self._policy(db, node_id, protocol)
            return self.store.history(db, policy.id)

    def save(self, node_id: str, protocol: str, draft: PolicyInput, *, expected_revision: int | None,
             actor: dict, ip: str, request_id: str | None = None) -> RoutingPolicy:
        self._protocol(protocol)
        with self.database.transaction() as db:
            self._node(db, node_id)
            try:
                policy = self.store.upsert(db, node_id, protocol, draft, expected_revision=expected_revision,
                                           now=int(self.clock.time()))
            except PolicyConflict as exc:
                raise RoutingError(409, "policy_conflict", f"policy revision is {exc.current_revision}") from exc
            except ValueError as exc:
                raise RoutingError(422, "backend_mismatch", str(exc)) from exc
            audit.record(db, actor=actor, action="routing.policy.update", target=policy.id, ip=ip, request_id=request_id,
                         detail={"node_id": node_id, "protocol": protocol, "revision": policy.revision,
                                 "rules": len(policy.rules), "default_action": policy.default_action})
            return policy

    def delete(self, node_id: str, protocol: str, *, actor: dict, ip: str, request_id: str | None = None) -> None:
        """Only a policy the node no longer enforces: applied means the runtime still runs
        it, and forgetting the policy would not change that (spec §8.1)."""
        with self.database.transaction() as db:
            policy = self._policy(db, node_id, protocol)
            reset = document_digest(direct_document(policy.backend))
            if policy.applied_digest is not None and policy.applied_digest != reset:
                raise RoutingError(409, "policy_applied", "reset the policy to direct and apply it before deleting")
            self.store.delete(db, policy.id)
            audit.record(db, actor=actor, action="routing.policy.delete", target=policy.id, ip=ip, request_id=request_id,
                         detail={"node_id": node_id, "protocol": protocol, "revision": policy.revision})

    # -- preview and apply -------------------------------------------------------------

    @staticmethod
    def _unavailable(policy: RoutingPolicy, exc: AdapterError) -> Compiled:
        return Compiled(status="unsupported", backend=policy.backend,
                        reasons=[Reason(code=exc.code or "manager_unavailable", message=str(exc))])

    async def preview(self, node_id: str, protocol: str, draft: PolicyInput | None) -> Compiled:
        self._protocol(protocol)
        with self.database.connect() as db:
            row = self._node(db, node_id)
            stored = self.store.get(db, node_id, protocol)
        if draft is None:
            if stored is None:
                raise RoutingError(404, "policy_not_found", "no routing policy for this node and protocol")
            policy = stored
        else:
            backend = BACKEND_FOR[protocol]
            if draft.backend is not None and draft.backend != backend:
                raise RoutingError(422, "backend_mismatch", f"{protocol} compiles to {backend}")
            policy = RoutingPolicy(id=stored.id if stored else "draft", node_id=node_id, protocol=protocol, backend=backend,
                                   revision=stored.revision if stored else 1,
                                   **draft.model_dump(exclude={"backend"}))
        try:
            target, egress_v1 = await self._target(row, protocol)
        except AdapterError as exc:
            return self._unavailable(policy, exc)
        return compile_policy(policy, target, node_egress_v1=egress_v1)

    def _operation_id(self, policy: RoutingPolicy) -> str:
        return f"routing:{policy.id}:{policy.revision}"

    def _record(self, policy: RoutingPolicy, compiled: Compiled, *, outcome: str, applied: AppliedEgress | None,
                error: str | None, actor: dict, ip: str, request_id: str | None, action: str) -> RoutingPolicy:
        now = int(self.clock.time())
        with self.database.transaction() as db:
            if outcome == "applied":
                self.store.mark(db, policy.id, state="applied", applied_revision=policy.revision,
                                applied_digest=compiled.digest, now=now)
                detail = {"manager_revision": applied.revision, "readback_sha256": applied.readback_sha256,
                          "replayed": applied.replayed}
            elif outcome == "rolled_back":
                previous = self.store.last_applied(db, policy.id)
                revision = previous["revision"] if previous and previous["digest"] == applied.digest else None
                self.store.mark(db, policy.id, state="rolled_back", applied_revision=revision,
                                applied_digest=applied.digest, now=now)
                detail = {"manager_revision": applied.revision, "to_revision": revision}
            else:
                self.store.mark(db, policy.id, state="failed", last_error=error, now=now)
                detail = {"error": error}
            self.store.record_apply(db, policy.id, revision=policy.revision,
                                    digest=applied.digest if applied is not None else compiled.digest,
                                    backend=policy.backend, outcome=outcome, detail=json.dumps(detail, sort_keys=True),
                                    actor=actor["username"], runtime_version=compiled.runtime_version,
                                    compiler_version=compiled.compiler_version,
                                    document=compiled.document if outcome == "applied" else None, now=now)
            audit.record(db, actor=actor, action=action, target=policy.id, ip=ip, request_id=request_id,
                         detail={"node_id": policy.node_id, "protocol": policy.protocol, "revision": policy.revision,
                                 "outcome": outcome, "digest": compiled.digest, **detail})
            return self.store.get_by_id(db, policy.id)

    def _for_change(self, node_id: str, protocol: str, expected_revision: int) -> tuple[RoutingPolicy, dict]:
        with self.database.connect() as db:
            policy = self._policy(db, node_id, protocol)
            row = self._node(db, node_id)
            master = self._master(db)
        if expected_revision != policy.revision:
            raise RoutingError(409, "policy_conflict", f"policy revision is {policy.revision}")
        if self._kind(row) == "local" and master is not None:
            raise RoutingError(409, "managed_by_central", "a central panel manages this node's egress")
        return policy, row

    async def apply(self, node_id: str, protocol: str, *, expected_revision: int, actor: dict, ip: str,
                    request_id: str | None = None) -> dict:
        """compile → plan → apply on the manager, then the outcome in one transaction."""
        policy, row = self._for_change(node_id, protocol, expected_revision)
        try:
            target, egress_v1 = await self._target(row, protocol)
        except AdapterError as exc:
            raise RoutingError(ERROR_STATUS.get(exc.code, 409), exc.code or "manager_unavailable", str(exc)) from exc
        compiled = compile_policy(policy, target, node_egress_v1=egress_v1)
        if compiled.status != "supported":
            raise RoutingError(422, "unsupported", "the policy cannot be enforced on this node", compiled=compiled)
        if self._kind(row) != "local":
            return await self._apply_remote(policy, compiled, actor=actor, ip=ip, request_id=request_id)
        adapter = self.adapters[protocol]
        try:
            await adapter.plan_egress(compiled.document, expected_revision=target.revision)
            applied = await adapter.apply_egress(compiled.document, expected_revision=target.revision,
                                                 operation_id=self._operation_id(policy))
        except AdapterError as exc:
            code = exc.code or "manager_unavailable"
            self._record(policy, compiled, outcome="failed", applied=None, error=code, actor=actor, ip=ip,
                         request_id=request_id, action="routing.policy.apply")
            raise RoutingError(ERROR_STATUS.get(code, 409), code, str(exc)) from exc
        updated = self._record(policy, compiled, outcome="applied", applied=applied, error=None, actor=actor, ip=ip,
                               request_id=request_id, action="routing.policy.apply")
        return {"policy": updated, "applied": applied, "compiled": compiled}

    def _publish_desired(self, policy: RoutingPolicy, desired: dict, *, action: str, detail: dict, actor, ip,
                         request_id) -> RoutingPolicy:
        """The remote path (spec §8.3): the policy's desired egress section joins the node's
        next generation; the node's report (pusher) then moves the policy on."""
        if self.publisher is None:
            raise RoutingError(409, "node_not_local", "this panel applies routing locally only")
        now = int(self.clock.time())
        with self.database.transaction() as db:
            self.store.set_desired(db, policy.id, desired, now=now)
            self.store.mark(db, policy.id, state="applying", now=now)
            if action == "routing.policy.rollback":
                self.store.record_apply(db, policy.id, revision=policy.revision, digest=desired["digest"],
                                        backend=policy.backend, outcome="rolled_back",
                                        detail=json.dumps(detail, sort_keys=True), actor=actor["username"], now=now)
            generation = self.publisher(db, policy.node_id)
            audit.record(db, actor=actor, action=action, target=policy.id, ip=ip, request_id=request_id,
                         detail={"node_id": policy.node_id, "protocol": policy.protocol, "revision": policy.revision,
                                 "outcome": "applying", "generation": generation, **detail})
            return self.store.get_by_id(db, policy.id)

    async def _apply_remote(self, policy: RoutingPolicy, compiled: Compiled, *, actor, ip, request_id) -> dict:
        desired = {"backend": policy.backend, "policy_id": policy.id, "policy_revision": policy.revision,
                   "document": compiled.document, "digest": compiled.digest}
        updated = self._publish_desired(policy, desired, action="routing.policy.apply", detail={"digest": compiled.digest},
                                        actor=actor, ip=ip, request_id=request_id)
        return {"policy": updated, "applied": None, "compiled": compiled}

    async def _rollback_remote(self, policy: RoutingPolicy, *, actor, ip, request_id) -> dict:
        """Back to the document of the previous successful apply in the central's own history
        (the manager's journal is the node's); one step, not a stack."""
        with self.database.connect() as db:
            previous = self.store.last_applied(db, policy.id)
        if previous is None or previous.get("document") is None:
            raise RoutingError(409, "egress_no_previous", "no previous applied document to return to")
        desired = {"backend": policy.backend, "policy_id": policy.id, "policy_revision": previous["revision"],
                   "document": previous["document"], "digest": previous["digest"]}
        updated = self._publish_desired(policy, desired, action="routing.policy.rollback",
                                        detail={"to_revision": previous["revision"], "digest": previous["digest"]},
                                        actor=actor, ip=ip, request_id=request_id)
        compiled = Compiled(status="supported", backend=policy.backend, digest=previous["digest"],
                            document=previous["document"])
        return {"policy": updated, "applied": None, "compiled": compiled}

    async def rollback(self, node_id: str, protocol: str, *, expected_revision: int, actor: dict, ip: str,
                       request_id: str | None = None) -> dict:
        policy, row = self._for_change(node_id, protocol, expected_revision)
        if self._kind(row) != "local":
            return await self._rollback_remote(policy, actor=actor, ip=ip, request_id=request_id)
        try:
            target = await self._local_target(protocol)
            if target is None:
                raise RoutingError(422, "protocol_disabled_on_node", f"{protocol} reports no egress target")
            applied = await self.adapters[protocol].rollback_egress(expected_revision=target.revision)
        except AdapterError as exc:
            code = exc.code or "manager_unavailable"
            raise RoutingError(ERROR_STATUS.get(code, 409), code, str(exc)) from exc
        compiled = Compiled(status="supported", backend=policy.backend, digest=applied.digest,
                            runtime_version=target.runtime_version, restart_required=target.restart_required)
        updated = self._record(policy, compiled, outcome="rolled_back", applied=applied, error=None, actor=actor, ip=ip,
                               request_id=request_id, action="routing.policy.rollback")
        return {"policy": updated, "applied": applied, "compiled": compiled}
