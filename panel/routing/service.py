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
from urllib.parse import urlsplit

from .. import audit
from ..database import Database
from ..nodes.registry import NodeRegistry
from ..protocols.base import AdapterError, AppliedEgress, EgressTarget, RouterTarget
from .compiler import compile as compile_policy
from .compiler import direct_document, explain
from .document import ROUTER_DIRECT_INTENT, attach_document, document_digest
from .lanes import DEFAULT_RELAY_PORT, ChainResolver, RelayRegistry, lane_policies
from .models import (
    BACKEND_FOR,
    LANE_SERVICE,
    ROUTER_BACKEND,
    Compiled,
    PolicyInput,
    Reason,
    RoutingPolicy,
    backends_for,
    exit_hops,
    normalise_lane,
)
from .store import PolicyConflict, RoutingStore

PROTOCOLS = ("mtproxy", "naive", "mieru")
# What an apply failure costs the caller: the manager's own refusals are conflicts, an
# unrecoverable runtime is a 503, a manager that does not answer a 502.
ERROR_STATUS = {"manual_intervention_required": 503, "manager_unavailable": 502, "artifact_mismatch": 503}


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
        router_attached=entry.get("router_attached") is True,
    )


def router_target_from_identity(protocol: str, router: dict | None) -> RouterTarget | None:
    """A linked panel's `identity.router` (v0.5) as the compiler's router target for one
    service: None when the node reports no router at all."""
    if not isinstance(router, dict):
        return None
    if not router.get("available"):
        reason = router.get("reason") if isinstance(router.get("reason"), str) else "router_unavailable"
        return RouterTarget(available=False, service=protocol, reason=reason)
    section = (router.get("services") or {}).get(protocol) or {}
    revision = str(section.get("revision") or "")
    digest = section.get("applied_digest")
    providers = {name: {"reachable": value.get("reachable")} for name, value in (router.get("providers") or {}).items()
                 if isinstance(value, dict)}
    return RouterTarget(
        available=True, service=protocol,
        capabilities=frozenset(item for item in router.get("capabilities", []) if isinstance(item, str)),
        providers=providers, revision=revision,
        applied=None if not isinstance(digest, str) else {"revision": revision, "digest": digest, "document": None},
        xray_version=router.get("xray_version") if isinstance(router.get("xray_version"), str) else None,
    )


class RoutingService:
    def __init__(self, database: Database, store: RoutingStore, adapters: dict, nodes: NodeRegistry, *,
                 enabled: Callable[[str], bool] = lambda protocol: True, publisher=None, managed=None, clock=time,
                 router=None, relays: RelayRegistry | None = None, own_guid: str = "local", local_host: str = "",
                 confirmed=None):
        self.database = database
        self.store = store
        self.adapters = adapters
        self.nodes = nodes
        self.enabled = enabled
        # Chains (v0.7): the relay accounts this panel issued and what each node reports about
        # its relay; this panel's own guid (a chain through it is a loop); the host other nodes
        # dial for this node's relay; `confirmed(node_id, email)` — whether a node's relay
        # carries an account yet (a linked panel says so through its report).
        self.relays = relays
        self.own_guid = own_guid
        self.local_host = local_host
        self.confirmed = confirmed or (lambda node_id, email: node_id == "local")
        # The local node's Xray-router adapter (v0.5), None when this panel runs no router.
        self.router = router
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

    @staticmethod
    def _capabilities(row: dict) -> list[str]:
        """What a linked node declared; a local node can do everything this release can."""
        if row["kind"] == "local" or not row.get("link"):
            return []
        return list(((row["link"].get("identity") or {}).get("capabilities")) or [])

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

    async def _router_target(self, row: dict, protocol: str) -> RouterTarget | None:
        """The service's section on the node's Xray-router, or None when the node has none."""
        kind = self._kind(row)
        if kind == "local":
            return None if self.router is None else await self.router.target(protocol)
        if kind != "remote":
            return None
        identity = row["link"].get("identity") or {}
        if "egress.router.v1" not in (identity.get("capabilities") or []):
            return None
        return router_target_from_identity(protocol, identity.get("router"))

    @staticmethod
    def _router_view(router: RouterTarget | None, target: EgressTarget | None) -> dict | None:
        if router is None:
            return None
        return {"available": router.available, "attached": target is not None and target.router_attached,
                "xray_version": router.xray_version, "restart_required": router.restart_required, "reason": router.reason}

    async def targets(self) -> list[dict]:
        """Nodes × protocols, with the policy each has (spec §8.1)."""
        with self.database.connect() as db:
            rows = [row for row in self.nodes.rows(db) if self._kind(row) != "v1"]
            policies = {(policy.node_id, policy.protocol): policy for policy in self.store.list(db) if policy.lane == LANE_SERVICE}
            lanes: dict[tuple[str, str], list[dict]] = {}
            for policy in self.store.list(db):
                if policy.lane != LANE_SERVICE:
                    lanes.setdefault((policy.node_id, policy.protocol), []).append(self._policy_view(policy))
            master = self._master(db)
            exits = self._exits(db, rows)
        items = []
        for row in rows:
            node_id, kind = row["node_id"], self._kind(row)
            for protocol in PROTOCOLS:
                item = {"node_id": node_id, "node_name": row["display_name"], "kind": kind, "protocol": protocol,
                        "backend": None, "capabilities": [], "providers": {}, "egress_v1": kind == "local",
                        "mode": None, "policy": None, "reason": None, "router": None,
                        "lanes": lanes.get((node_id, protocol), []),
                        "exits": [exit_ for exit_ in exits if exit_["node_id"] != node_id]}
                policy = policies.get((node_id, protocol))
                if policy is not None:
                    item["policy"] = self._policy_view(policy)
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
                router = await self._router_target(row, protocol)
                item["router"] = self._router_view(router, target)
                if target is None:
                    item["reason"] = item["reason"] or ("protocol_disabled_on_node" if egress_v1 else "node_lacks_egress_v1")
                elif target.router_attached:
                    # The service is handed to the router: the router's cells are what a policy
                    # can use, its absence is what the operator must hear about.
                    item.update({"backend": ROUTER_BACKEND, "mode": target.mode, "providers": target.providers,
                                 "capabilities": sorted(router.capabilities) if router is not None and router.available else []})
                    if router is None or not router.available:
                        item["reason"] = item["reason"] or (router.reason if router is not None else "router_unavailable")
                else:
                    item.update({"backend": target.backend, "capabilities": sorted(target.capabilities),
                                 "providers": target.providers, "mode": target.mode})
                items.append(item)
        return items

    @staticmethod
    def _policy_view(policy: RoutingPolicy) -> dict:
        enabled_rules = [rule for rule in policy.rules if rule.enabled]
        return {"id": policy.id, "lane": policy.lane, "revision": policy.revision, "state": policy.state, "backend": policy.backend,
                "applied_revision": policy.applied_revision, "applied_current": policy.applied_current,
                "last_error": policy.last_error, "default_action": policy.default_action,
                "default_egress": policy.default_egress,
                "rules": {action: sum(rule.action == action for rule in enabled_rules) for action in ("block", "direct", "egress")},
                "node_exits": policy.node_exits()}

    def _exits(self, db, rows: list[dict]) -> list[dict]:
        """The nodes of the fleet a policy may exit through (v0.7): every node with a relay
        the panel knows, its state and what it can do next (direct, its warp)."""
        if self.relays is None:
            return []
        exits = []
        for row in rows:
            node_id = row["node_id"]
            relay = self.relays.relay(db, node_id)
            if relay is None:
                continue
            guid = self.own_guid if node_id == "local" else node_id
            link = row.get("link") or {}
            online = node_id == "local" or link.get("status") == "online"
            exits.append({"kind": "node", "node_id": node_id, "guid": guid, "display_name": row["display_name"],
                          "enabled": bool(relay.get("enabled")), "port": relay.get("port"), "online": online,
                          "via": ["direct", "warp"], "exit": f"node:{guid}"})
        return exits

    async def _target_item(self, node_id: str, protocol: str) -> dict:
        for item in await self.targets():
            if item["node_id"] == node_id and item["protocol"] == protocol:
                return item
        raise RoutingError(404, "node_not_found", "node not found")

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

    @staticmethod
    def _lane(lane: str | None) -> str:
        try:
            return normalise_lane(lane)
        except ValueError as exc:
            raise RoutingError(422, "lane_invalid", str(exc)) from exc

    def _policy(self, db, node_id: str, protocol: str, lane: str = LANE_SERVICE) -> RoutingPolicy:
        self._protocol(protocol)
        self._node(db, node_id)
        policy = self.store.get(db, node_id, protocol, lane=self._lane(lane))
        if policy is None:
            raise RoutingError(404, "policy_not_found", "no routing policy for this node, protocol and lane")
        return policy

    def get(self, node_id: str, protocol: str, lane: str = LANE_SERVICE) -> RoutingPolicy:
        with self.database.connect() as db:
            return self._policy(db, node_id, protocol, lane)

    def history(self, node_id: str, protocol: str, lane: str = LANE_SERVICE) -> list[dict]:
        with self.database.connect() as db:
            policy = self._policy(db, node_id, protocol, lane)
            return self.store.history(db, policy.id)

    def _lane_allowed(self, db, node_id: str, protocol: str, lane: str) -> None:
        """A grant lane's policy exists only for a grant that has its lane on this node."""
        if lane == LANE_SERVICE:
            return
        row = db.execute("SELECT routing_lane FROM access_grants WHERE id=? AND node_id=? AND protocol=?",
                         (lane[6:], node_id, protocol)).fetchone()
        if row is None or row["routing_lane"] != "own":
            raise RoutingError(404, "lane_not_found", "the grant has no lane on this node")

    def save(self, node_id: str, protocol: str, draft: PolicyInput, *, expected_revision: int | None,
             actor: dict, ip: str, request_id: str | None = None, lane: str = LANE_SERVICE) -> RoutingPolicy:
        self._protocol(protocol)
        lane = self._lane(lane)
        with self.database.transaction() as db:
            self._node(db, node_id)
            self._lane_allowed(db, node_id, protocol, lane)
            try:
                policy = self.store.upsert(db, node_id, protocol, draft, expected_revision=expected_revision,
                                           now=int(self.clock.time()), lane=lane)
            except PolicyConflict as exc:
                raise RoutingError(409, "policy_conflict", f"policy revision is {exc.current_revision}") from exc
            except ValueError as exc:
                raise RoutingError(422, "backend_mismatch", str(exc)) from exc
            audit.record(db, actor=actor, action="routing.policy.update", target=policy.id, ip=ip, request_id=request_id,
                         detail={"node_id": node_id, "protocol": protocol, "lane": lane, "revision": policy.revision,
                                 "rules": len(policy.rules), "default_action": policy.default_action,
                                 "node_exits": policy.node_exits()})
            return policy

    def delete(self, node_id: str, protocol: str, *, actor: dict, ip: str, request_id: str | None = None,
               lane: str = LANE_SERVICE) -> None:
        """Only a policy the node no longer enforces: applied means the runtime still runs
        it, and forgetting the policy would not change that (spec §8.1). A grant lane's
        policy goes with the lane (`LaneService.disable`), not here."""
        with self.database.transaction() as db:
            policy = self._policy(db, node_id, protocol, lane)
            if policy.lane != LANE_SERVICE:
                raise RoutingError(409, "lane_policy", "a lane's policy is removed by taking the lane away from its grant")
            reset = document_digest(direct_document(policy.backend))
            if policy.applied_digest is not None and policy.applied_digest != reset:
                raise RoutingError(409, "policy_applied", "reset the policy to direct and apply it before deleting")
            self.store.delete(db, policy.id)
            audit.record(db, actor=actor, action="routing.policy.delete", target=policy.id, ip=ip, request_id=request_id,
                         detail={"node_id": node_id, "protocol": protocol, "revision": policy.revision})

    def explain_destination(self, node_id: str, protocol: str, host: str, port: int, lane: str = LANE_SERVICE) -> dict:
        """«Куда пойдёт этот домен»: the lane's rules walked for one destination, plus the
        exit's chain in the fleet's words (node names)."""
        with self.database.connect() as db:
            policy = self._policy(db, node_id, protocol, lane)
            names = {row["node_id"]: row["display_name"] for row in self.nodes.rows(db)}
        result = explain(policy, host, port)
        result["hop_names"] = [names.get("local" if guid == self.own_guid else guid, guid) for guid in result["hops"]]
        return result

    # -- preview and apply -------------------------------------------------------------

    @staticmethod
    def _unavailable(policy: RoutingPolicy, exc: AdapterError) -> Compiled:
        return Compiled(status="unsupported", backend=policy.backend,
                        reasons=[Reason(code=exc.code or "manager_unavailable", message=str(exc))])

    def _resolver(self, db, row: dict, *, issue: bool) -> ChainResolver | None:
        if self.relays is None:
            return None
        node_id = row["node_id"]
        source_guid = self.own_guid if node_id == "local" else node_id
        nodes_by_guid = {item["node_id"]: item for item in self.nodes.rows(db)}
        return ChainResolver(db, self.relays, source_guid=source_guid, nodes_by_guid=nodes_by_guid, own_guid=self.own_guid,
                             local_host=self.local_host, confirmed=self.confirmed, issue=issue, now=int(self.clock.time()))

    def _own_guids(self, row: dict) -> set[str]:
        return {row["node_id"], self.own_guid} if row["node_id"] == "local" else {row["node_id"]}

    def _compile(self, db, policy: RoutingPolicy, row: dict, target, egress_v1: bool, router, *, issue: bool) -> Compiled:
        """The policy with the service's other lanes folded in and the chains resolved."""
        others = [other for other in lane_policies(self.store, db, policy.node_id, policy.protocol) if other.id != policy.id]
        return compile_policy(policy, target, node_egress_v1=egress_v1, router=router, lanes=others,
                              chains=self._resolver(db, row, issue=issue), own_guids=self._own_guids(row))

    async def preview(self, node_id: str, protocol: str, draft: PolicyInput | None, lane: str = LANE_SERVICE) -> Compiled:
        self._protocol(protocol)
        lane = self._lane(lane)
        with self.database.connect() as db:
            row = self._node(db, node_id)
            stored = self.store.get(db, node_id, protocol, lane=lane)
        if draft is None:
            if stored is None:
                raise RoutingError(404, "policy_not_found", "no routing policy for this node, protocol and lane")
            policy = stored
        else:
            if draft.backend is not None and draft.backend not in backends_for(protocol):
                raise RoutingError(422, "backend_mismatch", f"{protocol} cannot run on {draft.backend}")
            backend = draft.backend or (stored.backend if stored else BACKEND_FOR[protocol])
            policy = RoutingPolicy(id=stored.id if stored else "draft", node_id=node_id, protocol=protocol, lane=lane,
                                   backend=backend, revision=stored.revision if stored else 1,
                                   **draft.model_dump(exclude={"backend"}))
        try:
            target, egress_v1 = await self._target(row, protocol)
        except AdapterError as exc:
            return self._unavailable(policy, exc)
        router = await self._router_target(row, protocol)
        with self.database.connect() as db:
            return self._compile(db, policy, row, target, egress_v1, router, issue=False)

    def _operation_id(self, policy: RoutingPolicy) -> str:
        return f"routing:{policy.id}:{policy.revision}"

    def _record(self, policy: RoutingPolicy, compiled: Compiled, *, outcome: str, applied: AppliedEgress | None,
                error: str | None, actor: dict, ip: str, request_id: str | None, action: str) -> RoutingPolicy:
        now = int(self.clock.time())
        with self.database.transaction() as db:
            if outcome == "applied":
                self.store.mark(db, policy.id, state="applied", applied_revision=policy.revision,
                                applied_digest=compiled.digest, now=now)
                if compiled.document is not None and compiled.document.get("schema") == 2:
                    # The router runs every lane of the service as one intent: they all stand applied now.
                    for other in lane_policies(self.store, db, policy.node_id, policy.protocol):
                        if other.id != policy.id:
                            self.store.mark(db, other.id, state="applied", applied_revision=other.revision,
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
                         detail={"node_id": policy.node_id, "protocol": policy.protocol, "lane": policy.lane,
                                 "revision": policy.revision, "outcome": outcome, "digest": compiled.digest, **detail})
            return self.store.get_by_id(db, policy.id)

    # -- attach / detach (v0.5): the service's whole traffic handed to the router, or back --

    async def _attachment_context(self, node_id: str, protocol: str) -> tuple[dict, RoutingPolicy | None, EgressTarget, RouterTarget]:
        self._protocol(protocol)
        with self.database.connect() as db:
            row = self._node(db, node_id)
            policy = self.store.get(db, node_id, protocol)
            master = self._master(db)
        if self._kind(row) == "local" and master is not None:
            raise RoutingError(409, "managed_by_central", "a central panel manages this node's egress")
        if self._kind(row) == "v1":
            raise RoutingError(409, "node_lacks_egress_v1", "the node must be updated to v0.4")
        try:
            target, egress_v1 = await self._target(row, protocol)
        except AdapterError as exc:
            raise RoutingError(ERROR_STATUS.get(exc.code, 409), exc.code or "manager_unavailable", str(exc)) from exc
        if not egress_v1:
            raise RoutingError(409, "node_lacks_egress_v1", "the node must be updated to v0.4")
        if target is None:
            raise RoutingError(422, "protocol_disabled_on_node", f"{protocol} reports no egress target")
        router = await self._router_target(row, protocol)
        if router is None or not router.available:
            code = "router_unavailable" if router is None or router.reason is None else router.reason
            raise RoutingError(ERROR_STATUS.get(code, 409), code, "the node has no Xray-router that answers")
        return row, policy, target, router

    def _stamp(self) -> str:
        return str(int(self.clock.time() * 1000))

    def _retarget(self, node_id: str, protocol: str, policy: RoutingPolicy | None, backend: str, *, action: str,
                  actor: dict, ip: str, request_id: str | None, detail: dict) -> None:
        with self.database.transaction() as db:
            now = int(self.clock.time())
            moved = policy is None or policy.backend != backend
            if policy is None:
                policy = self.store.upsert(db, node_id, protocol, PolicyInput(backend=backend), expected_revision=None, now=now)
            elif policy.backend != backend:
                policy = self.store.retarget(db, policy.id, backend, now=now)
            if moved:
                # The node now runs this backend's pass-through (the documents attach/detach
                # just applied), the rules wait as a draft: recorded here, as a linked node's
                # report would record it — so «delete» sees the reset it asks for.
                self.store.mark(db, policy.id, state="draft", applied_revision=None,
                                applied_digest=document_digest(direct_document(backend)), now=now)
                policy = self.store.get_by_id(db, policy.id)
            audit.record(db, actor=actor, action=action, target=policy.id, ip=ip, request_id=request_id,
                         detail={"node_id": node_id, "protocol": protocol, "backend": backend, "revision": policy.revision,
                                 **detail})

    async def attach(self, node_id: str, protocol: str, *, actor: dict, ip: str, request_id: str | None = None) -> dict:
        """Hand the service to the router: the router's section first (pass-through), then the
        native manager's document pointing at the router; the policy moves to `xray_router`."""
        row, policy, target, router = await self._attachment_context(node_id, protocol)
        provider = target.providers.get("router")
        if provider is None:
            raise RoutingError(409, "router_unavailable", f"the {protocol} manager knows no router ingress")
        if provider.get("reachable") is False:
            raise RoutingError(409, "router_unreachable", f"the router ingress does not answer the {protocol} manager")
        if (policy is not None and policy.backend != ROUTER_BACKEND and policy.applied_digest is not None
                and policy.applied_digest != document_digest(direct_document(policy.backend))):
            raise RoutingError(409, "policy_applied", "reset the native policy to direct and apply it before attaching")
        if self._kind(row) != "local":
            return await self._attach_remote(node_id, protocol, policy, actor=actor, ip=ip, request_id=request_id)
        stamp = self._stamp()
        try:
            if not target.router_attached:
                if router.applied is None or router.applied.get("document") != ROUTER_DIRECT_INTENT:
                    await self.router.apply(protocol, ROUTER_DIRECT_INTENT, expected_revision=router.revision,
                                            operation_id=f"routing:attach:{protocol}:{stamp}:router")
                await self.adapters[protocol].apply_egress(attach_document(protocol), expected_revision=target.revision,
                                                           operation_id=f"routing:attach:{protocol}:{stamp}:native")
        except AdapterError as exc:
            code = exc.code or "manager_unavailable"
            raise RoutingError(ERROR_STATUS.get(code, 409), code, str(exc)) from exc
        self._retarget(node_id, protocol, policy, ROUTER_BACKEND, action="routing.target.attach", actor=actor, ip=ip,
                       request_id=request_id, detail={"outcome": "attached"})
        return await self._target_item(node_id, protocol)

    async def detach(self, node_id: str, protocol: str, *, actor: dict, ip: str, request_id: str | None = None) -> dict:
        """Take the service back: the native manager to `direct` first, then the router's
        section to pass-through; the policy moves to the native backend."""
        row, policy, target, router = await self._attachment_context(node_id, protocol)
        native = BACKEND_FOR[protocol]
        if self._kind(row) != "local":
            return await self._detach_remote(node_id, protocol, policy, actor=actor, ip=ip, request_id=request_id)
        stamp = self._stamp()
        try:
            if target.router_attached:
                await self.adapters[protocol].apply_egress(direct_document(native), expected_revision=target.revision,
                                                           operation_id=f"routing:detach:{protocol}:{stamp}:native")
            if router.applied is None or router.applied.get("document") != ROUTER_DIRECT_INTENT:
                await self.router.apply(protocol, ROUTER_DIRECT_INTENT, expected_revision=router.revision,
                                        operation_id=f"routing:detach:{protocol}:{stamp}:router")
        except AdapterError as exc:
            code = exc.code or "manager_unavailable"
            raise RoutingError(ERROR_STATUS.get(code, 409), code, str(exc)) from exc
        self._retarget(node_id, protocol, policy, native, action="routing.target.detach", actor=actor, ip=ip,
                       request_id=request_id, detail={"outcome": "detached"})
        return await self._target_item(node_id, protocol)

    def _retargeted(self, node_id: str, protocol: str, policy: RoutingPolicy | None, backend: str) -> RoutingPolicy:
        with self.database.transaction() as db:
            now = int(self.clock.time())
            if policy is None:
                return self.store.upsert(db, node_id, protocol, PolicyInput(backend=backend), expected_revision=None, now=now)
            if policy.backend != backend:
                return self.store.retarget(db, policy.id, backend, now=now)
            return policy

    async def _attach_remote(self, node_id: str, protocol: str, policy, *, actor, ip, request_id) -> dict:
        """The linked node attaches through its next generation (spec §9.3): a router section
        that runs pass-through, with the native attach document as its companion."""
        policy = self._retargeted(node_id, protocol, policy, ROUTER_BACKEND)
        intent = json.loads(json.dumps(ROUTER_DIRECT_INTENT))
        desired = {"backend": ROUTER_BACKEND, "policy_id": policy.id, "policy_revision": policy.revision,
                   "document": intent, "digest": document_digest(intent), "companion": attach_document(protocol),
                   "passthrough": True}
        self._publish_desired(policy, desired, action="routing.target.attach",
                              detail={"backend": ROUTER_BACKEND, "outcome": "applying"}, actor=actor, ip=ip,
                              request_id=request_id)
        return await self._target_item(node_id, protocol)

    async def _detach_remote(self, node_id: str, protocol: str, policy, *, actor, ip, request_id) -> dict:
        """The linked node detaches through its next generation: the native document back to
        direct, the router's pass-through as its companion."""
        native = BACKEND_FOR[protocol]
        policy = self._retargeted(node_id, protocol, policy, native)
        document = direct_document(native)
        desired = {"backend": native, "policy_id": policy.id, "policy_revision": policy.revision,
                   "document": document, "digest": document_digest(document),
                   "companion": json.loads(json.dumps(ROUTER_DIRECT_INTENT)), "passthrough": True}
        self._publish_desired(policy, desired, action="routing.target.detach",
                              detail={"backend": native, "outcome": "applying"}, actor=actor, ip=ip, request_id=request_id)
        return await self._target_item(node_id, protocol)

    def _for_change(self, node_id: str, protocol: str, expected_revision: int, lane: str = LANE_SERVICE) -> tuple[RoutingPolicy, dict]:
        with self.database.connect() as db:
            policy = self._policy(db, node_id, protocol, lane)
            row = self._node(db, node_id)
            master = self._master(db)
        if expected_revision != policy.revision:
            raise RoutingError(409, "policy_conflict", f"policy revision is {policy.revision}")
        if self._kind(row) == "local" and master is not None:
            raise RoutingError(409, "managed_by_central", "a central panel manages this node's egress")
        return policy, row

    async def _deliver_relay_accounts(self, resolver: ChainResolver | None) -> None:
        """Accounts minted by an apply reach their nodes: the local router at once, a linked
        panel through its next generation (its report then confirms them)."""
        if resolver is None or not resolver.issued:
            return
        for node_id in sorted(resolver.issued):
            if node_id == "local":
                if self.router is not None:
                    with self.database.connect() as db:
                        accounts = self.relays.accounts(db, "local")
                    await self.router.relay_set_accounts(accounts)
            elif self.publisher is not None:
                with self.database.transaction() as db:
                    self.publisher(db, node_id)

    async def apply(self, node_id: str, protocol: str, *, expected_revision: int, actor: dict, ip: str,
                    request_id: str | None = None, lane: str = LANE_SERVICE) -> dict:
        """compile → plan → apply on the manager, then the outcome in one transaction."""
        policy, row = self._for_change(node_id, protocol, expected_revision, lane)
        try:
            target, egress_v1 = await self._target(row, protocol)
        except AdapterError as exc:
            raise RoutingError(ERROR_STATUS.get(exc.code, 409), exc.code or "manager_unavailable", str(exc)) from exc
        router = await self._router_target(row, protocol)
        if policy.node_exits() or any(other.node_exits() for other in self._other_lanes(policy)):
            # The chains' relay accounts are minted now and delivered; a linked hop that has not
            # confirmed them yet leaves the apply `relay_credential_pending` until its report.
            with self.database.transaction() as db:
                resolver = self._resolver(db, row, issue=True)
                if resolver is not None:
                    for value in {*policy.node_exits(), *(v for other in self._other_lanes(policy) for v in other.node_exits())}:
                        for guid in exit_hops(value)[0]:
                            resolver.resolve(guid)
            await self._deliver_relay_accounts(resolver)
        with self.database.connect() as db:
            compiled = self._compile(db, policy, row, target, egress_v1, router, issue=False)
        if compiled.status != "supported":
            if any(reason.code == "not_attached" for reason in compiled.reasons):
                raise RoutingError(409, "not_attached", f"{protocol} is not attached to the node's Xray-router",
                                   compiled=compiled)
            if (self._kind(row) == "remote" and router is None and policy.backend == ROUTER_BACKEND):
                raise RoutingError(422, "node_lacks_router", "the node must be updated to v0.5 and run an Xray-router",
                                   compiled=compiled)
            raise RoutingError(422, "unsupported", "the policy cannot be enforced on this node", compiled=compiled)
        if self._kind(row) != "local":
            if compiled.document.get("schema") == 2 and "egress.lanes.v1" not in self._capabilities(row):
                raise RoutingError(422, "node_lacks_lanes", "the node must be updated to v0.7 for lanes and chains",
                                   compiled=compiled)
            return await self._apply_remote(policy, compiled, actor=actor, ip=ip, request_id=request_id)
        try:
            if policy.backend == ROUTER_BACKEND:
                await self.router.plan(protocol, compiled.document, expected_revision=router.revision)
                applied = await self.router.apply(protocol, compiled.document, expected_revision=router.revision,
                                                  operation_id=self._operation_id(policy))
            else:
                adapter = self.adapters[protocol]
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
        next generation; the node's report (pusher) then moves the policy on. A lane's policy
        (v0.7) folds into the service's intent, so the section is held on the service's row
        while the lane's policy is the one `applying`."""
        if self.publisher is None:
            raise RoutingError(409, "node_not_local", "this panel applies routing locally only")
        now = int(self.clock.time())
        with self.database.transaction() as db:
            holder = policy.id
            if policy.lane != LANE_SERVICE:
                service = self.store.get(db, policy.node_id, policy.protocol)
                if service is None:
                    raise RoutingError(409, "lane_not_attached", "the service has no policy on this node")
                holder = service.id
            self.store.set_desired(db, holder, desired, now=now)
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
        if compiled.attach is not None:
            desired["companion"] = compiled.attach
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
        if policy.backend == ROUTER_BACKEND:
            desired["companion"] = attach_document(policy.protocol)
        updated = self._publish_desired(policy, desired, action="routing.policy.rollback",
                                        detail={"to_revision": previous["revision"], "digest": previous["digest"]},
                                        actor=actor, ip=ip, request_id=request_id)
        compiled = Compiled(status="supported", backend=policy.backend, digest=previous["digest"],
                            document=previous["document"])
        return {"policy": updated, "applied": None, "compiled": compiled}

    def _other_lanes(self, policy: RoutingPolicy) -> list[RoutingPolicy]:
        with self.database.connect() as db:
            return [other for other in lane_policies(self.store, db, policy.node_id, policy.protocol) if other.id != policy.id]

    # -- relay (v0.7): this node's relay inbound, and the accounts other nodes hold ----------

    async def relay_enable(self, node_id: str, *, actor: dict, ip: str, request_id: str | None = None,
                           port: int = DEFAULT_RELAY_PORT) -> dict:
        if self.relays is None:
            raise RoutingError(409, "relay_unavailable", "this panel keeps no relay registry")
        with self.database.connect() as db:
            row = self._node(db, node_id)
        if self._kind(row) == "v1":
            raise RoutingError(422, "node_lacks_relay", "a v1 node runs no relay")
        if self._kind(row) == "remote":
            return await self._relay_enable_remote(node_id, row, port, actor=actor, ip=ip, request_id=request_id)
        if self.router is None:
            raise RoutingError(409, "router_unavailable", "this node runs no Xray-router")
        try:
            view = await self.router.relay_enable(self.local_host, port)
        except AdapterError as exc:
            raise RoutingError(ERROR_STATUS.get(exc.code, 409), exc.code or "router_unavailable", str(exc)) from exc
        with self.database.transaction() as db:
            self.relays.record(db, "local", view, now=int(self.clock.time()))
            audit.record(db, actor=actor, action="routing.relay.enable", target=node_id, ip=ip, request_id=request_id,
                         detail={"port": view.get("port"), "server_name": view.get("server_name")})
        return {"node_id": node_id, "pending": False,
                **{key: view.get(key) for key in ("enabled", "port", "server_name", "public_key", "short_ids", "accounts")}}

    async def _relay_enable_remote(self, node_id: str, row: dict, port: int, *, actor, ip, request_id) -> dict:
        """A linked node's relay comes up through its next generation (spec §7): the section
        names the port and the node's own panel name as the cover; the node's report brings
        the public key, and `pending` says it has not yet."""
        if "relay.v1" not in self._capabilities(row):
            raise RoutingError(422, "node_lacks_relay", "the node must be updated to v0.7 and run an Xray-router")
        if self.publisher is None:
            raise RoutingError(409, "node_not_local", "this panel applies routing locally only")
        server_name = urlsplit((row.get("link") or {}).get("panel_url") or "").hostname
        if not server_name:
            raise RoutingError(409, "node_lacks_relay", "the node's panel address is unknown")
        now = int(self.clock.time())
        with self.database.transaction() as db:
            self.relays.desire(db, node_id, enabled=True, port=port, server_name=server_name, now=now)
            generation = self.publisher(db, node_id)
            relay = self.relays.relay(db, node_id)
            accounts = len(self.relays.peers(db, node_id))
            audit.record(db, actor=actor, action="routing.relay.enable", target=node_id, ip=ip, request_id=request_id,
                         detail={"port": port, "server_name": server_name, "generation": generation})
        return {"node_id": node_id, "enabled": True, "port": port, "server_name": server_name,
                "public_key": relay.get("public_key") or None, "short_ids": [relay["short_id"]] if relay.get("short_id") else [],
                "accounts": accounts, "pending": not relay.get("public_key")}

    async def relay_rotate(self, node_id: str, *, actor: dict, ip: str, request_id: str | None = None) -> dict:
        """New accounts for every source node that exits through this node; delivered the way
        the first ones were. The sources' policies then need a fresh apply (their chains
        carry the old credential until then)."""
        if self.relays is None:
            raise RoutingError(409, "relay_unavailable", "this panel keeps no relay registry")
        with self.database.transaction() as db:
            self._node(db, node_id)
            count = self.relays.rotate(db, node_id, now=int(self.clock.time()))
            accounts = self.relays.accounts(db, node_id) if node_id == "local" else None
            audit.record(db, actor=actor, action="routing.relay.rotate", target=node_id, ip=ip, request_id=request_id,
                         detail={"accounts": count})
        if node_id == "local" and self.router is not None:
            try:
                await self.router.relay_set_accounts(accounts)
            except AdapterError as exc:
                raise RoutingError(ERROR_STATUS.get(exc.code, 409), exc.code or "router_unavailable", str(exc)) from exc
        elif self.publisher is not None:
            with self.database.transaction() as db:
                self.publisher(db, node_id)
        return {"node_id": node_id, "rotated": count}

    async def rollback(self, node_id: str, protocol: str, *, expected_revision: int, actor: dict, ip: str,
                       request_id: str | None = None, lane: str = LANE_SERVICE) -> dict:
        policy, row = self._for_change(node_id, protocol, expected_revision, lane)
        if self._kind(row) != "local":
            return await self._rollback_remote(policy, actor=actor, ip=ip, request_id=request_id)
        try:
            target = await self._local_target(protocol)
            if target is None:
                raise RoutingError(422, "protocol_disabled_on_node", f"{protocol} reports no egress target")
            if policy.backend == ROUTER_BACKEND:
                router = await self._router_target(row, protocol)
                if router is None or not router.available:
                    code = "router_unavailable" if router is None or router.reason is None else router.reason
                    raise RoutingError(ERROR_STATUS.get(code, 409), code, "the node's Xray-router does not answer")
                applied = await self.router.rollback(protocol, expected_revision=router.revision)
                runtime_version, restart_required = router.xray_version, True
            else:
                applied = await self.adapters[protocol].rollback_egress(expected_revision=target.revision)
                runtime_version, restart_required = target.runtime_version, target.restart_required
        except AdapterError as exc:
            code = exc.code or "manager_unavailable"
            raise RoutingError(ERROR_STATUS.get(code, 409), code, str(exc)) from exc
        compiled = Compiled(status="supported", backend=policy.backend, digest=applied.digest,
                            runtime_version=runtime_version, restart_required=restart_required)
        updated = self._record(policy, compiled, outcome="rolled_back", applied=applied, error=None, actor=actor, ip=ip,
                               request_id=request_id, action="routing.policy.rollback")
        return {"policy": updated, "applied": applied, "compiled": compiled}
