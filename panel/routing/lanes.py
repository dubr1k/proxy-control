"""Lanes, relays and chains on the panel side (v0.7, spec §6.2).

Three things live here, all keyed by the routing store's tables of migration 16:

- `RelayRegistry` — what each node's router reports about its relay inbound
  (`router_relays`: port, Reality public key, short id, server name) and the relay
  accounts this panel issued to a node for a *source* node (`relay_peers`, the UUIDs in the
  secret store under `relay-account`). A pair (node, source, exit) has one account.
- `ChainResolver` — turns a node exit's guid into the `ChainHop` the compiler renders, or
  the `Reason` it cannot: no such node, no relay, relay off, the account not yet confirmed
  by the node (`relay_credential_pending`), no account for its warp.
- `LaneService` — gives a grant its own lane on this node's router (an account minted by
  the router, handed to the service's manager as the lane's upstream, a draft policy
  copied from the service's) and takes it away again.

Nothing here prints a UUID or a lane key: they travel router → manager → generation and
appear in no view, audit row or report.
"""
from __future__ import annotations

import json
import time
import uuid as uuid_module
from urllib.parse import urlsplit

from pydantic import ValidationError

from .. import audit
from ..clients.models import PROTOCOL_OPTIONS
from ..database import Database
from ..protocols.base import AdapterError
from ..secrets_store import SecretError, SecretRef, SecretStore
from .adapters.xray_router import ChainHop
from .document import document_digest, without_lane
from .models import LANE_SERVICE, PolicyInput, Reason, RoutingPolicy
from .store import RoutingStore

RELAY_PURPOSE = "relay-account"
DEFAULT_RELAY_PORT = 45443
EXITS = ("direct", "warp")


def relay_email(source_guid: str, exit_kind: str) -> str:
    return f"relay:{source_guid}:{exit_kind}"


class RelayRegistry:
    """The two relay tables; secrets through the panel's store."""

    def __init__(self, database: Database, secrets: SecretStore):
        self.database = database
        self.secrets = secrets

    # -- what a node's router reports ----------------------------------------------------

    @staticmethod
    def record(db, node_id: str, view: dict | None, *, now: int | None = None) -> None:
        """`view` is the router's relay view (`{enabled, port, server_name, public_key,
        short_ids}`), from the local router or a linked panel's identity; None forgets it."""
        now = int(time.time()) if now is None else now
        if not isinstance(view, dict):
            db.execute("DELETE FROM router_relays WHERE node_id=?", (node_id,))
            return
        short_ids = view.get("short_ids") or []
        db.execute(
            "INSERT INTO router_relays(node_id,port,public_key,short_id,server_name,enabled,updated_at) VALUES(?,?,?,?,?,?,?)"
            " ON CONFLICT(node_id) DO UPDATE SET port=excluded.port, public_key=excluded.public_key, short_id=excluded.short_id,"
            " server_name=excluded.server_name, enabled=excluded.enabled, updated_at=excluded.updated_at",
            (node_id, view.get("port"), view.get("public_key"), short_ids[0] if short_ids else None,
             view.get("server_name"), int(bool(view.get("enabled"))), now))

    @staticmethod
    def observe(db, node_id: str, report: dict, *, now: int | None = None) -> None:
        """A linked node's word on its relay (its report or identity): the public part joins
        the row, `enabled` stays what this panel asked for — the node converges to it."""
        now = int(time.time()) if now is None else now
        if report.get("state") not in (None, "converged"):
            return
        short_ids = report.get("short_ids")
        short_id = report.get("short_id") if short_ids is None else (short_ids[0] if short_ids else None)
        row = db.execute("SELECT enabled FROM router_relays WHERE node_id=?", (node_id,)).fetchone()
        enabled = int(bool(report.get("enabled"))) if row is None else row["enabled"]
        db.execute(
            "INSERT INTO router_relays(node_id,port,public_key,short_id,server_name,enabled,updated_at) VALUES(?,?,?,?,?,?,?)"
            " ON CONFLICT(node_id) DO UPDATE SET port=excluded.port, public_key=excluded.public_key, short_id=excluded.short_id,"
            " server_name=excluded.server_name, updated_at=excluded.updated_at",
            (node_id, report.get("port"), report.get("public_key"), short_id, report.get("server_name"), enabled, now))

    @staticmethod
    def desire(db, node_id: str, *, enabled: bool, port: int, server_name: str, now: int | None = None) -> None:
        """What this panel asks of a linked node's relay; the public part comes with its report."""
        now = int(time.time()) if now is None else now
        db.execute(
            "INSERT INTO router_relays(node_id,port,public_key,short_id,server_name,enabled,updated_at) VALUES(?,?,NULL,NULL,?,?,?)"
            " ON CONFLICT(node_id) DO UPDATE SET port=excluded.port, server_name=excluded.server_name, enabled=excluded.enabled,"
            " updated_at=excluded.updated_at",
            (node_id, port, server_name, int(enabled), now))

    @staticmethod
    def relay(db, node_id: str) -> dict | None:
        row = db.execute("SELECT * FROM router_relays WHERE node_id=?", (node_id,)).fetchone()
        return None if row is None else dict(row)

    # -- the accounts this panel issued --------------------------------------------------

    @staticmethod
    def peers(db, node_id: str) -> list[dict]:
        rows = db.execute("SELECT * FROM relay_peers WHERE node_id=? ORDER BY source_node_id, exit", (node_id,)).fetchall()
        return [dict(row) for row in rows]

    def issue(self, db, node_id: str, source_guid: str, exit_kind: str, *, now: int | None = None) -> str:
        """The UUID of the account (node, source, exit), minted and escrowed if missing."""
        if exit_kind not in EXITS:
            raise ValueError("a relay account exits direct or warp")
        now = int(time.time()) if now is None else now
        row = db.execute("SELECT secret_id FROM relay_peers WHERE node_id=? AND source_node_id=? AND exit=?",
                         (node_id, source_guid, exit_kind)).fetchone()
        if row is not None:
            return self.reveal(db, row["secret_id"], node_id)
        secret_id = str(uuid_module.uuid4())
        account = str(uuid_module.uuid4())
        self.secrets.store(db, secret_id=secret_id, version=1, purpose=RELAY_PURPOSE, grant_id=None,
                           permitted_node_id=node_id, plaintext=account.encode(), state="active")
        db.execute("INSERT INTO relay_peers(node_id,source_node_id,exit,secret_id,created_at) VALUES(?,?,?,?,?)",
                   (node_id, source_guid, exit_kind, secret_id, now))
        return account

    def reveal(self, db, secret_id: str, node_id: str) -> str:
        return self.secrets.reveal(db, SecretRef(secret_id, 1), purpose=RELAY_PURPOSE, grant_id=None,
                                   permitted_node_id=node_id).decode()

    def accounts(self, db, node_id: str) -> list[dict]:
        """Every account the node's relay must know: `[{email, uuid}]` — for the router."""
        return [{"email": relay_email(row["source_node_id"], row["exit"]), "uuid": self.reveal(db, row["secret_id"], node_id)}
                for row in self.peers(db, node_id)]

    @staticmethod
    def account_row(db, node_id: str, source_guid: str, exit_kind: str) -> dict | None:
        row = db.execute("SELECT * FROM relay_peers WHERE node_id=? AND source_node_id=? AND exit=?",
                         (node_id, source_guid, exit_kind)).fetchone()
        return None if row is None else dict(row)

    def rotate(self, db, node_id: str, *, now: int | None = None) -> int:
        """New UUIDs for every account of the node; the old secrets are revoked. Returns the count."""
        now = int(time.time()) if now is None else now
        count = 0
        for row in self.peers(db, node_id):
            try:
                self.secrets.transition(db, SecretRef(row["secret_id"], 1), "revoked")
            except SecretError:
                pass
            db.execute("DELETE FROM relay_peers WHERE node_id=? AND source_node_id=? AND exit=?",
                       (node_id, row["source_node_id"], row["exit"]))
            self.issue(db, node_id, row["source_node_id"], row["exit"], now=now)
            count += 1
        return count


class ChainResolver:
    """One preview or apply: hops for a source node, against what the panel knows now.

    `confirmed(node_id, email)` says whether the node's relay already carries the account
    (a linked panel confirms through its report; the local router the moment it is set);
    `issue` is True on apply — a missing account is minted then — and False on preview,
    where a missing account is simply «pending»."""

    def __init__(self, db, registry: RelayRegistry, *, source_guid: str, nodes_by_guid: dict[str, dict],
                 own_guid: str, local_host: str, confirmed, issue: bool = False, now: int | None = None):
        self.db = db
        self.registry = registry
        self.source_guid = source_guid
        self.nodes_by_guid = nodes_by_guid
        self.own_guid = own_guid
        self.local_host = local_host
        self.confirmed = confirmed
        self.issue = issue
        self.now = now
        self.issued: set[str] = set()

    def _address(self, node_id: str, row: dict) -> str | None:
        if node_id == "local":
            return self.local_host or None
        link = row.get("link") or {}
        url = link.get("panel_url")
        return urlsplit(url).hostname if isinstance(url, str) else None

    def resolve(self, guid: str) -> ChainHop | Reason:
        node_id = "local" if guid == self.own_guid else guid
        row = self.nodes_by_guid.get(node_id)
        if row is None:
            return Reason(code="node_unknown", message=f"no node {guid} on this panel")
        relay = self.registry.relay(self.db, node_id)
        if relay is None or not relay.get("public_key"):
            return Reason(code="node_lacks_relay", message=f"node {guid} has no relay (update it to v0.7 and enable the relay)")
        if not relay.get("enabled"):
            return Reason(code="relay_disabled", message=f"the relay of node {guid} is disabled")
        address = self._address(node_id, row)
        if not address or not relay.get("server_name") or not relay.get("port"):
            return Reason(code="node_lacks_relay", message=f"node {guid} has no relay address")
        uuids: dict[str, str | None] = {}
        for exit_kind in EXITS:
            account = self.registry.account_row(self.db, node_id, self.source_guid, exit_kind)
            if account is None:
                if not self.issue:
                    uuids[exit_kind] = None
                    continue
                self.registry.issue(self.db, node_id, self.source_guid, exit_kind, now=self.now)
                self.issued.add(node_id)
                account = self.registry.account_row(self.db, node_id, self.source_guid, exit_kind)
            email = relay_email(self.source_guid, exit_kind)
            if not self.confirmed(node_id, email):
                uuids[exit_kind] = None if exit_kind == "warp" else "pending"
                continue
            uuids[exit_kind] = self.registry.reveal(self.db, account["secret_id"], node_id)
        if uuids["direct"] in (None, "pending"):
            return Reason(code="relay_credential_pending",
                          message=f"node {guid} has not confirmed this node's relay account yet")
        return ChainHop(guid=guid, address=address, port=int(relay["port"]), server_name=relay["server_name"],
                        public_key=relay["public_key"], short_id=relay.get("short_id") or "",
                        uuid_direct=uuids["direct"], uuid_warp=uuids["warp"])


class LaneService:
    """A grant's own lane on this node (spec §6.2): the router's account, the manager's
    handler or slot, a draft policy — and the way back."""

    def __init__(self, database: Database, store: RoutingStore, clients, adapters: dict, router, *, clock=time,
                 publisher=None):
        self.database = database
        self.store = store
        self.clients = clients
        self.adapters = adapters
        self.router = router
        self.clock = clock
        # A linked node's lane travels in its generation (spec §7): `publisher(db, node_id)`.
        self.publisher = publisher

    @staticmethod
    def lane_of(grant_id: str) -> str:
        return f"grant:{grant_id}"

    def _grant(self, db, grant_id: str):
        try:
            return self.clients.store.grant(db, grant_id)
        except KeyError as exc:
            raise LaneError(404, "grant_not_found", "grant not found") from exc

    @staticmethod
    def _routing_lane(db, grant_id: str) -> str | None:
        row = db.execute("SELECT routing_lane FROM access_grants WHERE id=?", (grant_id,)).fetchone()
        return None if row is None else row["routing_lane"]

    def _lane_grants(self, db, node_id: str, protocol: str) -> list:
        rows = db.execute("SELECT id, runtime_username FROM access_grants WHERE node_id=? AND protocol=? AND routing_lane='own'"
                          " AND desired_state<>'deleted' ORDER BY created_at, id", (node_id, protocol)).fetchall()
        return [dict(row) for row in rows]

    async def _push_lanes(self, db, node_id: str, protocol: str, accounts: dict[str, dict]) -> dict:
        """`PUT /v1/lanes` to the service's manager with every lane of the service; the
        router accounts (`{lane: {user, password}}`) come from `issue` — never stored here."""
        lanes = []
        for row in self._lane_grants(db, node_id, protocol):
            lane = self.lane_of(row["id"])
            if lane in accounts:
                lanes.append({"lane": lane, "users": [row["runtime_username"]], "upstream": accounts[lane]})
        return await self.adapters[protocol].set_lanes(lanes)

    async def enable(self, grant_id: str, *, actor: dict, ip: str, request_id: str | None = None) -> dict:
        with self.database.connect() as db:
            grant = self._grant(db, grant_id)
            current = self._routing_lane(db, grant_id)
        if grant.protocol not in ("naive", "mieru"):
            raise LaneError(422, "protocol_out_of_scope", f"{grant.protocol} is outside routing")
        lane = self.lane_of(grant_id)
        if current == "own":
            return await self.view(grant_id)
        if grant.node_id != "local":
            return self._set_remote(grant, "own", actor=actor, ip=ip, request_id=request_id)
        if self.router is None:
            raise LaneError(409, "lane_requires_router", "a client lane runs only on the node's Xray-router")
        # 1. the router mints the lane's account (shown once, handed straight to the manager)
        try:
            issued = await self.router.lane_issue(grant.protocol, lane)
        except AdapterError as exc:
            raise LaneError(409 if exc.code else 502, exc.code or "router_unavailable", str(exc)) from exc
        # 2. the manager moves the user into the lane's handler / slot
        with self.database.transaction() as db:
            db.execute("UPDATE access_grants SET routing_lane='own', updated_at=? WHERE id=?", (int(self.clock.time()), grant_id))
        try:
            view = await self._push_existing(grant.node_id, grant.protocol, lane,
                                             {"user": issued["user"], "password": issued["password"]})
        except AdapterError as exc:
            with self.database.transaction() as db:
                db.execute("UPDATE access_grants SET routing_lane=NULL WHERE id=?", (grant_id,))
            try:
                await self.router.lane_forget(grant.protocol, lane)
            except AdapterError:
                pass
            raise LaneError(409 if exc.code else 502, exc.code or "manager_unavailable", str(exc)) from exc
        # 3. a draft policy for the lane, copied from the service's
        with self.database.transaction() as db:
            self._learn_share(db, grant, view, lane)
            service_policy = self.store.get(db, grant.node_id, grant.protocol)
            draft = PolicyInput.from_policy(service_policy) if service_policy else PolicyInput()
            draft = draft.model_copy(update={"backend": "xray_router",
                                             "rules": [rule.model_copy(update={"id": None}) for rule in draft.rules]})
            if self.store.get(db, grant.node_id, grant.protocol, lane=lane) is None:
                self.store.upsert(db, grant.node_id, grant.protocol, draft, expected_revision=None, lane=lane,
                                  now=int(self.clock.time()))
            audit.record(db, actor=actor, action="grant.lane.enable", target=grant_id, ip=ip, request_id=request_id,
                         detail={"node_id": grant.node_id, "protocol": grant.protocol, "lane": lane})
        return {**view, "grant_id": grant_id, "lane": lane, "mode": "own"}

    async def _push_existing(self, node_id: str, protocol: str, lane: str, account: dict | None) -> dict:
        """The manager's lanes: this lane with its fresh account (None when it is leaving),
        every other lane of the service re-issued by the router — the manager needs every
        upstream on every PUT, and the panel keeps no key."""
        with self.database.connect() as db:
            rows = self._lane_grants(db, node_id, protocol)
        accounts = {} if account is None else {lane: account}
        for row in rows:
            other = self.lane_of(row["id"])
            if other not in accounts:
                accounts[other] = await self.router.lane_issue(protocol, other)
                accounts[other] = {"user": accounts[other]["user"], "password": accounts[other]["password"]}
        with self.database.connect() as db:
            return await self._push_lanes(db, node_id, protocol, accounts)

    async def disable(self, grant_id: str, *, actor: dict, ip: str, request_id: str | None = None) -> dict:
        with self.database.connect() as db:
            grant = self._grant(db, grant_id)
            current = self._routing_lane(db, grant_id)
        lane = self.lane_of(grant_id)
        if current != "own":
            return await self.view(grant_id)
        if grant.node_id != "local":
            return self._set_remote(grant, "service", actor=actor, ip=ip, request_id=request_id)
        with self.database.transaction() as db:
            db.execute("UPDATE access_grants SET routing_lane=NULL, updated_at=? WHERE id=?", (int(self.clock.time()), grant_id))
        view: dict = {}
        try:
            if self.router is not None:
                view = await self._push_existing(grant.node_id, grant.protocol, lane, None)
        except AdapterError as exc:
            with self.database.transaction() as db:
                db.execute("UPDATE access_grants SET routing_lane='own' WHERE id=?", (grant_id,))
            raise LaneError(409 if exc.code else 502, exc.code or "manager_unavailable", str(exc)) from exc
        with self.database.transaction() as db:
            self._learn_share(db, grant, view, None)
            policy = self.store.get(db, grant.node_id, grant.protocol, lane=lane)
            if policy is not None:
                self.store.delete(db, policy.id)
            audit.record(db, actor=actor, action="grant.lane.disable", target=grant_id, ip=ip, request_id=request_id,
                         detail={"node_id": grant.node_id, "protocol": grant.protocol, "lane": lane})
        if self.router is not None:
            try:
                await self.router.lane_forget(grant.protocol, lane)
            except AdapterError:
                pass
        return await self.view(grant_id)

    def _set_remote(self, grant, mode: str, *, actor: dict, ip: str, request_id: str | None) -> dict:
        """A lane on a linked node (spec §7): the grant's resource carries `lane: own` in the
        node's next generation and the node builds the lane itself — the key never leaves it;
        the draft policy waits here. `service` withdraws it the same way. The node's report
        brings a Mieru lane's slot port back as the grant's `learned` template."""
        lane = self.lane_of(grant.id)
        if self.publisher is None:
            raise LaneError(409, "node_not_local", "this panel sets lanes locally only")
        with self.database.connect() as db:
            row = db.execute("SELECT identity_json FROM node_links WHERE node_id=?", (grant.node_id,)).fetchone()
        identity = json.loads(row["identity_json"]) if row is not None and row["identity_json"] else {}
        if "egress.lanes.v1" not in (identity.get("capabilities") or []):
            raise LaneError(422, "node_lacks_lanes", "the node must be updated to v0.7 and run an Xray-router")
        now = int(self.clock.time())
        with self.database.transaction() as db:
            if mode == "own":
                db.execute("UPDATE access_grants SET routing_lane='own', updated_at=? WHERE id=?", (now, grant.id))
                service_policy = self.store.get(db, grant.node_id, grant.protocol)
                draft = PolicyInput.from_policy(service_policy) if service_policy else PolicyInput()
                draft = draft.model_copy(update={"backend": "xray_router",
                                                 "rules": [rule.model_copy(update={"id": None}) for rule in draft.rules]})
                if self.store.get(db, grant.node_id, grant.protocol, lane=lane) is None:
                    self.store.upsert(db, grant.node_id, grant.protocol, draft, expected_revision=None, lane=lane, now=now)
            else:
                db.execute("UPDATE access_grants SET routing_lane=NULL, updated_at=? WHERE id=?", (now, grant.id))
                policy = self.store.get(db, grant.node_id, grant.protocol, lane=lane)
                if policy is not None:
                    self.store.delete(db, policy.id)
                # The service's section the node runs still names the lane (and its chains):
                # the next generation carries it without them, or the node's router would keep
                # checking a chain nobody uses — and refuse every generation if a hop went away.
                service = self.store.get(db, grant.node_id, grant.protocol)
                desired = self.store.desired_for_node(db, grant.node_id).get(grant.protocol) if service else None
                if desired and isinstance(desired.get("document"), dict) and lane in desired["document"].get("lanes", {}):
                    document = without_lane(desired["document"], lane)
                    self.store.set_desired(db, service.id, {**desired, "document": document, "digest": document_digest(document)},
                                           now=now)
            generation = self.publisher(db, grant.node_id)
            audit.record(db, actor=actor, action="grant.lane.enable" if mode == "own" else "grant.lane.disable",
                         target=grant.id, ip=ip, request_id=request_id,
                         detail={"node_id": grant.node_id, "protocol": grant.protocol, "lane": lane, "generation": generation})
            policy = self.store.get(db, grant.node_id, grant.protocol, lane=lane)
        return {"grant_id": grant.id, "lane": lane if mode == "own" else LANE_SERVICE, "mode": mode, "pending": True,
                "policy": None if policy is None else {"id": policy.id, "revision": policy.revision, "state": policy.state}}

    def _learn_share(self, db, grant, view: dict, lane: str | None) -> None:
        """Mieru: a lane user connects to the slot's port, so the manager's link template for
        the user becomes the grant's `share_template` — the client's link and every
        subscription follow. Leaving the lane returns the default template (the main port)."""
        if grant.protocol != "mieru":
            return
        template = view.get("service_share_template") if isinstance(view, dict) else None
        for entry in view.get("lanes", []) if lane is not None else []:
            if entry.get("lane") == lane:
                template = (entry.get("share_templates") or {}).get(grant.runtime_username)
        options = grant.options.model_dump()
        options["share_template"] = template
        try:
            typed = PROTOCOL_OPTIONS["mieru"].model_validate(options)
        except ValidationError:
            typed = PROTOCOL_OPTIONS["mieru"].model_validate({**options, "share_template": None})
        self.clients.store.update_grant(db, grant.id, protocol_options_json=typed.model_dump_json(),
                                        updated_at=int(self.clock.time()))

    async def view(self, grant_id: str) -> dict:
        with self.database.connect() as db:
            grant = self._grant(db, grant_id)
            current = self._routing_lane(db, grant_id)
            lane = self.lane_of(grant_id)
            policy = self.store.get(db, grant.node_id, grant.protocol, lane=lane) if current == "own" else None
        return {"grant_id": grant_id, "lane": lane if current == "own" else LANE_SERVICE, "mode": current or "service",
                "policy": None if policy is None else {"id": policy.id, "revision": policy.revision, "state": policy.state}}


class LaneError(Exception):
    def __init__(self, status: int, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.status = status
        self.code = code


def lane_policies(store: RoutingStore, db, node_id: str, protocol: str) -> list[RoutingPolicy]:
    """Every policy the router runs for the service: its own and the lanes of grants that
    still have one (a lane whose grant lost its lane is not rendered)."""
    active = {f"grant:{row['id']}" for row in db.execute(
        "SELECT id FROM access_grants WHERE node_id=? AND protocol=? AND routing_lane='own' AND desired_state<>'deleted'",
        (node_id, protocol)).fetchall()}
    return [policy for policy in store.lanes_of(db, node_id, protocol) if policy.lane == LANE_SERVICE or policy.lane in active]
