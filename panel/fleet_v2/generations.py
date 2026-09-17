"""Desired generations on the central side (ADR 002): compiled from grants, never edited.

`digest` is what the node verifies (it covers the number and the timestamps);
`content_digest` is what `publish` compares — the same resources renumbered are
not a new generation. Both are stored.
"""
from __future__ import annotations

import json
import time

from .protocol import (
    EgressDocument,
    GenerationDocument,
    ObservedGeneration,
    RelayAccount,
    RelaySection,
    Resource,
    canonical_digest,
)


class DesiredStore:
    def __init__(self, database):
        self.database = database

    @staticmethod
    def latest(db, node_id: str) -> dict | None:
        row = db.execute("SELECT * FROM desired_generations WHERE node_id=? ORDER BY generation DESC LIMIT 1",
                         (node_id,)).fetchone()
        return None if row is None else {"generation": row["generation"], "digest": row["digest"],
                                         "content_digest": row["content_digest"],
                                         "document": GenerationDocument.model_validate_json(row["document_json"]),
                                         "pushed_at": row["pushed_at"], "acknowledged_at": row["acknowledged_at"]}

    @staticmethod
    def insert(db, node_id: str, document: GenerationDocument, digest: str, content: str) -> None:
        db.execute("""INSERT INTO desired_generations(node_id,generation,digest,content_digest,document_json,
                      previous_generation,created_at,created_by) VALUES(?,?,?,?,?,?,?,?)""",
                   (node_id, document.generation, digest, content, document.model_dump_json(),
                    document.previous_generation, document.created_at, document.created_by))
        db.execute("UPDATE node_links SET config_dirty=1, desired_generation=?, updated_at=? WHERE node_id=?",
                   (document.generation, int(time.time()), node_id))

    @staticmethod
    def mark_pushed(db, node_id: str, generation: int) -> None:
        db.execute("UPDATE desired_generations SET pushed_at=? WHERE node_id=? AND generation=?",
                   (int(time.time()), node_id, generation))

    @staticmethod
    def record_observed(db, node_id: str, observed: ObservedGeneration, *, acknowledge: bool = True) -> None:
        """The node's report, as it is. A `converged` one also acknowledges the generation —
        unless the caller withholds that (`acknowledge=False`): the pusher does so while a
        credential the generation named is still to be captured, so the link stays
        `config_dirty` and the next tick delivers the same generation again."""
        db.execute("""INSERT INTO observed_generations(node_id,applied_generation,digest,reconcile_state,resources_json,
                      reported_at) VALUES(?,?,?,?,?,?)
                      ON CONFLICT(node_id) DO UPDATE SET applied_generation=excluded.applied_generation,
                      digest=excluded.digest, reconcile_state=excluded.reconcile_state,
                      resources_json=excluded.resources_json, reported_at=excluded.reported_at""",
                   (node_id, observed.applied_generation, observed.digest, observed.reconcile_state,
                    json.dumps([r.model_dump() for r in observed.resources]), observed.reported_at))
        if observed.reconcile_state == "converged" and acknowledge:
            db.execute("""UPDATE desired_generations SET acknowledged_at=?
                          WHERE node_id=? AND generation=? AND acknowledged_at IS NULL""",
                       (int(time.time()), node_id, observed.applied_generation))
            # Only the generation the central currently wants clears the dirty flag: a
            # late acknowledgement of an older one leaves the newer one still to push.
            db.execute("""UPDATE node_links SET acknowledged_generation=?,
                          config_dirty=CASE WHEN desired_generation=? THEN 0 ELSE config_dirty END
                          WHERE node_id=?""", (observed.applied_generation, observed.applied_generation, node_id))

    @staticmethod
    def record_relay(db, node_id: str, relay: dict | None) -> None:
        """What the node's report said about its relay (v0.7): the accounts it carries, its
        public part — beside the generation report."""
        db.execute("UPDATE observed_generations SET relay_json=? WHERE node_id=?",
                   (None if relay is None else json.dumps(relay, sort_keys=True), node_id))

    @staticmethod
    def observed_relay(db, node_id: str) -> dict | None:
        row = db.execute("SELECT relay_json FROM observed_generations WHERE node_id=?", (node_id,)).fetchone()
        if row is None or row["relay_json"] is None:
            return None
        return json.loads(row["relay_json"])

    def relay_confirmed(self, node_id: str, email: str) -> bool:
        """The node's relay carries this account, by its own last report."""
        with self.database.connect() as db:
            relay = self.observed_relay(db, node_id)
        return bool(relay) and email in (relay.get("accounts") or [])

    @staticmethod
    def observed(db, node_id: str) -> ObservedGeneration | None:
        row = db.execute("SELECT * FROM observed_generations WHERE node_id=?", (node_id,)).fetchone()
        return None if row is None else ObservedGeneration(
            applied_generation=row["applied_generation"], digest=row["digest"], reconcile_state=row["reconcile_state"],
            resources=json.loads(row["resources_json"]), reported_at=row["reported_at"])


def content_digest(document: GenerationDocument) -> str:
    """What the node would run, independent of numbering and timestamps."""
    return canonical_digest(document.model_copy(update={"generation": 1, "previous_generation": 0, "created_at": 0,
                                                        "created_by": ""}))


def node_capabilities(db, node_id: str) -> list[str]:
    row = db.execute("SELECT identity_json FROM node_links WHERE node_id=?", (node_id,)).fetchone()
    identity = json.loads(row["identity_json"]) if row is not None and row["identity_json"] else {}
    return list(identity.get("capabilities") or [])


def egress_section(db, routing, node_id: str) -> dict[str, EgressDocument] | None:
    """The egress the node's routing policies ask for (spec §8.3) — only for a node that
    declared `egress.v1`; a v0.3 node's strict model would refuse the whole generation."""
    if routing is None:
        return None
    capabilities = node_capabilities(db, node_id)
    if "egress.v1" not in capabilities:
        return None
    desired = {protocol: EgressDocument.model_validate(value)
               for protocol, value in routing.desired_for_node(db, node_id).items()}
    if "egress.router.v1" not in capabilities:
        # A v0.4 node: a router section or a companion would be refused by its strict model,
        # so such a policy stays out of the generation (its apply was refused earlier).
        desired = {protocol: entry for protocol, entry in desired.items()
                   if entry.backend != "xray_router" and entry.companion is None and not entry.passthrough}
    if "egress.lanes.v1" not in capabilities:
        # A v0.6 node: its router knows no lanes or chains (schema 2).
        desired = {protocol: entry for protocol, entry in desired.items() if entry.document.get("schema") != 2}
    return desired or None


def relay_section(db, node_id: str, capabilities: list[str]) -> RelaySection | None:
    """The node's relay as this panel wants it (spec §7): the row `relay_enable` wrote and
    the accounts issued to other nodes (`relay_peers`), for a node that declared `relay.v1`.
    The UUIDs travel in the push's secrets, by each account's ref."""
    if "relay.v1" not in capabilities:
        return None
    row = db.execute("SELECT * FROM router_relays WHERE node_id=?", (node_id,)).fetchone()
    if row is None or not row["port"] or not row["server_name"]:
        return None
    peers = db.execute("SELECT source_node_id, exit, secret_id FROM relay_peers WHERE node_id=? ORDER BY source_node_id, exit",
                       (node_id,)).fetchall()
    accounts = [RelayAccount(email=f"relay:{peer['source_node_id']}:{peer['exit']}", credential_ref=f"{peer['secret_id']}:1")
                for peer in peers] if row["enabled"] else []
    return RelaySection(enabled=bool(row["enabled"]), port=int(row["port"]), server_name=row["server_name"], accounts=accounts)


def compile(db, clients_store, *, node_id, node_guid, master_guid, previous, generation, now, created_by,
            routing=None) -> GenerationDocument:
    """Pure: the node's grants as they are, with credentials by reference only; the egress
    section from the routing store when one is given."""
    resources = []
    capabilities = node_capabilities(db, node_id)
    lanes = "egress.lanes.v1" in capabilities
    for grant in clients_store.grants(db, node_id=node_id, include_deleted=True):
        if grant.desired_state == "deleted" and grant.observed_state == "missing":
            continue  # the node already confirmed the deletion; the next generation omits it
        version = grant.secret_ref.version if grant.secret_ref else 1
        # MtproxyOptions.expiration is not an option any adapter applies, so it never
        # travels: a resource carrying it would sit `drifted` on the node forever.
        options = grant.options.model_dump(exclude_none=True, exclude={"expiration"})
        resources.append(Resource(
            ref=f"grant:{grant.id}", protocol=grant.protocol, runtime_username=grant.runtime_username,
            desired_state=grant.desired_state, credential_ref=f"grant:{grant.id}:{version}", credential_origin="caller",
            origin=grant.origin, options=options, valid_from=grant.valid_from, valid_until=grant.valid_until,
            lane=grant.routing_lane if lanes and grant.protocol in ("naive", "mieru") else None))
    resources.sort(key=lambda item: item.ref)
    return GenerationDocument(node_guid=node_guid, master_guid=master_guid, generation=generation,
                              previous_generation=previous, created_at=now, created_by=created_by, resources=resources,
                              egress=egress_section(db, routing, node_id), relay=relay_section(db, node_id, capabilities))


def publish(db, clients_store, desired: DesiredStore, *, node_id, master_guid, created_by="system", now=None,
            routing=None) -> int | None:
    """Inside the caller's transaction: a rolled-back grant change publishes nothing."""
    latest = desired.latest(db, node_id)
    previous = latest["generation"] if latest else 0
    document = compile(db, clients_store, node_id=node_id, node_guid=node_id, master_guid=master_guid, previous=previous,
                       generation=previous + 1, now=int(now if now is not None else time.time()), created_by=created_by,
                       routing=routing)
    content = content_digest(document)
    if latest and latest["content_digest"] == content:
        return None
    desired.insert(db, node_id, document, canonical_digest(document), content)
    return document.generation
