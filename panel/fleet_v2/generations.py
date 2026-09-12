"""Desired generations on the central side (ADR 002): compiled from grants, never edited.

`digest` is what the node verifies (it covers the number and the timestamps);
`content_digest` is what `publish` compares — the same resources renumbered are
not a new generation. Both are stored.
"""
from __future__ import annotations

import json
import time

from .protocol import GenerationDocument, ObservedGeneration, Resource, canonical_digest


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
    def record_observed(db, node_id: str, observed: ObservedGeneration) -> None:
        db.execute("""INSERT INTO observed_generations(node_id,applied_generation,digest,reconcile_state,resources_json,
                      reported_at) VALUES(?,?,?,?,?,?)
                      ON CONFLICT(node_id) DO UPDATE SET applied_generation=excluded.applied_generation,
                      digest=excluded.digest, reconcile_state=excluded.reconcile_state,
                      resources_json=excluded.resources_json, reported_at=excluded.reported_at""",
                   (node_id, observed.applied_generation, observed.digest, observed.reconcile_state,
                    json.dumps([r.model_dump() for r in observed.resources]), observed.reported_at))
        if observed.reconcile_state == "converged":
            db.execute("""UPDATE desired_generations SET acknowledged_at=?
                          WHERE node_id=? AND generation=? AND acknowledged_at IS NULL""",
                       (int(time.time()), node_id, observed.applied_generation))
            # Only the generation the central currently wants clears the dirty flag: a
            # late acknowledgement of an older one leaves the newer one still to push.
            db.execute("""UPDATE node_links SET acknowledged_generation=?,
                          config_dirty=CASE WHEN desired_generation=? THEN 0 ELSE config_dirty END
                          WHERE node_id=?""", (observed.applied_generation, observed.applied_generation, node_id))

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


def compile(db, clients_store, *, node_id, node_guid, master_guid, previous, generation, now, created_by) -> GenerationDocument:
    """Pure: the node's grants as they are, with credentials by reference only."""
    resources = []
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
            options=options, valid_from=grant.valid_from, valid_until=grant.valid_until))
    resources.sort(key=lambda item: item.ref)
    return GenerationDocument(node_guid=node_guid, master_guid=master_guid, generation=generation,
                              previous_generation=previous, created_at=now, created_by=created_by, resources=resources)


def publish(db, clients_store, desired: DesiredStore, *, node_id, master_guid, created_by="system", now=None) -> int | None:
    """Inside the caller's transaction: a rolled-back grant change publishes nothing."""
    latest = desired.latest(db, node_id)
    previous = latest["generation"] if latest else 0
    document = compile(db, clients_store, node_id=node_id, node_guid=node_id, master_guid=master_guid, previous=previous,
                       generation=previous + 1, now=int(now if now is not None else time.time()), created_by=created_by)
    content = content_digest(document)
    if latest and latest["content_digest"] == content:
        return None
    desired.insert(db, node_id, document, canonical_digest(document), content)
    return document.generation
