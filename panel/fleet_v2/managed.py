"""The node's view of Fleet v2: generations it accepted and resources it owns for the
central panel. Every method runs inside the caller's transaction (spec §4, §5.3)."""
from __future__ import annotations

import json
import time

from .identity import MASTER_KEY, read_setting, write_setting
from .protocol import GenerationConflict, GenerationDocument, ObservedEgress, ObservedGeneration, ObservedResource


class ManagedStore:
    def __init__(self, database):
        self.database = database

    @staticmethod
    def master_guid(db) -> str | None:
        return read_setting(db, MASTER_KEY)

    def accept(self, db, document: GenerationDocument, digest: str, *, node_guid: str) -> None:
        if document.node_guid != node_guid:
            raise GenerationConflict("guid_mismatch")
        master = self.master_guid(db)
        if master and master != document.master_guid:
            raise GenerationConflict("foreign_master")
        latest = self.latest(db)
        if latest is not None:
            if document.generation < latest["generation"]:
                raise GenerationConflict("stale_generation")
            if document.generation == latest["generation"]:
                if latest["digest"] != digest:
                    raise GenerationConflict("digest_conflict")
                return
        if master is None:
            write_setting(db, MASTER_KEY, document.master_guid)
        db.execute(
            """INSERT INTO managed_generations(generation,digest,master_guid,document_json,received_at,state)
               VALUES(?,?,?,?,?,'received')""",
            (document.generation, digest, document.master_guid, document.model_dump_json(), int(time.time())),
        )

    @staticmethod
    def latest(db) -> dict | None:
        row = db.execute("SELECT * FROM managed_generations ORDER BY generation DESC LIMIT 1").fetchone()
        if row is None:
            return None
        return {"generation": row["generation"], "digest": row["digest"], "state": row["state"],
                "master_guid": row["master_guid"],
                "document": GenerationDocument.model_validate_json(row["document_json"])}

    @staticmethod
    def set_state(db, generation: int, state: str) -> None:
        applied = int(time.time()) if state == "converged" else None
        db.execute("UPDATE managed_generations SET state=?, applied_at=COALESCE(?, applied_at) WHERE generation=?",
                   (state, applied, generation))

    @staticmethod
    def resources(db) -> dict[tuple[str, str], dict]:
        return {(r["protocol"], r["runtime_username"]): dict(r) for r in db.execute("SELECT * FROM managed_resources")}

    @staticmethod
    def upsert_resource(db, *, protocol, username, ref, generation, state, error=None, revision=None,
                        credential_ref=None, learned=None) -> None:
        """`credential_ref` and `learned` are kept from the previous row when the caller
        passes None: a state change does not forget what create/rotate established."""
        db.execute(
            """INSERT INTO managed_resources(protocol,runtime_username,ref,credential_ref,generation,state,
               last_error,revision,updated_at,learned_json) VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(protocol,runtime_username) DO UPDATE SET
               ref=excluded.ref, credential_ref=COALESCE(excluded.credential_ref, managed_resources.credential_ref),
               generation=excluded.generation, state=excluded.state,
               last_error=excluded.last_error, revision=excluded.revision, updated_at=excluded.updated_at,
               learned_json=COALESCE(excluded.learned_json, managed_resources.learned_json)""",
            (protocol, username, ref, credential_ref, generation, state, error, revision, int(time.time()),
             None if learned is None else json.dumps(learned, sort_keys=True)),
        )

    @staticmethod
    def remove_resource(db, protocol: str, username: str) -> None:
        db.execute("DELETE FROM managed_resources WHERE protocol=? AND runtime_username=?", (protocol, username))

    @classmethod
    def owned(cls, db) -> dict[tuple[str, str], dict]:
        """Resources the central owns right now: `resources()` without the rows left
        `missing` — a confirmed deletion kept only so the report can be repeated."""
        return {key: row for key, row in cls.resources(db).items() if row["state"] != "missing"}

    @staticmethod
    def is_managed(db, protocol: str, username: str) -> bool:
        return db.execute("SELECT 1 FROM managed_resources WHERE protocol=? AND runtime_username=? AND state<>'missing'",
                          (protocol, username)).fetchone() is not None

    # -- egress (v0.4): what each protocol's egress section came to, per generation ------

    @staticmethod
    def egress_rows(db) -> dict[str, dict]:
        return {row["protocol"]: dict(row) for row in db.execute("SELECT * FROM managed_egress")}

    @staticmethod
    def upsert_egress(db, *, protocol: str, generation: int, state: str, revision: str | None = None,
                      digest: str | None = None, error: str | None = None, router_revision: str | None = None,
                      router_digest: str | None = None) -> None:
        db.execute(
            """INSERT INTO managed_egress(protocol,generation,revision,digest,state,last_error,updated_at,
               router_revision,router_digest)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(protocol) DO UPDATE SET generation=excluded.generation, revision=excluded.revision,
               digest=excluded.digest, state=excluded.state, last_error=excluded.last_error,
               updated_at=excluded.updated_at, router_revision=excluded.router_revision,
               router_digest=excluded.router_digest""",
            (protocol, generation, revision, digest, state, error, int(time.time()), router_revision, router_digest))

    def observed(self, db) -> ObservedGeneration | None:
        latest = self.latest(db)
        if latest is None:
            return None
        state = {"received": "applying", "applying": "applying", "converged": "converged", "failed": "failed"}[latest["state"]]
        return ObservedGeneration(
            applied_generation=latest["generation"], digest=latest["digest"], reconcile_state=state,
            resources=[ObservedResource(ref=r["ref"], protocol=r["protocol"], runtime_username=r["runtime_username"],
                                        state=r["state"], error=r["last_error"], revision=r["revision"],
                                        learned=json.loads(r.get("learned_json") or "{}"))
                       for r in self.resources(db).values()],
            egress={protocol: ObservedEgress(state=row["state"], revision=row["revision"], digest=row["digest"],
                                             error=row["last_error"],
                                             router=None if row.get("router_revision") is None else {
                                                 "revision": row["router_revision"], "digest": row.get("router_digest")})
                    for protocol, row in self.egress_rows(db).items()},
            reported_at=int(time.time()),
        )

    @staticmethod
    def unlink(db) -> int:
        """Forget the master; runtime users stay and become local (spec §5.2). The egress each
        service runs stays too (spec §8.3) — only the bookkeeping about generations goes."""
        released = db.execute("SELECT count(*) FROM managed_resources").fetchone()[0]
        db.execute("DELETE FROM managed_resources")
        db.execute("DELETE FROM managed_egress")
        db.execute("DELETE FROM managed_generations")
        write_setting(db, MASTER_KEY, None)
        return released
