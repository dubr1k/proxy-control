import pytest

from panel.database import Database
from panel.fleet_v2.managed import ManagedStore
from panel.fleet_v2.protocol import GenerationConflict, GenerationDocument, Resource, canonical_digest
from panel.migrations import apply_migrations

NODE, MASTER, OTHER = "n" * 36, "m" * 36, "o" * 36


def _doc(generation, master=MASTER, users=("alice",)):
    return GenerationDocument(node_guid=NODE, master_guid=master, generation=generation,
                              previous_generation=max(generation - 1, 0), created_at=1, created_by="x",
                              resources=[Resource(ref=f"grant:{u}", protocol="naive", runtime_username=u,
                                                  desired_state="enabled", credential_ref=f"grant:{u}:1",
                                                  credential_origin="caller") for u in users])


@pytest.fixture
def store(tmp_path):
    database = Database(tmp_path / "p.sqlite3")
    apply_migrations(database)
    return ManagedStore(database), database


def _accept(store, db, doc):
    store.accept(db, doc, canonical_digest(doc), node_guid=NODE)


def test_accept_records_master_and_rejects_lower_same_digest_and_foreign(store):
    managed, database = store
    with database.transaction() as db:
        _accept(managed, db, _doc(2))
        assert managed.master_guid(db) == MASTER
        _accept(managed, db, _doc(2))  # идемпотентный повтор
        with pytest.raises(GenerationConflict) as stale:
            _accept(managed, db, _doc(1))
        assert stale.value.code == "stale_generation"
        with pytest.raises(GenerationConflict) as conflict:
            managed.accept(db, _doc(2, users=("bob",)), canonical_digest(_doc(2, users=("bob",))), node_guid=NODE)
        assert conflict.value.code == "digest_conflict"
        with pytest.raises(GenerationConflict) as foreign:
            _accept(managed, db, _doc(3, master=OTHER))
        assert foreign.value.code == "foreign_master"
        with pytest.raises(GenerationConflict) as guid:
            managed.accept(db, _doc(3), canonical_digest(_doc(3)), node_guid=OTHER)
        assert guid.value.code == "guid_mismatch"


def test_resources_ownership_observed_and_unlink(store):
    managed, database = store
    with database.transaction() as db:
        _accept(managed, db, _doc(1))
        managed.upsert_resource(db, protocol="naive", username="alice", ref="grant:alice", generation=1, state="enabled")
        assert managed.is_managed(db, "naive", "alice") and not managed.is_managed(db, "naive", "bob")
        managed.set_state(db, 1, "converged")
        observed = managed.observed(db)
        assert observed.applied_generation == 1 and observed.reconcile_state == "converged"
        assert [r.runtime_username for r in observed.resources] == ["alice"]
        assert managed.unlink(db) == 1
        assert managed.master_guid(db) is None and not managed.is_managed(db, "naive", "alice")
        assert managed.latest(db) is None
