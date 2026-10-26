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






