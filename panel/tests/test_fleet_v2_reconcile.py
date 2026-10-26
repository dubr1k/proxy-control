import pytest

from panel.database import Database
from panel.fleet_v2.managed import ManagedStore
from panel.fleet_v2.protocol import GenerationDocument, PushRequest, Resource, canonical_digest
from panel.fleet_v2.reconcile import Reconciler
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from panel.secrets_store import SecretStore
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio

NODE, MASTER = "n" * 36, "m" * 36


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def world(tmp_path):
    database = Database(tmp_path / "p.sqlite3")
    apply_migrations(database)
    telemt, naive, mieru = MemoryTelemt(), MemoryNaive(), MemoryMieru()
    naive.seed("local-bob", "pw")  # a user the node owns itself
    adapters = {"mtproxy": TelemtAdapter(telemt), "naive": NaiveAdapter(naive, public_host="n.example"),
                "mieru": MieruAdapter(mieru)}
    managed = ManagedStore(database)
    reconciler = Reconciler(database, SecretStore(Keyring.generate()), adapters, managed, guid=NODE)
    return database, managed, reconciler, telemt, naive, mieru


def _resource(protocol, user, state="enabled", version=1, options=None, origin="caller"):
    return Resource(ref=f"grant:{user}", protocol=protocol, runtime_username=user, desired_state=state,
                    credential_ref=f"grant:{user}:{version}", credential_origin=origin,
                    options=options or ({"quotas": []} if protocol == "mieru" else {}))


def _push(generation, resources, secrets):
    doc = GenerationDocument(node_guid=NODE, master_guid=MASTER, generation=generation,
                             previous_generation=generation - 1, created_at=1, created_by="c", resources=resources)
    return PushRequest(expected_guid=NODE, generation=doc, secrets=secrets)


async def _accept(world, request):
    database, managed, reconciler, *_ = world
    with database.transaction() as db:
        managed.accept(db, request.generation, canonical_digest(request.generation), node_guid=NODE)
        await reconciler.store_secrets(db, request)




















# ---- fix round 1: findings I1-I4 ---------------------------------------------------





























# ---- Task 11: explicit adoption of imported resources (spec §6, ADR 003 `adopted`) ----


def _imported(protocol, user, state="enabled"):
    return Resource(**{**_resource(protocol, user, state).model_dump(), "origin": "imported"})








# ---- lab finding (Task 14): the central renders links from what the node learned -----












