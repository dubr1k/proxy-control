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


async def test_first_generation_creates_users_on_all_protocols_and_never_touches_local_ones(world):
    database, managed, reconciler, telemt, naive, mieru = world
    request = _push(1, [_resource("naive", "alice"), _resource("mieru", "carol"), _resource("mtproxy", "dave")],
                    {"grant:alice:1": "pw-a", "grant:carol:1": "pw-c", "grant:dave:1": "0" * 32})
    await _accept(world, request)
    observed, credentials = await reconciler.apply(1)
    assert observed.reconcile_state == "converged"
    assert {r.runtime_username: r.state for r in observed.resources} == {"alice": "enabled", "carol": "enabled", "dave": "enabled"}
    assert credentials == {}
    assert "local-bob" in [u["username"] for u in await naive.list_users()]
    with database.connect() as db:
        assert managed.is_managed(db, "naive", "alice") and not managed.is_managed(db, "naive", "local-bob")


async def test_second_generation_disables_rotates_deletes_and_removes_orphans(world):
    database, managed, reconciler, telemt, naive, mieru = world
    await _accept(world, _push(1, [_resource("naive", "alice"), _resource("naive", "erin")],
                               {"grant:alice:1": "pw-a", "grant:erin:1": "pw-e"}))
    await reconciler.apply(1)
    await _accept(world, _push(2, [_resource("naive", "alice", "disabled", version=2)], {"grant:alice:2": "pw-a2"}))
    observed, _ = await reconciler.apply(2)
    rows = {u["username"]: u for u in await naive.list_users()}
    assert rows["alice"]["enabled"] is False and "erin" not in rows  # orphan of gen 1 is gone
    assert (await naive.reveal("alice"))["proxy_url"].count("pw-a2") == 1
    assert {r.runtime_username: r.state for r in observed.resources} == {"alice": "disabled"}


async def test_explicit_deleted_state_removes_and_reports_missing(world):
    database, managed, reconciler, telemt, naive, mieru = world
    await _accept(world, _push(1, [_resource("naive", "alice")], {"grant:alice:1": "pw"}))
    await reconciler.apply(1)
    await _accept(world, _push(2, [_resource("naive", "alice", "deleted")], {}))
    observed, _ = await reconciler.apply(2)
    assert observed.resources[0].state == "missing"
    assert "alice" not in [u["username"] for u in await naive.list_users()]


async def test_apply_is_idempotent_and_survives_a_restart_mid_apply(world):
    database, managed, reconciler, telemt, naive, mieru = world
    await _accept(world, _push(1, [_resource("naive", "alice"), _resource("naive", "erin")],
                               {"grant:alice:1": "a", "grant:erin:1": "e"}))
    naive.lose_next = "create"  # MemoryNaive: first create's reply is lost
    observed, _ = await reconciler.apply(1)
    assert observed.reconcile_state == "converged"
    again, _ = await reconciler.apply(1)
    assert again.model_copy(update={"reported_at": 0}) == observed.model_copy(update={"reported_at": 0})
    assert len(await naive.list_users()) == 3  # alice, erin, local-bob — no duplicates


async def test_one_failing_resource_marks_failed_but_applies_the_rest(world):
    database, managed, reconciler, telemt, naive, mieru = world

    class Broken:
        protocol, credential_origin, accepts_caller_credential = "mieru", "caller", True

        async def discover(self):
            raise RuntimeError("mita down")

    reconciler.adapters["mieru"] = Broken()
    await _accept(world, _push(1, [_resource("naive", "alice"), _resource("mieru", "carol")],
                               {"grant:alice:1": "a", "grant:carol:1": "c"}))
    observed, _ = await reconciler.apply(1)
    states = {r.runtime_username: r.state for r in observed.resources}
    assert states["alice"] == "enabled" and states["carol"] == "failed" and observed.reconcile_state == "failed"


async def test_manager_generated_credentials_come_back_in_the_result(world):
    database, managed, reconciler, telemt, naive, mieru = world
    await _accept(world, _push(1, [_resource("mtproxy", "dave", origin="manager")], {}))
    observed, credentials = await reconciler.apply(1)
    assert observed.resources[0].state == "enabled" and credentials["grant:dave:1"].startswith("ee")
    _, again = await reconciler.apply(1)
    assert again == credentials  # re-captured from the runtime, not regenerated
