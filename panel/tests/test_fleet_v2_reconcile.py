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


# ---- fix round 1: findings I1-I4 ---------------------------------------------------


async def test_present_but_unmanaged_runtime_user_is_never_adopted(world):
    """I1: a runtime user matching a pushed name but with no managed_resources row is a
    name collision (ADR 003), not an adoption target — it must be reported failed and
    left completely alone."""
    database, managed, reconciler, telemt, naive, mieru = world
    naive.seed("mallory", "local-pw")  # exists on the runtime, never pushed by the panel
    await _accept(world, _push(1, [_resource("naive", "mallory")], {"grant:mallory:1": "pw"}))
    observed, _ = await reconciler.apply(1)
    assert observed.resources[0].state == "failed"
    assert observed.resources[0].error == "runtime user exists and is not managed"
    assert observed.reconcile_state == "failed"
    assert naive.calls == []  # never touched
    assert "mallory" in [u["username"] for u in await naive.list_users()]
    with database.connect() as db:
        assert not managed.is_managed(db, "naive", "mallory")


async def test_deleted_naming_an_unmanaged_runtime_user_is_untouched(world):
    """I1: the same rule applies when the desired state is `deleted` — no adapter call,
    the runtime user survives, and the outcome is reported, not silently swallowed."""
    database, managed, reconciler, telemt, naive, mieru = world
    naive.seed("mallory", "local-pw")
    await _accept(world, _push(1, [_resource("naive", "mallory", "deleted")], {}))
    observed, _ = await reconciler.apply(1)
    assert observed.resources[0].state == "failed"
    assert observed.resources[0].error == "runtime user exists and is not managed"
    assert ("delete", "mallory") not in naive.calls
    assert "mallory" in [u["username"] for u in await naive.list_users()]


async def test_recovers_from_a_crash_between_create_and_record(world):
    """I1's exception: a create() the node itself started, interrupted before its final
    _record() call, always leaves a placeholder row behind — so on retry the resource is
    recognised as ours and recovered with an idempotent rotate, not treated as a collision."""
    database, managed, reconciler, telemt, naive, mieru = world
    await _accept(world, _push(1, [_resource("naive", "frank")], {"grant:frank:1": "pw-f"}))
    naive.seed("frank", "orphan-pw")  # adapter.create() had already mutated the runtime
    with database.transaction() as db:
        managed.upsert_resource(db, protocol="naive", username="frank", ref="grant:frank", generation=1,
                                 state="failed", credential_ref=None, error="create in flight")
    observed, _ = await reconciler.apply(1)
    assert observed.resources[0].state == "enabled"
    assert ("rotate", "frank") in naive.calls
    assert (await naive.reveal("frank"))["proxy_url"].count("pw-f") == 1


async def test_duplicate_resource_in_one_generation_is_marked_failed_defence_in_depth(world):
    """I2: GenerationDocument already rejects this on every read (`model_validate_json`
    re-runs the validator), so the only way this can reach `apply()` is a document a
    prior software version wrote before the validator existed — `ManagedStore.latest` is
    stubbed here to simulate exactly that stored-but-now-invalid row."""
    database, managed, reconciler, telemt, naive, mieru = world
    first = _resource("naive", "alice", version=1)
    second = Resource(ref="grant:alice-2", protocol="naive", runtime_username="alice", desired_state="enabled",
                      credential_ref="grant:alice:2", credential_origin="caller", options={})
    doc = GenerationDocument.model_construct(schema_version=1, node_guid=NODE, master_guid=MASTER, generation=1,
                                             previous_generation=0, created_at=1, created_by="c",
                                             resources=[first, second])
    digest = "deadbeef"
    with database.transaction() as db:
        db.execute(
            """INSERT INTO managed_generations(generation,digest,master_guid,document_json,received_at,state)
               VALUES(1,?,?,?,0,'received')""",
            (digest, MASTER, doc.model_dump_json()),
        )
    managed.latest = lambda db: {"generation": 1, "digest": digest, "state": "received",
                                 "master_guid": MASTER, "document": doc}
    observed, _ = await reconciler.apply(1)
    assert all(r.state == "failed" for r in observed.resources)
    assert "alice" not in [u["username"] for u in await naive.list_users()]


async def test_orphan_of_a_protocol_with_no_adapter_is_marked_failed_not_left_hanging(world):
    """I3: a store-only protocol (no adapter, or a broken discover()) must not hang
    forever silently — its known rows are reported failed with the reason."""
    database, managed, reconciler, telemt, naive, mieru = world
    await _accept(world, _push(1, [_resource("mieru", "carol")], {"grant:carol:1": "pw-c"}))
    await reconciler.apply(1)
    del reconciler.adapters["mieru"]
    await _accept(world, _push(2, [_resource("naive", "alice")], {"grant:alice:1": "pw-a"}))
    observed, _ = await reconciler.apply(2)
    states = {r.runtime_username: r.state for r in observed.resources}
    errors = {r.runtime_username: r.error for r in observed.resources}
    assert states == {"carol": "failed", "alice": "enabled"}
    assert "not enabled on this node" in errors["carol"]
    assert observed.reconcile_state == "failed"


async def test_options_drift_when_the_adapter_cannot_apply_a_pushed_option(world):
    """I4: an option the adapter accepts but cannot actually apply (mtproxy `expiration`,
    outside Telemt's UPDATABLE set) is reported `drifted`, not silently dropped."""
    database, managed, reconciler, telemt, naive, mieru = world
    await _accept(world, _push(1, [_resource("mtproxy", "dave")], {"grant:dave:1": "0" * 32}))
    await reconciler.apply(1)
    await _accept(world, _push(2, [_resource("mtproxy", "dave", options={"expiration": 999})], {}))
    observed, _ = await reconciler.apply(2)
    assert observed.resources[0].state == "drifted"
    assert observed.reconcile_state == "converged"  # drift is reported, not treated as a failure


async def test_run_pending_re_applies_a_generation_that_never_converged(world):
    database, managed, reconciler, telemt, naive, mieru = world
    await _accept(world, _push(1, [_resource("naive", "alice")], {"grant:alice:1": "pw"}))
    # apply() is never called — the generation stays "received".
    await reconciler.run_pending()
    with database.connect() as db:
        latest = managed.latest(db)
    assert latest["state"] == "converged"
    assert "alice" in [u["username"] for u in await naive.list_users()]


async def test_one_resource_create_failure_leaves_siblings_applied(world):
    """I4: per-resource isolation for a failure inside apply itself (not a discover()
    failure, already covered), so one bad create cannot block the rest of the protocol."""
    database, managed, reconciler, telemt, naive, mieru = world
    real = reconciler.adapters["naive"]

    class FlakyCreate:
        def __getattr__(self, name):
            return getattr(real, name)

        async def create(self, operation_id, intent, credential):
            if intent.runtime_username == "erin":
                raise RuntimeError("erin create boom")
            return await real.create(operation_id, intent, credential)

    reconciler.adapters["naive"] = FlakyCreate()
    await _accept(world, _push(1, [_resource("naive", "alice"), _resource("naive", "erin")],
                               {"grant:alice:1": "a", "grant:erin:1": "e"}))
    observed, _ = await reconciler.apply(1)
    states = {r.runtime_username: r.state for r in observed.resources}
    assert states["alice"] == "enabled" and states["erin"] == "failed"
    assert observed.reconcile_state == "failed"


async def test_store_secrets_is_idempotent_on_a_repeat_push(world):
    """I4: pushing the same generation (and secrets) twice must not duplicate secret
    rows or cause extra adapter calls beyond the single, correct apply."""
    database, managed, reconciler, telemt, naive, mieru = world
    request = _push(1, [_resource("naive", "alice")], {"grant:alice:1": "pw"})
    await _accept(world, request)
    await _accept(world, request)  # same generation and secrets pushed again
    with database.connect() as db:
        count = db.execute("SELECT count(*) FROM secret_versions WHERE secret_id=?", ("grant:alice",)).fetchone()[0]
    assert count == 1
    observed, _ = await reconciler.apply(1)
    assert observed.reconcile_state == "converged"
    again, _ = await reconciler.apply(1)
    assert again.model_copy(update={"reported_at": 0}) == observed.model_copy(update={"reported_at": 0})
    assert naive.calls.count(("create", "alice")) == 1
