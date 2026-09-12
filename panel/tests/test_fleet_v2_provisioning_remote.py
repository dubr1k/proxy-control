"""Provisioning a grant on a linked panel: no manager is called from the central.

The grant, its pending credential and the generation that carries it are one
transaction; the pusher finishes the operation when the node reports the grant
applied. Local grants keep the saga exactly as it was.
"""
import pytest

from panel.clients.models import GrantIntent, MtproxyOptions, NaiveOptions

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}  # фикстура `pair` приходит из panel/tests/conftest.py


async def test_start_writes_grant_secret_and_generation_atomically(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    central.state.provisioning.faults["before_remote_commit"] = True
    with pytest.raises(RuntimeError):
        await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        assert db.execute("SELECT count(*) FROM access_grants").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM secret_versions WHERE purpose='grant.credential'").fetchone()[0] == 0
        assert central.state.desired.latest(db, node_id) is None
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        assert central.state.desired.latest(db, node_id)["generation"] == 1
        assert db.execute("SELECT state FROM secret_versions WHERE purpose='grant.credential'").fetchone()["state"] == "pending"
    assert central.state.provisioning.status(operation)["steps"][0]["status"] == "remote"


async def test_local_only_mutations_publish_no_remote_generation(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="naive", node_id="local", runtime_username="bob", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        assert central.state.desired.latest(db, node_id) is None


# --- additional coverage beyond the brief's Step 2 tests ---

async def _linked(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    return node, central, node_id, client


async def test_a_remote_grant_names_its_pending_credential_and_never_touches_the_local_manager(pair):
    node, central, node_id, client = await _linked(pair)
    intent = GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username="alice", options=MtproxyOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    assert grant.observed_state == "pending" and grant.secret_ref.secret_id == f"grant:{grant.id}"
    assert grant.secret_ref.version == 1 and grant.origin == "provisioned"
    with central.state.database.connect() as db:
        secret = central.state.secrets.reveal(db, grant.secret_ref, purpose="grant.credential", grant_id=grant.id,
                                              permitted_node_id=node_id).decode()
        document = central.state.desired.latest(db, node_id)["document"]
    # Telemt's own format, so a runtime that accepts caller secrets never has to fall back.
    assert len(secret) == 32 and int(secret, 16) >= 0
    assert [(r.ref, r.credential_ref, r.desired_state) for r in document.resources] == \
        [(f"grant:{grant.id}", f"grant:{grant.id}:1", "enabled")]
    assert await central.state.telemt.list_users() == []  # the central's own runtime is not the node's


async def test_run_leaves_remote_steps_to_the_pusher_and_finishes_local_ones(pair):
    node, central, node_id, client = await _linked(pair)
    remote = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    local = GrantIntent(protocol="naive", node_id="local", runtime_username="bob", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [remote, local], actor=ACTOR, ip="x")
    result = await central.state.provisioning.run(operation)
    assert result.status == "pending_remote"
    assert sorted(step.status for step in result.steps) == ["active", "remote"]
    assert "bob" in [u["username"] for u in await central.state.naive.list_users()]
    assert "alice" not in [u["username"] for u in await central.state.naive.list_users()]
    # Resuming changes nothing: the remote step is the node's to finish.
    assert (await central.state.provisioning.run(operation)).status == "pending_remote"
    await central.state.pusher.tick()
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    assert "alice" in [u["username"] for u in await node.state.naive.list_users()]


async def test_a_failed_local_step_compensates_and_withdraws_the_remote_grant(pair):
    node, central, node_id, client = await _linked(pair)
    remote = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    local = GrantIntent(protocol="naive", node_id="local", runtime_username="bob", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [remote, local], actor=ACTOR, ip="x")
    central.state.provisioning.faults["after_apply"] = "naive"
    result = await central.state.provisioning.run(operation)
    assert result.status == "compensated"
    grants = {g.runtime_username: g for g in central.state.clients.client_with_grants(client.id)[1]}
    assert grants == {}  # both grants are deleted
    with central.state.database.connect() as db:
        latest = central.state.desired.latest(db, node_id)
    assert latest["generation"] == 2 and [r.desired_state for r in latest["document"].resources] == ["deleted"]
    await central.state.pusher.tick()
    assert "alice" not in [u["username"] for u in await node.state.naive.list_users()]
    with central.state.database.connect() as db:
        alice = db.execute("SELECT observed_state FROM access_grants WHERE runtime_username='alice'").fetchone()
    assert alice["observed_state"] == "missing"


async def test_compensation_never_sends_a_node_confirmed_remote_step_to_a_local_manager(pair, monkeypatch):
    from panel.fleet_v2.protocol import ObservedGeneration

    node, central, node_id, client = await _linked(pair)
    # An unrelated local user with the same runtime name on the central's own runtime.
    await central.state.naive.create("alice", None, password="local-secret", operation_id="local")
    remote = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    local = GrantIntent(protocol="naive", node_id="local", runtime_username="bob", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [remote, local], actor=ACTOR, ip="x")
    alice = next(g for g in central.state.clients.client_with_grants(client.id)[1] if g.runtime_username == "alice")
    adapter = central.state.adapters["naive"]
    create = adapter.create

    async def create_while_the_node_confirms(operation_id, intent, credential):
        applied = await create(operation_id, intent, credential)
        # A tick lands while the local step is in flight: the node reports alice applied.
        report = ObservedGeneration(applied_generation=1, digest="d", reconcile_state="converged", reported_at=1,
                                    resources=[{"ref": f"grant:{alice.id}", "protocol": "naive",
                                                "runtime_username": "alice", "state": "enabled"}])
        with central.state.database.transaction() as db:
            central.state.provisioning.remote_applied(db, report)
        assert central.state.provisioning.status(operation)["status"] == "applying"
        return applied

    monkeypatch.setattr(adapter, "create", create_while_the_node_confirms)
    central.state.provisioning.faults["after_apply"] = "naive"
    result = await central.state.provisioning.run(operation)
    assert result.status == "compensated" and sorted(step.status for step in result.steps) == ["compensated"] * 2
    users = [u["username"] for u in await central.state.naive.list_users()]
    assert "alice" in users and "bob" not in users  # the local runtime's alice is not the node's
    with central.state.database.connect() as db:
        latest = central.state.desired.latest(db, node_id)
        states = {row["runtime_username"]: (row["desired_state"], row["observed_state"])
                  for row in db.execute("SELECT runtime_username, desired_state, observed_state FROM access_grants")}
    assert states == {"alice": ("deleted", "enabled"), "bob": ("deleted", "missing")}
    assert latest["generation"] == 2 and [(r.ref, r.desired_state) for r in latest["document"].resources] == \
        [(f"grant:{alice.id}", "deleted")]


async def test_remote_applied_finishes_only_operations_whose_grants_the_node_confirmed(pair):
    from panel.fleet_v2.protocol import ObservedGeneration

    node, central, node_id, client = await _linked(pair)
    first = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    second = GrantIntent(protocol="naive", node_id=node_id, runtime_username="bob", options=NaiveOptions())
    one = await central.state.provisioning.start(client.id, [first], actor=ACTOR, ip="x")
    two = await central.state.provisioning.start(client.id, [second], actor=ACTOR, ip="x")
    grants = {g.runtime_username: g for g in central.state.clients.client_with_grants(client.id)[1]}
    alice, bob = grants["alice"], grants["bob"]
    report = ObservedGeneration(applied_generation=2, digest="d", reconcile_state="failed", reported_at=1, resources=[
        {"ref": f"grant:{alice.id}", "protocol": "naive", "runtime_username": "alice", "state": "enabled"},
        {"ref": f"grant:{bob.id}", "protocol": "naive", "runtime_username": "bob", "state": "failed", "error": "boom"},
    ])
    with central.state.database.transaction() as db:
        central.state.provisioning.remote_applied(db, report)
    assert central.state.provisioning.status(one)["status"] == "succeeded"
    status = central.state.provisioning.status(two)
    assert status["status"] == "pending_remote" and status["steps"][0] == \
        {"grant_id": bob.id, "protocol": "naive", "status": "remote", "error": "boom"}
    with central.state.database.connect() as db:
        states = {row["grant_id"]: row["state"] for row in db.execute("SELECT grant_id, state FROM secret_versions WHERE purpose='grant.credential'")}
    assert states == {alice.id: "active", bob.id: "pending"}
    grants = {g.runtime_username: g for g in central.state.clients.client_with_grants(client.id)[1]}
    assert (grants["alice"].observed_state, grants["bob"].observed_state) == ("enabled", "pending")


async def test_escrow_returned_credential_replaces_the_pending_version_in_place(pair):
    node, central, node_id, client = await _linked(pair)
    intent = GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username="alice", options=MtproxyOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    with central.state.database.transaction() as db:
        central.state.provisioning.escrow_returned_credential(db, grant.id, f"grant:{grant.id}:1", "ee" + "a" * 32)
        # A second report of the same version (a repeated push) is idempotent.
        central.state.provisioning.escrow_returned_credential(db, grant.id, f"grant:{grant.id}:1", "ee" + "a" * 32)
    with central.state.database.connect() as db:
        rows = db.execute("SELECT version, state FROM secret_versions WHERE secret_id=?", (f"grant:{grant.id}",)).fetchall()
        plaintext = central.state.secrets.reveal(db, grant.secret_ref, purpose="grant.credential", grant_id=grant.id,
                                                 permitted_node_id=node_id)
    assert [tuple(row) for row in rows] == [(1, "active")] and plaintext == b"ee" + b"a" * 32
    assert central.state.clients.client_with_grants(client.id)[1][0].secret_ref.version == 1
