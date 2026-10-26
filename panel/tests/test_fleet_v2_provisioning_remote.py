"""Provisioning a grant on a linked panel: no manager is called from the central.

The grant, its pending credential and the generation that carries it are one
transaction; the pusher finishes the operation when the node reports the grant
applied. Local grants keep the saga exactly as it was.
"""
import pytest

from panel.clients.models import GrantIntent, MieruOptions, MtproxyOptions, NaiveOptions

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}  # фикстура `pair` приходит из panel/tests/conftest.py





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





async def test_run_leaves_remote_steps_to_the_pusher_and_finishes_local_ones(pair):
    node, central, node_id, client = await _linked(pair)
    remote = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    local = GrantIntent(protocol="naive", node_id="local", runtime_username="bob", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [remote, local], actor=ACTOR, ip="x")
    result = await central.state.provisioning.run(operation)
    assert result.status == "pending_remote"
    assert sorted(step.status for step in result.steps) == ["active", "remote"]
    assert "bob" in [u["username"] for u in await central.naive.list_users()]
    assert "alice" not in [u["username"] for u in await central.naive.list_users()]
    # Resuming changes nothing: the remote step is the node's to finish.
    assert (await central.state.provisioning.run(operation)).status == "pending_remote"
    await central.tick("pusher")
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    assert "alice" in [u["username"] for u in await node.naive.list_users()]





async def test_compensation_never_sends_a_node_confirmed_remote_step_to_a_local_manager(pair, monkeypatch):
    from panel.fleet_v2.protocol import ObservedGeneration

    node, central, node_id, client = await _linked(pair)
    # An unrelated local user with the same runtime name on the central's own runtime.
    await central.naive.create("alice", None, password="local-secret", operation_id="local")
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
    users = [u["username"] for u in await central.naive.list_users()]
    assert "alice" in users and "bob" not in users  # the local runtime's alice is not the node's
    with central.state.database.connect() as db:
        latest = central.state.desired.latest(db, node_id)
        states = {row["runtime_username"]: (row["desired_state"], row["observed_state"])
                  for row in db.execute("SELECT runtime_username, desired_state, observed_state FROM access_grants")}
    # The remote grant is withdrawn through the next generation; the local one, confirmed
    # gone by its manager, leaves no tombstone (post-merge T10).
    assert states == {"alice": ("deleted", "enabled")}
    assert latest["generation"] == 2 and [(r.ref, r.desired_state) for r in latest["document"].resources] == \
        [(f"grant:{alice.id}", "deleted")]








# ---- lab finding (Task 14): a remote MTProxy/Mieru link must be the runtime's ----------


async def test_remote_links_render_with_the_nodes_runtime_host_port_and_fake_tls_secret(pair):
    """Before the node reported anything, the central knew only a bare 32-hex secret and
    the node's panel domain: a `tg://` link built from those is not Fake-TLS and names the
    wrong host. Once the node applies the grant, the central escrows Telemt's own secret
    form and keeps the host/port/share template it learned — the bundle and the
    subscription then carry what the runtime actually serves (spec §6, ADR 003)."""
    node, central, node_id, client = await _linked(pair)
    node.telemt.public_host, node.telemt.public_port = "proxy.node.example", 8443
    intents = [GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username="alice", options=MtproxyOptions()),
               GrantIntent(protocol="mieru", node_id=node_id, runtime_username="alice", options=MieruOptions(quotas=[]))]
    operation = await central.state.provisioning.start(client.id, intents, actor=ACTOR, ip="x")
    await central.state.provisioning.run(operation)
    await central.tick("pusher")
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    grants = {g.protocol: g for g in central.state.clients.client_with_grants(client.id)[1]}
    assert grants["mtproxy"].options.host == "proxy.node.example" and grants["mtproxy"].options.port == 8443
    assert grants["mieru"].options.share_template.startswith("mierus://{username}:{password}@mieru.example.com")
    bundle = central.state.provisioning.bundle(operation, public_hosts={"mtproxy": "panel.node.example", "mieru": "x"})
    links = {g["protocol"]: g["artifacts"][0]["value"] for g in bundle["grants"]}
    assert links["mtproxy"].startswith("tg://proxy?server=proxy.node.example&port=8443&secret=ee")
    assert links["mieru"].startswith("mierus://alice:") and "@mieru.example.com" in links["mieru"]
    with central.state.database.connect() as db:
        state = db.execute("SELECT state FROM secret_versions WHERE secret_id=?",
                           (f"grant:{grants['mtproxy'].id}",)).fetchall()
    assert [row["state"] for row in state] == ["active"]
