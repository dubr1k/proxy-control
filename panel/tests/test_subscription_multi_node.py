"""A subscription renders every grant of a client, each with its own node's public host."""
import pytest

from panel.clients.models import GrantIntent, NaiveOptions

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}  # фикстура `pair` приходит из panel/tests/conftest.py


async def test_subscription_lists_grants_of_every_node_with_node_public_hosts(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    operation_id = await central.state.provisioning.start(client.id, [
        GrantIntent(protocol="naive", node_id="local", runtime_username="a-local", options=NaiveOptions()),
        GrantIntent(protocol="naive", node_id=node_id, runtime_username="a-edge", options=NaiveOptions()),
    ], actor=ACTOR, ip="x")
    await central.state.provisioning.run(operation_id)  # the local step is applied here; the node's by the pusher
    await central.state.pusher.tick()
    subscription, token = central.state.subscriptions.create(client.id, actor=ACTOR, ip="x")
    manifest = central.state.subscriptions.effective_manifest(subscription, 10**9)
    from panel.subscriptions.renderers.base import resolve_artifacts
    from panel.fleet_v2.central_routes import public_hosts_for
    with central.state.database.connect() as db:
        artifacts = resolve_artifacts(manifest, central.state.secrets, central.state.adapters, db,
                                      public_hosts=lambda nid: public_hosts_for(central.state, nid))
    links = {g.runtime_username: artifacts[g.grant_id][0].value for g in manifest.grants}
    assert "central.example" in links["a-local"] and "node.example" in links["a-edge"]
