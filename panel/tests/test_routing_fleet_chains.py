"""Chains and lanes over Fleet v2 (v0.7, spec §7): the `relay` section and a resource's
`lane` on the wire (omitted when absent — a v0.6 node never sees them), the node enabling
its relay and building a client's lane before the egress, its report carrying the relay's
public part and the lane's link template, and the central enabling a linked node's relay,
minting the accounts a chain needs and following the node's report — never a UUID or a
lane key in a report or an identity."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from panel.clients.models import GrantIntent, MieruOptions, NaiveOptions
from panel.database import Database
from panel.fleet_v2.generations import compile as compile_generation
from panel.fleet_v2.managed import ManagedStore
from panel.fleet_v2.protocol import (
    EgressDocument,
    GenerationDocument,
    PushRequest,
    RelayAccount,
    RelaySection,
    Resource,
    canonical_digest,
)
from panel.fleet_v2.reconcile import Reconciler
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, RouterAdapter, TelemtAdapter
from panel.routing.document import attach_document, document_digest
from panel.routing.lanes import LaneError
from panel.routing.models import PolicyInput
from panel.routing.service import RoutingError
from panel.secrets_store import SecretStore
from panel.telemt import MemoryTelemt
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
NODE, MASTER = "n" * 36, "m" * 36
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": None}
UUID_DIRECT = "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10"
SECRET_ID = "7d1b2c3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
EMAIL = f"relay:{MASTER}:direct"
WARP_INTENT = {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []}


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _relay(enabled=True, accounts=None, port=45443):
    return RelaySection(enabled=enabled, port=port, server_name="node.example",
                        accounts=[RelayAccount(email=EMAIL, credential_ref=f"{SECRET_ID}:1")] if accounts is None else accounts)


def _doc(generation=1, *, resources=(), egress=None, relay=None):
    return GenerationDocument(node_guid=NODE, master_guid=MASTER, generation=generation, previous_generation=generation - 1,
                              created_at=1, created_by="c", resources=list(resources), egress=egress, relay=relay)


def _resource(protocol="naive", username="alice", ref="grant:g1", lane=None, state="enabled"):
    return Resource(ref=ref, protocol=protocol, runtime_username=username, desired_state=state,
                    credential_ref=f"{ref}:1", credential_origin="caller", lane=lane)


def _egress(document, *, backend="xray_router", companion=None, policy_id="p1", revision=1):
    return EgressDocument(backend=backend, policy_id=policy_id, policy_revision=revision, document=document,
                          digest=document_digest(document), companion=companion)


def _intent_v2(lane: str, exit_: str = "warp") -> dict:
    return {"schema": 2, "lanes": {"svc:naive": {"default": {"action": "direct", "egress": None}, "rules": []},
                                   lane: {"default": {"action": "egress", "egress": exit_}, "rules": []}}, "chains": {}}


# -- protocol --------------------------------------------------------------------------


def test_relay_and_lane_are_in_the_digest_and_omitted_when_absent():
    plain = _doc(resources=[_resource()])
    wire = plain.wire()
    assert "relay" not in wire and "lane" not in wire["resources"][0]
    assert canonical_digest(plain) == canonical_digest(GenerationDocument.model_validate(wire))
    laned = _doc(resources=[_resource(lane="own")], relay=_relay())
    wire = laned.wire()
    assert wire["resources"][0]["lane"] == "own" and wire["relay"]["accounts"] == [{"email": EMAIL, "credential_ref": f"{SECRET_ID}:1"}]
    assert canonical_digest(laned) != canonical_digest(plain)
    assert canonical_digest(laned) == canonical_digest(GenerationDocument.model_validate(wire))
    # a UUID never sits in the document: it travels in the push's secrets, by the account's ref
    request = PushRequest(expected_guid=NODE, generation=laned, secrets={f"{SECRET_ID}:1": UUID_DIRECT})
    assert request.wire()["secrets"] == {f"{SECRET_ID}:1": UUID_DIRECT} and UUID_DIRECT not in json.dumps(laned.wire())
    with pytest.raises(ValidationError):
        PushRequest(expected_guid=NODE, generation=plain, secrets={f"{SECRET_ID}:1": UUID_DIRECT})
    with pytest.raises(ValidationError):
        Resource.model_validate({**_resource().model_dump(), "lane": "theirs"})
    with pytest.raises(ValidationError):
        RelaySection(enabled=True, port=45443, server_name="node.example", accounts=[RelayAccount(email="bogus", credential_ref="x:1")])


# -- node: reconcile -------------------------------------------------------------------


@pytest.fixture
def node(tmp_path):
    database = Database(tmp_path / "node.sqlite3")
    apply_migrations(database)
    naive, mieru, router = MemoryNaive(), MemoryMieru(), MemoryXrayRouter()
    naive.router_url, mieru.router_url = "socks5://127.0.0.1:45101", "socks5://127.0.0.1:45102"
    adapters = {"mtproxy": TelemtAdapter(MemoryTelemt()), "naive": NaiveAdapter(naive, public_host="n.example"),
                "mieru": MieruAdapter(mieru, public_host="mieru.example.com")}
    managed = ManagedStore(database)
    reconciler = Reconciler(database, SecretStore(Keyring.generate()), adapters, managed, guid=NODE,
                            router=RouterAdapter(router))
    return {"database": database, "managed": managed, "reconciler": reconciler, "naive": naive, "mieru": mieru,
            "router": router}


async def _accept(node, document, secrets=None):
    secrets = secrets or {}
    for resource in document.resources:
        secrets.setdefault(resource.credential_ref, "correct horse battery staple")
    request = PushRequest(expected_guid=NODE, generation=document, secrets=secrets)
    with node["database"].transaction() as db:
        node["managed"].accept(db, request.generation, canonical_digest(request.generation), node_guid=NODE)
        await node["reconciler"].store_secrets(db, request)


async def test_relay_section_enables_the_relay_and_sets_accounts_before_the_egress(node):
    router = node["router"]
    await _accept(node, _doc(1, egress={"naive": _egress(WARP_INTENT, companion=attach_document("naive"))}, relay=_relay()),
                  {f"{SECRET_ID}:1": UUID_DIRECT})
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "converged", observed
    assert [call[0] for call in router.calls] == ["relay_enable", "relay_accounts", "apply"]
    assert router.calls[0] == ("relay_enable", "node.example", 45443) and router.calls[1] == ("relay_accounts", [EMAIL])
    assert router.relay_state["accounts"] == [{"email": EMAIL, "uuid": UUID_DIRECT}]
    report = observed.relay
    assert report.state == "converged" and report.accounts == [EMAIL] and report.enabled is True
    assert (report.public_key, report.short_id, report.port, report.server_name) == (router.public_key, "0123abcd", 45443, "node.example")
    assert UUID_DIRECT not in observed.model_dump_json()
    # the same section again: nothing re-applied; no section: the relay is left as it is
    router.calls.clear()
    await _accept(node, _doc(2, egress={"naive": _egress(WARP_INTENT, companion=attach_document("naive"))}, relay=_relay()),
                  {f"{SECRET_ID}:1": UUID_DIRECT})
    observed, _ = await node["reconciler"].apply(2)
    assert router.calls == [] and observed.relay.state == "converged" and observed.relay.accounts == [EMAIL]
    await _accept(node, _doc(3))
    observed, _ = await node["reconciler"].apply(3)
    assert router.calls == [] and router.relay_state["enabled"] is True and observed.relay.accounts == [EMAIL]
    # disabled: the inbound goes, the report says so
    await _accept(node, _doc(4, relay=_relay(enabled=False, accounts=[])))
    observed, _ = await node["reconciler"].apply(4)
    assert router.relay_state["enabled"] is False and observed.relay.state == "converged" and observed.relay.enabled is False


async def test_relay_section_without_a_router_fails_the_generation(node):
    node["reconciler"].router = None
    await _accept(node, _doc(1, relay=_relay()), {f"{SECRET_ID}:1": UUID_DIRECT})
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "failed"
    assert observed.relay.state == "failed" and observed.relay.error == "router_unavailable"


async def test_a_resource_with_its_own_lane_gets_a_router_account_and_a_manager_lane_before_the_egress(node):
    naive, router = node["naive"], node["router"]
    lane = "grant:g1"
    order = []
    naive.calls, router.calls = order, order
    await _accept(node, _doc(1, resources=[_resource(lane="own")],
                             egress={"naive": _egress(_intent_v2(lane), companion=attach_document("naive"))}))
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "converged", observed
    kinds = [call[0] for call in order]
    assert kinds.index("lane_issue") < kinds.index("set_lanes") < kinds.index("apply")
    assert lane in router.lane_accounts["naive"] and naive.lane_table[lane]["users"] == ["alice"]
    assert naive.lane_table[lane]["upstream_user"] == "grant-g1" and router.documents["naive"]["schema"] == 2
    assert router.lane_accounts["naive"][lane] not in observed.model_dump_json()
    assert observed.egress["naive"].lanes == [lane]
    # the same generation again: the lane is not re-issued
    order.clear()
    await _accept(node, _doc(2, resources=[_resource(lane="own")],
                             egress={"naive": _egress(_intent_v2(lane), companion=attach_document("naive"))}))
    await node["reconciler"].apply(2)
    assert [call[0] for call in order] == []
    # the lane withdrawn: the user returns to the service, the router forgets the account
    await _accept(node, _doc(3, resources=[_resource()], egress={"naive": _egress(WARP_INTENT, companion=attach_document("naive"))}))
    observed, _ = await node["reconciler"].apply(3)
    assert naive.lane_table == {} and lane not in router.lane_accounts["naive"]
    assert observed.egress["naive"].lanes == [] and observed.reconcile_state == "converged"


async def test_a_mieru_lane_teaches_the_slot_ports_link_template_and_the_service_one_on_return(node):
    mieru = node["mieru"]
    lane = "grant:g2"
    await _accept(node, _doc(1, resources=[_resource("mieru", "phone", "grant:g2", lane="own")]))
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "converged", observed
    assert mieru.lane_table[lane]["slot"] == 1
    learned = next(item.learned for item in observed.resources if item.ref == "grant:g2")
    assert learned["share_template"].endswith(f"port={mieru.lane_slots[1]}&protocol=TCP&mtu=1400")
    await _accept(node, _doc(2, resources=[_resource("mieru", "phone", "grant:g2")]))
    observed, _ = await node["reconciler"].apply(2)
    learned = next(item.learned for item in observed.resources if item.ref == "grant:g2")
    assert "port=8443" in learned["share_template"] and "{password}" in learned["share_template"]


async def test_a_lane_the_manager_refuses_fails_its_resource_and_leaves_the_router_clean(node):
    naive, router = node["naive"], node["router"]
    naive.lanes_fail_next = "lanes_invalid"
    await _accept(node, _doc(1, resources=[_resource(lane="own")]))
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "failed"
    item = next(item for item in observed.resources if item.ref == "grant:g1")
    assert item.state == "failed" and item.error == "lane: lanes_invalid"
    assert router.lane_accounts["naive"] == {}


# -- central: identity, relay, chains and lanes through generations ----------------------


async def _link(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    return node, central, node_id


@pytest.fixture
def routed_pair(pair):
    """Both panels run a memory router; the node's managers know their ingress."""
    node, central, plaintext = pair
    routers = {}
    for app in (node, central):
        router = MemoryXrayRouter()
        app.state.router = RouterAdapter(router)
        app.state.routing.router = app.state.router
        app.state.lanes.router = app.state.router
        app.state.reconciler.router = app.state.router
        app.state.naive.router_url = "socks5://127.0.0.1:45101"
        app.state.mieru.router_url = "socks5://127.0.0.1:45102"
        routers[app] = router
    return node, central, plaintext, routers


async def test_identity_reports_the_lanes_and_relay_capabilities_and_the_relays_public_part(routed_pair):
    node, central, plaintext, routers = routed_pair
    node, central, node_id = await _link((node, central, plaintext))
    await central.state.pusher.tick()
    with central.state.database.connect() as db:
        identity = central.state.links.link(db, node_id)["identity"]
    assert {"egress.lanes.v1", "relay.v1"} <= set(identity["capabilities"])
    assert identity["router"]["relay"]["enabled"] is False and identity["router"]["lanes"] == {"naive": [], "mieru": []}
    items = {(i["node_id"], i["protocol"]): i for i in await central.state.routing.targets()}
    assert items[("local", "naive")]["exits"] == []  # no relay anywhere yet


async def test_a_linked_nodes_relay_is_enabled_through_its_generation_and_a_chain_follows_its_report(routed_pair):
    node, central, plaintext, routers = routed_pair
    node, central, node_id = await _link((node, central, plaintext))
    routing = central.state.routing
    await central.state.pusher.tick()
    enabled = await routing.relay_enable(node_id, **CTX)
    assert enabled["enabled"] is True and enabled["port"] == 45443 and enabled["public_key"] is None and enabled["pending"] is True
    with central.state.database.connect() as db:
        section = central.state.desired.latest(db, node_id)["document"].relay
    assert section.enabled is True and section.port == 45443 and section.server_name == "node.example" and section.accounts == []
    await central.state.pusher.tick()
    assert routers[node].relay_state["enabled"] is True
    with central.state.database.connect() as db:
        relay = central.state.relays.relay(db, node_id)
        observed = central.state.desired.observed_relay(db, node_id)
    assert relay["public_key"] == routers[node].public_key and relay["short_id"] == "0123abcd" and relay["enabled"] == 1
    assert observed["state"] == "converged" and observed["accounts"] == []
    items = {(i["node_id"], i["protocol"]): i for i in await routing.targets()}
    exit_ = items[("local", "naive")]["exits"][0]
    assert exit_["node_id"] == node_id and exit_["enabled"] is True and exit_["online"] is True and exit_["exit"] == f"node:{node_id}"
    # the central's own service exits through the node: the apply mints the accounts, the
    # generation carries them, the apply waits for the node's word
    await routing.attach("local", "naive", **CTX)
    routing.save("local", "naive", PolicyInput(default_action="egress", default_egress=f"node:{node_id}"),
                 expected_revision=1, **CTX)
    with pytest.raises(RoutingError) as caught:
        await routing.apply("local", "naive", expected_revision=2, **CTX)
    assert caught.value.code == "unsupported" and [r.code for r in caught.value.compiled.reasons] == ["relay_credential_pending"]
    with central.state.database.connect() as db:
        latest = central.state.desired.latest(db, node_id)["document"]
        peers = central.state.relays.peers(db, node_id)
    emails = sorted(account.email for account in latest.relay.accounts)
    assert emails == sorted(f"relay:{central.state.panel_guid}:{kind}" for kind in ("direct", "warp"))
    assert {peer["exit"] for peer in peers} == {"direct", "warp"}
    request = central.state.pusher._secrets_for(node_id, latest)
    assert set(request) == {account.credential_ref for account in latest.relay.accounts}
    await central.state.pusher.tick()
    assert sorted(a["email"] for a in routers[node].relay_state["accounts"]) == emails
    result = await routing.apply("local", "naive", expected_revision=2, **CTX)
    chain = result["compiled"].document["chains"]["c1"]
    assert chain["exit"] == "direct" and chain["hops"][0]["address"] == "node.example" and chain["hops"][0]["port"] == 45443
    assert chain["hops"][0]["public_key"] == routers[node].public_key
    direct = next(a for a in routers[node].relay_state["accounts"] if a["email"].endswith(":direct"))
    assert chain["hops"][0]["uuid"] == direct["uuid"]
    assert direct["uuid"] not in json.dumps(central.state.store.audits())
    # rotate: the node gets fresh accounts through its next generation, the old ones are gone
    rotated = await routing.relay_rotate(node_id, **CTX)
    assert rotated["rotated"] == 2
    await central.state.pusher.tick()
    assert direct["uuid"] not in [a["uuid"] for a in routers[node].relay_state["accounts"]]


async def test_a_grant_on_a_linked_node_gets_its_lane_through_the_generation(routed_pair):
    node, central, plaintext, routers = routed_pair
    node, central, node_id = await _link((node, central, plaintext))
    await central.state.pusher.tick()
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intents = [GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions()),
               GrantIntent(protocol="mieru", node_id=node_id, runtime_username="phone", options=MieruOptions())]
    await central.state.provisioning.start(client.id, intents, actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    grants = {grant.protocol: grant for grant in central.state.clients.client_with_grants(client.id)[1]}
    assert all(grant.observed_state == "enabled" for grant in grants.values())
    await central.state.routing.attach(node_id, "naive", **CTX)
    await central.state.pusher.tick()
    enabled = await central.state.lanes.enable(grants["naive"].id, **CTX)
    lane = f"grant:{grants['naive'].id}"
    assert enabled["mode"] == "own" and enabled["lane"] == lane and enabled["pending"] is True
    with central.state.database.connect() as db:
        resource = next(r for r in central.state.desired.latest(db, node_id)["document"].resources if r.ref == lane)
    assert resource.lane == "own"
    await central.state.pusher.tick()
    assert lane in routers[node].lane_accounts["naive"] and node.state.naive.lane_table[lane]["users"] == ["alice"]
    policy = central.state.routing.get(node_id, "naive", lane=lane)
    assert policy.state == "draft" and policy.backend == "xray_router"
    # the lane's policy applies as the service's schema-2 intent through the next generation
    central.state.routing.save(node_id, "naive", PolicyInput(default_action="egress", default_egress="warp", backend="xray_router"),
                               expected_revision=1, lane=lane, **CTX)
    result = await central.state.routing.apply(node_id, "naive", expected_revision=2, lane=lane, **CTX)
    assert result["policy"].state == "applying" and result["compiled"].document["schema"] == 2
    await central.state.pusher.tick()
    assert routers[node].documents["naive"]["lanes"][lane]["default"] == {"action": "egress", "egress": "warp"}
    assert central.state.routing.get(node_id, "naive", lane=lane).state == "applied"
    assert central.state.routing.get(node_id, "naive").state == "applied"
    # a Mieru lane: the node's slot port reaches the central's link through `learned`
    enabled = await central.state.lanes.enable(grants["mieru"].id, **CTX)
    await central.state.pusher.tick()
    mieru_grant = next(g for g in central.state.clients.client_with_grants(client.id)[1] if g.protocol == "mieru")
    assert mieru_grant.routing_lane == "own"
    assert mieru_grant.options.share_template.endswith(f"port={node.state.mieru.lane_slots[1]}&protocol=TCP&mtu=1400")
    # back to the service: the node drops the lane, the template returns to the main port
    disabled = await central.state.lanes.disable(grants["mieru"].id, **CTX)
    assert disabled["mode"] == "service"
    await central.state.pusher.tick()
    assert node.state.mieru.lane_table == {}
    mieru_grant = next(g for g in central.state.clients.client_with_grants(client.id)[1] if g.protocol == "mieru")
    assert "port=8443" in mieru_grant.options.share_template
    audits = [row["action"] for row in central.state.store.audits()]
    assert "grant.lane.enable" in audits and "grant.lane.disable" in audits


async def test_a_v06_node_refuses_lanes_and_relay_by_code(routed_pair):
    node, central, plaintext, routers = routed_pair
    node, central, node_id = await _link((node, central, plaintext))
    await central.state.pusher.tick()
    with central.state.database.transaction() as db:
        row = db.execute("SELECT identity_json FROM node_links WHERE node_id=?", (node_id,)).fetchone()
        identity = json.loads(row["identity_json"])
        identity["capabilities"] = [c for c in identity["capabilities"] if c not in ("egress.lanes.v1", "relay.v1")]
        db.execute("UPDATE node_links SET identity_json=? WHERE node_id=?", (json.dumps(identity), node_id))
    with pytest.raises(RoutingError) as caught:
        await central.state.routing.relay_enable(node_id, **CTX)
    assert (caught.value.status, caught.value.code) == (422, "node_lacks_relay")
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    await central.state.provisioning.start(
        client.id, [GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())],
        actor=ACTOR, ip="x")
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    with pytest.raises(LaneError) as caught:
        await central.state.lanes.enable(grant.id, **CTX)
    assert (caught.value.status, caught.value.code) == (422, "node_lacks_lanes")
    # a schema-2 section never reaches such a node's router
    with central.state.database.transaction() as db:
        policy = central.state.routing.store.upsert(db, node_id, "naive", PolicyInput(backend="xray_router"), expected_revision=None)
        central.state.routing.store.set_desired(db, policy.id, {"backend": "xray_router", "policy_id": policy.id, "policy_revision": 1,
                                                                "document": _intent_v2("grant:x"), "digest": document_digest(_intent_v2("grant:x")),
                                                                "companion": attach_document("naive")})
        doc = compile_generation(db, central.state.clients.store, node_id=node_id, node_guid=node_id, master_guid="m",
                                 previous=0, generation=1, now=1, created_by="t", routing=central.state.routing.store)
    assert doc.egress is None and doc.relay is None
    # a resource's lane stays off the wire for such a node too
    with central.state.database.transaction() as db:
        db.execute("UPDATE access_grants SET routing_lane='own' WHERE id=?", (grant.id,))
        doc = compile_generation(db, central.state.clients.store, node_id=node_id, node_guid=node_id, master_guid="m",
                                 previous=0, generation=1, now=1, created_by="t", routing=central.state.routing.store)
    assert doc.resources[0].lane is None

