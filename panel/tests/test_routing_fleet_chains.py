"""Chains and lanes over Fleet v2 (v0.7, spec §7): the `relay` section and a resource's
`lane` on the wire (omitted when absent — a v0.6 node never sees them), the node enabling
its relay and building a client's lane before the egress, its report carrying the relay's
public part and the lane's link template, and the central enabling a linked node's relay,
minting the accounts a chain needs and following the node's report — never a UUID or a
lane key in a report or an identity."""
from __future__ import annotations



import pytest



from panel.database import Database

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
from panel.tests.harness.memories.mieru import MemoryMieru
from panel.tests.harness.memories.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, RouterAdapter, TelemtAdapter
from panel.routing.document import attach_document, document_digest



from panel.secrets_store import SecretStore
from panel.tests.harness.memories.telemt import MemoryTelemt
from panel.tests.harness.memories.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
NODE, MASTER = "n" * 36, "m" * 36


UUID_DIRECT = "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10"
SECRET_ID = "7d1b2c3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
EMAIL = f"relay:{MASTER}:direct"
WARP_INTENT = {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []}





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


async def test_a_node_without_warp_carries_the_direct_account_and_reports_only_what_it_carries(node):
    """The central mints `direct` and `warp` accounts for every source; a node without WARP
    (`[egress] warp = false`) cannot serve the warp one. It carries the direct account and its
    report names only that — so the central's chain through this node's direct exit converges
    and «via warp» stays `relay_no_warp`. Found live: AMS_Z → ams-test never converged because
    the router refused the whole set (`egress_invalid`)."""
    router = node["router"]
    router.warp_url = None
    warp_email = f"relay:{MASTER}:warp"
    section = _relay(accounts=[RelayAccount(email=EMAIL, credential_ref=f"{SECRET_ID}:1"),
                               RelayAccount(email=warp_email, credential_ref=f"{SECRET_ID}:2")])
    await _accept(node, _doc(1, relay=section), {f"{SECRET_ID}:1": UUID_DIRECT, f"{SECRET_ID}:2": "9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e"})
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "converged", observed
    assert router.relay_state["accounts"] == [{"email": EMAIL, "uuid": UUID_DIRECT}]
    assert observed.relay.state == "converged" and observed.relay.accounts == [EMAIL]
    # the same section again is «converged» already: nothing re-applied, the report unchanged
    router.calls.clear()
    await _accept(node, _doc(2, relay=section), {f"{SECRET_ID}:1": UUID_DIRECT, f"{SECRET_ID}:2": "9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e"})
    observed, _ = await node["reconciler"].apply(2)
    assert router.calls == [] and observed.relay.accounts == [EMAIL]


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



















