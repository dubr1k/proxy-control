"""Routing over Fleet v2 with the node's Xray-router (v0.5): the `companion` beside a
section, the node applying router → native (attach) and native → router (detach), the
identity naming the router, and the central attaching, applying and detaching through
generations — a v0.4 node never sees a field its strict model would refuse."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from panel.database import Database
from panel.fleet_v2.generations import compile as compile_generation
from panel.fleet_v2.managed import ManagedStore
from panel.fleet_v2.protocol import EgressDocument, GenerationDocument, PushRequest, canonical_digest
from panel.fleet_v2.reconcile import Reconciler
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, RouterAdapter, TelemtAdapter
from panel.routing.document import ROUTER_DIRECT_INTENT, attach_document, document_digest
from panel.routing.models import PolicyInput, RoutingRule, RuleMatch
from panel.routing.service import RoutingError
from panel.secrets_store import SecretStore
from panel.telemt import MemoryTelemt
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
NODE, MASTER = "n" * 36, "m" * 36
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": None}
NAIVE_DIRECT = {"schema": 1, "upstream": None, "acl": []}
WARP_INTENT = {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []}


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _egress(document, *, backend="naive_native", companion=None, passthrough=False, policy_id="p1", revision=1):
    return EgressDocument(backend=backend, policy_id=policy_id, policy_revision=revision, document=document,
                          digest=document_digest(document), companion=companion, passthrough=passthrough)


def _doc(generation=1, egress=None):
    return GenerationDocument(node_guid=NODE, master_guid=MASTER, generation=generation, previous_generation=generation - 1,
                              created_at=1, created_by="c", resources=[], egress=egress)


# -- protocol --------------------------------------------------------------------------


def test_companion_and_passthrough_are_in_the_digest_and_omitted_when_absent():
    plain = _doc(egress={"naive": _egress(NAIVE_DIRECT)})
    wire = plain.wire()["egress"]["naive"]
    assert "companion" not in wire and "passthrough" not in wire
    assert canonical_digest(plain) == canonical_digest(GenerationDocument.model_validate(plain.wire()))
    attached = _doc(egress={"naive": _egress(WARP_INTENT, backend="xray_router", companion=attach_document("naive"))})
    wire = attached.wire()["egress"]["naive"]
    assert wire["companion"] == attach_document("naive") and wire["backend"] == "xray_router"
    assert canonical_digest(attached) != canonical_digest(plain)
    assert canonical_digest(attached) == canonical_digest(GenerationDocument.model_validate(attached.wire()))
    flagged = _doc(egress={"naive": _egress(NAIVE_DIRECT, passthrough=True)})
    assert flagged.wire()["egress"]["naive"]["passthrough"] is True
    assert canonical_digest(flagged) != canonical_digest(plain)
    # What a v0.4 node's strict model refuses: any of the two keys.
    with pytest.raises(ValidationError):
        GenerationDocument.model_validate({**plain.wire(), "egress": {"naive": {**wire, "future": 1}}})
    huge = {"schema": 1, "upstream": None, "acl": [{"deny": [f"{'x' * 60}{i:04d}.example" for i in range(300)]}]}
    with pytest.raises(ValidationError, match="companion"):
        _egress(WARP_INTENT, backend="xray_router", companion=huge)


# -- node: reconcile -------------------------------------------------------------------


@pytest.fixture
def node(tmp_path):
    database = Database(tmp_path / "node.sqlite3")
    apply_migrations(database)
    naive, mieru, router = MemoryNaive(), MemoryMieru(), MemoryXrayRouter()
    naive.router_url, mieru.router_url = "socks5://127.0.0.1:45101", "socks5://127.0.0.1:45102"
    adapters = {"mtproxy": TelemtAdapter(MemoryTelemt()), "naive": NaiveAdapter(naive, public_host="n.example"),
                "mieru": MieruAdapter(mieru)}
    managed = ManagedStore(database)
    reconciler = Reconciler(database, SecretStore(Keyring.generate()), adapters, managed, guid=NODE,
                            router=RouterAdapter(router))
    return {"database": database, "managed": managed, "reconciler": reconciler, "naive": naive, "mieru": mieru,
            "router": router}


async def _accept(node, document):
    request = PushRequest(expected_guid=NODE, generation=document, secrets={})
    with node["database"].transaction() as db:
        node["managed"].accept(db, request.generation, canonical_digest(request.generation), node_guid=NODE)
        await node["reconciler"].store_secrets(db, request)


async def test_router_section_applies_router_then_native_attach(node):
    naive, router = node["naive"], node["router"]
    order = []
    naive.calls = order
    router.calls = order
    section = _egress(WARP_INTENT, backend="xray_router", companion=attach_document("naive"))
    await _accept(node, _doc(1, {"naive": section}))
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "converged"
    assert [call[0] for call in order] == ["apply", "egress_apply"]
    assert order[0] == ("apply", "naive", f"{NODE}:1:router:naive") and order[1] == ("egress_apply", f"{NODE}:1:egress:naive")
    assert router.documents["naive"] == WARP_INTENT and naive.egress_document == attach_document("naive")
    report = observed.egress["naive"]
    assert report.state == "converged" and report.digest == document_digest(WARP_INTENT)
    assert report.router["digest"] == document_digest(WARP_INTENT) and report.router["revision"]
    assert report.revision  # the native manager's revision of the attach document
    # The same generation again: nothing re-applied on either side.
    order.clear()
    await _accept(node, _doc(2, {"naive": _egress(WARP_INTENT, backend="xray_router", companion=attach_document("naive"),
                                                   revision=1)}))
    observed, _ = await node["reconciler"].apply(2)
    assert order == [] and observed.egress["naive"].state == "converged"


async def test_native_section_with_companion_applies_native_then_router(node):
    naive, router = node["naive"], node["router"]
    await _accept(node, _doc(1, {"naive": _egress(WARP_INTENT, backend="xray_router", companion=attach_document("naive"))}))
    await node["reconciler"].apply(1)
    order = []
    naive.calls = order
    router.calls = order
    detach = _egress(NAIVE_DIRECT, companion=json.loads(json.dumps(ROUTER_DIRECT_INTENT)), passthrough=True, revision=2)
    await _accept(node, _doc(2, {"naive": detach}))
    observed, _ = await node["reconciler"].apply(2)
    assert observed.reconcile_state == "converged"
    assert [call[0] for call in order] == ["egress_apply", "apply"]  # native first, router second
    assert naive.egress_document == NAIVE_DIRECT and router.documents["naive"] == ROUTER_DIRECT_INTENT
    report = observed.egress["naive"]
    assert report.digest == document_digest(NAIVE_DIRECT) and report.router["digest"] == document_digest(ROUTER_DIRECT_INTENT)


async def test_router_section_without_router_is_unsupported_and_native_untouched(node):
    node["reconciler"].router = None
    naive = node["naive"]
    await _accept(node, _doc(1, {"naive": _egress(WARP_INTENT, backend="xray_router", companion=attach_document("naive"))}))
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "failed"
    assert observed.egress["naive"].state == "failed" and observed.egress["naive"].error == "router_unavailable"
    assert naive.egress_document == NAIVE_DIRECT and [c for c in naive.calls if c[0] == "egress_apply"] == []


async def test_router_apply_failure_marks_failed_but_native_untouched(node):
    naive, router = node["naive"], node["router"]
    router.fail_next = "geosite_unknown"
    await _accept(node, _doc(1, {"naive": _egress(WARP_INTENT, backend="xray_router", companion=attach_document("naive"))}))
    observed, _ = await node["reconciler"].apply(1)
    assert observed.egress["naive"].state == "failed" and observed.egress["naive"].error == "geosite_unknown"
    assert naive.egress_document == NAIVE_DIRECT  # the service was never handed to a router that failed


# -- central: identity, generation, service -------------------------------------------------


async def _link(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    return node, central, node_id


@pytest.fixture
def routed_pair(pair):
    """The node of `pair` runs a memory router and its naive manager knows the ingress."""
    node, central, plaintext = pair
    router = MemoryXrayRouter()
    node.state.router = RouterAdapter(router)
    node.state.routing.router = node.state.router
    node.state.reconciler.router = node.state.router
    node.state.naive.router_url = "socks5://127.0.0.1:45101"
    return node, central, plaintext, router


def _warp(**extra):
    return PolicyInput(default_action="egress", default_egress="warp", **extra)


async def test_identity_reports_router_capability_and_attachment(routed_pair):
    node, central, plaintext, router = routed_pair
    node, central, node_id = await _link((node, central, plaintext))
    await central.state.pusher.tick()
    with central.state.database.connect() as db:
        identity = central.state.links.link(db, node_id)["identity"]
    assert "egress.router.v1" in identity["capabilities"] and identity["router"]["available"] is True
    assert identity["router"]["xray_version"].startswith("Xray") and "block_geosite" in identity["router"]["capabilities"]
    assert identity["router"]["services"]["naive"]["applied_digest"] == document_digest(ROUTER_DIRECT_INTENT)
    assert identity["protocols"]["naive"]["egress"]["router_attached"] is False
    assert "socks5://" not in json.dumps(identity)
    items = {(i["node_id"], i["protocol"]): i for i in await central.state.routing.targets()}
    remote = items[(node_id, "naive")]
    assert remote["router"]["available"] is True and remote["router"]["attached"] is False and remote["backend"] == "naive_native"


async def test_remote_attach_apply_and_detach_through_generations(routed_pair):
    node, central, plaintext, router = routed_pair
    node, central, node_id = await _link((node, central, plaintext))
    routing = central.state.routing
    await central.state.pusher.tick()
    # Attach: the generation carries the router's pass-through with the attach companion.
    item = await routing.attach(node_id, "naive", **CTX)
    assert item["policy"]["backend"] == "xray_router" and item["policy"]["state"] == "applying"
    with central.state.database.connect() as db:
        section = central.state.desired.latest(db, node_id)["document"].egress["naive"]
    assert section.backend == "xray_router" and section.companion == attach_document("naive") and section.passthrough is True
    await central.state.pusher.tick()
    assert node.state.naive.egress_document == attach_document("naive")
    policy = routing.get(node_id, "naive")
    # An empty policy *is* the pass-through: applied. (With rules it would wait as a draft.)
    assert policy.state == "applied" and policy.applied_digest == document_digest(ROUTER_DIRECT_INTENT)
    await central.state.pusher.tick()  # the identity (attachment) refreshes with the next heartbeat
    items = {(i["node_id"], i["protocol"]): i for i in await routing.targets()}
    assert items[(node_id, "naive")]["router"]["attached"] is True and items[(node_id, "naive")]["backend"] == "xray_router"
    # A router policy with a geosite rule, applied through the next generation.
    routing.save(node_id, "naive", _warp(rules=[RoutingRule(action="block", match=RuleMatch(geosites=["category-ads-all"]))]),
                 expected_revision=policy.revision, **CTX)
    result = await routing.apply(node_id, "naive", expected_revision=policy.revision + 1, **CTX)
    assert result["policy"].state == "applying" and result["compiled"].attach == attach_document("naive")
    await central.state.pusher.tick()
    assert router.documents["naive"]["rules"][0]["geosites"] == ["category-ads-all"]
    policy = routing.get(node_id, "naive")
    assert policy.state == "applied" and policy.applied_current is True
    assert policy.applied_digest == document_digest(router.documents["naive"])
    history = routing.history(node_id, "naive")
    assert history[0]["backend"] == "xray_router" and json.loads(history[0]["detail"])["router"]["digest"] == policy.applied_digest
    # Rollback on the router, remotely: back to the pass-through.
    result = await routing.rollback(node_id, "naive", expected_revision=policy.revision, **CTX)
    assert result["compiled"].document == ROUTER_DIRECT_INTENT
    await central.state.pusher.tick()
    assert router.documents["naive"] == ROUTER_DIRECT_INTENT and node.state.naive.egress_document == attach_document("naive")
    # Detach: the native document back to direct, then the router pass-through.
    item = await routing.detach(node_id, "naive", **CTX)
    assert item["policy"]["backend"] == "naive_native"
    await central.state.pusher.tick()
    assert node.state.naive.egress_document == NAIVE_DIRECT and router.documents["naive"] == ROUTER_DIRECT_INTENT
    policy = routing.get(node_id, "naive")
    assert policy.backend == "naive_native" and policy.state == "draft"
    audits = central.state.store.audits(action="routing.target.attach")
    assert audits and audits[0]["detail"]["outcome"] == "applying"


async def test_remote_apply_router_policy_on_node_without_capability_is_422(pair):
    node, central, node_id = await _link(pair)
    routing = central.state.routing
    await central.state.pusher.tick()
    routing.save(node_id, "naive", _warp(backend="xray_router"), expected_revision=None, **CTX)
    with pytest.raises(RoutingError) as caught:
        await routing.apply(node_id, "naive", expected_revision=1, **CTX)
    assert (caught.value.status, caught.value.code) == (422, "node_lacks_router")
    with pytest.raises(RoutingError) as caught:
        await routing.attach(node_id, "naive", **CTX)
    assert caught.value.code == "router_unavailable"
    # A stale router section never reaches a v0.4 node's strict model.
    with central.state.database.connect() as db:
        policy = routing.store.get(db, node_id, "naive")
        routing.store.set_desired(db, policy.id, {"backend": "xray_router", "policy_id": policy.id, "policy_revision": 1,
                                                  "document": WARP_INTENT, "digest": document_digest(WARP_INTENT),
                                                  "companion": attach_document("naive")})
        doc = compile_generation(db, central.state.clients.store, node_id=node_id, node_guid=node_id, master_guid="m",
                                 previous=0, generation=1, now=1, created_by="t", routing=routing.store)
    assert doc.egress is None
