"""Routing over Fleet v2 (spec §8.3): the egress section of a generation, the node applying
it after its resources, and the central absorbing the node's report into the policy."""

from __future__ import annotations

import json

import pytest



from panel.database import Database

from panel.fleet_v2.managed import ManagedStore
from panel.fleet_v2.protocol import (
    EgressDocument,
    GenerationDocument,
    ObservedGeneration,
    PushRequest,
    Resource,
    canonical_digest,
)
from panel.fleet_v2.reconcile import Reconciler
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.tests.harness.memories.mieru import MemoryMieru
from panel.tests.harness.memories.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from panel.routing.document import document_digest
from panel.routing.models import PolicyInput, RoutingRule, RuleMatch
from panel.routing.service import RoutingError
from panel.secrets_store import SecretStore
from panel.tests.harness.memories.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio
NODE, MASTER = "n" * 36, "m" * 36
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": None}
NAIVE_WARP = {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}
NAIVE_BLOCK = {"schema": 1, "upstream": None, "acl": [{"deny": ["example.com"]}]}





def _egress(document, *, backend="naive_native", policy_id="p1", revision=1):
    return EgressDocument(backend=backend, policy_id=policy_id, policy_revision=revision, document=document,
                          digest=document_digest(document))


def _doc(generation=1, resources=(), egress=None):
    return GenerationDocument(node_guid=NODE, master_guid=MASTER, generation=generation, previous_generation=generation - 1,
                              created_at=1, created_by="c", resources=list(resources), egress=egress)


def _resource(user="alice"):
    return Resource(ref=f"grant:{user}", protocol="naive", runtime_username=user, desired_state="enabled",
                    credential_ref=f"grant:{user}:1", credential_origin="caller")


# -- protocol --------------------------------------------------------------------------








def test_observed_egress_is_ignored_by_an_older_central_and_tolerates_new_fields():
    report = ObservedGeneration.model_validate({
        "applied_generation": 1, "digest": "d", "reconcile_state": "converged", "resources": [], "reported_at": 1,
        "egress": {"naive": {"state": "converged", "revision": "r", "digest": "x", "error": None, "future": 1}}})
    assert report.egress["naive"].state == "converged" and report.egress["naive"].revision == "r"
    assert ObservedGeneration.model_validate({"applied_generation": 1, "digest": "d", "reconcile_state": "converged",
                                              "resources": [], "reported_at": 1}).egress == {}


# -- node: reconcile -------------------------------------------------------------------


@pytest.fixture
def node(tmp_path):
    database = Database(tmp_path / "node.sqlite3")
    apply_migrations(database)
    naive, mieru = MemoryNaive(), MemoryMieru()
    adapters = {"mtproxy": TelemtAdapter(MemoryTelemt()), "naive": NaiveAdapter(naive, public_host="n.example"),
                "mieru": MieruAdapter(mieru)}
    managed = ManagedStore(database)
    reconciler = Reconciler(database, SecretStore(Keyring.generate()), adapters, managed, guid=NODE)
    return {"database": database, "managed": managed, "reconciler": reconciler, "naive": naive, "mieru": mieru}


async def _accept(node, document, secrets=None):
    request = PushRequest(expected_guid=NODE, generation=document, secrets=secrets or {})
    with node["database"].transaction() as db:
        node["managed"].accept(db, request.generation, canonical_digest(request.generation), node_guid=NODE)
        await node["reconciler"].store_secrets(db, request)


async def test_egress_applied_after_resources_and_reported(node):
    naive = node["naive"]
    order = []
    naive.calls = order
    await _accept(node, _doc(1, [_resource()], {"naive": _egress(NAIVE_WARP)}), {"grant:alice:1": "pw-alice-alice-01"})
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "converged"
    assert [call[0] for call in order] == ["create", "egress_apply"]
    assert order[1] == ("egress_apply", f"{NODE}:1:egress:naive")
    assert naive.egress_document == NAIVE_WARP
    report = observed.egress["naive"]
    assert report.state == "converged" and report.digest == document_digest(NAIVE_WARP) and report.revision
    assert report.error is None and "mieru" not in observed.egress


async def test_egress_failure_marks_generation_failed_but_resources_applied(node):
    naive = node["naive"]
    naive.reachable = False
    await _accept(node, _doc(1, [_resource()], {"naive": _egress(NAIVE_WARP)}), {"grant:alice:1": "pw-alice-alice-01"})
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "failed"
    assert {r.runtime_username: r.state for r in observed.resources} == {"alice": "enabled"}
    assert observed.egress["naive"].state == "failed" and observed.egress["naive"].error == "egress_unreachable"
    assert naive.egress_document["upstream"] is None
    # The next apply (a re-push after the backoff) succeeds once the provider answers.
    naive.reachable = True
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "converged" and observed.egress["naive"].state == "converged"


async def test_egress_skipped_when_digest_matches(node):
    naive = node["naive"]
    await _accept(node, _doc(1, egress={"naive": _egress(NAIVE_BLOCK)}))
    await node["reconciler"].apply(1)
    applies = [call for call in naive.calls if call[0] == "egress_apply"]
    assert len(applies) == 1
    await _accept(node, _doc(2, egress={"naive": _egress(NAIVE_BLOCK, revision=2)}))
    observed, _ = await node["reconciler"].apply(2)
    assert observed.reconcile_state == "converged" and observed.egress["naive"].state == "converged"
    assert len([call for call in naive.calls if call[0] == "egress_apply"]) == 1  # the runtime already ran it
    assert observed.egress["naive"].digest == document_digest(NAIVE_BLOCK)


async def test_egress_absent_leaves_manager_untouched(node):
    naive = node["naive"]
    await _accept(node, _doc(1, egress={"naive": _egress(NAIVE_WARP)}))
    await node["reconciler"].apply(1)
    await _accept(node, _doc(2))
    observed, _ = await node["reconciler"].apply(2)
    assert observed.reconcile_state == "converged" and naive.egress_document == NAIVE_WARP
    assert len([call for call in naive.calls if call[0] == "egress_apply"]) == 1
    assert observed.egress["naive"].state == "converged"  # the last word about it stays reported
    with node["database"].transaction() as db:
        node["managed"].unlink(db)
        assert node["managed"].egress_rows(db) == {}
    assert naive.egress_document == NAIVE_WARP  # unlink never touches the data plane


async def test_egress_for_a_protocol_without_a_target_is_unsupported(node):
    node["reconciler"].adapters.pop("mieru")
    await _accept(node, _doc(1, egress={"mieru": _egress({"schema": 1, "proxies": [], "rules": []}, backend="mieru_native")}))
    observed, _ = await node["reconciler"].apply(1)
    assert observed.reconcile_state == "failed"
    assert observed.egress["mieru"].state == "unsupported" and observed.egress["mieru"].error == "egress_unsupported"
    mismatch = _egress({"schema": 1, "proxies": [], "rules": []}, backend="mieru_native")
    await _accept(node, _doc(2, egress={"naive": mismatch}))
    observed, _ = await node["reconciler"].apply(2)
    assert observed.egress["naive"].state == "unsupported"


# -- central: generation, pusher, service ------------------------------------------------


async def _link(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    return node, central, node_id


def _warp(**extra):
    return PolicyInput(default_action="egress", default_egress="warp", **extra)


def _block(*domains):
    return PolicyInput(rules=[RoutingRule(action="block", match=RuleMatch(domains=list(domains)))])


async def test_targets_for_remote_node_from_identity_json(pair):
    node, central, node_id = await _link(pair)
    items = {(i["node_id"], i["protocol"]): i for i in await central.state.routing.targets()}
    assert items[(node_id, "naive")]["reason"] == "node_offline"  # no heartbeat yet: the link is `unknown`
    await central.tick("pusher")
    items = {(i["node_id"], i["protocol"]): i for i in await central.state.routing.targets()}
    remote = items[(node_id, "naive")]
    assert remote["kind"] == "remote" and remote["egress_v1"] is True and remote["backend"] == "naive_native"
    assert remote["providers"] == {"warp": {"reachable": True}} and "block_domain" in remote["capabilities"]
    assert remote["reason"] is None and remote["mode"] == "direct"
    assert items[(node_id, "mieru")]["reason"] == "protocol_disabled_on_node"  # the node runs Naive only
    assert items[(node_id, "mtproxy")]["backend"] == "mtproxy_native"  # v1.1: Telemt's upstream, direct only
    # A node without the capability (a v0.3 panel) is shown as such.
    with central.state.database.transaction() as db:
        row = central.state.links.link(db, node_id)
        identity = {**row["identity"], "capabilities": ["generation.v1"]}
        db.execute("UPDATE node_links SET identity_json=? WHERE node_id=?", (json.dumps(identity), node_id))
    items = {(i["node_id"], i["protocol"]): i for i in await central.state.routing.targets()}
    assert items[(node_id, "naive")]["egress_v1"] is False and items[(node_id, "naive")]["reason"] == "node_lacks_egress_v1"
    preview = await central.state.routing.preview(node_id, "naive", _warp())
    assert preview.status == "unsupported" and preview.reasons[0].code == "node_lacks_egress_v1"














async def test_local_apply_is_refused_while_a_central_manages_the_node(pair):
    node, central, node_id = await _link(pair)
    assert node.state.routing.managed is node.state.managed
    routing = central.state.routing
    routing.save(node_id, "naive", _warp(), expected_revision=None, **CTX)
    await routing.apply(node_id, "naive", expected_revision=1, **CTX)
    await central.tick("pusher")
    node.state.routing.save("local", "naive", _block("x.example"), expected_revision=None, **CTX)
    with pytest.raises(RoutingError) as failure:
        await node.state.routing.apply("local", "naive", expected_revision=1, **CTX)
    assert failure.value.status == 409 and failure.value.code == "managed_by_central"
    items = {(i["node_id"], i["protocol"]): i for i in await node.state.routing.targets()}
    assert items[("local", "naive")]["reason"] == "managed_by_central"
    assert (await node.state.routing.preview("local", "naive", None)).status == "supported"  # reading stays open
