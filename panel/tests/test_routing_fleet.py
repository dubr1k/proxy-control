"""Routing over Fleet v2 (spec §8.3): the egress section of a generation, the node applying
it after its resources, and the central absorbing the node's report into the policy."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from panel.clients.models import GrantIntent, NaiveOptions
from panel.database import Database
from panel.fleet_v2.generations import compile as compile_generation
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
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from panel.routing.document import document_digest
from panel.routing.models import PolicyInput, RoutingRule, RuleMatch
from panel.routing.service import RoutingError
from panel.secrets_store import SecretStore
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio
NODE, MASTER = "n" * 36, "m" * 36
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": None}
NAIVE_WARP = {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}
NAIVE_BLOCK = {"schema": 1, "upstream": None, "acl": [{"deny": ["example.com"]}]}


@pytest.fixture
def anyio_backend():
    return "asyncio"


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


def test_egress_section_is_part_of_the_digest_and_omitted_when_absent():
    plain = _doc()
    assert "egress" not in plain.wire() and "egress" not in PushRequest(expected_guid=NODE, generation=plain).wire()["generation"]
    assert canonical_digest(plain) == canonical_digest(GenerationDocument.model_validate(plain.wire()))
    with_egress = _doc(egress={"naive": _egress(NAIVE_WARP)})
    assert with_egress.wire()["egress"]["naive"]["digest"] == document_digest(NAIVE_WARP)
    assert canonical_digest(with_egress) != canonical_digest(plain)
    assert canonical_digest(with_egress) != canonical_digest(_doc(egress={"naive": _egress(NAIVE_BLOCK)}))
    # A v0.3 node's strict model is what `_doc(...).wire()` without egress satisfies; an unknown
    # key would be a 422 there — here, the same rule refuses mtproxy and unknown fields.
    with pytest.raises(ValidationError):
        _doc(egress={"mtproxy": _egress(NAIVE_WARP)})
    with pytest.raises(ValidationError):
        GenerationDocument.model_validate({**plain.wire(), "egress": {"naive": {**_egress(NAIVE_WARP).model_dump(), "x": 1}}})


def test_egress_document_validates_digest_and_size():
    with pytest.raises(ValidationError):
        EgressDocument(backend="naive_native", policy_id="p", policy_revision=1, document=NAIVE_WARP, digest="0" * 64)
    huge = {"schema": 1, "upstream": None, "acl": [{"deny": [f"{'x' * 60}{i:04d}.example" for i in range(300)]}]}
    with pytest.raises(ValidationError):
        _egress(huge)
    with pytest.raises(ValidationError):
        EgressDocument(backend="xray", policy_id="p", policy_revision=1, document=NAIVE_WARP, digest=document_digest(NAIVE_WARP))


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
    await central.state.pusher.tick()
    items = {(i["node_id"], i["protocol"]): i for i in await central.state.routing.targets()}
    remote = items[(node_id, "naive")]
    assert remote["kind"] == "remote" and remote["egress_v1"] is True and remote["backend"] == "naive_native"
    assert remote["providers"] == {"warp": {"reachable": True}} and "block_domain" in remote["capabilities"]
    assert remote["reason"] is None and remote["mode"] == "direct"
    assert items[(node_id, "mieru")]["reason"] == "protocol_disabled_on_node"  # the node runs Naive only
    assert items[(node_id, "mtproxy")]["reason"] == "protocol_out_of_scope"
    # A node without the capability (a v0.3 panel) is shown as such.
    with central.state.database.transaction() as db:
        row = central.state.links.link(db, node_id)
        identity = {**row["identity"], "capabilities": ["generation.v1"]}
        db.execute("UPDATE node_links SET identity_json=? WHERE node_id=?", (json.dumps(identity), node_id))
    items = {(i["node_id"], i["protocol"]): i for i in await central.state.routing.targets()}
    assert items[(node_id, "naive")]["egress_v1"] is False and items[(node_id, "naive")]["reason"] == "node_lacks_egress_v1"
    preview = await central.state.routing.preview(node_id, "naive", _warp())
    assert preview.status == "unsupported" and preview.reasons[0].code == "node_lacks_egress_v1"


async def test_compile_includes_only_desired_sections_for_an_egress_v1_node(pair):
    node, central, node_id = await _link(pair)
    routing = central.state.routing
    routing.save(node_id, "naive", _warp(), expected_revision=None, **CTX)  # a draft: not published
    with central.state.database.connect() as db:
        doc = compile_generation(db, central.state.clients.store, node_id=node_id, node_guid=node_id, master_guid="m",
                                 previous=0, generation=1, now=1, created_by="t", routing=routing.store)
        assert doc.egress is None
        policy = routing.store.get(db, node_id, "naive")
        routing.store.set_desired(db, policy.id, {"backend": "naive_native", "policy_id": policy.id, "policy_revision": 1,
                                                  "document": NAIVE_WARP, "digest": document_digest(NAIVE_WARP)})
        doc = compile_generation(db, central.state.clients.store, node_id=node_id, node_guid=node_id, master_guid="m",
                                 previous=0, generation=1, now=1, created_by="t", routing=routing.store)
        assert doc.egress["naive"].policy_id == policy.id and doc.egress["naive"].document == NAIVE_WARP
        # Without the capability the section is left out, whatever the policies say.
        db.execute("UPDATE node_links SET identity_json=? WHERE node_id=?", (json.dumps({"capabilities": []}), node_id))
        doc = compile_generation(db, central.state.clients.store, node_id=node_id, node_guid=node_id, master_guid="m",
                                 previous=0, generation=1, now=1, created_by="t", routing=routing.store)
        assert doc.egress is None
        # And a central without a routing store compiles as before.
        doc = compile_generation(db, central.state.clients.store, node_id=node_id, node_guid=node_id, master_guid="m",
                                 previous=0, generation=1, now=1, created_by="t")
        assert doc.egress is None


async def test_routing_apply_remote_publishes_generation_and_the_report_marks_it_applied(pair):
    node, central, node_id = await _link(pair)
    routing = central.state.routing
    routing.save(node_id, "naive", _warp(), expected_revision=None, **CTX)
    result = await routing.apply(node_id, "naive", expected_revision=1, **CTX)
    assert result["policy"].state == "applying" and result["applied"] is None
    with central.state.database.connect() as db:
        latest = central.state.desired.latest(db, node_id)
        assert latest["document"].egress["naive"].digest == result["compiled"].digest
        assert central.state.links.link(db, node_id)["config_dirty"] == 1
    await central.state.pusher.tick()
    assert node.state.naive.egress_document == NAIVE_WARP
    policy = routing.get(node_id, "naive")
    assert policy.state == "applied" and policy.applied_revision == 1 and policy.applied_current is True
    assert policy.applied_digest == document_digest(NAIVE_WARP)
    history = routing.history(node_id, "naive")
    assert [row["outcome"] for row in history] == ["applied"] and history[0]["actor"] == "node"
    assert history[0]["document"] == NAIVE_WARP and json.loads(history[0]["detail"])["generation"] == latest["generation"]
    # Another tick changes nothing: one history row per outcome.
    await central.state.pusher.tick()
    assert len(routing.history(node_id, "naive")) == 1
    # The target now reflects the node's applied digest; the preview shows no diff.
    preview = await routing.preview(node_id, "naive", None)
    assert preview.status == "supported" and preview.diff == [] and preview.rollback["to_digest"] == policy.applied_digest
    # A grant change republishes with the same egress section; the node re-applies nothing.
    client = central.state.clients.create_client("Alice", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    assert len([c for c in node.state.naive.calls if c[0] == "egress_apply"]) == 1
    assert routing.get(node_id, "naive").state == "applied"


async def test_pusher_marks_policy_failed_with_the_node_error(pair):
    node, central, node_id = await _link(pair)
    routing = central.state.routing
    routing.save(node_id, "naive", _warp(), expected_revision=None, **CTX)
    await routing.apply(node_id, "naive", expected_revision=1, **CTX)
    node.state.naive.reachable = False
    await central.state.pusher.tick()
    policy = routing.get(node_id, "naive")
    assert policy.state == "failed" and policy.last_error == "egress_unreachable" and policy.applied_revision is None
    assert [row["outcome"] for row in routing.history(node_id, "naive")] == ["failed"]
    items = {(i["node_id"], i["protocol"]): i for i in await routing.targets()}
    assert items[(node_id, "naive")]["policy"]["last_error"] == "egress_unreachable"
    await central.state.pusher.tick()
    assert len(routing.history(node_id, "naive")) == 1
    # Once the provider answers, the re-push (after the backoff) converges.
    node.state.naive.reachable = True
    central.state.pusher._backoff.clear()
    await central.state.pusher.tick()
    policy = routing.get(node_id, "naive")
    assert policy.state == "applied" and policy.applied_revision == 1


async def test_routing_rollback_remote_publishes_previous_document(pair):
    node, central, node_id = await _link(pair)
    routing = central.state.routing
    with pytest.raises(RoutingError) as failure:
        routing.save(node_id, "naive", _block("example.com"), expected_revision=None, **CTX)
        await routing.rollback(node_id, "naive", expected_revision=1, **CTX)
    assert failure.value.code == "egress_no_previous"
    await routing.apply(node_id, "naive", expected_revision=1, **CTX)
    await central.state.pusher.tick()
    routing.save(node_id, "naive", _warp(), expected_revision=1, **CTX)
    await routing.apply(node_id, "naive", expected_revision=2, **CTX)
    await central.state.pusher.tick()
    assert node.state.naive.egress_document == NAIVE_WARP
    result = await routing.rollback(node_id, "naive", expected_revision=2, **CTX)
    assert result["policy"].state == "applying" and result["compiled"].document == NAIVE_BLOCK
    await central.state.pusher.tick()
    policy = routing.get(node_id, "naive")
    assert node.state.naive.egress_document == NAIVE_BLOCK
    assert policy.state == "applied" and policy.applied_revision == 1 and policy.applied_current is False
    assert [row["outcome"] for row in routing.history(node_id, "naive")] == ["applied", "rolled_back", "applied", "applied"]
    audit = central.state.store.audits(action="routing.policy.rollback")
    assert audit and audit[0]["detail"]["to_revision"] == 1


async def test_local_apply_is_refused_while_a_central_manages_the_node(pair):
    node, central, node_id = await _link(pair)
    assert node.state.routing.managed is node.state.managed
    routing = central.state.routing
    routing.save(node_id, "naive", _warp(), expected_revision=None, **CTX)
    await routing.apply(node_id, "naive", expected_revision=1, **CTX)
    await central.state.pusher.tick()
    node.state.routing.save("local", "naive", _block("x.example"), expected_revision=None, **CTX)
    with pytest.raises(RoutingError) as failure:
        await node.state.routing.apply("local", "naive", expected_revision=1, **CTX)
    assert failure.value.status == 409 and failure.value.code == "managed_by_central"
    items = {(i["node_id"], i["protocol"]): i for i in await node.state.routing.targets()}
    assert items[("local", "naive")]["reason"] == "managed_by_central"
    assert (await node.state.routing.preview("local", "naive", None)).status == "supported"  # reading stays open
