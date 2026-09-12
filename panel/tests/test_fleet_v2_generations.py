import pytest

from panel.clients.models import AccessGrant, MtproxyOptions, NaiveOptions
from panel.clients.store import ClientStore
from panel.database import Database
from panel.fleet_v2.generations import DesiredStore, compile, content_digest, publish
from panel.fleet_v2.protocol import ObservedGeneration, ObservedResource, canonical_digest
from panel.migrations import apply_migrations
from panel.nodes.registry import NodeRegistry

NODE = "1" * 36


@pytest.fixture
def world(tmp_path):
    database = Database(tmp_path / "p.sqlite3")
    apply_migrations(database)
    store = ClientStore(database)
    with database.transaction() as db:
        NodeRegistry.insert(db, NODE, "Edge", transport="panel")
        db.execute("""INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,created_at,updated_at)
                      VALUES(?,?,?,?,0,0)""", (NODE, "https://edge.example", "verify", "node-key:x"))
        db.execute("INSERT INTO clients VALUES('c1','Alice','active','{}',0,0)")
        store.insert_grant(db, AccessGrant(id="g1", client_id="c1", protocol="naive", node_id=NODE,
                                           runtime_username="alice", secret_ref=None, desired_state="enabled",
                                           options=NaiveOptions(quota_bytes=10), origin="provisioned",
                                           created_at=0, updated_at=0))
    return database, store


def test_compile_is_pure_and_secret_free(world):
    database, store = world
    with database.connect() as db:
        doc = compile(db, store, node_id=NODE, node_guid=NODE, master_guid="m", previous=0, generation=1, now=5, created_by="t")
    assert [r.ref for r in doc.resources] == ["grant:g1"]
    assert doc.resources[0].credential_ref == "grant:g1:1" and doc.resources[0].options == {"quota_bytes": 10}
    with database.connect() as db:
        again = compile(db, store, node_id=NODE, node_guid=NODE, master_guid="m", previous=0, generation=1, now=5, created_by="t")
    assert canonical_digest(doc) == canonical_digest(again)


def test_publish_skips_when_nothing_changed_and_bumps_otherwise(world):
    database, store = world
    desired = DesiredStore(database)
    with database.transaction() as db:
        assert publish(db, store, desired, node_id=NODE, master_guid="m", created_by="t") == 1
        assert publish(db, store, desired, node_id=NODE, master_guid="m", created_by="t") is None
        store.update_grant(db, "g1", desired_state="disabled", updated_at=1)
        assert publish(db, store, desired, node_id=NODE, master_guid="m", created_by="t") == 2
        latest = desired.latest(db, NODE)
        link = db.execute("SELECT config_dirty, desired_generation FROM node_links WHERE node_id=?", (NODE,)).fetchone()
    assert latest["generation"] == 2 and latest["document"].previous_generation == 1
    assert tuple(link) == (1, 2)


# --- additional coverage beyond the brief's Step 2 tests ---

def test_content_digest_ignores_numbering_and_time_but_not_resources(world):
    database, store = world
    with database.connect() as db:
        first = compile(db, store, node_id=NODE, node_guid=NODE, master_guid="m", previous=0, generation=1, now=5, created_by="t")
        renumbered = compile(db, store, node_id=NODE, node_guid=NODE, master_guid="m", previous=3, generation=4, now=99,
                             created_by="someone-else")
    assert canonical_digest(first) != canonical_digest(renumbered)
    assert content_digest(first) == content_digest(renumbered)
    with database.transaction() as db:
        store.update_grant(db, "g1", desired_state="disabled", updated_at=1)
        changed = compile(db, store, node_id=NODE, node_guid=NODE, master_guid="m", previous=0, generation=1, now=5, created_by="t")
    assert content_digest(changed) != content_digest(first)


def test_compile_omits_grants_the_node_already_confirmed_gone_but_keeps_pending_deletions(world):
    database, store = world
    with database.transaction() as db:
        db.execute("INSERT INTO clients VALUES('c2','Bob','active','{}',0,0)")
        store.insert_grant(db, AccessGrant(id="g2", client_id="c2", protocol="naive", node_id=NODE,
                                           runtime_username="bob", secret_ref=None, desired_state="deleted",
                                           observed_state="enabled", options=NaiveOptions(), origin="imported",
                                           created_at=1, updated_at=1))
        store.insert_grant(db, AccessGrant(id="g3", client_id="c2", protocol="naive", node_id=NODE,
                                           runtime_username="carol", secret_ref=None, desired_state="deleted",
                                           observed_state="missing", options=NaiveOptions(), origin="imported",
                                           created_at=2, updated_at=2))
        doc = compile(db, store, node_id=NODE, node_guid=NODE, master_guid="m", previous=0, generation=1, now=5, created_by="t")
    states = {r.ref: r.desired_state for r in doc.resources}
    # g2 still has to be deleted on the node; g3 was already reported missing (spec §5.2).
    assert states == {"grant:g1": "enabled", "grant:g2": "deleted"}


def test_compile_leaves_mtproxy_expiration_out_of_the_options(world):
    database, store = world
    with database.transaction() as db:
        store.insert_grant(db, AccessGrant(id="g4", client_id="c1", protocol="mtproxy", node_id=NODE,
                                           runtime_username="alice", secret_ref=None, desired_state="enabled",
                                           options=MtproxyOptions(data_quota_bytes=5, expiration=1234567890, host="h", port=443),
                                           origin="provisioned", created_at=3, updated_at=3))
        doc = compile(db, store, node_id=NODE, node_guid=NODE, master_guid="m", previous=0, generation=1, now=5, created_by="t")
    mtproxy = next(r for r in doc.resources if r.ref == "grant:g4")
    assert mtproxy.options == {"data_quota_bytes": 5, "host": "h", "port": 443}


def test_publish_records_an_empty_generation_for_a_node_without_grants(world):
    database, store = world
    desired = DesiredStore(database)
    other = "2" * 36
    with database.transaction() as db:
        NodeRegistry.insert(db, other, "Other", transport="panel")
        db.execute("""INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,created_at,updated_at)
                      VALUES(?,?,?,?,0,0)""", (other, "https://other.example", "verify", "node-key:y"))
        # An empty desired set is still a generation: the first publish records "nothing".
        assert publish(db, store, desired, node_id=other, master_guid="m") == 1
        assert publish(db, store, desired, node_id=other, master_guid="m") is None
        assert desired.latest(db, other)["document"].resources == []
        assert desired.latest(db, NODE) is None


def test_observed_round_trips_and_a_converged_report_clears_config_dirty(world):
    database, store = world
    desired = DesiredStore(database)
    with database.transaction() as db:
        assert publish(db, store, desired, node_id=NODE, master_guid="m") == 1
        desired.mark_pushed(db, NODE, 1)
        assert desired.observed(db, NODE) is None
        applying = ObservedGeneration(applied_generation=1, digest="d", reconcile_state="applying",
                                      resources=[], reported_at=7)
        desired.record_observed(db, NODE, applying)
        link = db.execute("SELECT config_dirty, acknowledged_generation FROM node_links WHERE node_id=?", (NODE,)).fetchone()
        assert tuple(link) == (1, 0)
        converged = ObservedGeneration(applied_generation=1, digest="d", reconcile_state="converged",
                                       resources=[ObservedResource(ref="grant:g1", protocol="naive", runtime_username="alice",
                                                                   state="enabled", revision="r1")],
                                       reported_at=8)
        desired.record_observed(db, NODE, converged)
        assert desired.observed(db, NODE) == converged
        link = db.execute("SELECT config_dirty, acknowledged_generation FROM node_links WHERE node_id=?", (NODE,)).fetchone()
        latest = desired.latest(db, NODE)
    assert tuple(link) == (0, 1)
    assert latest["pushed_at"] is not None and latest["acknowledged_at"] is not None


def test_a_converged_report_for_an_older_generation_keeps_the_link_dirty(world):
    database, store = world
    desired = DesiredStore(database)
    with database.transaction() as db:
        assert publish(db, store, desired, node_id=NODE, master_guid="m") == 1
        store.update_grant(db, "g1", desired_state="disabled", updated_at=1)
        assert publish(db, store, desired, node_id=NODE, master_guid="m") == 2
        desired.record_observed(db, NODE, ObservedGeneration(applied_generation=1, digest="d", reconcile_state="converged",
                                                             resources=[], reported_at=9))
        link = db.execute("SELECT config_dirty, desired_generation, acknowledged_generation FROM node_links WHERE node_id=?",
                          (NODE,)).fetchone()
    assert tuple(link) == (1, 2, 1)
