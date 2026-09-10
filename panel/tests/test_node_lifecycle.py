"""Node lifecycle: an operator-facing façade that does not widen the v1 transport."""

from __future__ import annotations

import time

import pytest

from panel.database import Database
from panel.fleet import CommandConflict, FleetStore, ProtocolError
from panel.migrations import apply_migrations
from panel.nodes import LOCAL_NODE_ID
from panel.nodes.models import CertificateInfo
from panel.nodes.read_model import derive
from panel.nodes.service import NodeConflict, NodeLifecycleService

ACTOR = {"id": 1, "username": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}


def _cert(state="active", not_after=None):
    now = int(time.time())
    return CertificateInfo("AA01", "f" * 64, now - 10, not_after or now + 86400 * 30, state, now - 10, None)


@pytest.fixture
def service(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    return NodeLifecycleService(database, FleetStore(database.path))


def test_read_model_derives_enrollment_and_connectivity():
    now = int(time.time())
    row = {"node_id": "edge-01", "display_name": "edge", "kind": "remote", "disabled": 0,
           "inventory": {"telemt_version": "3.4.25", "capabilities": ["telemt.inventory.refresh"]},
           "last_seen_at": None, "updated_at": now}
    view = derive(row, [], 0, now)
    assert (view.enrollment_state, view.connectivity_state, view.daemon_health) == ("unenrolled", "never", "reported")
    view = derive({**row, "last_seen_at": now - 10}, [_cert()], 2, now)
    assert (view.enrollment_state, view.connectivity_state, view.pending_commands) == ("enrolled", "online", 2)
    view = derive({**row, "last_seen_at": now - 600}, [_cert()], 0, now)
    assert view.connectivity_state == "stale"
    view = derive({**row, "last_seen_at": now - 10}, [_cert(state="revoked")], 0, now)
    assert view.enrollment_state == "revoked"
    assert derive({**row, "kind": "local"}, [], 0, now).connectivity_state == "not_applicable"


def test_register_writes_node_and_audit_in_one_transaction(service):
    view = service.register("edge-01", "Edge", **CTX)
    assert view.enrollment_state == "unenrolled"
    with service.database.connect() as db:
        row = db.execute("SELECT action,target,request_id FROM audit_log").fetchone()
    assert tuple(row) == ("node.register", "edge-01", "req-1")
    with pytest.raises(NodeConflict):
        service.register("edge-01", "Edge again", **CTX)


def test_disabled_node_is_rejected_by_transport_authentication(service):
    service.register("edge-01", "Edge", **CTX)
    service.fleet.bind_certificate("edge-01", {"serial": "AA01", "fingerprint_sha256": "f" * 64,
                                               "not_before": 1, "not_after": 2**31 - 1})
    assert service.fleet.authenticate_certificate("edge-01", "AA01", "f" * 64, "edge-01") is True
    service.set_disabled("edge-01", True, **CTX)
    assert service.fleet.authenticate_certificate("edge-01", "AA01", "f" * 64, "edge-01") is False
    service.set_disabled("edge-01", False, **CTX)
    assert service.fleet.authenticate_certificate("edge-01", "AA01", "f" * 64, "edge-01") is True


def test_disable_refuses_while_commands_are_pending(service):
    service.register("edge-01", "Edge", **CTX)
    service.fleet.enqueue("edge-01", "disable-alice-1", "telemt.user.disable", {"username": "alice"}, "rev-1")
    with pytest.raises(NodeConflict, match="pending"):
        service.set_disabled("edge-01", True, **CTX)


def test_revoke_all_requires_typed_confirmation(service):
    service.register("edge-01", "Edge", **CTX)
    service.fleet.bind_certificate("edge-01", {"serial": "AA01", "fingerprint_sha256": "f" * 64,
                                               "not_before": 1, "not_after": 2**31 - 1})
    with pytest.raises(NodeConflict, match="confirm"):
        service.revoke_all_certificates("edge-01", confirm="wrong", **CTX)
    assert service.revoke_all_certificates("edge-01", confirm="edge-01", **CTX) == 1
    assert service.get("edge-01").enrollment_state == "revoked"


def test_local_node_has_no_transport_certificates_or_disable(service):
    # Migration 5 put the row there: the service never has to create it.
    view = service.local()
    assert (view.node_id, view.kind) == (LOCAL_NODE_ID, "local")
    assert (view.enrollment_state, view.connectivity_state) == ("local", "not_applicable")
    with pytest.raises(CommandConflict, match="local node"):
        service.fleet.enqueue("local", "refresh-1", "telemt.inventory.refresh", {}, "rev-1")
    with pytest.raises(CommandConflict, match="local node"):
        service.fleet.poll_next("local")
    with pytest.raises(ProtocolError, match="local node"):
        service.fleet.bind_certificate("local", {"serial": "BB02", "fingerprint_sha256": "a" * 64,
                                                 "not_before": 1, "not_after": 2**31 - 1})
    assert service.fleet.authenticate_certificate("local", "BB02", "a" * 64, "local") is False
    with pytest.raises(NodeConflict, match="local node"):
        service.set_disabled("local", True, **CTX)
    with pytest.raises(NodeConflict, match="local node"):
        service.revoke_all_certificates("local", confirm="local", **CTX)


def test_local_node_is_listed_first_and_can_be_renamed(service):
    service.register("edge-01", "Edge", **CTX)
    service.register("aaa-01", "Aaa", **CTX)
    # Sorted by node_id the local row would land last; the operator's own host comes first.
    assert [view.node_id for view in service.list()] == ["local", "aaa-01", "edge-01"]
    service.rename("local", "Амстердам", **CTX)
    assert service.local().display_name == "Амстердам"


def test_the_local_node_id_cannot_be_registered_again(service):
    with pytest.raises(ProtocolError, match="reserved"):
        service.register("local", "Impostor", **CTX)
    assert service.local().display_name == "Этот сервер"


def test_a_failed_mutation_leaves_neither_row_nor_audit(service):
    service.register("edge-01", "Edge", **CTX)
    with pytest.raises(NodeConflict):
        service.register("edge-01", "Duplicate", **CTX)
    with service.database.connect() as db:
        # One registered node next to the reserved local row, and one audit line for it.
        assert db.execute("SELECT count(*) FROM fleet_nodes WHERE kind='remote'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 1
