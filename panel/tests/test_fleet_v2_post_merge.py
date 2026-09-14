"""v0.3 post-merge fix-wave, central side (`docs/superpowers/plans/2026-09-14-v0.3-post-merge-issues.md`).

Each test names the review item it closes. All run against the in-process `pair`
(node panel + central panel) from `conftest.py`; nothing here sleeps.
"""
import asyncio
import json

import httpx
import pytest

from panel.clients.models import GrantIntent, MtproxyOptions, NaiveOptions
from panel.fleet_v2.client import NodeClient, NodeRejected
from panel.fleet_v2.links import LinkConflict
from panel.fleet_v2.protocol import ObservedGeneration, ObservedResource
from panel.secrets_store import SecretError

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}


async def _link(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    client = central.state.clients.create_client("Alice", actor=ACTOR, ip="x")
    return node, central, node_id, client


def _link_row(central, node_id) -> dict:
    with central.state.database.connect() as db:
        return central.state.links.link(db, node_id)


def _events(central) -> list[str]:
    return [e["name"] for e in central.state.events.since(0, 100) if e["name"].startswith("node.")]


class _Answering(httpx.AsyncBaseTransport):
    """The node answers `status` for a given path with `code` while `broken`; every other path is real."""

    def __init__(self, inner, path: str, code: int, body=None):
        self.inner, self.path, self.code, self.body, self.broken, self.hits = inner, path, code, body, True, 0

    async def handle_async_request(self, request):
        if request.url.path == self.path and self.broken:
            self.hits += 1
            if isinstance(self.body, bytes):
                return httpx.Response(self.code, content=self.body, headers={"content-type": "application/json"})
            return httpx.Response(self.code, json=self.body if self.body is not None else {"detail": "busy"})
        return await self.inner.handle_async_request(request)


def _transport(central, node, transport) -> None:
    central.state.links.client_factory = lambda url, key, **kw: NodeClient(url, key, transport=transport, **kw)


# --- [T9] NodeRejected 429/5xx: the node is up but refusing; not `offline`, no `node.down` ---

@pytest.mark.parametrize("code", [429, 500, 503])
async def test_a_429_or_5xx_heartbeat_answer_is_not_offline(pair, code):
    node, central, node_id, client = await _link(pair)
    await central.state.pusher.tick()
    assert _link_row(central, node_id)["status"] == "online"
    transport = _Answering(httpx.ASGITransport(app=node), "/api/fleet/v2/identity", code)
    _transport(central, node, transport)
    await central.state.pusher.tick()
    link = _link_row(central, node_id)
    assert link["status"] == "online" and link["last_error"] == f"NodeRejected: {code}"
    assert _events(central) == ["node.up"]
    transport.broken = False
    await central.state.pusher.tick()
    assert _link_row(central, node_id)["last_error"] is None and _events(central) == ["node.up"]


async def test_a_404_heartbeat_answer_is_still_offline(pair):
    """Anything else the node refuses (a panel without Fleet v2 at that URL) stays a down link."""
    node, central, node_id, client = await _link(pair)
    await central.state.pusher.tick()
    _transport(central, node, _Answering(httpx.ASGITransport(app=node), "/api/fleet/v2/identity", 404))
    await central.state.pusher.tick()
    assert _link_row(central, node_id)["status"] == "offline" and _events(central) == ["node.up", "node.down"]


async def test_a_refusing_node_does_not_get_a_push_until_it_answers_again(pair):
    node, central, node_id, client = await _link(pair)
    await central.state.pusher.tick()
    transport = _Answering(httpx.ASGITransport(app=node), "/api/fleet/v2/status", 503)
    _transport(central, node, transport)
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    assert "alice" not in [u["username"] for u in await node.state.naive.list_users()]
    assert _link_row(central, node_id)["status"] == "online"
    transport.broken = False
    await central.state.pusher.tick()
    assert "alice" in [u["username"] for u in await node.state.naive.list_users()]


# --- [T8] heartbeat bodies are bounded like a push ---

async def test_an_oversized_heartbeat_body_is_refused_before_it_is_parsed(pair):
    from panel.fleet_v2 import client as client_module

    node, central, node_id, client = await _link(pair)
    await central.state.pusher.tick()
    huge = b'{"guid": "' + b"x" * (client_module.MAX_RESPONSE_BYTES + 1) + b'"}'
    _transport(central, node, _Answering(httpx.ASGITransport(app=node), "/api/fleet/v2/identity", 200, huge))
    with pytest.raises(NodeRejected) as caught:
        await central.state.links.client_for(node_id).identity()
    assert caught.value.code == "response_too_large"
    await central.state.pusher.tick()
    assert _link_row(central, node_id)["status"] == "offline"


# --- [T9]/[T10] escrow: only a report about the generation the central wants now ---

def _escrowed(central, node_id, grant) -> str:
    with central.state.database.connect() as db:
        return central.state.secrets.reveal(db, grant.secret_ref, purpose="grant.credential", grant_id=grant.id,
                                            permitted_node_id=node_id).decode()


async def test_a_late_report_about_an_older_generation_never_escrows(pair):
    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username="alice", options=MtproxyOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    escrowed = _escrowed(central, node_id, grant)
    assert escrowed.startswith("ee")
    # A second generation for the same version (the grant is disabled meanwhile).
    await central.state.lifecycle.set_enabled(grant.id, False, actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        assert central.state.desired.latest(db, node_id)["generation"] == 2
    stale = ObservedGeneration(applied_generation=1, digest="d", reconcile_state="converged", reported_at=1, resources=[
        ObservedResource(ref=f"grant:{grant.id}", protocol="mtproxy", runtime_username="alice", state="enabled")])
    central.state.pusher._absorb(node_id, stale, {f"grant:{grant.id}:1": "eestale"})
    assert _escrowed(central, node_id, grant) == escrowed


async def test_escrowing_the_same_plaintext_again_does_not_rewrite_the_version(pair):
    """[re-review] every push/poll of a converged Telemt grant used to DELETE+INSERT the active
    version; an unchanged value leaves the row (and its `created_at`) alone."""
    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username="alice", options=MtproxyOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    plaintext = _escrowed(central, node_id, grant)

    def row():
        with central.state.database.connect() as db:
            return tuple(db.execute("SELECT state, created_at, nonce FROM secret_versions WHERE secret_id=? AND version=1",
                                    (f"grant:{grant.id}",)).fetchone())

    before = row()
    with central.state.database.transaction() as db:
        central.state.provisioning.escrow_returned_credential(db, grant.id, f"grant:{grant.id}:1", plaintext)
    assert row() == before
    with central.state.database.transaction() as db:
        central.state.provisioning.escrow_returned_credential(db, grant.id, f"grant:{grant.id}:1", "eeother")
    after = row()
    assert after[0] == "active" and after[2] != before[2] and _escrowed(central, node_id, grant) == "eeother"


async def test_escrow_of_an_unchanged_pending_value_activates_it_in_place(pair):
    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    with central.state.database.connect() as db:
        pending = central.state.secrets.reveal(db, grant.secret_ref, purpose="grant.credential", grant_id=grant.id,
                                               permitted_node_id=node_id).decode()
        nonce = db.execute("SELECT nonce FROM secret_versions WHERE secret_id=?", (f"grant:{grant.id}",)).fetchone()[0]
    with central.state.database.transaction() as db:
        central.state.provisioning.escrow_returned_credential(db, grant.id, f"grant:{grant.id}:1", pending)
    with central.state.database.connect() as db:
        row = db.execute("SELECT state, nonce FROM secret_versions WHERE secret_id=?", (f"grant:{grant.id}",)).fetchone()
    assert (row["state"], row["nonce"]) == ("active", nonce)


# --- [round 3, N4] a credential the node never captures: backoff and a visible reason ---

async def test_repeatedly_uncaptured_credential_defers_the_push_and_names_the_reason(pair, monkeypatch):
    from panel.fleet_v2 import node_routes, pusher as pusher_module

    node, central, node_id, client = await _link(pair)
    create = node.state.telemt.create_user

    async def slow_create(*args, **kwargs):
        await asyncio.sleep(0.05)
        return await create(*args, **kwargs)

    monkeypatch.setattr(node.state.telemt, "create_user", slow_create)
    monkeypatch.setattr(node_routes, "APPLY_DEADLINE", 0.001)
    intent = GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username="alice", options=MtproxyOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()  # 202
    await asyncio.sleep(0.1)

    async def nothing(ref):
        return None

    monkeypatch.setattr(node.state.adapters["mtproxy"], "capture", nothing)
    for _ in range(pusher_module.WITHHELD_TICKS_BEFORE_BACKOFF):
        await central.state.pusher.tick()
    status = central.state.provisioning.status(operation)
    step = status["steps"][0]
    assert status["status"] == "pending_remote" and step["status"] == "remote"
    assert step["error"] == "credential not captured yet"
    assert node_id in central.state.pusher._backoff
    assert _link_row(central, node_id)["status"] == "online"


# --- [T11] links: set_disabled without a `links` attribute, SecretError on update, dry probe ---

async def test_update_without_a_secret_store_is_a_409_with_a_code(pair, login_user):
    node, central, node_id, client = await _link(pair)
    central.state.secrets._keyring = None
    with pytest.raises(SecretError):
        central.state.links.update(node_id, api_key="pc_new_key", actor=ACTOR, ip="x")
    transport = httpx.ASGITransport(app=central)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        central.state.store.create_admin("owner", "correct horse battery staple", "owner")
        await login_user(http)
        csrf = http.cookies["panel_csrf"]
        response = await http.post(f"/api/nodes/{node_id}/link", json={"api_key": "pc_new_key"},
                                   headers={"X-CSRF-Token": csrf})
    assert response.status_code == 409 and response.json()["code"] == "secret_store_disabled"


async def test_probe_of_a_paused_link_only_heartbeats(pair):
    node, central, node_id, client = await _link(pair)
    await central.state.pusher.tick()
    central.state.links.set_enabled(node_id, False, actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.sync_node(node_id)
    assert "alice" not in [u["username"] for u in await node.state.naive.list_users()]
    assert _link_row(central, node_id)["last_heartbeat_at"] is not None


# --- [re-review, I4] a dead node: the owner can force the deletion, audited ---

async def test_force_delete_removes_a_node_with_an_unconfirmed_deletion(pair):
    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    await central.state.lifecycle.delete(grant.id, actor=ACTOR, ip="x")  # the node never confirms it

    def dead(url, key, **kw):
        from panel.fleet_v2.client import NodeUnreachable

        class Dead:
            async def unlink(self):
                raise NodeUnreachable("ConnectError")

        return Dead()

    central.state.links.client_factory = dead
    with pytest.raises(LinkConflict):
        await central.state.links.delete(node_id, actor=ACTOR, ip="x")
    await central.state.links.delete(node_id, actor=ACTOR, ip="x", force=True)
    with central.state.database.connect() as db:
        assert db.execute("SELECT count(*) FROM node_links").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM access_grants WHERE node_id=?", (node_id,)).fetchone()[0] == 0
        audit = json.loads(db.execute("SELECT detail_json FROM audit_log WHERE action='node.unlink'").fetchone()[0])
    assert audit["forced"] is True and audit["abandoned_provisioned"] == 1
    assert audit["node_released"] is False and audit["node_error"] == "NodeUnreachable"


async def test_delete_with_imported_and_provisioned_grants_is_refused_and_keeps_the_imported_credential(pair):
    """[T14] the refusal covers the provisioned grant only; nothing about the imported one changes."""
    from panel.fleet_v2.importing import ImportItem, import_resources

    node, central, node_id, client = await _link(pair)
    node.state.naive.seed("legacy", "pw-legacy")
    await import_resources(central.state, node_id, [ImportItem("naive", "legacy", "new")], actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    with pytest.raises(LinkConflict, match="provisioned grant"):
        await central.state.links.delete(node_id, actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        grants = {g.runtime_username: g for g in central.state.clients.store.grants(db, node_id=node_id)}
        imported = grants["legacy"]
        state = db.execute("SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
                           (imported.secret_ref.secret_id, imported.secret_ref.version)).fetchone()[0]
        assert state == "active" and db.execute("SELECT count(*) FROM node_links").fetchone()[0] == 1
    assert _escrowed(central, node_id, imported) == "pw-legacy"
    assert set(grants) == {"legacy", "alice"}


async def test_unlink_audit_names_the_class_of_the_swallowed_error(pair):
    node, central, node_id, client = await _link(pair)
    _transport(central, node, _Answering(httpx.ASGITransport(app=node), "/api/fleet/v2/unlink", 503))
    await central.state.links.delete(node_id, actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        audit = json.loads(db.execute("SELECT detail_json FROM audit_log WHERE action='node.unlink'").fetchone()[0])
    assert audit["node_released"] is False and audit["node_error"] == "NodeRejected: 503"


# --- [round 3] subscriptions never render a `pending` version ---

async def test_a_pending_credential_version_is_not_rendered(pair):
    from panel.fleet_v2.central_routes import public_hosts_for
    from panel.subscriptions.renderers.base import resolve_artifacts

    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username="alice", options=MtproxyOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    subscription, _token = central.state.subscriptions.create(client.id, actor=ACTOR, ip="x")

    def artifacts():
        manifest = central.state.subscriptions.effective_manifest(subscription, 10**9)
        with central.state.database.connect() as db:
            return resolve_artifacts(manifest, central.state.secrets, central.state.adapters, db,
                                     public_hosts=lambda nid: public_hosts_for(central.state, nid))

    assert artifacts() == {}  # the version is `pending`: the bare secret is not a link yet
    await central.state.pusher.tick()
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    assert "tg://proxy" in artifacts()[grant.id][0].value


# --- [round 3] imported Telemt grants without a credential are captured on the poll too ---

async def test_an_imported_grant_without_a_credential_is_captured_after_a_202(pair, monkeypatch):
    from panel.fleet_v2 import node_routes
    from panel.fleet_v2.importing import ImportItem, import_resources

    node, central, node_id, client = await _link(pair)
    await node.state.telemt.create_user("legacy")
    # The node cannot answer the capture at import time: the grant lands without a secret.
    telemt_adapter = node.state.adapters["mtproxy"]
    capture = telemt_adapter.capture

    async def nothing(ref):
        return None

    monkeypatch.setattr(telemt_adapter, "capture", nothing)
    await import_resources(central.state, node_id, [ImportItem("mtproxy", "legacy", "new")], actor=ACTOR, ip="x")

    def legacy():
        with central.state.database.connect() as db:
            return next(g for g in central.state.clients.store.grants(db, node_id=node_id) if g.runtime_username == "legacy")

    assert legacy().secret_ref is None
    monkeypatch.setattr(telemt_adapter, "capture", capture)
    monkeypatch.setattr(node_routes, "APPLY_DEADLINE", 0.001)
    apply = node.state.reconciler.apply

    async def slow_apply(generation):
        await asyncio.sleep(0.05)
        return await apply(generation)

    monkeypatch.setattr(node.state.reconciler, "apply", slow_apply)
    await central.state.pusher.tick()  # 202
    await asyncio.sleep(0.1)
    await central.state.pusher.tick()  # the poll captures the imported user's live link
    grant = legacy()
    assert grant.secret_ref is not None
    assert _escrowed(central, node_id, grant) == (await node.state.telemt.current_access("legacy"))["secret"]


# --- [fix wave, I2] one Telemt inventory read per apply, not one per resource ---

async def test_telemt_client_batches_inventory_reads_until_a_link_changes():
    from panel.telemt import TelemtClient

    reads = []

    def handler(request):
        reads.append((request.method, request.url.path))
        if request.method == "GET":
            return httpx.Response(200, json={"ok": True, "data": [
                {"username": "u1", "enabled": True, "links": {"tls": ["tg://proxy?server=h&port=443&secret=ee11"]}},
                {"username": "u2", "enabled": True, "links": {"tls": ["tg://proxy?server=h&port=443&secret=ee22"]}}]})
        return httpx.Response(200, json={"ok": True, "data": {}})

    client = TelemtClient("http://telemt", "Bearer t", transport=httpx.MockTransport(handler))
    async with client.batch():
        await client.list_users()  # discover
        for name in ("u1", "u2", "u1", "u2"):
            await client.set_enabled(name, False)
            assert (await client.current_access(name))["secret"] == f"ee{name[-1] * 2}"
        assert [path for method, path in reads if method == "GET"] == ["/v1/users"]
        await client.rotate("u1")  # a link changed: the next look-up reads again
        await client.current_access("u1")
        assert [path for method, path in reads if method == "GET"] == ["/v1/users", "/v1/users"]
    await client.current_access("u2")  # outside a batch every look-up reads
    assert [path for method, path in reads if method == "GET"] == ["/v1/users"] * 3


async def test_reconcile_reads_the_telemt_inventory_once_per_pass(pair, monkeypatch):
    node, central, node_id, client = await _link(pair)
    intents = [GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username=f"u{i}", options=MtproxyOptions())
               for i in range(5)]
    await central.state.provisioning.start(client.id, intents, actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    entered = []
    real = node.state.adapters["mtproxy"].batch

    def counted():
        entered.append(1)
        return real()

    monkeypatch.setattr(node.state.adapters["mtproxy"], "batch", counted)
    for grant in central.state.clients.client_with_grants(client.id)[1]:
        await central.state.lifecycle.set_enabled(grant.id, False, actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    assert all(not row["enabled"] for row in await node.state.telemt.list_users())
    assert len(entered) == 1  # one batch for the protocol's whole pass


# --- [T8] one source of truth for "disabled": the link's `enabled` ---

async def test_node_view_exposes_one_disabled_flag(pair):
    node, central, node_id, client = await _link(pair)
    central.state.links.set_enabled(node_id, False, actor=ACTOR, ip="x")
    view = central.state.nodes.get(node_id)
    assert view.link["enabled"] is False and view.disabled is True
    with central.state.database.connect() as db:
        assert db.execute("SELECT disabled FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone()[0] == 0


# --- [T11] the CLI's set_disabled pauses a panel link even without the link service wired ---

async def test_set_disabled_without_the_link_service_still_pauses_the_link(pair):
    from panel.fleet import FleetStore
    from panel.nodes.service import NodeLifecycleService

    node, central, node_id, client = await _link(pair)
    service = NodeLifecycleService(central.state.database, FleetStore(central.state.settings.database_path))  # as the CLI
    view = service.set_disabled(node_id, True, actor=ACTOR, ip="cli")
    assert view.disabled is True and view.link["enabled"] is False
    with central.state.database.connect() as db:
        assert db.execute("SELECT enabled FROM node_links WHERE node_id=?", (node_id,)).fetchone()[0] == 0
        assert db.execute("SELECT disabled FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone()[0] == 0
        assert db.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0] == "node.pause"
    assert service.set_disabled(node_id, False, actor=ACTOR, ip="cli").disabled is False
