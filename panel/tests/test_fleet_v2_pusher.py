"""The central's heartbeat and delivery loop against a real node panel in-process (`pair`).

A tick is one heartbeat per enabled link plus, when the node owes the central a
generation, one push and the absorption of what the node reported. Nothing here
sleeps: the loop's cadence is injected and each test drives `tick()` by hand.
"""
import asyncio
import time

import pytest

from panel.clients.models import GrantIntent, MtproxyOptions, NaiveOptions

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}  # фикстура `pair` приходит из panel/tests/conftest.py


async def _link(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    client = central.state.clients.create_client("Alice", actor=ACTOR, ip="x")
    return node, central, node_id, client


async def test_remote_grant_is_pushed_applied_and_activated(pair):
    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    await central.state.pusher.tick()
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    grants = central.state.clients.client_with_grants(client.id)[1]
    assert grants[0].observed_state == "enabled" and grants[0].secret_ref is not None
    assert "alice" in [u["username"] for u in await node.state.naive.list_users()]
    with central.state.database.connect() as db:
        link = central.state.links.link(db, node_id)
    assert link["config_dirty"] == 0 and link["acknowledged_generation"] == 1 and link["status"] == "online"


async def test_offline_node_keeps_the_grant_pending_and_converges_later(pair, monkeypatch):
    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    real = central.state.links.client_factory

    def dead(url, key, **kw):
        from panel.fleet_v2.client import NodeUnreachable
        class Dead:
            async def identity(self): raise NodeUnreachable("refused")
        return Dead()

    central.state.links.client_factory = dead
    await central.state.pusher.tick()
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    assert central.state.nodes.get(node_id).connectivity_state == "offline"
    events = central.state.events.since(0, 50)
    assert [e["name"] for e in events][-1] == "node.down"
    central.state.links.client_factory = real
    await central.state.pusher.tick()
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    assert [e["name"] for e in central.state.events.since(0, 50)][-1] == "node.up"


async def test_disable_rotate_and_delete_publish_new_generations(pair):
    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    await central.state.lifecycle.set_enabled(grant.id, False, actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    rows = {u["username"]: u for u in await node.state.naive.list_users()}
    assert rows["alice"]["enabled"] is False
    before = (await node.state.naive.reveal("alice"))["proxy_url"]
    await central.state.lifecycle.rotate(grant.id, actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    assert (await node.state.naive.reveal("alice"))["proxy_url"] != before
    await central.state.lifecycle.delete(grant.id, actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    assert "alice" not in [u["username"] for u in await node.state.naive.list_users()]
    with central.state.database.connect() as db:
        assert central.state.desired.latest(db, node_id)["generation"] == 4


async def test_paused_link_is_skipped(pair):
    node, central, node_id, client = await _link(pair)
    central.state.links.set_enabled(node_id, False, actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    assert "alice" not in [u["username"] for u in await node.state.naive.list_users()]


# --- additional coverage beyond the brief's Step 1 tests ---

def _accepts(node) -> int:
    with node.state.database.connect() as db:
        return db.execute("SELECT count(*) FROM audit_log WHERE action='fleet.generation.accept'").fetchone()[0]


def _link_row(central, node_id) -> dict:
    with central.state.database.connect() as db:
        return central.state.links.link(db, node_id)


async def test_heartbeat_events_carry_the_node_id_and_fire_only_on_transitions(pair):
    node, central, node_id, client = await _link(pair)
    await central.state.pusher.tick()
    await central.state.pusher.tick()
    events = [e for e in central.state.events.since(0, 50) if e["name"].startswith("node.")]
    assert [e["name"] for e in events] == ["node.up"]
    assert events[0]["node_id"] == node_id and "subscription_id" not in events[0]
    assert set(events[0]) == {"id", "name", "at", "node_id"}
    link = _link_row(central, node_id)
    assert link["status"] == "online" and link["last_heartbeat_at"] and link["latency_ms"] is not None
    assert link["identity"]["guid"] == node_id and "protocols" in link["status_json"]


async def test_a_refused_key_marks_the_node_offline_without_leaking_it(pair):
    node, central, node_id, client = await _link(pair)
    plaintext = pair[2]
    await central.state.pusher.tick()
    node.state.api_keys.set_enabled(node.state.api_keys.list()[0]["id"], False, actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    link = _link_row(central, node_id)
    assert link["status"] == "offline" and link["last_error"].startswith("NodeAuthFailed")
    assert plaintext not in link["last_error"]
    assert [e["name"] for e in central.state.events.since(0, 50) if e["name"].startswith("node.")] == ["node.up", "node.down"]


async def test_a_slow_apply_is_followed_by_observed_polling_not_a_second_push(pair, monkeypatch):
    from panel.fleet_v2 import node_routes

    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    # The manager is slower than the node's deadline: the push answers 202 mid-apply.
    create = node.state.naive.create

    async def slow_create(*args, **kwargs):
        await asyncio.sleep(0.05)
        return await create(*args, **kwargs)

    monkeypatch.setattr(node.state.naive, "create", slow_create)
    monkeypatch.setattr(node_routes, "APPLY_DEADLINE", 0.001)
    await central.state.pusher.tick()
    assert _accepts(node) == 1
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    link = _link_row(central, node_id)
    assert link["config_dirty"] == 1 and link["acknowledged_generation"] == 0
    with central.state.database.connect() as db:
        assert central.state.desired.observed(db, node_id).reconcile_state == "applying"
        assert central.state.desired.latest(db, node_id)["pushed_at"] is not None
    await asyncio.sleep(0.1)  # the node's background apply finishes
    await central.state.pusher.tick()
    assert _accepts(node) == 1  # observed was polled, the generation was not pushed again
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    link = _link_row(central, node_id)
    assert link["config_dirty"] == 0 and link["acknowledged_generation"] == 1


async def test_a_stale_generation_is_republished_above_what_the_node_holds(pair):
    from panel.fleet_v2.protocol import GenerationDocument, canonical_digest

    node, central, node_id, client = await _link(pair)
    # The node still carries a higher-numbered generation from this central (say, the
    # central's database was restored from a backup).
    old = GenerationDocument(node_guid=node_id, master_guid=central.state.panel_guid, generation=5, previous_generation=4,
                             created_at=1, created_by="system", resources=[])
    with node.state.database.transaction() as db:
        node.state.managed.accept(db, old, canonical_digest(old), node_guid=node_id)
        node.state.managed.set_state(db, 5, "converged")
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    link = _link_row(central, node_id)
    assert link["last_error"] == "push 409: stale_generation" and link["status"] == "online"
    with central.state.database.connect() as db:
        latest = central.state.desired.latest(db, node_id)
    assert latest["generation"] == 6 and latest["document"].previous_generation == 5
    assert [r.ref for r in latest["document"].resources] == [f"grant:{central.state.clients.client_with_grants(client.id)[1][0].id}"]
    await central.state.pusher.tick()
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    assert "alice" in [u["username"] for u in await node.state.naive.list_users()]
    link = _link_row(central, node_id)
    assert link["acknowledged_generation"] == 6 and link["config_dirty"] == 0 and link["last_error"] is None


async def test_a_manager_chosen_credential_is_escrowed_under_the_version_the_document_named(pair, monkeypatch):
    from panel.telemt import TelemtError

    node, central, node_id, client = await _link(pair)
    original = node.state.telemt.create_user

    async def refuses_caller_secrets(username, secret=None):
        if secret is not None:
            raise TelemtError("this build chooses its own secret (400)")
        return await original(username, secret=None)

    monkeypatch.setattr(node.state.telemt, "create_user", refuses_caller_secrets)
    intent = GrantIntent(protocol="mtproxy", node_id=node_id, runtime_username="alice", options=MtproxyOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    assert grant.secret_ref.version == 1 and grant.observed_state == "enabled"
    with central.state.database.connect() as db:
        rows = db.execute("SELECT version, state FROM secret_versions WHERE secret_id=?", (f"grant:{grant.id}",)).fetchall()
        escrowed = central.state.secrets.reveal(db, grant.secret_ref, purpose="grant.credential", grant_id=grant.id,
                                                permitted_node_id=node_id).decode()
    assert [tuple(row) for row in rows] == [(1, "active")]
    assert escrowed == (await node.state.telemt.current_access("alice"))["secret"]
    # The next tick has nothing to push: the same version is what the node holds, so it never rotates.
    before = (await node.state.telemt.current_access("alice"))["link"]
    await central.state.pusher.tick()
    assert _accepts(node) == 1 and (await node.state.telemt.current_access("alice"))["link"] == before
    with central.state.database.connect() as db:
        assert central.state.desired.latest(db, node_id)["generation"] == 1


class _Clock:
    """Real time as a starting point, advanced by hand: the backoff slots are minutes."""

    def __init__(self):
        self.now, self.mono = time.time(), time.monotonic()

    def time(self):
        return self.now

    def monotonic(self):
        return self.mono

    def advance(self, seconds):
        self.now += seconds
        self.mono += seconds


async def _failing_alice(pair):
    """A grant the node keeps refusing: a local user of the same name lives on the node (ADR 003)."""
    node, central, node_id, client = await _link(pair)
    await node.state.naive.create("alice", None, password="local-secret", operation_id="local")
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    clock = _Clock()
    central.state.pusher.clock = clock
    return node, central, node_id, client, operation, clock


async def test_a_failed_resource_is_reported_on_the_step_and_re_pushed_with_backoff(pair):
    node, central, node_id, client, operation, clock = await _failing_alice(pair)
    await central.state.pusher.tick()
    status = central.state.provisioning.status(operation)
    assert status["status"] == "pending_remote" and status["steps"][0]["status"] == "remote"
    assert "not managed" in status["steps"][0]["error"]
    assert central.state.clients.client_with_grants(client.id)[1][0].observed_state == "pending"
    link = _link_row(central, node_id)
    assert link["config_dirty"] == 1 and link["status"] == "online"
    with central.state.database.connect() as db:
        assert central.state.desired.observed(db, node_id).reconcile_state == "failed"
    # The next ticks heartbeat but do not re-push: the first slot is 30 s.
    await central.state.pusher.tick()
    clock.advance(29)
    await central.state.pusher.tick()
    assert _accepts(node) == 1 and _link_row(central, node_id)["last_heartbeat_at"] is not None
    clock.advance(2)
    await central.state.pusher.tick()
    assert _accepts(node) == 2  # the slot passed; the same generation went out again and failed again
    # Exponential: 60 s now, so 31 s later nothing goes out; 30 s more and it does.
    clock.advance(31)
    await central.state.pusher.tick()
    assert _accepts(node) == 2
    clock.advance(30)
    await central.state.pusher.tick()
    assert _accepts(node) == 3
    # Once the node can apply it, the push that converges clears the backoff.
    await node.state.naive.delete("alice")
    clock.advance(121)
    await central.state.pusher.tick()
    assert _accepts(node) == 4
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    assert _link_row(central, node_id)["config_dirty"] == 0 and node_id not in central.state.pusher._backoff


async def test_backoff_is_capped_at_ten_minutes(pair):
    node, central, node_id, client, operation, clock = await _failing_alice(pair)
    pushes = 0
    for slot in (30, 60, 120, 240, 480, 600, 600):
        await central.state.pusher.tick()
        pushes += 1
        assert _accepts(node) == pushes
        clock.advance(slot - 1)
        await central.state.pusher.tick()
        assert _accepts(node) == pushes
        clock.advance(1)
    await central.state.pusher.tick()
    assert _accepts(node) == pushes + 1


async def test_a_new_generation_resets_the_backoff(pair):
    node, central, node_id, client, operation, clock = await _failing_alice(pair)
    await central.state.pusher.tick()
    await central.state.pusher.tick()
    assert _accepts(node) == 1  # deferred
    # Something changed for this node: the new generation goes out at once, not after the slot.
    second = GrantIntent(protocol="naive", node_id=node_id, runtime_username="bob", options=NaiveOptions())
    other = await central.state.provisioning.start(client.id, [second], actor=ACTOR, ip="x")
    await central.state.pusher.tick()
    assert _accepts(node) == 2
    assert central.state.provisioning.status(other)["status"] == "succeeded"
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    assert "bob" in [u["username"] for u in await node.state.naive.list_users()]
    # alice still fails: the backoff starts over from the first slot for generation 2.
    await central.state.pusher.tick()
    assert _accepts(node) == 2
    clock.advance(31)
    await central.state.pusher.tick()
    assert _accepts(node) == 3


async def test_a_rejected_push_is_retried_with_backoff_not_every_tick(pair):
    from panel.fleet_v2.client import NodeRejected

    node, central, node_id, client = await _link(pair)
    clock = _Clock()
    central.state.pusher.clock = clock
    real = central.state.links.client_factory

    def rejecting(url, key, **kw):
        inner = real(url, key, **kw)

        class Rejecting:
            async def identity(self):
                return await inner.identity()

            async def status(self):
                return await inner.status()

            async def push(self, request):
                raise NodeRejected(409, "guid_mismatch", "the request names another panel")

        return Rejecting()

    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    central.state.links.client_factory = rejecting
    await central.state.pusher.tick()
    link = _link_row(central, node_id)
    assert link["last_error"] == "push 409: guid_mismatch" and "another panel" not in link["last_error"]
    central.state.links.client_factory = real
    await central.state.pusher.tick()
    assert _accepts(node) == 0  # the node is fine again, but the push waits for its slot
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    clock.advance(31)
    await central.state.pusher.tick()
    assert _accepts(node) == 1
    assert central.state.provisioning.status(operation)["status"] == "succeeded"


async def test_one_broken_node_does_not_stall_the_others(pair, caplog):
    node, central, node_id, client = await _link(pair)
    real = central.state.links.client_factory
    with central.state.database.transaction() as db:
        from panel.nodes.registry import NodeRegistry

        NodeRegistry.insert(db, "node-b", "Broken", transport="panel")
        secret_id = central.state.links._store_key(db, "node-b", "pc_x_y")
        db.execute("""INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,created_at,updated_at)
                      VALUES('node-b','https://broken.example','verify',?,0,0)""", (secret_id,))

    def factory(url, key, **kw):
        if url.startswith("https://broken."):
            class Broken:
                async def identity(self): raise RuntimeError("unexpected")
            return Broken()
        return real(url, key, **kw)

    central.state.links.client_factory = factory
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    with caplog.at_level("ERROR", logger="panel.fleet_v2.pusher"):
        await central.state.pusher.tick()
    assert "alice" in [u["username"] for u in await node.state.naive.list_users()]
    assert any("node-b" in record.getMessage() for record in caplog.records)


async def test_sync_node_is_serialised_per_node(pair):
    node, central, node_id, client = await _link(pair)
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    await asyncio.gather(central.state.pusher.sync_node(node_id), central.state.pusher.sync_node(node_id))
    assert _accepts(node) == 1


async def test_run_forever_ticks_on_its_interval_and_stops(pair):
    node, central, node_id, client = await _link(pair)
    pusher = central.state.pusher
    pusher.interval = 0.01
    ticks = 0
    original = pusher.tick

    async def counted():
        nonlocal ticks
        ticks += 1
        if ticks == 1:
            raise RuntimeError("a tick may fail; the loop goes on")
        await original()

    pusher.tick = counted
    task = asyncio.create_task(pusher.run_forever())
    for _ in range(200):
        await asyncio.sleep(0.01)
        if ticks >= 3:
            break
    pusher.stop()
    await asyncio.wait_for(task, timeout=2)
    assert ticks >= 3 and _link_row(central, node_id)["status"] == "online"


async def test_the_app_starts_the_loop_in_the_background_and_stops_it_on_shutdown(pair):
    node, central, plaintext = pair
    await central.router.startup()
    task = central.state.pusher_task
    assert isinstance(task, asyncio.Task) and not task.done()
    await central.router.shutdown()
    assert task.done() and not task.cancelled()
