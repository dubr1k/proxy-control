"""Runtime enforcement, including deadlines when the central panel is unreachable."""
from types import SimpleNamespace
import asyncio

import pytest
import httpx

from panel.clients.models import GrantIntent, NaiveOptions
from panel.protocols.base import AdapterError
from panel.tests.test_grant_lifecycle import ACTOR, _remote

pytestmark = pytest.mark.anyio


async def _local(app, **window):
    person = app.state.clients.create_client("A", actor=ACTOR, ip="test")
    op = await app.state.provisioning.start(person.id, [GrantIntent(
        protocol="naive", runtime_username="alice", options=NaiveOptions(), **window,
    )], actor=ACTOR, ip="test")
    await app.state.provisioning.run(op)
    return person, app.state.clients.client_with_grants(person.id)[1][0]


async def _enabled(app):
    return {row["username"]: row["enabled"] for row in await app.state.naive.list_users()}["alice"]


async def test_suspension_reaches_remote_runtime_and_resume_preserves_disabled_grant(pair):
    node, central, _, person, _, grant = await _remote(pair)
    await central.state.pusher.tick()
    central.state.clients.set_state(person.id, "suspended", actor=ACTOR, ip="test")
    await central.state.pusher.tick()
    assert await _enabled(node) is False
    await central.state.lifecycle.set_enabled(grant.id, False, actor=ACTOR, ip="test")
    central.state.clients.set_state(person.id, "active", actor=ACTOR, ip="test")
    await central.state.pusher.tick()
    assert await _enabled(node) is False
    assert central.state.clients.client_with_grants(person.id)[1][0].observed_state == "disabled"


async def test_local_suspension_is_pending_until_runtime_readback_and_retries(pair, monkeypatch):
    _, app, _ = pair
    person, grant = await _local(app)
    app.state.clients.set_state(person.id, "suspended", actor=ACTOR, ip="test")
    assert app.state.clients.client_with_grants(person.id)[1][0].observed_state == "pending"
    adapter = app.state.adapters["naive"]
    disable = adapter.disable

    async def fail(_ref):
        raise AdapterError("manager unavailable")

    monkeypatch.setattr(adapter, "disable", fail)
    await app.state.access_enforcer.tick()
    assert app.state.clients.client_with_grants(person.id)[1][0].observed_state == "pending"
    assert await _enabled(app) is True
    monkeypatch.setattr(adapter, "disable", disable)
    await app.state.access_enforcer.tick()
    assert await _enabled(app) is False
    observed = app.state.clients.client_with_grants(person.id)[1][0]
    assert observed.observed_state == "disabled" and observed.desired_state == "enabled"
    app.state.clients.set_state(person.id, "active", actor=ACTOR, ip="test")
    await app.state.access_enforcer.tick()
    assert await _enabled(app) is True


@pytest.mark.parametrize("protocol", ["mtproxy", "naive", "mieru"])
async def test_protocol_enable_cannot_bypass_a_suspended_known_grant(client, login_user, protocol):
    from panel.clients.models import PROTOCOL_OPTIONS

    app = client._transport.app
    person = app.state.clients.create_client("A", actor=ACTOR, ip="test")
    operation = await app.state.provisioning.start(person.id, [GrantIntent(
        protocol=protocol, runtime_username="alice", options=PROTOCOL_OPTIONS[protocol](),
    )], actor=ACTOR, ip="test")
    await app.state.provisioning.run(operation)
    app.state.clients.set_state(person.id, "suspended", actor=ACTOR, ip="test")
    await app.state.access_enforcer.tick()
    await login_user(client)
    path = {"mtproxy": "/api/users", "naive": "/api/naive/users", "mieru": "/api/mieru/users"}[protocol]
    body = {"expected_revision": app.state.mieru.revision} if protocol == "mieru" else {}
    response = await client.post(f"{path}/alice/enable", json=body,
                                headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    assert response.status_code == 200
    inventory = await app.state.adapters[protocol].discover()
    assert next(row for row in inventory.items if row.runtime_username == "alice").enabled is False


async def test_telemt_batch_readback_observes_enable_disable_mutations():
    from panel.telemt import TelemtClient

    enabled = True

    def upstream(request):
        nonlocal enabled
        if request.method == "POST":
            enabled = False
        return httpx.Response(200, json={"ok": True, "data": [{"username": "alice", "enabled": enabled}]})

    telemt = TelemtClient("https://runtime.example", "synthetic", transport=httpx.MockTransport(upstream))
    async with telemt.batch():
        assert (await telemt.list_users())[0]["enabled"] is True
        await telemt.set_enabled("alice", False)
        assert (await telemt.list_users())[0]["enabled"] is False


@pytest.mark.parametrize("window", [{"valid_until": 1}, {"valid_from": 9999999999}])
async def test_local_provisioning_finishes_disabled_outside_validity_window(pair, window):
    _, app, _ = pair
    person, _ = await _local(app, **window)
    assert await _enabled(app) is False
    assert app.state.clients.client_with_grants(person.id)[1][0].observed_state == "disabled"


async def test_local_clock_transition_enables_then_expires_without_request(pair):
    _, app, _ = pair
    person, grant = await _local(app, valid_from=9999999998, valid_until=9999999999)
    app.state.clients.clock = SimpleNamespace(time=lambda: 9999999998)
    await app.state.access_enforcer.tick()
    assert await _enabled(app) is True
    app.state.clients.clock = SimpleNamespace(time=lambda: 9999999999)
    await app.state.access_enforcer.tick()
    assert await _enabled(app) is False
    assert app.state.clients.client_with_grants(person.id)[1][0].desired_state == "enabled"


async def test_remote_clock_transition_enforces_without_central_or_new_generation(pair):
    node, central, node_id, person, _, grant = await _remote(pair)
    with central.state.database.transaction() as db:
        central.state.clients.store.update_grant(db, grant.id, valid_from=9999999998, valid_until=9999999999)
        central.state.clients.notify(db, person.id)
    await central.state.pusher.tick()
    assert await _enabled(node) is False
    with node.state.database.connect() as db:
        generation = node.state.managed.latest(db)["generation"]
    node.state.reconciler.clock = SimpleNamespace(time=lambda: 9999999998)
    await node.state.access_enforcer.tick()
    assert await _enabled(node) is True
    node.state.reconciler.clock = SimpleNamespace(time=lambda: 9999999999)
    await node.state.reconciler.run_pending()  # a restart must recheck a converged generation
    assert await _enabled(node) is False
    with node.state.database.connect() as db:
        assert node.state.managed.latest(db)["generation"] == generation


async def test_local_enable_cannot_bypass_suspension_or_expiry(pair):
    _, app, _ = pair
    person, grant = await _local(app, valid_until=1)
    await app.state.lifecycle.set_enabled(grant.id, True, actor=ACTOR, ip="test")
    assert await _enabled(app) is False
    app.state.clients.set_state(person.id, "suspended", actor=ACTOR, ip="test")
    await app.state.lifecycle.set_enabled(grant.id, True, actor=ACTOR, ip="test")
    assert await _enabled(app) is False


async def test_local_readback_does_not_accept_a_success_reply_without_runtime_change(pair, monkeypatch):
    _, app, _ = pair
    person, _ = await _local(app)
    app.state.clients.set_state(person.id, "suspended", actor=ACTOR, ip="test")
    from panel.protocols.base import AppliedGrant

    async def dishonest(_ref):
        return AppliedGrant(runtime_username="alice", enabled=False)

    monkeypatch.setattr(app.state.adapters["naive"], "disable", dishonest)
    await app.state.access_enforcer.tick()
    assert app.state.clients.client_with_grants(person.id)[1][0].observed_state == "pending"
    assert await _enabled(app) is True


async def test_local_enforcement_batches_runtime_inventory_per_protocol(pair, monkeypatch):
    _, app, _ = pair
    person = app.state.clients.create_client("A", actor=ACTOR, ip="test")
    operation = await app.state.provisioning.start(person.id, [GrantIntent(
        protocol="naive", runtime_username=f"user{index}", options=NaiveOptions(),
    ) for index in range(4)], actor=ACTOR, ip="test")
    await app.state.provisioning.run(operation)
    app.state.clients.set_state(person.id, "suspended", actor=ACTOR, ip="test")
    adapter = app.state.adapters["naive"]
    discover = adapter.discover
    reads = 0

    async def count():
        nonlocal reads
        reads += 1
        return await discover()

    monkeypatch.setattr(adapter, "discover", count)
    await app.state.access_enforcer.tick()
    assert all(row["enabled"] is False for row in await app.state.naive.list_users())
    assert reads == 2  # one plan and one readback, independent of the number of grants


async def test_background_timer_expires_access_without_a_request(pair):
    _, app, _ = pair
    await _local(app, valid_until=9999999999)
    app.state.clients.clock = SimpleNamespace(time=lambda: 9999999999)
    enforcer = app.state.access_enforcer
    enforcer.interval = 0.001
    task = asyncio.create_task(enforcer.run_forever())
    try:
        async with asyncio.timeout(2):
            while await _enabled(app):
                await asyncio.sleep(0.005)
        assert await _enabled(app) is False
    finally:
        enforcer.stop()
        await asyncio.wait_for(task, timeout=2)


async def test_lifespan_enforces_expired_local_access_before_serving(pair):
    _, app, _ = pair
    await _local(app, valid_until=9999999999)
    app.state.clients.clock = SimpleNamespace(time=lambda: 9999999999)
    async with app.router.lifespan_context(app):
        assert await _enabled(app) is False


async def test_remote_option_drift_does_not_report_suspended_runtime_as_enabled(pair, monkeypatch):
    node, central, _, person, _, grant = await _remote(pair)
    await central.state.pusher.tick()

    async def unsupported(ref, options):
        return None

    monkeypatch.setattr(node.state.adapters["naive"], "update_options", unsupported)
    with central.state.database.transaction() as db:
        central.state.clients.store.update_grant(db, grant.id, protocol_options_json='{"quota_bytes":100}')
    central.state.clients.set_state(person.id, "suspended", actor=ACTOR, ip="test")
    await central.state.pusher.tick()
    assert await _enabled(node) is False
    assert central.state.clients.client_with_grants(person.id)[1][0].observed_state == "disabled"


async def _drifted_report(pair, monkeypatch, **window):
    node, central, node_id, person, _, grant = await _remote(pair)
    await central.state.pusher.tick()

    async def unsupported(ref, options):
        return None

    monkeypatch.setattr(node.state.adapters["naive"], "update_options", unsupported)
    with central.state.database.transaction() as db:
        central.state.clients.store.update_grant(db, grant.id, protocol_options_json='{"quota_bytes":100}', **window)
        central.state.clients.notify(db, person.id)
    await central.state.pusher.tick()
    with node.state.database.connect() as db:
        report = node.state.managed.observed(db)
    assert report.resources[0].state == "drifted"
    return node, central, node_id, person, report


async def test_stale_option_drift_report_cannot_confirm_a_new_suspension(pair, monkeypatch):
    node, central, node_id, person, report = await _drifted_report(pair, monkeypatch)
    central.state.clients.set_state(person.id, "suspended", actor=ACTOR, ip="test")
    assert await _enabled(node) is True
    central.state.pusher._absorb(node_id, report, {})
    assert central.state.clients.client_with_grants(person.id)[1][0].observed_state == "pending"


@pytest.mark.parametrize("central_now", [0, 9999999999])
async def test_drift_report_does_not_infer_node_runtime_from_central_clock(pair, monkeypatch, central_now):
    node, central, node_id, person, report = await _drifted_report(
        pair, monkeypatch, valid_from=1, valid_until=9999999999,
    )
    central.state.pusher.clock = SimpleNamespace(time=lambda: central_now)
    assert await _enabled(node) is True
    central.state.pusher._absorb(node_id, report, {})
    assert central.state.clients.client_with_grants(person.id)[1][0].observed_state == "pending"
