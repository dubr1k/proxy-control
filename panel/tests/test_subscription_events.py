"""Subscription events are facts the panel recorded, never a promise that anyone received them.

Three moments produce one: the generation moved (inside the same transaction, so a
rolled-back change produces nothing), a client fetched the subscription (200 or 304),
and a URL was revoked — by an operator or by a rotation. No payload carries the token,
a link, or a claim such as `applied`/`delivered`.
"""

# ruff: noqa: F811  (fixtures imported from the HTTP suite reappear as test parameters)
from __future__ import annotations

import json

import httpx
import pytest

from test_subscription_http import (  # noqa: F401  (fixtures are registered by import)
    CTX,
    PANEL_HOST,
    app,
    client_id,
    clock,
    owner,
    public,
    subscriptions,
    token,
)

pytestmark = pytest.mark.anyio


def _events(app, after=0):
    with app.state.database.connect() as db:
        rows = db.execute(
            "SELECT id, action, target, detail_json, actor_username FROM audit_log"
            " WHERE action LIKE 'subscription.%' AND id > ? ORDER BY id",
            (after,),
        ).fetchall()
    return [
        {"id": row[0], "name": row[1], "target": row[2], "actor": row[4], **json.loads(row[3])}
        for row in rows
    ]


async def test_generation_change_emits_inside_the_transaction_or_not_at_all(app, subscriptions, client_id, token, monkeypatch):
    before = _events(app)
    subscription = subscriptions.get(client_id)
    app.state.clients.set_state(client_id, "suspended", **CTX)
    changed = [event for event in _events(app) if event["name"] == "subscription.generation.changed"]
    assert len(changed) == 1
    assert changed[0]["target"] == subscription.id and changed[0]["generation"] == 2
    assert changed[0]["client_id"] == client_id and changed[0]["actor"] == "system"
    assert app.state.events.recent[-1]["name"] == "subscription.generation.changed"

    # The audit write of the change itself fails: the transaction rolls back and the
    # event that was emitted inside it disappears with it.
    from panel.clients import service as clients_module

    monkeypatch.setattr(clients_module, "record", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit down")))
    with pytest.raises(RuntimeError):
        app.state.clients.set_state(client_id, "active", **CTX)
    assert len([e for e in _events(app) if e["name"] == "subscription.generation.changed"]) == 1
    assert len(_events(app)) == len(before) + 1  # exactly the one event of the change that held


async def test_fetches_emit_with_their_status_and_misses_emit_nothing(app, public, token):
    first = await public.get(f"/s/{token}", params={"format": "singbox"})
    again = await public.get(f"/s/{token}", headers={"If-None-Match": first.headers["etag"]}, params={"format": "singbox"})
    assert (first.status_code, again.status_code) == (200, 304)
    assert (await public.get("/s/" + "A" * 43)).status_code == 404
    assert (await public.get(f"/s/{token}", headers={"host": PANEL_HOST})).status_code == 404
    fetched = [event for event in _events(app) if event["name"] == "subscription.fetched"]
    assert [(event["status"], event["format"]) for event in fetched] == [(200, "singbox"), (304, "singbox")]
    assert all(event["target"] and "client_id" in event for event in fetched)


async def test_revocation_and_rotation_emit_revoked_for_the_old_url(app, owner, subscriptions, client_id, token):
    old = subscriptions.get(client_id)
    rotated = await owner.post(f"/api/clients/{client_id}/subscription/rotate")
    assert rotated.status_code == 200
    new = subscriptions.get(client_id)
    revoked = [event for event in _events(app) if event["name"] == "subscription.revoked"]
    assert [event["target"] for event in revoked] == [old.id]
    assert revoked[0]["reason"] == "rotated" and revoked[0]["client_id"] == client_id
    assert (await owner.post(f"/api/clients/{client_id}/subscription/revoke")).json() == {"revoked": True}
    revoked = [event for event in _events(app) if event["name"] == "subscription.revoked"]
    assert [event["target"] for event in revoked] == [old.id, new.id] and revoked[1]["reason"] == "revoked"
    # Revoking nothing emits nothing.
    await owner.post(f"/api/clients/{client_id}/subscription/revoke")
    assert len([e for e in _events(app) if e["name"] == "subscription.revoked"]) == 2


async def test_no_event_carries_a_token_a_link_or_a_delivery_claim(app, public, owner, client_id, token):
    await public.get(f"/s/{token}")
    await owner.post(f"/api/clients/{client_id}/subscription/rotate")
    events = _events(app)
    assert events
    for event in events:
        flat = json.dumps(event)
        assert token not in flat and "/s/" not in flat and "https://" not in flat
        assert not {"applied", "delivered", "token", "url", "link"} & set(event)


async def test_the_events_endpoint_pages_by_id_and_serves_only_subscription_events(app, public, owner, client_id, token, login_user):
    first = await public.get(f"/s/{token}")
    await public.get(f"/s/{token}", headers={"If-None-Match": first.headers["etag"]})
    await owner.post(f"/api/clients/{client_id}/subscription/rotate")
    await owner.post(f"/api/clients/{client_id}/subscription/revoke")
    app.state.store.create_admin("viewer", "correct horse battery staple", "viewer")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://{PANEL_HOST}"
    ) as viewer:
        await login_user(viewer, "viewer")
        page = await viewer.get("/api/events", params={"limit": 2})
        assert page.status_code == 200
        items = page.json()["items"]
        assert len(items) == 2 and all(item["name"].startswith("subscription.") for item in items)
        assert items[0]["id"] < items[1]["id"] and page.json()["next_after"] == items[1]["id"]
        rest = (await viewer.get("/api/events", params={"after": page.json()["next_after"], "limit": 100})).json()
        assert rest["items"] and all(item["id"] > items[1]["id"] for item in rest["items"])
        names = [item["name"] for item in items + rest["items"]]
        assert "subscription.fetched" in names and "subscription.revoked" in names
        # Operator actions with the same prefix in the audit trail are not events.
        assert "subscription.create" not in names and "subscription.rotate" not in names
        assert all(set(item) >= {"id", "name", "at", "subscription_id"} for item in items)
        assert (await viewer.get("/api/events", params={"limit": 0})).status_code == 422
        assert (await viewer.get("/api/events", params={"limit": 1000})).status_code == 422


def test_the_bus_refuses_unknown_names_and_scrubs_payloads(app):
    bus = app.state.events
    with app.state.database.transaction() as db:
        with pytest.raises(ValueError):
            bus.emit(db, "subscription.delivered", {"subscription_id": "s1"})
        row_id = bus.emit(db, "subscription.revoked", {"subscription_id": "s1", "client_id": "c1", "public_url": "https://x/s/t"})
    assert isinstance(row_id, int)
    assert "public_url" not in bus.recent[-1] and bus.recent[-1]["subscription_id"] == "s1"
    assert "public_url" not in json.dumps(_events(app))
