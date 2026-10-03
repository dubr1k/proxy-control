"""Readiness is an owner/admin diagnostic, not a public liveness probe."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio
PATH = "/api/readiness"


async def login(client, username="owner", password="correct horse battery staple"):
    csrf = (await client.get("/login")).cookies["panel_csrf"]
    return await client.post("/api/auth/login", json={"username": username, "password": password},
                             headers={"X-CSRF-Token": csrf})


async def test_readiness_requires_owner_or_admin_and_does_not_change_healthz(client):
    assert (await client.get("/healthz")).json() == {"status": "ok"}
    assert (await client.get(PATH)).status_code == 401
    app = client._transport.app
    for scope in ("monitor", "node-sync", "admin"):
        _, key = app.state.api_keys.create(scope, scope, None, actor={"id": 1, "username": "owner"}, ip="x")
        response = await client.get(PATH, headers={"Authorization": f"Bearer {key}"})
        assert response.status_code == (200 if scope == "admin" else 403)
        if scope == "admin":
            assert response.headers["cache-control"] == "no-store"
    app.state.store.create_admin("viewer", "viewer passphrase long", "viewer")
    await login(client, "viewer", "viewer passphrase long")
    assert (await client.get(PATH)).status_code == 403
    await login(client)
    assert (await client.get(PATH)).status_code == 200


async def test_readiness_baseline_is_not_applicable_not_failed(client, login_user):
    await login_user(client)
    response = await client.get(PATH)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "status": "ready", "database": {"queryable": True},
        "node": {"status": "not_applicable", "generation": None, "applied_at": None},
        "central": {"status": "not_applicable", "linked": 0, "lagging": 0},
        "provisioning": {"unfinished": 0, "manual_intervention": 0},
    }


@pytest.mark.parametrize("state,expected", [("applying", "pending"), ("failed", "failed"), ("converged", "ready")])
async def test_node_state_uses_actual_applied_timestamp(client, login_user, state, expected):
    await login_user(client)
    with client._transport.app.state.database.connect() as db:
        db.execute("INSERT INTO managed_generations VALUES(1,'digest','secret-guid','{}',100,90,'converged')")
        db.execute("INSERT INTO managed_generations VALUES(2,'digest2','secret-guid','{}',110,?,?)",
                   (120 if state == "converged" else None, state))
    body = (await client.get(PATH)).json()
    assert body["node"] == {"status": expected, "generation": 2,
                            "applied_at": 120 if state == "converged" else 90}
    assert body["status"] == expected
    assert "secret-guid" not in str(body)


async def test_central_lag_and_provisioning_are_aggregate_and_secret_free(client, login_user):
    await login_user(client)
    with client._transport.app.state.database.connect() as db:
        db.execute("INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at) VALUES('secret-node','secret-topology','linked','{}',1,1)")
        db.execute("""INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,
                   desired_generation,acknowledged_generation,created_at,updated_at,last_heartbeat_at)
                   VALUES('secret-node','https://secret.example','verify','secret-key',2,1,1,1,9999999999)""")
        db.execute("INSERT INTO clients(id,display_name,state,created_at,updated_at) VALUES('secret-client','secret client','active',1,1)")
        for status in ("pending_remote", "manual_intervention_required"):
            db.execute("""INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at)
                       VALUES(?, 'secret-client', ?, '[]', 1, 1)""", (status, status))
    body = (await client.get(PATH)).json()
    assert body["status"] == "failed"
    assert body["central"] == {"status": "pending", "linked": 1, "lagging": 1}
    assert body["provisioning"] == {"unfinished": 1, "manual_intervention": 1}
    assert not any(secret in str(body) for secret in ("secret-node", "secret-topology", "secret.example", "secret-key", "secret-client"))


async def test_database_query_failure_reports_hard_failure(client, login_user, monkeypatch):
    await login_user(client)
    database = client._transport.app.state.database
    def broken():
        raise OSError("private path")
    monkeypatch.setattr(database, "connect", broken)
    response = await client.get(PATH)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"status": "failed", "database": {"queryable": False}}
