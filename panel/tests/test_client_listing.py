"""Client listing keeps query count bounded and pages the complete filtered set."""
import pytest

from panel.clients.service import ClientService
from panel.database import Database
from panel.migrations import apply_migrations
from panel.secrets_store import SecretRef, SecretStore
from panel.tests.test_clients_filters_ui import CLIENTS
from panel.tests.test_clients_domain import _grant





@pytest.fixture
def listing_service(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    service = ClientService(database, SecretStore(None))
    with database.transaction() as db:
        db.execute("""INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)
                      VALUES('fra','Frankfurt','active','{}',1,1)""")
        for index, entry in enumerate(CLIENTS):
            client = service.new_client(db, entry["client"]["display_name"], now=index + 1)
            db.execute("UPDATE clients SET id=?,state=? WHERE id=?", (entry["client"]["id"], entry["client"]["state"], client.id))
            for raw in entry["grants"]:
                grant = _grant(entry["client"]["id"], protocol=raw["protocol"], username=raw["runtime_username"], node_id=raw["node_id"])
                grant = grant.model_copy(update={
                    **{key: raw[key] for key in ("id", "desired_state", "observed_state", "routing_lane")},
                    "secret_ref": SecretRef("synthetic", 1) if raw["secret_ref"] else None,
                })
                service.store.insert_grant(db, grant)
                db.execute("UPDATE access_grants SET routing_lane=? WHERE id=?", (grant.routing_lane, grant.id))
    return service








@pytest.mark.anyio
async def test_client_api_keeps_legacy_full_list_and_exposes_validated_pages(client, login_user):
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    for name in ("Первый", "Второй", "Иван"):
        response = await client.post("/api/clients", json={"display_name": name}, headers=headers)
        assert response.status_code == 201
    full = (await client.get("/api/clients")).json()
    assert len(full["items"]) == 3 and set(full) == {"items"}
    page = (await client.get("/api/clients", params={"limit": 1})).json()
    assert len(page["items"]) == 1 and page["next_cursor"] and page["total"] == 3
    found = (await client.get("/api/clients", params={"limit": 1, "query": "ИВАН"})).json()
    assert [entry["client"]["display_name"] for entry in found["items"]] == ["Иван"]
    for params in ({"limit": 201}, {"limit": 1, "cursor": "bad"}, {"limit": 1, "issue": "nonsense"}):
        assert (await client.get("/api/clients", params=params)).status_code == 422


@pytest.mark.anyio
async def test_client_delete_route_refuses_then_removes_and_the_token_stops_resolving(client, login_user):
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    made = (await client.post("/api/clients", json={"display_name": "Лишний"}, headers=headers)).json()
    client_id = made["id"]
    assert (await client.delete(f"/api/clients/{client_id}")).status_code == 403  # CSRF
    refused = await client.delete(f"/api/clients/{client_id}", headers=headers)
    assert refused.status_code == 409 and "archived" in refused.json()["detail"]
    assert (await client.post(f"/api/clients/{client_id}/state", json={"state": "archived"}, headers=headers)).status_code == 200
    assert (await client.delete(f"/api/clients/{client_id}", headers=headers)).json() == {"deleted": client_id}
    assert (await client.get(f"/api/clients/{client_id}")).status_code == 404
    assert (await client.delete(f"/api/clients/{client_id}", headers=headers)).status_code == 404
    with client._transport.app.state.database.connect() as db:  # noqa: SLF001
        assert db.execute("SELECT COUNT(*) FROM audit_log WHERE action='client.delete' AND target=?", (client_id,)).fetchone()[0] == 1


@pytest.mark.anyio
async def test_client_delete_route_is_closed_to_viewers(client, server, login_user):
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    client_id = (await client.post("/api/clients", json={"display_name": "Чужой"}, headers=headers)).json()["id"]
    server.create_admin("viewer", "viewer password long enough", "viewer")  # noqa: SLF001
    await login_user(client, "viewer", "viewer password long enough")
    viewer = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    assert (await client.delete(f"/api/clients/{client_id}", headers=viewer)).status_code == 403
