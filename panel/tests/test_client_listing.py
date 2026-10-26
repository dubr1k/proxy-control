"""Client listing keeps query count bounded and pages the complete filtered set."""
import pytest





















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
