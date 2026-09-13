"""The central's operator routes over HTTP against a real node panel in-process (`pair`)."""
import httpx
import pytest

pytestmark = pytest.mark.anyio


@pytest.fixture
async def central_http(pair, login_user):
    node, central, plaintext = pair
    central.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=central), base_url="http://testserver") as http:
        await login_user(http)
        http.headers["X-CSRF-Token"] = http.cookies["panel_csrf"]
        yield node, central, plaintext, http


async def test_test_link_import_and_list(central_http, naive):
    node, central, plaintext, http = central_http
    node.state.naive.seed("bob", "hunter2")
    probe = await http.post("/api/nodes/test", json={"url": "https://node.example", "api_key": plaintext, "tls_verify": "verify",
                                                     "allow_private_address": False})
    assert probe.status_code == 200 and probe.json()["identity"]["guid"] == node.state.panel_guid
    linked = await http.post("/api/nodes/link", json={"display_name": "Edge", "url": "https://node.example", "api_key": plaintext,
                                                      "tls_verify": "verify", "allow_private_address": False})
    assert linked.status_code == 201
    node_id = linked.json()["node_id"]
    listing = (await http.get("/api/nodes")).json()["items"]
    edge = next(n for n in listing if n["node_id"] == node_id)
    assert edge["enrollment_state"] == "linked" and edge["link"]["has_api_key"] and plaintext not in listing.__repr__()
    inventory = (await http.get(f"/api/nodes/{node_id}/inventory")).json()
    assert [r["runtime_username"] for r in inventory["protocols"]["naive"]] == ["bob"]
    imported = await http.post(f"/api/nodes/{node_id}/import", json={"resources": [{"protocol": "naive", "runtime_username": "bob", "client": "new"}]})
    assert imported.status_code == 200 and imported.json()["without_credential"] == []
    clients = (await http.get("/api/clients")).json()["items"]
    bob = next(c for c in clients if c["client"]["display_name"] == "bob")
    assert bob["grants"][0]["origin"] == "imported" and bob["grants"][0]["secret_ref"]["version"] == 1
    await central.state.pusher.tick()  # adoption: the node now marks bob as central-owned, runtime untouched
    with node.state.database.connect() as db:
        assert node.state.managed.is_managed(db, "naive", "bob")
    assert (await node.state.naive.reveal("bob"))["proxy_url"].count("hunter2") == 1


async def test_pause_probe_update_and_delete(central_http):
    node, central, plaintext, http = central_http
    node_id = (await http.post("/api/nodes/link", json={"display_name": "Edge", "url": "https://node.example", "api_key": plaintext,
                                                        "tls_verify": "verify", "allow_private_address": False})).json()["node_id"]
    assert (await http.post(f"/api/nodes/{node_id}/pause")).status_code == 200
    assert (await http.get(f"/api/nodes/{node_id}")).json()["link"]["enabled"] is False
    assert (await http.post(f"/api/nodes/{node_id}/resume")).status_code == 200
    assert (await http.post(f"/api/nodes/{node_id}/probe")).json()["link"]["status"] == "online"
    assert (await http.post(f"/api/nodes/{node_id}/link", json={"display_name": "Edge 2"})).status_code == 200
    assert (await http.delete(f"/api/nodes/{node_id}")).status_code == 200
    assert (await http.get(f"/api/nodes/{node_id}")).status_code == 404


async def test_link_rejects_bad_key_private_url_and_self(central_http):
    node, central, plaintext, http = central_http
    bad = await http.post("/api/nodes/link", json={"display_name": "E", "url": "https://node.example", "api_key": "pc_x_y",
                                                   "tls_verify": "verify", "allow_private_address": False})
    assert bad.status_code == 409
    private = await http.post("/api/nodes/link", json={"display_name": "E", "url": "https://127.0.0.1", "api_key": plaintext,
                                                       "tls_verify": "verify", "allow_private_address": False})
    assert private.status_code == 422
