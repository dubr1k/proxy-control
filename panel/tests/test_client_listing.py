"""Client listing keeps query count bounded and pages the complete filtered set."""
import pytest

from panel.clients.service import ClientService
from panel.database import Database
from panel.migrations import apply_migrations
from panel.secrets_store import SecretRef, SecretStore
from panel.tests.test_clients_filters_ui import CLIENTS
from panel.tests.test_clients_domain import _grant


def test_listing_batches_grants_without_losing_order_or_empty_clients(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    service = ClientService(database, SecretStore(None))
    with database.transaction() as db:
        clients = [service.new_client(db, f"client-{index}", now=index + 1) for index in range(1000)]
        for client in clients[:2]:
            service.store.insert_grant(db, _grant(client.id, username=client.id))
        deleted = _grant(clients[-1].id, username="removed").model_copy(update={"desired_state": "deleted"})
        service.store.insert_grant(db, deleted)
    queries = []
    with database.connect() as db:
        db.set_trace_callback(queries.append)
        listing = service.store.clients_with_grants(db)
    assert [client.id for client, _ in listing] == [client.id for client in clients]
    assert [len(grants) for _, grants in listing] == [1, 1] + [0] * 998
    assert len([sql for sql in queries if sql.startswith("SELECT")]) == 2


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


@pytest.mark.parametrize("filters,expected", [
    ({}, ["c1", "c2", "c3"]), ({"query": "НОУТБУК"}, ["c1"]),
    ({"query": "phone"}, ["c2"]), ({"query": "frankfurt"}, ["c1", "c2"]),
    ({"query": "сергея laptop"}, ["c1"]), ({"query": "%"}, []),
    ({"query": "ЭТОТ СЕРВЕР"}, ["c1"]), ({"state": "suspended"}, ["c2"]),
    ({"protocol": "mieru"}, ["c1"]), ({"protocol": "mieru", "node": "local"}, []),
    ({"node": "fra"}, ["c1", "c2"]), ({"issue": "pending"}, ["c2"]),
    ({"issue": "orphan"}, ["c2"]), ({"issue": "disabled"}, ["c1"]),
    ({"issue": "lane"}, ["c1"]), ({"issue": "problem"}, ["c2"]),
    ({"issue": "empty"}, ["c3"]), ({"issue": "empty", "protocol": "naive"}, ["c1", "c3"]),
    ({"issue": "orphan", "state": "archived"}, []),
    ({"protocol": "mtproxy", "node": "fra", "issue": "disabled"}, []),
])
def test_server_filters_match_client_search_semantics(listing_service, filters, expected):
    service = listing_service
    with service.database.connect() as db:
        page = service.store.client_page(db, limit=50, **filters)
    assert [client.id for client, _ in page["items"]] == expected
    assert page["matched"] == len(expected) and page["total"] == 3
    assert page["counts"] == {"active": 1, "suspended": 1, "archived": 1}


def test_cursor_pages_are_bounded_and_search_covers_clients_after_first_page(listing_service):
    service = listing_service
    with service.database.transaction() as db:
        for index in range(120):
            service.new_client(db, f"extra-{index:03d}", now=1)
    cursor, seen = None, []
    while True:
        with service.database.connect() as db:
            queries = []
            db.set_trace_callback(queries.append)
            page = service.store.client_page(db, limit=17, cursor=cursor)
        assert len(page["items"]) <= 17
        assert len([sql for sql in queries if sql.lstrip().startswith("SELECT")]) <= 5
        seen.extend(client.id for client, _ in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 123 and seen[-2:] == ["c2", "c3"]
    with service.database.connect() as db:
        page = service.store.client_page(db, limit=17, query="extra-119")
        assert [client.display_name for client, _ in page["items"]] == ["extra-119"]
        with pytest.raises(ValueError, match="cursor"):
            service.store.client_page(db, cursor="bad", limit=17)


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
