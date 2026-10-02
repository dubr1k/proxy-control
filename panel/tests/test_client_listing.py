"""Client listing keeps query count bounded and pages the complete filtered set."""
from panel.clients.service import ClientService
from panel.database import Database
from panel.migrations import apply_migrations
from panel.secrets_store import SecretStore
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
