"""One contract, three data planes — and the places where they honestly differ.

The same lifecycle runs against every adapter. Where the protocols really differ, the
test asserts the difference (`credential_origin`, `capture_supported`) instead of
letting a uniform interface paper over it.
"""

from __future__ import annotations

import pytest

from panel.clients.models import AccessGrant, MieruOptions, MtproxyOptions, NaiveOptions
from panel.tests.harness.memories.mieru import MemoryMieru
from panel.tests.harness.memories.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from panel.tests.harness.memories.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio





@pytest.fixture
def backends():
    return {
        "mtproxy": MemoryTelemt(public_host="proxy.example.com", public_port=443),
        "naive": MemoryNaive(),
        "mieru": MemoryMieru(),
    }
































# --- Step 4/4a: making an imported grant renderable ------------------------------


@pytest.fixture
def adopted(tmp_path, backends):
    from panel.clients.service import ClientService
    from panel.database import Database
    from panel.keyring import Keyring
    from panel.migrations import apply_migrations
    from panel.secrets_store import SecretStore

    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    service = ClientService(database, SecretStore(Keyring.generate()))
    service.adapters = {
        "mtproxy": TelemtAdapter(backends["mtproxy"]),
        "naive": NaiveAdapter(backends["naive"], public_host="naive.example.com"),
        "mieru": MieruAdapter(backends["mieru"]),
    }
    return service


CTX = {"actor": {"id": 1, "username": "owner"}, "ip": "127.0.0.1", "request_id": "req-1"}


async def _imported(service, backends, protocol, username="alice"):
    """Seed a runtime account the panel did not create, then adopt it as a grant."""
    import time
    import uuid

    if protocol == "mtproxy":
        await backends["mtproxy"].create_user(username)
        options = MtproxyOptions()
    elif protocol == "naive":
        await backends["naive"].create(username)
        options = NaiveOptions()
    else:
        mieru = backends["mieru"]
        await mieru.create({"username": username, "quotas": [], "expected_revision": mieru.revision})
        options = MieruOptions(quotas=[])
    client = service.create_client("Sergey", **CTX)
    now = int(time.time())
    grant = AccessGrant(
        id=str(uuid.uuid4()), client_id=client.id, protocol=protocol, node_id="local",
        endpoint_id="default", runtime_username=username, desired_state="enabled",
        observed_state="enabled", options=options, origin="imported", created_at=now, updated_at=now,
    )
    with service.database.transaction() as db:
        service.store.insert_grant(db, grant)
    return grant












