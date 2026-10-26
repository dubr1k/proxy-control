"""One contract, three data planes — and the places where they honestly differ.

The same lifecycle runs against every adapter. Where the protocols really differ, the
test asserts the difference (`credential_origin`, `capture_supported`) instead of
letting a uniform interface paper over it.
"""

from __future__ import annotations

import pytest

from panel.clients.models import (
    AccessGrant,
    GrantIntent,
    MieruOptions,
    MtproxyOptions,
    NaiveOptions,
)
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import (
    CredentialPlan,
    GrantRef,
    ManualInterventionRequired,
    MieruAdapter,
    NaiveAdapter,
    TelemtAdapter,
)
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def backends():
    return {
        "mtproxy": MemoryTelemt(public_host="proxy.example.com", public_port=443),
        "naive": MemoryNaive(),
        "mieru": MemoryMieru(),
    }


@pytest.fixture(params=["mtproxy", "naive", "mieru"])
def adapter(request, backends):
    return {
        "mtproxy": lambda: TelemtAdapter(backends["mtproxy"], public_host="proxy.example.com"),
        "naive": lambda: NaiveAdapter(backends["naive"], public_host="naive.example.com"),
        "mieru": lambda: MieruAdapter(backends["mieru"], public_host="mieru.example.com"),
    }[request.param]()


def _intent(protocol, username="alice"):
    options = {
        "mtproxy": MtproxyOptions(),
        "naive": NaiveOptions(quota_bytes=None),
        "mieru": MieruOptions(quotas=[], share_template=None),
    }[protocol]
    return GrantIntent(protocol=protocol, runtime_username=username, options=options)


def _credential(adapter, password=b"caller-supplied-password-01"):
    if adapter.credential_origin == "manager":
        return CredentialPlan("manager", None)
    return CredentialPlan("caller", password)


def _grant_row(protocol, applied, username="alice"):
    options = {
        "mtproxy": MtproxyOptions(),
        "naive": NaiveOptions(),
        "mieru": MieruOptions(quotas=[], share_template=applied.artifact_template.get("share_template")),
    }[protocol]
    return AccessGrant(
        id="g1", client_id="c1", protocol=protocol, node_id="local", endpoint_id="default",
        runtime_username=username, desired_state="enabled", options=options,
        origin="provisioned", created_at=1, updated_at=1,
    )




















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





async def test_mieru_cannot_be_captured_and_says_so(adopted, backends):
    from panel.clients.store import ClientConflict

    grant = await _imported(adopted, backends, "mieru")
    with pytest.raises(ClientConflict, match="rotation"):
        await adopted.capture_credential(grant.id, **CTX)
    with pytest.raises(ClientConflict, match="rotation"):
        await adopted.adopt_credential(grant.id, allow_rotation=False, **CTX)
    with adopted.database.connect() as db:
        assert adopted.store.grant(db, grant.id).secret_ref is None






