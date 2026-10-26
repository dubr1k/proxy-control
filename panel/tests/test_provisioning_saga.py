"""Creating several accesses at once: every failure ends in a state an operator can act on.

Three managers, no shared transaction. The saga's promise is not that nothing fails —
it is that after any single failure the operation lands in exactly one of three declared
outcomes, that resuming it never creates a second account, and that anything the panel
did not create is never deleted while cleaning up.
"""

from __future__ import annotations

import pytest

from panel.clients.models import GrantIntent, MieruOptions, MtproxyOptions, NaiveOptions
from panel.clients.provisioning import ProvisioningService
from panel.clients.service import ClientService
from panel.database import Database
from panel.keyring import Keyring
from panel.mieru import MemoryMieru
from panel.migrations import apply_migrations
from panel.naive import MemoryNaive
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from panel.secrets_store import SecretStore
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio

CTX = {"actor": {"id": 1, "username": "owner"}, "ip": "127.0.0.1", "request_id": "req-1"}
FAULTS = [
    "before_first_apply",
    "after_apply:naive",
    "after_apply:mieru",
    "during_compensation",
    "after_manager_commit_before_response:naive",
]


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


@pytest.fixture
def provisioning(tmp_path, backends):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    secrets = SecretStore(Keyring.generate())
    adapters = {
        "mtproxy": TelemtAdapter(backends["mtproxy"]),
        "naive": NaiveAdapter(backends["naive"], public_host="naive.example.com"),
        "mieru": MieruAdapter(backends["mieru"]),
    }
    clients = ClientService(database, secrets)
    clients.adapters = adapters
    service = ProvisioningService(database, secrets, adapters, clients)
    service.client_id = clients.create_client("Sergey", **CTX).id
    return service


def _intent(protocol, username="alice"):
    options = {
        "mtproxy": MtproxyOptions(),
        "naive": NaiveOptions(quota_bytes=None),
        "mieru": MieruOptions(quotas=[]),
    }[protocol]
    return GrantIntent(protocol=protocol, runtime_username=username, options=options)


def _grants(service):
    return service.clients.client_with_grants(service.client_id)[1]





















