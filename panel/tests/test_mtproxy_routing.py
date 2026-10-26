"""MTProxy routing (v1.1): Telemt's upstream handed to the node's Xray-router through the
`xray-router-ingress` bridge, policies on the router like any service, the native backend
that can only be direct, the journal for rollback, and what a node before v1.1 is told."""
from __future__ import annotations

import json

import pytest

from panel.database import Database
from panel.migrations import apply_migrations
from panel.nodes.registry import NodeRegistry
from panel.protocols import RouterAdapter, TelemtAdapter
from panel.protocols.base import AdapterError
from panel.routing.document import MTPROXY_BRIDGE_ADDRESS, TELEMT_DIRECT_DOCUMENT, attach_document, document_digest
from panel.routing.models import PolicyInput, RoutingRule, RuleMatch
from panel.routing.service import RoutingError, RoutingService, router_target_from_identity
from panel.routing.store import RoutingStore
from panel.telemt import MemoryTelemt
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


class Bridge:
    def __init__(self):
        self.up, self.calls = True, []

    async def __call__(self, ingress):
        self.calls.append(ingress["address"])
        return self.up


def _adapter(telemt, router=None, bridge=None, journal=None):
    adapter = TelemtAdapter(telemt, public_host="proxy.example.com", router=router, journal_path=journal,
                            bridge_probe=bridge or Bridge())
    adapter.reload_poll = 0
    return adapter


@pytest.fixture
def stand(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    telemt, router, bridge = MemoryTelemt(public_host="proxy.example.com"), MemoryXrayRouter(), Bridge()
    router_adapter = RouterAdapter(router)
    adapter = _adapter(telemt, router_adapter, bridge, tmp_path / "telemt-egress.json")
    service = RoutingService(database, RoutingStore(database), {"mtproxy": adapter}, NodeRegistry(database),
                             router=router_adapter)
    return {"database": database, "service": service, "telemt": telemt, "router": router, "bridge": bridge,
            "adapter": adapter, "journal": tmp_path / "telemt-egress.json"}


async def _item(service):
    return next(item for item in await service.targets() if item["protocol"] == "mtproxy")


# -- the adapter --------------------------------------------------------------------------------






































# -- the routing service ------------------------------------------------------------------------




















def test_a_linked_router_without_mtproxy_is_named():
    router = {"available": True, "services": {"naive": {"revision": "r"}, "mieru": {"revision": "r"}}, "capabilities": []}
    assert router_target_from_identity("mtproxy", router).reason == "router_lacks_mtproxy"
    assert router_target_from_identity("naive", router).available


def test_migration_21_widens_the_checks(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    with database.transaction() as db:
        db.execute("INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('mtproxy',1,'converged',0)")
        sql = db.execute("SELECT sql FROM sqlite_master WHERE name='routing_policies'").fetchone()["sql"]
    assert "'mtproxy'" in sql and "'mtproxy_native'" in sql
