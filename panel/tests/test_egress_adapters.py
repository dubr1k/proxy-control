"""Egress through the adapters (v0.4 routing): one surface over two managers.

NaiveProxy and Mieru compile the same policy into different documents, so the tests
here are parametrised over the two backends with their own document shapes and assert
the shared contract: a typed target, a typed applied result, bounded error codes, and
the fakes behaving the way the managers' egress APIs do (revision CAS, reachability
refusal, replay by operation id, rollback to the previous entry).
"""

from __future__ import annotations

import httpx
import pytest

from panel.mieru import MemoryMieru, MieruClient, MieruError
from panel.naive import MemoryNaive, NaiveClient, NaiveError
from panel.protocols import (
    AdapterError,
    AppliedEgress,
    EgressTarget,
    ManualInterventionRequired,
    MieruAdapter,
    NaiveAdapter,
    TelemtAdapter,
)
from panel.routing.document import EGRESS_REASON_CODES, document_digest
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio

NAIVE_WARP = {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}
NAIVE_BLOCK = {"schema": 1, "upstream": None, "acl": [{"deny": ["example.com", "*.example.com", "10.0.0.0/8"]}]}
MIERU_WARP = {"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
              "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"}]}
MIERU_BLOCK = {"schema": 1, "proxies": [],
               "rules": [{"domains": ["example.com"], "cidrs": [], "action": "REJECT", "proxy": None}]}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(params=["naive", "mieru"])
def backend(request):
    if request.param == "naive":
        fake = MemoryNaive()
        return {"protocol": "naive", "fake": fake, "adapter": NaiveAdapter(fake, public_host="naive.example.com"),
                "backend": "naive_native", "warp": NAIVE_WARP, "block": NAIVE_BLOCK,
                "invalid": {"schema": 1, "upstream": {"provider": "warp"}, "acl": [{"deny": ["example.com"]}]},
                "error": NaiveError}
    fake = MemoryMieru()
    return {"protocol": "mieru", "fake": fake, "adapter": MieruAdapter(fake, public_host="mieru.example.com"),
            "backend": "mieru_native", "warp": MIERU_WARP, "block": MIERU_BLOCK,
            "invalid": {"schema": 1, "proxies": [], "rules": [{"domains": ["a"], "cidrs": [], "action": "PROXY", "proxy": "warp"}]},
            "error": MieruError}
















































