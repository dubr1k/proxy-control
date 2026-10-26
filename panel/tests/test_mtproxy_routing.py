"""MTProxy routing (v1.1): Telemt's upstream handed to the node's Xray-router through the
`xray-router-ingress` bridge, policies on the router like any service, the native backend
that can only be direct, the journal for rollback, and what a node before v1.1 is told."""
from __future__ import annotations



import pytest








from panel.routing.service import router_target_from_identity




pytestmark = pytest.mark.anyio



















# -- the adapter --------------------------------------------------------------------------------






































# -- the routing service ------------------------------------------------------------------------




















def test_a_linked_router_without_mtproxy_is_named():
    router = {"available": True, "services": {"naive": {"revision": "r"}, "mieru": {"revision": "r"}}, "capabilities": []}
    assert router_target_from_identity("mtproxy", router).reason == "router_lacks_mtproxy"
    assert router_target_from_identity("naive", router).available



