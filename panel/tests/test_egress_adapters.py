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


async def test_egress_target_reports_backend_capabilities_and_providers_without_the_url(backend):
    target = await backend["adapter"].egress_target()
    assert isinstance(target, EgressTarget)
    assert target.protocol == backend["protocol"] and target.backend == backend["backend"]
    assert {"whole_direct", "whole_warp", "block_domain", "block_cidr"} <= target.capabilities
    assert target.providers == {"warp": {"reachable": True}}  # the endpoint stays in the manager's env
    assert target.mode == "direct" and target.applied is not None
    assert target.applied["revision"] == target.revision
    assert target.applied["digest"] == document_digest(target.applied["document"])
    assert "socks5://" not in repr(target)


async def test_egress_target_without_a_provider_lists_no_warp(backend):
    backend["fake"].provider_url = None
    target = await backend["adapter"].egress_target()
    assert target.providers == {} and "whole_warp" in target.capabilities


async def test_egress_target_reports_an_unreachable_provider(backend):
    backend["fake"].reachable = False
    assert (await backend["adapter"].egress_target()).providers == {"warp": {"reachable": False}}


async def test_egress_target_raises_a_typed_error_when_the_manager_is_down(backend):
    backend["fake"].broken = True
    with pytest.raises(AdapterError) as failure:
        await backend["adapter"].egress_target()
    assert failure.value.code == "manager_unavailable"


async def test_apply_egress_returns_the_applied_entry_and_moves_the_target(backend):
    adapter, fake = backend["adapter"], backend["fake"]
    before = await adapter.egress_target()
    plan = await adapter.plan_egress(backend["warp"], expected_revision=before.revision)
    assert plan["reachability"] == {"warp": True} and isinstance(plan["diff"], list)
    applied = await adapter.apply_egress(backend["warp"], expected_revision=before.revision, operation_id="routing:p1:1")
    assert isinstance(applied, AppliedEgress)
    assert applied.revision != before.revision and applied.replayed is False
    assert applied.digest == document_digest(backend["warp"])
    after = await adapter.egress_target()
    assert after.revision == applied.revision and after.mode == "proxy"
    assert after.applied == {"revision": applied.revision, "digest": applied.digest, "document": backend["warp"]}
    assert ("egress_apply", "routing:p1:1") in fake.calls


async def test_apply_egress_is_replayed_by_operation_id(backend):
    adapter = backend["adapter"]
    revision = (await adapter.egress_target()).revision
    first = await adapter.apply_egress(backend["block"], expected_revision=revision, operation_id="op-1")
    again = await adapter.apply_egress(backend["block"], expected_revision="stale", operation_id="op-1")
    assert again.replayed is True and again.revision == first.revision and again.digest == first.digest
    with pytest.raises(AdapterError) as failure:
        await adapter.apply_egress(backend["warp"], expected_revision=first.revision, operation_id="op-1")
    assert failure.value.code == "egress_conflict"


async def test_apply_egress_refuses_a_stale_revision(backend):
    with pytest.raises(AdapterError) as failure:
        await backend["adapter"].apply_egress(backend["warp"], expected_revision="stale", operation_id="op-2")
    assert failure.value.code == "egress_conflict"
    assert (await backend["adapter"].egress_target()).mode == "direct"


async def test_apply_egress_refuses_an_unreachable_provider_and_changes_nothing(backend):
    adapter, fake = backend["adapter"], backend["fake"]
    fake.reachable = False
    revision = (await adapter.egress_target()).revision
    with pytest.raises(AdapterError) as failure:
        await adapter.apply_egress(backend["warp"], expected_revision=revision, operation_id="op-3")
    assert failure.value.code == "egress_unreachable"
    assert (await adapter.egress_target()).revision == revision
    # A document without the provider still applies: only the provider is down, not the manager.
    applied = await adapter.apply_egress(backend["block"], expected_revision=revision, operation_id="op-4")
    assert applied.digest == document_digest(backend["block"])


async def test_apply_egress_refuses_an_invalid_document(backend):
    revision = (await backend["adapter"].egress_target()).revision
    with pytest.raises(AdapterError) as failure:
        await backend["adapter"].apply_egress(backend["invalid"], expected_revision=revision, operation_id="op-5")
    assert failure.value.code == "egress_invalid"


async def test_apply_egress_without_a_configured_provider_is_invalid(backend):
    backend["fake"].provider_url = None
    revision = (await backend["adapter"].egress_target()).revision
    with pytest.raises(AdapterError) as failure:
        await backend["adapter"].apply_egress(backend["warp"], expected_revision=revision, operation_id="op-6")
    assert failure.value.code == "egress_invalid"


@pytest.mark.parametrize("code, typed", [
    ("egress_readback_mismatch", AdapterError),
    ("manual_intervention_required", ManualInterventionRequired),
])
async def test_apply_egress_maps_the_manager_failure_codes(backend, code, typed):
    adapter, fake = backend["adapter"], backend["fake"]
    revision = (await adapter.egress_target()).revision
    fake.egress_fail_next = code
    with pytest.raises(typed) as failure:
        await adapter.apply_egress(backend["warp"], expected_revision=revision, operation_id="op-7")
    assert failure.value.code == code
    assert (await adapter.egress_target()).revision == revision  # the fake refuses before it mutates


async def test_apply_egress_when_the_manager_is_down_is_an_outage_not_a_refusal(backend):
    adapter, fake = backend["adapter"], backend["fake"]
    revision = (await adapter.egress_target()).revision
    fake.broken = True
    with pytest.raises(AdapterError) as failure:
        await adapter.apply_egress(backend["warp"], expected_revision=revision, operation_id="op-8")
    assert failure.value.code == "manager_unavailable"


async def test_rollback_egress_returns_to_the_previous_entry(backend):
    adapter = backend["adapter"]
    initial = await adapter.egress_target()
    with pytest.raises(AdapterError) as failure:
        await adapter.rollback_egress(expected_revision=initial.revision)
    assert failure.value.code == "egress_no_previous"
    first = await adapter.apply_egress(backend["block"], expected_revision=initial.revision, operation_id="op-9")
    second = await adapter.apply_egress(backend["warp"], expected_revision=first.revision, operation_id="op-10")
    rolled = await adapter.rollback_egress(expected_revision=second.revision)
    assert isinstance(rolled, AppliedEgress) and rolled.digest == first.digest
    assert (await adapter.egress_target()).applied["document"] == backend["block"]
    rolled = await adapter.rollback_egress(expected_revision=rolled.revision)
    assert rolled.digest == initial.applied["digest"]
    with pytest.raises(AdapterError) as failure:
        await adapter.rollback_egress(expected_revision="stale")
    assert failure.value.code == "egress_conflict"


async def test_a_custom_unmanaged_egress_has_no_applied_document(backend):
    fake = backend["fake"]
    if backend["protocol"] == "naive":
        fake.egress_custom = "socks5://10.0.0.1:1080"
    else:
        fake.egress_custom = {"proxies": [{"name": "corp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "10.0.0.1", "port": 1080}],
                              "rules": [{"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["corp"]}]}
    target = await backend["adapter"].egress_target()
    assert target.mode == "custom" and target.applied is None
    assert target.warnings and target.warnings[0].startswith("adopts_unmanaged")
    assert "10.0.0.1" not in repr(target)


async def test_telemt_adapter_has_no_egress_target():
    adapter = TelemtAdapter(MemoryTelemt(public_host="proxy.example.com", public_port=443), public_host="proxy.example.com")
    assert await adapter.egress_target() is None
    with pytest.raises(AdapterError) as failure:
        await adapter.apply_egress({"schema": 1}, expected_revision="x", operation_id="op")
    assert failure.value.code == "egress_unsupported"
    with pytest.raises(AdapterError) as failure:
        await adapter.rollback_egress(expected_revision="x")
    assert failure.value.code == "egress_unsupported"


@pytest.mark.parametrize("client_class, error, header", [
    (NaiveClient, NaiveError, "X-Naive-Token"),
    (MieruClient, MieruError, "X-Mieru-Token"),
])
async def test_manager_clients_speak_the_egress_routes_and_keep_the_bounded_codes(client_class, error, header):
    seen = []

    async def handler(request):
        seen.append((request.method, request.url.path, request.content))
        assert request.headers[header] == "internal-token"
        if request.url.path == "/v1/egress":
            return httpx.Response(200, json={"revision": "r1"})
        if request.url.path.endswith("/rollback"):
            return httpx.Response(503, json={"detail": "x", "code": "manual_intervention_required"})
        if request.url.path.endswith("/plan"):
            return httpx.Response(409, json={"detail": "x", "code": "egress_conflict"})
        if request.url.path.endswith("/apply"):
            return httpx.Response(409, json={"detail": "x", "code": "some_new_code"})
        return httpx.Response(404)

    client = client_class("/run/manager.sock", "internal-token", transport=httpx.MockTransport(handler))
    assert await client.egress() == {"revision": "r1"}
    with pytest.raises(error) as failure:
        await client.egress_plan("r1", {"schema": 1})
    assert failure.value.status_code == 409 and failure.value.code == "egress_conflict"
    with pytest.raises(error) as failure:
        await client.egress_apply("r1", {"schema": 1}, "op-1")
    assert failure.value.status_code == 409 and failure.value.code is None  # unknown codes never reach panel copy
    with pytest.raises(error) as failure:
        await client.egress_rollback("r1")
    assert failure.value.status_code == 502 and failure.value.code == "manual_intervention_required"
    bodies = {path: content for _method, path, content in seen}
    assert b'"expected_revision":"r1"' in bodies["/v1/egress/plan"].replace(b" ", b"")
    assert b'"operation_id":"op-1"' in bodies["/v1/egress/apply"].replace(b" ", b"")
    assert set(EGRESS_REASON_CODES) >= {"egress_conflict", "egress_invalid", "egress_unreachable",
                                        "egress_readback_mismatch", "manual_intervention_required", "egress_no_previous"}
