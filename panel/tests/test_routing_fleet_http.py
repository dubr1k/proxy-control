"""Routing's central↔node contract over HTTP, CLI and the real manager-client wire."""
from __future__ import annotations

import json

import pytest

from panel.routing.document import ROUTER_DIRECT_INTENT, attach_document, document_digest
from panel.tests.harness.routing import csrf, linked
from panel.tests.harness.memories.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
WARP = {"default_action": "egress", "default_egress": "warp"}
BLOCK = {"rules": [{"action": "block", "match": {"domains": ["example.com"]}}]}


async def converge(node, central):
    await central.tick("pusher")
    await node.settle()
    await central.tick("pusher")


async def request(client, method, path, body=None):
    answer = await client.request(method, path, headers=csrf(client), **({"json": body} if body is not None else {}))
    assert answer.status_code in (200, 201), answer.text
    return answer.json()


async def test_remote_native_preview_apply_failure_recovery_rollback_and_managed_gate(pair_factory, login_user):
    node, central, plaintext = pair_factory()
    async with linked(central, plaintext, login_user) as (client, node_id):
        path = f"/api/routing/policies/{node_id}/naive"
        saved = await request(client, "PUT", path, BLOCK)
        preview = await request(client, "POST", path + "/preview")
        assert preview["status"] == "supported" and preview["document"]["acl"] == [{"deny": ["example.com"]}]
        applied = await request(client, "POST", path + "/apply", {"expected_revision": saved["revision"]})
        assert applied["policy"]["state"] == "applying" and applied["applied"] is None
        await converge(node, central)
        assert (await client.get(path)).json()["state"] == "applied"
        assert node.naive.egress_document == preview["document"]
        await request(client, "PUT", path, {**WARP, "expected_revision": 1})
        node.naive.egress_fail_next = "egress_unreachable"
        await request(client, "POST", path + "/apply", {"expected_revision": 2})
        await central.tick("pusher")
        await node.settle()
        await central.tick("pusher")
        failed = (await client.get(path)).json()
        assert failed["state"] == "failed" and failed["last_error"] == "egress_unreachable", failed
        await request(client, "POST", path + "/apply", {"expected_revision": 2})
        central.clock.advance(60)
        await converge(node, central)
        assert (await client.get(path)).json()["applied_current"] is True
        rolled = await request(client, "POST", path + "/rollback", {"expected_revision": 2})
        assert rolled["compiled"]["document"] == preview["document"]
        await converge(node, central)
        assert node.naive.egress_document == preview["document"]
        history = (await client.get(path + "/history")).json()["items"]
        assert {row["outcome"] for row in history} >= {"applied", "failed", "rolled_back"}
        node.create_admin("owner", "correct horse battery staple", "owner")
        async with node.http() as local:
            await login_user(local)
            saved = await local.put("/api/routing/policies/local/naive", json=WARP, headers=csrf(local))
            assert saved.status_code == 200, saved.text
            refused = await local.post("/api/routing/policies/local/naive/apply",
                                       json={"expected_revision": saved.json()["revision"]}, headers=csrf(local))
            assert refused.status_code == 409 and refused.json()["code"] == "managed_by_central"


async def test_remote_router_attach_apply_rollback_detach_and_identity(pair_factory, login_user):
    router = MemoryXrayRouter()
    node, central, plaintext = pair_factory(node={"router": router})
    node.naive.router_url = "socks5://127.0.0.1:45101"
    async with linked(central, plaintext, login_user) as (client, node_id):
        target = f"/api/routing/targets/{node_id}/naive"
        path = f"/api/routing/policies/{node_id}/naive"
        attached = await request(client, "POST", target + "/attach")
        assert attached["target"]["policy"]["state"] == "applying"
        await converge(node, central)
        assert node.naive.egress_document == attach_document("naive")
        policy = (await client.get(path)).json()
        assert policy["state"] == "applied" and policy["applied_digest"] == document_digest(ROUTER_DIRECT_INTENT)
        saved = await request(client, "PUT", path, {**WARP, "expected_revision": policy["revision"],
            "rules": [{"action": "block", "match": {"geosites": ["category-ads-all"]}}]})
        result = await request(client, "POST", path + "/apply", {"expected_revision": saved["revision"]})
        assert result["compiled"]["attach"] == attach_document("naive")
        await converge(node, central)
        assert router.documents["naive"]["rules"][0]["geosites"] == ["category-ads-all"]
        assert (await client.get(path)).json()["applied_current"] is True
        history = (await client.get(path + "/history")).json()["items"]
        assert history[0]["backend"] == "xray_router"
        rolled = await request(client, "POST", path + "/rollback", {"expected_revision": saved["revision"]})
        assert rolled["compiled"]["document"] == ROUTER_DIRECT_INTENT
        await converge(node, central)
        assert router.documents["naive"] == ROUTER_DIRECT_INTENT
        await request(client, "POST", target + "/detach")
        await converge(node, central)
        assert node.naive.egress_document == {"schema": 1, "upstream": None, "acl": []}
        assert (await client.get(path)).json()["backend"] == "naive_native"


async def test_remote_lanes_apply_and_delete_lifecycle_deliver_one_complete_intent(pair_factory, login_user):
    router = MemoryXrayRouter()
    node, central, plaintext = pair_factory(node={"router": router, "mieru_enabled": True})
    node.naive.router_url, node.mieru.router_url = "socks5://127.0.0.1:45101", "socks5://127.0.0.1:45102"
    async with linked(central, plaintext, login_user) as (client, node_id):
        created = await request(client, "POST", "/api/clients", {"display_name": "A"})
        client_id = created["id"]
        await request(client, "POST", f"/api/clients/{client_id}/grants", {"grants": [
            {"protocol": protocol, "node_id": node_id, "runtime_username": username, "options": {}}
            for protocol, username in (("naive", "alice"), ("mieru", "phone"))]})
        await converge(node, central)
        grants = {row["protocol"]: row for row in (await client.get(f"/api/clients/{client_id}")).json()["grants"]}
        await request(client, "POST", f"/api/routing/targets/{node_id}/naive/attach")
        await converge(node, central)
        grant_id = grants["naive"]["id"]
        lane = f"grant:{grant_id}"
        enabled = await request(client, "POST", f"/api/routing/lanes/{grant_id}", {"mode": "own"})
        assert enabled["pending"] is True and enabled["lane"] == lane
        await converge(node, central)
        assert node.naive.lane_table[lane]["users"] == ["alice"]
        path = f"/api/routing/policies/{node_id}/naive?lane={lane}"
        await request(client, "PUT", path, {**WARP, "backend": "xray_router", "expected_revision": 1})
        applied = await request(client, "POST", f"/api/routing/policies/{node_id}/naive/apply?lane={lane}",
                                {"expected_revision": 2})
        assert applied["compiled"]["document"]["schema"] == 2
        await converge(node, central)
        assert router.documents["naive"]["lanes"][lane]["default"] == {"action": "egress", "egress": "warp"}
        assert (await client.get(path)).json()["state"] == "applied"
        mieru_id = grants["mieru"]["id"]
        await request(client, "POST", f"/api/routing/lanes/{mieru_id}", {"mode": "own"})
        await converge(node, central)
        listing = (await client.get(f"/api/clients/{client_id}")).json()["grants"]
        mieru = next(row for row in listing if row["protocol"] == "mieru")
        assert f"port={node.mieru.lane_slots[1]}" in mieru["options"]["share_template"]
        await request(client, "POST", f"/api/routing/lanes/{mieru_id}", {"mode": "service"})
        await converge(node, central)
        assert node.mieru.lane_table == {}
        await request(client, "POST", f"/api/clients/grants/{grant_id}/delete")
        await converge(node, central)
        assert lane not in router.lane_accounts["naive"] and node.naive.lane_table == {}
        assert list(router.documents["naive"]["lanes"]) == ["svc:naive"]
        assert (await client.get(path)).status_code == 404


async def test_remote_relay_account_confirmation_chain_redaction_explain_and_rotation(pair_factory, login_user):
    edge_router, local_router = MemoryXrayRouter(), MemoryXrayRouter()
    node, central, plaintext = pair_factory(node={"router": edge_router}, central={"router": local_router})
    node.naive.router_url = central.naive.router_url = "socks5://127.0.0.1:45101"
    async with linked(central, plaintext, login_user) as (client, node_id):
        enabled = await request(client, "POST", f"/api/routing/relay/{node_id}/enable")
        assert enabled["pending"] is True and enabled["public_key"] is None
        await converge(node, central)
        assert edge_router.relay_state["enabled"] is True
        await request(client, "POST", "/api/routing/targets/local/naive/attach")
        path = "/api/routing/policies/local/naive"
        await request(client, "PUT", path, {"default_action": "egress", "default_egress": f"node:{node_id}",
                                           "expected_revision": 1})
        pending = await client.post(path + "/apply", json={"expected_revision": 2}, headers=csrf(client))
        assert pending.status_code == 422, pending.text
        assert [reason["code"] for reason in pending.json()["compiled"]["reasons"]] == ["relay_credential_pending"]
        await converge(node, central)
        applied = await request(client, "POST", path + "/apply", {"expected_revision": 2})
        hop = applied["compiled"]["document"]["chains"]["c1"]["hops"][0]
        assert hop["uuid"] == "***" and hop["address"] == "node.example"
        account = next(row for row in edge_router.relay_state["accounts"] if row["email"].endswith(":direct"))
        assert local_router.documents["naive"]["chains"]["c1"]["hops"][0]["uuid"] == account["uuid"]
        history = await client.get(path + "/history")
        assert account["uuid"] not in history.text and account["uuid"] not in json.dumps(central.audits())
        explained = await request(client, "POST", path + "/explain", {"host": "example.com"})
        assert explained["hops"] == [node_id] and explained["hop_names"] == ["Edge"]
        rotated = await request(client, "POST", f"/api/routing/relay/{node_id}/rotate")
        assert rotated["rotated"] == 2
        await converge(node, central)
        assert account["uuid"] not in [row["uuid"] for row in edge_router.relay_state["accounts"]]
