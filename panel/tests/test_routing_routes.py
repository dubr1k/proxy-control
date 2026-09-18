"""The routing API over HTTP (spec §8.1): roles, revisions, preview, apply, delete, history."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio

WARP = {"default_action": "egress", "default_egress": "warp", "fallback": "fail_closed", "rules": []}
BLOCK = {"rules": [{"action": "block", "match": {"domains": ["example.com", "*.example.com"]}, "note": "ads"}]}


def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.cookies["panel_csrf"]}


async def test_viewer_reads_and_previews_but_never_mutates(client, login_user):
    await login_user(client)
    put = await client.put("/api/routing/policies/local/naive", json={**WARP, "expected_revision": None}, headers=_csrf(client))
    assert put.status_code == 200 and put.json()["revision"] == 1
    await client.post("/api/auth/logout", headers=_csrf(client))
    client.cookies.clear()
    client._transport.app.state.store.create_admin("reader", "viewer correct horse battery", "viewer")
    await login_user(client, "reader", "viewer correct horse battery")
    targets = await client.get("/api/routing/targets")
    assert targets.status_code == 200
    naive = next(item for item in targets.json()["items"] if item["protocol"] == "naive")
    assert naive["backend"] == "naive_native" and naive["policy"]["revision"] == 1 and naive["kind"] == "local"
    assert next(item for item in targets.json()["items"] if item["protocol"] == "mtproxy")["reason"] == "protocol_out_of_scope"
    assert (await client.get("/api/routing/policies/local/naive")).status_code == 200
    preview = await client.post("/api/routing/policies/local/naive/preview", json=BLOCK, headers=_csrf(client))
    assert preview.status_code == 200 and preview.json()["status"] == "supported"
    assert (await client.get("/api/routing/policies/local/naive/history")).status_code == 200
    for method, path, body in (("PUT", "/api/routing/policies/local/naive", WARP),
                               ("DELETE", "/api/routing/policies/local/naive", None),
                               ("POST", "/api/routing/policies/local/naive/apply", {"expected_revision": 1}),
                               ("POST", "/api/routing/policies/local/naive/rollback", {"expected_revision": 1})):
        response = await client.request(method, path, json=body, headers=_csrf(client))
        assert response.status_code == 403, (method, path)
    assert (await client.get("/api/routing/policies/local/naive")).json()["revision"] == 1


async def test_put_upserts_with_expected_revision_and_keeps_rule_ids(client, login_user):
    await login_user(client)
    created = await client.put("/api/routing/policies/local/mieru", json=BLOCK, headers=_csrf(client))
    assert created.status_code == 200
    body = created.json()
    assert body["revision"] == 1 and body["state"] == "draft" and body["backend"] == "mieru_native"
    rule_id = body["rules"][0]["id"]
    assert body["rules"][0]["match"] == {"domains": ["example.com", "*.example.com"], "cidrs": [], "ports": [], "geosites": [], "geoips": [], "protocols": []}
    assert body["applied_current"] is False
    stale = await client.put("/api/routing/policies/local/mieru", json={**BLOCK, "expected_revision": 5}, headers=_csrf(client))
    assert stale.status_code == 409 and stale.json()["code"] == "policy_conflict"
    rules = [{"id": rule_id, "action": "block", "match": {"domains": ["example.com"]}, "enabled": False},
             {"action": "egress", "egress": "warp", "match": {"cidrs": ["203.0.113.0/24"]}}]
    updated = await client.put("/api/routing/policies/local/mieru", json={"rules": rules, "expected_revision": 1},
                               headers=_csrf(client))
    assert updated.status_code == 200 and updated.json()["revision"] == 2
    assert [r["id"] for r in updated.json()["rules"]][0] == rule_id and updated.json()["rules"][0]["enabled"] is False
    assert updated.json()["rules"][1]["position"] == 1 and updated.json()["rules"][1]["id"] != rule_id
    for bad in ({"rules": [{"action": "egress", "match": {"domains": ["a.com"]}}]},
                {"default_action": "egress"}, {"rules": [{"action": "block", "match": {}}]},
                {"rules": [{"action": "block", "match": {"domains": ["a.com"]}, "surprise": 1}]},
                {"revision": 3}):
        assert (await client.put("/api/routing/policies/local/mieru", json=bad, headers=_csrf(client))).status_code == 422, bad
    out = await client.put("/api/routing/policies/local/mtproxy", json=BLOCK, headers=_csrf(client))
    assert out.status_code == 422 and out.json()["code"] == "protocol_out_of_scope"
    missing = await client.put("/api/routing/policies/ghost/naive", json=BLOCK, headers=_csrf(client))
    assert missing.status_code == 404 and missing.json()["code"] == "node_not_found"
    assert (await client.get("/api/routing/policies/local/naive")).status_code == 404
    mismatch = await client.put("/api/routing/policies/local/naive", json={**BLOCK, "backend": "mieru_native"}, headers=_csrf(client))
    assert mismatch.status_code == 422 and mismatch.json()["code"] == "backend_mismatch"


async def test_preview_of_a_draft_does_not_save(client, login_user):
    await login_user(client)
    draft = {"rules": [{"action": "egress", "egress": "warp", "match": {"domains": ["a.com"]}}]}
    preview = await client.post("/api/routing/policies/local/naive/preview", json=draft, headers=_csrf(client))
    assert preview.status_code == 200
    body = preview.json()
    assert body["status"] == "unsupported" and body["reasons"][0]["code"] == "backend_capability_missing"
    assert body["document"] is None and body["compiler_version"] == "3"
    assert (await client.get("/api/routing/policies/local/naive")).status_code == 404
    stored = await client.post("/api/routing/policies/local/naive/preview", headers=_csrf(client))
    assert stored.status_code == 404 and stored.json()["code"] == "policy_not_found"
    await client.put("/api/routing/policies/local/naive", json=WARP, headers=_csrf(client))
    stored = await client.post("/api/routing/policies/local/naive/preview", headers=_csrf(client))
    assert stored.status_code == 200 and stored.json()["document"] == {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}
    assert stored.json()["diff"] and stored.json()["restart_required"] is False


async def test_apply_rollback_delete_and_history(client, login_user, naive):
    await login_user(client)
    await client.put("/api/routing/policies/local/naive", json=BLOCK, headers=_csrf(client))
    conflict = await client.post("/api/routing/policies/local/naive/apply", json={"expected_revision": 2}, headers=_csrf(client))
    assert conflict.status_code == 409 and conflict.json()["code"] == "policy_conflict"
    applied = await client.post("/api/routing/policies/local/naive/apply", json={"expected_revision": 1}, headers=_csrf(client))
    assert applied.status_code == 200
    body = applied.json()
    assert body["policy"]["state"] == "applied" and body["policy"]["applied_current"] is True
    assert body["applied"]["digest"] == body["compiled"]["digest"] == body["policy"]["applied_digest"]
    assert naive.egress_document["acl"] == [{"deny": ["example.com", "*.example.com"]}]
    deleted = await client.delete("/api/routing/policies/local/naive", headers=_csrf(client))
    assert deleted.status_code == 409 and deleted.json()["code"] == "policy_applied"
    # An unsupported edit is refused at apply with the compiled reasons, nothing changes.
    await client.put("/api/routing/policies/local/naive", json={**WARP, **BLOCK, "expected_revision": 1}, headers=_csrf(client))
    refused = await client.post("/api/routing/policies/local/naive/apply", json={"expected_revision": 2}, headers=_csrf(client))
    assert refused.status_code == 422 and refused.json()["code"] == "unsupported"
    assert refused.json()["compiled"]["reasons"][0]["code"] == "rule_kind_unsupported"
    # A manager refusal is a 409 with the manager's code and a failed history row.
    await client.put("/api/routing/policies/local/naive", json={**WARP, "expected_revision": 2}, headers=_csrf(client))
    naive.reachable = False
    unreachable = await client.post("/api/routing/policies/local/naive/apply", json={"expected_revision": 3}, headers=_csrf(client))
    assert unreachable.status_code == 422 and unreachable.json()["compiled"]["reasons"][0]["code"] == "provider_unreachable"
    naive.reachable = True
    naive.egress_fail_next = "egress_unreachable"
    unreachable = await client.post("/api/routing/policies/local/naive/apply", json={"expected_revision": 3}, headers=_csrf(client))
    assert unreachable.status_code == 409 and unreachable.json()["code"] == "egress_unreachable"
    policy = (await client.get("/api/routing/policies/local/naive")).json()
    assert policy["state"] == "failed" and policy["last_error"] == "egress_unreachable" and policy["applied_revision"] == 1
    assert (await client.post("/api/routing/policies/local/naive/apply", json={"expected_revision": 3}, headers=_csrf(client))).status_code == 200
    rolled = await client.post("/api/routing/policies/local/naive/rollback", json={"expected_revision": 3}, headers=_csrf(client))
    assert rolled.status_code == 200 and rolled.json()["policy"]["state"] == "rolled_back"
    assert rolled.json()["policy"]["applied_revision"] == 1 and naive.egress_document["upstream"] is None
    history = (await client.get("/api/routing/policies/local/naive/history")).json()["items"]
    assert [row["outcome"] for row in history] == ["rolled_back", "applied", "failed", "applied"]
    assert history[0]["actor"] == "owner" and history[0]["compiler_version"] == "3"
    audit = (await client.get("/api/audit")).json()["items"]
    actions = [row["action"] for row in audit]
    assert {"routing.policy.update", "routing.policy.apply", "routing.policy.rollback"} <= set(actions)
    assert "socks5://" not in str(audit)
    # Reset and apply, then the policy may go.
    await client.put("/api/routing/policies/local/naive", json={"expected_revision": 3}, headers=_csrf(client))
    assert (await client.post("/api/routing/policies/local/naive/apply", json={"expected_revision": 4}, headers=_csrf(client))).status_code == 200
    assert (await client.delete("/api/routing/policies/local/naive", headers=_csrf(client))).status_code == 204
    assert "routing.policy.delete" in [row["action"] for row in (await client.get("/api/audit")).json()["items"]]
    assert (await client.get("/api/routing/policies/local/naive")).status_code == 404
