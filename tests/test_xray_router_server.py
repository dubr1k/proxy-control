"""The router manager's Unix-socket API: token, routes, the error codes the panel acts on."""
from __future__ import annotations

import threading

import httpx

from tests.test_xray_router_manager import BLOCK_DOC, WARP_DOC, manager
from xray_router_manager.healthcheck import check
from xray_router_manager.server import ManagerHTTPServer

TOKEN = "ci-xray-router-token-0123456789abcdef0123456789abcdef"


def _serve(tmp_path, instance):
    socket_path = tmp_path / "manager.sock"
    server = ManagerHTTPServer(socket_path, instance, TOKEN)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, socket_path


def test_unix_api_routes_codes_and_health(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    server, thread, socket_path = _serve(tmp_path, instance)
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        headers = {"X-Xray-Router-Token": TOKEN}
        with httpx.Client(transport=transport, base_url="http://router") as client:
            assert client.get("/v1/status").status_code == 401
            status = client.get("/v1/status", headers=headers)
            assert status.status_code == 200 and status.json()["running"]["generation"] == 1
            assert client.get("/v1/health", headers=headers).json() == {"ready": True}
            assert client.get("/v1/egress/mtproxy", headers=headers).status_code == 404
            view = client.get("/v1/egress/naive", headers=headers)
            revision = view.json()["revision"]
            plan = client.post("/v1/egress/naive/plan", json={"expected_revision": revision, "document": WARP_DOC},
                               headers=headers)
            assert plan.status_code == 200 and plan.json()["restart_required"] is True
            stale = client.post("/v1/egress/naive/apply", json={"expected_revision": "0" * 64, "document": WARP_DOC,
                                                                 "operation_id": "op-1"}, headers=headers)
            assert (stale.status_code, stale.json()["code"]) == (409, "egress_conflict")
            bad = client.post("/v1/egress/naive/apply", json={"expected_revision": revision, "document": {"inbounds": []},
                                                               "operation_id": "op-1"}, headers=headers)
            assert (bad.status_code, bad.json()["code"]) == (422, "egress_invalid")
            extra = client.post("/v1/egress/naive/apply", json={"expected_revision": revision, "document": WARP_DOC,
                                                                 "operation_id": "op-1", "path": "/etc"}, headers=headers)
            assert extra.status_code == 422
            applied = client.post("/v1/egress/naive/apply", json={"expected_revision": revision, "document": WARP_DOC,
                                                                   "operation_id": "op-1"}, headers=headers)
            assert applied.status_code == 200 and applied.json()["generation"] == 2
            runner.fail_test = "code not found in geosite.dat: X"
            unknown = client.post("/v1/egress/naive/apply", json={"expected_revision": applied.json()["revision"],
                                                                   "document": BLOCK_DOC, "operation_id": "op-2"}, headers=headers)
            assert (unknown.status_code, unknown.json()["code"]) == (422, "geosite_unknown")
            no_previous = client.post("/v1/egress/mieru/rollback", json={"expected_revision": client.get(
                "/v1/egress/mieru", headers=headers).json()["revision"]}, headers=headers)
            assert (no_previous.status_code, no_previous.json()["code"]) == (409, "egress_no_previous")
            rolled = client.post("/v1/egress/naive/rollback", json={"expected_revision": applied.json()["revision"]},
                                 headers=headers)
            assert rolled.status_code == 200 and rolled.json()["generation"] == 3
            assert "N" * 40 not in status.text + view.text + plan.text + applied.text
        token_file = tmp_path / "token"
        token_file.write_text(TOKEN + "\n")
        assert check(socket_path, token_file) is True
        (tmp_path / "wrong").write_text("x" * 40)
        assert check(socket_path, tmp_path / "wrong") is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unix_api_reports_artifact_mismatch_and_broken_router(tmp_path):
    instance, runner = manager(tmp_path, bad_digest=True)
    try:
        instance.bootstrap()
    except Exception:  # noqa: BLE001 — the API still answers with the reason
        pass
    server, thread, socket_path = _serve(tmp_path, instance)
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        headers = {"X-Xray-Router-Token": TOKEN}
        with httpx.Client(transport=transport, base_url="http://router") as client:
            status = client.get("/v1/status", headers=headers)
            assert status.status_code == 503 and status.json()["artifact_error"]
            health = client.get("/v1/health", headers=headers)
            assert (health.status_code, health.json()["code"]) == (503, "artifact_mismatch")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unix_api_manual_intervention_and_readback_codes(tmp_path):
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    server, thread, socket_path = _serve(tmp_path, instance)
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        headers = {"X-Xray-Router-Token": TOKEN}
        with httpx.Client(transport=transport, base_url="http://router") as client:
            revision = client.get("/v1/egress/naive", headers=headers).json()["revision"]
            runner.fail_ready = 1
            restored = client.post("/v1/egress/naive/apply", json={"expected_revision": revision, "document": BLOCK_DOC,
                                                                    "operation_id": "op-1"}, headers=headers)
            assert (restored.status_code, restored.json()["code"]) == (502, "egress_readback_mismatch")
            runner.fail_ready = 2
            broken = client.post("/v1/egress/naive/apply", json={"expected_revision": revision, "document": BLOCK_DOC,
                                                                  "operation_id": "op-2"}, headers=headers)
            assert (broken.status_code, broken.json()["code"]) == (503, "manual_intervention_required")
            health = client.get("/v1/health", headers=headers)
            assert (health.status_code, health.json()["code"]) == (503, "manual_intervention_required")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unix_api_lanes_and_relay_routes(tmp_path):
    """v0.7: the panel mints lane accounts and drives the relay through the same door."""
    instance, runner = manager(tmp_path)
    instance.bootstrap()
    server, thread, socket_path = _serve(tmp_path, instance)
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        headers = {"X-Xray-Router-Token": TOKEN}
        with httpx.Client(transport=transport, base_url="http://router") as client:
            issued = client.post("/v1/lanes/naive", json={"lane": "grant:7f3a"}, headers=headers)
            assert issued.status_code == 200 and issued.json()["user"] == "grant-7f3a" and len(issued.json()["password"]) >= 32
            assert client.post("/v1/lanes/naive", json={"lane": "svc:naive"}, headers=headers).status_code == 422
            assert client.post("/v1/lanes/mtproxy", json={"lane": "grant:1"}, headers=headers).status_code == 404
            listed = client.get("/v1/lanes/naive", headers=headers)
            assert listed.status_code == 200 and listed.json() == {"lanes": ["grant:7f3a"]} and issued.json()["password"] not in listed.text
            gone = client.delete("/v1/lanes/naive/grant:7f3a", headers=headers)
            assert gone.status_code == 200 and gone.json() == {"lane": "grant:7f3a", "forgotten": True}
            unknown = client.delete("/v1/lanes/naive/grant:7f3a", headers=headers)
            assert (unknown.status_code, unknown.json()["code"]) == (409, "lane_unknown")
            relay = client.get("/v1/relay", headers=headers)
            assert relay.status_code == 200 and relay.json()["enabled"] is False
            enabled = client.post("/v1/relay", json={"server_name": "panel.node-a.example.org", "port": 45443}, headers=headers)
            assert enabled.status_code == 200 and enabled.json()["public_key"] == runner.public_key and enabled.json()["accounts"] == 0
            assert runner.private_key not in enabled.text
            accounts = client.put("/v1/relay/accounts", json={"accounts": [{"email": "relay:" + "c" * 32 + ":direct",
                                                                            "uuid": "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10"}]}, headers=headers)
            assert accounts.status_code == 200 and accounts.json()["accounts"] == 1 and "3f0d9c6e" not in accounts.text
            assert client.put("/v1/relay/accounts", json={"accounts": [{"email": "x", "uuid": "y"}]}, headers=headers).status_code == 422
            disabled = client.delete("/v1/relay", headers=headers)
            assert disabled.status_code == 200 and disabled.json()["enabled"] is False
            refused = client.put("/v1/relay/accounts", json={"accounts": []}, headers=headers)
            assert (refused.status_code, refused.json()["code"]) == (409, "relay_disabled")
            status = client.get("/v1/status", headers=headers).json()
            assert status["lanes"] == {"naive": [], "mieru": []} and status["relay"]["enabled"] is False
            assert {"lanes", "chains", "relay"} <= set(status["capabilities"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
