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
