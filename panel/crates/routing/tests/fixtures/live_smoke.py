"""Isolated Rust-panel → real Rust-router → Xray preview/apply/rollback smoke.

Run only on ams-test, with PANEL_IMPL=rust, PANEL_RUST_BIN and
WP10_ROUTER_MANAGER_BIN set. The installed Xray artifacts are read-only inputs.
The native Naive manager is a wire double only for the attach companion; every
router operation and the SOCKS data-plane probes use the real manager and Xray.
No installed service, configuration, socket or listener is changed.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
from unittest import mock

import httpx

from panel.naive import MemoryNaive
from panel.tests.conftest import login
from panel.tests.harness.fake_managers import FakeManagers, attach_pending
from panel.tests.harness.server import start_panel


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def main():
    assert os.environ["PANEL_IMPL"] == "rust"
    binary = Path(os.environ["WP10_ROUTER_MANAGER_BIN"])
    artifacts = Path(os.environ.get("WP10_XRAY_ARTIFACTS", "/usr/local/lib/proxy-control/xray-router"))
    with tempfile.TemporaryDirectory(prefix="wp10-live-") as temp:
        root = Path(temp)
        token = root / "manager-token"
        token.write_text(secrets.token_hex(24))
        user, password = "wp10", secrets.token_urlsafe(24)
        ingress = root / "ingress"
        ingress.write_text(f"{user}:{password}")
        port, mieru_port = free_port(), free_port()
        manager_socket = root / "manager.sock"
        env = {**os.environ, "XRAY_ROUTER_BIN_DIR": str(artifacts),
               "XRAY_ROUTER_STATE_DIR": str(root / "state"), "XRAY_ROUTER_SOCKET": str(manager_socket),
               "XRAY_ROUTER_MANAGER_TOKEN_FILE": str(token),
               "XRAY_ROUTER_INGRESS_NAIVE_FILE": str(ingress), "XRAY_ROUTER_INGRESS_MIERU_FILE": str(ingress),
               "XRAY_ROUTER_PORT_NAIVE": str(port), "XRAY_ROUTER_PORT_MIERU": str(mieru_port),
               "XRAY_ROUTER_INGRESS_MTPROXY_SOCKET": "", "XRAY_ROUTER_PORT_TRUSTTUNNEL": "",
               "XRAY_ROUTER_TUN_AMNEZIAWG": "", "XRAY_ROUTER_EGRESS_WARP": "",
               "XRAY_ROUTER_XRAY_SHA256": digest(artifacts / "xray"),
               "XRAY_ROUTER_GEOIP_SHA256": digest(artifacts / "geoip.dat"),
               "XRAY_ROUTER_GEOSITE_SHA256": digest(artifacts / "geosite.dat")}
        with (root / "manager.log").open("wb") as output:
            manager = subprocess.Popen([str(binary)], env=env, stdout=output, stderr=output)
        panel = None
        origin = None
        try:
            for _ in range(500):
                if manager_socket.exists():
                    break
                if manager.poll() is not None:
                    raise AssertionError((root / "manager.log").read_text())
                await asyncio.sleep(0.02)
            assert manager_socket.exists(), "real router did not bind"
            transport = httpx.AsyncHTTPTransport(uds=str(manager_socket))
            async with httpx.AsyncClient(transport=transport, base_url="http://router",
                                         headers={"X-Xray-Router-Token": token.read_text()}) as router:
                health = await router.get("/v1/health")
                assert health.status_code == 200, health.text
                print("REAL_ROUTER_HEALTH", health.json(), flush=True)

            naive = MemoryNaive()
            naive.router_url = f"socks5://127.0.0.1:{port}"
            original_env = FakeManagers.env

            def runtime_env(managers):
                return {**original_env(managers), "XRAY_ROUTER_MANAGER_SOCKET": str(manager_socket),
                        "XRAY_ROUTER_MANAGER_TOKEN_FILE": str(token), "XRAY_ROUTER_ENABLED": "true"}

            with mock.patch.object(FakeManagers, "env", runtime_env):
                panel = start_panel(root, name="live-panel", naive=naive, naive_enabled=True,
                                    naive_public_host="naive.example.com", vnext_writer="domain")
            panel.create_admin("owner", "correct horse battery staple", "owner")
            attach_pending()

            async def serve_origin(reader, writer):
                await reader.readuntil(b"\r\n\r\n")
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nWP10-ORIGIN\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            # Private/loopback destinations are immutably blocked by the router, independently
            # of a policy. Use this lab host's global interface for the isolated origin.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect(("8.8.8.8", 53))
                origin_host = route.getsockname()[0]
            assert ipaddress.ip_address(origin_host).is_global, origin_host
            origin = await asyncio.start_server(serve_origin, origin_host, 0)
            origin_port = origin.sockets[0].getsockname()[1]

            async def through_xray():
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                try:
                    writer.write(b"\x05\x01\x02")
                    await writer.drain()
                    assert await reader.readexactly(2) == b"\x05\x02"
                    writer.write(bytes([1, len(user)]) + user.encode() + bytes([len(password)]) + password.encode())
                    await writer.drain()
                    assert await reader.readexactly(2) == b"\x01\x00"
                    writer.write(b"\x05\x01\x00\x01" + socket.inet_aton(origin_host) + origin_port.to_bytes(2, "big"))
                    await writer.drain()
                    answer = await reader.readexactly(10)
                    assert answer[1] == 0, answer
                    writer.write(b"GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    return await asyncio.wait_for(reader.read(), 5)
                except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
                    return b""
                finally:
                    writer.close()
                    await writer.wait_closed()

            async with panel.http() as client:
                await login(client)
                headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
                attached = await client.post("/api/routing/targets/local/naive/attach", headers=headers)
                assert attached.status_code == 200, attached.text
                assert b"WP10-ORIGIN" in await through_xray()
                policy = await client.put("/api/routing/policies/local/naive", headers=headers, json={
                    "expected_revision": 1, "backend": "xray_router",
                    "rules": [{"action": "block", "match": {"cidrs": [f"{origin_host}/32"]}}]})
                assert policy.status_code == 200, policy.text
                preview = await client.post("/api/routing/policies/local/naive/preview", headers=headers)
                assert preview.status_code == 200 and preview.json()["status"] == "supported", preview.text
                applied = await client.post("/api/routing/policies/local/naive/apply", headers=headers,
                                            json={"expected_revision": 2})
                assert applied.status_code == 200, applied.text
                assert applied.json()["compiled"]["digest"] == preview.json()["digest"]
                assert applied.json()["policy"]["state"] == "applied"
                assert b"WP10-ORIGIN" not in await through_xray(), "Xray did not enforce the CIDR block"
                rolled = await client.post("/api/routing/policies/local/naive/rollback", headers=headers,
                                           json={"expected_revision": 2})
                assert rolled.status_code == 200 and rolled.json()["policy"]["state"] == "rolled_back", rolled.text
                assert b"WP10-ORIGIN" in await through_xray(), "rollback did not restore traffic"
                history = await client.get("/api/routing/policies/local/naive/history")
                assert [row["outcome"] for row in history.json()["items"]][:2] == ["rolled_back", "applied"]
                assert password not in history.text and password not in json.dumps(panel.audits())
                print("REAL_XRAY_SMOKE", json.dumps({"preview": preview.json()["digest"],
                      "apply": applied.json()["policy"]["state"], "rollback": rolled.json()["policy"]["state"],
                      "traffic": ["direct_pass", "cidr_block", "rollback_pass"]}), flush=True)
        finally:
            if origin is not None:
                origin.close()
                await origin.wait_closed()
            if panel is not None:
                await panel.aclose()
            manager.terminate()
            try:
                manager.wait(timeout=15)
            except subprocess.TimeoutExpired:
                manager.kill()
                manager.wait()
            if manager.returncode not in (0, -15):
                print((root / "manager.log").read_text(), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
