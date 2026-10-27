"""Native central/node delivery over real HTTPS with private-address and certificate pin checks.

PANEL_RUST_BIN=/target/debug/panel PYTHONPATH=. python panel/crates/fleet-central/tests/fixtures/native_tls_delivery.py
The managers are private harness socket servers; no installed service is touched.
This supplements native coverage; it does NOT prove Python 3.3 ↔ Rust 4.0 interoperability.
The old mixed launcher incorrectly toggled IMPL on a native-only harness and was retired.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile

from panel.tests.harness.memories.mieru import MemoryMieru
from panel.tests.harness.memories.naive import MemoryNaive
from panel.tests.harness.memories.telemt import MemoryTelemt
from panel.tests.harness.memories.wire import document_digest
from panel.tests.harness.server import start_panel


def certificate(directory):
    cert_path, key_path = directory / "cert.pem", directory / "tls.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key_path), "-out", str(cert_path), "-days", "1",
                    "-subj", "/CN=fleet.node.test", "-addext", "subjectAltName=DNS:fleet.node.test"],
                   check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_path.read_text())).hexdigest()
    return context, pin


async def request(http, method, path, body=None, expected=200):
    response = await http.request(method, path, json=body)
    assert response.status_code == expected, (method, path, response.status_code, response.text)
    return response.json()


async def delivery(directory, *, central_factory=start_panel, node_factory=start_panel,
                   central_impl="rust", node_impl="rust"):
    directory.mkdir()
    node = node_factory(directory, name="node", hosts=("testserver", "127.0.0.1", "localhost"),
        naive=MemoryNaive(), mieru=MemoryMieru(), telemt=MemoryTelemt(public_host="runtime.node.example"),
        naive_enabled=True, mieru_enabled=True, naive_public_host="public.node.example", vnext_writer="domain")
    central = central_factory(directory, name="central", naive=MemoryNaive(), mieru=MemoryMieru(),
        telemt=MemoryTelemt(), naive_enabled=True, mieru_enabled=True,
        naive_public_host="central.example", vnext_writer="domain")
    seen = []
    tls, pin = certificate(directory)

    async def forward(reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head.decode("latin1").split("\r\n")
                method, path, _ = lines[0].split(" ", 2)
                headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
                length = next((int(value) for name, value in headers.items() if name.lower() == "content-length"), 0)
                body = await reader.readexactly(length)
                seen.append((method, path))
                response = await node.client.request(method, path, content=body, headers=headers)
                payload = response.content
                writer.write(f"HTTP/1.1 {response.status_code} OK\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n".encode() + payload)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    listener = await asyncio.start_server(forward, "127.0.0.1", 0, ssl=tls)
    url = f"https://127.0.0.1:{listener.sockets[0].getsockname()[1]}"
    try:
        central.client.headers["Authorization"] = "Bearer " + central.create_api_key("operator", "admin")
        key = node.create_api_key("central", "node-sync")
        body = {"display_name": "Mixed edge", "url": url, "api_key": key,
                "tls_verify": "pin", "pinned_sha256": pin, "allow_private_address": True, "auto_import": False}
        # All three negatives precede any HTTP bearer byte on the TLS listener.
        before = len(seen)
        private = await central.client.post("/api/nodes/test", json={**body, "allow_private_address": False})
        assert private.status_code == 422 and len(seen) == before
        untrusted = await central.client.post("/api/nodes/test", json={**body, "tls_verify": "verify"})
        assert untrusted.status_code == 409 and len(seen) == before
        mismatch = await central.client.post("/api/nodes/test", json={**body, "pinned_sha256": "0" * 64})
        assert mismatch.status_code == 409 and len(seen) == before
        linked = await request(central.client, "POST", "/api/nodes/link", body, 201)
        node_id = linked["node_id"]
        client = await request(central.client, "POST", "/api/clients", {"display_name": "Mixed", "subscription": False}, 201)
        operation = await request(central.client, "POST", f"/api/clients/{client['id']}/grants", {"grants": [
            {"protocol": protocol, "node_id": node_id, "runtime_username": "mixed", "options": {}}
            for protocol in ("naive", "mieru", "mtproxy")]})
        assert operation["status"] == "pending_remote"
        await central.tick("pusher")
        await node.settle()
        await central.tick("pusher")
        assert (await request(central.client, "GET", f"/api/operations/{operation['operation_id']}"))["status"] == "succeeded"
        with central.db() as db:
            desired = dict(db.execute("SELECT * FROM desired_generations ORDER BY generation DESC LIMIT 1").fetchone())
            states = [row[0] for row in db.execute("SELECT state FROM secret_versions WHERE purpose='grant.credential'")]
        with node.db() as db:
            managed = dict(db.execute("SELECT * FROM managed_generations ORDER BY generation DESC LIMIT 1").fetchone())
        assert states == ["active"] * 3
        digest = document_digest(json.loads(desired["document_json"]))
        assert desired["digest"] == managed["digest"] == digest
        links = await request(central.client, "POST", f"/api/clients/{client['id']}/links")
        revealed = await request(central.client, "GET", "/api/reveal/" + links["reveal_token"])
        assert "runtime.node.example" in json.dumps(revealed) and "public.node.example" in json.dumps(revealed)
        assert await central.naive.list_users() == [] and await central.telemt.list_users() == []
        await request(central.client, "DELETE", f"/api/nodes/{node_id}?force=true")
        node.client.headers["Authorization"] = "Bearer " + key
        central_identity = await request(central.client, "GET", "/api/fleet/v2/identity")
        node_identity = await request(node.client, "GET", "/api/fleet/v2/identity")
        print(json.dumps({"central": central_impl, "node": node_impl, "tls_private_negatives": 3,
                          "central_version": central_identity["panel_version"],
                          "node_version": node_identity["panel_version"],
                          "delivered_protocols": 3, "generation": desired["generation"], "digest": digest,
                          "http_requests": len(seen)}, sort_keys=True), flush=True)
    finally:
        listener.close()
        await listener.wait_closed()
        await central.aclose()
        await node.aclose()


async def main():
    assert os.environ.get("PANEL_RUST_BIN"), "PANEL_RUST_BIN must name a test-hooks panel"
    with tempfile.TemporaryDirectory(prefix="fleet-native-tls-") as temporary:
        await delivery(Path(temporary) / "pair")


if __name__ == "__main__":
    asyncio.run(main())
