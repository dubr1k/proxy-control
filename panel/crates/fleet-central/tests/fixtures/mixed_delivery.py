"""Run both rolling-upgrade directions over real HTTPS (Python 3.13.5 + a test-hooks Rust panel).

PANEL_RUST_BIN=/target/debug/panel PYTHONPATH=. python panel/crates/fleet-central/tests/fixtures/mixed_delivery.py
The only managers used are the harness's private socket servers; no installed service is touched.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from panel.fleet_v2.protocol import GenerationDocument, canonical_digest
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.telemt import MemoryTelemt
from panel.tests.harness import server as python_server


def rust_harness():
    name = "panel.tests.harness.rust_mixed_server"
    spec = importlib.util.spec_from_file_location(name, python_server.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    setattr(module, "IMPL", "rust")
    return module


def certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fleet.node.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("fleet.node.test")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / "cert.pem", directory / "tls.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return context, pin


async def request(http, method, path, body=None, expected=200):
    response = await http.request(method, path, json=body)
    assert response.status_code == expected, (method, path, response.status_code, response.text)
    return response.json()


async def direction(directory, rust, central_impl, node_impl):
    directory.mkdir()
    modules = {"rust": rust, "python": python_server}
    node = modules[node_impl].start_panel(directory, name="node", hosts=("testserver", "127.0.0.1", "localhost"),
        naive=MemoryNaive(), mieru=MemoryMieru(), telemt=MemoryTelemt(public_host="runtime.node.example"),
        naive_enabled=True, mieru_enabled=True, naive_public_host="public.node.example", vnext_writer="domain")
    central = modules[central_impl].start_panel(directory, name="central", naive=MemoryNaive(), mieru=MemoryMieru(),
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
        digest = canonical_digest(GenerationDocument.model_validate_json(desired["document_json"]))
        assert desired["digest"] == managed["digest"] == digest
        links = await request(central.client, "POST", f"/api/clients/{client['id']}/links")
        revealed = await request(central.client, "GET", "/api/reveal/" + links["reveal_token"])
        assert "runtime.node.example" in json.dumps(revealed) and "public.node.example" in json.dumps(revealed)
        assert await central.naive.list_users() == [] and await central.telemt.list_users() == []
        await request(central.client, "DELETE", f"/api/nodes/{node_id}?force=true")
        print(json.dumps({"central": central_impl, "node": node_impl, "tls_private_negatives": 3,
                          "delivered_protocols": 3, "generation": desired["generation"], "digest": digest,
                          "http_requests": len(seen)}, sort_keys=True), flush=True)
    finally:
        listener.close()
        await listener.wait_closed()
        await central.aclose()
        await node.aclose()


async def main():
    assert sys.version_info[:3] == (3, 13, 5), sys.version
    assert os.environ.get("PANEL_RUST_BIN"), "PANEL_RUST_BIN must name a test-hooks panel"
    python_server.IMPL = "python"
    rust = rust_harness()
    with tempfile.TemporaryDirectory(prefix="fleet-mixed-") as temporary:
        directory = Path(temporary)
        await direction(directory / "rust-central", rust, "rust", "python")
        await direction(directory / "python-central", rust, "python", "rust")


if __name__ == "__main__":
    asyncio.run(main())
