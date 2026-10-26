from __future__ import annotations

import hashlib
import ssl
import time
from pathlib import Path

import httpx
import pytest

from panel.agent_transport import AgentTransportServer, CertificateAuthority
from panel.fleet import FleetStore
from panel.node_agent import AgentJournal, AgentTransportClient, NodeAgent

pytestmark = pytest.mark.anyio


def issue_fixture(tmp_path: Path, node_id: str):
    ca = CertificateAuthority(tmp_path / "ca")
    ca.initialize("test fleet CA")
    server_key, server_cert = ca.issue_server("localhost", ["localhost", "127.0.0.1"], days=2)
    node_key, node_cert, metadata = ca.issue_node(node_id, days=2)
    return ca, server_key, server_cert, node_key, node_cert, metadata


async def start_server(tmp_path, store, server_key, server_cert, client_ca, **kwargs):
    server = AgentTransportServer(
        store,
        host="127.0.0.1",
        port=0,
        server_cert=server_cert,
        server_key=server_key,
        client_ca=client_ca,
        poll_seconds=0.05,
        request_timeout=2,
        **kwargs,
    )
    await server.start()
    return server, f"https://localhost:{server.port}"


def mtls_context(ca, cert, key):
    context = ssl.create_default_context(cafile=str(ca))
    context.load_cert_chain(str(cert), str(key))
    return context












