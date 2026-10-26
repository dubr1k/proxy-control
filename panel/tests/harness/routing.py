"""Routing acceptance helpers using only the operator HTTP API and harness controls."""
from __future__ import annotations

from contextlib import asynccontextmanager
import copy
import hashlib
import json

# Frozen manager wire expectations; no production implementation is imported by the oracle.
ROUTER_DIRECT_INTENT = {"schema": 1, "default": {"action": "direct", "egress": None}, "rules": []}
ATTACH_DOCUMENTS = {
    "naive": {"schema": 1, "upstream": {"provider": "router"}, "acl": []},
    "mieru": {"schema": 1, "proxies": [{"name": "router", "provider": "router"}],
              "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "router"}]},
    "mtproxy": {"schema": 1, "upstream": {"provider": "router"}},
    "trusttunnel": {"mode": "socks5", "address": "127.0.0.1:45104"},
    "amneziawg": {"schema": 1, "upstream": {"provider": "router"}},
}


def attach_document(protocol):
    return copy.deepcopy(ATTACH_DOCUMENTS[protocol])


def document_digest(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def csrf(client):
    return {"X-CSRF-Token": client.cookies["panel_csrf"]}


@asynccontextmanager
async def linked(central, plaintext, login_user, *, auto_import=False):
    central.create_admin("owner", "correct horse battery staple", "owner")
    async with central.http() as client:
        await login_user(client)
        response = await client.post("/api/nodes/link", headers=csrf(client), json={
            "display_name": "Edge", "url": "https://node.example", "api_key": plaintext,
            "tls_verify": "verify", "auto_import": auto_import,
        })
        assert response.status_code == 201, response.text
        await central.tick("pusher")
        yield client, response.json()["node_id"]
