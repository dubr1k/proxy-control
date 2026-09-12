"""Linked panels on the central side (spec §6): how to reach them, never their key in clear.

The node's API key is stored through `SecretStore` (purpose `node-api-key`, bound to
the node's guid) and revealed for one client at a time; rows, views and audit
details only ever say that a key exists. Network calls happen outside transactions.
"""
from __future__ import annotations

import json
import secrets as secret_tokens
import time

from ..audit import record
from ..nodes.registry import NodeRegistry
from ..secrets_store import SecretRef
from .client import TLS_MODES, NodeAuthFailed, NodeClient, NodeRejected, NodeUnreachable, validate_panel_url

KEY_PURPOSE = "node-api-key"
CLIENT_ERRORS = (NodeUnreachable, NodeAuthFailed, NodeRejected)


class LinkConflict(Exception):
    pass


class NodeLinkService:
    def __init__(self, database, secrets, nodes, *, own_guid: str, client_factory=NodeClient, clock=time):
        self.database, self.secrets, self.nodes = database, secrets, nodes
        self.own_guid, self.client_factory, self.clock = own_guid, client_factory, clock

    # --- rows -------------------------------------------------------------------

    @staticmethod
    def link(db, node_id: str) -> dict:
        row = db.execute("SELECT * FROM node_links WHERE node_id=?", (node_id,)).fetchone()
        if row is None:
            raise KeyError(node_id)
        return NodeRegistry.link_row(row)

    @staticmethod
    def links(db) -> list[dict]:
        return [NodeRegistry.link_row(row) for row in db.execute("SELECT * FROM node_links ORDER BY node_id")]

    def _reveal_key(self, db, link: dict) -> str:
        return self.secrets.reveal(db, SecretRef(link["api_key_secret_id"], 1), purpose=KEY_PURPOSE, grant_id=None,
                                   permitted_node_id=link["node_id"]).decode()

    def _store_key(self, db, node_id: str, api_key: str) -> str:
        """A fresh secret id per key: rotation is a new row, never an overwrite."""
        secret_id = f"node-key:{node_id}:{secret_tokens.token_hex(4)}"
        self.secrets.store(db, secret_id=secret_id, version=1, purpose=KEY_PURPOSE, grant_id=None,
                           permitted_node_id=node_id, plaintext=api_key.encode(), state="active")
        return secret_id

    def _client(self, link: dict, key: str) -> NodeClient:
        return self.client_factory(link["panel_url"], key, tls_verify=link["tls_verify"],
                                   pinned_sha256=link["pinned_cert_sha256"])

    def client_for(self, node_id: str) -> NodeClient:
        with self.database.connect() as db:
            link = self.link(db, node_id)
            key = self._reveal_key(db, link)
        return self._client(link, key)

    # --- operator actions --------------------------------------------------------

    async def test(self, url, api_key, tls_verify, pinned_sha256, allow_private) -> dict:
        """identity + status + inventory of the panel at `url`, nothing stored."""
        url = validate_panel_url(url, allow_private=allow_private)
        client = self.client_factory(url, api_key, tls_verify=tls_verify, pinned_sha256=pinned_sha256)
        started = self.clock.monotonic()
        try:
            identity = await client.identity()
            status = await client.status()
            inventory = await client.inventory()
        except NodeAuthFailed as exc:
            raise LinkConflict("the node refused the API key") from exc
        except NodeUnreachable as exc:
            raise LinkConflict(f"the node is unreachable: {exc}") from exc
        except NodeRejected as exc:
            raise LinkConflict(f"the node answered {exc.status}: {exc}") from exc
        return {"identity": identity, "status": status, "inventory": inventory,
                "latency_ms": int((self.clock.monotonic() - started) * 1000), "url": url}

    async def add(self, display_name, url, api_key, tls_verify, pinned_sha256, allow_private, *, actor, ip,
                  request_id=None) -> str:
        probe = await self.test(url, api_key, tls_verify, pinned_sha256, allow_private)
        identity = probe["identity"]
        if identity.get("api_version") != 2 or not identity.get("guid"):
            raise LinkConflict("the panel does not speak Fleet API v2")
        if identity.get("master_guid") not in (None, self.own_guid):
            raise LinkConflict("the panel is already managed by another central panel")
        node_id = identity["guid"]
        if node_id == self.own_guid:
            raise LinkConflict("a panel cannot manage itself")
        now = int(self.clock.time())
        with self.database.transaction() as db:
            if db.execute("SELECT 1 FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone():
                raise LinkConflict("this panel is already linked")
            NodeRegistry.insert(db, node_id, display_name, transport="panel")
            db.execute("UPDATE fleet_nodes SET auth_state='linked' WHERE node_id=?", (node_id,))
            secret_id = self._store_key(db, node_id, api_key)
            # What the probe saw is kept for the operator; `status` stays `unknown` until
            # the first heartbeat, which is what turns it into a `node.up` event.
            db.execute("""INSERT INTO node_links(node_id,panel_url,tls_verify,pinned_cert_sha256,api_key_secret_id,
                          allow_private_address,latency_ms,panel_version,identity_json,status_json,created_at,updated_at)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (node_id, probe["url"], tls_verify, pinned_sha256, secret_id, 1 if allow_private else 0,
                        probe["latency_ms"], identity.get("panel_version"), json.dumps(identity),
                        json.dumps(probe["status"]), now, now))
            record(db, actor=actor, action="node.link", target=node_id, ip=ip, request_id=request_id,
                   detail={"display_name": display_name, "panel": probe["url"], "tls_verify": tls_verify})
        return node_id

    def update(self, node_id: str, *, display_name=None, url=None, api_key=None, tls_verify=None, pinned_sha256=None,
               actor, ip, request_id=None) -> None:
        """Only the fields given change; a new key gets a new secret row and the old one is revoked."""
        now = int(self.clock.time())
        with self.database.transaction() as db:
            link = self.link(db, node_id)
            changes, changed = {}, []
            if display_name is not None:
                NodeRegistry.rename(db, node_id, display_name)
                changed.append("display_name")
            if url is not None:
                changes["panel_url"] = validate_panel_url(url, allow_private=bool(link["allow_private_address"]))
            mode = link["tls_verify"] if tls_verify is None else tls_verify
            pin = link["pinned_cert_sha256"] if pinned_sha256 is None else pinned_sha256
            if mode not in TLS_MODES:
                raise ValueError("tls_verify must be verify or pin")
            if mode == "pin" and not pin:
                raise ValueError("pin mode needs pinned_sha256")
            if tls_verify is not None:
                changes["tls_verify"] = mode
            if pinned_sha256 is not None:
                changes["pinned_cert_sha256"] = pin
            if api_key is not None:
                changes["api_key_secret_id"] = self._store_key(db, node_id, api_key)
                self.secrets.transition(db, SecretRef(link["api_key_secret_id"], 1), "revoked")
                changed.append("api_key")
            changed += [column for column in changes if column != "api_key_secret_id"]
            if changes:
                assignments = ",".join(f"{column}=?" for column in changes)
                db.execute(f"UPDATE node_links SET {assignments},updated_at=? WHERE node_id=?",
                           (*changes.values(), now, node_id))
            record(db, actor=actor, action="node.link.update", target=node_id, ip=ip, request_id=request_id,
                   detail={"changed": sorted(changed)})

    def set_enabled(self, node_id: str, enabled: bool, *, actor, ip, request_id=None) -> None:
        """Pause/resume: a paused link is skipped by the heartbeat and push loop."""
        with self.database.transaction() as db:
            changed = db.execute("UPDATE node_links SET enabled=?,updated_at=? WHERE node_id=?",
                                 (1 if enabled else 0, int(self.clock.time()), node_id)).rowcount
            if changed != 1:
                raise KeyError(node_id)
            record(db, actor=actor, action="node.resume" if enabled else "node.pause", target=node_id, ip=ip,
                   request_id=request_id)

    async def delete(self, node_id: str, *, actor, ip, request_id=None) -> None:
        """Refused while a grant on the node is not deleted. Tells the node to forget its
        master (best effort) and removes the row, its generations and its key."""
        with self.database.connect() as db:
            link = self.link(db, node_id)
            if NodeRegistry.active_grants(db, node_id):
                raise LinkConflict("the node still carries grants that are not deleted")
            key = self._reveal_key(db, link)
        try:
            await self._client(link, key).unlink()
            released = True
        except CLIENT_ERRORS:
            # The node's owner can still cut the link from that panel's own UI.
            released = False
        with self.database.transaction() as db:
            if NodeRegistry.active_grants(db, node_id):
                raise LinkConflict("the node still carries grants that are not deleted")
            # Deleted grants are history the node no longer needs, and they would keep the
            # node row alive (ON DELETE RESTRICT). fleet_nodes cascades to node_links,
            # desired_generations and observed_generations.
            db.execute("DELETE FROM access_grants WHERE node_id=?", (node_id,))
            db.execute("DELETE FROM secret_versions WHERE secret_id=? AND purpose=?",
                       (link["api_key_secret_id"], KEY_PURPOSE))
            db.execute("DELETE FROM fleet_nodes WHERE node_id=?", (node_id,))
            record(db, actor=actor, action="node.unlink", target=node_id, ip=ip, request_id=request_id,
                   detail={"node_released": released})

    # --- heartbeat bookkeeping ---------------------------------------------------

    def record_heartbeat(self, db, node_id: str, *, online: bool, identity=None, status=None, latency_ms=None,
                         error=None) -> str | None:
        """Inside the caller's transaction. Returns `node.up` / `node.down` only when the
        status actually changed, so the caller can emit exactly one event per transition."""
        row = db.execute("SELECT status FROM node_links WHERE node_id=?", (node_id,)).fetchone()
        if row is None:
            raise KeyError(node_id)
        now = int(self.clock.time())
        current = "online" if online else "offline"
        if online:
            # A failed contact keeps what the last good one reported; a good one refreshes it.
            fields = {"status": current, "last_heartbeat_at": now, "last_error": None}
            if latency_ms is not None:
                fields["latency_ms"] = latency_ms
            if identity is not None:
                fields["identity_json"] = json.dumps(identity)
                fields["panel_version"] = identity.get("panel_version")
            if status is not None:
                fields["status_json"] = json.dumps(status)
        else:
            fields = {"status": current, "last_error": error}
        fields["updated_at"] = now
        assignments = ",".join(f"{column}=?" for column in fields)
        db.execute(f"UPDATE node_links SET {assignments} WHERE node_id=?", (*fields.values(), node_id))
        if row["status"] == current:
            return None
        return "node.up" if online else "node.down"
