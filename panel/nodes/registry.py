"""Node rows: reads and writes that a caller composes into one transaction."""
from __future__ import annotations

import json
import time

from ..database import Database
from ..fleet import NODE_RE, FleetStore, ProtocolError, validate_inventory
from .models import LOCAL_NODE_ID


class NodeRegistry:
    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def link_row(row) -> dict:
        """A node_links row as the services see it: JSON columns parsed, and only the
        fact that a key exists — the key itself lives encrypted in secret_versions."""
        value = dict(row)
        value["identity"] = json.loads(value.pop("identity_json"))
        value["status_json"] = json.loads(value["status_json"])
        value["has_api_key"] = True
        return value

    @staticmethod
    def rows(db) -> list[dict]:
        # The operator's own host is what they look at first, and sorting by node_id would
        # bury it somewhere in the middle of the fleet.
        links = {row["node_id"]: NodeRegistry.link_row(row) for row in db.execute("SELECT * FROM node_links")}
        values = [
            FleetStore._node(row)
            for row in db.execute(
                "SELECT * FROM fleet_nodes ORDER BY CASE WHEN kind='local' THEN 0 ELSE 1 END, node_id"
            )
        ]
        for value in values:
            value["link"] = links.get(value["node_id"])
        return values

    @staticmethod
    def row(db, node_id: str) -> dict:
        row = db.execute("SELECT * FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone()
        if row is None:
            raise KeyError(node_id)
        value = FleetStore._node(row)
        link = db.execute("SELECT * FROM node_links WHERE node_id=?", (node_id,)).fetchone()
        value["link"] = None if link is None else NodeRegistry.link_row(link)
        return value

    @staticmethod
    def insert(db, node_id: str, display_name: str, *, kind: str = "remote", transport: str = "v1") -> None:
        """Same validation as FleetStore.register_node, but in the caller's transaction.

        Registration and its audit row must commit together, which a store method
        opening its own connection cannot promise.
        """
        if not NODE_RE.fullmatch(node_id or ""):
            raise ProtocolError("node_id is invalid")
        if node_id == LOCAL_NODE_ID:
            raise ProtocolError(f"node_id {LOCAL_NODE_ID!r} is reserved for this server")
        if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 128:
            raise ProtocolError("display_name is invalid")
        validate_inventory({})
        now = int(time.time())
        db.execute(
            """INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,kind,transport)
               VALUES(?,?,'unenrolled','{}',?,?,?,?)""",
            (node_id, display_name.strip(), now, now, kind, transport),
        )

    @staticmethod
    def rename(db, node_id: str, display_name: str) -> None:
        if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 128:
            raise ProtocolError("display_name is invalid")
        changed = db.execute(
            "UPDATE fleet_nodes SET display_name=?,updated_at=? WHERE node_id=?",
            (display_name.strip(), int(time.time()), node_id),
        ).rowcount
        if changed != 1:
            raise KeyError(node_id)

    @staticmethod
    def set_disabled(db, node_id: str, disabled: bool) -> None:
        changed = db.execute(
            "UPDATE fleet_nodes SET disabled=?,updated_at=? WHERE node_id=?",
            (1 if disabled else 0, int(time.time()), node_id),
        ).rowcount
        if changed != 1:
            raise KeyError(node_id)

    @staticmethod
    def active_grants(db, node_id: str) -> int:
        """Grants still pointing at this node. Written as SQL rather than through
        `panel.clients` so the lifecycle façade keeps no dependency on the domain."""
        return db.execute(
            "SELECT count(*) FROM access_grants WHERE node_id=? AND desired_state<>'deleted'",
            (node_id,),
        ).fetchone()[0]

    @staticmethod
    def pending_commands(db, node_id: str) -> int:
        return db.execute(
            "SELECT count(*) FROM fleet_commands WHERE node_id=? AND status IN ('queued','dispatched')",
            (node_id,),
        ).fetchone()[0]
