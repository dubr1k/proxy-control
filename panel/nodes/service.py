"""Node lifecycle as application service: every mutation and its audit row commit together.

This is the façade ADR 001 asks for. It owns registration, renaming, the operator
disable switch and certificate revocation, while `FleetStore` keeps doing exactly
what it did for the v1 transport — its public signatures do not change here.
"""
from __future__ import annotations

import sqlite3
import time

from .. import audit
from ..database import Database
from ..fleet import FleetStore
from .certificates import CertificateRegistry
from .models import LOCAL_NODE_ID, NodeView
from .read_model import derive
from .registry import NodeRegistry


class NodeConflict(RuntimeError):
    pass


class NodeLifecycleService:
    def __init__(self, database: Database, fleet: FleetStore, clock=time):
        self.database = database
        self.fleet = fleet
        self.clock = clock
        self.nodes = NodeRegistry(database)
        self.certificates = CertificateRegistry(database)

    def _view(self, db, row: dict) -> NodeView:
        return derive(
            row,
            self.certificates.list(db, row["node_id"]),
            self.nodes.pending_commands(db, row["node_id"]),
            int(self.clock.time()),
        )

    def list(self) -> list[NodeView]:
        with self.database.connect() as db:
            return [self._view(db, row) for row in self.nodes.rows(db)]

    def get(self, node_id: str) -> NodeView:
        with self.database.connect() as db:
            return self._view(db, self.nodes.row(db, node_id))

    def local(self) -> NodeView:
        """The reserved row migration 5 created; it exists in every database."""
        return self.get(LOCAL_NODE_ID)

    def register(self, node_id: str, display_name: str, *, actor: dict, ip: str, request_id: str | None = None) -> NodeView:
        with self.database.transaction() as db:
            try:
                self.nodes.insert(db, node_id, display_name)
            except sqlite3.IntegrityError as exc:
                raise NodeConflict("node already exists") from exc
            audit.record(
                db,
                actor=actor,
                action="node.register",
                target=node_id,
                ip=ip,
                request_id=request_id,
                detail={"display_name": display_name},
            )
            return self._view(db, self.nodes.row(db, node_id))

    def rename(self, node_id: str, display_name: str, *, actor: dict, ip: str, request_id: str | None = None) -> NodeView:
        with self.database.transaction() as db:
            self.nodes.rename(db, node_id, display_name)
            audit.record(
                db,
                actor=actor,
                action="node.rename",
                target=node_id,
                ip=ip,
                request_id=request_id,
                detail={"display_name": display_name},
            )
            return self._view(db, self.nodes.row(db, node_id))

    def set_disabled(self, node_id: str, disabled: bool, *, actor: dict, ip: str, request_id: str | None = None) -> NodeView:
        with self.database.transaction() as db:
            row = self.nodes.row(db, node_id)
            if disabled and self.nodes.pending_commands(db, node_id):
                # Disabling mid-flight would strand commands the node can no longer
                # fetch, so the operator has to resolve them first.
                raise NodeConflict("node has pending commands")
            if row["kind"] == "local" and disabled:
                raise NodeConflict("the local node cannot be disabled")
            if disabled and self.nodes.active_grants(db, node_id):
                # Cutting the node off the transport would silently strand every
                # subscriber whose access lives on it.
                raise NodeConflict("node still carries active grants")
            self.nodes.set_disabled(db, node_id, disabled)
            audit.record(
                db,
                actor=actor,
                action="node.disable" if disabled else "node.enable",
                target=node_id,
                ip=ip,
                request_id=request_id,
            )
            return self._view(db, self.nodes.row(db, node_id))

    def revoke_all_certificates(self, node_id: str, *, confirm: str, actor: dict, ip: str, request_id: str | None = None) -> int:
        with self.database.transaction() as db:
            row = self.nodes.row(db, node_id)
            if row["kind"] == "local":
                raise NodeConflict("the local node has no certificates to revoke")
            if confirm != node_id:
                raise NodeConflict("confirmation must equal node_id")
            revoked = self.certificates.revoke_all(db, node_id)
            audit.record(
                db,
                actor=actor,
                action="node.certificates.revoke_all",
                target=node_id,
                ip=ip,
                request_id=request_id,
                detail={"revoked": revoked},
            )
            return revoked
