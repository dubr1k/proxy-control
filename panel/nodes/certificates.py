"""Certificate rows read and revoked inside the caller's transaction."""
from __future__ import annotations

import time

from ..database import Database
from .models import CertificateInfo


class CertificateRegistry:
    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def list(db, node_id: str) -> list[CertificateInfo]:
        rows = db.execute(
            "SELECT * FROM fleet_certificates WHERE node_id=? ORDER BY issued_at DESC", (node_id,)
        )
        return [
            CertificateInfo(
                serial=row["serial"],
                fingerprint_sha256=row["fingerprint_sha256"],
                not_before=row["not_before"],
                not_after=row["not_after"],
                state=row["state"],
                issued_at=row["issued_at"],
                revoked_at=row["revoked_at"],
            )
            for row in rows
        ]

    @staticmethod
    def revoke_all(db, node_id: str) -> int:
        now = int(time.time())
        revoked = db.execute(
            "UPDATE fleet_certificates SET state='revoked',revoked_at=? WHERE node_id=? AND state='active'",
            (now, node_id),
        ).rowcount
        db.execute(
            "UPDATE fleet_nodes SET auth_state='revoked',updated_at=? WHERE node_id=?", (now, node_id)
        )
        return revoked
