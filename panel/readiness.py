"""Local, read-only readiness snapshot; never includes topology or credential fields."""
from __future__ import annotations

import sqlite3


def snapshot(database) -> dict:
    try:
        with database.connect() as db:
            db.execute("SELECT 1").fetchone()
            current = db.execute(
                "SELECT generation, state FROM managed_generations ORDER BY generation DESC LIMIT 1"
            ).fetchone()
            applied_at = db.execute("SELECT MAX(applied_at) FROM managed_generations").fetchone()[0]
            links = db.execute(
                """SELECT COUNT(*) AS linked,
                    COALESCE(SUM(CASE WHEN l.config_dirty = 1
                        OR l.desired_generation > l.acknowledged_generation
                        OR (l.desired_generation > 0 AND
                            (o.node_id IS NULL OR o.reconcile_state != 'converged'))
                        THEN 1 ELSE 0 END), 0) AS lagging,
                    COALESCE(SUM(CASE WHEN o.reconcile_state = 'failed' THEN 1 ELSE 0 END), 0) AS failed
                   FROM node_links AS l LEFT JOIN observed_generations AS o ON o.node_id = l.node_id
                   WHERE l.enabled = 1"""
            ).fetchone()
            operations = db.execute(
                """SELECT
                    COALESCE(SUM(CASE WHEN status IN ('pending', 'pending_remote', 'applying', 'compensating')
                        THEN 1 ELSE 0 END), 0) AS unfinished,
                    COALESCE(SUM(CASE WHEN status = 'manual_intervention_required'
                        THEN 1 ELSE 0 END), 0) AS manual_intervention
                   FROM provisioning_operations"""
            ).fetchone()
    except (sqlite3.Error, OSError):
        return {"status": "failed", "database": {"queryable": False}}

    node_status = ("not_applicable" if current is None else
                   "ready" if current["state"] == "converged" else
                   "failed" if current["state"] == "failed" else "pending")
    central_status = ("not_applicable" if links["linked"] == 0 else
                      "failed" if links["failed"] else
                      "pending" if links["lagging"] else "ready")
    status = ("failed" if "failed" in (node_status, central_status) or operations["manual_intervention"] else
              "pending" if "pending" in (node_status, central_status) or operations["unfinished"] else "ready")
    return {
        "status": status, "database": {"queryable": True},
        "node": {"status": node_status, "generation": current["generation"] if current else None,
                 "applied_at": applied_at},
        "central": {"status": central_status, "linked": links["linked"], "lagging": links["lagging"]},
        "provisioning": {"unfinished": operations["unfinished"],
                         "manual_intervention": operations["manual_intervention"]},
    }
