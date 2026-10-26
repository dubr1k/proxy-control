//! `panel/readiness.py`: a local, read-only readiness snapshot that never includes topology or
//! credential fields.

use panel_core::db::{Database, DbError};
use serde_json::{json, Value};

/// `snapshot(database)`; any database failure is `{"status":"failed","database":{"queryable":false}}`.
pub fn snapshot(database: &Database) -> Value {
    read(database).unwrap_or_else(|_| json!({"status": "failed", "database": {"queryable": false}}))
}

fn read(database: &Database) -> Result<Value, DbError> {
    database.with_connection(|db| -> Result<Value, DbError> {
        db.query_row("SELECT 1", [], |_| Ok(()))?;
        let current: Option<(i64, String)> = db
            .query_row(
                "SELECT generation, state FROM managed_generations ORDER BY generation DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map(Some)
            .or_else(|error| match error {
                panel_core::rusqlite::Error::QueryReturnedNoRows => Ok(None),
                error => Err(error),
            })?;
        let applied_at: Option<i64> =
            db.query_row("SELECT MAX(applied_at) FROM managed_generations", [], |row| row.get(0))?;
        let (linked, lagging, failed): (i64, i64, i64) = db.query_row(
            "SELECT COUNT(*) AS linked,
                    COALESCE(SUM(CASE WHEN l.config_dirty = 1
                        OR l.desired_generation > l.acknowledged_generation
                        OR (l.desired_generation > 0 AND
                            (o.node_id IS NULL OR o.reconcile_state != 'converged'))
                        THEN 1 ELSE 0 END), 0) AS lagging,
                    COALESCE(SUM(CASE WHEN o.reconcile_state = 'failed' THEN 1 ELSE 0 END), 0) AS failed
                   FROM node_links AS l LEFT JOIN observed_generations AS o ON o.node_id = l.node_id
                   WHERE l.enabled = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let (unfinished, manual): (i64, i64) = db.query_row(
            "SELECT
                    COALESCE(SUM(CASE WHEN status IN ('pending', 'pending_remote', 'applying', 'compensating')
                        THEN 1 ELSE 0 END), 0) AS unfinished,
                    COALESCE(SUM(CASE WHEN status = 'manual_intervention_required'
                        THEN 1 ELSE 0 END), 0) AS manual_intervention
                   FROM provisioning_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let node_status = match &current {
            None => "not_applicable",
            Some((_, state)) if state == "converged" => "ready",
            Some((_, state)) if state == "failed" => "failed",
            Some(_) => "pending",
        };
        let central_status = if linked == 0 {
            "not_applicable"
        } else if failed != 0 {
            "failed"
        } else if lagging != 0 {
            "pending"
        } else {
            "ready"
        };
        let statuses = [node_status, central_status];
        let status = if statuses.contains(&"failed") || manual != 0 {
            "failed"
        } else if statuses.contains(&"pending") || unfinished != 0 {
            "pending"
        } else {
            "ready"
        };
        Ok(json!({
            "status": status, "database": {"queryable": true},
            "node": {"status": node_status, "generation": current.as_ref().map(|(generation, _)| *generation),
                     "applied_at": applied_at},
            "central": {"status": central_status, "linked": linked, "lagging": lagging},
            "provisioning": {"unfinished": unfinished, "manual_intervention": manual},
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> (std::path::PathBuf, Database) {
        let dir = std::env::temp_dir().join(format!("panel-web-readiness-{}", panel_core::ids::token_hex(6)));
        let database = Database::open(dir.join("panel.db")).unwrap();
        panel_core::migrations::apply_migrations(&database).unwrap();
        (dir, database)
    }

    #[test]
    fn baseline_is_not_applicable_not_failed() {
        let (dir, database) = database();
        assert_eq!(
            panel_core::pyjson::compact_utf8(&snapshot(&database)),
            r#"{"status":"ready","database":{"queryable":true},"node":{"status":"not_applicable","generation":null,"applied_at":null},"central":{"status":"not_applicable","linked":0,"lagging":0},"provisioning":{"unfinished":0,"manual_intervention":0}}"#
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `test_database_query_failure_reports_hard_failure` (the Python test broke `connect`).
    #[test]
    fn database_query_failure_reports_hard_failure() {
        let (dir, database) = database();
        let conn = database.connect().unwrap();
        conn.execute_batch("DROP TABLE provisioning_operations").unwrap();
        drop(conn);
        assert_eq!(snapshot(&database), json!({"status": "failed", "database": {"queryable": false}}));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `test_node_state_uses_actual_applied_timestamp`.
    #[test]
    fn node_state_uses_actual_applied_timestamp() {
        for (state, expected) in [("applying", "pending"), ("failed", "failed"), ("converged", "ready")] {
            let (dir, database) = database();
            let conn = database.connect().unwrap();
            conn.execute_batch(
                "INSERT INTO managed_generations VALUES(1,'digest','secret-guid','{}',100,90,'converged')",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO managed_generations VALUES(2,'digest2','secret-guid','{}',110,?,?)",
                panel_core::rusqlite::params![if state == "converged" { Some(120) } else { None }, state],
            )
            .unwrap();
            conn.commit().unwrap();
            drop(conn);
            let body = snapshot(&database);
            let applied = if state == "converged" { 120 } else { 90 };
            assert_eq!(body["node"], json!({"status": expected, "generation": 2, "applied_at": applied}));
            assert_eq!(body["status"], expected);
            assert!(!body.to_string().contains("secret-guid"));
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
