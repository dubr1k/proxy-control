//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use panel_core::clock::FakeClock;
use panel_core::db::{row_to_json, Database};
use panel_core::serde_json::{self, Value};
use panel_nodes::NodeLifecycleService;

/// The `NOW` of the golden recordings.
pub const NOW: i64 = 1_793_000_000;

/// A directory removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "panel-nodes-{label}-{}-{}",
            std::process::id(),
            panel_core::ids::token_hex(6)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

pub fn fixture_json(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixture_path(name)).unwrap()).unwrap()
}

/// A freshly migrated database in `dir`.
pub fn migrated(dir: &TempDir) -> Database {
    let database = Database::open(dir.join("panel.sqlite3")).unwrap();
    panel_core::migrations::apply_migrations(&database).unwrap();
    database
}

/// A writable copy of a fixture database (the Python-migrated file is accepted as it is).
pub fn fixture_database(fixture: &str, dir: &TempDir) -> Database {
    let path = dir.join("panel.sqlite3");
    std::fs::copy(fixture_path(fixture), &path).unwrap();
    let database = Database::open(&path).unwrap();
    panel_core::migrations::apply_migrations(&database).unwrap();
    database
}

/// The lifecycle service at a pinned time.
pub fn service_at(database: Database, now: i64) -> NodeLifecycleService {
    NodeLifecycleService::new(database, Arc::new(FakeClock::new(now as f64)))
}

/// Every row of a query as `dict(row)`.
pub fn table(database: &Database, sql: &str) -> Vec<Value> {
    let conn = database.connect().unwrap();
    let mut statement = conn.prepare(sql).unwrap();
    statement.query_map([], row_to_json).unwrap().map(|row| Value::Object(row.unwrap())).collect()
}
