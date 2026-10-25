//! The SQLite boundary: the cases of `panel/tests/test_migrations.py` that pin `panel/database.py`,
//! plus the implicit-`BEGIN` semantics of Python's `sqlite3` that `with database.connect()` relies on.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use panel_core::db::{row_to_json, Database, DbError};
use panel_core::migrations::apply_migrations;
use rusqlite::Connection;
use serde_json::json;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "panel-core-db-{name}-{}-{}",
            std::process::id(),
            panel_core::ids::token_hex(4)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn file(&self) -> PathBuf {
        self.0.join("panel.sqlite3")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn opening_creates_the_directory_and_switches_to_wal() {
    let scratch = Scratch::new("mkdir");
    let path = scratch.0.join("nested/deeper/panel.sqlite3");
    let database = Database::open(&path).unwrap();
    assert_eq!(database.path(), path);
    let conn = database.connect().unwrap();
    assert_eq!(conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0)).unwrap(), "wal");
    assert_eq!(conn.query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0)).unwrap(), 10_000);
}

#[test]
fn wal_is_enabled_even_while_another_connection_holds_the_database() {
    let scratch = Scratch::new("wal-wait");
    let path = scratch.file();
    let plain = Connection::open(&path).unwrap();
    plain.execute_batch("CREATE TABLE probe(x)").unwrap();
    assert_eq!(plain.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0)).unwrap(), "delete");

    let (locked_tx, locked_rx) = mpsc::channel();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let holder = Connection::open(&holder_path).unwrap();
        holder.execute_batch("BEGIN IMMEDIATE; INSERT INTO probe VALUES(1);").unwrap();
        locked_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        holder.execute_batch("COMMIT").unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let database = Database::open(&path).unwrap();
    holder.join().unwrap();
    let conn = database.connect().unwrap();
    assert_eq!(conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0)).unwrap(), "wal");
}

#[test]
fn a_database_that_never_becomes_writable_fails_with_a_named_error() {
    let scratch = Scratch::new("wal-fail");
    let path = scratch.file();
    let plain = Connection::open(&path).unwrap();
    plain.execute_batch("CREATE TABLE probe(x)").unwrap();
    let holder = Connection::open(&path).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE; INSERT INTO probe VALUES(1);").unwrap();
    let error = Database::open_with_timeout(&path, Duration::from_millis(500)).unwrap_err();
    assert!(matches!(error, DbError::WalLocked { .. }));
    assert_eq!(
        error.to_string(),
        format!("could not enable write-ahead logging on {}: the database stayed locked", path.display())
    );
}

#[test]
fn connections_keep_temporary_storage_in_memory_and_enforce_foreign_keys() {
    let scratch = Scratch::new("pragmas");
    let database = Database::open(scratch.file()).unwrap();
    let conn = database.connect().unwrap();
    assert_eq!(count(&conn, "PRAGMA temp_store"), 2);
    assert_eq!(count(&conn, "PRAGMA foreign_keys"), 1);
    database
        .transaction(|db| -> Result<(), DbError> {
            assert_eq!(count(db, "PRAGMA temp_store"), 2);
            Ok(())
        })
        .unwrap();
}

#[test]
fn transaction_helper_commits_or_rolls_back_everything() {
    let scratch = Scratch::new("rollback");
    let database = Database::open(scratch.file()).unwrap();
    apply_migrations(&database).unwrap();
    let insert = "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at) \
                  VALUES('a','a','unenrolled','{}',1,1)";
    let failed: Result<(), TestError> = database.transaction(|db| {
        db.execute(insert, [])?;
        Err(TestError("injected".into()))
    });
    assert_eq!(failed.unwrap_err().0, "injected");
    assert_eq!(count(&database.connect().unwrap(), "SELECT count(*) FROM fleet_nodes WHERE node_id='a'"), 0);
    database.transaction(|db| db.execute(insert, []).map(|_| ())).unwrap();
    assert_eq!(count(&database.connect().unwrap(), "SELECT count(*) FROM fleet_nodes WHERE node_id='a'"), 1);
}

impl From<DbError> for TestError {
    fn from(error: DbError) -> Self {
        TestError(error.to_string())
    }
}

#[derive(Debug)]
struct TestError(String);

#[test]
fn with_connection_begins_before_the_first_write_and_commits_at_the_end() {
    let scratch = Scratch::new("implicit");
    let database = Database::open(scratch.file()).unwrap();
    database.with_connection(|db| db.execute("CREATE TABLE t(x)", []).map(|_| ())).unwrap();
    database
        .with_connection(|db| -> Result<(), TestError> {
            assert_eq!(count(db, "SELECT count(*) FROM t"), 0);
            assert!(!db.in_transaction(), "reads run in autocommit mode");
            db.execute("INSERT INTO t VALUES(1)", [])?;
            assert!(db.in_transaction(), "the first DML opened a transaction");
            db.execute("INSERT INTO t VALUES(2)", [])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(count(&database.connect().unwrap(), "SELECT count(*) FROM t"), 2);
    let failed = database.with_connection(|db| -> Result<(), TestError> {
        db.execute("INSERT INTO t VALUES(3)", [])?;
        Err(TestError("injected".into()))
    });
    assert!(failed.is_err());
    assert_eq!(count(&database.connect().unwrap(), "SELECT count(*) FROM t"), 2, "an error rolls the block back");
    // An explicit BEGIN IMMEDIATE inside the block (the login limiter's pattern) is committed too.
    database
        .with_connection(|db| -> Result<(), TestError> {
            db.execute("BEGIN IMMEDIATE", [])?;
            db.execute("DELETE FROM t WHERE x=1", [])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(count(&database.connect().unwrap(), "SELECT count(*) FROM t"), 1);
}

#[test]
fn insert_returns_the_rowid_and_rows_turn_into_python_dicts() {
    let scratch = Scratch::new("rows");
    let database = Database::open(scratch.file()).unwrap();
    database
        .with_connection(|db| -> Result<(), TestError> {
            db.execute("CREATE TABLE admins(id INTEGER PRIMARY KEY, username TEXT, active INTEGER, score REAL, note TEXT, raw BLOB)", [])?;
            assert_eq!(db.insert("INSERT INTO admins(username,active,score) VALUES('owner',1,0.5)", [])?, 1);
            assert_eq!(db.insert("INSERT INTO admins(username,active,raw) VALUES('Алиса',0,x'00')", [])?, 2);
            Ok(())
        })
        .unwrap();
    let conn = database.connect().unwrap();
    let mut statement =
        conn.prepare("SELECT id, username AS name, active, score, note FROM admins ORDER BY id").unwrap();
    let rows: Vec<_> = statement.query_map([], row_to_json).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        serde_json::Value::Array(rows.into_iter().map(serde_json::Value::Object).collect()),
        json!([
            {"id": 1, "name": "owner", "active": 1, "score": 0.5, "note": null},
            {"id": 2, "name": "Алиса", "active": 0, "score": null, "note": null},
        ])
    );
    let blob = conn.query_row("SELECT raw FROM admins WHERE id=2", [], row_to_json);
    assert!(blob.is_err(), "a BLOB has no JSON form");
}

#[test]
fn constraint_and_busy_errors_are_recognisable() {
    let scratch = Scratch::new("errors");
    let database = Database::open(scratch.file()).unwrap();
    let conn = database.connect().unwrap();
    conn.execute("CREATE TABLE t(x PRIMARY KEY)", []).unwrap();
    conn.execute("INSERT INTO t VALUES(1)", []).unwrap();
    let duplicate = conn.execute("INSERT INTO t VALUES(1)", []).unwrap_err();
    assert!(duplicate.is_constraint() && !duplicate.is_busy());
    conn.commit().unwrap();

    let holder = database.connect().unwrap();
    holder.execute("BEGIN IMMEDIATE", []).unwrap();
    let impatient = Database::open_with_timeout(scratch.file(), Duration::from_millis(100)).unwrap();
    let busy = impatient.transaction(|_| Ok::<_, DbError>(())).unwrap_err();
    assert!(busy.is_busy(), "{busy}");
    holder.rollback().unwrap();
}
