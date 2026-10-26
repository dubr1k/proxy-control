//! The migration runner against databases the Python runner made (`fixtures/migrations/`, from
//! `fixtures/generators/gen_migrations.py`) and the behaviours `panel/tests/test_migrations.py`
//! pins.

use std::path::{Path, PathBuf};

use panel_core::db::{Database, DbError};
use panel_core::migrations::{self, apply, apply_migrations, migration_status, Migration, MigrationError, MIGRATIONS};
use rusqlite::Connection;
use serde_json::{json, Value};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/migrations");

/// The checksums recorded on a freshly migrated Python database (inventory §3.2a).
const RECORDED: [(i64, &str, &str); 26] = [
    (1, "baseline-v0.1.0", "65266de1f801afb3720c00be88b27870bff1598636d4ea1a1c37a529bbdc8033"),
    (2, "audit-structured", "f094bd8f6e7a21e390b9d021cc65f8db1663eb6cc2d27d7370e63b79b0826c1d"),
    (3, "secret-versions", "154d0677662fe5ef743706e23ac3934cf3c1b66abe2e0d3b0447e763aead47ad"),
    (4, "node-lifecycle", "0db82e9647af5823246f7976bc55154705a8c66fab37235d6999169907f9256a"),
    (5, "local-node", "a6c4042ff026a51e1e9cb5a814eff944b5bcce8b13362af6769f80a8ca38633c"),
    (6, "clients-and-grants", "e9b0c301fb155193f8a57908b5a594df4239750ae46436a51b18849c91891e9d"),
    (7, "provisioning-operations", "2ef3fab99218ab4b466cd961d35b8e5de2f85d5998bf7026477b7467edff7642"),
    (8, "client-subscriptions", "999ab285cba4061ccc16698ef930007d7d2a2ab4b0959504712507931298a1e0"),
    (9, "panel-settings-and-api-keys", "4f7ee8475c471e6a7d872bff9a59a688d5ded2260d3733740673f0f1c083834b"),
    (10, "fleet-v2-managed", "2cb4b8da09553a7146a3866218c6100c82a4d6bbf6b359d5d93681445f572600"),
    (11, "fleet-v2-links", "d4d672944a9854fece96e449cbdf20519757253fa9f228884d37cef878c77ec8"),
    (12, "provisioning-pending-remote", "0e409295295f7e5eb9068703d17230168d7c43e5bb856e44c0e2298db07281aa"),
    (13, "fleet-v2-learned-options", "d6b39ee2cfee0822a97589d729f1804c7212680042ae8d072ea6f3eb98ff5d00"),
    (14, "routing-policies", "628ac9b5966a545caf3c32eea49fa68db24ca30694299a23195fb338663141a2"),
    (15, "routing-xray-router", "3e50af81b5f555d0ccdcb16ff6af120ae5b86e727d7e676c33ce731f85d18f6e"),
    (16, "routing-chains-lanes", "f0e8b982652d2f95d6f6f78594f77023905e3acbbd8cbdd9be0ade6550c5f559"),
    (17, "links-auto-import", "7b0cf9f4a1f854b5d167d605207a5569f2c3bf78e2630fd7aa19f96edb5b421e"),
    (18, "routing-presets", "3c3d33b5d60b106bb5f49b95e42a63c0bffbf8625d9da411a58d162f4f153a53"),
    (19, "routing-exits", "cae2c5422b2c9876a55160464f940eb83ee4f8aeeabbe00c5148094e3405c72f"),
    (20, "subscription-escrow", "d6765c96a25cb3a5f1fb554318d380271625ca3cef82607196aa0ef85afc423a"),
    (21, "routing-mtproxy", "025b2a47207de02b5930a0a8822313ffd9833b2997da7cd7c56f25e9e2c5d074"),
    (22, "grant-labels", "929a0111f484f7a79ec979fde52db5cbcb7b5f897e7a2974b23f98b45b293182"),
    (23, "amneziawg-grants", "1c2e547b56ed72c5050c683b8349e5e0c91abd99203a11184c66c241e3f01293"),
    (24, "trusttunnel", "e368fcd92557728fb1c84fa6b889f013f0c6cf0900cdad25e7408b0f762c28e1"),
    (25, "metrics", "2fb403a77e10f7ff8d50007242194918ea97e9ae8dc688082fa68c2a5efb2eea"),
    (26, "amneziawg_egress", "adda564d671163b8169162d49bf9e6225bbc9d3515f244b1d4848ca17c26c918"),
];

/// A fresh directory per test (removed when dropped).
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "panel-core-{name}-{}-{}",
            std::process::id(),
            panel_core::ids::token_hex(4)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read_json(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(Path::new(FIXTURES).join(name)).unwrap()).unwrap()
}

fn raw(path: &Path) -> Connection {
    Connection::open(path).unwrap()
}

fn cell(value: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef;
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => json!(value),
        ValueRef::Real(value) => json!(value),
        ValueRef::Text(text) => json!(std::str::from_utf8(text).unwrap()),
        ValueRef::Blob(bytes) => json!({"blob": panel_core::ids::hex(bytes)}),
    }
}

/// The generator's `canonical_dump`: schema (type, name, tbl_name, sql) and every table's rows in
/// an order both sides get from SQL alone; values that depend on the upgrade's wall clock nulled.
fn canonical_dump(path: &Path, snapshot_version: Option<i64>) -> (Value, Value) {
    let db = raw(path);
    let mut statement = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").unwrap();
    let schema: Vec<Value> = statement
        .query_map([], |row| {
            Ok(json!([
                row.get_ref(0).map(cell)?,
                row.get_ref(1).map(cell)?,
                row.get_ref(2).map(cell)?,
                row.get_ref(3).map(cell)?
            ]))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let names: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut tables = serde_json::Map::new();
    for name in names {
        let columns: Vec<String> = db
            .prepare(&format!("SELECT * FROM \"{name}\" LIMIT 0"))
            .unwrap()
            .column_names()
            .map(str::to_string)
            .collect();
        let order = (1..=columns.len()).map(|index| index.to_string()).collect::<Vec<_>>().join(",");
        let mut statement = db.prepare(&format!("SELECT * FROM \"{name}\" ORDER BY {order}")).unwrap();
        let mut rows: Vec<Vec<Value>> = statement
            .query_map([], |row| (0..columns.len()).map(|index| row.get_ref(index).map(cell)).collect())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        if let Some(version) = snapshot_version {
            if name == "schema_migrations" {
                for row in &mut rows {
                    if row[0].as_i64().unwrap() > version {
                        row[3] = Value::Null;
                    }
                }
            }
            if version < 5 && name == "fleet_nodes" {
                let created = columns.iter().position(|c| c == "created_at").unwrap();
                let updated = columns.iter().position(|c| c == "updated_at").unwrap();
                for row in &mut rows {
                    if row[0] == "local" {
                        row[created] = Value::Null;
                        row[updated] = Value::Null;
                    }
                }
            }
        }
        tables.insert(name, json!({"columns": columns, "rows": rows}));
    }
    (Value::Array(schema), json!({"tables": tables}))
}

#[test]
fn checksums_equal_the_recorded_ones() {
    assert_eq!(MIGRATIONS.len(), RECORDED.len());
    for (migration, (version, name, checksum)) in MIGRATIONS.iter().zip(RECORDED) {
        assert_eq!((migration.version, migration.name), (version, name));
        assert_eq!(migration.checksum(), checksum, "migration {version}");
    }
}

#[test]
fn statements_are_pythons_verbatim() {
    let python = read_json("migrations.json");
    let python = python.as_array().unwrap();
    assert_eq!(python.len(), MIGRATIONS.len());
    for (migration, recorded) in MIGRATIONS.iter().zip(python) {
        assert_eq!(migration.version, recorded["version"].as_i64().unwrap());
        assert_eq!(migration.name, recorded["name"].as_str().unwrap());
        assert_eq!(migration.checksum(), recorded["checksum"].as_str().unwrap());
        let statements: Vec<&str> =
            recorded["statements"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
        assert_eq!(migration.statements, statements.as_slice(), "migration {}", migration.version);
    }
}

#[test]
fn an_empty_database_migrates_to_pythons_exact_schema() {
    let scratch = Scratch::new("fresh");
    let path = scratch.path("panel.sqlite3");
    let database = Database::open(&path).unwrap();
    assert_eq!(apply_migrations(&database).unwrap(), (1..=26).collect::<Vec<_>>());
    let (schema, _) = canonical_dump(&path, None);
    assert_eq!(schema, read_json("schema-v26.json"));
    let db = raw(&path);
    let recorded: Vec<(i64, String, String)> = db
        .prepare("SELECT version,name,checksum FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let expected: Vec<(i64, String, String)> =
        RECORDED.iter().map(|(v, n, c)| (*v, n.to_string(), c.to_string())).collect();
    assert_eq!(recorded, expected);
    assert_eq!(db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
    assert_eq!(db.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0)).unwrap(), "wal");
    // A second run is a no-op.
    assert_eq!(apply_migrations(&database).unwrap(), Vec::<i64>::new());
}

#[test]
fn a_python_migrated_database_is_accepted_and_left_untouched() {
    let scratch = Scratch::new("python");
    let path = scratch.path("panel.sqlite3");
    std::fs::copy(Path::new(FIXTURES).join("python-v26.db"), &path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let (schema, rows) = canonical_dump(&path, None);
    assert_eq!(schema, read_json("schema-v26.json"));
    assert_eq!(rows, read_json("python-v26.json"));

    let database = Database::open(&path).unwrap();
    assert_eq!(apply_migrations(&database).unwrap(), Vec::<i64>::new());
    assert!(migration_status(&database).unwrap().iter().all(|row| row.applied && row.checksum_ok));
    drop(database);
    assert_eq!(canonical_dump(&path, None), (schema, rows));
    assert!(
        !scratch.path("panel.sqlite3-wal").exists()
            || std::fs::metadata(scratch.path("panel.sqlite3-wal")).unwrap().len() == 0
    );
    assert_eq!(std::fs::read(&path).unwrap(), before, "the database file changed");
}

#[test]
fn python_snapshots_upgrade_to_the_same_result_as_python() {
    let mut checked = 0;
    for entry in std::fs::read_dir(FIXTURES).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        let Some(version) = name.strip_prefix("snapshot-v").and_then(|rest| rest.strip_suffix(".sql")) else {
            continue;
        };
        let version: i64 = version.parse().unwrap();
        let scratch = Scratch::new(&format!("snapshot-{version}"));
        let path = scratch.path("panel.sqlite3");
        {
            let db = raw(&path);
            db.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            db.execute_batch(&std::fs::read_to_string(Path::new(FIXTURES).join(&name)).unwrap()).unwrap();
        }
        let database = Database::open(&path).unwrap();
        let before = migration_status(&database).unwrap();
        assert!(before.iter().all(|row| row.applied == (row.version <= version) && row.checksum_ok == row.applied));
        assert_eq!(apply_migrations(&database).unwrap(), (version + 1..=26).collect::<Vec<_>>(), "snapshot v{version}");
        let (schema, rows) = canonical_dump(&path, Some(version));
        assert_eq!(schema, read_json("schema-v26.json"), "schema after v{version}");
        assert_eq!(rows, read_json(&format!("expected-v{version:02}.json")), "rows after v{version}");
        checked += 1;
    }
    assert_eq!(checked, 13);
}

#[test]
fn a_pre_runner_database_is_refused_and_left_untouched() {
    // `PRE_V02_SCHEMA_SQL` of panel/tests/test_migrations.py: what v0.1.0 created.
    let scratch = Scratch::new("legacy");
    let path = scratch.path("panel.sqlite3");
    raw(&path)
        .execute_batch(
            "CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
               password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
               created_at INTEGER NOT NULL);
             CREATE TABLE fleet_nodes (node_id TEXT PRIMARY KEY, display_name TEXT NOT NULL);
             INSERT INTO admins(username,password_hash,role,created_at) VALUES('owner','$argon2id$stub','owner',1);",
        )
        .unwrap();
    let database = Database::open(&path).unwrap();
    let before = canonical_dump(&path, None);
    // `db-status` answers "nothing applied" and does not create the table.
    assert!(migration_status(&database).unwrap().iter().all(|row| !row.applied && !row.checksum_ok));
    let error = apply_migrations(&database).unwrap_err();
    assert!(matches!(&error, MigrationError::PreRunner { tables } if tables == &["admins", "fleet_nodes"]), "{error}");
    assert!(error.to_string().contains("before schema migrations existed"), "{error}");
    assert_eq!(canonical_dump(&path, None), before, "the refused database changed");
    let db = raw(&path);

    // The same once a crashed Python run left an empty `schema_migrations` behind.
    db.execute_batch(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)",
    )
    .unwrap();
    assert!(matches!(apply_migrations(&database).unwrap_err(), MigrationError::PreRunner { .. }));
}

#[test]
fn checksum_mismatch_fails_closed() {
    let scratch = Scratch::new("tampered");
    let path = scratch.path("panel.sqlite3");
    apply_migrations(&Database::open(&path).unwrap()).unwrap();
    raw(&path).execute_batch("UPDATE schema_migrations SET checksum='tampered' WHERE version=1").unwrap();
    let error = apply_migrations(&Database::open(&path).unwrap()).unwrap_err();
    assert_eq!(error.to_string(), "migration 1 checksum mismatch");
    let status = migration_status(&Database::open(&path).unwrap()).unwrap();
    assert!(status[0].applied && !status[0].checksum_ok);
}

#[test]
fn newer_database_than_code_fails_closed() {
    let scratch = Scratch::new("newer");
    let path = scratch.path("panel.sqlite3");
    apply_migrations(&Database::open(&path).unwrap()).unwrap();
    raw(&path).execute_batch("INSERT INTO schema_migrations VALUES(9999,'future','x',1)").unwrap();
    let error = apply_migrations(&Database::open(&path).unwrap()).unwrap_err();
    assert_eq!(error.to_string(), "database schema 9999 is newer than this code (26)");
}

#[test]
fn interrupted_migration_rolls_back_and_records_nothing() {
    let scratch = Scratch::new("broken");
    let path = scratch.path("panel.sqlite3");
    let mut list: Vec<Migration> = MIGRATIONS.to_vec();
    list.push(Migration {
        version: 9999,
        name: "broken",
        statements: &["CREATE TABLE probe(x)", "CREATE TABLE probe(x)"],
    });
    let database = Database::open(&path).unwrap();
    let error = apply(&database, &list).unwrap_err();
    assert!(matches!(error, MigrationError::Database(DbError::Sqlite(_))), "{error}");
    let db = raw(&path);
    assert_eq!(
        db.query_row("SELECT count(*) FROM sqlite_master WHERE name='probe'", [], |r| r.get::<_, i64>(0)).unwrap(),
        0
    );
    // The whole run is one transaction: nothing at all was recorded.
    assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
}

#[test]
fn concurrent_runners_are_safe() {
    let scratch = Scratch::new("concurrent");
    let path = scratch.path("panel.sqlite3");
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                let database = Database::open(&path).map_err(|error| error.to_string())?;
                apply_migrations(&database).map_err(|error| error.to_string())
            })
        })
        .collect();
    let mut applied: Vec<Vec<i64>> = threads.into_iter().map(|thread| thread.join().unwrap().unwrap()).collect();
    applied.sort();
    assert_eq!(applied, vec![vec![], vec![], vec![], (1..=26).collect()]);
    assert_eq!(migration_status(&Database::open(&path).unwrap()).unwrap().len(), 26);
}

#[test]
fn migration_12_rebuilds_provisioning_operations_with_existing_rows() {
    let scratch = Scratch::new("v12");
    let path = scratch.path("panel.sqlite3");
    let database = Database::open(&path).unwrap();
    assert_eq!(apply(&database, &MIGRATIONS[..11]).unwrap(), (1..=11).collect::<Vec<_>>());
    let statuses = ["pending", "applying", "succeeded", "compensated", "manual_intervention_required"];
    database
        .transaction(|db| -> Result<(), DbError> {
            db.execute("INSERT INTO clients(id,display_name,state,created_at,updated_at) VALUES('c1','A','active',1,1)", [])?;
            for (index, status) in statuses.iter().enumerate() {
                db.execute(
                    "INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                    rusqlite::params![format!("op-{index}"), "c1", status, r#"[{"grant_id":"g","status":"active"}]"#, index as i64, index as i64],
                )?;
            }
            let refused = db.execute(
                "INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at) VALUES('op-x','c1','pending_remote','[]',9,9)",
                [],
            );
            assert!(refused.unwrap_err().is_constraint());
            Ok(())
        })
        .unwrap();
    assert_eq!(apply_migrations(&database).unwrap(), (12..=26).collect::<Vec<_>>());
    database
        .transaction(|db| -> Result<(), DbError> {
            let rows: Vec<(String, String, i64)> = db
                .prepare("SELECT operation_id,status,created_at FROM provisioning_operations ORDER BY created_at")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<Result<_, _>>()?;
            assert_eq!(rows.len(), 5);
            db.execute(
                "INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at) VALUES('op-x','c1','pending_remote','[]',9,9)",
                [],
            )?;
            let foreign = db.execute(
                "INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at) VALUES('op-y','missing','pending','[]',9,9)",
                [],
            );
            assert!(foreign.unwrap_err().is_constraint());
            Ok(())
        })
        .unwrap();
}

#[test]
fn migration_creates_exactly_one_local_node_idempotently() {
    let scratch = Scratch::new("local");
    let path = scratch.path("panel.sqlite3");
    let database = Database::open(&path).unwrap();
    apply_migrations(&database).unwrap();
    apply_migrations(&database).unwrap();
    let conn = database.connect().unwrap();
    let rows: Vec<(String, String, String, i64, String)> = conn
        .prepare("SELECT node_id,kind,display_name,disabled,auth_state FROM fleet_nodes")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows, vec![("local".into(), "local".into(), "Этот сервер".into(), 0, "local".into())]);
}

#[test]
fn migration_25_creates_metric_rollups_without_rowid() {
    let scratch = Scratch::new("v25");
    let database = Database::open(scratch.path("panel.sqlite3")).unwrap();
    apply_migrations(&database).unwrap();
    database
        .transaction(|db| -> Result<(), DbError> {
            db.execute("INSERT INTO metric_rollups VALUES(60,100,'local','host.cpu',50.0,2,30.0,20.0)", [])?;
            assert!(db
                .execute("INSERT INTO metric_rollups VALUES(60,100,'local','host.cpu',1.0,1,1.0,1.0)", [])
                .unwrap_err()
                .is_constraint());
            let sql: String =
                db.query_row("SELECT sql FROM sqlite_master WHERE name='metric_rollups'", [], |r| r.get(0))?;
            assert!(sql.contains("WITHOUT ROWID"));
            Ok(())
        })
        .unwrap();
}

#[test]
fn status_lists_every_migration_in_order() {
    let scratch = Scratch::new("status");
    let database = Database::open(scratch.path("panel.sqlite3")).unwrap();
    let before = migration_status(&database).unwrap();
    assert_eq!(before.len(), 26);
    assert!(before.iter().all(|row| !row.applied));
    apply(&database, &MIGRATIONS[..3]).unwrap();
    let after = migrations::migration_status(&database).unwrap();
    assert_eq!(after.iter().filter(|row| row.applied).count(), 3);
    assert_eq!(
        serde_json::to_string(&after[0]).unwrap(),
        r#"{"version":1,"name":"baseline-v0.1.0","applied":true,"checksum_ok":true}"#
    );
}
