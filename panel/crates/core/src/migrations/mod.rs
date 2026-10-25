//! Versioned, checksummed, cross-process-safe schema migrations (`panel/migrations.py`).
//!
//! The runner takes `BEGIN IMMEDIATE` before touching anything, so two processes starting on one
//! file serialise; refuses a database whose newest recorded migration is newer than the code
//! (downgrade); refuses a recorded migration whose checksum no longer matches; and refuses a
//! database from before the runner existed (tables but no recorded migration — Proxy Control
//! v0.1.0), which the Python panel used to adopt (`_legacy_upgrade`, not ported: owner decision
//! 2026-10-25).
//!
//! The SQL text in `list.rs` is Python's, verbatim: the checksum of every migration is recorded in
//! every existing database, and `sqlite_master` keeps the statements' text.

mod list;

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::db::{Conn, Database, DbError};
use crate::ids::sha256_hex;
use crate::pytext;

pub use list::MIGRATIONS;

/// One migration: a version, a name and the statements it runs in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub statements: &'static [&'static str],
}

impl Migration {
    /// `sha256("{version}:{name}\n" + "\n".join(" ".join(s.split()) for s in statements))` — with
    /// Python's `str.split()` (Unicode whitespace).
    pub fn checksum(&self) -> String {
        let canonical: Vec<String> =
            self.statements.iter().map(|statement| pytext::collapse_whitespace(statement)).collect();
        sha256_hex(format!("{}:{}\n{}", self.version, self.name, canonical.join("\n")))
    }
}

/// The table the runner records applied migrations in (text kept for `sqlite_master`).
const SCHEMA_MIGRATIONS: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)";

/// Why the runner refused or failed.
#[derive(Debug)]
pub enum MigrationError {
    /// `database schema {newest} is newer than this code ({last})`.
    Newer { newest: i64, last: i64 },
    /// `migration {version} checksum mismatch`.
    ChecksumMismatch { version: i64 },
    /// Tables exist but no migration is recorded: a database from before the migration runner.
    PreRunner { tables: Vec<String> },
    /// A statement failed; the whole run was rolled back.
    Database(DbError),
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationError::Newer { newest, last } => {
                write!(f, "database schema {newest} is newer than this code ({last})")
            }
            MigrationError::ChecksumMismatch { version } => write!(f, "migration {version} checksum mismatch"),
            MigrationError::PreRunner { tables } => write!(
                f,
                "this database was created before schema migrations existed (Proxy Control v0.1.0: tables {} \
                 but no schema_migrations records) and cannot be upgraded by this version; upgrade it with \
                 a 3.x release first",
                tables.join(", ")
            ),
            MigrationError::Database(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MigrationError::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DbError> for MigrationError {
    fn from(error: DbError) -> Self {
        MigrationError::Database(error)
    }
}

impl From<rusqlite::Error> for MigrationError {
    fn from(error: rusqlite::Error) -> Self {
        MigrationError::Database(error.into())
    }
}

/// `apply_migrations(database)`: applies every pending migration in one `BEGIN IMMEDIATE`
/// transaction and returns the versions applied (empty when the database is current).
pub fn apply_migrations(database: &Database) -> Result<Vec<i64>, MigrationError> {
    apply(database, MIGRATIONS)
}

/// [`apply_migrations`] with an explicit list — the first `n` of [`MIGRATIONS`] build a database at
/// an older version in tests.
pub fn apply(database: &Database, migrations: &[Migration]) -> Result<Vec<i64>, MigrationError> {
    let last = migrations.last().map_or(0, |migration| migration.version);
    database.transaction(|db| {
        let recorded = table_exists(db, "schema_migrations")?;
        let newest: i64 = if recorded {
            db.query_row("SELECT max(version) FROM schema_migrations", [], |row| row.get::<_, Option<i64>>(0))?
                .unwrap_or(0)
        } else {
            0
        };
        if newest > last {
            return Err(MigrationError::Newer { newest, last });
        }
        if newest == 0 {
            let tables = user_tables(db)?;
            if !tables.is_empty() {
                return Err(MigrationError::PreRunner { tables });
            }
        }
        if !recorded {
            db.execute(SCHEMA_MIGRATIONS, [])?;
        }
        let mut applied = Vec::new();
        for migration in migrations {
            let checksum = migration.checksum();
            let stored: Option<String> = db
                .query_row("SELECT checksum FROM schema_migrations WHERE version=?", [migration.version], |row| {
                    row.get(0)
                })
                .map(Some)
                .or_else(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    error => Err(error),
                })?;
            if let Some(stored) = stored {
                if stored != checksum {
                    return Err(MigrationError::ChecksumMismatch { version: migration.version });
                }
                continue;
            }
            for statement in migration.statements {
                db.execute(statement, [])?;
            }
            let applied_at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs() as i64);
            db.execute(
                "INSERT INTO schema_migrations VALUES(?,?,?,?)",
                rusqlite::params![migration.version, migration.name, checksum, applied_at],
            )?;
            applied.push(migration.version);
        }
        Ok(applied)
    })
}

fn table_exists(db: &Conn, name: &str) -> Result<bool, rusqlite::Error> {
    db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", [name], |row| row.get::<_, i64>(0))
        .map(|count| count > 0)
}

/// Tables other than SQLite's own and the runner's.
fn user_tables(db: &Conn) -> Result<Vec<String>, rusqlite::Error> {
    let mut statement = db.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
         AND name <> 'schema_migrations' ORDER BY name",
    )?;
    let names = statement.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

/// One row of [`migration_status`] (`db-status`), keys in Python's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationStatus {
    pub version: i64,
    pub name: &'static str,
    pub applied: bool,
    pub checksum_ok: bool,
}

/// `migration_status(database)`: read-only; a database without the migrations table reports
/// nothing applied (and the table is not created).
pub fn migration_status(database: &Database) -> Result<Vec<MigrationStatus>, DbError> {
    status(database, MIGRATIONS)
}

/// [`migration_status`] against an explicit list.
pub fn status(database: &Database, migrations: &[Migration]) -> Result<Vec<MigrationStatus>, DbError> {
    let conn = database.connect()?;
    let mut recorded = std::collections::HashMap::new();
    if table_exists(&conn, "schema_migrations")? {
        let mut statement = conn.prepare("SELECT version, checksum FROM schema_migrations")?;
        let rows = statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?;
        for row in rows {
            let (version, checksum) = row?;
            recorded.insert(version, checksum);
        }
    }
    Ok(migrations
        .iter()
        .map(|migration| MigrationStatus {
            version: migration.version,
            name: migration.name,
            applied: recorded.contains_key(&migration.version),
            checksum_ok: recorded.get(&migration.version).is_some_and(|checksum| *checksum == migration.checksum()),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_consecutive_from_one() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(migration.version, index as i64 + 1);
        }
        assert_eq!(MIGRATIONS.len(), 26);
    }
}
