//! The panel's SQLite boundary (`panel/database.py`).
//!
//! - **One connection per unit of work**, opened by [`Database::connect`] with a 10 s busy timeout,
//!   `PRAGMA foreign_keys=ON` and `PRAGMA temp_store=MEMORY` (the root filesystem is read-only, so a
//!   statement journal must never spill to a temp directory), and closed when dropped.
//! - **WAL** is switched on when a [`Database`] is opened, retrying every 50 ms while another
//!   process holds the file (SQLite runs no busy handler for a journal-mode change), until the
//!   timeout.
//! - **Two transaction styles**, as in Python:
//!   - [`Database::transaction`] — `BEGIN IMMEDIATE` … `COMMIT`, `ROLLBACK` on an error;
//!   - [`Database::with_connection`] — Python's `with database.connect() as db:` block: reads run in
//!     autocommit mode, the first INSERT/UPDATE/DELETE/REPLACE executed through [`Conn::execute`]
//!     opens a deferred transaction (the `sqlite3` module's implicit `BEGIN`), and the block commits
//!     on success or rolls back on an error. An explicit `BEGIN IMMEDIATE` inside the block works too.
//!
//! Everything here blocks: call it from `spawn_blocking` and never keep a [`Conn`] across an
//! `.await`.

use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{ffi, types::ValueRef, Connection, OpenFlags, Params};
use serde_json::{Map, Number, Value};

/// The busy timeout and WAL deadline of `Database(path)` (`timeout=10.0`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

const WAL_RETRY: Duration = Duration::from_millis(50);

/// What can go wrong at the database boundary.
#[derive(Debug)]
pub enum DbError {
    /// SQLite refused a statement (Python's `sqlite3.Error` family).
    Sqlite(rusqlite::Error),
    /// The file stayed locked for the whole timeout while WAL was being switched on.
    WalLocked { path: PathBuf },
    /// The database directory could not be created.
    Io { path: PathBuf, error: std::io::Error },
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Sqlite(error) => write!(f, "{error}"),
            DbError::WalLocked { path } => {
                write!(f, "could not enable write-ahead logging on {}: the database stayed locked", path.display())
            }
            DbError::Io { path, error } => write!(f, "cannot create {}: {error}", path.display()),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DbError::Sqlite(error) => Some(error),
            DbError::Io { error, .. } => Some(error),
            DbError::WalLocked { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for DbError {
    fn from(error: rusqlite::Error) -> Self {
        DbError::Sqlite(error)
    }
}

impl DbError {
    /// True for a constraint violation (Python's `sqlite3.IntegrityError`).
    pub fn is_constraint(&self) -> bool {
        sqlite_code(self) == Some(ffi::ErrorCode::ConstraintViolation)
    }

    /// True while another connection holds the lock (`SQLITE_BUSY`/`SQLITE_LOCKED`).
    pub fn is_busy(&self) -> bool {
        matches!(sqlite_code(self), Some(ffi::ErrorCode::DatabaseBusy | ffi::ErrorCode::DatabaseLocked))
    }
}

fn sqlite_code(error: &DbError) -> Option<ffi::ErrorCode> {
    match error {
        DbError::Sqlite(rusqlite::Error::SqliteFailure(failure, _)) => Some(failure.code),
        _ => None,
    }
}

/// Errors Python's `sqlite3` raises as `OperationalError` — the ones the WAL loop waits out.
fn is_operational(error: &rusqlite::Error) -> bool {
    use ffi::ErrorCode::*;
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => matches!(
            failure.code,
            Unknown
                | PermissionDenied
                | OperationAborted
                | DatabaseBusy
                | DatabaseLocked
                | ReadOnly
                | OperationInterrupted
                | SystemIoFailure
                | DiskFull
                | CannotOpen
                | FileLockingProtocolFailed
                | SchemaChanged
        ),
        _ => false,
    }
}

/// The panel database file: where it is and how long to wait for its lock. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
    timeout: Duration,
}

impl Database {
    /// `Database(path)`: creates the parent directory and switches the file to WAL.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DbError> {
        Self::open_with_timeout(path, DEFAULT_TIMEOUT)
    }

    /// `Database(path, timeout=…)`.
    pub fn open_with_timeout(path: impl Into<PathBuf>, timeout: Duration) -> Result<Self, DbError> {
        let database = Self { path: path.into(), timeout };
        if let Some(parent) = database.path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| DbError::Io { path: parent.to_path_buf(), error })?;
        }
        let conn = database.connect()?;
        database.enable_wal(&conn)?;
        Ok(database)
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The busy timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    fn enable_wal(&self, conn: &Conn) -> Result<(), DbError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match conn.inner.query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0)) {
                Ok(mode) if mode == "wal" => return Ok(()),
                Ok(_) => {}
                Err(error) if is_operational(&error) => {}
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                return Err(DbError::WalLocked { path: self.path.clone() });
            }
            std::thread::sleep(WAL_RETRY);
        }
    }

    /// A new connection with the panel's pragmas (`Database.connect()`), in autocommit mode.
    pub fn connect(&self) -> Result<Conn, DbError> {
        let inner = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        inner.busy_timeout(self.timeout)?;
        inner.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;")?;
        Ok(Conn { inner })
    }

    /// `with database.transaction() as db:` — `BEGIN IMMEDIATE`, then `COMMIT` when `work`
    /// succeeds or `ROLLBACK` when it fails; the connection is closed either way.
    pub fn transaction<T, E>(&self, work: impl FnOnce(&Conn) -> Result<T, E>) -> Result<T, E>
    where
        E: From<DbError>,
    {
        let conn = self.connect()?;
        conn.inner.execute_batch("BEGIN IMMEDIATE").map_err(DbError::from)?;
        finish(conn, work)
    }

    /// `with database.connect() as db:` — autocommit reads, an implicit deferred `BEGIN` before the
    /// first DML through [`Conn::execute`], commit on success, rollback on an error, then close.
    pub fn with_connection<T, E>(&self, work: impl FnOnce(&Conn) -> Result<T, E>) -> Result<T, E>
    where
        E: From<DbError>,
    {
        let conn = self.connect()?;
        finish(conn, work)
    }
}

fn finish<T, E>(conn: Conn, work: impl FnOnce(&Conn) -> Result<T, E>) -> Result<T, E>
where
    E: From<DbError>,
{
    match work(&conn) {
        Ok(value) => {
            if conn.in_transaction() {
                conn.inner.execute_batch("COMMIT").map_err(DbError::from)?;
            }
            Ok(value)
        }
        Err(error) => {
            if conn.in_transaction() {
                // The original error matters more than a failed rollback; closing the connection
                // rolls back anyway.
                let _ = conn.inner.execute_batch("ROLLBACK");
            }
            Err(error)
        }
    }
}

/// One open connection. Dereferences to [`rusqlite::Connection`] for queries; writes go through
/// [`Conn::execute`]/[`Conn::insert`] so the implicit `BEGIN` of Python's `sqlite3` happens.
pub struct Conn {
    inner: Connection,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").field("path", &self.inner.path()).finish()
    }
}

impl Deref for Conn {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.inner
    }
}

impl Conn {
    /// True inside a transaction (Python's `in_transaction`).
    pub fn in_transaction(&self) -> bool {
        !self.inner.is_autocommit()
    }

    /// The `sqlite3` module's implicit `BEGIN`: opens a deferred transaction before a DML
    /// statement when none is open. Call it before running DML through a prepared statement.
    pub fn begin_implicit(&self, sql: &str) -> Result<(), DbError> {
        if is_dml(sql) && !self.in_transaction() {
            self.inner.execute_batch("BEGIN")?;
        }
        Ok(())
    }

    /// `db.execute(sql, params)` for a statement that returns no rows; the number of changed rows.
    pub fn execute<P: Params>(&self, sql: &str, params: P) -> Result<usize, DbError> {
        self.begin_implicit(sql)?;
        Ok(self.inner.execute(sql, params)?)
    }

    /// `db.execute(sql, params).lastrowid`.
    pub fn insert<P: Params>(&self, sql: &str, params: P) -> Result<i64, DbError> {
        self.execute(sql, params)?;
        Ok(self.inner.last_insert_rowid())
    }

    /// `db.commit()`: commits an open transaction (a no-op otherwise).
    pub fn commit(&self) -> Result<(), DbError> {
        if self.in_transaction() {
            self.inner.execute_batch("COMMIT")?;
        }
        Ok(())
    }

    /// `db.rollback()`: rolls back an open transaction (a no-op otherwise).
    pub fn rollback(&self) -> Result<(), DbError> {
        if self.in_transaction() {
            self.inner.execute_batch("ROLLBACK")?;
        }
        Ok(())
    }

    /// The underlying connection.
    pub fn raw(&self) -> &Connection {
        &self.inner
    }
}

/// Python 3.13 `sqlite3`'s DML test: after leading whitespace and comments, the statement starts
/// with INSERT, UPDATE, DELETE or REPLACE (any case).
pub fn is_dml(sql: &str) -> bool {
    let mut rest = sql;
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\u{c}', '\n', '\r']);
        if let Some(after) = rest.strip_prefix("--") {
            match after.find('\n') {
                Some(end) => rest = &after[end + 1..],
                None => return false,
            }
        } else if let Some(after) = rest.strip_prefix("/*") {
            match after.find("*/") {
                Some(end) => rest = &after[end + 2..],
                None => return false,
            }
        } else {
            break;
        }
    }
    let starts =
        |word: &str| rest.len() >= word.len() && rest.as_bytes()[..word.len()].eq_ignore_ascii_case(word.as_bytes());
    starts("insert") || starts("update") || starts("delete") || starts("replace")
}

/// `dict(row)` as the API returns it: column names (or aliases) in SELECT order, integers as
/// integers (booleans stay 0/1), reals as floats, NULL as null. A BLOB has no JSON form (Python
/// would fail to serialise it) and gives an error.
pub fn row_to_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Map<String, Value>> {
    let statement = row.as_ref();
    let mut out = Map::new();
    for index in 0..statement.column_count() {
        let name = statement.column_name(index)?.to_string();
        let value = match row.get_ref(index)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(value) => Value::Number(value.into()),
            ValueRef::Real(value) => Number::from_f64(value).map_or(Value::Null, Value::Number),
            ValueRef::Text(bytes) => Value::String(
                std::str::from_utf8(bytes).map_err(|error| rusqlite::Error::Utf8Error(index, error))?.to_string(),
            ),
            ValueRef::Blob(_) => {
                return Err(rusqlite::Error::InvalidColumnType(index, name, rusqlite::types::Type::Blob));
            }
        };
        out.insert(name, value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dml_detection_matches_python() {
        assert!(is_dml("INSERT INTO t VALUES(1)"));
        assert!(is_dml("  \n replace into t VALUES(1)"));
        assert!(is_dml("-- note\nUPDATE t SET x=1"));
        assert!(is_dml("/* c */ delete FROM t"));
        assert!(!is_dml("SELECT 1"));
        assert!(!is_dml("WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x"));
        assert!(!is_dml("BEGIN IMMEDIATE"));
        assert!(!is_dml("CREATE TABLE t(x)"));
    }
}
