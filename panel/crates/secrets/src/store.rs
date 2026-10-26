//! Administrators, sessions, CSRF, the login limiter and the audit trail (`panel/store.py`).
//!
//! - Passwords: [`PasswordHasher::panel`]; an unknown user is verified against
//!   [`DUMMY_PASSWORD_HASH`] so a login costs the same either way; a successful login re-hashes a
//!   password stored with other parameters.
//! - Sessions: `token_urlsafe(32)` session and CSRF tokens; only their sha256 hex is stored.
//! - Login limiter: `login_attempts` rows reserved before the password is checked, under a process
//!   lock and `BEGIN IMMEDIATE`; a successful login releases its own reservation only.
//!
//! [`Store::new`] expects a migrated database (Python's `Store.__init__` ran the migrations itself;
//! the Rust panel runs them once at start-up).

use std::fmt;
use std::sync::Mutex;

use panel_core::clock::{SharedClock, SystemClock};
use panel_core::db::{Database, DbError};
use panel_core::rusqlite::{self, params, OptionalExtension as _};
use panel_core::serde_json::{Map, Value};

use crate::audit::{self, Actor, AuditQuery, ListError, Record};
use crate::passwords::{InvalidHash, PasswordHasher, DUMMY_PASSWORD_HASH};

/// The roles an administrator can have.
pub const ROLES: [&str; 3] = ["owner", "admin", "viewer"];
/// Passwords shorter than this (in code points) are refused.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// What can go wrong in the store.
#[derive(Debug)]
pub enum StoreError {
    /// `ValueError("invalid administrator")`: unknown role or a password under 12 characters.
    InvalidAdministrator,
    /// `ValueError("invalid login limiter configuration")`.
    InvalidLimiter,
    /// `ConflictError("last owner")`: the change would leave no active owner.
    LastOwner,
    /// A stored password hash is not a usable argon2 hash.
    InvalidHash,
    Db(DbError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::InvalidAdministrator => f.write_str("invalid administrator"),
            StoreError::InvalidLimiter => f.write_str("invalid login limiter configuration"),
            StoreError::LastOwner => f.write_str("last owner"),
            StoreError::InvalidHash => f.write_str("invalid argon2 password hash"),
            StoreError::Db(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<DbError> for StoreError {
    fn from(error: DbError) -> Self {
        StoreError::Db(error)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        StoreError::Db(error.into())
    }
}

impl From<InvalidHash> for StoreError {
    fn from(_: InvalidHash) -> Self {
        StoreError::InvalidHash
    }
}

/// An `admins` row. `Debug` leaves the hash out.
#[derive(Clone, PartialEq, Eq)]
pub struct Admin {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub active: i64,
    pub created_at: i64,
}

impl fmt::Debug for Admin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admin")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("role", &self.role)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

/// A live session: the `sessions` row joined with its administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub token_hash: String,
    pub admin_id: i64,
    pub csrf_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: i64,
    pub username: String,
    pub role: String,
    pub active: i64,
}

/// The store.
pub struct Store {
    database: Database,
    clock: SharedClock,
    passwords: PasswordHasher,
    lock: Mutex<()>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").field("database", &self.database.path()).finish_non_exhaustive()
    }
}

impl Store {
    /// A store over a migrated database, with the panel's password policy and the system clock.
    pub fn new(database: Database) -> Self {
        Self::with_options(database, SystemClock::shared(), PasswordHasher::panel())
    }

    /// The same with another clock and password policy (tests).
    pub fn with_options(database: Database, clock: SharedClock, passwords: PasswordHasher) -> Self {
        Self { database, clock, passwords, lock: Mutex::new(()) }
    }

    /// The database.
    pub fn database(&self) -> &Database {
        &self.database
    }

    /// The password policy.
    pub fn passwords(&self) -> &PasswordHasher {
        &self.passwords
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `create_admin(username, password, role)`: create the administrator, or — when the username
    /// exists (case-insensitively) — set its password and role and re-activate it. The id.
    pub fn create_admin(&self, username: &str, password: &str, role: &str) -> Result<i64, StoreError> {
        if !ROLES.contains(&role) || panel_core::pytext::len(password) < MIN_PASSWORD_CHARS {
            return Err(StoreError::InvalidAdministrator);
        }
        let password_hash = self.passwords.hash(password);
        let now = self.clock.now();
        self.database.with_connection(|db| {
            let existing: Option<i64> = db
                .query_row("SELECT id FROM admins WHERE username=? COLLATE NOCASE", [username], |row| row.get(0))
                .optional()?;
            if let Some(id) = existing {
                db.execute(
                    "UPDATE admins SET password_hash=?, role=?, active=1 WHERE id=?",
                    params![password_hash, role, id],
                )?;
                return Ok(id);
            }
            Ok(db.insert(
                "INSERT INTO admins(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                params![username, password_hash, role, now],
            )?)
        })
    }

    /// `verify_admin(username, password)`: the active administrator whose password matches, or
    /// `None`. An unknown user still costs one argon2 verification. A match stored with other
    /// parameters is re-hashed in place.
    pub fn verify_admin(&self, username: &str, password: &str) -> Result<Option<Admin>, StoreError> {
        self.database.with_connection(|db| {
            let row = db
                .query_row(
                    "SELECT id,username,password_hash,role,active,created_at FROM admins WHERE username=? COLLATE NOCASE AND active=1",
                    [username],
                    |row| {
                        Ok(Admin {
                            id: row.get(0)?,
                            username: row.get(1)?,
                            password_hash: row.get(2)?,
                            role: row.get(3)?,
                            active: row.get(4)?,
                            created_at: row.get(5)?,
                        })
                    },
                )
                .optional()?;
            let Some(admin) = row else {
                // Timing equalisation: the result does not matter.
                let _ = self.passwords.verify(DUMMY_PASSWORD_HASH, password);
                return Ok(None);
            };
            if !self.passwords.verify(&admin.password_hash, password)? {
                return Ok(None);
            }
            if self.passwords.needs_rehash(&admin.password_hash)? {
                db.execute("UPDATE admins SET password_hash=? WHERE id=?", params![self.passwords.hash(password), admin.id])?;
            }
            Ok(Some(admin))
        })
    }

    /// `create_session(admin_id, ttl)`: purge expired sessions, store a new one; the plaintext
    /// session and CSRF tokens.
    pub fn create_session(&self, admin_id: i64, ttl: i64) -> Result<(String, String), StoreError> {
        let token = panel_core::ids::token_urlsafe(32);
        let csrf = panel_core::ids::token_urlsafe(32);
        let now = self.clock.now();
        self.database.with_connection(|db| -> Result<(), StoreError> {
            db.execute("DELETE FROM sessions WHERE expires_at<=?", [now])?;
            db.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?,?)",
                params![crate::hash_token(&token), admin_id, crate::hash_token(&csrf), now, now + ttl, now],
            )?;
            Ok(())
        })?;
        Ok((token, csrf))
    }

    /// `session(token)`: the unexpired session of an active administrator (its `last_seen_at`
    /// updated, no sliding expiry), or `None`.
    pub fn session(&self, token: Option<&str>) -> Result<Option<Session>, StoreError> {
        let Some(token) = token.filter(|token| !token.is_empty()) else {
            return Ok(None);
        };
        let now = self.clock.now();
        self.database.with_connection(|db| {
            let row = db
                .query_row(
                    "SELECT s.token_hash,s.admin_id,s.csrf_hash,s.created_at,s.expires_at,s.last_seen_at,a.username,a.role,a.active FROM sessions s
                JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.active=1",
                    params![crate::hash_token(token), now],
                    |row| {
                        Ok(Session {
                            token_hash: row.get(0)?,
                            admin_id: row.get(1)?,
                            csrf_hash: row.get(2)?,
                            created_at: row.get(3)?,
                            expires_at: row.get(4)?,
                            last_seen_at: row.get(5)?,
                            username: row.get(6)?,
                            role: row.get(7)?,
                            active: row.get(8)?,
                        })
                    },
                )
                .optional()?;
            if let Some(session) = &row {
                db.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", params![now, session.token_hash])?;
            }
            Ok(row)
        })
    }

    /// `csrf_valid(session, supplied, cookie)`: the header equals the cookie and its hash equals
    /// the session's, both compared in constant time.
    pub fn csrf_valid(&self, session: &Session, supplied: Option<&str>, cookie: Option<&str>) -> bool {
        match (supplied, cookie) {
            (Some(supplied), Some(cookie)) if !supplied.is_empty() && !cookie.is_empty() => {
                crate::compare_digest(supplied, cookie)
                    && crate::compare_digest(&crate::hash_token(supplied), &session.csrf_hash)
            }
            _ => false,
        }
    }

    /// `delete_session(token)`.
    pub fn delete_session(&self, token: Option<&str>) -> Result<(), StoreError> {
        if let Some(token) = token.filter(|token| !token.is_empty()) {
            self.database.with_connection(|db| -> Result<(), StoreError> {
                db.execute("DELETE FROM sessions WHERE token_hash=?", [crate::hash_token(token)])?;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// `reserve_login_attempt(scopes, attempts, window)`: atomically reserve one attempt per scope
    /// before the expensive password check. `None` when any scope already has `attempts` rows in
    /// the window (rows older than the window are purged either way); otherwise the reservation
    /// id (`token_urlsafe(18)`).
    pub fn reserve_login_attempt(
        &self,
        scopes: &[String],
        attempts: i64,
        window: i64,
    ) -> Result<Option<String>, StoreError> {
        if scopes.is_empty() || attempts < 1 || window < 1 {
            return Err(StoreError::InvalidLimiter);
        }
        let now = self.clock.now();
        let reservation_id = panel_core::ids::token_urlsafe(18);
        let cutoff = now - window;
        let _guard = self.locked();
        self.database.with_connection(|db| {
            db.execute_batch("BEGIN IMMEDIATE")?;
            db.execute("DELETE FROM login_attempts WHERE happened_at<?", [cutoff])?;
            for scope in scopes {
                let count: i64 =
                    db.query_row("SELECT count(*) FROM login_attempts WHERE scope=?", [scope], |row| row.get(0))?;
                if count >= attempts {
                    return Ok(None);
                }
            }
            for scope in scopes {
                db.execute(
                    "INSERT INTO login_attempts(scope,happened_at,reservation_id) VALUES(?,?,?)",
                    params![scope, now, reservation_id],
                )?;
            }
            Ok(Some(reservation_id))
        })
    }

    /// `release_login_attempt(reservation_id)`.
    pub fn release_login_attempt(&self, reservation_id: &str) -> Result<(), StoreError> {
        let _guard = self.locked();
        self.database.with_connection(|db| -> Result<(), StoreError> {
            db.execute("DELETE FROM login_attempts WHERE reservation_id=?", [reservation_id])?;
            Ok(())
        })
    }

    /// `admins()`: `id, username, role, active, created_at` of every administrator by username.
    pub fn admins(&self) -> Result<Vec<Map<String, Value>>, StoreError> {
        self.database.with_connection(|db| {
            let mut statement =
                db.prepare("SELECT id,username,role,active,created_at FROM admins ORDER BY username")?;
            let rows = statement.query_map([], panel_core::db::row_to_json)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// `update_admin(admin_id, role=…, password=…, active=…)`: `false` for an unknown id. An empty
    /// role or password changes nothing. A new password or deactivation ends the admin's sessions.
    /// Demoting or deactivating the last active owner is refused.
    pub fn update_admin(
        &self,
        admin_id: i64,
        role: Option<&str>,
        password: Option<&str>,
        active: Option<bool>,
    ) -> Result<bool, StoreError> {
        let role = role.filter(|role| !role.is_empty());
        let password_hash =
            password.filter(|password| !password.is_empty()).map(|password| self.passwords.hash(password));
        let _guard = self.locked();
        self.database.with_connection(|db| {
            let current: Option<String> =
                db.query_row("SELECT role FROM admins WHERE id=?", [admin_id], |row| row.get(0)).optional()?;
            let Some(current) = current else {
                return Ok(false);
            };
            if current == "owner" && role.is_some_and(|role| role != "owner") && owner_count(db)? <= 1 {
                return Err(StoreError::LastOwner);
            }
            if current == "owner" && active == Some(false) && owner_count(db)? <= 1 {
                return Err(StoreError::LastOwner);
            }
            if let Some(role) = role {
                db.execute("UPDATE admins SET role=? WHERE id=?", params![role, admin_id])?;
            }
            if let Some(password_hash) = &password_hash {
                db.execute("UPDATE admins SET password_hash=? WHERE id=?", params![password_hash, admin_id])?;
                db.execute("DELETE FROM sessions WHERE admin_id=?", [admin_id])?;
            }
            if let Some(active) = active {
                db.execute("UPDATE admins SET active=? WHERE id=?", params![i64::from(active), admin_id])?;
                if !active {
                    db.execute("DELETE FROM sessions WHERE admin_id=?", [admin_id])?;
                }
            }
            Ok(true)
        })
    }

    /// `delete_admin(admin_id)`: `false` for an unknown id; the last active owner stays.
    pub fn delete_admin(&self, admin_id: i64) -> Result<bool, StoreError> {
        let _guard = self.locked();
        self.database.with_connection(|db| {
            let role: Option<String> =
                db.query_row("SELECT role FROM admins WHERE id=?", [admin_id], |row| row.get(0)).optional()?;
            let Some(role) = role else {
                return Ok(false);
            };
            if role == "owner" && owner_count(db)? <= 1 {
                return Err(StoreError::LastOwner);
            }
            db.execute("DELETE FROM admins WHERE id=?", [admin_id])?;
            Ok(true)
        })
    }

    /// `audit(actor, action, target, ip, detail, request_id)` in its own connection.
    pub fn audit(
        &self,
        actor: &Actor,
        action: &str,
        target: &str,
        ip: &str,
        detail: Option<Map<String, Value>>,
        request_id: Option<&str>,
    ) -> Result<i64, StoreError> {
        let mut record = Record::new(actor, action, target, ip).request_id(request_id);
        record.detail = detail;
        let now = self.clock.now();
        Ok(self.database.with_connection(|db| audit::record_at(db, &record, now))?)
    }

    /// `audits(limit, before_id=…, actor=…, action=…, target=…, request_id=…)`.
    pub fn audits(&self, query: &AuditQuery) -> Result<Vec<Map<String, Value>>, ListError> {
        audit::list(&self.database, query)
    }
}

fn owner_count(db: &panel_core::db::Conn) -> Result<i64, StoreError> {
    Ok(db.query_row("SELECT count(*) FROM admins WHERE role='owner' AND active=1", [], |row| row.get(0))?)
}
