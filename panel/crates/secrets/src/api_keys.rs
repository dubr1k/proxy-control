//! Scoped Bearer keys, 3x-ui style: hashed at rest, shown once, revocable (`panel/api_keys.py`,
//! ADR 008).
//!
//! A key is `pc_` + 8 random hex digits (the stored `prefix`) + `_` + `token_urlsafe(32)`; only the
//! sha256 hex of the whole text is stored. The per-key request rate limit lives with the HTTP layer.

use std::fmt;

use panel_core::clock::{SharedClock, SystemClock};
use panel_core::db::{Database, DbError};
use panel_core::pytext;
use panel_core::rusqlite::{self, params};
use panel_core::serde_json::{Map, Value};

use crate::audit::{self, Actor, Record};

/// The scopes a key can have.
pub const SCOPES: [&str; 3] = ["admin", "monitor", "node-sync"];
/// Every key starts with this.
pub const KEY_PREFIX: &str = "pc_";
/// `last_used_at` is written at most this often (seconds).
pub const LAST_USED_GRANULARITY: i64 = 60;

/// The role a scope acts as: `admin→owner`, `monitor→viewer`, `node-sync→node-sync`.
pub fn scope_role(scope: &str) -> Option<&'static str> {
    match scope {
        "admin" => Some("owner"),
        "monitor" => Some("viewer"),
        "node-sync" => Some("node-sync"),
        _ => None,
    }
}

/// Why a key operation was refused.
#[derive(Debug)]
pub enum ApiKeyError {
    /// `ValueError` with one of the fixed messages.
    Invalid(&'static str),
    /// No key has this id (`KeyError`).
    NotFound(i64),
    Db(DbError),
}

impl ApiKeyError {
    pub const NAME: &'static str = "name is invalid";
    pub const SCOPE: &'static str = "scope is invalid";
    pub const EXPIRED: &'static str = "expires_at is in the past";
}

impl fmt::Display for ApiKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiKeyError::Invalid(message) => f.write_str(message),
            ApiKeyError::NotFound(key_id) => write!(f, "{key_id}"),
            ApiKeyError::Db(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ApiKeyError {}

impl From<DbError> for ApiKeyError {
    fn from(error: DbError) -> Self {
        ApiKeyError::Db(error)
    }
}

impl From<rusqlite::Error> for ApiKeyError {
    fn from(error: rusqlite::Error) -> Self {
        ApiKeyError::Db(error.into())
    }
}

/// A key as the API shows it (never the hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKey {
    pub id: i64,
    pub name: String,
    pub scope: String,
    pub prefix: String,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub created_by: String,
    pub last_used_at: Option<i64>,
}

impl ApiKey {
    const COLUMNS: &'static str = "id,name,scope,prefix,enabled,expires_at,created_at,created_by,last_used_at";

    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name: row.get(1)?,
            scope: row.get(2)?,
            prefix: row.get(3)?,
            enabled: row.get::<_, i64>(4)? != 0,
            expires_at: row.get(5)?,
            created_at: row.get(6)?,
            created_by: row.get(7)?,
            last_used_at: row.get(8)?,
        })
    }

    /// `_row(row)`: the JSON object in Python's key order.
    pub fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("id".into(), self.id.into());
        out.insert("name".into(), self.name.clone().into());
        out.insert("scope".into(), self.scope.clone().into());
        out.insert("prefix".into(), self.prefix.clone().into());
        out.insert("enabled".into(), self.enabled.into());
        out.insert("expires_at".into(), self.expires_at.into());
        out.insert("created_at".into(), self.created_at.into());
        out.insert("created_by".into(), self.created_by.clone().into());
        out.insert("last_used_at".into(), self.last_used_at.into());
        out
    }
}

/// Who an authenticated key acts as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyPrincipal {
    pub key_id: i64,
    /// `key:<name>`.
    pub username: String,
    pub role: &'static str,
    pub scope: String,
}

impl ApiKeyPrincipal {
    /// `{"id": None, "key_id", "username", "role", "scope", "via": "api-key"}`.
    pub fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("id".into(), Value::Null);
        out.insert("key_id".into(), self.key_id.into());
        out.insert("username".into(), self.username.clone().into());
        out.insert("role".into(), self.role.into());
        out.insert("scope".into(), self.scope.clone().into());
        out.insert("via".into(), "api-key".into());
        out
    }
}

/// `id, name, scope, key_hash, enabled, expires_at, last_used_at` of a key with the right prefix.
type Candidate = (i64, String, String, String, i64, Option<i64>, Option<i64>);

/// The key service.
#[derive(Clone)]
pub struct ApiKeyService {
    database: Database,
    clock: SharedClock,
}

impl fmt::Debug for ApiKeyService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyService").field("database", &self.database.path()).finish_non_exhaustive()
    }
}

impl ApiKeyService {
    pub fn new(database: Database) -> Self {
        Self::with_clock(database, SystemClock::shared())
    }

    pub fn with_clock(database: Database, clock: SharedClock) -> Self {
        Self { database, clock }
    }

    /// `create(name, scope, expires_at, actor=…, ip=…, request_id=…)`: the stored key and the
    /// plaintext, which is never shown again. Audited `api_key.create` in the same transaction.
    pub fn create(
        &self,
        name: &str,
        scope: &str,
        expires_at: Option<i64>,
        actor: &Actor,
        ip: &str,
        request_id: Option<&str>,
    ) -> Result<(ApiKey, String), ApiKeyError> {
        let stripped = pytext::strip(name);
        if stripped.is_empty() || pytext::len(name) > 64 {
            return Err(ApiKeyError::Invalid(ApiKeyError::NAME));
        }
        if !SCOPES.contains(&scope) {
            return Err(ApiKeyError::Invalid(ApiKeyError::SCOPE));
        }
        let now = self.clock.now();
        if expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(ApiKeyError::Invalid(ApiKeyError::EXPIRED));
        }
        let prefix = panel_core::ids::token_hex(4);
        let plaintext = format!("{KEY_PREFIX}{prefix}_{}", panel_core::ids::token_urlsafe(32));
        let key = self.database.transaction(|db| -> Result<ApiKey, ApiKeyError> {
            let id = db.insert(
                "INSERT INTO api_keys(name,scope,prefix,key_hash,enabled,expires_at,created_at,created_by)
                   VALUES(?,?,?,?,1,?,?,?)",
                params![stripped, scope, prefix, crate::hash_token(&plaintext), expires_at, now, actor.username],
            )?;
            let mut detail = Map::new();
            detail.insert("name".into(), stripped.into());
            detail.insert("scope".into(), scope.into());
            detail.insert("expires_at".into(), expires_at.into());
            audit::record_at(
                db,
                &Record::new(actor, "api_key.create", id.to_string(), ip).request_id(request_id).detail(detail),
                now,
            )?;
            Ok(db.query_row(&format!("SELECT {} FROM api_keys WHERE id=?", ApiKey::COLUMNS), [id], ApiKey::read)?)
        })?;
        Ok((key, plaintext))
    }

    /// `list()`: every key by id.
    pub fn list(&self) -> Result<Vec<ApiKey>, DbError> {
        self.database.with_connection(|db| {
            let mut statement = db.prepare(&format!("SELECT {} FROM api_keys ORDER BY id", ApiKey::COLUMNS))?;
            let rows = statement.query_map([], ApiKey::read)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// `set_enabled(key_id, enabled, …)`, audited `api_key.enable`/`api_key.disable`.
    pub fn set_enabled(
        &self,
        key_id: i64,
        enabled: bool,
        actor: &Actor,
        ip: &str,
        request_id: Option<&str>,
    ) -> Result<(), ApiKeyError> {
        self.database.transaction(|db| {
            if db.execute("UPDATE api_keys SET enabled=? WHERE id=?", params![i64::from(enabled), key_id])? != 1 {
                return Err(ApiKeyError::NotFound(key_id));
            }
            let action = if enabled { "api_key.enable" } else { "api_key.disable" };
            audit::record_at(
                db,
                &Record::new(actor, action, key_id.to_string(), ip).request_id(request_id),
                self.clock.now(),
            )?;
            Ok(())
        })
    }

    /// `delete(key_id, …)`, audited `api_key.delete`.
    pub fn delete(&self, key_id: i64, actor: &Actor, ip: &str, request_id: Option<&str>) -> Result<(), ApiKeyError> {
        self.database.transaction(|db| {
            if db.execute("DELETE FROM api_keys WHERE id=?", [key_id])? != 1 {
                return Err(ApiKeyError::NotFound(key_id));
            }
            audit::record_at(
                db,
                &Record::new(actor, "api_key.delete", key_id.to_string(), ip).request_id(request_id),
                self.clock.now(),
            )?;
            Ok(())
        })
    }

    /// `authenticate(plaintext)`: the principal of an enabled, unexpired key whose hash matches,
    /// comparing in constant time against every row with the same prefix. `last_used_at` is
    /// written (and committed at once) at most every [`LAST_USED_GRANULARITY`] seconds.
    pub fn authenticate(&self, plaintext: Option<&str>) -> Result<Option<ApiKeyPrincipal>, DbError> {
        let Some(plaintext) = plaintext.filter(|text| text.starts_with(KEY_PREFIX) && text.matches('_').count() >= 2)
        else {
            return Ok(None);
        };
        let prefix = plaintext.split('_').nth(1).unwrap_or_default();
        let digest = crate::hash_token(plaintext);
        let now = self.clock.now();
        self.database.with_connection(|db| {
            let rows: Vec<Candidate> = {
                let mut statement = db.prepare(
                    "SELECT id,name,scope,key_hash,enabled,expires_at,last_used_at FROM api_keys WHERE prefix=?",
                )?;
                let rows = statement.query_map([prefix], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (id, name, scope, key_hash, enabled, expires_at, last_used_at) in rows {
                if !crate::compare_digest(&key_hash, &digest) {
                    continue;
                }
                if enabled == 0 || expires_at.is_some_and(|expires_at| expires_at <= now) {
                    return Ok(None);
                }
                if last_used_at.is_none_or(|last| last == 0 || now - last >= LAST_USED_GRANULARITY) {
                    db.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", params![now, id])?;
                    db.commit()?;
                }
                let role = scope_role(&scope).unwrap_or("viewer");
                return Ok(Some(ApiKeyPrincipal { key_id: id, username: format!("key:{name}"), role, scope }));
            }
            Ok(None)
        })
    }
}
