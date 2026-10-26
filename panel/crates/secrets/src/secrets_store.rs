//! AES-256-GCM secret versions bound to their identity through AAD (`panel/secrets_store.py`).
//!
//! - Nonce: 12 random bytes, stored raw in `secret_versions.nonce`.
//! - Ciphertext: `ct ‖ tag(16)`, stored raw in `secret_versions.ciphertext` (what both
//!   `cryptography`'s `AESGCM.encrypt` and RustCrypto's `aes-gcm` produce).
//! - AAD: `json.dumps({secret_id, version, purpose, grant_id, permitted_node_id}, sort_keys=True,
//!   separators=(",", ":"))` — ASCII-escaped, `null` for a missing grant or node. A ciphertext
//!   copied into another row, or revealed for another node, fails authentication.
//!
//! [`SecretStore::reveal`] rebuilds the AAD from the caller's identity (the anti-transplant check);
//! [`SecretStore::rewrap`] and [`SecretStore::verify_all`] rebuild it from the row. Error messages
//! are fixed strings: nothing here ever formats plaintext or ciphertext.
//!
//! Also here: what the CLI and the app factory do with the keyring ([`rotate_master_key`],
//! [`verify_master_key`], [`SecretStore::open`]).

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use panel_core::clock::{SharedClock, SystemClock};
use panel_core::db::{Conn, Database, DbError};
use panel_core::pyjson;
use panel_core::rusqlite::{self, params, OptionalExtension as _};
use panel_core::serde_json::json;

use crate::keyring::{Keyring, KeyringError};

/// The states of a secret version.
pub const STATES: [&str; 4] = ["pending", "active", "retiring", "revoked"];

/// What can go wrong in the secret store.
#[derive(Debug)]
pub enum SecretError {
    /// A refusal with a fixed message (`SecretError` in Python).
    Refused(&'static str),
    /// The database failed.
    Db(DbError),
}

impl SecretError {
    pub const DISABLED: &'static str = "secret store is disabled: PANEL_MASTER_KEY_FILE is not configured";
    pub const INVALID_STATE: &'static str = "invalid secret state";
    pub const UNAVAILABLE: &'static str = "secret version unavailable";
    pub const UNKNOWN_KEY: &'static str = "secret version was encrypted under an unknown key";
    pub const AUTHENTICATION: &'static str = "secret version failed authentication for this identity";
    pub const REWRAP: &'static str = "rewrap cannot decrypt a row under the overlap keyring";
    pub const VERIFY: &'static str = "a secret version does not decrypt under the current keyring";

    /// The fixed message of a refusal.
    pub fn message(&self) -> Option<&'static str> {
        match self {
            SecretError::Refused(message) => Some(message),
            SecretError::Db(_) => None,
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Refused(message) => f.write_str(message),
            SecretError::Db(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SecretError {}

impl From<DbError> for SecretError {
    fn from(error: DbError) -> Self {
        SecretError::Db(error)
    }
}

impl From<rusqlite::Error> for SecretError {
    fn from(error: rusqlite::Error) -> Self {
        SecretError::Db(error.into())
    }
}

/// Which version of which secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    pub secret_id: String,
    pub version: i64,
}

impl SecretRef {
    pub fn new(secret_id: impl Into<String>, version: i64) -> Self {
        Self { secret_id: secret_id.into(), version }
    }
}

/// Everything the AAD binds a ciphertext to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity<'a> {
    pub secret_id: &'a str,
    pub version: i64,
    pub purpose: &'a str,
    pub grant_id: Option<&'a str>,
    pub permitted_node_id: Option<&'a str>,
}

impl Identity<'_> {
    /// `_aad(...)`: the canonical JSON of the five fields, as bytes.
    pub fn aad(&self) -> Vec<u8> {
        pyjson::canonical(&json!({
            "secret_id": self.secret_id,
            "version": self.version,
            "purpose": self.purpose,
            "grant_id": self.grant_id,
            "permitted_node_id": self.permitted_node_id,
        }))
        .into_bytes()
    }
}

/// `AESGCM(key).encrypt(nonce, plaintext, aad)`: `ct ‖ tag`.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("AES-GCM encryption of an in-memory buffer cannot fail")
}

/// `AESGCM(key).decrypt(nonce, ct ‖ tag, aad)`; `None` when the tag does not authenticate. Only
/// 12-byte nonces are accepted (the only length the panel ever writes).
pub fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != 12 {
        return None;
    }
    Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .ok()
}

/// A `secret_versions` row as the store reads it.
struct Row {
    secret_id: String,
    version: i64,
    purpose: String,
    grant_id: Option<String>,
    permitted_node_id: Option<String>,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    state: String,
}

impl Row {
    const COLUMNS: &'static str = "secret_id,version,purpose,grant_id,permitted_node_id,key_id,nonce,ciphertext,state";

    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            secret_id: row.get(0)?,
            version: row.get(1)?,
            purpose: row.get(2)?,
            grant_id: row.get(3)?,
            permitted_node_id: row.get(4)?,
            key_id: row.get(5)?,
            nonce: row.get(6)?,
            ciphertext: row.get(7)?,
            state: row.get(8)?,
        })
    }

    fn identity(&self) -> Identity<'_> {
        Identity {
            secret_id: &self.secret_id,
            version: self.version,
            purpose: &self.purpose,
            grant_id: self.grant_id.as_deref(),
            permitted_node_id: self.permitted_node_id.as_deref(),
        }
    }
}

/// The secret store: disabled without a keyring (every call but [`SecretStore::transition`]
/// refuses). `Debug` shows only whether it is enabled.
#[derive(Clone)]
pub struct SecretStore {
    keyring: Option<Keyring>,
    clock: SharedClock,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretStore(enabled={})", if self.enabled() { "True" } else { "False" })
    }
}

/// Why the app factory refused the master key configuration.
#[derive(Debug)]
pub enum OpenError {
    /// `PANEL_MASTER_KEY_FILE` is unset while `secret_versions` holds rows.
    KeyRequired,
    /// The keyring file could not be loaded.
    Keyring(KeyringError),
    /// The database failed.
    Db(DbError),
}

impl OpenError {
    pub const KEY_REQUIRED: &'static str = "PANEL_MASTER_KEY_FILE is required: the database holds encrypted secrets";
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::KeyRequired => f.write_str(Self::KEY_REQUIRED),
            OpenError::Keyring(error) => write!(f, "{error}"),
            OpenError::Db(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl SecretStore {
    /// `SecretStore(keyring)` on the system clock.
    pub fn new(keyring: Option<Keyring>) -> Self {
        Self { keyring, clock: SystemClock::shared() }
    }

    /// The same with another clock (tests).
    pub fn with_clock(keyring: Option<Keyring>, clock: SharedClock) -> Self {
        Self { keyring, clock }
    }

    /// What `create_app` does (`app.py:122-129`): load the keyring when a file is configured;
    /// without one, refuse to start if `secret_versions` holds any row.
    pub fn open(database: &Database, master_key_file: Option<&Path>) -> Result<Self, OpenError> {
        let keyring = match master_key_file {
            Some(path) => Some(Keyring::load(path).map_err(OpenError::Keyring)?),
            None => None,
        };
        if keyring.is_none() {
            let count: i64 = database
                .with_connection(|db| {
                    db.query_row("SELECT count(*) FROM secret_versions", [], |row| row.get(0)).map_err(DbError::from)
                })
                .map_err(OpenError::Db)?;
            if count != 0 {
                return Err(OpenError::KeyRequired);
            }
        }
        Ok(Self::new(keyring))
    }

    /// True with a keyring.
    pub fn enabled(&self) -> bool {
        self.keyring.is_some()
    }

    /// The keyring, if any.
    pub fn keyring(&self) -> Option<&Keyring> {
        self.keyring.as_ref()
    }

    fn require(&self) -> Result<&Keyring, SecretError> {
        self.keyring.as_ref().ok_or(SecretError::Refused(SecretError::DISABLED))
    }

    /// `store(db, …)`: encrypt `plaintext` under the active key with a fresh nonce and insert the
    /// row in the caller's transaction. `state` must be one of [`STATES`] (Python's default is
    /// `pending`).
    pub fn store(
        &self,
        db: &Conn,
        identity: &Identity<'_>,
        plaintext: &[u8],
        state: &str,
    ) -> Result<SecretRef, SecretError> {
        self.store_with_nonce(db, identity, plaintext, state, &crate::random_bytes())
    }

    /// [`SecretStore::store`] with a given nonce — only for reproducing recorded rows in tests.
    /// A nonce must never be used twice under one key.
    #[doc(hidden)]
    pub fn store_with_nonce(
        &self,
        db: &Conn,
        identity: &Identity<'_>,
        plaintext: &[u8],
        state: &str,
        nonce: &[u8; 12],
    ) -> Result<SecretRef, SecretError> {
        if !STATES.contains(&state) {
            return Err(SecretError::Refused(SecretError::INVALID_STATE));
        }
        let key = self.require()?.active();
        let ciphertext = encrypt(key.material(), nonce, plaintext, &identity.aad());
        let now = self.clock.now();
        db.execute(
            "INSERT INTO secret_versions(secret_id,version,purpose,grant_id,permitted_node_id,key_id,
               nonce,ciphertext,state,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                identity.secret_id,
                identity.version,
                identity.purpose,
                identity.grant_id,
                identity.permitted_node_id,
                key.key_id,
                &nonce[..],
                ciphertext,
                state,
                now,
                now
            ],
        )?;
        Ok(SecretRef::new(identity.secret_id, identity.version))
    }

    /// `reveal(db, ref, purpose=…, grant_id=…, permitted_node_id=…)`: the plaintext, if the row
    /// exists, is not revoked, its key is in the ring and the caller's identity authenticates.
    pub fn reveal(
        &self,
        db: &Conn,
        secret: &SecretRef,
        purpose: &str,
        grant_id: Option<&str>,
        permitted_node_id: Option<&str>,
    ) -> Result<Vec<u8>, SecretError> {
        let keyring = self.require()?;
        let row = db
            .query_row(
                &format!("SELECT {} FROM secret_versions WHERE secret_id=? AND version=?", Row::COLUMNS),
                params![secret.secret_id, secret.version],
                Row::read,
            )
            .optional()?;
        let row = match row {
            Some(row) if row.state != "revoked" => row,
            _ => return Err(SecretError::Refused(SecretError::UNAVAILABLE)),
        };
        let key = keyring.get(&row.key_id).map_err(|_| SecretError::Refused(SecretError::UNKNOWN_KEY))?;
        let identity =
            Identity { secret_id: &secret.secret_id, version: secret.version, purpose, grant_id, permitted_node_id };
        decrypt(key.material(), &row.nonce, &row.ciphertext, &identity.aad())
            .ok_or(SecretError::Refused(SecretError::AUTHENTICATION))
    }

    /// `transition(db, ref, state)`: change only `state`/`updated_at` of exactly one row (no key
    /// needed).
    pub fn transition(&self, db: &Conn, secret: &SecretRef, state: &str) -> Result<(), SecretError> {
        if !STATES.contains(&state) {
            return Err(SecretError::Refused(SecretError::INVALID_STATE));
        }
        let changed = db.execute(
            "UPDATE secret_versions SET state=?,updated_at=? WHERE secret_id=? AND version=?",
            params![state, self.clock.now(), secret.secret_id, secret.version],
        )?;
        if changed != 1 {
            return Err(SecretError::Refused(SecretError::UNAVAILABLE));
        }
        Ok(())
    }

    /// `rewrap(db, batch_size=…)`: re-encrypt up to `batch_size` rows that are not under the
    /// active key (fresh nonce, the row's own identity); how many. Like SQLite's `LIMIT`, a
    /// negative `batch_size` means all rows.
    pub fn rewrap(&self, db: &Conn, batch_size: i64) -> Result<usize, SecretError> {
        let keyring = self.require()?;
        let active = keyring.active();
        let rows = {
            let mut statement =
                db.prepare(&format!("SELECT {} FROM secret_versions WHERE key_id<>? LIMIT ?", Row::COLUMNS))?;
            let rows = statement.query_map(params![active.key_id, batch_size], Row::read)?;
            rows.collect::<rusqlite::Result<Vec<Row>>>()?
        };
        for row in &rows {
            let aad = row.identity().aad();
            let plaintext = keyring
                .get(&row.key_id)
                .ok()
                .and_then(|key| decrypt(key.material(), &row.nonce, &row.ciphertext, &aad))
                .ok_or(SecretError::Refused(SecretError::REWRAP))?;
            let nonce: [u8; 12] = crate::random_bytes();
            db.execute(
                "UPDATE secret_versions SET key_id=?,nonce=?,ciphertext=?,updated_at=? WHERE secret_id=? AND version=?",
                params![
                    active.key_id,
                    &nonce[..],
                    encrypt(active.material(), &nonce, &plaintext, &aad),
                    self.clock.now(),
                    row.secret_id,
                    row.version
                ],
            )?;
        }
        Ok(rows.len())
    }

    /// `verify_all(db)`: decrypt every row (plaintext discarded) and count rows per key id; the
    /// first failure stops with an error.
    pub fn verify_all(&self, db: &Conn) -> Result<BTreeMap<String, u64>, SecretError> {
        let keyring = self.require()?;
        let mut statement = db.prepare(&format!("SELECT {} FROM secret_versions", Row::COLUMNS))?;
        let mut rows = statement.query([])?;
        let mut counts = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let row = Row::read(row)?;
            keyring
                .get(&row.key_id)
                .ok()
                .and_then(|key| decrypt(key.material(), &row.nonce, &row.ciphertext, &row.identity().aad()))
                .ok_or(SecretError::Refused(SecretError::VERIFY))?;
            *counts.entry(row.key_id).or_insert(0) += 1;
        }
        Ok(counts)
    }
}

/// What a completed rotation reports (`{"active_key_id": …, "rewrapped": {key_id: count}}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub active_key_id: String,
    pub rewrapped: BTreeMap<String, u64>,
}

/// Why a rotation or verification stopped.
#[derive(Debug)]
pub enum RotationError {
    Keyring(KeyringError),
    Secret(SecretError),
    /// Rows stayed under a retiring key after the rewrap loop; the file still holds both keys.
    LeftOver,
}

impl RotationError {
    pub const LEFT_OVER: &'static str = "rewrap left rows under a retiring key; the keyring was not narrowed";
}

impl fmt::Display for RotationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RotationError::Keyring(error) => write!(f, "{error}"),
            RotationError::Secret(error) => write!(f, "{error}"),
            RotationError::LeftOver => f.write_str(Self::LEFT_OVER),
        }
    }
}

impl std::error::Error for RotationError {}

impl From<KeyringError> for RotationError {
    fn from(error: KeyringError) -> Self {
        RotationError::Keyring(error)
    }
}

impl From<SecretError> for RotationError {
    fn from(error: SecretError) -> Self {
        RotationError::Secret(error)
    }
}

impl From<DbError> for RotationError {
    fn from(error: DbError) -> Self {
        RotationError::Secret(SecretError::Db(error))
    }
}

/// `master-key-rotate` (`cli.py:111-129`): a new active key saved overlap-first, rows rewrapped in
/// one `BEGIN IMMEDIATE` transaction per batch until none is left, every row verified, then the
/// file narrowed to the active key. `batch_size` must be positive (the CLI checks it).
pub fn rotate_master_key(database: &Database, path: &Path, batch_size: i64) -> Result<Rotation, RotationError> {
    rotate_master_key_to(database, path, batch_size, crate::keyring::Key::generate("active"))
}

/// [`rotate_master_key`] with a given new key (tests).
#[doc(hidden)]
pub fn rotate_master_key_to(
    database: &Database,
    path: &Path,
    batch_size: i64,
    new_key: crate::keyring::Key,
) -> Result<Rotation, RotationError> {
    let rotated = Keyring::load(path)?.rotate_to(new_key);
    rotated.save(path)?;
    let store = SecretStore::new(Some(rotated.clone()));
    while database.transaction(|db| store.rewrap(db, batch_size))? != 0 {}
    let counts = database.with_connection(|db| store.verify_all(db))?;
    if counts.keys().any(|key_id| key_id != rotated.active_key_id()) {
        return Err(RotationError::LeftOver);
    }
    rotated.retire_all_but_active().save(path)?;
    Ok(Rotation { active_key_id: rotated.active_key_id().to_string(), rewrapped: counts })
}

/// `master-key-verify` (`cli.py:130-132`): rows per key id, every row decrypted.
pub fn verify_master_key(database: &Database, path: &Path) -> Result<BTreeMap<String, u64>, RotationError> {
    let store = SecretStore::new(Some(Keyring::load(path)?));
    Ok(database.with_connection(|db| store.verify_all(db))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_is_python_canonical_json() {
        let identity = Identity {
            secret_id: "s1",
            version: 1,
            purpose: "grant.credential",
            grant_id: Some("g1"),
            permitted_node_id: None,
        };
        assert_eq!(
            String::from_utf8(identity.aad()).unwrap(),
            r#"{"grant_id":"g1","permitted_node_id":null,"purpose":"grant.credential","secret_id":"s1","version":1}"#
        );
        let unicode =
            Identity { secret_id: "ж🙂", version: -2, purpose: "p", grant_id: None, permitted_node_id: None };
        // Non-ASCII is escaped as lowercase \uXXXX with a surrogate pair above the BMP.
        let escaped = ["u0436", "ud83d", "ude42"].map(|unit| format!("{}{unit}", char::from(92))).concat();
        assert_eq!(
            String::from_utf8(unicode.aad()).unwrap(),
            format!(
                r#"{{"grant_id":null,"permitted_node_id":null,"purpose":"p","secret_id":"{escaped}","version":-2}}"#
            )
        );
    }

    #[test]
    fn ciphertext_is_ct_then_tag_and_short_or_odd_inputs_fail_closed() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let sealed = encrypt(&key, &nonce, b"abc", b"aad");
        assert_eq!(sealed.len(), 3 + 16);
        assert_eq!(decrypt(&key, &nonce, &sealed, b"aad").as_deref(), Some(&b"abc"[..]));
        assert_eq!(decrypt(&key, &nonce, &sealed, b"other"), None);
        assert_eq!(decrypt(&key, &nonce[..8], &sealed, b"aad"), None);
        assert_eq!(decrypt(&key, &nonce, &sealed[..15], b"aad"), None);
    }

    #[test]
    fn debug_shows_only_whether_enabled() {
        assert_eq!(format!("{:?}", SecretStore::new(None)), "SecretStore(enabled=False)");
        assert_eq!(format!("{:?}", SecretStore::new(Some(Keyring::generate()))), "SecretStore(enabled=True)");
    }
}
