//! The versioned master keyring file (`panel/keyring.py`, ADR 005).
//!
//! The file never lives beside the database it protects. It is written 0600, refuses to load if
//! group or others have any permission bit, and carries every key needed to decrypt existing rows:
//! rotation is overlap-first, so a crash in the middle of a rewrap leaves nothing unreadable.
//!
//! Format (schema 1), written as Python's `json.dumps(obj, indent=2) + "\n"` — insertion order,
//! ASCII escaping — which is also what the installer renders:
//!
//! ```json
//! {
//!   "schema": 1,
//!   "active_key_id": "k-0a1b2c3d",
//!   "keys": [
//!     {
//!       "key_id": "k-0a1b2c3d",
//!       "state": "active",
//!       "created_at": 1761350400,
//!       "key_material": "<standard base64 of 32 bytes, padded>"
//!     }
//!   ]
//! }
//! ```
//!
//! The 32 raw bytes are the AES-256 key; there is no key derivation.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use panel_core::pyjson;
use panel_core::serde_json::{self, json, Value};

use crate::pyvalue::{py_eq_int, py_int, py_str};

/// The keyring file format version.
pub const SCHEMA: i64 = 1;
/// States a key may have in the file.
pub const STATES: [&str; 2] = ["active", "retiring"];

/// `base64.b64decode(text, validate=True)` (Python 3.13 = `binascii.a2b_base64(strict_mode=True)`):
/// standard alphabet only, padding exactly as long as needed and only at the end, but non-zero
/// bits in the last character are ignored.
const STRICT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Why a keyring could not be loaded or used. The messages are Python's, word for word.
#[derive(Debug)]
pub enum KeyringError {
    /// A refusal with one of the fixed messages (`KeyringError` in Python).
    Invalid(&'static str),
    /// The file system failed in another way (Python lets the `OSError` through).
    Io { path: PathBuf, error: io::Error },
}

impl KeyringError {
    pub const DOES_NOT_EXIST: &'static str = "master key file does not exist";
    pub const BAD_MODE: &'static str = "master key file must be a regular file with mode 0600 or 0400";
    pub const UNSUPPORTED_SCHEMA: &'static str = "unsupported keyring schema";
    pub const MALFORMED: &'static str = "master key file is malformed";
    pub const INVALID_KEY: &'static str = "master key file contains an invalid key";
    pub const DUPLICATE_KEY_ID: &'static str = "duplicate key id";
    pub const UNKNOWN_KEY_ID: &'static str = "unknown key id";
    pub const ACTIVE_NOT_ACTIVE: &'static str = "active key is not in state active";

    /// The fixed message of a refusal (`None` for an I/O failure).
    pub fn message(&self) -> Option<&'static str> {
        match self {
            KeyringError::Invalid(message) => Some(message),
            KeyringError::Io { .. } => None,
        }
    }
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyringError::Invalid(message) => f.write_str(message),
            KeyringError::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for KeyringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeyringError::Io { error, .. } => Some(error),
            KeyringError::Invalid(_) => None,
        }
    }
}

fn io(path: &Path) -> impl FnOnce(io::Error) -> KeyringError + '_ {
    move |error| KeyringError::Io { path: path.to_path_buf(), error }
}

/// One key of the ring. `Debug` never shows the material.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    pub key_id: String,
    pub state: String,
    pub created_at: i64,
    material: [u8; 32],
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key(key_id={:?}, state={:?})", self.key_id, self.state)
    }
}

impl Key {
    /// A key from its parts.
    pub fn new(key_id: impl Into<String>, state: impl Into<String>, created_at: i64, material: [u8; 32]) -> Self {
        Self { key_id: key_id.into(), state: state.into(), created_at, material }
    }

    /// `new_key(state)`: id `k-` + 8 random lowercase hex digits, the current time, 32 random bytes.
    pub fn generate(state: &str) -> Self {
        Self::new(format!("k-{}", panel_core::ids::token_hex(4)), state, crate::now(), crate::random_bytes())
    }

    /// The raw AES-256 key.
    pub fn material(&self) -> &[u8; 32] {
        &self.material
    }
}

/// The keys and which one encrypts new rows. Every keyring that exists has its active key among
/// its keys. `Debug` never shows key material.
#[derive(Clone, PartialEq, Eq)]
pub struct Keyring {
    keys: Vec<Key>,
    active_key_id: String,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyring(active={:?}, keys={})", self.active_key_id, self.keys.len())
    }
}

impl Keyring {
    /// A keyring of `keys` whose active key is `active_key_id`; refused with `unknown key id` when
    /// no key has that id.
    pub fn new(keys: Vec<Key>, active_key_id: impl Into<String>) -> Result<Self, KeyringError> {
        let active_key_id = active_key_id.into();
        if !keys.iter().any(|key| key.key_id == active_key_id) {
            return Err(KeyringError::Invalid(KeyringError::UNKNOWN_KEY_ID));
        }
        Ok(Self { keys, active_key_id })
    }

    /// `Keyring.generate()`: one new active key.
    pub fn generate() -> Self {
        let key = Key::generate("active");
        let active_key_id = key.key_id.clone();
        Self { keys: vec![key], active_key_id }
    }

    /// The keys in file order.
    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    /// The id of the key that encrypts new rows.
    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    /// The key that encrypts new rows.
    pub fn active(&self) -> &Key {
        self.get(&self.active_key_id).expect("a keyring always holds its active key")
    }

    /// The key with this id, or `unknown key id`.
    pub fn get(&self, key_id: &str) -> Result<&Key, KeyringError> {
        self.keys.iter().find(|key| key.key_id == key_id).ok_or(KeyringError::Invalid(KeyringError::UNKNOWN_KEY_ID))
    }

    /// The set of key ids.
    pub fn key_ids(&self) -> std::collections::BTreeSet<&str> {
        self.keys.iter().map(|key| key.key_id.as_str()).collect()
    }

    /// Overlap-first rotation: a new active key first, every previous key kept as `retiring`.
    pub fn rotate(&self) -> Self {
        self.rotate_to(Key::generate("active"))
    }

    /// [`Keyring::rotate`] with a given new key (tests, the installer).
    pub fn rotate_to(&self, key: Key) -> Self {
        let active_key_id = key.key_id.clone();
        let mut keys = vec![key];
        keys.extend(self.keys.iter().map(|old| Key { state: "retiring".into(), ..old.clone() }));
        Self { keys, active_key_id }
    }

    /// The active key only (after every row was rewrapped to it).
    pub fn retire_all_but_active(&self) -> Self {
        Self { keys: vec![self.active().clone()], active_key_id: self.active_key_id.clone() }
    }

    /// The file text: `json.dumps(…, indent=2) + "\n"`.
    pub fn to_json(&self) -> String {
        let keys: Vec<Value> = self
            .keys
            .iter()
            .map(|key| {
                json!({
                    "key_id": key.key_id,
                    "state": key.state,
                    "created_at": key.created_at,
                    "key_material": STANDARD.encode(key.material),
                })
            })
            .collect();
        let document = json!({"schema": SCHEMA, "active_key_id": self.active_key_id, "keys": keys});
        let options = pyjson::Options { indent: Some(2), ..pyjson::Options::default() };
        let mut text = pyjson::dumps(&document, &options);
        text.push('\n');
        text
    }

    /// `Keyring.save(path)`: `<name>.tmp` opened `O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW` with mode
    /// 0600, written and fsynced, renamed over `path`, then `chmod 0600` (no directory fsync).
    pub fn save(&self, path: &Path) -> Result<(), KeyringError> {
        let mut name = path.file_name().map(|name| name.to_os_string()).unwrap_or_default();
        name.push(".tmp");
        let temporary = path.with_file_name(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(io(&temporary))?;
        file.write_all(self.to_json().as_bytes()).map_err(io(&temporary))?;
        file.flush().map_err(io(&temporary))?;
        file.sync_all().map_err(io(&temporary))?;
        drop(file);
        fs::rename(&temporary, path).map_err(io(path))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io(path))?;
        Ok(())
    }

    /// `Keyring.load(path)` with Python's checks, in Python's order, and its messages.
    pub fn load(path: &Path) -> Result<Self, KeyringError> {
        let info = match fs::symlink_metadata(path) {
            Ok(info) => info,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(KeyringError::Invalid(KeyringError::DOES_NOT_EXIST));
            }
            Err(error) => return Err(KeyringError::Io { path: path.to_path_buf(), error }),
        };
        if !info.file_type().is_file() || info.mode() & 0o077 != 0 {
            return Err(KeyringError::Invalid(KeyringError::BAD_MODE));
        }
        let bytes = fs::read(path).map_err(|error| KeyringError::Io { path: path.to_path_buf(), error })?;
        Self::parse(&bytes)
    }

    /// The JSON part of [`Keyring::load`]: parse, coerce like Python, then validate.
    pub fn parse(bytes: &[u8]) -> Result<Self, KeyringError> {
        let malformed = || KeyringError::Invalid(KeyringError::MALFORMED);
        let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
        let data: Value = serde_json::from_str(text).map_err(|_| malformed())?;
        let data = data.as_object().ok_or_else(malformed)?;
        if !py_eq_int(data.get("schema").ok_or_else(malformed)?, SCHEMA) {
            return Err(KeyringError::Invalid(KeyringError::UNSUPPORTED_SCHEMA));
        }
        // `for item in data["keys"]`: a list yields its items; an empty dict or string yields
        // nothing; anything else fails to index or to iterate.
        let items: &[Value] = match data.get("keys").ok_or_else(malformed)? {
            Value::Array(items) => items,
            Value::Object(map) if map.is_empty() => &[],
            Value::String(text) if text.is_empty() => &[],
            _ => return Err(malformed()),
        };
        let mut parsed = Vec::with_capacity(items.len());
        for item in items {
            let item = item.as_object().ok_or_else(malformed)?;
            let field = |name: &str| item.get(name).ok_or_else(malformed);
            let key_id = py_str(field("key_id")?).ok_or_else(malformed)?;
            let state = py_str(field("state")?).ok_or_else(malformed)?;
            let created_at = py_int(field("created_at")?).ok_or_else(malformed)?;
            let material = match field("key_material")? {
                Value::String(text) => STRICT_BASE64.decode(text).map_err(|_| malformed())?,
                _ => return Err(malformed()),
            };
            parsed.push((key_id, state, created_at, material));
        }
        let active_key_id = py_str(data.get("active_key_id").ok_or_else(malformed)?).ok_or_else(malformed)?;
        if parsed.is_empty()
            || parsed.iter().any(|(_, state, _, material)| material.len() != 32 || !STATES.contains(&state.as_str()))
        {
            return Err(KeyringError::Invalid(KeyringError::INVALID_KEY));
        }
        let keys: Vec<Key> = parsed
            .into_iter()
            .map(|(key_id, state, created_at, material)| {
                Key::new(key_id, state, created_at, material.try_into().expect("checked to be 32 bytes"))
            })
            .collect();
        let ids: std::collections::BTreeSet<&str> = keys.iter().map(|key| key.key_id.as_str()).collect();
        if ids.len() != keys.len() {
            return Err(KeyringError::Invalid(KeyringError::DUPLICATE_KEY_ID));
        }
        let keyring = Keyring::new(keys, active_key_id)?;
        if keyring.active().state != "active" {
            return Err(KeyringError::Invalid(KeyringError::ACTIVE_NOT_ACTIVE));
        }
        Ok(keyring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keyring_has_one_active_key_with_python_id_shape() {
        let keyring = Keyring::generate();
        assert_eq!(keyring.keys().len(), 1);
        let key = keyring.active();
        assert_eq!(key.state, "active");
        assert_eq!(key.key_id.len(), 10);
        assert!(key.key_id.starts_with("k-"));
        assert!(key.key_id[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_ne!(Keyring::generate().active().material(), key.material());
    }

    #[test]
    fn rotation_is_overlap_first() {
        let first = Keyring::generate();
        let rotated = first.rotate();
        assert_eq!(rotated.keys().len(), 2);
        assert_eq!(rotated.keys()[0].key_id, rotated.active_key_id());
        assert_eq!(rotated.keys()[0].state, "active");
        assert_eq!(rotated.keys()[1].state, "retiring");
        assert_eq!(rotated.keys()[1].material(), first.active().material());
        let narrowed = rotated.retire_all_but_active();
        assert_eq!(narrowed.keys(), &rotated.keys()[..1]);
    }

    #[test]
    fn debug_never_shows_material() {
        let keyring = Keyring::new(vec![Key::new("k-1", "active", 0, [0x41; 32])], "k-1").unwrap();
        let shown = format!("{keyring:?} {:?}", keyring.active());
        assert_eq!(shown, "Keyring(active=\"k-1\", keys=1) Key(key_id=\"k-1\", state=\"active\")");
    }

    #[test]
    fn new_refuses_an_absent_active_key() {
        let error = Keyring::new(vec![Key::new("k-1", "active", 0, [0; 32])], "k-2").unwrap_err();
        assert_eq!(error.to_string(), "unknown key id");
    }
}
