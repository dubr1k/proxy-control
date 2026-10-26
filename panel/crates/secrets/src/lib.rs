//! Secrets and identity of the Proxy Control panel's Rust port (work package WP3).
//!
//! Everything here reproduces the Python panel (`panel/*.py`) byte for byte where bytes are stored
//! or exchanged:
//!
//! - [`keyring`] — the master keyring file (`keyring.py`): load rules and messages, the file
//!   written exactly as Python's `json.dumps(…, indent=2) + "\n"`, overlap-first rotation;
//! - [`secrets_store`] — AES-256-GCM secret versions bound to their identity through a canonical
//!   JSON AAD (`secrets_store.py`), plus the master-key rotation and verification procedures of
//!   the CLI;
//! - [`passwords`] — argon2id PHC strings with argon2-cffi's policy (m=65536, t=3, p=2, 16-byte
//!   salt, 32-byte hash) and its rehash rule;
//! - [`store`] — administrators, sessions, CSRF checks, the login limiter and the audit listing
//!   (`store.py`);
//! - [`api_keys`] — scoped Bearer keys (`api_keys.py`);
//! - [`audit`] — scrubbed audit rows written inside the caller's transaction (`audit.py`);
//! - [`events`] — subscription and node events (`events.py`);
//! - [`identity`] — the panel GUID, settings rows and the reported version (`fleet_v2/identity.py`);
//! - [`stage_secret`] — the root-side validation and staging of the Mieru token
//!   (`stage_secret.py`), for the future `panel stage-secret verify|stage` subcommand.
//!
//! Store APIs are synchronous over [`panel_core::db`]: call them from `spawn_blocking`.

pub mod api_keys;
pub mod audit;
pub mod casefold;
pub mod events;
pub mod identity;
pub mod keyring;
pub mod passwords;
pub mod secrets_store;
pub mod stage_secret;
pub mod store;

mod pyvalue;

/// `secrets.compare_digest` for two strings: constant time in the length of the inputs.
pub fn compare_digest(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// `hashlib.sha256(value.encode()).hexdigest()` — every token is hashed as its text.
pub fn hash_token(value: &str) -> String {
    panel_core::ids::sha256_hex(value.as_bytes())
}

/// The current time as Python's `int(time.time())`.
pub(crate) fn now() -> i64 {
    use panel_core::clock::Clock as _;
    panel_core::clock::SystemClock.now()
}

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system's random source is available");
    bytes
}
