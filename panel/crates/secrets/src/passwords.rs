//! Administrator passwords: argon2id PHC strings with argon2-cffi's policy (`store.py:32`).
//!
//! `PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)` with argon2-cffi 25.1.0's other
//! defaults: argon2id, version 0x13, 16-byte random salt, 32-byte hash, the password as UTF-8. The
//! PHC string is libargon2's encoding, `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>` in standard
//! base64 without padding — what the `argon2` crate writes too, so hashes move both ways between
//! the Python and the Rust panel.
//!
//! Hashing costs 64 MiB and a few hundred milliseconds: run it in `spawn_blocking` behind the
//! login semaphore.

use std::fmt;

use argon2::password_hash::{self, PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

/// A valid hash of a password nobody knows, verified for unknown users so that a login for a
/// missing account costs the same as one for an existing account (`store.py:18-20`).
pub const DUMMY_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=2$WgRGk2j919KU4cq8Aoq1eQ$Yu6TDt/n0xMCzUMjf0cpxeC/CkNXj2ilMtTlv2L+2wU";

/// A stored string that is not a usable argon2 PHC hash (argon2-cffi raises `InvalidHashError` or
/// `VerificationError`; the panel does not catch either).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidHash;

impl fmt::Display for InvalidHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid argon2 password hash")
    }
}

impl std::error::Error for InvalidHash {}

/// The hashing policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHasher {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    hash_len: usize,
    salt_len: usize,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::panel()
    }
}

impl PasswordHasher {
    /// The panel's policy: argon2id, m=65536 KiB, t=3, p=2, 32-byte hash, 16-byte salt.
    pub const fn panel() -> Self {
        Self { memory_cost: 65536, time_cost: 3, parallelism: 2, hash_len: 32, salt_len: 16 }
    }

    /// Another policy (tests use a cheap one where the parameters do not matter).
    pub const fn with_parameters(
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        hash_len: usize,
        salt_len: usize,
    ) -> Self {
        Self { memory_cost, time_cost, parallelism, hash_len, salt_len }
    }

    fn argon2(&self) -> Argon2<'static> {
        let params = Params::new(self.memory_cost, self.time_cost, self.parallelism, Some(self.hash_len))
            .expect("the hashing policy has valid argon2 parameters");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    /// `PasswordHasher.hash(password)` with a fresh random salt.
    pub fn hash(&self, password: &str) -> String {
        let mut salt = vec![0u8; self.salt_len];
        getrandom::fill(&mut salt).expect("the operating system's random source is available");
        self.hash_with_salt(password, &salt).expect("the policy's salt length is valid")
    }

    /// The PHC string for a given salt (`argon2.low_level.hash_secret` with the policy).
    pub fn hash_with_salt(&self, password: &str, salt: &[u8]) -> Result<String, password_hash::Error> {
        let salt = SaltString::encode_b64(salt)?;
        Ok(self.argon2().hash_password(password.as_bytes(), &salt)?.to_string())
    }

    /// `PasswordHasher.verify(hash, password)`: `Ok(true)` on a match, `Ok(false)` on a mismatch
    /// (`VerifyMismatchError`), `Err` when `phc` is not a complete argon2 hash. The hash's own
    /// variant, version and parameters are used, whatever the policy.
    pub fn verify(&self, phc: &str, password: &str) -> Result<bool, InvalidHash> {
        let hash = PasswordHash::new(phc).map_err(|_| InvalidHash)?;
        if hash.salt.is_none() || hash.hash.is_none() || Algorithm::try_from(hash.algorithm).is_err() {
            return Err(InvalidHash);
        }
        match Argon2::default().verify_password(password.as_bytes(), &hash) {
            Ok(()) => Ok(true),
            Err(password_hash::Error::Password) => Ok(false),
            Err(_) => Err(InvalidHash),
        }
    }

    /// `PasswordHasher.check_needs_rehash(hash)`: true when the variant, version, memory, time,
    /// parallelism, hash length or salt length differ from the policy.
    pub fn needs_rehash(&self, phc: &str) -> Result<bool, InvalidHash> {
        let hash = PasswordHash::new(phc).map_err(|_| InvalidHash)?;
        let decimal = |name: &str| hash.params.get_decimal(name);
        // argon2-cffi derives lengths from the base64 text: 4 chars = 3 bytes, 3 = 2, 2 = 1.
        let decoded_len = |chars: usize| chars / 4 * 3 + [0, 0, 1, 2][chars % 4];
        let salt_len = hash.salt.map(|salt| decoded_len(salt.as_str().len()));
        let hash_len = hash.hash.map(|output| output.len());
        Ok(!(hash.algorithm.as_str() == "argon2id"
            && hash.version == Some(0x13)
            && decimal("m") == Some(self.memory_cost)
            && decimal("t") == Some(self.time_cost)
            && decimal("p") == Some(self.parallelism)
            && hash_len == Some(self.hash_len)
            && salt_len == Some(self.salt_len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: PasswordHasher = PasswordHasher::with_parameters(64, 1, 1, 32, 16);

    #[test]
    fn cheap_hashes_round_trip_and_need_rehash_under_the_panel_policy() {
        let phc = CHEAP.hash("correct horse battery staple");
        assert!(phc.starts_with("$argon2id$v=19$m=64,t=1,p=1$"));
        assert_eq!(CHEAP.verify(&phc, "correct horse battery staple"), Ok(true));
        assert_eq!(CHEAP.verify(&phc, "wrong"), Ok(false));
        assert_eq!(CHEAP.needs_rehash(&phc), Ok(false));
        assert_eq!(PasswordHasher::panel().needs_rehash(&phc), Ok(true));
        assert_ne!(CHEAP.hash("x"), CHEAP.hash("x"));
    }

    #[test]
    fn dummy_hash_has_the_policy_parameters() {
        let policy = PasswordHasher::panel();
        assert_eq!(policy.needs_rehash(DUMMY_PASSWORD_HASH), Ok(false));
    }

    #[test]
    fn incomplete_or_foreign_hashes_are_invalid() {
        for phc in ["", "nonsense", "$argon2id$v=19$m=65536,t=3,p=2$abc", "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ"] {
            assert_eq!(CHEAP.verify(phc, "x"), Err(InvalidHash), "{phc}");
        }
    }
}
