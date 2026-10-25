//! Identifiers and tokens in the formats Python's `uuid` and `secrets` modules produce.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

fn random_bytes(count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    getrandom::fill(&mut bytes).expect("the operating system's random source is available");
    bytes
}

/// `str(uuid.uuid4())`: 36 lower-case characters with hyphens.
pub fn uuid4() -> String {
    let mut bytes = random_bytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex(&bytes);
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// `secrets.token_urlsafe(nbytes)`: base64url of `nbytes` random bytes, padding stripped
/// (`token_urlsafe(32)` is 43 characters).
pub fn token_urlsafe(nbytes: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(nbytes))
}

/// `secrets.token_hex(nbytes)`: `2 * nbytes` lower-case hex digits.
pub fn token_hex(nbytes: usize) -> String {
    hex(&random_bytes(nbytes))
}

/// Lower-case hex of `bytes` (`bytes.hex()`, `hashlib…hexdigest()`).
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `hashlib.sha256(text.encode()).hexdigest()`.
pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    use sha2::Digest as _;
    hex(&sha2::Sha256::digest(data.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid4_has_python_shape() {
        let id = uuid4();
        assert_eq!(id.len(), 36);
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
        assert!(parts[2].starts_with('4'));
        assert!(matches!(&parts[3][..1], "8" | "9" | "a" | "b"));
        assert_eq!(id, id.to_lowercase());
        assert_ne!(uuid4(), uuid4());
    }

    #[test]
    fn tokens_have_python_lengths() {
        assert_eq!(token_urlsafe(32).len(), 43);
        assert_eq!(token_urlsafe(18).len(), 24);
        assert!(token_urlsafe(32).bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_eq!(token_hex(4).len(), 8);
        assert_eq!(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
