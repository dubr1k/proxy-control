//! X25519 (RFC 7748) and the WireGuard key helpers: strict 32-byte base64 keys and their UAPI hex.
//!
//! `awg-manager keys genkey|genpsk|pubkey` is the tiny CLI the Python module offered as
//! `python -m awg_manager.keys` (`pubkey` reads the private key from stdin).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// RFC 7748 section 5 scalar multiplication: clamps the scalar and ignores the top bit of `u`.
pub fn x25519(scalar: [u8; 32], u: [u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(scalar, u)
}

pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES)
}

pub fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the system random source is available");
    bytes
}

/// A clamped random private key, as `wg genkey` prints it.
pub fn generate_private() -> [u8; 32] {
    let mut bytes = random_bytes();
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    bytes
}

pub fn b64(raw: &[u8]) -> String {
    STANDARD.encode(raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(pub &'static str);

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for KeyError {}

/// A strict 32-byte base64 key: exactly 44 characters that are the canonical encoding.
pub fn unb64(text: &str) -> Result<[u8; 32], KeyError> {
    if text.chars().count() != 44 {
        return Err(KeyError("key must be 44 base64 characters"));
    }
    let raw = STANDARD.decode(text).map_err(|_| KeyError("key is not valid base64"))?;
    let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| KeyError("key must decode to 32 bytes"))?;
    if b64(&key) != text {
        return Err(KeyError("key must decode to 32 bytes"));
    }
    Ok(key)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The UAPI form of a base64 key.
pub fn hexkey(text: &str) -> Result<String, KeyError> {
    Ok(hex(&unb64(text)?))
}

/// `awg-manager keys …`; returns the exit code.
pub fn cli(args: &[String]) -> i32 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["genkey"] => println!("{}", b64(&generate_private())),
        ["genpsk"] => println!("{}", b64(&random_bytes())),
        ["pubkey"] => {
            let mut input = String::new();
            let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input);
            match unb64(input.trim()) {
                Ok(private) => println!("{}", b64(&public_key(&private))),
                Err(err) => {
                    eprintln!("{err}");
                    return 1;
                }
            }
        }
        _ => {
            eprintln!("usage: awg-manager keys genkey|genpsk|pubkey");
            return 2;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(text: &str) -> [u8; 32] {
        let raw: Vec<u8> =
            (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect();
        raw.try_into().unwrap()
    }

    #[test]
    fn x25519_rfc7748_section_5_2_vectors() {
        for (scalar, u, expected) in [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ] {
            assert_eq!(hex(&x25519(bytes(scalar), bytes(u))), expected);
        }
    }

    #[test]
    fn x25519_rfc7748_one_iteration_and_diffie_hellman() {
        let mut nine = [0u8; 32];
        nine[0] = 9;
        assert_eq!(hex(&x25519(nine, nine)), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        let alice = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assert_eq!(hex(&public_key(&alice)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(hex(&public_key(&bob)), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(hex(&x25519(alice, public_key(&bob))), shared);
        assert_eq!(hex(&x25519(bob, public_key(&alice))), shared);
    }

    #[test]
    fn generated_private_key_is_clamped_and_base64_is_strict() {
        let private = generate_private();
        assert!(private[0] & 7 == 0 && private[31] & 0x80 == 0 && private[31] & 0x40 != 0);
        assert_eq!(unb64(&b64(&private)).unwrap(), private);
        // A non-canonical encoding of the same bytes ("…=" with stray low bits) is refused too.
        let stray = format!("{}B=", &b64(&[0u8; 32])[..42]);
        for bad in ["", "abc", &"A".repeat(44), &(b64(&[1u8; 31]) + "="), &stray] {
            assert!(unb64(bad).is_err(), "{bad}");
        }
        assert_eq!(hexkey(&b64(&(0..32).collect::<Vec<u8>>())).unwrap(), hex(&(0..32).collect::<Vec<u8>>()));
    }
}
