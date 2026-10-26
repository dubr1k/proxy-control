//! argon2 PHC strings in both directions (`fixtures/argon2.json`): Rust verifies what argon2-cffi
//! made, makes byte-identical strings for the same salt, and Python verified what Rust made.

mod common;

use common::{fixture_json, unhex};
use panel_secrets::passwords::{InvalidHash, PasswordHasher, DUMMY_PASSWORD_HASH};

fn verdict(phc: &str, password: &str) -> &'static str {
    match PasswordHasher::panel().verify(phc, password) {
        Ok(true) => "ok",
        Ok(false) => "mismatch",
        Err(InvalidHash) => "invalid",
    }
}

#[test]
fn python_made_hashes_verify_and_need_no_rehash() {
    let fixture = fixture_json("argon2.json");
    let policy = PasswordHasher::panel();
    for item in fixture["random_salt"].as_array().unwrap() {
        let (password, phc) = (item["password"].as_str().unwrap(), item["phc"].as_str().unwrap());
        assert_eq!(verdict(phc, password), item["verify"].as_str().unwrap(), "{phc}");
        assert_eq!(verdict(phc, &format!("{password}!")), item["verify_wrong"].as_str().unwrap(), "{phc}");
        assert_eq!(policy.needs_rehash(phc).unwrap(), item["needs_rehash"].as_bool().unwrap(), "{phc}");
    }
}

#[test]
fn hashes_for_a_given_salt_are_byte_identical_to_python() {
    let fixture = fixture_json("argon2.json");
    for item in fixture["fixed_salt"].as_array().unwrap() {
        let salt = unhex(item["salt_hex"].as_str().unwrap());
        let ours = PasswordHasher::panel().hash_with_salt(item["password"].as_str().unwrap(), &salt).unwrap();
        assert_eq!(ours, item["phc"].as_str().unwrap());
    }
}

#[test]
fn other_parameters_verify_with_their_own_parameters_and_need_rehash() {
    let fixture = fixture_json("argon2.json");
    let policy = PasswordHasher::panel();
    for item in fixture["other_parameters"].as_array().unwrap() {
        let (label, phc) = (item["label"].as_str().unwrap(), item["phc"].as_str().unwrap());
        let python = item["verify"].as_str().unwrap();
        let ours = verdict(phc, item["password"].as_str().unwrap());
        // Verification uses the hash's own variant, version and parameters (incl. an 8-byte salt).
        assert_eq!(ours, python, "{label}");
        assert_eq!(policy.needs_rehash(phc).unwrap(), item["needs_rehash"].as_bool().unwrap(), "{label}");
    }
}

#[test]
fn invalid_strings_are_refused_like_python() {
    let fixture = fixture_json("argon2.json");
    for item in fixture["invalid"].as_array().unwrap() {
        let phc = item["phc"].as_str().unwrap();
        // Python tells InvalidHashError ("invalid") from VerificationError ("error"); the panel
        // catches neither, so both are one error here.
        assert!(matches!(item["verify"].as_str().unwrap(), "invalid" | "error"));
        assert_eq!(verdict(phc, "whatever-password"), "invalid", "{phc:?}");
    }
}

#[test]
fn dummy_hash_is_valid_policy_matched_and_rejects_everything() {
    let fixture = fixture_json("argon2.json");
    assert_eq!(fixture["dummy_hash"].as_str().unwrap(), DUMMY_PASSWORD_HASH);
    assert_eq!(fixture["dummy_verify_any"].as_str().unwrap(), "mismatch");
    assert_eq!(verdict(DUMMY_PASSWORD_HASH, "not-the-real-password"), "mismatch");
    assert_eq!(PasswordHasher::panel().needs_rehash(DUMMY_PASSWORD_HASH), Ok(false));
}

#[test]
fn rust_made_hashes_were_verified_by_python() {
    let fixture = fixture_json("argon2.json");
    let made = fixture["rust_made"].as_array().expect("argon2.json records the Rust-made hashes Python verified");
    assert!(made.len() >= 3);
    for item in made {
        let (password, phc) = (item["password"].as_str().unwrap(), item["phc"].as_str().unwrap());
        assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=2$"));
        assert_eq!(item["python_verify"], "ok", "{phc}");
        assert_eq!(item["python_verify_wrong"], "mismatch", "{phc}");
        assert_eq!(item["python_needs_rehash"], false, "{phc}");
        assert_eq!(verdict(phc, password), "ok");
    }
}

/// Writes fresh Rust-made hashes for the generator to verify with argon2-cffi:
/// `RUST_MADE_OUT=/path cargo test -p panel-secrets --test passwords -- --ignored`.
#[test]
#[ignore]
fn print_rust_made_hashes() {
    let out = std::env::var("RUST_MADE_OUT").expect("RUST_MADE_OUT names the output file");
    let policy = PasswordHasher::panel();
    let items: Vec<panel_core::serde_json::Value> =
        ["correct horse battery staple", "пароль-с-кириллицей-🙂", "exactly12chr"]
            .iter()
            .map(|password| panel_core::serde_json::json!({"password": password, "phc": policy.hash(password)}))
            .collect();
    std::fs::write(out, panel_core::serde_json::to_string_pretty(&items).unwrap()).unwrap();
}
