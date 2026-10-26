//! `proxy-control-host-probe`: the stand-in host binary of the release pipeline.
//!
//! It exists to prove `release/Dockerfile.host-binaries` before the installer crate does: a
//! static musl binary built twice from the same commit has the same bytes. It links what the
//! real host binaries link (the shared crate, registry crates, ring's C and assembly), so a
//! reproducibility problem in any of them shows up here first.
//!
//! - no arguments: one JSON line naming the binary, the release version and the libc;
//! - `sha256 FILE [EXPECTED]`: the file's SHA-256 (ring), and with `EXPECTED` exit 1 unless
//!   it matches (compared in constant time by `pc_common`).

use std::process::ExitCode;

const BINARY: &str = "proxy-control-host-probe";
/// The release version, compiled in from the tree: no timestamp and no `git describe`.
const VERSION: &str = include_str!("../../../VERSION");

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (code, output) = run(&arguments);
    match code {
        0 => println!("{output}"),
        _ => eprintln!("{output}"),
    }
    ExitCode::from(code)
}

fn run(arguments: &[String]) -> (u8, String) {
    match arguments {
        [] => (0, identity()),
        [command, path] if command == "sha256" => digest_of(path, None),
        [command, path, expected] if command == "sha256" => digest_of(path, Some(expected)),
        _ => (2, format!("usage: {BINARY} [sha256 FILE [EXPECTED]]")),
    }
}

fn identity() -> String {
    serde_json::json!({
        "binary": BINARY,
        "libc": if cfg!(target_env = "musl") { "musl" } else { "gnu" },
        "static": cfg!(target_feature = "crt-static"),
        "version": VERSION.trim(),
    })
    .to_string()
}

fn digest_of(path: &str, expected: Option<&String>) -> (u8, String) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => return (1, format!("{BINARY}: cannot read {path}: {error}")),
    };
    let actual = sha256_hex(&bytes);
    match expected {
        Some(expected) if !pc_common::constant_time_eq(actual.as_bytes(), expected.to_ascii_lowercase().as_bytes()) => {
            (1, format!("{BINARY}: {path} has sha256 {actual}, expected {expected}"))
        }
        _ => (0, format!("{actual}  {path}")),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes).as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn identity_names_the_binary_and_the_release_version() {
        let document: serde_json::Value = serde_json::from_str(&identity()).unwrap();
        assert_eq!(document["binary"], BINARY);
        assert_eq!(document["version"], VERSION.trim());
        assert!(!VERSION.trim().is_empty());
        assert_eq!(run(&[]), (0, identity()));
    }

    #[test]
    fn sha256_matches_the_known_vector() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn sha256_of_a_file_and_the_expected_check() {
        let path = std::env::temp_dir().join(format!("host-probe-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        let name = path.to_str().unwrap();
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(run(&arguments(&["sha256", name])), (0, format!("{digest}  {name}")));
        assert_eq!(run(&arguments(&["sha256", name, &digest.to_ascii_uppercase()])).0, 0);
        let (code, message) = run(&arguments(&["sha256", name, &"0".repeat(64)]));
        assert_eq!(code, 1);
        assert!(message.contains(digest), "{message}");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(run(&arguments(&["sha256", name])).0, 1);
    }

    #[test]
    fn anything_else_is_a_usage_error() {
        assert_eq!(run(&arguments(&["version"])).0, 2);
        assert_eq!(run(&arguments(&["sha256"])).0, 2);
    }
}
