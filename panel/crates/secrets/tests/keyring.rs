//! The keyring against files Python wrote and Python's verdicts on files it loaded
//! (`fixtures/keyring/*.json`, `fixtures/keyring-cases.json`, made by
//! `fixtures/generators/gen_secrets.py`).

mod common;

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use base64::Engine as _;
use common::{fixture_json, fixture_path, private_copy, unhex, TempDir};
use panel_secrets::keyring::{Key, Keyring, KeyringError};

fn material(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start + i as u8)
}

#[test]
fn keyring_files_are_written_byte_identical_to_python() {
    let expected = [
        ("one-key.json", Keyring::new(vec![Key::new("k-0a1b2c3d", "active", 1761350400, material(0))], "k-0a1b2c3d")),
        (
            "rotated.json",
            Keyring::new(
                vec![
                    Key::new("k-11223344", "active", 1761436800, material(32)),
                    Key::new("k-0a1b2c3d", "retiring", 1761350400, material(0)),
                    Key::new("k-99aabbcc", "retiring", 1700000000, material(64)),
                ],
                "k-11223344",
            ),
        ),
        ("non-ascii-id.json", Keyring::new(vec![Key::new("k-ключ-🙂", "active", 0, material(0))], "k-ключ-🙂")),
    ];
    let dir = TempDir::new("keyring-files");
    for (name, keyring) in expected {
        let keyring = keyring.unwrap();
        let python = std::fs::read(fixture_path(&format!("keyring/{name}"))).unwrap();
        assert_eq!(keyring.to_json().as_bytes(), &python[..], "{name}");
        let loaded = Keyring::load(&private_copy(&format!("keyring/{name}"), &dir, name)).unwrap();
        assert_eq!(loaded, keyring, "{name}");
        let saved = dir.join(&format!("saved-{name}"));
        loaded.save(&saved).unwrap();
        assert_eq!(std::fs::read(&saved).unwrap(), python, "{name}");
        assert_eq!(std::fs::metadata(&saved).unwrap().mode() & 0o7777, 0o600);
        assert!(!dir.join(&format!("saved-{name}.tmp")).exists());
    }
}

#[test]
fn rotating_the_python_keyring_writes_what_python_writes() {
    let one = Keyring::load(&private_copy("keyring/one-key.json", &TempDir::new("rotate"), "k")).unwrap();
    let rotated = one.rotate_to(Key::new("k-11223344", "active", 1761436800, material(32)));
    let mut keys = rotated.keys().to_vec();
    keys.push(Key::new("k-99aabbcc", "retiring", 1700000000, material(64)));
    let three = Keyring::new(keys, rotated.active_key_id()).unwrap();
    assert_eq!(three.to_json(), std::fs::read_to_string(fixture_path("keyring/rotated.json")).unwrap());
}

fn setup_case(dir: &TempDir, case: &panel_core::serde_json::Value) -> std::path::PathBuf {
    let path = dir.join("master-key");
    let content = base64::engine::general_purpose::STANDARD.decode(case["content_b64"].as_str().unwrap()).unwrap();
    let mode = case["mode"].as_u64().unwrap() as u32;
    match case["kind"].as_str().unwrap() {
        "file" => {
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        "symlink" => {
            let target = dir.join("target");
            std::fs::write(&target, content).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
        }
        "dir" => {
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        "missing" => {}
        other => panic!("unknown case kind {other}"),
    }
    path
}

#[test]
fn load_accepts_and_refuses_exactly_what_python_does() {
    let cases = fixture_json("keyring-cases.json");
    let cases = cases.as_array().unwrap();
    assert!(cases.len() > 70);
    let mut wrong = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mode = case["mode"].as_u64().unwrap() as u32;
        if !common::is_root() && case["kind"] == "file" && mode & 0o400 == 0 {
            continue; // Python recorded these as root: only root can read a file without owner read.
        }
        let dir = TempDir::new("keyring-case");
        let path = setup_case(&dir, case);
        let expected = &case["expected"];
        let result = Keyring::load(&path);
        let ok = match (expected.get("error").and_then(|e| e.as_str()), &result) {
            (Some(message), Err(error)) => error.message() == Some(message),
            (None, Ok(keyring)) => {
                let keys: Vec<(String, String, i64, Vec<u8>)> = expected["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| {
                        (
                            k[0].as_str().unwrap().to_string(),
                            k[1].as_str().unwrap().to_string(),
                            k[2].as_i64().unwrap(),
                            unhex(k[3].as_str().unwrap()),
                        )
                    })
                    .collect();
                let ours: Vec<(String, String, i64, Vec<u8>)> = keyring
                    .keys()
                    .iter()
                    .map(|k| (k.key_id.clone(), k.state.clone(), k.created_at, k.material().to_vec()))
                    .collect();
                keyring.active_key_id() == expected["active_key_id"].as_str().unwrap() && keys == ours
            }
            _ => false,
        };
        if !ok {
            wrong.push(format!("{name}: python {expected}, ours {result:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn keyring_file_is_private_json_with_one_active_key() {
    let dir = TempDir::new("private");
    let path = dir.join("master-key");
    Keyring::generate().save(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    let data: panel_core::serde_json::Value =
        panel_core::serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(data["schema"], 1);
    assert_eq!(data["keys"].as_array().unwrap().len(), 1);
    let material = base64::engine::general_purpose::STANDARD.decode(data["keys"][0]["key_material"].as_str().unwrap());
    assert_eq!(material.unwrap().len(), 32);
    let keyring = Keyring::load(&path).unwrap();
    assert_eq!(keyring.active().key_id, data["active_key_id"].as_str().unwrap());
}

#[test]
fn keyring_refuses_world_readable_or_malformed_files() {
    let dir = TempDir::new("refuses");
    let path = dir.join("master-key");
    Keyring::generate().save(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = Keyring::load(&path).unwrap_err();
    assert!(error.to_string().contains("mode"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, r#"{"schema": 1, "active_key_id": "missing", "keys": []}"#).unwrap();
    assert!(matches!(Keyring::load(&path), Err(KeyringError::Invalid(_))));
}

#[test]
fn save_replaces_a_stale_temporary_file_and_fixes_its_mode() {
    let dir = TempDir::new("stale");
    let path = dir.join("master-key");
    std::fs::write(dir.join("master-key.tmp"), "stale").unwrap();
    std::fs::set_permissions(dir.join("master-key.tmp"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let keyring = Keyring::generate();
    keyring.save(&path).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), keyring.to_json());
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
}

#[test]
fn save_does_not_follow_a_symlinked_temporary_file() {
    let dir = TempDir::new("symlink");
    let target = dir.join("elsewhere");
    std::fs::write(&target, "untouched").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("master-key.tmp")).unwrap();
    assert!(Keyring::generate().save(&dir.join("master-key")).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
}
