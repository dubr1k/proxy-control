//! The secret store against a database the Python panel's secret store wrote
//! (`fixtures/golden.db`, its keyring `fixtures/golden-keyring.json` and every row in
//! `fixtures/secret-versions.json`), plus the ported `panel/tests/test_secrets_store.py`.

mod common;

use std::collections::BTreeMap;

use common::{fixture_json, migrated, private_copy, unhex, TempDir};
use panel_core::db::Database;
use panel_core::serde_json::Value;
use panel_secrets::keyring::{Key, Keyring};
use panel_secrets::secrets_store::{self, decrypt, encrypt, Identity, OpenError, SecretError, SecretRef, SecretStore};

struct GoldenRow {
    secret_id: String,
    version: i64,
    purpose: String,
    grant_id: Option<String>,
    permitted_node_id: Option<String>,
    key_id: String,
    state: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
}

impl GoldenRow {
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

fn golden_rows() -> (Vec<GoldenRow>, BTreeMap<String, u64>) {
    let fixture = fixture_json("secret-versions.json");
    let text = |row: &Value, name: &str| row[name].as_str().map(str::to_string);
    let rows = fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| GoldenRow {
            secret_id: text(row, "secret_id").unwrap(),
            version: row["version"].as_i64().unwrap(),
            purpose: text(row, "purpose").unwrap(),
            grant_id: text(row, "grant_id"),
            permitted_node_id: text(row, "permitted_node_id"),
            key_id: text(row, "key_id").unwrap(),
            state: text(row, "state").unwrap(),
            nonce: unhex(row["nonce_hex"].as_str().unwrap()),
            ciphertext: unhex(row["ciphertext_hex"].as_str().unwrap()),
            aad: unhex(row["aad_hex"].as_str().unwrap()),
            plaintext: unhex(row["plaintext_hex"].as_str().unwrap()),
        })
        .collect();
    let counts =
        fixture["verify_all"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_u64().unwrap())).collect();
    (rows, counts)
}

/// A private copy of the golden database and keyring.
fn golden(dir: &TempDir) -> (Database, std::path::PathBuf) {
    let path = dir.join("panel.sqlite3");
    std::fs::copy(common::fixture_path("golden.db"), &path).unwrap();
    let database = Database::open(&path).unwrap();
    // The Python-migrated file is accepted as is (nothing to apply).
    assert!(panel_core::migrations::apply_migrations(&database).unwrap().is_empty());
    (database, private_copy("golden-keyring.json", dir, "master-key"))
}

#[test]
fn every_python_row_decrypts_and_re_encrypts_identically() {
    let dir = TempDir::new("golden");
    let (database, keyring_path) = golden(&dir);
    let keyring = Keyring::load(&keyring_path).unwrap();
    let store = SecretStore::new(Some(keyring.clone()));
    let (rows, counts) = golden_rows();
    assert_eq!(rows.len(), 17);
    assert_eq!(counts.len(), 2, "the golden database holds rows under two keys");
    database
        .with_connection(|db| -> Result<(), SecretError> {
            let stored: i64 = db.query_row("SELECT count(*) FROM secret_versions", [], |r| r.get(0))?;
            assert_eq!(stored as usize, rows.len());
            for row in &rows {
                let (key_id, nonce, ciphertext, state): (String, Vec<u8>, Vec<u8>, String) = db.query_row(
                    "SELECT key_id,nonce,ciphertext,state FROM secret_versions WHERE secret_id=? AND version=?",
                    panel_core::rusqlite::params![row.secret_id, row.version],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?;
                assert_eq!(
                    (key_id.as_str(), &nonce, &ciphertext, state.as_str()),
                    (row.key_id.as_str(), &row.nonce, &row.ciphertext, row.state.as_str())
                );
                assert_eq!(row.identity().aad(), row.aad, "AAD of {:?}", row.secret_id);
                let key = keyring.get(&row.key_id).unwrap();
                let nonce: [u8; 12] = row.nonce.clone().try_into().unwrap();
                assert_eq!(encrypt(key.material(), &nonce, &row.plaintext, &row.aad), row.ciphertext);
                assert_eq!(decrypt(key.material(), &row.nonce, &row.ciphertext, &row.aad).unwrap(), row.plaintext);
                let reference = SecretRef::new(&row.secret_id, row.version);
                let revealed = store.reveal(
                    db,
                    &reference,
                    &row.purpose,
                    row.grant_id.as_deref(),
                    row.permitted_node_id.as_deref(),
                );
                if row.state == "revoked" {
                    assert_eq!(revealed.unwrap_err().message(), Some(SecretError::UNAVAILABLE));
                } else {
                    assert_eq!(revealed.unwrap(), row.plaintext, "{:?}", row.secret_id);
                }
            }
            assert_eq!(store.verify_all(db)?, counts);
            Ok(())
        })
        .unwrap();
}

#[test]
fn rows_written_by_rust_with_the_same_nonce_equal_the_python_rows() {
    let dir = TempDir::new("rewrite");
    let database = migrated(&dir);
    let (rows, _) = golden_rows();
    let keyring = Keyring::load(&private_copy("golden-keyring.json", &dir, "master-key")).unwrap();
    for key_id in ["k-0a1b2c3d", "k-11223344"] {
        let key = keyring.get(key_id).unwrap().clone();
        let store =
            SecretStore::new(Some(Keyring::new(vec![Key::new(key_id, "active", 0, *key.material())], key_id).unwrap()));
        database
            .transaction(|db| -> Result<(), SecretError> {
                for row in rows.iter().filter(|row| row.key_id == key_id) {
                    let nonce: [u8; 12] = row.nonce.clone().try_into().unwrap();
                    store.store_with_nonce(db, &row.identity(), &row.plaintext, &row.state, &nonce)?;
                }
                Ok(())
            })
            .unwrap();
    }
    database
        .with_connection(|db| -> Result<(), SecretError> {
            for row in &rows {
                let (key_id, nonce, ciphertext): (String, Vec<u8>, Vec<u8>) = db.query_row(
                    "SELECT key_id,nonce,ciphertext FROM secret_versions WHERE secret_id=? AND version=?",
                    panel_core::rusqlite::params![row.secret_id, row.version],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                assert_eq!(
                    (key_id, nonce, ciphertext),
                    (row.key_id.clone(), row.nonce.clone(), row.ciphertext.clone())
                );
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn rotating_the_golden_database_rewraps_every_row_and_narrows_the_file() {
    let dir = TempDir::new("rotate");
    let (database, keyring_path) = golden(&dir);
    let (rows, _) = golden_rows();
    let rotation = secrets_store::rotate_master_key_to(
        &database,
        &keyring_path,
        5,
        Key::new("k-55667788", "active", 1761500000, [9; 32]),
    )
    .unwrap();
    assert_eq!(rotation.active_key_id, "k-55667788");
    assert_eq!(rotation.rewrapped, BTreeMap::from([("k-55667788".to_string(), rows.len() as u64)]));
    let narrowed = Keyring::load(&keyring_path).unwrap();
    assert_eq!(narrowed.keys().len(), 1);
    assert_eq!(narrowed.active_key_id(), "k-55667788");
    assert_eq!(secrets_store::verify_master_key(&database, &keyring_path).unwrap(), rotation.rewrapped);
    let store = SecretStore::new(Some(narrowed));
    database
        .with_connection(|db| -> Result<(), SecretError> {
            for row in rows.iter().filter(|row| row.state != "revoked") {
                let reference = SecretRef::new(&row.secret_id, row.version);
                let plaintext = store.reveal(
                    db,
                    &reference,
                    &row.purpose,
                    row.grant_id.as_deref(),
                    row.permitted_node_id.as_deref(),
                )?;
                assert_eq!(plaintext, row.plaintext);
            }
            Ok(())
        })
        .unwrap();
}

fn store_one(store: &SecretStore, database: &Database, secret_id: &str, grant_id: &str, plaintext: &[u8]) -> SecretRef {
    database
        .transaction(|db| {
            store.store(
                db,
                &Identity {
                    secret_id,
                    version: 1,
                    purpose: "p",
                    grant_id: Some(grant_id),
                    permitted_node_id: Some("local"),
                },
                plaintext,
                "pending",
            )
        })
        .unwrap()
}

fn fresh(dir: &TempDir) -> (Database, Keyring) {
    let path = dir.join("master-key");
    Keyring::generate().save(&path).unwrap();
    (migrated(dir), Keyring::load(&path).unwrap())
}

#[test]
fn store_and_reveal_round_trip_binds_identity() {
    let dir = TempDir::new("round-trip");
    let (database, keyring) = fresh(&dir);
    let store = SecretStore::new(Some(keyring));
    let reference = database
        .transaction(|db| {
            store.store(
                db,
                &Identity {
                    secret_id: "s1",
                    version: 1,
                    purpose: "grant.credential",
                    grant_id: Some("g1"),
                    permitted_node_id: Some("local"),
                },
                b"hunter2-hunter2",
                "pending",
            )
        })
        .unwrap();
    assert_eq!(reference, SecretRef::new("s1", 1));
    database
        .with_connection(|db| -> Result<(), SecretError> {
            assert_eq!(
                store.reveal(db, &reference, "grant.credential", Some("g1"), Some("local"))?,
                b"hunter2-hunter2"
            );
            assert!(store.reveal(db, &reference, "grant.credential", Some("g2"), Some("local")).is_err());
            assert!(store.reveal(db, &reference, "grant.credential", Some("g1"), Some("edge-01")).is_err());
            Ok(())
        })
        .unwrap();
}

#[test]
fn copied_ciphertext_under_another_row_fails() {
    let dir = TempDir::new("copied");
    let (database, keyring) = fresh(&dir);
    let store = SecretStore::new(Some(keyring));
    store_one(&store, &database, "s1", "g1", b"a");
    store_one(&store, &database, "s2", "g2", b"b");
    database
        .transaction(|db| -> Result<(), panel_core::db::DbError> {
            let (nonce, ciphertext): (Vec<u8>, Vec<u8>) =
                db.query_row("SELECT nonce,ciphertext FROM secret_versions WHERE secret_id='s1'", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            db.execute(
                "UPDATE secret_versions SET nonce=?,ciphertext=? WHERE secret_id='s2'",
                panel_core::rusqlite::params![nonce, ciphertext],
            )?;
            Ok(())
        })
        .unwrap();
    let result =
        database.with_connection(|db| store.reveal(db, &SecretRef::new("s2", 1), "p", Some("g2"), Some("local")));
    assert_eq!(result.unwrap_err().message(), Some(SecretError::AUTHENTICATION));
}

#[test]
fn database_without_key_holds_no_recognisable_secret() {
    let dir = TempDir::new("canary");
    let (database, keyring) = fresh(&dir);
    let store = SecretStore::new(Some(keyring));
    let canary = b"CANARY-9f3c1c0a-do-not-leak";
    store_one(&store, &database, "s1", "g1", canary);
    let raw = common::database_bytes(&database);
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(canary);
    assert!(!raw.windows(canary.len()).any(|w| w == canary));
    assert!(!raw.windows(encoded.len()).any(|w| w == encoded.as_bytes()));
}

#[test]
fn unknown_or_retired_key_ids_fail_closed() {
    let dir = TempDir::new("unknown-key");
    let (database, keyring) = fresh(&dir);
    store_one(&SecretStore::new(Some(keyring)), &database, "s1", "g1", b"x");
    let other = SecretStore::new(Some(Keyring::generate()));
    let error = database
        .with_connection(|db| other.reveal(db, &SecretRef::new("s1", 1), "p", Some("g1"), Some("local")))
        .unwrap_err();
    assert!(error.to_string().contains("key"));
    assert_eq!(error.message(), Some(SecretError::UNKNOWN_KEY));
}

#[test]
fn rotation_is_overlap_first_and_interrupted_rewrap_stays_decryptable() {
    let dir = TempDir::new("overlap");
    let (database, old) = fresh(&dir);
    let old_store = SecretStore::new(Some(old.clone()));
    database
        .transaction(|db| -> Result<(), SecretError> {
            for index in 0..5 {
                let (secret_id, grant_id) = (format!("s{index}"), format!("g{index}"));
                let identity = Identity {
                    secret_id: &secret_id,
                    version: 1,
                    purpose: "p",
                    grant_id: Some(&grant_id),
                    permitted_node_id: Some("local"),
                };
                old_store.store(db, &identity, b"v", "pending")?;
            }
            Ok(())
        })
        .unwrap();
    let rotated = old.rotate();
    let states: std::collections::BTreeSet<&str> = rotated.keys().iter().map(|k| k.state.as_str()).collect();
    assert_eq!(states, ["active", "retiring"].into());
    let new_store = SecretStore::new(Some(rotated.clone()));
    // Interrupt after the first batch of two rows.
    let crashed: Result<(), SecretError> = database.transaction(|db| {
        new_store.rewrap(db, 2)?;
        Err(SecretError::Refused("crash between batches"))
    });
    assert!(crashed.is_err());
    let counts = database.with_connection(|db| new_store.verify_all(db)).unwrap();
    assert_eq!(counts.values().sum::<u64>(), 5);
    while database.transaction(|db| new_store.rewrap(db, 2)).unwrap() != 0 {}
    let counts = database.with_connection(|db| new_store.verify_all(db)).unwrap();
    assert_eq!(counts, BTreeMap::from([(rotated.active_key_id().to_string(), 5)]));
}

#[test]
fn repr_and_errors_never_contain_plaintext() {
    let dir = TempDir::new("repr");
    let (database, keyring) = fresh(&dir);
    let store = SecretStore::new(Some(keyring));
    let reference = store_one(&store, &database, "s1", "g1", b"PLAINTEXT-CANARY");
    assert!(!format!("{reference:?}").contains("PLAINTEXT") && !format!("{store:?}").contains("PLAINTEXT"));
    let error =
        database.with_connection(|db| store.reveal(db, &reference, "wrong", Some("g1"), Some("local"))).unwrap_err();
    assert!(!error.to_string().contains("PLAINTEXT") && !format!("{error:?}").contains("PLAINTEXT"));
}

#[test]
fn missing_key_with_encrypted_rows_fails_closed_at_app_start() {
    let dir = TempDir::new("app-start");
    let (database, keyring) = fresh(&dir);
    assert!(!SecretStore::open(&database, None).unwrap().enabled());
    store_one(&SecretStore::new(Some(keyring)), &database, "s1", "g1", b"x");
    let error = SecretStore::open(&database, None).unwrap_err();
    assert!(matches!(error, OpenError::KeyRequired));
    assert!(error.to_string().contains("PANEL_MASTER_KEY_FILE"));
    assert!(SecretStore::open(&database, Some(&dir.join("master-key"))).unwrap().enabled());
}

#[test]
fn disabled_store_refuses_and_transition_needs_no_key() {
    let dir = TempDir::new("disabled");
    let (database, keyring) = fresh(&dir);
    let reference = store_one(&SecretStore::new(Some(keyring)), &database, "s1", "g1", b"x");
    let disabled = SecretStore::new(None);
    let error =
        database.with_connection(|db| disabled.reveal(db, &reference, "p", Some("g1"), Some("local"))).unwrap_err();
    assert_eq!(error.message(), Some(SecretError::DISABLED));
    database.transaction(|db| disabled.transition(db, &reference, "revoked")).unwrap();
    let missing = database.transaction(|db| disabled.transition(db, &SecretRef::new("nope", 1), "active")).unwrap_err();
    assert_eq!(missing.message(), Some(SecretError::UNAVAILABLE));
    let invalid = database.transaction(|db| disabled.transition(db, &reference, "gone")).unwrap_err();
    assert_eq!(invalid.message(), Some(SecretError::INVALID_STATE));
}
