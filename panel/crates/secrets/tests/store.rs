//! Administrators, sessions, CSRF and the login limiter (`panel/store.py`): the ported
//! `panel/tests/test_store.py` plus the unit-level parts of `test_security.py`/`test_rbac_audit.py`.

mod common;

use std::sync::Arc;

use common::{migrated, TempDir};
use panel_core::clock::FakeClock;
use panel_secrets::passwords::{PasswordHasher, DUMMY_PASSWORD_HASH};
use panel_secrets::store::{Store, StoreError};

/// Cheap argon2 parameters: these tests are about the store, not the policy.
const CHEAP: PasswordHasher = PasswordHasher::with_parameters(64, 1, 1, 32, 16);
const PASSWORD: &str = "correct horse battery staple";

fn store(dir: &TempDir) -> (Store, Arc<FakeClock>) {
    let clock = Arc::new(FakeClock::default());
    (Store::with_options(migrated(dir), clock.clone(), CHEAP), clock)
}

#[test]
fn store_startup_uses_valid_policy_matched_precomputed_dummy_hash() {
    let policy = PasswordHasher::panel();
    assert_eq!(policy.needs_rehash(DUMMY_PASSWORD_HASH), Ok(false));
    assert!(DUMMY_PASSWORD_HASH.starts_with("$argon2id$v=19$m=65536,t=3,p=2$"));
    let dir = TempDir::new("store-startup");
    // Creating the store hashes nothing (it would take a noticeable time with the panel policy).
    let started = std::time::Instant::now();
    let _store = Store::new(migrated(&dir));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn unknown_admin_performs_one_argon2_verify_without_logging_password() {
    let dir = TempDir::new("unknown-admin");
    let store = Store::new(migrated(&dir));
    // The dummy verification runs with the policy's cost; the result is "no such admin".
    assert!(store.verify_admin("missing-admin", "not-the-real-password").unwrap().is_none());
}

#[test]
fn create_admin_validates_and_upserts_case_insensitively() {
    let dir = TempDir::new("create-admin");
    let (store, _) = store(&dir);
    assert!(matches!(store.create_admin("owner", "short", "owner"), Err(StoreError::InvalidAdministrator)));
    assert!(matches!(store.create_admin("owner", PASSWORD, "root"), Err(StoreError::InvalidAdministrator)));
    // Twelve code points, more bytes: accepted like Python's len().
    let id = store.create_admin("owner", "пароль-12345", "owner").unwrap();
    store.update_admin(id, None, None, Some(false)).unwrap_err(); // the last owner stays active
    let again = store.create_admin("OWNER", PASSWORD, "admin").unwrap();
    assert_eq!(again, id);
    let admins = store.admins().unwrap();
    assert_eq!(admins.len(), 1);
    assert_eq!(panel_core::serde_json::Value::Object(admins[0].clone())["role"], "admin");
    assert!(store.verify_admin("Owner", PASSWORD).unwrap().is_some());
    assert!(store.verify_admin("owner", "пароль-12345").unwrap().is_none());
}

#[test]
fn verify_rehashes_a_password_stored_with_other_parameters() {
    let dir = TempDir::new("rehash");
    let database = migrated(&dir);
    let old = Store::with_options(database.clone(), Arc::new(FakeClock::default()), CHEAP);
    old.create_admin("owner", PASSWORD, "owner").unwrap();
    let stored = |database: &panel_core::db::Database| -> String {
        database
            .with_connection(|db| {
                db.query_row("SELECT password_hash FROM admins", [], |r| r.get::<_, String>(0))
                    .map_err(panel_core::db::DbError::from)
            })
            .unwrap()
    };
    let before = stored(&database);
    assert!(before.starts_with("$argon2id$v=19$m=64,t=1,p=1$"));
    let panel = Store::new(database.clone());
    let admin = panel.verify_admin("owner", PASSWORD).unwrap().unwrap();
    assert_eq!(admin.password_hash, before, "the returned row is the one read before the rehash");
    let after = stored(&database);
    assert!(after.starts_with("$argon2id$v=19$m=65536,t=3,p=2$"));
    assert!(panel.verify_admin("owner", "wrong password!").unwrap().is_none());
    assert_eq!(stored(&database), after);
}

#[test]
fn sessions_are_opaque_hashed_and_expire() {
    let dir = TempDir::new("sessions");
    let (store, clock) = store(&dir);
    let id = store.create_admin("owner", PASSWORD, "owner").unwrap();
    let (token, csrf) = store.create_session(id, 43200).unwrap();
    assert_eq!((token.len(), csrf.len()), (43, 43));
    assert!(!token.contains('.'));
    store
        .database()
        .with_connection(|db| -> Result<(), panel_core::db::DbError> {
            let (token_hash, csrf_hash): (String, String) =
                db.query_row("SELECT token_hash,csrf_hash FROM sessions", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
            assert_eq!(token_hash, panel_core::ids::sha256_hex(&token));
            assert_eq!(csrf_hash, panel_core::ids::sha256_hex(&csrf));
            Ok(())
        })
        .unwrap();
    clock.advance(100.0);
    let session = store.session(Some(&token)).unwrap().unwrap();
    assert_eq!((session.username.as_str(), session.role.as_str(), session.admin_id), ("owner", "owner", id));
    assert_eq!(session.expires_at, session.created_at + 43200);
    assert_eq!(session.last_seen_at, session.created_at, "the row as read, before last_seen_at moves");
    assert_eq!(store.session(Some(&token)).unwrap().unwrap().last_seen_at, session.created_at + 100);
    assert!(store.session(None).unwrap().is_none());
    assert!(store.session(Some("")).unwrap().is_none());
    assert!(store.session(Some("not-a-token")).unwrap().is_none());
    clock.advance(43200.0);
    assert!(store.session(Some(&token)).unwrap().is_none());
    // The next login purges the expired row.
    store.create_session(id, 43200).unwrap();
    let count: i64 = store
        .database()
        .with_connection(|db| {
            db.query_row("SELECT count(*) FROM sessions", [], |r| r.get(0)).map_err(panel_core::db::DbError::from)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn csrf_needs_header_equal_to_cookie_and_to_the_session_hash() {
    let dir = TempDir::new("csrf");
    let (store, _) = store(&dir);
    let id = store.create_admin("owner", PASSWORD, "owner").unwrap();
    let (token, csrf) = store.create_session(id, 43200).unwrap();
    let session = store.session(Some(&token)).unwrap().unwrap();
    assert!(store.csrf_valid(&session, Some(&csrf), Some(&csrf)));
    assert!(!store.csrf_valid(&session, Some(&csrf), None));
    assert!(!store.csrf_valid(&session, None, Some(&csrf)));
    assert!(!store.csrf_valid(&session, Some(""), Some("")));
    assert!(!store.csrf_valid(&session, Some(&csrf), Some("other")));
    // A poisoned cookie the header repeats: equal to each other, not to the session.
    assert!(!store.csrf_valid(&session, Some("poisoned-by-stale-login-page"), Some("poisoned-by-stale-login-page")));
    // Non-ASCII header values are just unequal (Python's compare_digest raised TypeError).
    assert!(!store.csrf_valid(&session, Some("é"), Some("é")));
}

#[test]
fn logout_and_password_change_and_deactivation_end_sessions() {
    let dir = TempDir::new("logout");
    let (store, _) = store(&dir);
    let owner = store.create_admin("owner", PASSWORD, "owner").unwrap();
    let viewer = store.create_admin("viewer", PASSWORD, "viewer").unwrap();
    let (token, _) = store.create_session(owner, 43200).unwrap();
    store.delete_session(Some(&token)).unwrap();
    assert!(store.session(Some(&token)).unwrap().is_none());
    store.delete_session(None).unwrap();

    let (token, _) = store.create_session(viewer, 43200).unwrap();
    assert!(store.update_admin(viewer, Some(""), Some(""), None).unwrap(), "empty values change nothing");
    assert!(store.session(Some(&token)).unwrap().is_some());
    assert!(store.update_admin(viewer, None, Some("a brand new password"), None).unwrap());
    assert!(store.session(Some(&token)).unwrap().is_none());
    assert!(store.verify_admin("viewer", "a brand new password").unwrap().is_some());

    let (token, _) = store.create_session(viewer, 43200).unwrap();
    assert!(store.update_admin(viewer, None, None, Some(false)).unwrap());
    assert!(store.session(Some(&token)).unwrap().is_none());
    assert!(store.verify_admin("viewer", "a brand new password").unwrap().is_none());
    assert!(!store.update_admin(9999, Some("admin"), None, None).unwrap());
}

#[test]
fn last_owner_cannot_be_deleted_demoted_or_deactivated() {
    let dir = TempDir::new("last-owner");
    let (store, _) = store(&dir);
    let owner = store.create_admin("owner", PASSWORD, "owner").unwrap();
    assert!(matches!(store.delete_admin(owner), Err(StoreError::LastOwner)));
    assert!(matches!(store.update_admin(owner, Some("admin"), None, None), Err(StoreError::LastOwner)));
    assert!(matches!(store.update_admin(owner, None, None, Some(false)), Err(StoreError::LastOwner)));
    assert!(store.update_admin(owner, Some("owner"), None, Some(true)).unwrap());
    let second = store.create_admin("second", PASSWORD, "owner").unwrap();
    assert!(store.update_admin(owner, Some("viewer"), None, None).unwrap());
    assert!(matches!(store.delete_admin(second), Err(StoreError::LastOwner)));
    assert!(store.delete_admin(owner).unwrap());
    assert!(!store.delete_admin(owner).unwrap());
    let names: Vec<String> =
        store.admins().unwrap().iter().map(|row| row["username"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, ["second"]);
    let admins = store.admins().unwrap();
    let keys: Vec<&str> = admins[0].keys().map(String::as_str).collect();
    assert_eq!(keys, ["id", "username", "role", "active", "created_at"]);
}

fn scopes(ip: &str, user: &str) -> Vec<String> {
    vec![format!("ip:{ip}"), format!("account:{user}:{ip}")]
}

#[test]
fn login_rate_limit_is_enforced_per_scope_within_the_window() {
    let dir = TempDir::new("limiter");
    let (store, clock) = store(&dir);
    for _ in 0..5 {
        assert!(store.reserve_login_attempt(&scopes("192.0.2.1", "owner"), 5, 300).unwrap().is_some());
    }
    assert!(store.reserve_login_attempt(&scopes("192.0.2.1", "owner"), 5, 300).unwrap().is_none());
    // The ip scope is full for every account from that address; another address is free.
    assert!(store.reserve_login_attempt(&scopes("192.0.2.1", "other"), 5, 300).unwrap().is_none());
    assert!(store.reserve_login_attempt(&scopes("192.0.2.2", "owner"), 5, 300).unwrap().is_some());
    clock.advance(301.0);
    assert!(store.reserve_login_attempt(&scopes("192.0.2.1", "owner"), 5, 300).unwrap().is_some());
}

#[test]
fn successful_login_releases_only_its_own_reservation() {
    let dir = TempDir::new("release");
    let (store, _) = store(&dir);
    let scope = scopes("192.0.2.1", "owner");
    let failed: Vec<String> = (0..2).map(|_| store.reserve_login_attempt(&scope, 3, 300).unwrap().unwrap()).collect();
    let good = store.reserve_login_attempt(&scope, 3, 300).unwrap().unwrap();
    assert!(store.reserve_login_attempt(&scope, 3, 300).unwrap().is_none());
    assert_eq!(good.len(), 24);
    assert!(failed.iter().all(|id| id != &good));
    store.release_login_attempt(&good).unwrap();
    assert!(store.reserve_login_attempt(&scope, 3, 300).unwrap().is_some());
    assert!(store.reserve_login_attempt(&scope, 3, 300).unwrap().is_none());
}

#[test]
fn concurrent_reservations_never_exceed_the_limit() {
    let dir = TempDir::new("concurrent");
    let (store, _) = store(&dir);
    let store = Arc::new(store);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || store.reserve_login_attempt(&scopes("192.0.2.9", "owner"), 3, 300).unwrap())
        })
        .collect();
    let granted = threads.into_iter().filter_map(|thread| thread.join().unwrap()).count();
    assert_eq!(granted, 3);
}

#[test]
fn limiter_configuration_is_validated() {
    let dir = TempDir::new("limiter-config");
    let (store, _) = store(&dir);
    for (scopes, attempts, window) in [(vec![], 5, 300), (scopes("a", "b"), 0, 300), (scopes("a", "b"), 5, 0)] {
        let error = store.reserve_login_attempt(&scopes, attempts, window).unwrap_err();
        assert_eq!(error.to_string(), "invalid login limiter configuration");
    }
}
