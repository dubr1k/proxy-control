//! The ported `panel/tests/test_api_keys.py` (API keys and the panel identity).

mod common;

use std::sync::Arc;

use common::{migrated, TempDir};
use panel_core::clock::{Clock as _, FakeClock};
use panel_secrets::api_keys::{ApiKeyError, ApiKeyService, SCOPES};
use panel_secrets::audit::Actor;
use panel_secrets::identity::{ensure_guid, read_panel_version, read_setting, write_setting, GUID_KEY};

fn actor() -> Actor {
    Actor::new(Some(1), "owner")
}

#[test]
fn guid_is_created_once_and_stable() {
    let dir = TempDir::new("guid");
    let database = migrated(&dir);
    let first = ensure_guid(&database).unwrap();
    assert_eq!(first.len(), 36);
    assert_eq!(ensure_guid(&database).unwrap(), first);
    // An empty stored value counts as none, like Python's `if found:`.
    database.transaction(|db| write_setting(db, GUID_KEY, Some(""))).unwrap();
    let replaced = ensure_guid(&database).unwrap();
    assert_eq!(replaced.len(), 36);
    assert_ne!(replaced, first);
    database.transaction(|db| write_setting(db, GUID_KEY, None)).unwrap();
    assert_eq!(database.with_connection(|db| read_setting(db, GUID_KEY)).unwrap(), None);
}

#[test]
fn panel_version_falls_back_to_dev_instead_of_crashing() {
    let dir = TempDir::new("version");
    assert_eq!(read_panel_version(&dir.join("absent")), "dev");
    assert_eq!(read_panel_version(dir.path()), "dev"); // a directory is an OS error, not a crash
    std::fs::write(dir.join("VERSION"), "\n").unwrap();
    assert_eq!(read_panel_version(&dir.join("VERSION")), "dev");
    std::fs::write(dir.join("VERSION"), "0.3.0\n").unwrap();
    assert_eq!(read_panel_version(&dir.join("VERSION")), "0.3.0");
    std::fs::write(dir.join("VERSION"), b"\xff\xfe").unwrap();
    assert_eq!(read_panel_version(&dir.join("VERSION")), "dev");
}

#[test]
fn create_returns_plaintext_once_and_stores_only_a_hash() {
    let dir = TempDir::new("create");
    let database = migrated(&dir);
    let service = ApiKeyService::new(database.clone());
    let (row, plaintext) = service.create("central", "node-sync", None, &actor(), "127.0.0.1", None).unwrap();
    assert!(plaintext.starts_with("pc_") && row.scope == "node-sync");
    assert_eq!(plaintext.len(), 55);
    let json = row.to_json();
    assert!(!json.contains_key("token") && !json.contains_key("key_hash"));
    let keys: Vec<&str> = json.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["id", "name", "scope", "prefix", "enabled", "expires_at", "created_at", "created_by", "last_used_at"]
    );
    let (key_hash, prefix): (String, String) = database
        .with_connection(|db| {
            db.query_row("SELECT key_hash, prefix FROM api_keys", [], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(panel_core::db::DbError::from)
        })
        .unwrap();
    assert!(!key_hash.contains(&plaintext) && plaintext.starts_with(&format!("pc_{prefix}_")));
    assert_eq!(key_hash, panel_core::ids::sha256_hex(&plaintext));
    let listed = service.list().unwrap();
    assert_eq!(listed.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(), ["central"]);
    assert_eq!(listed[0].created_by, "owner");
}

#[test]
fn authenticate_maps_scope_to_role() {
    for (scope, role) in [("admin", "owner"), ("monitor", "viewer"), ("node-sync", "node-sync")] {
        let dir = TempDir::new("scope-role");
        let service = ApiKeyService::new(migrated(&dir));
        let (_, plaintext) = service.create("k", scope, None, &actor(), "x", None).unwrap();
        let user = service.authenticate(Some(&plaintext)).unwrap().unwrap();
        assert_eq!((user.role, user.username.as_str()), (role, "key:k"));
        let json = user.to_json();
        assert_eq!(json["via"], "api-key");
        assert_eq!(json["id"], panel_core::serde_json::Value::Null);
        assert_eq!(json["scope"], scope);
    }
}

#[test]
fn wrong_disabled_expired_and_deleted_keys_do_not_authenticate() {
    let dir = TempDir::new("wrong");
    let clock = Arc::new(FakeClock::new(1_000_000.0));
    let service = ApiKeyService::with_clock(migrated(&dir), clock.clone());
    let (row, plaintext) = service.create("k", "admin", Some(1_000_100), &actor(), "x", None).unwrap();
    let last = plaintext.chars().last().unwrap();
    let tampered = format!("{}{}", &plaintext[..plaintext.len() - 1], if last != 'A' { 'A' } else { 'B' });
    assert!(service.authenticate(Some(&tampered)).unwrap().is_none());
    assert!(service.authenticate(Some("pc_not_a_key")).unwrap().is_none());
    assert!(service.authenticate(Some("pc_only-one-underscore")).unwrap().is_none());
    assert!(service.authenticate(None).unwrap().is_none());
    assert!(service.authenticate(Some("")).unwrap().is_none());
    service.set_enabled(row.id, false, &actor(), "x", None).unwrap();
    assert!(service.authenticate(Some(&plaintext)).unwrap().is_none());
    service.set_enabled(row.id, true, &actor(), "x", None).unwrap();
    assert!(service.authenticate(Some(&plaintext)).unwrap().is_some());
    clock.set(1_000_101.0);
    assert!(service.authenticate(Some(&plaintext)).unwrap().is_none());
    service.delete(row.id, &actor(), "x", None).unwrap();
    assert!(service.list().unwrap().is_empty());
    assert!(matches!(service.delete(row.id, &actor(), "x", None), Err(ApiKeyError::NotFound(_))));
    assert!(matches!(service.set_enabled(row.id, true, &actor(), "x", None), Err(ApiKeyError::NotFound(_))));
}

#[test]
fn last_used_is_written_at_most_every_minute() {
    let dir = TempDir::new("last-used");
    let clock = Arc::new(FakeClock::new(2_000_000.0));
    let service = ApiKeyService::with_clock(migrated(&dir), clock.clone());
    let (_, plaintext) = service.create("k", "monitor", None, &actor(), "x", None).unwrap();
    let last_used = || service.list().unwrap()[0].last_used_at;
    assert_eq!(last_used(), None);
    service.authenticate(Some(&plaintext)).unwrap().unwrap();
    assert_eq!(last_used(), Some(2_000_000));
    clock.advance(59.0);
    service.authenticate(Some(&plaintext)).unwrap().unwrap();
    assert_eq!(last_used(), Some(2_000_000));
    clock.advance(1.0);
    service.authenticate(Some(&plaintext)).unwrap().unwrap();
    assert_eq!(last_used(), Some(clock.now()));
}

#[test]
fn invalid_scope_and_name_are_refused() {
    let dir = TempDir::new("invalid");
    let service = ApiKeyService::new(migrated(&dir));
    let refused =
        |name: &str, scope: &str, expires: Option<i64>| match service.create(name, scope, expires, &actor(), "x", None)
        {
            Err(ApiKeyError::Invalid(message)) => message,
            other => panic!("{other:?}"),
        };
    assert_eq!(refused("k", "root", None), "scope is invalid");
    assert_eq!(refused("", "admin", None), "name is invalid");
    assert_eq!(refused(" \u{3000}\t", "admin", None), "name is invalid");
    assert_eq!(refused(&"й".repeat(65), "admin", None), "name is invalid");
    assert_eq!(refused("k", "admin", Some(1)), "expires_at is in the past");
    // 64 code points are fine, and the stored name is stripped.
    let (row, _) = service.create(&format!(" {} ", "й".repeat(62)), "admin", None, &actor(), "x", None).unwrap();
    assert_eq!(row.name, "й".repeat(62));
    assert_eq!(SCOPES, ["admin", "monitor", "node-sync"]);
}

#[test]
fn every_change_is_audited_without_the_key() {
    let dir = TempDir::new("audited");
    let database = migrated(&dir);
    let service = ApiKeyService::new(database.clone());
    let (row, plaintext) = service.create("k", "admin", None, &actor(), "x", Some("req-1")).unwrap();
    service.set_enabled(row.id, false, &actor(), "x", None).unwrap();
    service.set_enabled(row.id, true, &actor(), "x", None).unwrap();
    service.delete(row.id, &actor(), "x", None).unwrap();
    type AuditRow = (String, String, String, Option<String>, Option<i64>);
    let rows: Vec<AuditRow> = database
        .with_connection(|db| {
            let mut statement =
                db.prepare("SELECT action, detail_json, target, request_id, actor_id FROM audit_log ORDER BY id")?;
            let rows = statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(panel_core::db::DbError::from)
        })
        .unwrap();
    let actions: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(actions, ["api_key.create", "api_key.disable", "api_key.enable", "api_key.delete"]);
    assert!(rows.iter().all(|r| !r.1.contains(&plaintext)));
    assert_eq!(rows[0].1, r#"{"name": "k", "scope": "admin", "expires_at": null}"#);
    assert_eq!(rows[0].2, row.id.to_string());
    assert_eq!(rows[0].3.as_deref(), Some("req-1"));
    assert_eq!(rows[0].4, Some(1));
    assert_eq!(rows[1].1, "{}");
}
