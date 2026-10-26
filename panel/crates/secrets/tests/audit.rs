//! The audit trail against Python (`fixtures/audit.json`) and the ported
//! `panel/tests/test_audit_transactions.py` (unit parts).

mod common;

use common::{fixture_json, migrated, TempDir};
use panel_core::db::DbError;
use panel_core::serde_json::{self, json, Value};
use panel_secrets::audit::{self, Actor, AuditQuery, Record};
use panel_secrets::casefold::casefold_for_ascii_match;
use panel_secrets::store::Store;

fn actor() -> Actor {
    Actor::new(Some(1), "owner")
}

#[test]
fn detail_json_and_digests_are_byte_identical_to_python() {
    let fixture = fixture_json("audit.json");
    let details = fixture["details"].as_array().unwrap();
    assert!(details.len() >= 14);
    for case in details {
        let input: Value = serde_json::from_str(case["detail_json_input"].as_str().unwrap()).unwrap();
        let map = input.as_object().unwrap();
        assert_eq!(audit::detail_json(Some(map)), case["detail_json"].as_str().unwrap(), "{input}");
        assert_eq!(audit::digest(&input), case["digest"].as_str().unwrap(), "{input}");
        assert_eq!(audit::digest(&audit::scrub(&input)), case["digest_scrubbed"].as_str().unwrap(), "{input}");
    }
    assert_eq!(audit::detail_json(None), fixture["record_none_detail"].as_str().unwrap());
}

#[test]
fn forbidden_keys_are_the_ones_python_forbids() {
    let fixture = fixture_json("audit.json");
    for probe in fixture["forbidden"].as_array().unwrap() {
        let key = probe[0].as_str().unwrap();
        assert_eq!(audit::forbidden(key), probe[1].as_bool().unwrap(), "{key:?}");
    }
}

#[test]
fn casefold_matches_python_wherever_the_fold_contains_ascii() {
    let fixture = fixture_json("audit.json");
    let table: std::collections::BTreeMap<u32, String> = fixture["casefold_with_ascii"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry[0].as_u64().unwrap() as u32, entry[1].as_str().unwrap().to_string()))
        .collect();
    for code in 0x80..=0x10ffffu32 {
        let Some(ch) = char::from_u32(code) else { continue };
        let ours = casefold_for_ascii_match(&ch.to_string());
        match table.get(&code) {
            Some(python) => assert_eq!(&ours, python, "U+{code:04X}"),
            None => assert!(!ours.chars().any(|c| c.is_ascii()), "U+{code:04X} folds to {ours:?}, Python has no ASCII"),
        }
    }
    for code in 0..0x80u8 {
        assert_eq!(
            casefold_for_ascii_match(&char::from(code).to_string()),
            char::from(code).to_ascii_lowercase().to_string()
        );
    }
}

#[test]
fn domain_write_and_audit_commit_or_roll_back_together() {
    let dir = TempDir::new("audit-tx");
    let database = migrated(&dir);
    let insert = "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at) VALUES('n1','n','unenrolled','{}',1,1)";
    let failed: Result<(), DbError> = database.transaction(|db| {
        db.execute(insert, [])?;
        audit::record(db, &Record::new(&actor(), "fleet.node.create", "n1", "127.0.0.1"))?;
        Err(DbError::Sqlite(panel_core::rusqlite::Error::InvalidQuery))
    });
    assert!(failed.is_err());
    let counts = |database: &panel_core::db::Database| -> (i64, i64) {
        database
            .with_connection(|db| -> Result<(i64, i64), DbError> {
                Ok((
                    db.query_row("SELECT count(*) FROM fleet_nodes WHERE node_id='n1'", [], |r| r.get(0))?,
                    db.query_row("SELECT count(*) FROM audit_log", [], |r| r.get(0))?,
                ))
            })
            .unwrap()
    };
    assert_eq!(counts(&database), (0, 0));
    database
        .transaction(|db| -> Result<(), DbError> {
            db.execute(insert, [])?;
            let mut record = Record::new(&actor(), "fleet.node.create", "n1", "127.0.0.1").request_id(Some("req-1"));
            record.reason_code = Some("operator".into());
            record.after_digest = Some(audit::digest(&json!({"node_id": "n1"})));
            audit::record(db, &record)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(counts(&database), (1, 1));
    let rows = audit::list(&database, &AuditQuery::default()).unwrap();
    assert_eq!((rows[0]["request_id"].as_str(), rows[0]["reason_code"].as_str()), (Some("req-1"), Some("operator")));
    assert_eq!(rows[0]["after_digest"].as_str().unwrap().len(), 64);
}

#[test]
fn scrub_removes_secret_bearing_keys_recursively() {
    for detail in [
        json!({"password": "CANARY-1", "quota_bytes": 5}),
        json!({"nested": {"share_url": "mierus://user:CANARY-2@host", "keep": 1}, "quota_bytes": 5}),
        json!({"list": [{"token": "CANARY-3"}], "quota_bytes": 5}),
        json!({"proxy-url": "CANARY-4", "quota_bytes": 5}),
    ] {
        let scrubbed = audit::scrub(&detail);
        let rendered = scrubbed.to_string();
        assert_eq!(scrubbed["quota_bytes"], 5);
        assert!(!rendered.contains("CANARY") && !rendered.contains("mierus"));
        for forbidden in ["password", "share_url", "token", "proxy-url"] {
            assert!(!rendered.contains(forbidden));
        }
        if detail.get("nested").is_some() {
            assert_eq!(scrubbed["nested"], json!({"keep": 1}));
        }
    }
}

#[test]
fn scrubbed_detail_is_written_without_the_secret() {
    let dir = TempDir::new("audit-canary");
    let database = migrated(&dir);
    let detail =
        json!({"quota_bytes": 5, "password": "CANARY-PASSWORD", "clients": [{"share_url": "naive+https://x"}]});
    database
        .transaction(|db| {
            audit::record(
                db,
                &Record::new(&actor(), "naive.create", "alice", "127.0.0.1")
                    .detail(detail.as_object().unwrap().clone()),
            )
        })
        .unwrap();
    let written = common::database_bytes(&database);
    assert!(!written.windows(15).any(|w| w == b"CANARY-PASSWORD"));
    let stored: String = database
        .with_connection(|db| {
            db.query_row("SELECT detail_json FROM audit_log", [], |r| r.get(0)).map_err(DbError::from)
        })
        .unwrap();
    assert_eq!(stored, r#"{"quota_bytes": 5, "clients": [{}]}"#);
}

#[test]
fn audits_list_newest_first_with_filters_and_parsed_detail() {
    let dir = TempDir::new("audits");
    let store = Store::new(migrated(&dir));
    let owner = actor();
    let key = Actor::new(None, "key:central");
    let mut detail = serde_json::Map::new();
    detail.insert("name".into(), "Ж".into());
    store.audit(&owner, "user.create", "alice", "127.0.0.1", Some(detail), Some("r1")).unwrap();
    store.audit(&key, "user.delete", "alice", "127.0.0.1", None, Some("r2")).unwrap();
    store.audit(&owner, "user.create", "bob", "127.0.0.1", None, None).unwrap();
    let all = store.audits(&AuditQuery::default()).unwrap();
    assert_eq!(all.iter().map(|r| r["target"].as_str().unwrap()).collect::<Vec<_>>(), ["bob", "alice", "alice"]);
    let columns: Vec<&str> = all[0].keys().map(String::as_str).collect();
    assert_eq!(
        columns,
        [
            "id",
            "happened_at",
            "actor_id",
            "actor_username",
            "action",
            "target",
            "detail_json",
            "ip",
            "request_id",
            "correlation_id",
            "reason_code",
            "generation",
            "before_digest",
            "after_digest",
            "detail"
        ]
    );
    let first = &all[2];
    assert_eq!(first["detail_json"], format!(r#"{{"name": "{}u0416"}}"#, char::from(92)));
    assert_eq!(first["detail"], json!({"name": "Ж"}));
    assert_eq!(all[1]["actor_id"], Value::Null);
    let query = |query: AuditQuery| -> Vec<String> {
        store.audits(&query).unwrap().iter().map(|r| r["target"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(query(AuditQuery { actor: Some("OWNER".into()), ..Default::default() }), ["bob", "alice"]);
    assert_eq!(query(AuditQuery { action: Some("user.delete".into()), ..Default::default() }), ["alice"]);
    assert_eq!(query(AuditQuery { request_id: Some("r1".into()), ..Default::default() }), ["alice"]);
    assert_eq!(query(AuditQuery { target: Some("bob".into()), ..Default::default() }), ["bob"]);
    let newest = all[0]["id"].as_i64().unwrap();
    assert_eq!(query(AuditQuery { before_id: Some(newest), limit: 1, ..Default::default() }), ["alice"]);
}
