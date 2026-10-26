//! `panel/tests/test_clients_domain.py`: clients and their grants — one owner per grant, typed
//! options, no secrets in the model, every mutation audited in its own transaction.

mod common;

use std::sync::{Arc, Mutex};

use common::{ctx, Env};
use panel_clients::store::{self, GrantUpdate};
use panel_clients::ClientsError;
use panel_core::db::{Conn, DbError};
use panel_model::clients::{
    effective_enabled, AccessGrant, ClientState, GrantDesiredState, GrantIntent, GrantObservedState, GrantOrigin,
    MieruOptions, MieruQuota, MtproxyOptions, NaiveOptions, ProtocolOptions,
};
use panel_model::seams::SeamError;
use panel_model::{Model as _, Protocol};
use serde_json::json;

/// `_grant(client_id, protocol, username, node_id)` of the Python test.
pub fn grant(client_id: &str, protocol: Protocol, username: &str, node_id: &str) -> AccessGrant {
    let now = 1_800_000_000;
    AccessGrant {
        protocol,
        options: ProtocolOptions::default_for(protocol),
        id: panel_core::ids::uuid4(),
        client_id: client_id.into(),
        node_id: node_id.into(),
        endpoint_id: "default".into(),
        runtime_username: username.into(),
        secret_ref: None,
        desired_state: GrantDesiredState::Enabled,
        observed_state: GrantObservedState::Unknown,
        valid_from: None,
        valid_until: None,
        origin: GrantOrigin::Imported,
        own_lane: false,
        label: None,
        created_at: now,
        updated_at: now,
    }
}

fn insert(env: &Env, grant: &AccessGrant) {
    env.database.transaction(|db| store::insert_grant(db, grant)).unwrap();
}

#[test]
fn client_ids_are_uuids_and_grants_belong_to_one_client_and_node() {
    let env = Env::new("ids");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    assert_eq!(client.id.len(), 36);
    env.database
        .transaction(|db| {
            store::insert_grant(db, &grant(&client.id, Protocol::Naive, "alice", "local"))?;
            // Same protocol, node, endpoint and username: refused before any SQL runs, so the
            // caller's transaction stays usable.
            match store::insert_grant(db, &grant(&client.id, Protocol::Naive, "alice", "local")) {
                Err(ClientsError::Conflict(message)) => assert!(message.contains("runtime_username")),
                other => panic!("{other:?}"),
            }
            store::insert_grant(db, &grant(&client.id, Protocol::Mtproxy, "alice", "local"))
        })
        .unwrap();
    env.database
        .with_connection(|db| {
            assert_eq!(store::client_grants(db, &client.id)?.len(), 2);
            assert_eq!(store::find_grant(db, "naive", "local", "default", "alice")?.unwrap().client_id, client.id);
            match store::insert_grant(db, &grant(&client.id, Protocol::Naive, "alice", "edge-missing")) {
                Err(ClientsError::Db(error)) => assert!(error.is_constraint()),
                other => panic!("{other:?}"),
            }
            Ok::<_, ClientsError>(())
        })
        .unwrap();
}

#[test]
fn a_grant_round_trips_through_the_database_with_its_typed_options() {
    let env = Env::new("roundtrip");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    let mut stored = grant(&client.id, Protocol::Mieru, "mieru-one", "local");
    stored.options = ProtocolOptions::Mieru(MieruOptions {
        quotas: vec![MieruQuota { days: 30, megabytes: 10 }],
        share_template: None,
    });
    insert(&env, &stored);
    let loaded = env.database.with_connection(|db| store::grant(db, &stored.id)).unwrap();
    match &loaded.options {
        ProtocolOptions::Mieru(options) => assert_eq!(options.quotas[0].megabytes, 10),
        other => panic!("{other:?}"),
    }
    assert_eq!(loaded, stored);
    // The column holds `model_dump_json()`.
    let column: String = env
        .database
        .with_connection(|db| {
            db.query_row("SELECT protocol_options_json FROM access_grants WHERE id=?", [&stored.id], |row| row.get(0))
                .map_err(DbError::from)
        })
        .unwrap();
    assert_eq!(column, r#"{"quotas":[{"days":30,"megabytes":10}],"share_template":null}"#);
}

#[test]
fn options_are_typed_and_secret_free() {
    let naive = ProtocolOptions::Naive(NaiveOptions { quota_bytes: Some(1) });
    assert!(GrantIntent::new(Protocol::Mieru, "a", naive.clone()).is_err());
    assert!(GrantIntent::new(Protocol::Naive, "a b", naive).is_err());
    // A rendered link, not a template: the real credential would be stored in the row.
    assert!(
        MieruOptions::validate(&json!({"quotas": [], "share_template": "mierus://u:realpassword@h?port=1"})).is_err()
    );
    assert!(MtproxyOptions::validate(&json!({"max_tcp_conns": 0})).is_err());
    let intent = GrantIntent::new(Protocol::Mieru, "alice", ProtocolOptions::default_for(Protocol::Mieru)).unwrap();
    assert_eq!((intent.node_id.as_str(), intent.endpoint_id.as_str()), ("local", "default"));
    assert!(MieruOptions::validate(
        &json!({"quotas": [], "share_template": "mierus://{username}:{password}@h?port=1"})
    )
    .is_ok());
}

#[test]
fn suspended_client_compiles_every_grant_as_disabled() {
    let env = Env::new("suspend");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    let now = 1_800_000_000;
    let mut subject = grant(&client.id, Protocol::Naive, "alice", "local");
    assert!(effective_enabled(&subject, &client, now));
    env.clients.set_state(&client.id, "suspended", &ctx()).unwrap();
    let (client, _) = env.clients.client_with_grants(&client.id).unwrap();
    assert!(!effective_enabled(&subject, &client, now));
    let mut active = client.clone();
    active.state = ClientState::Active;
    subject.valid_until = Some(now - 1);
    assert!(!effective_enabled(&subject, &active, now));
    subject.valid_until = None;
    subject.valid_from = Some(now + 1);
    assert!(!effective_enabled(&subject, &active, now));
    subject.valid_from = None;
    subject.desired_state = GrantDesiredState::Disabled;
    assert!(!effective_enabled(&subject, &active, now));
}

#[test]
fn archive_refuses_while_grants_are_not_deleted() {
    let env = Env::new("archive");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    let subject = grant(&client.id, Protocol::Naive, "alice", "local");
    insert(&env, &subject);
    match env.clients.set_state(&client.id, "archived", &ctx()) {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("grants")),
        other => panic!("{other:?}"),
    }
    env.database
        .transaction(|db| store::update_grant(db, &subject.id, &GrantUpdate::new().desired(GrantDesiredState::Deleted)))
        .unwrap();
    assert_eq!(env.clients.set_state(&client.id, "archived", &ctx()).unwrap().state, ClientState::Archived);
}

#[test]
fn every_mutation_leaves_an_audit_row_in_the_same_transaction() {
    let env = Env::new("audit");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    let row: (String, String, String) = env
        .database
        .with_connection(|db| {
            db.query_row("SELECT action,target,request_id FROM audit_log", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(DbError::from)
        })
        .unwrap();
    assert_eq!(row, ("client.create".to_string(), client.id.clone(), "req-1".to_string()));
    // A failing step after the insert (Python patched `record`; here a hook fails) rolls it back.
    env.clients.add_hook(Arc::new(|_db: &Conn, _client: &str| -> Result<(), SeamError> { Err("audit failed".into()) }));
    assert!(env.clients.create_client("Nobody", &ctx()).is_err());
    let names: Vec<String> =
        env.clients.list_clients().unwrap().into_iter().map(|client| client.display_name).collect();
    assert_eq!(names, ["Sergey"]);
}

#[test]
fn a_state_change_notifies_subscribers_inside_the_transaction() {
    let env = Env::new("notify");
    let seen: Arc<Mutex<Vec<(bool, String)>>> = Arc::default();
    let sink = seen.clone();
    env.clients.add_hook(Arc::new(move |db: &Conn, client_id: &str| -> Result<(), SeamError> {
        sink.lock().unwrap().push((db.in_transaction(), client_id.to_string()));
        Ok(())
    }));
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    env.clients.set_state(&client.id, "suspended", &ctx()).unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![(true, client.id.clone()), (true, client.id.clone())]);
}

#[test]
fn delete_client_removes_its_rows_and_keeps_the_audit() {
    let env = Env::new("delete");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    let subject = grant(&client.id, Protocol::Naive, "alice", "local");
    insert(&env, &subject);
    match env.clients.delete_client(&client.id, &ctx()) {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("archived")),
        other => panic!("{other:?}"),
    }
    env.database
        .transaction(|db| {
            store::update_grant(
                db,
                &subject.id,
                &GrantUpdate::new().desired(GrantDesiredState::Deleted).observed(GrantObservedState::Missing),
            )
        })
        .unwrap();
    env.clients.set_state(&client.id, "archived", &ctx()).unwrap();
    env.clients.delete_client(&client.id, &ctx()).unwrap();
    assert_eq!(env.count(&format!("SELECT COUNT(*) FROM clients WHERE id='{}'", client.id)), 0);
    assert_eq!(env.count(&format!("SELECT COUNT(*) FROM access_grants WHERE client_id='{}'", client.id)), 0);
    let actions = env.actions();
    assert_eq!(actions.last().unwrap(), "client.delete");
    assert!(actions.contains(&"client.create".to_string()));
    assert!(matches!(env.clients.delete_client(&client.id, &ctx()), Err(ClientsError::NotFound(_))));
}

#[test]
fn delete_client_waits_for_the_node_to_confirm_a_grant_deletion() {
    let env = Env::new("confirm");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    let subject = grant(&client.id, Protocol::Naive, "alice", "local");
    insert(&env, &subject);
    env.database
        .transaction(|db| {
            store::update_grant(
                db,
                &subject.id,
                &GrantUpdate::new().desired(GrantDesiredState::Deleted).observed(GrantObservedState::Unknown),
            )
        })
        .unwrap();
    env.clients.set_state(&client.id, "archived", &ctx()).unwrap();
    match env.clients.delete_client(&client.id, &ctx()) {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("not confirmed")),
        other => panic!("{other:?}"),
    }
    env.database
        .transaction(|db| {
            store::update_grant(db, &subject.id, &GrantUpdate::new().observed(GrantObservedState::Missing))
        })
        .unwrap();
    env.clients.delete_client(&client.id, &ctx()).unwrap();
}

fn operation_then_delete(status: &str, expected: &str, settled: &str) {
    let env = Env::new("operation");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    env.database
        .transaction(|db| {
            db.execute(
                "INSERT INTO provisioning_operations VALUES (?,?,?,?,?,?)",
                panel_core::rusqlite::params!["op1", client.id, status, "[]", 1, 1],
            )?;
            db.execute("UPDATE clients SET state='archived' WHERE id=?", [&client.id])?;
            Ok::<_, DbError>(())
        })
        .unwrap();
    match env.clients.delete_client(&client.id, &ctx()) {
        Err(ClientsError::Conflict(message)) => assert!(message.contains(expected), "{message}"),
        other => panic!("{other:?}"),
    }
    env.database
        .transaction(|db| {
            db.execute("UPDATE provisioning_operations SET status=?", [settled])?;
            Ok::<_, DbError>(())
        })
        .unwrap();
    env.clients.delete_client(&client.id, &ctx()).unwrap();
}

#[test]
fn delete_client_refuses_an_unfinished_provisioning_operation() {
    operation_then_delete("pending_remote", "unfinished", "succeeded");
}

#[test]
fn delete_client_refuses_an_operation_needing_manual_intervention() {
    operation_then_delete("manual_intervention_required", "manual intervention", "compensated");
}

#[test]
fn delete_client_refuses_live_grants() {
    let env = Env::new("live");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    insert(&env, &grant(&client.id, Protocol::Naive, "alice", "local"));
    env.database
        .transaction(|db| {
            db.execute("UPDATE clients SET state='archived' WHERE id=?", [&client.id])?;
            Ok::<_, DbError>(())
        })
        .unwrap();
    match env.clients.delete_client(&client.id, &ctx()) {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("grants")),
        other => panic!("{other:?}"),
    }
}

/// `test_renaming.py` (service level): names are collapsed, bounded and audited; a label is set,
/// reset and refused for a deleted grant.
#[test]
fn renames_and_labels_are_collapsed_bounded_and_audited() {
    let env = Env::new("rename");
    let client = env.clients.create_client("Sergey", &ctx()).unwrap();
    let renamed = env.clients.rename_client(&client.id, "  Сергей \t ноутбук ", &ctx()).unwrap();
    assert_eq!(renamed.display_name, "Сергей ноутбук");
    assert!(matches!(env.clients.rename_client(&client.id, "   ", &ctx()), Err(ClientsError::Conflict(_))));
    assert!(matches!(env.clients.rename_client("nope", "x", &ctx()), Err(ClientsError::NotFound(_))));
    let subject = grant(&client.id, Protocol::Naive, "alice", "local");
    insert(&env, &subject);
    let labelled = env.clients.set_grant_label(&subject.id, Some(" Дом   'кухня' "), &ctx()).unwrap();
    assert_eq!(labelled.label.as_deref(), Some("Дом 'кухня'"));
    assert_eq!(env.clients.set_grant_label(&subject.id, Some(""), &ctx()).unwrap().label, None);
    env.database
        .transaction(|db| store::update_grant(db, &subject.id, &GrantUpdate::new().desired(GrantDesiredState::Deleted)))
        .unwrap();
    assert!(matches!(env.clients.set_grant_label(&subject.id, Some("x"), &ctx()), Err(ClientsError::NotFound(_))));
    let actions = env.actions();
    assert!(actions.contains(&"client.rename".to_string()) && actions.contains(&"grant.label".to_string()));
    // The dump the API returns.
    assert_eq!(renamed.dump()["display_name"], "Сергей ноутбук");
}
