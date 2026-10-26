//! `panel/tests/test_client_import.py` at service level: inventory, proposals, the all-or-nothing
//! confirmation and its audit row.

mod common;

use common::{ctx, Env};
use panel_clients::importer::{self, ImportDecision};
use panel_clients::ClientsError;
use panel_core::db::DbError;
use panel_model::clients::GrantDesiredState;
use panel_model::Protocol;
use serde_json::{json, Value};

fn runtime_rows() -> Vec<(Protocol, Vec<Value>)> {
    vec![
        (
            Protocol::Mtproxy,
            vec![json!({
                "username": "alice", "enabled": true, "data_quota_bytes": 5, "max_tcp_conns": true,
                "links": {"tls": ["tg://proxy?server=relay.example.net&port=8443&secret=ee00"]},
            })],
        ),
        (
            Protocol::Naive,
            vec![
                json!({"username": "alice", "quota_bytes": 0}),
                json!({"username": "bob", "enabled": false}),
                json!("junk"),
            ],
        ),
        (
            Protocol::Mieru,
            vec![json!({"username": "carol", "quotas": [{"days": 30, "megabytes": 10}]}), json!({"name": "x"})],
        ),
    ]
}

#[test]
fn inventory_proposes_same_username_only_as_a_hint() {
    let env = Env::new("inventory");
    let items = importer::inventory(&env.database, &runtime_rows()).unwrap();
    let names: Vec<(Protocol, &str)> =
        items.iter().map(|item| (item.protocol, item.runtime_username.as_str())).collect();
    assert_eq!(
        names,
        [
            (Protocol::Mtproxy, "alice"),
            (Protocol::Naive, "alice"),
            (Protocol::Naive, "bob"),
            (Protocol::Mieru, "carol")
        ]
    );
    // Telemt's endpoint comes from the link it serves; a bool is not an integer.
    assert_eq!(
        items[0].to_json(),
        json!({"protocol": "mtproxy", "runtime_username": "alice", "enabled": true, "options": {
            "data_quota_bytes": 5, "rate_limit_up_bps": null, "rate_limit_down_bps": null, "max_tcp_conns": null,
            "max_unique_ips": null, "expiration": null, "host": "relay.example.net", "port": 8443}, "imported_grant_id": null})
    );
    assert_eq!(items[1].options, json!({"quota_bytes": null}));
    assert!(!items[2].enabled);
    let proposals = importer::propose(&items);
    let hints: Vec<bool> = proposals.iter().map(|proposal| proposal.same_username_hint).collect();
    assert_eq!(hints, [true, true, false, false]);
}

#[test]
fn import_is_idempotent_and_records_the_runtime_state_never_a_credential() {
    let env = Env::new("confirm");
    let known = importer::inventory(&env.database, &runtime_rows()).unwrap();
    let decisions = vec![
        ImportDecision {
            display_name: "Alice".into(),
            client_id: None,
            items: vec![(Protocol::Mtproxy, "alice".into()), (Protocol::Naive, "alice".into())],
        },
        ImportDecision { display_name: "bob".into(), client_id: None, items: vec![(Protocol::Naive, "bob".into())] },
    ];
    let result = importer::confirm(&env.clients, &decisions, &known, &ctx()).unwrap();
    assert_eq!(result.to_json(), json!({"created_clients": 2, "created_grants": 3, "skipped": []}));
    let again = importer::inventory(&env.database, &runtime_rows()).unwrap();
    assert_eq!(again.iter().filter(|item| item.imported_grant_id.is_some()).count(), 3);
    let second = importer::confirm(&env.clients, &decisions, &again, &ctx()).unwrap();
    assert_eq!(
        second.to_json(),
        json!({"created_clients": 0, "created_grants": 0, "skipped": ["mtproxy:alice", "naive:alice", "naive:bob"]})
    );
    let bob = env.facade.grant(Protocol::Naive, "bob").unwrap().unwrap();
    assert_eq!((bob.desired_state, bob.secret_ref.is_none()), (GrantDesiredState::Disabled, true));
    assert_eq!(env.count("SELECT count(*) FROM secret_versions"), 0);
    let detail: String = env
        .database
        .with_connection(|db| {
            db.query_row(
                "SELECT detail_json FROM audit_log WHERE action='client.import' ORDER BY id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .map_err(DbError::from)
        })
        .unwrap();
    assert_eq!(
        detail,
        r#"{"created_clients": 2, "created_grants": 3, "skipped": [], "accounts": ["mtproxy:alice", "naive:alice", "naive:bob"]}"#
    );
}

#[test]
fn import_can_attach_to_an_existing_client_and_rejects_unknown_accounts_atomically() {
    let env = Env::new("attach");
    let known = importer::inventory(&env.database, &runtime_rows()).unwrap();
    let existing = env.clients.create_client("Sergey", &ctx()).unwrap();
    let attach = vec![ImportDecision {
        display_name: "ignored".into(),
        client_id: Some(existing.id.clone()),
        items: vec![(Protocol::Mieru, "carol".into())],
    }];
    importer::confirm(&env.clients, &attach, &known, &ctx()).unwrap();
    assert_eq!(env.grants(&existing.id).len(), 1);
    let bad = vec![
        ImportDecision { display_name: "x".into(), client_id: None, items: vec![(Protocol::Naive, "bob".into())] },
        ImportDecision { display_name: "y".into(), client_id: None, items: vec![(Protocol::Naive, "nobody".into())] },
    ];
    match importer::confirm(&env.clients, &bad, &known, &ctx()) {
        Err(ClientsError::Invalid(message)) => assert_eq!(message, "unknown runtime account: naive/nobody"),
        other => panic!("{other:?}"),
    }
    assert!(env.facade.grant(Protocol::Naive, "bob").unwrap().is_none());
    let missing = vec![ImportDecision {
        display_name: "z".into(),
        client_id: Some("nope".into()),
        items: vec![(Protocol::Naive, "bob".into())],
    }];
    assert!(matches!(importer::confirm(&env.clients, &missing, &known, &ctx()), Err(ClientsError::NotFound(_))));
    let twice = vec![ImportDecision {
        display_name: "w".into(),
        client_id: None,
        items: vec![(Protocol::Naive, "bob".into()), (Protocol::Naive, "bob".into())],
    }];
    assert!(matches!(importer::confirm(&env.clients, &twice, &known, &ctx()), Err(ClientsError::Conflict(_))));
}

#[test]
fn accounts_the_central_owns_never_appear() {
    let env = Env::new("owned");
    env.database
        .transaction(|db| {
            db.execute(
                "INSERT INTO managed_resources(protocol,runtime_username,ref,generation,state,updated_at)
                 VALUES('naive','bob','grant:x',1,'enabled',1),('mieru','carol','grant:y',1,'missing',1)",
                [],
            )?;
            Ok::<_, DbError>(())
        })
        .unwrap();
    let items = importer::inventory(&env.database, &runtime_rows()).unwrap();
    let names: Vec<&str> = items.iter().map(|item| item.runtime_username.as_str()).collect();
    assert_eq!(names, ["alice", "alice", "carol"]);
}
