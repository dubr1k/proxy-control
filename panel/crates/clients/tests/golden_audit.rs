//! The clients domain's audit rows of the recorded scenarios (`panel/tests/goldens/audit/`): the
//! same operations on rows with the recorded ids give the same `action`, `target`, actor, ip,
//! request id, `reason_code`, digests and byte-identical `detail_json`.

mod common;

use common::{golden_path, Env};
use panel_clients::store;
use panel_clients::AuditContext;
use panel_core::db::DbError;
use panel_model::clients::{
    AccessGrant, Client, ClientState, GrantDesiredState, GrantObservedState, GrantOrigin, ProtocolOptions,
};
use panel_model::{Model as _, Protocol};
use panel_secrets::audit::{digest, Actor};
use serde_json::{json, Map, Value};

fn golden() -> Value {
    serde_json::from_str(&std::fs::read_to_string(golden_path("audit/audit.json")).unwrap()).unwrap()
}

fn row(golden: &Value, scenario: &str, id: i64) -> Map<String, Value> {
    golden[scenario]["audit_log"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

fn context(golden: &Map<String, Value>) -> AuditContext {
    AuditContext::new(
        Actor::new(golden["actor_id"].as_i64(), golden["actor_username"].as_str().unwrap()),
        golden["ip"].as_str().unwrap(),
        golden["request_id"].as_str().map(str::to_string),
    )
}

fn last_row(env: &Env) -> Map<String, Value> {
    env.database
        .with_connection(|db| {
            db.query_row("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1", [], panel_core::db::row_to_json)
                .map_err(DbError::from)
        })
        .unwrap()
}

/// Everything but the row id and the time.
fn assert_same(actual: &Map<String, Value>, expected: &Map<String, Value>, skip_target: bool) {
    for (key, value) in expected {
        if key == "id" || key == "happened_at" || (skip_target && key == "target") {
            continue;
        }
        assert_eq!(actual.get(key), Some(value), "{key} of {}", expected["action"]);
    }
}

fn client_row(id: &str, name: &str, at: i64) -> Client {
    Client {
        id: id.into(),
        display_name: name.into(),
        state: ClientState::Active,
        metadata: Map::new(),
        created_at: at,
        updated_at: at,
    }
}

fn grant_row(id: &str, client_id: &str, protocol: Protocol, username: &str, node_id: &str) -> AccessGrant {
    AccessGrant {
        protocol,
        options: ProtocolOptions::default_for(protocol),
        id: id.into(),
        client_id: client_id.into(),
        node_id: node_id.into(),
        endpoint_id: "default".into(),
        runtime_username: username.into(),
        secret_ref: None,
        desired_state: GrantDesiredState::Enabled,
        observed_state: GrantObservedState::Enabled,
        valid_from: None,
        valid_until: None,
        origin: GrantOrigin::Provisioned,
        own_lane: false,
        label: None,
        created_at: 1,
        updated_at: 1,
    }
}

fn insert(env: &Env, client: &Client, grants: &[AccessGrant]) {
    env.database
        .transaction(|db| {
            store::insert_client(db, client)?;
            for grant in grants {
                store::insert_grant(db, grant)?;
            }
            Ok::<_, panel_clients::ClientsError>(())
        })
        .unwrap();
}

#[test]
fn client_create_digests_match_the_recordings() {
    let golden = golden();
    let cursor: Value =
        serde_json::from_str(&std::fs::read_to_string(golden_path("clients/client_cursor.json")).unwrap()).unwrap();
    let full = cursor["exchanges"].as_array().unwrap().iter().find(|e| e["name"] == "limit=200:page=0").unwrap();
    let body: Value = serde_json::from_str(full["response"]["body"]["text"].as_str().unwrap()).unwrap();
    let names: std::collections::HashMap<String, (String, i64)> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let client = &item["client"];
            (
                client["id"].as_str().unwrap().to_string(),
                (client["display_name"].as_str().unwrap().to_string(), client["created_at"].as_i64().unwrap()),
            )
        })
        .collect();
    let mut checked = 0;
    for entry in golden["subscriptions"]["audit_log"].as_array().unwrap() {
        if entry["action"] != "client.create" {
            continue;
        }
        let (name, at) = &names[entry["target"].as_str().unwrap()];
        let client = client_row(entry["target"].as_str().unwrap(), name, *at);
        assert_eq!(json!(digest(&client.dump())), entry["after_digest"], "{name}");
        checked += 1;
    }
    assert_eq!(checked, 10);
}

/// `fleet-central` 4/10/12: create, suspend, resume with before/after digests.
#[test]
fn client_state_rows_match_the_fleet_recording() {
    let golden = golden();
    let env = Env::new("state");
    let client = client_row("40afb27f-1540-4f0d-b3ca-5c4d54f04cbb", "Fleet client", 1_793_005_892);
    assert_eq!(json!(digest(&client.dump())), row(&golden, "fleet-central", 4)["after_digest"]);
    insert(&env, &client, &[]);
    for (id, state, at) in [(10, "suspended", 1_793_005_894.0), (12, "active", 1_793_005_895.0)] {
        let expected = row(&golden, "fleet-central", id);
        env.clock.set(at);
        env.clients.set_state(&client.id, state, &context(&expected)).unwrap();
        assert_same(&last_row(&env), &expected, false);
    }
}

/// `subscriptions` 4/12/23: `grant.provision.start` (the operation id is random).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_start_rows_match_the_recording() {
    let golden = golden();
    for (id, client_id, intents) in [
        (
            4,
            "b17d0c1c-2407-44a6-8a30-f62fe4497d5a",
            vec![Protocol::Mtproxy, Protocol::Naive, Protocol::Mieru, Protocol::Amneziawg, Protocol::Trusttunnel],
        ),
        (
            12,
            "373e72ef-341d-4ff2-9da7-6d86115cd8b9",
            vec![Protocol::Naive, Protocol::Naive, Protocol::Mieru, Protocol::Trusttunnel],
        ),
        (23, "3cbfd0ce-f14f-4189-9ab1-e4aa9759f91b", vec![Protocol::Naive]),
    ] {
        let env = Env::new("start");
        let expected = row(&golden, "subscriptions", id);
        insert(&env, &client_row(client_id, "x", 1), &[]);
        let intents = intents
            .iter()
            .enumerate()
            .map(|(index, protocol)| common::intent(*protocol, &format!("user-{index}")))
            .collect();
        env.provisioning.start(client_id, intents, &context(&expected)).await.unwrap();
        assert_same(&last_row(&env), &expected, true);
    }
}

/// `subscriptions` 17: `grant.label` with the recorded input (collapsed whitespace, a control
/// character and non-ASCII escaped in `detail_json`).
#[test]
fn grant_label_row_matches_the_recording() {
    let golden = golden();
    let expected = row(&golden, "subscriptions", 17);
    let env = Env::new("label");
    let client_id = "373e72ef-341d-4ff2-9da7-6d86115cd8b9";
    let grant_id = expected["target"].as_str().unwrap();
    insert(
        &env,
        &client_row(client_id, "Bob's phone", 1),
        &[grant_row(grant_id, client_id, Protocol::Naive, "bob-naive", "local")],
    );
    env.clients.set_grant_label(grant_id, Some("Дом   'кухня'\u{7} — Wi‑Fi"), &context(&expected)).unwrap();
    assert_same(&last_row(&env), &expected, false);
}

/// `subscriptions` 19: `grant.disable` written by the domain writer for a local grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_disable_row_matches_the_recording() {
    let golden = golden();
    let expected = row(&golden, "subscriptions", 19);
    let env = Env::new("disable");
    let client_id = "373e72ef-341d-4ff2-9da7-6d86115cd8b9";
    let grant_id = expected["target"].as_str().unwrap();
    env.fake(Protocol::Mieru).seed("bob-mieru", "pw-0000000001");
    insert(
        &env,
        &client_row(client_id, "Bob's phone", 1),
        &[grant_row(grant_id, client_id, Protocol::Mieru, "bob-mieru", "local")],
    );
    env.lifecycle.set_enabled(grant_id, false, &context(&expected)).await.unwrap();
    let rows = env.database.with_connection(|db| {
        db.query_row("SELECT * FROM audit_log WHERE action='grant.disable'", [], panel_core::db::row_to_json)
            .map_err(DbError::from)
    });
    assert_same(&rows.unwrap(), &expected, false);
}

/// `subscriptions` 25: a local `grant.delete` (the domain writer's `forget`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_grant_delete_row_matches_the_recording() {
    let golden = golden();
    let expected = row(&golden, "subscriptions", 25);
    let env = Env::new("delete");
    let client_id = "3cbfd0ce-f14f-4189-9ab1-e4aa9759f91b";
    let grant_id = expected["target"].as_str().unwrap();
    env.fake(Protocol::Naive).seed("e-1", "pw-0000000001");
    insert(
        &env,
        &client_row(client_id, "Empty", 1),
        &[grant_row(grant_id, client_id, Protocol::Naive, "e-1", "local")],
    );
    env.lifecycle.delete(grant_id, &context(&expected)).await.unwrap();
    assert_same(&last_row(&env), &expected, false);
}

/// `fleet-central` 14: a remote `grant.delete` (declared for the next generation).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_grant_delete_row_matches_the_recording() {
    let golden = golden();
    let expected = row(&golden, "fleet-central", 14);
    let env = Env::new("remote");
    let node = "16bc64cb-2337-4a53-b98c-83335b5dd136";
    env.link_node(node, json!({}));
    let client_id = "40afb27f-1540-4f0d-b3ca-5c4d54f04cbb";
    let grant_id = expected["target"].as_str().unwrap();
    insert(
        &env,
        &client_row(client_id, "Fleet client", 1),
        &[grant_row(grant_id, client_id, Protocol::Mtproxy, "fleet-mt", node)],
    );
    env.lifecycle.delete(grant_id, &context(&expected)).await.unwrap();
    assert_same(&last_row(&env), &expected, false);
}
