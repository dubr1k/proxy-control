//! The client API (WP7) through the whole HTTP stack: the recorded refusals of the cursor golden
//! and of `errors/error_bodies.json`, and a create/rename/label/list round trip.

mod common;

use common::Client;
use serde_json::{json, Value};

const OWNER_PASSWORD: &str = "correct horse battery staple";

fn golden(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/goldens").join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn signed_in(panel: &common::Panel) -> Client {
    panel.state.store.create_admin("owner", OWNER_PASSWORD, "owner").unwrap();
    let mut client = Client::default();
    assert_eq!(client.login(panel, "owner", OWNER_PASSWORD).status, 204);
    client
}

#[test]
fn recorded_refusals_are_byte_identical() {
    let panel = common::start(&[]);
    let mut client = signed_in(&panel);
    let csrf = client.csrf();
    let cursor = golden("clients/client_cursor.json");
    let mut checked = 0;
    for exchange in cursor["exchanges"].as_array().unwrap() {
        if !exchange["name"].as_str().unwrap().starts_with("invalid:") {
            continue;
        }
        let answer = client.send(&panel, "GET", exchange["request"]["path"].as_str().unwrap(), &[], None);
        assert_eq!(answer.status as i64, exchange["response"]["status"].as_i64().unwrap());
        assert_eq!(String::from_utf8(answer.body).unwrap(), exchange["response"]["body"]["text"].as_str().unwrap());
        checked += 1;
    }
    assert_eq!(checked, 4);
    for exchange in golden("errors/error_bodies.json").as_array().unwrap() {
        let name = exchange["name"].as_str().unwrap();
        if !["422:validation", "422:validation-extra", "422:query", "client:not-found", "operation:not-found"]
            .contains(&name)
        {
            continue;
        }
        let request = &exchange["request"];
        let body = request["body"].get("text").and_then(Value::as_str);
        let answer = client.send(
            &panel,
            request["method"].as_str().unwrap(),
            request["path"].as_str().unwrap(),
            &[("X-CSRF-Token", &csrf)],
            body,
        );
        assert_eq!(answer.status as i64, exchange["response"]["status"].as_i64().unwrap(), "{name}");
        assert_eq!(
            String::from_utf8(answer.body).unwrap(),
            exchange["response"]["body"]["text"].as_str().unwrap(),
            "{name}"
        );
        checked += 1;
    }
    assert_eq!(checked, 9);
}

#[test]
fn clients_are_created_renamed_labelled_and_listed() {
    let panel = common::start(&[]);
    let mut client = signed_in(&panel);
    let csrf = client.csrf();
    let created =
        client.send(&panel, "POST", "/api/clients", &[("X-CSRF-Token", &csrf)], Some(r#"{"display_name":"Алиса"}"#));
    assert_eq!(created.status, 201);
    let body = created.json();
    assert_eq!(body["subscription_reveal_token"], Value::Null);
    let id = body["id"].as_str().unwrap().to_string();
    let renamed = client.send(
        &panel,
        "POST",
        &format!("/api/clients/{id}/rename"),
        &[("X-CSRF-Token", &csrf)],
        Some(r#"{"display_name":"  Алиса   2 "}"#),
    );
    assert_eq!((renamed.status, renamed.json()["display_name"].clone()), (200, json!("Алиса 2")));
    let blank = client.send(
        &panel,
        "POST",
        &format!("/api/clients/{id}/rename"),
        &[("X-CSRF-Token", &csrf)],
        Some(r#"{"display_name":"   "}"#),
    );
    assert_eq!((blank.status, blank.json()), (422, json!({"detail": "display_name must be 1-128 characters"})));
    let listing = client.send(&panel, "GET", "/api/clients", &[], None).json();
    assert_eq!(listing["items"][0]["client"]["display_name"], "Алиса 2");
    let page = client.send(&panel, "GET", "/api/clients?limit=5&state=active", &[], None).json();
    assert_eq!((page["matched"].clone(), page["counts"]["active"].clone()), (json!(1), json!(1)));
    let state = client.send(&panel, "GET", "/api/clients?state=gone", &[], None);
    assert_eq!(state.status, 422);
    assert_eq!(state.json()["detail"][0]["loc"], json!(["query", "state"]));
    // A grant the central owns: refused before any manager call, with the reason header.
    panel
        .state
        .database
        .transaction(|db| {
            db.execute(
                "INSERT INTO access_grants(id,client_id,protocol,node_id,endpoint_id,runtime_username,desired_state,
                   observed_state,protocol_options_json,origin,created_at,updated_at)
                 VALUES('g1',?,'naive','local','default','bob','enabled','enabled','{\"quota_bytes\":null}','imported',1,1)",
                [&id],
            )?;
            db.execute(
                "INSERT INTO managed_resources(protocol,runtime_username,ref,generation,state,updated_at)
                 VALUES('naive','bob','grant:g1',1,'enabled',1)",
                [],
            )?;
            Ok::<_, panel_core::db::DbError>(())
        })
        .unwrap();
    let refused = client.send(&panel, "POST", "/api/clients/grants/g1/disable", &[("X-CSRF-Token", &csrf)], None);
    assert_eq!((refused.status, refused.header("x-reason")), (409, Some("managed_by_central")));
    assert_eq!(refused.json(), json!({"detail": "managed by central"}));
    let label = client.send(
        &panel,
        "POST",
        "/api/clients/grants/g1/label",
        &[("X-CSRF-Token", &csrf)],
        Some(r#"{"label":" Дом  "}"#),
    );
    assert_eq!((label.status, label.json()["label"].clone()), (200, json!("Дом")));
    let freeze = client.send(&panel, "POST", "/api/clients/grants/g1/freeze", &[("X-CSRF-Token", &csrf)], None);
    assert_eq!(freeze.status, 422);
    let missing = client.send(&panel, "POST", "/api/clients/grants/nope/enable", &[("X-CSRF-Token", &csrf)], None);
    assert_eq!((missing.status, missing.json()), (404, json!({"detail": "grant not found"})));
    let detail = client.send(&panel, "GET", &format!("/api/clients/{id}"), &[], None).json();
    assert_eq!(detail["grants"][0]["label"], "Дом");
}
