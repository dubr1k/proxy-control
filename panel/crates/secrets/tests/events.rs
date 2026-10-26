//! The event bus (`panel/events.py`): the unit part of `panel/tests/test_subscription_events.py`.

mod common;

use std::sync::Arc;

use common::{migrated, TempDir};
use panel_core::clock::FakeClock;
use panel_core::db::DbError;
use panel_core::serde_json::{json, Map, Value};
use panel_secrets::audit::{self, Actor, Record};
use panel_secrets::events::{EventBus, EventError};

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn the_bus_refuses_unknown_names_and_scrubs_payloads() {
    let dir = TempDir::new("bus");
    let database = migrated(&dir);
    let bus = EventBus::new(database.clone());
    let row_id = database
        .transaction(|db| -> Result<i64, EventError> {
            let error = bus.emit(db, "subscription.delivered", &map(json!({"subscription_id": "s1"}))).unwrap_err();
            assert_eq!(error.to_string(), "unknown event name: subscription.delivered");
            bus.emit(
                db,
                "subscription.revoked",
                &map(json!({"subscription_id": "s1", "client_id": "c1", "public_url": "https://x/s/t"})),
            )
        })
        .map_err(|error| error.to_string())
        .unwrap();
    assert!(row_id > 0);
    let recent = bus.recent();
    let last = recent.last().unwrap();
    assert!(!last.contains_key("public_url"));
    assert_eq!(last["subscription_id"], "s1");
    let keys: Vec<&str> = last.keys().map(String::as_str).collect();
    assert_eq!(keys, ["id", "name", "at", "subscription_id", "client_id"]);
    let events = bus.since(0, 100).unwrap();
    assert!(!Value::Array(events.iter().cloned().map(Value::Object).collect()).to_string().contains("public_url"));
    assert_eq!(events[0]["id"], row_id);
}

#[test]
fn the_target_is_the_subscription_or_else_the_node() {
    let dir = TempDir::new("target");
    let database = migrated(&dir);
    let clock = Arc::new(FakeClock::new(1_900_000_000.0));
    let bus = EventBus::with_options(database.clone(), 2, clock.clone());
    database
        .transaction(|db| -> Result<(), EventError> {
            for payload in
                [json!({}), json!({"subscription_id": ""}), json!({"node_id": 5}), json!({"subscription_id": 0})]
            {
                assert!(matches!(bus.emit(db, "node.up", &map(payload)), Err(EventError::NoTarget)));
            }
            bus.emit(db, "node.up", &map(json!({"subscription_id": "", "node_id": "edge-01"})))?;
            bus.emit(db, "node.down", &map(json!({"node_id": "edge-01"})))?;
            clock.advance(5.0);
            bus.emit(db, "subscription.fetched", &map(json!({"subscription_id": "s1", "status": 200})))?;
            Ok(())
        })
        .map_err(|error| error.to_string())
        .unwrap();
    // The ring keeps the last `capacity` events.
    let recent = bus.recent();
    assert_eq!(
        recent.iter().map(|e| e["name"].as_str().unwrap()).collect::<Vec<_>>(),
        ["node.down", "subscription.fetched"]
    );
    assert_eq!(recent[1]["at"], 1_900_000_005);
    let events = bus.since(0, 500).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["node_id"], "edge-01");
    assert!(!events[0].contains_key("subscription_id") || events[0]["subscription_id"] == "");
    assert_eq!(events[2]["subscription_id"], "s1");
    assert_eq!(events[2]["status"], 200);
    assert_eq!(events[2]["at"], 1_900_000_005);
    let keys: Vec<&str> = events[1].keys().map(String::as_str).collect();
    assert_eq!(keys, ["id", "name", "at", "node_id"]);
}

#[test]
fn since_pages_by_id_and_skips_operator_actions() {
    let dir = TempDir::new("since");
    let database = migrated(&dir);
    let bus = EventBus::new(database.clone());
    database
        .transaction(|db| -> Result<(), EventError> {
            for index in 0..4 {
                bus.emit(db, "subscription.fetched", &map(json!({"subscription_id": format!("s{index}")})))?;
                audit::record(
                    db,
                    &Record::new(&Actor::new(Some(1), "owner"), "subscription.create", "s", "127.0.0.1"),
                )?;
            }
            Ok(())
        })
        .map_err(|error| error.to_string())
        .unwrap();
    let first = bus.since(0, 2).unwrap();
    assert_eq!(first.iter().map(|e| e["subscription_id"].as_str().unwrap()).collect::<Vec<_>>(), ["s0", "s1"]);
    let rest = bus.since(first[1]["id"].as_i64().unwrap(), 500).unwrap();
    assert_eq!(rest.iter().map(|e| e["subscription_id"].as_str().unwrap()).collect::<Vec<_>>(), ["s2", "s3"]);
    assert!(rest.iter().all(|e| e["name"] == "subscription.fetched"));
}

#[test]
fn a_rolled_back_transaction_leaves_no_event_row() {
    let dir = TempDir::new("rollback");
    let database = migrated(&dir);
    let bus = EventBus::new(database.clone());
    let result: Result<(), DbError> = database.transaction(|db| {
        bus.emit(db, "subscription.revoked", &map(json!({"subscription_id": "s1"}))).unwrap();
        Err(DbError::Sqlite(panel_core::rusqlite::Error::InvalidQuery))
    });
    assert!(result.is_err());
    assert!(bus.since(0, 10).unwrap().is_empty());
}
