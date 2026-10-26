//! The service layer against what the Python panel made of the same database
//! (`tests/fixtures/nodes.db` + `nodes.json`, recorded by `generators/gen_nodes.py`).

mod common;

use common::{fixture_database, fixture_json, service_at, table, TempDir};
use panel_core::db::row_to_json;
use panel_core::pyjson;
use panel_core::serde_json::{Map, Value};
use panel_nodes::read_model::view_to_value;
use panel_nodes::registry::{self, AuditContext};
use panel_nodes::service::{cli_node_list, NodeLifecycleService};
use panel_nodes::{NodeView, NodesError};
use panel_secrets::audit::Actor;

fn bytes(value: &Value) -> String {
    pyjson::compact_utf8(value)
}

fn view_bytes(view: &NodeView) -> String {
    bytes(&view_to_value(view))
}

/// The recorded outcome of a call (`{"ok": …}` or `{"error": class, "message"?: …}`).
fn outcome<T>(result: Result<T, NodesError>, ok: impl FnOnce(T) -> Value) -> Value {
    let mut out = Map::new();
    match result {
        Ok(value) => {
            out.insert("ok".into(), ok(value));
        }
        Err(NodesError::NotFound(_)) => {
            out.insert("error".into(), "KeyError".into());
        }
        Err(error) if error.is_integrity() => {
            out.insert("error".into(), "IntegrityError".into());
        }
        Err(NodesError::Conflict(message)) => {
            out.insert("error".into(), "NodeConflict".into());
            out.insert("message".into(), message.into());
        }
        Err(NodesError::Protocol(message)) => {
            out.insert("error".into(), "ProtocolError".into());
            out.insert("message".into(), message.into());
        }
        Err(other) => panic!("unexpected failure {other}"),
    }
    Value::Object(out)
}

struct Golden {
    _dir: TempDir,
    service: NodeLifecycleService,
    golden: Value,
}

fn golden(label: &str) -> Golden {
    let dir = TempDir::new(label);
    let golden = fixture_json("nodes.json");
    let now = golden["now"].as_i64().unwrap();
    let service = service_at(fixture_database("nodes.db", &dir), now);
    Golden { _dir: dir, service, golden }
}

fn node_ids(golden: &Value) -> Vec<String> {
    golden["node_ids"].as_array().unwrap().iter().map(|id| id.as_str().unwrap().to_string()).collect()
}

#[test]
fn views_are_byte_identical() {
    let Golden { _dir, service, golden } = golden("views");
    let views = service.list().unwrap();
    assert_eq!(bytes(&Value::Array(views.iter().map(view_to_value).collect())), golden["list"].as_str().unwrap());
    for (node_id, expected) in golden["get"].as_object().unwrap() {
        let got = outcome(service.get(node_id), |view| Value::String(view_bytes(&view)));
        assert_eq!(&got, expected, "{node_id}");
    }
}

#[test]
fn cli_node_list_is_byte_identical() {
    let Golden { _dir, service, golden } = golden("cli");
    assert_eq!(cli_node_list(&service.list().unwrap()), golden["cli_node_list"].as_str().unwrap());
}

#[test]
fn registry_rows_and_counts_match() {
    let Golden { _dir, service, golden } = golden("rows");
    let db = service.database().connect().unwrap();
    let rows: Vec<Value> = registry::rows(&db).unwrap().iter().map(|row| row.to_value()).collect();
    assert_eq!(bytes(&Value::Array(rows)), golden["rows"].as_str().unwrap());
    for node_id in node_ids(&golden) {
        assert_eq!(bytes(&registry::row(&db, &node_id).unwrap().to_value()), golden["row"][&node_id].as_str().unwrap());
    }
    let mut statement = db.prepare("SELECT * FROM node_links ORDER BY node_id").unwrap();
    let links: Vec<Value> = statement
        .query_map([], row_to_json)
        .unwrap()
        .map(|row| Value::Object(registry::link_row(row.unwrap()).unwrap()))
        .collect();
    assert_eq!(bytes(&Value::Array(links)), golden["link_rows"].as_str().unwrap());
    for (node_id, counts) in golden["counts"].as_object().unwrap() {
        assert_eq!(
            registry::active_grants(&db, node_id).unwrap(),
            counts["active_grants"].as_i64().unwrap(),
            "{node_id}"
        );
        assert_eq!(
            registry::provisioned_grants(&db, node_id).unwrap(),
            counts["provisioned_grants"].as_i64().unwrap(),
            "{node_id}"
        );
        assert_eq!(
            registry::pending_commands(&db, node_id).unwrap(),
            counts["pending_commands"].as_i64().unwrap(),
            "{node_id}"
        );
    }
}

fn context(step: &Value) -> AuditContext {
    let actor = &step["actor"];
    AuditContext::new(
        Actor::new(actor.get("id").and_then(Value::as_i64), actor["username"].as_str().unwrap()),
        step["ip"].as_str().unwrap(),
        step["request_id"].as_str().map(str::to_string),
    )
}

#[test]
fn mutations_inserts_and_their_rows_match() {
    let Golden { _dir, service, golden } = golden("mutations");
    let now = golden["now"].as_i64().unwrap();
    for step in golden["mutations"].as_array().unwrap() {
        let node_id = step["node_id"].as_str().unwrap();
        let got = match step["op"].as_str().unwrap() {
            "rename" => service.rename(node_id, step["value"].as_str().unwrap(), &context(step)),
            "set_disabled" => service.set_disabled(node_id, step["value"].as_bool().unwrap(), &context(step)),
            other => panic!("unknown step {other}"),
        };
        assert_eq!(outcome(got, |view| Value::String(view_bytes(&view))), step["result"], "{step}");
    }
    for case in golden["inserts"].as_array().unwrap() {
        let got = service.database().transaction(|db| {
            registry::insert(
                db,
                case["node_id"].as_str().unwrap(),
                case["display_name"].as_str().unwrap(),
                case["kind"].as_str().unwrap(),
                case["transport"].as_str().unwrap(),
                now,
            )
        });
        assert_eq!(outcome(got, |()| Value::Null), case["result"], "{case}");
    }
    let after = &golden["after"];
    let database = service.database();
    assert_eq!(
        table(database, "SELECT * FROM fleet_nodes ORDER BY node_id"),
        after["fleet_nodes"].as_array().unwrap().clone()
    );
    assert_eq!(
        table(database, "SELECT node_id,enabled,updated_at FROM node_links ORDER BY node_id"),
        after["node_links"].as_array().unwrap().clone()
    );
    assert_eq!(table(database, "SELECT * FROM audit_log ORDER BY id"), after["audit_log"].as_array().unwrap().clone());
}
