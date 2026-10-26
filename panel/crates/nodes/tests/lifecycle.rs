//! Node lifecycle (`panel/tests/test_node_lifecycle.py`, the parts fleet v1's retirement leaves):
//! an operator-facing façade whose every mutation commits with its audit row.

mod common;

use common::{migrated, service_at, TempDir, NOW};
use panel_core::db::Database;
use panel_nodes::registry::{self, AuditContext};
use panel_nodes::{NodesError, LOCAL_NODE_ID};
use panel_secrets::audit::Actor;

fn ctx() -> AuditContext {
    AuditContext::new(Actor::new(Some(1), "owner"), "127.0.0.1", Some("req-1".into()))
}

/// What `service.register` did for the tests' setup: a v1 row through the registry.
fn add_node(database: &Database, node_id: &str, display_name: &str) {
    database.transaction(|db| registry::insert(db, node_id, display_name, "remote", "v1", NOW)).unwrap();
}

fn count(database: &Database, sql: &str) -> i64 {
    database.connect().unwrap().query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn disable_refuses_while_commands_are_pending() {
    let dir = TempDir::new("pending");
    let database = migrated(&dir);
    add_node(&database, "edge-01", "Edge");
    // A command a retired v1 node never fetched (what `fleet.enqueue` wrote).
    database
        .connect()
        .unwrap()
        .raw()
        .execute(
            "INSERT INTO fleet_commands(command_id,node_id,sequence,idempotency_key,protocol_version,operation,
             expected_revision,payload_json,status,created_at,actor,expires_at,payload_sha256)
             VALUES('00000000-0000-4000-8000-000000000001','edge-01',1,'disable-alice-1',1,'telemt.user.disable',
             'rev-1','{\"username\":\"alice\"}','queued',1,'system',2,'')",
            [],
        )
        .unwrap();
    let service = service_at(database, NOW);
    match service.set_disabled("edge-01", true, &ctx()) {
        Err(NodesError::Conflict(message)) => assert!(message.contains("pending"), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn local_node_has_no_transport_certificates_or_disable() {
    let dir = TempDir::new("local");
    let service = service_at(migrated(&dir), NOW);
    // Migration 5 put the row there: the service never has to create it.
    let view = service.local().unwrap();
    assert_eq!((view.node_id.as_str(), view.kind.as_str()), (LOCAL_NODE_ID, "local"));
    assert_eq!((view.enrollment_state.as_str(), view.connectivity_state.as_str()), ("local", "not_applicable"));
    assert!(view.certificates.is_empty() && view.pending_commands == 0);
    match service.set_disabled("local", true, &ctx()) {
        Err(NodesError::Conflict(message)) => assert!(message.contains("local node"), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn local_node_is_listed_first_and_can_be_renamed() {
    let dir = TempDir::new("order");
    let database = migrated(&dir);
    add_node(&database, "edge-01", "Edge");
    add_node(&database, "aaa-01", "Aaa");
    let service = service_at(database, NOW);
    // Sorted by node_id the local row would land last; the operator's own host comes first.
    let order: Vec<String> = service.list().unwrap().into_iter().map(|view| view.node_id).collect();
    assert_eq!(order, ["local", "aaa-01", "edge-01"]);
    service.rename("local", "Амстердам", &ctx()).unwrap();
    assert_eq!(service.local().unwrap().display_name, "Амстердам");
}

#[test]
fn the_local_node_id_cannot_be_registered_again() {
    let dir = TempDir::new("reserved");
    let database = migrated(&dir);
    let refused = database.transaction(|db| registry::insert(db, "local", "Impostor", "remote", "v1", NOW));
    match refused {
        Err(NodesError::Protocol(message)) => assert!(message.contains("reserved"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(service_at(database, NOW).local().unwrap().display_name, "Этот сервер");
}

#[test]
fn a_failed_mutation_leaves_neither_row_nor_audit() {
    let dir = TempDir::new("atomic");
    let database = migrated(&dir);
    add_node(&database, "edge-01", "Edge");
    // A duplicate registration fails inside its transaction (an IntegrityError in Python).
    let duplicate = database.transaction(|db| {
        registry::insert(db, "edge-01", "Duplicate", "remote", "v1", NOW)?;
        ctx().record(db, "node.register", "edge-01", None, NOW)
    });
    assert!(duplicate.unwrap_err().is_integrity());
    // A refused disable writes nothing either: a grant still points at the node.
    database
        .connect()
        .unwrap()
        .execute_batch(
            "INSERT INTO clients(id,display_name,state,metadata_json,created_at,updated_at)
               VALUES('client-1','Alice','active','{}',1,1);
             INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,
               created_at,updated_at) VALUES('grant-1','client-1','mtproxy','edge-01','alice','enabled','provisioned',1,1);",
        )
        .unwrap();
    let service = service_at(database.clone(), NOW);
    match service.set_disabled("edge-01", true, &ctx()) {
        Err(NodesError::Conflict(message)) => assert_eq!(message, "node still carries active grants"),
        other => panic!("{other:?}"),
    }
    // One registered node next to the reserved local row, no audit line, still enabled.
    assert_eq!(count(&database, "SELECT count(*) FROM fleet_nodes WHERE kind='remote'"), 1);
    assert_eq!(count(&database, "SELECT count(*) FROM audit_log"), 0);
    assert_eq!(count(&database, "SELECT disabled FROM fleet_nodes WHERE node_id='edge-01'"), 0);
}

#[test]
fn a_linked_panel_is_paused_not_disabled() {
    let dir = TempDir::new("pause");
    let database = migrated(&dir);
    database.transaction(|db| registry::insert(db, "node-a", "Linked", "remote", "panel", NOW)).unwrap();
    database
        .connect()
        .unwrap()
        .raw()
        .execute(
            "INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,created_at,updated_at)
             VALUES('node-a','https://node-a.example','verify','node-key:node-a:00000000',1,1)",
            [],
        )
        .unwrap();
    let service = service_at(database.clone(), NOW);
    let view = service.set_disabled("node-a", true, &ctx()).unwrap();
    assert!(view.disabled && view.link.as_ref().unwrap()["enabled"] == panel_core::serde_json::Value::Bool(false));
    assert_eq!(count(&database, "SELECT disabled FROM fleet_nodes WHERE node_id='node-a'"), 0);
    assert_eq!(count(&database, "SELECT count(*) FROM audit_log WHERE action='node.pause'"), 1);
    assert!(!service.set_disabled("node-a", false, &ctx()).unwrap().disabled);
    assert_eq!(count(&database, "SELECT count(*) FROM audit_log WHERE action='node.resume'"), 1);
}

#[test]
fn unknown_nodes_are_not_found() {
    let dir = TempDir::new("ghost");
    let service = service_at(migrated(&dir), NOW);
    assert!(matches!(service.get("ghost"), Err(NodesError::NotFound(_))));
    assert!(matches!(service.rename("ghost", "x", &ctx()), Err(NodesError::NotFound(_))));
    assert!(matches!(service.set_disabled("ghost", true, &ctx()), Err(NodesError::NotFound(_))));
    // The name is checked before the node is looked up (422 before 404, as in Python).
    assert!(matches!(service.rename("ghost", "  ", &ctx()), Err(NodesError::Protocol(_))));
}
