#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::exits::ExitInput;
use crate::lanes::LaneService;
use crate::runtime::RoutingAdapters;
use panel_clients::{store as clients_store, AuditContext};
use panel_core::clock::FakeClock;
use panel_core::db::{Conn, Database};
use panel_model::clients::{
    AccessGrant, GrantDesiredState, GrantObservedState, GrantOrigin, NaiveOptions, ProtocolOptions,
};
use panel_model::protocols::{AdapterError, BoxFuture, ProtocolAdapter};
use panel_model::seams::GenerationPublisher;
use panel_model::validate::Model;
use panel_model::Protocol;
use panel_nodes::NodeRow;
use panel_secrets::audit::Actor;
use panel_secrets::keyring::Keyring;
use panel_secrets::secrets_store::SecretStore;
use serde_json::{json, Map, Value};

pub const GUID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const GUID_C: &str = "cccccccccccccccccccccccccccccccc";
pub const NODE: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
pub const MASTER: &str = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
pub const UUID: &str = "9d3b6b2c-1e6a-4b2a-9f0e-3c2f8a1d5e77";
pub const PUBLIC_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "panel-routing-lanes-exits-{label}-{}-{}",
            std::process::id(),
            panel_core::ids::token_hex(6)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn migrated(label: &str) -> (TempDir, Database) {
    let dir = TempDir::new(label);
    let database = Database::open(dir.join("panel.sqlite3")).unwrap();
    panel_core::migrations::apply_migrations(&database).unwrap();
    (dir, database)
}

pub fn secrets() -> SecretStore {
    SecretStore::new(Some(Keyring::generate()))
}

pub fn exit_input(value: Value) -> ExitInput {
    ExitInput::validate(&value).unwrap()
}

pub fn policy_input(value: Value) -> panel_model::routing::models::PolicyInput {
    panel_model::routing::models::PolicyInput::validate(&value).unwrap()
}

pub fn rule(egress: Option<&str>, action: &str) -> Value {
    json!({"match": {"domains": ["a.example"]}, "action": action, "egress": egress})
}

pub fn insert_node(db: &Conn, node_id: &str) {
    panel_nodes::registry::insert(db, node_id, "Edge", "remote", "panel", 1).unwrap();
}

pub fn node_row(node_id: &str, panel_url: Option<&str>) -> NodeRow {
    let link = panel_url.map(|panel_url| {
        let mut row = Map::new();
        row.insert("panel_url".into(), json!(panel_url));
        row
    });
    NodeRow {
        node_id: node_id.into(),
        display_name: "Edge".into(),
        auth_state: "enrolled".into(),
        created_at: 1,
        updated_at: 1,
        next_sequence: 1,
        last_result_sequence: 0,
        last_seen_at: None,
        kind: if node_id == "local" { "local" } else { "remote" }.into(),
        disabled: false,
        transport: if node_id == "local" { "v1" } else { "panel" }.into(),
        inventory: Map::new(),
        link,
    }
}

pub fn seed_remote_grant(db: &Conn, capabilities: &[&str]) {
    insert_node(db, NODE);
    db.execute(
        "INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,identity_json,created_at,updated_at) \
         VALUES(?,?, 'verify','api-key',?,1,1)",
        panel_core::rusqlite::params![
            NODE,
            "https://node.example",
            serde_json::to_string(&json!({"capabilities": capabilities})).unwrap()
        ],
    )
    .unwrap();
    db.execute(
        "INSERT INTO clients(id,display_name,state,metadata_json,created_at,updated_at) VALUES('c1','A','active','{}',1,1)",
        [],
    )
    .unwrap();
    let grant = AccessGrant {
        protocol: Protocol::Naive,
        options: ProtocolOptions::Naive(NaiveOptions::default()),
        id: "g1".into(),
        client_id: "c1".into(),
        node_id: NODE.into(),
        endpoint_id: "default".into(),
        runtime_username: "alice".into(),
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
    };
    clients_store::insert_grant(db, &grant).unwrap();
}

pub fn context() -> AuditContext {
    AuditContext::new(Actor::new(Some(1), "owner"), "127.0.0.1", Some("req-1".into()))
}

#[derive(Debug)]
pub struct NoAdapters;

impl RoutingAdapters for NoAdapters {
    fn adapter(&self, _protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        None
    }

    fn set_lanes<'a>(&'a self, _protocol: Protocol, _lanes: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async { Err(AdapterError::new("remote lanes do not use local adapters")) })
    }
}

pub fn remote_lanes(database: Database, calls: Arc<Mutex<Vec<String>>>) -> LaneService {
    let publisher: Arc<dyn GenerationPublisher> =
        Arc::new(move |_db: &Conn, node_id: &str| -> Result<Option<i64>, panel_model::seams::SeamError> {
            calls.lock().unwrap().push(node_id.into());
            Ok(Some(7))
        });
    LaneService::new(database, Arc::new(NoAdapters), None, Arc::new(FakeClock::default()), Some(publisher))
}
