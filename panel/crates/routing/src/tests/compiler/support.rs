//! Fixtures shared by the Python compiler/store/preset ports.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use panel_core::db::{Conn, Database};
use panel_core::migrations::apply_migrations;
use panel_managers::xray_router::ROUTER_CAPABILITIES;
use panel_model::protocols::{AppliedDocument, EgressMode, EgressTarget, RouterTarget};
use panel_model::routing::document::{attach_document, document_digest};
use panel_model::routing::models::{
    backend_for, Action, Compiled, DefaultAction, Intent, PolicyInput, Reason, RoutingPolicy, RoutingRule,
};
use panel_model::validate::Model;
use panel_model::Backend;
use serde_json::{json, Map, Value};

use crate::compiler::{self, HopResolver, Lookup, Options};
use crate::intent::ChainHop;

pub const NAIVE_CAPS: &[&str] = &["whole_direct", "whole_warp", "block_domain", "block_cidr"];
pub const MIERU_CAPS: &[&str] =
    &["whole_direct", "whole_warp", "block_domain", "block_cidr", "selective_domain", "selective_cidr"];
pub const GUID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const GUID_C: &str = "cccccccccccccccccccccccccccccccc";

pub fn capabilities(cells: &[&str]) -> BTreeSet<String> {
    cells.iter().map(|cell| (*cell).to_string()).collect()
}

pub fn providers(entries: &[(&str, Option<bool>)]) -> Map<String, Value> {
    entries.iter().map(|(name, reachable)| ((*name).to_string(), json!({"reachable": reachable}))).collect()
}

pub fn applied(revision: &str, document: &Value) -> AppliedDocument {
    AppliedDocument { revision: revision.to_string(), digest: document_digest(document), document: document.clone() }
}

pub fn native_target(protocol: &str) -> EgressTarget {
    let backend = backend_for(protocol).unwrap();
    let cells: &[&str] = match backend {
        Backend::NaiveNative => NAIVE_CAPS,
        Backend::MieruNative => MIERU_CAPS,
        Backend::AmneziawgNative => &["whole_direct", "whole_warp"],
        Backend::MtproxyNative | Backend::TrusttunnelNative => &["whole_direct"],
        Backend::XrayRouter => unreachable!("native target"),
    };
    let mut target = EgressTarget::new(protocol, backend, "rev-a");
    target.capabilities = capabilities(cells);
    target.providers = providers(&[("warp", Some(true))]);
    target.restart_required = backend == Backend::MieruNative;
    target
}

pub fn attached_target(protocol: &str) -> EgressTarget {
    let mut target = native_target(protocol);
    let document = attach_document(protocol).unwrap();
    target.revision = "rev-native".into();
    target.applied = Some(applied("rev-native", &document));
    target.mode = EgressMode::Proxy;
    target.router_attached = true;
    target.providers = providers(&[("warp", Some(true)), ("router", Some(true))]);
    target
}

pub fn router(service: &str) -> RouterTarget {
    RouterTarget {
        available: true,
        service: service.into(),
        capabilities: capabilities(ROUTER_CAPABILITIES),
        providers: providers(&[("warp", Some(true))]),
        revision: "rev-router".into(),
        applied: None,
        xray_version: Some("Xray 26.3.27".into()),
        restart_required: true,
        reason: None,
    }
}

pub fn rule(action: Action, matcher: Value) -> RoutingRule {
    RoutingRule::validate(&json!({"action": action.as_str(), "match": matcher})).unwrap()
}

pub fn egress_rule(matcher: Value, egress: &str) -> RoutingRule {
    RoutingRule::validate(&json!({"action": "egress", "egress": egress, "match": matcher})).unwrap()
}

pub fn policy(protocol: &str, backend: Backend) -> RoutingPolicy {
    RoutingPolicy::validate(&json!({
        "id": "p1",
        "node_id": "local",
        "protocol": protocol,
        "backend": backend.as_str(),
        "revision": 1,
    }))
    .unwrap()
}

pub fn native_policy(protocol: &str) -> RoutingPolicy {
    policy(protocol, backend_for(protocol).unwrap())
}

pub fn router_policy(protocol: &str) -> RoutingPolicy {
    policy(protocol, Backend::XrayRouter)
}

pub fn set_default(policy: &mut RoutingPolicy, action: DefaultAction, egress: Option<&str>) {
    policy.intent.default_action = action;
    policy.intent.default_egress = egress.map(str::to_string);
}

pub fn with_rules(mut policy: RoutingPolicy, rules: Vec<RoutingRule>) -> RoutingPolicy {
    policy.intent.rules = rules;
    policy
}

pub fn input(rules: Vec<RoutingRule>) -> PolicyInput {
    PolicyInput { intent: Intent { rules, ..Intent::default() }, backend: None }
}

pub fn lane(name: &str) -> RoutingPolicy {
    let mut policy = router_policy("naive");
    policy.id = format!("p-{name}");
    policy.lane = name.into();
    policy
}

pub fn compile_native(policy: &RoutingPolicy, target: Option<&EgressTarget>) -> Compiled {
    compiler::compile(policy, target, Options::default()).unwrap()
}

pub fn document(compiled: &Compiled) -> &Value {
    compiled.document.as_ref().unwrap()
}

pub fn codes(compiled: &Compiled) -> Vec<&str> {
    compiled.reasons.iter().map(|reason| reason.code.as_str()).collect()
}

pub fn hop_b() -> ChainHop {
    ChainHop {
        guid: GUID_B.into(),
        address: "panel.node-b.example.org".into(),
        port: 45443,
        server_name: "panel.node-b.example.org".into(),
        public_key: "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s".into(),
        short_id: "0123abcd".into(),
        uuid_direct: "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10".into(),
        uuid_warp: Some("9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e".into()),
    }
}

pub fn hop_c() -> ChainHop {
    ChainHop {
        guid: GUID_C.into(),
        address: "203.0.113.7".into(),
        port: 45443,
        server_name: "panel.node-c.example.org".into(),
        public_key: "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s".into(),
        short_id: "89abcdef".into(),
        uuid_direct: "1b4e4a6b-9a1e-4c8f-8d7e-9a103f0d9c6e".into(),
        uuid_warp: None,
    }
}

pub struct Resolver {
    pub hops: HashMap<String, ChainHop>,
    pub reasons: HashMap<String, Reason>,
}

impl Resolver {
    pub fn new() -> Self {
        Self { hops: HashMap::from([(GUID_B.into(), hop_b()), (GUID_C.into(), hop_c())]), reasons: HashMap::new() }
    }
}

impl HopResolver for Resolver {
    fn resolve(&mut self, guid: &str) -> Lookup<ChainHop> {
        if let Some(reason) = self.reasons.get(guid) {
            return Ok(Err(reason.clone()));
        }
        match self.hops.get(guid) {
            Some(hop) => Ok(Ok(hop.clone())),
            None => Ok(Err(Reason::new("node_unknown", None, format!("no node {guid}")))),
        }
    }
}

/// A fresh temporary directory, removed after its database connections.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "panel-routing-compiler-{label}-{}-{}",
            std::process::id(),
            panel_core::ids::token_hex(6)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn database(&self) -> Database {
        Database::open(self.0.join("panel.sqlite3")).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn migrated(scratch: &Scratch) -> Database {
    let database = scratch.database();
    apply_migrations(&database).unwrap();
    database
}

pub fn database(label: &str) -> (Scratch, Database) {
    let scratch = Scratch::new(label);
    let database = migrated(&scratch);
    let connection = database.connect().unwrap();
    connection
        .execute(
            "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,kind) \
         VALUES('n1','Node','pending','{}',1,1,'remote')",
            [],
        )
        .unwrap();
    connection.commit().unwrap();
    (scratch, database)
}

pub fn count(connection: &Conn, table: &str) -> i64 {
    connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0)).unwrap()
}
