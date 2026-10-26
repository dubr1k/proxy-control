//! The Python adapters' unit tests, replayed against the Rust adapters.
//!
//! `fixtures/record_transcripts.py` ran the Python tests that drive an adapter
//! (`test_protocol_adapter_contract.py`, `test_egress_adapters.py`, `test_trusttunnel.py`, …) and
//! recorded, per test, every top-level adapter call (arguments, result or error) and every call
//! each adapter made to its client (arguments, answer or error), plus what the Telemt bridge probe
//! was asked and the Telemt egress journal before and after each call. Each Rust test replays one
//! transcript: the same adapter calls, against clients that check every call the Rust adapter
//! makes (method, positional and keyword arguments as the Python call site passes them) and hand
//! back the recorded answer. The results, the errors, the journal and the set of client calls must
//! match exactly. The in-memory `Memory*` fakes stay Python: their behaviour is in the recordings.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use panel_managers::{Manager, ManagerError, TelemtAccess, TelemtError};
use panel_model::clients::{AccessGrant, GrantIntent};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{
    AccessArtifact, AdapterError, AppliedEgress, AppliedGrant, CredentialPlan, EgressTarget, GrantRef,
    ObservedInventory, Preflight, RouterTarget,
};
use panel_model::validate::Model;
use panel_model::Protocol;
use panel_protocols::api::{
    AmneziawgApi, ManagerResult, MieruApi, NaiveApi, RouterApi, TelemtApi, TelemtResult, TrusttunnelApi,
};
use panel_protocols::error::runtime_failure;
use panel_protocols::telemt::BridgeProbe;
use panel_protocols::xray_router::GeodataAction;
use panel_protocols::{AmneziawgAdapter, MieruAdapter, NaiveAdapter, RouterAdapter, TelemtAdapter, TrusttunnelAdapter};
use serde_json::{json, Map, Value};

include!("fixtures/transcript_cases.rs");

fn transcripts() -> &'static HashMap<String, Value> {
    static TRANSCRIPTS: OnceLock<HashMap<String, Value>> = OnceLock::new();
    TRANSCRIPTS.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transcripts.json");
        let all: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        all.into_iter().map(|item| (item["test"].as_str().unwrap().to_string(), item)).collect()
    })
}

type Queues = Arc<Mutex<HashMap<String, VecDeque<Value>>>>;

/// A client that answers from the transcript, checking each call against the recorded one.
#[derive(Clone)]
struct Replay {
    id: String,
    queues: Queues,
}

const ERROR_CLASSES: &[&str] = &[
    "NaiveError",
    "MieruError",
    "AmneziawgError",
    "TrusttunnelError",
    "XrayRouterError",
    "TelemtError",
    "TelemtIndeterminate",
];

impl Replay {
    fn next(&self, method: &str, args: Value, kwargs: Value) -> Result<Value, Value> {
        let event = self
            .queues
            .lock()
            .unwrap()
            .get_mut(&self.id)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| panic!("{}: unexpected call {method} {args} {kwargs}", self.id));
        assert_eq!(
            event["method"],
            json!(method),
            "{}: expected {} but the adapter called {method}",
            self.id,
            event["method"]
        );
        assert_eq!(event["args"], args, "{}: positional arguments of {method}", self.id);
        assert_eq!(event["kwargs"], kwargs, "{}: keyword arguments of {method}", self.id);
        match event.get("error") {
            Some(error) => {
                let class = error["class"].as_str().unwrap_or_default();
                assert!(
                    ERROR_CLASSES.contains(&class)
                        || error["indeterminate"] == json!(true)
                        || error.get("status_code").is_some(),
                    "{}: the fake raised {error}, which no Rust client can",
                    self.id
                );
                Err(error.clone())
            }
            None => Ok(event["result"].clone()),
        }
    }

    fn manager(&self, manager: Manager, method: &str, args: Value, kwargs: Value) -> ManagerResult {
        self.next(method, args, kwargs).map_err(|error| {
            let status = error["status_code"].as_u64().unwrap_or(502) as u16;
            ManagerError::new(manager, error["message"].as_str().unwrap_or_default(), status, error["code"].as_str())
        })
    }

    fn telemt(&self, method: &str, args: Value, kwargs: Value) -> TelemtResult {
        self.next(method, args, kwargs).map_err(|error| TelemtError {
            message: error["message"].as_str().unwrap_or_default().to_string(),
            status_code: error["status_code"].as_u64().unwrap_or(502) as u16,
            indeterminate: error["indeterminate"] == json!(true),
        })
    }
}

fn none() -> Value {
    json!({})
}

impl NaiveApi for Replay {
    async fn list_users(&self) -> ManagerResult {
        self.manager(Manager::Naive, "list_users", json!([]), none())
    }
    async fn create(
        &self,
        username: &str,
        quota_bytes: Option<i64>,
        password: &str,
        operation_id: &str,
    ) -> ManagerResult {
        let kwargs = json!({"password": password, "operation_id": operation_id});
        self.manager(Manager::Naive, "create", json!([username, quota_bytes]), kwargs)
    }
    async fn reveal(&self, username: &str) -> ManagerResult {
        self.manager(Manager::Naive, "reveal", json!([username]), none())
    }
    async fn rotate(&self, username: &str, password: &str, operation_id: &str) -> ManagerResult {
        let kwargs = json!({"password": password, "operation_id": operation_id});
        self.manager(Manager::Naive, "rotate", json!([username]), kwargs)
    }
    async fn set_enabled(&self, username: &str, enabled: bool) -> ManagerResult {
        self.manager(Manager::Naive, "set_enabled", json!([username, enabled]), none())
    }
    async fn set_quota(&self, username: &str, quota_bytes: &Value) -> ManagerResult {
        self.manager(Manager::Naive, "set_quota", json!([username, quota_bytes]), none())
    }
    async fn delete(&self, username: &str) -> ManagerResult {
        self.manager(Manager::Naive, "delete", json!([username]), none())
    }
    async fn egress(&self) -> ManagerResult {
        self.manager(Manager::Naive, "egress", json!([]), none())
    }
    async fn egress_plan(&self, expected_revision: &str, document: &Value) -> ManagerResult {
        self.manager(Manager::Naive, "egress_plan", json!([expected_revision, document]), none())
    }
    async fn egress_apply(&self, expected_revision: &str, document: &Value, operation_id: &str) -> ManagerResult {
        self.manager(Manager::Naive, "egress_apply", json!([expected_revision, document, operation_id]), none())
    }
    async fn egress_rollback(&self, expected_revision: &str) -> ManagerResult {
        self.manager(Manager::Naive, "egress_rollback", json!([expected_revision]), none())
    }
    async fn lanes(&self) -> ManagerResult {
        self.manager(Manager::Naive, "lanes", json!([]), none())
    }
    async fn set_lanes(&self, lanes: &Value) -> ManagerResult {
        self.manager(Manager::Naive, "set_lanes", json!([lanes]), none())
    }
}

impl MieruApi for Replay {
    async fn health(&self) -> ManagerResult {
        self.manager(Manager::Mieru, "health", json!([]), none())
    }
    async fn list_users(&self) -> ManagerResult {
        self.manager(Manager::Mieru, "list_users", json!([]), none())
    }
    async fn create(&self, payload: &Value) -> ManagerResult {
        self.manager(Manager::Mieru, "create", json!([payload]), none())
    }
    async fn operation(&self, username: &str, operation: &str, revision: &Value) -> ManagerResult {
        self.manager(Manager::Mieru, "operation", json!([username, operation, revision]), none())
    }
    async fn rotate(&self, username: &str, revision: &Value, password: &str, operation_id: &str) -> ManagerResult {
        let kwargs = json!({"password": password, "operation_id": operation_id});
        self.manager(Manager::Mieru, "rotate", json!([username, revision]), kwargs)
    }
    async fn delete(&self, username: &str, revision: &Value) -> ManagerResult {
        self.manager(Manager::Mieru, "delete", json!([username, revision]), none())
    }
    async fn set_quotas(&self, username: &str, payload: &Value) -> ManagerResult {
        self.manager(Manager::Mieru, "set_quotas", json!([username, payload]), none())
    }
    async fn egress(&self) -> ManagerResult {
        self.manager(Manager::Mieru, "egress", json!([]), none())
    }
    async fn egress_plan(&self, expected_revision: &str, document: &Value) -> ManagerResult {
        self.manager(Manager::Mieru, "egress_plan", json!([expected_revision, document]), none())
    }
    async fn egress_apply(&self, expected_revision: &str, document: &Value, operation_id: &str) -> ManagerResult {
        self.manager(Manager::Mieru, "egress_apply", json!([expected_revision, document, operation_id]), none())
    }
    async fn egress_rollback(&self, expected_revision: &str) -> ManagerResult {
        self.manager(Manager::Mieru, "egress_rollback", json!([expected_revision]), none())
    }
    async fn lanes(&self) -> ManagerResult {
        self.manager(Manager::Mieru, "lanes", json!([]), none())
    }
    async fn set_lanes(&self, lanes: &Value) -> ManagerResult {
        self.manager(Manager::Mieru, "set_lanes", json!([lanes]), none())
    }
}

impl AmneziawgApi for Replay {
    async fn instances(&self) -> ManagerResult {
        self.manager(Manager::Amneziawg, "instances", json!([]), none())
    }
    async fn peers(&self) -> ManagerResult {
        self.manager(Manager::Amneziawg, "peers", json!([]), none())
    }
    async fn create_peer(&self, payload: &Value) -> ManagerResult {
        self.manager(Manager::Amneziawg, "create_peer", json!([payload]), none())
    }
    async fn peer_state(&self, username: &str, action: &str) -> ManagerResult {
        self.manager(Manager::Amneziawg, "peer_state", json!([username, action]), none())
    }
    async fn rotate_peer(&self, username: &str, payload: &Value) -> ManagerResult {
        self.manager(Manager::Amneziawg, "rotate_peer", json!([username, payload]), none())
    }
    async fn delete_peer(&self, username: &str) -> ManagerResult {
        self.manager(Manager::Amneziawg, "delete_peer", json!([username]), none())
    }
    async fn egress(&self) -> ManagerResult {
        self.manager(Manager::Amneziawg, "egress", json!([]), none())
    }
    async fn egress_plan(&self, expected_revision: &str, document: &Value) -> ManagerResult {
        self.manager(Manager::Amneziawg, "egress_plan", json!([expected_revision, document]), none())
    }
    async fn egress_apply(&self, expected_revision: &str, document: &Value, operation_id: &str) -> ManagerResult {
        self.manager(Manager::Amneziawg, "egress_apply", json!([expected_revision, document, operation_id]), none())
    }
    async fn egress_rollback(&self, expected_revision: &str) -> ManagerResult {
        self.manager(Manager::Amneziawg, "egress_rollback", json!([expected_revision]), none())
    }
}

impl TrusttunnelApi for Replay {
    async fn endpoint(&self) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "endpoint", json!([]), none())
    }
    async fn clients(&self) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "clients", json!([]), none())
    }
    async fn create_client(&self, payload: &Value) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "create_client", json!([payload]), none())
    }
    async fn client_state(&self, username: &str, action: &str) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "client_state", json!([username, action]), none())
    }
    async fn rotate_client(&self, username: &str, payload: &Value) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "rotate_client", json!([username, payload]), none())
    }
    async fn delete_client(&self, username: &str) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "delete_client", json!([username]), none())
    }
    async fn egress(&self) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "egress", json!([]), none())
    }
    async fn egress_plan(&self, document: &Value) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "egress_plan", json!([document]), none())
    }
    async fn egress_apply(&self, document: &Value) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "egress_apply", json!([document]), none())
    }
    async fn egress_rollback(&self) -> ManagerResult {
        self.manager(Manager::Trusttunnel, "egress_rollback", json!([]), none())
    }
}

impl RouterApi for Replay {
    async fn status(&self) -> ManagerResult {
        self.manager(Manager::XrayRouter, "status", json!([]), none())
    }
    async fn egress(&self, service: &str) -> ManagerResult {
        self.manager(Manager::XrayRouter, "egress", json!([service]), none())
    }
    async fn egress_plan(&self, service: &str, expected_revision: &str, document: &Value) -> ManagerResult {
        self.manager(Manager::XrayRouter, "egress_plan", json!([service, expected_revision, document]), none())
    }
    async fn egress_apply(
        &self,
        service: &str,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> ManagerResult {
        let args = json!([service, expected_revision, document, operation_id]);
        self.manager(Manager::XrayRouter, "egress_apply", args, none())
    }
    async fn egress_rollback(&self, service: &str, expected_revision: &str) -> ManagerResult {
        self.manager(Manager::XrayRouter, "egress_rollback", json!([service, expected_revision]), none())
    }
    async fn lanes(&self, service: &str) -> ManagerResult {
        self.manager(Manager::XrayRouter, "lanes", json!([service]), none())
    }
    async fn lane_issue(&self, service: &str, lane: &str) -> ManagerResult {
        self.manager(Manager::XrayRouter, "lane_issue", json!([service, lane]), none())
    }
    async fn lane_forget(&self, service: &str, lane: &str) -> ManagerResult {
        self.manager(Manager::XrayRouter, "lane_forget", json!([service, lane]), none())
    }
    async fn relay(&self) -> ManagerResult {
        self.manager(Manager::XrayRouter, "relay", json!([]), none())
    }
    async fn ingress(&self, service: &str) -> ManagerResult {
        self.manager(Manager::XrayRouter, "ingress", json!([service]), none())
    }
    async fn relay_enable(&self, server_name: &str, port: i64) -> ManagerResult {
        self.manager(Manager::XrayRouter, "relay_enable", json!([server_name, port]), none())
    }
    async fn relay_disable(&self) -> ManagerResult {
        self.manager(Manager::XrayRouter, "relay_disable", json!([]), none())
    }
    async fn relay_set_accounts(&self, accounts: &Value) -> ManagerResult {
        self.manager(Manager::XrayRouter, "relay_set_accounts", json!([accounts]), none())
    }
    async fn exit_test(&self, spec: &Value) -> ManagerResult {
        self.manager(Manager::XrayRouter, "exit_test", json!([spec]), none())
    }
    async fn geodata(&self) -> ManagerResult {
        self.manager(Manager::XrayRouter, "geodata", json!([]), none())
    }
    async fn geodata_codes(&self) -> ManagerResult {
        self.manager(Manager::XrayRouter, "geodata_codes", json!([]), none())
    }
    async fn geodata_settings(&self, body: &Value) -> ManagerResult {
        self.manager(Manager::XrayRouter, "geodata_settings", json!([body]), none())
    }
    async fn geodata_update(&self) -> ManagerResult {
        self.manager(Manager::XrayRouter, "geodata_update", json!([]), none())
    }
    async fn geodata_restore(&self) -> ManagerResult {
        self.manager(Manager::XrayRouter, "geodata_restore", json!([]), none())
    }
}

fn access_of(value: &Value) -> Option<TelemtAccess> {
    let access = value.as_object()?;
    Some(TelemtAccess {
        link: access["link"].as_str().unwrap_or_default().to_string(),
        secret: access["secret"].as_str().map(str::to_string),
        server: access["server"].as_str().map(str::to_string),
        port: access["port"].as_u64().map(|port| port as u16),
    })
}

fn pair(value: Value) -> (Value, Value) {
    match value {
        Value::Array(mut items) if items.len() == 2 => {
            let second = items.pop().unwrap();
            (items.pop().unwrap(), second)
        }
        other => panic!("a (data, revision) pair was recorded as {other}"),
    }
}

impl TelemtApi for Replay {
    type Batch = ();

    fn batch(&self) {}

    async fn list_users(&self) -> TelemtResult {
        self.telemt("list_users", json!([]), none())
    }
    async fn create_user(&self, username: &str, secret: Option<&str>) -> TelemtResult {
        self.telemt("create_user", json!([username]), json!({"secret": secret}))
    }
    async fn delete_user(&self, username: &str) -> TelemtResult {
        self.telemt("delete_user", json!([username]), none())
    }
    async fn set_enabled(&self, username: &str, enabled: bool) -> TelemtResult {
        self.telemt("set_enabled", json!([username, enabled]), none())
    }
    async fn rotate(&self, username: &str, secret: Option<&str>) -> TelemtResult {
        self.telemt("rotate", json!([username]), json!({"secret": secret}))
    }
    async fn update_user(&self, username: &str, fields: &Value) -> TelemtResult {
        self.telemt("update_user", json!([username, fields]), none())
    }
    async fn current_access(&self, username: &str) -> TelemtResult<Option<TelemtAccess>> {
        Ok(access_of(&self.telemt("current_access", json!([username]), none())?))
    }
    async fn config(&self) -> TelemtResult<(Value, Value)> {
        Ok(pair(self.telemt("config", json!([]), none())?))
    }
    async fn patch_config(&self, body: &Value, revision: &str) -> TelemtResult<(Value, Value)> {
        Ok(pair(self.telemt("patch_config", json!([body, revision]), none())?))
    }
    async fn reload(&self, revision: &Value) -> TelemtResult {
        self.telemt("reload", json!([revision]), none())
    }
    async fn reload_status(&self, reload_id: &Value) -> TelemtResult {
        self.telemt("reload_status", json!([reload_id]), none())
    }
}

// ---- building the adapters a transcript names --------------------------------------------------

enum Built {
    Naive(NaiveAdapter<Replay>),
    Mieru(MieruAdapter<Replay>),
    Amneziawg(AmneziawgAdapter<Replay>),
    Trusttunnel(TrusttunnelAdapter<Replay, Replay>),
    Telemt(Box<TelemtAdapter<Replay, Replay>>, Option<TempDir>),
    Router(Arc<RouterAdapter<Replay>>),
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).unwrap();
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("wp6-journal-{name}"));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Stage {
    queues: Queues,
    probes: HashMap<String, Arc<Mutex<VecDeque<Value>>>>,
    routers: HashMap<String, Arc<RouterAdapter<Replay>>>,
    adapters: HashMap<String, (Value, Built)>,
}

impl Stage {
    fn client(&self, id: &Value) -> Replay {
        Replay { id: id.as_str().unwrap().to_string(), queues: self.queues.clone() }
    }

    fn router(&mut self, state: &Value) -> Option<Arc<RouterAdapter<Replay>>> {
        let id = state.get("router")?.as_str()?.to_string();
        let client = self.client(&state["router_client"]);
        Some(self.routers.entry(id).or_insert_with(|| Arc::new(RouterAdapter::new(client))).clone())
    }

    fn probe(&mut self, adapter: &str) -> BridgeProbe {
        let queue = self.probes.entry(adapter.to_string()).or_default().clone();
        let name = adapter.to_string();
        Arc::new(move |ingress: Value| {
            let event = queue.lock().unwrap().pop_front().unwrap_or_else(|| panic!("{name}: unexpected bridge probe"));
            assert_eq!(event["ingress"], ingress, "{name}: the bridge probe was asked about another ingress");
            let reachable = event["result"] == json!(true);
            Box::pin(async move { reachable })
        })
    }

    fn build(&mut self, adapter: &str, state: &Value) -> Built {
        let client = self.client(&state["client"]);
        let text = |key: &str| state[key].as_str().unwrap_or_default().to_string();
        match state["class"].as_str().unwrap() {
            "NaiveAdapter" => Built::Naive(NaiveAdapter::new(client, text("public_host"))),
            "MieruAdapter" => {
                Built::Mieru(MieruAdapter::new(client, text("public_host")).with_port(state["port"].as_i64().unwrap()))
            }
            "AmneziawgAdapter" => Built::Amneziawg(AmneziawgAdapter::new(client, text("public_host"))),
            "TrusttunnelAdapter" => {
                let router = self.router(state);
                Built::Trusttunnel(TrusttunnelAdapter::new(client, text("public_host")).with_router(router))
            }
            "TelemtAdapter" => {
                let router = self.router(state);
                let journal = (state["journal"] == json!("file")).then(TempDir::new);
                let seconds = |key: &str| Duration::from_secs_f64(state[key].as_f64().unwrap());
                let built = TelemtAdapter::new(client)
                    .with_public_host(text("public_host"))
                    .with_public_port(state["public_port"].as_i64().unwrap())
                    .with_router(router)
                    .with_journal_path(journal.as_ref().map(|dir| dir.0.join("telemt-egress.json")))
                    .with_bridge_probe(self.probe(adapter))
                    .with_reload_timing(seconds("reload_timeout"), seconds("reload_poll"));
                Built::Telemt(Box::new(built), journal)
            }
            "RouterAdapter" => {
                let id = adapter.to_string();
                Built::Router(self.routers.entry(id).or_insert_with(|| Arc::new(RouterAdapter::new(client))).clone())
            }
            other => panic!("no adapter class {other}"),
        }
    }
}

// ---- arguments and results in the recorder's encoding -------------------------------------------

fn bytes(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(value["$bytes"].as_str().unwrap()).unwrap()
}

fn enc_bytes(value: &[u8]) -> Value {
    json!({"$bytes": base64::engine::general_purpose::STANDARD.encode(value)})
}

fn intent(value: &Value) -> GrantIntent {
    GrantIntent::validate(&value["data"]).unwrap()
}

fn access_grant(value: &Value) -> AccessGrant {
    AccessGrant::validate(&value["data"]).unwrap()
}

fn grant_ref(value: &Value) -> GrantRef {
    GrantRef {
        protocol: Protocol::from_wire(value["protocol"].as_str().unwrap()).unwrap(),
        runtime_username: value["runtime_username"].as_str().unwrap().to_string(),
        revision: value["revision"].as_str().map(str::to_string),
    }
}

fn credential(value: &Value) -> CredentialPlan {
    let origin = CredentialOrigin::from_wire(value["origin"].as_str().unwrap()).unwrap();
    let plaintext = (!value["plaintext"].is_null()).then(|| bytes(&value["plaintext"]));
    CredentialPlan::new(origin, plaintext).unwrap()
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn enc_applied(applied: &AppliedGrant) -> Value {
    json!({"$dc": "AppliedGrant", "runtime_username": applied.runtime_username, "enabled": applied.enabled,
           "credential": applied.credential.as_deref().map(enc_bytes), "revision": applied.revision,
           "artifact_template": applied.artifact_template, "recovered": applied.recovered,
           "credential_origin": applied.credential_origin.as_str()})
}

fn enc_inventory(inventory: &ObservedInventory) -> Value {
    let items: Vec<Value> = inventory
        .items
        .iter()
        .map(|item| {
            json!({"$dc": "ObservedGrant", "runtime_username": item.runtime_username, "enabled": item.enabled,
                   "options": item.options, "revision": item.revision})
        })
        .collect();
    json!({"$dc": "ObservedInventory", "items": items})
}

fn enc_preflight(preflight: &Preflight) -> Value {
    json!({"$dc": "Preflight", "ok": preflight.ok, "reason": preflight.reason})
}

fn enc_artifacts(artifacts: &[AccessArtifact]) -> Value {
    artifacts
        .iter()
        .map(|item| {
            json!({"$dc": "AccessArtifact", "kind": item.kind, "label": item.label, "media_type": item.media_type,
                   "value": item.value, "auto_refresh": item.auto_refresh.as_str()})
        })
        .collect()
}

fn enc_target(target: &EgressTarget) -> Value {
    json!({"$dc": "EgressTarget", "protocol": target.protocol, "backend": target.backend.as_str(),
           "capabilities": target.capabilities, "providers": target.providers, "revision": target.revision,
           "applied": target.applied.as_ref().map(|applied| applied.to_value()), "mode": target.mode.as_str(),
           "restart_required": target.restart_required, "warnings": target.warnings,
           "runtime_version": target.runtime_version, "router_attached": target.router_attached})
}

fn enc_router_target(target: &RouterTarget) -> Value {
    json!({"$dc": "RouterTarget", "available": target.available, "service": target.service,
           "capabilities": target.capabilities, "providers": target.providers, "revision": target.revision,
           "applied": target.applied.as_ref().map(|applied| applied.to_value()), "xray_version": target.xray_version,
           "restart_required": target.restart_required, "reason": target.reason})
}

fn enc_applied_egress(applied: &AppliedEgress) -> Value {
    json!({"$dc": "AppliedEgress", "revision": applied.revision, "digest": applied.digest,
           "readback_sha256": applied.readback_sha256, "replayed": applied.replayed})
}

type Outcome = Result<Value, AdapterError>;

macro_rules! common {
    ($adapter:expr, $method:expr, $args:expr) => {{
        let adapter = $adapter;
        let args = $args;
        match $method {
            "discover" => Some(adapter.discover().await.map(|value| enc_inventory(&value))),
            "preflight" => Some(adapter.preflight(&intent(&args["intent"])).await.map(|value| enc_preflight(&value))),
            "create" => Some(
                adapter
                    .create(
                        args["operation_id"].as_str().unwrap(),
                        &intent(&args["intent"]),
                        &credential(&args["credential"]),
                    )
                    .await
                    .map(|value| enc_applied(&value)),
            ),
            "enable" => Some(adapter.enable(&grant_ref(&args["grant"])).await.map(|value| enc_applied(&value))),
            "disable" => Some(adapter.disable(&grant_ref(&args["grant"])).await.map(|value| enc_applied(&value))),
            "rotate" => Some(
                adapter
                    .rotate(
                        args["operation_id"].as_str().unwrap(),
                        &grant_ref(&args["grant"]),
                        &credential(&args["credential"]),
                    )
                    .await
                    .map(|value| enc_applied(&value)),
            ),
            "delete" => Some(adapter.delete(&grant_ref(&args["grant"])).await.map(|_| Value::Null)),
            "capture" => Some(adapter.capture(&grant_ref(&args["grant"])).await.map(|value| match value {
                Some(bytes) => enc_bytes(&bytes),
                None => Value::Null,
            })),
            "update_options" => Some(
                adapter
                    .update_options(&grant_ref(&args["grant"]), &object(&args["options"]))
                    .await
                    .map(|value| value.as_ref().map_or(Value::Null, enc_applied)),
            ),
            "render_artifacts" => Some(
                adapter
                    .render_artifacts(
                        &access_grant(&args["grant"]),
                        &bytes(&args["credential"]),
                        args["public_host"].as_str().unwrap(),
                    )
                    .map(|value| enc_artifacts(&value)),
            ),
            "egress_target" => {
                Some(adapter.egress_target().await.map(|value| value.as_ref().map_or(Value::Null, enc_target)))
            }
            "plan_egress" => Some(
                adapter
                    .plan_egress(&object(&args["document"]), args["expected_revision"].as_str().unwrap())
                    .await
                    .map(Value::Object),
            ),
            "apply_egress" => Some(
                adapter
                    .apply_egress(
                        &object(&args["document"]),
                        args["expected_revision"].as_str().unwrap(),
                        args["operation_id"].as_str().unwrap(),
                    )
                    .await
                    .map(|value| enc_applied_egress(&value)),
            ),
            "rollback_egress" => Some(
                adapter
                    .rollback_egress(args["expected_revision"].as_str().unwrap())
                    .await
                    .map(|value| enc_applied_egress(&value)),
            ),
            _ => None,
        }
    }};
}

async fn dispatch(built: &Built, method: &str, args: &Value) -> Outcome {
    let text = |key: &str| args[key].as_str().unwrap().to_string();
    let found = match built {
        Built::Naive(adapter) => match method {
            "lanes" => Some(adapter.lanes().await),
            "set_lanes" => Some(adapter.set_lanes(&args["lanes"]).await),
            _ => common!(adapter, method, args),
        },
        Built::Mieru(adapter) => match method {
            "lanes" => Some(adapter.lanes().await),
            "set_lanes" => Some(adapter.set_lanes(&args["lanes"]).await),
            "share" => Some(Ok(json!(adapter.share(&text("username"), &text("password"))))),
            _ => common!(adapter, method, args),
        },
        Built::Amneziawg(adapter) => match method {
            "versions" => Some(adapter.versions().await.map(|versions| json!(versions))),
            _ => common!(adapter, method, args),
        },
        Built::Trusttunnel(adapter) => match method {
            "endpoint" => Some(adapter.endpoint().await),
            _ => common!(adapter, method, args),
        },
        Built::Telemt(adapter, _) => common!(adapter, method, args),
        Built::Router(adapter) => match method {
            "target" => Some(Ok(enc_router_target(&adapter.target(&text("service")).await))),
            "ingress" => Some(adapter.ingress(&text("service")).await),
            "status" => Some(Ok(adapter.status().await.unwrap_or(Value::Null))),
            "plan" => Some(adapter.plan(&text("service"), &args["document"], &text("expected_revision")).await),
            "apply" => Some(
                adapter
                    .apply(&text("service"), &args["document"], &text("expected_revision"), &text("operation_id"))
                    .await
                    .map(|value| enc_applied_egress(&value)),
            ),
            "rollback" => Some(
                adapter
                    .rollback(&text("service"), &text("expected_revision"))
                    .await
                    .map(|value| enc_applied_egress(&value)),
            ),
            "lanes" => Some(adapter.lanes(&text("service")).await),
            "lane_issue" => Some(adapter.lane_issue(&text("service"), &text("lane")).await),
            "lane_forget" => Some(adapter.lane_forget(&text("service"), &text("lane")).await),
            "relay" => Some(Ok(adapter.relay().await.unwrap_or(Value::Null))),
            "relay_enable" => Some(adapter.relay_enable(&text("server_name"), args["port"].as_i64().unwrap()).await),
            "relay_disable" => Some(adapter.relay_disable().await),
            "relay_set_accounts" => Some(adapter.relay_set_accounts(&args["accounts"]).await),
            "exit_test" => Some(adapter.exit_test(&args["spec"]).await),
            "geodata" => {
                let action = GeodataAction::parse(&text("action")).unwrap();
                Some(adapter.geodata(action, Some(&args["body"]).filter(|body| !body.is_null())).await)
            }
            _ => None,
        },
    };
    found.unwrap_or_else(|| panic!("no replay for {method}"))
}

fn check_error(context: &str, recorded: &Value, error: &AdapterError) {
    let class = recorded["class"].as_str().unwrap();
    if recorded["adapter_error"] == json!(true) {
        assert_eq!(error.message, recorded["message"].as_str().unwrap(), "{context}: message");
        assert_eq!(error.code.as_deref(), recorded["code"].as_str(), "{context}: code");
        assert_eq!(error.already_gone, recorded["already_gone"] == json!(true), "{context}: already_gone");
        assert_eq!(error.is_manual_intervention(), recorded["manual"] == json!(true), "{context}: class {class}");
        return;
    }
    let failure = runtime_failure(error)
        .unwrap_or_else(|| panic!("{context}: Python let {class} escape, Rust answered {error:?}"));
    if ERROR_CLASSES.contains(&class) {
        assert_eq!(error.message, recorded["message"].as_str().unwrap(), "{context}: message");
        assert_eq!(u64::from(failure.status), recorded["status_code"].as_u64().unwrap(), "{context}: status");
        assert_eq!(failure.indeterminate, recorded["indeterminate"] == json!(true), "{context}: indeterminate");
        assert_eq!(failure.code.as_deref(), recorded["code"].as_str(), "{context}: code");
    } else {
        // Python crashed on a malformed answer (a 500): so does Rust, with its own message.
        assert_eq!(failure.status, 500, "{context}: Python raised {class}");
    }
}

fn journal_file(built: &Built) -> Option<PathBuf> {
    match built {
        Built::Telemt(adapter, Some(_)) => adapter.journal().path().map(PathBuf::from),
        _ => None,
    }
}

fn set_journal(built: &Built, recorded: &Value) {
    let Built::Telemt(adapter, _) = built else { return };
    if let Some(memory) = recorded.get("memory") {
        adapter.journal().write(memory).unwrap();
    } else if let Some(path) = journal_file(built) {
        match recorded["file"].as_str() {
            Some(text) => std::fs::write(&path, text).unwrap(),
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

fn check_journal(context: &str, built: &Built, recorded: &Value) {
    let Built::Telemt(adapter, _) = built else { return };
    if let Some(memory) = recorded.get("memory") {
        assert_eq!(&adapter.journal().read().unwrap(), memory, "{context}: the in-memory journal");
    } else if let Some(path) = journal_file(built) {
        let written = std::fs::read_to_string(&path).ok();
        assert_eq!(written.as_deref(), recorded["file"].as_str(), "{context}: the journal file, byte for byte");
    }
}

async fn replay(name: &str) {
    let transcript = &transcripts()[name];
    let queues: HashMap<String, VecDeque<Value>> = transcript["clients"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, events)| (id.clone(), events.as_array().unwrap().iter().cloned().collect()))
        .collect();
    let probes = transcript["probes"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, events)| (id.clone(), Arc::new(Mutex::new(events.as_array().unwrap().iter().cloned().collect()))))
        .collect();
    let mut stage =
        Stage { queues: Arc::new(Mutex::new(queues)), probes, routers: HashMap::new(), adapters: HashMap::new() };
    for (index, call) in transcript["calls"].as_array().unwrap().iter().enumerate() {
        let adapter = call["adapter"].as_str().unwrap();
        let method = call["method"].as_str().unwrap();
        let context = format!("call {index} {adapter}.{method}");
        let state = &call["state"];
        let rebuild = stage.adapters.get(adapter).is_none_or(|(built_from, _)| built_from != state);
        if rebuild {
            let built = stage.build(adapter, state);
            stage.adapters.insert(adapter.to_string(), (state.clone(), built));
        }
        let built = &stage.adapters[adapter].1;
        set_journal(built, &call["journal_before"]);
        let outcome = dispatch(built, method, &call["args"]).await;
        match (call.get("error"), outcome) {
            (None, Ok(value)) => assert_eq!(value, call["result"], "{context}: result"),
            (Some(recorded), Err(error)) => check_error(&context, recorded, &error),
            (None, Err(error)) => panic!("{context}: Python answered {}, Rust failed with {error:?}", call["result"]),
            (Some(recorded), Ok(value)) => panic!("{context}: Python raised {recorded}, Rust answered {value}"),
        }
        check_journal(&context, built, &call["journal_after"]);
    }
    for (id, queue) in stage.queues.lock().unwrap().iter() {
        assert!(
            queue.is_empty(),
            "{name}: client {id} was never asked {:?}",
            queue.iter().map(|e| &e["method"]).collect::<Vec<_>>()
        );
    }
    for (id, queue) in &stage.probes {
        assert!(queue.lock().unwrap().is_empty(), "{name}: the bridge probe of {id} was asked less often");
    }
}

#[tokio::test]
async fn telemt_adapter_wraps_a_failing_readback() {
    for action in ["enable", "disable", "update_options"] {
        let first = if action == "update_options" {
            json!({"method":"update_user", "args":["alice", {"max_tcp_conns":3}], "kwargs":{}, "result":{}})
        } else {
            json!({"method":"set_enabled", "args":["alice", action == "enable"], "kwargs":{}, "result":{}})
        };
        let failure = json!({"method":"current_access", "args":["alice"], "kwargs":{},
            "error":{"class":"TelemtError", "message":"Telemt API error (502)", "status_code":502}});
        let queues = Arc::new(Mutex::new(HashMap::from([
            ("telemt".into(), VecDeque::from([first, failure])),
        ])));
        let adapter = TelemtAdapter::new(Replay { id: "telemt".into(), queues: queues.clone() });
        let grant = grant_ref(&json!({"protocol":"mtproxy", "runtime_username":"alice"}));
        let error = match action {
            "enable" => adapter.enable(&grant).await.unwrap_err(),
            "disable" => adapter.disable(&grant).await.unwrap_err(),
            _ => adapter.update_options(&grant, &object(&json!({"max_tcp_conns":3}))).await.unwrap_err(),
        };
        assert!(runtime_failure(&error).is_none(), "{action}: {error:?}");
        assert_eq!(error.to_string(), "Telemt refused the request");
        assert!(queues.lock().unwrap()["telemt"].is_empty(), "{action}");
    }
}
