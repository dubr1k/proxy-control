//! The in-memory manager doubles of the Python tests (`MemoryTelemt`, `MemoryNaive`,
//! `MemoryMieru`, `MemoryAmneziawg`, `MemoryTrusttunnel` in `panel/*.py`), ported as far as the
//! fleet node uses them: the same answers byte for byte, so the real `panel_protocols` adapters
//! over them behave as the Python adapters did over the Python doubles (the golden replay relies
//! on it). Each double is a cheap handle (`Clone`) on shared state the tests inspect.

#![allow(dead_code)]

use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;
use panel_core::ids::{sha256_hex, token_hex, token_urlsafe};
use panel_core::pyjson;
use panel_core::pytext::quote;
use panel_managers::{access_from_user, Manager, ManagerError, TelemtAccess, TelemtError};
use panel_protocols::api::{AmneziawgApi, ManagerResult, MieruApi, NaiveApi, TelemtApi, TelemtResult, TrusttunnelApi};
use serde_json::{json, Map, Value};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn canonical_sha(value: &Value) -> String {
    sha256_hex(pyjson::canonical(value))
}

// -- Telemt ---------------------------------------------------------------------------------------

#[derive(Default)]
pub struct TelemtState {
    pub users: IndexMap<String, Value>,
    pub public_host: String,
    pub public_port: i64,
    pub upstreams: Value,
    pub config_version: i64,
    pub reloads: IndexMap<i64, Value>,
    /// `current_access` raises `TelemtError("Telemt API error (502)")`.
    pub access_down: bool,
}

#[derive(Clone)]
pub struct MemoryTelemt(pub Arc<Mutex<TelemtState>>);

impl MemoryTelemt {
    pub fn new(public_host: &str, public_port: i64) -> Self {
        Self(Arc::new(Mutex::new(TelemtState {
            public_host: public_host.into(),
            public_port,
            upstreams: json!([{"type": "direct", "ipv4": true, "ipv6": false}]),
            config_version: 1,
            ..TelemtState::default()
        })))
    }

    pub fn state(&self) -> MutexGuard<'_, TelemtState> {
        lock(&self.0)
    }

    fn link(state: &TelemtState, secret: &str) -> String {
        format!("tg://proxy?server={}&port={}&secret=ee{secret}", state.public_host, state.public_port)
    }

    fn revision(state: &TelemtState) -> String {
        format!("{:064x}", state.config_version)
    }
}

impl TelemtApi for MemoryTelemt {
    type Batch = ();

    fn batch(&self) {}

    async fn list_users(&self) -> TelemtResult {
        Ok(Value::Array(self.state().users.values().cloned().collect()))
    }

    async fn create_user(&self, username: &str, secret: Option<&str>) -> TelemtResult {
        let mut state = self.state();
        let secret = secret.map(str::to_string).unwrap_or_else(|| token_hex(16));
        let user = json!({"username": username, "enabled": true, "links": {"tls": [Self::link(&state, &secret)]}});
        state.users.insert(username.into(), user.clone());
        Ok(json!({"user": user, "secret": secret}))
    }

    async fn delete_user(&self, username: &str) -> TelemtResult {
        self.state().users.shift_remove(username);
        Ok(json!({"username": username}))
    }

    async fn set_enabled(&self, username: &str, enabled: bool) -> TelemtResult {
        let mut state = self.state();
        let user = state.users.get_mut(username).ok_or_else(|| TelemtError::new("Telemt API error (404)"))?;
        user["enabled"] = json!(enabled);
        Ok(user.clone())
    }

    async fn rotate(&self, username: &str, secret: Option<&str>) -> TelemtResult {
        let mut state = self.state();
        let secret = secret.map(str::to_string).unwrap_or_else(|| token_hex(16));
        let link = Self::link(&state, &secret);
        let user = state.users.get_mut(username).ok_or_else(|| TelemtError::new("Telemt API error (404)"))?;
        user["links"] = json!({"tls": [link]});
        Ok(json!({"user": user.clone(), "secret": secret}))
    }

    async fn update_user(&self, username: &str, fields: &Value) -> TelemtResult {
        let mut state = self.state();
        let user = state.users.get_mut(username).ok_or_else(|| TelemtError::new("Telemt API error (404)"))?;
        if let (Some(user), Some(fields)) = (user.as_object_mut(), fields.as_object()) {
            for (key, value) in fields {
                user.insert(key.clone(), value.clone());
            }
        }
        Ok(user.clone())
    }

    async fn current_access(&self, username: &str) -> TelemtResult<Option<TelemtAccess>> {
        let state = self.state();
        if state.access_down {
            return Err(TelemtError::new("Telemt API error (502)"));
        }
        Ok(state.users.get(username).and_then(access_from_user))
    }

    async fn config(&self) -> TelemtResult<(Value, Value)> {
        let state = self.state();
        Ok((
            json!({"general": {"use_middle_proxy": false}, "upstreams": state.upstreams}),
            json!(Self::revision(&state)),
        ))
    }

    async fn patch_config(&self, body: &Value, revision: &str) -> TelemtResult<(Value, Value)> {
        let mut state = self.state();
        if revision != Self::revision(&state) {
            return Err(TelemtError::with_status("Telemt API error (412)", 412));
        }
        state.upstreams = body["upstreams"].clone();
        state.config_version += 1;
        let revision = Self::revision(&state);
        Ok((
            json!({"revision": revision, "runtime_reload_required": true, "process_restart_required": false,
                   "changed": ["upstreams"]}),
            json!(revision),
        ))
    }

    async fn reload(&self, revision: &Value) -> TelemtResult {
        let mut state = self.state();
        if revision.as_str() != Some(Self::revision(&state).as_str()) {
            return Err(TelemtError::with_status("Telemt API error (412)", 412));
        }
        let id = state.reloads.len() as i64 + 1;
        state.reloads.insert(id, json!({"reload_id": id, "state": "succeeded"}));
        Ok(json!({"reload_id": id, "state": "accepted"}))
    }

    async fn reload_status(&self, reload_id: &Value) -> TelemtResult {
        let state = self.state();
        Ok(state.reloads.get(&reload_id.as_i64().unwrap_or(0)).cloned().unwrap_or(Value::Null))
    }
}

// -- NaiveProxy -----------------------------------------------------------------------------------

fn naive_error(message: &str, status: u16, code: Option<&str>) -> ManagerError {
    ManagerError::new(Manager::Naive, message, status, code)
}

pub struct NaiveState {
    pub public_host: String,
    pub users: IndexMap<String, Value>,
    pub calls: Vec<String>,
    pub traffic_rows: IndexMap<String, (i64, i64)>,
    pub operations: IndexMap<String, Value>,
    pub lose_next: Option<String>,
    pub broken: bool,
    pub traffic_broken: bool,
    pub reachable: bool,
    pub router_url: Option<String>,
    pub egress_document: Value,
    pub egress_history: Vec<Value>,
    pub egress_operations: IndexMap<String, Value>,
    pub lane_table: IndexMap<String, Value>,
    /// The next `create` of this user waits until the gate opens (`slow_create` of the tests).
    pub create_gates: IndexMap<String, Arc<tokio::sync::Semaphore>>,
    pub create_entered: IndexMap<String, Arc<tokio::sync::Notify>>,
    /// `create` of this user fails (`FlakyCreate`).
    pub create_fails: Vec<String>,
}

#[derive(Clone)]
pub struct MemoryNaive(pub Arc<Mutex<NaiveState>>);

pub const PERIOD_START: &str = "2026-10-26T00:00:00+00:00";

impl Default for MemoryNaive {
    fn default() -> Self {
        Self::new("naive.example.com")
    }
}

impl MemoryNaive {
    pub fn new(public_host: &str) -> Self {
        Self(Arc::new(Mutex::new(NaiveState {
            public_host: public_host.into(),
            users: IndexMap::new(),
            calls: Vec::new(),
            traffic_rows: IndexMap::new(),
            operations: IndexMap::new(),
            lose_next: None,
            broken: false,
            traffic_broken: false,
            reachable: true,
            router_url: None,
            egress_document: json!({"schema": 1, "upstream": null, "acl": []}),
            egress_history: Vec::new(),
            egress_operations: IndexMap::new(),
            lane_table: IndexMap::new(),
            create_gates: IndexMap::new(),
            create_entered: IndexMap::new(),
            create_fails: Vec::new(),
        })))
    }

    pub fn state(&self) -> MutexGuard<'_, NaiveState> {
        lock(&self.0)
    }

    pub fn seed(&self, username: &str, password: &str) {
        Self::seed_in(&mut self.state(), username, password, None);
    }

    fn seed_in(state: &mut NaiveState, username: &str, password: &str, quota: Option<i64>) {
        state.users.insert(
            username.into(),
            json!({"username": username, "password": password, "enabled": true, "quota_bytes": quota,
                   "disabled_reason": null}),
        );
        state.traffic_rows.entry(username.into()).or_insert((0, 0));
    }

    pub fn set_traffic(&self, username: &str, upload: i64, download: i64) {
        self.state().traffic_rows.insert(username.into(), (upload, download));
    }

    pub fn password(&self, username: &str) -> Option<String> {
        self.state().users.get(username).and_then(|user| user["password"].as_str().map(str::to_string))
    }

    pub fn usernames(&self) -> Vec<String> {
        self.state().users.keys().cloned().collect()
    }

    pub fn calls(&self) -> Vec<String> {
        self.state().calls.clone()
    }

    fn access(state: &NaiveState, username: &str) -> Value {
        let password = state.users[username]["password"].as_str().unwrap_or_default().to_string();
        let url = format!("https://{}:{}@{}", quote(username, ""), quote(&password, ""), state.public_host);
        json!({"username": username, "proxy_url": url, "config": {"listen": "socks://127.0.0.1:1080", "proxy": url}})
    }

    fn guard(state: &NaiveState) -> Result<(), ManagerError> {
        if state.broken {
            return Err(ManagerError::plain(Manager::Naive, "NaiveProxy manager unavailable"));
        }
        Ok(())
    }

    fn replay(state: &NaiveState, operation_id: &str, operation: &str, username: &str) -> ManagerResult<Option<Value>> {
        let Some(record) = state.operations.get(operation_id) else { return Ok(None) };
        if record["operation"] != operation || record["username"] != username {
            return Err(naive_error("operation id already used for another request", 409, Some("operation_conflict")));
        }
        let mut result = record["result"].clone();
        result["replayed"] = json!(true);
        Ok(Some(result))
    }

    fn egress_revision(state: &NaiveState) -> String {
        canonical_sha(&state.egress_document)
    }
}

impl NaiveApi for MemoryNaive {
    async fn list_users(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        Ok(Value::Array(
            state
                .users
                .values()
                .map(|row| {
                    json!({"username": row["username"], "enabled": row["enabled"], "quota_bytes": row["quota_bytes"],
                           "disabled_reason": row["disabled_reason"]})
                })
                .collect(),
        ))
    }

    async fn create(
        &self,
        username: &str,
        quota_bytes: Option<i64>,
        password: &str,
        operation_id: &str,
    ) -> ManagerResult {
        let (gate, entered) = {
            let mut state = self.state();
            Self::guard(&state)?;
            state.calls.push(format!("create {username}"));
            (state.create_gates.shift_remove(username), state.create_entered.get(username).cloned())
        };
        if let Some(entered) = entered {
            entered.notify_one();
        }
        if let Some(gate) = gate {
            let _ = gate.acquire().await;
        }
        let mut state = self.state();
        if state.create_fails.iter().any(|name| name == username) {
            return Err(ManagerError::plain(Manager::Naive, format!("{username} create boom")));
        }
        if let Some(replayed) = Self::replay(&state, operation_id, "create", username)? {
            return Ok(replayed);
        }
        let password = if password.is_empty() { token_urlsafe(18) } else { password.to_string() };
        Self::seed_in(&mut state, username, &password, quota_bytes);
        let result = Self::access(&state, username);
        state
            .operations
            .insert(operation_id.into(), json!({"operation": "create", "username": username, "result": result}));
        if state.lose_next.as_deref() == Some("create") {
            state.lose_next = None;
            return Err(ManagerError::plain(Manager::Naive, "NaiveProxy manager unavailable"));
        }
        Ok(result)
    }

    async fn reveal(&self, username: &str) -> ManagerResult {
        let mut state = self.state();
        state.calls.push(format!("access {username}"));
        if !state.users.contains_key(username) {
            return Err(naive_error("NaiveProxy manager rejected request", 404, None));
        }
        Ok(Self::access(&state, username))
    }

    async fn rotate(&self, username: &str, password: &str, operation_id: &str) -> ManagerResult {
        let mut state = self.state();
        state.calls.push(format!("rotate {username}"));
        if let Some(replayed) = Self::replay(&state, operation_id, "rotate", username)? {
            return Ok(replayed);
        }
        let password = if password.is_empty() { token_urlsafe(18) } else { password.to_string() };
        let Some(user) = state.users.get_mut(username) else {
            return Err(naive_error("NaiveProxy manager rejected request", 404, None));
        };
        user["password"] = json!(password);
        let result = Self::access(&state, username);
        state
            .operations
            .insert(operation_id.into(), json!({"operation": "rotate", "username": username, "result": result}));
        Ok(result)
    }

    async fn set_enabled(&self, username: &str, enabled: bool) -> ManagerResult {
        let mut state = self.state();
        state.calls.push(format!("enabled {username} {enabled}"));
        let Some(user) = state.users.get_mut(username) else {
            return Err(naive_error("NaiveProxy manager rejected request", 404, None));
        };
        user["enabled"] = json!(enabled);
        user["disabled_reason"] = if enabled { Value::Null } else { json!("manual") };
        Ok(json!({"username": username, "enabled": enabled, "disabled_reason": user["disabled_reason"]}))
    }

    async fn set_quota(&self, username: &str, quota_bytes: &Value) -> ManagerResult {
        let mut state = self.state();
        state.calls.push(format!("set_quota {username}"));
        let Some(user) = state.users.get_mut(username) else {
            return Err(naive_error("NaiveProxy manager rejected request", 404, None));
        };
        user["quota_bytes"] = quota_bytes.clone();
        Ok(json!({"username": username, "quota_bytes": quota_bytes, "enabled": user["enabled"],
                  "disabled_reason": user["disabled_reason"]}))
    }

    async fn delete(&self, username: &str) -> ManagerResult {
        let mut state = self.state();
        state.calls.push(format!("delete {username}"));
        if state.users.shift_remove(username).is_none() {
            return Err(naive_error("NaiveProxy manager rejected request", 404, Some("not_found")));
        }
        Ok(json!({"ok": true}))
    }

    async fn egress(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        let document = state.egress_document.clone();
        let upstream = if document["upstream"].is_null() { Value::Null } else { json!("socks5://127.0.0.1:40000") };
        let mut providers = Map::new();
        providers.insert("warp".into(), json!({"url": "socks5://127.0.0.1:40000", "reachable": state.reachable}));
        if let Some(url) = &state.router_url {
            providers.insert("router".into(), json!({"url": url, "reachable": true}));
        }
        let acl: Vec<Value> = document["acl"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|rule| rule["deny"].as_array().cloned().unwrap_or_default())
            .collect();
        let managed = !state.egress_history.is_empty();
        Ok(json!({
            "revision": Self::egress_revision(&state),
            "mode": if upstream.is_null() { "direct" } else { "proxy" },
            "upstream": upstream, "acl": acl, "document": document, "managed": managed,
            "providers": providers,
            "capabilities": ["whole_direct", "whole_warp", "block_domain", "block_cidr"],
            "restart_required": false, "warnings": [],
            "previous": if managed { json!({"revision": "previous"}) } else { Value::Null },
            "current": if managed { json!({"revision": Self::egress_revision(&state)}) } else { Value::Null },
        }))
    }

    async fn egress_plan(&self, expected_revision: &str, document: &Value) -> ManagerResult {
        let state = self.state();
        if expected_revision != Self::egress_revision(&state) {
            return Err(naive_error("egress revision does not match", 409, Some("egress_conflict")));
        }
        let target = canonical_sha(document);
        Ok(json!({"revision": expected_revision, "target_revision": target, "rendered_sha256": target, "diff": [],
                  "warnings": [], "reachability": {}, "restart_required": false}))
    }

    async fn egress_apply(&self, expected_revision: &str, document: &Value, operation_id: &str) -> ManagerResult {
        let mut state = self.state();
        state.calls.push(format!("egress_apply {operation_id}"));
        Self::guard(&state)?;
        let acl: Vec<Value> = document["acl"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|rule| json!({"deny": rule["deny"].clone()}))
            .collect();
        let normalised = json!({"schema": 1, "upstream": document["upstream"], "acl": acl});
        if let Some(record) = state.egress_operations.get(operation_id) {
            let mut record = record.clone();
            record["replayed"] = json!(true);
            return Ok(record);
        }
        if expected_revision != Self::egress_revision(&state) {
            return Err(naive_error("egress revision does not match", 409, Some("egress_conflict")));
        }
        let previous = state.egress_document.clone();
        state.egress_history.push(previous);
        state.egress_document = normalised.clone();
        let result = json!({"revision": Self::egress_revision(&state), "applied": normalised,
                            "readback_sha256": canonical_sha(&normalised)});
        state.egress_operations.insert(operation_id.into(), result.clone());
        let mut answer = result;
        answer["replayed"] = json!(false);
        Ok(answer)
    }

    async fn egress_rollback(&self, _expected_revision: &str) -> ManagerResult {
        Err(naive_error("no previous egress to roll back to", 409, Some("egress_no_previous")))
    }

    async fn lanes(&self) -> ManagerResult {
        let state = self.state();
        Ok(json!({"lanes": state.lane_table.values().cloned().collect::<Vec<_>>()}))
    }

    async fn set_lanes(&self, lanes: &Value) -> ManagerResult {
        let mut state = self.state();
        if !lanes.as_array().is_some_and(Vec::is_empty) && state.router_url.is_none() {
            return Err(naive_error(
                "egress provider router is not configured on this node",
                422,
                Some("egress_invalid"),
            ));
        }
        state.lane_table = lanes
            .as_array()
            .into_iter()
            .flatten()
            .map(|entry| (entry["lane"].as_str().unwrap_or_default().to_string(), entry.clone()))
            .collect();
        Ok(json!({"lanes": state.lane_table.values().cloned().collect::<Vec<_>>()}))
    }
}

impl MemoryNaive {
    /// `traffic()`.
    pub fn traffic(&self) -> ManagerResult {
        let state = self.state();
        if state.traffic_broken {
            return Err(naive_error("manager down", 503, None));
        }
        let rows: Vec<Value> = state
            .traffic_rows
            .iter()
            .map(|(username, (up, down))| {
                json!({"username": username, "upload_bytes": up, "download_bytes": down, "total_bytes": up + down,
                       "period_start": PERIOD_START, "updated_at": PERIOD_START,
                       "upload_bytes_decimal": up.to_string(), "download_bytes_decimal": down.to_string(),
                       "total_bytes_decimal": (up + down).to_string()})
            })
            .collect();
        let (up, down): (i64, i64) =
            state.traffic_rows.values().fold((0, 0), |acc, row| (acc.0 + row.0, acc.1 + row.1));
        Ok(json!({"source": "caddy_connect_access_log", "unit": "bytes", "pending": false,
                  "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
                  "aggregate": {"upload_bytes": up, "download_bytes": down, "total_bytes": up + down},
                  "users": rows}))
    }
}

// -- Mieru ----------------------------------------------------------------------------------------

fn mieru_error(message: &str, status: u16, code: Option<&str>) -> ManagerError {
    ManagerError::new(Manager::Mieru, message, status, code)
}

pub struct MieruState {
    pub users: IndexMap<String, Value>,
    pub revision: i64,
    pub broken: bool,
    pub reachable: bool,
    pub operations: IndexMap<String, Value>,
    pub egress_document: Value,
    pub egress_history: Vec<Value>,
}

#[derive(Clone)]
pub struct MemoryMieru(pub Arc<Mutex<MieruState>>);

impl Default for MemoryMieru {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(MieruState {
            users: IndexMap::new(),
            revision: 1,
            broken: false,
            reachable: true,
            operations: IndexMap::new(),
            egress_document: json!({"schema": 1, "proxies": [], "rules": []}),
            egress_history: Vec::new(),
        })))
    }
}

impl MemoryMieru {
    pub fn state(&self) -> MutexGuard<'_, MieruState> {
        lock(&self.0)
    }

    pub fn usernames(&self) -> Vec<String> {
        self.state().users.keys().cloned().collect()
    }

    fn revision(state: &MieruState) -> String {
        format!("rev-{}", state.revision)
    }

    fn next(state: &mut MieruState) -> String {
        state.revision += 1;
        Self::revision(state)
    }

    fn share(username: &str, password: &str) -> String {
        format!(
            "mierus://{}:{}@mieru.example.com?profile={}&port=8443&protocol=TCP",
            quote(username, ""),
            quote(password, ""),
            quote(username, "/")
        )
    }

    fn guard(state: &MieruState) -> Result<(), ManagerError> {
        if state.broken {
            return Err(ManagerError::plain(Manager::Mieru, "unavailable"));
        }
        Ok(())
    }

    fn check(state: &MieruState, revision: &Value) -> Result<(), ManagerError> {
        if revision.as_str() != Some(Self::revision(state).as_str()) {
            return Err(mieru_error("conflict", 409, None));
        }
        Ok(())
    }
}

impl MieruApi for MemoryMieru {
    async fn health(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        Ok(json!({"ready": true, "status": "running", "revision": Self::revision(&state)}))
    }

    async fn list_users(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        Ok(Value::Array(state.users.values().cloned().collect()))
    }

    async fn create(&self, payload: &Value) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        let username = payload["username"].as_str().unwrap_or_default().to_string();
        let operation_id = payload["operation_id"].as_str().map(str::to_string);
        if let Some(record) = operation_id.as_ref().and_then(|id| state.operations.get(id)) {
            return Ok(json!({"username": username, "revision": record["revision"], "replayed": true}));
        }
        Self::check(&state, &payload["expected_revision"])?;
        let password = payload["password"]
            .as_str()
            .filter(|text| !text.is_empty())
            .map_or_else(|| token_urlsafe(18), str::to_string);
        state
            .users
            .insert(username.clone(), json!({"username": username, "enabled": true, "quotas": payload["quotas"]}));
        let revision = Self::next(&mut state);
        if let Some(id) = operation_id {
            state
                .operations
                .insert(id, json!({"operation": "user.create", "username": username, "revision": revision}));
        }
        Ok(json!({"username": username, "share_url": Self::share(&username, &password), "revision": revision}))
    }

    async fn operation(&self, username: &str, operation: &str, revision: &Value) -> ManagerResult {
        let mut state = self.state();
        Self::check(&state, revision)?;
        let enabled = operation == "enable";
        if let Some(user) = state.users.get_mut(username) {
            user["enabled"] = json!(enabled);
        }
        let revision = Self::next(&mut state);
        Ok(json!({"username": username, "enabled": enabled, "revision": revision}))
    }

    async fn rotate(&self, username: &str, revision: &Value, password: &str, _operation_id: &str) -> ManagerResult {
        let mut state = self.state();
        Self::check(&state, revision)?;
        let revision = Self::next(&mut state);
        Ok(json!({"username": username, "share_url": Self::share(username, password), "revision": revision}))
    }

    async fn delete(&self, username: &str, _revision: &Value) -> ManagerResult {
        let mut state = self.state();
        if state.users.shift_remove(username).is_none() {
            return Err(mieru_error("Mieru manager rejected request", 404, Some("not_found")));
        }
        let revision = Self::next(&mut state);
        Ok(json!({"username": username, "revision": revision}))
    }

    async fn set_quotas(&self, username: &str, payload: &Value) -> ManagerResult {
        let mut state = self.state();
        if let Some(user) = state.users.get_mut(username) {
            user["quotas"] = payload["quotas"].clone();
        }
        let revision = Self::next(&mut state);
        Ok(json!({"username": username, "revision": revision}))
    }

    async fn egress(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        let document = state.egress_document.clone();
        let proxy = document["rules"].as_array().into_iter().flatten().any(|rule| rule["action"] == "PROXY");
        let managed = !state.egress_history.is_empty();
        Ok(json!({
            "revision": Self::revision(&state), "mode": if proxy { "proxy" } else { "direct" },
            "document": document, "raw": null, "managed": managed,
            "providers": {"warp": {"url": "socks5://127.0.0.1:40000", "reachable": state.reachable}},
            "capabilities": ["whole_direct", "whole_warp", "block_domain", "block_cidr", "selective_domain",
                             "selective_cidr"],
            "restart_required": true, "warnings": [],
            "previous": if managed { json!({"applied_at": null}) } else { Value::Null },
            "current": if managed { json!({"digest": canonical_sha(&state.egress_document)}) } else { Value::Null },
        }))
    }

    async fn egress_plan(&self, _expected_revision: &str, document: &Value) -> ManagerResult {
        let state = self.state();
        Ok(json!({"revision": Self::revision(&state), "target": document, "diff": [], "reachability": {},
                  "restart_required": true, "warnings": []}))
    }

    async fn egress_apply(&self, expected_revision: &str, document: &Value, _operation_id: &str) -> ManagerResult {
        let mut state = self.state();
        if expected_revision != Self::revision(&state) {
            return Err(mieru_error("egress revision does not match", 409, Some("egress_conflict")));
        }
        let previous = state.egress_document.clone();
        state.egress_history.push(previous);
        state.egress_document = document.clone();
        let revision = Self::next(&mut state);
        Ok(json!({"revision": revision, "applied": document, "replayed": false}))
    }

    async fn egress_rollback(&self, _expected_revision: &str) -> ManagerResult {
        Err(mieru_error("no previous egress to roll back to", 409, Some("egress_no_previous")))
    }

    async fn lanes(&self) -> ManagerResult {
        Ok(json!({"lanes": [], "free_slots": 2}))
    }

    async fn set_lanes(&self, _lanes: &Value) -> ManagerResult {
        Err(mieru_error("egress provider router is not configured on this node", 422, Some("egress_invalid")))
    }
}

// -- AmneziaWG ------------------------------------------------------------------------------------

fn awg_error(message: &str, status: u16, code: Option<&str>) -> ManagerError {
    ManagerError::new(Manager::Amneziawg, message, status, code)
}

pub struct AmneziawgState {
    pub versions: Vec<String>,
    pub peers: IndexMap<String, Value>,
    pub operations: IndexMap<String, Value>,
    pub broken: bool,
    pub egress_history: Vec<Value>,
    pub egress_revision: i64,
}

#[derive(Clone)]
pub struct MemoryAmneziawg(pub Arc<Mutex<AmneziawgState>>);

impl Default for MemoryAmneziawg {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(AmneziawgState {
            versions: vec!["1.5".into(), "2.0".into(), "3.1".into()],
            peers: IndexMap::new(),
            operations: IndexMap::new(),
            broken: false,
            egress_history: Vec::new(),
            egress_revision: 0,
        })))
    }
}

fn subnet(version: &str) -> &'static str {
    match version {
        "1.5" => "10.66.15",
        "2.0" => "10.66.20",
        _ => "10.66.31",
    }
}

fn awg_port(version: &str) -> i64 {
    match version {
        "1.5" => 51820,
        "2.0" => 51821,
        _ => 51822,
    }
}

fn obfuscation(version: &str) -> Value {
    match version {
        "1.5" => json!({"Jc": "5", "Jmin": "10", "Jmax": "50", "S1": "40", "S2": "70", "H1": "1234567891",
                        "H2": "1234567892", "H3": "1234567893", "H4": "1234567894",
                        "I1": "<b 0xc70000000108><r 16><t>"}),
        "2.0" => json!({"Jc": "5", "Jmin": "10", "Jmax": "50", "S1": "40", "S2": "70", "S3": "20", "S4": "16",
                        "H1": "100000-200000", "H2": "300000-400000", "H3": "500000-600000",
                        "H4": "700000-800000", "I1": "<b 0xc70000000108><r 16><t>"}),
        _ => json!({"Jc": "5", "Jmin": "10", "Jmax": "50", "S1": "24", "S2": "28", "S3": "20", "S4": "32",
                    "H1": "1", "H2": "2", "H3": "3", "H4": "4", "I1": "<b 0xc70000000108><r 16><t>",
                    "HeaderProtectionKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                    "ContentPaddingAddition": "0-32"}),
    }
}

impl MemoryAmneziawg {
    pub fn state(&self) -> MutexGuard<'_, AmneziawgState> {
        lock(&self.0)
    }

    fn instance(version: &str) -> Value {
        use base64::Engine as _;
        let key_byte = version.as_bytes()[0] - b'0' + 40;
        json!({"version": version, "interface": format!("awg{}", version.replace('.', "")), "port": awg_port(version),
               "server_public_key": base64::engine::general_purpose::STANDARD.encode([key_byte; 32]),
               "gateway": format!("{}.1", subnet(version)), "subnet": format!("{}.0/24", subnet(version)),
               "mtu": 1280, "dns": ["1.1.1.1", "1.0.0.1"], "obfuscation": obfuscation(version)})
    }

    fn view(state: &AmneziawgState, username: &str) -> Value {
        let row = &state.peers[username];
        json!({"username": username, "version": row["version"], "enabled": row["enabled"], "address": row["address"],
               "public_key": row["public_key"], "revision": row["revision"], "rx": 0, "tx": 0,
               "latest_handshake": null})
    }

    fn guard(state: &AmneziawgState) -> Result<(), ManagerError> {
        if state.broken {
            return Err(ManagerError::plain(Manager::Amneziawg, "unavailable"));
        }
        Ok(())
    }

    fn document(state: &AmneziawgState) -> Value {
        state.egress_history.last().cloned().unwrap_or_else(|| json!({"schema": 1, "upstream": null}))
    }
}

impl AmneziawgApi for MemoryAmneziawg {
    async fn instances(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        Ok(Value::Array(state.versions.iter().map(|version| Self::instance(version)).collect()))
    }

    async fn peers(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        Ok(Value::Array(state.peers.keys().map(|name| Self::view(&state, name)).collect()))
    }

    async fn create_peer(&self, payload: &Value) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        let username = payload["username"].as_str().unwrap_or_default().to_string();
        let version = payload["version"].as_str().unwrap_or_default().to_string();
        let operation_id = payload["operation_id"].as_str().unwrap_or_default().to_string();
        let body = json!({"username": username, "version": version, "public_key": payload["public_key"],
                          "preshared_key": payload["preshared_key"]});
        if let Some(known) = state.operations.get(&operation_id) {
            if known["body"] != body {
                return Err(awg_error("operation id reused", 409, Some("operation_conflict")));
            }
            return Ok(json!({"peer": Self::view(&state, &username), "instance": Self::instance(&version)}));
        }
        if state.peers.contains_key(&username) {
            return Err(awg_error("username exists", 409, Some("exists")));
        }
        let used: Vec<String> =
            state.peers.values().filter_map(|row| row["address"].as_str().map(str::to_string)).collect();
        let address = (2..255)
            .map(|host| format!("{}.{host}", subnet(&version)))
            .find(|candidate| !used.contains(candidate))
            .ok_or_else(|| awg_error("no free address", 409, Some("no_free_address")))?;
        state.peers.insert(
            username.clone(),
            json!({"version": version, "enabled": true, "address": address, "public_key": payload["public_key"],
                   "preshared_key": payload["preshared_key"], "revision": 1}),
        );
        state.operations.insert(operation_id, json!({"body": body}));
        Ok(json!({"peer": Self::view(&state, &username), "instance": Self::instance(&version)}))
    }

    async fn peer_state(&self, username: &str, action: &str) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        let Some(row) = state.peers.get_mut(username) else {
            return Err(awg_error("not found", 404, Some("not_found")));
        };
        let enabled = action == "enable";
        if row["enabled"] != json!(enabled) {
            row["enabled"] = json!(enabled);
            row["revision"] = json!(row["revision"].as_i64().unwrap_or(0) + 1);
        }
        Ok(json!({"peer": Self::view(&state, username)}))
    }

    async fn rotate_peer(&self, username: &str, payload: &Value) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        let operation_id = payload["operation_id"].as_str().unwrap_or_default().to_string();
        let known = state.operations.contains_key(&operation_id);
        let Some(row) = state.peers.get_mut(username) else {
            return Err(awg_error("not found", 404, Some("not_found")));
        };
        if !known {
            row["public_key"] = payload["public_key"].clone();
            row["preshared_key"] = payload["preshared_key"].clone();
            row["revision"] = json!(row["revision"].as_i64().unwrap_or(0) + 1);
            state.operations.insert(operation_id, json!({"body": {"username": username}}));
        }
        Ok(json!({"peer": Self::view(&state, username)}))
    }

    async fn delete_peer(&self, username: &str) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        if state.peers.shift_remove(username).is_none() {
            return Err(awg_error("not found", 404, Some("not_found")));
        }
        Ok(Value::Null)
    }

    async fn egress(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        let document = Self::document(&state);
        let warp = !document["upstream"].is_null();
        Ok(json!({"revision": state.egress_revision.to_string(), "mode": if warp { "proxy" } else { "direct" },
                  "document": document, "managed": !state.egress_history.is_empty(),
                  "providers": {"warp": {"reachable": null}, "router": {"reachable": true}},
                  "router": {"device": "awgxr", "present": true, "attached": true},
                  "capabilities": ["whole_direct", "whole_warp"], "restart_required": false, "warnings": [],
                  "warp": {"registered": false, "address": null, "endpoint": null, "account_type": "free",
                           "tunnel": "off", "latest_handshake": null, "rx": 0, "tx": 0}}))
    }

    async fn egress_plan(&self, _expected_revision: &str, document: &Value) -> ManagerResult {
        let state = self.state();
        Ok(json!({"revision": state.egress_revision.to_string(), "target": document, "diff": [],
                  "restart_required": false, "warnings": [], "reachability": {"warp": true}}))
    }

    async fn egress_apply(&self, expected_revision: &str, document: &Value, _operation_id: &str) -> ManagerResult {
        let mut state = self.state();
        if expected_revision != state.egress_revision.to_string() {
            return Err(awg_error("AmneziaWG manager rejected request", 409, Some("egress_conflict")));
        }
        state.egress_history.push(document.clone());
        state.egress_revision += 1;
        Ok(json!({"revision": state.egress_revision.to_string(), "applied": document, "replayed": false}))
    }

    async fn egress_rollback(&self, _expected_revision: &str) -> ManagerResult {
        Err(awg_error("AmneziaWG manager rejected request", 409, Some("egress_no_previous")))
    }
}

// -- TrustTunnel ----------------------------------------------------------------------------------

fn tt_error(message: &str, status: u16, code: Option<&str>) -> ManagerError {
    ManagerError::new(Manager::Trusttunnel, message, status, code)
}

pub struct TrusttunnelState {
    pub hostname: String,
    pub public_port: i64,
    pub clients: IndexMap<String, Value>,
    pub operations: IndexMap<String, Value>,
    pub broken: bool,
    pub egress_document: Value,
    pub egress_previous: Option<Value>,
}

#[derive(Clone)]
pub struct MemoryTrusttunnel(pub Arc<Mutex<TrusttunnelState>>);

impl MemoryTrusttunnel {
    pub fn new(hostname: &str) -> Self {
        Self(Arc::new(Mutex::new(TrusttunnelState {
            hostname: hostname.into(),
            public_port: 443,
            clients: IndexMap::new(),
            operations: IndexMap::new(),
            broken: false,
            egress_document: json!({"mode": "direct", "address": null}),
            egress_previous: None,
        })))
    }

    pub fn state(&self) -> MutexGuard<'_, TrusttunnelState> {
        lock(&self.0)
    }

    fn view(state: &TrusttunnelState, username: &str) -> Value {
        let row = &state.clients[username];
        json!({"username": username, "enabled": row["enabled"], "revision": row["revision"],
               "rx": row.get("rx").cloned().unwrap_or(json!(0)), "tx": row.get("tx").cloned().unwrap_or(json!(0)),
               "sessions": 0})
    }

    fn guard(state: &TrusttunnelState) -> Result<(), ManagerError> {
        if state.broken {
            return Err(ManagerError::plain(Manager::Trusttunnel, "unavailable"));
        }
        Ok(())
    }

    fn egress_view(document: &Value) -> Value {
        let revision =
            sha256_hex(pyjson::canonical(&json!({"mode": document["mode"], "address": document["address"]})));
        let mut view = document.clone();
        view["revision"] = json!(revision);
        view
    }
}

impl TrusttunnelApi for MemoryTrusttunnel {
    async fn endpoint(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        Ok(json!({"hostname": state.hostname, "listen": "127.0.0.1:4453", "public_port": state.public_port,
                  "version": "1.1.0", "certificate_trusted": true, "certificate_der_b64": null,
                  "fingerprint": sha256_hex("trusted")}))
    }

    async fn clients(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        let mut names: Vec<&String> = state.clients.keys().collect();
        names.sort();
        Ok(Value::Array(names.into_iter().map(|name| Self::view(&state, name)).collect()))
    }

    async fn create_client(&self, payload: &Value) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        let username = payload["username"].as_str().unwrap_or_default().to_string();
        let operation_id = payload["operation_id"].as_str().unwrap_or_default().to_string();
        let body = json!({"username": username, "password": payload["password"]});
        if let Some(known) = state.operations.get(&operation_id) {
            if known["body"] != body {
                return Err(tt_error("operation id reused", 409, Some("operation_conflict")));
            }
            return Ok(json!({"client": Self::view(&state, &username)}));
        }
        if state.clients.contains_key(&username) {
            return Err(tt_error("username exists", 409, Some("exists")));
        }
        state
            .clients
            .insert(username.clone(), json!({"enabled": true, "password": payload["password"], "revision": 1}));
        state.operations.insert(operation_id, json!({"body": body}));
        Ok(json!({"client": Self::view(&state, &username)}))
    }

    async fn client_state(&self, username: &str, action: &str) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        let Some(row) = state.clients.get_mut(username) else {
            return Err(tt_error("not found", 404, Some("not_found")));
        };
        let enabled = action == "enable";
        if row["enabled"] != json!(enabled) {
            row["enabled"] = json!(enabled);
            row["revision"] = json!(row["revision"].as_i64().unwrap_or(0) + 1);
        }
        Ok(json!({"client": Self::view(&state, username)}))
    }

    async fn rotate_client(&self, username: &str, payload: &Value) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        let Some(row) = state.clients.get_mut(username) else {
            return Err(tt_error("not found", 404, Some("not_found")));
        };
        row["password"] = payload["password"].clone();
        row["revision"] = json!(row["revision"].as_i64().unwrap_or(0) + 1);
        Ok(json!({"client": Self::view(&state, username)}))
    }

    async fn delete_client(&self, username: &str) -> ManagerResult {
        let mut state = self.state();
        Self::guard(&state)?;
        state.clients.shift_remove(username);
        Ok(Value::Null)
    }

    async fn egress(&self) -> ManagerResult {
        let state = self.state();
        Self::guard(&state)?;
        Ok(Self::egress_view(&state.egress_document))
    }

    async fn egress_plan(&self, document: &Value) -> ManagerResult {
        let state = self.state();
        Ok(json!({"changed": *document != state.egress_document, "current": Self::egress_view(&state.egress_document),
                  "proposed": Self::egress_view(document)}))
    }

    async fn egress_apply(&self, document: &Value) -> ManagerResult {
        let mut state = self.state();
        if *document != state.egress_document {
            let previous = std::mem::replace(&mut state.egress_document, document.clone());
            state.egress_previous = Some(previous);
        }
        Ok(Self::egress_view(&state.egress_document))
    }

    async fn egress_rollback(&self) -> ManagerResult {
        Err(tt_error("nothing to roll back to", 409, Some("no_previous")))
    }
}
