//! Transactional, fail-closed manager for the separate GPL mita daemon.
//!
//! Every change is a whole-config transaction: snapshot the observed config to a backup,
//! write an authenticated journal, apply, read back, reload or restart, probe — and on any
//! failure put the snapshot back and restart, or say plainly that a person must recover it.
//! The state file (`state.json`, canonical JSON) carries the revision a caller must name to
//! change anything, the disabled users, the tombstoned names, replay records, the egress
//! journal and the lanes.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::egress::{self, Credential, Providers};
use crate::error::{Error, Result};
use crate::lanes::{self, Slot};
use crate::mita::{Mita, MitaCli};
use crate::validate::validate_config;
use crate::{pyjson, pyurl, util};

pub type State = Map<String, Value>;
pub type SlotFactory = Box<dyn Fn(&Slot) -> Arc<dyn Mita> + Send + Sync>;
/// `(url, timeout, auth)`: a SOCKS5 greeting answered with the offered method.
pub type Reachability = Box<dyn Fn(Option<&str>, f64, bool) -> bool + Send + Sync>;
pub type TokenSource = Box<dyn Fn() -> Result<String> + Send + Sync>;

const STATE_KEYS: [&str; 7] =
    ["version", "generation", "revision", "config_hash", "disabled", "tombstones", "metric_baselines"];
/// `operations` appears the first time an idempotent request is recorded, `egress` the first
/// time one is applied, so a state file written by an older manager stays readable.
const OPTIONAL_STATE_KEYS: [&str; 4] = ["operations", "egress", "lanes", "lanes_stale"];
const OPERATION_FIELDS: [&str; 5] = ["operation", "username", "revision", "completed_at", "credential_origin"];
const OPERATION_RETENTION_SECONDS: f64 = 7.0 * 86400.0;
const JOURNAL_FIELDS: [&str; 15] = [
    "version",
    "schema",
    "phase",
    "operation",
    "mode",
    "previous_config_hash",
    "desired_config_hash",
    "state_revision",
    "state_generation",
    "next_revision",
    "next_generation",
    "backup_basename",
    "backup_size",
    "backup_sha256",
    "mac",
];
const JOURNAL_SCHEMA: &str = "mieru-transaction-journal-v3";

/// How each operation reaches the running daemon. `dynamic`: reload, unless an added user is
/// allowed private or loopback targets (mita applies those flags only on a restart).
fn transaction_mode(operation: &str) -> Option<&'static str> {
    Some(match operation {
        "user.create" => "dynamic",
        "user.rotate" | "user.enable" | "user.disable" | "user.delete" => "restart",
        "user.quotas" => "reload",
        // `mita reload` re-reads users, not the egress section.
        "egress.apply" | "egress.rollback" => "restart",
        // The router ingress credential rotated while the manager was down.
        "egress.refresh" => "restart",
        _ => return None,
    })
}

/// A caller-supplied credential, so the panel can escrow it before mita commits.
pub fn is_password(text: &str) -> bool {
    (16..=128).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'~' | b'-'))
}

pub fn is_operation_id(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-'))
}

/// `MITA_VERSION`: an optional `mita ` and something shaped like a version.
pub fn mita_version(text: &str) -> Option<String> {
    let mut rest = text;
    if let Some(after) = rest.strip_prefix("mita") {
        let trimmed = after.trim_start_matches(char::is_whitespace);
        if trimmed.len() < after.len() {
            rest = trimmed;
        }
    }
    let numbers: Vec<&str> = rest.splitn(3, '.').collect();
    if numbers.len() != 3 {
        return None;
    }
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    let third_len = numbers[2].chars().take_while(char::is_ascii_digit).count();
    let tail = &numbers[2][third_len..];
    let tail_ok = tail.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'));
    (digits(numbers[0]) && digits(numbers[1]) && third_len > 0 && tail_ok).then(|| rest.to_string())
}

fn get<'a>(state: &'a State, key: &str) -> Result<&'a Value> {
    state.get(key).ok_or_else(|| Error::internal(format!("state has no {key}")))
}

fn get_str<'a>(state: &'a State, key: &str) -> Result<&'a str> {
    get(state, key)?.as_str().ok_or_else(|| Error::internal(format!("state {key} is not a string")))
}

fn map_mut<'a>(state: &'a mut State, key: &str) -> Result<&'a mut Map<String, Value>> {
    state
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::internal(format!("state {key} is not an object")))
}

fn list_mut<'a>(state: &'a mut State, key: &str) -> Result<&'a mut Vec<Value>> {
    state
        .get_mut(key)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::internal(format!("state {key} is not a list")))
}

/// `name in container` for the containers the state holds: a dict's keys or a list's items.
fn contains(container: &Value, name: &Value) -> bool {
    match container {
        Value::Object(map) => name.as_str().is_some_and(|n| map.contains_key(n)),
        Value::Array(items) => items.iter().any(|item| pyjson::eq(item, name)),
        Value::String(text) => name.as_str().is_some_and(|n| text.contains(n)),
        _ => false,
    }
}

fn users_of(config: &Value) -> &[Value] {
    config.get("users").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn hash_value(value: &Value) -> String {
    util::hash(value)
}

/// `_pruned_operations`: replay records, never secrets — who did what, not the credential.
fn pruned_operations(operations: Option<&Value>) -> Result<Value> {
    let invalid = || Error::conflict("invalid operation state");
    let operations = match operations {
        None | Some(Value::Null) => return Ok(Value::Object(Map::new())),
        Some(Value::Object(map)) => map,
        Some(_) => return Err(invalid()),
    };
    let cutoff = util::now_timestamp() - OPERATION_RETENTION_SECONDS;
    let mut kept = Map::new();
    for (key, record) in operations {
        let record_ok = record.as_object().is_some_and(|r| {
            r.len() == OPERATION_FIELDS.len()
                && OPERATION_FIELDS.iter().all(|f| r.contains_key(*f))
                && matches!(r["operation"].as_str(), Some("user.create" | "user.rotate"))
                && matches!(r["credential_origin"].as_str(), Some("caller" | "manager"))
                && r["completed_at"].is_string()
        });
        if !is_operation_id(key) || !record_ok {
            return Err(invalid());
        }
        let completed =
            util::fromisoformat_timestamp(record["completed_at"].as_str().unwrap_or_default()).ok_or_else(invalid)?;
        if completed >= cutoff {
            kept.insert(key.clone(), record.clone());
        }
    }
    Ok(Value::Object(kept))
}

/// `_transaction_mode`: the mode an operation needs for this change.
fn mode_for(operation: &str, before: &Value, desired: &Value) -> Result<&'static str> {
    let mode = transaction_mode(operation).ok_or_else(|| Error::validation("invalid transaction metadata"))?;
    if mode != "dynamic" {
        return Ok(mode);
    }
    let old: Vec<Value> = users_of(before).iter().map(|row| row.get("name").cloned().unwrap_or(Value::Null)).collect();
    let privileged = users_of(desired)
        .iter()
        .filter(|row| {
            let name = row.get("name").cloned().unwrap_or(Value::Null);
            !old.iter().any(|known| pyjson::eq(known, &name))
        })
        .any(|row| {
            row.get("allowPrivateIP") == Some(&Value::Bool(true))
                || row.get("allowLoopbackIP") == Some(&Value::Bool(true))
        });
    Ok(if privileged { "restart" } else { "reload" })
}

/// `_expected`: the config as mita will read it back — a fresh password replaced by its stored
/// hash beside a blanked field, an empty quota list left out.
fn expected_readback(config: &Value) -> Value {
    let mut result = config.clone();
    if let Some(Value::Array(users)) = result.get_mut("users") {
        for user in users.iter_mut().filter_map(Value::as_object_mut) {
            // Only a freshly supplied password is hashed: re-hashing the blanked one of an
            // earlier user would replace its credential and fail the readback.
            if user.get("password").is_some_and(pyjson::truthy) {
                let raw = user["password"].as_str().unwrap_or_default().to_string();
                let name = user.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
                user.insert("password".into(), json!(""));
                user.insert("hashedPassword".into(), json!(util::sha256_hex(format!("{raw}\0{name}").as_bytes())));
            }
            if user.get("quotas").is_some_and(|q| q.as_array().is_some_and(Vec::is_empty)) {
                user.shift_remove("quotas");
            }
        }
    }
    result
}

struct Writer<'a> {
    _guard: MutexGuard<'a, ()>,
    _file: File,
}

pub struct MieruManager {
    mita: Arc<dyn Mita>,
    state_dir: PathBuf,
    public_host: String,
    lane_slots: Vec<Slot>,
    slot_factory: SlotFactory,
    slot_clients: Mutex<BTreeMap<u32, Arc<dyn Mita>>>,
    status_timeout: Duration,
    status_poll_interval: Duration,
    providers: Providers,
    router_credential_file: Option<PathBuf>,
    reachability: Reachability,
    token: TokenSource,
    lock: Mutex<()>,
    pub state_file: PathBuf,
    journal_file: PathBuf,
    journal_key_file: PathBuf,
    backup_dir: PathBuf,
    lock_file: PathBuf,
}

/// Lane slots driven by the CLI: the main daemon's executable, environment and pin, the
/// slot's own socket and config file.
pub fn cli_slot_factory(
    executable: PathBuf,
    env: Vec<(String, String)>,
    expected_sha256: Option<String>,
) -> SlotFactory {
    Box::new(move |slot: &Slot| {
        let mut slot_env = env.clone();
        slot_env.retain(|(key, _)| key != "MITA_UDS_PATH" && key != "MITA_CONFIG_JSON_FILE");
        slot_env.push(("MITA_UDS_PATH".into(), slot.uds.clone()));
        slot_env.push(("MITA_CONFIG_JSON_FILE".into(), format!("{}/server_config.json", slot.state_dir)));
        Arc::new(MitaCli::new(executable.clone(), slot_env, expected_sha256.clone())) as Arc<dyn Mita>
    })
}

impl MieruManager {
    pub fn new(mita: Arc<dyn Mita>, state_dir: impl Into<PathBuf>, public_host: impl Into<String>) -> Self {
        let state_dir = state_dir.into();
        Self {
            mita,
            public_host: public_host.into(),
            lane_slots: Vec::new(),
            slot_factory: cli_slot_factory(PathBuf::from("/usr/bin/mita"), Vec::new(), None),
            slot_clients: Mutex::new(BTreeMap::new()),
            status_timeout: Duration::from_secs(10),
            status_poll_interval: Duration::from_millis(50),
            providers: Providers::default(),
            router_credential_file: None,
            reachability: Box::new(egress::check_reachable),
            token: Box::new(|| util::token_urlsafe(24)),
            lock: Mutex::new(()),
            state_file: state_dir.join("state.json"),
            journal_file: state_dir.join("journal.json"),
            journal_key_file: state_dir.join("journal.key"),
            backup_dir: state_dir.join("backups"),
            lock_file: state_dir.join("writer.lock"),
            state_dir,
        }
    }

    /// The WARP proxy-mode endpoint (v0.4), this service's router ingress and its credential
    /// file (v0.5): the only addresses the egress API ever writes into mita's config.
    pub fn with_providers(mut self, warp: Option<String>, router: Option<String>, credential: Option<PathBuf>) -> Self {
        self.providers = Providers { warp, router };
        self.router_credential_file = credential;
        self
    }

    /// The installer's slot daemons for lanes (v0.7) and how to reach each.
    pub fn with_lanes(mut self, slots: Vec<Slot>, factory: Option<SlotFactory>) -> Self {
        self.lane_slots = slots;
        if let Some(factory) = factory {
            self.slot_factory = factory;
        }
        self
    }

    #[cfg(test)]
    pub fn with_status_timing(mut self, timeout: Duration, interval: Duration) -> Self {
        self.status_timeout = timeout;
        self.status_poll_interval = interval;
        self
    }

    #[cfg(test)]
    pub fn with_reachability(mut self, reachability: Reachability) -> Self {
        self.reachability = reachability;
        self
    }

    #[cfg(test)]
    pub fn with_token(mut self, token: TokenSource) -> Self {
        self.token = token;
        self
    }

    fn router_url(&self) -> Option<&str> {
        self.providers.router.as_deref().filter(|u| !u.is_empty())
    }

    fn warp_url(&self) -> Option<&str> {
        self.providers.warp.as_deref().filter(|u| !u.is_empty())
    }

    fn probe(&self) -> Result<()> {
        self.mita.probe()
    }

    fn writer(&self) -> Result<Writer<'_>> {
        util::mkdir(&self.state_dir, 0o700)?;
        let guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let file = OpenOptions::new().read(true).append(true).create(true).open(&self.lock_file)?;
        fs::set_permissions(&self.lock_file, fs::Permissions::from_mode(0o600))?;
        loop {
            // SAFETY: flock on a descriptor owned by `file`, which outlives the lock.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err.into());
            }
        }
        Ok(Writer { _guard: guard, _file: file })
    }

    // ------------------------------------------------------------------ state

    /// `_state()`: the state file, validated, with expired replay records dropped.
    pub fn read_state(&self) -> Result<State> {
        let info = fs::symlink_metadata(&self.state_file)?;
        if !info.file_type().is_file() || info.permissions().mode() & 0o077 != 0 {
            return Err(Error::conflict("unsafe manager state"));
        }
        let invalid = || Error::conflict("invalid manager state");
        let text = fs::read(&self.state_file).map_err(|_| invalid())?;
        let text = String::from_utf8(text).map_err(|_| invalid())?;
        let Value::Object(mut state) = serde_json::from_str(&text).map_err(|_| invalid())? else {
            return Err(invalid());
        };
        let generation_ok = state.get("generation").and_then(pyjson::int_of).is_some_and(|g| g >= 0);
        if !STATE_KEYS.iter().all(|k| state.contains_key(*k))
            || state.keys().any(|k| !STATE_KEYS.contains(&k.as_str()) && !OPTIONAL_STATE_KEYS.contains(&k.as_str()))
            || !pyjson::eq_int(&state["version"], 2)
            || !generation_ok
        {
            return Err(invalid());
        }
        let operations = pruned_operations(state.get("operations"))?;
        state.insert("operations".into(), operations);
        if !state.contains_key("lanes") {
            state.insert("lanes".into(), Value::Object(Map::new()));
        }
        let lanes_ok = state["lanes"].as_object().is_some_and(|lanes| {
            lanes.iter().all(|(lane, entry)| {
                lanes::is_lane_id(lane)
                    && entry.as_object().is_some_and(|e| {
                        e.len() == 3
                            && e.get("slot").and_then(pyjson::int_of).is_some()
                            && e.get("users").is_some_and(Value::is_array)
                            && e.get("upstream")
                                .and_then(Value::as_object)
                                .is_some_and(|u| u.len() == 2 && u.contains_key("user") && u.contains_key("password"))
                    })
            })
        });
        if !lanes_ok {
            return Err(Error::conflict("invalid lanes state"));
        }
        Ok(state)
    }

    fn write_state(&self, state: &State) -> Result<()> {
        util::atomic_json(&self.state_file, &Value::Object(state.clone()))?;
        Ok(())
    }

    fn journal_key(&self) -> Result<Vec<u8>> {
        if !util::lexists(&self.journal_key_file) {
            if util::lexists(&self.journal_file) {
                return Err(Error::conflict("transaction recovery authentication unavailable"));
            }
            util::atomic_write(&self.journal_key_file, &util::random_bytes(32)?)?;
        }
        let key = util::read_secure(&self.journal_key_file, 32)?;
        if key.len() != 32 {
            return Err(Error::conflict("invalid transaction recovery authentication"));
        }
        Ok(key)
    }

    fn write_journal(&self, journal: &Map<String, Value>) -> Result<()> {
        let mut authenticated = journal.clone();
        authenticated.shift_remove("mac");
        let mac = util::hmac_sha256_hex(
            &self.journal_key()?,
            pyjson::canonical(&Value::Object(authenticated.clone())).as_bytes(),
        );
        authenticated.insert("mac".into(), json!(mac));
        util::atomic_json(&self.journal_file, &Value::Object(authenticated))?;
        Ok(())
    }

    fn remove_journal(&self) -> Result<()> {
        match fs::remove_file(&self.journal_file) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        util::fsync_dir(&self.state_dir)?;
        Ok(())
    }

    fn check_revision(state: &State, expected: &Value) -> Result<()> {
        let current = get(state, "revision")?.as_str().unwrap_or_default();
        match expected.as_str() {
            Some(expected) if pc_common::constant_time_eq(current.as_bytes(), expected.as_bytes()) => Ok(()),
            _ => Err(Error::conflict("desired revision does not match")),
        }
    }

    fn observed_consistent(&self, state: &State) -> Result<Value> {
        let observed = Value::Object(self.mita.observe()?);
        validate_config(&observed, true)?;
        if hash_value(&observed) != get_str(state, "config_hash")? {
            return Err(Error::conflict("observed config changed outside manager"));
        }
        Ok(observed)
    }

    // ------------------------------------------------------------------ lifecycle

    pub fn bootstrap(&self) -> Result<Value> {
        let _writer = self.writer()?;
        self.journal_key()?;
        if util::lexists(&self.journal_file) {
            self.recover()?;
        }
        let version = self.mita.version()?;
        let Some(version) = mita_version(pyjson::strip(&version)) else {
            return Err(Error::conflict("mita did not report its version"));
        };
        let observed = Value::Object(self.mita.observe()?);
        validate_config(&observed, true)?;
        let state = if self.state_file.exists() {
            let mut state = self.read_state()?;
            if get_str(&state, "config_hash")? != hash_value(&observed) {
                return Err(Error::conflict("observed config changed outside manager"));
            }
            self.refresh_router_credential(&mut state, &observed)?;
            let state = self.read_state()?;
            if state.get("lanes").is_some_and(pyjson::truthy) {
                self.sync_slots(&state, &Value::Object(self.mita.observe()?))?;
            }
            state
        } else {
            let digest = hash_value(&observed);
            let state = json!({
                "version": 2,
                "generation": 0,
                "revision": digest,
                "config_hash": digest,
                "disabled": {},
                "tombstones": [],
                "metric_baselines": {},
            });
            util::atomic_json(&self.state_file, &state)?;
            state.as_object().cloned().unwrap_or_default()
        };
        Ok(json!({
            "ready": self.mita.status()? == "RUNNING",
            "version": version,
            "revision": get(&state, "revision")?,
        }))
    }

    pub fn inspect(&self) -> Result<Value> {
        let _writer = self.writer()?;
        let state = self.read_state()?;
        let observed = Value::Object(self.mita.observe()?);
        validate_config(&observed, true)?;
        if hash_value(&observed) != get_str(&state, "config_hash")? {
            return Err(Error::conflict("observed config changed outside manager"));
        }
        let status = self.mita.status()?.to_uppercase();
        Ok(json!({"revision": get(&state, "revision")?, "ready": status == "RUNNING", "status": status.to_lowercase()}))
    }

    fn wait_status(&self, target: &str, error: &str) -> Result<String> {
        let deadline = Instant::now() + self.status_timeout;
        loop {
            let status = self.mita.status()?.to_uppercase();
            if status == target {
                return Ok(status);
            }
            if !matches!(status.as_str(), "STARTING" | "STOPPING") || Instant::now() >= deadline {
                return Err(Error::mita(error));
            }
            std::thread::sleep(self.status_poll_interval.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    pub fn lifecycle(&self, action: &str) -> Result<Value> {
        if !matches!(action, "start" | "stop" | "restart") {
            return Err(Error::validation("invalid lifecycle action"));
        }
        let _writer = self.writer()?;
        let state = self.read_state()?;
        let config_hash = get_str(&state, "config_hash")?.to_string();
        let before = Value::Object(self.mita.observe()?);
        validate_config(&before, true)?;
        if hash_value(&before) != config_hash {
            return Err(Error::conflict("observed config changed outside manager"));
        }
        if action == "stop" {
            self.mita.stop()?;
        } else {
            if action == "restart" {
                self.mita.stop()?;
                self.wait_status("IDLE", "mita failed to reach idle state")?;
            }
            self.mita.start()?;
        }
        let after = Value::Object(self.mita.observe()?);
        validate_config(&after, true)?;
        if hash_value(&after) != config_hash {
            return Err(Error::conflict("lifecycle changed observed configuration"));
        }
        let status = if action == "stop" {
            self.wait_status("IDLE", "mita failed to reach idle state")?
        } else {
            let status = self.wait_status("RUNNING", "mita failed to reach running state")?;
            self.probe()?;
            status
        };
        Ok(json!({"revision": get(&state, "revision")?, "ready": status == "RUNNING", "status": status.to_lowercase()}))
    }

    // ------------------------------------------------------------------ users

    pub fn list_users(&self) -> Result<Value> {
        let _writer = self.writer()?;
        let state = self.read_state()?;
        let config = Value::Object(self.mita.observe()?);
        let mut lane_of: Vec<(Value, String)> = Vec::new();
        for (lane, entry) in get(&state, "lanes")?.as_object().into_iter().flatten() {
            for user in entry["users"].as_array().into_iter().flatten() {
                lane_of.push((user.clone(), lane.clone()));
            }
        }
        // A dict comprehension keeps the last lane naming a user.
        let lane_for = |name: &Value| -> Value {
            lane_of.iter().rev().find(|(user, _)| pyjson::eq(user, name)).map_or(Value::Null, |(_, lane)| json!(lane))
        };
        let mut rows = Vec::new();
        for row in users_of(&config) {
            let name = row.get("name").ok_or_else(|| Error::internal("user row without a name"))?;
            rows.push(json!({
                "username": name,
                "enabled": true,
                "quotas": row.get("quotas").cloned().unwrap_or_else(|| json!([])),
                "lane": lane_for(name),
            }));
        }
        for (name, row) in
            get(&state, "disabled")?.as_object().ok_or_else(|| Error::internal("disabled is not a dict"))?
        {
            rows.push(json!({
                "username": name,
                "enabled": false,
                "quotas": row.get("quotas").cloned().unwrap_or_else(|| json!([])),
                "lane": lane_for(&json!(name)),
            }));
        }
        rows.sort_by(|a, b| pyjson::py_str(&a["username"]).cmp(&pyjson::py_str(&b["username"])));
        Ok(Value::Array(rows))
    }

    fn validate_credential(password: Option<&Value>, operation_id: Option<&Value>) -> Result<()> {
        if let Some(password) = password.filter(|v| !v.is_null()) {
            if !password.as_str().is_some_and(is_password) {
                return Err(Error::validation("invalid password"));
            }
        }
        if let Some(operation_id) = operation_id.filter(|v| !v.is_null()) {
            if !operation_id.as_str().is_some_and(is_operation_id) {
                return Err(Error::validation("invalid operation id"));
            }
        }
        Ok(())
    }

    /// Answer a retry from the journal, or refuse honestly: the journal holds no credential, so
    /// a manager-generated password cannot be handed out twice.
    fn replay(state: &State, operation_id: Option<&str>, operation: &str, username: &str) -> Result<Option<Value>> {
        let Some(operation_id) = operation_id else { return Ok(None) };
        let Some(record) = state.get("operations").and_then(|ops| ops.get(operation_id)) else { return Ok(None) };
        if record["operation"].as_str() != Some(operation) || record["username"].as_str() != Some(username) {
            return Err(Error::conflict("operation id already used for another request"));
        }
        if record["credential_origin"].as_str() != Some("caller") {
            return Err(Error::conflict("operation result is unrecoverable; rotate the credential"));
        }
        Ok(Some(json!({"username": username, "revision": record["revision"], "replayed": true})))
    }

    fn record(operation: &str, username: &str, password: Option<&str>) -> Value {
        json!({
            "operation": operation,
            "username": username,
            "revision": null,
            "completed_at": util::now_isoformat(),
            "credential_origin": if password.is_some_and(|p| !p.is_empty()) { "caller" } else { "manager" },
        })
    }

    fn find_active(config: &Value, username: &str) -> Result<usize> {
        users_of(config)
            .iter()
            .position(|row| row.get("name").and_then(Value::as_str) == Some(username))
            .ok_or_else(|| Error::conflict("user not found"))
    }

    fn users_mut(config: &mut Value) -> Result<&mut Vec<Value>> {
        let map = config.as_object_mut().ok_or_else(|| Error::internal("config is not an object"))?;
        if !map.contains_key("users") {
            map.insert("users".into(), json!([]));
        }
        map.get_mut("users").and_then(Value::as_array_mut).ok_or_else(|| Error::internal("users is not a list"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_user(
        &self,
        username: &Value,
        quotas: &Value,
        expected_revision: &Value,
        elevated: &Value,
        allow_private_ip: &Value,
        allow_loopback_ip: &Value,
        password: Option<&Value>,
        operation_id: Option<&Value>,
    ) -> Result<Value> {
        let _writer = self.writer()?;
        let Some(username) = username.as_str().filter(|u| !u.is_empty() && u.len() <= 64) else {
            return Err(Error::validation("invalid username"));
        };
        Self::validate_credential(password, operation_id)?;
        let password = password.and_then(Value::as_str);
        let operation_id = operation_id.and_then(Value::as_str);
        let mut state = self.read_state()?;
        if let Some(replayed) = Self::replay(&state, operation_id, "user.create", username)? {
            // A retry carries the revision it saw before the response was lost, so the replay
            // answers before the compare-and-swap can reject it.
            return Ok(replayed);
        }
        Self::check_revision(&state, expected_revision)?;
        let name = json!(username);
        if contains(get(&state, "tombstones")?, &name) {
            return Err(Error::conflict("username reuse is forbidden"));
        }
        let mut config = Value::Object(self.mita.observe()?);
        if users_of(&config).iter().any(|row| row.get("name").and_then(Value::as_str) == Some(username))
            || contains(get(&state, "disabled")?, &name)
        {
            return Err(Error::conflict("user already exists"));
        }
        let flagged = pyjson::truthy(allow_private_ip) || pyjson::truthy(allow_loopback_ip);
        if flagged && !pyjson::truthy(elevated) {
            return Err(Error::validation("private/loopback SSRF flags require elevated approval"));
        }
        let raw = match password {
            Some(password) if !password.is_empty() => password.to_string(),
            _ => (self.token)()?,
        };
        let mut user = json!({"name": username, "password": raw, "quotas": quotas});
        if pyjson::truthy(allow_private_ip) {
            user["allowPrivateIP"] = json!(true);
        }
        if pyjson::truthy(allow_loopback_ip) {
            user["allowLoopbackIP"] = json!(true);
        }
        Self::users_mut(&mut config)?.push(user);
        let share_url = self.share(username, &raw, &config)?;
        let mode = if flagged { "restart" } else { "reload" };
        let record = operation_id.map(|op| (op.to_string(), Self::record("user.create", username, password)));
        let revision = self.transaction(config, &mut state, mode, "user.create", record)?;
        Ok(json!({"username": username, "share_url": share_url, "revision": revision}))
    }

    pub fn disable_user(&self, username: &str, expected_revision: &Value) -> Result<Value> {
        let _writer = self.writer()?;
        let mut state = self.read_state()?;
        Self::check_revision(&state, expected_revision)?;
        let mut config = Value::Object(self.mita.observe()?);
        let index = Self::find_active(&config, username)?;
        let row = Self::users_mut(&mut config)?.remove(index);
        map_mut(&mut state, "disabled")?.insert(username.into(), row);
        let revision = self.transaction(config, &mut state, "restart", "user.disable", None)?;
        Ok(json!({"username": username, "enabled": false, "revision": revision}))
    }

    pub fn enable_user(&self, username: &str, expected_revision: &Value) -> Result<Value> {
        let _writer = self.writer()?;
        let mut state = self.read_state()?;
        Self::check_revision(&state, expected_revision)?;
        if !contains(get(&state, "disabled")?, &json!(username)) {
            return Err(Error::conflict("user not found"));
        }
        let mut config = Value::Object(self.mita.observe()?);
        let row = map_mut(&mut state, "disabled")?.shift_remove(username).unwrap_or(Value::Null);
        Self::users_mut(&mut config)?.push(row);
        let revision = self.transaction(config, &mut state, "restart", "user.enable", None)?;
        Ok(json!({"username": username, "enabled": true, "revision": revision}))
    }

    pub fn rotate_user(
        &self,
        username: &str,
        expected_revision: &Value,
        password: Option<&Value>,
        operation_id: Option<&Value>,
    ) -> Result<Value> {
        let _writer = self.writer()?;
        Self::validate_credential(password, operation_id)?;
        let password = password.and_then(Value::as_str);
        let operation_id = operation_id.and_then(Value::as_str);
        let mut state = self.read_state()?;
        if let Some(replayed) = Self::replay(&state, operation_id, "user.rotate", username)? {
            return Ok(replayed);
        }
        Self::check_revision(&state, expected_revision)?;
        let mut config = Value::Object(self.mita.observe()?);
        let index = Self::find_active(&config, username)?;
        let raw = match password {
            Some(password) if !password.is_empty() => password.to_string(),
            _ => (self.token)()?,
        };
        let users = Self::users_mut(&mut config)?;
        let mut row: Map<String, Value> = users[index]
            .as_object()
            .map(|old| {
                old.iter().filter(|(k, _)| *k != "hashedPassword").map(|(k, v)| (k.clone(), v.clone())).collect()
            })
            .unwrap_or_default();
        row.insert("password".into(), json!(raw));
        users[index] = Value::Object(row);
        let share_url = self.share(username, &raw, &config)?;
        let record = operation_id.map(|op| (op.to_string(), Self::record("user.rotate", username, password)));
        let revision = self.transaction(config, &mut state, "restart", "user.rotate", record)?;
        Ok(json!({"username": username, "share_url": share_url, "revision": revision}))
    }

    pub fn delete_user(&self, username: &str, expected_revision: &Value) -> Result<Value> {
        let _writer = self.writer()?;
        let mut state = self.read_state()?;
        Self::check_revision(&state, expected_revision)?;
        let mut config = Value::Object(self.mita.observe()?);
        let name = json!(username);
        if contains(get(&state, "disabled")?, &name) {
            map_mut(&mut state, "disabled")?.shift_remove(username);
        } else {
            let index = Self::find_active(&config, username)?;
            Self::users_mut(&mut config)?.remove(index);
        }
        list_mut(&mut state, "tombstones")?.push(name.clone());
        for entry in map_mut(&mut state, "lanes")?.values_mut() {
            if let Some(users) = entry.get_mut("users").and_then(Value::as_array_mut) {
                if let Some(at) = users.iter().position(|u| pyjson::eq(u, &name)) {
                    users.remove(at);
                }
            }
        }
        let revision = self.transaction(config, &mut state, "restart", "user.delete", None)?;
        Ok(json!({"username": username, "revision": revision}))
    }

    pub fn set_quotas(&self, username: &str, quotas: &Value, expected_revision: &Value) -> Result<Value> {
        let _writer = self.writer()?;
        let mut state = self.read_state()?;
        Self::check_revision(&state, expected_revision)?;
        let mut config = Value::Object(self.mita.observe()?);
        let index = Self::find_active(&config, username)?;
        if let Some(row) = Self::users_mut(&mut config)?[index].as_object_mut() {
            row.insert("quotas".into(), quotas.clone());
        }
        let revision = self.transaction(config, &mut state, "reload", "user.quotas", None)?;
        Ok(json!({"username": username, "revision": revision}))
    }

    pub fn metrics(&self) -> Result<Value> {
        let _writer = self.writer()?;
        Ok(json!({
            "status": "error",
            "stale": true,
            "users": [],
            "capability": "unavailable",
            "reason": "typed_histories_unavailable",
        }))
    }

    pub fn reset_metric_baseline(&self, _username: &str) -> Result<Value> {
        let _writer = self.writer()?;
        Err(Error::conflict("per-user Mieru metrics capability is unavailable"))
    }

    /// Live per-user byte counters for the monitor: the main daemon plus every running lane
    /// slot, summed per user. Read-only: no lock, so a slow transaction never stalls the poll.
    pub fn traffic(&self) -> Result<Value> {
        let mut totals: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut clients = vec![self.mita.clone()];
        clients.extend(self.lane_slots.iter().map(|slot| self.slot_client(slot)));
        for (index, client) in clients.iter().enumerate() {
            if index > 0 && client.status()? != "RUNNING" {
                continue;
            }
            for (name, (up, down)) in client.traffic()? {
                let row = totals.entry(name).or_insert((0, 0));
                row.0 = row.0.saturating_add(up);
                row.1 = row.1.saturating_add(down);
            }
        }
        let users: Vec<Value> = totals
            .into_iter()
            .map(|(name, (up, down))| json!({"username": name, "upload_bytes": up, "download_bytes": down}))
            .collect();
        Ok(json!({"users": users}))
    }

    /// The share link of a user: the lane slot's port when the user is in a lane.
    fn share(&self, username: &str, password: &str, config: &Value) -> Result<String> {
        if config.get("trafficPattern").is_some() {
            return Err(Error::validation("share-link creation is unavailable for trafficPattern configurations"));
        }
        let bindings = match self.slot_of_user(username) {
            Some(slot) => vec![json!({"port": slot.port, "protocol": "TCP"})],
            None => config
                .get("portBindings")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| Error::internal("config has no port bindings"))?,
        };
        let mtu = config.get("mtu").cloned().unwrap_or_else(|| json!(1400));
        let mut query = vec![("profile", username.to_string())];
        query.extend(lanes::binding_query(&bindings, &mtu));
        Ok(format!(
            "mierus://{}:{}@{}?{}",
            pyurl::quote(username),
            pyurl::quote(password),
            lanes::link_host(&self.public_host),
            pyurl::urlencode(&query)
        ))
    }

    // ------------------------------------------------------------------ transactions

    /// Apply `desired` as a whole: backup, authenticated journal, apply, readback, reload or
    /// restart, probe; on failure restore the snapshot. Commits the state and returns the new
    /// revision.
    fn transaction(
        &self,
        desired: Value,
        state: &mut State,
        mode: &str,
        operation: &str,
        operation_record: Option<(String, Value)>,
    ) -> Result<String> {
        if !matches!(mode, "reload" | "restart") || transaction_mode(operation).is_none() {
            return Err(Error::validation("invalid transaction metadata"));
        }
        validate_config(&desired, true)?;
        let before = Value::Object(self.mita.observe()?);
        validate_config(&before, true)?;
        let expected = expected_readback(&desired);
        if mode != mode_for(operation, &before, &expected)? {
            return Err(Error::validation("invalid transaction metadata"));
        }
        let previous_hash = hash_value(&before);
        if previous_hash != get_str(state, "config_hash")? {
            return Err(Error::conflict("observed config changed outside manager"));
        }
        let desired_hash = hash_value(&expected);
        let generation = get(state, "generation")?.clone();
        let next_generation = pyjson::int_of(&generation).ok_or_else(|| Error::internal("generation"))? + 1;
        let revision = get_str(state, "revision")?.to_string();
        let next_revision = hash_value(&json!({
            "config": expected,
            "disabled": get(state, "disabled")?,
            "tombstones": get(state, "tombstones")?,
            "generation": next_generation as i64,
        }));
        util::mkdir(&self.backup_dir, 0o700)?;
        let backup_name = format!("g{}-{revision}.json", pyjson::py_str(&generation));
        let backup = self.backup_dir.join(&backup_name);
        util::atomic_json(&backup, &before)?;
        let backup_data = util::read_secure(&backup, self.mita.max_output())?;
        let mut journal: Map<String, Value> = json!({
            "version": 3,
            "schema": JOURNAL_SCHEMA,
            "phase": "prepared",
            "operation": operation,
            "mode": mode,
            "previous_config_hash": previous_hash,
            "desired_config_hash": desired_hash,
            "state_revision": revision,
            "state_generation": generation,
            "next_revision": next_revision,
            "next_generation": next_generation as i64,
            "backup_basename": backup_name,
            "backup_size": backup_data.len(),
            "backup_sha256": util::sha256_hex(&backup_data),
        })
        .as_object()
        .cloned()
        .unwrap_or_default();
        self.write_journal(&journal)?;
        let attempt = (|| -> Result<()> {
            self.mita.apply(&desired)?;
            journal.insert("phase".into(), json!("applied"));
            self.write_journal(&journal)?;
            if hash_value(&Value::Object(self.mita.observe()?)) != desired_hash {
                return Err(Error::mita("mita readback mismatch"));
            }
            if mode == "reload" {
                self.mita.reload()?;
            } else {
                self.mita.stop()?;
                self.wait_status("IDLE", "mita failed to reach idle state")?;
                self.mita.start()?;
            }
            self.wait_status("RUNNING", "mita failed to reach running state")?;
            self.probe()
        })();
        if attempt.is_err() {
            let rollback = (|| -> Result<()> {
                self.mita.apply(&before)?;
                if hash_value(&Value::Object(self.mita.observe()?)) != previous_hash {
                    return Err(Error::mita("rollback readback mismatch"));
                }
                journal.insert("phase".into(), json!("rollback_applied"));
                self.write_journal(&journal)?;
                self.mita.stop()?;
                self.wait_status("IDLE", "rollback failed to reach idle state")?;
                self.mita.start()?;
                self.wait_status("RUNNING", "rollback status failed")?;
                self.probe()
            })();
            if rollback.is_err() {
                return Err(Error::mita("transaction rollback requires recovery"));
            }
            self.remove_journal()?;
            return Err(Error::mita("transaction failed and was rolled back"));
        }
        state.insert("config_hash".into(), json!(desired_hash));
        state.insert("revision".into(), json!(next_revision));
        state.insert("generation".into(), json!(next_generation as i64));
        if let Some((operation_id, mut record)) = operation_record {
            // The revision exists only now, and the record lands in the same atomic write as
            // the state it describes.
            record["revision"] = json!(next_revision);
            if !state.contains_key("operations") {
                state.insert("operations".into(), json!({}));
            }
            map_mut(state, "operations")?.insert(operation_id, record);
        }
        self.write_state(state)?;
        self.remove_journal()?;
        if state.get("lanes").is_some_and(pyjson::truthy) {
            // The lanes mirror the main daemon: the main change is committed; a slot that will
            // not follow is marked and brought back at the next lanes request or start.
            let synced = self.mita.observe().and_then(|config| self.sync_slots(state, &Value::Object(config)));
            if synced.is_err() {
                state.insert("lanes_stale".into(), json!(true));
                self.write_state(state)?;
            }
        }
        Ok(next_revision)
    }

    fn recover(&self) -> Result<()> {
        self.recover_inner().map_err(|_| Error::conflict("transaction recovery failed"))
    }

    fn recover_inner(&self) -> Result<()> {
        let bad = |what: &str| Error::internal(what.to_string());
        let key = self.journal_key()?;
        let raw = util::read_secure(&self.journal_file, 65_536)?;
        let journal: Value = serde_json::from_slice(&raw).map_err(|_| bad("invalid journal"))?;
        let journal = journal.as_object().ok_or_else(|| bad("invalid journal"))?;
        let mac = journal.get("mac").and_then(Value::as_str).filter(|m| util::is_hex64(m));
        if journal.len() != JOURNAL_FIELDS.len()
            || !JOURNAL_FIELDS.iter().all(|f| journal.contains_key(*f))
            || mac.is_none()
        {
            return Err(bad("invalid journal"));
        }
        let mut unsigned = journal.clone();
        unsigned.shift_remove("mac");
        let expected_mac = util::hmac_sha256_hex(&key, pyjson::canonical(&Value::Object(unsigned)).as_bytes());
        if !pc_common::constant_time_eq(mac.unwrap_or_default().as_bytes(), expected_mac.as_bytes()) {
            return Err(bad("journal authentication failed"));
        }
        let text = |field: &str| journal[field].as_str();
        let hex64 = |field: &str| text(field).is_some_and(util::is_hex64);
        let state_generation = pyjson::int_of(&journal["state_generation"]);
        let backup_size = pyjson::int_of(&journal["backup_size"]);
        let expected_name = format!(
            "g{}-{}.json",
            pyjson::py_str(&journal["state_generation"]),
            pyjson::py_str(&journal["state_revision"])
        );
        if !pyjson::eq_int(&journal["version"], 3)
            || text("schema") != Some(JOURNAL_SCHEMA)
            || !matches!(text("phase"), Some("prepared" | "applied" | "rollback_applied"))
            || !matches!(text("mode"), Some("reload" | "restart"))
            || text("operation").and_then(transaction_mode).is_none()
            || text("backup_basename") != Some(expected_name.as_str())
            || !hex64("previous_config_hash")
            || !hex64("desired_config_hash")
            || !hex64("state_revision")
            || !hex64("next_revision")
            || !state_generation.is_some_and(|g| g >= 0)
            || !pyjson::eq_int(&journal["next_generation"], state_generation.unwrap_or(-2) as i64 + 1)
            || !backup_size.is_some_and(|s| s >= 1)
            || !hex64("backup_sha256")
        {
            return Err(bad("invalid journal"));
        }
        let (phase, mode, operation) = (
            text("phase").unwrap_or_default(),
            text("mode").unwrap_or_default(),
            text("operation").unwrap_or_default(),
        );
        let (previous_hash, desired_hash) =
            (text("previous_config_hash").unwrap_or_default(), text("desired_config_hash").unwrap_or_default());
        let state = self.read_state()?;
        let observed = Value::Object(self.mita.observe()?);
        let observed_hash = hash_value(&observed);
        let state_config_hash = get_str(&state, "config_hash")?;
        let state_revision = get_str(&state, "revision")?;
        if pyjson::eq(get(&state, "generation")?, &journal["next_generation"])
            && Some(state_revision) == text("next_revision")
            && state_config_hash == desired_hash
            && observed_hash == desired_hash
        {
            // Committed before the journal could be removed.
            fs::remove_file(&self.journal_file)?;
            util::fsync_dir(&self.state_dir)?;
            return Ok(());
        }
        if !pyjson::eq(get(&state, "generation")?, &journal["state_generation"])
            || Some(state_revision) != text("state_revision")
            || state_config_hash != previous_hash
        {
            return Err(bad("journal generation is stale"));
        }
        let allowed: &[&str] = match phase {
            "prepared" => &[previous_hash, desired_hash],
            "applied" => &[desired_hash],
            _ => &[previous_hash],
        };
        if !allowed.contains(&observed_hash.as_str()) {
            return Err(bad("observed config does not match journal phase"));
        }
        let backup = self.backup_dir.join(text("backup_basename").unwrap_or_default());
        if backup.parent() != Some(self.backup_dir.as_path()) {
            return Err(bad("backup escapes state"));
        }
        let backup_data = util::read_secure(&backup, 1_048_576)?;
        if Some(backup_data.len() as i128) != backup_size
            || !pc_common::constant_time_eq(
                util::sha256_hex(&backup_data).as_bytes(),
                text("backup_sha256").unwrap_or_default().as_bytes(),
            )
        {
            return Err(bad("backup digest mismatch"));
        }
        let config: Value = serde_json::from_slice(&backup_data).map_err(|_| bad("backup config"))?;
        validate_config(&config, true)?;
        if hash_value(&config) != previous_hash {
            return Err(bad("backup config mismatch"));
        }
        if observed_hash == desired_hash {
            if mode != mode_for(operation, &config, &observed)? {
                return Err(bad("journal mode mismatch"));
            }
            let canonical_next = hash_value(&json!({
                "config": observed,
                "disabled": get(&state, "disabled")?,
                "tombstones": get(&state, "tombstones")?,
                "generation": journal["next_generation"],
            }));
            if text("next_revision") != Some(canonical_next.as_str()) {
                return Err(bad("journal next revision mismatch"));
            }
        }
        if observed_hash != previous_hash {
            self.mita.apply(&config)?;
        }
        self.mita.stop()?;
        self.wait_status("IDLE", "recovery failed to reach idle state")?;
        self.mita.start()?;
        self.wait_status("RUNNING", "recovery status failed")?;
        self.probe()?;
        if hash_value(&Value::Object(self.mita.observe()?)) != previous_hash {
            return Err(Error::mita("recovery readback mismatch"));
        }
        fs::remove_file(&self.journal_file)?;
        util::fsync_dir(&self.state_dir)?;
        Ok(())
    }

    // ------------------------------------------------------------------ egress

    fn providers_view(&self, probe: bool) -> Value {
        let mut providers = Map::new();
        if let Some(url) = self.warp_url() {
            let reachable = if probe { json!((self.reachability)(Some(url), 3.0, false)) } else { Value::Null };
            providers.insert("warp".into(), json!({"url": url, "reachable": reachable}));
        }
        if let Some(url) = self.router_url() {
            let reachable = if probe { json!((self.reachability)(Some(url), 3.0, true)) } else { Value::Null };
            providers.insert("router".into(), json!({"url": url, "reachable": reachable}));
        }
        Value::Object(providers)
    }

    fn router_credential(&self) -> Result<Credential> {
        match (self.router_url(), &self.router_credential_file) {
            (Some(_), Some(file)) => egress::read_credential(file),
            _ => Err(Error::egress_invalid("egress provider router is not configured on this node")),
        }
    }

    fn proxy_names(document: &Value) -> Vec<String> {
        document["proxies"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p["name"].as_str().map(str::to_string))
            .collect()
    }

    /// mita's section for a document, the router credential read from the file now.
    fn target(&self, document: &Value) -> Result<Value> {
        let credential = if Self::proxy_names(document).iter().any(|n| n == "router") {
            Some(self.router_credential()?)
        } else {
            None
        };
        egress::to_mita(document, &self.providers, credential.as_ref())
    }

    fn providers_reachable(&self, document: &Value) -> Map<String, Value> {
        let mut reachability = Map::new();
        for name in Self::proxy_names(document) {
            if name == "router" {
                let reachable = self.router_url().is_some_and(|url| (self.reachability)(Some(url), 3.0, true));
                reachability.insert("router".into(), json!(reachable));
            } else {
                reachability.insert("warp".into(), json!((self.reachability)(self.warp_url(), 3.0, false)));
            }
        }
        reachability
    }

    fn assert_reachable(&self, document: &Value) -> Result<()> {
        for (name, reachable) in self.providers_reachable(document) {
            if reachable != json!(true) {
                return Err(Error::EgressUnreachable(format!("egress provider {name} is unreachable")));
            }
        }
        Ok(())
    }

    fn router_credential_stale(&self, section: Option<&Value>) -> bool {
        match self.router_credential() {
            Ok(credential) => egress::router_credential_stale(section, &credential),
            Err(_) => false,
        }
    }

    /// After a credential rotation the running section still carries the old key: the section
    /// is rendered again from the document and the file through the restart transaction.
    fn refresh_router_credential(&self, state: &mut State, observed: &Value) -> Result<()> {
        let section = observed.get("egress").filter(|s| !s.is_null());
        if !self.router_credential_stale(section) {
            return Ok(());
        }
        let document = egress::from_mita(section, &self.providers);
        let history = Self::journal(state)?;
        // The installer's seed has no journal yet; a section the manager applied must still be
        // the one its journal names — anything else is a hand edit, left alone.
        let Some(document) = document else { return Ok(()) };
        if let Some(last) = history.last() {
            if !pyjson::eq(last.get("document").unwrap_or(&Value::Null), &document) {
                return Ok(());
            }
        }
        let mut desired = observed.clone();
        desired["egress"] = self.target(&document)?;
        self.transaction(desired, state, "restart", "egress.refresh", None)?;
        Ok(())
    }

    fn journal(state: &State) -> Result<Vec<Value>> {
        match state.get("egress") {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Object(journal)) => match journal.get("history") {
                Some(Value::Array(history)) => Ok(history.clone()),
                _ => Err(Error::conflict("invalid egress journal")),
            },
            Some(_) => Err(Error::conflict("invalid egress journal")),
        }
    }

    fn egress_view(&self, state: &State, observed: &Value, probe: bool) -> Result<Value> {
        let section = observed.get("egress").filter(|s| !s.is_null());
        let document = egress::from_mita(section, &self.providers);
        let history = Self::journal(state)?;
        let mode = match &document {
            None => "custom",
            Some(doc) if doc["rules"].as_array().into_iter().flatten().any(|r| r["action"] == "PROXY") => "proxy",
            Some(_) => "direct",
        };
        let current = history.last();
        let mut warnings = Vec::new();
        if section.is_some() && history.is_empty() {
            warnings.push("adopts_unmanaged_egress");
        }
        if self.router_credential_stale(section) {
            warnings.push("router_credential_stale");
        }
        let entry_get = |entry: &Value, key: &str| entry.get(key).cloned().unwrap_or(Value::Null);
        let managed = current.is_some_and(|c| pyjson::truthy(c) && !entry_get(c, "document").is_null());
        Ok(json!({
            "revision": get(state, "revision")?,
            "mode": mode,
            "document": document,
            "raw": if document.is_none() { egress::redact_section(section) } else { Value::Null },
            "managed": managed,
            "providers": self.providers_view(probe),
            "capabilities": egress::CAPABILITIES,
            "restart_required": true,
            "warnings": warnings,
            "previous": if history.len() < 2 { Value::Null } else { json!({"applied_at": entry_get(&history[history.len() - 2], "applied_at")}) },
            "current": current.map_or(Value::Null, |c| json!({
                "operation_id": entry_get(c, "operation_id"),
                "applied_at": entry_get(c, "applied_at"),
                "digest": entry_get(c, "digest"),
            })),
        }))
    }

    pub fn egress(&self) -> Result<Value> {
        let _writer = self.writer()?;
        let state = self.read_state()?;
        let observed = self.observed_consistent(&state)?;
        self.egress_view(&state, &observed, true)
    }

    pub fn egress_plan(&self, expected_revision: &Value, document: &Value) -> Result<Value> {
        let _writer = self.writer()?;
        let normalised = egress::validate_document(document)?;
        let state = self.read_state()?;
        Self::check_revision(&state, expected_revision)?;
        let observed = self.observed_consistent(&state)?;
        let target = self.target(&normalised)?;
        let section = observed.get("egress").filter(|s| !s.is_null());
        let lines = |value: &Value| -> Vec<String> {
            pyjson::dumps(value, true, Some(1)).split('\n').map(str::to_string).collect()
        };
        let before = lines(&egress::redact_section(section));
        let planned = if pyjson::truthy(&target) { egress::redact_section(Some(&target)) } else { Value::Null };
        let after = lines(&planned);
        let diff: Vec<String> = crate::difflib::changed_lines(&before, &after)
            .into_iter()
            .filter(|line| !(line.starts_with("---") || line.starts_with("+++") || line.starts_with("@@")))
            .collect();
        let reachability = self.providers_reachable(&normalised);
        let warnings: Vec<&str> = if section.is_some() && Self::journal(&state)?.is_empty() {
            vec!["adopts_unmanaged_egress"]
        } else {
            vec![]
        };
        Ok(json!({
            "revision": get(&state, "revision")?,
            "target": egress::redact_section(Some(&target)),
            "diff": diff,
            "reachability": reachability,
            "restart_required": true,
            "warnings": warnings,
        }))
    }

    /// Replace the `egress` section through the restart transaction and push the entry on the
    /// journal. Idempotent by `operation_id`: a retry after a lost reply gets the same answer
    /// without a second restart.
    pub fn egress_apply(&self, expected_revision: &Value, document: &Value, operation_id: &Value) -> Result<Value> {
        let _writer = self.writer()?;
        let Some(operation_id) = operation_id.as_str().filter(|op| is_operation_id(op)) else {
            return Err(Error::validation("invalid operation id"));
        };
        let normalised = egress::validate_document(document)?;
        let mut state = self.read_state()?;
        let history = Self::journal(&state)?;
        if let Some(current) = history.last() {
            if current.get("operation_id").and_then(Value::as_str) == Some(operation_id) {
                let applied = current.get("document").cloned().unwrap_or(Value::Null);
                if !pyjson::eq(&applied, &normalised) {
                    return Err(Error::conflict("operation id already used for another request"));
                }
                return Ok(json!({"revision": get(&state, "revision")?, "applied": applied, "replayed": true}));
            }
        }
        Self::check_revision(&state, expected_revision)?;
        let observed = self.observed_consistent(&state)?;
        let target = self.target(&normalised)?;
        self.assert_reachable(&normalised)?;
        let entry = json!({
            "document": normalised,
            "digest": egress::document_digest(&normalised),
            "operation_id": operation_id,
            "applied_at": util::now_isoformat(),
        });
        let revision = self.egress_transaction(&mut state, &observed, target, entry, "egress.apply")?;
        Ok(json!({"revision": revision, "applied": normalised, "replayed": false}))
    }

    /// Back to the previous journal entry: a managed document, or the section mita had before
    /// the first apply (restored verbatim).
    pub fn egress_rollback(&self, expected_revision: &Value) -> Result<Value> {
        let _writer = self.writer()?;
        let mut state = self.read_state()?;
        Self::check_revision(&state, expected_revision)?;
        let observed = self.observed_consistent(&state)?;
        let history = Self::journal(&state)?;
        if history.len() < 2 {
            return Err(Error::conflict("no previous egress to roll back to"));
        }
        let previous = history[history.len() - 2].clone();
        let document = previous.get("document").cloned().unwrap_or(Value::Null);
        let target = if document.is_null() {
            match previous.get("raw") {
                Some(raw) if pyjson::truthy(raw) => raw.clone(),
                _ => json!({}),
            }
        } else {
            let target = self.target(&document)?;
            self.assert_reachable(&document)?;
            target
        };
        let mut entry = previous;
        if let Some(map) = entry.as_object_mut() {
            map.insert("applied_at".into(), json!(util::now_isoformat()));
        }
        let applied = entry.get("document").cloned().unwrap_or(Value::Null);
        let revision = self.egress_transaction(&mut state, &observed, target, entry, "egress.rollback")?;
        Ok(json!({"revision": revision, "applied": applied, "replayed": false}))
    }

    /// The journal is a stack of what was applied, oldest first; its floor is the section mita
    /// had before the first apply (kept verbatim). An apply pushes, a rollback pops.
    fn egress_transaction(
        &self,
        state: &mut State,
        observed: &Value,
        target: Value,
        entry: Value,
        operation: &str,
    ) -> Result<String> {
        let mut history = Self::journal(state)?;
        if operation == "egress.rollback" {
            history.pop();
            if let Some(last) = history.last_mut() {
                *last = entry;
            }
        } else {
            if history.is_empty() {
                history.push(json!({
                    "document": null,
                    "raw": observed.get("egress").cloned().unwrap_or(Value::Null),
                    "digest": null,
                    "operation_id": null,
                    "applied_at": null,
                }));
            }
            history.push(entry);
            if history.len() > 10 {
                history.drain(..history.len() - 10);
            }
        }
        let mut desired = observed.clone();
        if let Some(map) = desired.as_object_mut() {
            if pyjson::truthy(&target) {
                map.insert("egress".into(), target);
            } else {
                map.shift_remove("egress");
            }
        }
        state.insert("egress".into(), json!({"history": history}));
        self.transaction(desired, state, "restart", operation, None)
    }

    // ------------------------------------------------------------------ lanes

    fn slot_client(&self, slot: &Slot) -> Arc<dyn Mita> {
        let mut clients = self.slot_clients.lock().unwrap_or_else(PoisonError::into_inner);
        clients.entry(slot.index).or_insert_with(|| (self.slot_factory)(slot)).clone()
    }

    fn slot_by_index(&self, index: &Value) -> Option<&Slot> {
        self.lane_slots.iter().find(|slot| pyjson::eq_int(index, i64::from(slot.index)))
    }

    fn slot_of_user(&self, username: &str) -> Option<Slot> {
        let state = self.read_state().ok()?;
        let name = json!(username);
        for entry in state.get("lanes")?.as_object()?.values() {
            if entry.get("users").is_some_and(|users| contains(users, &name)) {
                return self.slot_by_index(&entry["slot"]).cloned();
            }
        }
        None
    }

    /// What the slot should run now: its lane's enabled users mirrored from the main config
    /// with the lane's account as the egress, or the empty config.
    fn slot_desired(&self, slot: &Slot, state: &State, config: &Value) -> Result<Value> {
        let lanes = state.get("lanes").and_then(Value::as_object);
        let lane = lanes
            .into_iter()
            .flatten()
            .map(|(_, entry)| entry)
            .find(|entry| pyjson::eq_int(&entry["slot"], i64::from(slot.index)));
        let Some(lane) = lane else { return Ok(lanes::empty_config(slot)) };
        let mut users: Vec<Value> = users_of(config)
            .iter()
            .filter(|row| contains(&lane["users"], row.get("name").unwrap_or(&Value::Null)))
            .cloned()
            .collect();
        for row in users.iter_mut().filter_map(Value::as_object_mut) {
            row.shift_remove("password");
        }
        if users.is_empty() {
            return Ok(lanes::empty_config(slot));
        }
        let router = egress::provider_endpoint(self.router_url(), "router")?;
        let upstream = &lane["upstream"];
        Ok(lanes::slot_config(
            slot,
            users,
            router,
            (&upstream["user"], &upstream["password"]),
            config.get("mtu").filter(|m| !m.is_null()),
        ))
    }

    fn wait_slot(&self, client: &Arc<dyn Mita>, target: &str) -> Result<()> {
        let deadline = Instant::now() + self.status_timeout;
        loop {
            let status = client.status()?;
            if status == target {
                return Ok(());
            }
            if !matches!(status.as_str(), "STARTING" | "STOPPING") || Instant::now() >= deadline {
                return Err(Error::mita(format!("lane slot failed to reach {} state", target.to_lowercase())));
            }
            std::thread::sleep(self.status_poll_interval.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// Bring every slot to its desired config: apply, then start or stop, then probe the
    /// running ones. A slot that fails is put back the way it was and the error is raised.
    fn sync_slots(&self, state: &State, config: &Value) -> Result<()> {
        for slot in &self.lane_slots {
            let client = self.slot_client(slot);
            let desired = self.slot_desired(slot, state, config)?;
            let wants_users = desired.get("users").is_some_and(pyjson::truthy);
            let before = Value::Object(client.observe()?);
            let was_running = client.status()? == "RUNNING";
            let (before_hash, desired_hash) = (hash_value(&before), hash_value(&desired));
            if before_hash == desired_hash && was_running == wants_users {
                continue;
            }
            let attempt = (|| -> Result<()> {
                if before_hash != desired_hash {
                    client.apply(&desired)?;
                    if hash_value(&Value::Object(client.observe()?)) != desired_hash {
                        return Err(Error::mita("slot readback mismatch"));
                    }
                }
                if wants_users {
                    if was_running {
                        client.stop()?;
                        self.wait_slot(&client, "IDLE")?;
                    }
                    client.start()?;
                    self.wait_slot(&client, "RUNNING")?;
                    client.probe()?;
                } else if was_running {
                    client.stop()?;
                    self.wait_slot(&client, "IDLE")?;
                }
                Ok(())
            })();
            if attempt.is_err() {
                let restore = (|| -> Result<()> {
                    client.apply(&before)?;
                    if hash_value(&Value::Object(client.observe()?)) != before_hash {
                        return Err(Error::mita("slot rollback readback mismatch"));
                    }
                    if client.status()? == "RUNNING" {
                        client.stop()?;
                        self.wait_slot(&client, "IDLE")?;
                    }
                    if was_running {
                        client.start()?;
                        self.wait_slot(&client, "RUNNING")?;
                    }
                    Ok(())
                })();
                if restore.is_err() {
                    return Err(Error::mita(format!("lane slot {} needs recovery", slot.index)));
                }
                return Err(Error::mita(format!("lane slot {} did not take its config", slot.index)));
            }
        }
        Ok(())
    }

    /// Replace the lanes: assign a slot to each (keeping the one it has), mirror its users there
    /// with the lane's account as the egress; users not named leave their slot.
    pub fn set_lanes(&self, body: &Value) -> Result<Value> {
        let _writer = self.writer()?;
        let state = self.read_state()?;
        let config = Value::Object(self.mita.observe()?);
        validate_config(&config, true)?;
        if hash_value(&config) != get_str(&state, "config_hash")? {
            return Err(Error::conflict("observed config changed outside manager"));
        }
        let mut known: HashSet<String> = users_of(&config)
            .iter()
            .filter_map(|row| row.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();
        known.extend(get(&state, "disabled")?.as_object().into_iter().flatten().map(|(name, _)| name.clone()));
        let requested = match lanes::validate_request(body, &known) {
            Ok(lanes) => lanes,
            Err(err) => return Err(Error::conflict(format!("lanes_invalid: {err}"))),
        };
        if !requested.is_empty() && self.router_url().is_none() {
            return Err(Error::egress_invalid("egress provider router is not configured on this node"));
        }
        let previous = get(&state, "lanes")?.as_object().cloned().unwrap_or_default();
        let named: HashSet<&str> = requested.iter().map(|item| item.lane.as_str()).collect();
        let taken: Vec<&Value> = previous
            .iter()
            .filter(|(lane, _)| named.contains(lane.as_str()))
            .map(|(_, entry)| &entry["slot"])
            .collect();
        let mut free: Vec<u32> = self
            .lane_slots
            .iter()
            .map(|slot| slot.index)
            .filter(|index| !taken.iter().any(|t| pyjson::eq_int(t, i64::from(*index))))
            .collect();
        let mut desired = Map::new();
        for item in &requested {
            let slot = match previous.get(&item.lane) {
                Some(entry) => entry["slot"].clone(),
                None => {
                    if free.is_empty() {
                        return Err(Error::conflict("lane_slots_exhausted"));
                    }
                    json!(free.remove(0))
                }
            };
            desired.insert(
                item.lane.clone(),
                json!({"slot": slot, "users": item.users, "upstream": {"user": item.upstream.0, "password": item.upstream.1}}),
            );
        }
        let mut candidate = state.clone();
        candidate.insert("lanes".into(), Value::Object(desired));
        candidate.shift_remove("lanes_stale");
        self.sync_slots(&candidate, &config)?;
        self.write_state(&candidate)?;
        util::fsync_dir(&self.state_dir)?;
        self.lanes_view(&candidate, &config)
    }

    pub fn lanes(&self) -> Result<Value> {
        let _writer = self.writer()?;
        let state = self.read_state()?;
        let config = Value::Object(self.mita.observe()?);
        self.lanes_view(&state, &config)
    }

    fn lanes_view(&self, state: &State, config: &Value) -> Result<Value> {
        let enabled: Vec<Value> =
            users_of(config).iter().map(|row| row.get("name").cloned().unwrap_or(Value::Null)).collect();
        let stale = state.get("lanes_stale").is_some_and(pyjson::truthy);
        let mtu = config.get("mtu").cloned().unwrap_or_else(|| json!(1400));
        let lanes_map = get(state, "lanes")?.as_object().cloned().unwrap_or_default();
        let mut view = Vec::new();
        for (lane, entry) in &lanes_map {
            let slot = self.slot_by_index(&entry["slot"]);
            let status = if stale {
                "stale"
            } else if let Some(slot) = slot {
                if self.slot_client(slot).status()? == "RUNNING" {
                    "running"
                } else {
                    "idle"
                }
            } else {
                "idle"
            };
            let users = entry["users"].as_array().cloned().unwrap_or_default();
            let mut templates = Map::new();
            if let Some(slot) = slot {
                for user in &users {
                    if enabled.iter().any(|name| pyjson::eq(name, user)) {
                        let name = pyjson::py_str(user);
                        templates.insert(
                            name.clone(),
                            json!(lanes::share_template(&name, &self.public_host, slot.port, &mtu)),
                        );
                    }
                }
            }
            let upstream = self.router_url().map(|url| {
                let tail = url.rsplit_once('@').map_or(url, |(_, rest)| rest);
                let tail = tail.rsplit_once("://").map_or(tail, |(_, rest)| rest);
                format!("socks5://***@{tail}")
            });
            view.push(json!({
                "lane": lane,
                "slot": entry["slot"],
                "port": slot.map(|s| s.port),
                "users": users,
                "upstream": upstream,
                "status": status,
                "share_templates": templates,
            }));
        }
        let used: Vec<&Value> = lanes_map.values().map(|entry| &entry["slot"]).collect();
        let free = self
            .lane_slots
            .iter()
            .filter(|slot| !used.iter().any(|u| pyjson::eq_int(u, i64::from(slot.index))))
            .count();
        let config_map = config.as_object().cloned().unwrap_or_default();
        Ok(json!({
            "lanes": view,
            "free_slots": free,
            "service_share_template": lanes::service_share_template(&self.public_host, &config_map),
        }))
    }
}
