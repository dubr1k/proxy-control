//! The manager's behaviour, ported from the Python suite (tests/test_mieru_manager.py,
//! tests/test_mieru_manager_lanes.py, tests/test_mieru_egress.py and the manager half of
//! panel/tests/test_mieru_management.py): a fake mita that hashes a fresh password the way
//! mita does and records every call.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use pc_common::{ServerOptions, UdsServer};
use serde_json::{json, Map, Value};

use crate::egress;
use crate::error::{Error, Result};
use crate::lanes::{self, Slot};
use crate::mita::Mita;
use crate::service::MieruManager;
use crate::{pyjson, util};

pub fn base() -> Value {
    json!({
        "portBindings": [{"port": 8443, "protocol": "TCP"}],
        "users": [{"name": "alice", "hashedPassword": "a".repeat(64)}],
        "loggingLevel": "INFO",
        "mtu": 1400,
    })
}

pub fn with(mut value: Value, key: &str, item: Value) -> Value {
    value[key] = item;
    value
}

pub fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mieru-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------- the fake daemon

#[derive(Default)]
pub struct Fake {
    pub config: Value,
    pub calls: Vec<Value>,
    pub fail_probe: bool,
    pub traffic: BTreeMap<String, (u64, u64)>,
    pub running: bool,
    pub statuses: VecDeque<String>,
    pub version: String,
    /// `apply` merges into the stored config (mita 3.38 `apply config`).
    pub merging: bool,
    /// `apply` fails before touching anything (an interrupted process).
    pub interrupted: bool,
    /// `version` is recorded as a call.
    pub record_version: bool,
}

pub struct FakeMita(Mutex<Fake>);

impl FakeMita {
    pub fn new(config: Value) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Fake { config, running: true, version: "3.35.0".into(), ..Fake::default() })))
    }

    pub fn base() -> Arc<Self> {
        Self::new(base())
    }

    /// A slot daemon: starts empty and idle (nothing listens), like the installer leaves it.
    pub fn slot(port: u32) -> Arc<Self> {
        let fake = Self::new(json!({"portBindings": [{"port": port, "protocol": "TCP"}], "loggingLevel": "INFO"}));
        fake.get().running = false;
        fake
    }

    pub fn get(&self) -> MutexGuard<'_, Fake> {
        self.0.lock().unwrap()
    }

    pub fn calls(&self) -> Vec<Value> {
        self.get().calls.clone()
    }

    pub fn names(&self) -> Vec<String> {
        self.calls().iter().map(|call| call[0].as_str().unwrap().to_string()).collect()
    }

    pub fn clear(&self) {
        self.get().calls.clear();
    }

    pub fn config(&self) -> Value {
        self.get().config.clone()
    }

    pub fn statuses(&self, statuses: &[&str]) {
        self.get().statuses = statuses.iter().map(|s| s.to_string()).collect();
    }

    /// mita hashes a fresh password and keeps the blanked field in place, so a readback carries
    /// an empty password beside the stored hash.
    fn persist(config: &Value) -> Value {
        let mut value = config.clone();
        if let Some(Value::Array(users)) = value.get_mut("users") {
            for user in users.iter_mut().filter_map(Value::as_object_mut) {
                if user.get("password").is_some_and(pc_common::pyvalue::truthy) {
                    let raw = user["password"].as_str().unwrap().to_string();
                    let name = user["name"].as_str().unwrap().to_string();
                    user.insert("password".into(), json!(""));
                    user.insert("hashedPassword".into(), json!(util::sha256_hex(format!("{raw}\0{name}").as_bytes())));
                }
                if user.get("quotas") == Some(&json!([])) {
                    user.shift_remove("quotas");
                }
            }
        }
        value
    }
}

impl Mita for FakeMita {
    fn version(&self) -> Result<String> {
        let mut fake = self.get();
        if fake.record_version {
            fake.calls.push(json!(["version"]));
        }
        Ok(fake.version.clone())
    }

    fn observe(&self) -> Result<Map<String, Value>> {
        Ok(self.get().config.as_object().cloned().unwrap())
    }

    fn apply(&self, config: &Value) -> Result<()> {
        let mut fake = self.get();
        if fake.interrupted {
            fake.calls.push(json!(["apply"]));
            return Err(Error::internal("interrupted"));
        }
        fake.calls.push(json!(["apply", config]));
        if fake.merging {
            let mut merged = fake.config.as_object().cloned().unwrap();
            for (key, value) in config.as_object().unwrap() {
                merged.insert(key.clone(), value.clone());
            }
            let mut users: BTreeMap<String, Value> = BTreeMap::new();
            for row in fake.config["users"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(config["users"].as_array().into_iter().flatten())
            {
                users.insert(row["name"].as_str().unwrap().into(), row.clone());
            }
            merged.insert("users".into(), Value::Array(users.into_values().collect()));
            fake.config = Self::persist(&Value::Object(merged));
        } else {
            fake.config = Self::persist(config);
        }
        Ok(())
    }

    fn reload(&self) -> Result<()> {
        self.get().calls.push(json!(["reload"]));
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        let mut fake = self.get();
        fake.calls.push(json!(["stop"]));
        fake.running = false;
        Ok(())
    }

    fn start(&self) -> Result<()> {
        let mut fake = self.get();
        fake.calls.push(json!(["start"]));
        fake.running = true;
        Ok(())
    }

    fn status(&self) -> Result<String> {
        let mut fake = self.get();
        if let Some(status) = fake.statuses.pop_front() {
            return Ok(status);
        }
        Ok(if fake.running { "RUNNING" } else { "IDLE" }.into())
    }

    fn traffic(&self) -> Result<BTreeMap<String, (u64, u64)>> {
        Ok(self.get().traffic.clone())
    }

    fn probe(&self) -> Result<()> {
        let mut fake = self.get();
        fake.calls.push(json!(["probe"]));
        if fake.fail_probe {
            fake.fail_probe = false;
            return Err(Error::internal("probe secret must not escape"));
        }
        Ok(())
    }
}

fn manager_in(dir: &Path, mita: &Arc<FakeMita>) -> MieruManager {
    MieruManager::new(mita.clone(), dir.join("state"), "proxy.example.com")
}

fn service(name: &str) -> (PathBuf, Arc<FakeMita>, MieruManager, Value) {
    let dir = tempdir(name);
    let mita = FakeMita::base();
    let manager = manager_in(&dir, &mita);
    let revision = manager.bootstrap().unwrap()["revision"].clone();
    (dir, mita, manager, revision)
}

fn s(text: &str) -> Value {
    json!(text)
}

fn create(manager: &MieruManager, name: &str, quotas: Value, revision: &Value) -> Result<Value> {
    manager.create_user(&s(name), &quotas, revision, &json!(false), &json!(false), &json!(false), None, None)
}

fn create_with(
    manager: &MieruManager,
    name: &str,
    revision: &Value,
    password: Option<&str>,
    op: Option<&str>,
) -> Result<Value> {
    let (password, op) = (password.map(s), op.map(s));
    manager.create_user(
        &s(name),
        &json!([]),
        revision,
        &json!(false),
        &json!(false),
        &json!(false),
        password.as_ref(),
        op.as_ref(),
    )
}

fn revision_of(manager: &MieruManager) -> Value {
    manager.inspect().unwrap()["revision"].clone()
}

fn conflict(result: Result<Value>) -> String {
    match result {
        Err(Error::Conflict(message)) => message,
        other => panic!("expected a conflict, got {other:?}"),
    }
}

fn mita_error(result: Result<Value>) -> String {
    match result {
        Err(Error::Mita(message)) => message,
        other => panic!("expected a mita error, got {other:?}"),
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------- bootstrap and lifecycle

#[test]
fn bootstrap_accepts_mita_3_36() {
    let dir = tempdir("v336");
    let mita = FakeMita::base();
    mita.get().version = "3.36.0".into();
    assert_eq!(manager_in(&dir, &mita).bootstrap().unwrap()["version"], "3.36.0");
}

/// v1.0.1: no list of verified mita lines — the readback after every apply catches a CLI whose
/// semantics moved, and the version-agent rolls a bad update back.
#[test]
fn bootstrap_accepts_any_mita_version() {
    for version in ["3.37.0", "3.38.0", "4.0.0"] {
        let dir = tempdir(&format!("any-{version}"));
        let mita = FakeMita::base();
        mita.get().version = version.into();
        assert_eq!(manager_in(&dir, &mita).bootstrap().unwrap()["version"], version);
    }
    let dir = tempdir("any-prefixed");
    let mita = FakeMita::base();
    mita.get().version = "mita  3.38.1-beta.2".into();
    assert_eq!(manager_in(&dir, &mita).bootstrap().unwrap()["version"], "3.38.1-beta.2");
    for bad in ["", "3.38", "mita3.38.1", "v3.38.1"] {
        let dir = tempdir("any-bad");
        let mita = FakeMita::base();
        mita.get().version = bad.into();
        assert_eq!(
            manager_in(&dir, &mita).bootstrap().unwrap_err(),
            Error::conflict("mita did not report its version")
        );
    }
}

#[test]
fn a_rollback_that_does_not_restore_the_snapshot_is_not_reported_as_rolled_back() {
    let (_dir, mita, manager, revision) = service("merging");
    mita.get().merging = true;
    mita.get().fail_probe = true;
    let message = mita_error(create(&manager, "bob", json!([]), &revision));
    assert!(message.contains("transaction rollback requires recovery"), "{message}");
}

#[test]
fn bootstrap_creates_private_durable_journal_authentication_key() {
    let (dir, mita, _manager, _) = service("journal-key");
    let key = dir.join("state/journal.key");
    assert!(std::fs::symlink_metadata(&key).unwrap().file_type().is_file());
    assert_eq!(mode_of(&key), 0o600);
    let first = std::fs::read(&key).unwrap();
    assert_eq!(first.len(), 32);
    manager_in(&dir, &mita).bootstrap().unwrap();
    assert_eq!(std::fs::read(&key).unwrap(), first);
}

#[test]
fn lifecycle_revalidates_readback_and_probes_running_service() {
    let (_dir, mita, manager, revision) = service("lifecycle");
    mita.clear();
    assert_eq!(manager.lifecycle("stop").unwrap(), json!({"ready": false, "status": "idle", "revision": revision}));
    assert_eq!(mita.calls(), [json!(["stop"])]);
    mita.clear();
    assert_eq!(manager.lifecycle("start").unwrap(), json!({"ready": true, "status": "running", "revision": revision}));
    assert_eq!(mita.calls(), [json!(["start"]), json!(["probe"])]);
    mita.clear();
    assert_eq!(manager.lifecycle("restart").unwrap()["ready"], true);
    assert_eq!(mita.calls(), [json!(["stop"]), json!(["start"]), json!(["probe"])]);
    assert_eq!(manager.lifecycle("reload").unwrap_err(), Error::validation("invalid lifecycle action"));
}

#[test]
fn lifecycle_polls_official_transient_statuses_until_exact_terminal_state() {
    let (_dir, mita, manager, revision) = service("transient");
    mita.clear();
    mita.statuses(&["STOPPING", "IDLE"]);
    assert_eq!(manager.lifecycle("stop").unwrap(), json!({"ready": false, "status": "idle", "revision": revision}));
    mita.clear();
    mita.statuses(&["STARTING", "RUNNING"]);
    assert_eq!(manager.lifecycle("start").unwrap()["ready"], true);
    assert_eq!(mita.calls(), [json!(["start"]), json!(["probe"])]);
}

#[test]
fn lifecycle_rejects_stopped_as_stop_terminal_and_bounds_transient_polling() {
    let dir = tempdir("stopped");
    let mita = FakeMita::base();
    let manager = manager_in(&dir, &mita).with_status_timing(Duration::from_millis(10), Duration::from_millis(1));
    manager.bootstrap().unwrap();
    mita.statuses(&["STOPPED"; 100]);
    assert!(mita_error(manager.lifecycle("stop")).contains("failed to reach idle state"));
    assert_eq!(mita.calls(), [json!(["stop"])]);
}

// ---------------------------------------------------------------- users

#[test]
fn create_uses_complete_snapshot_cas_and_reveals_password_once() {
    let (_dir, mita, manager, initial) = service("create");
    let result = create(&manager, "bob", json!([{"days": 30, "megabytes": 1024}]), &initial).unwrap();
    let url = result["share_url"].as_str().unwrap();
    assert!(url.starts_with("mierus://bob:") && url.contains("@proxy.example.com?"), "{url}");
    let calls = mita.calls();
    assert_eq!(calls[0][0], "apply");
    assert_eq!(calls[0][1]["portBindings"], base()["portBindings"]);
    assert!(calls[0][1]["users"][1].get("password").is_some());
    assert_eq!(calls[1..], [json!(["reload"]), json!(["probe"])]);
    let listed = manager.list_users().unwrap().to_string();
    assert!(!listed.contains("password") && !listed.contains("hashedPassword"));
    assert!(conflict(create(&manager, "carol", json!([]), &initial)).contains("revision"));
}

#[test]
fn later_transactions_keep_the_stored_hash_of_an_earlier_created_user() {
    let (_dir, mita, manager, revision) = service("keep-hash");
    let first = create(&manager, "bob", json!([{"days": 30, "megabytes": 1024}]), &revision).unwrap();
    let stored = mita.config()["users"][1]["hashedPassword"].clone();
    let second = create(&manager, "carol", json!([]), &first["revision"]).unwrap();
    assert!(second["share_url"].as_str().unwrap().starts_with("mierus://carol:"));
    assert_eq!(mita.config()["users"][1]["hashedPassword"], stored);
    let names: Vec<Value> =
        manager.list_users().unwrap().as_array().unwrap().iter().map(|r| r["username"].clone()).collect();
    assert_eq!(names, [s("alice"), s("bob"), s("carol")]);
    assert!(mita.config()["users"][2].get("quotas").is_none());
}

#[test]
fn create_with_private_or_loopback_policy_forces_controlled_restart() {
    for flag in ["allow_private_ip", "allow_loopback_ip"] {
        let (_dir, mita, manager, revision) = service(&format!("flag-{flag}"));
        mita.clear();
        let (private, loopback) = (json!(flag == "allow_private_ip"), json!(flag == "allow_loopback_ip"));
        manager.create_user(&s("bob"), &json!([]), &revision, &json!(true), &private, &loopback, None, None).unwrap();
        assert_eq!(mita.calls()[mita.calls().len() - 3..], [json!(["stop"]), json!(["start"]), json!(["probe"])]);
    }
    let (_dir, _mita, manager, revision) = service("flag-refused");
    let refused =
        manager.create_user(&s("bob"), &json!([]), &revision, &json!(false), &json!(true), &json!(false), None, None);
    assert_eq!(refused.unwrap_err(), Error::validation("private/loopback SSRF flags require elevated approval"));
}

#[test]
fn transaction_restart_waits_for_idle_then_running_through_transients() {
    let (_dir, mita, manager, revision) = service("restart-transients");
    mita.clear();
    mita.statuses(&["STOPPING", "IDLE", "STARTING", "RUNNING"]);
    manager
        .create_user(&s("bob"), &json!([]), &revision, &json!(true), &json!(true), &json!(false), None, None)
        .unwrap();
    assert_eq!(mita.calls()[mita.calls().len() - 3..], [json!(["stop"]), json!(["start"]), json!(["probe"])]);
}

#[test]
fn rotation_delete_and_disable_force_restart_and_tombstone_names() {
    let (_dir, mita, manager, revision) = service("rotation");
    let restarted = |mita: &FakeMita| {
        let calls = mita.calls();
        assert_eq!(calls[calls.len() - 3..], [json!(["stop"]), json!(["start"]), json!(["probe"])]);
        mita.clear();
    };
    let revision = create(&manager, "bob", json!([]), &revision).unwrap()["revision"].clone();
    mita.clear();
    let revision = manager.disable_user("bob", &revision).unwrap()["revision"].clone();
    restarted(&mita);
    assert_eq!(manager.list_users().unwrap()[1]["enabled"], false);
    let revision = manager.enable_user("bob", &revision).unwrap()["revision"].clone();
    restarted(&mita);
    let rotated = manager.rotate_user("bob", &revision, None, None).unwrap();
    assert!(rotated["share_url"].as_str().unwrap().starts_with("mierus://bob:"));
    restarted(&mita);
    manager.delete_user("bob", &rotated["revision"]).unwrap();
    restarted(&mita);
    assert!(conflict(create(&manager, "bob", json!([]), &revision_of(&manager))).contains("reuse"));
}

#[test]
fn transaction_phase_journal_is_v3_authenticated_without_config_snapshot() {
    let (dir, mita, manager, revision) = service("journal-v3");
    mita.get().interrupted = true;
    assert!(mita_error(create(&manager, "bob", json!([]), &revision)).contains("requires recovery"));
    let root = dir.join("state");
    let mut journal = read_json(&root.join("journal.json")).as_object().cloned().unwrap();
    let mac = journal.shift_remove("mac").unwrap();
    let key = std::fs::read(root.join("journal.key")).unwrap();
    let expected = util::hmac_sha256_hex(&key, pyjson::canonical(&Value::Object(journal.clone())).as_bytes());
    assert_eq!((&journal["version"], &journal["schema"]), (&json!(3), &json!("mieru-transaction-journal-v3")));
    assert_eq!(mac, json!(expected));
    assert!(journal.values().all(|value| !value.is_object() && !value.is_array()));
}

#[test]
fn failed_probe_rolls_back_full_snapshot_and_restarts() {
    let (dir, mita, manager, revision) = service("probe-rollback");
    let before = mita.config();
    mita.get().fail_probe = true;
    assert!(mita_error(create(&manager, "bob", json!([]), &revision)).contains("transaction failed"));
    assert_eq!(mita.config(), before);
    assert_eq!(mita.names().iter().filter(|n| *n == "apply").count(), 2);
    let calls = mita.calls();
    assert_eq!(calls[calls.len() - 3..], [json!(["stop"]), json!(["start"]), json!(["probe"])]);
    assert!(!dir.join("state/journal.json").exists());
}

// ---------------------------------------------------------------- recovery

fn hash(value: &Value) -> String {
    util::hash(value)
}

fn authenticate_journal(root: &Path, journal: &Value) -> Value {
    let key = std::fs::read(root.join("journal.key")).unwrap();
    let mut authenticated = journal.clone();
    authenticated["mac"] = json!(util::hmac_sha256_hex(&key, pyjson::canonical(journal).as_bytes()));
    authenticated
}

fn write_private(path: &Path, data: &[u8]) {
    std::fs::write(path, data).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_recovery_fixture(
    root: &Path,
    state: &Value,
    before: &Value,
    desired: &Value,
    generation: Option<i64>,
    phase: &str,
) -> (PathBuf, PathBuf) {
    let backup_dir = root.join("backups");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let backup = backup_dir.join(format!("g{}-{}.json", state["generation"], state["revision"].as_str().unwrap()));
    let mut backup_bytes = pyjson::canonical(before).into_bytes();
    backup_bytes.push(b'\n');
    write_private(&backup, &backup_bytes);
    let generation = generation.unwrap_or(state["generation"].as_i64().unwrap());
    let journal = json!({
        "version": 3,
        "schema": "mieru-transaction-journal-v3",
        "phase": phase,
        "operation": "user.create",
        "mode": "reload",
        "previous_config_hash": util::sha256_hex(&backup_bytes[..backup_bytes.len() - 1]),
        "desired_config_hash": hash(desired),
        "state_revision": state["revision"],
        "state_generation": generation,
        "next_revision": hash(&json!({
            "config": desired,
            "disabled": state["disabled"],
            "tombstones": state["tombstones"],
            "generation": state["generation"].as_i64().unwrap() + 1,
        })),
        "next_generation": generation + 1,
        "backup_basename": backup.file_name().unwrap().to_str().unwrap(),
        "backup_size": backup_bytes.len(),
        "backup_sha256": util::sha256_hex(&backup_bytes),
    });
    let path = root.join("journal.json");
    write_private(&path, authenticate_journal(root, &journal).to_string().as_bytes());
    (path, backup)
}

fn debug_config() -> Value {
    with(base(), "loggingLevel", s("DEBUG"))
}

#[test]
fn recovery_is_generation_bound_and_checks_observed_phase_before_side_effect() {
    let (dir, mita, _manager, _) = service("recovery");
    let root = dir.join("state");
    let state = read_json(&root.join("state.json"));
    mita.get().config = debug_config();
    write_recovery_fixture(&root, &state, &base(), &debug_config(), None, "applied");
    mita.clear();
    let recovered = manager_in(&dir, &mita).bootstrap().unwrap();
    assert_eq!(recovered["ready"], true);
    assert_eq!(mita.config(), base());
    assert_eq!(mita.calls()[..3], [json!(["apply", base()]), json!(["stop"]), json!(["start"])]);
    assert!(!root.join("journal.json").exists());
}

#[test]
fn stale_or_tampered_recovery_journal_fails_closed_without_backup_apply() {
    let (dir, mita, _manager, _) = service("recovery-stale");
    let root = dir.join("state");
    let state = read_json(&root.join("state.json"));
    mita.get().config = debug_config();
    let generation = state["generation"].as_i64().unwrap() + 1;
    let (journal, _) = write_recovery_fixture(&root, &state, &base(), &debug_config(), Some(generation), "applied");
    mita.clear();
    assert!(conflict(manager_in(&dir, &mita).bootstrap()).contains("recovery"));
    assert!(mita.calls().is_empty());
    assert_eq!(mita.config(), debug_config());
    assert!(journal.exists());
}

#[test]
fn prepared_recovery_rejects_any_unauthenticated_metadata_before_side_effects() {
    let cases = [
        ("operation", s("user.quotas")),
        ("mode", s("restart")),
        ("next_revision", s(&"0".repeat(64))),
        ("backup_basename", s("not-generation-bound.json")),
        ("phase", s("rollback_applied")),
        ("desired_config_hash", s(&"0".repeat(64))),
    ];
    for (field, value) in cases {
        let (dir, mita, _manager, _) = service(&format!("tamper-{field}"));
        mita.get().record_version = true;
        let root = dir.join("state");
        let state = read_json(&root.join("state.json"));
        let (journal_path, _) = write_recovery_fixture(&root, &state, &base(), &debug_config(), None, "prepared");
        let mut journal = read_json(&journal_path);
        journal[field] = value;
        write_private(&journal_path, journal.to_string().as_bytes());
        mita.clear();
        assert!(conflict(manager_in(&dir, &mita).bootstrap()).contains("recovery"), "{field}");
        assert!(mita.calls().is_empty(), "{field}");
        assert_eq!(mita.config(), base());
        assert!(journal_path.exists());
    }
}

#[test]
fn authenticated_recovery_completes_each_legitimate_phase() {
    for (phase, observed, first) in [
        ("prepared", base(), json!(["stop"])),
        ("applied", debug_config(), json!(["apply", base()])),
        ("rollback_applied", base(), json!(["stop"])),
    ] {
        let (dir, mita, _manager, _) = service(&format!("phase-{phase}"));
        let root = dir.join("state");
        let state = read_json(&root.join("state.json"));
        mita.get().config = observed;
        let (journal_path, _) = write_recovery_fixture(&root, &state, &base(), &debug_config(), None, phase);
        mita.clear();
        assert_eq!(manager_in(&dir, &mita).bootstrap().unwrap()["ready"], true);
        assert_eq!(mita.calls()[0], first, "{phase}");
        assert_eq!(mita.config(), base());
        assert!(!journal_path.exists());
    }
}

#[test]
fn recovery_fails_closed_when_journal_key_is_unavailable_or_unsafe() {
    for damage in ["missing", "symlink", "mode", "contents"] {
        let (dir, mita, _manager, _) = service(&format!("key-{damage}"));
        mita.get().record_version = true;
        let root = dir.join("state");
        let state = read_json(&root.join("state.json"));
        let (journal_path, _) = write_recovery_fixture(&root, &state, &base(), &debug_config(), None, "prepared");
        let key = root.join("journal.key");
        match damage {
            "missing" => std::fs::remove_file(&key).unwrap(),
            "symlink" => {
                std::fs::remove_file(&key).unwrap();
                std::os::unix::fs::symlink(root.join("state.json"), &key).unwrap();
            }
            "mode" => std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap(),
            _ => write_private(&key, &[b'x'; 32]),
        }
        mita.clear();
        assert!(matches!(manager_in(&dir, &mita).bootstrap(), Err(Error::Conflict(_))), "{damage}");
        assert!(mita.calls().is_empty(), "{damage}");
        assert!(journal_path.exists());
    }
}

// ---------------------------------------------------------------- metrics, links, traffic

#[test]
fn per_user_metrics_fail_closed_when_typed_getusers_boundary_is_unavailable() {
    let (dir, _mita, manager, _) = service("metrics");
    assert_eq!(
        manager.metrics().unwrap(),
        json!({"status": "error", "stale": true, "users": [], "capability": "unavailable", "reason": "typed_histories_unavailable"})
    );
    assert!(conflict(manager.reset_metric_baseline("alice")).contains("unavailable"));
    assert!(!dir.join("state/metrics.pb").exists());
}

#[test]
fn share_links_bracket_ipv6_and_reject_traffic_pattern_before_mutation() {
    let dir = tempdir("ipv6");
    let mita = FakeMita::base();
    let manager = MieruManager::new(mita.clone(), dir.join("ipv6"), "2001:db8::1");
    let revision = manager.bootstrap().unwrap()["revision"].clone();
    let created = create(&manager, "bob", json!([]), &revision).unwrap();
    assert!(created["share_url"].as_str().unwrap().contains("@[2001:db8::1]?"));
    let mita = FakeMita::new(with(base(), "trafficPattern", json!({"seed": 42})));
    let manager = manager_in(&dir.join("traffic"), &mita);
    let revision = manager.bootstrap().unwrap()["revision"].clone();
    mita.clear();
    match create(&manager, "bob", json!([]), &revision) {
        Err(Error::Validation(message)) => assert!(message.contains("trafficPattern")),
        other => panic!("{other:?}"),
    }
    assert!(mita.calls().is_empty());
}

#[test]
fn manager_traffic_lists_every_user_with_client_side_directions() {
    let (_dir, mita, manager, _) = service("traffic");
    mita.get().traffic = BTreeMap::from([("bob".into(), (5, 50)), ("alice".into(), (1, 10))]);
    assert_eq!(
        manager.traffic().unwrap(),
        json!({"users": [
            {"username": "alice", "upload_bytes": 1, "download_bytes": 10},
            {"username": "bob", "upload_bytes": 5, "download_bytes": 50},
        ]})
    );
}

// ---------------------------------------------------------------- replays

#[test]
fn create_with_caller_password_and_operation_id_replays_without_secret() {
    let (_dir, _mita, manager, revision) = service("replay");
    let first = create_with(&manager, "phone", &revision, Some("caller-supplied-password-01"), Some("op-1")).unwrap();
    assert!(first["share_url"].as_str().unwrap().contains("caller-supplied-password-01"));
    // The retry carries a stale revision — that is the whole point of a lost response.
    let second =
        create_with(&manager, "phone", &s("stale"), Some("caller-supplied-password-01"), Some("op-1")).unwrap();
    assert_eq!(second, json!({"username": "phone", "revision": first["revision"], "replayed": true}));
    let names: Vec<Value> =
        manager.list_users().unwrap().as_array().unwrap().iter().map(|r| r["username"].clone()).collect();
    assert_eq!(names, [s("alice"), s("phone")]);
    let journal = Value::Object(manager.read_state().unwrap()).to_string();
    assert!(!journal.contains("caller-supplied-password-01") && !journal.contains("share_url"));
}

#[test]
fn manager_generated_credential_cannot_be_replayed() {
    let (_dir, _mita, manager, revision) = service("generated");
    create_with(&manager, "phone", &revision, None, Some("op-2")).unwrap();
    assert!(conflict(create_with(&manager, "phone", &s("stale"), None, Some("op-2"))).contains("unrecoverable"));
}

#[test]
fn rotate_with_operation_id_is_replayable() {
    let (_dir, _mita, manager, revision) = service("rotate-replay");
    let created = create(&manager, "phone", json!([]), &revision).unwrap();
    let (password, op) = (s("rotated-password-0123456"), s("op-3"));
    let first = manager.rotate_user("phone", &created["revision"], Some(&password), Some(&op)).unwrap();
    let second = manager.rotate_user("phone", &s("stale"), Some(&password), Some(&op)).unwrap();
    assert_eq!(second, json!({"username": "phone", "revision": first["revision"], "replayed": true}));
    assert!(first["share_url"].as_str().unwrap().contains("rotated-password-0123456"));
}

#[test]
fn operation_id_reused_for_another_request_conflicts() {
    let (_dir, _mita, manager, revision) = service("reused");
    create_with(&manager, "phone", &revision, Some("caller-supplied-password-01"), Some("op-4")).unwrap();
    let reused = create_with(&manager, "laptop", &s("stale"), Some("caller-supplied-password-02"), Some("op-4"));
    assert!(conflict(reused).contains("operation id"));
}

#[test]
fn a_caller_password_is_validated_and_operations_are_pruned() {
    let (_dir, _mita, manager, revision) = service("pruned");
    assert_eq!(
        create_with(&manager, "phone", &revision, Some("short"), None).unwrap_err(),
        Error::validation("invalid password")
    );
    let created = create_with(&manager, "phone", &revision, Some("caller-supplied-password-01"), Some("op-5")).unwrap();
    let mut state = manager.read_state().unwrap();
    assert_eq!(state["operations"]["op-5"]["credential_origin"], "caller");
    assert_eq!(state["operations"]["op-5"]["revision"], created["revision"]);
    state["operations"].as_object_mut().unwrap().insert(
        "op-old".into(),
        json!({"operation": "user.create", "username": "ghost", "revision": "r",
               "completed_at": "2000-01-01T00:00:00+00:00", "credential_origin": "caller"}),
    );
    util::atomic_json(&manager.state_file, &Value::Object(state)).unwrap();
    let kept: Vec<String> = manager.read_state().unwrap()["operations"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(kept, ["op-5"]);
}

// ---------------------------------------------------------------- the real CLI in a transaction

#[test]
fn fake_mita_process_covers_fd_lifecycle_rollback_recovery_and_secret_hygiene() {
    let dir = tempdir("fake-process");
    let fake = dir.join("mita");
    let (argv_log, live, running, fail_reload) =
        (dir.join("argv.jsonl"), dir.join("live.json"), dir.join("running"), dir.join("fail-reload"));
    std::fs::write(&live, base().to_string()).unwrap();
    std::fs::write(&running, "yes").unwrap();
    std::fs::write(
        &fake,
        r#"#!/usr/bin/python3
import hashlib, json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['ARGV_LOG'], 'a') as stream:
    stream.write(json.dumps(args) + '\n')
config = pathlib.Path(os.environ['LIVE_CONFIG'])
running = pathlib.Path(os.environ['RUNNING'])
if args == ['version']:
    print('mita 3.35.0')
elif args == ['describe', 'config']:
    print(config.read_text())
elif args[:2] == ['apply', 'config']:
    assert len(args) == 3 and args[2].startswith('/proc/self/fd/')
    value = json.load(open(args[2]))
    for user in value.get('users', []):
        if 'password' in user:
            raw = user.pop('password')
            user['hashedPassword'] = hashlib.sha256((raw + '\0' + user['name']).encode()).hexdigest()
    config.write_text(json.dumps(value, sort_keys=True))
elif args == ['reload']:
    marker = pathlib.Path(os.environ['FAIL_RELOAD'])
    if marker.exists():
        marker.unlink()
        raise SystemExit(9)
elif args == ['stop']:
    running.unlink(missing_ok=True)
elif args == ['start']:
    running.write_text('yes')
elif args == ['status']:
    state = 'RUNNING' if running.exists() else 'IDLE'
    print(f'mita server status is "{state}"')
elif args == ['get', 'metrics']:
    print('{"users": []}')
else:
    raise SystemExit(8)
"#,
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = vec![
        ("ARGV_LOG".to_string(), argv_log.display().to_string()),
        ("LIVE_CONFIG".to_string(), live.display().to_string()),
        ("RUNNING".to_string(), running.display().to_string()),
        ("FAIL_RELOAD".to_string(), fail_reload.display().to_string()),
    ];
    let cli = Arc::new(crate::mita::MitaCli::new(&fake, env, None));
    let manager = MieruManager::new(cli.clone(), dir.join("manager"), "proxy.example.com")
        .with_token(Box::new(|| Ok("raw-integration-secret".into())));
    let revision = manager.bootstrap().unwrap()["revision"].clone();
    std::fs::write(&fail_reload, "once").unwrap();
    let error = create(&manager, "bob", json!([]), &revision).unwrap_err();
    assert!(error.message().contains("rolled back"), "{error}");
    assert_eq!(read_json(&live), base());
    assert_eq!(manager.lifecycle("stop").unwrap()["ready"], false);
    assert_eq!(manager.lifecycle("start").unwrap()["ready"], true);
    assert_eq!(manager.lifecycle("restart").unwrap()["ready"], true);

    let state = read_json(&dir.join("manager/state.json"));
    let backup =
        dir.join(format!("manager/backups/g{}-{}.json", state["generation"], state["revision"].as_str().unwrap()));
    let backup_data = pyjson::canonical(&base()).into_bytes();
    write_private(&backup, &backup_data);
    let changed = debug_config();
    let next_generation = state["generation"].as_i64().unwrap() + 1;
    let next_revision = hash(&json!({
        "config": changed, "disabled": state["disabled"], "tombstones": state["tombstones"], "generation": next_generation,
    }));
    std::fs::write(&live, changed.to_string()).unwrap();
    let journal = json!({
        "version": 3, "schema": "mieru-transaction-journal-v3", "phase": "applied", "operation": "user.create",
        "mode": "reload", "previous_config_hash": state["config_hash"], "desired_config_hash": hash(&changed),
        "state_revision": state["revision"], "state_generation": state["generation"], "next_revision": next_revision,
        "next_generation": next_generation, "backup_basename": backup.file_name().unwrap().to_str().unwrap(),
        "backup_size": backup_data.len(), "backup_sha256": util::sha256_hex(&backup_data),
    });
    let journal_path = dir.join("manager/journal.json");
    write_private(&journal_path, authenticate_journal(&dir.join("manager"), &journal).to_string().as_bytes());
    let recovered = MieruManager::new(cli, dir.join("manager"), "proxy.example.com").bootstrap().unwrap();
    assert_eq!(recovered["ready"], true);
    assert_eq!(read_json(&live), base());
    assert!(!journal_path.exists());

    let mut persisted = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap().path();
            if entry.is_dir() {
                stack.push(entry);
            } else if entry != fake {
                persisted.extend(std::fs::read(&entry).unwrap());
            }
        }
    }
    assert!(!String::from_utf8_lossy(&persisted).contains("raw-integration-secret"));
    assert!(!error.to_string().contains("raw-integration-secret"));
    assert!(std::fs::read_to_string(&argv_log).unwrap().contains("/proc/self/fd/"));
}

// ---------------------------------------------------------------- egress API

const WARP: &str = "socks5://127.0.0.1:45000";
const ROUTER: &str = "socks5://127.0.0.1:45102";

fn router_secret() -> String {
    format!("mieru-e5f6a7b8:{}", "K".repeat(40))
}

fn direct_doc() -> Value {
    json!({"schema": 1, "proxies": [], "rules": []})
}

fn warp_doc() -> Value {
    json!({"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
           "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"}]})
}

fn selective_doc() -> Value {
    json!({"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}], "rules": [
        {"domains": ["example.com"], "cidrs": [], "action": "REJECT", "proxy": null},
        {"domains": ["api.ipify.org"], "cidrs": ["10.0.0.0/8"], "action": "DIRECT", "proxy": null},
        {"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"},
    ]})
}

fn router_doc() -> Value {
    json!({"schema": 1, "proxies": [{"name": "router", "provider": "router"}],
           "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "router"}]})
}

fn normal(document: &Value) -> Value {
    egress::validate_document(document).unwrap()
}

fn warp_providers() -> egress::Providers {
    egress::Providers::warp(Some(WARP))
}

fn egress_manager(dir: &Path, mita: &Arc<FakeMita>, provider: Option<&str>, reachable: bool) -> MieruManager {
    let manager = manager_in(dir, mita)
        .with_providers(provider.map(str::to_string), None, None)
        .with_reachability(Box::new(move |_url, _timeout, _auth| reachable));
    manager.bootstrap().unwrap();
    manager
}

type Greetings = Arc<Mutex<Vec<(Option<String>, bool)>>>;

fn router_manager(dir: &Path, mita: &Arc<FakeMita>, secret: &str, reachable: bool) -> (MieruManager, Greetings) {
    let credential = dir.join("xray-router-ingress");
    std::fs::write(&credential, format!("{secret}\n")).unwrap();
    let greetings: Greetings = Arc::default();
    let seen = greetings.clone();
    let manager = manager_in(dir, mita)
        .with_providers(Some(WARP.into()), Some(ROUTER.into()), Some(credential))
        .with_reachability(Box::new(move |url, _timeout, auth| {
            seen.lock().unwrap().push((url.map(str::to_string), auth));
            reachable
        }));
    manager.bootstrap().unwrap();
    (manager, greetings)
}

fn egress_error(result: Result<Value>) -> Error {
    result.unwrap_err()
}

#[test]
fn get_reports_the_section_document_providers_and_capabilities() {
    let dir = tempdir("egress-get");
    let manager = egress_manager(&dir, &FakeMita::base(), Some(WARP), true);
    let view = manager.egress().unwrap();
    assert_eq!((&view["document"], &view["mode"]), (&normal(&direct_doc()), &s("direct")));
    assert_eq!((&view["raw"], &view["managed"]), (&Value::Null, &json!(false)));
    assert_eq!(view["providers"], json!({"warp": {"url": WARP, "reachable": true}}));
    assert_eq!(view["capabilities"], json!(egress::CAPABILITIES));
    assert_eq!(view["restart_required"], true);
    assert_eq!((&view["revision"], &view["previous"]), (&revision_of(&manager), &Value::Null));
    let seeded = FakeMita::new(with(
        base(),
        "egress",
        json!({
        "proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 40000}],
        "rules": [{"ipRanges": ["*"], "action": "PROXY", "proxyNames": ["warp"]}]}),
    ));
    let custom = egress_manager(&dir.join("custom"), &seeded, Some(WARP), true).egress().unwrap();
    assert_eq!((&custom["mode"], &custom["document"]), (&s("custom"), &Value::Null));
    assert_eq!(custom["raw"]["proxies"][0]["port"], 40000);
    assert_eq!(
        egress_manager(&dir.join("none"), &FakeMita::base(), None, true).egress().unwrap()["providers"],
        json!({})
    );
}

#[test]
fn plan_is_read_only_and_reports_the_target_section() {
    let dir = tempdir("egress-plan");
    let mita = FakeMita::base();
    let manager = egress_manager(&dir, &mita, Some(WARP), true);
    let revision = revision_of(&manager);
    let plan = manager.egress_plan(&revision, &warp_doc()).unwrap();
    assert!(mita.calls().is_empty() && mita.config() == base());
    assert_eq!((&plan["revision"], &plan["restart_required"]), (&revision, &json!(true)));
    assert_eq!(plan["target"], egress::to_mita(&normal(&warp_doc()), &warp_providers(), None).unwrap());
    assert_eq!(plan["reachability"], json!({"warp": true}));
    assert!(plan["diff"].as_array().unwrap().iter().any(|line| line.as_str().unwrap().contains("warp")));
}

#[test]
fn apply_replaces_only_the_egress_section_with_a_restart() {
    let dir = tempdir("egress-apply");
    let mita = FakeMita::base();
    let manager = egress_manager(&dir, &mita, Some(WARP), true);
    let revision = create(&manager, "bob", json!([]), &revision_of(&manager)).unwrap()["revision"].clone();
    let before = mita.config();
    mita.clear();
    let result = manager.egress_apply(&revision, &selective_doc(), &s("routing:p1:1")).unwrap();
    let after = mita.config();
    assert_eq!(after["egress"], egress::to_mita(&normal(&selective_doc()), &warp_providers(), None).unwrap());
    let without = |value: &Value| {
        let mut map = value.as_object().cloned().unwrap();
        map.shift_remove("egress");
        map
    };
    assert_eq!(without(&after), without(&before));
    let calls = mita.calls();
    assert_eq!(calls[calls.len() - 3..], [json!(["stop"]), json!(["start"]), json!(["probe"])]);
    assert!(result["revision"] == revision_of(&manager) && result["revision"] != revision);
    assert_eq!((&result["applied"], &result["replayed"]), (&normal(&selective_doc()), &json!(false)));
    let view = manager.egress().unwrap();
    assert_eq!(
        (&view["document"], &view["mode"], &view["managed"]),
        (&normal(&selective_doc()), &s("proxy"), &json!(true))
    );
    assert!(!view["previous"].is_null());
    let state = read_json(&dir.join("state/state.json"));
    let history = state["egress"]["history"].as_array().unwrap();
    assert_eq!((&history[history.len() - 1]["operation_id"], history.len()), (&s("routing:p1:1"), 2));
}

#[test]
fn apply_conflicts_and_refusals_leave_mita_untouched() {
    let dir = tempdir("egress-refusals");
    let mita = FakeMita::base();
    let manager = egress_manager(&dir, &mita, Some(WARP), false);
    let revision = revision_of(&manager);
    assert!(conflict(manager.egress_apply(&s(&"0".repeat(64)), &warp_doc(), &s("op-1"))).contains("revision"));
    assert!(matches!(
        egress_error(manager.egress_apply(&revision, &warp_doc(), &s("op-1"))),
        Error::EgressUnreachable(_)
    ));
    let empty_rule =
        json!({"schema": 1, "proxies": [], "rules": [{"domains": [], "cidrs": [], "action": "REJECT", "proxy": null}]});
    assert!(matches!(egress_error(manager.egress_apply(&revision, &empty_rule, &s("op-1"))), Error::EgressInvalid(_)));
    assert!(mita.calls().is_empty() && mita.config() == base());
    let result = manager.egress_apply(&revision, &direct_doc(), &s("op-2")).unwrap(); // direct never needs the provider
    assert_eq!(result["applied"], normal(&direct_doc()));
    let without = egress_manager(&dir.join("none"), &FakeMita::base(), None, true);
    match egress_error(without.egress_apply(&revision_of(&without), &warp_doc(), &s("op-3"))) {
        Error::EgressInvalid(message) => assert!(message.contains("not configured")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn apply_is_idempotent_by_operation_id() {
    let dir = tempdir("egress-idempotent");
    let mita = FakeMita::base();
    let manager = egress_manager(&dir, &mita, Some(WARP), true);
    let first = manager.egress_apply(&revision_of(&manager), &warp_doc(), &s("op-1")).unwrap();
    let applies = mita.names().iter().filter(|n| *n == "apply").count();
    let again = manager.egress_apply(&first["revision"], &warp_doc(), &s("op-1")).unwrap();
    assert_eq!((&again["revision"], &again["replayed"]), (&first["revision"], &json!(true)));
    assert_eq!(mita.names().iter().filter(|n| *n == "apply").count(), applies);
    assert!(conflict(manager.egress_apply(&first["revision"], &direct_doc(), &s("op-1"))).contains("operation id"));
}

#[test]
fn a_failed_probe_rolls_the_section_back() {
    let dir = tempdir("egress-probe");
    let mita = FakeMita::base();
    let manager = egress_manager(&dir, &mita, Some(WARP), true);
    let revision = revision_of(&manager);
    mita.get().fail_probe = true;
    assert!(mita_error(manager.egress_apply(&revision, &warp_doc(), &s("op-1"))).contains("rolled back"));
    assert!(mita.config() == base() && revision_of(&manager) == revision);
    assert!(manager.egress().unwrap()["previous"].is_null());
}

#[test]
fn rollback_walks_back_to_the_seeded_section() {
    let dir = tempdir("egress-rollback");
    let seed = with(
        base(),
        "egress",
        json!({
        "proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 40000}],
        "rules": [{"ipRanges": ["0.0.0.0/0", "::/0"], "action": "DIRECT"}]}),
    );
    let mita = FakeMita::new(seed.clone());
    let manager = egress_manager(&dir, &mita, Some(WARP), true);
    let first = manager.egress_apply(&revision_of(&manager), &warp_doc(), &s("op-1")).unwrap();
    let second = manager.egress_apply(&first["revision"], &selective_doc(), &s("op-2")).unwrap();
    let rolled = manager.egress_rollback(&second["revision"]).unwrap();
    assert_eq!(manager.egress().unwrap()["document"], normal(&warp_doc()));
    assert_eq!(rolled["applied"], normal(&warp_doc()));
    let rolled = manager.egress_rollback(&rolled["revision"]).unwrap();
    assert_eq!(mita.config()["egress"], seed["egress"]); // the seeded section, verbatim
    assert_eq!((&manager.egress().unwrap()["mode"], &rolled["applied"]), (&s("custom"), &Value::Null));
    assert!(conflict(manager.egress_rollback(&rolled["revision"])).contains("no previous"));
}

#[test]
fn egress_views_never_contain_router_credential() {
    let dir = tempdir("egress-router-views");
    let mita = FakeMita::base();
    let (manager, greetings) = router_manager(&dir, &mita, &router_secret(), true);
    let revision = revision_of(&manager);
    let plan = manager.egress_plan(&revision, &router_doc()).unwrap();
    assert_eq!(plan["reachability"], json!({"router": true}));
    assert!(greetings.lock().unwrap().contains(&(Some(ROUTER.into()), true)));
    let result = manager.egress_apply(&revision, &router_doc(), &s("op-router")).unwrap();
    assert_eq!(
        mita.config()["egress"]["proxies"][0]["socks5Authentication"],
        json!({"user": "mieru-e5f6a7b8", "password": "K".repeat(40)})
    );
    let view = manager.egress().unwrap();
    assert_eq!((&view["document"], &view["mode"]), (&normal(&router_doc()), &s("proxy")));
    assert_eq!(view["providers"]["router"], json!({"url": ROUTER, "reachable": true}));
    let other_plan = manager.egress_plan(&view["revision"], &warp_doc()).unwrap();
    for text in [plan.to_string(), view.to_string(), result.to_string(), other_plan.to_string()] {
        assert!(!text.contains(&"K".repeat(40)) && !text.contains("mieru-e5f6a7b8"));
    }
    assert!(!std::fs::read_to_string(dir.join("state/state.json")).unwrap().contains(&"K".repeat(40)));
}

#[test]
fn apply_router_unreachable_refuses() {
    let dir = tempdir("egress-router-down");
    let mita = FakeMita::base();
    let (manager, _) = router_manager(&dir, &mita, &router_secret(), false);
    match egress_error(manager.egress_apply(&revision_of(&manager), &router_doc(), &s("op-1"))) {
        Error::EgressUnreachable(message) => assert!(message.contains("router")),
        other => panic!("{other:?}"),
    }
    assert!(mita.config().get("egress").is_none());
    let plain = egress_manager(&dir.join("plain"), &FakeMita::base(), Some(WARP), true);
    match egress_error(plain.egress_apply(&revision_of(&plain), &router_doc(), &s("op-1"))) {
        Error::EgressInvalid(message) => assert!(message.contains("router")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn bootstrap_rerenders_after_rotation() {
    let dir = tempdir("egress-rotation");
    let mita = FakeMita::base();
    let (manager, _) = router_manager(&dir, &mita, &router_secret(), true);
    let applied = manager.egress_apply(&revision_of(&manager), &router_doc(), &s("op-router")).unwrap();
    let rotated = format!("mieru-e5f6a7b8:{}", "Z".repeat(40));
    std::fs::write(dir.join("xray-router-ingress"), format!("{rotated}\n")).unwrap();
    assert_eq!(manager.egress().unwrap()["warnings"], json!(["router_credential_stale"]));
    mita.clear();
    let (fresh, _) = router_manager(&dir, &mita, &rotated, true);
    assert_eq!(mita.config()["egress"]["proxies"][0]["socks5Authentication"]["password"], "Z".repeat(40));
    assert!(mita.names().contains(&"stop".into()) && mita.names().contains(&"start".into()));
    let view = fresh.egress().unwrap();
    assert_eq!((&view["warnings"], &view["document"]), (&json!([]), &normal(&router_doc())));
    assert!(view["revision"] != applied["revision"] && view["current"]["operation_id"] == "op-router");
    assert!(!view["previous"].is_null());
    // A rollback still walks back: the floor (no section) is restored.
    fresh.egress_rollback(&view["revision"]).unwrap();
    assert!(mita.config().get("egress").is_none());
    // A custom hand-written router proxy with somebody's credential is shown masked.
    let custom = FakeMita::new(with(
        base(),
        "egress",
        json!({
        "proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102,
                     "socks5Authentication": {"user": "x", "password": "y".repeat(20)}}],
        "rules": [{"ipRanges": ["*"], "action": "PROXY", "proxyNames": ["router"]}]}),
    ));
    let other = egress_manager(&dir.join("custom"), &custom, Some(WARP), true);
    let view = other.egress().unwrap();
    assert!(view["mode"] == "custom" && !view.to_string().contains(&"y".repeat(20)));
}

/// The installer seeds mita's `egress` with the router proxy and the credential of the day;
/// there is no journal yet. After a rotation bootstrap re-renders the section from the file
/// through the restart transaction, exactly as it does for an applied one.
#[test]
fn bootstrap_refreshes_the_installer_seed_after_rotation() {
    let dir = tempdir("egress-seed-rotation");
    let seeded = FakeMita::new(with(
        base(),
        "egress",
        json!({
        "proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102,
                     "socks5Authentication": {"user": "mieru-e5f6a7b8", "password": "K".repeat(40)}}],
        "rules": [{"action": "PROXY", "ipRanges": ["*"], "domainNames": ["*"], "proxyNames": ["router"]}]}),
    ));
    let (manager, _) = router_manager(&dir, &seeded, &router_secret(), true);
    let view = manager.egress().unwrap();
    assert_eq!((&view["mode"], &view["document"]), (&s("proxy"), &normal(&router_doc())));
    assert_eq!(view["warnings"], json!(["adopts_unmanaged_egress"]));
    let rotated = format!("mieru-e5f6a7b8:{}", "Z".repeat(40));
    std::fs::write(dir.join("xray-router-ingress"), format!("{rotated}\n")).unwrap();
    assert!(manager.egress().unwrap()["warnings"].as_array().unwrap().contains(&s("router_credential_stale")));
    seeded.clear();
    let (fresh, _) = router_manager(&dir, &seeded, &rotated, true);
    assert_eq!(seeded.config()["egress"]["proxies"][0]["socks5Authentication"]["password"], "Z".repeat(40));
    assert!(seeded.names().contains(&"stop".into()) && seeded.names().contains(&"start".into()));
    let view = fresh.egress().unwrap();
    assert!(!view["warnings"].as_array().unwrap().contains(&s("router_credential_stale")));
    assert_eq!(view["document"], normal(&router_doc()));
}

// ---------------------------------------------------------------- lanes

const SLOTS: &str =
    "1:46101:/run/mita/lane-1.sock:/var/lib/mita/lanes/1,2:46102:/run/mita/lane-2.sock:/var/lib/mita/lanes/2";

fn two_users() -> Value {
    with(
        base(),
        "users",
        json!([
            {"name": "alice", "hashedPassword": "a".repeat(64)},
            {"name": "bob", "hashedPassword": "b".repeat(64), "quotas": [{"days": 30, "megabytes": 1024}]},
            {"name": "carol", "hashedPassword": "c".repeat(64)},
        ]),
    )
}

fn lane_a() -> Value {
    json!({"lane": "grant:7f3a", "users": ["alice"], "upstream": {"user": "grant-7f3a", "password": "A".repeat(43)}})
}

fn lane_b() -> Value {
    json!({"lane": "grant:b2c4", "users": ["bob"], "upstream": {"user": "grant-b2c4", "password": "B".repeat(43)}})
}

const SERVICE_TEMPLATE: &str =
    "mierus://{username}:{password}@proxy.example.com?profile={profile}&port=8443&protocol=TCP&mtu=1400";

type Slots = BTreeMap<u32, Arc<FakeMita>>;

fn lane_build(
    dir: &Path,
    main: &Arc<FakeMita>,
    router: Option<&str>,
    slots: Option<&str>,
    fakes: &Slots,
) -> MieruManager {
    std::fs::create_dir_all(dir).unwrap();
    let credential = dir.join("xray-router-ingress");
    std::fs::write(&credential, format!("{}\n", router_secret())).unwrap();
    let parsed = lanes::parse_slots(slots).unwrap();
    let factory_fakes = fakes.clone();
    manager_in(dir, main)
        .with_providers(None, router.map(str::to_string), router.map(|_| credential))
        .with_lanes(parsed, Some(Box::new(move |slot: &Slot| factory_fakes[&slot.index].clone() as Arc<dyn Mita>)))
        .with_reachability(Box::new(|_, _, _| true))
}

fn lane_manager(dir: &Path, router: Option<&str>, slots: Option<&str>) -> (MieruManager, Arc<FakeMita>, Slots) {
    let main = FakeMita::new(two_users());
    let parsed = lanes::parse_slots(slots).unwrap();
    let fakes: Slots = parsed.iter().map(|slot| (slot.index, FakeMita::slot(slot.port))).collect();
    let manager = lane_build(dir, &main, router, slots, &fakes);
    manager.bootstrap().unwrap();
    (manager, main, fakes)
}

fn lanes_body(lanes: &[Value]) -> Value {
    json!({"lanes": lanes})
}

#[test]
fn set_lanes_mirrors_the_lane_users_into_a_slot_with_the_router_egress() {
    let dir = tempdir("lanes-mirror");
    let (manager, main, slots) = lane_manager(&dir, Some(ROUTER), Some(SLOTS));
    let view = manager.set_lanes(&lanes_body(&[lane_a()])).unwrap();
    let config = slots[&1].config();
    assert_eq!(config["portBindings"], json!([{"port": 46101, "protocol": "TCP"}]));
    assert_eq!(config["users"], json!([{"name": "alice", "hashedPassword": "a".repeat(64)}]));
    assert_eq!(
        config["egress"],
        json!({
        "proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102,
                     "socks5Authentication": {"user": "grant-7f3a", "password": "A".repeat(43)}}],
        "rules": [{"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["router"]}]})
    );
    assert!(slots[&1].get().running && slots[&1].names().contains(&"start".into()));
    assert!(!slots[&2].get().running && slots[&2].calls().is_empty());
    // the main daemon is untouched: users stay there (the slot mirrors), no restart
    assert!(main.config() == two_users() && !main.names().contains(&"stop".into()));
    assert_eq!(
        view,
        json!({"lanes": [{"lane": "grant:7f3a", "slot": 1, "port": 46101, "users": ["alice"],
        "upstream": "socks5://***@127.0.0.1:45102", "status": "running",
        "share_templates": {"alice": "mierus://{username}:{password}@proxy.example.com?profile=alice&port=46101&protocol=TCP&mtu=1400"}}],
        "free_slots": 1, "service_share_template": SERVICE_TEMPLATE})
    );
    assert!(!view.to_string().contains(&"A".repeat(43)));
    let state = read_json(&manager.state_file);
    assert_eq!(
        state["lanes"],
        json!({"grant:7f3a": {"slot": 1, "users": ["alice"], "upstream": {"user": "grant-7f3a", "password": "A".repeat(43)}}})
    );
    let lanes: Vec<Value> =
        manager.list_users().unwrap().as_array().unwrap().iter().map(|r| r["lane"].clone()).collect();
    assert_eq!(lanes, [s("grant:7f3a"), Value::Null, Value::Null]);
}

#[test]
fn lanes_keep_their_slot_move_users_and_run_out_of_slots() {
    let dir = tempdir("lanes-keep");
    let (manager, _main, slots) = lane_manager(&dir, Some(ROUTER), Some(SLOTS));
    manager.set_lanes(&lanes_body(&[lane_a(), lane_b()])).unwrap();
    assert!(slots[&1].config()["users"][0]["name"] == "alice" && slots[&2].config()["users"][0]["name"] == "bob");
    // a lane keeps its slot across requests; a dropped lane frees its slot (empty config, stopped)
    manager.set_lanes(&lanes_body(&[lane_b()])).unwrap();
    assert!(slots[&2].config()["users"][0]["name"] == "bob" && manager.lanes().unwrap()["lanes"][0]["slot"] == 2);
    let freed = slots[&1].config();
    assert!(freed.get("users").is_none() && !slots[&1].get().running && freed.get("egress").is_none());
    assert_eq!(manager.lanes().unwrap()["free_slots"], 1);
    let moved = json!({"lane": "grant:b2c4", "users": ["alice", "bob"], "upstream": lane_b()["upstream"]});
    manager.set_lanes(&lanes_body(&[moved])).unwrap();
    let names: Vec<Value> = slots[&2].config()["users"].as_array().unwrap().iter().map(|u| u["name"].clone()).collect();
    assert_eq!(names, [s("alice"), s("bob")]);
    assert_eq!(slots[&2].config()["users"][1]["quotas"], json!([{"days": 30, "megabytes": 1024}]));
    let third =
        json!({"lane": "grant:c3", "users": ["carol"], "upstream": {"user": "grant-c3", "password": "C".repeat(43)}});
    assert_eq!(conflict(manager.set_lanes(&lanes_body(&[lane_a(), lane_b(), third]))), "lane_slots_exhausted");
    manager.set_lanes(&lanes_body(&[])).unwrap();
    assert_eq!(
        manager.lanes().unwrap(),
        json!({"lanes": [], "free_slots": 2, "service_share_template": SERVICE_TEMPLATE})
    );
    assert!(slots.values().all(|slot| !slot.get().running));
}

#[test]
fn user_changes_on_the_main_daemon_are_mirrored_into_the_slot() {
    let dir = tempdir("lanes-mirrored-changes");
    let (manager, main, slots) = lane_manager(&dir, Some(ROUTER), Some(SLOTS));
    manager.set_lanes(&lanes_body(&[lane_a()])).unwrap();
    let rotated = manager.rotate_user("alice", &revision_of(&manager), None, None).unwrap();
    let slot_hash = slots[&1].config()["users"][0]["hashedPassword"].clone();
    assert!(slot_hash == main.config()["users"][0]["hashedPassword"] && slot_hash != s(&"a".repeat(64)));
    // the rotated link names the lane's port, not the main one
    let url = rotated["share_url"].as_str().unwrap();
    assert!(url.contains("port=46101") && !url.contains("port=8443"), "{url}");
    manager.disable_user("alice", &rotated["revision"]).unwrap();
    assert!(slots[&1].config().get("users").is_none() && !slots[&1].get().running);
    assert_eq!(manager.lanes().unwrap()["lanes"][0]["users"], json!(["alice"])); // the lane remembers a disabled member
    manager.enable_user("alice", &revision_of(&manager)).unwrap();
    assert!(slots[&1].config()["users"][0]["name"] == "alice" && slots[&1].get().running);
    manager.delete_user("alice", &revision_of(&manager)).unwrap();
    assert!(slots[&1].config().get("users").is_none());
    assert_eq!(manager.lanes().unwrap()["lanes"][0]["users"], json!([])); // gone from the lane too (the name is tombstoned)
}

#[test]
fn set_lanes_refuses_bad_requests_without_touching_a_slot() {
    let upstream_a = lane_a()["upstream"].clone();
    let bodies = [
        json!({"lanes": [{"lane": "svc:mieru", "users": ["alice"], "upstream": upstream_a}]}),
        json!({"lanes": [{"lane": "grant:7f3a", "users": ["nobody"], "upstream": upstream_a}]}),
        json!({"lanes": [lane_a(), {"lane": "grant:x", "users": ["alice"], "upstream": lane_b()["upstream"]}]}),
        json!({"lanes": [{"lane": "grant:7f3a", "users": [], "upstream": upstream_a}]}),
        json!({"lanes": [{"lane": "grant:7f3a", "users": ["alice"], "upstream": {"user": "grant-7f3a"}}]}),
        json!({"lanes": "nope"}),
    ];
    for (i, body) in bodies.iter().enumerate() {
        let dir = tempdir(&format!("lanes-bad-{i}"));
        let (manager, _main, slots) = lane_manager(&dir, Some(ROUTER), Some(SLOTS));
        assert!(conflict(manager.set_lanes(body)).starts_with("lanes_invalid"), "{body}");
        assert!(slots.values().all(|slot| slot.calls().is_empty()));
    }
}

#[test]
fn lanes_need_the_router_and_slots() {
    let dir = tempdir("lanes-need");
    let (without_router, _, _) = lane_manager(&dir.join("a"), None, Some(SLOTS));
    match without_router.set_lanes(&lanes_body(&[lane_a()])) {
        Err(Error::EgressInvalid(message)) => assert!(message.contains("router")),
        other => panic!("{other:?}"),
    }
    let (without_slots, _, _) = lane_manager(&dir.join("b"), Some(ROUTER), None);
    assert_eq!(conflict(without_slots.set_lanes(&lanes_body(&[lane_a()]))), "lane_slots_exhausted");
    assert_eq!(
        without_slots.lanes().unwrap(),
        json!({"lanes": [], "free_slots": 0, "service_share_template": SERVICE_TEMPLATE})
    );
}

#[test]
fn a_failed_slot_probe_restores_the_slot_and_keeps_the_state() {
    let dir = tempdir("lanes-probe");
    let (manager, _main, slots) = lane_manager(&dir, Some(ROUTER), Some(SLOTS));
    slots[&1].get().fail_probe = true;
    let state_before = std::fs::read(&manager.state_file).unwrap();
    assert!(manager.set_lanes(&lanes_body(&[lane_a()])).is_err());
    assert_eq!(std::fs::read(&manager.state_file).unwrap(), state_before);
    assert!(slots[&1].config().get("users").is_none() && !slots[&1].get().running);
    assert_eq!(
        manager.lanes().unwrap(),
        json!({"lanes": [], "free_slots": 2, "service_share_template": SERVICE_TEMPLATE})
    );
}

#[test]
fn bootstrap_resyncs_the_slots_from_the_state() {
    let dir = tempdir("lanes-resync");
    let (manager, main, slots) = lane_manager(&dir, Some(ROUTER), Some(SLOTS));
    manager.set_lanes(&lanes_body(&[lane_a()])).unwrap();
    // the slot lost its config (a reboot of a slot daemon without persisted config, or a crash mid-apply)
    slots[&1].get().config = json!({"portBindings": [{"port": 46101, "protocol": "TCP"}], "loggingLevel": "INFO"});
    slots[&1].get().running = false;
    let again = lane_build(&dir, &main, Some(ROUTER), Some(SLOTS), &slots);
    again.bootstrap().unwrap();
    assert!(slots[&1].config()["users"][0]["name"] == "alice" && slots[&1].get().running);
    assert_eq!(again.lanes().unwrap()["lanes"][0]["lane"], "grant:7f3a");
}

#[test]
fn traffic_adds_the_counters_of_running_lane_slots_and_skips_idle_ones() {
    let dir = tempdir("lanes-traffic");
    let (manager, main, slots) = lane_manager(&dir, Some(ROUTER), Some(SLOTS));
    manager.set_lanes(&lanes_body(&[lane_a()])).unwrap(); // slot 1 runs, slot 2 stays idle
    main.get().traffic = BTreeMap::from([("alice".into(), (10, 100)), ("carol".into(), (1, 2))]);
    slots[&1].get().traffic = BTreeMap::from([("alice".into(), (5, 50))]);
    slots[&2].get().traffic = BTreeMap::from([("bob".into(), (999, 999))]); // idle daemon: not read
    assert_eq!(
        manager.traffic().unwrap(),
        json!({"users": [
            {"username": "alice", "upload_bytes": 15, "download_bytes": 150},
            {"username": "carol", "upload_bytes": 1, "download_bytes": 2},
        ]})
    );
}

// ---------------------------------------------------------------- HTTP

const TOKEN: &str = "tttttttttttttttttttttttttttttttttttttttt";

struct Api {
    socket: PathBuf,
    handle: pc_common::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Api {
    fn drop(&mut self) {
        self.handle.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(manager: MieruManager, socket: PathBuf, token: &str) -> Api {
    let mut options = ServerOptions::new(&socket);
    options.max_body = crate::server::MAX_BODY;
    let server = UdsServer::bind(options).unwrap();
    let handle = server.shutdown_handle();
    let handler = crate::server::handler(Arc::new(manager), token.into()).unwrap();
    let thread = std::thread::spawn(move || server.serve(handler));
    Api { socket, handle, thread: Some(thread) }
}

fn call_with(
    api: &Api,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    token: Option<&str>,
) -> (u16, HashMap<String, String>, Option<Value>) {
    let headers: Vec<(&str, &str)> = token.map(|t| vec![("X-Mieru-Token", t)]).unwrap_or_default();
    let reply = pc_common::client::request(&api.socket, method, path, &headers, body, Duration::from_secs(5)).unwrap();
    let headers = reply.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();
    (reply.status, headers, if reply.body.is_empty() { None } else { Some(reply.json().unwrap()) })
}

fn call(api: &Api, method: &str, path: &str, body: Option<Value>, token: &str) -> (u16, Option<Value>) {
    let raw = body.map(|b| b.to_string().into_bytes());
    let (status, _, body) = call_with(api, method, path, raw.as_deref(), Some(token));
    (status, body)
}

#[test]
fn manager_unix_api_is_authenticated_bounded_and_no_store() {
    let (dir, _mita, manager, revision) = service("http-api");
    let token = "x".repeat(32);
    let api = serve(manager, dir.join("manager.sock"), &token);
    assert_eq!(call(&api, "GET", "/v1/users", None, "wrong"), (401, Some(json!({"detail": "unauthorized"}))));
    let (status, headers, body) = call_with(&api, "GET", "/v1/users", None, Some(&token));
    assert_eq!((status, &body.unwrap()[0]["username"]), (200, &s("alice")));
    assert_eq!(headers["cache-control"], "no-store");
    let created = call(
        &api,
        "POST",
        "/v1/users",
        Some(json!({"username": "bob", "quotas": [], "expected_revision": revision})),
        &token,
    );
    assert_eq!(created.0, 201);
    assert!(created.1.unwrap()["share_url"].as_str().unwrap().starts_with("mierus://"));
    let (status, body) = call(&api, "POST", "/v1/lifecycle/restart", Some(json!({})), &token);
    let current = call(&api, "GET", "/v1/health", None, &token).1.unwrap()["revision"].clone();
    assert_eq!((status, body.unwrap()), (200, json!({"ready": true, "status": "running", "revision": current})));
    assert_eq!(
        call(&api, "POST", "/v1/lifecycle/restart", Some(json!({"action": "stop"})), &token),
        (422, Some(json!({"detail": "invalid request"})))
    );
    assert_eq!(
        call(&api, "POST", "/v1/lifecycle/reload", Some(json!({})), &token),
        (404, Some(json!({"detail": "not found"})))
    );
    // Over the body limit, or not an object: the same refusal.
    let big = vec![b' '; crate::server::MAX_BODY + 1];
    assert_eq!(call_with(&api, "POST", "/v1/users", Some(&big), Some(&token)).0, 422);
    assert_eq!(call_with(&api, "POST", "/v1/users", Some(b"[1]"), Some(&token)).0, 422);
    assert!(crate::server::handler(Arc::new(manager_in(&dir, &FakeMita::base())), "short".into()).is_err());
}

#[test]
fn manager_healthcheck_uses_authenticated_unix_health_endpoint() {
    let (dir, _mita, manager, _) = service("http-health");
    let token = "x".repeat(32);
    let api = serve(manager, dir.join("manager.sock"), &token);
    let token_file = dir.join("token");
    std::fs::write(&token_file, &token).unwrap();
    assert!(crate::health_probe(&api.socket, &token_file));
    std::fs::write(&token_file, "y".repeat(32)).unwrap();
    assert!(!crate::health_probe(&api.socket, &token_file));
    std::fs::write(&token_file, "short").unwrap();
    assert!(!crate::health_probe(&api.socket, &token_file));
    assert!(!crate::health_probe(&dir.join("none.sock"), &token_file));
}

#[test]
fn unix_api_lanes_routes() {
    let dir = tempdir("http-lanes");
    let (manager, _main, _slots) = lane_manager(&dir, Some(ROUTER), Some(SLOTS));
    let api = serve(manager, dir.join("manager.sock"), TOKEN);
    let (status, _, _) = call_with(&api, "GET", "/v1/lanes", None, None);
    assert_eq!(status, 401);
    let empty = json!({"lanes": [], "free_slots": 2, "service_share_template": SERVICE_TEMPLATE});
    assert_eq!(call(&api, "GET", "/v1/lanes", None, TOKEN), (200, Some(empty.clone())));
    let (status, put) = call(&api, "PUT", "/v1/lanes", Some(lanes_body(&[lane_a()])), TOKEN);
    let put = put.unwrap();
    assert!(status == 200 && put["lanes"][0]["port"] == 46101 && !put.to_string().contains(&"A".repeat(43)));
    let bad = json!({"lanes": [{"lane": "svc:mieru", "users": ["alice"], "upstream": lane_a()["upstream"]}]});
    let (status, body) = call(&api, "PUT", "/v1/lanes", Some(bad), TOKEN);
    assert_eq!((status, &body.unwrap()["code"]), (409, &s("lanes_invalid")));
    assert_eq!(call(&api, "GET", "/v1/users", None, TOKEN).1.unwrap()[0]["lane"], "grant:7f3a");
    assert_eq!(call(&api, "PUT", "/v1/lanes", Some(lanes_body(&[])), TOKEN), (200, Some(empty)));
}

#[test]
fn http_error_bodies_and_routes_follow_the_python_server() {
    let (dir, mita, manager, revision) = service("http-errors");
    let api = serve(manager, dir.join("manager.sock"), TOKEN);
    // A stale revision: 409 with the code the panel maps.
    let stale = call(
        &api,
        "POST",
        "/v1/users",
        Some(json!({"username": "bob", "quotas": [], "expected_revision": "x"})),
        TOKEN,
    );
    assert_eq!(stale, (409, Some(json!({"detail": "configuration conflict", "code": "egress_conflict"}))));
    // A conflict without an actionable reason carries `code: null`.
    let missing = call(&api, "POST", "/v1/users/nobody/disable", Some(json!({"expected_revision": revision})), TOKEN);
    assert_eq!(missing, (409, Some(json!({"detail": "configuration conflict", "code": null}))));
    // An unknown operation still needs exactly the revision field, then 404.
    assert_eq!(call(&api, "POST", "/v1/users/alice/explode", Some(json!({})), TOKEN).0, 422);
    assert_eq!(
        call(&api, "POST", "/v1/users/alice/explode", Some(json!({"expected_revision": revision})), TOKEN).0,
        404
    );
    // Percent-encoded names reach the manager decoded, as `unquote` did.
    let disabled = call(&api, "POST", "/v1/users/%61lice/disable", Some(json!({"expected_revision": revision})), TOKEN);
    assert_eq!((disabled.0, &disabled.1.unwrap()["username"]), (200, &s("alice")));
    // A failed transaction: 503, the recovery case flagged.
    let current = call(&api, "GET", "/v1/health", None, TOKEN).1.unwrap()["revision"].clone();
    mita.get().fail_probe = true;
    let failed = call(
        &api,
        "POST",
        "/v1/users",
        Some(json!({"username": "carol", "quotas": [], "expected_revision": current})),
        TOKEN,
    );
    assert_eq!(failed, (503, Some(json!({"detail": "manager operation failed"}))));
    mita.get().interrupted = true;
    let stuck = call(
        &api,
        "POST",
        "/v1/users",
        Some(json!({"username": "dave", "quotas": [], "expected_revision": current})),
        TOKEN,
    );
    assert_eq!(
        stuck,
        (503, Some(json!({"detail": "manager operation failed", "code": "manual_intervention_required"})))
    );
    // Egress refusals carry their own detail and code.
    let invalid = call(
        &api,
        "POST",
        "/v1/egress/plan",
        Some(json!({"expected_revision": current, "document": {"schema": 2}})),
        TOKEN,
    );
    assert_eq!(invalid, (422, Some(json!({"detail": "unsupported egress document schema", "code": "egress_invalid"}))));
    assert_eq!(call(&api, "POST", "/v1/egress/rollback", Some(json!({})), TOKEN).0, 422);
    assert_eq!(call(&api, "GET", "/v1/metrics", None, TOKEN).1.unwrap()["reason"], "typed_histories_unavailable");
    let reset = call(&api, "POST", "/v1/users/alice/reset-metrics", Some(json!({})), TOKEN);
    assert_eq!(reset, (409, Some(json!({"detail": "configuration conflict", "code": null}))));
}

// ---------------------------------------------------------------- Python compatibility

fn vectors() -> Value {
    // Produced by the Python manager on python:3.13.5-slim before it was removed.
    serde_json::from_str(include_str!("python_vectors.json")).unwrap()
}

#[test]
fn state_written_by_the_python_manager_is_read() {
    let vectors = vectors();
    let python = &vectors["state"];
    let dir = tempdir("python-state");
    let root = dir.join("state");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&root.join("state.json"), python["state_r2"].as_str().unwrap().as_bytes());
    write_private(&root.join("journal.key"), &[7u8; 32]);
    let mita = FakeMita::new(python["config_r2"].clone());
    let manager = manager_in(&dir, &mita);
    assert_eq!(manager.bootstrap().unwrap()["revision"], python["r2"]);
    // The same transactions reach the same revisions and write the same bytes.
    let r3 = manager.set_quotas("alice", &json!([{"days": 7, "megabytes": 100}]), &python["r2"]).unwrap();
    assert_eq!(r3["revision"], python["r3"]);
    assert_eq!(std::fs::read_to_string(root.join("state.json")).unwrap(), python["state_r3"].as_str().unwrap());
    assert_eq!(mita.config(), python["config_r3"]);
    let r4 = manager.enable_user("jürgen", &python["r3"]).unwrap();
    assert_eq!(r4["revision"], python["r4"]);
    assert_eq!(std::fs::read_to_string(root.join("state.json")).unwrap(), python["state_r4"].as_str().unwrap());
    assert_eq!(mita.config(), python["config_r4"]);
    assert_eq!(manager.list_users().unwrap(), python["users_r4"]);
    // A write that changes nothing writes the Python bytes back unchanged.
    manager.set_lanes(&lanes_body(&[])).unwrap();
    assert_eq!(std::fs::read_to_string(root.join("state.json")).unwrap(), python["state_r4"].as_str().unwrap());
}

#[test]
fn json_dumps_matches_python() {
    let vectors = vectors();
    for case in vectors["canonical"].as_array().unwrap() {
        assert_eq!(pyjson::canonical(&case[0]), case[1].as_str().unwrap());
    }
    for case in vectors["indent1"].as_array().unwrap() {
        assert_eq!(pyjson::dumps(&case[0], true, Some(1)), case[1].as_str().unwrap());
    }
}

#[test]
fn addresses_networks_and_domains_match_python() {
    let vectors = vectors();
    for case in vectors["ip_network"].as_array().unwrap() {
        assert_eq!(
            crate::pyip::network_str(case[0].as_str().unwrap()).map(Value::String).unwrap_or(Value::Null),
            case[1],
            "{}",
            case[0]
        );
    }
    for case in vectors["ip_address"].as_array().unwrap() {
        assert_eq!(json!(crate::pyip::is_address(&case[0])), case[1], "{}", case[0]);
    }
    for case in vectors["domains"].as_array().unwrap() {
        let got =
            egress::validate_document(&json!({"schema": 1, "rules": [{"domains": [case[0]], "action": "REJECT"}]}))
                .ok()
                .map(|doc| doc["rules"][0]["domains"][0].clone())
                .unwrap_or(Value::Null);
        assert_eq!(got, case[1], "{}", case[0]);
    }
}

#[test]
fn durations_quoting_and_diffs_match_python() {
    let vectors = vectors();
    for case in vectors["durations"].as_array().unwrap() {
        let got = crate::validate::go_duration_ns(&case[0]).ok().map(|n| json!(n)).unwrap_or(Value::Null);
        assert_eq!(got, case[1], "{}", case[0]);
    }
    for case in vectors["quote"].as_array().unwrap() {
        assert_eq!(crate::pyurl::quote(case[0].as_str().unwrap()), case[1].as_str().unwrap());
    }
    for case in vectors["urlencode"].as_array().unwrap() {
        let pairs = [("profile", case[0].as_str().unwrap().to_string()), ("port", "8443".to_string())];
        assert_eq!(crate::pyurl::urlencode(&pairs), case[1].as_str().unwrap());
    }
    for case in vectors["diff"].as_array().unwrap() {
        let lines = |value: &Value| -> Vec<String> {
            pyjson::dumps(value, true, Some(1)).split('\n').map(str::to_string).collect()
        };
        let got: Vec<String> = crate::difflib::changed_lines(&lines(&case[0]), &lines(&case[1]))
            .into_iter()
            .filter(|line| !(line.starts_with("---") || line.starts_with("+++") || line.starts_with("@@")))
            .collect();
        assert_eq!(json!(got), case[2]);
    }
}
