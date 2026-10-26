//! Test helpers for the engine and the adapter packages: a temporary root, plans built like
//! `tests/test_installer_transaction.py` builds them, and the recording adapter of that file.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use crate::adapter::Adapter;
use crate::engine::TransactionEngine;
use crate::error::Error;
use crate::journal::{CheckpointData, Phase, RollbackTarget};
use crate::model::InstallerConfig;
use crate::planner::{Action, AuditFacts, Evidence, InstallPlan, ReleaseIdentity, PLAN_SCHEMA};
use crate::store::TransactionStore;

/// A directory removed on drop (`tmp_path`).
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> TempDir {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "installer-{label}-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
            pc_host::fs::token_hex::<4>()
        ));
        fs::create_dir_all(&path).expect("temporary directory");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `action_for(name)`.
pub fn action_for(name: &str) -> Action {
    Action {
        id: format!("{name}.install"),
        adapter: name.into(),
        owner: format!("proxy-control:{name}"),
        mutations: vec![format!("write /{name}.owned")],
        preconditions: vec![format!("/{name}.owned is absent")],
        verification: vec![format!("/{name}.owned has the approved content")],
        inverse: vec![format!("remove /{name}.owned")],
        credentials_required: false,
    }
}

/// A plan over the given actions (`plan_for` with explicit actions).
pub fn plan_with(actions: Vec<Action>, platform: Map<String, Value>) -> InstallPlan {
    let mut order: Vec<String> = Vec::new();
    for action in &actions {
        if !order.contains(&action.adapter) {
            order.push(action.adapter.clone());
        }
    }
    InstallPlan::new(
        json!({"profile": "test"}),
        AuditFacts { platform, ..AuditFacts::default() },
        release(),
        order.clone(),
        order.iter().map(|name| (name.clone(), Vec::new())).collect(),
        actions,
        PLAN_SCHEMA,
    )
    .expect("valid test plan")
}

/// The release identity of the test plans (`v1.2.3`, commit `a…`, manifest `b…`).
pub fn release() -> ReleaseIdentity {
    ReleaseIdentity::new("v1.2.3", &"a".repeat(40), &"b".repeat(64), BTreeMap::new(), BTreeMap::new())
        .expect("valid test release")
}

/// `plan_for(*names)`: one `<name>.install` action per name, platform `{"os": "test"}`.
pub fn plan_for(names: &[&str]) -> InstallPlan {
    let mut platform = Map::new();
    platform.insert("os".into(), json!("test"));
    let actions: Vec<Action> = names.iter().map(|name| action_for(name)).collect();
    let mut plan = plan_with(actions, platform);
    // Python kept duplicates in `adapter_order` (`tuple(names)`).
    plan.adapter_order = names.iter().map(|name| name.to_string()).collect();
    plan
}

/// `engine_for(root, *adapters)`.
pub fn engine_for(root: &Path, adapters: Vec<Arc<dyn Adapter>>) -> TransactionEngine {
    let mut engine = TransactionEngine::new(TransactionStore::new(root).expect("store"));
    for adapter in adapters {
        engine.register(adapter);
    }
    engine
}

/// What an injected failure raises: Python's `InjectedCrash(BaseException)` or `RuntimeError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Crash,
    Runtime,
}

impl Failure {
    pub fn error(self, message: &str) -> Error {
        match self {
            Failure::Crash => Error::fatal("InjectedCrash", message),
            Failure::Runtime => Error::other("RuntimeError", message),
        }
    }
}

/// The `RecordingAdapter` of `tests/test_installer_transaction.py`: owns `/<name>.owned` (and
/// `/<name>.data` when `preserve_data`) under the root, counts its mutations and can crash or
/// fail at chosen points.
pub struct RecordingAdapter {
    pub name: String,
    pub root: PathBuf,
    pub crash_after: Mutex<Option<Phase>>,
    pub fail_apply: bool,
    pub crash_during_apply: Mutex<Option<Failure>>,
    pub crash_during_rollback: Mutex<Option<Failure>>,
    pub crash_before_rollback: AtomicBool,
    pub preserve_data: bool,
    pub mutable_data: bool,
    pub log: Option<Arc<Mutex<Vec<String>>>>,
}

impl RecordingAdapter {
    pub fn new(name: &str, root: &Path) -> RecordingAdapter {
        RecordingAdapter {
            name: name.into(),
            root: root.to_path_buf(),
            crash_after: Mutex::new(None),
            fail_apply: false,
            crash_during_apply: Mutex::new(None),
            crash_during_rollback: Mutex::new(None),
            crash_before_rollback: AtomicBool::new(false),
            preserve_data: false,
            mutable_data: false,
            log: None,
        }
    }

    pub fn target(&self) -> PathBuf {
        self.root.join(format!("{}.owned", self.name))
    }

    pub fn data_path(&self) -> PathBuf {
        self.root.join(format!("{}.data", self.name))
    }

    pub fn counter(&self) -> PathBuf {
        self.root.join(format!("{}.mutations", self.name))
    }

    fn record(&self, entry: String) {
        if let Some(log) = &self.log {
            log.lock().unwrap().push(entry);
        }
    }

    fn expected(action: &Action) -> Vec<u8> {
        format!("owned by {}\n", action.owner).into_bytes()
    }
}

fn evidence(action: &Action, success: bool, observation: &str) -> Result<Evidence, Error> {
    Ok(Evidence::with_details(&action.id, success, vec![observation.into()], Map::new())?)
}

impl Adapter for RecordingAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn plan(&self, _config: &InstallerConfig, _facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        Ok(vec![action_for(&self.name)])
    }

    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        let mut ownership = Map::new();
        ownership.insert(format!("/{}.owned", self.name), json!({"preserve": false}));
        if self.preserve_data {
            ownership.insert(format!("/{}.data", self.name), json!({"preserve": true, "mutable": self.mutable_data}));
        }
        let mut data = Map::new();
        data.insert("ownership".into(), Value::Object(ownership));
        data.insert("owner".into(), Value::String(action.owner.clone()));
        Ok(data)
    }

    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.record(format!("apply:{}", self.name));
        if self.fail_apply {
            return Err(Error::other("RuntimeError", format!("{} failed", self.name)));
        }
        let count: u64 = fs::read_to_string(self.counter()).ok().and_then(|text| text.parse().ok()).unwrap_or(0);
        fs::write(self.counter(), (count + 1).to_string())?;
        fs::write(self.target(), Self::expected(action))?;
        if self.preserve_data {
            fs::write(self.data_path(), b"persistent data\n")?;
        }
        if let Some(failure) = self.crash_during_apply.lock().unwrap().take() {
            return Err(failure.error("apply mutation committed"));
        }
        Ok(checkpoint)
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        if self.target().exists() {
            return Ok(checkpoint);
        }
        self.apply(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let mut valid = fs::read(self.target())? == Self::expected(action);
        if self.preserve_data && !self.mutable_data {
            valid = valid && fs::read(self.data_path())? == b"persistent data\n";
        }
        evidence(action, valid, "owned file verified")
    }

    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let expected = Self::expected(action);
        if self.target().exists() && fs::read(self.target())? != expected {
            return Err(crate::error::ownership("owned file drifted").into());
        }
        if !self.target().exists() {
            fs::write(self.target(), &expected)?;
        }
        if self.preserve_data {
            if !self.mutable_data && self.data_path().exists() && fs::read(self.data_path())? != b"persistent data\n" {
                return Err(crate::error::ownership("owned data drifted").into());
            }
            if !self.data_path().exists() {
                fs::write(self.data_path(), b"persistent data\n")?;
            }
        }
        Ok(checkpoint)
    }

    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        _target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        assert!(checkpoint["ownership"].as_object().unwrap().contains_key(&format!("/{}.owned", self.name)));
        if self.crash_before_rollback.swap(false, Ordering::SeqCst) {
            return Err(Error::fatal("InjectedCrash", "before rollback deletion"));
        }
        self.record(format!("rollback:{}", self.name));
        let _ = fs::remove_file(self.target());
        if purge_data {
            let _ = fs::remove_file(self.data_path());
        }
        if let Some(failure) = self.crash_during_rollback.lock().unwrap().take() {
            return Err(failure.error("rollback mutation committed"));
        }
        evidence(action, true, "owned file removed")
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        if self.target().exists() || (purge_data && self.data_path().exists()) {
            return self.rollback(action, checkpoint, purge_data, target);
        }
        evidence(action, true, "rollback already committed")
    }

    fn checkpoint_committed(&self, phase: Phase, _action: &Action) -> Result<(), Error> {
        let mut crash_after = self.crash_after.lock().unwrap();
        if *crash_after == Some(phase) {
            *crash_after = None;
            return Err(Error::fatal("InjectedCrash", phase.as_str()));
        }
        Ok(())
    }
}
