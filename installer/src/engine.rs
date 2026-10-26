//! The checkpointed adapter executor with fail-closed ownership recovery (`TransactionEngine`,
//! `installer/transaction.py:870-1410`, host inventory B.2.6).
//!
//! Every step is persisted before the next one runs: `state.json` first (authoritative), then
//! the derived `ownership.json` and `report.json`. An ordinary error during apply rolls back
//! everything applied so far (in reverse order, purging data) and is returned; a fatal one
//! ([`Error::is_fatal`], Python's `BaseException`) leaves the journal as it is for `resume`.
//! Nothing owned is ever touched before the engine proved its bytes are the ones it recorded.
//!
//! The runtime-v2 adapter (legacy `scripts/proxyctl.py` installations) is not ported (owner
//! decision 10): a journal with `origin: runtime-v2` fails with `adapter is unavailable:
//! runtime-v2` on resume, repair and uninstall.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use pc_host::fs::{owned_path, path_identity, uuid4_hex};
use pc_host::TxError;
use serde_json::Value;

use crate::adapter::Adapter;
use crate::error::Error;
use crate::journal::{
    Checkpoint, CheckpointData, Ownership, OwnershipEntry, Phase, RollbackTarget, Status, TransactionState,
};
use crate::planner::{Action, Evidence, InstallPlan};
use crate::store::TransactionStore;

/// Files the version-agent legitimately rewrites after the installer recorded them
/// (`installer/runtime_state.py:48`): ownership still requires them to exist with the same kind,
/// but their digest is not compared.
pub const AGENT_MANAGED_PATHS: &[&str] = &[
    "/etc/proxy-control/caddy-naive.pin",
    "/usr/local/bin/caddy",
    "/usr/bin/mita",
    "/opt/mtproxy-shared443/.env.mieru",
    "/opt/mtproxy-shared443/.env.xray-router",
    "/usr/local/lib/proxy-control/xray-router/xray",
    "/usr/local/lib/proxy-control/xray-router/geoip.dat",
    "/usr/local/lib/proxy-control/xray-router/geosite.dat",
];

fn drifted(host_path: &str) -> TxError {
    crate::error::ownership(format!("owned file drifted: {host_path}"))
}

fn exists_or_symlink(path: &Path) -> bool {
    path.exists() || fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// `_assert_owned`: every entry still exists with its kind and (unless mutable or agent-managed)
/// its digest; otherwise `owned file drifted: <path>`.
pub(crate) fn assert_owned(
    root: &Path,
    ownership: &Ownership,
    agent_managed: &BTreeSet<String>,
) -> Result<(), TxError> {
    for (host_path, expected) in ownership {
        let (_, path) = owned_path(root, host_path)?;
        let actual = match path_identity(&path) {
            Ok(actual) => actual,
            Err(TxError::Ownership(_)) => return Err(drifted(host_path)),
            Err(err) => return Err(err),
        };
        if actual.kind.as_str() != expected.kind
            || (!expected.is_mutable() && !agent_managed.contains(host_path) && actual.sha256 != expected.sha256)
        {
            return Err(drifted(host_path));
        }
    }
    Ok(())
}

/// `_read_matching_plan`: `plan.json` must re-render to the digest the state recorded.
pub(crate) fn read_matching_plan(store: &TransactionStore, state: &TransactionState) -> Result<InstallPlan, TxError> {
    let plan = store.read_plan()?;
    if plan.digest() != state.plan_digest || state.accepted_digest != state.plan_digest {
        return Err(crate::error::transaction("persisted plan digest does not match transaction state"));
    }
    Ok(plan)
}

/// `_persist`: `state.json`, then the derived `ownership.json` and `report.json`.
pub(crate) fn persist(store: &TransactionStore, state: &TransactionState) -> Result<(), Error> {
    store.write_state(state)?;
    store.write_ownership(&state.ownership(true)?)?;
    store.write_report(&state.report_value())
}

/// The default agent-managed set.
pub fn agent_managed_paths() -> BTreeSet<String> {
    AGENT_MANAGED_PATHS.iter().map(|path| path.to_string()).collect()
}

/// Executes an approved plan through its adapters, durably and recoverably.
pub struct TransactionEngine {
    store: TransactionStore,
    adapters: BTreeMap<String, Arc<dyn Adapter>>,
    agent_managed: BTreeSet<String>,
}

impl TransactionEngine {
    /// An engine without adapters.
    pub fn new(store: TransactionStore) -> TransactionEngine {
        TransactionEngine { store, adapters: BTreeMap::new(), agent_managed: agent_managed_paths() }
    }

    /// Registers (or replaces) the adapter for its name.
    pub fn register(&mut self, adapter: Arc<dyn Adapter>) {
        self.adapters.insert(adapter.name().to_string(), adapter);
    }

    /// Builder form of [`register`](Self::register).
    pub fn with_adapter(mut self, adapter: Arc<dyn Adapter>) -> TransactionEngine {
        self.register(adapter);
        self
    }

    /// Replaces the agent-managed path set (tests).
    pub fn with_agent_managed(mut self, paths: BTreeSet<String>) -> TransactionEngine {
        self.agent_managed = paths;
        self
    }

    pub fn store(&self) -> &TransactionStore {
        &self.store
    }

    /// The registered adapter called `name` (the planner composes a plan from these).
    pub fn adapter_named(&self, name: &str) -> Option<Arc<dyn Adapter>> {
        self.adapters.get(name).cloned()
    }

    /// The names of the registered adapters, sorted.
    pub fn adapter_names(&self) -> Vec<String> {
        self.adapters.keys().cloned().collect()
    }

    /// Install an approved plan. The accepted digest must be the plan's; re-applying the same
    /// intent to an active installation only proves ownership and returns it; a finished
    /// rollback or uninstall is cleared; any other journal refuses.
    pub fn apply(&self, plan: &InstallPlan, accepted_digest: &str) -> Result<TransactionState, Error> {
        if accepted_digest != plan.digest() {
            return Err(TxError::AcceptedDigest("accepted plan digest does not match".into()).into());
        }
        let _lock = self.store.locked()?;
        if self.store.state_exists() {
            let existing = self.store.read_state()?;
            if existing.status == Status::Active
                && read_matching_plan(&self.store, &existing)?.intent_digest() == plan.intent_digest()
            {
                self.validate_adapters(plan)?;
                self.assert_all_owned(&existing)?;
                return Ok(existing);
            }
            if !matches!(existing.status, Status::RolledBack | Status::Uninstalled) {
                return Err(crate::error::transaction("an installer transaction already exists").into());
            }
            self.store.remove_state()?;
        }
        self.validate_adapters(plan)?;
        self.store.write_plan(plan)?;
        let state = TransactionState::new(&uuid4_hex(), Status::Applying, &plan.digest());
        self.persist(&state)?;
        self.apply_or_roll_back(plan, state)
    }

    /// Finish what a crash interrupted: continue an apply, finish a rollback or uninstall, or
    /// (for a settled journal) prove ownership and rebuild the derived files.
    pub fn resume(&self) -> Result<TransactionState, Error> {
        let _lock = self.store.locked()?;
        let state = self.store.read_state()?;
        let plan = read_matching_plan(&self.store, &state)?;
        match state.status {
            Status::Applying => {
                self.validate_adapters(&plan)?;
                return self.apply_or_roll_back(&plan, state);
            }
            Status::RollingBack | Status::RollbackFailed | Status::Uninstalling => {
                self.validate_adapters(&plan)?;
                let target = state.rollback_target.unwrap_or(if state.status == Status::Uninstalling {
                    RollbackTarget::Uninstalled
                } else {
                    RollbackTarget::RolledBack
                });
                return self.rollback(&plan, state, target, None);
            }
            Status::Active => {
                self.validate_adapters(&plan)?;
                self.assert_all_owned(&state)?;
            }
            Status::RolledBack | Status::Uninstalled => {}
        }
        self.persist(&state)?;
        Ok(state)
    }

    /// Restore an active installation: each adapter repairs its action, ownership is
    /// re-captured and verified.
    pub fn repair(&self) -> Result<TransactionState, Error> {
        let _lock = self.store.locked()?;
        let mut state = self.store.read_state()?;
        let plan = read_matching_plan(&self.store, &state)?;
        self.validate_adapters(&plan)?;
        if state.status != Status::Active {
            if state.status.is_interrupted() {
                return Err(crate::error::transaction("resume the interrupted transaction before repair").into());
            }
            return Ok(state);
        }
        let mut by_id: BTreeMap<String, Checkpoint> =
            state.checkpoints.iter().map(|item| (item.action_id.clone(), item.clone())).collect();
        for action in &plan.actions {
            let checkpoint = match by_id.get(&action.id) {
                Some(checkpoint) if checkpoint.phase == Phase::Verified => checkpoint.clone(),
                _ => return Err(crate::error::transaction("active transaction has incomplete checkpoints").into()),
            };
            let adapter = self.adapter(action)?;
            let data = adapter.repair(action, checkpoint.data.clone())?;
            let ownership = self.capture_ownership(action, &data)?;
            let evidence = self.verify(action)?;
            let checkpoint = Checkpoint { data, ownership, evidence: Some(evidence.to_map()), ..checkpoint };
            state.with_checkpoint(checkpoint.clone());
            self.persist_checkpoint(&state, &checkpoint, action)?;
            by_id.insert(action.id.clone(), checkpoint);
        }
        state.error = None;
        self.persist(&state)?;
        Ok(state)
    }

    /// Remove the installation (keeping preserved data unless `purge_data`).
    pub fn uninstall(&self, purge_data: bool) -> Result<TransactionState, Error> {
        let _lock = self.store.locked()?;
        let mut state = self.store.read_state()?;
        let plan = read_matching_plan(&self.store, &state)?;
        self.validate_adapters(&plan)?;
        if matches!(state.status, Status::Uninstalled | Status::RolledBack) {
            self.persist(&state)?;
            return Ok(state);
        }
        if !matches!(state.status, Status::Active | Status::Uninstalling) {
            return Err(crate::error::transaction("resume the interrupted transaction before uninstall").into());
        }
        if state.status == Status::Uninstalling && state.purge_data != Some(purge_data) {
            let required = if state.purge_data == Some(true) { "with --purge-data" } else { "without --purge-data" };
            return Err(crate::error::transaction(format!("retry the interrupted uninstall {required}")).into());
        }
        self.assert_all_owned(&state)?;
        state.status = Status::Uninstalling;
        state.purge_data = Some(purge_data);
        state.rollback_target = Some(RollbackTarget::Uninstalled);
        state.error = None;
        self.persist(&state)?;
        self.rollback(&plan, state, RollbackTarget::Uninstalled, None)
    }

    /// `_persist` (public for tests and recovery tools).
    pub fn persist(&self, state: &TransactionState) -> Result<(), Error> {
        persist(&self.store, state)
    }

    /// `_ownership_for(state)` including `rollback_in_progress`.
    pub fn ownership_for(&self, state: &TransactionState) -> Result<Ownership, TxError> {
        state.ownership(true)
    }

    /// `_assert_all_owned`: every path of every applied or verified checkpoint is intact.
    pub fn assert_all_owned(&self, state: &TransactionState) -> Result<(), TxError> {
        assert_owned(self.store.root(), &state.ownership(false)?, &self.agent_managed)
    }

    fn apply_or_roll_back(&self, plan: &InstallPlan, state: TransactionState) -> Result<TransactionState, Error> {
        match self.continue_apply(plan, state) {
            Ok(state) => Ok(state),
            Err(err) if err.is_fatal() => Err(err),
            Err(err) => {
                let state = self.store.read_state()?;
                self.rollback(plan, state, RollbackTarget::RolledBack, Some(&err))?;
                Err(err)
            }
        }
    }

    fn continue_apply(&self, plan: &InstallPlan, mut state: TransactionState) -> Result<TransactionState, Error> {
        let mut checkpoints: BTreeMap<String, Checkpoint> =
            state.checkpoints.iter().map(|item| (item.action_id.clone(), item.clone())).collect();
        for action in &plan.actions {
            let adapter = self.adapter(action)?;
            let mut checkpoint = match checkpoints.get(&action.id) {
                Some(checkpoint) => checkpoint.clone(),
                None => {
                    let data = adapter.prepare(action)?;
                    let checkpoint = Checkpoint::new(&action.id, &action.adapter, Phase::Prepared, data);
                    self.record(&mut state, &checkpoint, action)?;
                    checkpoints.insert(action.id.clone(), checkpoint.clone());
                    checkpoint
                }
            };
            if checkpoint.phase == Phase::Prepared {
                checkpoint.phase = Phase::Applying;
                self.record(&mut state, &checkpoint, action)?;
                checkpoints.insert(action.id.clone(), checkpoint.clone());
                let data = adapter.apply(action, checkpoint.data.clone())?;
                checkpoint = self.finish_apply(action, checkpoint, data)?;
                self.record(&mut state, &checkpoint, action)?;
                checkpoints.insert(action.id.clone(), checkpoint.clone());
            } else if checkpoint.phase == Phase::Applying {
                let data = adapter.reconcile_apply(action, checkpoint.data.clone())?;
                checkpoint = self.finish_apply(action, checkpoint, data)?;
                self.record(&mut state, &checkpoint, action)?;
                checkpoints.insert(action.id.clone(), checkpoint.clone());
            }
            if checkpoint.phase == Phase::Applied {
                let evidence = self.verify(action)?;
                checkpoint.phase = Phase::Verified;
                checkpoint.evidence = Some(evidence.to_map());
                self.record(&mut state, &checkpoint, action)?;
                checkpoints.insert(action.id.clone(), checkpoint.clone());
            }
            if matches!(checkpoint.phase, Phase::RollbackInProgress | Phase::RolledBack) {
                return Err(crate::error::transaction("cannot apply a rolled-back checkpoint").into());
            }
        }
        state.status = Status::Active;
        state.error = None;
        self.persist(&state)?;
        Ok(state)
    }

    /// Puts `checkpoint` into `state` and persists it with the adapter's hook.
    fn record(&self, state: &mut TransactionState, checkpoint: &Checkpoint, action: &Action) -> Result<(), Error> {
        state.with_checkpoint(checkpoint.clone());
        self.persist_checkpoint(state, checkpoint, action)
    }

    fn finish_apply(&self, action: &Action, checkpoint: Checkpoint, data: CheckpointData) -> Result<Checkpoint, Error> {
        let ownership = self.capture_ownership(action, &data)?;
        Ok(Checkpoint { phase: Phase::Applied, data, ownership, ..checkpoint })
    }

    fn rollback(
        &self,
        plan: &InstallPlan,
        mut state: TransactionState,
        target: RollbackTarget,
        error: Option<&Error>,
    ) -> Result<TransactionState, Error> {
        match self.rollback_steps(plan, &mut state, target, error) {
            Ok(()) => Ok(state),
            Err(err) if err.is_fatal() => Err(err),
            Err(err) => {
                state.status = Status::RollbackFailed;
                state.rollback_target = Some(target);
                state.error = Some(err.python_class_name().to_string());
                self.persist(&state)?;
                Err(err)
            }
        }
    }

    fn rollback_steps(
        &self,
        plan: &InstallPlan,
        state: &mut TransactionState,
        target: RollbackTarget,
        error: Option<&Error>,
    ) -> Result<(), Error> {
        self.assert_all_owned(state)?;
        state.status = if target == RollbackTarget::Uninstalled { Status::Uninstalling } else { Status::RollingBack };
        state.rollback_target = Some(target);
        if let Some(error) = error {
            state.error = Some(error.python_class_name().to_string());
        }
        self.persist(state)?;
        let by_action: BTreeMap<&str, &Action> =
            plan.actions.iter().map(|action| (action.id.as_str(), action)).collect();
        let purge_data = target == RollbackTarget::RolledBack || state.purge_data == Some(true);
        let snapshot = state.checkpoints.clone();
        for mut checkpoint in snapshot.into_iter().rev() {
            if checkpoint.phase == Phase::RolledBack {
                continue;
            }
            let action = match by_action.get(checkpoint.action_id.as_str()) {
                Some(action) if action.adapter == checkpoint.adapter => *action,
                _ => return Err(crate::error::transaction("checkpoint does not belong to the persisted plan").into()),
            };
            if checkpoint.phase == Phase::Prepared {
                checkpoint.phase = Phase::RolledBack;
                state.with_checkpoint(checkpoint);
                self.persist(state)?;
                continue;
            }
            let adapter = self.adapter(action)?;
            let preserve: Ownership = checkpoint
                .ownership
                .iter()
                .filter(|(_, entry)| entry.preserve)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let evidence = match checkpoint.phase {
                Phase::Applied | Phase::Verified => {
                    assert_owned(self.store.root(), &checkpoint.ownership, &self.agent_managed)?;
                    checkpoint.phase = Phase::RollbackInProgress;
                    self.record(state, &checkpoint, action)?;
                    adapter.rollback(action, checkpoint.data.clone(), purge_data, target)?
                }
                Phase::Applying | Phase::RollbackInProgress => {
                    if checkpoint.phase == Phase::Applying {
                        checkpoint.phase = Phase::RollbackInProgress;
                        self.record(state, &checkpoint, action)?;
                    }
                    self.assert_reconcile_safe(&checkpoint.ownership, purge_data)?;
                    adapter.reconcile_rollback(action, checkpoint.data.clone(), purge_data, target)?
                }
                Phase::Prepared | Phase::RolledBack => continue,
            };
            if !evidence.success {
                return Err(crate::error::transaction(format!("adapter rollback failed: {}", action.adapter)).into());
            }
            if !purge_data {
                assert_owned(self.store.root(), &preserve, &self.agent_managed)?;
            }
            checkpoint.phase = Phase::RolledBack;
            checkpoint.rollback_evidence = Some(evidence.to_map());
            state.with_checkpoint(checkpoint);
            self.persist(state)?;
        }
        state.status = target.status();
        self.persist(state)
    }

    /// `_assert_reconcile_safe`: a path may already be gone (unless it is preserved data and
    /// nothing is purged); one that exists must still be what the journal recorded.
    fn assert_reconcile_safe(&self, ownership: &Ownership, purge_data: bool) -> Result<(), TxError> {
        for (host_path, expected) in ownership {
            let (_, path) = owned_path(self.store.root(), host_path)?;
            if !exists_or_symlink(&path) {
                if expected.preserve && !purge_data {
                    return Err(drifted(host_path));
                }
                continue;
            }
            let actual = path_identity(&path)?;
            if actual.kind.as_str() != expected.kind
                || (!expected.is_mutable()
                    && !self.agent_managed.contains(host_path)
                    && actual.sha256 != expected.sha256)
            {
                return Err(drifted(host_path));
            }
        }
        Ok(())
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let evidence = self.adapter(action)?.verify(action)?;
        if evidence.action_id != action.id {
            return Err(
                crate::error::transaction(format!("adapter returned invalid evidence: {}", action.adapter)).into()
            );
        }
        if !evidence.success {
            return Err(crate::error::transaction(format!("adapter verification failed: {}", action.adapter)).into());
        }
        Ok(evidence)
    }

    /// `_capture_ownership`: hash every path the checkpoint data declares and check it against
    /// the declaration.
    fn capture_ownership(&self, action: &Action, data: &CheckpointData) -> Result<Ownership, Error> {
        let invalid = || crate::error::transaction(format!("adapter ownership is invalid: {}", action.adapter));
        let present = |key: &str| data.get(key).filter(|value| !value.is_null());
        let declaration = match present("ownership").or_else(|| present("owned_files")) {
            Some(value) => value.clone(),
            None => match data.get("owned_paths") {
                None => Value::Array(Vec::new()),
                Some(value) => value.clone(),
            },
        };
        let declared: Vec<(Value, Value)> = match declaration {
            Value::Object(map) => map.into_iter().map(|(path, expected)| (Value::String(path), expected)).collect(),
            Value::Array(items) => items.into_iter().map(|path| (path, Value::Null)).collect(),
            _ => return Err(invalid().into()),
        };
        let mut ownership = Ownership::new();
        for (raw_path, expected) in declared {
            let raw_path = raw_path.as_str().ok_or_else(|| crate::error::ownership("owned path is unsafe"))?;
            let (host_path, path) = owned_path(self.store.root(), raw_path)?;
            let actual = path_identity(&path)?;
            let mut preserve = false;
            let mut mutable = false;
            match &expected {
                Value::String(digest) => {
                    if *digest != actual.sha256 {
                        return Err(drifted(&host_path).into());
                    }
                }
                Value::Object(flags) => {
                    if let Some(value) = flags.get("mutable") {
                        mutable = value
                            .as_bool()
                            .ok_or_else(|| crate::error::transaction("adapter ownership mutability flag is invalid"))?;
                    }
                    let expected_hash = flags.get("sha256").filter(|value| !value.is_null());
                    if !mutable && expected_hash.is_some_and(|hash| hash.as_str() != Some(actual.sha256.as_str())) {
                        return Err(drifted(&host_path).into());
                    }
                    if let Some(value) = flags.get("preserve") {
                        preserve = value.as_bool().ok_or_else(|| {
                            crate::error::transaction("adapter ownership preservation flag is invalid")
                        })?;
                    }
                }
                Value::Null => {}
                _ => return Err(invalid().into()),
            }
            ownership.insert(
                host_path,
                OwnershipEntry {
                    action_id: action.id.clone(),
                    adapter: action.adapter.clone(),
                    kind: actual.kind.as_str().into(),
                    mutable: Some(mutable),
                    preserve,
                    sha256: actual.sha256,
                },
            );
        }
        Ok(ownership)
    }

    fn persist_checkpoint(
        &self,
        state: &TransactionState,
        checkpoint: &Checkpoint,
        action: &Action,
    ) -> Result<(), Error> {
        self.persist(state)?;
        self.adapter(action)?.checkpoint_committed(checkpoint.phase, action)
    }

    fn validate_adapters(&self, plan: &InstallPlan) -> Result<(), TxError> {
        for action in &plan.actions {
            self.adapter(action)?;
        }
        Ok(())
    }

    fn adapter(&self, action: &Action) -> Result<&Arc<dyn Adapter>, TxError> {
        match self.adapters.get(&action.adapter) {
            Some(adapter) if adapter.name() == action.adapter => Ok(adapter),
            _ => Err(crate::error::transaction(format!("adapter is unavailable: {}", action.adapter))),
        }
    }
}
