//! `tests/test_installer_transaction.py`, minus the runtime-v2 cases (owner decision 10).

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use pc_host::runner::RunError;
use serde_json::{json, Map};

use crate::adapter::Adapter;
use crate::engine::TransactionEngine;
use crate::error::Error;
use crate::journal::{Phase, Status, TransactionState};
use crate::store::{JournalFile, TransactionStore};
use crate::testkit::{engine_for, plan_for, plan_with, Failure, RecordingAdapter, TempDir};

fn shared(adapter: RecordingAdapter) -> Arc<RecordingAdapter> {
    Arc::new(adapter)
}

fn engine(root: &Path, adapters: &[&Arc<RecordingAdapter>]) -> TransactionEngine {
    engine_for(root, adapters.iter().map(|adapter| Arc::clone(adapter) as Arc<dyn Adapter>).collect())
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).unwrap()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn expect_message(result: Result<TransactionState, Error>, fragment: &str) -> Error {
    let err = result.expect_err("the operation must fail");
    assert!(err.message().contains(fragment), "{:?} does not mention {fragment:?}", err.message());
    err
}

#[test]
fn unconfirmed_core_command_cleanup_prevents_automatic_rollback() {
    // The runner proves a killed process group gone or stops the engine (pc_host WP1); here: a
    // stop (`SystemExit`, or the operator's interrupt) after the mutation leaves `applying`.
    for stop in [RunError::CleanupUnconfirmed, RunError::Interrupted { stderr: Vec::new() }] {
        let dir = TempDir::new("cleanup");
        let log = Arc::new(Mutex::new(Vec::new()));
        struct CommandAdapter(RecordingAdapter, Mutex<Option<RunError>>);
        impl Adapter for CommandAdapter {
            fn name(&self) -> &str {
                self.0.name()
            }
            fn plan(
                &self,
                c: &crate::model::InstallerConfig,
                f: &crate::plan::AuditFacts,
            ) -> Result<Vec<crate::plan::Action>, Error> {
                self.0.plan(c, f)
            }
            fn prepare(&self, a: &crate::plan::Action) -> Result<crate::journal::CheckpointData, Error> {
                self.0.prepare(a)
            }
            fn apply(
                &self,
                a: &crate::plan::Action,
                c: crate::journal::CheckpointData,
            ) -> Result<crate::journal::CheckpointData, Error> {
                self.0.apply(a, c)?;
                Err(self.1.lock().unwrap().take().unwrap().into())
            }
            fn reconcile_apply(
                &self,
                a: &crate::plan::Action,
                c: crate::journal::CheckpointData,
            ) -> Result<crate::journal::CheckpointData, Error> {
                self.0.reconcile_apply(a, c)
            }
            fn verify(&self, a: &crate::plan::Action) -> Result<crate::plan::Evidence, Error> {
                self.0.verify(a)
            }
            fn repair(
                &self,
                a: &crate::plan::Action,
                c: crate::journal::CheckpointData,
            ) -> Result<crate::journal::CheckpointData, Error> {
                self.0.repair(a, c)
            }
            fn rollback(
                &self,
                a: &crate::plan::Action,
                c: crate::journal::CheckpointData,
                p: bool,
                t: crate::journal::RollbackTarget,
            ) -> Result<crate::plan::Evidence, Error> {
                self.0.rollback(a, c, p, t)
            }
            fn reconcile_rollback(
                &self,
                a: &crate::plan::Action,
                c: crate::journal::CheckpointData,
                p: bool,
                t: crate::journal::RollbackTarget,
            ) -> Result<crate::plan::Evidence, Error> {
                self.0.reconcile_rollback(a, c, p, t)
            }
        }
        let inner = RecordingAdapter { log: Some(log.clone()), ..RecordingAdapter::new("core", dir.path()) };
        let target = inner.target();
        let adapter: Arc<dyn Adapter> = Arc::new(CommandAdapter(inner, Mutex::new(Some(stop))));
        let engine = engine_for(dir.path(), vec![adapter]);
        let plan = plan_for(&["core"]);
        let err = engine.apply(&plan, &plan.digest()).unwrap_err();
        assert!(err.is_fatal());
        assert_eq!(engine.store().read_state().unwrap().status, Status::Applying);
        assert!(target.exists());
        assert_eq!(*log.lock().unwrap(), vec!["apply:core".to_string()]);
    }
}

#[test]
fn resume_after_each_checkpoint_does_not_repeat_committed_mutation() {
    for crash_after in [Phase::Prepared, Phase::Applied, Phase::Verified] {
        let dir = TempDir::new("resume");
        let adapter = RecordingAdapter::new("core", dir.path());
        *adapter.crash_after.lock().unwrap() = Some(crash_after);
        let adapter = shared(adapter);
        let plan = plan_for(&["core"]);
        let err = engine(dir.path(), &[&adapter]).apply(&plan, &plan.digest()).unwrap_err();
        assert_eq!((err.python_class_name(), err.message()), ("InjectedCrash", crash_after.as_str().to_string()));

        let recovered = engine(dir.path(), &[&shared(RecordingAdapter::new("core", dir.path()))]).resume().unwrap();
        assert_eq!(recovered.status, Status::Active);
        assert_eq!(read(adapter.counter()), "1");
    }
}

#[test]
fn applied_state_is_durable_before_derived_ownership_journal() {
    let dir = TempDir::new("durable");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.store().set_fault_hook(Some(Box::new(|file, value| {
        if file == JournalFile::Ownership && !value["files"].as_object().unwrap().is_empty() {
            return Err(Error::fatal("InjectedCrash", "ownership"));
        }
        Ok(())
    })));
    let err = engine_a.apply(&plan, &plan.digest()).unwrap_err();
    assert_eq!(err.message(), "ownership");

    let recovered = engine(dir.path(), &[&shared(RecordingAdapter::new("core", dir.path()))]).resume().unwrap();
    assert_eq!(recovered.status, Status::Active);
    assert_eq!(read(adapter.counter()), "1");
}

#[test]
fn resume_reconciles_process_death_after_adapter_mutation() {
    let dir = TempDir::new("death");
    let adapter = RecordingAdapter::new("core", dir.path());
    *adapter.crash_during_apply.lock().unwrap() = Some(Failure::Crash);
    let adapter = shared(adapter);
    let plan = plan_for(&["core"]);
    let err = engine(dir.path(), &[&adapter]).apply(&plan, &plan.digest()).unwrap_err();
    assert_eq!(err.message(), "apply mutation committed");

    let state = TransactionStore::new(dir.path()).unwrap().read_state().unwrap();
    assert_eq!(state.checkpoints.last().unwrap().phase, Phase::Applying);
    let recovered = engine(dir.path(), &[&shared(RecordingAdapter::new("core", dir.path()))]).resume().unwrap();
    assert_eq!(recovered.status, Status::Active);
    assert_eq!(read(adapter.counter()), "1");
}

#[test]
fn normal_exception_after_adapter_mutation_rolls_it_back() {
    let dir = TempDir::new("rollback");
    let adapter = RecordingAdapter::new("core", dir.path());
    *adapter.crash_during_apply.lock().unwrap() = Some(Failure::Runtime);
    let adapter = shared(adapter);
    let plan = plan_for(&["core"]);
    let err = engine(dir.path(), &[&adapter]).apply(&plan, &plan.digest()).unwrap_err();
    assert_eq!((err.python_class_name(), err.message().as_str()), ("RuntimeError", "apply mutation committed"));

    assert!(!adapter.target().exists());
    let state = TransactionStore::new(dir.path()).unwrap().read_state().unwrap();
    assert_eq!(state.status, Status::RolledBack);
    assert_eq!(state.error.as_deref(), Some("RuntimeError"));
}

#[test]
fn resume_reconciles_death_or_error_after_destructive_rollback() {
    for failure in [Failure::Crash, Failure::Runtime] {
        let dir = TempDir::new("destructive");
        let adapter = shared(RecordingAdapter::new("core", dir.path()));
        let plan = plan_for(&["core"]);
        let engine_a = engine(dir.path(), &[&adapter]);
        engine_a.apply(&plan, &plan.digest()).unwrap();
        *adapter.crash_during_rollback.lock().unwrap() = Some(failure);

        expect_message(engine_a.uninstall(false), "rollback mutation committed");

        let recovered = engine(dir.path(), &[&shared(RecordingAdapter::new("core", dir.path()))]).resume().unwrap();
        assert_eq!(recovered.status, Status::Uninstalled);
        assert!(!adapter.target().exists());
    }
}

#[test]
fn rollback_reconciliation_refuses_foreign_edit_before_deletion() {
    let dir = TempDir::new("foreign");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    adapter.crash_before_rollback.store(true, Ordering::SeqCst);
    expect_message(engine_a.uninstall(false), "before rollback deletion");
    fs::write(adapter.target(), "foreign edit").unwrap();

    let err = expect_message(
        engine(dir.path(), &[&shared(RecordingAdapter::new("core", dir.path()))]).resume(),
        "owned file drifted",
    );
    assert_eq!(err.python_class_name(), "OwnershipError");
    assert_eq!(read(adapter.target()), "foreign edit");
}

#[test]
fn uninstall_routes_persisted_data_policy_to_adapter() {
    for purge_data in [false, true] {
        let dir = TempDir::new("policy");
        let adapter = shared(RecordingAdapter { preserve_data: true, ..RecordingAdapter::new("core", dir.path()) });
        let plan = plan_for(&["core"]);
        let engine_a = engine(dir.path(), &[&adapter]);
        engine_a.apply(&plan, &plan.digest()).unwrap();

        let state = engine_a.uninstall(purge_data).unwrap();

        assert_eq!(state.status, Status::Uninstalled);
        assert_eq!(adapter.data_path().exists(), !purge_data);
        assert_eq!(state.purge_data, Some(purge_data));
    }
}

#[test]
fn failed_install_removes_data_even_when_uninstall_would_preserve_it() {
    let dir = TempDir::new("failed");
    let first = shared(RecordingAdapter { preserve_data: true, ..RecordingAdapter::new("first", dir.path()) });
    let second = shared(RecordingAdapter { fail_apply: true, ..RecordingAdapter::new("second", dir.path()) });
    let plan = plan_for(&["first", "second"]);

    expect_message(engine(dir.path(), &[&first, &second]).apply(&plan, &plan.digest()), "second failed");

    assert!(!first.target().exists());
    assert!(!first.data_path().exists());
}

#[test]
fn terminal_resume_rebuilds_derived_journals_from_state() {
    let dir = TempDir::new("terminal");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.store().set_fault_hook(Some(Box::new(|file, value| {
        if file == JournalFile::Report && value["status"] == "active" {
            return Err(Error::fatal("InjectedCrash", "terminal report"));
        }
        Ok(())
    })));
    expect_message(engine_a.apply(&plan, &plan.digest()), "terminal report");

    let recovered_engine = engine(dir.path(), &[&shared(RecordingAdapter::new("core", dir.path()))]);
    assert_eq!(recovered_engine.resume().unwrap().status, Status::Active);
    let report: serde_json::Value = serde_json::from_str(&read(recovered_engine.store().report_path())).unwrap();
    assert_eq!(report["status"], "active");
}

#[test]
fn rollback_refuses_foreign_drift_before_deletion() {
    let dir = TempDir::new("drift");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    fs::write(adapter.target(), "foreign edit").unwrap();

    expect_message(engine_a.uninstall(false), "owned file drifted");

    assert_eq!(read(adapter.target()), "foreign edit");
}

#[test]
fn normal_failure_rolls_back_committed_actions_in_reverse_order() {
    let dir = TempDir::new("reverse");
    let log = Arc::new(Mutex::new(Vec::new()));
    let first = shared(RecordingAdapter { log: Some(log.clone()), ..RecordingAdapter::new("first", dir.path()) });
    let second = shared(RecordingAdapter { log: Some(log.clone()), ..RecordingAdapter::new("second", dir.path()) });
    let third = shared(RecordingAdapter {
        fail_apply: true,
        log: Some(log.clone()),
        ..RecordingAdapter::new("third", dir.path())
    });
    let plan = plan_for(&["first", "second", "third"]);

    expect_message(engine(dir.path(), &[&first, &second, &third]).apply(&plan, &plan.digest()), "third failed");

    assert_eq!(
        *log.lock().unwrap(),
        ["apply:first", "apply:second", "apply:third", "rollback:second", "rollback:first"]
    );
    assert!(!first.target().exists());
    assert!(!second.target().exists());
}

#[test]
fn store_uses_private_directory_and_file_permissions() {
    let dir = TempDir::new("modes");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();

    let store = engine_a.store();
    for directory in [store.directory(), store.backups_path(), store.credentials_path()] {
        assert_eq!(mode(directory), 0o700);
    }
    for path in [store.state_path(), store.plan_path(), store.ownership_path(), store.report_path()] {
        assert_eq!(mode(path), 0o600);
    }
}

#[test]
fn store_rejects_symlinked_parent_that_escapes_root() {
    let dir = TempDir::new("escape");
    let root = dir.path().join("root");
    let outside = dir.path().join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, root.join("var")).unwrap();
    let original_mode = mode(&outside);

    let err = TransactionStore::new(&root).unwrap_err();
    assert_eq!(
        (err.python_class_name(), err.message().as_str()),
        ("OwnershipError", "rooted path escapes supplied root")
    );

    assert_eq!(mode(&outside), original_mode);
    assert!(!outside.join("lib").exists());
}

#[test]
fn operation_lock_rejects_final_symlink_without_chmod_or_flock() {
    let dir = TempDir::new("locklink");
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("run/lock")).unwrap();
    let outside = dir.path().join("outside.lock");
    fs::write(&outside, "outside").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&outside, root.join("run/lock/proxy-control.lock")).unwrap();

    let err = TransactionStore::new(&root).unwrap().locked().unwrap_err();
    assert!(err.message().contains("operation lock"));

    assert_eq!(read(&outside), "outside");
    assert_eq!(mode(&outside), 0o644);
}

#[test]
fn operation_lock_rejects_hard_link_before_chmod_or_flock() {
    let dir = TempDir::new("lockhard");
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("run/lock")).unwrap();
    let outside = dir.path().join("outside.lock");
    fs::write(&outside, "outside").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).unwrap();
    fs::hard_link(&outside, root.join("run/lock/proxy-control.lock")).unwrap();

    let err = TransactionStore::new(&root).unwrap().locked().unwrap_err();
    assert!(err.message().contains("operation lock"));

    assert_eq!(read(&outside), "outside");
    assert_eq!(mode(&outside), 0o644);
}

#[test]
fn apply_requires_the_complete_accepted_plan_digest() {
    let dir = TempDir::new("accepted");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);

    let err = expect_message(engine_a.apply(&plan, &plan.digest()[..12]), "accepted plan digest does not match");
    assert_eq!(err.python_class_name(), "AcceptedDigestError");

    assert!(!adapter.target().exists());
    assert!(!engine_a.store().state_path().exists());
}

#[test]
fn a_service_rewritten_owned_file_is_not_foreign_drift() {
    let dir = TempDir::new("mutable");
    let adapter = shared(RecordingAdapter {
        preserve_data: true,
        mutable_data: true,
        ..RecordingAdapter::new("core", dir.path())
    });
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    fs::write(adapter.data_path(), "rewritten by the service").unwrap();

    engine_a.repair().unwrap();

    fs::write(adapter.target(), "foreign edit").unwrap();
    expect_message(engine_a.repair(), "owned file drifted");
}

#[test]
fn a_file_the_version_agent_manages_is_not_foreign_drift() {
    let dir = TempDir::new("managed");
    let adapter = shared(RecordingAdapter { preserve_data: true, ..RecordingAdapter::new("core", dir.path()) });
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    fs::write(adapter.data_path(), "replaced by the version agent").unwrap();

    expect_message(engine_a.uninstall(false), "owned file drifted");

    let managed: BTreeSet<String> = ["/core.data".to_string()].into_iter().collect();
    let engine_b = engine(dir.path(), &[&adapter]).with_agent_managed(managed);
    assert_eq!(engine_b.uninstall(false).unwrap().status, Status::Uninstalled);
}

#[test]
fn repair_refuses_owned_file_drift_before_adapter_verification() {
    let dir = TempDir::new("repairdrift");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    fs::write(adapter.target(), "foreign edit").unwrap();

    expect_message(engine_a.repair(), "owned file drifted");
}

/// Python's `test_apply_rejects_adapter_without_checkpoint_aware_repair`: the trait makes a
/// missing method impossible, so the remaining refusal is an adapter that is not registered
/// under the plan's name.
#[test]
fn apply_rejects_adapter_without_checkpoint_aware_repair() {
    let dir = TempDir::new("unavailable");
    let adapter = shared(RecordingAdapter::new("other", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);

    let err = expect_message(engine_a.apply(&plan, &plan.digest()), "adapter is unavailable: core");
    assert_eq!(err.python_class_name(), "TransactionError");

    assert!(!engine_a.store().state_path().exists());
}

#[test]
fn reapplying_the_same_plan_is_a_no_op() {
    let dir = TempDir::new("noop");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    let first = engine_a.apply(&plan, &plan.digest()).unwrap();
    let mutations = read(adapter.counter());

    let again = engine_a.apply(&plan, &plan.digest()).unwrap();

    assert_eq!(again.transaction_id, first.transaction_id);
    assert_eq!(again.status, Status::Active);
    assert_eq!(read(adapter.counter()), mutations);
}

#[test]
fn reapplying_a_different_plan_still_refuses() {
    let dir = TempDir::new("different");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();

    let other = plan_for(&["core", "core"]);
    expect_message(engine_a.apply(&other, &other.digest()), "already exists");
}

#[test]
fn reapplying_over_drifted_ownership_refuses() {
    let dir = TempDir::new("redrift");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    fs::write(adapter.target(), "foreign edit").unwrap();

    expect_message(engine_a.apply(&plan, &plan.digest()), "owned file drifted");
}

#[test]
fn reapplying_the_same_intent_after_the_host_changed_is_a_no_op() {
    let dir = TempDir::new("intent");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    let first = engine_a.apply(&plan, &plan.digest()).unwrap();
    let mutations = read(adapter.counter());

    let mut platform = Map::new();
    platform.insert("os".into(), json!("test"));
    platform.insert("changed".into(), json!("1"));
    let replanned = plan_with(plan.actions.clone(), platform);
    assert_ne!(replanned.digest(), plan.digest());
    assert_eq!(replanned.intent_digest(), plan.intent_digest());

    let again = engine_a.apply(&replanned, &replanned.digest()).unwrap();

    assert_eq!(again.transaction_id, first.transaction_id);
    assert_eq!(read(adapter.counter()), mutations);
}

fn seeded_engine(root: &Path, status: Status) -> (TransactionEngine, Arc<RecordingAdapter>) {
    let adapter = shared(RecordingAdapter::new("core", root));
    let plan = plan_for(&["core"]);
    let engine_a = engine(root, &[&adapter]);
    engine_a.store().initialize().unwrap();
    engine_a.store().write_plan(&plan).unwrap();
    engine_a.persist(&TransactionState::new(&"0".repeat(32), status, &plan.digest())).unwrap();
    (engine_a, adapter)
}

#[test]
fn a_completed_rollback_does_not_block_the_next_attempt() {
    let dir = TempDir::new("afterrollback");
    let (engine_a, _) = seeded_engine(dir.path(), Status::RolledBack);
    let plan = plan_for(&["core"]);
    assert_eq!(engine_a.apply(&plan, &plan.digest()).unwrap().status, Status::Active);
}

#[test]
fn a_completed_uninstall_does_not_block_the_next_install() {
    let dir = TempDir::new("afteruninstall");
    let (engine_a, _) = seeded_engine(dir.path(), Status::Uninstalled);
    let plan = plan_for(&["core"]);
    let state = engine_a.apply(&plan, &plan.digest()).unwrap();
    assert_eq!(state.status, Status::Active);
    assert_ne!(state.transaction_id, "0".repeat(32));
}

#[test]
fn an_interrupted_transaction_still_blocks_a_fresh_start() {
    let dir = TempDir::new("interrupted");
    let (engine_a, _) = seeded_engine(dir.path(), Status::Applying);
    let plan = plan_for(&["core"]);
    expect_message(engine_a.apply(&plan, &plan.digest()), "already exists");
}

// ------------------------------------------------------------------------------------------
// Beyond the Python file: the guards around the lifecycle.
// ------------------------------------------------------------------------------------------

#[test]
fn repair_and_uninstall_refuse_an_interrupted_transaction() {
    let dir = TempDir::new("guards");
    let (engine_a, _) = seeded_engine(dir.path(), Status::Applying);
    expect_message(engine_a.repair(), "resume the interrupted transaction before repair");
    expect_message(engine_a.uninstall(false), "resume the interrupted transaction before uninstall");
}

#[test]
fn an_interrupted_uninstall_must_be_retried_with_the_same_data_policy() {
    let dir = TempDir::new("retry");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    adapter.crash_before_rollback.store(true, Ordering::SeqCst);
    expect_message(engine_a.uninstall(true), "before rollback deletion");
    expect_message(engine_a.uninstall(false), "retry the interrupted uninstall with --purge-data");
    assert_eq!(engine_a.uninstall(true).unwrap().status, Status::Uninstalled);
}

#[test]
fn the_persisted_plan_must_match_the_state_digest() {
    let dir = TempDir::new("plandigest");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    engine_a.store().write_plan(&plan_for(&["core", "core"])).unwrap();
    expect_message(engine_a.resume(), "persisted plan digest does not match transaction state");
}

#[test]
fn a_rollback_failure_is_recorded_and_resumable() {
    let dir = TempDir::new("rollbackfailed");
    let adapter = shared(RecordingAdapter::new("core", dir.path()));
    let plan = plan_for(&["core"]);
    let engine_a = engine(dir.path(), &[&adapter]);
    engine_a.apply(&plan, &plan.digest()).unwrap();
    *adapter.crash_during_rollback.lock().unwrap() = Some(Failure::Runtime);
    expect_message(engine_a.uninstall(false), "rollback mutation committed");
    let state = engine_a.store().read_state().unwrap();
    assert_eq!(state.status, Status::RollbackFailed);
    assert_eq!(state.error.as_deref(), Some("RuntimeError"));
    assert_eq!(state.rollback_target, Some(crate::journal::RollbackTarget::Uninstalled));
    let resumed = engine_a.resume().unwrap();
    assert_eq!(resumed.status, Status::Uninstalled);
    // A finished uninstall is persisted again on a second request, not refused.
    assert_eq!(engine_a.uninstall(false).unwrap().status, Status::Uninstalled);
}

#[test]
fn a_runtime_v2_journal_is_refused_by_name() {
    // Owner decision 10: the runtime-v2 adapter is gone; such a journal stops every command.
    let dir = TempDir::new("runtimev2");
    let (engine_a, _) = seeded_engine(dir.path(), Status::Active);
    let mut plan = plan_for(&["core"]);
    plan.actions[0].adapter = "runtime-v2".into();
    plan.actions[0].id = "runtime-v2.import".into();
    let mut state = TransactionState::new(&"0".repeat(32), Status::Active, &plan.digest());
    state.origin = "runtime-v2".into();
    engine_a.store().write_plan(&plan).unwrap();
    engine_a.persist(&state).unwrap();
    for result in [engine_a.resume(), engine_a.repair(), engine_a.uninstall(false)] {
        expect_message(result, "adapter is unavailable: runtime-v2");
    }
}
