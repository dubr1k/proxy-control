//! The worked minimal adapter of the crate documentation (`lib.rs`, "Writing an adapter"),
//! compiled and tested with the crate so the documented API cannot drift. It is not part of the
//! registry or the binary.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pc_host::runner::{HostRunner, RunOptions};
use serde_json::{json, Map, Value};

use crate::adapter::Adapter;
use crate::adapters::AdapterContext;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::InstallerConfig;
use crate::planner::{Action, AuditFacts, Evidence};

/// The one file this adapter owns.
const MARKER: &str = "/etc/proxy-control/example.marker";

/// Owns `/etc/proxy-control/example.marker` (`panel=<domain>`) and reloads systemd after
/// writing it.
pub struct ExampleAdapter {
    root: PathBuf,
    runner: Arc<dyn HostRunner>,
}

impl ExampleAdapter {
    pub fn new(context: &AdapterContext) -> ExampleAdapter {
        ExampleAdapter { root: context.root.clone(), runner: context.runner.clone() }
    }

    fn marker(&self) -> Result<PathBuf, Error> {
        Ok(pc_host::fs::root_path(&self.root, MARKER)?)
    }

    /// Everything after `plan` is configuration-free: the content comes from the action.
    fn content(action: &Action) -> Result<String, Error> {
        let prefix = format!("write {MARKER} ");
        action
            .mutations
            .iter()
            .find_map(|mutation| mutation.strip_prefix(prefix.as_str()))
            .map(|assignment| format!("{assignment}\n"))
            .ok_or_else(|| Error::other("ExampleError", "the example action names no marker content"))
    }

    fn write_marker(&self, action: &Action, mut data: CheckpointData) -> Result<CheckpointData, Error> {
        let content = Self::content(action)?;
        pc_host::fs::atomic_write(&self.marker()?, content.as_bytes(), 0o644, None)?;
        let output = self.runner.run(&["systemctl", "daemon-reload"], &RunOptions::default())?;
        if output.returncode != 0 {
            return Err(Error::other("ExampleError", "systemd could not reload its units"));
        }
        let digest = pc_host::fs::sha256_hex(content.as_bytes());
        data.insert("ownership".into(), json!({ MARKER: {"sha256": digest, "preserve": false} }));
        Ok(data)
    }

    fn remove_marker(&self, action: &Action) -> Result<Evidence, Error> {
        pc_host::fs::durable_remove(&self.marker()?, true)?;
        Ok(Evidence::ok(&action.id, &["the example marker is removed"])?)
    }
}

fn holds(path: &Path, content: &str) -> bool {
    std::fs::read(path).is_ok_and(|bytes| bytes == content.as_bytes())
}

impl Adapter for ExampleAdapter {
    fn name(&self) -> &str {
        "example"
    }

    fn plan(&self, config: &InstallerConfig, _facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        Ok(vec![Action::new(
            "example.marker",
            "example",
            "proxy-control:example",
            vec![format!("write {MARKER} panel={}", config.domains.panel)],
            vec![format!("{MARKER} is absent")],
            vec![format!("{MARKER} names the panel domain")],
            vec![format!("remove {MARKER}")],
            false,
        )?])
    }

    fn prepare(&self, _action: &Action) -> Result<CheckpointData, Error> {
        let mut data = Map::new();
        data.insert("marker".into(), Value::String(MARKER.into()));
        Ok(data)
    }

    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.write_marker(action, checkpoint)
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.write_marker(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let observation = ["the example marker names the panel domain"];
        if holds(&self.marker()?, &Self::content(action)?) {
            Ok(Evidence::ok(&action.id, &observation)?)
        } else {
            Ok(Evidence::failed(&action.id, &observation)?)
        }
    }

    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.write_marker(action, checkpoint)
    }

    fn rollback(&self, action: &Action, _: CheckpointData, _: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        self.remove_marker(action)
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        _: CheckpointData,
        _: bool,
        _: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.remove_marker(action)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pc_host::runner::{CallKind, RecordingRunner, Reply};

    use super::*;
    use crate::adapter::compose_plan;
    use crate::journal::{Phase, Status};
    use crate::testkit::{engine_for, release, TempDir};

    fn config() -> InstallerConfig {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer/core.toml");
        installer_core::config::load_config(&path).unwrap()
    }

    #[test]
    fn example_adapter_installs_verifies_and_uninstalls() {
        let dir = TempDir::new("example");
        let runner = Arc::new(RecordingRunner::new());
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
        let adapter: Arc<dyn Adapter> = Arc::new(ExampleAdapter::new(&context));

        // Plan exactly as the CLI does, then run the plan through the real engine.
        let plan = compose_plan(&config(), &AuditFacts::default(), std::slice::from_ref(&adapter), &release()).unwrap();
        assert_eq!(plan.actions[0].mutations, ["write /etc/proxy-control/example.marker panel=panel.example.com"]);
        let engine = engine_for(dir.path(), vec![adapter]);
        let state = engine.apply(&plan, &plan.digest()).unwrap();
        assert_eq!(state.status, Status::Active);
        assert_eq!(state.checkpoints[0].phase, Phase::Verified);
        let marker = dir.path().join("etc/proxy-control/example.marker");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "panel=panel.example.com\n");
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, CallKind::Run);
        assert_eq!(calls[0].argv, ["systemctl", "daemon-reload"]);

        // The engine refuses to undo what it no longer owns...
        std::fs::write(&marker, "panel=elsewhere\n").unwrap();
        assert_eq!(engine.uninstall(false).unwrap_err().message(), format!("owned file drifted: {MARKER}"));
        // ...`repair` restores it, and `uninstall` removes it.
        assert_eq!(engine.repair().unwrap().status, Status::Active);
        assert_eq!(engine.uninstall(false).unwrap().status, Status::Uninstalled);
        assert!(!marker.exists());
    }

    #[test]
    fn a_failed_reload_rolls_the_marker_back() {
        let dir = TempDir::new("example-failure");
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(&["systemctl", "daemon-reload"], Reply::exit(1, "", "Failed to reload"));
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
        let adapter: Arc<dyn Adapter> = Arc::new(ExampleAdapter::new(&context));
        let plan = compose_plan(&config(), &AuditFacts::default(), std::slice::from_ref(&adapter), &release()).unwrap();
        let engine = engine_for(dir.path(), vec![adapter]);
        let err = engine.apply(&plan, &plan.digest()).unwrap_err();
        assert_eq!(
            (err.python_class_name(), err.message().as_str()),
            ("ExampleError", "systemd could not reload its units")
        );
        let state = engine.store().read_state().unwrap();
        assert_eq!((state.status, state.error.as_deref()), (Status::RolledBack, Some("ExampleError")));
        assert!(!dir.path().join("etc/proxy-control/example.marker").exists());
    }
}
