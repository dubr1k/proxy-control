//! An installer journal for the panel self-update tests: stand-ins for the Core and version-agent
//! adapters with the ownership shapes the real ones journal (Core `{preserve, sha256}` for the
//! project files, the agent the bare digest for its code and unit and `{sha256, mutable}` for its
//! env), applied through the installer's engine — `_owned_panel_host` of the Python tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use installer::adapter::Adapter;
use installer::error::Error;
use installer::journal::{CheckpointData, RollbackTarget};
use installer::model::InstallerConfig;
use installer::plan::{Action, AuditFacts, Evidence, InstallPlan, ReleaseIdentity};
use installer::{TransactionEngine, TransactionStore};
use serde_json::{json, Map, Value};

use super::write;

pub const PROJECT: &str = "/opt/mtproxy-shared443";
pub const AGENT_CODE: &str = "/opt/proxy-control/version_agent";
pub const UNIT: &str = "/etc/systemd/system/version-agent.service";
const ENV: &str = "/etc/proxy-control/version-agent.env";
const TMPFILES: &str = "/etc/tmpfiles.d/proxy-control-version-agent.conf";

/// `<root>` + an absolute host path.
pub fn host(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

fn action(id: &str, adapter: &str) -> Action {
    Action {
        id: id.into(),
        adapter: adapter.into(),
        owner: format!("proxy-control:{adapter}"),
        mutations: vec![format!("install {adapter}")],
        preconditions: vec![format!("{adapter} is not installed")],
        verification: vec![format!("{adapter} files are in place")],
        inverse: vec![format!("remove {adapter}")],
        credentials_required: false,
    }
}

fn files_under(directory: &Path, relative: &str, out: &mut Vec<(String, PathBuf)>) {
    let mut entries: Vec<_> = fs::read_dir(directory).unwrap().map(|entry| entry.unwrap()).collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let child = if relative.is_empty() { name.clone() } else { format!("{relative}/{name}") };
        if entry.file_type().unwrap().is_dir() {
            files_under(&entry.path(), &child, out);
        } else {
            out.push((child, entry.path()));
        }
    }
}

fn remove_owned(root: &Path, checkpoint: &CheckpointData, purge: bool) {
    for (path, declared) in checkpoint["ownership"].as_object().unwrap() {
        let preserve = declared.get("preserve").and_then(Value::as_bool).unwrap_or(false);
        if !preserve || purge {
            let _ = fs::remove_file(host(root, path));
        }
    }
}

fn ok(action: &Action, observation: &str) -> Result<Evidence, Error> {
    Ok(Evidence::ok(&action.id, &[observation])?)
}

/// Core: copies every file of `source` into the project and keeps a preserved master key.
struct FakeCore {
    root: PathBuf,
    source: PathBuf,
}

impl Adapter for FakeCore {
    fn name(&self) -> &str {
        "core"
    }

    fn plan(&self, _: &InstallerConfig, _: &AuditFacts) -> Result<Vec<Action>, Error> {
        Ok(vec![action("core.runtime", "core")])
    }

    fn prepare(&self, _: &Action) -> Result<CheckpointData, Error> {
        Ok(Map::new())
    }

    fn apply(&self, _: &Action, mut checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let mut files = Vec::new();
        files_under(&self.source, "", &mut files);
        let mut ownership = Map::new();
        for (relative, source) in files {
            let data = fs::read(&source)?;
            let path = format!("{PROJECT}/{relative}");
            write(&host(&self.root, &path), &data);
            ownership.insert(path, json!({"preserve": false, "sha256": pc_host::fs::sha256_hex(&data)}));
        }
        let key = format!("{PROJECT}/secrets/panel-master-key");
        write(&host(&self.root, &key), b"keep me\n");
        ownership.insert(key, json!({"preserve": true, "sha256": pc_host::fs::sha256_hex(b"keep me\n")}));
        checkpoint.insert("ownership".into(), Value::Object(ownership));
        Ok(checkpoint)
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        ok(action, "core files verified")
    }

    fn repair(&self, _: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        Ok(checkpoint)
    }

    fn rollback(&self, action: &Action, checkpoint: CheckpointData, purge: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        remove_owned(&self.root, &checkpoint, purge);
        ok(action, "core files removed")
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.rollback(action, checkpoint, purge, target)
    }
}

/// The version-agent adapter of 3.x: top-level `source/version_agent/*.py`, the unit, the
/// tmpfiles file and the mutable env.
struct FakeAgent {
    root: PathBuf,
    source: PathBuf,
}

impl Adapter for FakeAgent {
    fn name(&self) -> &str {
        "version_agent"
    }

    fn requires(&self) -> &[&'static str] {
        &["core"]
    }

    fn plan(&self, _: &InstallerConfig, _: &AuditFacts) -> Result<Vec<Action>, Error> {
        Ok(vec![action("version_agent.runtime", "version_agent")])
    }

    fn prepare(&self, _: &Action) -> Result<CheckpointData, Error> {
        Ok(Map::new())
    }

    fn apply(&self, _: &Action, mut checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let mut ownership = Map::new();
        let mut entries: Vec<_> = fs::read_dir(&self.source)?.map(|entry| entry.unwrap().path()).collect();
        entries.sort();
        for source in entries.into_iter().filter(|path| path.extension().is_some_and(|ext| ext == "py")) {
            let data = fs::read(&source)?;
            let path = format!("{AGENT_CODE}/{}", source.file_name().unwrap().to_string_lossy());
            write(&host(&self.root, &path), &data);
            ownership.insert(path, json!(pc_host::fs::sha256_hex(&data)));
        }
        let unit = b"[Service]\nExecStart=/usr/bin/python3 -m version_agent.server\n";
        let tmpfiles = b"d /run/proxy-control 0770 root 10001 -\n";
        for (path, data) in [(UNIT, &unit[..]), (TMPFILES, &tmpfiles[..])] {
            write(&host(&self.root, path), data);
            ownership.insert(path.into(), json!(pc_host::fs::sha256_hex(data)));
        }
        let env = b"PROXY_CONTROL_COMPOSE_DIR=/opt/mtproxy-shared443\n";
        write(&host(&self.root, ENV), env);
        ownership.insert(ENV.into(), json!({"mutable": true, "sha256": pc_host::fs::sha256_hex(env)}));
        checkpoint.insert("ownership".into(), Value::Object(ownership));
        Ok(checkpoint)
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        ok(action, "agent verified")
    }

    fn repair(&self, _: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        Ok(checkpoint)
    }

    fn rollback(&self, action: &Action, checkpoint: CheckpointData, purge: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        remove_owned(&self.root, &checkpoint, purge);
        ok(action, "agent removed")
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.rollback(action, checkpoint, purge, target)
    }
}

/// Installs Core (the project files of `project_source`) and, with `agent_source`, the 3.x agent
/// (its top-level `*.py`) through the engine under `root`.
pub fn install(root: &Path, project_source: &Path, agent_source: Option<&Path>) -> TransactionEngine {
    let mut engine = TransactionEngine::new(TransactionStore::new(root).unwrap());
    engine.register(Arc::new(FakeCore { root: root.into(), source: project_source.into() }));
    let mut actions = vec![action("core.runtime", "core")];
    if let Some(source) = agent_source {
        engine.register(Arc::new(FakeAgent { root: root.into(), source: source.into() }));
        actions.push(action("version_agent.runtime", "version_agent"));
    }
    let mut order: Vec<String> = Vec::new();
    for action in &actions {
        if !order.contains(&action.adapter) {
            order.push(action.adapter.clone());
        }
    }
    let plan = InstallPlan {
        config: json!({"profile": "test"}),
        facts: AuditFacts::default(),
        release: ReleaseIdentity::new("v-test", &"b".repeat(40), &"a".repeat(64)),
        adapter_dependencies: order.iter().map(|name| (name.clone(), Vec::new())).collect(),
        adapter_order: order,
        actions,
        schema: 1,
    }
    .checked()
    .unwrap();
    engine.apply(&plan, &plan.digest()).unwrap();
    engine
}
