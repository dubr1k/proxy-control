//! Stand-ins for the Core and version-agent adapters with the ownership shapes the real ones
//! journal (host inventory C1.0): Core declares `{preserve, sha256}` for the project files it
//! copies, the agent the bare digest for its code and unit and `{sha256, mutable: true}` for its
//! env. They are enough to drive the handoff and the migration through real journals.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pc_host::fs::sha256_hex;
use serde_json::{json, Map, Value};

use crate::adapter::Adapter;
use crate::engine::TransactionEngine;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::InstallerConfig;
use crate::plan::{Action, AuditFacts, Evidence};
use crate::testkit::{engine_for, plan_with};

pub const PROJECT: &str = "/opt/mtproxy-shared443";
pub const AGENT_CODE: &str = "/opt/proxy-control/version_agent";
pub const UNIT: &str = "/etc/systemd/system/version-agent.service";
pub const ENV: &str = "/etc/proxy-control/version-agent.env";
pub const TMPFILES: &str = "/etc/tmpfiles.d/proxy-control-version-agent.conf";

pub fn action(id: &str, adapter: &str) -> Action {
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

/// `<root>` + an absolute host path.
pub fn host(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

pub fn write(path: &Path, data: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
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

fn owned_paths(checkpoint: &CheckpointData) -> Vec<(String, bool)> {
    checkpoint["ownership"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(path, declared)| (path.clone(), declared.get("preserve").and_then(Value::as_bool).unwrap_or(false)))
        .collect()
}

fn remove_owned(root: &Path, checkpoint: &CheckpointData, purge_data: bool) {
    for (path, preserve) in owned_paths(checkpoint) {
        if !preserve || purge_data {
            let _ = fs::remove_file(host(root, &path));
        }
    }
}

fn ok(action: &Action, observation: &str) -> Result<Evidence, Error> {
    Ok(Evidence::ok(&action.id, &[observation])?)
}

/// Core: copies every file of `source` into the project and keeps a preserved master key.
pub struct FakeCore {
    pub root: PathBuf,
    pub source: PathBuf,
}

impl Adapter for FakeCore {
    fn name(&self) -> &str {
        "core"
    }

    fn plan(&self, _config: &InstallerConfig, _facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        Ok(vec![action("core.runtime", "core")])
    }

    fn prepare(&self, _action: &Action) -> Result<CheckpointData, Error> {
        Ok(Map::new())
    }

    fn apply(&self, _action: &Action, mut checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let mut files = Vec::new();
        files_under(&self.source, "", &mut files);
        let mut ownership = Map::new();
        for (relative, source) in files {
            let data = fs::read(&source)?;
            let path = format!("{PROJECT}/{relative}");
            write(&host(&self.root, &path), &data);
            ownership.insert(path, json!({"preserve": false, "sha256": sha256_hex(&data)}));
        }
        let key = format!("{PROJECT}/secrets/panel-master-key");
        write(&host(&self.root, &key), b"keep me\n");
        ownership.insert(key, json!({"preserve": true, "sha256": sha256_hex(b"keep me\n")}));
        checkpoint.insert("ownership".into(), Value::Object(ownership));
        Ok(checkpoint)
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        ok(action, "core files verified")
    }

    fn repair(&self, _action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        Ok(checkpoint)
    }

    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        _t: RollbackTarget,
    ) -> Result<Evidence, Error> {
        remove_owned(&self.root, &checkpoint, purge);
        ok(action, "core files removed")
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        t: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.rollback(action, checkpoint, purge, t)
    }
}

/// The version-agent adapter: top-level `source/version_agent/*.py`, the unit, the tmpfiles
/// file and the mutable env.
pub struct FakeAgent {
    pub root: PathBuf,
    pub source: PathBuf,
}

pub const PYTHON_UNIT: &[u8] = b"[Service]\nExecStart=/usr/bin/python3 -m version_agent.server\n";

impl Adapter for FakeAgent {
    fn name(&self) -> &str {
        "version_agent"
    }

    fn requires(&self) -> &[&'static str] {
        &["core"]
    }

    fn plan(&self, _config: &InstallerConfig, _facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        Ok(vec![action("version_agent.runtime", "version_agent")])
    }

    fn prepare(&self, _action: &Action) -> Result<CheckpointData, Error> {
        Ok(Map::new())
    }

    fn apply(&self, _action: &Action, mut checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let mut ownership = Map::new();
        let mut entries: Vec<_> =
            fs::read_dir(self.source.join("version_agent"))?.map(|entry| entry.unwrap().path()).collect();
        entries.sort();
        for source in entries.into_iter().filter(|path| path.extension().is_some_and(|ext| ext == "py")) {
            let data = fs::read(&source)?;
            let path = format!("{AGENT_CODE}/{}", source.file_name().unwrap().to_string_lossy());
            write(&host(&self.root, &path), &data);
            ownership.insert(path, json!(sha256_hex(&data)));
        }
        for (path, data) in
            [(UNIT, PYTHON_UNIT), (TMPFILES, b"d /var/lib/proxy-control/version-agent 0700 root root -\n" as &[u8])]
        {
            write(&host(&self.root, path), data);
            ownership.insert(path.into(), json!(sha256_hex(data)));
        }
        let env = b"VERSION_AGENT_COMPOSE_DIR=/opt/mtproxy-shared443\n";
        write(&host(&self.root, ENV), env);
        ownership.insert(ENV.into(), json!({"mutable": true, "sha256": sha256_hex(env)}));
        checkpoint.insert("ownership".into(), Value::Object(ownership));
        Ok(checkpoint)
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        ok(action, "agent verified")
    }

    fn repair(&self, _action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        Ok(checkpoint)
    }

    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        _t: RollbackTarget,
    ) -> Result<Evidence, Error> {
        remove_owned(&self.root, &checkpoint, purge);
        ok(action, "agent removed")
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        t: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.rollback(action, checkpoint, purge, t)
    }
}

/// A release tree like `_PanelHost`'s project (`tests/test_version_agent_panel.py:88`).
pub fn release_tree(directory: &Path, version: &str) {
    for (name, text) in [
        ("VERSION", format!("{version}\n")),
        ("panel/app.py", "old panel\n".into()),
        ("panel/static/js/app.js", "old js\n".into()),
        ("compose.yaml", "old compose\n".into()),
        ("naive_manager/app.py", "old naive\n".into()),
        ("mieru_manager/app.py", "same mieru\n".into()),
        ("version_agent/service.py", "old agent\n".into()),
        ("version_agent/catalog.py", "old catalog\n".into()),
    ] {
        write(&directory.join(name), text.as_bytes());
    }
}

/// An installed host: Core (and, with `with_agent`, the version-agent) applied through the
/// engine from a release tree under `<work>/source`. The project's `version_agent/` sources are
/// not part of Core's copy (the release keeps them apart).
pub struct OwnedHost {
    pub root: PathBuf,
    pub engine: TransactionEngine,
}

pub fn owned_host(root: &Path, work: &Path, with_agent: bool) -> OwnedHost {
    fs::create_dir_all(root).unwrap();
    let source = work.join("source");
    release_tree(&source, "0.10.0");
    let core_source = work.join("core-source");
    for name in ["VERSION", "panel", "compose.yaml", "naive_manager", "mieru_manager"] {
        copy_tree(&source.join(name), &core_source.join(name));
    }
    let mut adapters: Vec<Arc<dyn Adapter>> = vec![Arc::new(FakeCore { root: root.into(), source: core_source })];
    let mut actions = vec![action("core.runtime", "core")];
    if with_agent {
        adapters.push(Arc::new(FakeAgent { root: root.into(), source: source.clone() }));
        actions.push(action("version_agent.runtime", "version_agent"));
    }
    let engine = engine_for(root, adapters);
    let plan = plan_with(actions, Map::new());
    engine.apply(&plan, &plan.digest()).unwrap();
    OwnedHost { root: root.into(), engine }
}

pub fn copy_tree(source: &Path, destination: &Path) {
    if source.is_dir() {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            copy_tree(&entry.path(), &destination.join(entry.file_name()));
        }
    } else {
        write(destination, &fs::read(source).unwrap());
    }
}

/// Replaces `target` with a copy of `source` (what the agent's sync does).
pub fn replace_tree(source: &Path, target: &Path) {
    if target.is_dir() {
        fs::remove_dir_all(target).unwrap();
    } else if target.exists() {
        fs::remove_file(target).unwrap();
    }
    copy_tree(source, target);
}
