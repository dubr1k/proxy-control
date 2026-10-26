//! The journals the Python installer wrote (`tests/fixtures/host-golden/`): every one is read and
//! written back byte for byte, the interrupted install resumes to the recorded state, and the
//! recorded panel handoffs are reproduced.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pc_host::fs::{sha256_hex, PathIdentity, PathKind};
use pc_host::json;
use serde_json::{Map, Value};

use super::fakes::{host, write};
use crate::adapter::Adapter;
use crate::error::Error;
use crate::handoff::rebase_panel_ownership;
use crate::journal::{CheckpointData, RollbackTarget, Status, TransactionState};
use crate::migration::rebase_agent_ownership;
use crate::model::InstallerConfig;
use crate::planner::{Action, AuditFacts, Evidence, InstallPlan};
use crate::store::TransactionStore;
use crate::testkit::{engine_for, TempDir};

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden")
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn bytes(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(path.as_ref()).unwrap_or_else(|err| panic!("{}: {err}", path.as_ref().display()))
}

fn load(path: impl AsRef<Path>) -> Value {
    json::loads(&bytes(path)).unwrap()
}

fn state_of(directory: &Path) -> TransactionState {
    TransactionState::from_value(&load(directory.join("state.json"))).unwrap()
}

/// Every recorded journal directory (it holds a `state.json`).
fn journal_dirs() -> Vec<PathBuf> {
    fn visit(directory: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(directory).unwrap().map(|entry| entry.unwrap().path()).collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                if path.join("state.json").is_file() && path.join("plan.json").is_file() {
                    out.push(path.clone());
                }
                visit(&path, out);
            }
        }
    }
    let mut out = Vec::new();
    visit(&golden().join("journals"), &mut out);
    visit(&golden().join("installs"), &mut out);
    out
}

/// Copies a recorded journal into `<root>/var/lib/proxy-control/installer`.
fn install_journal(source: &Path, root: &Path) -> TransactionStore {
    let directory = host(root, pc_host::INSTALLER_PATH);
    for name in ["state.json", "plan.json", "ownership.json", "report.json"] {
        write(&directory.join(name), &bytes(source.join(name)));
    }
    TransactionStore::new(root).unwrap()
}

fn mode(path: &Path) -> String {
    format!("{:04o}", fs::metadata(path).unwrap().permissions().mode() & 0o7777)
}

#[test]
fn every_recorded_journal_is_read_and_written_back_byte_for_byte() {
    let directories = journal_dirs();
    assert!(directories.len() >= 19, "{directories:?}");
    for directory in directories {
        let name = directory.strip_prefix(golden()).unwrap().display().to_string();
        let state = state_of(&directory);
        assert_eq!(json::pretty2(&state.to_value()).as_bytes(), bytes(directory.join("state.json")), "{name}: state");

        let plan = InstallPlan::from_value(&load(directory.join("plan.json"))).unwrap();
        assert_eq!(plan.to_canonical_json().as_bytes(), bytes(directory.join("plan.json")), "{name}: plan");
        assert_eq!(plan.digest(), state.plan_digest, "{name}: digest");

        // The derived files are exactly what the engine derives from the state.
        let mut ownership = Map::new();
        ownership.insert("files".into(), crate::journal::ownership_to_value(&state.ownership(true).unwrap()));
        ownership.insert("schema".into(), Value::from(1));
        assert_eq!(
            json::pretty2(&Value::Object(ownership)).as_bytes(),
            bytes(directory.join("ownership.json")),
            "{name}: ownership"
        );
        assert_eq!(
            json::pretty2(&state.report_value()).as_bytes(),
            bytes(directory.join("report.json")),
            "{name}: report"
        );

        // Through the store: read, write back, same bytes and the recorded modes.
        let dir = TempDir::new("golden");
        let store = install_journal(&directory, dir.path());
        let read_state = store.read_state().unwrap();
        let read_plan = store.read_plan().unwrap();
        let read_ownership = store.read_ownership().unwrap();
        store.write_state(&read_state).unwrap();
        store.write_plan(&read_plan).unwrap();
        store.write_ownership(&read_ownership).unwrap();
        store.write_report(&read_state.report_value()).unwrap();
        for file in ["state.json", "plan.json", "ownership.json", "report.json"] {
            assert_eq!(
                bytes(store.directory().join(file)),
                bytes(directory.join(file)),
                "{name}: {file} through the store"
            );
        }
        let modes = load(directory.join("modes.json"));
        // `nginx/` holds the nginx adapter's own backups, not the engine's journal.
        for (file, expected) in modes.as_object().unwrap().iter().filter(|(file, _)| !file.starts_with("nginx")) {
            assert_eq!(&Value::String(mode(&store.directory().join(file))), expected, "{name}: mode of {file}");
        }
    }
}

#[test]
fn the_recorded_lifecycle_outcomes_read_as_python_left_them() {
    let rolled_back = state_of(&golden().join("journals/rolled-back"));
    assert_eq!((rolled_back.status, rolled_back.error.as_deref()), (Status::RolledBack, Some("AcceptanceError")));
    assert_eq!(state_of(&golden().join("journals/uninstalled")).status, Status::Uninstalled);
    let purged = state_of(&golden().join("journals/uninstalled-purged"));
    assert_eq!((purged.status, purged.purge_data), (Status::Uninstalled, Some(true)));
    assert_eq!(state_of(&golden().join("journals/repaired")).status, Status::Active);
    let summary = load(golden().join("journals/home-like/summary.json"));
    let home = state_of(&golden().join("journals/home-like/journal"));
    assert_eq!(summary["status"], home.status.as_str());
    assert_eq!(summary["checkpoints"].as_array().unwrap().len(), home.checkpoints.len());
}

// ------------------------------------------------------------------------------------------
// Resume of `journals/interrupted/applying` (a crash inside `mieru.runtime`).
// ------------------------------------------------------------------------------------------

/// Replays what the Python adapters did on resume: `reconcile_apply`/`apply` return the data
/// the recorded run ended with, `verify` its evidence. The engine does the rest (ownership
/// capture against the files, phases, persistence) and must land on the recorded bytes.
struct Replay {
    name: String,
    resumed: TransactionState,
}

impl Replay {
    fn data(&self, action: &Action) -> CheckpointData {
        self.resumed.checkpoint(&action.id).unwrap().data.clone()
    }
}

impl Adapter for Replay {
    fn name(&self) -> &str {
        &self.name
    }
    fn plan(&self, _: &InstallerConfig, _: &AuditFacts) -> Result<Vec<Action>, Error> {
        unreachable!("resume never plans")
    }
    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        Ok(self.data(action))
    }
    fn apply(&self, action: &Action, _: CheckpointData) -> Result<CheckpointData, Error> {
        Ok(self.data(action))
    }
    fn reconcile_apply(&self, action: &Action, _: CheckpointData) -> Result<CheckpointData, Error> {
        Ok(self.data(action))
    }
    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        Ok(Evidence::from_map(self.resumed.checkpoint(&action.id).unwrap().evidence.as_ref().unwrap())?)
    }
    fn repair(&self, _: &Action, _: CheckpointData) -> Result<CheckpointData, Error> {
        unreachable!()
    }
    fn rollback(&self, _: &Action, _: CheckpointData, _: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        unreachable!("the recorded resume never rolled back")
    }
    fn reconcile_rollback(&self, _: &Action, _: CheckpointData, _: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        unreachable!("the recorded resume never rolled back")
    }
}

/// The bytes of every file `mieru.runtime` and `version_agent.runtime` own after the resume,
/// rebuilt from the recording's inputs (README "Determinism"): copies of release files, the
/// seeded token, markers named in the checkpoint data, and the files the install snapshot kept.
fn interrupted_host_files(resumed: &TransactionState) -> BTreeMap<String, Vec<u8>> {
    let mieru = &resumed.checkpoint("mieru.runtime").unwrap().data;
    let agent = &resumed.checkpoint("version_agent.runtime").unwrap().data;
    let line = |value: &Value| format!("{}\n", value.as_str().unwrap()).into_bytes();
    let snapshot = golden().join("installs/core-mieru/root/files");
    let mut files = BTreeMap::new();
    // Release-tree copies.
    for (host_path, source) in [
        ("/etc/systemd/system/mita.service", "deploy/mita.service"),
        ("/etc/systemd/system/mita@.service", "deploy/mita@.service"),
        ("/etc/tmpfiles.d/mita.conf", "deploy/mita.tmpfiles.conf"),
        ("/usr/local/libexec/prepare-mieru-state", "scripts/prepare-mieru-state.sh"),
        ("/usr/local/libexec/prepare-mieru-token", "scripts/prepare_mieru_token.py"),
        ("/etc/systemd/system/version-agent.service", "deploy/version-agent.service"),
        ("/etc/tmpfiles.d/proxy-control-version-agent.conf", "deploy/proxy-control-version-agent.tmpfiles.conf"),
    ] {
        files.insert(host_path.to_string(), bytes(repo().join(source)));
    }
    for name in
        ["__init__", "artifacts", "catalog", "host", "hostmetrics", "metrics_ports", "server", "service", "upstream"]
    {
        files.insert(
            format!("/opt/proxy-control/version_agent/{name}.py"),
            format!("# golden stand-in for version_agent/{name}.py\n").into_bytes(),
        );
    }
    // Files the installs snapshot kept verbatim (same bytes in every core-mieru install).
    for host_path in [
        "/usr/bin/mita",
        "/usr/share/doc/mita/copyright",
        "/etc/proxy-control/version-agent.env",
        "/opt/mtproxy-shared443/.env.mieru",
    ] {
        files.insert(host_path.to_string(), bytes(snapshot.join(host_path.trim_start_matches('/'))));
    }
    // Seeded: the 123rd draw of `host-golden:journal:interrupted`, and the markers.
    let token = sha256_hex(b"host-golden:journal:interrupted:123");
    files.insert("/etc/mieru-manager/token".into(), format!("{token}\n").into_bytes());
    files.insert("/etc/proxy-control/mieru-owned".into(), line(&mieru["marker_value"]));
    files.insert("/etc/proxy-control/mieru-acceptance-owner".into(), line(&mieru["acceptance_name"]));
    files.insert("/etc/proxy-control/version-agent-owned".into(), line(&agent["marker_value"]));
    files
}

#[test]
fn resume_of_the_interrupted_install_reaches_the_recorded_state() {
    let applying = golden().join("journals/interrupted/applying");
    let resumed_dir = golden().join("journals/interrupted/resumed");
    let resumed = state_of(&resumed_dir);
    let dir = TempDir::new("interrupted");
    let root = dir.path();
    let store = install_journal(&applying, root);
    assert_eq!(store.read_state().unwrap().status, Status::Applying);
    for (host_path, data) in interrupted_host_files(&resumed) {
        let recorded = &resumed.ownership(true).unwrap()[&host_path];
        assert_eq!(sha256_hex(&data), recorded.sha256, "{host_path}: the stand-in no longer matches the recording");
        write(&host(root, &host_path), &data);
    }
    let names: Vec<String> = store.read_plan().unwrap().adapter_order;
    drop(store);
    let adapters: Vec<Arc<dyn Adapter>> = names
        .iter()
        .map(|name| Arc::new(Replay { name: name.clone(), resumed: resumed.clone() }) as Arc<dyn Adapter>)
        .collect();
    let engine = engine_for(root, adapters);

    let state = engine.resume().unwrap();

    assert_eq!(state, resumed);
    for file in ["state.json", "ownership.json", "report.json", "plan.json"] {
        assert_eq!(bytes(engine.store().directory().join(file)), bytes(resumed_dir.join(file)), "{file}");
    }
    // The CLI's summary of the same run (`resume --json`) names the same phases.
    let stdout: Value =
        serde_json::from_str(load(golden().join("journals/interrupted/resume.json"))["stdout"].as_str().unwrap())
            .unwrap();
    assert_eq!(stdout["status"], "active");
    let phases: Vec<(String, String)> = stdout["checkpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| (item["action_id"].as_str().unwrap().into(), item["phase"].as_str().unwrap().into()))
        .collect();
    let ours: Vec<(String, String)> =
        state.checkpoints.iter().map(|item| (item.action_id.clone(), item.phase.as_str().into())).collect();
    assert_eq!(phases, ours);
}

// ------------------------------------------------------------------------------------------
// The recorded panel handoffs (`panel_update` of the recorder).
// ------------------------------------------------------------------------------------------

fn file(data: &[u8]) -> PathIdentity {
    PathIdentity { kind: PathKind::File, sha256: sha256_hex(data) }
}

/// What the recorder staged for a panel update to `version`: the stand-in sources, a new panel
/// stand-in and file, the version, and the agent code with a changed `service.py`.
fn staged_identities(before: &TransactionState, version: &str) -> BTreeMap<String, PathIdentity> {
    let mut expected = BTreeMap::new();
    let project = "/opt/mtproxy-shared443";
    expected.insert(format!("{project}/VERSION"), file(format!("{version}\n").as_bytes()));
    expected.insert(
        format!("{project}/panel/GOLDEN-STAND-IN"),
        file(format!("golden stand-in for panel/ (release {version})\n").as_bytes()),
    );
    expected.insert(
        format!("{project}/panel/added-in-{version}.txt"),
        file(format!("a file new in {version}\n").as_bytes()),
    );
    for name in ["installer", "pc_common"] {
        expected.insert(
            format!("{project}/{name}/GOLDEN-STAND-IN"),
            file(format!("golden stand-in for {name}/\n").as_bytes()),
        );
    }
    // compose.yaml is the release's own file, unchanged by the update.
    let compose =
        before.checkpoint("core.runtime").unwrap().ownership[&format!("{project}/compose.yaml")].sha256.clone();
    expected.insert(format!("{project}/compose.yaml"), PathIdentity { kind: PathKind::File, sha256: compose });
    let agent = before.checkpoint("version_agent.runtime").unwrap();
    for path in agent.ownership.keys().filter(|path| path.starts_with("/opt/proxy-control/version_agent/")) {
        let name = path.rsplit('/').next().unwrap();
        let text = if name == "service.py" {
            format!("# golden stand-in for version_agent/service.py ({version})\n")
        } else {
            format!("# golden stand-in for version_agent/{name}\n")
        };
        expected.insert(path.clone(), file(text.as_bytes()));
    }
    expected
}

fn names(update: &Value) -> Vec<String> {
    update["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .filter(|n| n != "version_agent")
        .collect()
}

fn assert_journal_bytes(state: &TransactionState, directory: &Path) {
    assert_eq!(json::pretty2(&state.to_value()).as_bytes(), bytes(directory.join("state.json")), "state");
    let mut ownership = Map::new();
    ownership.insert("files".into(), crate::journal::ownership_to_value(&state.ownership(true).unwrap()));
    ownership.insert("schema".into(), Value::from(1));
    assert_eq!(
        json::pretty2(&Value::Object(ownership)).as_bytes(),
        bytes(directory.join("ownership.json")),
        "ownership"
    );
    assert_eq!(json::pretty2(&state.report_value()).as_bytes(), bytes(directory.join("report.json")), "report");
}

#[test]
fn the_recorded_handoff_is_reproduced_from_before_to_after() {
    let update = load(golden().join("journals/handoff/update.json"));
    let before = state_of(&golden().join("journals/handoff/before"));
    let version = update["version"].as_str().unwrap();
    let expected = staged_identities(&before, version);
    let after = rebase_panel_ownership(&before, &names(&update), &expected, true).unwrap();
    assert_journal_bytes(&after, &golden().join("journals/handoff/after"));
}

#[test]
fn the_home_like_journal_is_reproduced_by_two_handoffs() {
    let installed = state_of(&golden().join("journals/home-like/installed"));
    let names: Vec<String> =
        ["panel", "installer", "pc_common", "compose.yaml", "VERSION"].iter().map(|s| s.to_string()).collect();
    let first = rebase_panel_ownership(&installed, &names, &staged_identities(&installed, "3.2.1"), true).unwrap();
    let second = rebase_panel_ownership(&first, &names, &staged_identities(&first, "3.3.0"), true).unwrap();
    assert_journal_bytes(&second, &golden().join("journals/home-like/journal"));
}

#[test]
fn the_agent_migration_rebases_the_home_like_journal() {
    // The `home` host is the one production host with a journal: its agent checkpoint (3.x code
    // under /opt/proxy-control/version_agent/*.py) is rebased onto a 4.0 tree and a new unit.
    let before = state_of(&golden().join("journals/home-like/journal"));
    let code = "/opt/proxy-control/version_agent";
    let mut expected = BTreeMap::new();
    for (name, data) in [
        ("bin/linux-amd64/proxy-control-version-agent", &b"\x7fELF rust agent"[..]),
        ("Cargo.toml", b"[package]\nname = \"version_agent\"\n"),
        ("src/main.rs", b"fn main() {}\n"),
    ] {
        expected.insert(format!("{code}/{name}"), file(data));
    }
    let unit = crate::migration::AGENT_UNIT.to_string();
    let rehashed: BTreeMap<String, PathIdentity> = [(
        unit.clone(),
        file(b"[Service]\nExecStart=/opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent\n"),
    )]
    .into_iter()
    .collect();
    let after = rebase_agent_ownership(&before, &expected, &rehashed).unwrap();
    after.validate().unwrap();
    let agent_before = before.checkpoint("version_agent.runtime").unwrap();
    let agent = after.checkpoint("version_agent.runtime").unwrap();
    assert!(agent.ownership.keys().all(|path| !path.ends_with(".py")));
    assert_eq!(agent.ownership[&format!("{code}/src/main.rs")].sha256, sha256_hex(b"fn main() {}\n"));
    assert_eq!(agent.ownership[&unit].sha256, rehashed[&unit].sha256);
    assert_eq!(agent.data["ownership"][&unit], Value::String(rehashed[&unit].sha256.clone()));
    // Everything else, the env and the other checkpoints included, is untouched.
    let env = crate::migration::AGENT_ENV;
    assert_eq!(agent.ownership[env], agent_before.ownership[env]);
    assert_eq!(agent.data["ownership"][env], agent_before.data["ownership"][env]);
    for (left, right) in before.checkpoints.iter().zip(&after.checkpoints) {
        if left.action_id != "version_agent.runtime" {
            assert_eq!(left, right);
        }
    }
    // The rebased state round-trips and its derived journal has no duplicate path.
    assert_eq!(TransactionState::from_value(&after.to_value()).unwrap(), after);
    after.ownership(true).unwrap();
}
