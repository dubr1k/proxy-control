//! Ported from `tests/test_version_agent_panel.py` (agent side), `tests/test_version_agent_managers.py`
//! (the rebuild after a panel update) and `tests/test_version_agent_update_safety.py`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use serde_json::{json, Value};

use super::journal::{self, AGENT_CODE, PROJECT, UNIT};
use super::*;
use crate::errors::{AgentError, UpdateState};
use crate::runner::{Command, CommandError};
use crate::service::{AgentConfig, VersionAgent};
use crate::testutil::TempDir;
use crate::updater::panel::tree_hash;

const OLD_PANEL: &str = "0.10.0-beta.1";
const NEW_PANEL: &str = "0.11.0-beta.1";
const PANEL_URL: &str =
    "https://github.com/dubr1k/proxy-control/releases/download/v0.11.0-beta.1/proxy-control-v0.11.0-beta.1.tar.gz";
const PANEL_EXEC: [&str; 5] = ["docker", "exec", "proxy-control-panel", "cat", "/app/VERSION"];
const ROUTER_OVERLAY: &str = "services:\n  xray-router:\n    image: x\n  xray-router-ingress:\n    image: x\n";
const OLD: &str = "2020-01-01T00:00:00.123456789Z";
const RESTART: [&str; 6] = [
    "systemd-run",
    "--on-active=5",
    "--unit=proxy-control-version-agent-restart",
    "systemctl",
    "restart",
    "version-agent",
];

fn panel_image_id() -> String {
    format!("sha256:{}", "a".repeat(64))
}

/// `_release_tar(entries)`: a release archive, each member with its mode.
pub(crate) fn release_tar(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (name, data, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_size(data.len() as u64);
        header.set_mode(*mode);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, *data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// `_panel_archive(naive=…, agent=…)`.
fn panel_archive(naive: &[u8], agent: &[u8]) -> Vec<u8> {
    let version = format!("{NEW_PANEL}\n");
    release_tar(&[
        ("proxy-control/VERSION", version.as_bytes(), 0o644),
        ("proxy-control/panel/app.py", b"new panel\n", 0o644),
        ("proxy-control/panel/static/js/app.js", b"new js\n", 0o644),
        ("proxy-control/compose.yaml", b"new compose\n", 0o644),
        ("proxy-control/scripts/tool.sh", b"#!/bin/sh\n", 0o755),
        ("proxy-control/naive_manager/app.py", naive, 0o644),
        ("proxy-control/mieru_manager/app.py", b"same mieru\n", 0o644),
        ("proxy-control/version_agent/service.py", agent, 0o644),
        // Never synced: the release tree has no secrets, but the sync set must not even look.
        ("proxy-control/secrets/panel-master-key", b"from the archive\n", 0o644),
        ("proxy-control/.env", b"FROM=archive\n", 0o644),
        ("proxy-control/tests/test_x.py", b"not synced\n", 0o644),
    ])
}

fn default_archive() -> Vec<u8> {
    panel_archive(b"changed naive\n", b"new agent\n")
}

fn hex_id(service: &str) -> String {
    service.bytes().map(|b| format!("{b:02x}")).collect::<String>().repeat(64)[..64].to_string()
}

fn iso(epoch: i64) -> String {
    let (year, month, day) = pc_common::logger::civil_from_days(epoch.div_euclid(86_400));
    let rest = epoch.rem_euclid(86_400);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000000001Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

fn now() -> i64 {
    crate::hostmetrics::wall_clock() as i64
}

type Intercept = Box<dyn Fn(&[String], &mut State) -> Option<Result<String, CommandError>> + Send>;

/// What the fake host knows (`_PanelHost` + `ManagerHost`).
pub(crate) struct State {
    pub commands: Vec<Vec<String>>,
    pub running_services: Vec<String>,
    pub project: String,
    pub container_version: Option<String>,
    pub migrate: bool,
    pub running: String,
    /// Compose service → its container's image creation time (`ManagerHost.created`).
    pub created: BTreeMap<String, String>,
    pub health: BTreeMap<String, String>,
    pub fail_up: bool,
    pub sleeps: Vec<f64>,
    pub payload: Vec<u8>,
    /// Services that start running while the archive downloads.
    pub services_on_download: Option<Vec<String>>,
    /// Runs before the host's own answer (the tests' replacement runners).
    pub intercept: Option<Intercept>,
}

/// A fake host: the compose dir, the agent dir, the panel volume and a runner that answers
/// `docker` like the real one would. The container reads the VERSION it was created with, so
/// `running` changes on `up` only.
#[derive(Clone)]
pub(crate) struct PanelHost {
    pub dir: PathBuf,
    pub compose: PathBuf,
    pub agent_dir: PathBuf,
    pub volume: PathBuf,
    pub state: Arc<Mutex<State>>,
    pub host: Host,
}

impl PanelHost {
    fn with_layout(dir: &Path, compose: PathBuf, agent_dir: PathBuf, files: bool) -> PanelHost {
        if files {
            for (name, text) in [
                ("VERSION", format!("{OLD_PANEL}\n")),
                ("panel/app.py", "old panel\n".into()),
                ("panel/static/js/app.js", "old js\n".into()),
                ("compose.yaml", "old compose\n".into()),
                ("naive_manager/app.py", "old naive\n".into()),
                ("mieru_manager/app.py", "same mieru\n".into()),
                ("secrets/panel-master-key", "keep me\n".into()),
            ] {
                write(&compose.join(name), text.as_bytes());
            }
            write(&agent_dir.join("version_agent/service.py"), b"old agent\n");
        }
        write(&compose.join(".env"), b"KEEP=1\n");
        write(&compose.join("version-overrides/compose.versions.yaml"), b"keep\n");
        let volume = dir.join("volume");
        write(&volume.join("panel.sqlite3"), b"db-old");
        write(&volume.join("panel.sqlite3-wal"), b"wal-old");
        let state = Arc::new(Mutex::new(State {
            commands: Vec::new(),
            running_services: Vec::new(),
            project: "proxy_panel_by_dubr1k".into(),
            container_version: None,
            migrate: false,
            running: format!("{OLD_PANEL}\n"),
            created: BTreeMap::new(),
            health: BTreeMap::new(),
            fail_up: false,
            sleeps: Vec::new(),
            payload: Vec::new(),
            services_on_download: None,
            intercept: None,
        }));
        let (shared, compose_dir, volume_dir) = (state.clone(), compose.clone(), volume.clone());
        let host = Host::new(move |command: &Command| {
            let mut state = shared.lock().unwrap();
            if let Some(intercept) = state.intercept.take() {
                let answer = intercept(&command.argv, &mut state);
                state.intercept = Some(intercept);
                if let Some(answer) = answer {
                    return answer;
                }
            }
            answer(&command.argv, &mut state, &compose_dir, &volume_dir)
        });
        PanelHost { dir: dir.to_path_buf(), compose, agent_dir, volume, state, host }
    }

    /// `_PanelHost(tmp_path)`: the project in `<dir>/compose`, the agent in `<dir>/agent`.
    pub fn new(dir: &Path) -> PanelHost {
        PanelHost::with_layout(dir, dir.join("compose"), dir.join("agent"), true)
    }

    /// The project and the agent where an installer root `dir` keeps them, installed through the
    /// engine (`_owned_panel_host`); `None` for the agent installs Core only.
    pub fn owned(dir: &Path, with_agent: bool) -> (PanelHost, installer::TransactionEngine) {
        let source = dir.join("release-source");
        for (name, text) in [
            ("VERSION", format!("{OLD_PANEL}\n")),
            ("panel/app.py", "old panel\n".into()),
            ("panel/static/js/app.js", "old js\n".into()),
            ("compose.yaml", "old compose\n".into()),
            ("naive_manager/app.py", "old naive\n".into()),
            ("mieru_manager/app.py", "same mieru\n".into()),
        ] {
            write(&source.join("project").join(name), text.as_bytes());
        }
        write(&source.join("version_agent/service.py"), b"old agent\n");
        write(&source.join("version_agent/catalog.py"), b"old catalog\n");
        let agent_source = source.join("version_agent");
        let engine = journal::install(dir, &source.join("project"), with_agent.then_some(agent_source.as_path()));
        if !with_agent {
            write(&journal::host(dir, AGENT_CODE).join("service.py"), b"old agent\n");
        }
        let host = PanelHost::with_layout(dir, journal::host(dir, PROJECT), dir.join("opt/proxy-control"), false);
        (host, engine)
    }

    pub fn set(&self, change: impl FnOnce(&mut State)) {
        change(&mut self.state.lock().unwrap());
    }

    pub fn commands(&self) -> Vec<Vec<String>> {
        self.state.lock().unwrap().commands.clone()
    }

    pub fn clear(&self) {
        self.state.lock().unwrap().commands.clear();
    }

    pub fn running(&self) -> String {
        self.state.lock().unwrap().running.clone()
    }

    /// `host.agent(payload, **extra)`: the catalog of the Python tests, the panel candidate from
    /// the upstream cache (its digest is the payload's), synchronous.
    pub fn agent(
        &self,
        payload: Vec<u8>,
        configure: impl FnOnce(&mut AgentConfig),
    ) -> (Arc<VersionAgent>, HostUpdater) {
        let digest = sha(&payload);
        self.set(|state| state.payload = payload);
        write(&self.dir.join("catalog.json"), br#"{"schema": 1, "components": {}}"#);
        let mut config = AgentConfig::new(self.dir.join("catalog.json"), self.dir.join("state.json"));
        config.compose_dir = Some(self.compose.clone());
        config.compose_files = vec!["compose.yaml".into()];
        config.agent_dir = self.agent_dir.clone();
        config.synchronous = true;
        configure(&mut config);
        let shared = self.state.clone();
        let mut updater = HostUpdater::with_downloader(move |_, _| {
            let mut state = shared.lock().unwrap();
            if let Some(services) = state.services_on_download.take() {
                state.running_services = services;
            }
            Ok(state.payload.clone())
        });
        let sleeps = self.state.clone();
        updater.sleep = Arc::new(move |seconds| sleeps.lock().unwrap().sleeps.push(seconds));
        updater.machine = "x86_64".into();
        let mut agent = VersionAgent::new(config);
        agent.runner = Arc::new(self.host.clone());
        agent.updater = Arc::new(updater.clone());
        let candidate = json!({"version": NEW_PANEL, "tag": format!("v{NEW_PANEL}"), "kind": "release", "source": "upstream",
                               "url": PANEL_URL, "sha256": digest, "published_at": "2026-09-21T00:00:00Z"});
        agent.checker = Box::new(move |_, _, _| {
            json!({"panel": {"latest": NEW_PANEL, "installable": true, "reason": null, "candidates": [candidate.clone()]}})
                .as_object()
                .unwrap()
                .clone()
        });
        let agent = Arc::new(agent);
        agent.check_upstream(false).unwrap();
        self.clear();
        (agent, updater)
    }

    /// `ManagerHost(tmp_path, services=…, created=…)`: containers per Compose service and the
    /// router overlay.
    pub fn with_managers(self, services: &[&str], created: &str) -> PanelHost {
        write(&self.compose.join("compose.xray-router.yaml"), ROUTER_OVERLAY.as_bytes());
        self.set(|state| {
            state.created = services.iter().map(|s| (s.to_string(), created.to_string())).collect();
        });
        self
    }
}

/// The host's answers (`_PanelHost.run` with `ManagerHost.run` in front).
fn answer(argv: &[String], state: &mut State, compose: &Path, volume: &Path) -> Result<String, CommandError> {
    let owned: Vec<String> = argv.to_vec();
    // ManagerHost
    if starts(argv, &["docker", "ps", "-a"]) {
        let filter = argv.iter().enumerate().skip(5).find(|(_, a)| *a == "--filter").map(|(i, _)| i).unwrap();
        let service = argv[filter + 1].rsplit_once('=').unwrap().1.to_string();
        state.commands.push(owned);
        return Ok(if state.created.contains_key(&service) { hex_id(&service) } else { String::new() });
    }
    let last = argv.last().map(String::as_str).unwrap_or("");
    if starts(argv, &["docker", "inspect"]) && last != "proxy-control-panel" && !last.starts_with("sha256") {
        if let Some(service) = state.created.keys().find(|s| hex_id(s) == last).cloned() {
            state.commands.push(owned);
            if has(argv, "{{.Image}}") {
                return Ok(format!("sha256:{}", hex_id(&service)));
            }
            return Ok(state.health.get(&service).cloned().unwrap_or_else(|| "healthy".into()));
        }
    }
    if starts(argv, &["docker", "image", "inspect"]) {
        state.commands.push(owned);
        let service = state.created.keys().find(|s| format!("sha256:{}", hex_id(s)) == last).cloned().unwrap();
        return Ok(state.created[&service].clone());
    }
    if starts(argv, &["docker", "compose"]) && has(argv, "--build") {
        state.commands.push(owned);
        if state.fail_up {
            return Err(runtime_error("build failed"));
        }
        let services: Vec<String> = state.created.keys().filter(|s| has(argv, s)).cloned().collect();
        for service in services {
            state.created.insert(service, iso(now()));
        }
        return Ok(String::new());
    }
    // _PanelHost
    if starts(argv, &["docker", "inspect", "--format"])
        && last == "proxy-control-panel"
        && argv[3].contains("com.docker.compose.project")
    {
        return Ok(state.project.clone());
    }
    state.commands.push(owned);
    let ps = format!("label=com.docker.compose.project={}", state.project);
    if is(argv, &["docker", "ps", "--filter", &ps, "--format", "{{.Label \"com.docker.compose.service\"}}"]) {
        return Ok(state.running_services.join("\n"));
    }
    if starts(argv, &["docker", "volume", "inspect"]) {
        return Ok(path_text(volume));
    }
    if is(argv, &["docker", "inspect", "--format", "{{.Image}}", "proxy-control-panel"]) {
        return Ok(panel_image_id());
    }
    let version_file = || std::fs::read_to_string(compose.join("VERSION")).unwrap_or_default();
    if starts(argv, &["docker", "compose"]) && has(argv, "up") && state.migrate && version_file().trim() == NEW_PANEL {
        // A newer panel migrates the database at start-up; the restored one does not.
        std::fs::write(volume.join("panel.sqlite3"), b"db-migrated").unwrap();
        std::fs::write(volume.join("panel.sqlite3-shm"), b"shm-new").unwrap();
    }
    if starts(argv, &["docker", "compose"]) && has(argv, "up") {
        state.running = state.container_version.clone().unwrap_or_else(version_file);
    }
    if is(argv, &PANEL_EXEC) {
        return Ok(state.running.clone());
    }
    Ok(String::new())
}

/// `_verbs(commands)`.
fn verbs(commands: &[Vec<String>]) -> Vec<&'static str> {
    let mut verbs = Vec::new();
    for command in commands {
        if starts(command, &["docker", "compose"]) {
            for word in &command[2..] {
                if let Some(verb) = ["build", "stop", "up"].into_iter().find(|v| word == v) {
                    verbs.push(verb);
                    break;
                }
            }
        } else if starts(command, &["docker", "tag"]) {
            verbs.push("tag");
        } else if is(command, &PANEL_EXEC) {
            verbs.push("exec");
        } else if command[0] == "systemd-run" {
            verbs.push("systemd-run");
        }
    }
    verbs
}

/// `_mutations(commands)`: everything but «which version is running» and `docker ps`.
fn mutations(commands: &[Vec<String>]) -> Vec<Vec<String>> {
    commands.iter().filter(|c| !is(c, &PANEL_EXEC) && !starts(c, &["docker", "ps"])).cloned().collect()
}

fn panel_state(dir: &Path) -> Value {
    state_json(&dir.join("state.json"))["components"]["panel"].clone()
}

fn write_panel(dir: &Path, panel: Value) {
    let mut data = state_json(&dir.join("state.json"));
    data["components"]["panel"] = panel;
    write(&dir.join("state.json"), data.to_string().as_bytes());
}

fn update_panel(agent: &Arc<VersionAgent>) -> Result<Value, AgentError> {
    agent.update("panel", NEW_PANEL, Some(OLD_PANEL))
}

fn update_error(result: Result<Value, AgentError>) -> crate::UpdateError {
    match result {
        Err(AgentError::Update(error)) => error,
        other => panic!("expected an UpdateError, got {other:?}"),
    }
}

fn version_text(host: &PanelHost) -> String {
    text(&host.compose.join("VERSION"))
}

// --- tests/test_version_agent_panel.py ---------------------------------------------------------

#[test]
fn panel_current_is_the_running_container_and_the_state_carries_the_status() {
    let dir = TempDir::new("panel-current");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    let listed = agent.list_versions(true).unwrap()["components"]["panel"].clone();
    assert_eq!((&listed["current"], &listed["status"]), (&json!(OLD_PANEL), &json!("ready")));
    assert_eq!(listed["available"].as_array().unwrap().len(), 1);
    assert_eq!(
        (&listed["available"][0]["version"], &listed["available"][0]["kind"], &listed["available"][0]["source"]),
        (&json!(NEW_PANEL), &json!("release"), &json!("upstream"))
    );
    assert!(matches!(agent.update("panel", NEW_PANEL, Some("0.9.0-beta.1")), Err(AgentError::Conflict(_))));
    let error = agent.update("panel", "0.12.0-beta.1", Some(OLD_PANEL)).unwrap_err();
    assert!(matches!(&error, AgentError::Catalog(e) if e.0.contains("not approved")), "{error:?}");
    write(&host.compose.join("VERSION"), format!("{NEW_PANEL}\n").as_bytes());
    host.set(|state| state.running = format!("{NEW_PANEL}\n")); // already running: nothing to do
    assert_eq!(
        agent.update("panel", NEW_PANEL, Some(NEW_PANEL)).unwrap(),
        json!({"component": "panel", "version": NEW_PANEL, "changed": false})
    );
    assert!(mutations(&host.commands()).is_empty());
}

#[test]
fn direct_panel_update_refuses_omitted_running_optional_service() {
    for (service, overlay) in [("mcp", "compose.mcp.yaml"), ("mieru-manager", "compose.mieru.yaml")] {
        let dir = TempDir::new("panel-scope");
        let host = PanelHost::new(dir.path());
        host.set(|state| state.running_services = vec![service.into()]);
        let (agent, _) = host.agent(default_archive(), |_| {});
        let error = update_error(update_panel(&agent));
        assert!(error.message.contains(overlay), "{error:?}");
        assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
        assert!(!host.commands().iter().any(|c| has(c, "build")));
    }
}

#[test]
fn direct_panel_update_allows_declared_running_mcp() {
    let dir = TempDir::new("panel-mcp");
    let host = PanelHost::new(dir.path());
    host.set(|state| state.running_services = vec!["mcp".into()]);
    let (agent, _) = host.agent(default_archive(), |config| {
        config.compose_files = vec!["compose.yaml".into(), "compose.mcp.yaml".into()]
    });
    assert_eq!(update_panel(&agent).unwrap()["changed"], true);
}

#[test]
fn direct_panel_update_fails_closed_when_running_services_cannot_be_listed() {
    let dir = TempDir::new("panel-ps");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    host.set(|state| {
        state.intercept = Some(Box::new(|argv, _| {
            starts(argv, &["docker", "ps"]).then(|| Err(CommandError::Os("docker unavailable".into())))
        }))
    });
    let error = update_error(update_panel(&agent));
    assert_eq!(error.message, "could not determine running Compose services");
    assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
}

#[test]
fn panel_update_rechecks_compose_scope_after_download_before_tree_mutation() {
    let dir = TempDir::new("panel-recheck");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    host.set(|state| state.services_on_download = Some(vec!["mcp".into()]));
    let error = update_error(update_panel(&agent));
    assert!(error.message.contains("compose.mcp.yaml"), "{error:?}");
    assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
    assert!(!host.commands().iter().any(|c| has(c, "build")));
}

#[test]
fn panel_update_refuses_installer_lock_before_tree_mutation() {
    let dir = TempDir::new("panel-lock");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    let held = pc_host::operation_lock(dir.path()).unwrap();
    let error = update_error(update_panel(&agent));
    drop(held);
    assert_eq!(error.message, "another proxyctl operation is in progress");
    assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
    assert!(mutations(&host.commands()).is_empty());
    assert_eq!(panel_state(dir.path())["status"], "update_failed");
}

#[test]
fn panel_update_refuses_an_unreadable_installer_journal_before_mutation() {
    // Python refused an installer module loaded from elsewhere than the project; the compiled-in
    // handoff refuses a journal its strict reader does not accept (two-generation rule).
    let dir = TempDir::new("panel-journal");
    let host =
        PanelHost::with_layout(dir.path(), journal::host(dir.path(), PROJECT), dir.join("opt/proxy-control"), true);
    write(&dir.join("var/lib/proxy-control/installer/state.json"), b"{}");
    let (agent, _) = host.agent(default_archive(), |config| config.installer_root = Some(dir.path().to_path_buf()));
    let error = update_error(update_panel(&agent));
    assert_eq!(error.message, "panel update failed: transaction state is invalid");
    assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
    assert!(mutations(&host.commands()).is_empty());
}

#[test]
fn failed_panel_handoff_restores_tree_and_never_reports_ready() {
    let dir = TempDir::new("panel-handoff-fails");
    let (host, engine) = PanelHost::owned(dir.path(), false);
    let (agent, _) = host.agent(default_archive(), |config| config.installer_root = Some(dir.path().to_path_buf()));
    // Another writer changes the journal while the panel builds: the commit refuses.
    let root = dir.path().to_path_buf();
    host.set(|state| {
        state.intercept = Some(Box::new(move |argv, _| {
            if starts(argv, &["docker", "compose"]) && tail(argv, 2) == ["build", "panel"] {
                let store = installer::TransactionStore::new(&root).unwrap();
                let mut journal = store.read_state().unwrap();
                journal.error = Some("TransactionError".into());
                store.write_state(&journal).unwrap();
            }
            None
        }))
    });
    let error = update_error(update_panel(&agent));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert!(error.message.contains("installer transaction changed during panel update"), "{error:?}");
    assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
    assert_eq!(host.running().trim(), OLD_PANEL);
    let state = panel_state(dir.path());
    assert!(state["status"] != "ready" || state["version"] == OLD_PANEL);
    drop(engine);
}

#[test]
fn panel_update_rebases_active_core_for_repair_and_uninstall() {
    let dir = TempDir::new("panel-rebase");
    let (host, engine) = PanelHost::owned(dir.path(), false);
    let old = engine.store().read_state().unwrap();
    let (agent, _) = host.agent(default_archive(), |config| config.installer_root = Some(dir.path().to_path_buf()));
    update_panel(&agent).unwrap();
    let updated = engine.store().read_state().unwrap();
    assert_eq!(updated.plan_digest, old.plan_digest);
    let core = updated.checkpoint("core.runtime").unwrap();
    assert_eq!(
        core.data["ownership"]["/opt/mtproxy-shared443/VERSION"]["sha256"],
        json!(sha(format!("{NEW_PANEL}\n").as_bytes()))
    );
    assert!(core.ownership.contains_key("/opt/mtproxy-shared443/scripts/tool.sh"));
    assert_eq!(engine.repair().unwrap().status, installer::journal::Status::Active);
    assert_eq!(engine.uninstall(false).unwrap().status, installer::journal::Status::Uninstalled);
}

#[test]
fn panel_update_hands_off_installed_agent_package_together_with_core() {
    let dir = TempDir::new("panel-agent-handoff");
    let (host, engine) = PanelHost::owned(dir.path(), true);
    let before = engine.store().read_state().unwrap();
    let (agent, _) = host.agent(default_archive(), |config| config.installer_root = Some(dir.path().to_path_buf()));
    update_panel(&agent).unwrap();
    let after = engine.store().read_state().unwrap();
    assert_eq!(after.plan_digest, before.plan_digest);
    let checkpoint = after.checkpoint("version_agent.runtime").unwrap();
    let code = "/opt/proxy-control/version_agent/service.py";
    assert_eq!(checkpoint.ownership[code].sha256, sha(b"new agent\n"));
    assert!(!checkpoint.ownership.keys().any(|path| path.ends_with("/catalog.py")));
    assert!(checkpoint.ownership.contains_key(UNIT));
    engine.assert_all_owned(&after).unwrap();
    assert_eq!(engine.repair().unwrap().status, installer::journal::Status::Active);
    assert_eq!(engine.uninstall(false).unwrap().status, installer::journal::Status::Uninstalled);
    // The agent's tree changed: its restart is the last command.
    assert!(is(host.commands().last().unwrap(), &RESTART));
}

#[test]
fn panel_update_never_adopts_foreign_agent_code_or_unit() {
    for path in ["/opt/proxy-control/version_agent/service.py", UNIT] {
        let dir = TempDir::new("panel-foreign");
        let (host, engine) = PanelHost::owned(dir.path(), true);
        let before = engine.store().read_state().unwrap();
        write(&journal::host(dir.path(), path), b"foreign modification\n");
        let (agent, _) = host.agent(default_archive(), |config| config.installer_root = Some(dir.path().to_path_buf()));
        let error = update_error(update_panel(&agent));
        assert!(error.message.contains("drift"), "{error:?}");
        assert_eq!(engine.store().read_state().unwrap(), before);
        assert!(!host.commands().iter().any(|c| has(c, "build")));
    }
}

#[test]
fn a_version_file_ahead_of_the_running_panel_does_not_hide_the_update() {
    // Seen live: a project dir kept in sync from a working copy got the next release's files
    // (VERSION included) while the container still ran the previous build.
    let dir = TempDir::new("panel-ahead");
    let host = PanelHost::new(dir.path());
    write(&host.compose.join("VERSION"), format!("{NEW_PANEL}\n").as_bytes());
    let (agent, _) = host.agent(default_archive(), |_| {});
    let listed = agent.list_versions(true).unwrap()["components"]["panel"].clone();
    assert_eq!(listed["current"], OLD_PANEL);
    assert_eq!(listed["available"][0]["version"], NEW_PANEL);
    assert_eq!(update_panel(&agent).unwrap()["changed"], true);
    assert_eq!(panel_state(dir.path())["previous_version"], OLD_PANEL);
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["current"], NEW_PANEL);
}

#[test]
fn panel_current_falls_back_to_the_version_file_without_a_container() {
    let dir = TempDir::new("panel-fallback");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    host.set(|state| {
        state.intercept = Some(Box::new(|argv, _| {
            is(argv, &PANEL_EXEC).then(|| Err(runtime_error("No such container: proxy-control-panel")))
        }))
    });
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["current"], OLD_PANEL);
    host.set(|state| {
        state.intercept = None;
        state.running = String::new();
    });
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["current"], OLD_PANEL);
}

#[test]
fn panel_update_syncs_the_tree_backs_up_the_db_rebuilds_and_verifies() {
    let dir = TempDir::new("panel-sync");
    let host = PanelHost::new(dir.path());
    host.set(|state| state.migrate = true);
    let (agent, _) = host.agent(default_archive(), |_| {});
    assert_eq!(
        update_panel(&agent).unwrap(),
        json!({"component": "panel", "version": NEW_PANEL, "changed": true, "async": true})
    );
    // The sync set is replaced, everything else in the project dir is left alone.
    assert_eq!(version_text(&host), format!("{NEW_PANEL}\n"));
    assert_eq!(text(&host.compose.join("panel/app.py")), "new panel\n");
    assert_eq!(text(&host.compose.join("compose.yaml")), "new compose\n");
    assert_ne!(mode(&host.compose.join("scripts/tool.sh")) & 0o111, 0);
    assert_eq!(text(&host.compose.join("secrets/panel-master-key")), "keep me\n");
    assert_eq!(text(&host.compose.join(".env")), "KEEP=1\n");
    assert_eq!(text(&host.compose.join("version-overrides/compose.versions.yaml")), "keep\n");
    assert!(!host.compose.join("tests").exists());
    // Rollback copies: the previous tree and the previous database.
    let backups = dir.join("backups");
    assert_eq!(text(&backups.join("panel.previous/panel/app.py")), "old panel\n");
    assert_eq!(text(&backups.join("panel.previous/VERSION")), format!("{OLD_PANEL}\n"));
    assert_eq!(text(&backups.join("panel.previous/version_agent/service.py")), "old agent\n");
    assert_eq!(read(&backups.join("panel-db.previous/panel.sqlite3")), b"db-old");
    assert_eq!(read(&backups.join("panel-db.previous/panel.sqlite3-wal")), b"wal-old");
    assert!(!backups.join("panel-db.previous/panel.sqlite3-shm").exists());
    // The agent's own code follows the release; its restart is the very last command.
    assert_eq!(text(&host.agent_dir.join("version_agent/service.py")), "new agent\n");
    let commands = host.commands();
    assert_eq!(verbs(&commands), ["exec", "tag", "build", "stop", "up", "exec", "systemd-run"]);
    let tag = commands.iter().find(|c| starts(c, &["docker", "tag"])).unwrap();
    assert_eq!(tag[2], panel_image_id());
    assert!(tag[3].starts_with("proxy_panel_by_dubr1k-panel:rollback-"));
    let build = commands.iter().find(|c| has(c, "build")).unwrap();
    assert_eq!(build[..4], ["docker", "compose", "--project-name", "proxy_panel_by_dubr1k"]);
    assert!(has(build, "--env-file"));
    assert_eq!(tail(build, 2), ["build", "panel"]);
    assert!(commands
        .iter()
        .any(|c| is(c, &["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", "proxy_panel_by_dubr1k_panel-data"])));
    assert!(is(commands.last().unwrap(), &RESTART));
    let state = panel_state(dir.path());
    assert_eq!(
        (&state["version"], &state["status"], &state["previous_version"]),
        (&json!(NEW_PANEL), &json!("ready"), &json!(OLD_PANEL))
    );
    assert_eq!(
        (&state["kind"], &state["url"], &state["pending_rebuild"]),
        (&json!("release"), &json!(PANEL_URL), &json!(["naive_manager"]))
    );
    // heal=false: this host has no naive overlay, so the self-healing listing would drop it.
    let listed = agent.list_versions(false).unwrap()["components"]["panel"].clone();
    assert_eq!((&listed["current"], &listed["status"]), (&json!(NEW_PANEL), &json!("ready")));
    assert_eq!(listed["pending_rebuild"], json!(["naive_manager"]));
    assert!(!dir.join("staging").exists());
    // Python's timeouts: tag 60, build 900, stop 180, up 300, the restart 30.
    let timeouts: Vec<(Vec<String>, u64)> =
        host.host.commands().into_iter().map(|c| (c.argv.clone(), c.timeout.as_secs())).collect();
    let timeout_of =
        |pick: &dyn Fn(&[String]) -> bool| timeouts.iter().find(|(a, _)| pick(a)).map(|(_, t)| *t).unwrap();
    assert_eq!(timeout_of(&|a| starts(a, &["docker", "tag"])), 60);
    assert_eq!(timeout_of(&|a| has(a, "build")), 900);
    assert_eq!(timeout_of(&|a| has(a, "stop")), 180);
    assert_eq!(timeout_of(&|a| starts(a, &["docker", "compose"]) && has(a, "up")), 300);
    assert_eq!(timeout_of(&|a| a[0] == "systemd-run"), 30);
}

#[test]
fn panel_update_without_manager_or_agent_changes_neither_flags_nor_restarts() {
    let dir = TempDir::new("panel-unchanged");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(panel_archive(b"old naive\n", b"old agent\n"), |_| {});
    update_panel(&agent).unwrap();
    assert_eq!(panel_state(dir.path())["pending_rebuild"], json!([]));
    assert!(!verbs(&host.commands()).contains(&"systemd-run"));
}

#[test]
fn panel_update_does_not_restart_the_agent_when_only_the_installer_changes() {
    // 4.0: the agent links the installer; nothing of the project's `installer/` is loaded at run
    // time, so an installer change alone no longer restarts the agent (Python restarted it).
    let dir = TempDir::new("panel-installer");
    let host = PanelHost::new(dir.path());
    write(&host.compose.join("installer/transaction.py"), b"old handoff implementation\n");
    let version = format!("{NEW_PANEL}\n");
    let payload = release_tar(&[
        ("proxy-control/VERSION", version.as_bytes(), 0o644),
        ("proxy-control/panel/app.py", b"new panel\n", 0o644),
        ("proxy-control/installer/transaction.py", b"new handoff implementation\n", 0o644),
        ("proxy-control/version_agent/service.py", b"old agent\n", 0o644),
    ]);
    let (agent, _) = host.agent(payload, |_| {});
    update_panel(&agent).unwrap();
    assert_eq!(text(&host.compose.join("installer/transaction.py")), "new handoff implementation\n");
    assert_eq!(text(&host.agent_dir.join("version_agent/service.py")), "old agent\n");
    assert!(!verbs(&host.commands()).contains(&"systemd-run"));
}

#[test]
fn a_changed_agent_binary_restarts_the_agent() {
    // The tree hash covers every byte of the agent's tree, the prebuilt binary included.
    let dir = TempDir::new("panel-binary");
    let host = PanelHost::new(dir.path());
    let binary = host.agent_dir.join("version_agent/bin/linux-amd64/proxy-control-version-agent");
    write(&binary, b"\x7fELF old agent");
    set_mode(&binary, 0o755);
    let version = format!("{NEW_PANEL}\n");
    let payload = release_tar(&[
        ("proxy-control/VERSION", version.as_bytes(), 0o644),
        ("proxy-control/version_agent/service.py", b"old agent\n", 0o644),
        ("proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent", b"\x7fELF new agent", 0o755),
    ]);
    let (agent, _) = host.agent(payload, |_| {});
    update_panel(&agent).unwrap();
    assert_eq!(read(&binary), b"\x7fELF new agent");
    assert_eq!(mode(&binary), 0o755);
    assert_eq!(
        read(&dir.join("backups/panel.previous/version_agent/bin/linux-amd64/proxy-control-version-agent")),
        b"\x7fELF old agent"
    );
    assert!(is(host.commands().last().unwrap(), &RESTART));
}

#[test]
fn a_pc_common_change_rebuilds_every_rust_manager() {
    let dir = TempDir::new("panel-pc-common");
    let host = PanelHost::new(dir.path());
    write(&host.compose.join("pc_common/src/lib.rs"), b"old\n");
    for manager in ["trusttunnel_manager", "awg_manager", "mieru_manager"] {
        write(&host.compose.join(manager).join("src/main.rs"), b"same\n");
    }
    let version = format!("{NEW_PANEL}\n");
    let payload = release_tar(&[
        ("proxy-control/VERSION", version.as_bytes(), 0o644),
        ("proxy-control/pc_common/src/lib.rs", b"new\n", 0o644),
        ("proxy-control/naive_manager/app.py", b"changed naive\n", 0o644),
        ("proxy-control/trusttunnel_manager/src/main.rs", b"same\n", 0o644),
        ("proxy-control/awg_manager/src/main.rs", b"same\n", 0o644),
        ("proxy-control/mieru_manager/src/main.rs", b"same\n", 0o644),
        ("proxy-control/mieru_manager/app.py", b"same mieru\n", 0o644),
        ("proxy-control/version_agent/service.py", b"old agent\n", 0o644),
    ]);
    let (agent, _) = host.agent(payload, |config| config.auto_rebuild_managers = false);
    update_panel(&agent).unwrap();
    // The changed manager first (PANEL_MANAGERS order), then the Rust managers present in the
    // release (RUST_MANAGERS order); `mcp_server`/`xray_router_manager` are not in this release.
    assert_eq!(
        panel_state(dir.path())["pending_rebuild"],
        json!(["naive_manager", "trusttunnel_manager", "awg_manager", "mieru_manager"])
    );
    assert!(dir.join("compose/pc_common/src/lib.rs").exists());
    assert_eq!(text(&host.compose.join("pc_common/src/lib.rs")), "new\n");
}

#[test]
fn a_host_not_moved_to_the_new_project_is_updated_in_its_old_one() {
    let dir = TempDir::new("panel-legacy-project");
    let host = PanelHost::new(dir.path());
    host.set(|state| state.project = "mtproxy".into());
    let (agent, _) = host.agent(default_archive(), |config| {
        config.panel_image = Some("mtproxy-panel".into());
        config.panel_volume = Some("mtproxy_panel-data".into());
    });
    update_panel(&agent).unwrap();
    let commands = host.commands();
    let tag = commands.iter().find(|c| starts(c, &["docker", "tag"])).unwrap();
    assert!(tag[3].starts_with("mtproxy-panel:rollback-"));
    let build = commands.iter().find(|c| has(c, "build")).unwrap();
    assert_eq!(build[..4], ["docker", "compose", "--project-name", "mtproxy"]);
    assert!(commands
        .iter()
        .any(|c| is(c, &["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", "mtproxy_panel-data"])));
    assert_eq!(
        (agent.panel_image(), agent.panel_volume()),
        ("mtproxy-panel".to_string(), "mtproxy_panel-data".to_string())
    );
    host.set(|state| state.project = "proxy_panel_by_dubr1k".into()); // moved while the agent runs
    assert_eq!(agent.panel_image(), "proxy_panel_by_dubr1k-panel");
    assert_eq!(agent.panel_volume(), "proxy_panel_by_dubr1k_panel-data");
}

#[test]
fn panel_update_rolls_back_files_db_and_image_when_the_container_reports_the_old_version() {
    let dir = TempDir::new("panel-rollback");
    let host = PanelHost::new(dir.path());
    host.set(|state| {
        state.container_version = Some(format!("{OLD_PANEL}\n"));
        state.migrate = true;
    });
    let (agent, _) = host.agent(default_archive(), |_| {});
    let error = update_error(update_panel(&agent));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert!(error.message.contains("restored"));
    assert_eq!(
        error.message,
        format!("panel update failed (panel container reports {OLD_PANEL}, expected {NEW_PANEL}); previous generation was restored and verified")
    );
    assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
    assert_eq!(text(&host.compose.join("panel/app.py")), "old panel\n");
    assert_eq!(text(&host.compose.join("compose.yaml")), "old compose\n");
    assert!(!host.compose.join("scripts").exists());
    assert_eq!(text(&host.compose.join("secrets/panel-master-key")), "keep me\n");
    assert_eq!(text(&host.agent_dir.join("version_agent/service.py")), "old agent\n");
    assert_eq!(read(&host.volume.join("panel.sqlite3")), b"db-old");
    assert_eq!(read(&host.volume.join("panel.sqlite3-wal")), b"wal-old");
    assert!(!host.volume.join("panel.sqlite3-shm").exists()); // the migrated generation's leftovers are gone
    let commands = host.commands();
    assert_eq!(verbs(&commands), ["exec", "tag", "build", "stop", "up", "exec", "stop", "tag", "up", "exec"]);
    let tags: Vec<&Vec<String>> = commands.iter().filter(|c| starts(c, &["docker", "tag"])).collect();
    assert_eq!((&tags[1][2], tags[1][3].as_str()), (&tags[0][3], "proxy_panel_by_dubr1k-panel:latest"));
    let state = panel_state(dir.path());
    assert_eq!((&state["version"], &state["status"]), (&json!(OLD_PANEL), &json!("ready")));
    assert!(state["last_error"].as_str().unwrap().contains("restored"));
    let listed = agent.list_versions(true).unwrap()["components"]["panel"].clone();
    assert_eq!((&listed["current"], &listed["status"]), (&json!(OLD_PANEL), &json!("ready")));
    assert!(listed["last_error"].as_str().unwrap().contains("restored"));
}

#[test]
fn panel_rollback_that_does_not_verify_is_reported_and_blocks_further_updates() {
    let dir = TempDir::new("panel-unverified");
    let host = PanelHost::new(dir.path());
    host.set(|state| state.container_version = Some("9.9.9\n".into()));
    let (agent, _) = host.agent(default_archive(), |_| {});
    assert_eq!(update_error(update_panel(&agent)).state, UpdateState::RollbackFailed);
    let state = panel_state(dir.path());
    assert_eq!((&state["status"], &state["version"]), (&json!("rollback_failed"), &json!(OLD_PANEL)));
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["status"], "rollback_failed");
    let error = update_error(update_panel(&agent));
    assert_eq!(error.state, UpdateState::RollbackFailed);
    assert!(error.message.contains("operator recovery"));
}

#[test]
fn panel_preflight_refuses_an_unsafe_archive_before_touching_anything() {
    let tar_with =
        |extra: (&str, &[u8])| release_tar(&[("proxy-control/VERSION", b"x\n", 0o644), (extra.0, extra.1, 0o644)]);
    let cases: Vec<Vec<u8>> = vec![
        tar_with(("proxy-control/../etc/cron.d/x", b"* * * * * root id\n")),
        tar_with(("/etc/passwd", b"root::0:0\n")),
        tar_with(("other/VERSION", b"x\n")),
        crate::artifacts::tests::targz_of(&[("proxy-control/VERSION", b"x\n")], Some("proxy-control/panel/link")),
        b"not a tarball".to_vec(),
    ];
    for bad in cases {
        let dir = TempDir::new("panel-unsafe");
        let host = PanelHost::new(dir.path());
        let (agent, _) = host.agent(bad, |_| {});
        let error = update_error(update_panel(&agent));
        assert!(error.message.contains("archive"), "{error:?}");
        assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
        assert!(!dir.join("backups").exists() && mutations(&host.commands()).is_empty());
        let state = panel_state(dir.path());
        assert_eq!((&state["status"], &state["version"]), (&json!("update_failed"), &json!(OLD_PANEL)));
        assert!(state["last_error"].as_str().unwrap().contains("archive"));
        // A refused archive is not a broken generation: the next attempt is allowed.
        host.set(|state| state.payload = default_archive());
        assert!(update_error(update_panel(&agent)).message.contains("SHA-256"));
    }
}

#[test]
fn panel_digest_mismatch_touches_nothing() {
    let dir = TempDir::new("panel-digest");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    host.set(|state| state.payload = panel_archive(b"changed naive\n", b"tampered\n"));
    assert_eq!(update_error(update_panel(&agent)).message, "panel artifact SHA-256 mismatch");
    assert_eq!(version_text(&host), format!("{OLD_PANEL}\n"));
    assert!(mutations(&host.commands()).is_empty());
}

#[test]
fn the_panel_is_never_downgraded_even_from_the_catalog() {
    // v1.0.1: the database migrates forward only; an older build would not start on it.
    let dir = TempDir::new("panel-downgrade");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    host.set(|state| state.running = "0.12.0-beta.1\n".into());
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["available"][0]["newer"], false);
    let error = update_error(agent.update("panel", NEW_PANEL, Some("0.12.0-beta.1")));
    assert!(error.message.contains("cannot be downgraded"));
    assert!(mutations(&host.commands()).is_empty());
}

#[test]
fn a_second_panel_update_is_refused_while_one_is_running() {
    let dir = TempDir::new("panel-second");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    write_panel(dir.path(), json!({"version": OLD_PANEL, "status": "updating"}));
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["status"], "updating");
    let error = update_panel(&agent).unwrap_err();
    assert!(matches!(&error, AgentError::Conflict(m) if m.contains("already")), "{error:?}");
    assert!(mutations(&host.commands()).is_empty());
}

#[test]
fn other_updates_wait_for_a_running_panel_update() {
    // New in 4.0: one Compose writer at a time (Python ran both).
    let dir = TempDir::new("panel-exclusive");
    let host = PanelHost::new(dir.path());
    let (agent, _) = host.agent(default_archive(), |_| {});
    let catalog = json!({"schema": 1, "components": {"telemt": [{"version": "3.4.25", "kind": "image",
        "image": format!("ghcr.io/example/telemt@sha256:{}", "a".repeat(64))}]}});
    write(&dir.join("catalog.json"), catalog.to_string().as_bytes());
    for panel in [
        json!({"version": OLD_PANEL, "status": "updating"}),
        json!({"version": OLD_PANEL, "status": "ready", "rebuilding_managers": now()}),
    ] {
        write_panel(dir.path(), panel);
        let error = agent.update("telemt", "3.4.25", None).unwrap_err();
        assert_eq!(error, AgentError::conflict("panel update or manager rebuild is already running"));
    }
}

#[test]
fn panel_update_runs_in_a_background_thread_and_the_request_returns_first() {
    let dir = TempDir::new("panel-thread");
    let host = PanelHost::new(dir.path());
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new())); // (started, released)
    let (base, updater) = host.agent(default_archive(), |config| config.synchronous = false);
    // The worker blocks on `docker tag` until the test releases it (outside the host's lock).
    let (waiter, inner) = (gate.clone(), host.host.clone());
    let runner = move |command: &Command| -> Result<String, CommandError> {
        if starts(&command.argv, &["docker", "tag"]) {
            let (lock, wake) = &*waiter;
            let mut flags = lock.lock().unwrap();
            flags.0 = true;
            wake.notify_all();
            let (flags, _) = wake.wait_timeout_while(flags, std::time::Duration::from_secs(5), |f| !f.1).unwrap();
            assert!(flags.1);
        }
        crate::runner::CommandRunner::run(&inner, command)
    };
    let mut owned = VersionAgent::new(base.config.clone());
    owned.runner = Arc::new(runner);
    owned.updater = Arc::new(updater.clone());
    let agent = Arc::new(owned);
    let result = update_panel(&agent).unwrap();
    assert_eq!(result["async"], true);
    {
        let (lock, wake) = &*gate;
        let flags = lock.lock().unwrap();
        let (flags, _) = wake.wait_timeout_while(flags, std::time::Duration::from_secs(5), |f| !f.0).unwrap();
        assert!(flags.0);
    }
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["status"], "updating");
    let error = update_panel(&agent).unwrap_err();
    assert!(matches!(&error, AgentError::Conflict(m) if m.contains("already")), "{error:?}");
    {
        let (lock, wake) = &*gate;
        lock.lock().unwrap().1 = true;
        wake.notify_all();
    }
    join(&updater);
    let listed = agent.list_versions(true).unwrap()["components"]["panel"].clone();
    assert_eq!((&listed["status"], &listed["current"]), (&json!("ready"), &json!(NEW_PANEL)));
}

#[test]
fn panel_worker_swallows_a_failure_in_the_background_and_persists_it() {
    let dir = TempDir::new("panel-worker");
    let host = PanelHost::new(dir.path());
    host.set(|state| state.container_version = Some("9.9.9\n".into()));
    let (agent, updater) = host.agent(default_archive(), |config| config.synchronous = false);
    assert_eq!(update_panel(&agent).unwrap()["async"], true);
    join(&updater);
    assert_eq!(panel_state(dir.path())["status"], "rollback_failed");
}

#[test]
fn the_tree_hash_skips_bytecode_and_symlinks_and_orders_like_os_walk() {
    let dir = TempDir::new("tree-hash");
    let tree = dir.join("tree");
    write(&tree.join("b.txt"), b"b");
    write(&tree.join("a/z.txt"), b"z");
    write(&tree.join("a/__pycache__/x.pyc"), b"cache");
    std::os::unix::fs::symlink(tree.join("b.txt"), tree.join("link")).unwrap();
    // os.walk: the directory's files first (sorted), then each subdirectory.
    let mut digest = <sha2::Sha256 as sha2::Digest>::new();
    for (path, data) in [("b.txt", &b"b"[..]), ("a/z.txt", b"z")] {
        sha2::Digest::update(&mut digest, path.as_bytes());
        sha2::Digest::update(&mut digest, b"\0");
        sha2::Digest::update(&mut digest, data);
        sha2::Digest::update(&mut digest, b"\0");
    }
    let expected: String = sha2::Digest::finalize(digest).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(tree_hash(&tree).unwrap(), Some(expected));
    assert_eq!(tree_hash(&tree.join("b.txt")).unwrap(), Some(sha(b"b")));
    assert_eq!(tree_hash(&tree.join("link")).unwrap(), None);
    assert_eq!(tree_hash(&dir.join("missing")).unwrap(), None);
}

// --- tests/test_version_agent_managers.py (the rebuild after a panel update) --------------------

fn manager_files(config: &mut AgentConfig) {
    config.compose_files = ["compose.yaml", "compose.naive.yaml", "compose.xray-router.yaml", "compose.mcp.yaml"]
        .map(String::from)
        .to_vec();
}

#[test]
fn successful_panel_update_rebuilds_managers_in_one_compose_call_before_the_agent_restart() {
    let dir = TempDir::new("managers-rebuild");
    let host = PanelHost::new(dir.path()).with_managers(&["naive-manager", "xray-router", "xray-router-ingress"], OLD);
    let payload = release_tar(&[
        ("proxy-control/VERSION", NEW_PANEL.as_bytes(), 0o644),
        ("proxy-control/naive_manager/app.py", b"changed", 0o644),
        ("proxy-control/xray_router_manager/app.py", b"changed", 0o644),
        ("proxy-control/version_agent/service.py", b"new agent", 0o644),
    ]);
    let (agent, _) = host.agent(payload, manager_files);
    update_panel(&agent).unwrap();
    let commands = host.commands();
    let builds: Vec<&Vec<String>> =
        commands.iter().filter(|c| starts(c, &["docker", "compose"]) && has(c, "--build")).collect();
    assert_eq!(builds.len(), 1);
    assert_eq!(tail(builds[0], 4), ["--no-deps", "naive-manager", "xray-router", "xray-router-ingress"]);
    assert!(has(builds[0], "--env-file") && has(builds[0], "up"));
    let tags: std::collections::BTreeSet<String> = commands
        .iter()
        .filter(|c| {
            starts(c, &["docker", "tag"])
                && c[3].starts_with("proxy_panel_by_dubr1k-")
                && !c[3].starts_with("proxy_panel_by_dubr1k-panel")
        })
        .map(|c| c[3].split(':').next().unwrap().to_string())
        .collect();
    assert_eq!(
        tags,
        [
            "proxy_panel_by_dubr1k-naive-manager",
            "proxy_panel_by_dubr1k-xray-router",
            "proxy_panel_by_dubr1k-xray-router-ingress"
        ]
        .map(String::from)
        .into_iter()
        .collect()
    );
    let panel = panel_state(dir.path());
    assert_eq!((&panel["status"], &panel["pending_rebuild"]), (&json!("ready"), &json!([])));
    assert!(panel["managers_rebuilt_at"].is_i64() && panel.get("rebuilding_managers").is_none());
    assert_eq!(commands.last().unwrap()[0], "systemd-run"); // the agent restart is the very last step
    let build = host.host.commands().into_iter().find(|c| has(&c.argv, "--build")).unwrap();
    assert_eq!(build.timeout.as_secs(), 900);
}

#[test]
fn failed_manager_rebuild_keeps_the_panel_pending_and_records_the_error() {
    let dir = TempDir::new("managers-failed");
    let host = PanelHost::new(dir.path()).with_managers(&["naive-manager"], OLD);
    host.set(|state| state.fail_up = true);
    let (agent, _) = host.agent(default_archive(), manager_files);
    update_panel(&agent).unwrap();
    let panel = panel_state(dir.path());
    assert_eq!((&panel["status"], &panel["version"]), (&json!("ready"), &json!(NEW_PANEL))); // panel never rolled back
    assert_eq!(panel["pending_rebuild"], json!(["naive_manager"]));
    assert!(panel["rebuild_error"].as_str().unwrap().contains("build failed"));
    assert!(panel.get("rebuilding_managers").is_none());
    let commands = host.commands();
    assert!(commands
        .iter()
        .any(|c| starts(c, &["docker", "tag"]) && c.last().unwrap() == "proxy_panel_by_dubr1k-naive-manager:latest"));
    assert_eq!(commands.last().unwrap()[0], "systemd-run");
}

#[test]
fn unhealthy_managers_time_out_without_dropping_the_pending_list() {
    let dir = TempDir::new("managers-unhealthy");
    let host = PanelHost::new(dir.path()).with_managers(&["naive-manager"], OLD);
    host.set(|state| {
        state.health.insert("naive-manager".into(), "starting".into());
    });
    let (agent, _) = host.agent(default_archive(), |config| {
        manager_files(config);
        config.manager_health_timeout = 6.0;
    });
    update_panel(&agent).unwrap();
    let panel = panel_state(dir.path());
    assert_eq!(panel["pending_rebuild"], json!(["naive_manager"]));
    assert!(panel["rebuild_error"].as_str().unwrap().contains("not healthy: naive-manager=starting"), "{panel}");
    assert_eq!(host.state.lock().unwrap().sleeps, [2.0, 2.0, 2.0]);
}

#[test]
fn auto_rebuild_can_be_switched_off() {
    let dir = TempDir::new("managers-off");
    let host = PanelHost::new(dir.path()).with_managers(&["naive-manager"], OLD);
    let (agent, _) = host.agent(default_archive(), |config| {
        manager_files(config);
        config.auto_rebuild_managers = false;
    });
    update_panel(&agent).unwrap();
    assert!(!host.commands().iter().any(|c| has(c, "--build")));
    assert_eq!(panel_state(dir.path())["pending_rebuild"], json!(["naive_manager"]));
}

#[test]
fn manual_rebuild_rebuilds_the_pending_managers_and_ack_is_idempotent() {
    let dir = TempDir::new("managers-manual");
    let host = PanelHost::new(dir.path()).with_managers(&["naive-manager", "mcp"], OLD);
    let (agent, _) = host.agent(default_archive(), |config| {
        manager_files(config);
        config.auto_rebuild_managers = false;
    });
    update_panel(&agent).unwrap();
    let mut panel = panel_state(dir.path());
    panel["pending_rebuild"] = json!(["naive_manager", "mcp_server", "docker"]);
    write_panel(dir.path(), panel);
    assert_eq!(
        agent.ack_managers(&json!(["mcp_server"])).unwrap()["pending_rebuild"],
        json!(["naive_manager", "docker"])
    );
    assert_eq!(
        agent.ack_managers(&json!(["mcp_server"])).unwrap()["pending_rebuild"],
        json!(["naive_manager", "docker"])
    );
    let mut panel = panel_state(dir.path());
    panel["status"] = json!("updating");
    write_panel(dir.path(), panel.clone());
    assert!(matches!(agent.rebuild_managers(), Err(AgentError::Conflict(_))));
    panel["status"] = json!("ready");
    write_panel(dir.path(), panel);
    let result = agent.rebuild_managers().unwrap();
    assert_eq!((&result["pending_rebuild"], &result["rebuilding"]), (&json!(["docker"]), &json!(false)));
    assert!(result.get("managers_rebuilt_at").is_some());
    let builds: Vec<Vec<String>> = host.commands().into_iter().filter(|c| has(c, "--build")).collect();
    assert_eq!(builds.len(), 1);
    assert_eq!(tail(&builds[0], 2), ["--no-deps", "naive-manager"]);
}

#[test]
fn a_background_rebuild_answers_first_and_records_its_verdict() {
    let dir = TempDir::new("managers-background");
    let host = PanelHost::new(dir.path()).with_managers(&["naive-manager"], OLD);
    let (agent, updater) = host.agent(default_archive(), |config| {
        manager_files(config);
        config.auto_rebuild_managers = false;
    });
    let gate = Arc::new((Mutex::new((false, false)), std::sync::Condvar::new()));
    let blocked = gate.clone();
    host.set(|state| {
        state.intercept = Some(Box::new(move |argv, _| {
            if starts(argv, &["docker", "compose"]) && has(argv, "--build") {
                let (lock, wake) = &*blocked;
                let mut state = lock.lock().unwrap();
                state.0 = true;
                wake.notify_all();
                while !state.1 {
                    state = wake.wait(state).unwrap();
                }
            }
            None
        }))
    });
    update_panel(&agent).unwrap();
    let mut owned = VersionAgent::new(AgentConfig { synchronous: false, ..agent.config.clone() });
    owned.runner = agent.runner.clone();
    owned.updater = Arc::new(updater.clone());
    let agent = Arc::new(owned);
    let answered = agent.rebuild_managers().unwrap();
    let (lock, wake) = &*gate;
    let mut state = lock.lock().unwrap();
    while !state.0 {
        state = wake.wait(state).unwrap();
    }
    assert_eq!(answered["pending_rebuild"], json!(["naive_manager"]));
    assert_eq!(answered["rebuilding"], json!(true));
    state.1 = true;
    wake.notify_all();
    drop(state);
    join(&updater);
    let panel = panel_state(dir.path());
    assert_eq!(panel["pending_rebuild"], json!([]));
    assert!(panel.get("rebuilding_managers").is_none() && panel["managers_rebuilt_at"].is_i64());
}

// --- tests/test_version_agent_update_safety.py -------------------------------------------------

fn mcp_archive() -> Vec<u8> {
    release_tar(&[
        ("proxy-control/VERSION", NEW_PANEL.as_bytes(), 0o644),
        ("proxy-control/mcp_server/server.py", b"new mcp", 0o644),
    ])
}

#[test]
fn mcp_source_is_updated_and_reported_for_rebuild() {
    let dir = TempDir::new("safety-mcp");
    let host = PanelHost::new(dir.path());
    let source = host.compose.join("mcp_server/server.py");
    write(&source, b"old mcp");
    let (agent, _) = host.agent(mcp_archive(), |_| {});
    update_panel(&agent).unwrap();
    assert_eq!(text(&source), "new mcp");
    assert_eq!(panel_state(dir.path())["pending_rebuild"], json!(["mcp_server"]));
    assert_eq!(text(&dir.join("backups/panel.previous/mcp_server/server.py")), "old mcp");
}

#[test]
fn rollback_quiesces_real_sqlite_writer_and_restores_integrity() {
    let dir = TempDir::new("safety-writer");
    let host = PanelHost::new(dir.path());
    for entry in std::fs::read_dir(&host.volume).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let database = host.volume.join("panel.sqlite3");
    let connection = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0)).unwrap(), "wal");
    connection.execute("CREATE TABLE records (value TEXT)", []).unwrap();
    connection.execute("INSERT INTO records VALUES ('previous')", []).unwrap();
    let writer = Arc::new(Mutex::new(Some(connection)));
    let (agent, _) = host.agent(default_archive(), |config| {
        config.compose_files = vec!["compose.yaml".into(), "compose.fleet-central.yaml".into()];
    });
    let compose = host.compose.clone();
    let stops = Arc::new(Mutex::new(Vec::new()));
    let (active, stopped) = (writer.clone(), stops.clone());
    let running_database = database.clone();
    host.set(|state| {
        state.intercept = Some(Box::new(move |argv, state| {
            if starts(argv, &["docker", "compose"]) && has(argv, "stop") {
                stopped.lock().unwrap().push(argv.to_vec());
                active.lock().unwrap().take();
            }
            if starts(argv, &["docker", "ps"]) {
                state.commands.push(argv.to_vec());
                return Some(Ok(if active.lock().unwrap().is_some() { "writer".into() } else { String::new() }));
            }
            let new_generation =
                std::fs::read_to_string(compose.join("VERSION")).unwrap_or_default().trim() == NEW_PANEL;
            if starts(argv, &["docker", "compose"]) && has(argv, "up") && new_generation {
                let connection = rusqlite::Connection::open(&running_database).unwrap();
                connection.execute("INSERT INTO records VALUES ('new generation')", []).unwrap();
                *active.lock().unwrap() = Some(connection);
                state.commands.push(argv.to_vec());
                return Some(Err(runtime_error("health check failed with SQLite writer still running")));
            }
            None
        }))
    });
    let error = update_error(update_panel(&agent));
    assert_eq!(error.state, UpdateState::RolledBack);
    let stops = stops.lock().unwrap();
    assert_eq!(stops.len(), 2);
    assert!(stops.iter().all(|c| tail(c, 2) == ["panel", "fleet-ingress"]));
    drop(stops);
    assert!(writer.lock().unwrap().is_none());
    let restored = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(restored.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0)).unwrap(), "ok");
    let mut rows = restored.prepare("SELECT value FROM records").unwrap();
    let values = rows.query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(values, ["previous"]);
}

#[test]
fn rollback_refuses_to_overwrite_database_if_writers_cannot_be_stopped() {
    for failure in ["stop", "writer"] {
        let dir = TempDir::new("safety-stop");
        let host = PanelHost::new(dir.path());
        host.set(|state| {
            state.migrate = true;
            state.container_version = Some("unexpected".into());
        });
        let (agent, _) = host.agent(default_archive(), |_| {});
        let stops = Arc::new(Mutex::new(0));
        let counter = stops.clone();
        host.set(|state| {
            state.intercept = Some(Box::new(move |argv, _| {
                let mut stops = counter.lock().unwrap();
                if starts(argv, &["docker", "compose"]) && has(argv, "stop") {
                    *stops += 1;
                    if *stops == 2 && failure == "stop" {
                        return Some(Err(runtime_error("stop failed")));
                    }
                }
                if starts(argv, &["docker", "ps"]) && *stops == 2 && failure == "writer" {
                    return Some(Ok("unexpected writer".into()));
                }
                None
            }))
        });
        assert_eq!(update_error(update_panel(&agent)).state, UpdateState::RollbackFailed, "{failure}");
        assert_eq!(read(&host.volume.join("panel.sqlite3")), b"db-migrated");
        assert_eq!(read(&dir.join("backups/panel-db.previous/panel.sqlite3")), b"db-old");
        assert_eq!(panel_state(dir.path())["status"], "rollback_failed");
    }
}

#[test]
fn failed_database_snapshot_never_restores_a_partial_set() {
    let dir = TempDir::new("safety-snapshot");
    let host = PanelHost::new(dir.path());
    let (agent, updater) = host.agent(default_archive(), |_| {});
    let mut failing = updater.clone();
    failing.copy_db_file = Arc::new(|source: &Path, target: &Path| {
        let into_backup = target.parent().and_then(|p| p.file_name()).is_some_and(|n| n == "panel-db.previous");
        if into_backup && source.to_string_lossy().ends_with("-wal") {
            return Err(std::io::Error::from_raw_os_error(28));
        }
        crate::updater::copy2(source, target)
    });
    let mut owned = VersionAgent::new(agent.config.clone());
    owned.runner = agent.runner.clone();
    owned.updater = Arc::new(failing);
    let agent = Arc::new(owned);
    let error = update_error(update_panel(&agent));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert!(error.message.contains("No space left on device"), "{error:?}");
    assert_eq!(read(&host.volume.join("panel.sqlite3-wal")), b"wal-old");
}

#[test]
fn mcp_source_rolls_back_with_failed_panel_generation() {
    let dir = TempDir::new("safety-mcp-rollback");
    let host = PanelHost::new(dir.path());
    host.set(|state| state.container_version = Some(OLD_PANEL.into()));
    let source = host.compose.join("mcp_server/server.py");
    write(&source, b"old mcp");
    let (agent, _) = host.agent(mcp_archive(), |_| {});
    assert_eq!(update_error(update_panel(&agent)).state, UpdateState::RolledBack);
    assert_eq!(text(&source), "old mcp");
}

#[test]
fn rollback_image_is_the_running_container_even_when_latest_was_rebuilt() {
    let dir = TempDir::new("safety-image");
    let host = PanelHost::new(dir.path());
    host.set(|state| state.container_version = Some(OLD_PANEL.into()));
    let running_image = format!("sha256:{}", "1".repeat(64));
    let (agent, _) = host.agent(default_archive(), |_| {});
    let image = running_image.clone();
    host.set(|state| {
        state.intercept = Some(Box::new(move |argv, state| {
            if is(argv, &["docker", "inspect", "--format", "{{.Image}}", "proxy-control-panel"]) {
                state.commands.push(argv.to_vec());
                return Some(Ok(image.clone()));
            }
            None
        }))
    });
    assert_eq!(update_error(update_panel(&agent)).state, UpdateState::RolledBack);
    let tags: Vec<Vec<String>> = host.commands().into_iter().filter(|c| starts(c, &["docker", "tag"])).collect();
    assert_eq!(tags[0][2], running_image); // latest may already name a different image
    assert_eq!((&tags[1][2], tags[1][3].as_str()), (&tags[0][3], "proxy_panel_by_dubr1k-panel:latest"));
}

#[test]
fn missing_rollback_image_refuses_before_recreating_from_latest() {
    for failure in ["identity", "tag"] {
        let dir = TempDir::new("safety-missing-image");
        let host = PanelHost::new(dir.path());
        let (agent, _) = host.agent(default_archive(), |_| {});
        host.set(|state| {
            state.intercept = Some(Box::new(move |argv, _| {
                if failure == "identity" && starts(argv, &["docker", "inspect", "--format", "{{.Image}}"]) {
                    return Some(Ok(String::new()));
                }
                if failure == "tag" && starts(argv, &["docker", "tag"]) {
                    return Some(Err(runtime_error("could not save rollback image")));
                }
                None
            }))
        });
        update_error(update_panel(&agent));
        assert!(!host.commands().iter().any(|c| starts(c, &["docker", "compose"])), "{failure}");
        assert_eq!(version_text(&host).trim(), OLD_PANEL);
    }
}
