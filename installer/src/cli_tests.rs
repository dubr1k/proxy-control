//! The dispatch half of `tests/test_installer_cli.py` (the parsing half is in
//! `installer_core::cli`), driven through [`run`] with injected services, and the Python CLI
//! outputs recorded in `tests/fixtures/host-golden/` (`plans/*/plan-cli.*`,
//! `installs/*/{status.*,report/}`, `config/cli-blocked.json`) reproduced through the binary's
//! dispatch.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pc_host::fs::sha256_hex;
use pc_host::runner::{HostRunner, RecordingRunner, Reply};
use serde_json::{json, Value};

use super::*;
use crate::journal::{CheckpointData, RollbackTarget, Status};
use crate::planner::Action;
use crate::testkit::{Failure as Injected, RecordingAdapter, TempDir};
use crate::tests::fakes::{host as host_path, owned_host, write, PROJECT};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn golden() -> PathBuf {
    repo().join("tests/fixtures/host-golden")
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn load(path: &Path) -> Value {
    serde_json::from_slice(&read(path)).unwrap()
}

fn text(path: &Path) -> String {
    String::from_utf8(read(path)).unwrap()
}

struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_with(arguments: &[&str], compose: &dyn Fn(&Path) -> Result<Services, Error>) -> Ran {
    let arguments: Vec<String> = arguments.iter().map(|item| item.to_string()).collect();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let code = run(&arguments, compose, &mut stdout, &mut stderr);
    Ran { code, stdout: String::from_utf8(stdout).unwrap(), stderr: String::from_utf8(stderr).unwrap() }
}

fn never(_: &Path) -> Result<Services, Error> {
    panic!("this command must not compose services")
}

/// A host root (with the golden machine id) and a release tree (with the golden identity).
struct Host {
    dir: TempDir,
    root: PathBuf,
    tree: PathBuf,
}

impl Host {
    fn new(label: &str) -> Host {
        let dir = TempDir::new(label);
        let root = dir.path().join("root");
        let tree = dir.path().join("tree");
        let index = load(&golden().join("plans/index.json"));
        write(&root.join("etc/machine-id"), format!("{}\n", index["host"]["machine_id"].as_str().unwrap()).as_bytes());
        write(&tree.join("release/release.json"), &read(&golden().join("plans/release.json")));
        Host { dir, root, tree }
    }

    fn root(&self) -> &str {
        self.root.to_str().unwrap()
    }

    fn journal(&self) -> PathBuf {
        self.root.join("var/lib/proxy-control/installer")
    }

    /// Copies a recorded journal (`state.json`, `plan.json`, `ownership.json`, `report.json`).
    fn install_journal(&self, directory: &Path) {
        for name in ["state.json", "plan.json", "ownership.json", "report.json"] {
            let source = directory.join(name);
            if source.exists() {
                write(&self.journal().join(name), &read(&source));
            }
        }
    }
}

/// What a test composes: recorded facts, adapters, a runner and the MCP handoff entries.
#[derive(Clone, Default)]
struct Fixture {
    facts: AuditFacts,
    adapters: Vec<Arc<dyn Adapter>>,
    runner: Option<Arc<RecordingRunner>>,
    mcp: Option<BTreeMap<String, String>>,
}

impl Fixture {
    fn compose(&self, host: &Host, root: &Path) -> Result<Services, Error> {
        assert_eq!(root, host.root.as_path(), "--root reaches the services");
        let runner: Arc<dyn HostRunner> = match &self.runner {
            Some(runner) => runner.clone(),
            None => Arc::new(RecordingRunner::new()),
        };
        let context = AdapterContext { root: root.to_path_buf(), tree: host.tree.clone(), runner };
        let facts = self.facts.clone();
        let mcp = self.mcp.clone();
        let mut services = Services::with_context(
            context,
            Box::new(move |config: Option<&InstallerConfig>| {
                Ok(if config.is_some() { facts.clone() } else { AuditFacts::default() })
            }),
            Box::new(move |_: &AdapterContext, _: &InstallerConfig| {
                mcp.clone().ok_or_else(|| Error::other("McpError", "no MCP in this test"))
            }),
        )?;
        for adapter in &self.adapters {
            services.engine.register(adapter.clone());
        }
        Ok(services)
    }

    fn run(&self, host: &Host, arguments: &[&str]) -> Ran {
        let mut full = vec!["--root", host.root()];
        full.extend_from_slice(arguments);
        run_with(&full, &|root| self.compose(host, root))
    }
}

/// An adapter that plans exactly the actions the Python adapter planned and does nothing else.
struct Recorded {
    name: String,
    actions: Vec<Action>,
}

fn not_here() -> Error {
    Error::other("RuntimeError", "not part of this test")
}

impl Adapter for Recorded {
    fn name(&self) -> &str {
        &self.name
    }

    fn plan(&self, _: &InstallerConfig, _: &AuditFacts) -> Result<Vec<Action>, Error> {
        Ok(self.actions.clone())
    }

    fn prepare(&self, _: &Action) -> Result<CheckpointData, Error> {
        Err(not_here())
    }

    fn apply(&self, _: &Action, _: CheckpointData) -> Result<CheckpointData, Error> {
        Err(not_here())
    }

    fn reconcile_apply(&self, _: &Action, _: CheckpointData) -> Result<CheckpointData, Error> {
        Err(not_here())
    }

    fn verify(&self, _: &Action) -> Result<Evidence, Error> {
        Err(not_here())
    }

    fn repair(&self, _: &Action, _: CheckpointData) -> Result<CheckpointData, Error> {
        Err(not_here())
    }

    fn rollback(&self, _: &Action, _: CheckpointData, _: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        Err(not_here())
    }

    fn reconcile_rollback(&self, _: &Action, _: CheckpointData, _: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        Err(not_here())
    }
}

fn config_path(entry: &Value) -> PathBuf {
    let path = entry["config"].as_str().unwrap();
    if path.starts_with("plans/") {
        golden().join(path)
    } else {
        repo().join(path)
    }
}

fn core_toml() -> PathBuf {
    repo().join("examples/installer/core.toml")
}

fn test_facts() -> AuditFacts {
    let mut facts = AuditFacts::default();
    facts.platform.insert("os".into(), json!("test"));
    facts
}

#[test]
fn version_help_and_usage_need_no_services() {
    let ran = run_with(&["--version"], &never);
    assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
    assert_eq!(ran.stdout, format!("proxy-control-installer {}\n", installer_core::cli::VERSION.trim()));
    let ran = run_with(&["-h"], &never);
    assert_eq!(ran.code, 0);
    assert!(ran.stdout.starts_with("usage: proxy-control-installer [-h] [--version]"), "{}", ran.stdout);
    let ran = run_with(&[], &never);
    assert_eq!(ran.code, 2);
    assert!(ran.stderr.ends_with("error: the following arguments are required: command\n"), "{}", ran.stderr);
    let ran = run_with(&["install", "--config", "x.toml"], &never);
    assert_eq!(ran.code, 2);
    assert!(ran.stderr.ends_with("error: the following arguments are required: --accept-plan\n"), "{}", ran.stderr);
}

#[test]
fn verify_release_runs_without_a_root() {
    let ran = run_with(&["verify-release", "manifest", "/nonexistent/release-manifest.json"], &never);
    let (code, out, err) = installer_core::verify_release::run(&installer_core::verify_release::Request::Manifest {
        manifest: "/nonexistent/release-manifest.json".into(),
    });
    assert_eq!((ran.code, ran.stdout, ran.stderr), (code, out, err));
    assert_ne!(ran.code, 0);
}

#[test]
fn config_errors_are_blocked_like_python() {
    let host = Host::new("cli-config");
    let cases = load(&golden().join("config/cli-blocked.json"));
    let corpus = load(&golden().join("config/errors.json"));
    let directory = host.dir.path().join("configs");
    fs::create_dir_all(&directory).unwrap();
    let shown = directory.to_string_lossy().to_string();
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let path = directory.join(format!("{name}.toml"));
        match name {
            "missing-file" => {}
            "invalid-utf8" => fs::write(&path, b"schema = 1\nacme_email = \"\xff\"\n").unwrap(),
            _ => {
                let input = corpus.as_array().unwrap().iter().find(|c| c["name"] == name).unwrap()["input"].clone();
                fs::write(&path, input.as_str().unwrap()).unwrap();
            }
        }
        let ran = run_with(&["--root", host.root(), "plan", "--config", path.to_str().unwrap()], &Services::system);
        assert_eq!(ran.code, case["exit"].as_i64().unwrap() as i32, "{name}");
        assert_eq!(ran.stdout, case["stdout"].as_str().unwrap(), "{name}");
        assert_eq!(ran.stderr.replace(&shown, "<dir>"), case["stderr"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn recorded_plans_come_out_of_the_cli_byte_for_byte() {
    let index = load(&golden().join("plans/index.json"));
    let plans = index["plans"].as_object().unwrap();
    assert_eq!(plans.len(), 10);
    for (name, entry) in plans {
        let directory = golden().join("plans").join(name);
        let recorded = InstallPlan::from_json(&read(&directory.join("plan.json"))).unwrap();
        let adapters: Vec<Arc<dyn Adapter>> = recorded
            .adapter_order
            .iter()
            .map(|adapter| {
                Arc::new(Recorded {
                    name: adapter.clone(),
                    actions: recorded.actions.iter().filter(|a| a.adapter == *adapter).cloned().collect(),
                }) as Arc<dyn Adapter>
            })
            .collect();
        let fixture = Fixture { facts: recorded.facts.clone(), adapters, ..Fixture::default() };
        let host = Host::new("cli-plan");
        let config = config_path(entry);
        let config = config.to_str().unwrap();
        let ran = fixture.run(&host, &["plan", "--config", config, "--json"]);
        assert_eq!((ran.code, ran.stderr.as_str()), (0, ""), "{name}");
        assert_eq!(ran.stdout, text(&directory.join("plan-cli.json")), "{name}: plan --json");
        let ran = fixture.run(&host, &["plan", "--config", config]);
        assert_eq!(ran.stdout, text(&directory.join("plan-cli.txt")), "{name}: plan");
    }
}

#[test]
fn a_missing_adapter_is_blocked() {
    let host = Host::new("cli-missing");
    let core = core_toml();
    let core = core.to_str().unwrap();
    let fixture = Fixture { facts: test_facts(), ..Fixture::default() };
    for command in [&["plan", "--config", core][..], &["install", "--config", core, "--accept-plan", &"0".repeat(64)]] {
        let ran = fixture.run(&host, command);
        assert_eq!((ran.code, ran.stderr.as_str()), (2, "BLOCKED: adapter is unavailable: packages\n"));
    }
    // A recorded installation: the engine refuses before touching the journal.
    host.install_journal(&golden().join("installs/core/journal"));
    let before = read(&host.journal().join("state.json"));
    for command in [&["resume"][..], &["repair"], &["uninstall"], &["uninstall", "--purge-data", "--json"]] {
        let ran = run_with(&[&["--root", host.root()][..], command].concat(), &Services::system);
        assert_eq!((ran.code, ran.stdout.as_str()), (2, ""), "{command:?}");
        assert_eq!(ran.stderr, "BLOCKED: adapter is unavailable: packages\n", "{command:?}");
    }
    assert_eq!(read(&host.journal().join("state.json")), before);
}

#[test]
fn audit_failure_is_blocked_without_a_traceback() {
    assert_eq!(system_audit(None).unwrap().stable_dict(), AuditFacts::default().stable_dict());
    let host = Host::new("cli-audit-error");
    let fixture = Fixture::default();
    let compose = |root: &Path| {
        let mut services = fixture.compose(&host, root)?;
        services.audit = Box::new(|_| Err(Error::other("AuditError", "DNS resolution failed")));
        Ok(services)
    };
    let ran = run_with(&["--root", host.root(), "plan", "--config", core_toml().to_str().unwrap()], &compose);
    assert_eq!(ran.code, 2);
    assert!(ran.stdout.is_empty());
    assert_eq!(ran.stderr, "BLOCKED: DNS resolution failed\n");
}

#[test]
fn wizard_reads_preliminary_facts_from_the_composed_audit() {
    let host = Host::new("cli-wizard-initial-audit");
    let mut services = Fixture::default().compose(&host, &host.root).unwrap();
    let mut facts = AuditFacts::default();
    facts.listeners.insert("tcp".into(), json!([12345]));
    facts.ownership.insert("installer".into(), json!({"present": true}));
    let expected = facts.clone();
    services.audit = Box::new(move |config| {
        assert!(config.is_none(), "the initial wizard audit has no configuration");
        Ok(facts.clone())
    });
    let mut engine = CliWizardEngine { services: &services };
    assert_eq!(engine.initial_facts().unwrap().stable_dict(), expected.stable_dict());
}

#[test]
fn status_and_report_of_recorded_installs_match_python() {
    let index = load(&golden().join("plans/index.json"));
    let mut seen = 0;
    for (name, entry) in index["plans"].as_object().unwrap() {
        let directory = golden().join("installs").join(name);
        if !directory.exists() {
            continue;
        }
        seen += 1;
        let host = Host::new("cli-report");
        host.install_journal(&directory.join("journal"));
        let overlay = directory.join("root/files/opt/mtproxy-shared443/.env.amneziawg");
        if overlay.exists() {
            write(&host.root.join("opt/mtproxy-shared443/.env.amneziawg"), &read(&overlay));
        }
        let handoff = directory.join("report/credentials/handoff.json");
        let mcp = handoff.exists().then(|| {
            load(&handoff)["credentials"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
                .collect()
        });
        let fixture = Fixture { mcp, ..Fixture::default() };

        let ran = fixture.run(&host, &["status"]);
        assert_eq!((ran.code, ran.stdout), (0, text(&directory.join("status.txt"))), "{name}");
        let ran = fixture.run(&host, &["status", "--json"]);
        assert_eq!(ran.stdout, text(&directory.join("status.json")), "{name}");

        let output = host.dir.path().join("report");
        let config = config_path(entry);
        let ran = fixture.run(
            &host,
            &["report", "--config", config.to_str().unwrap(), "--output", output.to_str().unwrap(), "--json"],
        );
        assert_eq!((ran.code, ran.stderr.as_str()), (0, ""), "{name}");
        assert_eq!(
            ran.stdout.replace(output.to_str().unwrap(), "<output>"),
            text(&directory.join("report/stdout.json")),
            "{name}"
        );
        // Python wrote the journal origin as the release tag (§12 #2); the binary writes the
        // plan's tag, everything else is Python's bytes.
        let plan = load(&directory.join("journal/plan.json"));
        let mut expected = load(&directory.join("report/report.json"));
        assert_eq!(expected["release"]["tag"], "installer-v1");
        expected["release"]["tag"] = plan["release"]["tag"].clone();
        assert_eq!(text(&output.join("report.json")), pc_host::json::pretty2(&expected), "{name}");
        if handoff.exists() {
            assert_eq!(read(&output.join("credentials/handoff.json")), read(&handoff), "{name}");
        }
    }
    assert_eq!(seen, 9);
}

#[test]
fn a_report_needs_an_active_installation_and_its_mcp_handoff() {
    let host = Host::new("cli-report-refusals");
    let output = host.dir.path().join("report");
    let core = core_toml();
    let report = ["report", "--config", core.to_str().unwrap(), "--output", output.to_str().unwrap()];
    let fixture = Fixture::default();
    assert_eq!(fixture.run(&host, &report).stderr, "BLOCKED: no installer transaction exists\n");
    host.install_journal(&golden().join("journals/rolled-back"));
    assert_eq!(fixture.run(&host, &report).stderr, "BLOCKED: a report requires a completed installation\n");
    let host = Host::new("cli-report-mcp");
    host.install_journal(&golden().join("installs/kitchen-sink/journal"));
    let kitchen = golden().join("plans/kitchen-sink/config.toml");
    let ran =
        fixture.run(&host, &["report", "--config", kitchen.to_str().unwrap(), "--output", output.to_str().unwrap()]);
    assert_eq!(ran.code, 2);
    assert_eq!(ran.stderr, "BLOCKED: the MCP handoff cannot be written: no MCP in this test\n");
}

#[test]
fn status_of_a_host_without_a_journal() {
    let host = Host::new("cli-legacy");
    let fixture = Fixture::default();
    let ran = fixture.run(&host, &["status"]);
    assert_eq!((ran.code, ran.stderr.as_str()), (2, "BLOCKED: no installer transaction exists\n"));
    let legacy = host.root.join("var/lib/proxy-control/runtime.json");
    write(&legacy, br#"{"status": "half-done", "plan_digest": "abc"}"#);
    let ran = fixture.run(&host, &["status", "--json"]);
    assert_eq!(ran.code, 0);
    assert_eq!(
        serde_json::from_str::<Value>(&ran.stdout).unwrap(),
        json!({
            "checkpoints": [], "error": "legacy transaction requires import", "origin": "runtime-v2-unimported",
            "plan_digest": "0".repeat(64), "schema": 1, "status": "rollback_failed",
        })
    );
    let digest = "e".repeat(64);
    write(&legacy, format!(r#"{{"status": "active", "plan_digest": "{digest}"}}"#).as_bytes());
    let ran = fixture.run(&host, &["status"]);
    assert_eq!(
        ran.stdout,
        format!("status: active\nplan_digest: {digest}\norigin: runtime-v2-unimported\nerror: legacy transaction requires import\n")
    );
    for command in ["resume", "repair", "uninstall"] {
        let ran = fixture.run(&host, &[command]);
        assert_eq!(
            ran.stderr,
            "BLOCKED: this host has a legacy runtime-v2 installation, which this installer cannot import\n"
        );
    }
    write(&legacy, b"[]");
    assert_eq!(fixture.run(&host, &["status"]).stderr, "BLOCKED: legacy runtime state is invalid\n");
    write(&legacy, b"{");
    assert_eq!(fixture.run(&host, &["resume"]).stderr, "BLOCKED: legacy runtime state is unreadable\n");
}

/// The adapters `adapters_for(core.toml)` selects, as the transaction tests' recording adapter.
fn recording_adapters(host: &Host) -> Vec<Arc<RecordingAdapter>> {
    ["packages", "nginx", "firewall", "certificates", "core", "version_agent"]
        .iter()
        .map(|name| Arc::new(RecordingAdapter::new(name, &host.root)))
        .collect()
}

fn fixture_with(adapters: &[Arc<RecordingAdapter>]) -> Fixture {
    Fixture {
        facts: test_facts(),
        adapters: adapters.iter().map(|adapter| adapter.clone() as Arc<dyn Adapter>).collect(),
        ..Fixture::default()
    }
}

fn plan_digest(fixture: &Fixture, host: &Host) -> String {
    let core = core_toml();
    let ran = fixture.run(host, &["plan", "--config", core.to_str().unwrap(), "--json"]);
    assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
    serde_json::from_str::<Value>(&ran.stdout).unwrap()["digest"].as_str().unwrap().to_string()
}

#[test]
fn install_status_repair_and_uninstall_through_the_cli() {
    let host = Host::new("cli-install");
    let adapters = recording_adapters(&host);
    let fixture = fixture_with(&adapters);
    let digest = plan_digest(&fixture, &host);
    let core = core_toml();
    let core = core.to_str().unwrap();
    let install = |accept: &str| fixture.run(&host, &["install", "--config", core, "--accept-plan", accept, "--json"]);
    assert_eq!(install(&digest[..12]).stderr, "BLOCKED: --accept-plan requires the complete plan digest\n");
    assert_eq!(install(&"0".repeat(64)).stderr, "BLOCKED: accepted plan digest does not match\n");
    assert!(!host.journal().join("state.json").exists());

    let ran = install(&digest);
    assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
    let status: Value = serde_json::from_str(&ran.stdout).unwrap();
    assert_eq!(status["status"], "active");
    assert_eq!(status["plan_digest"], digest.as_str());
    let checkpoints: Vec<(String, String, bool)> = status["checkpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["action_id"].as_str().unwrap().into(), c["phase"].as_str().unwrap().into(), c["success"] == true))
        .collect();
    let ids = ["packages", "nginx", "firewall", "certificates", "core", "version_agent"];
    assert_eq!(checkpoints, ids.map(|name| (format!("{name}.install"), "verified".to_string(), true)));
    assert!(host.root.join("core.owned").exists());
    assert!(!installer_core::credentials::staged_path(&host.root).unwrap().exists());

    let ran = fixture.run(&host, &["status"]);
    assert_eq!(ran.stdout, format!("status: active\nplan_digest: {digest}\norigin: installer-v1\n"));
    // Re-installing the same intent is a no-op.
    assert_eq!(install(&digest).code, 0);
    assert_eq!(fs::read_to_string(host.root.join("core.mutations")).unwrap(), "1");
    // repair restores a removed owned file.
    fs::remove_file(host.root.join("core.owned")).unwrap();
    let ran = fixture.run(&host, &["repair", "--json"]);
    assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
    assert!(host.root.join("core.owned").exists());
    assert_eq!(fixture.run(&host, &["resume"]).code, 0);

    let ran = fixture.run(&host, &["uninstall"]);
    assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
    assert!(ran.stdout.starts_with("status: uninstalled\n"), "{}", ran.stdout);
    assert!(!host.root.join("core.owned").exists());
}

#[test]
fn a_failed_install_rolls_back_and_a_crash_is_resumed() {
    let host = Host::new("cli-failure");
    let mut adapters = recording_adapters(&host);
    adapters[4] = Arc::new(RecordingAdapter { fail_apply: true, ..RecordingAdapter::new("core", &host.root) });
    let fixture = fixture_with(&adapters);
    let digest = plan_digest(&fixture, &host);
    let core = core_toml();
    let core = core.to_str().unwrap();
    let ran = fixture.run(&host, &["install", "--config", core, "--accept-plan", &digest]);
    assert_eq!((ran.code, ran.stdout.as_str(), ran.stderr.as_str()), (2, "", "BLOCKED: core failed\n"));
    let ran = fixture.run(&host, &["status"]);
    assert_eq!(
        ran.stdout,
        format!("status: rolled_back\nplan_digest: {digest}\norigin: installer-v1\nerror: RuntimeError\n")
    );
    assert!(!host.root.join("packages.owned").exists());

    let host = Host::new("cli-crash");
    let mut adapters = recording_adapters(&host);
    let crashing = RecordingAdapter::new("core", &host.root);
    *crashing.crash_during_apply.lock().unwrap() = Some(Injected::Crash);
    adapters[4] = Arc::new(crashing);
    let fixture = fixture_with(&adapters);
    let ran = fixture.run(&host, &["install", "--config", core, "--accept-plan", &plan_digest(&fixture, &host)]);
    assert_eq!((ran.code, ran.stdout.as_str(), ran.stderr.as_str()), (1, "", "apply mutation committed\n"));
    assert!(fixture.run(&host, &["status"]).stdout.starts_with("status: applying\n"));
    let ran = fixture.run(&host, &["resume", "--json"]);
    assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
    assert_eq!(serde_json::from_str::<Value>(&ran.stdout).unwrap()["status"], "active");
}

/// `tar -czf` of `files` under `proxy-control/`.
fn release_archive(directory: &Path, files: &[(&str, &[u8])]) -> PathBuf {
    let tree = directory.join("archive-tree");
    for (name, data) in files {
        write(&tree.join("proxy-control").join(name), data);
    }
    let archive = directory.join("release.tar.gz");
    let status = std::process::Command::new("tar")
        .args(["-czf", archive.to_str().unwrap(), "-C", tree.to_str().unwrap(), "proxy-control"])
        .status()
        .unwrap();
    assert!(status.success());
    archive
}

#[test]
fn reconcile_panel_update_rebases_core_ownership_to_the_running_release() {
    let dir = TempDir::new("cli-reconcile");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let identity = json!({
        "commit": "a".repeat(40), "manifest_sha256": "b".repeat(64), "schema": 1, "tag": "v1.1.2-rc.1",
        "version": "1.1.2-rc.1",
    });
    let identity = pc_host::json::pretty2(&identity);
    let files: [(&str, &[u8]); 3] =
        [("VERSION", b"1.1.2-rc.1\n"), ("panel/app.py", b"new panel\n"), ("release/release.json", identity.as_bytes())];
    // An old agent synced the release but left Core's ownership generation as it was.
    let project = host_path(&root, PROJECT);
    fs::remove_dir_all(project.join("panel")).unwrap();
    for (name, data) in files {
        write(&project.join(name), data);
    }
    let archive = release_archive(dir.path(), &files);
    let sha256 = sha256_hex(&read(&archive));
    let host = Host { dir, root, tree: PathBuf::from("/nonexistent") };
    let runner = Arc::new(RecordingRunner::new());
    let fixture = Fixture { runner: Some(runner.clone()), ..Fixture::default() };
    let reconcile = |sha: &str| {
        fixture.run(&host, &["reconcile-panel-update", "--archive", archive.to_str().unwrap(), "--sha256", sha])
    };

    assert_eq!(reconcile("ABC").stderr, "BLOCKED: release archive SHA-256 must be 64 lowercase hex digits\n");
    assert_eq!(reconcile(&"0".repeat(64)).stderr, "BLOCKED: release archive SHA-256 mismatch\n");
    runner.reply_once(&["docker", "exec"], Reply::exit(1, "", "no such container"));
    assert_eq!(reconcile(&sha256).stderr, "BLOCKED: running panel version could not be verified\n");
    runner.reply_once(&["docker", "exec"], Reply::ok("1.1.1\n"));
    assert_eq!(reconcile(&sha256).stderr, "BLOCKED: archive identity does not match the running panel\n");
    let core_digest = || {
        let state = owned.engine.store().read_state().unwrap();
        state.checkpoint("core.runtime").unwrap().data["ownership"]["/opt/mtproxy-shared443/VERSION"]["sha256"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_ne!(core_digest(), sha256_hex(b"1.1.2-rc.1\n"));

    runner.clear();
    runner.reply(&["docker", "exec", "proxy-control-panel", "cat", "/app/VERSION"], Reply::ok("1.1.2-rc.1\n"));
    let ran = reconcile(&sha256);
    assert_eq!((ran.code, ran.stderr.as_str()), (0, ""));
    assert!(ran.stdout.starts_with("status: active\n"), "{}", ran.stdout);
    assert_eq!(runner.argvs(), vec![vec!["docker", "exec", "proxy-control-panel", "cat", "/app/VERSION"]]);
    assert_eq!(core_digest(), sha256_hex(b"1.1.2-rc.1\n"));
    assert_eq!(owned.engine.repair().unwrap().status, Status::Active);
}

#[test]
fn release_versions_follow_the_python_pattern() {
    for good in ["1.2.3", "10.0.0", "1.1.2-rc.1", "1.2.3.4", "3.3.0-beta.2.x"] {
        assert!(is_release_version(good), "{good}");
    }
    for bad in ["1.2", "1.2.3-", "1.2.3_x", "v1.2.3", "1..3", "1.2.3-r c", "１.2.3", ""] {
        assert!(!is_release_version(bad), "{bad}");
    }
    assert!(is_commit(&"0".repeat(40)) && !is_commit(&"A".repeat(40)));
}
