//! Ported from `tests/test_version_agent.py` (listing, upstream cache, update plumbing) and
//! `tests/test_version_agent_managers.py` (heal, ack), plus the golden agent states and
//! `/v1/versions` bodies.

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use super::*;
use crate::errors::{AgentError, UpdateState};
use crate::runner::{Command, CommandError};
use crate::testutil::TempDir;

type Answer = dyn Fn(&[String]) -> Result<String, CommandError> + Send + Sync;

/// A runner that records every argv and answers through `answer`.
#[derive(Clone)]
pub(crate) struct FakeRunner {
    pub calls: Arc<Mutex<Vec<Vec<String>>>>,
    answer: Arc<Answer>,
}

impl FakeRunner {
    pub fn new(answer: impl Fn(&[String]) -> Result<String, CommandError> + Send + Sync + 'static) -> FakeRunner {
        FakeRunner { calls: Arc::new(Mutex::new(Vec::new())), answer: Arc::new(answer) }
    }

    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, command: &Command) -> Result<String, CommandError> {
        self.calls.lock().unwrap().push(command.argv.clone());
        (self.answer)(&command.argv)
    }
}

/// An updater that records what it was asked and installs the entry as given.
#[derive(Default)]
struct Recording {
    applied: Mutex<Vec<(String, String, Option<String>)>>,
    fail: Option<UpdateError>,
}

impl Updater for Recording {
    fn apply(
        &self,
        _: &Arc<VersionAgent>,
        component: &str,
        entry: &CatalogEntry,
        current: Option<&str>,
    ) -> Result<Applied, UpdateError> {
        self.applied.lock().unwrap().push((component.into(), entry.version.clone(), current.map(String::from)));
        match &self.fail {
            Some(error) => Err(error.clone()),
            None => Ok(Applied::from_entry(entry)),
        }
    }

    fn update_panel(&self, _: &Arc<VersionAgent>, version: &str, _: Option<&str>) -> Result<Value, AgentError> {
        Ok(json!({"component": "panel", "version": version, "changed": true, "async": true}))
    }

    fn rebuild_managers(&self, agent: &Arc<VersionAgent>) -> Result<Value, AgentError> {
        NotPorted.rebuild_managers(agent)
    }
}

const TELEMT_IMAGE: &str =
    "ghcr.io/example/telemt@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn binary_sha() -> String {
    pc_host::fs::sha256_hex(b"verified-runtime-binary\n")
}

/// `write_catalog` of the Python tests.
fn write_catalog(path: &Path) {
    let document = json!({"schema": 1, "components": {
        "telemt": [{"version": "3.4.25", "kind": "image", "image": TELEMT_IMAGE}],
        "naive": [{"version": "2.11.4-custom.1", "kind": "binary", "url": "https://artifacts.example.com/caddy-2.11.4-custom.1",
                   "sha256": binary_sha()}],
        "mita": [{"version": "3.35.0", "kind": "binary", "url": "https://artifacts.example.com/mita-3.35.0", "sha256": binary_sha()}],
    }});
    std::fs::write(path, document.to_string()).unwrap();
}

fn mita_candidate() -> Value {
    json!({"version": "3.37.0", "tag": "v3.37.0", "kind": "binary", "source": "upstream",
           "url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz",
           "sha256": "b".repeat(64), "archive": {"format": "tar.gz", "member": "mita"}, "published_at": null})
}

/// `_agent(tmp_path)`: the catalog above, a runner that answers `active`.
fn agent_in(dir: &TempDir) -> VersionAgent {
    let catalog = dir.join("catalog.json");
    write_catalog(&catalog);
    let mut agent = VersionAgent::new(AgentConfig::new(catalog, dir.join("state.json")));
    agent.runner = Arc::new(FakeRunner::new(|_| Ok("active\n".into())));
    agent
}

fn fixed_clock(now: Arc<Mutex<f64>>) -> Box<dyn Fn() -> f64 + Send + Sync> {
    Box::new(move || *now.lock().unwrap())
}

fn probes(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn versions_of(listed: &Value, component: &str) -> Vec<String> {
    listed["components"][component]["available"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["version"].as_str().unwrap().into())
        .collect()
}

#[test]
fn check_upstream_caches_candidates_and_lists_them_after_the_catalog() {
    let dir = TempDir::new("agent-check");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let now = Arc::new(Mutex::new(1_000_000.0));
    let mut agent = agent_in(&dir);
    agent.clock = fixed_clock(now.clone());
    let seen = calls.clone();
    agent.checker = Box::new(move |current, _, _| {
        seen.lock().unwrap().push(current.clone());
        probes(json!({
            "mita": {"latest": "3.37.0", "installable": true, "reason": null, "candidates": [mita_candidate()]},
            "telemt": {"latest": null, "installable": false, "reason": "no_releases", "candidates": []},
            "naive": {"latest": null, "installable": false, "reason": null, "candidates": [], "last_error": "upstream unreachable"},
            "xray": {"latest": null, "installable": false, "reason": "router_not_installed", "candidates": []},
        }))
    });
    let listed = agent.check_upstream(false).unwrap();
    let expected: BTreeMap<String, Option<String>> =
        ["telemt", "naive", "mita", "panel"].iter().map(|c| (c.to_string(), None)).collect();
    assert_eq!(*calls.lock().unwrap(), vec![expected]);
    let mita = &listed["components"]["mita"];
    assert_eq!(versions_of(&listed, "mita"), ["3.35.0", "3.37.0"]);
    assert_eq!(
        (&mita["available"][0]["source"], &mita["available"][1]["source"]),
        (&json!("catalog"), &json!("upstream"))
    );
    assert_eq!(
        mita["upstream"],
        json!({"checked_at": 1_000_000, "latest": "3.37.0", "installable": true, "reason": null, "last_error": null})
    );
    assert_eq!((&listed["checked_at"], &listed["upstream_enabled"]), (&json!(1_000_000), &json!(true)));
    assert_eq!(listed["components"]["naive"]["upstream"]["last_error"], "upstream unreachable");
    assert!(listed["components"].get("xray").is_none()); // router off → the component is not shown
    let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("state.json")).unwrap()).unwrap();
    assert_eq!(saved["schema"], 2);
    assert_eq!(agent.list_versions(true).unwrap(), listed);
    *now.lock().unwrap() += 30.0;
    agent.check_upstream(false).unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1); // inside the 60 s window the cache answers
    *now.lock().unwrap() += 31.0;
    agent.check_upstream(false).unwrap();
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn a_failed_source_keeps_its_previous_candidates_next_to_the_error() {
    let dir = TempDir::new("agent-failed-source");
    let answers = Arc::new(Mutex::new(vec![
        probes(json!({"mita": {"latest": null, "installable": false, "reason": null, "candidates": [],
                               "last_error": "upstream answered 403"}})),
        probes(
            json!({"mita": {"latest": "3.37.0", "installable": true, "reason": null, "candidates": [mita_candidate()]}}),
        ),
    ]));
    let now = Arc::new(Mutex::new(1000.0));
    let mut agent = agent_in(&dir);
    agent.clock = fixed_clock(now.clone());
    agent.checker = Box::new(move |_, _, _| answers.lock().unwrap().pop().unwrap());
    agent.check_upstream(false).unwrap();
    *now.lock().unwrap() += 100.0;
    let listed = agent.check_upstream(false).unwrap();
    let mita = &listed["components"]["mita"];
    assert_eq!(versions_of(&listed, "mita"), ["3.35.0", "3.37.0"]);
    assert_eq!(
        (&mita["upstream"]["last_error"], &mita["upstream"]["latest"]),
        (&json!("upstream answered 403"), &json!("3.37.0"))
    );
}

#[test]
fn update_installs_a_cached_upstream_candidate_by_version() {
    let dir = TempDir::new("agent-cached-update");
    let mut agent = agent_in(&dir);
    let digest = "c".repeat(64);
    let mut candidate = mita_candidate();
    candidate["sha256"] = json!(digest);
    agent.checker = Box::new(move |_, _, _| {
        probes(
            json!({"mita": {"latest": "3.37.0", "installable": true, "reason": null, "candidates": [candidate.clone()]}}),
        )
    });
    let recording = Arc::new(Recording::default());
    agent.updater = recording.clone();
    let agent = Arc::new(agent);
    agent.check_upstream(false).unwrap();
    let result = agent.update("mita", "3.37.0", None).unwrap();
    assert_eq!(result, json!({"component": "mita", "version": "3.37.0", "changed": true}));
    assert_eq!(*recording.applied.lock().unwrap(), [("mita".to_string(), "3.37.0".to_string(), None)]);
    let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("state.json")).unwrap()).unwrap();
    let mita = &saved["components"]["mita"];
    assert_eq!(
        (&mita["version"], &mita["source"], &mita["sha256"]),
        (&json!("3.37.0"), &json!("upstream"), &json!(digest))
    );
    assert_eq!(mita["archive"], json!({"format": "tar.gz", "member": "mita"}));
    assert_eq!(mita["image"], Value::Null);
    assert!(mita["updated_at"].is_i64());
    // v1.0.1: the screen splits the list into updates and roll-backs by `newer`.
    let listed = agent.list_versions(true).unwrap();
    let newer: BTreeMap<String, bool> = listed["components"]["mita"]["available"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["version"].as_str().unwrap().to_string(), e["newer"].as_bool().unwrap()))
        .collect();
    assert_eq!(newer, BTreeMap::from([("3.35.0".to_string(), false), ("3.37.0".to_string(), false)]));
    // The same version again is not a change.
    assert_eq!(agent.update("mita", "3.37.0", None).unwrap()["changed"], false);
}

#[test]
fn update_refuses_a_version_that_is_neither_in_the_catalog_nor_cached() {
    let dir = TempDir::new("agent-not-approved");
    let agent = Arc::new(agent_in(&dir));
    let error = agent.update("mita", "9.9.9", None).unwrap_err();
    assert!(matches!(&error, AgentError::Catalog(e) if e.0.contains("not approved")), "{error:?}");
    let error = agent.update("xray", "26.4.1", None).unwrap_err();
    assert!(matches!(&error, AgentError::Catalog(e) if e.0.contains("unsupported component")), "{error:?}");
}

#[test]
fn upstream_disabled_lists_only_the_catalog_and_refuses_to_check() {
    let dir = TempDir::new("agent-upstream-off");
    let mut agent = agent_in(&dir);
    agent.config.upstream_enabled = false;
    let listed = agent.list_versions(true).unwrap();
    assert_eq!(listed["upstream_enabled"], false);
    assert_eq!(versions_of(&listed, "mita"), ["3.35.0"]);
    let error = agent.check_upstream(false).unwrap_err();
    assert!(error.message().contains("disabled"));
    assert_eq!(error.update_state(), Some(UpdateState::UpdateFailed));
}

#[test]
fn update_rejects_stale_expected_revision() {
    let dir = TempDir::new("agent-stale");
    std::fs::write(dir.join("state.json"), json!({"components": {"naive": {"version": "2.11.3"}}}).to_string())
        .unwrap();
    let agent = Arc::new(agent_in(&dir));
    let error = agent.update("naive", "2.11.4-custom.1", Some("2.11.2")).unwrap_err();
    assert!(matches!(&error, AgentError::Conflict(message) if message.contains("changed")), "{error:?}");
}

#[test]
fn an_unverified_rollback_blocks_updates_and_a_failed_rollback_is_recorded() {
    let dir = TempDir::new("agent-rollback-failed");
    std::fs::write(
        dir.join("state.json"),
        json!({"components": {"mita": {"version": "3.34.0", "kind": "binary"}}}).to_string(),
    )
    .unwrap();
    let mut agent = agent_in(&dir);
    agent.now = Box::new(|| 1_767_225_600.5);
    agent.updater = Arc::new(Recording {
        fail: Some(UpdateError::rollback_failed("restored generation is unhealthy")),
        ..Recording::default()
    });
    let agent = Arc::new(agent);
    let error = agent.update("mita", "3.35.0", Some("3.34.0")).unwrap_err();
    assert_eq!(error.update_state(), Some(UpdateState::RollbackFailed));
    let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("state.json")).unwrap()).unwrap();
    assert_eq!(
        saved["components"]["mita"],
        json!({"version": "3.34.0", "kind": "binary", "status": "rollback_failed",
                                                  "failed_at": 1_767_225_600})
    );
    let error = agent.update("mita", "3.35.0", Some("3.34.0")).unwrap_err();
    assert!(error.message().contains("operator recovery"), "{error:?}");
    assert_eq!(error.update_state(), Some(UpdateState::RollbackFailed));
}

#[test]
fn the_stub_updater_refuses_with_the_python_error_shape() {
    let dir = TempDir::new("agent-stub");
    std::fs::write(dir.join("state.json"), json!({"components": {"naive": {"version": "2.11.3"}}}).to_string())
        .unwrap();
    let mut agent = agent_in(&dir);
    agent.updater = Arc::new(NotPorted);
    let agent = Arc::new(agent);
    let before = std::fs::read(dir.join("state.json")).unwrap();
    let error = agent.update("naive", "2.11.4-custom.1", None).unwrap_err();
    assert_eq!(error.update_state(), Some(UpdateState::UpdateFailed));
    assert_eq!(std::fs::read(dir.join("state.json")).unwrap(), before);
    assert_eq!(agent.update("panel", "9.9.9", None).unwrap_err().update_state(), Some(UpdateState::UpdateFailed));
}

#[test]
fn cached_upstream_telemt_build_candidate_is_installable_and_listed() {
    let dir = TempDir::new("agent-telemt-build");
    let base = format!("ghcr.io/samnet-dev/mtproxymax-telemt@sha256:{}", "d".repeat(64));
    let sha = pc_host::fs::sha256_hex(b"\x7fELF-telemt-3.5.14");
    let candidate = json!({"version": "3.5.14", "tag": "3.5.14", "kind": "build", "source": "upstream", "base_image": base,
                           "url": "https://github.com/telemt/telemt/releases/download/3.5.14/telemt", "sha256": sha,
                           "published_at": "2026-10-05T15:39:55Z"});
    std::fs::write(dir.join("catalog.json"), r#"{"schema": 1, "components": {}}"#).unwrap();
    std::fs::write(
        dir.join("state.json"),
        json!({"components": {"telemt": {"version": "3.5.9"}}, "upstream": {"checked_at": 1, "components": {
            "telemt": {"latest": "3.5.14", "installable": true, "reason": null, "candidates": [candidate]}}}})
        .to_string(),
    )
    .unwrap();
    let mut agent = VersionAgent::new(AgentConfig::new(dir.join("catalog.json"), dir.join("state.json")));
    agent.runner = Arc::new(FakeRunner::new(|_| Ok("ok\n".into())));
    agent.updater = Arc::new(Recording::default());
    let agent = Arc::new(agent);
    let listed = agent.list_versions(true).unwrap()["components"]["telemt"]["available"].clone();
    assert_eq!(
        (&listed[0]["kind"], &listed[0]["base_image"], &listed[0]["newer"]),
        (&json!("build"), &json!(base), &json!(true))
    );
    assert_eq!(agent.update("telemt", "3.5.14", Some("3.5.9")).unwrap()["changed"], true);
    let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("state.json")).unwrap()).unwrap();
    let telemt = &saved["components"]["telemt"];
    assert_eq!(
        (&telemt["kind"], &telemt["base_image"], &telemt["source"]),
        (&json!("build"), &json!(base), &json!("upstream"))
    );
}

#[test]
fn state_reading_keeps_python_rules() {
    let dir = TempDir::new("agent-state");
    let path = dir.join("state.json");
    assert_eq!(load_state(&path).unwrap(), probes(json!({"schema": 2, "components": {}})));
    for (text, message) in [
        ("not json", "version state is unreadable"),
        ("[]", "version state is invalid"),
        (r#"{"schema": 3}"#, "version state is invalid"),
        (r#"{"components": []}"#, "version state is invalid"),
        (r#"{"upstream": 1}"#, "version state is invalid"),
    ] {
        std::fs::write(&path, text).unwrap();
        assert_eq!(load_state(&path).unwrap_err().message, message, "{text}");
    }
    for text in [r#"{"schema": 1}"#, r#"{"schema": true}"#, r#"{"schema": 2.0}"#, "{}"] {
        std::fs::write(&path, text).unwrap();
        assert!(load_state(&path).is_ok(), "{text}");
    }
}

#[test]
fn configuration_from_the_environment() {
    let env: BTreeMap<&str, &str> = BTreeMap::from([
        ("PROXY_CONTROL_COMPOSE_FILES", "compose.yaml::compose.naive.yaml:"),
        ("PROXY_CONTROL_BINARY_PATHS", "naive=/a,broken, mita = /b"),
        ("PROXY_CONTROL_XRAY_ROUTER", " Yes "),
        ("PROXY_CONTROL_UPSTREAM_CHECK", " OFF"),
        ("PROXY_CONTROL_PANEL_IMAGE", ""),
        ("PROXY_CONTROL_PANEL_VOLUME", "mtproxy_panel-data"),
        ("PROXY_CONTROL_VERSION_HEALTH_TIMEOUT", " 90 "),
        ("VERSION_AGENT_AUTO_REBUILD_MANAGERS", "0"),
    ]);
    let config = AgentConfig::from_env(|name| env.get(name).map(|v| v.to_string())).unwrap();
    assert_eq!(config.compose_files, ["compose.yaml", "compose.naive.yaml"]);
    assert_eq!(config.binary_paths.get("naive"), Some(&PathBuf::from("/a")));
    assert_eq!(config.binary_paths.get(" mita "), Some(&PathBuf::from(" /b")));
    assert!(config.router_enabled && !config.upstream_enabled && !config.auto_rebuild_managers);
    assert_eq!(config.health_timeout, 90.0);
    assert_eq!(config.panel_image, None);
    assert_eq!(VersionAgent::new(config).config.panel_volume, None);
    let defaults = AgentConfig::from_env(|_| None).unwrap();
    assert_eq!(defaults.state_path, PathBuf::from("/var/lib/proxy-control/version-agent/state.json"));
    assert_eq!(defaults.compose_dir, Some(PathBuf::from("/opt/mtproxy-shared443")));
    assert_eq!(
        defaults.consumer_overlays.get("mita"),
        Some(&(PathBuf::from("/opt/mtproxy-shared443/.env.mieru"), "MIERU_MITA_SHA256".into(), "mieru-manager".into()))
    );
    assert!(AgentConfig::from_env(|name| (name == "PROXY_CONTROL_CONSUMER_OVERLAYS").then(|| "mita=/x:y".to_string()))
        .is_err());
    assert!(AgentConfig::from_env(|name| (name == "PROXY_CONTROL_VERSION_HEALTH_TIMEOUT").then(String::new)).is_err());
}

#[test]
fn docker_epochs_parse_like_strptime() {
    assert_eq!(docker_epoch("2020-01-01T00:00:00.123456789Z").unwrap(), 1_577_836_800);
    assert_eq!(docker_epoch(" 2026-01-01T00:00:00+03:00\n").unwrap(), 1_767_225_600 - 3 * 3600);
    assert_eq!(docker_epoch("2026-01-01T00:00:00-01:30").unwrap(), 1_767_225_600 + 5400);
    for bad in ["2026-02-30T00:00:00Z", "2026-01-01 00:00:00Z", "2026-01-01T00:00:00", "nope", "2026-01-01T00:00:00.Z"]
    {
        assert!(docker_epoch(bad).is_err(), "{bad}");
    }
}

// --- pending_rebuild: heal, ack, rebuild ------------------------------------------------------

fn hex_id(service: &str) -> String {
    service.bytes().map(|b| format!("{b:02x}")).collect::<String>().repeat(64)[..64].to_string()
}

fn iso(epoch: i64) -> String {
    let (year, month, day) = pc_common::logger::civil_from_days(epoch.div_euclid(86_400));
    let rest = epoch.rem_euclid(86_400);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000000001Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

const OLD: &str = "2020-01-01T00:00:00.123456789Z";
const UPDATED_AT: i64 = 1_767_225_600;

/// The managers' host: a container per service with an image created at `created[service]`.
fn manager_agent(
    dir: &TempDir,
    created: Arc<Mutex<BTreeMap<String, String>>>,
    broken: Arc<Mutex<bool>>,
) -> (VersionAgent, FakeRunner) {
    let compose = dir.join("compose");
    std::fs::create_dir_all(&compose).unwrap();
    std::fs::write(
        compose.join("compose.xray-router.yaml"),
        "services:\n  xray-router:\n    image: x\n  xray-router-ingress:\n    image: x\n",
    )
    .unwrap();
    std::fs::write(dir.join("catalog.json"), r#"{"schema": 1, "components": {}}"#).unwrap();
    let runner = FakeRunner::new(move |argv| {
        let created = created.lock().unwrap();
        if argv.starts_with(&["docker".into(), "ps".into(), "-a".into()]) && argv.len() > 6 {
            let service = argv[6].rsplit_once('=').unwrap().1.to_string();
            return Ok(if created.contains_key(&service) { hex_id(&service) } else { String::new() });
        }
        if argv[..2] == ["docker", "inspect"] && argv.contains(&"{{.Image}}".to_string()) {
            let service = created.keys().find(|s| hex_id(s) == *argv.last().unwrap()).unwrap();
            return Ok(format!("sha256:{}", hex_id(service)));
        }
        if argv[..3] == ["docker", "image", "inspect"] {
            if *broken.lock().unwrap() {
                return Err(CommandError::Os("docker down".into()));
            }
            let service = created.keys().find(|s| format!("sha256:{}", hex_id(s)) == *argv.last().unwrap()).unwrap();
            return Ok(created[service].clone());
        }
        if argv[..2] == ["docker", "inspect"] && argv.last().unwrap() == "proxy-control-panel" {
            return Ok("proxy_panel_by_dubr1k".into());
        }
        Ok(String::new())
    });
    let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
    config.compose_dir = Some(compose);
    config.compose_files = ["compose.yaml", "compose.naive.yaml", "compose.xray-router.yaml", "compose.mcp.yaml"]
        .map(String::from)
        .to_vec();
    let mut agent = VersionAgent::new(config);
    agent.runner = Arc::new(runner.clone());
    agent.now = Box::new(|| (UPDATED_AT + 100) as f64);
    (agent, runner)
}

fn write_panel(dir: &TempDir, panel: Value) {
    std::fs::write(dir.join("state.json"), json!({"schema": 2, "components": {"panel": panel}}).to_string()).unwrap();
}

fn panel_state(dir: &TempDir) -> Value {
    let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("state.json")).unwrap()).unwrap();
    saved["components"]["panel"].clone()
}

fn ready_panel(pending: &[&str]) -> Value {
    json!({"version": "0.11.0-beta.1", "kind": "release", "status": "ready", "updated_at": UPDATED_AT, "pending_rebuild": pending})
}

fn created(services: &[(&str, String)]) -> Arc<Mutex<BTreeMap<String, String>>> {
    Arc::new(Mutex::new(services.iter().map(|(s, c)| (s.to_string(), c.clone())).collect()))
}

#[test]
fn card_drops_managers_whose_container_image_is_newer_than_the_panel_update() {
    let dir = TempDir::new("heal-newer");
    let services =
        created(&[("naive-manager", OLD.into()), ("xray-router", iso(UPDATED_AT + 60)), ("mcp", iso(UPDATED_AT + 60))]);
    let (agent, _) = manager_agent(&dir, services, Arc::new(Mutex::new(false)));
    write_panel(&dir, ready_panel(&["naive_manager", "xray_router_manager", "mcp_server", "docker"]));
    let listed = agent.list_versions(true).unwrap();
    // naive is still old; the router (both services) and mcp were rebuilt; docker is untouched.
    assert_eq!(listed["components"]["panel"]["pending_rebuild"], json!(["naive_manager", "docker"]));
    assert_eq!(panel_state(&dir)["pending_rebuild"], json!(["naive_manager", "docker"]));
    // persisted
}

#[test]
fn slack_and_missing_services_and_absent_overlays() {
    let dir = TempDir::new("heal-slack");
    let services = created(&[("naive-manager", iso(UPDATED_AT - 5))]);
    let (agent, _) = manager_agent(&dir, services.clone(), Arc::new(Mutex::new(false)));
    write_panel(&dir, ready_panel(&["naive_manager", "mcp_server", "awg_manager"]));
    // mcp has no container, awg has no overlay: nothing to rebuild for either.
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["pending_rebuild"], json!([]));
    services.lock().unwrap().insert("naive-manager".into(), iso(UPDATED_AT - 60));
    write_panel(&dir, ready_panel(&["naive_manager"]));
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["pending_rebuild"], json!(["naive_manager"]));
}

#[test]
fn docker_error_leaves_the_list_unchanged_and_nothing_runs_for_an_empty_list() {
    let dir = TempDir::new("heal-docker-error");
    let broken = Arc::new(Mutex::new(true));
    let services = created(&[("naive-manager", iso(UPDATED_AT + 3600))]);
    let (agent, runner) = manager_agent(&dir, services, broken.clone());
    write_panel(&dir, ready_panel(&["naive_manager"]));
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["pending_rebuild"], json!(["naive_manager"]));
    *broken.lock().unwrap() = false;
    assert_eq!(agent.list_versions(true).unwrap()["components"]["panel"]["pending_rebuild"], json!([]));
    write_panel(&dir, ready_panel(&[]));
    runner.calls.lock().unwrap().clear();
    agent.list_versions(true).unwrap();
    assert!(!runner.calls().iter().any(|c| c[..2] == ["docker", "ps"] && c.contains(&"-a".to_string())));
}

#[test]
fn manual_rebuild_refuses_while_updating_and_ack_is_idempotent() {
    let dir = TempDir::new("ack");
    let services = created(&[("naive-manager", OLD.into()), ("mcp", OLD.into())]);
    let (agent, _) = manager_agent(&dir, services, Arc::new(Mutex::new(false)));
    let agent = Arc::new(agent);
    write_panel(&dir, ready_panel(&["naive_manager", "mcp_server", "docker"]));
    assert!(matches!(agent.ack_managers(&json!([])), Err(AgentError::Invalid(_))));
    assert!(matches!(agent.ack_managers(&json!(["nope"])), Err(AgentError::Invalid(_))));
    assert!(matches!(agent.ack_managers(&json!("mcp_server")), Err(AgentError::Invalid(_))));
    assert_eq!(
        agent.ack_managers(&json!(["mcp_server"])).unwrap()["pending_rebuild"],
        json!(["naive_manager", "docker"])
    );
    assert_eq!(
        agent.ack_managers(&json!(["mcp_server"])).unwrap()["pending_rebuild"],
        json!(["naive_manager", "docker"])
    );
    let mut panel = panel_state(&dir);
    panel["status"] = json!("updating");
    write_panel(&dir, panel.clone());
    assert!(matches!(agent.rebuild_managers(), Err(AgentError::Conflict(_))));
    panel["status"] = json!("rollback_failed");
    write_panel(&dir, panel.clone());
    assert_eq!(agent.rebuild_managers().unwrap_err().update_state(), Some(UpdateState::RollbackFailed));
    panel["status"] = json!("ready");
    panel["pending_rebuild"] = json!(["docker"]);
    panel["managers_rebuilt_at"] = json!(5);
    write_panel(&dir, panel);
    // Nothing service-backed is pending: the state answers at once.
    assert_eq!(
        agent.rebuild_managers().unwrap(),
        json!({"pending_rebuild": ["docker"], "rebuilding": false, "managers_rebuilt_at": 5})
    );
}

#[test]
fn a_rebuild_marker_counts_for_half_an_hour() {
    let dir = TempDir::new("rebuilding");
    let (agent, _) = manager_agent(&dir, created(&[]), Arc::new(Mutex::new(false)));
    let now = UPDATED_AT + 100;
    let panel = |started: Value| json!({"rebuilding_managers": started}).as_object().unwrap().clone();
    assert!(agent.rebuilding(&panel(json!(now - 10))));
    assert!(!agent.rebuilding(&panel(json!(now - 1800))));
    assert!(!agent.rebuilding(&panel(json!(now + 10))));
    assert!(!agent.rebuilding(&panel(json!(true))));
    assert!(!agent.rebuilding(&panel(json!((now - 10) as f64 + 0.5))));
}

#[test]
fn stale_markers_are_recovered_at_start() {
    let dir = TempDir::new("recover");
    let (agent, _) = manager_agent(&dir, created(&[]), Arc::new(Mutex::new(false)));
    write_panel(
        &dir,
        json!({"version": "3.3.0", "kind": "release", "url": "u", "status": "updating", "started_at": 5}),
    );
    assert_eq!(agent.recover_interrupted().unwrap().len(), 1);
    assert_eq!(
        panel_state(&dir),
        json!({"version": "3.3.0", "kind": "release", "status": "update_failed", "last_error": INTERRUPTED_PANEL_UPDATE,
               "failed_at": UPDATED_AT + 100})
    );
    let mut panel = ready_panel(&["naive_manager"]);
    panel["rebuilding_managers"] = json!(UPDATED_AT + 90);
    write_panel(&dir, panel.clone());
    assert_eq!(agent.recover_interrupted().unwrap().len(), 1);
    let recovered = panel_state(&dir);
    assert!(recovered.get("rebuilding_managers").is_none());
    assert_eq!(recovered["rebuild_error"], INTERRUPTED_REBUILD);
    assert_eq!(recovered["pending_rebuild"], json!(["naive_manager"]));
    let before = std::fs::read(dir.join("state.json")).unwrap();
    assert!(agent.recover_interrupted().unwrap().is_empty());
    assert_eq!(std::fs::read(dir.join("state.json")).unwrap(), before);
}

// --- goldens ---------------------------------------------------------------------------------

fn golden_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/agent").join(relative)
}

fn golden_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(golden_path(relative)).unwrap_or_else(|err| panic!("{relative}: {err}"))
}

fn golden_json(relative: &str) -> Value {
    serde_json::from_slice(&golden_bytes(relative)).unwrap()
}

const STEPS: [&str; 6] = [
    "00-seed",
    "01-check-upstream",
    "02-update-telemt",
    "03-update-mita",
    "04-update-xray",
    "05-update-naive-rolled-back",
];

#[test]
fn seed_and_agent_states_are_read_and_written_back_byte_identical() {
    let dir = TempDir::new("golden-roundtrip");
    let agent = VersionAgent::new(AgentConfig::new(dir.join("catalog.json"), dir.join("state.json")));
    for seed in ["seed/state.json", "seed/state.core.json", "updates/00-seed/state.json"] {
        let bytes = golden_bytes(seed);
        std::fs::write(dir.join("state.json"), &bytes).unwrap();
        let mut state = agent.load_state().unwrap();
        // The installer's seed carries a newline (pretty2_ascii); the agent writes none.
        assert_eq!(pc_host::json::pretty2_ascii(&Value::Object(state.clone())).as_bytes(), bytes.as_slice(), "{seed}");
        agent.save_state(&mut state).unwrap();
        assert_eq!(std::fs::read(dir.join("state.json")).unwrap(), &bytes[..bytes.len() - 1], "{seed}");
    }
    for step in &STEPS[1..] {
        let bytes = golden_bytes(&format!("updates/{step}/state.json"));
        std::fs::write(dir.join("state.json"), &bytes).unwrap();
        let mut state = agent.load_state().unwrap();
        agent.save_state(&mut state).unwrap();
        assert_eq!(std::fs::read(dir.join("state.json")).unwrap(), bytes, "{step}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("state.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

/// The catalog the recorder used, rebuilt from the catalog entries the listings show.
fn golden_catalog() -> Value {
    let listed = golden_json("updates/01-check-upstream/versions.json");
    let mut components = Map::new();
    for (component, data) in listed["components"].as_object().unwrap() {
        let entries: Vec<Value> = data["available"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["source"] == "catalog")
            .map(|e| {
                let mut entry = e.as_object().unwrap().clone();
                entry.remove("newer");
                entry.remove("source");
                if component == "naive" {
                    entry.insert("runtime_version".into(), json!("v2.11.8 h1:golden"));
                }
                Value::Object(entry)
            })
            .collect();
        if !entries.is_empty() {
            components.insert(component.clone(), Value::Array(entries));
        }
    }
    json!({"schema": 1, "components": components})
}

fn golden_agent(dir: &TempDir) -> (VersionAgent, FakeRunner) {
    std::fs::write(dir.join("catalog.json"), golden_catalog().to_string()).unwrap();
    std::fs::create_dir_all(dir.join("project")).unwrap();
    let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
    config.compose_dir = Some(dir.join("project"));
    config.compose_files = ["compose.yaml", "compose.naive.yaml", "compose.mieru.yaml", "compose.xray-router.yaml"]
        .map(String::from)
        .to_vec();
    config.router_enabled = true;
    let runner = FakeRunner::new(|argv| {
        if argv[..2] == ["docker", "inspect"] && argv.iter().any(|a| a.contains("com.docker.compose.project")) {
            return Ok("proxy_panel_by_dubr1k".into());
        }
        Ok(String::new())
    });
    let mut agent = VersionAgent::new(config);
    agent.runner = Arc::new(runner.clone());
    agent.clock = Box::new(|| 1_767_225_600.0);
    agent.now = Box::new(|| 1_767_225_600.0);
    (agent, runner)
}

fn steps() -> Vec<Value> {
    golden_json("updates/steps.json").as_array().unwrap().clone()
}

#[test]
fn versions_bodies_equal_the_recorded_ones() {
    let dir = TempDir::new("golden-versions");
    let (agent, runner) = golden_agent(&dir);
    let recorded = steps();
    for (step, record) in STEPS.iter().zip(&recorded) {
        let state = golden_bytes(&format!("updates/{step}/state.json"));
        std::fs::write(dir.join("state.json"), &state).unwrap();
        runner.calls.lock().unwrap().clear();
        let listed = agent.list_versions(true).unwrap();
        let expected = golden_json(&format!("updates/{step}/versions.json"));
        assert_eq!(listed, expected, "{step}");
        assert_eq!(crate::py::body(&listed), crate::py::body(&expected), "{step}");
        // A listing ran exactly the last recorded command of its step and wrote nothing.
        assert_eq!(
            runner.calls(),
            [record["calls"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap().to_string())
                .collect::<Vec<_>>()],
            "{step}"
        );
        assert_eq!(std::fs::read(dir.join("state.json")).unwrap(), state, "{step}");
    }
}

#[test]
fn the_recorded_upstream_check_is_reproduced() {
    let dir = TempDir::new("golden-check");
    let (mut agent, runner) = golden_agent(&dir);
    std::fs::write(dir.join("state.json"), golden_bytes("updates/00-seed/state.json")).unwrap();
    let probes =
        golden_json("updates/01-check-upstream/state.json")["upstream"]["components"].as_object().unwrap().clone();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    agent.checker = Box::new(move |current, _, router| {
        seen.lock().unwrap().push((current.clone(), router));
        probes.clone()
    });
    let result = agent.check_upstream(true).unwrap();
    let record = &steps()[1];
    assert_eq!(result, record["result"]);
    assert_eq!(std::fs::read(dir.join("state.json")).unwrap(), golden_bytes("updates/01-check-upstream/state.json"));
    let expected_current: BTreeMap<String, Option<String>> = [
        ("telemt", Some("sha256:7c843f370ec5")),
        ("naive", Some("2.11.7")),
        ("mita", Some("3.38.1")),
        ("xray", Some("26.10.17")),
        ("panel", None),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.map(String::from)))
    .collect();
    assert_eq!(*asked.lock().unwrap(), [(expected_current, true)]);
    let calls: Vec<Vec<String>> = record["calls"].as_array().unwrap()[..2]
        .iter()
        .map(|c| c.as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect())
        .collect();
    assert_eq!(runner.calls(), calls);
}

/// Ported from `tests/test_version_agent_protocol_managers.py`.
#[test]
fn the_components_follow_the_installed_overlays_and_read_the_running_versions() {
    let dir = TempDir::new("protocol-managers");
    std::fs::write(dir.join("catalog.json"), r#"{"schema": 1, "components": {}}"#).unwrap();
    std::fs::create_dir_all(dir.join("compose")).unwrap();
    let runner = FakeRunner::new(|argv| {
        if argv.len() > 3 && argv[3].contains("Config.Env") {
            let awg = argv.last().unwrap().contains("awg");
            let (key, version) = if awg { ("AWG_GO_VERSION", "3.1.20260814") } else { ("TT_VERSION", "v1.1.0") };
            return Ok(format!("PATH=/usr/bin\n{key}={version}\n"));
        }
        Ok(String::new())
    });
    let agent_with = |files: &[&str]| {
        let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
        config.compose_dir = Some(dir.join("compose"));
        config.compose_files = files.iter().map(|f| f.to_string()).collect();
        let mut agent = VersionAgent::new(config);
        agent.runner = Arc::new(runner.clone());
        agent
    };
    let all = ["compose.yaml", "compose.amneziawg.yaml", "compose.trusttunnel.yaml"];
    let listed = agent_with(&all).list_versions(true).unwrap();
    assert_eq!(listed["components"]["amneziawg"]["current"], "3.1.20260814");
    assert_eq!(listed["components"]["trusttunnel"]["current"], "1.1.0");
    let bare = agent_with(&["compose.yaml"]).list_versions(true).unwrap();
    assert!(bare["components"].get("amneziawg").is_none() && bare["components"].get("trusttunnel").is_none());
}
