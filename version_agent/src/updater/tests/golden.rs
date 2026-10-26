//! The golden update steps of `tests/fixtures/host-golden/agent/updates/` (recorded from the
//! Python agent by `scripts/dev/record-host-goldens.py:record_agent`), replayed byte for byte:
//! the agent state after each step, the `/v1/versions` body, every command in order, the version
//! override and the two env overlays the updates rewrite.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::*;
use crate::errors::{AgentError, UpdateState};
use crate::runner::{Command, CommandError};
use crate::service::{AgentConfig, VersionAgent};
use crate::testutil::TempDir;
use crate::upstream::DownloadError;

const NOW: f64 = 1_767_225_600.0;
const TELEMT_IMAGE_NEW: &str =
    "ghcr.io/samnet-dev/mtproxymax-telemt@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TELEMT_IMAGE_OLD: &str =
    "ghcr.io/samnet-dev/mtproxymax-telemt@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn golden(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden").join(relative)
}

fn golden_bytes(relative: &str) -> Vec<u8> {
    read(&golden(relative))
}

fn golden_json(relative: &str) -> Value {
    serde_json::from_slice(&golden_bytes(relative)).unwrap()
}

/// What the recorder's `AgentHost` answered.
struct Simulated {
    calls: Vec<Vec<String>>,
    fail_restart: Vec<String>,
    xray_version: String,
}

fn simulated_host(work: &Path, state: Arc<Mutex<Simulated>>) -> Host {
    let work_text = path_text(work);
    let override_file = work.join("project/version-overrides/compose.versions.yaml");
    Host::new(move |command: &Command| {
        let argv = &command.argv;
        let mut host = state.lock().unwrap();
        host.calls.push(argv.iter().map(|part| part.replace(&work_text, "<work>")).collect());
        if starts(argv, &["systemctl", "restart"]) {
            if let Some(index) = host.fail_restart.iter().position(|unit| unit == &argv[2]) {
                host.fail_restart.remove(index); // the rollback restart succeeds
                return Err(CommandError::Failed {
                    argv: argv.clone(),
                    returncode: 1,
                    stdout: String::new(),
                    stderr: "Job for mita.service failed".into(),
                });
            }
        }
        if starts(argv, &["systemctl", "is-active"]) {
            return Ok("active".into());
        }
        if starts(argv, &["systemctl", "list-units", "--plain"]) {
            return Ok("mita@1.service loaded active running\nmita@2.service loaded active running".into());
        }
        if has(argv, "{{.Config.Image}}") {
            let configured = std::fs::read_to_string(&override_file).unwrap_or_default();
            return Ok(if configured.contains(TELEMT_IMAGE_NEW) { TELEMT_IMAGE_NEW } else { TELEMT_IMAGE_OLD }.into());
        }
        if has(argv, "{{.State.Health.Status}}") {
            return Ok("healthy".into());
        }
        if starts(argv, &["docker", "exec"]) && argv.join(" ").contains("--status") {
            return Ok(json!({"xray_version": format!("Xray {} (Xray, Penetrates Everything.) Custom", host.xray_version),
                             "phase": "idle", "running": {"generation": 2}})
            .to_string());
        }
        if starts(argv, &["docker", "inspect"]) && argv.join(" ").contains("com.docker.compose.project") {
            return Ok("proxy_panel_by_dubr1k".into());
        }
        Ok(String::new())
    })
}

/// The recorder's work tree: the project with four Compose files and their env overlays, the
/// agent state, the host binaries, the router's bin dir and the naive pin, all from the
/// kitchen-sink install golden.
fn work_tree(work: &Path) {
    let installed = |path: &str| golden_bytes(&format!("installs/kitchen-sink/root/files/{path}"));
    for name in ["compose.yaml", "compose.naive.yaml", "compose.mieru.yaml", "compose.xray-router.yaml"] {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(name);
        write(&work.join("project").join(name), &read(&source));
    }
    for name in [".env", ".env.naive", ".env.mieru", ".env.xray-router"] {
        write(&work.join("project").join(name), &installed(&format!("opt/mtproxy-shared443/{name}")));
    }
    write(&work.join("state/state.json"), &golden_bytes("agent/updates/01-check-upstream/state.json"));
    write(&work.join("bin/mita"), &installed("usr/bin/mita"));
    write(&work.join("bin/caddy"), &installed("usr/local/bin/caddy"));
    set_mode(&work.join("bin/mita"), 0o755);
    set_mode(&work.join("bin/caddy"), 0o755);
    for name in ["xray", "geoip.dat", "geosite.dat"] {
        write(&work.join("xray-router").join(name), &installed(&format!("usr/local/lib/proxy-control/xray-router/{name}")));
    }
    write(&work.join("caddy-naive.pin"), &installed("etc/proxy-control/caddy-naive.pin"));
    let xray_archive = golden_bytes("agent/updates/downloads/Xray-linux-64.zip");
    let caddy = golden_bytes("agent/updates/downloads/caddy-2.11.8");
    let catalog = json!({"schema": 1, "components": {
        "telemt": [{"version": "3.5.15", "kind": "image", "image": TELEMT_IMAGE_NEW}],
        "xray": [{"version": "26.11.1", "kind": "binary",
                  "url": "https://github.com/XTLS/Xray-core/releases/download/v26.11.1/Xray-linux-64.zip",
                  "sha256": sha(&xray_archive),
                  "archive": {"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}}}],
        "naive": [{"version": "2.11.8", "kind": "binary", "url": "https://artifacts.example.com/caddy-2.11.8",
                   "sha256": sha(&caddy), "runtime_version": "v2.11.8 h1:golden"}],
    }});
    write(&work.join("versions.json"), catalog.to_string().as_bytes());
}

fn golden_agent(work: &Path, host: &Host) -> Arc<VersionAgent> {
    let mut config = AgentConfig::new(work.join("versions.json"), work.join("state/state.json"));
    let project = work.join("project");
    config.compose_dir = Some(project.clone());
    config.compose_files =
        ["compose.yaml", "compose.naive.yaml", "compose.mieru.yaml", "compose.xray-router.yaml"].map(String::from).to_vec();
    config.binary_paths = [("naive", work.join("bin/caddy")), ("mita", work.join("bin/mita"))]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    config.service_names =
        [("naive", "caddy-naive"), ("mita", "mita")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    config.checkers = Default::default();
    config.caddyfiles = Default::default();
    config.version_pins = [("naive".to_string(), work.join("caddy-naive.pin"))].into_iter().collect();
    config.consumer_overlays = [(
        "mita".to_string(),
        (project.join(".env.mieru"), "MIERU_MITA_SHA256".to_string(), "mieru-manager".to_string()),
    )]
    .into_iter()
    .collect();
    config.health_timeout = 5.0;
    config.router_enabled = true;
    config.xray_bin_dir = work.join("xray-router");
    config.xray_overlay = project.join(".env.xray-router");
    config.caddy_build_dir = work.join("caddy-build");
    config.agent_dir = work.join("agent");
    config.synchronous = true;
    let downloads = golden("agent/updates/downloads");
    let mut updater = HostUpdater::with_downloader(move |url, _| {
        let name = url.rsplit_once('/').map(|(_, name)| name).unwrap_or(url);
        std::fs::read(downloads.join(name)).map_err(|err| DownloadError::Refused(format!("{url}: {err}")))
    });
    updater.sleep = Arc::new(|_| {});
    updater.machine = "x86_64".into();
    let mut agent = VersionAgent::new(config);
    agent.runner = Arc::new(host.clone());
    agent.updater = Arc::new(updater);
    agent.clock = Box::new(|| NOW);
    agent.now = Box::new(|| NOW);
    Arc::new(agent)
}

fn recorded_calls(step: &Value) -> Vec<Vec<String>> {
    step["calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|call| call.as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect())
        .collect()
}

#[test]
fn the_recorded_updates_are_reproduced_byte_for_byte() {
    let dir = TempDir::new("golden-updates");
    let work = dir.join("agent");
    work_tree(&work);
    let state = Arc::new(Mutex::new(Simulated { calls: Vec::new(), fail_restart: Vec::new(), xray_version: "26.10.17".into() }));
    let host = simulated_host(&work, state.clone());
    let agent = golden_agent(&work, &host);
    let steps = golden_json("agent/updates/steps.json");
    let steps = steps.as_array().unwrap();
    let check = |index: usize, name: &str, result: Value| {
        let step = &steps[index];
        assert_eq!(step["step"], name);
        assert_eq!(result, step["result"], "{name}: result");
        // `record()` lists the versions after the step (the last recorded command).
        let listed = agent.list_versions(true).unwrap();
        let directory = format!("agent/updates/{index:02}-{name}");
        assert_eq!(
            read(&work.join("state/state.json")),
            golden_bytes(&format!("{directory}/state.json")),
            "{name}: state.json"
        );
        assert_eq!(listed, golden_json(&format!("{directory}/versions.json")), "{name}: /v1/versions");
        let mut host = state.lock().unwrap();
        assert_eq!(host.calls, recorded_calls(step), "{name}: commands");
        host.calls.clear();
    };

    let result = agent.update("telemt", "3.5.15", None).unwrap();
    check(2, "update-telemt", result);
    assert_eq!(
        read(&work.join("project/version-overrides/compose.versions.yaml")),
        golden_bytes("agent/updates/compose.versions.yaml")
    );

    let result = agent.update("mita", "3.39.0", Some("3.38.1")).unwrap();
    check(3, "update-mita", result);
    assert_eq!(read(&work.join("project/.env.mieru")), golden_bytes("agent/updates/env.mieru"));
    assert_eq!(read(&work.join("bin/mita")), b"#!/bin/sh\n# golden stand-in mita 3.39.0\n");

    state.lock().unwrap().xray_version = "26.11.1".into();
    let result = agent.update("xray", "26.11.1", None).unwrap();
    check(4, "update-xray", result);
    assert_eq!(read(&work.join("project/.env.xray-router")), golden_bytes("agent/updates/env.xray-router"));
    assert_eq!(read(&work.join("xray-router/xray")), b"golden stand-in xray 26.11.1\n");

    state.lock().unwrap().fail_restart.push("caddy-naive".into());
    let before = read(&work.join("bin/caddy"));
    let pin = read(&work.join("caddy-naive.pin"));
    let outcome = match agent.update("naive", "2.11.8", None) {
        Err(AgentError::Update(error)) if error.state == UpdateState::RolledBack => {
            json!({"exception": "RolledBackError", "message": error.message})
        }
        other => panic!("expected a rolled-back update, got {other:?}"),
    };
    check(5, "update-naive-rolled-back", outcome);
    assert_eq!(read(&work.join("bin/caddy")), before);
    assert_eq!(read(&work.join("caddy-naive.pin")), pin);
}
