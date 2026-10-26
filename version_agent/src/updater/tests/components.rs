//! Ported from `tests/test_version_agent.py` (binary, naive build, xray, telemt, Compose argv)
//! and `tests/test_version_agent_protocol_managers.py` (the AmneziaWG/TrustTunnel rebuilds).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use super::*;
use crate::artifacts::tests::{targz_of, zip_of};
use crate::errors::{AgentError, UpdateState};
use crate::runner::Command;
use crate::service::AgentConfig;
use crate::testutil::TempDir;
use crate::updater::xray::XRAY_STATUS_COMMAND;
use crate::updater::{compose_command, override_with};

const TELEMT_IMAGE: &str = "ghcr.io/example/telemt@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BINARY: &[u8] = b"verified-runtime-binary\n";
const PINNED_CADDY: &str = "v2.11.7 h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4=";
const CHECKER: &str = "/usr/local/libexec/check-naive-caddy-build";

/// `write_catalog(path, naive_runtime_version=…)`.
fn write_catalog(path: &Path, naive_runtime_version: Option<&str>) {
    let mut naive = json!({"version": "2.11.4-custom.1", "kind": "binary",
                           "url": "https://artifacts.example.com/caddy-2.11.4-custom.1", "sha256": sha(BINARY)});
    if let Some(version) = naive_runtime_version {
        naive["runtime_version"] = json!(version);
    }
    let document = json!({"schema": 1, "components": {
        "telemt": [{"version": "3.4.25", "kind": "image", "image": TELEMT_IMAGE}],
        "naive": [naive],
        "mita": [{"version": "3.35.0", "kind": "binary", "url": "https://artifacts.example.com/mita-3.35.0", "sha256": sha(BINARY)}],
    }});
    write(path, document.to_string().as_bytes());
}

/// `VersionAgent(catalog_path=<dir>/catalog.json, state_path=<dir>/state.json)` with the catalog.
fn config_in(dir: &Path, naive_runtime_version: Option<&str>) -> AgentConfig {
    write_catalog(&dir.join("catalog.json"), naive_runtime_version);
    AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"))
}

fn update_error(result: Result<Value, AgentError>) -> crate::UpdateError {
    match result {
        Err(AgentError::Update(error)) => error,
        other => panic!("expected an UpdateError, got {other:?}"),
    }
}

fn components(map: &[(&str, &Path)]) -> BTreeMap<String, PathBuf> {
    map.iter().map(|(k, v)| (k.to_string(), v.to_path_buf())).collect()
}

fn names(map: &[(&str, &str)]) -> BTreeMap<String, String> {
    map.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// A directory on another file system than the temporary directory, when the host has one
/// (`/dev/shm`): a rename between them fails with EXDEV, as between the unit's bind mounts
/// (`exdev_between_directories` of the Python tests).
fn other_device(label: &str) -> Option<TempDir> {
    use std::os::unix::fs::MetadataExt;
    let shm = Path::new("/dev/shm");
    let (Ok(a), Ok(b)) = (std::fs::metadata(shm), std::fs::metadata(std::env::temp_dir())) else { return None };
    if a.dev() == b.dev() {
        return None;
    }
    let dir = shm.join(format!("pc-va-{label}-{}-{}", std::process::id(), pc_host::fs::token_hex::<4>()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(TempDir::adopt(dir))
}

// --- binaries ---------------------------------------------------------------------------------

fn mita_candidate(digest: &str) -> Value {
    json!({"version": "3.37.0", "tag": "v3.37.0", "kind": "binary", "source": "upstream",
           "url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz",
           "sha256": digest, "archive": {"format": "tar.gz", "member": "mita"}, "published_at": null})
}

#[test]
fn archive_member_hash_is_checked_against_the_archive_not_the_file() {
    let dir = TempDir::new("member-hash");
    let target = dir.write("mita", "old");
    let payload = targz_of(&[("mita", BINARY)], None);
    let mut config = config_in(dir.path(), None);
    config.binary_paths = components(&[("mita", &target)]);
    config.service_names = names(&[("mita", "mita")]);
    let mut agent = VersionAgent::new(config);
    agent.runner = Arc::new(Host::answering("active\n"));
    agent.updater = Arc::new(serving(payload));
    let candidate = mita_candidate(&sha(BINARY));
    agent.checker = Box::new(move |_, _, _| {
        json!({"mita": {"latest": "3.37.0", "installable": true, "reason": null, "candidates": [candidate.clone()]}})
            .as_object()
            .unwrap()
            .clone()
    });
    let agent = Arc::new(agent);
    agent.check_upstream(false).unwrap();
    let error = update_error(agent.update("mita", "3.37.0", None));
    assert!(error.message.contains("SHA-256 mismatch"), "{error:?}");
    assert_eq!(read(&target), b"old");
}

#[test]
fn binary_update_uses_catalog_hash_and_persists_revision() {
    let dir = TempDir::new("binary-catalog");
    let target = dir.write("caddy", "old");
    set_mode(&target, 0o755);
    let mut config = config_in(dir.path(), None);
    config.binary_paths = components(&[("naive", &target)]);
    config.service_names = names(&[("naive", "caddy-naive")]);
    config.checkers = components(&[("naive", Path::new(CHECKER))]);
    let host = Host::answering("active\n");
    let agent = agent_with(config, &host, serving(BINARY.to_vec()));
    let result = agent.update("naive", "2.11.4-custom.1", None).unwrap();
    assert_eq!(result["version"], "2.11.4-custom.1");
    assert_eq!(read(&target), BINARY);
    assert_ne!(mode(&target) & 0o111, 0);
    assert_eq!(state_json(&dir.join("state.json"))["components"]["naive"]["version"], "2.11.4-custom.1");
    // A reload keeps the running process on the old binary, so replacing it restarts.
    let commands = host.commands();
    assert!(commands.iter().any(|c| is(&c.argv, &["systemctl", "restart", "caddy-naive"])));
    assert!(!commands.iter().any(|c| starts(&c.argv, &["systemctl", "reload"])));
    assert!(commands.iter().any(|c| c.env.iter().any(|(k, v)| k == "CADDY_BIN" && v.ends_with(".proxy-control-new"))));
    // Python's timeouts: the checker 120 s (default), restart 120 s, is-active 30 s.
    let timeout = |argv: &[&str]| commands.iter().find(|c| is(&c.argv, argv)).map(|c| c.timeout.as_secs());
    assert_eq!(timeout(&[CHECKER]), Some(120));
    assert_eq!(timeout(&["systemctl", "restart", "caddy-naive"]), Some(120));
    assert_eq!(timeout(&["systemctl", "is-active", "caddy-naive"]), Some(30));
    assert_eq!(timeout(&["systemctl", "list-units", "--plain", "--no-legend", "caddy-naive@*.service"]), Some(30));
}

#[test]
fn binary_update_records_the_pin_the_unit_check_reads() {
    // ExecStartPre runs without the agent's environment: the pin must persist.
    let dir = TempDir::new("binary-pin");
    let target = dir.write("caddy", "old");
    set_mode(&target, 0o755);
    let pin = dir.write("caddy-naive.pin", "v2.11.3 h1:stale=\n");
    let mut config = config_in(dir.path(), Some(PINNED_CADDY));
    config.binary_paths = components(&[("naive", &target)]);
    config.service_names = names(&[("naive", "caddy-naive")]);
    config.version_pins = components(&[("naive", &pin)]);
    let agent = agent_with(config, &Host::answering("active\n"), serving(BINARY.to_vec()));
    agent.update("naive", "2.11.4-custom.1", None).unwrap();
    assert_eq!(text(&pin).trim(), PINNED_CADDY);
    assert_eq!(mode(&pin), 0o644);
}

#[test]
fn binary_update_restores_the_previous_pin_when_the_service_fails() {
    let dir = TempDir::new("binary-pin-restore");
    let target = dir.write("caddy", "old");
    set_mode(&target, 0o755);
    let pin = dir.write("caddy-naive.pin", "v2.11.3 h1:previous=\n");
    let caddyfile = dir.write("Caddyfile", ":443 {}\n");
    let mut config = config_in(dir.path(), Some(PINNED_CADDY));
    config.binary_paths = components(&[("naive", &target)]);
    config.service_names = names(&[("naive", "caddy-naive")]);
    config.version_pins = components(&[("naive", &pin)]);
    config.checkers = components(&[("naive", Path::new(CHECKER))]);
    config.caddyfiles = components(&[("naive", &caddyfile)]);
    let watched = target.clone();
    let host = Host::new(move |c: &Command| {
        if starts(&c.argv, &["systemctl", "restart"]) && std::fs::read(&watched).unwrap() == BINARY {
            return Err(runtime_error("restart failed"));
        }
        Ok("active\n".into())
    });
    let agent = agent_with(config, &host, serving(BINARY.to_vec()));
    let error = update_error(agent.update("naive", "2.11.4-custom.1", None));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert!(error.message.contains("restored and verified"));
    assert_eq!(read(&target), b"old");
    assert_eq!(text(&pin).trim(), "v2.11.3 h1:previous=");
    let expected: Vec<String> = host
        .commands()
        .into_iter()
        .filter(|c| is(&c.argv, &[CHECKER]))
        .map(|c| c.env.iter().find(|(k, _)| k == "EXPECTED_CADDY_VERSION").unwrap().1.clone())
        .collect();
    assert_eq!(expected, [PINNED_CADDY, "v2.11.3 h1:previous="]);
    assert!(host.argvs().iter().any(|argv| argv[0] == path_text(&target) && has(argv, "adapt")));
}

#[test]
fn mita_update_rewrites_the_consumer_pin_restarts_slots_and_recreates_the_manager() {
    // The manager pins the host binary by digest: its overlay follows the new build.
    let dir = TempDir::new("mita-consumer");
    let target = dir.write("mita", "old");
    set_mode(&target, 0o755);
    dir.write("compose.yaml", "services: {}\n");
    dir.write(".env", "PANEL_DOMAIN=p.example.com\n");
    dir.write(".optional.env", "NAIVE_EGRESS_WARP=socks5://127.0.0.1:45000\n");
    dir.write(".env.naive", "NAIVE_PUBLIC_HOST=n.example.com\n");
    let overlay = dir.write(
        ".env.mieru",
        &format!("MIERU_PUBLIC_HOST=m.example.com\nMIERU_MITA_SHA256={}\nMIERU_LANE_SLOTS=1:46101:/run/mita1/s:/var/lib/mita1\n", "0".repeat(64)),
    );
    let mut config = config_in(dir.path(), None);
    config.compose_dir = Some(dir.path().to_path_buf());
    config.compose_files = vec!["compose.yaml".into(), "compose.mieru.yaml".into()];
    config.binary_paths = components(&[("mita", &target)]);
    config.service_names = names(&[("mita", "mita")]);
    config.consumer_overlays =
        BTreeMap::from([("mita".to_string(), (overlay.clone(), "MIERU_MITA_SHA256".to_string(), "mieru-manager".to_string()))]);
    let host = Host::new(|c: &Command| {
        if starts(&c.argv, &["systemctl", "list-units", "--plain"]) {
            return Ok("mita@1.service loaded active running\n".into());
        }
        Ok("active\n".into())
    });
    let agent = agent_with(config, &host, serving(BINARY.to_vec()));
    agent.update("mita", "3.35.0", None).unwrap();
    let written = text(&overlay);
    assert!(written.contains(&format!("MIERU_MITA_SHA256={}", sha(BINARY))) && written.contains("MIERU_PUBLIC_HOST=m.example.com"));
    let position = |key: &str| written.find(key).unwrap();
    assert!(position("MIERU_PUBLIC_HOST") < position("MIERU_MITA_SHA256"));
    assert!(position("MIERU_MITA_SHA256") < position("MIERU_LANE_SLOTS"));
    assert!(!written.contains(&"0".repeat(64)));
    let argvs = host.argvs();
    for expected in [&["systemctl", "restart", "mita"][..], &["systemctl", "restart", "mita@1"], &["systemctl", "is-active", "mita@1"]] {
        assert!(argvs.iter().any(|a| is(a, expected)), "{expected:?}");
    }
    let ups: Vec<&Vec<String>> =
        argvs.iter().filter(|a| starts(a, &["docker", "compose", "--project-name", "proxy_panel_by_dubr1k"])).collect();
    assert_eq!(ups.len(), 1);
    let up = ups[0];
    assert_eq!(tail(up, 5), ["up", "-d", "--no-deps", "--wait", "mieru-manager"]);
    // `.optional.env` (a host keeps its WARP egress there) rides right after `.env`.
    assert_eq!(
        env_files_of(up),
        [dir.join(".env"), dir.join(".optional.env"), dir.join(".env.naive"), overlay.clone()].map(|p| path_text(&p))
    );
    assert!(has(up, "-f") && has(up, &path_text(&dir.join("compose.mieru.yaml"))));
    assert!(!up.join(" ").contains("version-overrides"));
    let restart = argvs.iter().position(|a| is(a, &["systemctl", "restart", "mita"])).unwrap();
    assert!(restart < argvs.iter().position(|a| a == up).unwrap());
    let command = host.commands().into_iter().find(|c| &c.argv == up).unwrap();
    assert_eq!((command.timeout.as_secs(), command.cwd.clone()), (300, Some(dir.path().to_path_buf())));
}

#[test]
fn mita_update_restores_the_consumer_pin_when_the_manager_does_not_come_back() {
    let dir = TempDir::new("mita-restore");
    // The backups live on another file system when the host has one (EXDEV on every rename).
    let state_dir = other_device("mita-restore-state");
    let state_root = state_dir.as_ref().map(|d| d.path().to_path_buf()).unwrap_or_else(|| dir.join("state"));
    let target = dir.join("bin/mita");
    write(&target, b"old");
    set_mode(&target, 0o755);
    let overlay = dir.write(".env.mieru", &format!("MIERU_MITA_SHA256={}\n", "0".repeat(64)));
    write_catalog(&dir.join("catalog.json"), None);
    let mut config = AgentConfig::new(dir.join("catalog.json"), state_root.join("state.json"));
    config.compose_dir = Some(dir.path().to_path_buf());
    config.compose_files = vec!["compose.yaml".into()];
    config.binary_paths = components(&[("mita", &target)]);
    config.service_names = names(&[("mita", "mita")]);
    config.consumer_overlays =
        BTreeMap::from([("mita".to_string(), (overlay.clone(), "MIERU_MITA_SHA256".to_string(), "mieru-manager".to_string()))]);
    let ups = Arc::new(Mutex::new(Vec::new()));
    let (seen, watched) = (ups.clone(), overlay.clone());
    let host = Host::new(move |c: &Command| {
        let argv = &c.argv;
        if argv.len() >= 5 && tail(argv, 5)[..4] == ["up", "-d", "--no-deps", "--wait"] {
            let mut ups = seen.lock().unwrap();
            ups.push(String::from_utf8(std::fs::read(&watched).unwrap()).unwrap());
            if ups.len() == 1 {
                return Err(runtime_error("unhealthy"));
            }
        }
        Ok(if starts(argv, &["systemctl", "list-units", "--plain"]) { String::new() } else { "active\n".into() })
    });
    let agent = agent_with(config, &host, serving(BINARY.to_vec()));
    let error = update_error(agent.update("mita", "3.35.0", None));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert_eq!(read(&target), b"old");
    assert_eq!(mode(&target), 0o755);
    assert!(!dir.join("bin/.mita.proxy-control-restore").exists());
    assert_eq!(text(&overlay), format!("MIERU_MITA_SHA256={}\n", "0".repeat(64)));
    assert_eq!(
        *ups.lock().unwrap(),
        [format!("MIERU_MITA_SHA256={}\n", sha(BINARY)), format!("MIERU_MITA_SHA256={}\n", "0".repeat(64))]
    );
    assert_eq!(agent.list_versions(true).unwrap()["components"]["mita"]["current"], Value::Null);
}

#[test]
fn binary_update_rolls_back_when_service_restart_fails() {
    let dir = TempDir::new("binary-restart");
    let target = dir.write("mita", "old");
    set_mode(&target, 0o755);
    dir.write("state.json", &json!({"components": {"mita": {"version": "3.34.0"}}}).to_string());
    let mut config = config_in(dir.path(), None);
    config.binary_paths = components(&[("mita", &target)]);
    config.service_names = names(&[("mita", "mita")]);
    let attempts = Arc::new(Mutex::new(0));
    let counter = attempts.clone();
    let host = Host::new(move |c: &Command| {
        if is(&c.argv, &["systemctl", "restart", "mita"]) {
            let mut attempts = counter.lock().unwrap();
            *attempts += 1;
            if *attempts == 1 {
                return Err(runtime_error("service failed"));
            }
        }
        Ok("active\n".into())
    });
    let agent = agent_with(config, &host, serving(BINARY.to_vec()));
    let error = update_error(agent.update("mita", "3.35.0", Some("3.34.0")));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert!(error.message.contains("restored and verified"));
    assert_eq!(read(&target), b"old");
    assert_eq!(state_json(&dir.join("state.json"))["components"]["mita"]["version"], "3.34.0");
    assert!(host.argvs().iter().filter(|a| is(a, &["systemctl", "restart", "mita"])).count() >= 2);
}

#[test]
fn binary_rollback_restart_is_not_success_without_health() {
    let dir = TempDir::new("binary-health");
    let target = dir.write("mita", "old");
    set_mode(&target, 0o755);
    dir.write("state.json", &json!({"components": {"mita": {"version": "3.34.0"}}}).to_string());
    let mut config = config_in(dir.path(), None);
    config.binary_paths = components(&[("mita", &target)]);
    config.service_names = names(&[("mita", "mita")]);
    let host = Host::new(|c: &Command| {
        if is(&c.argv, &["systemctl", "is-active", "mita"]) {
            return Err(runtime_error("service remained unhealthy"));
        }
        Ok("ok\n".into())
    });
    let agent = agent_with(config, &host, serving(BINARY.to_vec()));
    let error = update_error(agent.update("mita", "3.35.0", Some("3.34.0")));
    assert_eq!(error.state, UpdateState::RollbackFailed);
    assert!(error.message.contains("could not be verified"));
    let saved = &state_json(&dir.join("state.json"))["components"]["mita"];
    assert_eq!(read(&target), b"old");
    assert_eq!((&saved["version"], &saved["status"]), (&json!("3.34.0"), &json!("rollback_failed")));
    assert_eq!(agent.list_versions(true).unwrap()["components"]["mita"]["status"], "rollback_failed");
    let argvs = host.argvs();
    assert_eq!(argvs.iter().filter(|a| is(a, &["systemctl", "restart", "mita"])).count(), 2);
    assert_eq!(argvs.iter().filter(|a| is(a, &["systemctl", "is-active", "mita"])).count(), 2);
    let error = update_error(agent.update("mita", "3.35.0", Some("3.34.0")));
    assert_eq!(error.state, UpdateState::RollbackFailed);
    assert!(error.message.contains("operator recovery"));
}

// --- the naive build ----------------------------------------------------------------------------

fn build_catalog(path: &Path) {
    let document = json!({"schema": 1, "components": {"naive": [{"version": "2.12.0", "kind": "build", "build": {
        "caddy_version": "2.12.0", "builder_image": format!("caddy:2.12.0-builder@sha256:{}", "e".repeat(64)),
        "forwardproxy_commit": "d".repeat(40)}}]}});
    write(path, document.to_string().as_bytes());
}

fn caddy_host(reported: &'static str) -> Host {
    Host::new(move |c: &Command| {
        let argv = &c.argv;
        if starts(argv, &["docker", "create"]) {
            return Ok("0123456789abcdef\n".into());
        }
        if starts(argv, &["docker", "cp"]) {
            std::fs::write(&argv[3], BINARY).unwrap();
            return Ok(String::new());
        }
        if argv.len() == 2 && argv[1] == "version" {
            return Ok(reported.into());
        }
        Ok("active\n".into())
    })
}

#[test]
fn naive_build_writes_a_pinned_dockerfile_builds_extracts_and_installs() {
    let dir = TempDir::new("naive-build");
    build_catalog(&dir.join("catalog.json"));
    let target = dir.write("caddy", "old");
    set_mode(&target, 0o755);
    let pin = dir.write("caddy-naive.pin", &format!("{PINNED_CADDY}\n"));
    let build_dir = dir.join("caddy-build");
    let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
    config.binary_paths = components(&[("naive", &target)]);
    config.service_names = names(&[("naive", "caddy-naive")]);
    config.checkers = components(&[("naive", Path::new(CHECKER))]);
    config.version_pins = components(&[("naive", &pin)]);
    config.caddy_build_dir = build_dir.clone();
    let host = caddy_host("v2.12.0 h1:newbuildhash=\n");
    let agent = agent_with(config, &host, no_download());
    assert_eq!(agent.update("naive", "2.12.0", None).unwrap()["changed"], true);
    let dockerfile = text(&build_dir.join("Dockerfile"));
    assert_eq!(
        dockerfile,
        format!(
            "# Generated by proxy-control version-agent; do not edit manually.\n\
             FROM caddy:2.12.0-builder@sha256:{} AS builder\n\
             RUN xcaddy build v2.12.0 \\\n    \
             --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@{}\n\
             FROM scratch\nCOPY --from=builder /usr/bin/caddy /caddy\n",
            "e".repeat(64),
            "d".repeat(40)
        )
    );
    assert_eq!((mode(&build_dir), mode(&build_dir.join("Dockerfile"))), (0o700, 0o600));
    let commands = host.commands();
    let build = commands.iter().find(|c| starts(&c.argv, &["docker", "build"])).unwrap();
    assert_eq!(build.argv[2..4], ["-f".to_string(), path_text(&build_dir.join("Dockerfile"))]);
    assert_eq!(build.argv.last().unwrap(), &path_text(&build_dir));
    assert_eq!(build.timeout.as_secs(), 900);
    assert!(commands.iter().any(|c| is(&c.argv, &["docker", "rm", "0123456789abcdef"])));
    let create = commands.iter().find(|c| starts(&c.argv, &["docker", "create"])).unwrap();
    assert_eq!(create.argv, ["docker", "create", "--entrypoint", "/caddy", "proxy-control/caddy-naive:agent", "version"]);
    assert_eq!(read(&target), BINARY);
    assert_eq!(text(&pin).trim(), "v2.12.0 h1:newbuildhash=");
    assert!(commands
        .iter()
        .any(|c| c.env.iter().any(|(k, v)| k == "EXPECTED_CADDY_VERSION" && v == "v2.12.0 h1:newbuildhash=")));
    assert!(commands.iter().any(|c| is(&c.argv, &["systemctl", "restart", "caddy-naive"])));
    assert!(!build_dir.join("caddy").exists());
    let state = &state_json(&dir.join("state.json"))["components"]["naive"];
    assert_eq!((&state["version"], &state["kind"]), (&json!("2.12.0"), &json!("build")));
    assert_eq!(state["runtime_version"], "v2.12.0 h1:newbuildhash=");
    assert_eq!((&state["sha256"], &state["build"]["caddy_version"]), (&json!(sha(BINARY)), &json!("2.12.0")));
}

#[test]
fn naive_build_failure_leaves_the_running_binary_alone() {
    let dir = TempDir::new("naive-build-failure");
    build_catalog(&dir.join("catalog.json"));
    let target = dir.write("caddy", "old");
    let pin = dir.write("caddy-naive.pin", &format!("{PINNED_CADDY}\n"));
    let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
    config.binary_paths = components(&[("naive", &target)]);
    config.service_names = names(&[("naive", "caddy-naive")]);
    config.version_pins = components(&[("naive", &pin)]);
    config.caddy_build_dir = dir.join("caddy-build");
    let host = Host::new(|c: &Command| {
        if starts(&c.argv, &["docker", "build"]) {
            return Err(runtime_error("build failed"));
        }
        Ok("active\n".into())
    });
    let agent = agent_with(config, &host, serving(BINARY.to_vec()));
    let error = update_error(agent.update("naive", "2.12.0", None));
    assert_eq!((error.state, error.message.as_str()), (UpdateState::UpdateFailed, "naive update failed"));
    assert_eq!(read(&target), b"old");
    assert_eq!(text(&pin).trim(), PINNED_CADDY);
    assert!(!host.argvs().iter().any(|a| starts(a, &["systemctl", "restart"])));
}

#[test]
fn naive_build_that_reports_another_caddy_version_is_refused() {
    let dir = TempDir::new("naive-build-version");
    build_catalog(&dir.join("catalog.json"));
    let target = dir.write("caddy", "old");
    let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
    config.binary_paths = components(&[("naive", &target)]);
    config.service_names = names(&[("naive", "caddy-naive")]);
    config.caddy_build_dir = dir.join("caddy-build");
    let agent = agent_with(config, &caddy_host("v2.11.4 h1:oldbuildhash=\n"), serving(BINARY.to_vec()));
    let error = update_error(agent.update("naive", "2.12.0", None));
    assert_eq!(error.message, "built Caddy reports v2.11.4 h1:oldbuildhash=, expected v2.12.0");
    assert_eq!(read(&target), b"old");
}

// --- xray ---------------------------------------------------------------------------------------

const XRAY_MEMBERS: [&str; 3] = ["xray", "geoip.dat", "geosite.dat"];

fn xray_status_argv() -> Vec<String> {
    let mut argv = vec!["docker".to_string(), "exec".into(), "proxy-control-xray-router".into()];
    argv.extend(XRAY_STATUS_COMMAND.iter().map(|s| s.to_string()));
    argv
}

fn xray_zip() -> Vec<u8> {
    zip_of(&[("xray", b"xray-new"), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite"), ("README.md", b"x")])
}

fn xray_status(version: &str, phase: &str) -> String {
    format!(
        "{}\n",
        json!({"xray_version": format!("Xray {version} (Xray, Penetrates Everything.) Custom (go1.24 linux/amd64)"),
               "phase": phase, "running": {"generation": 3}})
    )
}

/// `_xray_fixture`: the bin dir with the old members, the overlay, the catalog and the payload.
fn xray_fixture(dir: &TempDir, overlay_text: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    let bin_dir = dir.join("xray-router");
    for name in XRAY_MEMBERS {
        write(&bin_dir.join(name), format!("old-{name}").as_bytes());
    }
    set_mode(&bin_dir.join("xray"), 0o755);
    let overlay = dir.write(".env.xray-router", overlay_text);
    let payload = xray_zip();
    let catalog = json!({"schema": 1, "components": {"xray": [{
        "version": "26.4.1", "kind": "binary",
        "url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip",
        "sha256": sha(&payload),
        "archive": {"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}}}]}});
    write(&dir.join("catalog.json"), catalog.to_string().as_bytes());
    (bin_dir, overlay, payload)
}

fn xray_config(dir: &TempDir, state: &Path, bin_dir: &Path, overlay: &Path, files: &[&str], router: bool) -> AgentConfig {
    let mut config = AgentConfig::new(dir.join("catalog.json"), state);
    config.compose_dir = Some(dir.path().to_path_buf());
    config.compose_files = files.iter().map(|f| f.to_string()).collect();
    config.router_enabled = router;
    config.xray_bin_dir = bin_dir.to_path_buf();
    config.xray_overlay = overlay.to_path_buf();
    config
}

#[test]
fn xray_update_replaces_members_rewrites_overlay_and_verifies_the_running_version() {
    let dir = TempDir::new("xray-update");
    let overlay_text = format!(
        "XRAY_ROUTER_BIN_DIR={}\nXRAY_ROUTER_XRAY_SHA256={}\nXRAY_ROUTER_GEOIP_SHA256={}\nXRAY_ROUTER_GEOSITE_SHA256={}\nXRAY_ROUTER_EGRESS_WARP=\n",
        path_text(&dir.join("xray-router")),
        "0".repeat(64),
        "1".repeat(64),
        "2".repeat(64)
    );
    let (bin_dir, overlay, payload) = xray_fixture(&dir, &overlay_text);
    dir.write(".env", "PANEL_DOMAIN=p.example.com\n");
    let status = xray_status_argv();
    let host = Host::new(move |c: &Command| Ok(if c.argv == status { xray_status("26.4.1", "idle") } else { String::new() }));
    let config =
        xray_config(&dir, &dir.join("state.json"), &bin_dir, &overlay, &["compose.yaml", "compose.xray-router.yaml"], true);
    let agent = agent_with(config, &host, serving(payload.clone()));
    assert_eq!(agent.update("xray", "26.4.1", None).unwrap()["changed"], true);
    assert_eq!((read(&bin_dir.join("xray")), read(&bin_dir.join("geosite.dat"))), (b"xray-new".to_vec(), b"geosite".to_vec()));
    assert_eq!((mode(&bin_dir.join("xray")), mode(&bin_dir.join("geoip.dat"))), (0o755, 0o644));
    assert!(!bin_dir.join("README.md").exists());
    let written = text(&overlay);
    assert!(written.contains(&format!("XRAY_ROUTER_XRAY_SHA256={}", sha(b"xray-new"))));
    assert!(written.contains(&format!("XRAY_ROUTER_GEOSITE_SHA256={}", sha(b"geosite"))));
    assert!(written.contains("XRAY_ROUTER_EGRESS_WARP=") && written.contains("XRAY_ROUTER_BIN_DIR="));
    assert!(!written.contains(&"0".repeat(64)));
    let argvs = host.argvs();
    let ups: Vec<&Vec<String>> =
        argvs.iter().filter(|a| starts(a, &["docker", "compose", "--project-name", "proxy_panel_by_dubr1k"])).collect();
    assert_eq!(ups.len(), 1);
    assert_eq!(tail(ups[0], 5), ["up", "-d", "--no-deps", "--wait", "xray-router"]);
    assert_eq!(env_files_of(ups[0]), [path_text(&dir.join(".env")), path_text(&overlay)]);
    let position = |argv: &Vec<String>| argvs.iter().position(|a| a == argv).unwrap();
    assert!(position(ups[0]) < position(&xray_status_argv()));
    let state = &state_json(&dir.join("state.json"))["components"]["xray"];
    let expected: Map<String, Value> = [("xray", &b"xray-new"[..]), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")]
        .iter()
        .map(|(name, data)| (name.to_string(), json!(sha(data))))
        .collect();
    assert_eq!(state["members"], Value::Object(expected));
    assert_eq!((&state["version"], &state["sha256"]), (&json!("26.4.1"), &json!(sha(&payload))));
    assert_eq!(read(&dir.join("backups/xray.previous/xray")), b"old-xray");
    assert_eq!(agent.list_versions(true).unwrap()["components"]["xray"]["current"], "26.4.1");
}

#[test]
fn compose_commands_carry_the_mcp_overlay_and_the_panel_sync_ships_its_file() {
    // v0.11 §9a: `.env.mcp` rides along like the protocol overlays, after them, and the panel
    // self-update syncs `compose.mcp.yaml` with the other Compose files.
    assert!(pc_host::archive::PANEL_SYNC.contains(&"compose.mcp.yaml"));
    let dir = TempDir::new("mcp-overlay");
    dir.write(".env", "PANEL_DOMAIN=p.example.com\n");
    dir.write(".env.mieru", "MIERU_PUBLIC_HOST=m\n");
    dir.write(".env.mcp", "MCP_DOMAIN=mcp.example.com\nMCP_PANEL_HOST=p.example.com\n");
    dir.write("catalog.json", r#"{"schema": 1, "components": {}}"#);
    let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
    config.compose_dir = Some(dir.path().to_path_buf());
    config.compose_files = ["compose.yaml", "compose.mieru.yaml", "compose.mcp.yaml"].map(String::from).to_vec();
    let agent = agent_with(config, &Host::answering(""), no_download());
    let command = compose_command(&agent, &["up", "-d", "--no-deps", "--wait", "mcp"], false, true).unwrap();
    assert_eq!(env_files_of(&command), [".env", ".env.mieru", ".env.mcp"].map(|n| path_text(&dir.join(n))));
    assert_eq!(
        files_of(&command),
        ["compose.yaml", "compose.mieru.yaml", "compose.mcp.yaml"].map(|n| path_text(&dir.join(n)))
    );
    // A Compose file outside the project directory is refused before anything runs.
    let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
    config.compose_dir = Some(dir.path().to_path_buf());
    for bad in ["/etc/compose.yaml", "../compose.yaml", "x/../../compose.yaml"] {
        config.compose_files = vec![bad.into()];
        let agent = agent_with(config.clone(), &Host::answering(""), no_download());
        assert_eq!(compose_command(&agent, &["up"], false, false).unwrap_err().message(), "invalid Compose file path");
    }
    config.compose_files = vec![];
    let agent = agent_with(config, &Host::answering(""), no_download());
    assert_eq!(compose_command(&agent, &["up"], false, false).unwrap_err().message(), "Compose deployment is not configured");
}

#[test]
fn xray_update_rolls_back_all_three_members_when_the_router_reports_another_version() {
    let dir = TempDir::new("xray-rollback");
    let state_dir = other_device("xray-rollback-state");
    let state = state_dir.as_ref().map(|d| d.join("state.json")).unwrap_or_else(|| dir.join("state.json"));
    let (bin_dir, overlay, payload) = xray_fixture(&dir, &format!("XRAY_ROUTER_XRAY_SHA256={}\n", "0".repeat(64)));
    write(&state, json!({"schema": 2, "components": {"xray": {"version": "26.3.27"}}}).to_string().as_bytes());
    let ups = Arc::new(Mutex::new(0));
    let (counter, status) = (ups.clone(), xray_status_argv());
    let host = Host::new(move |c: &Command| {
        if c.argv.len() >= 5 && tail(&c.argv, 5) == ["up", "-d", "--no-deps", "--wait", "xray-router"] {
            *counter.lock().unwrap() += 1;
        }
        // The container keeps reporting the old build: the new one never came up.
        Ok(if c.argv == status { xray_status("26.3.27", "idle") } else { String::new() })
    });
    let config = xray_config(&dir, &state, &bin_dir, &overlay, &["compose.yaml"], true);
    let agent = agent_with(config, &host, serving(payload));
    let error = update_error(agent.update("xray", "26.4.1", Some("26.3.27")));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert!(error.message.contains("restored and verified"));
    for name in XRAY_MEMBERS {
        assert_eq!(read(&bin_dir.join(name)), format!("old-{name}").into_bytes());
    }
    assert_eq!(mode(&bin_dir.join("xray")), 0o755);
    assert_eq!(text(&overlay), format!("XRAY_ROUTER_XRAY_SHA256={}\n", "0".repeat(64)));
    assert_eq!(*ups.lock().unwrap(), 2);
    assert_eq!(state_json(&state)["components"]["xray"]["version"], "26.3.27");
    // The cause chain names the version check.
    assert!(error.causes.iter().any(|c| c.message == "xray-router runs 26.3.27, expected 26.4.1"), "{error:?}");
}

#[test]
fn xray_rollback_that_does_not_reach_idle_is_reported_as_unverified() {
    let dir = TempDir::new("xray-unverified");
    let (bin_dir, overlay, payload) = xray_fixture(&dir, &format!("XRAY_ROUTER_XRAY_SHA256={}\n", "0".repeat(64)));
    dir.write("state.json", &json!({"schema": 2, "components": {"xray": {"version": "26.3.27"}}}).to_string());
    let status = xray_status_argv();
    let host =
        Host::new(move |c: &Command| Ok(if c.argv == status { xray_status("26.3.27", "broken") } else { String::new() }));
    let config = xray_config(&dir, &dir.join("state.json"), &bin_dir, &overlay, &["compose.yaml"], true);
    let agent = agent_with(config, &host, serving(payload));
    let error = update_error(agent.update("xray", "26.4.1", Some("26.3.27")));
    assert_eq!(error.state, UpdateState::RollbackFailed);
    let saved = &state_json(&dir.join("state.json"))["components"]["xray"];
    assert_eq!((&saved["version"], &saved["status"]), (&json!("26.3.27"), &json!("rollback_failed")));
}

#[test]
fn xray_is_refused_without_the_router_and_with_a_mismatched_archive() {
    let dir = TempDir::new("xray-refused");
    let (bin_dir, overlay, payload) = xray_fixture(&dir, "");
    let config = xray_config(&dir, &dir.join("state.json"), &bin_dir, &overlay, &["compose.yaml"], false);
    let agent = agent_with(config, &Host::answering(""), serving(payload.clone()));
    assert!(agent.list_versions(true).unwrap()["components"].get("xray").is_none());
    let error = agent.update("xray", "26.4.1", None).unwrap_err();
    assert!(matches!(&error, AgentError::Catalog(e) if e.0.contains("unsupported component")), "{error:?}");
    let config = xray_config(&dir, &dir.join("state.json"), &bin_dir, &overlay, &["compose.yaml"], true);
    let mut tampered = payload;
    tampered.push(b'x');
    let agent = agent_with(config, &Host::answering(""), serving(tampered));
    assert!(update_error(agent.update("xray", "26.4.1", None)).message.contains("SHA-256 mismatch"));
    assert_eq!(read(&bin_dir.join("xray")), b"old-xray");
    assert_eq!(text(&overlay), "");
}

#[test]
fn the_router_status_falls_back_to_the_python_module_on_an_old_image() {
    // 4.0: the Rust manager's subcommand first; the Python module only when the binary is absent
    // (a router still on its pre-4.0 image while its rebuild is pending).
    assert_eq!(XRAY_STATUS_COMMAND[..2], ["sh", "-c"]);
    assert_eq!(
        XRAY_STATUS_COMMAND[2],
        "if [ -x /usr/local/bin/xray-router-manager ]; then exec /usr/local/bin/xray-router-manager healthcheck --status; \
         else exec python -m xray_router_manager.healthcheck --status; fi"
    );
}

// --- telemt -------------------------------------------------------------------------------------

fn telemt_config(dir: &TempDir, state: &Path) -> (AgentConfig, PathBuf) {
    let compose = dir.join("deployment");
    write(&compose.join("compose.yaml"), b"name: mtproxy\nservices: {}\n");
    let mut config = AgentConfig::new(dir.join("catalog.json"), state);
    config.compose_dir = Some(compose.clone());
    config.compose_files = vec!["compose.yaml".into()];
    config.telemt_container = "telemt-test".into();
    (config, compose.join("version-overrides").join("compose.versions.yaml"))
}

#[test]
fn telemt_update_persists_override_and_uses_expected_compose_files() {
    let dir = TempDir::new("telemt-image");
    write_catalog(&dir.join("catalog.json"), None);
    dir.write("state.json", &json!({"components": {"telemt": {"version": "3.4.24"}}}).to_string());
    let (config, override_file) = telemt_config(&dir, &dir.join("state.json"));
    let old_image = format!("ghcr.io/example/telemt@sha256:{}", "b".repeat(64));
    let watched = override_file.clone();
    let host = Host::new(move |c: &Command| {
        if has(&c.argv, "{{.Config.Image}}") {
            let configured = std::fs::read_to_string(&watched).unwrap_or_default();
            return Ok(if configured.contains(TELEMT_IMAGE) { TELEMT_IMAGE.into() } else { old_image.clone() });
        }
        if has(&c.argv, "{{.State.Health.Status}}") {
            return Ok("healthy\n".into());
        }
        Ok("ok\n".into())
    });
    let agent = agent_with(config, &host, serving(BINARY.to_vec()));
    assert_eq!(agent.update("telemt", "3.4.25", Some("3.4.24")).unwrap()["version"], "3.4.25");
    assert!(text(&override_file).contains(TELEMT_IMAGE));
    assert_eq!(mode(&override_file), 0o640);
    let commands = host.commands();
    let pull = commands.iter().find(|c| has(&c.argv, "pull")).unwrap();
    assert_eq!((tail(&pull.argv, 2), pull.timeout.as_secs()), (vec!["pull", "mtproxy"], 900));
    let up = commands.iter().find(|c| has(&c.argv, "up") && has(&c.argv, "mtproxy")).unwrap();
    assert_eq!((tail(&up.argv, 4), up.timeout.as_secs()), (vec!["up", "-d", "--no-deps", "mtproxy"], 300));
    // The overlays' variables are required by the model: every Compose call names them.
    for command in commands.iter().filter(|c| starts(&c.argv, &["docker", "compose"])) {
        assert_eq!(env_files_of(&command.argv), [path_text(&dir.join("deployment/.env"))], "{:?}", command.argv);
        assert_eq!(files_of(&command.argv).last().unwrap(), &path_text(&override_file));
    }
    let inspects: Vec<&Command> = commands.iter().filter(|c| starts(&c.argv, &["docker", "inspect"])).collect();
    assert_eq!(inspects.last().unwrap().argv.last().unwrap(), "telemt-test");
}

#[test]
fn telemt_rollback_verifies_restored_image_and_health() {
    let dir = TempDir::new("telemt-rollback");
    write_catalog(&dir.join("catalog.json"), None);
    dir.write("state.json", &json!({"components": {"telemt": {"version": "3.4.24"}}}).to_string());
    let (mut config, override_file) = telemt_config(&dir, &dir.join("state.json"));
    config.health_timeout = 0.0;
    let old_image = format!("ghcr.io/example/telemt@sha256:{}", "b".repeat(64));
    let old_override = format!("services:\n  mtproxy:\n    image: {old_image}\n");
    write(&override_file, old_override.as_bytes());
    let running = Arc::new(Mutex::new(old_image.clone()));
    let reads = Arc::new(Mutex::new(Vec::new()));
    let (current, seen, watched) = (running.clone(), reads.clone(), override_file.clone());
    let host = Host::new(move |c: &Command| {
        if starts(&c.argv, &["docker", "compose", "--project-name"]) && has(&c.argv, "up") {
            let configured = std::fs::read_to_string(&watched).unwrap_or_default();
            *current.lock().unwrap() = if configured.contains(TELEMT_IMAGE) { TELEMT_IMAGE.into() } else { old_image.clone() };
            return Ok("ok\n".into());
        }
        if has(&c.argv, "{{.Config.Image}}") {
            return Ok(current.lock().unwrap().clone());
        }
        if has(&c.argv, "{{.State.Health.Status}}") {
            let image = current.lock().unwrap().clone();
            seen.lock().unwrap().push(image.clone());
            return Ok(if image == TELEMT_IMAGE { "unhealthy".into() } else { "healthy".into() });
        }
        Ok("ok\n".into())
    });
    let agent = agent_with(config, &host, no_download());
    let error = update_error(agent.update("telemt", "3.4.25", Some("3.4.24")));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert!(error.message.contains("restored and verified"));
    assert_eq!(text(&override_file), old_override);
    assert_eq!(*reads.lock().unwrap(), [TELEMT_IMAGE.to_string(), format!("ghcr.io/example/telemt@sha256:{}", "b".repeat(64))]);
    assert_eq!(state_json(&dir.join("state.json"))["components"]["telemt"]["version"], "3.4.24");
}

const BUILD_BINARY: &[u8] = b"\x7fELF-telemt-3.5.14";
const BUILD_URL: &str = "https://github.com/telemt/telemt/releases/download/3.5.14/telemt";

fn build_base() -> String {
    format!("ghcr.io/samnet-dev/mtproxymax-telemt@sha256:{}", "d".repeat(64))
}

fn build_tag() -> String {
    format!("proxy-control-telemt:3.5.14-{}", &sha(BUILD_BINARY)[..12])
}

/// What the fake `docker build` saw.
#[derive(Default)]
struct Built {
    dockerfile: String,
    binary: Vec<u8>,
    dir_mode: u32,
    bin_mode: u32,
    argv: Vec<String>,
}

struct BuildHost {
    agent: Arc<VersionAgent>,
    override_file: PathBuf,
    host: Host,
    built: Arc<Mutex<Built>>,
    state: PathBuf,
}

/// `_build_agent(tmp_path, downloader=…, fail_on=…, previous_override=…)`.
fn build_agent(dir: &TempDir, updater: HostUpdater, fail_on: Option<&'static str>, previous: Option<&str>) -> BuildHost {
    let entry = json!({"version": "3.5.14", "kind": "build", "base_image": build_base(), "url": BUILD_URL, "sha256": sha(BUILD_BINARY)});
    write(&dir.join("catalog.json"), json!({"schema": 1, "components": {"telemt": [entry]}}).to_string().as_bytes());
    let state = dir.join("agent/state.json");
    write(&state, json!({"components": {"telemt": {"version": "3.5.9"}}}).to_string().as_bytes());
    let (mut config, override_file) = telemt_config(dir, &state);
    config.health_timeout = 0.0;
    if let Some(previous) = previous {
        write(&override_file, previous.as_bytes());
    }
    let built = Arc::new(Mutex::new(Built::default()));
    let (record, watched) = (built.clone(), override_file.clone());
    let host = Host::new(move |c: &Command| {
        let argv = &c.argv;
        let current = || {
            let text = std::fs::read_to_string(&watched).unwrap_or_default();
            if text.contains(&build_tag()) { build_tag() } else { "proxy-control-telemt:3.5.9-aaaaaaaaaaaa".to_string() }
        };
        if starts(argv, &["docker", "build"]) {
            let directory = PathBuf::from(argv.last().unwrap());
            let mut built = record.lock().unwrap();
            built.dockerfile = std::fs::read_to_string(directory.join("Dockerfile")).unwrap();
            built.binary = std::fs::read(directory.join("telemt")).unwrap();
            built.dir_mode = mode(&directory);
            built.bin_mode = mode(&directory.join("telemt"));
            built.argv = argv.clone();
            if fail_on == Some("build") {
                return Err(runtime_error("build failed"));
            }
        }
        if has(argv, "{{.Config.Image}}") {
            return Ok(current());
        }
        if has(argv, "{{.State.Health.Status}}") {
            return Ok(if fail_on == Some("health") && current() == build_tag() { "unhealthy" } else { "healthy" }.into());
        }
        if starts(argv, &["docker", "image", "ls"]) {
            return Ok(format!("{}\nproxy-control-telemt:3.5.9-aaaaaaaaaaaa\nproxy-control-telemt:3.5.7-bbbbbbbbbbbb\n", build_tag()));
        }
        Ok("ok\n".into())
    });
    let agent = agent_with(config, &host, updater);
    BuildHost { agent, override_file, host, built, state }
}

#[test]
fn telemt_build_update_builds_the_local_image_and_never_pulls() {
    let dir = TempDir::new("telemt-build");
    let run = build_agent(&dir, serving(BUILD_BINARY.to_vec()), None, None);
    assert_eq!(
        run.agent.update("telemt", "3.5.14", Some("3.5.9")).unwrap(),
        json!({"component": "telemt", "version": "3.5.14", "changed": true})
    );
    let built = run.built.lock().unwrap();
    assert_eq!(
        built.dockerfile,
        format!(
            "FROM {}\nCOPY telemt /usr/local/bin/telemt\nRUN chmod 0755 /usr/local/bin/telemt\n\
             LABEL org.proxy-control.telemt.version=\"3.5.14\" org.proxy-control.telemt.sha256=\"{}\"\n",
            build_base(),
            sha(BUILD_BINARY)
        )
    );
    assert_eq!(built.binary, BUILD_BINARY);
    assert_eq!((built.dir_mode, built.bin_mode), (0o700, 0o755));
    assert_eq!(built.argv[..4], ["docker", "build", "-t", build_tag().as_str()]);
    assert!(text(&run.override_file).contains(&format!("image: {}\n", build_tag())));
    let argvs = run.host.argvs();
    assert!(!argvs.iter().any(|a| has(a, "pull")));
    assert!(argvs.iter().any(|a| has(a, "up") && has(a, "mtproxy")));
    let saved = &state_json(&run.state)["components"]["telemt"];
    assert_eq!((&saved["version"], &saved["kind"], &saved["base_image"]), (&json!("3.5.14"), &json!("build"), &json!(build_base())));
    // Only the image now in use and the previous generation survive (best effort).
    let removed: Vec<&String> =
        argvs.iter().filter(|a| starts(a, &["docker", "image", "rm"])).map(|a| a.last().unwrap()).collect();
    assert_eq!(removed, ["proxy-control-telemt:3.5.7-bbbbbbbbbbbb"]);
    let build_command = run.host.commands().into_iter().find(|c| starts(&c.argv, &["docker", "build"])).unwrap();
    assert_eq!(build_command.timeout.as_secs(), 900);
}

#[test]
fn telemt_build_with_a_wrong_sha256_refuses_before_anything_changes() {
    let dir = TempDir::new("telemt-build-sha");
    let run = build_agent(&dir, serving(b"tampered".to_vec()), None, None);
    assert!(update_error(run.agent.update("telemt", "3.5.14", Some("3.5.9"))).message.contains("SHA-256 mismatch"));
    assert!(run.host.argvs().is_empty() && !run.override_file.exists());
    assert!(!dir.join("agent/telemt-build").exists());
    assert_eq!(state_json(&run.state)["components"]["telemt"]["version"], "3.5.9");
}

#[test]
fn telemt_build_refuses_a_host_that_is_not_x86_64() {
    let dir = TempDir::new("telemt-build-arch");
    let mut updater = serving(BUILD_BINARY.to_vec());
    updater.machine = "aarch64".into();
    let run = build_agent(&dir, updater, None, None);
    assert!(update_error(run.agent.update("telemt", "3.5.14", Some("3.5.9"))).message.contains("x86_64"));
    assert!(run.host.argvs().is_empty());
}

#[test]
fn telemt_build_refuses_an_oversized_binary() {
    let dir = TempDir::new("telemt-build-size");
    let mut updater = serving(BUILD_BINARY.to_vec());
    updater.telemt_binary_max = 8;
    let run = build_agent(&dir, updater, None, None);
    assert!(update_error(run.agent.update("telemt", "3.5.14", Some("3.5.9"))).message.contains("too large"));
    assert!(run.host.argvs().is_empty());
}

#[test]
fn telemt_build_failure_restores_the_previous_override() {
    for fail_on in ["build", "health"] {
        let dir = TempDir::new("telemt-build-restore");
        let old_override = "services:\n  mtproxy:\n    image: proxy-control-telemt:3.5.9-aaaaaaaaaaaa\n";
        let run = build_agent(&dir, serving(BUILD_BINARY.to_vec()), Some(fail_on), Some(old_override));
        let error = update_error(run.agent.update("telemt", "3.5.14", Some("3.5.9")));
        assert_eq!(error.state, UpdateState::RolledBack, "{fail_on}");
        assert!(error.message.contains("restored and verified"));
        assert_eq!(text(&run.override_file), old_override);
        assert!(!run.host.argvs().iter().any(|a| has(a, "pull")));
        assert_eq!(state_json(&run.state)["components"]["telemt"]["version"], "3.5.9");
    }
}

#[test]
fn telemt_build_failure_without_a_previous_override_removes_it() {
    let dir = TempDir::new("telemt-build-none");
    let run = build_agent(&dir, serving(BUILD_BINARY.to_vec()), Some("build"), None);
    assert_eq!(update_error(run.agent.update("telemt", "3.5.14", Some("3.5.9"))).state, UpdateState::RolledBack);
    assert!(!run.override_file.exists());
    // The rollback's `up` runs without the override it removed.
    let last_up = run.host.argvs().into_iter().rfind(|a| has(a, "up")).unwrap();
    assert!(!last_up.join(" ").contains("version-overrides"));
}

// --- the version override -----------------------------------------------------------------------

#[test]
fn the_override_keeps_every_other_block_and_replaces_one() {
    let text = "# Generated by proxy-control version-agent; do not edit manually.\nservices:\n  mtproxy:\n    image: x\n\
                \n  awg-manager:\n    build:\n      args:\n        AWG_GO_VERSION: \"1\"\nnot indented\n";
    let lines = ["    image: y".to_string()];
    assert_eq!(
        override_with(text, "mtproxy", &lines),
        "# Generated by proxy-control version-agent; do not edit manually.\nservices:\n  mtproxy:\n    image: y\n  \
         awg-manager:\n    build:\n      args:\n        AWG_GO_VERSION: \"1\"\n"
    );
    // A new service is appended; a header with trailing whitespace counts; an empty file starts over.
    assert_eq!(
        override_with("services:\n  mtproxy:  \n    image: x\n", "awg-manager", &["    build:".into()]),
        "# Generated by proxy-control version-agent; do not edit manually.\nservices:\n  mtproxy:\n    image: x\n  \
         awg-manager:\n    build:\n"
    );
    assert_eq!(override_with("", "mtproxy", &lines), format!("{}services:\n  mtproxy:\n    image: y\n", crate::updater::OVERRIDE_HEADER));
    // A repeated header starts its block over (Python's dict assignment).
    assert_eq!(
        override_with("  a:\n    one\n  b:\n    two\n  a:\n    three\n", "c", &[]),
        format!("{}services:\n  a:\n    three\n  b:\n    two\n  c:\n", crate::updater::OVERRIDE_HEADER)
    );
}

// --- the AmneziaWG and TrustTunnel managers -----------------------------------------------------

const TT: &str = "https://github.com/TrustTunnel/TrustTunnel/releases/download";

/// The protocol managers' host: containers report the version they were built with.
struct ManagerHost {
    compose: PathBuf,
    host: Host,
}

fn manager_host(dir: &TempDir, fail_build: bool, env_version: Option<&'static str>) -> ManagerHost {
    let compose = dir.join("compose");
    std::fs::create_dir_all(compose.join("version-overrides")).unwrap();
    let original: BTreeMap<String, String> = BTreeMap::from([
        ("proxy-control-awg-manager".to_string(), "3.1.20260814".to_string()),
        ("proxy-control-trusttunnel-manager".to_string(), "v1.1.0".to_string()),
    ]);
    let versions = Arc::new(Mutex::new(original.clone()));
    let override_file = compose.join("version-overrides/compose.versions.yaml");
    let host = Host::new(move |c: &Command| {
        let argv = &c.argv;
        if starts(argv, &["docker", "inspect", "--format"]) && argv[3].contains("com.docker.compose.project") {
            return Ok("proxy_panel_by_dubr1k".into());
        }
        if starts(argv, &["docker", "inspect", "--format"]) && argv[3].contains("Config.Env") {
            let container = argv.last().unwrap();
            let key = if container.contains("awg") { "AWG_GO_VERSION" } else { "TT_VERSION" };
            return Ok(format!("PATH=/usr/bin\n{key}={}\n", versions.lock().unwrap()[container]));
        }
        if starts(argv, &["docker", "inspect", "--format"]) && argv[3] == "{{.Image}}" {
            return Ok(format!("sha256:{}", "d".repeat(64)));
        }
        if starts(argv, &["docker", "ps"]) {
            return Ok("c1".into());
        }
        if starts(argv, &["docker", "inspect", "--format"]) {
            return Ok("healthy".into());
        }
        if starts(argv, &["docker", "compose"]) && has(argv, "--no-build") {
            // The rollback image runs again.
            *versions.lock().unwrap() = original.clone();
            return Ok(String::new());
        }
        if starts(argv, &["docker", "compose"]) && has(argv, "--build") {
            if fail_build {
                return Err(runtime_error("build failed"));
            }
            let text = std::fs::read_to_string(&override_file).unwrap();
            let value = |key: &str| text.split(&format!("{key}: \"")).nth(1).map(|rest| rest.split('"').next().unwrap().to_string());
            let mut versions = versions.lock().unwrap();
            if has(argv, "awg-manager") {
                if let Some(version) = value("AWG_GO_VERSION") {
                    versions.insert("proxy-control-awg-manager".into(), env_version.map(String::from).unwrap_or(version));
                }
            }
            if has(argv, "trusttunnel-manager") {
                if let Some(version) = value("TT_VERSION") {
                    versions.insert("proxy-control-trusttunnel-manager".into(), version);
                }
            }
        }
        Ok(String::new())
    });
    ManagerHost { compose, host }
}

fn manager_agent(dir: &TempDir, host: &ManagerHost, sleeps: Option<Arc<Mutex<Vec<f64>>>>) -> Arc<VersionAgent> {
    let catalog = json!({"schema": 1, "components": {
        "amneziawg": [{"version": "3.1.20260828", "kind": "build", "build": {"commit": "b".repeat(40), "tag": "v3.1.20260828"}}],
        "trusttunnel": [{"version": "1.2.0", "kind": "build", "url": format!("{TT}/v1.2.0/trusttunnel-v1.2.0-linux-x86_64.tar.gz"),
                         "sha256": "a".repeat(64)}],
    }});
    write(&dir.join("catalog.json"), catalog.to_string().as_bytes());
    let mut config = AgentConfig::new(dir.join("catalog.json"), dir.join("state.json"));
    config.compose_dir = Some(host.compose.clone());
    config.compose_files = ["compose.yaml", "compose.amneziawg.yaml", "compose.trusttunnel.yaml"].map(String::from).to_vec();
    config.manager_health_timeout = 4.0;
    let mut updater = no_download();
    if let Some(sleeps) = sleeps {
        updater.sleep = Arc::new(move |seconds| sleeps.lock().unwrap().push(seconds));
    }
    agent_with(config, &host.host, updater)
}

#[test]
fn an_update_rebuilds_the_manager_with_build_args_and_keeps_the_other_overrides() {
    let dir = TempDir::new("manager-update");
    let host = manager_host(&dir, false, None);
    let override_file = host.compose.join("version-overrides/compose.versions.yaml");
    write(
        &override_file,
        b"# Generated by proxy-control version-agent; do not edit manually.\nservices:\n  mtproxy:\n    image: proxy-control-telemt:3.5.14-abc\n",
    );
    let agent = manager_agent(&dir, &host, None);
    assert_eq!(agent.update("amneziawg", "3.1.20260828", Some("3.1.20260814")).unwrap()["changed"], true);
    assert_eq!(agent.update("trusttunnel", "1.2.0", Some("1.1.0")).unwrap()["changed"], true);
    let written = text(&override_file);
    assert!(written.contains("  mtproxy:\n    image: proxy-control-telemt:3.5.14-abc\n")); // Telemt's pin kept
    assert!(written.contains(&format!(
        "  awg-manager:\n    build:\n      args:\n        AWG_GO_VERSION: \"3.1.20260828\"\n        AWG_GO_COMMIT: \"{}\"\n",
        "b".repeat(40)
    )));
    assert!(written.contains(&format!(
        "  trusttunnel-manager:\n    build:\n      args:\n        TT_VERSION: \"v1.2.0\"\n        TT_SHA256_X86_64: \"{}\"\n",
        "a".repeat(64)
    )));
    let commands = host.host.commands();
    let builds: Vec<&Command> =
        commands.iter().filter(|c| starts(&c.argv, &["docker", "compose"]) && has(&c.argv, "--build")).collect();
    assert_eq!(builds.iter().map(|c| c.argv.last().unwrap().as_str()).collect::<Vec<_>>(), ["awg-manager", "trusttunnel-manager"]);
    for build in &builds {
        assert!(has(&build.argv, "--project-name") && has(&build.argv, "proxy_panel_by_dubr1k"));
        assert!(has(&build.argv, &path_text(&override_file)));
        assert_eq!(build.timeout.as_secs(), 1080);
    }
    let tags: Vec<&Command> = commands.iter().filter(|c| starts(&c.argv, &["docker", "tag"])).collect();
    assert!(tags[0].argv[3].starts_with("proxy_panel_by_dubr1k-awg-manager:rollback-"));
    let listed = agent.list_versions(true).unwrap()["components"].clone();
    assert_eq!((&listed["amneziawg"]["current"], &listed["trusttunnel"]["current"]), (&json!("3.1.20260828"), &json!("1.2.0")));
}

#[test]
fn a_failed_build_restores_the_override_and_the_image_and_proves_the_old_version() {
    let dir = TempDir::new("manager-failed");
    let host = manager_host(&dir, true, None);
    let override_file = host.compose.join("version-overrides/compose.versions.yaml");
    write(&override_file, b"# Generated by proxy-control version-agent; do not edit manually.\nservices:\n  mtproxy:\n    image: x\n");
    let before = read(&override_file);
    let agent = manager_agent(&dir, &host, None);
    let error = update_error(agent.update("amneziawg", "3.1.20260828", Some("3.1.20260814")));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert_eq!(read(&override_file), before);
    let commands = host.host.commands();
    assert!(commands.iter().any(|c| starts(&c.argv, &["docker", "tag"]) && c.argv.last().unwrap() == "proxy_panel_by_dubr1k-awg-manager:latest"));
    let restore = commands.iter().find(|c| starts(&c.argv, &["docker", "compose"]) && has(&c.argv, "--no-build")).unwrap();
    assert_eq!(restore.timeout.as_secs(), 300);
}

#[test]
fn a_rebuild_that_reports_another_version_is_rolled_back() {
    let dir = TempDir::new("manager-version");
    let host = manager_host(&dir, false, Some("3.1.20260812"));
    let agent = manager_agent(&dir, &host, None);
    let error = update_error(agent.update("amneziawg", "3.1.20260828", Some("3.1.20260814")));
    assert_eq!(error.state, UpdateState::RolledBack);
    assert!(error.causes.iter().any(|c| c.message == "awg-manager reports 3.1.20260812 after the rebuild"), "{error:?}");
    // There was no override before.
    assert!(!host.compose.join("version-overrides/compose.versions.yaml").exists());
}

#[test]
fn a_trusttunnel_update_needs_an_x86_64_host() {
    let dir = TempDir::new("manager-arch");
    let host = manager_host(&dir, false, None);
    let agent = {
        let agent = manager_agent(&dir, &host, None);
        let mut updater = no_download();
        updater.machine = "aarch64".into();
        let mut owned = VersionAgent::new(agent.config.clone());
        owned.runner = agent.runner.clone();
        owned.updater = Arc::new(updater);
        Arc::new(owned)
    };
    let error = update_error(agent.update("trusttunnel", "1.2.0", Some("1.1.0")));
    assert_eq!(error.message, "the TrustTunnel release archive is pinned for x86_64 only");
}
