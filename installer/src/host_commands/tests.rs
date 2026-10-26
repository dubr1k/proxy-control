use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pc_host::fs::sha256_hex;
use pc_host::runner::{CallKind, RecordingRunner, Reply};
use serde_json::json;

use super::{agent, compose, update, Host};
use crate::testkit::TempDir;

#[path = "../tests/fakes.rs"]
#[allow(dead_code)]
mod fakes;

fn release(path: &Path) -> PathBuf {
    let tree = path.join("release");
    let binary = tree.join(pc_host::archive::identity::AGENT_BINARY);
    fakes::write(&binary, b"native agent executable\n");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    fakes::write(&tree.join("VERSION"), b"4.0.0\n");
    fakes::write(
        &tree.join("release/release.json"),
        &serde_json::to_vec(&json!({
            "version": "4.0.0", "tag": "v4.0.0", "commit": "a".repeat(40), "manifest_sha256": "b".repeat(64),
            "binaries": { pc_host::archive::identity::AGENT_BINARY: sha256_hex(b"native agent executable\n") }
        }))
        .unwrap(),
    );
    tree
}

fn host<'a>(root: &Path, source: &Path, runner: &'a RecordingRunner) -> Host<'a> {
    Host {
        root: root.to_path_buf(),
        source: source.to_path_buf(),
        runner,
        socket: root.join("run/proxy-control/version-agent.sock"),
        env: root.join("etc/proxy-control/version-agent.env"),
        poll: Duration::ZERO,
    }
}

fn old_host(root: &Path) {
    fakes::write(&root.join("opt/proxy-control/version_agent/server.py"), b"old python agent\n");
    fakes::write(&root.join("etc/systemd/system/version-agent.service"), b"[Service]\nEnvironmentFile=/etc/custom.env\nExecStart=/usr/bin/python3 -m version_agent.server\nMemoryDenyWriteExecute=false\n");
    fakes::write(&root.join("etc/proxy-control/version-agent.env"), b"OPERATOR_OVERRIDE=keep\n");
    fakes::write(&root.join("etc/tmpfiles.d/proxy-control-version-agent.conf"), b"operator tmpfiles\n");
    fakes::write(
        &root.join("etc/systemd/system/version-agent.service.d/operator.conf"),
        b"[Service]\nLimitNOFILE=9999\n",
    );
}

fn agent_runner(root: &Path, health: serde_json::Value, fail_start: bool) -> RecordingRunner {
    let root = root.to_path_buf();
    RecordingRunner::with_responder(move |call| {
        let native = root.join("opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent").exists();
        if call.argv.first().is_some_and(|s| s == "curl") {
            return Some(Reply::ok(&if native { health.to_string() } else { json!({"status": "ok"}).to_string() }));
        }
        if fail_start && native && call.argv == ["systemctl", "start", "version-agent"] {
            return Some(Reply::exit(1, "", "start refused"));
        }
        None
    })
}

#[test]
fn migrates_python_agent_without_journal_preserving_operator_overrides() {
    let dir = TempDir::new("host-migrate");
    let root = dir.path().join("root");
    old_host(&root);
    let source = release(dir.path());
    let runner = agent_runner(&root, json!({"status":"ok","implementation":"rust","version":"4.0.0"}), false);
    agent::migrate(&host(&root, &source, &runner), "4.0.0").unwrap();
    assert!(!root.join("opt/proxy-control/version_agent/server.py").exists());
    assert!(root.join("opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent").is_file());
    assert_eq!(
        fs::read_to_string(root.join("etc/proxy-control/version-agent.env")).unwrap(),
        "OPERATOR_OVERRIDE=keep\n"
    );
    let unit = fs::read_to_string(root.join("etc/systemd/system/version-agent.service")).unwrap();
    assert!(unit.contains("EnvironmentFile=/etc/custom.env\n"));
    assert!(unit.contains("MemoryDenyWriteExecute=false\n"));
    assert_eq!(
        fs::read_to_string(root.join("etc/systemd/system/version-agent.service.d/operator.conf")).unwrap(),
        "[Service]\nLimitNOFILE=9999\n"
    );
    let calls = runner.argvs();
    let stop = calls.iter().position(|a| a == &["systemctl", "stop", "version-agent"]).unwrap();
    let reload = calls.iter().position(|a| a == &["systemctl", "daemon-reload"]).unwrap();
    let start = calls.iter().position(|a| a == &["systemctl", "start", "version-agent"]).unwrap();
    assert!(stop < reload && reload < start);
    assert!(!root.join("var/lib/proxy-control/installer/state.json").exists());
}

#[test]
fn rejects_missing_or_wrong_native_version_and_rolls_back_before_dependents() {
    for health in [
        json!({"status":"ok","implementation":"rust"}),
        json!({"status":"ok","implementation":"rust","version":"3.3.0"}),
        json!({"status":"ok","implementation":"python","version":"4.0.0"}),
        json!({"status":"failed","implementation":"rust","version":"4.0.0"}),
    ] {
        let dir = TempDir::new("bad-health");
        let root = dir.path().join("root");
        old_host(&root);
        let before_unit = fs::read(root.join("etc/systemd/system/version-agent.service")).unwrap();
        let source = release(dir.path());
        let runner = agent_runner(&root, health, false);
        let error = agent::migrate(&host(&root, &source, &runner), "4.0.0").unwrap_err();
        assert!(error.contains("previous generation restored and verified"), "{error}");
        assert_eq!(fs::read(root.join("etc/systemd/system/version-agent.service")).unwrap(), before_unit);
        assert_eq!(fs::read(root.join("opt/proxy-control/version_agent/server.py")).unwrap(), b"old python agent\n");
        assert!(!root.join("opt/proxy-control/version_agent/bin").exists());
        assert!(runner.argvs().iter().all(|args| !args
            .iter()
            .any(|arg| arg.contains("/v1/update") || arg.contains("/v1/upstream") || arg == "docker")));
    }
}

#[test]
fn failed_start_restores_old_unit_code_and_tmpfiles() {
    let dir = TempDir::new("failed-start");
    let root = dir.path().join("root");
    old_host(&root);
    let source = release(dir.path());
    let runner = agent_runner(&root, json!({"status":"ok","implementation":"rust","version":"4.0.0"}), true);
    let error = agent::migrate(&host(&root, &source, &runner), "4.0.0").unwrap_err();
    assert!(error.contains("previous generation restored and verified"));
    assert_eq!(fs::read(root.join("etc/tmpfiles.d/proxy-control-version-agent.conf")).unwrap(), b"operator tmpfiles\n");
}

#[test]
fn invalid_source_binary_refuses_before_stop() {
    let dir = TempDir::new("bad-binary");
    let root = dir.path().join("root");
    old_host(&root);
    let source = release(dir.path());
    fs::write(source.join(pc_host::archive::identity::AGENT_BINARY), b"tampered").unwrap();
    let runner = agent_runner(&root, json!({}), false);
    assert!(agent::migrate(&host(&root, &source, &runner), "4.0.0").unwrap_err().contains("digest mismatch"));
    assert!(!runner.argvs().iter().any(|a| a.first().is_some_and(|s| s == "systemctl")));
}

#[test]
fn full_agent_swap_rebases_python_checkpoint_and_stays_repairable() {
    let dir = TempDir::new("owned-swap");
    let root = dir.path().join("root");
    let owned = fakes::owned_host(&root, dir.path(), true);
    // The fixture unit is a minimal Python unit; give it the actual recognized 3.x entry point
    // and update its owned bytes before the migration, just as the Python adapter records them.
    let source = release(dir.path());
    let runner = agent_runner(&root, json!({"status":"ok","implementation":"rust","version":"4.0.0"}), false);
    let before = owned.engine.store().read_state().unwrap();
    agent::migrate(&host(&root, &source, &runner), "4.0.0").unwrap();
    let after = owned.engine.store().read_state().unwrap();
    assert_eq!(before.plan_digest, after.plan_digest);
    assert_eq!(after.ownership(true).unwrap(), owned.engine.store().read_ownership().unwrap());
    let checkpoint = after.checkpoint("version_agent.runtime").unwrap();
    assert!(checkpoint
        .ownership
        .contains_key("/opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent"));
    assert!(!checkpoint.ownership.keys().any(|name| name.ends_with(".py")));
    owned.engine.assert_all_owned(&after).unwrap();
    owned.engine.repair().unwrap();
    owned.engine.uninstall(false).unwrap();
}

#[test]
fn native_health_is_strict_even_when_agent_already_responds() {
    let dir = TempDir::new("strict-health");
    let root = dir.path().join("root");
    let runner = RecordingRunner::new();
    for value in [
        json!({"status":"ok"}),
        json!({"status":"ok","implementation":"rust"}),
        json!({"status":"ok","implementation":"rust","version":"4.0.1"}),
    ] {
        let runner = RecordingRunner::new();
        runner.reply(&["curl"], Reply::ok(&value.to_string()));
        assert!(agent::healthy(&host(&root, dir.path(), &runner), "4.0.0").is_err());
    }
    runner.reply(&["curl"], Reply::ok("{\"status\":\"ok\",\"implementation\":\"rust\",\"version\":\"4.0.0\"}"));
    agent::healthy(&host(&root, dir.path(), &runner), "4.0.0").unwrap();
}

#[test]
fn pending_read_failure_is_not_no_work() {
    let dir = TempDir::new("pending-json");
    let root = dir.path().join("root");
    let runner = RecordingRunner::new();
    runner.reply(&["curl"], Reply::ok("not JSON"));
    assert!(host(&root, dir.path(), &runner).agent("/v1/versions", None).is_err());
}

#[test]
fn mutation_nonzero_exit_is_not_success() {
    let dir = TempDir::new("nonzero");
    let runner = RecordingRunner::new();
    runner.reply_for(CallKind::Run, &["docker"], Reply::exit(1, "", "failed"));
    assert!(host(dir.path(), dir.path(), &runner).run(&super::strings(&["docker", "compose", "up"])).is_err());
}

#[test]
fn rejects_foreign_compose_destination_before_stop() {
    let dir = TempDir::new("compose-foreign");
    let root = dir.path().join("root");
    let project = root.join("project");
    fakes::write(&project.join("compose.yaml"), b"services: {}\n");
    fakes::write(&project.join(".env"), b"\n");
    let runner = RecordingRunner::with_responder(|call| {
        let args = call.argv.join(" ");
        if args.starts_with("docker ps -a") {
            Some(Reply::ok("old-container\n"))
        } else if args.starts_with("docker ps --filter") {
            Some(Reply::ok("panel\n"))
        } else if args.contains(" config --format json") {
            Some(Reply::ok("{\"services\":{\"panel\":{}},\"volumes\":{\"panel-data\":{}}}"))
        } else {
            None
        }
    });
    assert!(compose::migrate(&host(&root, dir.path(), &runner), &project, false)
        .unwrap_err()
        .contains("already exists"));
    assert!(runner.calls().iter().all(|call| call.kind != CallKind::Run));
}

#[test]
fn unknown_host_command_option_fails_without_composing_services() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(super::cli(&["update-host".into(), "--bogus".into()], &mut out, &mut err), Some(2));
    assert!(String::from_utf8(err).unwrap().contains("unknown or incomplete"));
}

#[test]
fn host_help_lists_native_transition_contract() {
    for name in ["update-host", "migrate-agent", "migrate-compose-project"] {
        let mut out = Vec::new();
        assert_eq!(super::cli(&[name.into(), "--help".into()], &mut out, &mut Vec::new()), Some(0));
        assert!(String::from_utf8(out).unwrap().contains(name));
    }
}

#[test]
fn update_fleet_v1_is_rejected_before_migration() {
    let dir = TempDir::new("fleet-scope");
    let root = dir.path().join("root");
    let project = root.join("opt/mtproxy-shared443");
    fakes::write(&project.join("compose.yaml"), b"services: {}\n");
    let socket = root.join("run/proxy-control/version-agent.sock");
    fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    let runner = RecordingRunner::with_responder(|call| {
        let line = call.argv.join(" ");
        if line.contains("/v1/versions") {
            Some(Reply::ok("{\"components\":{\"panel\":{\"current\":\"3.3.0\"}}}"))
        } else if line.contains("docker inspect --format") {
            Some(Reply::ok("mtproxy\n"))
        } else if line.starts_with("docker ps --filter") {
            Some(Reply::ok("fleet-ingress\n"))
        } else {
            None
        }
    });
    let error = update::update(&host(&root, dir.path(), &runner), "4.0.0", &"a".repeat(64)).unwrap_err();
    assert!(error.contains("Fleet v1 is retired"));
    assert!(runner.calls().iter().all(|call| call.kind != CallKind::Run));
}
