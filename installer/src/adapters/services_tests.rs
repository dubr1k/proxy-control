//! Golden, crash/recovery and fake-runner conformance for WP5b.
use super::{mcp::McpAdapter, version_agent::VersionAgentAdapter, warp::WarpAdapter, AdapterContext};
use crate::adapter::Adapter;
use crate::journal::{Phase, RollbackTarget, Status};
use crate::planner::{Action, AuditFacts};
use crate::testkit::{engine_for, plan_with, TempDir};
use pc_host::runner::{Call, RecordingRunner, Reply};
use serde_json::{json, Map, Value};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().into()
}
fn golden(path: &str) -> PathBuf {
    repository().join("tests/fixtures/host-golden").join(path)
}
fn config() -> crate::model::InstallerConfig {
    installer_core::config::load_config(&repository().join("examples/installer/core.toml")).unwrap()
}
fn put(root: &Path, path: &str, text: &str) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}
fn source(root: &Path) -> PathBuf {
    let tree = root.join("source");
    for file in [
        "deploy/version-agent.service",
        "deploy/proxy-control-version-agent.tmpfiles.conf",
        "deploy/version-agent.env.example",
        "compose.yaml",
        "release/external-artifacts.json",
    ] {
        put(&tree, file, &fs::read_to_string(repository().join(file)).unwrap());
    }
    put(&tree, "version_agent/Cargo.toml", "[package]\nname=\"version-agent\"\nversion=\"1\"\n");
    put(&tree, "version_agent/src/main.rs", "fn main() {}\n");
    put(&tree, "version_agent/bin/linux-amd64/proxy-control-version-agent", "binary test payload\n");
    fs::set_permissions(
        tree.join("version_agent/bin/linux-amd64/proxy-control-version-agent"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    tree
}
fn context(root: &Path, runner: Arc<RecordingRunner>) -> AdapterContext {
    AdapterContext { root: root.into(), tree: source(root), runner }
}
fn action_from_golden(name: &str, variant: &str) -> Action {
    let values: Value =
        serde_json::from_slice(&fs::read(golden(&format!("renders/{variant}/actions.json"))).unwrap()).unwrap();
    let v = values.as_array().unwrap().iter().find(|v| v["adapter"] == name).unwrap();
    let strings = |key: &str| v[key].as_array().unwrap().iter().map(|s| s.as_str().unwrap().into()).collect();
    Action::new(
        v["id"].as_str().unwrap(),
        name,
        v["owner"].as_str().unwrap(),
        strings("mutations"),
        strings("preconditions"),
        strings("verification"),
        strings("inverse"),
        v["credentials_required"].as_bool().unwrap(),
    )
    .unwrap()
}
fn health_reply(call: &Call) -> Option<Reply> {
    let a = &call.argv;
    if a == &["systemctl", "is-active", "version-agent"] {
        return Some(Reply::ok("active\n"));
    }
    if a == &["systemctl", "is-enabled", "version-agent"] {
        return Some(Reply::ok("enabled\n"));
    }
    if a.last().is_some_and(|s| s.ends_with("/v1/health")) {
        return Some(Reply::ok("{\"status\":\"ok\",\"implementation\":\"rust\"}"));
    }
    None
}
fn socket(root: &Path) -> UnixListener {
    let path = root.join("run/proxy-control/version-agent.sock");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o660)).unwrap();
    listener
}
fn agent_runner(root: &Path) -> Arc<RecordingRunner> {
    let root = root.to_owned();
    Arc::new(RecordingRunner::with_responder(move |call| {
        if let Some(reply) = health_reply(call) {
            return Some(reply);
        }
        if call.argv.last().is_some_and(|s| s.ends_with("/v1/versions")) {
            let state: Value =
                serde_json::from_slice(&fs::read(root.join("var/lib/proxy-control/version-agent/state.json")).unwrap())
                    .unwrap();
            let components: Map<_, _> = state["components"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, v)| (name.clone(), json!({"current":v["version"]})))
                .collect();
            return Some(Reply::ok(&json!({"enabled":true,"components":components}).to_string()));
        }
        None
    }))
}
fn mcp_runner() -> Arc<RecordingRunner> {
    Arc::new(RecordingRunner::with_responder(|call| {
        let a = &call.argv;
        if a.iter().any(|s| s == "api-key-create") {
            return Some(Reply::ok("starting\n{\"plaintext\":\"pc_test-only-key\"}\n"));
        }
        if a == &["docker", "inspect", "--format", "{{.State.Health.Status}}", "proxy-control-mcp"] {
            return Some(Reply::ok("healthy\n"));
        }
        if a.first().is_some_and(|s| s == "curl") {
            return Some(Reply::ok(if a.iter().any(|s| s == "POST") { "200" } else { "401" }));
        }
        None
    }))
}
fn mcp_action() -> Action {
    action_from_golden("mcp", "kitchen-sink")
}
fn warp_action() -> Action {
    action_from_golden("warp", "managed-three-xui-warp")
}
fn seed_warp(root: &Path, action: &Action) -> crate::journal::CheckpointData {
    let nonce = "a".repeat(32);
    put(root, "/var/lib/proxy-control/warp/owner", &nonce);
    json!({"owner":action.owner,"marker":nonce,"ownership":{}}).as_object().unwrap().clone()
}
fn warp_runner(installed: Arc<Mutex<bool>>) -> Arc<RecordingRunner> {
    Arc::new(RecordingRunner::with_responder(move |call| {
        let a = &call.argv;
        if a.first().is_some_and(|s| s == "dpkg-query") {
            if !*installed.lock().unwrap() {
                return Some(Reply::exit(1, "", ""));
            }
            return Some(Reply::ok(if a[2] == "-f=${Version}" { super::warp::VERSION } else { "installed" }));
        }
        if a == &["apt-get", "purge", "--yes", "cloudflare-warp"] {
            *installed.lock().unwrap() = false;
        }
        if a == &["systemctl", "is-active", "warp-svc"] {
            return Some(Reply::ok("active"));
        }
        if a == &["systemctl", "is-enabled", "warp-svc"] {
            return Some(Reply::ok("enabled"));
        }
        if a == &["ss", "-H", "-ltnp"] {
            return Some(Reply::ok("LISTEN 0 128 127.0.0.1:40000 0.0.0.0:* users:((\"warp-svc\",pid=42,fd=3))\n"));
        }
        if a == &["warp-cli", "--accept-tos", "status"] {
            return Some(Reply::ok("Status update: Connected\n"));
        }
        if a.first().is_some_and(|s| s == "curl") {
            return Some(Reply::ok(if a.iter().any(|s| s == "--socks5-hostname") {
                "ip=203.0.113.2\nwarp=on\n"
            } else {
                "ip=203.0.113.1\nwarp=off\n"
            }));
        }
        None
    }))
}
#[test]
fn service_actions_match_python_goldens() {
    let dir = TempDir::new("s");
    let cx = context(dir.path(), Arc::new(RecordingRunner::new()));
    let agent = VersionAgentAdapter::new(&cx);
    let expected = action_from_golden("version_agent", "direct");
    let mut cfg = config();
    cfg.profile = crate::model::Profile::Full;
    assert_eq!(agent.plan(&cfg, &AuditFacts::default()).unwrap()[0].to_value(), expected.to_value());
    let mcp = McpAdapter::new(&cx);
    cfg.domains.mcp = Some("mcp.example.com".into());
    let expected = mcp_action();
    let action = mcp.plan(&cfg, &AuditFacts::default()).unwrap().remove(0);
    // The kitchen sink carries optional overlays; all remaining bytes are fixed.
    let mut actual = action.to_value();
    let mut expected = expected.to_value();
    actual["mutations"].as_array_mut().unwrap().pop();
    expected["mutations"].as_array_mut().unwrap().pop();
    assert_eq!(actual, expected);
}
#[test]
fn agent_env_fresh_is_byte_exact_python_golden() {
    let dir = TempDir::new("s");
    let agent = VersionAgentAdapter::new(&context(dir.path(), Arc::new(RecordingRunner::new())));
    let action = action_from_golden("version_agent", "direct");
    let selected = action
        .mutations
        .iter()
        .map(|m| {
            let (k, v) = m.split_once('=').unwrap();
            (k.into(), v.into())
        })
        .collect();
    assert_eq!(
        agent.env_text(&selected, "").unwrap().as_bytes(),
        fs::read(golden("renders/direct/version-agent/env.fresh")).unwrap()
    );
}
#[test]
fn repair_preserves_operator_values_and_deduplicates_env() {
    let dir = TempDir::new("s");
    let agent = VersionAgentAdapter::new(&context(dir.path(), Arc::new(RecordingRunner::new())));
    let action = action_from_golden("version_agent", "direct");
    let selected = action
        .mutations
        .iter()
        .map(|m| {
            let (k, v) = m.split_once('=').unwrap();
            (k.into(), v.into())
        })
        .collect();
    let text = agent.env_text(&selected,"PROXY_CONTROL_UPSTREAM_CHECK=off\r\nPROXY_CONTROL_VERSION_HEALTH_TIMEOUT=420\nPROXY_CONTROL_EXTRA=kept\nPROXY_CONTROL_EXTRA=bad\nPROXY_CONTROL_COMPOSE_FILES=bad\nPROXY_CONTROL_COMPOSE_DIR=bad\nPROXY_CONTROL_VERSION_SOCKET=bad\nPROXY_CONTROL_VERSION_SOCKET_GID=bad\nPROXY_CONTROL_VERSION_CATALOG=/etc/proxy-control/operator-versions.json\nPROXY_CONTROL_VERSION_STATE=/var/lib/proxy-control/version-agent/operator/state.json\n").unwrap();
    for line in [
        "PROXY_CONTROL_UPSTREAM_CHECK=off\n",
        "PROXY_CONTROL_VERSION_HEALTH_TIMEOUT=420\n",
        "PROXY_CONTROL_EXTRA=kept\n",
        "PROXY_CONTROL_COMPOSE_DIR=/opt/mtproxy-shared443\n",
        "PROXY_CONTROL_VERSION_SOCKET=/run/proxy-control/version-agent.sock\n",
        "PROXY_CONTROL_VERSION_SOCKET_GID=10001\n",
        "PROXY_CONTROL_VERSION_CATALOG=/etc/proxy-control/operator-versions.json\n",
        "PROXY_CONTROL_VERSION_STATE=/var/lib/proxy-control/version-agent/operator/state.json\n",
    ] {
        assert!(text.contains(line));
    }
    assert_eq!(text.matches("PROXY_CONTROL_EXTRA=").count(), 1);
    assert!(!text.contains("=bad"));
}
#[test]
fn agent_engine_fresh_repair_and_uninstall_own_the_complete_tree() {
    let dir = TempDir::new("s");
    let runner = agent_runner(dir.path());
    let cx = context(dir.path(), runner.clone());
    let adapter: Arc<dyn Adapter> = Arc::new(VersionAgentAdapter::new(&cx));
    let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    let plan = plan_with(vec![action], Map::new());
    let _socket = socket(dir.path());
    let engine = engine_for(dir.path(), vec![adapter]);
    let state = engine.apply(&plan, &plan.digest()).unwrap();
    assert_eq!(state.status, Status::Active);
    let data = &state.checkpoints[0].data;
    for file in ["Cargo.toml", "src/main.rs", "bin/linux-amd64/proxy-control-version-agent"] {
        assert!(data["ownership"].get(format!("/opt/proxy-control/version_agent/{file}")).is_some());
    }
    assert_eq!(data["ownership"]["/etc/proxy-control/version-agent.env"]["mutable"], true);
    assert!(fs::read_to_string(dir.path().join("etc/systemd/system/version-agent.service"))
        .unwrap()
        .contains("ExecStart=/opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent"));
    put(
        dir.path(),
        "/etc/proxy-control/version-agent.env",
        "PROXY_CONTROL_UPSTREAM_CHECK=off\nPROXY_CONTROL_VERSION_HEALTH_TIMEOUT=333\n",
    );
    assert_eq!(engine.repair().unwrap().status, Status::Active);
    assert!(runner.argvs().iter().any(|a| a == &["systemctl", "restart", "version-agent"]));
    assert_eq!(engine.uninstall(false).unwrap().status, Status::Uninstalled);
    assert!(dir.path().join("var/lib/proxy-control/version-agent/state.json").exists());
    assert!(!dir.path().join("opt/proxy-control/version_agent").exists());
}
#[test]
fn agent_verify_reads_selected_state_and_still_rejects_version_drift() {
    let dir = TempDir::new("s");
    let agent = VersionAgentAdapter::new(&context(dir.path(), agent_runner(dir.path())));
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    agent.apply(&action, agent.prepare(&action).unwrap()).unwrap();
    let _socket = socket(dir.path());
    let mut state: Value = serde_json::from_slice(
        &fs::read(dir.path().join("var/lib/proxy-control/version-agent/state.json")).unwrap(),
    ).unwrap();
    state["components"]["telemt"]["version"] = json!("operator-current");
    let selected_state = "/var/lib/proxy-control/version-agent/operator state.json";
    put(dir.path(), selected_state, &state.to_string());
    put(dir.path(), "/etc/proxy-control/version-agent.env", &format!(
        "PROXY_CONTROL_VERSION_STATE=\"{selected_state}\"\nPROXY_CONTROL_COMPOSE_FILES=compose.yaml\nPROXY_CONTROL_XRAY_ROUTER=off\n",
    ));
    let components: Map<_, _> = state["components"].as_object().unwrap().iter()
        .map(|(name, value)| (name.clone(), json!({"current":value["version"]}))).collect();
    let response = json!({"enabled":true,"components":components}).to_string();
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        if call.argv.last().is_some_and(|arg| arg.ends_with("/v1/versions")) {
            return Some(Reply::ok(&response));
        }
        health_reply(call)
    }));
    let agent = VersionAgentAdapter::new(&context(dir.path(), runner));
    assert!(agent.verify(&action).unwrap().success);
    state["components"]["telemt"]["version"] = json!("unrecorded-running-version");
    put(dir.path(), selected_state, &state.to_string());
    assert!(agent.verify(&action).unwrap_err().message().contains("state does not record"));
}
#[test]
fn repair_migrates_pre40_python_checkpoint_and_removes_stale_python() {
    let dir = TempDir::new("s");
    let runner = agent_runner(dir.path());
    let agent = VersionAgentAdapter::new(&context(dir.path(), runner));
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    let mut data = agent.prepare(&action).unwrap();
    let marker = data["marker_value"].as_str().unwrap().to_owned();
    put(dir.path(), "/etc/proxy-control/version-agent-owned", &(marker + "\n"));
    put(dir.path(), "/opt/proxy-control/version_agent/server.py", "old python\n");
    put(dir.path(), "/opt/proxy-control/version_agent/__pycache__/server.pyc", "old bytecode");
    data.insert(
        "ownership".into(),
        json!({"/opt/proxy-control/version_agent/server.py":pc_host::fs::sha256_hex(b"old python\n")}),
    );
    let applied = agent.repair(&action, data).unwrap();
    assert!(!dir.path().join("opt/proxy-control/version_agent/server.py").exists());
    assert!(applied["ownership"]
        .get("/opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent")
        .is_some());
}
#[test]
fn agent_preflight_refuses_foreign_installation_and_unsafe_sources() {
    let dir = TempDir::new("s");
    let cx = context(dir.path(), agent_runner(dir.path()));
    let agent = VersionAgentAdapter::new(&cx);
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    put(dir.path(), "/etc/systemd/system/version-agent.service", "foreign");
    assert!(agent.prepare(&action).is_err());
    fs::remove_file(dir.path().join("etc/systemd/system/version-agent.service")).unwrap();
    let data = agent.prepare(&action).unwrap();
    symlink("/etc/passwd", cx.tree.join("version_agent/src/unsafe")).unwrap();
    assert!(agent.apply(&action, data).unwrap_err().message().contains("symlink"));
}
#[test]
fn agent_rejects_nonexecutable_binary_before_starting_service() {
    let dir = TempDir::new("s");
    let runner = agent_runner(dir.path());
    let cx = context(dir.path(), runner.clone());
    fs::set_permissions(
        cx.tree.join("version_agent/bin/linux-amd64/proxy-control-version-agent"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let agent = VersionAgentAdapter::new(&cx);
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    assert!(agent.apply(&action, agent.prepare(&action).unwrap()).is_err());
    assert!(!runner.argvs().iter().any(|a| a.iter().any(|v| v == "enable")));
}
#[test]
fn agent_preserves_catalog_state_and_rejects_foreign_tree_files() {
    let dir = TempDir::new("s");
    let agent = VersionAgentAdapter::new(&context(dir.path(), agent_runner(dir.path())));
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    put(dir.path(), "/etc/proxy-control/versions.json", "{\"operator\":true}");
    put(dir.path(), "/var/lib/proxy-control/version-agent/state.json", "{\"operator\":true}");
    let data = agent.apply(&action, agent.prepare(&action).unwrap()).unwrap();
    assert_eq!(fs::read_to_string(dir.path().join("etc/proxy-control/versions.json")).unwrap(), "{\"operator\":true}");
    put(dir.path(), "/opt/proxy-control/version_agent/foreign", "keep");
    assert!(agent.repair(&action, data.clone()).unwrap_err().message().contains("foreign file"));
    assert!(agent
        .rollback(&action, data, true, RollbackTarget::Uninstalled)
        .unwrap_err()
        .message()
        .contains("foreign file"));
}
#[test]
fn agent_verify_refuses_open_socket_wrong_versions_and_env_drift() {
    let dir = TempDir::new("s");
    let runner = agent_runner(dir.path());
    let agent = VersionAgentAdapter::new(&context(dir.path(), runner.clone()));
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    agent.apply(&action, agent.prepare(&action).unwrap()).unwrap();
    assert!(agent.verify(&action).unwrap_err().message().contains("socket"));
    let _socket = socket(dir.path());
    fs::set_permissions(dir.path().join("run/proxy-control/version-agent.sock"), fs::Permissions::from_mode(0o666))
        .unwrap();
    assert!(agent.verify(&action).is_err());
    fs::set_permissions(dir.path().join("run/proxy-control/version-agent.sock"), fs::Permissions::from_mode(0o660))
        .unwrap();
    put(dir.path(), "/etc/proxy-control/version-agent.env", "PROXY_CONTROL_COMPOSE_FILES=wrong\n");
    assert!(agent.verify(&action).unwrap_err().message().contains("as planned"));
}
#[test]
fn agent_checkpoint_validation_and_marker_drift_prevent_mutation() {
    let dir = TempDir::new("s");
    let runner = agent_runner(dir.path());
    let agent = VersionAgentAdapter::new(&context(dir.path(), runner.clone()));
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    let data = agent.prepare(&action).unwrap();
    for (key, value) in [("marker_value", json!("bad")), ("extra", json!(true)), ("owner", json!("foreign"))] {
        let mut bad = data.clone();
        bad.insert(key.into(), value);
        assert!(agent.apply(&action, bad).is_err());
    }
    put(dir.path(), "/etc/proxy-control/version-agent-owned", &"0".repeat(32));
    assert!(agent.apply(&action, data).is_err());
    assert!(runner.calls().is_empty());
}
#[test]
fn agent_purge_removes_only_owned_code_and_persistent_data() {
    let dir = TempDir::new("s");
    let agent = VersionAgentAdapter::new(&context(dir.path(), agent_runner(dir.path())));
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    let data = agent.apply(&action, agent.prepare(&action).unwrap()).unwrap();
    put(dir.path(), "/etc/proxy-control/unrelated", "keep");
    agent.rollback(&action, data, true, RollbackTarget::Uninstalled).unwrap();
    assert!(!dir.path().join("var/lib/proxy-control/version-agent").exists());
    assert!(dir.path().join("etc/proxy-control/unrelated").exists());
}
#[test]
fn mcp_engine_installs_repairs_and_uninstalls_without_python_or_secret_journal() {
    let dir = TempDir::new("s");
    let runner = mcp_runner();
    let cx = context(dir.path(), runner.clone());
    let adapter: Arc<dyn Adapter> = Arc::new(McpAdapter::new(&cx));
    let action = mcp_action();
    let plan = plan_with(vec![action], Map::new());
    put(dir.path(), "/opt/mtproxy-shared443/.env.naive", "NAIVE=yes\n");
    put(dir.path(), "/opt/mtproxy-shared443/version-overrides/compose.versions.yaml", "services:\n");
    let engine = engine_for(dir.path(), vec![adapter]);
    let state = engine.apply(&plan, &plan.digest()).unwrap();
    assert_eq!(state.status, Status::Active);
    let token = fs::read_to_string(dir.path().join("opt/mtproxy-shared443/secrets/mcp-token")).unwrap();
    let key = fs::read_to_string(dir.path().join("opt/mtproxy-shared443/secrets/mcp-panel-key")).unwrap();
    let journal = serde_json::to_string(&state.checkpoints[0].data).unwrap();
    assert!(!journal.contains(token.trim()) && !journal.contains(key.trim()));
    assert_eq!(engine.repair().unwrap().status, Status::Active);
    assert_eq!(fs::read_to_string(dir.path().join("opt/mtproxy-shared443/secrets/mcp-token")).unwrap(), token);
    let calls = runner.argvs();
    let create = calls.iter().find(|a| a.iter().any(|v| v == "api-key-create")).unwrap();
    assert!(create.windows(2).any(|w| w == ["/usr/local/bin/panel", "cli"]));
    assert!(!create.iter().any(|v| v.contains("python")));
    assert!(create.iter().any(|v| v.ends_with("version-overrides/compose.versions.yaml")));
    assert_eq!(calls.iter().filter(|a| a.iter().any(|v| v == "api-key-create")).count(), 1);
    assert_eq!(engine.uninstall(false).unwrap().status, Status::Uninstalled);
    assert!(!dir.path().join("opt/mtproxy-shared443/secrets/mcp-token").exists());
    assert!(dir.path().join("opt/mtproxy-shared443/.env.naive").exists());
}
#[test]
fn mcp_foreign_secrets_and_tampered_actions_are_refused() {
    let dir = TempDir::new("s");
    let runner = mcp_runner();
    let adapter = McpAdapter::new(&context(dir.path(), runner.clone()));
    let action = mcp_action();
    put(dir.path(), "/opt/mtproxy-shared443/secrets/mcp-foreign", "keep");
    assert!(adapter.prepare(&action).is_err());
    for mutation in ["port=1", "domain=bad", "compose-files=compose.yaml:../evil.yaml", "domain=panel.example.com"] {
        let mut bad = action.clone();
        let key = mutation.split_once('=').unwrap().0;
        bad.mutations.retain(|v| !v.starts_with(&format!("{key}=")));
        bad.mutations.push(mutation.into());
        assert!(adapter.prepare(&bad).is_err());
    }
    assert!(runner.calls().is_empty());
}
#[test]
fn mcp_failing_key_issue_rolls_back_partial_install_and_keeps_secret_out_of_error() {
    for output in ["exit=1 sensitive-secret", "not JSON", "{\"name\":\"mcp\"}"] {
        let dir = TempDir::new("s");
        let output = output.to_owned();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            call.argv.iter().any(|v| v == "api-key-create").then(|| Reply::ok(&output))
        }));
        let adapter: Arc<dyn Adapter> = Arc::new(McpAdapter::new(&context(dir.path(), runner)));
        let plan = plan_with(vec![mcp_action()], Map::new());
        let engine = engine_for(dir.path(), vec![adapter]);
        let error = engine.apply(&plan, &plan.digest()).unwrap_err();
        assert!(!error.message().contains("sensitive-secret"));
        assert_eq!(engine.store().read_state().unwrap().status, Status::RolledBack);
        assert!(!dir.path().join("etc/proxy-control/mcp-owned").exists());
    }
}
#[test]
fn mcp_verify_checks_health_anonymous_and_authenticated_statuses() {
    for (health, anonymous, authenticated) in
        [("unhealthy", "401", "200"), ("healthy", "200", "200"), ("healthy", "401", "403")]
    {
        let dir = TempDir::new("s");
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            if call.argv.iter().any(|v| v == "api-key-create") {
                return Some(Reply::ok("{\"plaintext\":\"key\"}"));
            }
            if call.argv.last().is_some_and(|v| v == "proxy-control-mcp") {
                return Some(Reply::ok(health));
            }
            if call.argv.first().is_some_and(|v| v == "curl") {
                return Some(Reply::ok(if call.argv.iter().any(|v| v == "POST") { authenticated } else { anonymous }));
            }
            None
        }));
        let adapter = McpAdapter::new(&context(dir.path(), runner));
        let action = mcp_action();
        adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
        assert!(adapter.verify(&action).is_err());
    }
}
#[test]
fn mcp_handoff_is_private_and_secret_permissions_are_0440() {
    let dir = TempDir::new("s");
    let cx = context(dir.path(), mcp_runner());
    let adapter = McpAdapter::new(&cx);
    let action = mcp_action();
    adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
    let mut cfg = config();
    assert!(super::mcp_handoff(&cx, &cfg).unwrap().is_empty());
    cfg.domains.mcp = Some("mcp.example.com".into());
    let handoff = super::mcp_handoff(&cx, &cfg).unwrap();
    assert_eq!(handoff["mcp_url"], "https://mcp.example.com/mcp");
    assert_eq!(handoff["mcp_token"], adapter.read_token().unwrap());
    for path in ["mcp-token", "mcp-panel-key"] {
        assert_eq!(
            fs::metadata(dir.path().join("opt/mtproxy-shared443/secrets").join(path)).unwrap().permissions().mode()
                & 0o777,
            0o440
        );
    }
}
#[test]
fn warp_distinct_egress_validation() {
    assert!(WarpAdapter::validate_egress("ip=192.0.2.1\n", "ip=192.0.2.2\nwarp=plus\n").is_ok());
    for (a, b) in
        [("ip=192.0.2.1", "ip=192.0.2.1\nwarp=on"), ("ip=bad", "ip=192.0.2.2\nwarp=on"), ("ip=::1", "ip=::2\nwarp=off")]
    {
        assert!(WarpAdapter::validate_egress(a, b).is_err());
    }
}
#[test]
fn warp_repair_and_rollback_keep_marker_until_purge_finishes() {
    let dir = TempDir::new("s");
    let installed = Arc::new(Mutex::new(true));
    let runner = warp_runner(installed);
    let adapter = WarpAdapter::new(&context(dir.path(), runner.clone()));
    let action = warp_action();
    let data = seed_warp(dir.path(), &action);
    let data = adapter.repair(&action, data).unwrap();
    adapter.verify(&action).unwrap();
    adapter.rollback(&action, data, false, RollbackTarget::Uninstalled).unwrap();
    assert!(!dir.path().join("var/lib/proxy-control/warp").exists());
    let args = runner.argvs();
    let proxied = args.iter().find(|a| a.iter().any(|v| v == "--socks5-hostname")).unwrap();
    assert!(proxied.windows(2).any(|w| w == ["--noproxy", ""]));
    assert!(runner
        .calls()
        .iter()
        .filter(|c| c.argv.first().is_some_and(|a| a == "warp-cli"))
        .all(|c| c.timeout.as_secs() <= 5));
}
#[test]
fn warp_pending_owner_prefix_is_resumable_and_foreign_pending_is_refused() {
    let dir = TempDir::new("s");
    let runner = warp_runner(Arc::new(Mutex::new(false)));
    let adapter = WarpAdapter::new(&context(dir.path(), runner));
    let action = warp_action();
    let data = adapter.prepare(&action).unwrap();
    let nonce = data["marker"].as_str().unwrap();
    let path = format!("/var/lib/proxy-control/warp/.owner.{nonce}.tmp");
    put(dir.path(), &path, &nonce[..12]);
    adapter.reconcile_rollback(&action, data.clone(), true, RollbackTarget::RolledBack).unwrap();
    assert!(!dir.path().join("var/lib/proxy-control/warp").exists());
    put(dir.path(), &path, "foreign");
    assert!(adapter.reconcile_rollback(&action, data, true, RollbackTarget::RolledBack).is_err());
}
#[test]
fn warp_drift_is_checked_before_any_mutation() {
    for target in ["/var/lib/proxy-control/warp/owner", "/etc/apt/sources.list.d/proxy-control-warp.list"] {
        let dir = TempDir::new("s");
        let runner = warp_runner(Arc::new(Mutex::new(true)));
        let adapter = WarpAdapter::new(&context(dir.path(), runner.clone()));
        let action = warp_action();
        let data = seed_warp(dir.path(), &action);
        put(dir.path(), target, "foreign");
        assert!(adapter.repair(&action, data.clone()).is_err());
        assert!(adapter.rollback(&action, data, false, RollbackTarget::Uninstalled).is_err());
        assert!(runner.calls().is_empty());
    }
}
#[test]
fn warp_failed_download_cleans_private_stage_and_never_truncates_links() {
    let dir = TempDir::new("s");
    let runner = Arc::new(RecordingRunner::with_responder(|call| {
        if call.argv.first().is_some_and(|v| v == "dpkg-query") {
            return Some(Reply::exit(1, "", ""));
        }
        if let Some(index) = call.argv.iter().position(|v| v == "--output") {
            fs::write(&call.argv[index + 1], "not the pinned key").unwrap();
        }
        None
    }));
    let adapter = WarpAdapter::new(&context(dir.path(), runner));
    let action = warp_action();
    let data = adapter.prepare(&action).unwrap();
    assert!(adapter.apply(&action, data.clone()).unwrap_err().message().contains("digest mismatch"));
    let children: Vec<_> =
        fs::read_dir(dir.path().join("var/lib/proxy-control/warp")).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(children, ["owner"]);
    adapter.reconcile_rollback(&action, data, true, RollbackTarget::RolledBack).unwrap();
    for hardlink in [true, false] {
        let dir = TempDir::new("s");
        let adapter = WarpAdapter::new(&context(dir.path(), warp_runner(Arc::new(Mutex::new(false)))));
        let action = warp_action();
        let data = adapter.prepare(&action).unwrap();
        let pending =
            dir.path().join(format!("var/lib/proxy-control/warp/.owner.{}.tmp", data["marker"].as_str().unwrap()));
        fs::create_dir_all(pending.parent().unwrap()).unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "do not truncate").unwrap();
        if hardlink {
            fs::hard_link(&victim, &pending).unwrap();
        } else {
            symlink(&victim, &pending).unwrap();
        }
        assert!(adapter.apply(&action, data).is_err());
        assert_eq!(fs::read_to_string(victim).unwrap(), "do not truncate");
    }
}
#[test]
fn warp_foreign_state_after_prepare_is_refused() {
    for target in [
        "/var/lib/cloudflare-warp/state",
        "/usr/share/keyrings/proxy-control-warp.asc",
        "/etc/apt/sources.list.d/proxy-control-warp.list",
    ] {
        let dir = TempDir::new("s");
        let adapter = WarpAdapter::new(&context(dir.path(), warp_runner(Arc::new(Mutex::new(false)))));
        let action = warp_action();
        let data = adapter.prepare(&action).unwrap();
        put(dir.path(), target, "foreign");
        assert!(adapter.apply(&action, data).is_err());
        assert!(!dir.path().join("var/lib/proxy-control/warp/owner").exists());
    }
}

fn delegated_warp_reply(base: &RecordingRunner, call: &Call) -> Option<Reply> {
    use pc_host::runner::HostRunner;
    let argv: Vec<_> = call.argv.iter().map(String::as_str).collect();
    let output = base.bounded(&argv, pc_host::runner::Bounded::WARP).unwrap();
    Some(Reply::exit(output.returncode, &output.stdout, &output.stderr))
}
#[test]
fn warp_engine_resumes_failed_purge_without_losing_ownership_proof() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = TempDir::new("s");
    let base = warp_runner(Arc::new(Mutex::new(true)));
    let fail = Arc::new(AtomicBool::new(true));
    let flag = fail.clone();
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        if call.argv == ["apt-get", "purge", "--yes", "cloudflare-warp"] && flag.swap(false, Ordering::SeqCst) {
            Some(Reply::exit(1, "", "purge failed"))
        } else {
            delegated_warp_reply(&base, call)
        }
    }));
    let adapter: Arc<dyn Adapter> = Arc::new(WarpAdapter::new(&context(dir.path(), runner)));
    let action = warp_action();
    let data = seed_warp(dir.path(), &action);
    let plan = plan_with(vec![action.clone()], Map::new());
    let engine = engine_for(dir.path(), vec![adapter]);
    engine.store().write_plan(&plan).unwrap();
    engine.store().write_ownership(&Default::default()).unwrap();
    let mut state = crate::journal::TransactionState::new(&pc_host::fs::uuid4_hex(), Status::Applying, &plan.digest());
    state.checkpoints.push(crate::journal::Checkpoint::new(&action.id, &action.adapter, Phase::Applying, data));
    engine.store().write_state(&state).unwrap();
    assert_eq!(engine.resume().unwrap().status, Status::Active);
    assert!(engine.uninstall(false).is_err());
    assert!(dir.path().join("var/lib/proxy-control/warp/owner").exists());
    assert_eq!(engine.resume().unwrap().status, Status::Uninstalled);
    assert!(!dir.path().join("var/lib/proxy-control/warp").exists());
}
#[test]
fn warp_resume_completes_only_its_unpacked_package() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = TempDir::new("s");
    let base = warp_runner(Arc::new(Mutex::new(true)));
    let configured = Arc::new(AtomicBool::new(false));
    let flag = configured.clone();
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        if call.argv == ["dpkg-query", "-W", "-f=${db:Status-Status}", "cloudflare-warp"]
            && !flag.load(Ordering::SeqCst)
        {
            return Some(Reply::ok("unpacked"));
        }
        if call.argv == ["dpkg", "--configure", "cloudflare-warp"] {
            flag.store(true, Ordering::SeqCst);
        }
        delegated_warp_reply(&base, call)
    }));
    let adapter = WarpAdapter::new(&context(dir.path(), runner.clone()));
    let action = warp_action();
    adapter.reconcile_apply(&action, seed_warp(dir.path(), &action)).unwrap();
    assert!(configured.load(Ordering::SeqCst));
    assert!(runner.argvs().iter().any(|a| a == &["dpkg", "--configure", "cloudflare-warp"]));
    assert!(!runner.argvs().iter().any(|a| a.iter().any(|v| v == "-a")));
}
#[test]
fn warp_verify_rejects_public_foreign_and_unidentified_listeners() {
    for row in [
        "LISTEN 0 128 0.0.0.0:40000 0.0.0.0:* users:((\"warp-svc\",pid=1,fd=3))",
        "LISTEN 0 128 127.0.0.1:40000 0.0.0.0:* users:((\"other\",pid=1,fd=3))",
        "LISTEN 0 128 127.0.0.1:40000 0.0.0.0:*",
    ] {
        let dir = TempDir::new("s");
        let base = warp_runner(Arc::new(Mutex::new(true)));
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            if call.argv == ["ss", "-H", "-ltnp"] {
                Some(Reply::ok(row))
            } else {
                delegated_warp_reply(&base, call)
            }
        }));
        let adapter = WarpAdapter::new(&context(dir.path(), runner));
        assert!(adapter.verify(&warp_action()).is_err());
    }
}
#[test]
fn service_adapters_resume_python_written_applying_checkpoints() {
    let dir = TempDir::new("s");
    let runner = mcp_runner();
    let adapter: Arc<dyn Adapter> = Arc::new(McpAdapter::new(&context(dir.path(), runner)));
    let action = mcp_action();
    let plan = plan_with(vec![action.clone()], Map::new());
    let engine = engine_for(dir.path(), vec![adapter.clone()]);
    engine.store().initialize().unwrap();
    engine.store().write_plan(&plan).unwrap();
    engine.store().write_ownership(&Default::default()).unwrap();
    let mut state = crate::journal::TransactionState::new(&pc_host::fs::uuid4_hex(), Status::Applying, &plan.digest());
    let python: Value =
        serde_json::from_slice(&fs::read(golden("installs/kitchen-sink/journal/state.json")).unwrap()).unwrap();
    let mut data = python["checkpoints"].as_array().unwrap().iter().find(|c| c["adapter"] == "mcp").unwrap()["data"]
        .as_object()
        .unwrap()
        .clone();
    data.insert("ownership".into(), json!({}));
    state.checkpoints.push(crate::journal::Checkpoint::new(&action.id, &action.adapter, Phase::Applying, data));
    engine.store().write_state(&state).unwrap();
    assert_eq!(engine.resume().unwrap().status, Status::Active);
    assert_eq!(engine.repair().unwrap().status, Status::Active);
}

#[test]
fn agent_verify_refuses_wrong_current_missing_component_dead_unit_and_bad_health() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = TempDir::new("s");
    let mode = Arc::new(AtomicUsize::new(0));
    let flag = mode.clone();
    let root = dir.path().to_owned();
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        let mode = flag.load(Ordering::SeqCst);
        if call.argv == ["systemctl", "is-active", "version-agent"] && mode == 1 {
            return Some(Reply::ok("inactive"));
        }
        if call.argv == ["systemctl", "is-enabled", "version-agent"] && mode == 2 {
            return Some(Reply::ok("disabled"));
        }
        if call.argv.last().is_some_and(|v| v.ends_with("/v1/health")) {
            return Some(Reply::ok(match mode {
                3 => "{\"status\":\"error\"}",
                7 => "bad JSON",
                _ => "{\"status\":\"ok\"}",
            }));
        }
        if call.argv.last().is_some_and(|v| v.ends_with("/v1/versions")) {
            let state: Value =
                serde_json::from_slice(&fs::read(root.join("var/lib/proxy-control/version-agent/state.json")).unwrap())
                    .unwrap();
            let components: Map<_, _> = state["components"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), json!({"current":v["version"]})))
                .collect();
            let mut response = json!({"enabled":true,"components":components});
            match mode {
                4 => response["enabled"] = json!(false),
                5 => response["components"] = json!({}),
                6 => response["components"]["telemt"]["current"] = json!("wrong"),
                8 => response["padding"] = json!("x".repeat(10000)),
                _ => (),
            }
            return Some(Reply::ok(&response.to_string()));
        }
        health_reply(call)
    }));
    let agent = VersionAgentAdapter::new(&context(dir.path(), runner.clone()));
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    agent.apply(&action, agent.prepare(&action).unwrap()).unwrap();
    let _socket = socket(dir.path());
    for bad in 1..=7 {
        mode.store(bad, Ordering::SeqCst);
        assert!(agent.verify(&action).is_err(), "mode {bad}");
    }
    mode.store(8, Ordering::SeqCst);
    assert!(agent.verify(&action).unwrap().success);
    assert!(runner
        .calls()
        .iter()
        .filter(|c| c.argv.last().is_some_and(|v| v.ends_with("/v1/versions")))
        .all(|c| c.max_output == Some(1_048_576)));
}

#[test]
fn warp_engine_recovers_sigkill_before_owner_replace() {
    use std::os::unix::process::ExitStatusExt;
    for finish_install in [true, false] {
        let dir = TempDir::new("s");
        let root = dir.path().to_owned();
        let package = Arc::new(Mutex::new(true));
        let installed = package.clone();
        let base = warp_runner(package);
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            let owner = root.join("var/lib/proxy-control/warp/owner").exists();
            if call.argv.first().is_some_and(|a| a == "dpkg-query") && (!owner || !*installed.lock().unwrap()) {
                return Some(Reply::exit(1, "", ""));
            }
            if call.argv == ["ss", "-H", "-ltnp"] && !owner {
                return Some(Reply::ok(""));
            }
            delegated_warp_reply(&base, call)
        }));
        let adapter: Arc<dyn Adapter> = Arc::new(WarpAdapter::new(&context(dir.path(), runner)));
        let action = warp_action();
        let data = adapter.prepare(&action).unwrap();
        let nonce = data["marker"].as_str().unwrap();
        let pending = dir.path().join(format!("var/lib/proxy-control/warp/.owner.{nonce}.tmp"));
        fs::create_dir_all(pending.parent().unwrap()).unwrap();
        let exit = std::process::Command::new("/bin/sh")
            .args(["-c", "umask 077; printf '%s' \"$1\" > \"$2\"; kill -KILL $$", "pending-owner"])
            .arg(&nonce[..12])
            .arg(&pending)
            .status()
            .unwrap();
        assert_eq!(exit.signal(), Some(9));
        let plan = plan_with(vec![action.clone()], Map::new());
        let engine = engine_for(dir.path(), vec![adapter]);
        engine.store().write_plan(&plan).unwrap();
        engine.store().write_ownership(&Default::default()).unwrap();
        let mut state = crate::journal::TransactionState::new(
            &pc_host::fs::uuid4_hex(),
            if finish_install { Status::Applying } else { Status::RollingBack },
            &plan.digest(),
        );
        if !finish_install {
            state.rollback_target = Some(RollbackTarget::RolledBack);
            state.purge_data = Some(true);
        }
        state.checkpoints.push(crate::journal::Checkpoint::new(&action.id, &action.adapter, Phase::Applying, data));
        engine.store().write_state(&state).unwrap();
        assert_eq!(engine.resume().unwrap().status, if finish_install { Status::Active } else { Status::RolledBack });
        assert!(!pending.exists());
    }
}

#[test]
fn agent_seed_records_full_profile_binaries_and_runtime_pin() {
    let dir = TempDir::new("s");
    let agent = VersionAgentAdapter::new(&context(dir.path(), agent_runner(dir.path())));
    let action = action_from_golden("version_agent", "kitchen-sink");
    for path in [
        "/usr/local/bin/caddy",
        "/usr/bin/mita",
        "/usr/local/lib/proxy-control/xray-router/xray",
        "/usr/local/lib/proxy-control/xray-router/geoip.dat",
        "/usr/local/lib/proxy-control/xray-router/geosite.dat",
    ] {
        put(dir.path(), path, "installed payload");
    }
    put(dir.path(), "/etc/proxy-control/caddy-naive.pin", "v2.11.7 operator-pin\n");
    agent.apply(&action, agent.prepare(&action).unwrap()).unwrap();
    let _socket = socket(dir.path());
    assert!(agent.verify(&action).unwrap().success);
    let state: Value =
        serde_json::from_slice(&fs::read(dir.path().join("var/lib/proxy-control/version-agent/state.json")).unwrap())
            .unwrap();
    let components = state["components"].as_object().unwrap();
    assert_eq!(components.len(), 4);
    assert_eq!(components["naive"]["runtime_version"], "v2.11.7 operator-pin");
    assert_eq!(components["mita"]["version"], "3.38.1");
    let manifest = pc_host::archive::ReleaseManifest::from_bytes(
        &fs::read(repository().join("release/external-artifacts.json")).unwrap(),
    )
    .unwrap();
    let pin = manifest.external_artifact("xray", "amd64").unwrap();
    assert_eq!(components["xray"]["version"], pin.version);
    assert_eq!(components["xray"]["sha256"], pin.sha256);
    assert_eq!(components["xray"]["members"].as_object().unwrap().len(), 3);
    for name in ["xray", "geoip.dat", "geosite.dat"] {
        let installed = dir.path().join("usr/local/lib/proxy-control/xray-router").join(name);
        assert_eq!(components["xray"]["members"][name], pc_host::fs::sha256_file(&installed).unwrap());
    }

    // A repair must not replace an upstream/operator-selected runtime with the release default.
    let mut updated = state;
    updated["components"]["xray"]["version"] = json!("99.12.31");
    updated["components"]["xray"]["sha256"] = json!("f".repeat(64));
    updated["components"]["xray"]["source"] = json!("upstream");
    let state_path = dir.path().join("var/lib/proxy-control/version-agent/state.json");
    let updated = serde_json::to_vec(&updated).unwrap();
    fs::write(&state_path, &updated).unwrap();
    agent.repair(&action, agent.prepare(&action).unwrap()).unwrap();
    assert!(agent.verify(&action).unwrap().success);
    assert_eq!(fs::read(state_path).unwrap(), updated);
}

#[test]
fn agent_seed_refuses_an_unvalidated_xray_manifest() {
    for duplicate_key in [false, true] {
        let dir = TempDir::new("s");
        let context = context(dir.path(), agent_runner(dir.path()));
        let manifest_path = context.tree.join("release/external-artifacts.json");
        let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let xray = manifest["artifacts"].as_array_mut().unwrap().iter_mut().find(|v| v["name"] == "xray").unwrap();
        xray["platforms"]["amd64"]["sha256"] = json!("invalid");
        let invalid = if duplicate_key {
            fs::read_to_string(repository().join("release/external-artifacts.json"))
                .unwrap()
                .replacen("\"schema_version\": 1,", "\"schema_version\": 1, \"schema_version\": 1,", 1)
        } else {
            manifest.to_string()
        };
        fs::write(manifest_path, invalid).unwrap();
        for path in [
            "/usr/local/bin/caddy",
            "/usr/bin/mita",
            "/usr/local/lib/proxy-control/xray-router/xray",
            "/usr/local/lib/proxy-control/xray-router/geoip.dat",
            "/usr/local/lib/proxy-control/xray-router/geosite.dat",
        ] {
            put(dir.path(), path, "installed payload");
        }
        let agent = VersionAgentAdapter::new(&context);
        let action = action_from_golden("version_agent", "kitchen-sink");
        let error = agent.apply(&action, agent.prepare(&action).unwrap()).unwrap_err();
        assert!(error.message().contains("release manifest is invalid"), "{error}");
        assert!(!dir.path().join("var/lib/proxy-control/version-agent/state.json").exists());
    }
}
#[test]
fn missing_profile_binary_has_the_python_adapter_error_class() {
    let dir = TempDir::new("s");
    let agent = VersionAgentAdapter::new(&context(dir.path(), agent_runner(dir.path())));
    let action = action_from_golden("version_agent", "direct");
    let error = agent.apply(&action, agent.prepare(&action).unwrap()).unwrap_err();
    assert_eq!(error.python_class_name(), "VersionAgentError");
    assert!(error.message().contains("installed caddy is missing"));
}

/// Runs on ams-test in `unshare --mount --propagation private`, with tmpfs covering
/// `/etc`, `/var/lib` and `/run`. systemctl/tmpfiles/docker are executable stand-ins;
/// curl and both Rust binaries are real fresh processes.
#[test]
#[ignore = "requires built installer/agent binaries; run separately with --ignored --test-threads=1"]
fn isolated_real_agent_engine_and_cli_fresh_repair_resume_smoke() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    let mounts = fs::read_to_string("/proc/self/mountinfo").expect("Linux mount namespace");
    for path in ["/etc", "/var/lib", "/run"] {
        assert!(
            mounts.lines().any(|line| line.split_whitespace().nth(4) == Some(path)
                && line.split(" - ").nth(1).is_some_and(|value| value.starts_with("tmpfs "))),
            "smoke requires a private tmpfs over {path}"
        );
    }
    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    struct PathEnv(Option<std::ffi::OsString>);
    impl Drop for PathEnv {
        fn drop(&mut self) {
            if let Some(path) = &self.0 {
                std::env::set_var("PATH", path);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }
    let real_agent = PathBuf::from(std::env::var_os("PC_SERVICES_SMOKE_AGENT").expect("PC_SERVICES_SMOKE_AGENT"));
    let real_installer =
        PathBuf::from(std::env::var_os("PC_SERVICES_SMOKE_INSTALLER").expect("PC_SERVICES_SMOKE_INSTALLER"));
    let dir = TempDir::new("s");
    let tree = source(dir.path());
    let root = dir.path();
    fs::copy(&real_agent, tree.join("version_agent/bin/linux-amd64/proxy-control-version-agent")).unwrap();
    let release_installer = tree.join("installer/bin/linux-amd64/proxy-control-installer");
    fs::create_dir_all(release_installer.parent().unwrap()).unwrap();
    fs::copy(&real_installer, &release_installer).unwrap();
    put(root, "opt/mtproxy-shared443/compose.yaml", &fs::read_to_string(repository().join("compose.yaml")).unwrap());
    put(root, "opt/mtproxy-shared443/VERSION", include_str!("../../../VERSION"));
    let shim = root.join("commands");
    fs::create_dir(&shim).unwrap();
    put(
        root,
        "commands/systemctl",
        "#!/bin/sh\ncase \"$1\" in is-active) echo active;; is-enabled) echo enabled;; esac\nexit 0\n",
    );
    put(root, "commands/systemd-tmpfiles", "#!/bin/sh\nexit 0\n");
    put(root, "commands/docker", "#!/bin/sh\nexit 0\n");
    put(root,"commands/curl",&format!("#!/bin/bash\nargs=()\nfor arg in \"$@\"; do\n if [[ \"$arg\" == /run/proxy-control/version-agent.sock ]]; then args+=(\"{}/run/proxy-control/version-agent.sock\"); else args+=(\"$arg\"); fi\ndone\nexec /usr/bin/curl \"${{args[@]}}\"\n",root.display()));
    for entry in fs::read_dir(&shim).unwrap() {
        fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let _path = PathEnv(std::env::var_os("PATH"));
    std::env::set_var("PATH", format!("{}:{}", shim.display(), std::env::var("PATH").unwrap_or_default()));
    fs::create_dir_all(root.join("run/proxy-control")).unwrap();
    let start = |binary: &Path| {
        let child = Command::new("/bin/bash")
            .args([
                "-c",
                "until test -f \"$PROXY_CONTROL_VERSION_STATE\"; do sleep 0.05; done; set -a; source \"$2/etc/proxy-control/version-agent.env\"; set +a; export PROXY_CONTROL_COMPOSE_DIR=\"$2/opt/mtproxy-shared443\" PROXY_CONTROL_VERSION_SOCKET=\"$2/run/proxy-control/version-agent.sock\" PROXY_CONTROL_VERSION_CATALOG=\"$2$PROXY_CONTROL_VERSION_CATALOG\" PROXY_CONTROL_VERSION_STATE=\"$2$PROXY_CONTROL_VERSION_STATE\" PROXY_CONTROL_UPSTREAM_CHECK=off PROXY_CONTROL_UPSTREAM_CHECK_INTERVAL=0; exec \"$1\"",
                "agent-start",
            ])
            .arg(binary)
            .arg(root)
            .env("PROXY_CONTROL_COMPOSE_DIR", root.join("opt/mtproxy-shared443"))
            .env("PROXY_CONTROL_COMPOSE_FILES", "compose.yaml")
            .env("PROXY_CONTROL_VERSION_SOCKET", root.join("run/proxy-control/version-agent.sock"))
            .env("PROXY_CONTROL_VERSION_SOCKET_GID", "10001")
            .env("PROXY_CONTROL_VERSION_CATALOG", root.join("etc/proxy-control/versions.json"))
            .env("PROXY_CONTROL_VERSION_STATE", root.join("var/lib/proxy-control/version-agent/state.json"))
            .env("PROXY_CONTROL_UPSTREAM_CHECK", "off")
            .env("PROXY_CONTROL_UPSTREAM_CHECK_INTERVAL", "0")
            .env("PROXY_CONTROL_AGENT_DIR", root.join("opt/proxy-control"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Process(child)
    };
    // Catalog/state are seeded by the adapter. The real daemon must see the seeded state,
    // so its initial launch waits for files before applying through the engine.
    let cx = AdapterContext { root: root.into(), tree: tree.clone(), runner: Arc::new(pc_host::runner::SystemRunner) };
    let agent: Arc<dyn Adapter> = Arc::new(VersionAgentAdapter::new(&cx));
    let action = agent.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    let plan = plan_with(vec![action.clone()], Map::new());
    let mut daemon = start(&real_agent);
    let engine = engine_for(root, vec![agent]);
    assert_eq!(engine.apply(&plan, &plan.digest()).unwrap().status, Status::Active);
    // Restart from the installed ExecStart binary, not the build output or the release copy.
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    let installed = root.join("opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent");
    daemon = start(&installed);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = Command::new("/usr/bin/curl")
            .args(["--fail", "--silent", "--unix-socket"])
            .arg(root.join("run/proxy-control/version-agent.sock"))
            .arg("http://version-agent/v1/health")
            .output()
            .unwrap();
        if out.status.success() {
            let value: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(value["implementation"], "rust");
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(50));
    }
    // Both paths are inside the shipped unit's existing ReadWritePaths. Distinct
    // defaults expose a silent switch even when both agent generations are healthy.
    let default_state = root.join("var/lib/proxy-control/version-agent/state.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&default_state).unwrap()).unwrap();
    state["components"]["telemt"]["version"] = json!("operator-current");
    put(root, "var/lib/proxy-control/version-agent/operator/state.json", &state.to_string());
    state["components"]["telemt"]["version"] = json!("default-current");
    fs::write(&default_state, state.to_string()).unwrap();
    for (path, version) in [
        ("etc/proxy-control/operator-versions.json", "operator-approved"),
        ("etc/proxy-control/versions.json", "default-approved"),
    ] {
        put(root, path, &json!({"schema":1,"components":{"telemt":[{
            "version":version,"kind":"image","image":format!("example/telemt@sha256:{}", "a".repeat(64))
        }]}}).to_string());
    }
    put(
        root,
        "etc/proxy-control/version-agent.env",
        &format!("PROXY_CONTROL_UPSTREAM_CHECK=off\nPROXY_CONTROL_VERSION_HEALTH_TIMEOUT=321\nPROXY_CONTROL_COMPOSE_DIR={}/opt/mtproxy-shared443\nPROXY_CONTROL_COMPOSE_FILES=compose.yaml\nPROXY_CONTROL_VERSION_CATALOG=/etc/proxy-control/operator-versions.json\nPROXY_CONTROL_VERSION_STATE=/var/lib/proxy-control/version-agent/operator/state.json\n",root.display()),
    );
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    daemon = start(&installed);
    let versions = || {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let out = Command::new("/usr/bin/curl")
                .args(["--fail", "--silent", "--unix-socket"])
                .arg(root.join("run/proxy-control/version-agent.sock"))
                .arg("http://version-agent/v1/versions")
                .output()
                .unwrap();
            if out.status.success() {
                return serde_json::from_slice::<Value>(&out.stdout).unwrap();
            }
            assert!(Instant::now() < deadline, "installed agent did not return after restart");
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let assert_operator_files = |value: Value| {
        assert_eq!(value["components"]["telemt"]["current"], "operator-current");
        assert_eq!(value["components"]["telemt"]["available"][0]["version"], "operator-approved");
    };
    assert_operator_files(versions());
    // Exercise update-host's actual final whole-engine repair, not only env rendering.
    // The panel already has this release; Docker is the external boundary, while
    // migrate-agent, health, persisted journal and the installed daemon are real.
    put(root, "commands/docker", &format!(
        "#!/bin/sh\ncase \"$*\" in\n'inspect --format {{{{index .Config.Labels \"com.docker.compose.project\"}}}} proxy-control-panel') echo proxy_panel_by_dubr1k;;\n'exec proxy-control-panel cat /app/VERSION') echo {};;\nesac\n",
        include_str!("../../../VERSION").trim()
    ));
    fs::set_permissions(shim.join("docker"), fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(&release_installer)
        .arg("--root").arg(root).arg("--source").arg(&tree)
        .args(["update-host", "--version", include_str!("../../../VERSION").trim(), "--sha256", &"a".repeat(64)])
        .output().unwrap();
    assert!(output.status.success(), "update-host: {}", String::from_utf8_lossy(&output.stderr));
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    daemon = start(&installed);
    assert_operator_files(versions());
    // A subsequent operator edit may use systemd quoting without changing the files.
    let env_path = root.join("etc/proxy-control/version-agent.env");
    let quoted = fs::read_to_string(&env_path).unwrap()
        .replace(
            "PROXY_CONTROL_VERSION_CATALOG=/etc/proxy-control/operator-versions.json",
            "PROXY_CONTROL_VERSION_CATALOG=\"/etc/proxy-control/operator-versions.json\"",
        )
        .replace(
            "PROXY_CONTROL_VERSION_STATE=/var/lib/proxy-control/version-agent/operator/state.json",
            "PROXY_CONTROL_VERSION_STATE='/var/lib/proxy-control/version-agent/operator/state.json'",
        );
    fs::write(env_path, quoted).unwrap();
    let mut interrupted = engine.store().read_state().unwrap();
    interrupted.status = Status::Applying;
    interrupted.checkpoints[0].phase = Phase::Applying;
    interrupted.checkpoints[0].ownership.clear();
    engine.store().write_state(&interrupted).unwrap();
    engine.store().write_ownership(&Default::default()).unwrap();
    for operation in ["resume", "repair", "status"] {
        let output =
            Command::new(&release_installer).arg("--root").arg(root).arg(operation).arg("--json").output().unwrap();
        assert!(output.status.success(), "{operation}: {}", String::from_utf8_lossy(&output.stderr));
        let status: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(status["status"], "active");
    }
    assert!(fs::read_to_string(root.join("etc/proxy-control/version-agent.env"))
        .unwrap()
        .contains("PROXY_CONTROL_VERSION_HEALTH_TIMEOUT=321\n"));
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    daemon = start(&installed);
    assert_operator_files(versions());
    drop(daemon);
    assert_eq!(engine.uninstall(false).unwrap().status, Status::Uninstalled);
    assert!(root.join("etc/proxy-control/operator-versions.json").is_file());
    let preserved: Value = serde_json::from_slice(
        &fs::read(root.join("var/lib/proxy-control/version-agent/operator/state.json")).unwrap(),
    ).unwrap();
    assert_eq!(preserved["components"]["telemt"]["version"], "operator-current");
    println!("WP5b isolated smoke: fresh install; real installed daemon; update-host whole-engine repair; distinct operator catalog/state survive restart, resume/repair/status; uninstall preserve-data: PASS");
}
