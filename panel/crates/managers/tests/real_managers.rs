//! Contract tests against the real Rust managers of this repository (`trusttunnel_manager`,
//! `awg_manager`, `mieru_manager`, `naive_manager`, `xray_router_manager`), each run as its own
//! binary with a fake backend (`tests/fakes/`), in private network and mount namespaces so nothing
//! on the host is touched (Linux, root: `unshare`, `mount -t overlay`).
//!
//! Ignored by default. On ams-test:
//!
//! ```text
//! for d in trusttunnel_manager awg_manager mieru_manager naive_manager xray_router_manager; do
//!     (cd $d && CARGO_TARGET_DIR=/root/rust-target-panel-wp5-managers cargo build --locked); done
//! PANEL_MANAGERS_BIN_DIR=/root/rust-target-panel-wp5-managers/debug \
//!     cargo test -p panel-managers --test real_managers -- --ignored --test-threads 1
//! ```

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::TempDir;
use panel_managers::{
    AmneziawgClient, LifecycleAction, ManagerError, MieruClient, NaiveClient, TrusttunnelClient, XrayRouterClient,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TOKEN: &str = "contract-token-0123456789abcdef0123456789abcdef";
const WRONG: &str = "wrong-token-0123456789abcdef0123456789abcdef00";

fn bin(name: &str) -> PathBuf {
    let dir = std::env::var("PANEL_MANAGERS_BIN_DIR")
        .expect("PANEL_MANAGERS_BIN_DIR: the directory holding the five manager binaries");
    PathBuf::from(dir).join(name)
}

fn write(path: &Path, content: impl AsRef<[u8]>, mode: u32) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn fake(name: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes").join(name)).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// A manager process in its own namespaces; stopped with SIGTERM on drop.
struct Running {
    child: Child,
    socket: PathBuf,
    log: PathBuf,
    dir: TempDir,
}

impl Running {
    fn start(binary: &str, dir: TempDir, socket: PathBuf, env: &[(&str, String)], setup: &str) -> Self {
        let log = dir.path().join("manager.log");
        let output = std::fs::File::create(&log).unwrap();
        let script = format!("set -e\n/usr/sbin/ip link set lo up\n{setup}\nexec \"$0\"");
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--net", "--mount", "--propagation", "private", "--", "/bin/bash", "-c", &script])
            .arg(bin(binary))
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output);
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(40);
        while !socket.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("{binary} exited ({status}): {}", std::fs::read_to_string(&log).unwrap_or_default());
            }
            assert!(Instant::now() < deadline, "{binary} did not bind: {}", std::fs::read_to_string(&log).unwrap());
            std::thread::sleep(Duration::from_millis(100));
        }
        Self { child, socket, log, dir }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        eprintln!("manager log: {}", std::fs::read_to_string(&self.log).unwrap_or_default());
    }
}

/// `(status, code)` of a refusal.
fn refusal(result: Result<Value, ManagerError>) -> (u16, Option<String>) {
    let error = result.expect_err("a refusal");
    (error.status_code, error.code)
}

fn random_key() -> String {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut bytes).unwrap();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the manager binaries (PANEL_MANAGERS_BIN_DIR), root and unshare"]
async fn trusttunnel_manager_contract() {
    let dir = TempDir::new("wp5-tt");
    let t = dir.path().to_path_buf();
    write(&t.join("token"), format!("{TOKEN}\n"), 0o600);
    write(&t.join("cert.pem"), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", 0o600);
    write(&t.join("key.pem"), "key", 0o600);
    write(
        &t.join("bin/trusttunnel_endpoint"),
        "#!/bin/sh\ntrap 'exit 0' TERM\nwhile kill -0 \"$PPID\" 2>/dev/null; do sleep 0.2; done\n",
        0o755,
    );
    let socket = t.join("run/tt.sock");
    let env = [
        ("TT_MANAGER_TOKEN_FILE", t.join("token").display().to_string()),
        ("TT_MANAGER_SOCKET", socket.display().to_string()),
        ("TT_MANAGER_SOCKET_MODE", "600".into()),
        ("TT_STATE_DIR", t.join("state").display().to_string()),
        ("TT_HOSTNAME", "tt.example.test".into()),
        ("TT_CERT", t.join("cert.pem").display().to_string()),
        ("TT_KEY", t.join("key.pem").display().to_string()),
        ("TT_BINARY", t.join("bin/trusttunnel_endpoint").display().to_string()),
        ("TT_METRICS", "127.0.0.1:41987".into()),
        ("TT_LISTEN", "127.0.0.1:41443".into()),
        ("TT_VERSION", "v1.1.0".into()),
        ("TT_PUBLIC_PORT", "443".into()),
    ];
    let manager = Running::start("trusttunnel-manager", dir, socket.clone(), &env, "");
    let client = TrusttunnelClient::new(&manager.socket, TOKEN);

    let health = client.health().await.unwrap();
    assert!(health["status"] == "ok" || health["status"] == "degraded", "{health}");
    let endpoint = client.endpoint().await.unwrap();
    assert_eq!((endpoint["hostname"].as_str(), endpoint["public_port"].as_i64()), (Some("tt.example.test"), Some(443)));
    assert_eq!(client.clients().await.unwrap(), json!([]));
    let created = client
        .create_client(&json!({"operation_id": "op-1", "username": "alice", "password": "password-01"}))
        .await
        .unwrap();
    assert_eq!(created["client"]["username"], "alice");
    let again = json!({"operation_id": "op-2", "username": "alice", "password": "password-01"});
    assert_eq!(refusal(client.create_client(&again).await), (409, Some("exists".into())));
    let invalid = json!({"operation_id": "op-3", "username": "bad name", "password": "password-01"});
    assert_eq!(refusal(client.create_client(&invalid).await), (422, Some("invalid_request".into())));
    assert_eq!(refusal(client.client_state("ghost", "enable").await), (404, Some("not_found".into())));
    assert_eq!(client.client_state("alice", "disable").await.unwrap()["client"]["enabled"], false);
    let rotated =
        client.rotate_client("alice", &json!({"operation_id": "op-4", "password": "password-02"})).await.unwrap();
    assert_eq!(rotated["client"]["revision"], 3);
    assert_eq!(client.clients().await.unwrap()[0]["username"], "alice");
    // 204 → None, and deleting a missing client is idempotent.
    assert_eq!(client.delete_client("alice").await.unwrap(), Value::Null);
    assert_eq!(client.delete_client("alice").await.unwrap(), Value::Null);

    // The bare egress document: no envelope, revision = the panel's own egress_revision.
    let egress = client.egress().await.unwrap();
    assert_eq!((egress["mode"].as_str(), &egress["address"]), (Some("direct"), &Value::Null));
    assert_eq!(egress["revision"].as_str(), panel_managers::trusttunnel::egress_revision(&egress).as_deref());
    assert_eq!(refusal(client.egress_rollback().await), (409, Some("no_previous".into())));
    let socks = json!({"mode": "socks5", "address": "127.0.0.1:45103"});
    assert_eq!(client.egress_plan(&socks).await.unwrap()["changed"], true);
    let applied = client.egress_apply(&socks).await.unwrap();
    assert_eq!(applied["revision"].as_str(), panel_managers::trusttunnel::egress_revision(&socks).as_deref());
    assert_eq!(refusal(client.egress_plan(&json!({"mode": "socks5", "address": "10.0.0.1:1"})).await).0, 422);
    assert_eq!(client.egress_rollback().await.unwrap()["mode"], "direct");

    let stranger = TrusttunnelClient::new(&manager.socket, WRONG);
    let error = stranger.health().await.unwrap_err();
    assert_eq!((error.status_code, error.code.as_deref()), (502, Some("unauthorized")));
    assert_eq!(error.message, "TrustTunnel manager rejected request");
    assert_eq!(error.app_error().unwrap().body(), json!({"detail": "TrustTunnel manager unavailable"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the manager binaries (PANEL_MANAGERS_BIN_DIR), root and unshare"]
async fn awg_manager_contract() {
    let dir = TempDir::new("wp5-awg");
    let t = dir.path().to_path_buf();
    write(&t.join("token"), TOKEN, 0o600);
    write(
        &t.join("bin/ip"),
        "#!/bin/sh\necho \"ip $*\" >> \"$(dirname \"$0\")/calls.log\"\ncase \"$*\" in\n  \"-j \"*) echo '[]' ;;\nesac\nexit 0\n",
        0o755,
    );
    write(
        &t.join("bin/nft"),
        "#!/bin/sh\necho \"nft $*\" >> \"$(dirname \"$0\")/calls.log\"\n[ \"$1\" = \"-f\" ] && cat > /dev/null\nexit 0\n",
        0o755,
    );
    let socket = t.join("run/awg.sock");
    let env = [
        ("PATH", format!("{}:/usr/sbin:/usr/bin:/sbin:/bin", t.join("bin").display())),
        ("AWG_MANAGER_TOKEN_FILE", t.join("token").display().to_string()),
        ("AWG_MANAGER_SOCKET", socket.display().to_string()),
        ("AWG_MANAGER_SOCKET_MODE", "600".into()),
        ("AWG_STATE_DIR", t.join("state").display().to_string()),
        ("AWG_VERSIONS", "1.5,2.0,3.1".into()),
        ("AWG_PORTS", "1.5=40015,2.0=40020,3.1=40031".into()),
        ("AWG_SUBNETS", "1.5=10.66.15.0/24,2.0=10.66.20.0/24,3.1=10.66.31.0/24".into()),
        ("AWG_LOG_LEVEL", "error".into()),
    ];
    let manager = Running::start("awg-manager", dir, socket.clone(), &env, "");
    let client = AmneziawgClient::new(&manager.socket, TOKEN);

    assert!(client.health().await.unwrap()["instances"]["2.0"]["interface"] == "awg20");
    let instances = client.instances().await.unwrap();
    assert_eq!(instances.as_array().unwrap().len(), 3);
    assert_eq!(client.peers().await.unwrap(), json!([]));
    let peer = |op: &str, name: &str, version: &str| {
        json!({"operation_id": op, "username": name, "version": version, "public_key": random_key(),
               "preshared_key": random_key()})
    };
    let created = client.create_peer(&peer("op-1", "alice-awg20", "2.0")).await.unwrap();
    assert_eq!(created["peer"]["address"], "10.66.20.2");
    assert_eq!(
        refusal(client.create_peer(&peer("op-2", "alice-awg20", "2.0")).await),
        (409, Some("username_taken".into()))
    );
    assert_eq!(refusal(client.create_peer(&peer("op-3", "bob", "9.9")).await), (422, Some("unknown_version".into())));
    assert_eq!(refusal(client.peer_state("ghost", "enable").await), (404, Some("not_found".into())));
    assert_eq!(client.peer_state("alice-awg20", "disable").await.unwrap()["peer"]["enabled"], false);
    let rotated = client
        .rotate_peer(
            "alice-awg20",
            &json!({"operation_id": "op-4", "public_key": random_key(), "preshared_key": random_key()}),
        )
        .await
        .unwrap();
    assert!(rotated["peer"]["revision"].as_i64().unwrap() > created["peer"]["revision"].as_i64().unwrap());
    assert_eq!(client.peers().await.unwrap()[0]["username"], "alice-awg20");
    assert_eq!(client.delete_peer("alice-awg20").await.unwrap(), Value::Null); // 204
    assert_eq!(refusal(client.delete_peer("alice-awg20").await), (404, Some("not_found".into())));

    let egress = client.egress().await.unwrap();
    let revision = egress["revision"].as_str().unwrap().to_string();
    assert_eq!(egress["mode"], "direct");
    let direct = json!({"schema": 1, "upstream": null});
    assert_eq!(refusal(client.egress_rollback(&revision).await), (409, Some("egress_no_previous".into())));
    assert_eq!(client.egress_plan(&revision, &direct).await.unwrap()["revision"], revision.as_str());
    assert_eq!(refusal(client.egress_apply("stale", &direct, "op-e0").await), (409, Some("egress_conflict".into())));
    let bad = json!({"schema": 1, "upstream": {"provider": "nowhere"}});
    assert_eq!(refusal(client.egress_plan(&revision, &bad).await), (422, Some("egress_invalid".into())));
    let applied = client.egress_apply(&revision, &direct, "op-e1").await.unwrap();
    assert_eq!(applied["replayed"], false);
    let replayed = client.egress_apply("stale", &direct, "op-e1").await.unwrap();
    assert_eq!(replayed["replayed"], true);
    let current = client.egress().await.unwrap()["revision"].as_str().unwrap().to_string();
    assert_eq!(client.egress_rollback(&current).await.unwrap()["replayed"], false);

    let error = AmneziawgClient::new(&manager.socket, WRONG).peers().await.unwrap_err();
    assert_eq!((error.status_code, error.code.as_deref()), (502, Some("unauthorized")));
    assert_eq!(error.app_error().unwrap().body(), json!({"detail": "AmneziaWG manager unavailable"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the manager binaries (PANEL_MANAGERS_BIN_DIR), root and unshare"]
async fn mieru_manager_contract() {
    let dir = TempDir::new("wp5-mieru");
    let t = dir.path().to_path_buf();
    write(&t.join("token"), TOKEN, 0o600);
    let mita = fake("fake-mita.py");
    write(&t.join("ovl/mita"), &mita, 0o755);
    std::fs::create_dir_all(t.join("mita")).unwrap();
    std::fs::create_dir_all(t.join("tmp")).unwrap();
    let socket = t.join("run/mieru.sock");
    let env = [
        ("MIERU_MANAGER_TOKEN_FILE", t.join("token").display().to_string()),
        ("MIERU_MITA_SHA256", sha256_hex(mita.as_bytes())),
        ("MIERU_PUBLIC_HOST", "proxy.example.com".into()),
        ("MIERU_MANAGER_STATE", t.join("state").display().to_string()),
        ("MIERU_MANAGER_SOCKET", socket.display().to_string()),
        ("MIERU_SOCKET_MODE", "600".into()),
        ("FAKE_MITA_DIR", t.join("mita").display().to_string()),
        ("TMPDIR", t.join("tmp").display().to_string()),
    ];
    // /usr/bin/mita is fixed in the manager: an overlay shows the fake there, in this mount
    // namespace only.
    let setup = format!("mount -t overlay overlay -o lowerdir={}:/usr/bin /usr/bin", t.join("ovl").display());
    let manager = Running::start("mieru-manager", dir, socket.clone(), &env, &setup);
    let client = MieruClient::new(&manager.socket, TOKEN);

    let health = client.health().await.unwrap();
    assert_eq!(health["status"], "running");
    let revision = |value: &Value| value["revision"].as_str().unwrap().to_string();
    let mut current = revision(&health);
    assert_eq!(client.list_users().await.unwrap(), json!([]));
    // The exact value the panel requires, byte for byte the manager's constant.
    assert_eq!(client.metrics().await.unwrap(), panel_managers::mieru::metrics_unavailable());
    write(
        &manager.path("mita/main.metrics.json"),
        r#"{"users":{"alice":{"UploadBytes":10,"DownloadBytes":20}}}"#,
        0o644,
    );
    let created = client
        .create(&json!({"username": "alice", "quotas": [], "expected_revision": current,
                         "password": "caller-password-0001", "operation_id": "op-1"}))
        .await
        .unwrap();
    assert!(created["share_url"]
        .as_str()
        .unwrap()
        .starts_with("mierus://alice:caller-password-0001@proxy.example.com"));
    current = revision(&created);
    let traffic = client.traffic().await.unwrap();
    assert_eq!(traffic["users"][0]["download_bytes"], 20);
    let stale = client.operation("alice", "disable", "stale").await;
    assert_eq!(refusal(stale), (409, Some("egress_conflict".into())));
    assert_eq!(refusal(client.operation("ghost", "enable", &current).await), (409, None));
    let disabled = client.operation("alice", "disable", &current).await.unwrap();
    assert_eq!(disabled["enabled"], false);
    current = revision(&disabled);
    current = revision(&client.operation("alice", "enable", &current).await.unwrap());
    let quotas = json!({"quotas": [{"days": 1, "megabytes": 10}], "expected_revision": current});
    current = revision(&client.set_quotas("alice", &quotas).await.unwrap());
    let rotated = client.rotate("alice", &current, Some("caller-password-0002"), Some("op-2")).await.unwrap();
    assert!(rotated["share_url"].as_str().unwrap().contains("caller-password-0002"));
    assert_eq!(refusal(client.reset_metrics("alice").await), (409, None));
    let restarted = client.lifecycle(LifecycleAction::Restart).await.unwrap();
    assert_eq!(restarted["ready"], true);
    current = revision(&restarted);
    let extra = json!({"username": "bob", "quotas": [], "expected_revision": current, "x": 1});
    assert_eq!(refusal(client.create(&extra).await), (422, None));

    let egress = client.egress().await.unwrap();
    assert_eq!(egress["document"], panel_managers::mieru::egress_direct());
    assert_eq!(refusal(client.egress_rollback(&current).await), (409, Some("egress_no_previous".into())));
    let plan = client.egress_plan(&current, &panel_managers::mieru::egress_direct()).await.unwrap();
    assert!(plan.get("diff").is_some());
    let warp = json!({"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
                      "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"}]});
    assert_eq!(refusal(client.egress_plan(&current, &warp).await), (422, Some("egress_invalid".into())));
    let lanes = client.set_lanes(&json!([])).await.unwrap();
    assert_eq!(lanes["lanes"], json!([]));
    assert_eq!(client.lanes().await.unwrap()["lanes"], json!([]));
    current = revision(&client.health().await.unwrap());
    let deleted = client.delete("alice", &current).await.unwrap(); // DELETE with a JSON body
    assert_eq!(deleted["username"], "alice");

    let error = MieruClient::new(&manager.socket, WRONG).health().await.unwrap_err();
    assert_eq!((error.status_code, error.code.as_deref()), (502, None));
    assert_eq!(error.app_error().unwrap().body(), json!({"detail": "Mieru manager unavailable"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the manager binaries (PANEL_MANAGERS_BIN_DIR), root and unshare"]
async fn naive_manager_contract() {
    let dir = TempDir::new("wp5-naive");
    let t = dir.path().to_path_buf();
    write(&t.join("token"), TOKEN, 0o600);
    write(&t.join("fake-caddy.py"), fake("fake-caddy.py"), 0o755);
    let made = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=naive.example.com"])
        .args(["-addext", "subjectAltName=DNS:naive.example.com", "-keyout", "key.pem", "-out", "cert.pem"])
        .current_dir(&t)
        .output()
        .unwrap();
    assert!(made.status.success());
    let caddyfile = "{\n    admin 127.0.0.1:2019\n}\n:443, naive.example.com {\n    route {\n        forward_proxy {\n            basic_auth seed seed-password-000001\n            hide_ip\n            hide_via\n            probe_resistance\n        }\n        file_server { root /var/www/naive }\n    }\n}\n";
    write(&t.join("Caddyfile"), caddyfile, 0o640);
    write(&t.join("logs/access.json"), "", 0o640);
    std::fs::create_dir_all(t.join("data")).unwrap();
    let socket = t.join("run/naive.sock");
    let env = [
        ("NAIVE_PUBLIC_HOST", "naive.example.com".to_string()),
        ("NAIVE_CADDYFILE", t.join("Caddyfile").display().to_string()),
        ("NAIVE_STATE_FILE", t.join("data/users.json").display().to_string()),
        ("NAIVE_BACKUP_DIR", t.join("backups").display().to_string()),
        ("NAIVE_TRAFFIC_LOG", t.join("logs/access.json").display().to_string()),
        ("NAIVE_TRAFFIC_DATABASE", t.join("data/traffic.sqlite3").display().to_string()),
        ("NAIVE_MANAGER_TOKEN_FILE", t.join("token").display().to_string()),
        ("NAIVE_MANAGER_SOCKET", socket.display().to_string()),
        ("NAIVE_SOCKET_MODE", "600".into()),
        ("NAIVE_QUOTA_INTERVAL_SECONDS", "3600".into()),
    ];
    // Caddy's admin API (2019) and the cover site (4443) are fixed ports: the fake serves them in
    // this network namespace, as a child of the manager.
    let setup = format!(
        "/usr/bin/python3 {t}/fake-caddy.py {t}/cert.pem {t}/key.pem &\n\
         for i in $(seq 100); do (exec 3<>/dev/tcp/127.0.0.1/2019) 2>/dev/null && break; sleep 0.1; done",
        t = t.display()
    );
    let manager = Running::start("naive-manager", dir, socket.clone(), &env, &setup);
    let client = NaiveClient::new(&manager.socket, TOKEN);

    assert_eq!(client.health().await.unwrap(), json!({"ready": true, "host": "naive.example.com"}));
    let created = client.create("alice", Some(100), Some("caller-password-0001"), Some("op-1")).await.unwrap();
    assert_eq!(created["username"], "alice");
    assert_eq!(created["proxy_url"], "https://alice:caller-password-0001@naive.example.com");
    let replayed = client.create("alice", Some(100), Some("caller-password-0001"), Some("op-1")).await.unwrap();
    assert_eq!(replayed["replayed"], true);
    // A plain conflict keeps no code (`configuration_conflict` is not a panel reason).
    assert_eq!(refusal(client.create("alice", None, None, Some("op-2")).await), (409, None));
    assert_eq!(refusal(client.create("bad name", None, None, None).await), (422, None));
    assert_eq!(refusal(client.reveal("ghost").await), (404, None));
    assert_eq!(client.reveal("alice").await.unwrap()["username"], "alice");
    let rotated = client.rotate("alice", Some("caller-password-0002"), Some("op-3")).await.unwrap();
    assert_eq!(rotated["proxy_url"], "https://alice:caller-password-0002@naive.example.com");
    assert_eq!(client.set_enabled("alice", false).await.unwrap()["disabled_reason"], "manual");
    let users = client.list_users().await.unwrap();
    assert!(users.as_array().unwrap().iter().any(|user| user["username"] == "alice"), "{users}");

    // Usage over the quota: enable answers 409 `quota_exhausted`, which the panel shows as such.
    let mut log = std::fs::OpenOptions::new().append(true).open(manager.path("logs/access.json")).unwrap();
    log.write_all(
        b"{\"request\":{\"method\":\"CONNECT\"},\"status\":200,\"user_id\":\"alice\",\"bytes_read\":60,\"size\":60}\n",
    )
    .unwrap();
    drop(log);
    client.set_quota("alice", Some(100)).await.unwrap();
    let exhausted = client.set_enabled("alice", true).await.unwrap_err();
    assert_eq!((exhausted.status_code, exhausted.code.as_deref()), (409, Some("quota_exhausted")));
    let answer = exhausted.app_error().unwrap();
    assert_eq!(
        (answer.status(), answer.body_bytes()),
        (
            409,
            br#"{"detail":"Quota exhausted: reset traffic or raise the quota first","code":"quota_exhausted"}"#
                .to_vec()
        )
    );
    assert_eq!(client.reset_traffic("alice").await.unwrap()["upload_bytes"], 0);
    assert!(client.traffic().await.unwrap()["users"].is_array());
    assert_eq!(client.set_quota("alice", None).await.unwrap()["quota_bytes"], Value::Null);

    let egress = client.egress().await.unwrap();
    let revision = egress["revision"].as_str().unwrap().to_string();
    assert_eq!(egress["document"], panel_managers::naive::egress_direct());
    assert_eq!(refusal(client.egress_rollback(&revision).await), (409, Some("egress_no_previous".into())));
    assert_eq!(refusal(client.egress_plan("stale", &egress["document"]).await), (409, Some("egress_conflict".into())));
    let acl = json!({"schema": 1, "upstream": null, "acl": [{"deny": ["example.com"]}]});
    assert!(client.egress_plan(&revision, &acl).await.unwrap()["diff"].is_array());
    let applied = client.egress_apply(&revision, &acl, "op-e1").await.unwrap();
    assert_eq!(applied["replayed"], false);
    let rolled = client.egress_rollback(applied["revision"].as_str().unwrap()).await.unwrap();
    assert_eq!(rolled["revision"].as_str(), Some(revision.as_str()));
    assert_eq!(client.lanes().await.unwrap(), json!({"lanes": []}));
    assert_eq!(client.set_lanes(&json!([])).await.unwrap()["lanes"], json!([]));
    assert_eq!(refusal(client.set_lanes(&json!([{"lane": "x"}])).await), (409, Some("lanes_invalid".into())));

    assert_eq!(client.delete("alice").await.unwrap(), Value::Null); // 204
    assert_eq!(refusal(client.delete("alice").await), (404, None));

    let error = NaiveClient::new(&manager.socket, WRONG).health().await.unwrap_err();
    assert_eq!((error.status_code, error.code.as_deref()), (502, None));
    assert_eq!(error.app_error().unwrap().body(), json!({"detail": "NaiveProxy manager unavailable"}));
}

/// A `GeoSiteList`/`GeoIPList` with these country codes (protobuf: repeated entry=1 {code=1}).
fn geodata(codes: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for code in codes {
        let mut inner = vec![0x0a, code.len() as u8];
        inner.extend_from_slice(code.as_bytes());
        out.push(0x0a);
        out.push(inner.len() as u8);
        out.extend(inner);
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the manager binaries (PANEL_MANAGERS_BIN_DIR), root and unshare"]
async fn xray_router_manager_contract() {
    let dir = TempDir::new("wp5-xr");
    let t = dir.path().to_path_buf();
    write(&t.join("token"), TOKEN, 0o600);
    let xray = fake("fake-xray.py");
    write(&t.join("bin/xray"), &xray, 0o755);
    let (geosite, geoip) = (geodata(&["category-ads-all", "cn"]), geodata(&["cn", "ru"]));
    write(&t.join("bin/geosite.dat"), &geosite, 0o644);
    write(&t.join("bin/geoip.dat"), &geoip, 0o644);
    write(&t.join("secrets/naive"), format!("naive-test:{}\n", "N".repeat(40)), 0o600);
    write(&t.join("secrets/mieru"), format!("mieru-test:{}\n", "M".repeat(40)), 0o600);
    write(
        &t.join("state/geodata/meta.json"),
        r#"{"schema":2,"source":{"kind":"xray","geosite_url":null,"geoip_url":null},"auto_update":false,"interval_hours":24,"update_hour":2,"origin":"seed","version":null,"updated_at":null,"last_check_at":null,"last_error":null,"files":{}}"#,
        0o600,
    );
    let socket = t.join("run/manager.sock");
    let env = [
        ("XRAY_ROUTER_BIN_DIR", t.join("bin").display().to_string()),
        ("XRAY_ROUTER_STATE_DIR", t.join("state").display().to_string()),
        ("XRAY_ROUTER_SOCKET", socket.display().to_string()),
        ("XRAY_ROUTER_SOCKET_MODE", "600".into()),
        ("XRAY_ROUTER_MANAGER_TOKEN_FILE", t.join("token").display().to_string()),
        ("XRAY_ROUTER_INGRESS_NAIVE_FILE", t.join("secrets/naive").display().to_string()),
        ("XRAY_ROUTER_INGRESS_MIERU_FILE", t.join("secrets/mieru").display().to_string()),
        ("XRAY_ROUTER_XRAY_SHA256", sha256_hex(xray.as_bytes())),
        ("XRAY_ROUTER_GEOIP_SHA256", sha256_hex(&geoip)),
        ("XRAY_ROUTER_GEOSITE_SHA256", sha256_hex(&geosite)),
        ("XRAY_ROUTER_PORT_NAIVE", "45101".into()),
        ("XRAY_ROUTER_PORT_MIERU", "45102".into()),
        ("XRAY_ROUTER_INGRESS_MTPROXY_SOCKET", t.join("run/ingress-mtproxy.sock").display().to_string()),
        ("XRAY_ROUTER_PORT_TRUSTTUNNEL", "".into()),
    ];
    let manager = Running::start("xray-router-manager", dir, socket.clone(), &env, "");
    let client = XrayRouterClient::new(&manager.socket, TOKEN);

    let status = client.status().await.unwrap();
    assert_eq!(status["running"]["generation"], 1);
    let direct = json!({"schema": 1, "default": {"action": "direct", "egress": null}, "rules": []});
    let block = json!({"schema": 1, "default": {"action": "direct", "egress": null},
                       "rules": [{"domains": ["example.com"], "geosites": [], "cidrs": [], "geoips": [], "ports": [],
                                  "action": "block", "egress": null}]});
    let egress = client.egress("naive").await.unwrap();
    let revision = egress["revision"].as_str().unwrap().to_string();
    assert_eq!(egress["document"], direct);
    assert_eq!(refusal(client.egress("bogus").await), (404, None));
    assert_eq!(refusal(client.egress_rollback("naive", &revision).await), (409, Some("egress_no_previous".into())));
    assert!(client.egress_plan("naive", &revision, &block).await.unwrap()["diff"].is_array());
    assert_eq!(
        refusal(client.egress_apply("naive", "stale", &block, "op-1").await),
        (409, Some("egress_conflict".into()))
    );
    let applied = client.egress_apply("naive", &revision, &block, "op-2").await.unwrap();
    assert_eq!(applied["replayed"], false);
    let rolled = client.egress_rollback("naive", applied["revision"].as_str().unwrap()).await.unwrap();
    assert_eq!(rolled["applied"], direct);

    assert_eq!(client.lanes("naive").await.unwrap(), json!({"lanes": []}));
    assert_eq!(refusal(client.lanes("mtproxy").await), (404, None));
    let issued = client.lane_issue("naive", "grant:a1").await.unwrap();
    assert_eq!(issued["user"], "grant-a1");
    // The lane id keeps its colon raw in the path (as httpx sends it).
    assert_eq!(client.lane_forget("naive", "grant:a1").await.unwrap()["forgotten"], true);
    assert_eq!(refusal(client.lane_forget("naive", "grant:a1").await), (409, Some("lane_unknown".into())));
    assert_eq!(client.relay().await.unwrap()["enabled"], false);
    let accounts = json!([{"email": "relay:a1:direct", "uuid": "0b6e9c2e-5f0a-4c1e-9f7e-1d2c3b4a5f60"}]);
    assert_eq!(refusal(client.relay_set_accounts(&accounts).await), (409, Some("relay_disabled".into())));
    let relay = client.relay_enable("relay.example.com", 8443).await.unwrap();
    assert_eq!(relay["enabled"], true);
    assert_eq!(client.relay_set_accounts(&accounts).await.unwrap()["accounts"], 1);
    assert_eq!(client.relay_disable().await.unwrap()["enabled"], false);
    assert_eq!(client.ingress("mtproxy").await.unwrap()["username"], "telemt");
    assert_eq!(client.geodata().await.unwrap()["source"]["kind"], "xray");
    assert_eq!(client.geodata_codes().await.unwrap()["codes"]["geoip"], json!(["cn", "ru"]));
    let refused = client.geodata_settings(&json!({"interval_hours": 0})).await;
    assert_eq!(refusal(refused), (422, Some("geodata_invalid".into())));
    assert_eq!(client.geodata_settings(&json!({"interval_hours": 48})).await.unwrap()["interval_hours"], 48);
    assert_eq!(client.geodata_update().await.unwrap()["changed"], false);
    assert_eq!(client.geodata_restore().await.unwrap()["changed"], true);
    let probe = client.exit_test(&json!({"protocol": "socks", "address": "10.0.0.2", "port": 1080})).await.unwrap();
    assert_eq!(probe["ok"], false);
    assert_eq!(refusal(client.exit_test(&json!({"protocol": "nope"})).await), (422, Some("egress_invalid".into())));

    // A broken router answers 503, which this client (alone) passes through.
    write(&manager.path("state/state.json"), r#"{"candidate":null,"failures":3,"phase":"broken"}"#, 0o600);
    let current = client.egress("mieru").await.unwrap()["revision"].as_str().unwrap().to_string();
    let broken = client.egress_plan("mieru", &current, &direct).await;
    assert_eq!(refusal(broken), (503, Some("manual_intervention_required".into())));

    let error = XrayRouterClient::new(&manager.socket, WRONG).status().await.unwrap_err();
    assert_eq!((error.status_code, error.code.as_deref(), error.app_error()), (502, None, None));
}
