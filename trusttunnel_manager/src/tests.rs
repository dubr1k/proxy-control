//! The manager's behaviour, ported from the Python suite: a fake endpoint process whose
//! counters reset on every start, and a hand-driven clock.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pc_common::{ApiError, ServerOptions, UdsServer};
use serde_json::{json, Map, Value};

use crate::config::{from_env, tests::make_env};
use crate::service::TrusttunnelManager;
use crate::supervisor::Supervisor;

const TOKEN: &str = "tttttttttttttttttttttttttttttttttttttttt";
const PASSWORD: &str = "pppppppppppppppppppppppppppppppp";

#[derive(Default)]
struct Fake {
    is_running: bool,
    starts: u32,
    stops: u32,
    reloads: u32,
    reload_error: bool,
    metrics_down: bool,
    credentials_at_start: Vec<Vec<String>>,
    vpn_at_start: Vec<toml::Table>,
    counters: BTreeMap<String, Value>,
}

#[derive(Clone, Default)]
struct FakeSupervisor(Arc<Mutex<Fake>>);

impl FakeSupervisor {
    fn get(&self) -> std::sync::MutexGuard<'_, Fake> {
        self.0.lock().unwrap()
    }

    fn traffic(&self, name: &str, inbound: u64, outbound: u64, sessions: u64) {
        self.get().counters.insert(
            name.into(),
            json!({"username": name, "ip": "1.2.3.4", "sessions": sessions, "inbound": inbound, "outbound": outbound}),
        );
    }

    fn fetch(&self) -> Option<Vec<Value>> {
        let fake = self.get();
        (fake.is_running && !fake.metrics_down).then(|| fake.counters.values().cloned().collect())
    }
}

impl Supervisor for FakeSupervisor {
    fn start(&mut self, vpn_toml: &Path, _hosts_toml: &Path) -> std::io::Result<()> {
        let mut fake = self.get();
        fake.is_running = true;
        fake.starts += 1;
        fake.counters.clear();
        let creds = read_toml(&vpn_toml.parent().unwrap().join("credentials.toml"));
        let names = creds["client"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["username"].as_str().unwrap().to_string())
            .filter(|name| name != "proxy-control-idle")
            .collect();
        fake.credentials_at_start.push(names);
        fake.vpn_at_start.push(read_toml(vpn_toml));
        Ok(())
    }

    fn stop(&mut self) {
        let mut fake = self.get();
        if fake.is_running {
            fake.stops += 1;
        }
        fake.is_running = false;
    }

    fn running(&mut self) -> bool {
        self.get().is_running
    }

    fn reload(&mut self) -> std::io::Result<()> {
        let mut fake = self.get();
        if fake.reload_error {
            return Err(std::io::Error::other("SECRET-KEY-BYTES"));
        }
        fake.reloads += 1;
        Ok(())
    }

    fn pid(&mut self) -> Option<u32> {
        self.get().is_running.then_some(4242)
    }
}

/// Seconds since an arbitrary start, advanced by hand; stored as millis in an atomic.
#[derive(Clone)]
struct Clock(Arc<AtomicU64>);

impl Clock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(1_000_000)))
    }

    fn advance(&self, seconds: f64) {
        self.0.fetch_add((seconds * 1000.0) as u64, Ordering::SeqCst);
    }

    fn now(&self) -> f64 {
        self.0.load(Ordering::SeqCst) as f64 / 1000.0
    }
}

struct Harness {
    dir: PathBuf,
    manager: Arc<TrusttunnelManager>,
    sup: FakeSupervisor,
    clock: Clock,
}

impl Harness {
    fn settle(&self) {
        self.clock.advance(3.0);
        self.manager.tick();
    }

    fn tick_after(&self, seconds: f64) {
        self.clock.advance(seconds);
        self.manager.tick();
    }

    fn state(&self, name: &str) -> PathBuf {
        self.dir.join("state").join(name)
    }

    fn raw_credentials(&self) -> Vec<toml::Value> {
        read_toml(&self.state("credentials.toml"))["client"].as_array().unwrap().clone()
    }

    fn credentials(&self) -> Vec<(String, String)> {
        self.raw_credentials()
            .iter()
            .map(|c| (c["username"].as_str().unwrap().to_string(), c["password"].as_str().unwrap().to_string()))
            .filter(|(name, _)| name != "proxy-control-idle")
            .collect()
    }

    fn clients(&self) -> Vec<Value> {
        self.manager.list_clients()["clients"].as_array().unwrap().clone()
    }

    fn create(&self, body: Value) -> Result<Value, ApiError> {
        self.manager.create_client(&obj(body))
    }
}

fn read_toml(path: &Path) -> toml::Table {
    std::fs::read_to_string(path).unwrap().parse().unwrap()
}

fn obj(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn tempdir(name: &str) -> PathBuf {
    crate::state::tests::tempdir(&format!("svc-{name}"))
}

fn make_in(dir: &Path, cert: bool, extra: &[(&str, &str)]) -> Harness {
    if cert {
        std::fs::write(dir.join("cert.pem"), "cert").unwrap();
        std::fs::write(dir.join("key.pem"), "key").unwrap();
    }
    let sup = FakeSupervisor::default();
    let clock = Clock::new();
    let (fetch_sup, clock_fn) = (sup.clone(), clock.clone());
    let manager = TrusttunnelManager::new(
        from_env(&make_env(dir, extra)).unwrap(),
        Box::new(sup.clone()),
        Box::new(move || fetch_sup.fetch()),
        Box::new(move || clock_fn.now()),
        Box::new(|| 1_700_000_000.0),
    );
    manager.bootstrap().unwrap();
    Harness { dir: dir.to_path_buf(), manager: Arc::new(manager), sup, clock }
}

fn make(name: &str) -> Harness {
    make_in(&tempdir(name), true, &[])
}

fn create_body(name: &str, password: &str, op: &str) -> Value {
    json!({"operation_id": op, "username": name, "password": password})
}

fn alice() -> Value {
    create_body("alice", PASSWORD, "op-1")
}

fn status_code(err: ApiError) -> (u16, String) {
    (err.status, err.code)
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------- toml

#[test]
fn toml_string_round_trips_hostile_characters() {
    for value in ["a\"b", "back\\slash", "new\nline", "tab\t", "ends\\\"", "ünï", "del\u{7f}"] {
        let table: toml::Table = format!("v = {}", crate::service::toml_string(value)).parse().unwrap();
        assert_eq!(table["v"].as_str().unwrap(), value);
    }
}

#[test]
fn generated_settings_are_tcp_only_and_loopback() {
    let h = make("settings");
    let vpn = read_toml(&h.state("vpn.toml"));
    assert_eq!(vpn["listen_address"].as_str(), Some("127.0.0.1:4453"));
    let protocols: Vec<&String> = vpn["listen_protocols"].as_table().unwrap().keys().collect();
    assert_eq!(protocols, ["http1", "http2"]);
    assert_eq!(
        vpn["forward_protocol"],
        toml::Value::Table(toml::Table::from_iter([("direct".to_string(), toml::Value::Table(toml::Table::new()))]))
    );
    let metrics = vpn["metrics"].as_table().unwrap();
    assert_eq!(metrics["address"].as_str(), Some("127.0.0.1:1987"));
    assert_eq!(metrics["request_timeout_secs"].as_integer(), Some(3));
    assert_eq!(metrics["per_client_metrics"].as_bool(), Some(true));
    assert_eq!(metrics.len(), 3);
    assert_eq!(vpn["credentials_file"].as_str().unwrap(), h.state("credentials.toml").display().to_string());
    assert!(!std::fs::read_to_string(h.state("vpn.toml")).unwrap().contains("quic"));
    let hosts = read_toml(&h.state("hosts.toml"));
    let main = hosts["main_hosts"].as_array().unwrap();
    assert_eq!(main.len(), 1);
    assert_eq!(main[0]["hostname"].as_str(), Some("gate.example.com"));
    assert_eq!(main[0]["cert_chain_path"].as_str().unwrap(), h.dir.join("cert.pem").display().to_string());
    assert_eq!(main[0]["private_key_path"].as_str().unwrap(), h.dir.join("key.pem").display().to_string());
    assert_eq!(h.sup.get().starts, 1);
}

#[test]
fn files_are_private() {
    let h = make("private");
    h.create(alice()).unwrap();
    assert_eq!(mode_of(&h.dir.join("state")), 0o700);
    for name in ["credentials.toml", "vpn.toml", "hosts.toml", "state.json"] {
        assert_eq!(mode_of(&h.state(name)), 0o600, "{name}");
    }
}

// ---------------------------------------------------------------- clients

#[test]
fn create_is_idempotent_per_operation_and_hides_the_password() {
    let h = make("create");
    let first = h.create(alice()).unwrap();
    assert_eq!(first, h.create(alice()).unwrap());
    assert_eq!(
        first["client"],
        json!({"username": "alice", "enabled": true, "revision": 1, "rx": 0, "tx": 0, "sessions": 0})
    );
    assert!(!first.to_string().contains(PASSWORD));
    assert_eq!(h.credentials(), [("alice".to_string(), PASSWORD.to_string())]);
}

#[test]
fn create_conflicts_and_validation() {
    let h = make("conflicts");
    h.create(alice()).unwrap();
    assert_eq!(status_code(h.create(create_body("alice", PASSWORD, "op-2")).unwrap_err()), (409, "exists".into()));
    assert_eq!(
        status_code(h.create(create_body("bob", PASSWORD, "op-1")).unwrap_err()),
        (409, "operation_conflict".into())
    );
    let long = "x".repeat(65);
    for bad in [
        create_body("bad name", PASSWORD, "op-1"),
        create_body("", PASSWORD, "op-1"),
        create_body(&long, PASSWORD, "op-1"),
        create_body("alice", "short", "op-1"),
        create_body("alice", "has space in it 123", "op-1"),
        json!({"operation_id": "op-1", "username": "alice", "password": PASSWORD, "extra": 1}),
        json!({"username": "a", "password": PASSWORD}),
    ] {
        assert_eq!(status_code(h.create(bad).unwrap_err()), (422, "invalid_request".into()));
    }
}

#[test]
fn disable_removes_from_credentials_and_enable_restores_the_same_password() {
    let h = make("toggle");
    h.create(alice()).unwrap();
    h.create(create_body("bob", &"q".repeat(32), "op-2")).unwrap();
    h.manager.set_enabled("alice", false).unwrap();
    assert_eq!(h.credentials().iter().map(|c| c.0.as_str()).collect::<Vec<_>>(), ["bob"]);
    assert_eq!(h.clients()[0]["enabled"], false);
    h.settle();
    assert_eq!(h.sup.get().credentials_at_start.last().unwrap(), &["bob".to_string()]);
    h.manager.set_enabled("alice", true).unwrap();
    assert!(h.credentials().contains(&("alice".to_string(), PASSWORD.to_string())));
    assert_eq!(h.clients()[0]["revision"], 3);
}

#[test]
fn rotate_changes_the_password_and_is_idempotent() {
    let h = make("rotate");
    h.create(alice()).unwrap();
    let new = "n".repeat(32);
    let body = obj(json!({"operation_id": "rot-1", "password": new}));
    assert_eq!(h.manager.rotate("alice", &body).unwrap()["client"]["revision"], 2);
    assert_eq!(h.credentials(), [("alice".to_string(), new.clone())]);
    assert_eq!(h.manager.rotate("alice", &body).unwrap()["client"]["revision"], 2);
    let conflict = h.manager.rotate("alice", &obj(json!({"operation_id": "rot-1", "password": "z".repeat(32)})));
    assert_eq!(conflict.unwrap_err().code, "operation_conflict");
    let missing = h.manager.rotate("nobody", &obj(json!({"operation_id": "rot-2", "password": new})));
    assert_eq!(missing.unwrap_err().status, 404);
}

#[test]
fn rotating_a_disabled_client_keeps_it_out_and_does_not_restart() {
    let h = make("rotate-disabled");
    h.create(alice()).unwrap();
    h.settle();
    h.manager.set_enabled("alice", false).unwrap();
    h.settle();
    let starts = h.sup.get().starts;
    h.manager.rotate("alice", &obj(json!({"operation_id": "r", "password": "n".repeat(32)}))).unwrap();
    h.settle();
    assert_eq!(h.sup.get().starts, starts);
    assert!(h.credentials().is_empty());
    h.manager.set_enabled("alice", true).unwrap();
    assert_eq!(h.credentials(), [("alice".to_string(), "n".repeat(32))]);
}

#[test]
fn delete_is_idempotent() {
    let h = make("delete");
    h.create(alice()).unwrap();
    h.manager.delete_client("alice").unwrap();
    h.manager.delete_client("alice").unwrap();
    assert_eq!(h.manager.list_clients(), json!({"clients": []}));
    assert!(h.credentials().is_empty());
    assert_eq!(h.manager.set_enabled("alice", true).unwrap_err().status, 404);
}

#[test]
fn state_survives_a_manager_restart() {
    let h = make("survives");
    h.create(alice()).unwrap();
    h.manager.set_enabled("alice", false).unwrap();
    let again = make_in(&h.dir, true, &[]);
    assert_eq!(again.clients()[0]["enabled"], false);
    assert_eq!(again.create(alice()).unwrap()["client"]["username"], "alice");
}

// ---------------------------------------------------------------- restarts and counters

#[test]
fn credential_changes_coalesce_into_one_restart() {
    let h = make("coalesce");
    assert_eq!(h.sup.get().starts, 1);
    for i in 0..5 {
        h.create(create_body(&format!("u{i}"), PASSWORD, &format!("op-{i}"))).unwrap();
    }
    h.tick_after(1.0);
    assert_eq!(h.sup.get().starts, 1); // still inside the coalescing window
    h.tick_after(2.0);
    let (starts, stops) = {
        let fake = h.sup.get();
        (fake.starts, fake.stops)
    };
    assert_eq!((starts, stops), (2, 1));
    let expected: Vec<String> = (0..5).map(|i| format!("u{i}")).collect();
    assert_eq!(h.sup.get().credentials_at_start.last().unwrap(), &expected);
    h.tick_after(10.0);
    assert_eq!(h.sup.get().starts, 2);
}

#[test]
fn totals_survive_restarts_and_use_a_final_poll() {
    let h = make("totals");
    h.create(alice()).unwrap();
    h.settle(); // first restart picks up alice
    h.sup.traffic("alice", 100, 1000, 2);
    h.tick_after(15.0);
    let view = &h.clients()[0];
    // rx = endpoint `outbound` = what the client uploaded; tx = endpoint `inbound` = what it downloaded
    assert_eq!((&view["rx"], &view["tx"], &view["sessions"]), (&json!(1000), &json!(100), &json!(2)));
    h.sup.traffic("alice", 150, 1500, 1); // traffic after the last poll
    h.create(create_body("bob", PASSWORD, "op-2")).unwrap();
    h.settle(); // restart: a final poll runs before the stop
    assert_eq!(h.sup.get().starts, 3);
    let view = &h.clients()[0];
    assert_eq!((&view["rx"], &view["tx"], &view["sessions"]), (&json!(1500), &json!(150), &json!(0)));
    h.sup.traffic("alice", 10, 20, 1); // counters restarted from zero
    h.tick_after(15.0);
    let view = &h.clients()[0];
    assert_eq!((&view["rx"], &view["tx"]), (&json!(1520), &json!(160)));
}

#[test]
fn totals_persist_in_state() {
    let h = make("persist");
    h.create(alice()).unwrap();
    h.settle();
    h.sup.traffic("alice", 5, 9, 1);
    h.tick_after(15.0);
    let again = make_in(&h.dir, true, &[]);
    let view = &again.clients()[0];
    assert_eq!((&view["rx"], &view["tx"]), (&json!(9), &json!(5)));
}

#[test]
fn unreachable_metrics_do_not_disturb_totals() {
    let h = make("unreachable");
    h.create(alice()).unwrap();
    h.settle();
    h.sup.traffic("alice", 5, 9, 1);
    h.sup.get().metrics_down = true;
    h.tick_after(15.0);
    assert_eq!(h.clients()[0]["rx"], 0);
}

#[test]
fn a_crashed_endpoint_is_started_again_with_backoff() {
    let h = make("backoff");
    h.sup.get().is_running = false;
    h.manager.tick(); // inside the backoff window of the first start
    assert_eq!(h.sup.get().starts, 1);
    h.tick_after(3.0);
    assert_eq!(h.sup.get().starts, 2);
    h.sup.get().is_running = false;
    h.manager.tick();
    assert_eq!(h.sup.get().starts, 2);
    h.tick_after(10.0);
    assert_eq!(h.sup.get().starts, 3);
}

// ---------------------------------------------------------------- health, endpoint

#[test]
fn missing_certificate_is_degraded_not_a_crash() {
    let dir = tempdir("nocert");
    let h = make_in(&dir, false, &[]);
    let health = h.manager.health();
    assert_eq!((&health["status"], &health["code"]), (&json!("degraded"), &json!("certificate_missing")));
    assert_eq!(h.sup.get().starts, 0);
    h.create(alice()).unwrap(); // the API keeps working
    std::fs::write(dir.join("cert.pem"), "cert").unwrap();
    std::fs::write(dir.join("key.pem"), "key").unwrap();
    h.tick_after(5.0);
    assert_eq!(h.sup.get().starts, 1);
    let health = h.manager.health();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["clients"], 1);
    assert_eq!(health["endpoint"], json!({"running": true, "pid": 4242}));
    assert!(health.get("code").is_none());
}

#[test]
fn health_reports_a_dead_endpoint() {
    let h = make("dead");
    h.sup.get().is_running = false;
    assert_eq!(h.manager.health()["code"], "endpoint_down");
}

#[test]
fn endpoint_info_without_a_readable_certificate() {
    let h = make_in(&tempdir("info"), true, &[("TT_VERSION", "v1.1.0")]);
    let info = h.manager.endpoint();
    assert_eq!((&info["hostname"], &info["listen"]), (&json!("gate.example.com"), &json!("127.0.0.1:4453")));
    assert_eq!((&info["public_port"], &info["version"]), (&json!(443), &json!("v1.1.0")));
    assert_eq!(info["certificate_trusted"], false);
    assert!(info["certificate_der_b64"].is_null() && info["fingerprint"].is_null());
}

fn openssl_self_signed(dir: &Path, cn: &str) {
    let out = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(dir.join("key.pem"))
        .arg("-out")
        .arg(dir.join("cert.pem"))
        .args(["-days", "30", "-subj", &format!("/CN={cn}")])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn self_signed_certificate_is_exposed_for_pinning() {
    let dir = tempdir("pinning");
    openssl_self_signed(&dir, "gate.example.com");
    let found = crate::cert::inspect_certificate(&dir.join("cert.pem"), 1_700_000_000.0).unwrap();
    let h = make_in(&dir, false, &[]);
    let info = h.manager.endpoint();
    assert_eq!(info["certificate_trusted"], false);
    assert!(info["certificate_der_b64"].as_str().is_some_and(|b| !b.is_empty()));
    assert_eq!(info["fingerprint"], found.fingerprint.as_str());
}

#[test]
fn endpoint_info_follows_the_renewed_certificate() {
    let dir = tempdir("renewed-info");
    let h = make_in(&dir, false, &[]);
    let mut seen = Vec::new();
    for cn in ["a.example.com", "b.example.com"] {
        openssl_self_signed(&dir, cn);
        seen.push(h.manager.endpoint()["fingerprint"].clone());
    }
    assert_ne!(seen[0], seen[1]);
}

// ---------------------------------------------------------------- egress

#[test]
fn egress_default_apply_and_rollback() {
    let h = make("egress");
    let direct = h.manager.egress();
    assert_eq!((&direct["mode"], &direct["address"]), (&json!("direct"), &Value::Null));
    assert_eq!(direct["revision"].as_str().unwrap().len(), 64);
    let doc = obj(json!({"mode": "socks5", "address": "127.0.0.1:41080"}));
    let plan = h.manager.egress_plan(&doc).unwrap();
    assert_eq!(plan["changed"], true);
    assert_eq!(plan["current"]["revision"], direct["revision"]);
    assert_eq!(h.manager.egress()["mode"], "direct"); // planning changes nothing
    let applied = h.manager.egress_apply(&doc).unwrap();
    assert_eq!(applied["mode"], "socks5");
    assert_eq!(applied["revision"], plan["proposed"]["revision"]);
    let vpn = read_toml(&h.state("vpn.toml"));
    let socks = vpn["forward_protocol"]["socks5"].as_table().unwrap();
    assert_eq!(socks["address"].as_str(), Some("127.0.0.1:41080"));
    assert_eq!(socks["extended_auth"].as_bool(), Some(false));
    assert_eq!(socks.len(), 2);
    h.settle();
    assert_eq!(
        h.sup.get().vpn_at_start.last().unwrap()["forward_protocol"]["socks5"]["extended_auth"].as_bool(),
        Some(false)
    );
    let starts = h.sup.get().starts;
    assert_eq!(h.manager.egress_apply(&doc).unwrap(), applied);
    h.settle();
    assert_eq!(h.sup.get().starts, starts); // same document: no restart
    assert_eq!(h.manager.egress_rollback().unwrap(), direct);
    assert_eq!(
        read_toml(&h.state("vpn.toml"))["forward_protocol"],
        toml::Value::Table(toml::Table::from_iter([("direct".to_string(), toml::Value::Table(toml::Table::new()))]))
    );
    assert_eq!(h.manager.egress_rollback().unwrap_err().code, "no_previous");
    // The revision is the hash of the canonical JSON the Python manager hashed.
    assert_eq!(
        direct["revision"],
        crate::cert::hex(&<sha2::Sha256 as sha2::Digest>::digest(br#"{"address":null,"mode":"direct"}"#))
    );
}

#[test]
fn egress_rejects_bad_documents() {
    let h = make("egress-bad");
    for body in [
        json!({"mode": "http"}),
        json!({"mode": "socks5"}),
        json!({"mode": "socks5", "address": "10.0.0.1:1080"}),
        json!({"mode": "socks5", "address": "127.0.0.1:80"}),
        json!({"mode": "direct", "address": "127.0.0.1:41080"}),
        json!({"mode": "socks5", "address": "127.0.0.1:41080", "x": 1}),
        json!({}),
    ] {
        assert_eq!(h.manager.egress_apply(&obj(body)).unwrap_err().status, 422);
    }
}

#[test]
fn egress_survives_a_manager_restart() {
    let h = make("egress-restart");
    h.manager.egress_apply(&obj(json!({"mode": "socks5", "address": "127.0.0.1:41080"}))).unwrap();
    let again = make_in(&h.dir, true, &[]);
    assert_eq!(again.manager.egress()["address"], "127.0.0.1:41080");
    assert!(std::fs::read_to_string(h.state("vpn.toml")).unwrap().contains("socks5"));
}

// ---------------------------------------------------------------- certificate renewal

#[test]
fn renewed_certificate_triggers_one_reload_and_no_restart() {
    let h = make("reload");
    h.tick_after(61.0);
    assert_eq!(h.sup.get().reloads, 0); // unchanged since start
    std::fs::write(h.dir.join("cert.pem"), "renewed").unwrap();
    h.tick_after(61.0);
    let fake = h.sup.get();
    assert_eq!((fake.reloads, fake.starts, fake.stops), (1, 1, 0));
    drop(fake);
    h.tick_after(61.0);
    assert_eq!(h.sup.get().reloads, 1);
}

#[test]
fn reload_failure_is_retried() {
    let h = make("reload-fail");
    std::fs::write(h.dir.join("key.pem"), "SECRET-KEY-BYTES").unwrap();
    h.sup.get().reload_error = true;
    h.tick_after(61.0);
    assert_eq!(h.sup.get().reloads, 0);
    h.sup.get().reload_error = false;
    h.tick_after(61.0);
    assert_eq!(h.sup.get().reloads, 1);
}

// ---------------------------------------------------------------- idle placeholder client

#[test]
fn zero_client_credentials_file_is_valid_and_non_empty() {
    let h = make("zero");
    let clients = h.raw_credentials();
    assert_eq!(clients[0]["username"].as_str(), Some("proxy-control-idle"));
    assert!(clients[0]["password"].as_str().unwrap().len() >= 32);
    h.create(alice()).unwrap();
    h.manager.set_enabled("alice", false).unwrap();
    assert_eq!(h.raw_credentials().len(), 1); // the last real client is disabled: still valid
    h.manager.delete_client("alice").unwrap();
    assert_eq!(h.raw_credentials().len(), 1);
}

#[test]
fn placeholder_is_stable_private_and_never_toggles_a_restart() {
    let h = make("placeholder");
    let password = h.raw_credentials()[0]["password"].as_str().unwrap().to_string();
    let _again = make_in(&h.dir, true, &[]);
    assert_eq!(h.raw_credentials()[0]["password"].as_str().unwrap(), password);
    let state: Value = serde_json::from_slice(&std::fs::read(h.state("state.json")).unwrap()).unwrap();
    assert_eq!(state["placeholder"], password.as_str());
    assert_eq!(mode_of(&h.state("state.json")), 0o600);
    h.settle();
    let starts = h.sup.get().starts;
    h.create(alice()).unwrap();
    h.settle();
    assert_eq!(h.sup.get().starts, starts + 1); // one restart for the real change only
}

#[test]
fn placeholder_username_is_reserved_and_invisible() {
    let h = make("reserved");
    let password = h.raw_credentials()[0]["password"].as_str().unwrap().to_string();
    let err = h.create(create_body("proxy-control-idle", PASSWORD, "op-1")).unwrap_err();
    assert_eq!(status_code(err), (422, "reserved_username".into()));
    h.create(alice()).unwrap();
    h.sup.traffic("proxy-control-idle", 7, 7, 1);
    h.sup.traffic("alice", 1, 2, 1);
    h.settle();
    h.tick_after(15.0);
    let shown =
        json!([h.manager.list_clients(), h.manager.health(), h.manager.endpoint(), h.manager.egress()]).to_string();
    assert!(!shown.contains("proxy-control-idle") && !shown.contains(&password));
    assert_eq!(h.manager.health()["clients"], 1);
    let names: Vec<Value> = h.clients().iter().map(|c| c["username"].clone()).collect();
    assert_eq!(names, [json!("alice")]);
    let state: Value = serde_json::from_slice(&std::fs::read(h.state("state.json")).unwrap()).unwrap();
    assert!(!state["clients"].to_string().contains("proxy-control-idle"));
}

// ---------------------------------------------------------------- HTTP

struct Api {
    harness: Harness,
    socket: PathBuf,
    handle: pc_common::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Api {
    fn drop(&mut self) {
        self.handle.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn api_with(harness: Harness) -> Api {
    let socket = harness.dir.join("m.sock");
    let mut options = ServerOptions::new(&socket);
    options.mode = 0o660;
    options.max_body = crate::server::MAX_BODY;
    let server = UdsServer::bind(options).unwrap();
    let handle = server.shutdown_handle();
    let handler = crate::server::handler(harness.manager.clone(), TOKEN.into()).unwrap();
    let thread = std::thread::spawn(move || server.serve(handler));
    Api { harness, socket, handle, thread: Some(thread) }
}

fn api(name: &str) -> Api {
    api_with(make(name))
}

fn call_raw(api: &Api, method: &str, path: &str, raw: Option<&[u8]>, token: Option<&str>) -> (u16, Option<Value>) {
    let headers: Vec<(&str, &str)> = token.map(|t| vec![("X-Trusttunnel-Token", t)]).unwrap_or_default();
    let reply = pc_common::client::request(&api.socket, method, path, &headers, raw, Duration::from_secs(5)).unwrap();
    (reply.status, if reply.body.is_empty() { None } else { Some(reply.json().unwrap()) })
}

fn call(api: &Api, method: &str, path: &str, body: Option<Value>) -> (u16, Option<Value>) {
    let raw = body.map(|b| b.to_string().into_bytes());
    call_raw(api, method, path, raw.as_deref(), Some(TOKEN))
}

#[test]
fn socket_is_private_and_token_is_required() {
    let api = api("http-token");
    assert_eq!(mode_of(&api.socket), 0o660);
    let wrong = "wrong".repeat(10);
    for token in [None, Some(wrong.as_str())] {
        let (status, body) = call_raw(&api, "GET", "/v1/health", None, token);
        assert_eq!((status, body.unwrap()), (401, json!({"detail": "unauthorized", "code": "unauthorized"})));
    }
    let raw = alice().to_string();
    assert_eq!(call_raw(&api, "POST", "/v1/clients", Some(raw.as_bytes()), None).0, 401);
    assert!(crate::server::handler(api.harness.manager.clone(), "short".into()).is_err());
}

#[test]
fn http_client_lifecycle() {
    let api = api("http-life");
    let (status, body) = call(&api, "POST", "/v1/clients", Some(alice()));
    assert_eq!((status, &body.as_ref().unwrap()["client"]["username"]), (200, &json!("alice")));
    assert_eq!(call(&api, "POST", "/v1/clients", Some(alice())), (200, body));
    let exists = call(&api, "POST", "/v1/clients", Some(create_body("alice", PASSWORD, "o2"))).1.unwrap();
    assert_eq!(exists["code"], "exists");
    assert_eq!(call(&api, "GET", "/v1/clients", None).1.unwrap()["clients"][0]["username"], "alice");
    assert_eq!(call(&api, "POST", "/v1/clients/alice/disable", None).1.unwrap()["client"]["enabled"], false);
    assert_eq!(call(&api, "POST", "/v1/clients/alice/enable", None).1.unwrap()["client"]["enabled"], true);
    assert_eq!(call(&api, "POST", "/v1/clients/alice/enable", Some(json!({"x": 1}))).0, 422);
    let rotated =
        call(&api, "POST", "/v1/clients/alice/rotate", Some(json!({"operation_id": "r", "password": "n".repeat(32)})));
    assert_eq!((rotated.0, &rotated.1.unwrap()["client"]["revision"]), (200, &json!(4)));
    assert_eq!(call(&api, "DELETE", "/v1/clients/alice", None), (204, None));
    assert_eq!(call(&api, "POST", "/v1/clients/alice/enable", None).0, 404);
    assert_eq!(call(&api, "GET", "/v1/nope", None).0, 404);
    // Percent-encoded names reach the manager decoded, as `unquote` did.
    call(&api, "POST", "/v1/clients", Some(create_body("a.b", PASSWORD, "op-dot"))).1.unwrap();
    assert_eq!(call(&api, "POST", "/v1/clients/a%2Eb/disable", None).1.unwrap()["client"]["username"], "a.b");
}

#[test]
fn http_health_endpoint_and_egress() {
    let api = api("http-egress");
    assert_eq!(call(&api, "GET", "/v1/health", None).1.unwrap()["status"], "ok");
    assert_eq!(call(&api, "GET", "/v1/endpoint", None).1.unwrap()["hostname"], "gate.example.com");
    assert_eq!(call(&api, "GET", "/v1/egress", None).1.unwrap()["mode"], "direct");
    let doc = json!({"mode": "socks5", "address": "127.0.0.1:41080"});
    assert_eq!(call(&api, "POST", "/v1/egress/plan", Some(doc.clone())).1.unwrap()["changed"], true);
    assert_eq!(call(&api, "POST", "/v1/egress/apply", Some(doc)).1.unwrap()["mode"], "socks5");
    assert_eq!(call(&api, "POST", "/v1/egress/rollback", None).1.unwrap()["mode"], "direct");
    assert_eq!(
        call(&api, "POST", "/v1/egress/apply", Some(json!({"mode": "x"}))).1.unwrap()["code"],
        "invalid_request"
    );
}

#[test]
fn body_cap_and_malformed_bodies() {
    let api = api("http-body");
    let big = vec![b'x'; crate::server::MAX_BODY + 1];
    assert_eq!(call_raw(&api, "POST", "/v1/clients", Some(&big), Some(TOKEN)).0, 422);
    assert_eq!(call_raw(&api, "POST", "/v1/clients", Some(b"[1]"), Some(TOKEN)).0, 422);
    assert_eq!(call_raw(&api, "POST", "/v1/clients", Some(b"{nope"), Some(TOKEN)).0, 422);
}

fn health_probe(api: &Api, token_file: &Path) -> bool {
    pc_common::client::health_probe(
        &api.socket,
        token_file,
        "X-Trusttunnel-Token",
        &[("degraded", "certificate_missing")],
    )
}

#[test]
fn healthcheck_probe() {
    let api = api("http-probe");
    let token_file = api.harness.dir.join("tok");
    std::fs::write(&token_file, TOKEN).unwrap();
    assert!(health_probe(&api, &token_file));
    std::fs::write(&token_file, "w".repeat(40)).unwrap();
    assert!(!health_probe(&api, &token_file));
    std::fs::write(&token_file, "short").unwrap();
    assert!(!health_probe(&api, &token_file));
    std::fs::write(&token_file, TOKEN).unwrap();
    assert!(!pc_common::client::health_probe(
        &api.harness.dir.join("none.sock"),
        &token_file,
        "X-Trusttunnel-Token",
        &[]
    ));
}

#[test]
fn healthcheck_tolerates_only_a_missing_certificate() {
    let dir = tempdir("probe-cert");
    let api = api_with(make_in(&dir, false, &[]));
    let token_file = dir.join("tok");
    std::fs::write(&token_file, TOKEN).unwrap();
    assert!(health_probe(&api, &token_file));
    std::fs::write(dir.join("cert.pem"), "c").unwrap();
    std::fs::write(dir.join("key.pem"), "k").unwrap(); // certificate there, endpoint not started yet
    assert!(!health_probe(&api, &token_file));
}

#[test]
fn state_written_by_the_python_manager_is_read() {
    let dir = tempdir("python-state");
    std::fs::create_dir_all(dir.join("state")).unwrap();
    // json.dumps(doc, indent=1, sort_keys=True) of a Python manager's state.
    let python = r#"{
 "clients": {
  "alice": {
   "enabled": true,
   "last_in": 3,
   "last_out": 4,
   "password": "pppppppppppppppppppppppppppppppp",
   "revision": 2,
   "rx": 10,
   "tx": 20
  }
 },
 "egress": {
  "document": {
   "address": "127.0.0.1:41080",
   "mode": "socks5"
  },
  "previous": {
   "address": null,
   "mode": "direct"
  }
 },
 "operations": {
  "op-1": {
   "fingerprint": "abc",
   "username": "alice"
  }
 },
 "placeholder": "placeholder-secret-placeholder-secret-12345",
 "schema": 1
}"#;
    std::fs::write(dir.join("state/state.json"), python).unwrap();
    let h = make_in(&dir, true, &[]);
    assert_eq!(
        h.clients()[0],
        json!({"username": "alice", "enabled": true, "revision": 2, "rx": 10, "tx": 20, "sessions": 0})
    );
    assert_eq!(h.manager.egress()["mode"], "socks5");
    assert_eq!(h.raw_credentials()[0]["password"].as_str(), Some("placeholder-secret-placeholder-secret-12345"));
    h.manager.shutdown();
    // Written back in the same layout.
    assert_eq!(std::fs::read_to_string(dir.join("state/state.json")).unwrap(), python);
}
