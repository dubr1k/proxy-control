//! The manager's behaviour, ported from the Python suites (`tests/test_xray_router_*.py`):
//! generations, the journal per service, the swap and its failure modes, recovery after a crash,
//! the watchdog, lanes, the relay, chains, geodata, exits, the MTProxy, TrustTunnel and AmneziaWG
//! ingresses and the Unix-socket API — against a fake Xray runner.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pc_common::{ServerOptions, UdsServer};
use serde_json::{json, Map, Value};

use crate::errors::Error;
use crate::geodata::{preset_urls, tests::geodata_file, tests::Publisher, Fetcher};
use crate::intent::{direct_document, tests::hop, tests::with, validate_document, PORTS, TRUSTTUNNEL_PORT};
use crate::render::{config_bytes, Ingress, MTPROXY_PRIVATE_EXCEPTION};
use crate::runner::{Handle, XrayRunner};
use crate::service::{Options, XrayRouterManager};
use crate::util::sha256_hex;

const WARP: &str = "socks5://127.0.0.1:45000";
const PUBLIC_KEY: &str = "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s";

fn secret_naive() -> String {
    format!("naive-a1b2c3d4:{}", "N".repeat(40))
}

fn secret_mieru() -> String {
    format!("mieru-e5f6a7b8:{}", "M".repeat(40))
}

fn private_key() -> String {
    format!("kPrivate_{}", "k".repeat(34))
}

fn warp_doc() -> Value {
    json!({"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []})
}

fn block_doc() -> Value {
    json!({"schema": 1, "default": {"action": "direct", "egress": null}, "rules": [{"domains": ["example.com"], "action": "block"}]})
}

// ---------------------------------------------------------------- the fake runner

struct FakeHandle {
    id: u64,
    path: PathBuf,
    alive: bool,
    config: Value,
    tun: Option<String>,
}

#[derive(Default)]
struct Fake {
    calls: Vec<String>,
    fail_test: Option<String>,
    fail_ready: u32,
    fail_start: bool,
    handles: Vec<FakeHandle>,
    x25519_calls: u32,
}

/// Records every call; `fail_test` refuses the next -test with the given text, `fail_ready` makes
/// the next N starts never open their ports, `fail_start` refuses every start.
#[derive(Clone, Default)]
struct FakeRunner(Arc<Mutex<Fake>>);

fn name_of(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

impl FakeRunner {
    fn get(&self) -> std::sync::MutexGuard<'_, Fake> {
        self.0.lock().unwrap()
    }

    fn calls(&self) -> Vec<String> {
        self.get().calls.clone()
    }

    fn running_config(&self) -> Value {
        self.running().expect("a running process").0
    }

    /// (config, path name, tun) of the one live process; two at once is a bug.
    fn running(&self) -> Option<(Value, String, Option<String>)> {
        let fake = self.get();
        let alive: Vec<&FakeHandle> = fake.handles.iter().filter(|h| h.alive).collect();
        assert!(alive.len() <= 1, "two xray processes alive at once");
        alive.first().map(|h| (h.config.clone(), name_of(&h.path), h.tun.clone()))
    }

    fn kill_running(&self) {
        for handle in self.get().handles.iter_mut() {
            handle.alive = false;
        }
    }
}

impl XrayRunner for FakeRunner {
    fn version(&self) -> crate::errors::Result<String> {
        Ok("Xray 26.3.27 (fake)".into())
    }

    fn x25519(&self) -> crate::errors::Result<(String, String)> {
        self.get().x25519_calls += 1;
        Ok((private_key(), PUBLIC_KEY.into()))
    }

    fn test(&self, config: &Path, asset_dir: Option<&Path>) -> crate::errors::Result<()> {
        let mut fake = self.get();
        let call = match asset_dir {
            Some(dir) => format!("test {} {}", name_of(config), name_of(dir)),
            None => format!("test {}", name_of(config)),
        };
        fake.calls.push(call);
        serde_json::from_slice::<Value>(&std::fs::read(config).unwrap()).unwrap();
        match fake.fail_test.take() {
            Some(message) => Err(Error::Xray(message)),
            None => Ok(()),
        }
    }

    fn start(&self, config: &Path, tun: Option<&str>) -> crate::errors::Result<Handle> {
        let mut fake = self.get();
        fake.calls.push(format!("start {}", name_of(config)));
        if fake.fail_start {
            return Err(Error::Xray("xray exited: config error".into()));
        }
        let id = fake.handles.len() as u64 + 1;
        let parsed = serde_json::from_slice(&std::fs::read(config).unwrap()).unwrap();
        fake.handles.push(FakeHandle {
            id,
            path: config.to_path_buf(),
            alive: true,
            config: parsed,
            tun: tun.map(str::to_string),
        });
        Ok(Handle { id, child: None })
    }

    fn stop(&self, handle: &Handle) {
        let mut fake = self.get();
        let entry = fake.handles.iter_mut().find(|h| h.id == handle.id).unwrap();
        entry.alive = false;
        let call = format!("stop {}", name_of(&entry.path));
        fake.calls.push(call);
    }

    fn alive(&self, handle: &Handle) -> bool {
        self.get().handles.iter().any(|h| h.id == handle.id && h.alive)
    }

    fn wait_ready(&self, ports: &[i64], _timeout: f64, sockets: &[String]) -> crate::errors::Result<()> {
        let mut fake = self.get();
        let ports: Vec<String> = ports.iter().map(i64::to_string).collect();
        let mut call = format!("ready {}", ports.join(","));
        if !sockets.is_empty() {
            call.push_str(&format!(" {}", sockets.join(",")));
        }
        fake.calls.push(call);
        if fake.fail_ready > 0 {
            fake.fail_ready -= 1;
            fake.handles.last_mut().unwrap().alive = false;
            return Err(Error::Xray("the ingress ports did not open in time".into()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- the manager under test

#[derive(Clone)]
struct Setup {
    warp: Option<&'static str>,
    reachable: bool,
    bad_digest: bool,
    mtproxy: bool,
    trusttunnel: bool,
    /// AmneziaWG: `Some(device present)`.
    amneziawg: Option<bool>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            warp: Some(WARP),
            reachable: true,
            bad_digest: false,
            mtproxy: false,
            trusttunnel: false,
            amneziawg: None,
        }
    }
}

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("xr-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn artifact(dir: &Path, name: &str, data: &[u8]) -> (PathBuf, String) {
    let path = dir.join("bin").join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, data).unwrap();
    (path, sha256_hex(data))
}

type Registrations = Arc<Mutex<Vec<String>>>;

fn build(dir: &Path, runner: &FakeRunner, setup: &Setup, registrations: &Registrations) -> XrayRouterManager {
    let secrets = dir.join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    for (name, secret) in [("naive", secret_naive()), ("mieru", secret_mieru())] {
        if !secrets.join(name).exists() {
            // a second manager over the same files keeps them
            std::fs::write(secrets.join(name), format!("{secret}\n")).unwrap();
        }
    }
    let (xray, xray_sha) = artifact(dir, "xray", b"ELF");
    let (geoip, geoip_sha) = artifact(dir, "geoip.dat", b"ip");
    let (geosite, mut geosite_sha) = artifact(dir, "geosite.dat", b"site");
    if setup.bad_digest {
        geosite_sha = "0".repeat(64);
    }
    let mut options = Options::new(dir.join("state"));
    options.warp_url = setup.warp.map(str::to_string);
    options.ingress_files =
        [("naive".to_string(), secrets.join("naive")), ("mieru".to_string(), secrets.join("mieru"))].into();
    options.artifacts = vec![
        ("xray".into(), xray, xray_sha),
        ("geoip".into(), geoip, geoip_sha),
        ("geosite".into(), geosite, geosite_sha),
    ];
    options.ports = Some([("naive".to_string(), 45101), ("mieru".to_string(), 45102)].into());
    if setup.mtproxy {
        std::fs::create_dir_all(dir.join("run")).unwrap();
        options.mtproxy_socket = Some(dir.join("run/ingress-mtproxy.sock"));
    }
    if setup.trusttunnel {
        options.trusttunnel_port = Some(TRUSTTUNNEL_PORT);
    }
    if let Some(device) = setup.amneziawg {
        let net = dir.join("net");
        std::fs::create_dir_all(&net).unwrap();
        if device {
            std::fs::create_dir_all(net.join("awgxr")).unwrap();
            std::fs::write(net.join("awgxr/ifindex"), "41\n").unwrap();
        }
        options.amneziawg_tun = Some("awgxr".into());
        options.net_root = net;
    }
    let mut manager = XrayRouterManager::new(options, Arc::new(runner.clone()));
    let reachable = setup.reachable;
    manager.reachability = Box::new(move |_, _| reachable);
    let calls = registrations.clone();
    manager.warp_opener = Box::new(move |method, _url, _headers, _body| {
        calls.lock().unwrap().push(method.to_string());
        Ok((
            200,
            Some(json!({"id": "d1", "token": "t1", "account": {"account_type": "free"}, "config": {
            "interface": {"addresses": {"v4": "172.16.0.2"}},
            "peers": [{"public_key": crate::warp::tests::peer(), "endpoint": {"v4": "162.159.192.5:0"}}]}})),
        ))
    });
    manager
}

struct H {
    dir: PathBuf,
    manager: Arc<XrayRouterManager>,
    runner: FakeRunner,
    registrations: Registrations,
}

impl H {
    fn state(&self) -> Value {
        read_json(&self.dir.join("state/state.json"))
    }

    fn revision(&self, service: &str) -> Value {
        self.manager.egress(service).unwrap()["revision"].clone()
    }

    fn apply(&self, service: &str, document: Value, op: &str) -> crate::errors::Result<Value> {
        self.manager.egress_apply(service, &self.revision(service), &document, &json!(op))
    }

    fn generation(&self) -> Value {
        self.manager.status().unwrap()["running"]["generation"].clone()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join("state").join(name)
    }

    /// Another manager over the same directory, as after a restart of the container.
    fn again(&self, setup: &Setup) -> H {
        make_in(&self.dir, setup, FakeRunner::default(), |_| {})
    }
}

fn make_in(dir: &Path, setup: &Setup, runner: FakeRunner, tweak: impl FnOnce(&mut XrayRouterManager)) -> H {
    let registrations: Registrations = Arc::default();
    let mut manager = build(dir, &runner, setup, &registrations);
    tweak(&mut manager);
    H { dir: dir.to_path_buf(), manager: Arc::new(manager), runner, registrations }
}

fn make(name: &str, setup: &Setup) -> H {
    make_in(&tempdir(name), setup, FakeRunner::default(), |_| {})
}

fn booted(name: &str, setup: &Setup) -> H {
    let h = make(name, setup);
    h.manager.bootstrap().unwrap();
    h
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn mode_of(path: &Path) -> u32 {
    std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(path).unwrap().permissions()) & 0o777
}

fn inbound(config: &Value, tag: &str) -> Option<Value> {
    config["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == tag).cloned()
}

fn outbound_tags(config: &Value) -> Vec<String> {
    config["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap().to_string()).collect()
}

fn rules_of(config: &Value, tag: &str) -> Vec<Value> {
    config["routing"]["rules"].as_array().unwrap().iter().filter(|r| r["inboundTag"] == json!([tag])).cloned().collect()
}

fn code_of(result: crate::errors::Result<Value>) -> String {
    result.unwrap_err().code().unwrap_or("").to_string()
}

fn text(value: &Value) -> String {
    value.to_string()
}

// ---------------------------------------------------------------- generations

#[test]
fn bootstrap_verifies_artifacts_and_starts_generation_1_direct() {
    let h = booted("boot", &Setup::default());
    assert_eq!(h.runner.calls()[..3], ["test 1.json", "start 1.json", "ready 45101,45102"]);
    let status = h.manager.status().unwrap();
    assert_eq!((&status["running"]["generation"], &status["phase"]), (&json!(1), &json!("idle")));
    assert!(status["artifacts"].as_object().unwrap().values().all(|entry| entry["verified"] == true));
    assert!(status["xray_version"].as_str().unwrap().starts_with("Xray 26.3.27"));
    assert_eq!(status["services"]["naive"]["document"], direct_document());
    assert_eq!(mode_of(&h.file("generations/1.json")), 0o600);
    let config = h.runner.running_config();
    assert_eq!(
        config["inbounds"][0]["settings"]["accounts"],
        json!([{"user": "naive-a1b2c3d4", "pass": "N".repeat(40)}])
    );
    assert_eq!(outbound_tags(&config), ["block", "direct"]);
}

#[test]
fn bootstrap_artifact_mismatch_refuses_to_start() {
    let h = make("mismatch", &Setup { bad_digest: true, ..Setup::default() });
    let err = h.manager.bootstrap().unwrap_err();
    assert!(matches!(&err, Error::ArtifactMismatch(message) if message.contains("geosite")));
    assert!(h.runner.calls().is_empty());
    let status = h.manager.status().unwrap();
    assert!(status["artifact_error"].as_str().is_some());
    assert_eq!(status["artifacts"]["geosite"]["verified"], false);
}

#[test]
fn egress_plan_runs_test_without_mutation() {
    let h = booted("plan", &Setup::default());
    let list = |h: &H| {
        let mut names: Vec<String> = std::fs::read_dir(h.file("generations"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let before = list(&h);
    let revision = h.revision("naive");
    let plan = h.manager.egress_plan("naive", &revision, &warp_doc()).unwrap();
    assert_eq!(h.runner.calls().last().unwrap(), "test .plan.json");
    assert_eq!(list(&h), before);
    assert!(!h.file(".plan.json").exists());
    assert!(plan["revision"] == revision && plan["target_revision"] != revision);
    assert_eq!((&plan["reachability"], &plan["restart_required"]), (&json!({"warp": true}), &json!(true)));
    assert!(plan["diff"]
        .as_array()
        .unwrap()
        .iter()
        .any(|line| line.as_str().unwrap().contains("\"action\": \"egress\"")));
    assert_eq!(h.generation(), 1);
}

#[test]
fn apply_renders_tests_swaps_and_commits() {
    let h = booted("apply", &Setup::default());
    let revision = h.revision("naive");
    let result = h.manager.egress_apply("naive", &revision, &warp_doc(), &json!("routing:p1:1")).unwrap();
    let calls = h.runner.calls();
    assert_eq!(calls[calls.len() - 4..], ["test 2.json", "stop 1.json", "start 2.json", "ready 45101,45102"]);
    assert_eq!(
        (&result["generation"], &result["applied"], &result["replayed"]),
        (&json!(2), &warp_doc(), &json!(false))
    );
    let current = read_json(&h.file("current.json"));
    assert!(current["generation"] == 2 && result["readback_sha256"] == current["digest"]);
    assert_eq!(result["readback_sha256"], sha256_hex(&std::fs::read(h.file("generations/2.json")).unwrap()));
    let view = h.manager.egress("naive").unwrap();
    assert!(view["document"] == warp_doc() && view["mode"] == "proxy" && view["revision"] == result["revision"]);
    assert!(view["previous"]["revision"] == revision && view["current"]["operation_id"] == "routing:p1:1");
    assert_eq!(outbound_tags(&h.runner.running_config()), ["block", "direct", "warp"]);
    assert_eq!(h.state()["phase"], "idle");
}

#[test]
fn apply_conflict_on_stale_revision() {
    let h = booted("stale", &Setup::default());
    let result = h.manager.egress_apply("naive", &json!("0".repeat(64)), &warp_doc(), &json!("op-1"));
    assert_eq!(code_of(result), "egress_conflict");
    assert_eq!(h.generation(), 1);
    assert_eq!(h.runner.calls().last().unwrap(), "ready 45101,45102");
}

#[test]
fn apply_idempotent_by_operation_id() {
    let h = booted("idem", &Setup::default());
    let first = h.apply("naive", warp_doc(), "op-same").unwrap();
    let calls = h.runner.calls().len();
    let again =
        h.manager.egress_apply("naive", &json!("stale-does-not-matter"), &warp_doc(), &json!("op-same")).unwrap();
    assert!(again["replayed"] == true && again["revision"] == first["revision"] && h.runner.calls().len() == calls);
    let conflict = h.manager.egress_apply("naive", &first["revision"], &block_doc(), &json!("op-same"));
    assert_eq!(code_of(conflict), "operation_conflict");
}

#[test]
fn apply_unreachable_warp_refuses_without_changes() {
    let h = booted("unreachable", &Setup { reachable: false, ..Setup::default() });
    let calls = h.runner.calls().len();
    assert!(matches!(h.apply("naive", warp_doc(), "op-1"), Err(Error::EgressUnreachable(_))));
    assert_eq!((h.runner.calls().len(), h.generation()), (calls, json!(1)));
    // A document that does not use warp still applies.
    h.apply("naive", block_doc(), "op-2").unwrap();
    assert_eq!(h.generation(), 2);
}

#[test]
fn apply_without_warp_provider_is_invalid() {
    let h = booted("nowarp", &Setup { warp: None, ..Setup::default() });
    let err = h.apply("naive", warp_doc(), "op-1").unwrap_err();
    assert!(matches!(&err, Error::EgressInvalid { message, .. } if message.contains("warp")));
    assert_eq!(h.manager.status().unwrap()["providers"], json!({}));
}

#[test]
fn apply_test_failure_reports_geosite_unknown_and_keeps_generation() {
    let h = booted("unknown", &Setup::default());
    h.runner.get().fail_test =
        Some("infra/conf: failed to load geosite: NOPE > infra/conf: code not found in geosite.dat: NOPE".into());
    assert_eq!(code_of(h.apply("naive", block_doc(), "op-1")), "geosite_unknown");
    assert!(!h.file("generations/2.json").exists());
    assert_eq!(h.generation(), 1);
    assert_eq!(h.runner.running().unwrap().1, "1.json");
    h.runner.get().fail_test = Some("code not found in geoip.dat: ZZ".into());
    assert_eq!(code_of(h.manager.egress_plan("naive", &h.revision("naive"), &block_doc())), "geoip_unknown");
}

#[test]
fn apply_ready_failure_restores_last_known_good() {
    let h = booted("lkg", &Setup::default());
    h.runner.get().fail_ready = 1;
    let err = h.apply("naive", block_doc(), "op-1").unwrap_err();
    assert!(matches!(&err, Error::Xray(message) if message.contains("restored")));
    assert_eq!(h.runner.running().unwrap().1, "1.json");
    assert!(!h.file("generations/2.json").exists());
    assert_eq!((h.generation(), h.state()["phase"].clone()), (json!(1), json!("idle")));
    assert_eq!(h.manager.egress("naive").unwrap()["document"], direct_document());
}

#[test]
fn apply_lkg_failure_is_manual_intervention_and_broken_phase() {
    let h = booted("broken", &Setup::default());
    h.runner.get().fail_ready = 2;
    let err = h.apply("naive", block_doc(), "op-1").unwrap_err();
    assert!(matches!(&err, Error::Manual(message) if message.contains("1.json")));
    assert_eq!(
        (h.state()["phase"].clone(), h.manager.status().unwrap()["running"].clone()),
        (json!("broken"), Value::Null)
    );
    assert!(matches!(h.apply("naive", block_doc(), "op-2"), Err(Error::Manual(_))));
    // The watchdog does not fight a broken router; a restart of the manager tries again.
    h.manager.watchdog_tick().unwrap();
    assert!(h.manager.status().unwrap()["running"].is_null());
    let fresh = h.again(&Setup::default());
    fresh.manager.bootstrap().unwrap();
    assert_eq!((fresh.generation(), fresh.state()["phase"].clone()), (json!(1), json!("idle")));
}

#[test]
fn other_service_intent_survives_apply() {
    let h = booted("survives", &Setup::default());
    h.apply("mieru", warp_doc(), "op-m").unwrap();
    let mieru_before = h.manager.egress("mieru").unwrap();
    h.apply("naive", block_doc(), "op-n").unwrap();
    let mieru_after = h.manager.egress("mieru").unwrap();
    assert!(mieru_after["document"] == warp_doc() && mieru_after["previous"] == mieru_before["previous"]);
    assert_ne!(mieru_after["revision"], mieru_before["revision"]); // a new generation, the same document
    let config = h.runner.running_config();
    assert_eq!(rules_of(&config, "mieru").last().unwrap()["outboundTag"], "warp");
    assert!(rules_of(&config, "naive").iter().any(|r| r["domain"] == json!(["domain:example.com"])));
}

#[test]
fn rollback_pops_journal_and_creates_new_generation() {
    let h = booted("rollback", &Setup::default());
    h.apply("naive", warp_doc(), "op-1").unwrap();
    h.apply("naive", block_doc(), "op-2").unwrap();
    let rolled = h.manager.egress_rollback("naive", &h.revision("naive")).unwrap();
    assert!(rolled["applied"] == warp_doc() && rolled["generation"] == 4);
    let view = h.manager.egress("naive").unwrap();
    assert!(view["document"] == warp_doc() && !view["previous"]["revision"].is_null());
    let rolled = h.manager.egress_rollback("naive", &view["revision"]).unwrap();
    assert!(rolled["applied"] == direct_document() && h.manager.egress("naive").unwrap()["previous"].is_null());
    assert_eq!(code_of(h.manager.egress_rollback("naive", &h.revision("naive"))), "egress_no_previous");
    assert_eq!(h.runner.running().unwrap().1, "5.json");
}

#[test]
fn rollback_conflict_on_stale_revision() {
    let h = booted("rollback-stale", &Setup::default());
    assert_eq!(code_of(h.manager.egress_rollback("naive", &json!("nope"))), "egress_conflict");
}

#[test]
fn recover_after_crash_in_swapping_discards_candidate() {
    let h = booted("recover", &Setup::default());
    // A crash after generation 2 was written and the phase recorded, before the commit.
    std::fs::write(h.file("generations/2.json"), "{}").unwrap();
    std::fs::write(h.file("state.json"), r#"{"phase": "swapping", "candidate": 2, "failures": 0}"#).unwrap();
    let fresh = h.again(&Setup::default());
    fresh.manager.bootstrap().unwrap();
    assert!(!h.file("generations/2.json").exists());
    assert_eq!((fresh.generation(), fresh.state()["phase"].clone()), (json!(1), json!("idle")));
    let calls = fresh.runner.calls();
    assert_eq!(calls[calls.len() - 2..], ["start 1.json", "ready 45101,45102"]);
}

#[test]
fn watchdog_restarts_dead_process() {
    let h = booted("watchdog", &Setup::default());
    h.runner.kill_running();
    assert!(h.manager.status().unwrap()["running"].is_null());
    h.manager.watchdog_tick().unwrap();
    assert_eq!(h.generation(), 1);
    let calls = h.runner.calls();
    assert!(calls[calls.len() - 2].starts_with("start"));
    let count = h.runner.calls().len();
    h.manager.watchdog_tick().unwrap();
    assert_eq!(h.runner.calls().len(), count); // alive: nothing to do
    h.runner.kill_running();
    h.runner.get().fail_ready = 3;
    for _ in 0..3 {
        h.manager.watchdog_tick().unwrap();
    }
    assert_eq!(h.state()["phase"], "broken");
    h.manager.watchdog_tick().unwrap();
    assert!(h.manager.status().unwrap()["running"].is_null());
}

#[test]
fn status_and_egress_views_have_no_credentials() {
    let h = booted("secret-free", &Setup::default());
    h.apply("naive", warp_doc(), "op-1").unwrap();
    let revision = h.revision("naive");
    let texts = [
        text(&h.manager.status().unwrap()),
        text(&h.manager.egress("naive").unwrap()),
        text(&h.manager.egress("mieru").unwrap()),
        text(&h.manager.egress_plan("naive", &revision, &block_doc()).unwrap()),
    ];
    for text in texts {
        assert!(!text.contains(&"N".repeat(40)) && !text.contains(&"M".repeat(40)) && !text.contains("naive-a1b2c3d4"));
    }
    assert!(!std::fs::read_to_string(h.file("journal.json")).unwrap().contains(&"N".repeat(40)));
    assert!(!std::fs::read_to_string(h.file("current.json")).unwrap().contains(&"N".repeat(40)));
    assert!(std::fs::read_to_string(h.file("generations/1.json")).unwrap().contains(&"N".repeat(40)));
}

#[test]
fn credential_files_reread_on_bootstrap() {
    let h = booted("reread", &Setup::default());
    h.apply("naive", block_doc(), "op-1").unwrap();
    let fresh = h.again(&Setup::default());
    std::fs::write(h.dir.join("secrets/naive"), format!("naive-a1b2c3d4:{}\n", "R".repeat(40))).unwrap(); // rotated before the restart
    fresh.manager.bootstrap().unwrap();
    assert_eq!(fresh.generation(), 3);
    assert_eq!(fresh.runner.running_config()["inbounds"][0]["settings"]["accounts"][0]["pass"], "R".repeat(40));
    // The intents survive the re-render, the journal keeps its history.
    assert_eq!(fresh.manager.egress("naive").unwrap()["document"]["rules"][0]["domains"], json!(["example.com"]));
    assert!(!fresh.manager.egress("naive").unwrap()["previous"].is_null());
    // Unchanged files: the same generation starts again, no new one.
    let again = h.again(&Setup::default());
    again.manager.bootstrap().unwrap();
    assert_eq!((again.generation(), again.runner.calls()[0].clone()), (json!(3), "start 3.json".to_string()));
}

#[test]
fn malformed_credential_is_manual_intervention() {
    let h = make("malformed", &Setup::default());
    std::fs::write(h.dir.join("secrets/naive"), "no colon here\n").unwrap();
    assert!(matches!(h.manager.bootstrap(), Err(Error::Manual(message)) if message.contains("malformed")));
}

#[test]
fn unknown_service_and_bad_operation_id_are_validation_errors() {
    let h = booted("validation", &Setup::default());
    assert!(matches!(h.manager.egress("mtproxy"), Err(Error::Validation(_))));
    let bad = h.manager.egress_apply("naive", &h.revision("naive"), &block_doc(), &json!("bad id with spaces"));
    assert!(matches!(bad, Err(Error::Validation(_))));
}

// ---------------------------------------------------------------- v0.7: lanes, relay, chains

fn lanes_doc(lane_default: Value, chains: Value) -> Value {
    json!({"schema": 2, "lanes": {"grant:7f3a": {"default": lane_default, "rules": []},
                                  "svc:naive": {"default": {"action": "direct", "egress": null}, "rules": []}},
           "chains": chains})
}

fn naive_accounts(h: &H) -> Value {
    inbound(&h.runner.running_config(), "naive").unwrap()["settings"]["accounts"].clone()
}

#[test]
fn lane_issue_puts_the_account_on_the_ingress_at_once_and_never_shows_it_again() {
    let h = booted("lanes", &Setup::default());
    let before = h.generation().as_i64().unwrap();
    let issued = h.manager.lane_issue("naive", &json!("grant:7f3a")).unwrap();
    let password = issued["password"].as_str().unwrap().to_string();
    assert!(issued["user"] == "grant-7f3a" && password.len() >= 32);
    // a new generation carries the account; the service intents are untouched
    assert!(naive_accounts(&h).as_array().unwrap().contains(&json!({"user": "grant-7f3a", "pass": password})));
    assert_eq!(h.generation(), before + 1);
    assert_eq!(h.manager.status().unwrap()["lanes"], json!({"naive": ["grant:7f3a"], "mieru": []}));
    assert!(!text(&h.manager.status().unwrap()).contains(&password));
    let lanes_file = h.file("lanes.json");
    assert!(mode_of(&lanes_file) == 0o600 && std::fs::read_to_string(&lanes_file).unwrap().contains(&password));
    // re-issuing rotates the password; the old one leaves the ingress
    let rotated = h.manager.lane_issue("naive", &json!("grant:7f3a")).unwrap();
    assert_ne!(rotated["password"], issued["password"]);
    let accounts = naive_accounts(&h);
    assert!(accounts.as_array().unwrap().contains(&json!({"user": "grant-7f3a", "pass": rotated["password"]})));
    assert!(!text(&accounts).contains(&password));
    // forgetting removes the account and refuses a lane the intent still names
    h.manager.lane_forget("naive", "grant:7f3a").unwrap();
    assert_eq!(h.manager.status().unwrap()["lanes"]["naive"], json!([]));
    assert!(naive_accounts(&h).as_array().unwrap().iter().all(|account| account["user"] != "grant-7f3a"));
    let err =
        h.apply("naive", lanes_doc(json!({"action": "direct", "egress": null}), json!({})), "op-lane").unwrap_err();
    assert!(matches!(&err, Error::EgressInvalid { message, .. } if message.contains("lane")));
    for bad in ["svc:naive", "grant:", "grant:has space", "mieru"] {
        assert!(
            matches!(
                h.manager.lane_issue("naive", &json!(bad)),
                Err(Error::Validation(_) | Error::EgressInvalid { .. })
            ),
            "{bad}"
        );
    }
}

#[test]
fn lane_intent_applies_with_the_lane_account_and_the_views_stay_secret_free() {
    let h = booted("lane-intent", &Setup::default());
    let issued = h.manager.lane_issue("naive", &json!("grant:7f3a")).unwrap();
    let result =
        h.apply("naive", lanes_doc(json!({"action": "egress", "egress": "warp"}), json!({})), "op-lane").unwrap();
    let lanes: Vec<&String> = result["applied"]["lanes"].as_object().unwrap().keys().collect();
    assert!(result["applied"]["schema"] == 2 && lanes == ["grant:7f3a", "svc:naive"]);
    let config = h.runner.running_config();
    let rules: Vec<Value> =
        rules_of(&config, "naive").into_iter().filter(|r| r.get("ip").is_none() && r.get("domain").is_none()).collect();
    assert_eq!(rules[0], json!({"inboundTag": ["naive"], "user": ["grant-7f3a"], "outboundTag": "warp"}));
    assert_eq!(rules[1], json!({"inboundTag": ["naive"], "outboundTag": "direct"}));
    assert!(!text(&h.manager.egress("naive").unwrap()).contains(issued["password"].as_str().unwrap()));
}

/// The lab caught the router crash-looping at start: `lane_forget` had written lanes.json without
/// the account while the running intent still named the lane, and every render since refused it.
/// The forget now strips the lane (and the chains only it used) from the intent it commits; the
/// file changes only with a successful swap, and a restart with a stale intent strips the same way.
#[test]
fn forgetting_a_lane_the_intent_still_names_drops_its_rules_in_the_same_generation() {
    let reachable_hops = |m: &mut XrayRouterManager| m.hop_reachability = Box::new(|_, _, _, _| true);
    let h = make_in(&tempdir("forget"), &Setup::default(), FakeRunner::default(), reachable_hops);
    h.manager.bootstrap().unwrap();
    h.manager.lane_issue("naive", &json!("grant:7f3a")).unwrap();
    let chain = json!({"c1": {"hops": [with(&hop(), json!({"address": "panel.b.example", "server_name": "panel.b.example"}))], "exit": "direct"}});
    h.apply("naive", lanes_doc(json!({"action": "egress", "egress": "chain:c1"}), chain), "op-lane").unwrap();
    let generation = h.generation().as_i64().unwrap();
    h.manager.lane_forget("naive", "grant:7f3a").unwrap();
    assert_eq!(h.generation(), generation + 1);
    let running = h.runner.running_config();
    assert!(running["routing"]["rules"].as_array().unwrap().iter().all(|rule| !text(rule).contains("grant-7f3a")));
    assert!(outbound_tags(&running).iter().all(|tag| !tag.starts_with("chain:")));
    let applied = h.manager.egress("naive").unwrap()["document"].clone();
    let lanes: Vec<&String> = applied["lanes"].as_object().unwrap().keys().collect();
    assert!(lanes == ["svc:naive"] && applied["chains"] == json!({}));
    // a running intent naming a lane whose account is gone from lanes.json (what the buggy forget
    // left behind): the next start strips the lane and commits instead of refusing to render
    h.manager.lane_issue("naive", &json!("grant:7f3a")).unwrap();
    h.apply("naive", lanes_doc(json!({"action": "egress", "egress": "warp"}), json!({})), "op-lane-2").unwrap();
    std::fs::write(h.file("lanes.json"), r#"{"naive": {}, "mieru": {}}"#).unwrap();
    let again = h.again(&Setup::default());
    again.manager.bootstrap().unwrap();
    let lanes: Vec<String> =
        again.manager.egress("naive").unwrap()["document"]["lanes"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(lanes, ["svc:naive"]);
    let status = again.manager.status().unwrap();
    assert!(status["phase"] == "idle" && status["running"]["generation"].as_i64().unwrap() > generation + 2);
    assert!(again.runner.running_config()["routing"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| !text(r).contains("grant-7f3a")));
    // a rollback to the entry that named the lane goes back without it, not to a refusal
    let rolled = again.manager.egress_rollback("naive", &again.revision("naive")).unwrap();
    let lanes: Vec<&String> = rolled["applied"]["lanes"].as_object().unwrap().keys().collect();
    assert!(lanes == ["svc:naive"] && again.manager.status().unwrap()["phase"] == "idle");
}

fn relay_inbound(h: &H) -> Option<Value> {
    inbound(&h.runner.running_config(), "relay")
}

#[test]
fn relay_enable_mints_a_keypair_once_listens_and_takes_accounts_from_the_central() {
    let h = booted("relay", &Setup::default());
    let view = h.manager.relay_enable(&json!("panel.node-a.example.org"), &json!(45443)).unwrap();
    assert_eq!(
        view,
        json!({"enabled": true, "port": 45443, "server_name": "panel.node-a.example.org", "public_key": PUBLIC_KEY,
               "short_ids": view["short_ids"], "accounts": 0, "emails": []})
    );
    assert!(view["short_ids"].as_array().unwrap().len() == 1 && view["short_ids"][0].as_str().unwrap().len() == 8);
    let relay_file = h.file("relay.json");
    assert!(mode_of(&relay_file) == 0o600 && std::fs::read_to_string(&relay_file).unwrap().contains(&private_key()));
    assert!(!text(&h.manager.status().unwrap()).contains(&private_key()) && !text(&view).contains(&private_key()));
    let relay = relay_inbound(&h).unwrap();
    assert!(relay["port"] == 45443 && relay["settings"]["clients"] == json!([]));
    assert_eq!(relay["streamSettings"]["realitySettings"]["serverNames"], json!(["panel.node-a.example.org"]));
    // a second enable keeps the keypair (the peers already trust it) but may move the port
    let again = h.manager.relay_enable(&json!("panel.node-a.example.org"), &json!(45444)).unwrap();
    assert!(again["public_key"] == view["public_key"] && again["port"] == 45444 && h.runner.get().x25519_calls == 1);
    // accounts arrive from the central and replace the previous set
    let c = "c".repeat(32);
    let accounts = json!([{"email": format!("relay:{c}:direct"), "uuid": hop()["uuid"]},
                          {"email": format!("relay:{c}:warp"), "uuid": "9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e"}]);
    assert_eq!(h.manager.relay_set_accounts(&accounts).unwrap()["accounts"], 2);
    let emails: Vec<Value> = relay_inbound(&h).unwrap()["settings"]["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["email"].clone())
        .collect();
    assert_eq!(emails, [json!(format!("relay:{c}:direct")), json!(format!("relay:{c}:warp"))]);
    assert_eq!(
        h.manager.status().unwrap()["relay"],
        json!({"enabled": true, "port": 45444, "server_name": "panel.node-a.example.org", "public_key": PUBLIC_KEY,
               "short_ids": view["short_ids"], "accounts": 2, "emails": [format!("relay:{c}:direct"), format!("relay:{c}:warp")]})
    );
    assert!(!text(&h.manager.status().unwrap()).contains(hop()["uuid"].as_str().unwrap()));
    for bad in [
        json!([{"email": "nope", "uuid": hop()["uuid"]}]),
        json!([{"email": "relay:x:direct", "uuid": "bad"}]),
        json!([{"email": "relay:x:direct"}]),
    ] {
        assert!(matches!(h.manager.relay_set_accounts(&bad), Err(Error::Validation(_))));
    }
    // the view names the accounts the inbound carries (emails only, never a UUID)
    assert_eq!(h.manager.relay().unwrap()["emails"], json!([format!("relay:{c}:direct"), format!("relay:{c}:warp")]));
    // a node without WARP carries the direct accounts and sets the warp ones aside — the central
    // mints both per source, and a chain through this node's direct exit must still work
    let no_warp = booted("relay-nowarp", &Setup { warp: None, ..Setup::default() });
    no_warp.manager.relay_enable(&json!("panel.node-a.example.org"), &json!(45443)).unwrap();
    let carried = no_warp
        .manager
        .relay_set_accounts(&json!([{"email": "relay:x:warp", "uuid": hop()["uuid"]},
                                     {"email": "relay:x:direct", "uuid": "9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e"}]))
        .unwrap();
    assert!(carried["accounts"] == 1 && carried["emails"] == json!(["relay:x:direct"]));
    let clients = relay_inbound(&no_warp).unwrap()["settings"]["clients"].clone();
    assert_eq!(
        clients.as_array().unwrap().iter().map(|c| c["email"].clone()).collect::<Vec<_>>(),
        [json!("relay:x:direct")]
    );
    assert!(outbound_tags(&no_warp.runner.running_config()).iter().all(|tag| tag != "warp"));
    let mut expected = carried.clone();
    expected["accounts"] = json!(0);
    expected["emails"] = json!([]);
    assert_eq!(
        no_warp.manager.relay_set_accounts(&json!([{"email": "relay:x:warp", "uuid": hop()["uuid"]}])).unwrap(),
        expected
    );
    // disabling closes the inbound and keeps the keypair
    assert_eq!(h.manager.relay_disable().unwrap()["enabled"], false);
    assert!(relay_inbound(&h).is_none());
    assert_eq!(
        h.manager.relay_enable(&json!("panel.node-a.example.org"), &json!(45443)).unwrap()["public_key"],
        view["public_key"]
    );
}

#[test]
fn chain_apply_checks_every_hop_and_refuses_an_unreachable_one_before_changing_anything() {
    let hops = |m: &mut XrayRouterManager| {
        m.hop_reachability = Box::new(|address, port, _, _| match (address, port.as_i64()) {
            ("panel.node-b.example.org", Some(45443)) => true,
            ("203.0.113.7", Some(45443)) => false,
            other => panic!("unexpected hop {other:?}"),
        })
    };
    let h = make_in(&tempdir("chain"), &Setup::default(), FakeRunner::default(), hops);
    h.manager.bootstrap().unwrap();
    let revision = h.revision("naive");
    let good = json!({"schema": 2, "lanes": {"svc:naive": {"default": {"action": "egress", "egress": "chain:c1"}, "rules": []}},
                      "chains": {"c1": {"hops": [hop()], "exit": "warp"}}});
    let plan = h.manager.egress_plan("naive", &revision, &good).unwrap();
    assert_eq!(plan["reachability"], json!({"chain:c1:1": true}));
    let generation = h.generation().as_i64().unwrap();
    let second = with(&hop(), json!({"guid": "c".repeat(32), "address": "203.0.113.7"}));
    let bad = json!({"schema": 2, "lanes": {"svc:naive": {"default": {"action": "egress", "egress": "chain:c2"}, "rules": []}},
                     "chains": {"c2": {"hops": [hop(), second], "exit": "direct"}}});
    let err = h.manager.egress_apply("naive", &revision, &bad, &json!("op-bad")).unwrap_err();
    assert!(matches!(&err, Error::EgressUnreachable(message) if message.contains("chain c2 hop 2")));
    assert_eq!(h.generation(), generation);
    let applied = h.manager.egress_apply("naive", &revision, &good, &json!("op-good")).unwrap();
    assert_eq!(applied["applied"]["chains"]["c1"]["hops"][0]["uuid"], hop()["uuid"]);
    assert!(outbound_tags(&h.runner.running_config()).contains(&"chain:naive:c1:1".to_string()));
    // the hop credential lives in the generation file and nowhere the API shows
    let uuid = hop()["uuid"].as_str().unwrap().to_string();
    assert!(std::fs::read_to_string(h.file(&format!("generations/{}.json", generation + 1))).unwrap().contains(&uuid));
    for shown in [h.manager.egress("naive").unwrap(), h.manager.status().unwrap(), plan] {
        assert!(!text(&shown).contains(&uuid));
    }
    assert_eq!(h.manager.egress("naive").unwrap()["document"]["chains"]["c1"]["hops"][0]["uuid"], "***");
    let capabilities = h.manager.status().unwrap()["capabilities"].clone();
    assert!(["lanes", "chains", "relay"].iter().all(|c| capabilities.as_array().unwrap().contains(&json!(c))));
}

// ---------------------------------------------------------------- geodata (v0.8, v1.0.1)

#[test]
fn bootstrap_seeds_the_geodata_directory_from_the_pinned_pair() {
    let h = booted("seed", &Setup::default());
    let directory = h.file("geodata");
    assert_eq!(std::fs::read(directory.join("geosite.dat")).unwrap(), b"site");
    assert_eq!(std::fs::read(directory.join("geoip.dat")).unwrap(), b"ip");
    let view = h.manager.geodata_view();
    // v1.0.1: the seed is only what Xray starts on; the source is Loyalsoldier, kept fresh.
    assert!(view["origin"] == "seed" && view["source"]["kind"] == "loyalsoldier" && view["auto_update"] == true);
    assert!(view["interval_hours"] == 24 && view["update_hour"] == 2 && h.manager.geodata.due());
    assert_eq!(view["files"]["geosite"]["sha256"], sha256_hex(b"site"));
    assert_eq!(h.manager.status().unwrap()["geodata"]["origin"], "seed");
    // The seed is not copied again over an operator's files.
    std::fs::write(directory.join("geosite.dat"), b"mine").unwrap();
    h.manager.bootstrap().unwrap();
    assert_eq!(std::fs::read(directory.join("geosite.dat")).unwrap(), b"mine");
}

struct Loyal {
    h: H,
    publisher: Arc<Publisher>,
    site: Vec<u8>,
}

impl Loyal {
    fn fetcher(&self) -> Arc<Fetcher> {
        let publisher = self.publisher.clone();
        Arc::new(move |url: &str, max: usize| publisher.fetch(url, max))
    }

    fn update(&self) -> crate::errors::Result<Value> {
        let fetcher = self.fetcher();
        self.h.manager.geodata_update(Some(fetcher.as_ref()))
    }
}

fn loyal(name: &str) -> Loyal {
    let site = geodata_file(&["cn", "category-ads-all"]);
    let ip = geodata_file(&["cn", "ru"]);
    let urls = preset_urls("loyalsoldier").unwrap();
    let mut publisher = Publisher::new(&[(&urls.geosite, &site), (&urls.geoip, &ip)]);
    publisher.reported.insert(urls.geosite.clone(), "https://x/releases/download/v1/geosite.dat".into());
    let publisher = Arc::new(publisher);
    let fetch = publisher.clone();
    let h = make_in(&tempdir(name), &Setup::default(), FakeRunner::default(), move |m| {
        // What the watchdog's automatic update downloads with.
        m.fetcher = Arc::new(move |url: &str, max: usize| fetch.fetch(url, max));
    });
    h.manager.bootstrap().unwrap();
    h.manager.geodata_settings(json!({"source": {"kind": "loyalsoldier"}}).as_object().unwrap()).unwrap();
    Loyal { h, publisher, site }
}

#[test]
fn update_tests_the_running_config_against_the_candidates_then_swaps_and_restarts() {
    let l = loyal("geo-update");
    let before = l.h.runner.calls().len();
    let view = l.update().unwrap();
    assert!(view["changed"] == true && view["origin"] == "download" && view["version"] == "v1");
    assert_eq!(std::fs::read(l.h.file("geodata/geosite.dat")).unwrap(), l.site);
    assert!(view["files"]["geosite"]["codes"] == 2 && view["last_error"].is_null());
    // -test against the staged directory, then a stop and a fresh start of the same generation.
    let tail = l.h.runner.calls()[before..].to_vec();
    assert!(tail[0].starts_with("test 1.json geodata-test."), "{tail:?}");
    assert_eq!(tail[1..], ["stop 1.json", "start 1.json", "ready 45101,45102"]);
    assert_eq!(
        l.h.manager.geodata_codes()["codes"],
        json!({"geosite": ["category-ads-all", "cn"], "geoip": ["cn", "ru"]})
    );
    let leftovers: Vec<String> = std::fs::read_dir(l.h.file("geodata"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp") || name.starts_with("geodata-test."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    // The same files again: nothing changes, no restart.
    let calls = l.h.runner.calls().len();
    assert_eq!(l.update().unwrap()["changed"], false);
    assert_eq!(l.h.runner.calls().len(), calls);
}

#[test]
fn update_refuses_lists_the_running_config_does_not_compile_against() {
    let l = loyal("geo-refused");
    l.h.runner.get().fail_test = Some("geosite: code not found in geosite.dat: cn".into());
    let err = l.update().unwrap_err();
    assert!(err.to_string().contains("does not compile"));
    let view = l.h.manager.geodata_view();
    assert!(view["origin"] == "seed" && view["last_error"].as_str().unwrap().contains("geodata_rejected"));
    assert_eq!(std::fs::read(l.h.file("geodata/geosite.dat")).unwrap(), b"site");
    assert_eq!(l.h.runner.running().unwrap().1, "1.json");
}

#[test]
fn update_failures_are_recorded_and_leave_the_files_alone() {
    let l = loyal("geo-failure");
    let urls = preset_urls("loyalsoldier").unwrap();
    let broken = Publisher::new(&[(&urls.geosite, &l.site)]);
    let err = l.h.manager.geodata_update(Some(&move |url: &str, max: usize| broken.fetch(url, max))).unwrap_err();
    assert!(err.to_string().contains("404"));
    let view = l.h.manager.geodata_view();
    assert!(view["last_error"].as_str().unwrap().starts_with("geodata_fetch_failed") && view["origin"] == "seed");
    assert_eq!(l.update().unwrap()["changed"], true);
}

#[test]
fn automatic_updates_run_at_the_interval_from_the_watchdog() {
    let l = loyal("geo-auto");
    let now = Arc::new(Mutex::new(1_000_000.0));
    let clock = now.clone();
    l.h.manager.geodata.set_clock(Arc::new(move || *clock.lock().unwrap()));
    l.h.manager.geodata_settings(json!({"auto_update": true, "interval_hours": 6}).as_object().unwrap()).unwrap();
    assert!(l.h.manager.geodata.due());
    l.h.manager.watchdog_tick().unwrap();
    // v1.0.1: the download runs off the watchdog thread, which keeps restarting a dead Xray.
    l.h.manager.join_geodata_thread();
    assert_eq!(l.h.manager.geodata_view()["origin"], "download");
    assert!(!l.h.manager.geodata.due());
    *now.lock().unwrap() += 6.0 * 3600.0 - 1.0;
    assert!(!l.h.manager.geodata.due());
    *now.lock().unwrap() += 2.0;
    assert!(l.h.manager.geodata.due());
    // The seed source never phones anywhere.
    l.h.manager.geodata_settings(json!({"source": {"kind": "xray"}}).as_object().unwrap()).unwrap();
    assert!(!l.h.manager.geodata.due());
}

#[test]
fn restore_returns_to_the_pinned_pair_and_turns_auto_update_off() {
    let l = loyal("geo-restore");
    l.h.manager.geodata_settings(json!({"auto_update": true}).as_object().unwrap()).unwrap();
    l.update().unwrap();
    let view = l.h.manager.geodata_restore().unwrap();
    assert!(view["origin"] == "seed" && view["source"]["kind"] == "xray" && view["auto_update"] == false);
    assert_eq!(std::fs::read(l.h.file("geodata/geosite.dat")).unwrap(), b"site");
}

#[test]
fn settings_are_validated() {
    let h = booted("geo-settings", &Setup::default());
    let settings = |body: Value| h.manager.geodata_settings(body.as_object().unwrap());
    assert!(matches!(settings(json!({"interval_hours": 0})), Err(Error::Geodata { .. })));
    assert!(matches!(settings(json!({"auto_update": "yes"})), Err(Error::Geodata { .. })));
    let view = settings(json!({"source": {"kind": "custom", "geosite_url": "https://m.example/a.dat",
                                          "geoip_url": "https://m.example/b.dat"}, "interval_hours": 12}))
    .unwrap();
    assert!(view["source"]["geosite_url"] == "https://m.example/a.dat" && view["interval_hours"] == 12);
}

#[test]
fn concurrent_updates_are_refused() {
    let l = loyal("geo-busy");
    let manager = l.h.manager.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let urls = preset_urls("loyalsoldier").unwrap();
    let slow = Arc::new(move |url: &str, _max: usize| -> crate::errors::Result<(Vec<u8>, String)> {
        let _ = started_tx.send(());
        let _ = release_rx.lock().unwrap().recv_timeout(Duration::from_secs(10));
        Err(Error::geodata(format!("404 {url}"), "geodata_fetch_failed"))
    });
    let worker = std::thread::spawn(move || manager.geodata_update(Some(slow.as_ref())));
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let err = l.update().unwrap_err();
    assert!(err.to_string().contains("already running") && err.code() == Some("geodata_busy"));
    assert!(matches!(l.h.manager.geodata_restore(), Err(Error::Conflict { .. })));
    release_tx.send(()).unwrap();
    assert!(worker.join().unwrap().unwrap_err().to_string().contains(&urls.geosite));
}

#[test]
fn block_document_still_applies_after_an_update() {
    let l = loyal("geo-apply");
    l.update().unwrap();
    let result = l.h.apply("naive", block_doc(), "op-1").unwrap();
    assert_eq!(result["applied"]["rules"][0]["action"], "block");
    assert_eq!(read_json(&l.h.file("current.json"))["generation"], 2);
}

fn old_meta(directory: &Path, extra: Value) {
    std::fs::create_dir_all(directory).unwrap();
    let mut meta = json!({"source": {"kind": "xray", "geosite_url": null, "geoip_url": null}, "auto_update": false,
                          "interval_hours": 24, "origin": "seed", "version": null, "updated_at": "2026-09-19T12:47:00Z",
                          "last_check_at": null, "last_error": null, "files": {}});
    for (key, value) in extra.as_object().unwrap() {
        meta[key] = value.clone();
    }
    std::fs::write(directory.join("meta.json"), meta.to_string()).unwrap();
}

#[test]
fn a_pin_nobody_ever_chose_moves_to_loyalsoldier_but_a_chosen_one_stays() {
    let untouched = make("pin-untouched", &Setup::default());
    old_meta(&untouched.file("geodata"), json!({}));
    untouched.manager.bootstrap().unwrap();
    let view = untouched.manager.geodata_view();
    assert!(view["source"]["kind"] == "loyalsoldier" && view["auto_update"] == true);
    let chosen = make("pin-chosen", &Setup::default());
    // «Вернуть пин» leaves a check time behind: the owner's choice, kept.
    old_meta(&chosen.file("geodata"), json!({"last_check_at": 1_790_000_000.0}));
    chosen.manager.bootstrap().unwrap();
    let view = chosen.manager.geodata_view();
    assert!(view["source"]["kind"] == "xray" && view["auto_update"] == false);
}

#[test]
fn the_hour_is_a_setting_of_the_manager_api() {
    let h = booted("geo-hour", &Setup::default());
    let settings = |body: Value| h.manager.geodata_settings(body.as_object().unwrap());
    assert_eq!(settings(json!({"update_hour": 5})).unwrap()["update_hour"], 5);
    assert!(settings(json!({"update_hour": null})).unwrap()["update_hour"].is_null());
    assert!(matches!(settings(json!({"update_hour": "5"})), Err(Error::Geodata { .. })));
}

#[test]
fn a_router_that_does_not_come_back_after_the_swap_is_recorded() {
    let l = loyal("geo-restart");
    l.h.runner.get().fail_start = true;
    assert!(matches!(l.update(), Err(Error::Xray(_))));
    let view = l.h.manager.geodata_view();
    assert!(view["last_error"].as_str().unwrap().starts_with("geodata_restart_failed") && view["origin"] == "download");
}

// ---------------------------------------------------------------- exits (v0.8)

const EXIT_UUID: &str = "9d3b6b2c-1e6a-4b2a-9f0e-3c2f8a1d5e77";

fn socks_exit() -> Value {
    json!({"protocol": "socks", "address": "10.0.0.2", "port": 1080, "credential": {"username": "u", "password": "p"}})
}

fn vless_exit() -> Value {
    json!({"protocol": "vless", "address": "vpn.example.org", "port": 443, "credential": {"uuid": EXIT_UUID}, "flow": "xtls-rprx-vision",
           "transport": {"network": "tcp"}, "security": {"kind": "reality", "server_name": "www.example.com", "public_key": "a".repeat(43),
                                                         "short_id": "0123abcd", "fingerprint": "chrome"}})
}

fn trojan_ws_exit() -> Value {
    json!({"protocol": "trojan", "address": "t.example.org", "port": 8443, "credential": {"password": "pw"},
           "transport": {"network": "ws", "path": "/ws", "host": "t.example.org"}, "security": {"kind": "tls", "server_name": "t.example.org"}})
}

fn ss_exit() -> Value {
    json!({"protocol": "shadowsocks", "address": "203.0.113.5", "port": 8388, "credential": {"password": "pw"}, "method": "aes-256-gcm"})
}

fn exits_doc(exits: Value, egress: &str) -> Value {
    json!({"schema": 2, "chains": {}, "exits": exits,
           "lanes": {"svc:naive": {"default": {"action": "egress", "egress": egress},
                                   "rules": [{"domains": ["example.com"], "action": "direct"}]}}})
}

#[test]
fn validate_exit_normalises_every_protocol_and_refuses_the_impossible() {
    use crate::intent::validate_exit;
    let socks = validate_exit(&socks_exit()).unwrap();
    assert!(socks["transport"] == json!({"network": "tcp"}) && socks["security"] == json!({"kind": "none"}));
    let vless = validate_exit(&vless_exit()).unwrap();
    assert!(vless["security"]["public_key"] == "a".repeat(43) && vless["flow"] == "xtls-rprx-vision");
    assert_eq!(
        validate_exit(&trojan_ws_exit()).unwrap()["transport"],
        json!({"network": "ws", "path": "/ws", "host": "t.example.org"})
    );
    assert_eq!(validate_exit(&ss_exit()).unwrap()["method"], "aes-256-gcm");
    assert_eq!(validate_exit(&with(&socks_exit(), json!({"credential": {}}))).unwrap()["credential"], json!({}));
    for (broken, message) in [
        (with(&socks_exit(), json!({"protocol": "wireguard"})), "exit protocol"),
        (with(&socks_exit(), json!({"port": 70000})), "exit port"),
        (with(&socks_exit(), json!({"credential": {"username": "u"}})), "both username and password"),
        (with(&vless_exit(), json!({"credential": {"uuid": "nope"}})), "exit uuid"),
        (with(&vless_exit(), json!({"security": {"kind": "reality", "public_key": "a".repeat(43)}})), "server name"),
        (with(&ss_exit(), json!({"method": "rc4-md5"})), "shadowsocks method"),
        (with(&ss_exit(), json!({"transport": {"network": "ws"}})), "tcp only"),
        (
            with(
                &socks_exit(),
                json!({"security": {"kind": "reality", "server_name": "x.com", "public_key": "a".repeat(43)}}),
            ),
            "vless or trojan",
        ),
        (with(&vless_exit(), json!({"transport": {"network": "ws"}})), "xtls-rprx-vision needs tcp"),
        (with(&socks_exit(), json!({"extra": 1})), "invalid exit"),
        (with(&socks_exit(), json!({"address": "*.example.com"})), "exit address"),
    ] {
        let err = validate_exit(&broken).unwrap_err();
        assert!(err.to_string().contains(message), "{broken}: {err}");
    }
}

#[test]
fn the_intent_names_exits_and_a_rule_may_leave_through_one() {
    let document = validate_document(&exits_doc(json!({"e1": socks_exit()}), "exit:e1")).unwrap();
    assert!(
        document["exits"]["e1"]["protocol"] == "socks"
            && document["lanes"]["svc:naive"]["default"]["egress"] == "exit:e1"
    );
    let message = |doc: Value| validate_document(&doc).unwrap_err().to_string();
    assert!(message(exits_doc(json!({"e1": socks_exit()}), "exit:e2")).contains("egress provider"));
    assert!(message(exits_doc(json!({"bad id!": socks_exit()}), "exit:bad id!")).contains("exit id"));
    let many: Map<String, Value> = (0..17).map(|i| (format!("e{i}"), socks_exit())).collect();
    assert!(message(exits_doc(Value::Object(many), "exit:e1")).contains("exits list"));
    // Without exits the document is byte-for-byte what v0.7 produced.
    let plain = validate_document(&json!({"schema": 2, "chains": {}, "lanes": {"svc:naive": {"default": {"action": "direct", "egress": null}, "rules": []}}})).unwrap();
    assert!(plain.get("exits").is_none());
    assert!(crate::intent::CAPABILITIES.contains(&"custom_exits"));
}

#[test]
fn credentials_are_masked_in_the_redacted_intent() {
    let masked = crate::intent::redact_intent(
        &validate_document(&exits_doc(json!({"e1": vless_exit(), "e2": socks_exit()}), "exit:e1")).unwrap(),
    );
    assert_eq!(masked["exits"]["e1"]["credential"], json!({"uuid": "***"}));
    assert_eq!(masked["exits"]["e2"]["credential"], json!({"username": "***", "password": "***"}));
    assert!(!text(&masked).contains(EXIT_UUID) && !text(&masked).contains("\"p\""));
}

#[test]
fn exit_outbounds_render_the_way_xray_dials_them() {
    use crate::intent::validate_exit;
    use crate::render::exit_outbound;
    let socks = exit_outbound("x", &validate_exit(&socks_exit()).unwrap());
    assert!(
        socks["protocol"] == "socks" && socks["settings"]["servers"][0]["users"] == json!([{"user": "u", "pass": "p"}])
    );
    let vless = exit_outbound("x", &validate_exit(&vless_exit()).unwrap());
    assert_eq!(
        vless["settings"]["vnext"][0]["users"][0],
        json!({"id": EXIT_UUID, "encryption": "none", "flow": "xtls-rprx-vision"})
    );
    assert!(
        vless["streamSettings"]["security"] == "reality"
            && vless["streamSettings"]["realitySettings"]["publicKey"] == "a".repeat(43)
    );
    let trojan = exit_outbound("x", &validate_exit(&trojan_ws_exit()).unwrap());
    assert!(
        trojan["streamSettings"]["network"] == "ws"
            && trojan["streamSettings"]["wsSettings"] == json!({"path": "/ws", "host": "t.example.org"})
    );
    assert_eq!(trojan["streamSettings"]["tlsSettings"]["serverName"], "t.example.org");
    assert_eq!(
        exit_outbound("x", &validate_exit(&ss_exit()).unwrap())["settings"]["servers"][0]["method"],
        "aes-256-gcm"
    );
    let render = crate::render::RenderInput {
        intents: [(
            "naive".to_string(),
            validate_document(&exits_doc(json!({"e1": socks_exit()}), "exit:e1")).unwrap(),
        )]
        .into_iter()
        .collect(),
        ingresses: vec![
            Ingress::new("naive", 45101, "naive-a", &"N".repeat(40)),
            Ingress::new("mieru", 45102, "mieru-b", &"M".repeat(40)),
        ],
        ..Default::default()
    };
    let config = crate::render::render_config(&render).unwrap();
    assert!(outbound_tags(&config).contains(&"exit:naive:e1".to_string()));
    let catch_all: Vec<Value> =
        rules_of(&config, "naive").into_iter().filter(|r| r.get("domain").is_none() && r.get("ip").is_none()).collect();
    assert_eq!(catch_all.last().unwrap()["outboundTag"], "exit:naive:e1");
}

#[test]
fn exit_test_runs_a_throwaway_xray_and_reports_what_the_far_end_saw() {
    let seen = Arc::new(Mutex::new(None));
    let record = seen.clone();
    let prober = move |m: &mut XrayRouterManager| {
        m.exit_prober = Box::new(move |port, host, _timeout| {
            *record.lock().unwrap() = Some((port, host.to_string()));
            if port == 0 {
                return Err("never".into());
            }
            Ok(json!({"ip": "203.0.113.9", "colo": "AMS"}))
        })
    };
    let h = make_in(&tempdir("exit-test"), &Setup::default(), FakeRunner::default(), prober);
    h.manager.bootstrap().unwrap();
    let before = h.runner.calls().len();
    let result = h.manager.exit_test(&socks_exit()).unwrap();
    assert!(
        result["ok"] == true
            && result["ip"] == "203.0.113.9"
            && result["colo"] == "AMS"
            && result["latency_ms"].as_u64().is_some()
    );
    let keys: Vec<&String> = result.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["ok", "ip", "colo", "latency_ms"]);
    let tail = h.runner.calls()[before..].to_vec();
    let kinds: Vec<&str> = tail.iter().map(|call| call.split(' ').next().unwrap()).collect();
    assert_eq!(kinds, ["test", "start", "ready", "stop"]);
    assert_eq!(tail[0], "test exit-test.json");
    let (port, host) = seen.lock().unwrap().clone().unwrap();
    assert_eq!((host.as_str(), format!("ready {port}")), ("www.cloudflare.com", tail[2].clone()));
    assert!(!h.file("exit-test.json").exists());
    // The running router was never stopped.
    assert_eq!(h.runner.running().unwrap().1, "1.json");
    let probe =
        h.runner.get().handles.iter().find(|handle| name_of(&handle.path) == "exit-test.json").unwrap().config.clone();
    assert!(probe["inbounds"][0]["protocol"] == "dokodemo-door" && probe["outbounds"][0]["tag"] == "probe-exit");
}

#[test]
fn exit_test_reports_an_unreachable_or_refused_exit() {
    let failing = |m: &mut XrayRouterManager| m.exit_prober = Box::new(|_, _, _| Err("connection refused".into()));
    let h = make_in(&tempdir("exit-fail"), &Setup::default(), FakeRunner::default(), failing);
    h.manager.bootstrap().unwrap();
    let refused = h.manager.exit_test(&vless_exit()).unwrap();
    assert!(refused["ok"] == false && refused["code"] == "exit_unreachable");
    assert_eq!(refused["error"], "no answer through the exit: connection refused");
    h.runner.get().fail_test = Some("invalid outbound".into());
    assert_eq!(h.manager.exit_test(&ss_exit()).unwrap()["code"], "exit_invalid");
    assert!(matches!(h.manager.exit_test(&json!({"protocol": "socks"})), Err(Error::EgressInvalid { .. })));
}

// ---------------------------------------------------------------- TrustTunnel (v1.6)

fn trusttunnel() -> Setup {
    Setup { trusttunnel: true, ..Setup::default() }
}

#[test]
fn the_port_is_a_frozen_identifier_and_the_authenticated_ports_are_unchanged() {
    assert_eq!(TRUSTTUNNEL_PORT, 45104);
    assert_eq!(PORTS, [("naive", 45101), ("mieru", 45102)]);
}

#[test]
fn bootstrap_opens_a_noauth_socks_inbound_on_the_loopback() {
    let h = booted("tt-boot", &trusttunnel());
    let config = h.runner.running_config();
    let tt = inbound(&config, "trusttunnel").unwrap();
    assert!(tt["listen"] == "127.0.0.1" && tt["port"] == 45104 && tt["protocol"] == "socks");
    assert_eq!(tt["settings"], json!({"auth": "noauth", "udp": false}));
    assert_eq!(tt["sniffing"]["routeOnly"], true);
    assert!(h.runner.calls().contains(&"ready 45101,45102,45104".to_string()));
    assert_eq!(h.manager.status().unwrap()["services"]["trusttunnel"]["document"], direct_document());
    // the other ingresses keep their accounts
    assert_eq!(inbound(&config, "naive").unwrap()["settings"]["auth"], "password");
}

#[test]
fn without_the_port_the_router_serves_what_it_served_before() {
    let h = booted("tt-off", &Setup::default());
    let tags: Vec<Value> =
        h.runner.running_config()["inbounds"].as_array().unwrap().iter().map(|i| i["tag"].clone()).collect();
    assert_eq!(tags, [json!("naive"), json!("mieru")]);
    assert!(matches!(h.manager.egress("trusttunnel"), Err(Error::Validation(_))));
}

#[test]
fn a_policy_for_trusttunnel_routes_only_its_own_inbound() {
    let h = booted("tt-policy", &trusttunnel());
    h.apply("trusttunnel", block_doc(), "op-1").unwrap();
    let mine: Vec<Value> = rules_of(&h.runner.running_config(), "trusttunnel")
        .into_iter()
        .filter(|r| r["outboundTag"] == "block")
        .collect();
    assert!(mine.iter().any(|rule| rule["domain"] == json!(["domain:example.com"])));
    assert_eq!(h.manager.egress("naive").unwrap()["document"], direct_document());
}

#[test]
fn warp_for_trusttunnel_needs_the_warp_provider_like_any_service() {
    let h = booted("tt-warp", &Setup { warp: None, ..trusttunnel() });
    let plan = h.manager.egress_plan("trusttunnel", &h.revision("trusttunnel"), &warp_doc());
    assert!(matches!(plan, Err(Error::EgressInvalid { .. })));
}

#[test]
fn trusttunnel_has_no_lanes() {
    let h = booted("tt-lanes", &trusttunnel());
    assert!(matches!(h.manager.lane_issue("trusttunnel", &json!("grant:abc")), Err(Error::Validation(_))));
}

#[test]
fn a_schema_two_document_may_name_the_trusttunnel_service_lane() {
    let document = json!({"schema": 2, "lanes": {"svc:trusttunnel": {"default": {"action": "direct", "egress": null}, "rules": []}}, "chains": {}});
    let lanes: Vec<String> =
        validate_document(&document).unwrap()["lanes"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(lanes, ["svc:trusttunnel"]);
}

#[test]
fn render_config_without_an_account_for_trusttunnel() {
    let render = crate::render::RenderInput {
        ingresses: vec![Ingress::new("trusttunnel", 45104, "", "")],
        ports: Some([("trusttunnel".to_string(), 45104)].into()),
        ..Default::default()
    };
    let config = crate::render::render_config(&render).unwrap();
    assert_eq!(inbound(&config, "trusttunnel").unwrap()["settings"], json!({"auth": "noauth", "udp": false}));
    assert!(config["routing"]["rules"]
        .as_array()
        .unwrap()
        .contains(&json!({"inboundTag": ["trusttunnel"], "outboundTag": "direct"})));
}

#[test]
fn the_environment_enables_the_ingress() {
    let dir = tempdir("tt-env");
    let mut env: HashMap<String, String> = [
        ("XRAY_ROUTER_BIN_DIR", dir.display().to_string()),
        ("XRAY_ROUTER_XRAY_SHA256", "0".repeat(64)),
        ("XRAY_ROUTER_GEOIP_SHA256", "0".repeat(64)),
        ("XRAY_ROUTER_GEOSITE_SHA256", "0".repeat(64)),
        ("XRAY_ROUTER_STATE_DIR", dir.join("state").display().to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let off = crate::build_manager(&env).unwrap();
    assert!(!off.services.contains(&"trusttunnel"));
    env.insert("XRAY_ROUTER_PORT_TRUSTTUNNEL".into(), "45104".into());
    let on = crate::build_manager(&env).unwrap();
    assert!(on.services.contains(&"trusttunnel") && on.ports["trusttunnel"] == 45104);
    // what the Python entry point refused, refused the same way
    env.remove("XRAY_ROUTER_XRAY_SHA256");
    assert_eq!(crate::build_manager(&env).err().unwrap(), "XRAY_ROUTER_XRAY_SHA256 is required");
    env.insert("XRAY_ROUTER_XRAY_SHA256".into(), "  ".into());
    assert_eq!(crate::build_manager(&env).err().unwrap(), "XRAY_ROUTER_XRAY_SHA256 is required");
    // the defaults: the MTProxy socket and the shipped paths
    env.insert("XRAY_ROUTER_XRAY_SHA256".into(), "0".repeat(64));
    let defaults = crate::build_manager(&env).unwrap();
    assert_eq!(defaults.mtproxy_socket.as_deref(), Some(Path::new("/run/xray-router/ingress-mtproxy.sock")));
    assert_eq!(defaults.ingress_files["naive"], PathBuf::from("/run/secrets/xray-router-ingress-naive"));
    assert!(defaults.amneziawg_tun.is_none() && defaults.warp_url.is_none());
}

// ---------------------------------------------------------------- AmneziaWG (v3.0.0)

fn amneziawg(device: bool) -> Setup {
    Setup { amneziawg: Some(device), ..Setup::default() }
}

fn mixed_doc() -> Value {
    json!({"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": [{"domains": ["cloudflare.com"], "action": "direct"}]})
}

fn warp_account() -> Value {
    json!({"id": "d1", "token": "t1", "private_key": format!("{}=", "B".repeat(43)), "address": "172.16.0.2",
           "peer_public_key": crate::warp::tests::peer(), "endpoint": "162.159.192.5:2408"})
}

#[test]
fn amneziawg_is_a_tun_service_without_lanes() {
    assert!(
        crate::intent::TUN_SERVICES.contains(&"amneziawg") && crate::intent::NO_LANE_SERVICES.contains(&"amneziawg")
    );
}

#[test]
fn the_tun_inbound_and_the_warp_wireguard_outbound_render_and_redact() {
    let tun = Ingress { tag: "amneziawg".into(), tun: Some("awgxr".into()), ..Ingress::default() };
    let mut render = crate::render::RenderInput {
        intents: [("amneziawg".to_string(), validate_document(&mixed_doc()).unwrap())].into_iter().collect(),
        ingresses: vec![tun],
        warp_wg: Some(warp_account()),
        ..Default::default()
    };
    let config = crate::render::render_config(&render).unwrap();
    assert_eq!(
        inbound(&config, "amneziawg").unwrap(),
        json!({"tag": "amneziawg", "port": 0, "protocol": "tun", "settings": {"name": "awgxr", "mtu": 1280},
               "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}})
    );
    let wg = config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == crate::intent::WARP_WG_TAG)
        .unwrap()
        .clone();
    assert!(wg == crate::render::warp_wg_outbound(&warp_account()) && wg["settings"]["noKernelTun"] == true);
    assert!(!outbound_tags(&config).contains(&"warp".to_string())); // no SOCKS warp needed here
    let rules = rules_of(&config, "amneziawg");
    assert_eq!(rules.last().unwrap(), &json!({"inboundTag": ["amneziawg"], "outboundTag": crate::intent::WARP_WG_TAG}));
    assert!(rules.iter().any(|r| r["domain"] == json!(["domain:cloudflare.com"]) && r["outboundTag"] == "direct"));
    assert_eq!(
        crate::render::redact(&config)["outbounds"].as_array().unwrap().last().unwrap()["settings"]["secretKey"],
        "***"
    );
    render.warp_wg = None;
    assert_eq!(crate::render::render_config(&render).unwrap_err().code(), Some("egress_unreachable"));
}

#[test]
fn bootstrap_passes_the_device_and_registers_warp_only_when_used() {
    let h = booted("awg-boot", &amneziawg(true));
    let (config, _, tun) = h.runner.running().unwrap();
    assert!(tun.as_deref() == Some("awgxr") && inbound(&config, "amneziawg").unwrap()["protocol"] == "tun");
    let view = h.manager.egress("amneziawg").unwrap();
    assert_eq!(view["document"], direct_document());
    assert_eq!(view["tun"], json!({"device": "awgxr", "present": true, "attached": true, "warp_registered": false}));
    let keys: Vec<&String> = view.as_object().unwrap().keys().collect();
    assert_eq!(keys[0], "tun");
    h.apply("amneziawg", block_doc(), "op-1").unwrap();
    assert!(h.registrations.lock().unwrap().is_empty()); // no warp in the document: nothing registered
    h.apply("amneziawg", warp_doc(), "op-2").unwrap();
    assert_eq!(*h.registrations.lock().unwrap(), ["POST"]);
    assert_eq!(h.manager.egress("amneziawg").unwrap()["tun"]["warp_registered"], true);
    assert!(outbound_tags(&h.runner.running_config()).contains(&crate::intent::WARP_WG_TAG.to_string()));
    let stored = read_json(&h.file("warp-wg.json"));
    assert!(crate::warp::valid_account(&stored) && stored["private_key"] != private_key()); // standard base64
                                                                                            // another service's apply re-renders AmneziaWG with the same account, no second registration
    h.apply("naive", block_doc(), "op-3").unwrap();
    assert_eq!(*h.registrations.lock().unwrap(), ["POST"]);
    assert!(outbound_tags(&h.runner.running_config()).contains(&crate::intent::WARP_WG_TAG.to_string()));
}

#[test]
fn a_failed_registration_refuses_the_apply_and_changes_nothing() {
    let refusing = |m: &mut XrayRouterManager| m.warp_opener = Box::new(|_, _, _, _| Ok((403, None)));
    let h = make_in(&tempdir("awg-refused"), &amneziawg(true), FakeRunner::default(), refusing);
    h.manager.bootstrap().unwrap();
    let revision = h.revision("amneziawg");
    assert!(matches!(h.apply("amneziawg", warp_doc(), "op-1"), Err(Error::EgressUnreachable(_))));
    assert_eq!(h.revision("amneziawg"), revision);
}

#[test]
fn the_plan_works_before_any_registration() {
    let h = booted("awg-plan", &amneziawg(true));
    let plan = h.manager.egress_plan("amneziawg", &h.revision("amneziawg"), &warp_doc()).unwrap();
    assert_eq!(plan["reachability"], json!({"warp": null}));
    assert!(h.registrations.lock().unwrap().is_empty());
}

#[test]
fn without_the_device_nothing_of_it_renders_and_its_arrival_re_renders() {
    let h = booted("awg-device", &amneziawg(false));
    let (config, _, tun) = h.runner.running().unwrap();
    assert!(inbound(&config, "amneziawg").is_none() && tun.is_none());
    let net = h.dir.join("net");
    std::fs::create_dir_all(net.join("awgxr")).unwrap();
    std::fs::write(net.join("awgxr/ifindex"), "7\n").unwrap();
    h.manager.watchdog_tick().unwrap();
    let (config, _, tun) = h.runner.running().unwrap();
    assert!(tun.as_deref() == Some("awgxr") && inbound(&config, "amneziawg").is_some());
    // a device made anew (another ifindex) restarts Xray on it
    std::fs::write(net.join("awgxr/ifindex"), "8\n").unwrap();
    let starts = h.runner.get().handles.len();
    h.manager.watchdog_tick().unwrap();
    assert_eq!(h.runner.get().handles.len(), starts + 1);
    assert_eq!(h.runner.running().unwrap().2.as_deref(), Some("awgxr"));
    h.manager.watchdog_tick().unwrap();
    assert_eq!(h.runner.get().handles.len(), starts + 1); // settled
}

#[test]
fn the_router_without_the_device_name_serves_what_it_served_before() {
    let h = booted("awg-off", &Setup::default());
    assert!(h.manager.status().unwrap()["services"].get("amneziawg").is_none());
}

// ---------------------------------------------------------------- MTProxy (v1.1)

fn mtproxy() -> Setup {
    Setup { mtproxy: true, ..Setup::default() }
}

fn chain_doc() -> Value {
    json!({"schema": 2, "lanes": {"svc:mtproxy": {"default": {"action": "egress", "egress": "chain:b"}, "rules": []}},
           "chains": {"b": {"exit": "direct", "hops": [{
               "guid": "node-b", "address": "203.0.113.7", "port": 45443, "server_name": "panel.example.com",
               "public_key": "A".repeat(43), "short_id": "ab12", "uuid": "11111111-2222-4333-8444-555555555555"}]}}})
}

#[test]
fn bootstrap_mints_the_credential_and_listens_on_the_socket() {
    let h = booted("mt-boot", &mtproxy());
    let record = read_json(&h.file("ingress-mtproxy.json"));
    let mut keys: Vec<&String> = record.as_object().unwrap().keys().collect();
    keys.sort();
    assert!(keys == ["password", "username", "uuid"] && record["password"].as_str().unwrap().len() >= 32);
    assert_eq!(mode_of(&h.file("ingress-mtproxy.json")), 0o600);
    let socket = h.dir.join("run/ingress-mtproxy.sock");
    let bridge_copy = h.dir.join("run/ingress-mtproxy.json");
    assert!(read_json(&bridge_copy) == record && mode_of(&bridge_copy) == 0o600);
    assert!(h.runner.calls().contains(&format!("ready 45101,45102 {}", socket.display())));
    let mt = inbound(&h.runner.running_config(), "mtproxy").unwrap();
    assert!(mt["listen"] == socket.display().to_string() && mt["port"] == 0);
    assert!(mt["protocol"] == "vless" && mt["streamSettings"] == json!({"network": "raw"}));
    assert_eq!(mt["settings"]["clients"], json!([{"id": record["uuid"], "email": "mtproxy", "flow": ""}]));
    assert_eq!(h.manager.status().unwrap()["services"]["mtproxy"]["document"], direct_document());
}

#[test]
fn the_credential_survives_a_restart_and_the_panel_reads_the_bridge_address() {
    let h = booted("mt-restart", &mtproxy());
    let first = h.manager.ingress("mtproxy").unwrap();
    let again = h.again(&mtproxy());
    again.manager.bootstrap().unwrap();
    assert_eq!(again.manager.ingress("mtproxy").unwrap(), first);
    let keys: Vec<&String> = first.as_object().unwrap().keys().collect();
    assert!(first["address"] == crate::intent::MTPROXY_BRIDGE_ADDRESS && keys == ["address", "username", "password"]);
    assert!(matches!(h.manager.ingress("naive"), Err(Error::Validation(_))));
}

#[test]
fn a_malformed_credential_is_a_manual_intervention_not_a_new_one() {
    let h = make("mt-malformed", &mtproxy());
    std::fs::create_dir_all(h.dir.join("state")).unwrap();
    std::fs::write(h.file("ingress-mtproxy.json"), r#"{"uuid": "x", "username": "telemt", "password": "short"}"#)
        .unwrap();
    assert!(matches!(h.manager.bootstrap(), Err(Error::Manual(_))));
}

#[test]
fn a_stale_socket_is_removed_before_xray_starts() {
    let h = make("mt-stale", &mtproxy());
    let socket = h.dir.join("run/ingress-mtproxy.sock");
    std::fs::write(&socket, "left behind").unwrap();
    h.manager.bootstrap().unwrap();
    assert!(!socket.exists()); // the fake never creates it; the manager removed it
    assert!(h.runner.calls().contains(&"start 1.json".to_string()));
}

#[test]
fn rules_start_with_the_mask_exception_then_the_bypass() {
    let h = booted("mt-rules", &mtproxy());
    h.apply("mtproxy", warp_doc(), "routing:p:1").unwrap();
    let rules = rules_of(&h.runner.running_config(), "mtproxy");
    assert_eq!(
        rules[0],
        json!({"inboundTag": ["mtproxy"], "ip": MTPROXY_PRIVATE_EXCEPTION, "port": "443", "outboundTag": "direct"})
    );
    assert_eq!(rules[1], json!({"inboundTag": ["mtproxy"], "ip": ["geoip:private"], "outboundTag": "block"}));
    assert_eq!(rules.last().unwrap(), &json!({"inboundTag": ["mtproxy"], "outboundTag": "warp"}));
    assert!(!MTPROXY_PRIVATE_EXCEPTION.contains(&"127.0.0.0/8"));
}

#[test]
fn a_chain_for_mtproxy_renders_like_any_service() {
    let reachable = |m: &mut XrayRouterManager| m.hop_reachability = Box::new(|_, _, _, _| true);
    let h = make_in(&tempdir("mt-chain"), &mtproxy(), FakeRunner::default(), reachable);
    h.manager.bootstrap().unwrap();
    h.apply("mtproxy", chain_doc(), "routing:p:2").unwrap();
    let config = h.runner.running_config();
    assert!(outbound_tags(&config).contains(&"chain:mtproxy:b:1".to_string()));
    assert_eq!(
        config["routing"]["rules"].as_array().unwrap().last().unwrap(),
        &json!({"inboundTag": ["mtproxy"], "outboundTag": "chain:mtproxy:b:1"})
    );
}

#[test]
fn mtproxy_has_no_lanes() {
    let h = booted("mt-lanes", &mtproxy());
    assert!(matches!(h.manager.lane_issue("mtproxy", &json!("grant:abc")), Err(Error::Validation(_))));
}

#[test]
fn a_node_updated_from_a_router_without_mtproxy_rerenders_it_pass_through() {
    let old = booted("mt-update", &Setup::default());
    let current = read_json(&old.file("current.json"));
    let mut services: Vec<&String> = current["services"].as_object().unwrap().keys().collect();
    services.sort();
    assert_eq!(services, ["mieru", "naive"]);
    old.manager.close(); // the container is recreated with the new image
    let updated = make_in(&old.dir, &mtproxy(), old.runner.clone(), |_| {});
    updated.manager.bootstrap().unwrap();
    let current = read_json(&updated.file("current.json"));
    let mut services: Vec<&String> = current["services"].as_object().unwrap().keys().collect();
    services.sort();
    assert!(current["generation"] == 2 && services == ["mieru", "mtproxy", "naive"]);
    assert_eq!(current["services"]["mtproxy"]["document"], direct_document());
    assert_eq!(inbound(&updated.runner.running_config(), "mtproxy").unwrap()["protocol"], "vless");
    updated.apply("mtproxy", warp_doc(), "routing:p:3").unwrap();
}

#[test]
fn a_manager_without_the_socket_does_not_know_mtproxy() {
    let h = booted("mt-off", &Setup::default());
    assert!(h.manager.status().unwrap()["services"].get("mtproxy").is_none());
    assert!(matches!(h.manager.egress("mtproxy"), Err(Error::Validation(_))));
}

#[test]
fn render_without_an_mtproxy_ingress_is_unchanged() {
    let render = crate::render::RenderInput {
        ingresses: vec![
            Ingress::new("naive", 45101, "naive-a", &"N".repeat(20)),
            Ingress::new("mieru", 45102, "mieru-a", &"M".repeat(20)),
        ],
        ..Default::default()
    };
    let config = crate::render::render_config(&render).unwrap();
    let tags: Vec<Value> = config["inbounds"].as_array().unwrap().iter().map(|i| i["tag"].clone()).collect();
    assert_eq!(tags, [json!("naive"), json!("mieru")]);
    assert!(!config["routing"]["rules"].as_array().unwrap().iter().any(|r| r["port"] == "443"));
}

#[test]
fn the_constructor_switch() {
    let dir = tempdir("switch");
    let mut with_socket = Options::new(dir.join("a"));
    with_socket.mtproxy_socket = Some(dir.join("s.sock"));
    let runner: Arc<dyn XrayRunner> = Arc::new(FakeRunner::default());
    assert_eq!(XrayRouterManager::new(with_socket, runner.clone()).services, ["naive", "mieru", "mtproxy"]);
    assert_eq!(XrayRouterManager::new(Options::new(dir.join("b")), runner).services, ["naive", "mieru"]);
}

// ---------------------------------------------------------------- the Unix-socket API

const TOKEN: &str = "ci-xray-router-token-0123456789abcdef0123456789abcdef";

struct Api {
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

fn serve(h: &H) -> Api {
    let socket = h.dir.join("manager.sock");
    let mut options = ServerOptions::new(&socket);
    options.max_body = crate::server::MAX_BODY;
    let server = UdsServer::bind(options).unwrap();
    let handle = server.shutdown_handle();
    let handler = crate::server::handler(h.manager.clone(), TOKEN.into()).unwrap();
    let thread = std::thread::spawn(move || server.serve(handler));
    Api { socket, handle, thread: Some(thread) }
}

fn call_with(api: &Api, method: &str, path: &str, body: Option<Value>, token: Option<&str>) -> (u16, Value, String) {
    let headers: Vec<(&str, &str)> = token.map(|t| vec![("X-Xray-Router-Token", t)]).unwrap_or_default();
    let raw = body.map(|b| b.to_string().into_bytes());
    let reply =
        pc_common::client::request(&api.socket, method, path, &headers, raw.as_deref(), Duration::from_secs(10))
            .unwrap();
    let text = String::from_utf8_lossy(&reply.body).into_owned();
    (reply.status, serde_json::from_str(&text).unwrap_or(Value::Null), text)
}

fn call(api: &Api, method: &str, path: &str, body: Option<Value>) -> (u16, Value, String) {
    call_with(api, method, path, body, Some(TOKEN))
}

#[test]
fn unix_api_routes_codes_and_health() {
    let h = booted("api", &Setup::default());
    let api = serve(&h);
    assert_eq!(call_with(&api, "GET", "/v1/status", None, None).0, 401);
    assert_eq!(call_with(&api, "GET", "/v1/status", None, None).1, json!({"detail": "unauthorized"}));
    let status = call(&api, "GET", "/v1/status", None);
    assert!(status.0 == 200 && status.1["running"]["generation"] == 1);
    assert_eq!(call(&api, "GET", "/v1/health", None).1, json!({"ready": true}));
    assert_eq!(
        call(&api, "GET", "/v1/egress/mtproxy", None),
        (404, json!({"detail": "not found"}), r#"{"detail":"not found"}"#.into())
    );
    let view = call(&api, "GET", "/v1/egress/naive", None);
    let revision = view.1["revision"].clone();
    let plan = call(
        &api,
        "POST",
        "/v1/egress/naive/plan",
        Some(json!({"expected_revision": revision, "document": warp_doc()})),
    );
    assert!(plan.0 == 200 && plan.1["restart_required"] == true);
    let stale = call(
        &api,
        "POST",
        "/v1/egress/naive/apply",
        Some(json!({"expected_revision": "0".repeat(64), "document": warp_doc(), "operation_id": "op-1"})),
    );
    assert_eq!((stale.0, &stale.1["code"]), (409, &json!("egress_conflict")));
    let bad = call(
        &api,
        "POST",
        "/v1/egress/naive/apply",
        Some(json!({"expected_revision": revision, "document": {"inbounds": []}, "operation_id": "op-1"})),
    );
    assert_eq!((bad.0, &bad.1["code"]), (422, &json!("egress_invalid")));
    let extra = call(
        &api,
        "POST",
        "/v1/egress/naive/apply",
        Some(json!({"expected_revision": revision, "document": warp_doc(), "operation_id": "op-1", "path": "/etc"})),
    );
    assert_eq!((extra.0, extra.1.clone()), (422, json!({"detail": "invalid request"})));
    let applied = call(
        &api,
        "POST",
        "/v1/egress/naive/apply",
        Some(json!({"expected_revision": revision, "document": warp_doc(), "operation_id": "op-1"})),
    );
    assert!(applied.0 == 200 && applied.1["generation"] == 2);
    h.runner.get().fail_test = Some("code not found in geosite.dat: X".into());
    let unknown = call(
        &api,
        "POST",
        "/v1/egress/naive/apply",
        Some(json!({"expected_revision": applied.1["revision"], "document": block_doc(), "operation_id": "op-2"})),
    );
    assert_eq!((unknown.0, &unknown.1["code"]), (422, &json!("geosite_unknown")));
    let mieru = call(&api, "GET", "/v1/egress/mieru", None).1["revision"].clone();
    let no_previous = call(&api, "POST", "/v1/egress/mieru/rollback", Some(json!({"expected_revision": mieru})));
    assert_eq!((no_previous.0, &no_previous.1["code"]), (409, &json!("egress_no_previous")));
    let rolled =
        call(&api, "POST", "/v1/egress/naive/rollback", Some(json!({"expected_revision": applied.1["revision"]})));
    assert!(rolled.0 == 200 && rolled.1["generation"] == 3);
    assert!(![status.2, view.2, plan.2, applied.2].concat().contains(&"N".repeat(40)));
    // the compact answer keeps the manager's key order and escapes like json.dumps
    assert!(call(&api, "GET", "/v1/health", None).2 == r#"{"ready":true}"#);
    assert_eq!(call(&api, "PATCH", "/v1/status", None).0, 501);
    assert_eq!(call(&api, "POST", "/v1/egress/naive/plan", None).1, json!({"detail": "invalid request"}));
    let token_file = h.dir.join("token");
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    assert!(crate::healthcheck::check(&api.socket, &token_file));
    std::fs::write(h.dir.join("wrong"), "x".repeat(40)).unwrap();
    assert!(!crate::healthcheck::check(&api.socket, &h.dir.join("wrong")));
}

#[test]
fn unix_api_reports_artifact_mismatch_and_broken_router() {
    let h = make("api-mismatch", &Setup { bad_digest: true, ..Setup::default() });
    let _ = h.manager.bootstrap();
    let api = serve(&h);
    let status = call(&api, "GET", "/v1/status", None);
    assert!(status.0 == 503 && status.1["artifact_error"].as_str().is_some());
    let health = call(&api, "GET", "/v1/health", None);
    assert_eq!((health.0, &health.1["code"]), (503, &json!("artifact_mismatch")));
}

#[test]
fn unix_api_manual_intervention_and_readback_codes() {
    let h = booted("api-codes", &Setup::default());
    let api = serve(&h);
    let revision = call(&api, "GET", "/v1/egress/naive", None).1["revision"].clone();
    h.runner.get().fail_ready = 1;
    let restored = call(
        &api,
        "POST",
        "/v1/egress/naive/apply",
        Some(json!({"expected_revision": revision, "document": block_doc(), "operation_id": "op-1"})),
    );
    assert_eq!((restored.0, &restored.1["code"]), (502, &json!("egress_readback_mismatch")));
    h.runner.get().fail_ready = 2;
    let broken = call(
        &api,
        "POST",
        "/v1/egress/naive/apply",
        Some(json!({"expected_revision": revision, "document": block_doc(), "operation_id": "op-2"})),
    );
    assert_eq!((broken.0, &broken.1["code"]), (503, &json!("manual_intervention_required")));
    let health = call(&api, "GET", "/v1/health", None);
    assert_eq!((health.0, &health.1["code"]), (503, &json!("manual_intervention_required")));
}

/// v0.7: the panel mints lane accounts and drives the relay through the same door.
#[test]
fn unix_api_lanes_and_relay_routes() {
    let h = booted("api-lanes", &Setup::default());
    let api = serve(&h);
    let issued = call(&api, "POST", "/v1/lanes/naive", Some(json!({"lane": "grant:7f3a"})));
    assert!(issued.0 == 200 && issued.1["user"] == "grant-7f3a" && issued.1["password"].as_str().unwrap().len() >= 32);
    assert_eq!(call(&api, "POST", "/v1/lanes/naive", Some(json!({"lane": "svc:naive"}))).0, 422);
    assert_eq!(call(&api, "POST", "/v1/lanes/mtproxy", Some(json!({"lane": "grant:1"}))).0, 404);
    let listed = call(&api, "GET", "/v1/lanes/naive", None);
    assert!(
        listed.0 == 200
            && listed.1 == json!({"lanes": ["grant:7f3a"]})
            && !listed.2.contains(issued.1["password"].as_str().unwrap())
    );
    assert_eq!(
        call(&api, "DELETE", "/v1/lanes/naive/grant:7f3a", None).1,
        json!({"lane": "grant:7f3a", "forgotten": true})
    );
    let unknown = call(&api, "DELETE", "/v1/lanes/naive/grant:7f3a", None);
    assert_eq!((unknown.0, &unknown.1["code"]), (409, &json!("lane_unknown")));
    let relay = call(&api, "GET", "/v1/relay", None);
    assert!(relay.0 == 200 && relay.1["enabled"] == false);
    let enabled =
        call(&api, "POST", "/v1/relay", Some(json!({"server_name": "panel.node-a.example.org", "port": 45443})));
    assert!(enabled.0 == 200 && enabled.1["public_key"] == PUBLIC_KEY && enabled.1["accounts"] == 0);
    assert!(!enabled.2.contains(&private_key()));
    let accounts = call(
        &api,
        "PUT",
        "/v1/relay/accounts",
        Some(
            json!({"accounts": [{"email": format!("relay:{}:direct", "c".repeat(32)), "uuid": "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10"}]}),
        ),
    );
    assert!(accounts.0 == 200 && accounts.1["accounts"] == 1 && !accounts.2.contains("3f0d9c6e"));
    assert_eq!(
        call(&api, "PUT", "/v1/relay/accounts", Some(json!({"accounts": [{"email": "x", "uuid": "y"}]}))).0,
        422
    );
    let disabled = call(&api, "DELETE", "/v1/relay", None);
    assert!(disabled.0 == 200 && disabled.1["enabled"] == false);
    let refused = call(&api, "PUT", "/v1/relay/accounts", Some(json!({"accounts": []})));
    assert_eq!((refused.0, &refused.1["code"]), (409, &json!("relay_disabled")));
    let status = call(&api, "GET", "/v1/status", None).1;
    assert!(status["lanes"] == json!({"naive": [], "mieru": []}) && status["relay"]["enabled"] == false);
    assert!(["lanes", "chains", "relay"]
        .iter()
        .all(|c| status["capabilities"].as_array().unwrap().contains(&json!(c))));
}

#[test]
fn unix_api_geodata_routes() {
    let l = loyal("api-geodata");
    let api = serve(&l.h);
    assert_eq!(call_with(&api, "GET", "/v1/geodata", None, None).0, 401);
    let view = call(&api, "GET", "/v1/geodata", None).1;
    assert!(view["source"]["kind"] == "loyalsoldier" && view["origin"] == "seed");
    let bad = call(&api, "PUT", "/v1/geodata/settings", Some(json!({"interval_hours": 0})));
    assert_eq!((bad.0, &bad.1["code"]), (422, &json!("geodata_invalid")));
    assert_eq!(call(&api, "PUT", "/v1/geodata/settings", Some(json!({"extra": 1}))).0, 422);
    let ok = call(&api, "PUT", "/v1/geodata/settings", Some(json!({"auto_update": true, "interval_hours": 12})));
    assert!(ok.0 == 200 && ok.1["auto_update"] == true);
    let updated = call(&api, "POST", "/v1/geodata/update", None);
    assert!(updated.0 == 200 && updated.1["changed"] == true);
    assert_eq!(call(&api, "GET", "/v1/geodata/codes", None).1["codes"]["geosite"], json!(["category-ads-all", "cn"]));
    let restored = call(&api, "POST", "/v1/geodata/restore", None);
    assert!(restored.0 == 200 && restored.1["origin"] == "seed");
    let status = call(&api, "GET", "/v1/status", None).1;
    assert!(
        status["geodata"]["source"]["kind"] == "xray"
            && status["capabilities"].as_array().unwrap().contains(&json!("geodata"))
    );
}

#[test]
fn unix_api_exit_test_route() {
    let prober = |m: &mut XrayRouterManager| {
        m.exit_prober = Box::new(|_, _, _| Ok(json!({"ip": "198.51.100.1", "colo": "FRA"})))
    };
    let h = make_in(&tempdir("api-exit"), &Setup::default(), FakeRunner::default(), prober);
    h.manager.bootstrap().unwrap();
    let api = serve(&h);
    let ok = call(&api, "POST", "/v1/exits/test", Some(json!({"exit": socks_exit()})));
    assert!(ok.0 == 200 && ok.1["ip"] == "198.51.100.1");
    let bad = call(&api, "POST", "/v1/exits/test", Some(json!({"exit": {"protocol": "socks"}})));
    assert_eq!((bad.0, &bad.1["code"]), (422, &json!("egress_invalid")));
    assert_eq!(call(&api, "POST", "/v1/exits/test", Some(json!({"outbound": socks_exit()}))).0, 422);
}

// ---------------------------------------------------------------- the shared contract

const CONTRACT: &str = include_str!("../../tests/fixtures/xray-router-contract.json");

/// The numbers and names the panel and the installer read from `tests/fixtures/xray-router-contract.json`
/// (their Python tests compare against it) are the ones this manager serves; the exit specs the
/// panel builds from share links are exits this manager accepts.
#[test]
fn the_contract_fixture_is_what_the_manager_serves() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    assert_eq!(contract["services"], json!(crate::intent::SERVICES));
    let ports: Map<String, Value> = PORTS.iter().map(|(tag, port)| (tag.to_string(), json!(port))).collect();
    assert_eq!(contract["ports"], Value::Object(ports));
    assert_eq!(contract["trusttunnel_port"], TRUSTTUNNEL_PORT);
    let h = booted("contract", &Setup::default());
    assert_eq!(contract["capabilities"], h.manager.status().unwrap()["capabilities"]);
    assert_eq!(contract["geodata_source_kinds"], json!(crate::geodata::SOURCE_KINDS));
    for kind in crate::geodata::PRESETS {
        let urls = preset_urls(kind).unwrap();
        assert_eq!(contract["geodata_presets"][kind], json!({"geosite": urls.geosite, "geoip": urls.geoip}), "{kind}");
    }
    assert_eq!(contract["geodata_presets"].as_object().unwrap().len(), crate::geodata::PRESETS.len());
    for spec in contract["panel_exit_specs"].as_array().unwrap() {
        assert_eq!(crate::intent::validate_exit(spec).unwrap()["protocol"], spec["protocol"], "{spec}");
    }
}

// ---------------------------------------------------------------- the Python manager's state

const PYTHON_STATE: &str = include_str!("../testdata/state.json");

/// A state directory the Python manager wrote (lanes, a chain and an exit with a non-ASCII
/// credential, the relay, every ingress, a WARP device, a rollback, geodata settings) is read
/// as it is: the re-render gives the Python bytes (same digest, so the same generation starts —
/// no new one), every state file re-serialises byte for byte, and the views agree.
#[test]
fn state_written_by_the_python_manager_is_read() {
    let golden: Value = serde_json::from_str(PYTHON_STATE).unwrap();
    let dir = tempdir("python-state");
    for (name, content) in golden["files"].as_object().unwrap() {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content.as_str().unwrap()).unwrap();
    }
    // The Python run used this socket path; it is part of the generation's bytes.
    let run = PathBuf::from("/tmp/xray-router-golden-run");
    std::fs::create_dir_all(&run).unwrap();
    let mut options = Options::new(dir.join("state"));
    options.warp_url = Some(WARP.into());
    options.ingress_files =
        [("naive".to_string(), dir.join("secrets/naive")), ("mieru".to_string(), dir.join("secrets/mieru"))].into();
    options.artifacts = ["xray", "geoip", "geosite"]
        .iter()
        .map(|name| {
            let path = dir.join(if *name == "xray" { "bin/xray".to_string() } else { format!("bin/{name}.dat") });
            let digest = sha256_hex(&std::fs::read(&path).unwrap());
            (name.to_string(), path, digest)
        })
        .collect();
    options.mtproxy_socket = Some(run.join("ingress-mtproxy.sock"));
    options.trusttunnel_port = Some(45104);
    options.amneziawg_tun = Some("awgxr".into());
    options.net_root = dir.join("net");
    let runner = FakeRunner::default();
    let mut manager = XrayRouterManager::new(options, Arc::new(runner.clone()));
    manager.reachability = Box::new(|_, _| true);
    let manager = Arc::new(manager);
    manager.bootstrap().unwrap();
    let generation = golden["generation"].as_i64().unwrap();
    assert_eq!(
        runner.calls(),
        [
            format!("start {generation}.json"),
            format!("ready 45101,45102,45104 {}", run.join("ingress-mtproxy.sock").display())
        ]
    );
    let current = read_json(&dir.join("state/current.json"));
    assert_eq!(
        (current["generation"].as_i64().unwrap(), current["digest"].clone()),
        (generation, golden["digest"].clone())
    );
    // Every JSON file the Python manager wrote is what this manager would write for the same value.
    for (name, content) in golden["files"].as_object().unwrap() {
        if name.starts_with("state/") && name.ends_with(".json") {
            let on_disk = std::fs::read_to_string(dir.join(name)).unwrap();
            assert_eq!(&on_disk, content.as_str().unwrap(), "{name} changed at start");
            let value: Value = serde_json::from_str(&on_disk).unwrap();
            let rewritten = if name.contains("/generations/") {
                String::from_utf8(config_bytes(&value)).unwrap()
            } else {
                format!("{}\n", crate::pyjson::dumps(&value, &crate::pyjson::SORTED))
            };
            assert_eq!(&rewritten, content.as_str().unwrap(), "{name}");
        }
    }
    // The views: what the Python manager answered, minus what moves with time.
    let mut status = manager.status().unwrap();
    let mut python_status = golden["status"].clone();
    for value in [&mut status, &mut python_status] {
        value["running"] = Value::Null;
    }
    assert_eq!(status, python_status);
    for (tag, python_view) in golden["egress"].as_object().unwrap() {
        let mut view = manager.egress(tag).unwrap();
        let mut python_view = python_view.clone();
        if let Some(tun) = view.get_mut("tun") {
            tun["attached"] = python_view["tun"]["attached"].clone(); // the Python run had stopped its process
        }
        python_view["runtime_version"] = view["runtime_version"].clone();
        assert_eq!(
            crate::pyjson::dumps(&view, &crate::pyjson::COMPACT),
            crate::pyjson::dumps(&python_view, &crate::pyjson::COMPACT),
            "{tag}"
        );
    }
    let mut geodata = manager.geodata_view();
    let mut python_geodata = golden["geodata"].clone();
    geodata["next_check_at"] = Value::Null;
    python_geodata["next_check_at"] = Value::Null;
    assert_eq!(
        crate::pyjson::dumps(&geodata, &crate::pyjson::COMPACT),
        crate::pyjson::dumps(&python_geodata, &crate::pyjson::COMPACT)
    );
    // And it keeps working on them: a change commits the next generation.
    let revision = manager.egress("mieru").unwrap()["revision"].clone();
    manager.egress_apply("mieru", &revision, &warp_doc(), &json!("op-rust")).unwrap();
    assert_eq!(read_json(&dir.join("state/current.json"))["generation"], generation + 1);
    let _ = std::fs::remove_dir_all(run);
}
