//! The manager's behaviour, ported from the Python suites (`tests/test_awg_manager.py`,
//! `tests/test_awg_egress.py`): a fake host that models amneziawg-go's control socket, `ip rule`,
//! the WARP device's handshake and the router's TUN device, a hand-driven clock and a fake WARP API.

use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use indexmap::IndexMap;
use pc_common::{ApiError, ServerOptions, UdsServer};
use serde_json::{json, Map, Value};

use crate::config::{from_env, tests::make_env};
use crate::egress::{IFACE, PRIORITY, TABLE};
use crate::host::{Host, HostError, Proc, UapiError};
use crate::ipnet::{ip_network, Network};
use crate::keys::{self, b64, hexkey};
use crate::obfuscation::{tests::params, Params, SeededRng};
use crate::service::{AwgManager, Options};
use crate::state::StateError;

const TOKEN: &str = "tttttttttttttttttttttttttttttttttttttttt";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const WALL: f64 = 1_700_000_000.0;

// ---------------------------------------------------------------- fakes

#[derive(Default)]
struct ProcState {
    returncode: Option<i32>,
    killed: bool,
}

struct FakeProc(Arc<Mutex<ProcState>>);

impl Proc for FakeProc {
    fn poll(&mut self) -> Option<i32> {
        self.0.lock().unwrap().returncode
    }

    fn terminate(&mut self) {
        self.0.lock().unwrap().returncode = Some(-15);
    }

    fn kill(&mut self) {
        let mut state = self.0.lock().unwrap();
        state.killed = true;
        state.returncode = Some(-9);
    }

    fn wait(&mut self, _timeout: Duration) -> Result<i32, ()> {
        Ok(self.0.lock().unwrap().returncode.unwrap_or(0))
    }
}

#[derive(Default, Clone)]
struct FakePeer {
    psk: String,
    allowed: Vec<String>,
}

#[derive(Default, Clone)]
struct Device {
    device: IndexMap<String, String>,
    peers: IndexMap<String, FakePeer>,
}

#[derive(Default, Clone, Copy)]
struct Stats {
    rx: i64,
    tx: i64,
    hs: i64,
}

struct HostState {
    procs: IndexMap<String, Arc<Mutex<ProcState>>>,
    devices: IndexMap<String, Device>,
    sets: Vec<(String, String)>,
    ip_calls: Vec<Vec<String>>,
    nft_scripts: Vec<String>,
    nft_deleted: u32,
    forward: bool,
    ready: bool,
    stats: HashMap<String, Stats>,
    starts: Vec<(String, String)>,
    // the routing part (`RoutingHost` of the Python egress suite)
    rules: BTreeSet<String>,
    warp_handshake: i64,
    links: IndexMap<String, Vec<String>>,
    router_reads: bool,
    refuse_warp_sets: usize,
}

/// Models the control socket of amneziawg-go closely enough to test reconciliation.
#[derive(Clone)]
struct FakeHost(Arc<Mutex<HostState>>);

impl FakeHost {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HostState {
            procs: IndexMap::new(),
            devices: IndexMap::new(),
            sets: Vec::new(),
            ip_calls: Vec::new(),
            nft_scripts: Vec::new(),
            nft_deleted: 0,
            forward: true,
            ready: true,
            stats: HashMap::new(),
            starts: Vec::new(),
            rules: BTreeSet::new(),
            warp_handshake: 0,
            links: IndexMap::new(),
            router_reads: true,
            refuse_warp_sets: 0,
        })))
    }

    fn get(&self) -> MutexGuard<'_, HostState> {
        self.0.lock().unwrap()
    }

    fn crash(&self, iface: &str) {
        let mut state = self.get();
        state.procs[iface].lock().unwrap().returncode = Some(2);
        state.devices.insert(iface.into(), Device::default());
    }

    fn returncode(&self, iface: &str) -> Option<i32> {
        self.get().procs[iface].lock().unwrap().returncode
    }

    fn killed(&self, iface: &str) -> bool {
        self.get().procs[iface].lock().unwrap().killed
    }

    fn peers(&self, iface: &str) -> IndexMap<String, FakePeer> {
        self.get().devices[iface].peers.clone()
    }

    fn has_call(&self, call: &[&str]) -> bool {
        self.get().ip_calls.iter().any(|c| c == call)
    }

    fn rules(&self) -> BTreeSet<String> {
        self.get().rules.clone()
    }

    fn alive(state: &HostState, iface: &str) -> Result<(), UapiError> {
        let alive = state.procs.get(iface).is_some_and(|proc| proc.lock().unwrap().returncode.is_none());
        if !alive || !state.ready {
            return Err(UapiError("no control socket".into()));
        }
        Ok(())
    }
}

fn subnet_text(raw: &str) -> String {
    match ip_network(raw, true) {
        Some(Network::V4(net)) => net.to_string(),
        other => panic!("{raw}: {other:?}"),
    }
}

impl Host for FakeHost {
    fn start_process(&self, iface: &str, log_level: &str) -> std::io::Result<Box<dyn Proc>> {
        let mut state = self.get();
        state.starts.push((iface.into(), log_level.into()));
        let proc = Arc::new(Mutex::new(ProcState::default()));
        state.procs.insert(iface.into(), proc.clone());
        state.devices.insert(iface.into(), Device::default());
        Ok(Box::new(FakeProc(proc)))
    }

    fn ip(&self, args: &[&str]) -> Result<(), HostError> {
        let mut state = self.get();
        state.ip_calls.push(args.iter().map(|a| a.to_string()).collect());
        if args[..2] == ["tuntap", "add"] {
            let flags: &[&str] = if state.router_reads {
                &["POINTOPOINT", "UP", "LOWER_UP"]
            } else {
                &["NO-CARRIER", "POINTOPOINT", "UP"]
            };
            state.links.insert(args[3].into(), flags.iter().map(|f| f.to_string()).collect());
        }
        if args[..2] == ["rule", "add"] {
            state.rules.insert(subnet_text(args[3]));
        } else if args[..2] == ["rule", "del"] {
            state.rules.remove(&subnet_text(args[3]));
        }
        Ok(())
    }

    fn ip_json(&self, args: &[&str]) -> Result<Vec<Value>, HostError> {
        let state = self.get();
        if args[..3] == ["link", "show", "dev"] {
            let Some(flags) = state.links.get(args[3]) else { return Err(HostError("no such device".into())) };
            return Ok(vec![json!({"ifname": args[3], "flags": flags})]);
        }
        assert_eq!(args, ["-4", "rule", "show", "table", TABLE]);
        Ok(state
            .rules
            .iter()
            .map(|source| {
                let (address, length) = source.split_once('/').unwrap();
                json!({"priority": PRIORITY.parse::<i64>().unwrap(), "src": address,
                       "srclen": length.parse::<i64>().unwrap(), "table": TABLE})
            })
            .collect())
    }

    fn nft_apply(&self, script: &str) -> Result<(), HostError> {
        self.get().nft_scripts.push(script.into());
        Ok(())
    }

    fn nft_delete(&self) {
        self.get().nft_deleted += 1;
    }

    fn uapi_set(&self, iface: &str, body: &str) -> Result<(), UapiError> {
        let mut state = self.get();
        if iface == IFACE && state.refuse_warp_sets > 0 {
            state.refuse_warp_sets -= 1;
            return Err(UapiError("no control socket yet".into()));
        }
        Self::alive(&state, iface)?;
        state.sets.push((iface.into(), body.into()));
        let dev = state.devices.get_mut(iface).unwrap();
        let mut current: Option<String> = None;
        let fresh = || FakePeer { psk: ZERO.into(), allowed: Vec::new() };
        for line in body.lines() {
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            match (key, current.clone()) {
                ("public_key", _) => {
                    current = Some(value.into());
                    dev.peers.entry(value.into()).or_insert_with(fresh);
                }
                (_, None) => {
                    dev.device.insert(key.into(), value.into());
                }
                ("remove", Some(name)) => {
                    dev.peers.shift_remove(&name);
                    current = Some("gone".into());
                    dev.peers.entry("gone".into()).or_insert_with(fresh);
                }
                ("preshared_key", Some(name)) => dev.peers[&name].psk = value.into(),
                ("replace_allowed_ips", Some(name)) => dev.peers[&name].allowed.clear(),
                ("allowed_ip", Some(name)) => dev.peers[&name].allowed.push(value.into()),
                _ => {}
            }
        }
        dev.peers.shift_remove("gone");
        Ok(())
    }

    fn uapi_get(&self, iface: &str) -> Result<String, UapiError> {
        let state = self.get();
        Self::alive(&state, iface)?;
        if iface == IFACE {
            return Ok(format!(
                "private_key=x\npublic_key=y\nlast_handshake_time_sec={}\nrx_bytes=10\ntx_bytes=20\n",
                state.warp_handshake
            ));
        }
        let dev = &state.devices[iface];
        let mut lines: Vec<String> = dev.device.iter().map(|(k, v)| format!("{k}={v}")).collect();
        for (public, peer) in &dev.peers {
            let st = state.stats.get(public).copied().unwrap_or_default();
            lines.extend([
                format!("public_key={public}"),
                format!("preshared_key={}", peer.psk),
                "protocol_version=1".into(),
                format!("last_handshake_time_sec={}", st.hs),
                "last_handshake_time_nsec=0".into(),
                format!("tx_bytes={}", st.tx),
                format!("rx_bytes={}", st.rx),
            ]);
            lines.extend(peer.allowed.iter().map(|a| format!("allowed_ip={a}")));
        }
        Ok(lines.join("\n") + "\n")
    }

    fn ip_forward_enabled(&self) -> bool {
        self.get().forward
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
        self.0.fetch_add((seconds * 1000.0).round() as u64, Ordering::SeqCst);
    }

    fn now(&self) -> f64 {
        self.0.load(Ordering::SeqCst) as f64 / 1000.0
    }
}

struct Make<'a> {
    env: &'a [(&'a str, &'a str)],
    overrides: IndexMap<String, Params>,
    seed: u64,
    wall: f64,
    status: u16,
    handshake: bool,
    router_reads: bool,
    host: Option<FakeHost>,
    private: fn() -> [u8; 32],
}

impl Default for Make<'_> {
    fn default() -> Self {
        Self {
            env: &[],
            overrides: IndexMap::new(),
            seed: 7,
            wall: WALL,
            status: 200,
            handshake: true,
            router_reads: true,
            host: None,
            private: keys::generate_private,
        }
    }
}

struct Harness {
    dir: PathBuf,
    manager: Arc<AwgManager>,
    host: FakeHost,
    clock: Clock,
    calls: Arc<Mutex<Vec<(String, String)>>>,
}

fn build(dir: &Path, make: Make) -> Result<Harness, StateError> {
    let host = make.host.unwrap_or_else(FakeHost::new);
    host.get().router_reads = make.router_reads;
    let clock = Clock::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (clock_fn, sleeper, handshake, wall) = (clock.clone(), host.clone(), make.handshake, make.wall);
    let options = Options {
        overrides: make.overrides,
        clock: Box::new(move || clock_fn.now()),
        wall: Box::new(move || wall),
        rng: Box::new(SeededRng(make.seed)),
        warp_opener: crate::warp::tests::registrar(make.status, calls.clone()),
        sleep: Some(Box::new(move |_| {
            if handshake {
                sleeper.get().warp_handshake = 1_700_000_000;
            }
        })),
        generate_private: make.private,
    };
    let manager = AwgManager::new(from_env(&make_env(dir, make.env)).unwrap(), Box::new(host.clone()), options);
    manager.bootstrap()?;
    Ok(Harness { dir: dir.to_path_buf(), manager: Arc::new(manager), host, clock, calls })
}

fn make_in(dir: &Path, make: Make) -> Harness {
    build(dir, make).unwrap()
}

fn tempdir(name: &str) -> PathBuf {
    crate::state::tests::tempdir(&format!("svc-{name}"))
}

fn make(name: &str) -> Harness {
    make_in(&tempdir(name), Make::default())
}

fn make_with(name: &str, env: &[(&str, &str)]) -> Harness {
    make_in(&tempdir(name), Make { env, ..Make::default() })
}

fn obj(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn keypair() -> (String, String) {
    (b64(&keys::public_key(&keys::generate_private())), b64(&keys::random_bytes()))
}

fn create_body(name: &str, version: &str, op: &str) -> Value {
    let (public, psk) = keypair();
    json!({"operation_id": op, "username": name, "version": version, "public_key": public, "preshared_key": psk})
}

impl Harness {
    fn create(&self, body: &Value) -> Result<(u16, Value), ApiError> {
        self.manager.create_peer(&obj(body.clone()))
    }

    fn peers(&self) -> Map<String, Value> {
        self.manager.lock().store.peers().clone()
    }

    fn state_file(&self) -> PathBuf {
        self.dir.join("state").join("state.json")
    }

    fn tick_after(&self, seconds: f64) {
        self.clock.advance(seconds);
        self.manager.tick();
    }

    fn egress_has_proc(&self) -> bool {
        self.manager.lock().egress.proc.is_some()
    }

    fn apply(&self, document: &Value, op: &str) -> Result<Value, ApiError> {
        let revision = self.manager.egress_view()["revision"].clone();
        self.manager
            .egress_apply(&obj(json!({"expected_revision": revision, "document": document, "operation_id": op})))
    }
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn fixed_private() -> [u8; 32] {
    core::array::from_fn(|i| i as u8 + 1)
}

// ---------------------------------------------------------------- obfuscation through the manager

#[test]
fn overrides_are_validated_and_applied_once() {
    let mut overrides = IndexMap::new();
    overrides.insert("2.0".to_string(), params(&[("Jc", "6"), ("I1", "<r 20>")]));
    let h = make_in(&tempdir("overrides"), Make { overrides, ..Make::default() });
    let obf = h.manager.list_instances()["instances"][1]["obfuscation"].clone();
    assert!(obf["Jc"] == "6" && obf["I1"] == "<r 20>");
    let mut bad = IndexMap::new();
    bad.insert("2.0".to_string(), params(&[("Jc", "0")]));
    assert!(build(&tempdir("overrides-bad"), Make { overrides: bad, ..Make::default() }).is_err());
    assert!(crate::obfuscation::load_overrides(&json!({"9.9": {}})).is_err());
    assert_eq!(
        crate::obfuscation::load_overrides(&json!({"2.0": {"Jc": 6, "RandomTrailers": true}})).unwrap()["2.0"],
        params(&[("Jc", "6"), ("RandomTrailers", "true")])
    );
}

// ---------------------------------------------------------------- state

#[test]
fn failed_save_rolls_the_document_back() {
    let h = make("save-fails");
    h.manager.lock().store.fail_save = true;
    let err = h.create(&create_body("alice", "2.0", "op-1")).unwrap_err();
    assert_eq!((err.status, err.code.as_str()), (500, "internal_error"));
    assert!(h.peers().is_empty());
}

#[test]
fn bootstrap_persists_keys_once_and_never_regenerates() {
    let dir = tempdir("keys-once");
    let first = make_in(&dir, Make { seed: 1, ..Make::default() });
    let snapshot = first.manager.list_instances();
    let second = make_in(&dir, Make { seed: 2, ..Make::default() });
    assert_eq!(second.manager.list_instances(), snapshot);
    let state: Value = serde_json::from_slice(&std::fs::read(first.state_file()).unwrap()).unwrap();
    let versions: Vec<&str> = state["instances"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!((state["schema"].as_i64(), versions), (Some(1), vec!["1.5", "2.0", "3.1"]));
    assert!(!snapshot.to_string().contains("private_key"));
}

#[test]
fn corrupt_stored_instance_is_refused() {
    let dir = tempdir("corrupt");
    let h = make_in(&dir, Make::default());
    let mut doc: Value = serde_json::from_slice(&std::fs::read(h.state_file()).unwrap()).unwrap();
    doc["instances"]["2.0"]["obfuscation"]["S1"] = json!("999999");
    std::fs::write(h.state_file(), doc.to_string()).unwrap();
    assert!(build(&dir, Make::default()).is_err());
}

// ---------------------------------------------------------------- UAPI text and host plumbing

#[test]
fn exact_device_and_peer_uapi_for_each_version() {
    let key: Vec<u8> = (0..32).collect();
    let mut pins = IndexMap::new();
    pins.insert(
        "1.5".to_string(),
        params(&[
            ("Jc", "5"),
            ("Jmin", "10"),
            ("Jmax", "70"),
            ("S1", "20"),
            ("S2", "30"),
            ("H1", "11"),
            ("H2", "12"),
            ("H3", "13"),
            ("H4", "14"),
            ("I1", "<r 8>"),
        ]),
    );
    pins.insert(
        "2.0".to_string(),
        params(&[
            ("Jc", "6"),
            ("Jmin", "11"),
            ("Jmax", "71"),
            ("S1", "21"),
            ("S2", "31"),
            ("S3", "41"),
            ("S4", "51"),
            ("H1", "100-2000"),
            ("H2", "3000-5000"),
            ("H3", "6000-8000"),
            ("H4", "9000-11000"),
            ("I1", "<r 9>"),
        ]),
    );
    let mut v31 = params(&[
        ("Jc", "7"),
        ("Jmin", "12"),
        ("Jmax", "72"),
        ("S1", "22"),
        ("S2", "32"),
        ("S3", "42"),
        ("S4", "52"),
        ("H1", "1"),
        ("H2", "2"),
        ("H3", "3"),
        ("H4", "4"),
        ("ContentPaddingAddition", "0-32"),
        ("I1", "<r 10>"),
    ]);
    v31.insert("HeaderProtectionKey".into(), b64(&key));
    pins.insert("3.1".to_string(), v31);
    let h = make_in(&tempdir("exact-uapi"), Make { overrides: pins, private: fixed_private, ..Make::default() });
    let private = keys::hex(&fixed_private());
    let mut by_iface: IndexMap<String, Vec<String>> = IndexMap::new();
    for (iface, body) in h.host.get().sets.iter() {
        by_iface.entry(iface.clone()).or_default().push(body.clone());
    }
    assert_eq!(
        by_iface["awg15"][0],
        format!(
            "private_key={private}\nlisten_port=51820\njc=5\njmin=10\njmax=70\ns1=20\ns2=30\n\
             h1=11\nh2=12\nh3=13\nh4=14\ni1=<r 8>\n"
        )
    );
    assert_eq!(
        by_iface["awg20"][0],
        format!(
            "private_key={private}\nlisten_port=51821\njc=6\njmin=11\njmax=71\ns1=21\ns2=31\ns3=41\ns4=51\n\
             h1=100-2000\nh2=3000-5000\nh3=6000-8000\nh4=9000-11000\ni1=<r 9>\n"
        )
    );
    assert_eq!(
        by_iface["awg31"][0],
        format!(
            "private_key={private}\nlisten_port=51822\njc=7\njmin=12\njmax=72\ns1=22\ns2=32\ns3=42\ns4=52\n\
             h1=1\nh2=2\nh3=3\nh4=4\ni1=<r 10>\nheader_protection_key={}\n\
             content_padding_addition=0-32\n",
            keys::hex(&key)
        )
    );
    let body = create_body("alice", "2.0", "op-1");
    h.create(&body).unwrap();
    let public = hexkey(body["public_key"].as_str().unwrap()).unwrap();
    let psk = hexkey(body["preshared_key"].as_str().unwrap()).unwrap();
    assert_eq!(
        h.host.get().sets.last().unwrap().clone(),
        (
            "awg20".to_string(),
            format!("public_key={public}\npreshared_key={psk}\nreplace_allowed_ips=true\nallowed_ip=10.66.20.2/32\n")
        )
    );
}

#[test]
fn interfaces_addresses_and_nft_table() {
    let h = make("interfaces");
    assert!(h.host.has_call(&["addr", "replace", "10.66.20.1/24", "dev", "awg20"]));
    assert!(h.host.has_call(&["link", "set", "awg31", "mtu", "1280", "up"]));
    let starts = h.host.get().starts.clone();
    let expected: Vec<(String, String)> =
        ["awg15", "awg20", "awg31"].iter().map(|i| (i.to_string(), "error".to_string())).collect();
    assert_eq!(starts, expected);
    let script = h.host.get().nft_scripts[0].clone();
    assert!(script.starts_with("table inet awg_manager\ndelete table inet awg_manager\n"));
    assert!(script.contains("iifname { \"awg15\", \"awg20\", \"awg31\" } accept"));
    assert!(script.contains("ip saddr 10.66.20.0/24 oifname != \"awg20\" masquerade"));
    // The whole script, as the Python manager wrote it.
    assert_eq!(
        script,
        "table inet awg_manager\ndelete table inet awg_manager\ntable inet awg_manager {\n  chain forward {\n    \
         type filter hook forward priority 0; policy accept;\n    iifname { \"awg15\", \"awg20\", \"awg31\" } accept\n    \
         oifname { \"awg15\", \"awg20\", \"awg31\" } accept\n  }\n  chain postrouting {\n    \
         type nat hook postrouting priority srcnat; policy accept;\n    \
         ip saddr 10.66.15.0/24 oifname != \"awg15\" masquerade\n    \
         ip saddr 10.66.20.0/24 oifname != \"awg20\" masquerade\n    \
         ip saddr 10.66.31.0/24 oifname != \"awg31\" masquerade\n  }\n}\n"
    );
}

#[test]
fn nat_can_be_disabled() {
    let h = make_with("no-nat", &[("AWG_NAT", "false")]);
    let script = h.host.get().nft_scripts[0].clone();
    assert!(!script.contains("masquerade"));
    assert!(script.contains("policy accept;\n\n  }\n}\n"));
}

#[test]
fn shutdown_stops_processes_and_removes_nft_but_keeps_state() {
    let h = make("shutdown");
    h.create(&create_body("alice", "2.0", "op-1")).unwrap();
    h.manager.shutdown();
    let procs: Vec<Option<i32>> = h.host.get().procs.values().map(|p| p.lock().unwrap().returncode).collect();
    assert!(procs.iter().all(|code| *code == Some(-15)));
    assert_eq!(h.host.get().nft_deleted, 1);
    assert!(h.state_file().exists());
}

// ---------------------------------------------------------------- peers (service level)

#[test]
fn create_allocates_lowest_free_address_and_reuses_freed_ones() {
    let h = make("allocate");
    let mut addresses = Vec::new();
    for (i, name) in ["a", "b", "c"].iter().enumerate() {
        let (status, out) = h.create(&create_body(name, "2.0", &format!("op-{i}"))).unwrap();
        assert_eq!(status, 201);
        addresses.push(out["peer"]["address"].clone());
    }
    assert_eq!(addresses, [json!("10.66.20.2"), json!("10.66.20.3"), json!("10.66.20.4")]);
    h.manager.delete_peer("b").unwrap();
    assert_eq!(h.create(&create_body("d", "2.0", "op-d")).unwrap().1["peer"]["address"], "10.66.20.3");
    // Another version has its own pool.
    assert_eq!(h.create(&create_body("e", "3.1", "op-e")).unwrap().1["peer"]["address"], "10.66.31.2");
}

#[test]
fn disabled_peer_keeps_its_address_reserved() {
    let h = make("reserved");
    h.create(&create_body("a", "2.0", "op-a")).unwrap();
    h.manager.set_enabled("a", false).unwrap();
    assert_eq!(h.create(&create_body("b", "2.0", "op-b")).unwrap().1["peer"]["address"], "10.66.20.3");
}

#[test]
fn pool_exhaustion() {
    let h = make_with("pool", &[("AWG_VERSIONS", "2.0"), ("AWG_SUBNETS", "2.0=10.66.20.0/28")]);
    for i in 0..13 {
        h.create(&create_body(&format!("u{i}"), "2.0", &format!("op{i}"))).unwrap();
    }
    let err = h.create(&create_body("overflow", "2.0", "opx")).unwrap_err();
    assert_eq!(
        (err.status, err.code.as_str(), err.detail.as_str()),
        (409, "address_pool_exhausted", "no free address in the subnet")
    );
}

#[test]
fn idempotent_create_conflicts_and_uniqueness() {
    let h = make("idempotent");
    let body = create_body("alice", "2.0", "op-1");
    let (status, first) = h.create(&body).unwrap();
    let sets = h.host.get().sets.len();
    let (status2, second) = h.create(&body).unwrap();
    assert_eq!((status, status2), (201, 200));
    assert_eq!(first["peer"], second["peer"]);
    assert_eq!(h.host.get().sets.len(), sets); // replay does not touch the device
    assert_eq!(h.peers()["alice"]["revision"], 1);
    let mut other = body.clone();
    other["version"] = json!("3.1");
    assert_eq!(h.create(&other).unwrap_err().code, "operation_conflict");
    // same name, another version, new operation
    assert_eq!(h.create(&create_body("alice", "3.1", "op-2")).unwrap_err().code, "username_taken");
    let mut clash = create_body("bob", "2.0", "op-3");
    clash["public_key"] = body["public_key"].clone();
    assert_eq!(h.create(&clash).unwrap_err().code, "public_key_in_use");
}

#[test]
fn create_validation() {
    let h = make("validation");
    let zero_key = b64(&[0u8; 32]);
    let long = "x".repeat(65);
    let a44 = "A".repeat(44);
    for (key, value) in [
        ("username", json!("Bad Name")),
        ("username", json!("-lead")),
        ("username", json!(long)),
        ("username", json!("")),
        ("public_key", json!("nope")),
        ("preshared_key", json!(a44)),
        ("public_key", json!(zero_key)),
        ("operation_id", json!("has space")),
        ("operation_id", json!(1)),
    ] {
        let mut body = create_body("alice", "2.0", "op-1");
        body[key] = value.clone();
        let err = h.create(&body).unwrap_err();
        assert_eq!((err.status, err.code.as_str()), (422, "invalid_request"), "{key}={value}");
    }
}

#[test]
fn create_rejects_missing_and_extra_fields() {
    let h = make("fields");
    let body = create_body("alice", "2.0", "op-1");
    let mut missing = obj(body.clone());
    missing.remove("version");
    let mut extra = obj(body);
    extra.insert("extra".into(), json!(1));
    for bad in [missing, extra] {
        assert_eq!(h.manager.create_peer(&bad).unwrap_err().status, 422);
    }
}

#[test]
fn unknown_and_disabled_versions() {
    let h = make_with("versions", &[("AWG_VERSIONS", "2.0")]);
    let err = h.create(&create_body("alice", "9.9", "op-1")).unwrap_err();
    assert_eq!((err.status, err.code.as_str()), (422, "unknown_version"));
    let err = h.create(&create_body("alice", "3.1", "op-1")).unwrap_err();
    assert_eq!((err.status, err.code.as_str()), (409, "version_disabled"));
    let versions: Vec<Value> =
        h.manager.list_instances()["instances"].as_array().unwrap().iter().map(|i| i["version"].clone()).collect();
    assert_eq!(versions, [json!("2.0")]);
}

#[test]
fn enable_disable_are_idempotent_and_apply_live() {
    let h = make("enable");
    let body = create_body("alice", "2.0", "op-1");
    h.create(&body).unwrap();
    let public = hexkey(body["public_key"].as_str().unwrap()).unwrap();
    assert!(h.host.peers("awg20").contains_key(&public));
    let first = h.manager.set_enabled("alice", false).unwrap()["peer"].clone();
    assert!(first["enabled"] == false && first["revision"] == 2);
    assert!(!h.host.peers("awg20").contains_key(&public));
    assert_eq!(h.manager.set_enabled("alice", false).unwrap()["peer"]["revision"], 2);
    let again = h.manager.set_enabled("alice", true).unwrap()["peer"].clone();
    assert!(again["enabled"] == true && again["revision"] == 3 && again["address"] == "10.66.20.2");
    assert!(h.host.peers("awg20").contains_key(&public));
    assert_eq!(h.manager.set_enabled("alice", true).unwrap()["peer"]["revision"], 3);
    assert_eq!(h.manager.set_enabled("ghost", true).unwrap_err().code, "not_found");
}

#[test]
fn rotate_replaces_keys_keeps_address_and_is_idempotent() {
    let h = make("rotate");
    let body = create_body("alice", "3.1", "op-1");
    h.create(&body).unwrap();
    let old = hexkey(body["public_key"].as_str().unwrap()).unwrap();
    let (public, psk) = keypair();
    let rot = obj(json!({"operation_id": "rot-1", "public_key": public, "preshared_key": psk}));
    let peer = h.manager.rotate("alice", &rot).unwrap()["peer"].clone();
    assert!(peer["public_key"] == public.as_str() && peer["revision"] == 2 && peer["address"] == "10.66.31.2");
    let live = h.host.peers("awg31");
    assert!(!live.contains_key(&old));
    assert_eq!(live[&hexkey(&public).unwrap()].psk, hexkey(&psk).unwrap());
    assert_eq!(h.manager.rotate("alice", &rot).unwrap()["peer"]["revision"], 2);
    let mut conflict = rot.clone();
    conflict.insert("public_key".into(), json!(keypair().0));
    assert_eq!(h.manager.rotate("alice", &conflict).unwrap_err().code, "operation_conflict");
    assert_eq!(h.manager.rotate("ghost", &rot).unwrap_err().code, "not_found");
}

#[test]
fn rotate_of_a_disabled_peer_stays_off_the_device() {
    let h = make("rotate-disabled");
    h.create(&create_body("alice", "2.0", "op-1")).unwrap();
    h.manager.set_enabled("alice", false).unwrap();
    let (public, psk) = keypair();
    h.manager.rotate("alice", &obj(json!({"operation_id": "r", "public_key": public, "preshared_key": psk}))).unwrap();
    assert!(h.host.peers("awg20").is_empty());
}

#[test]
fn delete_removes_from_state_and_device() {
    let h = make("delete");
    h.create(&create_body("alice", "1.5", "op-1")).unwrap();
    h.manager.delete_peer("alice").unwrap();
    assert!(!h.peers().contains_key("alice") && h.host.peers("awg15").is_empty());
    assert_eq!(h.manager.delete_peer("alice").unwrap_err().code, "not_found");
}

#[test]
fn peers_list_reports_live_counters_and_handshake() {
    let h = make("counters");
    let body = create_body("alice", "2.0", "op-1");
    h.create(&body).unwrap();
    assert!(h.manager.list_peers()["peers"][0]["latest_handshake"].is_null());
    let public = hexkey(body["public_key"].as_str().unwrap()).unwrap();
    h.host.get().stats.insert(public, Stats { rx: 10, tx: 20, hs: 1_700_000_001 });
    let peer = h.manager.list_peers()["peers"][0].clone();
    assert_eq!((&peer["rx"], &peer["tx"], &peer["latest_handshake"]), (&json!(10), &json!(20), &json!(1_700_000_001)));
    let keys: BTreeSet<&String> = peer.as_object().unwrap().keys().collect();
    let expected: BTreeSet<String> =
        ["username", "version", "enabled", "address", "public_key", "revision", "rx", "tx", "latest_handshake"]
            .map(String::from)
            .into();
    assert_eq!(keys, expected.iter().collect());
}

#[test]
fn create_response_carries_instance_with_client_obfuscation() {
    let h = make("instance-view");
    let (_, out) = h.create(&create_body("alice", "3.1", "op-1")).unwrap();
    let inst = &out["instance"];
    assert!(inst["interface"] == "awg31" && inst["gateway"] == "10.66.31.1");
    assert!(inst["subnet"] == "10.66.31.0/24" && inst["port"] == 51822 && inst["mtu"] == 1280);
    assert_eq!(inst["dns"], json!(["1.1.1.1", "1.0.0.1"]));
    assert_eq!(inst["server_public_key"], h.manager.lock().store.instances()["3.1"]["public_key"]);
    let obfuscation = inst["obfuscation"].as_object().unwrap();
    assert!(obfuscation.contains_key("HeaderProtectionKey") && !obfuscation.contains_key("I2"));
    assert!(obfuscation.values().all(Value::is_string));
}

// ---------------------------------------------------------------- supervision / reconcile

#[test]
fn health_degrades_without_ip_forward_or_with_a_dead_instance() {
    let h = make("health");
    let health = h.manager.health();
    assert!(health["status"] == "ok" && health["ip_forward"] == true);
    assert_eq!(health["instances"]["2.0"], json!({"interface": "awg20", "running": true, "port": 51821, "peers": 0}));
    h.host.get().forward = false;
    assert_eq!(h.manager.health()["status"], "degraded");
    h.host.get().forward = true;
    h.host.get().ready = false;
    h.host.crash("awg20");
    h.manager.tick();
    assert_eq!(h.manager.health()["instances"]["2.0"]["running"], false);
    assert_eq!(h.manager.health()["status"], "degraded");
}

#[test]
fn reconcile_restores_peers_after_the_process_crashes() {
    let h = make("crash");
    let (a, b) = (create_body("alice", "2.0", "o1"), create_body("bob", "2.0", "o2"));
    h.create(&a).unwrap();
    h.create(&b).unwrap();
    h.manager.set_enabled("bob", false).unwrap();
    h.host.crash("awg20");
    h.manager.tick(); // notices the crash, backoff 1 s before the restart
    assert_eq!(h.manager.health()["instances"]["2.0"]["running"], false);
    assert!(h.host.peers("awg20").is_empty());
    h.tick_after(1.5);
    let live = h.host.peers("awg20");
    let alice = hexkey(a["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(live.keys().collect::<Vec<_>>(), [&alice]); // disabled bob stays off
    assert_eq!(live[&alice].allowed, ["10.66.20.2/32"]);
    assert_eq!(h.host.get().devices["awg20"].device["listen_port"], "51821");
    assert_eq!(h.manager.health()["status"], "ok");
    assert_eq!(h.host.get().starts.iter().filter(|s| s.0 == "awg20").count(), 2);
}

#[test]
fn restart_backoff_grows_and_resets_after_a_stable_run() {
    let h = make("backoff");
    for expected in [1.0, 2.0, 4.0] {
        h.host.crash("awg20");
        h.manager.tick();
        h.tick_after(expected - 0.1);
        assert_eq!(h.host.returncode("awg20"), Some(2)); // still down inside the window
        h.tick_after(0.2);
        assert_eq!(h.host.returncode("awg20"), None);
    }
    h.clock.advance(120.0);
    h.host.crash("awg20");
    h.manager.tick();
    assert_eq!(h.manager.lock().instances[1].failures, 1);
}

#[test]
fn periodic_reconcile_repairs_drift_and_removes_strays() {
    let h = make("drift");
    let body = create_body("alice", "2.0", "op-1");
    h.create(&body).unwrap();
    let public = hexkey(body["public_key"].as_str().unwrap()).unwrap();
    let stray = hexkey(&keypair().0).unwrap();
    {
        let mut state = h.host.get();
        let dev = state.devices.get_mut("awg20").unwrap();
        dev.peers.shift_remove(&public);
        dev.peers.insert(stray.clone(), FakePeer { psk: ZERO.into(), allowed: vec!["10.66.20.99/32".into()] });
    }
    h.manager.tick(); // inside the interval: nothing changes
    assert!(!h.host.peers("awg20").contains_key(&public));
    h.tick_after(31.0);
    let live = h.host.peers("awg20");
    assert!(live.contains_key(&public) && !live.contains_key(&stray));
}

#[test]
fn failed_live_update_marks_dirty_and_next_tick_converges() {
    let h = make("dirty");
    h.host.get().ready = false;
    let body = create_body("alice", "2.0", "op-1");
    let (status, _) = h.create(&body).unwrap(); // device unreachable: state still wins
    assert!(status == 201 && h.manager.lock().instances[1].dirty);
    h.host.get().ready = true;
    h.manager.tick();
    assert!(h.host.peers("awg20").contains_key(&hexkey(body["public_key"].as_str().unwrap()).unwrap()));
}

#[test]
fn unready_control_socket_is_retried_then_process_is_killed() {
    let host = FakeHost::new();
    host.get().ready = false;
    let h = make_in(
        &tempdir("unready"),
        Make { env: &[("AWG_VERSIONS", "2.0")], wall: 1.0, seed: 1, host: Some(host), ..Make::default() },
    );
    assert_eq!(h.manager.health()["instances"]["2.0"]["running"], false);
    h.tick_after(11.0);
    assert!(h.host.killed("awg20"));
    h.host.get().ready = true;
    h.manager.tick(); // sees the exit, schedules the restart
    h.tick_after(2.0);
    assert_eq!(h.manager.health()["instances"]["2.0"]["running"], true);
}

// ---------------------------------------------------------------- HTTP API

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

fn api(name: &str) -> Api {
    let harness = make(name);
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

fn call_raw(api: &Api, method: &str, path: &str, raw: Option<&[u8]>, token: Option<&str>) -> (u16, Option<Value>) {
    let headers: Vec<(&str, &str)> = token.map(|t| vec![("X-Awg-Token", t)]).unwrap_or_default();
    let reply = pc_common::client::request(&api.socket, method, path, &headers, raw, Duration::from_secs(5)).unwrap();
    (reply.status, if reply.body.is_empty() { None } else { Some(reply.json().unwrap()) })
}

fn call(api: &Api, method: &str, path: &str, body: Option<Value>) -> (u16, Option<Value>) {
    let raw = body.map(|b| b.to_string().into_bytes());
    call_raw(api, method, path, raw.as_deref(), Some(TOKEN))
}

#[test]
fn api_requires_the_token() {
    let api = api("http-token");
    let wrong = "wrong".repeat(10);
    for token in [None, Some(""), Some(wrong.as_str())] {
        let (status, body) = call_raw(&api, "GET", "/v1/health", None, token);
        assert_eq!((status, &body.unwrap()["code"]), (401, &json!("unauthorized")));
    }
    assert_eq!(call(&api, "GET", "/v1/health", None).0, 200);
}

#[test]
fn api_health_and_instances() {
    let api = api("http-health");
    let (status, health) = call(&api, "GET", "/v1/health", None);
    let health = health.unwrap();
    assert!(status == 200 && health["status"] == "ok");
    let versions: Vec<&String> = health["instances"].as_object().unwrap().keys().collect();
    assert_eq!(versions, ["1.5", "2.0", "3.1"]);
    let (_, body) = call(&api, "GET", "/v1/instances", None);
    let interfaces: Vec<Value> =
        body.unwrap()["instances"].as_array().unwrap().iter().map(|i| i["interface"].clone()).collect();
    assert_eq!(interfaces, [json!("awg15"), json!("awg20"), json!("awg31")]);
    api.harness.host.get().forward = false;
    assert_eq!(call(&api, "GET", "/v1/health", None).1.unwrap()["status"], "degraded");
}

#[test]
fn api_peer_lifecycle() {
    let api = api("http-peers");
    let body = create_body("alice", "2.0", "op-1");
    let (status, created) = call(&api, "POST", "/v1/peers", Some(body.clone()));
    assert!(status == 201 && created.unwrap()["peer"]["address"] == "10.66.20.2");
    assert_eq!(call(&api, "POST", "/v1/peers", Some(body.clone())).0, 200);
    let mut other = body.clone();
    other["version"] = json!("3.1");
    assert_eq!(call(&api, "POST", "/v1/peers", Some(other)).0, 409);
    let (_, listing) = call(&api, "GET", "/v1/peers", None);
    assert_eq!(listing.unwrap()["peers"][0]["username"], "alice");
    assert_eq!(call(&api, "POST", "/v1/peers/alice/disable", Some(json!({}))).1.unwrap()["peer"]["enabled"], false);
    assert_eq!(call(&api, "POST", "/v1/peers/alice/disable", None).0, 200);
    assert_eq!(call(&api, "POST", "/v1/peers/alice/enable", Some(json!({}))).1.unwrap()["peer"]["enabled"], true);
    let (public, psk) = keypair();
    let (status, rotated) = call(
        &api,
        "POST",
        "/v1/peers/alice/rotate",
        Some(json!({"operation_id": "r1", "public_key": public, "preshared_key": psk})),
    );
    assert!(status == 200 && rotated.unwrap()["peer"]["public_key"] == public.as_str());
    assert_eq!(call(&api, "DELETE", "/v1/peers/alice", None), (204, None));
    let (status, err) = call(&api, "DELETE", "/v1/peers/alice", None);
    assert!(status == 404 && err.unwrap()["code"] == "not_found");
}

#[test]
fn api_error_shapes() {
    let api = api("http-errors");
    let (status, err) = call(&api, "POST", "/v1/peers", Some(create_body("alice", "9.9", "op-1")));
    let err = err.unwrap();
    assert!(status == 422 && err["code"] == "unknown_version" && err.get("detail").is_some());
    api.harness.manager.lock().instances.retain(|inst| inst.version != "3.1");
    let (status, err) = call(&api, "POST", "/v1/peers", Some(create_body("alice", "3.1", "op-1")));
    assert!(status == 409 && err.unwrap()["code"] == "version_disabled");
    assert_eq!(call(&api, "POST", "/v1/peers", Some(json!({"junk": 1}))).1.unwrap()["code"], "invalid_request");
    assert_eq!(call(&api, "GET", "/v1/nothing", None).0, 404);
    assert_eq!(call(&api, "POST", "/v1/peers/alice/explode", Some(json!({}))).0, 404);
    assert_eq!(call(&api, "POST", "/v1/peers/alice/enable", Some(json!({"x": 1}))).0, 422);
    // The body limit and malformed bodies answer 422, as the Python handler's `_body()` did.
    let big = vec![b'x'; crate::server::MAX_BODY + 1];
    assert_eq!(call_raw(&api, "POST", "/v1/peers", Some(&big), Some(TOKEN)).0, 422);
    assert_eq!(call_raw(&api, "POST", "/v1/peers", Some(b"[1]"), Some(TOKEN)).0, 422);
}

#[test]
fn api_socket_mode_and_healthcheck_probe() {
    let api = api("http-probe");
    let token_file = api.harness.dir.join("tok");
    std::fs::write(&token_file, TOKEN).unwrap();
    assert!(crate::probe(&api.socket, &token_file));
    std::fs::write(&token_file, "x".repeat(40)).unwrap();
    assert!(!crate::probe(&api.socket, &token_file));
    std::fs::write(&token_file, TOKEN).unwrap();
    api.harness.host.get().forward = false;
    assert!(!crate::probe(&api.socket, &token_file)); // degraded
    api.harness.host.get().forward = true;
    api.harness.host.get().ready = false;
    api.harness.host.crash("awg15");
    api.harness.manager.tick();
    assert!(!crate::probe(&api.socket, &token_file)); // an instance is down
    assert!(!crate::probe(&api.harness.dir.join("missing.sock"), &token_file));
}

#[test]
fn server_socket_permissions_and_short_token() {
    let api = api("http-mode");
    assert_eq!(mode_of(&api.socket), 0o660);
    assert!(crate::server::handler(api.harness.manager.clone(), "short".into()).is_err());
}

// ---------------------------------------------------------------- egress: direct and WARP

fn warp_doc() -> Value {
    json!({"schema": 1, "upstream": {"provider": "warp"}})
}

fn router_doc() -> Value {
    json!({"schema": 1, "upstream": {"provider": "router"}})
}

fn subnets() -> BTreeSet<String> {
    ["10.66.15.0/24", "10.66.20.0/24", "10.66.31.0/24"].map(String::from).into()
}

fn make_egress(name: &str, make: Make) -> Harness {
    make_in(&tempdir(name), Make { seed: 3, ..make })
}

fn registrations(h: &Harness) -> Vec<String> {
    h.calls.lock().unwrap().iter().map(|c| c.0.clone()).collect()
}

#[test]
fn a_fresh_node_is_direct_with_both_capabilities_and_no_tunnel() {
    let h = make_egress("eg-fresh", Make::default());
    let view = h.manager.egress_view();
    assert!(view["mode"] == "direct" && view["document"] == crate::egress::direct() && view["managed"] == false);
    assert_eq!(view["capabilities"], json!(["whole_direct", "whole_warp"]));
    assert_eq!(view["providers"], json!({"warp": {"reachable": null}}));
    assert!(view["warp"]["registered"] == false && view["warp"]["tunnel"] == "off");
    assert!(!h.host.get().procs.contains_key(IFACE) && h.host.rules().is_empty() && registrations(&h).is_empty());
    let health = h.manager.health();
    assert_eq!(health["egress"], json!({"mode": "direct", "tunnel": "off"}));
    assert_eq!(health["status"], "ok");
}

#[test]
fn warp_registers_once_starts_the_device_and_steers_every_subnet() {
    let h = make_egress("eg-warp", Make::default());
    let result = h.apply(&warp_doc(), "op-1").unwrap();
    assert!(result["applied"] == warp_doc() && result["replayed"] == false);
    assert_eq!(registrations(&h), ["POST"]);
    let config: HashMap<String, String> = h
        .host
        .get()
        .sets
        .iter()
        .filter(|(iface, _)| iface == IFACE)
        .flat_map(|(_, body)| {
            body.lines()
                .map(|l| l.split_once('=').unwrap())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(config["endpoint"] == "162.159.192.9:2408" && config["allowed_ip"] == "0.0.0.0/0");
    assert_eq!(config["public_key"], hexkey(&crate::warp::tests::peer_key()).unwrap());
    assert_eq!(config["persistent_keepalive_interval"], "25");
    assert!(!config.contains_key("jc") && !config.contains_key("h1")); // a plain WireGuard device: WARP knows no obfuscation
    assert!(h.host.has_call(&["addr", "replace", "172.16.0.2/32", "dev", IFACE]));
    assert!(h.host.has_call(&["route", "replace", "blackhole", "default", "table", TABLE, "metric", "1024"]));
    assert!(h.host.has_call(&["route", "replace", "default", "dev", IFACE, "table", TABLE]));
    assert!(h.host.has_call(&["route", "replace", "throw", "10.0.0.0/8", "table", TABLE]));
    assert_eq!(h.host.rules(), subnets());
    let view = h.manager.egress_view();
    assert!(view["mode"] == "proxy" && view["providers"]["warp"]["reachable"] == true);
    assert_eq!(
        view["warp"],
        json!({"registered": true, "address": "172.16.0.2", "endpoint": "162.159.192.9:2408",
               "account_type": "free", "tunnel": "up", "latest_handshake": 1_700_000_000, "rx": 10, "tx": 20})
    );
    assert!(!view.to_string().contains("tok-1") && !view.to_string().contains("private"));
    assert_eq!(h.manager.health()["egress"], json!({"mode": "proxy", "tunnel": "up"}));
    // direct again: the registration stays, the rules and the device go
    h.apply(&crate::egress::direct(), "op-2").unwrap();
    assert!(h.host.rules().is_empty() && !h.egress_has_proc());
    assert!(h.host.has_call(&["route", "flush", "table", TABLE]));
    h.apply(&warp_doc(), "op-3").unwrap();
    assert_eq!(registrations(&h), ["POST"]); // no second registration
}

#[test]
fn a_control_socket_that_is_not_ready_at_first_is_configured_while_waiting() {
    // The live bug of the first lab run: the device's socket was not ready when the apply first
    // tried to configure it, and nothing tried again while the apply held the lock waiting.
    let h = make_egress("eg-flaky", Make::default());
    h.host.get().refuse_warp_sets = 2;
    h.apply(&warp_doc(), "op-1").unwrap();
    assert_eq!(h.manager.egress_view()["warp"]["tunnel"], "up");
    assert!(!h.host.rules().is_empty());
}

#[test]
fn no_handshake_puts_the_previous_document_back_and_fails() {
    let h = make_egress("eg-nohs", Make { handshake: false, ..Make::default() });
    let before = h.manager.egress_view()["revision"].clone();
    let err = h.apply(&warp_doc(), "op-1").unwrap_err();
    assert_eq!((err.status, err.code.as_str()), (503, "egress_unreachable"));
    let view = h.manager.egress_view();
    assert!(view["mode"] == "direct" && view["revision"] != before);
    assert!(h.host.rules().is_empty() && !h.egress_has_proc());
    assert_eq!(view["warp"]["registered"], true); // kept for the next attempt
}

#[test]
fn a_refused_registration_changes_nothing() {
    let h = make_egress("eg-refused", Make { status: 429, ..Make::default() });
    let err = h.apply(&warp_doc(), "op-1").unwrap_err();
    assert_eq!(
        (err.code.as_str(), err.detail.as_str()),
        ("egress_unreachable", "WARP registration refused (HTTP 429)")
    );
    let view = h.manager.egress_view();
    assert!(view["mode"] == "direct" && view["revision"] == "0" && view["warp"]["registered"] == false);
    assert!(h.host.rules().is_empty());
}

#[test]
fn revision_replay_and_rollback() {
    let h = make_egress("eg-replay", Make::default());
    let apply = |revision: &str, document: Value, op: &str| {
        h.manager.egress_apply(&obj(json!({"expected_revision": revision, "document": document, "operation_id": op})))
    };
    assert_eq!(apply("7", warp_doc(), "x").unwrap_err().code, "egress_conflict");
    h.apply(&warp_doc(), "same").unwrap();
    assert_eq!(apply("0", warp_doc(), "same").unwrap()["replayed"], true);
    assert_eq!(apply("1", crate::egress::direct(), "same").unwrap_err().code, "egress_conflict");
    let revision = h.manager.egress_view()["revision"].clone();
    let rolled = h.manager.egress_rollback(&obj(json!({"expected_revision": revision}))).unwrap();
    assert!(rolled["applied"] == crate::egress::direct() && h.host.rules().is_empty());
    let revision = h.manager.egress_view()["revision"].clone();
    let err = h.manager.egress_rollback(&obj(json!({"expected_revision": revision}))).unwrap_err();
    assert_eq!(err.code, "egress_no_previous");
}

#[test]
fn the_tunnel_comes_back_after_a_crash_and_the_table_stays_fail_closed() {
    let h = make_egress("eg-crash", Make::default());
    h.apply(&warp_doc(), "op-1").unwrap();
    h.host.crash(IFACE);
    h.tick_after(1.0); // the dead device is noticed; restart waits for the backoff
    assert!(!h.host.rules().is_empty()); // rules stay: with the device gone the blackhole drops the traffic
    assert_eq!(h.manager.egress_view()["warp"]["tunnel"], "down");
    h.tick_after(2.0);
    assert_eq!(h.host.returncode(IFACE), None);
    assert!(h.manager.lock().egress.configured);
}

#[test]
fn restart_keeps_warp_and_shutdown_removes_the_rules() {
    let h = make_egress("eg-restart", Make::default());
    h.apply(&warp_doc(), "op-1").unwrap();
    h.manager.shutdown();
    assert!(h.host.rules().is_empty() && !h.egress_has_proc());
    let again = make_in(&h.dir, Make { seed: 3, host: Some(h.host.clone()), ..Make::default() });
    assert_eq!(again.manager.egress_view()["mode"], "proxy");
    assert!(!h.host.rules().is_empty());
    assert_eq!(registrations(&h), ["POST"]);
    assert!(registrations(&again).is_empty());
}

#[test]
fn stale_rules_are_swept_when_direct() {
    let h = make_egress("eg-stale", Make::default());
    h.host.get().rules.insert("10.66.20.0/24".into()); // left by a manager that was killed while on WARP
    h.tick_after(crate::egress::NETWORK_RECHECK + 1.0);
    assert!(h.host.rules().is_empty());
}

#[test]
fn a_malformed_egress_section_is_refused() {
    let h = make_egress("eg-malformed", Make::default());
    {
        let mut inner = h.manager.lock();
        inner.store.doc["egress"] = json!({"revision": "x", "history": [], "warp": null});
        inner.store.save().unwrap();
    }
    assert!(build(&h.dir, Make::default()).is_err());
}

#[test]
fn api_routes_and_field_checks() {
    let h = make_egress("eg-fields", Make::default());
    let err = h.manager.egress_apply(&obj(json!({"expected_revision": "0", "document": warp_doc()}))).unwrap_err();
    assert_eq!(err.code, "invalid_request");
    let plan = h.manager.egress_plan(&obj(json!({"expected_revision": "0", "document": warp_doc()}))).unwrap();
    assert!(plan["target"] == warp_doc() && plan["restart_required"] == false);
    assert_eq!(plan["diff"], json!(["- \"upstream\": null", "+ \"upstream\": {", "+  \"provider\": \"warp\"", "+ }"]));
    assert_eq!(plan["reachability"], json!({"warp": false}));
}

// ---------------------------------------------------------------- egress through the Xray-router (variant 2)

#[test]
fn the_router_device_is_made_for_the_routers_uid_and_offered_as_a_provider() {
    let h = make_egress("eg-router-made", Make { env: &[("AWG_EGRESS_ROUTER_TUN", "awgxr")], ..Make::default() });
    assert!(h.host.has_call(&["tuntap", "add", "dev", "awgxr", "mode", "tun", "user", "10006", "group", "10006"]));
    assert!(h.host.has_call(&["addr", "replace", "198.18.0.1/30", "dev", "awgxr"]));
    let view = h.manager.egress_view();
    assert_eq!(view["providers"]["router"], json!({"reachable": true}));
    assert_eq!(view["router"], json!({"device": "awgxr", "present": true, "attached": true}));
    assert!(h.host.rules().is_empty()); // made, not routed: the panel attaches
}

#[test]
fn attach_steers_every_subnet_into_the_router_device_and_stops_the_warp_tunnel() {
    let h = make_egress("eg-router-attach", Make { env: &[("AWG_EGRESS_ROUTER_TUN", "awgxr")], ..Make::default() });
    h.apply(&warp_doc(), "op-1").unwrap();
    assert_eq!(h.host.returncode(IFACE), None);
    h.apply(&router_doc(), "op-2").unwrap();
    assert!(h.host.has_call(&["route", "replace", "default", "dev", "awgxr", "table", TABLE]));
    assert_eq!(h.host.rules(), subnets());
    assert!(!h.egress_has_proc());
    assert_eq!(h.manager.health()["egress"], json!({"mode": "router", "tunnel": "up"}));
    let view = h.manager.egress_view();
    assert!(view["mode"] == "proxy" && view["document"] == router_doc());
    h.apply(&crate::egress::direct(), "op-3").unwrap();
    assert!(h.host.rules().is_empty() && h.host.get().links.contains_key("awgxr"));
    // the device stays for the router
}

#[test]
fn attach_waits_for_the_router_to_read_the_device_or_goes_back() {
    let h = make_egress(
        "eg-router-wait",
        Make { env: &[("AWG_EGRESS_ROUTER_TUN", "awgxr")], router_reads: false, ..Make::default() },
    );
    let err = h.apply(&router_doc(), "op-1").unwrap_err();
    assert_eq!(
        (err.code.as_str(), err.detail.as_str()),
        ("egress_unreachable", "the Xray-router does not read the AmneziaWG device")
    );
    assert!(h.manager.egress_view()["document"] == crate::egress::direct() && h.host.rules().is_empty());
}

#[test]
fn a_node_without_the_router_device_refuses_the_router_provider() {
    let h = make_egress("eg-router-none", Make::default());
    let view = h.manager.egress_view();
    assert!(view["providers"].get("router").is_none() && view["router"].is_null());
    let err = h.apply(&router_doc(), "op-1").unwrap_err();
    assert!(err.code == "egress_invalid" && h.host.get().links.is_empty());
}

#[test]
fn egress_routes_over_http() {
    let api = api("http-egress");
    assert_eq!(call(&api, "GET", "/v1/egress", None).1.unwrap()["mode"], "direct");
    let plan = call(&api, "POST", "/v1/egress/plan", Some(json!({"expected_revision": "0", "document": warp_doc()})));
    assert_eq!(plan.1.unwrap()["target"], warp_doc());
    let applied = call(
        &api,
        "POST",
        "/v1/egress/apply",
        Some(json!({"expected_revision": "0", "document": warp_doc(), "operation_id": "op-1"})),
    );
    assert_eq!((applied.0, &applied.1.unwrap()["revision"]), (200, &json!("1")));
    let rolled = call(&api, "POST", "/v1/egress/rollback", Some(json!({"expected_revision": "1"})));
    assert_eq!(rolled.1.unwrap()["applied"], crate::egress::direct());
    let stale = call(&api, "POST", "/v1/egress/rollback", Some(json!({"expected_revision": "1"})));
    assert_eq!((stale.0, &stale.1.unwrap()["code"]), (409, &json!("egress_conflict")));
}

// ---------------------------------------------------------------- state written by Python

/// `json.dumps(doc, indent=1, sort_keys=True)` of a Python manager's state, keys made up.
fn python_state() -> String {
    let private = fixed_private();
    let server_private = b64(&private);
    let server_public = b64(&keys::public_key(&private));
    let peer_public = b64(&keys::public_key(&core::array::from_fn(|i| i as u8 + 40)));
    let psk = b64(&[7u8; 32]);
    let warp_private = b64(&core::array::from_fn::<u8, 32, _>(|i| i as u8 + 70));
    let warp_peer = crate::warp::tests::peer_key();
    format!(
        r#"{{
 "egress": {{
  "history": [
   {{
    "applied_at": "2026-10-20T08:52:04+00:00",
    "digest": "664488495d35f2e19b2ae6d5c7b3de92e163954ab1909121c66f595e5e018851",
    "document": {{
     "schema": 1,
     "upstream": {{
      "provider": "warp"
     }}
    }},
    "operation_id": "routing:ad10b4b5-ca0c-49ab-922f-7445a56e641b:3"
   }}
  ],
  "revision": 12,
  "warp": {{
   "account_type": "free",
   "address": "172.16.0.2",
   "endpoint": "162.159.192.2:2408",
   "id": "dev-1",
   "peer_public_key": "{warp_peer}",
   "private_key": "{warp_private}",
   "registered_at": "2026-10-20T08:49:45.713Z",
   "token": "tok-1"
  }}
 }},
 "instances": {{
  "2.0": {{
   "created_at": 1792263721,
   "obfuscation": {{
    "H1": "354326967-487222516",
    "H2": "3396979145-3691205740",
    "H3": "1236983797-1262889538",
    "H4": "2386265177-2562815490",
    "I1": "<b 0xc10000000108><r 8><b 0x0000><t><r 79>",
    "Jc": "8",
    "Jmax": "112",
    "Jmin": "19",
    "S1": "83",
    "S2": "140",
    "S3": "36",
    "S4": "37"
   }},
   "private_key": "{server_private}",
   "public_key": "{server_public}"
  }}
 }},
 "operations": {{
  "01b40b58-aa8b-4c77-b21c-55a71d28187e:9019688e-75ad-4c17-8693-621e44519225": {{
   "digest": "619b71eb9e164e22a5e9c2d531baf36c709c92416beafe59a0413df76b0c1a53",
   "username": "demo-monitor-amne"
  }}
 }},
 "peers": {{
  "demo-monitor-amne": {{
   "address": "10.66.20.2",
   "created_at": 1792346838,
   "enabled": true,
   "operation_id": "01b40b58-aa8b-4c77-b21c-55a71d28187e:9019688e-75ad-4c17-8693-621e44519225",
   "preshared_key": "{psk}",
   "public_key": "{peer_public}",
   "revision": 1,
   "version": "2.0"
  }}
 }},
 "schema": 1
}}"#
    )
}

#[test]
fn state_written_by_the_python_manager_is_read() {
    let dir = tempdir("python-state");
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let python = python_state();
    std::fs::write(dir.join("state/state.json"), &python).unwrap();
    let h = make_in(&dir, Make { env: &[("AWG_VERSIONS", "2.0")], ..Make::default() });
    // The stored keys are kept, never regenerated, and the stored peer is on its device.
    let instance = &h.manager.list_instances()["instances"][0];
    assert_eq!(instance["server_public_key"], b64(&keys::public_key(&fixed_private())).as_str());
    assert_eq!(instance["obfuscation"]["H1"], "354326967-487222516");
    let peer = &h.manager.list_peers()["peers"][0];
    assert!(peer["username"] == "demo-monitor-amne" && peer["address"] == "10.66.20.2");
    let device_private = &h.host.get().devices["awg20"].device["private_key"].clone();
    assert_eq!(device_private, &keys::hex(&fixed_private()));
    // The stored WARP egress comes up again with its own account: no second registration.
    let view = h.manager.egress_view();
    assert!(view["mode"] == "proxy" && view["revision"] == "12" && view["warp"]["endpoint"] == "162.159.192.2:2408");
    assert!(registrations(&h).is_empty() && h.host.rules().contains("10.66.20.0/24"));
    // The stored operation id stays taken: another request under it is refused.
    let replay = json!({"operation_id": "01b40b58-aa8b-4c77-b21c-55a71d28187e:9019688e-75ad-4c17-8693-621e44519225",
                        "username": "demo-monitor-amne", "version": "2.0",
                        "public_key": peer["public_key"], "preshared_key": b64(&[7u8; 32])});
    let conflict = h.create(&replay).unwrap_err();
    assert_eq!(conflict.code, "operation_conflict");
    // Written back in the same layout.
    h.manager.lock().store.save().unwrap();
    assert_eq!(std::fs::read_to_string(h.state_file()).unwrap(), python);
}

#[test]
fn request_digests_match_the_python_manager() {
    // hashlib.sha256(json.dumps({"kind": "create", "username": "alice", "version": "2.0", "pub": "P",
    //   "psk": "S"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    let h = make("digest");
    let body = create_body("alice", "2.0", "op-1");
    h.create(&body).unwrap();
    let blob = format!(
        r#"{{"kind":"create","psk":"{}","pub":"{}","username":"alice","version":"2.0"}}"#,
        body["preshared_key"].as_str().unwrap(),
        body["public_key"].as_str().unwrap()
    );
    let expected = keys::hex(&<sha2::Sha256 as sha2::Digest>::digest(blob.as_bytes()));
    assert_eq!(h.manager.lock().store.operations()["op-1"]["digest"], expected.as_str());
}

/// The state file of a real node, copied by hand (never commit one: it holds the server keys):
/// `AWG_PYTHON_STATE=/root/… cargo test -- --ignored live_python_state_round_trips`.
#[test]
#[ignore]
fn live_python_state_round_trips() {
    let source = PathBuf::from(std::env::var("AWG_PYTHON_STATE").expect("AWG_PYTHON_STATE"));
    let original = std::fs::read_to_string(&source).unwrap();
    let dir = tempdir("live-state");
    std::fs::create_dir_all(dir.join("state")).unwrap();
    std::fs::write(dir.join("state/state.json"), &original).unwrap();
    let h = make_in(&dir, Make::default()); // validates every stored key pair and the obfuscation
    h.manager.lock().store.save().unwrap();
    assert!(
        std::fs::read_to_string(h.state_file()).unwrap() == original,
        "the state is not written back byte-identical"
    );
    let _ = std::fs::remove_dir_all(dir);
}
