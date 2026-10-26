//! Ported from `tests/test_version_agent_hostmetrics.py`, plus the golden rulesets, counters and
//! sampler ticks.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::*;
use crate::metrics_ports::Ports;
use crate::runner::CommandError;
use crate::testutil::TempDir;

/// A temporary /proc and cgroup tree that tests rewrite between ticks.
pub(crate) struct FakeHost {
    pub dir: TempDir,
    pub cpu: Vec<i64>,
    pub net: Vec<(String, (i64, i64))>,
    pub disk: (i64, i64, i64),
}

impl FakeHost {
    pub fn new() -> FakeHost {
        let dir = TempDir::new("metrics-host");
        std::fs::create_dir_all(dir.join("proc/net")).unwrap();
        std::fs::create_dir_all(dir.join("proc/self")).unwrap();
        std::fs::create_dir_all(dir.join("virtual")).unwrap();
        let mut host = FakeHost {
            dir,
            cpu: vec![100, 0, 100, 800, 0, 0, 0, 0],
            net: [("ens3", (1000, 500)), ("lo", (5, 5)), ("docker0", (7, 7)), ("awg15", (0, 0))]
                .into_iter()
                .map(|(name, counters)| (name.to_string(), counters))
                .collect(),
            disk: (0, 0, 0),
        };
        host.write();
        host
    }

    pub fn set_net(&mut self, name: &str, counters: (i64, i64)) {
        match self.net.iter_mut().find(|(known, _)| known == name) {
            Some(entry) => entry.1 = counters,
            None => self.net.push((name.to_string(), counters)),
        }
    }

    pub fn proc(&self) -> PathBuf {
        self.dir.join("proc")
    }

    pub fn write(&mut self) {
        let cpu: Vec<String> = self.cpu.iter().map(i64::to_string).collect();
        self.dir.write("proc/stat", &format!("cpu  {}\ncpu0 1 1 1 1\n", cpu.join(" ")));
        self.dir.write("proc/loadavg", "0.50 0.25 0.10 1/100 1234\n");
        self.dir.write("proc/uptime", "1234.56 99.0\n");
        self.dir
            .write("proc/meminfo", "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 400 kB\nSwapFree: 300 kB\n");
        let mut lines = String::from("Inter-|   Receive\n face |bytes\n");
        for (name, (rx, tx)) in &self.net {
            lines.push_str(&format!("{name:>6}: {rx} 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0\n"));
        }
        self.dir.write("proc/net/dev", &lines);
        let (r, w, t) = self.disk;
        self.dir.write("proc/diskstats", &format!("   8  1 vda1 1 0 {r} 0 1 0 {w} 0 0 {t} 0\n"));
    }

    pub fn container(&self, id: &str, usage: i64, mem: i64) {
        self.dir.write(
            &format!("cg/system.slice/docker-{id}.scope/cpu.stat"),
            &format!("usage_usec {usage}\nuser_usec 1\n"),
        );
        self.dir.write(&format!("cg/system.slice/docker-{id}.scope/memory.current"), &format!("{mem}\n"));
    }
}

#[derive(Clone)]
pub(crate) struct TestClock(Arc<Mutex<f64>>);

impl TestClock {
    pub fn new() -> TestClock {
        TestClock(Arc::new(Mutex::new(1000.0)))
    }

    pub fn advance(&self, seconds: f64) {
        *self.0.lock().unwrap() += seconds;
    }

    fn reader(&self) -> Clock {
        let clock = self.0.clone();
        Box::new(move || *clock.lock().unwrap())
    }
}

#[derive(Default)]
pub(crate) struct FakeNftState {
    pub counters: Vec<(String, i64)>,
    pub scripts: Vec<String>,
    pub fail: Option<String>,
}

#[derive(Clone, Default)]
pub(crate) struct FakeNft(pub Arc<Mutex<FakeNftState>>);

impl FakeNft {
    pub fn with(counters: &[(&str, i64)]) -> FakeNft {
        let nft = FakeNft::default();
        nft.set(counters);
        nft
    }

    pub fn set(&self, counters: &[(&str, i64)]) {
        self.0.lock().unwrap().counters = counters.iter().map(|(n, b)| (n.to_string(), *b)).collect();
    }

    fn scripts(&self) -> Vec<String> {
        self.0.lock().unwrap().scripts.clone()
    }
}

impl Nft for FakeNft {
    fn call(&self, _args: &[&str], stdin: Option<&str>) -> Result<String, NftUnavailable> {
        let mut state = self.0.lock().unwrap();
        if let Some(fail) = &state.fail {
            return Err(NftUnavailable(fail.clone()));
        }
        if let Some(script) = stdin {
            state.scripts.push(script.to_string());
            return Ok(String::new());
        }
        let items: Vec<Value> =
            state.counters.iter().map(|(n, b)| json!({"counter": {"name": n, "bytes": b}})).collect();
        Ok(json!({"nftables": items}).to_string())
    }
}

fn ports_of(entries: &[(&str, &[u32], &[u32])]) -> PortMap {
    entries.iter().map(|(name, tcp, udp)| (name.to_string(), Ports { tcp: tcp.to_vec(), udp: udp.to_vec() })).collect()
}

#[derive(Default)]
pub(crate) struct Options {
    pub ports: PortMap,
    pub nft: Option<FakeNft>,
    pub runner: Option<Arc<dyn CommandRunner>>,
    pub virtual_net: Option<PathBuf>,
}

pub(crate) fn make(host: &FakeHost, clock: &TestClock, options: Options) -> MetricsSampler {
    let ports = options.ports;
    let nft: Box<dyn Nft> = match options.nft {
        Some(nft) => Box::new(nft),
        None => Box::new(|_: &[&str], _: Option<&str>| Err(NftUnavailable("nft: command not found".into()))),
    };
    MetricsSampler::new(SamplerConfig {
        ports: Box::new(move || Ok(ports.clone())),
        runner: options.runner.unwrap_or_else(|| Arc::new(|_: &Command| Ok(String::new()))),
        nft,
        clock: clock.reader(),
        wall: Box::new(|| 1_700_000_000.0),
        proc: host.proc(),
        cgroup: host.dir.join("cg"),
        virtual_net: options.virtual_net.unwrap_or_else(|| host.dir.join("virtual")),
        root_path: "/".into(),
        root_device: Some("vda1".into()),
        statvfs: Box::new(|_| Ok(StatVfs { frsize: 4096, blocks: 1000, bfree: 400, bavail: 400 })),
        cores: Some(4),
        interval: INTERVAL,
    })
}

#[test]
fn first_tick_primes_and_publishes_nothing() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let sampler = make(&host, &clock, Options::default());
    assert!(sampler.tick().is_none());
    assert!(sampler.latest().is_none());
    assert_eq!(metrics_response(Some(&sampler)), (503, json!({"detail": "metrics_warming_up"})));
    assert_eq!(metrics_response(None).0, 503);
}

#[test]
fn host_rates_from_deltas() {
    let (mut host, clock) = (FakeHost::new(), TestClock::new());
    let sampler = make(&host, &clock, Options::default());
    sampler.tick();
    clock.advance(2.0);
    host.cpu = vec![200, 0, 200, 900, 0, 0, 0, 0];
    host.set_net("ens3", (3000, 1500));
    host.set_net("lo", (999999, 999999));
    host.disk = (100, 200, 500);
    host.write();
    let sample = sampler.tick().unwrap();
    let h = &sample["host"];
    assert_eq!(h["cpu_percent"], json!(66.7));
    assert_eq!((&h["cores"], &h["load"], &h["uptime_seconds"]), (&json!(4), &json!([0.5, 0.25, 0.1]), &json!(1234)));
    assert_eq!(h["mem"], json!({"used": 750 * 1024, "total": 1000 * 1024, "percent": 75.0, "available": 250 * 1024}));
    assert_eq!(h["swap"]["percent"], json!(25.0));
    assert_eq!(h["disk"]["percent"], json!(60.0));
    assert_eq!(h["disk"]["read_bps"], json!(100.0 * 512.0 / 2.0));
    assert_eq!(h["disk"]["write_bps"], json!(200.0 * 512.0 / 2.0));
    assert_eq!(h["disk"]["busy_percent"], json!(25.0));
    assert_eq!((&h["net"]["rx_bps"], &h["net"]["tx_bps"]), (&json!(1000.0), &json!(500.0)));
    let names: Vec<&str> =
        h["net"]["interfaces"].as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["ens3"]);
    assert_eq!(h["net"]["interfaces"][0]["rx_bytes"], json!(2000));
    assert_eq!((&sample["interval"], &sample["ts"]), (&json!(1.0), &json!(1_700_000_000.0)));
}

#[test]
fn virtual_interfaces_of_any_name_stay_out_of_the_host_totals() {
    let (mut host, clock) = (FakeHost::new(), TestClock::new());
    host.set_net("vmonawg", (10, 10));
    host.write();
    let virtual_net = host.dir.join("sys-virtual-net");
    std::fs::create_dir_all(virtual_net.join("vmonawg")).unwrap();
    let sampler = make(&host, &clock, Options { virtual_net: Some(virtual_net), ..Options::default() });
    sampler.tick();
    clock.advance(1.0);
    host.set_net("vmonawg", (5_000_010, 5_000_010));
    host.set_net("ens3", (2000, 1000));
    host.write();
    let net = sampler.tick().unwrap()["host"]["net"].clone();
    let names: Vec<&str> = net["interfaces"].as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["ens3"]);
    assert_eq!(net["rx_bps"], json!(1000.0));
}

#[test]
fn cpu_percent_exact() {
    let (mut host, clock) = (FakeHost::new(), TestClock::new());
    let sampler = make(&host, &clock, Options::default());
    sampler.tick();
    clock.advance(1.0);
    host.cpu = vec![175, 0, 100, 850, 0, 0, 0, 0];
    host.write();
    assert_eq!(sampler.tick().unwrap()["host"]["cpu_percent"], json!(60.0));
}

#[test]
fn interface_counter_reset_uses_new_reading() {
    let (mut host, clock) = (FakeHost::new(), TestClock::new());
    let sampler = make(&host, &clock, Options::default());
    sampler.tick();
    clock.advance(1.0);
    host.set_net("ens3", (5000, 500));
    host.write();
    sampler.tick();
    clock.advance(1.0);
    host.set_net("ens3", (300, 500)); // interface reset: the counter went down
    host.write();
    let net = sampler.tick().unwrap()["host"]["net"].clone();
    assert_eq!(net["interfaces"][0]["rx_bps"], json!(300.0));
    assert_eq!(net["interfaces"][0]["rx_bytes"], json!(4000 + 300));
}

#[test]
fn amneziawg_from_interface_counters() {
    let (mut host, clock) = (FakeHost::new(), TestClock::new());
    let sampler = make(&host, &clock, Options::default());
    sampler.tick();
    clock.advance(2.0);
    host.set_net("awg15", (4000, 2000));
    host.write();
    let awg = sampler.tick().unwrap()["protocols"]["amneziawg"].clone();
    assert_eq!(
        awg,
        json!({"up_bps": 2000.0, "down_bps": 1000.0, "up_bytes": 4000, "down_bytes": 2000, "source": "interface",
               "connections": null})
    );
    let latest = sampler.latest().unwrap();
    assert!(latest["host"]["net"]["interfaces"].as_array().unwrap().iter().all(|i| i["name"] != "awg15"));
}

#[test]
fn containers_from_cgroup_and_docker_ps() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let id = "a".repeat(64);
    host.container(&id, 1_000_000, 4096);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = calls.clone();
    let listing = format!("{id} proxy-control-panel\n{} not-in-cgroup\nnoise\n", "b".repeat(64));
    let runner: Arc<dyn CommandRunner> = Arc::new(move |command: &Command| {
        seen.lock().unwrap().push(command.argv.clone());
        Ok(listing.clone())
    });
    let sampler = make(&host, &clock, Options { runner: Some(runner), ..Options::default() });
    sampler.tick();
    clock.advance(2.0);
    host.container(&id, 2_000_000, 8192); // +1 s of CPU over 2 s = 50 % of one core
    sampler.tick();
    let sample = sampler.latest().unwrap();
    assert_eq!(
        sample["host"]["containers"],
        json!([{"name": "proxy-control-panel", "cpu_percent": 50.0, "mem_bytes": 8192}])
    );
    assert_eq!(calls.lock().unwrap().len(), 1); // names cached for 30 s
    assert_eq!(calls.lock().unwrap()[0], ["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"]);
}

#[test]
fn docker_failure_gives_empty_containers() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let runner: Arc<dyn CommandRunner> = Arc::new(|_: &Command| Err(CommandError::Os("no docker".into())));
    let sampler = make(&host, &clock, Options { runner: Some(runner), ..Options::default() });
    sampler.tick();
    clock.advance(1.0);
    assert_eq!(sampler.tick().unwrap()["host"]["containers"], json!([]));
}

#[test]
fn parse_counters_of_nft_json() {
    let document = json!({"nftables": [
        {"metainfo": {"version": "1.0.9"}},
        {"counter": {"family": "inet", "name": "up_naive_tcp_4443", "table": "proxy_control_metrics", "bytes": 1000, "packets": 5}},
        {"counter": {"family": "inet", "name": "down_naive_tcp_4443", "table": "proxy_control_metrics", "bytes": 4000, "packets": 5}},
    ]});
    assert_eq!(
        parse_counters(&document.to_string()).unwrap(),
        [("up_naive_tcp_4443".to_string(), 1000), ("down_naive_tcp_4443".to_string(), 4000)]
    );
    assert!(parse_counters("not json").is_err());
    assert!(parse_counters("[1]").is_err());
}

#[test]
fn render_ruleset_is_one_atomic_script_for_our_table_only() {
    let text = render_ruleset(&ports_of(&[("naive", &[4443], &[]), ("mieru", &[], &[9000])]));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "add table inet proxy_control_metrics");
    assert_eq!(lines[1], "delete table inet proxy_control_metrics");
    assert!(text.contains("tcp dport 4443 counter name \"up_naive_tcp_4443\""));
    assert!(text.contains("tcp sport 4443 counter name \"down_naive_tcp_4443\""));
    assert!(text.contains("udp dport 9000 counter name \"up_mieru_udp_9000\""));
    assert!(text.contains("hook input priority -300; policy accept;"));
    assert!(text.contains("hook output priority -300; policy accept;"));
    assert!(!text.contains("flush ruleset") && !text.contains("accept\n    udp"));
    assert!(!text.contains("verdict") && !text.contains(" drop"));
}

#[test]
fn kernel_counters_become_protocol_rates_and_totals() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::with(&[("up_naive_tcp_4443", 1000), ("down_naive_tcp_4443", 4000)]);
    let sampler = make(
        &host,
        &clock,
        Options { ports: ports_of(&[("naive", &[4443], &[])]), nft: Some(nft.clone()), ..Options::default() },
    );
    sampler.tick();
    assert_eq!(nft.scripts().len(), 1);
    clock.advance(2.0);
    nft.set(&[("up_naive_tcp_4443", 3000), ("down_naive_tcp_4443", 10000)]);
    let sample = sampler.tick().unwrap();
    assert_eq!(sample["kernel_counters"], "ok");
    assert_eq!(
        sample["protocols"]["naive"],
        // No /proc/net/tcp in the fake tree: unknown, not zero.
        json!({"up_bps": 1000.0, "down_bps": 3000.0, "up_bytes": 2000, "down_bytes": 6000, "source": "kernel", "connections": null})
    );
    assert_eq!(nft.scripts().len(), 1); // same map: not recreated
}

#[test]
fn kernel_counter_reset_is_a_reset_not_negative() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::with(&[("up_naive_tcp_4443", 1000), ("down_naive_tcp_4443", 4000)]);
    let sampler = make(
        &host,
        &clock,
        Options { ports: ports_of(&[("naive", &[4443], &[])]), nft: Some(nft.clone()), ..Options::default() },
    );
    sampler.tick();
    clock.advance(1.0);
    nft.set(&[("up_naive_tcp_4443", 5000), ("down_naive_tcp_4443", 5000)]);
    sampler.tick();
    clock.advance(1.0);
    nft.set(&[("up_naive_tcp_4443", 200), ("down_naive_tcp_4443", 100)]); // table recreated
    let protocol = sampler.tick().unwrap()["protocols"]["naive"].clone();
    assert_eq!((&protocol["up_bps"], &protocol["down_bps"]), (&json!(200.0), &json!(100.0)));
    assert_eq!(protocol["up_bytes"], json!(4000 + 200));
}

#[test]
fn port_map_change_recreates_table_atomically() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::with(&[("up_naive_tcp_4443", 1000), ("down_naive_tcp_4443", 4000)]);
    let current = Arc::new(Mutex::new(ports_of(&[("naive", &[4443], &[])])));
    let reader = current.clone();
    let sampler = MetricsSampler::new(SamplerConfig {
        ports: Box::new(move || Ok(reader.lock().unwrap().clone())),
        runner: Arc::new(|_: &Command| Ok(String::new())),
        nft: Box::new(nft.clone()),
        clock: clock.reader(),
        wall: Box::new(|| 1.0),
        proc: host.proc(),
        cgroup: host.dir.join("cg"),
        virtual_net: host.dir.join("virtual"),
        root_device: Some("vda1".into()),
        statvfs: Box::new(|_| Ok(StatVfs { frsize: 4096, blocks: 1000, bfree: 400, bavail: 400 })),
        ..SamplerConfig::default()
    });
    sampler.tick();
    *current.lock().unwrap() = ports_of(&[("naive", &[4443], &[]), ("mieru", &[8443], &[])]);
    clock.advance(DISCOVERY_INTERVAL + 1.0);
    sampler.tick();
    let scripts = nft.scripts();
    assert_eq!(scripts.len(), 2);
    assert!(scripts[1].contains("mieru_tcp_8443") && scripts[1].starts_with("add table inet proxy_control_metrics"));
}

#[test]
fn nft_failure_is_unavailable_without_protocol_numbers_and_logged_once() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::with(&[("up_naive_tcp_4443", 1000), ("down_naive_tcp_4443", 4000)]);
    nft.0.lock().unwrap().fail = Some("nft: command not found".into());
    let sampler = make(
        &host,
        &clock,
        Options { ports: ports_of(&[("naive", &[4443], &[])]), nft: Some(nft.clone()), ..Options::default() },
    );
    sampler.tick();
    let mut sample = Value::Null;
    for _ in 0..3 {
        clock.advance(NFT_RETRY_SECONDS + 1.0);
        sample = sampler.tick().unwrap();
    }
    assert_eq!(sample["kernel_counters"], "unavailable");
    assert!(sample["protocols"].get("naive").is_none());
    // Logged once: the state stays "unavailable" between failures.
    assert!(sampler.state.lock().unwrap().nft_unavailable);
    // recovers by itself
    nft.0.lock().unwrap().fail = None;
    clock.advance(NFT_RETRY_SECONDS + 1.0);
    assert_eq!(sampler.tick().unwrap()["kernel_counters"], "ok");
    assert!(!sampler.state.lock().unwrap().nft_unavailable);
}

#[test]
fn nft_retries_only_after_the_pause() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::default();
    nft.0.lock().unwrap().fail = Some("boom".into());
    let sampler = make(
        &host,
        &clock,
        Options { ports: ports_of(&[("naive", &[4443], &[])]), nft: Some(nft.clone()), ..Options::default() },
    );
    sampler.tick();
    nft.0.lock().unwrap().fail = None;
    clock.advance(1.0);
    assert_eq!(sampler.tick().unwrap()["kernel_counters"], "unavailable");
    assert!(nft.scripts().is_empty());
}

#[test]
fn no_ports_means_no_nft_calls() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::default();
    let sampler = make(&host, &clock, Options { nft: Some(nft.clone()), ..Options::default() });
    sampler.tick();
    clock.advance(1.0);
    let protocols = sampler.tick().unwrap()["protocols"].clone();
    assert_eq!(protocols.as_object().unwrap().keys().collect::<Vec<_>>(), ["amneziawg"]);
    assert!(nft.scripts().is_empty());
}

#[test]
fn endpoint_shape_and_thread_safety() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let sampler = Arc::new(make(&host, &clock, Options::default()));
    sampler.tick();
    clock.advance(1.0);
    sampler.tick();
    let (status, body) = metrics_response(Some(&sampler));
    assert_eq!(status, 200);
    let keys = |value: &Value| value.as_object().unwrap().keys().cloned().collect::<BTreeSet<String>>();
    let set = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<BTreeSet<String>>();
    assert_eq!(keys(&body), set(&["ts", "interval", "host", "protocols", "kernel_counters"]));
    assert_eq!(
        keys(&body["host"]),
        set(&["cpu_percent", "cores", "load", "mem", "swap", "disk", "net", "uptime_seconds", "containers"])
    );
    assert_eq!(keys(&body["host"]["net"]), set(&["rx_bps", "tx_bps", "interfaces"]));
    assert!(set(&["used", "total", "percent", "read_bps", "write_bps", "busy_percent"])
        .is_subset(&keys(&body["host"]["disk"])));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let sampler = sampler.clone();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    let _ = crate::py::body(&metrics_response(Some(&sampler)).1);
                }
            })
        })
        .collect();
    for _ in 0..50 {
        clock.advance(1.0);
        sampler.tick();
    }
    for reader in readers {
        reader.join().unwrap();
    }
}

#[test]
fn deltas_baseline_then_reset() {
    let mut deltas = Deltas::default();
    assert_eq!(deltas.update("a", 100), 0);
    assert_eq!(deltas.update("a", 150), 50);
    assert_eq!(deltas.update("a", 20), 20);
    assert_eq!(deltas.total("a"), 70);
}

const HEADER: &str =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

fn row(local: &str, state: &str) -> String {
    format!("   0: {local} 0100007F:9C40 {state} 00000000:00000000 00:00000000 00000000     0        0 1 1\n")
}

#[test]
fn connections_count_established_on_protocol_ports_only() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::with(&[
        ("up_naive_tcp_4443", 0),
        ("down_naive_tcp_4443", 0),
        ("up_trusttunnel_tcp_4453", 0),
        ("down_trusttunnel_tcp_4453", 0),
    ]);
    host.dir.write(
        "proc/net/tcp",
        &format!(
            "{HEADER}{}{}{}{}{}{}",
            row("0100007F:115B", "01"),
            row("0100007F:115B", "01"), // 4443 established x2
            row("0100007F:115B", "06"), // TIME_WAIT: ignored
            row("00000000:115B", "0A"), // LISTEN: ignored
            row("0100007F:1165", "01"), // 4453 established
            row("0100007F:1F90", "01"), // unrelated 8080: ignored
        ),
    );
    host.dir.write(
        "proc/net/tcp6",
        &format!(
            "{HEADER}{}{}",
            row("00000000000000000000000001000000:115B", "01"), // 4443 over IPv6
            row("00000000000000000000000001000000:1165", "08"), // CLOSE_WAIT: ignored
        ),
    );
    let sampler = make(
        &host,
        &clock,
        Options {
            nft: Some(nft),
            ports: ports_of(&[("naive", &[4443], &[]), ("trusttunnel", &[4453], &[])]),
            ..Options::default()
        },
    );
    sampler.tick();
    clock.advance(1.0);
    let protocols = sampler.tick().unwrap()["protocols"].clone();
    assert_eq!(protocols["naive"]["connections"], json!(3));
    assert_eq!(protocols["trusttunnel"]["connections"], json!(1));
}

#[test]
fn connections_tolerate_missing_ipv6_and_garbage() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::with(&[("up_naive_tcp_4443", 1000), ("down_naive_tcp_4443", 4000)]);
    host.dir.write("proc/net/tcp", &format!("{HEADER}{}garbage\n0: x y\n", row("0100007F:115B", "01")));
    let sampler = make(
        &host,
        &clock,
        Options { nft: Some(nft), ports: ports_of(&[("naive", &[4443], &[])]), ..Options::default() },
    );
    sampler.tick();
    clock.advance(1.0);
    assert_eq!(sampler.tick().unwrap()["protocols"]["naive"]["connections"], json!(1));
}

#[test]
fn connections_zero_when_files_readable_and_null_without_tcp_ports_or_files() {
    let (mut host, clock) = (FakeHost::new(), TestClock::new());
    host.dir.write("proc/net/tcp", HEADER);
    host.set_net("awg15", (10, 10));
    host.write();
    let nft = FakeNft::with(&[("up_naive_tcp_4443", 1000), ("down_naive_tcp_4443", 4000)]);
    let sampler = make(
        &host,
        &clock,
        Options { nft: Some(nft), ports: ports_of(&[("naive", &[4443], &[])]), ..Options::default() },
    );
    sampler.tick();
    clock.advance(1.0);
    host.set_net("awg15", (20, 30));
    host.write();
    let protocols = sampler.tick().unwrap()["protocols"].clone();
    assert_eq!(protocols["naive"]["connections"], json!(0));
    assert_eq!(protocols["amneziawg"]["connections"], Value::Null); // peer based, not port based
    std::fs::remove_file(host.dir.join("proc/net/tcp")).unwrap();
    clock.advance(1.0);
    assert_eq!(sampler.tick().unwrap()["protocols"]["naive"]["connections"], Value::Null);
}

#[test]
fn mieru_counts_tcp_ports_only() {
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let nft = FakeNft::with(&[("up_mieru_tcp_8443", 0), ("down_mieru_tcp_8443", 0)]);
    host.dir.write("proc/net/tcp", &format!("{HEADER}{}{}", row("0100007F:20FB", "01"), row("0100007F:20FC", "01")));
    let sampler = make(
        &host,
        &clock,
        Options { nft: Some(nft), ports: ports_of(&[("mieru", &[8443], &[8444])]), ..Options::default() },
    );
    sampler.tick();
    clock.advance(1.0);
    assert_eq!(sampler.tick().unwrap()["protocols"]["mieru"]["connections"], json!(1));
}

#[test]
fn counter_names_parse_like_the_python_regex() {
    assert_eq!(counter_name("up_naive_tcp_4443"), Some(("up", "naive")));
    assert_eq!(counter_name("down_mieru_udp_46002"), Some(("down", "mieru")));
    assert_eq!(counter_name("up_naive_tcp_4443\n"), Some(("up", "naive")));
    for bad in [
        "foreign",
        "up_Naive_tcp_1",
        "up_naive_sctp_1",
        "up_naive_tcp_123456",
        "side_naive_tcp_1",
        "up__tcp_1",
        "up_my_x_tcp_1",
    ] {
        assert_eq!(counter_name(bad), None, "{bad}");
    }
}

// --- goldens ------------------------------------------------------------------------------

fn golden(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/metrics").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

#[test]
fn golden_rulesets_are_byte_identical() {
    let maps: Value = serde_json::from_str(&golden("port-maps.json")).unwrap();
    let from_json = |value: &Value| -> PortMap {
        value
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, ports)| {
                let list = |key: &str| -> Vec<u32> {
                    ports
                        .get(key)
                        .and_then(Value::as_array)
                        .map(|l| l.iter().map(|p| p.as_u64().unwrap() as u32).collect())
                        .unwrap_or_default()
                };
                (name.clone(), Ports { tcp: list("tcp"), udp: list("udp") })
            })
            .collect()
    };
    let cases = [
        ("discovered", from_json(&maps["no-override"])),
        ("empty", PortMap::new()),
        ("mtproxy-only", ports_of(&[("mtproxy", &[8445], &[])])),
        ("skips-bad-protocol-names", ports_of(&[("Bad-Name", &[1], &[]), ("naive", &[4443], &[])])),
    ];
    for (name, map) in cases {
        assert_eq!(render_ruleset(&map), golden(&format!("nft/{name}.nft")), "{name}");
    }
}

#[test]
fn golden_parse_counters() {
    let case: Value = serde_json::from_str(&golden("parse-counters.json")).unwrap();
    let parsed = parse_counters(case["input"].as_str().unwrap()).unwrap();
    let expected: Vec<(String, i64)> =
        case["parsed"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), crate::py::as_int(v).unwrap())).collect();
    let mut sorted = parsed.clone();
    sorted.sort();
    assert_eq!(sorted, expected);
    // Python's `isinstance(True, int)`: a boolean byte count is read as 1.
    assert!(parsed.contains(&("foreign".to_string(), 1)));
}

const CONTAINER_IDS: [(&str, char); 3] =
    [("proxy-control-panel", '1'), ("proxy-control-mtproxy", '2'), ("proxy-control-awg-manager", '3')];

fn write_golden_proc(dir: &TempDir, tick: usize) {
    let stat = ["cpu  1000 0 500 8000 100 0 0 0 0 0", "cpu  1333 0 667 8889 112 0 0 0 0 0"][tick];
    dir.write("proc/stat", &format!("{stat}\ncpu0 1 2 3 4 5\n"));
    dir.write(
        "proc/meminfo",
        "MemTotal:        4009296 kB\nMemFree:          500000 kB\nMemAvailable:    2672864 kB\n\
         SwapTotal:       1048572 kB\nSwapFree:         699048 kB\n",
    );
    dir.write("proc/loadavg", ["0.125 0.375 2.675 1/200 3000\n", "0.135 0.385 2.665 2/200 3001\n"][tick]);
    dir.write("proc/uptime", ["12345.67 23456.78\n", "12346.67 23457.78\n"][tick]);
    dir.write("proc/self/mountinfo", "22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n");
    dir.write(
        "proc/diskstats",
        [
            "   8       0 vda1 100 0 2000 50 300 0 4000 60 0 1000 110\n",
            "   8       0 vda1 110 0 2333 55 310 0 4777 66 0 1333 121\n",
        ][tick],
    );
    let header = "Inter-|   Receive                                                |  Transmit\n \
                  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n";
    let rows = [
        "    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n  eth0: 5000000 100 0 0 0 0 0 0 7000000 100 0 0 0 0 0 0\n \
         awg15: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\nveth12: 900 1 0 0 0 0 0 0 900 1 0 0 0 0 0 0\n\
         docker0: 50 1 0 0 0 0 0 0 50 1 0 0 0 0 0 0\nvirt0: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n",
        "    lo: 2000 10 0 0 0 0 0 0 2000 10 0 0 0 0 0 0\n  eth0: 5123457 100 0 0 0 0 0 0 7333333 100 0 0 0 0 0 0\n \
         awg15: 1100 1 0 0 0 0 0 0 1700 1 0 0 0 0 0 0\nveth12: 1900 1 0 0 0 0 0 0 1900 1 0 0 0 0 0 0\n\
         docker0: 50 1 0 0 0 0 0 0 50 1 0 0 0 0 0 0\nvirt0: 2 1 0 0 0 0 0 0 2 1 0 0 0 0 0 0\n",
    ];
    dir.write("proc/net/dev", &format!("{header}{}", rows[tick]));
    dir.write(
        "proc/net/tcp",
        "  sl  local_address rem_address   st\n   0: 0100007F:20FD 0100007F:A000 01 0\n   \
         1: 00000000:01BB 00000000:0000 0A 0\n   2: 0100007F:115B 0100007F:A001 01 0\n   3: 0100007F:115B 0100007F:A002 01 0\n",
    );
    dir.write(
        "proc/net/tcp6",
        "  sl  local_address rem_address   st\n   0: 00000000000000000000000001000000:B3B1 00000000000000000000000001000000:A003 01 0\n",
    );
    for (offset, (_, digit)) in CONTAINER_IDS.iter().enumerate() {
        let id: String = std::iter::repeat_n(*digit, 64).collect();
        let usage = 1_000_000 * (offset + 1) + tick * 123_457 * (offset + 1);
        dir.write(
            &format!("cgroup/system.slice/docker-{id}.scope/cpu.stat"),
            &format!("usage_usec {usage}\nuser_usec 1\n"),
        );
        dir.write(
            &format!("cgroup/system.slice/docker-{id}.scope/memory.current"),
            &format!("{}\n", (offset + 1) * 50_000_000),
        );
    }
}

#[test]
fn golden_sampler_ticks_are_reproduced() {
    let recorded: Value = serde_json::from_str(&golden("sampler.json")).unwrap();
    let dir = TempDir::new("metrics-golden");
    std::fs::create_dir_all(dir.join("virtual-net/virt0")).unwrap();
    let counters: [Vec<(&str, i64)>; 2] = [
        vec![
            ("up_mtproxy_tcp_8445", 1000),
            ("down_mtproxy_tcp_8445", 5000),
            ("up_naive_tcp_4443", 0),
            ("down_naive_tcp_4443", 0),
            ("up_mieru_udp_46002", 7),
        ],
        vec![
            ("up_mtproxy_tcp_8445", 2500),
            ("down_mtproxy_tcp_8445", 4000),
            ("up_naive_tcp_4443", 333),
            ("down_naive_tcp_4443", 777),
            ("up_mieru_udp_46002", 9),
        ],
    ];
    let tick_index = Arc::new(Mutex::new(0usize));
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let (index, recorder) = (tick_index.clone(), calls.clone());
    let table = counters.clone();
    let nft = move |args: &[&str], stdin: Option<&str>| -> Result<String, NftUnavailable> {
        recorder.lock().unwrap().push(json!({"args": args, "stdin": stdin}));
        if args.starts_with(&["-j", "list"]) {
            let items: Vec<Value> = table[*index.lock().unwrap()]
                .iter()
                .map(|(n, b)| json!({"counter": {"name": n, "bytes": b}}))
                .collect();
            return Ok(json!({"nftables": items}).to_string());
        }
        Ok(String::new())
    };
    let listing: String = CONTAINER_IDS
        .iter()
        .map(|(name, digit)| format!("{} {name}\n", std::iter::repeat_n(*digit, 64).collect::<String>()))
        .collect();
    let clocks = Arc::new(Mutex::new(vec![101.0, 100.0]));
    let walls = Arc::new(Mutex::new(vec![1_767_225_600.0 + 1.2346, 1_767_225_600.0 + 0.1234]));
    let port_map = ports_of(&[("mtproxy", &[8445], &[]), ("naive", &[4443], &[]), ("mieru", &[46001], &[46002])]);
    let sampler = MetricsSampler::new(SamplerConfig {
        ports: Box::new(move || Ok(port_map.clone())),
        runner: Arc::new(move |_: &Command| Ok(listing.trim_end().to_string())),
        nft: Box::new(nft),
        clock: Box::new(move || clocks.lock().unwrap().pop().unwrap()),
        wall: Box::new(move || walls.lock().unwrap().pop().unwrap()),
        proc: dir.join("proc"),
        cgroup: dir.join("cgroup"),
        virtual_net: dir.join("virtual-net"),
        root_path: "/".into(),
        root_device: None,
        statvfs: Box::new(|_| Ok(StatVfs { frsize: 4096, blocks: 20_000_000, bfree: 15_000_000, bavail: 14_000_000 })),
        cores: Some(2),
        interval: INTERVAL,
    });
    let mut samples = Vec::new();
    for tick in 0..2 {
        *tick_index.lock().unwrap() = tick;
        write_golden_proc(&dir, tick);
        samples.push(sampler.tick().unwrap_or(Value::Null));
    }
    // Same values and the same bytes Python's json.dumps writes.
    let dump = |value: &Value| pc_host::json::canonical(value);
    assert_eq!(dump(&Value::Array(samples)), dump(&recorded["samples"]));
    assert_eq!(dump(&Value::Array(calls.lock().unwrap().clone())), dump(&recorded["nft_calls"]));
}
