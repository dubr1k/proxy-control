//! Live host telemetry behind `GET /v1/metrics` (`version_agent/hostmetrics.py`).
//!
//! A thread reads /proc, cgroup v2 and an nftables counter table once a second and keeps the
//! latest sample in memory; the HTTP handler only returns that cached sample. The nft rules only
//! count, they never decide a verdict.
//!
//! Bytes in the sample are cumulative since the sampler started counting (a counter that goes
//! down — table recreated, interface reset — is a reset: the new reading is the delta). Rates
//! come from a monotonic clock. Direction is the client's point of view: up = from clients
//! (dport, input hook), down = to clients (sport, output hook). Rounding is Python's `round()`.
//!
//! Clean-up of the kernel side, should the agent be removed: `nft delete table inet
//! proxy_control_metrics`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::metrics_ports::PortMap;
use crate::py;
use crate::runner::{Command, CommandRunner, SystemRunner};

pub const TABLE: &str = "proxy_control_metrics";
pub const INTERVAL: f64 = 1.0;
pub const DISCOVERY_INTERVAL: f64 = 60.0;
pub const CONTAINER_NAMES_TTL: f64 = 30.0;
pub const NFT_RETRY_SECONDS: f64 = 30.0;
const SKIP_PREFIXES: [&str; 7] = ["lo", "veth", "br-", "docker", "awg", "tun", "wg"];
const LOG: &str = "version_agent.metrics";

/// `NftUnavailable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftUnavailable(pub String);

impl std::fmt::Display for NftUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `nft <args>` with an optional script on stdin; its stdout.
pub trait Nft: Send + Sync {
    fn call(&self, args: &[&str], stdin: Option<&str>) -> Result<String, NftUnavailable>;
}

impl<F> Nft for F
where
    F: Fn(&[&str], Option<&str>) -> Result<String, NftUnavailable> + Send + Sync,
{
    fn call(&self, args: &[&str], stdin: Option<&str>) -> Result<String, NftUnavailable> {
        self(args, stdin)
    }
}

/// `_nft`: the real `nft`, 10 s, a non-zero exit is the last stderr line (200 characters).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNft;

impl Nft for SystemNft {
    fn call(&self, args: &[&str], stdin: Option<&str>) -> Result<String, NftUnavailable> {
        let mut argv = vec!["nft"];
        argv.extend_from_slice(args);
        match pc_common::process::run(&argv, stdin.map(str::as_bytes), Duration::from_secs(10)) {
            Ok(output) if output.success() => Ok(output.stdout_text()),
            Ok(output) => {
                let stderr = output.stderr_text();
                let stderr = pc_common::pytext::strip(&stderr);
                Err(NftUnavailable(match pc_common::pytext::splitlines(stderr).last() {
                    Some(line) if !stderr.is_empty() => line.chars().take(200).collect(),
                    _ => "nft failed".into(),
                }))
            }
            Err(pc_common::process::RunError::Spawn(err)) => Err(NftUnavailable(crate::runner::os_class(&err).into())),
            Err(pc_common::process::RunError::Timeout { .. }) => Err(NftUnavailable("TimeoutExpired".into())),
            Err(pc_common::process::RunError::Io(err)) => Err(NftUnavailable(crate::runner::os_class(&err).into())),
        }
    }
}

/// `re.match(r"^[a-z0-9]+$", text)` (`$` also matches before a final newline).
fn is_protocol_name(text: &str) -> bool {
    let text = text.strip_suffix('\n').unwrap_or(text);
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `_COUNTER_NAME.match(name)`: `^(up|down)_([a-z0-9]+)_(tcp|udp)_([0-9]{1,5})$` → (direction,
/// protocol).
fn counter_name(name: &str) -> Option<(&str, &str)> {
    let name = name.strip_suffix('\n').unwrap_or(name);
    let (direction, rest) = name.split_once('_')?;
    if direction != "up" && direction != "down" {
        return None;
    }
    let (rest, port) = rest.rsplit_once('_')?;
    let (protocol, transport) = rest.rsplit_once('_')?;
    let valid = matches!(transport, "tcp" | "udp")
        && (1..=5).contains(&port.len())
        && port.bytes().all(|b| b.is_ascii_digit())
        && is_protocol_name(protocol)
        && !protocol.ends_with('\n');
    valid.then_some((direction, protocol))
}

/// `render_ruleset`: one transaction that drops our table if present and defines it again.
pub fn render_ruleset(port_map: &PortMap) -> String {
    let mut counters = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    for (protocol, ports) in port_map {
        if !is_protocol_name(protocol) {
            continue;
        }
        for (transport, list) in [("tcp", &ports.tcp), ("udp", &ports.udp)] {
            for port in list {
                for (direction, key) in [("up", "dport"), ("down", "sport")] {
                    let name = format!("{direction}_{protocol}_{transport}_{port}");
                    counters.push(format!("    counter {name} {{ }}"));
                    let rule = format!("    {transport} {key} {port} counter name \"{name}\"");
                    if direction == "up" {
                        inputs.push(rule);
                    } else {
                        outputs.push(rule);
                    }
                }
            }
        }
    }
    let mut lines =
        vec![format!("add table inet {TABLE}"), format!("delete table inet {TABLE}"), format!("table inet {TABLE} {{")];
    lines.extend(counters);
    for (chain, rules) in [("input", inputs), ("output", outputs)] {
        lines.push(format!("  chain {chain} {{"));
        lines.push(format!("    type filter hook {chain} priority -300; policy accept;"));
        lines.extend(rules);
        lines.push("  }".into());
    }
    lines.push("}".into());
    lines.join("\n") + "\n"
}

/// `parse_counters`: bytes per named counter of `nft -j list counters table …`, in the order
/// listed (a repeated name keeps its first place and its last value).
pub fn parse_counters(output: &str) -> Result<Vec<(String, i64)>, NftUnavailable> {
    let unparseable = || NftUnavailable("unparseable nft output".into());
    let document: Value = serde_json::from_str(output).map_err(|_| unparseable())?;
    let Some(document) = document.as_object() else {
        return Err(unparseable());
    };
    let items = match document.get("nftables") {
        Some(Value::Array(items)) => items.as_slice(),
        _ => &[],
    };
    let mut found: Vec<(String, i64)> = Vec::new();
    for item in items {
        let Some(counter) = item.get("counter").and_then(Value::as_object) else { continue };
        let (Some(name), Some(bytes)) =
            (counter.get("name").and_then(Value::as_str), counter.get("bytes").and_then(py::as_int))
        else {
            continue;
        };
        match found.iter_mut().find(|(known, _)| known == name) {
            Some(entry) => entry.1 = bytes,
            None => found.push((name.to_string(), bytes)),
        }
    }
    Ok(found)
}

/// Reset-aware deltas and running totals for named monotonic counters.
#[derive(Debug, Default, Clone)]
pub struct Deltas {
    pub previous: HashMap<String, i64>,
    pub totals: HashMap<String, i64>,
}

impl Deltas {
    pub fn update(&mut self, key: &str, value: i64) -> i64 {
        let delta = match self.previous.insert(key.to_string(), value) {
            None => 0, // baseline: a first reading says nothing about a period
            Some(before) if value < before => value,
            Some(before) => value - before,
        };
        *self.totals.entry(key.to_string()).or_insert(0) += delta;
        delta
    }

    pub fn forget_missing<'a>(&mut self, keys: impl IntoIterator<Item = &'a str>) {
        let keep: BTreeSet<&str> = keys.into_iter().collect();
        self.previous.retain(|key, _| keep.contains(key.as_str()));
    }

    pub fn total(&self, key: &str) -> i64 {
        self.totals.get(key).copied().unwrap_or(0)
    }
}

/// `os.statvfs` as an injectable function.
pub type StatVfsFn = dyn Fn(&str) -> io::Result<StatVfs> + Send + Sync;

/// The `statvfs` fields the sampler uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatVfs {
    pub frsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
}

/// `os.statvfs(path)`.
pub fn statvfs(path: &str) -> io::Result<StatVfs> {
    let c_path = std::ffi::CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid NUL-terminated path and a properly sized out-structure.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(StatVfs {
        frsize: stat.f_frsize as u64,
        blocks: stat.f_blocks as u64,
        bfree: stat.f_bfree as u64,
        bavail: stat.f_bavail as u64,
    })
}

/// `os.cpu_count()`: online processors.
pub fn cpu_count() -> Option<i64> {
    // SAFETY: sysconf has no preconditions.
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    (count > 0).then_some(count as i64)
}

/// `time.monotonic()` as seconds.
pub fn monotonic() -> f64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_secs_f64() + 1.0
}

/// `time.time()`.
pub fn wall_clock() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

type Clock = Box<dyn Fn() -> f64 + Send + Sync>;

/// What the sampler reads and runs; every field has the production default.
pub struct SamplerConfig {
    pub ports: Box<dyn Fn() -> Result<PortMap, String> + Send + Sync>,
    pub runner: Arc<dyn CommandRunner>,
    pub nft: Box<dyn Nft>,
    pub clock: Clock,
    pub wall: Clock,
    pub proc: PathBuf,
    pub cgroup: PathBuf,
    pub virtual_net: PathBuf,
    pub root_path: String,
    pub root_device: Option<String>,
    pub statvfs: Box<StatVfsFn>,
    pub cores: Option<i64>,
    pub interval: f64,
}

impl Default for SamplerConfig {
    fn default() -> Self {
        SamplerConfig {
            ports: Box::new(|| Ok(PortMap::new())),
            runner: Arc::new(SystemRunner),
            nft: Box::new(SystemNft),
            clock: Box::new(monotonic),
            wall: Box::new(wall_clock),
            proc: "/proc".into(),
            cgroup: "/sys/fs/cgroup".into(),
            virtual_net: "/sys/devices/virtual/net".into(),
            root_path: "/".into(),
            root_device: None,
            statvfs: Box::new(statvfs),
            cores: cpu_count(),
            interval: INTERVAL,
        }
    }
}

#[derive(Default)]
struct State {
    last_clock: Option<f64>,
    cpu_prev: Option<(i64, i64)>,
    net: Deltas,
    disk: Deltas,
    containers: Deltas,
    kernel: Deltas,
    /// Interface → (rx delta, tx delta) of the last tick, in name order.
    net_delta: Vec<(String, (i64, i64))>,
    proto_totals: HashMap<(String, String), i64>,
    port_map: PortMap,
    ports_checked: Option<f64>,
    applied: Option<PortMap>,
    nft_failed_at: Option<f64>,
    nft_unavailable: bool,
    names: Vec<(String, String)>,
    names_at: Option<f64>,
    device_resolved: bool,
    root_device: Option<String>,
    logged: BTreeSet<&'static str>,
}

impl State {
    fn log_once(&mut self, key: &'static str, message: String) {
        if self.logged.insert(key) {
            log::warn!(target: LOG, "{message}");
        }
    }
}

/// `MetricsSampler`.
pub struct MetricsSampler {
    config: SamplerConfig,
    state: Mutex<State>,
    latest: Mutex<Option<Value>>,
    stop: Arc<(Mutex<bool>, Condvar)>,
}

fn float(value: f64) -> Value {
    Value::from(value)
}

fn rate(delta: i64, elapsed: Option<f64>) -> Value {
    match elapsed {
        Some(elapsed) if elapsed != 0.0 => py::round_json(delta as f64 / elapsed, 1),
        _ => Value::Null,
    }
}

impl MetricsSampler {
    pub fn new(config: SamplerConfig) -> MetricsSampler {
        let state = State {
            device_resolved: config.root_device.is_some(),
            root_device: config.root_device.clone(),
            ..State::default()
        };
        MetricsSampler {
            config,
            state: Mutex::new(state),
            latest: Mutex::new(None),
            stop: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub fn interval(&self) -> f64 {
        self.config.interval
    }

    /// The last published sample.
    pub fn latest(&self) -> Option<Value> {
        self.latest.lock().map(|latest| latest.clone()).unwrap_or(None)
    }

    /// Starts the `host-metrics` thread.
    pub fn start(self: &Arc<Self>) -> io::Result<()> {
        let sampler = Arc::clone(self);
        std::thread::Builder::new().name("host-metrics".into()).spawn(move || sampler.run_loop())?;
        Ok(())
    }

    pub fn stop(&self) {
        let (flag, wake) = &*self.stop;
        if let Ok(mut stopped) = flag.lock() {
            *stopped = true;
            wake.notify_all();
        }
    }

    /// Waits up to `seconds`; true when stopped.
    fn wait(&self, seconds: f64) -> bool {
        let (flag, wake) = &*self.stop;
        let Ok(guard) = flag.lock() else { return true };
        let timeout = Duration::from_secs_f64(seconds.max(0.0));
        match wake.wait_timeout_while(guard, timeout, |stopped| !*stopped) {
            Ok((stopped, _)) => *stopped,
            Err(_) => true,
        }
    }

    fn run_loop(&self) {
        let interval = self.config.interval;
        let mut next_at = monotonic();
        loop {
            if self.stop.0.lock().map(|stopped| *stopped).unwrap_or(true) {
                return;
            }
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.tick())).is_err() {
                log::warn!(target: LOG, "metrics tick failed: panic");
            }
            next_at += interval;
            let mut delay = next_at - monotonic();
            if delay < -5.0 * interval {
                // Stalled (suspend): do not burst to catch up.
                next_at = monotonic();
                delay = 0.0;
            }
            if self.wait(delay) {
                return;
            }
        }
    }

    /// One sampling pass. The first call only primes the baselines and publishes nothing.
    pub fn tick(&self) -> Option<Value> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = (self.config.clock)();
        let elapsed = state.last_clock.map(|last| now - last);
        state.last_clock = Some(now);
        let host = self.host(&mut state, now, elapsed);
        let (protocols, kernel) = self.protocols(&mut state, now, elapsed);
        if !elapsed.is_some_and(|elapsed| elapsed > 0.0) {
            return None;
        }
        let sample = json!({
            "ts": py::round_json((self.config.wall)(), 3),
            "interval": float(self.config.interval),
            "host": host,
            "protocols": protocols,
            "kernel_counters": kernel,
        });
        if let Ok(mut latest) = self.latest.lock() {
            *latest = Some(sample.clone());
        }
        Some(sample)
    }

    // --- host ---------------------------------------------------------------------------

    fn read(&self, relative: &str) -> Option<String> {
        std::fs::read(self.config.proc.join(relative)).ok().and_then(|data| String::from_utf8(data).ok())
    }

    fn cpu_percent(&self, state: &mut State) -> Value {
        let Some(text) = self.read("stat").filter(|t| !t.is_empty()) else { return Value::Null };
        let first = text.split('\n').next().unwrap_or("");
        let fields = pc_common::pytext::split(first);
        if fields.len() < 6 || fields[0] != "cpu" {
            return Value::Null;
        }
        let Ok(values) = fields[1..].iter().map(|v| v.parse::<i64>()).collect::<Result<Vec<_>, _>>() else {
            return Value::Null;
        };
        let current = (values.iter().sum::<i64>(), values[3] + values[4]);
        let Some(previous) = state.cpu_prev.replace(current) else { return Value::Null };
        let (total, idle) = (current.0 - previous.0, current.1 - previous.1);
        if total <= 0 {
            return Value::Null;
        }
        py::round_json((100.0 * (total - idle) as f64 / total as f64).clamp(0.0, 100.0), 1)
    }

    fn meminfo(&self) -> HashMap<String, i64> {
        let mut values = HashMap::new();
        for line in pc_common::pytext::splitlines(&self.read("meminfo").unwrap_or_default()) {
            let (key, rest) = line.split_once(':').unwrap_or((line, ""));
            if let Some(first) = pc_common::pytext::split(rest).first().filter(|f| pc_common::pytext::is_ascii_digits(f)) {
                if let Ok(number) = first.parse::<i64>() {
                    values.insert(key.to_string(), number * 1024);
                }
            }
        }
        values
    }

    fn used(total: Option<i64>, available: Option<i64>) -> Value {
        let (Some(total), Some(available)) = (total.filter(|t| *t != 0), available) else { return Value::Null };
        let available = available.min(total);
        let used = total - available;
        json!({"used": used, "total": total, "percent": py::round_json(100.0 * used as f64 / total as f64, 1), "available": available})
    }

    fn disk_usage(&self) -> Map<String, Value> {
        let mut result = Map::new();
        let Ok(stat) = (self.config.statvfs)(&self.config.root_path) else { return result };
        let total = i128::from(stat.blocks) * i128::from(stat.frsize);
        if total <= 0 {
            return result;
        }
        let used = total - i128::from(stat.bfree) * i128::from(stat.frsize);
        result.insert("used".into(), json!(used as i64));
        result.insert("total".into(), json!(total as i64));
        result.insert("percent".into(), py::round_json(100.0 * used as f64 / total as f64, 1));
        result
    }

    fn resolve_root_device(&self, state: &mut State) -> Option<String> {
        if state.device_resolved {
            return state.root_device.clone();
        }
        state.device_resolved = true;
        for line in pc_common::pytext::splitlines(&self.read("self/mountinfo").unwrap_or_default()) {
            let (head, tail) = line.split_once(" - ").unwrap_or((line, ""));
            let fields = pc_common::pytext::split(head);
            if fields.len() > 4 && fields[4] == "/" && !tail.is_empty() {
                let tail_fields = pc_common::pytext::split(tail);
                let source = tail_fields.get(1).copied().unwrap_or("");
                if source.starts_with("/dev/") {
                    let real = std::fs::canonicalize(source).unwrap_or_else(|_| PathBuf::from(source));
                    state.root_device = real.file_name().map(|name| name.to_string_lossy().into_owned());
                }
            }
        }
        state.root_device.clone()
    }

    fn disk_io(&self, state: &mut State, elapsed: Option<f64>) -> [(&'static str, Value); 3] {
        let empty = [("read_bps", Value::Null), ("write_bps", Value::Null), ("busy_percent", Value::Null)];
        let Some(device) = self.resolve_root_device(state).filter(|d| !d.is_empty()) else { return empty };
        for line in pc_common::pytext::splitlines(&self.read("diskstats").unwrap_or_default()) {
            let parts = pc_common::pytext::split(line);
            if parts.len() > 12 && parts[2] == device {
                let parsed = (parts[5].parse::<i64>(), parts[9].parse::<i64>(), parts[12].parse::<i64>());
                let (Ok(read), Ok(write), Ok(ticks)) = parsed else { return empty };
                let dr = state.disk.update("read", read * 512);
                let dw = state.disk.update("write", write * 512);
                let dt = state.disk.update("ticks", ticks);
                let Some(elapsed) = elapsed.filter(|e| *e > 0.0) else { return empty };
                return [
                    ("read_bps", py::round_json(dr as f64 / elapsed, 1)),
                    ("write_bps", py::round_json(dw as f64 / elapsed, 1)),
                    ("busy_percent", py::round_json((100.0 * dt as f64 / (elapsed * 1000.0)).min(100.0), 1)),
                ];
            }
        }
        empty
    }

    fn net_dev(&self) -> Vec<(String, (i64, i64))> {
        let mut found: Vec<(String, (i64, i64))> = Vec::new();
        let text = self.read("net/dev").unwrap_or_default();
        for line in pc_common::pytext::splitlines(&text).into_iter().skip(2) {
            let (name, rest) = line.split_once(':').unwrap_or((line, ""));
            let fields = pc_common::pytext::split(rest);
            if fields.len() >= 9 && pc_common::pytext::is_ascii_digits(fields[0]) && pc_common::pytext::is_ascii_digits(fields[8]) {
                if let (Ok(rx), Ok(tx)) = (fields[0].parse::<i64>(), fields[8].parse::<i64>()) {
                    let name = pc_common::pytext::strip(name).to_string();
                    match found.iter_mut().find(|(known, _)| *known == name) {
                        Some(entry) => entry.1 = (rx, tx),
                        None => found.push((name, (rx, tx))),
                    }
                }
            }
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        found
    }

    fn network(&self, state: &mut State, elapsed: Option<f64>) -> Value {
        let readings = self.net_dev();
        state.net_delta.clear();
        let keys: Vec<String> = readings.iter().flat_map(|(n, _)| [format!("{n}:rx"), format!("{n}:tx")]).collect();
        state.net.forget_missing(keys.iter().map(String::as_str));
        let elapsed = elapsed.filter(|e| *e != 0.0);
        let (mut rx_total, mut tx_total) = (0.0_f64, 0.0_f64);
        let mut interfaces = Vec::new();
        for (name, (rx, tx)) in readings {
            let drx = state.net.update(&format!("{name}:rx"), rx);
            let dtx = state.net.update(&format!("{name}:tx"), tx);
            state.net_delta.push((name.clone(), (drx, dtx)));
            // Virtual devices (veth, tap, bridges, tunnels under any name) would double-count the NIC.
            if SKIP_PREFIXES.iter().any(|p| name.starts_with(p)) || self.config.virtual_net.join(&name).exists() {
                continue;
            }
            let rx_bps = elapsed.map(|e| py::round(drx as f64 / e, 1));
            let tx_bps = elapsed.map(|e| py::round(dtx as f64 / e, 1));
            rx_total += rx_bps.unwrap_or(0.0);
            tx_total += tx_bps.unwrap_or(0.0);
            interfaces.push(json!({
                "name": name, "rx_bps": rx_bps, "tx_bps": tx_bps,
                "rx_bytes": state.net.total(&format!("{name}:rx")), "tx_bytes": state.net.total(&format!("{name}:tx")),
            }));
        }
        json!({"rx_bps": py::round_json(rx_total, 1), "tx_bps": py::round_json(tx_total, 1), "interfaces": interfaces})
    }

    fn container_names(&self, state: &mut State, now: f64) -> Vec<(String, String)> {
        if state.names_at.is_some_and(|at| now - at < CONTAINER_NAMES_TTL) {
            return state.names.clone();
        }
        state.names_at = Some(now);
        let listing = match self
            .config
            .runner
            .run(&Command::new(&["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"]).timeout(5))
        {
            Ok(listing) => listing,
            Err(err) => {
                // Docker absent or slow: no container section.
                state.log_once("docker-ps", format!("container names unavailable: {}", err.class_name()));
                state.names.clear();
                return Vec::new();
            }
        };
        let mut names: Vec<(String, String)> = Vec::new();
        for line in pc_common::pytext::splitlines(&listing) {
            let line = pc_common::pytext::strip(line);
            let (id, name) = line.split_once(' ').unwrap_or((line, ""));
            if id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) && !name.is_empty() {
                match names.iter_mut().find(|(known, _)| known == id) {
                    Some(entry) => entry.1 = name.to_string(),
                    None => names.push((id.to_string(), name.to_string())),
                }
            }
        }
        state.names = names.clone();
        names
    }

    fn container_stats(&self, state: &mut State, now: f64, elapsed: Option<f64>) -> Value {
        let names = self.container_names(state, now);
        let mut stats = Vec::new();
        let mut seen = Vec::new();
        for (id, name) in names {
            let scope = self.config.cgroup.join("system.slice").join(format!("docker-{id}.scope"));
            let read = |file: &str| std::fs::read(scope.join(file)).ok().and_then(|data| String::from_utf8(data).ok());
            let Some(cpu_text) = read("cpu.stat") else { continue };
            let Some(mem) = read("memory.current").and_then(|text| pc_common::pytext::strip(&text).parse::<i64>().ok()) else {
                continue;
            };
            let usage = pc_common::pytext::splitlines(&cpu_text)
                .into_iter()
                .find(|line| line.starts_with("usage_usec "))
                .and_then(|line| pc_common::pytext::split(line).get(1).and_then(|v| v.parse::<i64>().ok()));
            let Some(usage) = usage else { continue };
            seen.push(name.clone());
            let delta = state.containers.update(&name, usage);
            let percent = match elapsed {
                Some(elapsed) if elapsed != 0.0 => py::round_json(100.0 * delta as f64 / (elapsed * 1_000_000.0), 1),
                _ => Value::Null,
            };
            stats.push((name.clone(), json!({"name": name, "cpu_percent": percent, "mem_bytes": mem})));
        }
        state.containers.forget_missing(seen.iter().map(String::as_str));
        stats.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Array(stats.into_iter().map(|(_, stat)| stat).collect())
    }

    fn host(&self, state: &mut State, now: f64, elapsed: Option<f64>) -> Value {
        let info = self.meminfo();
        let swap = match (info.get("SwapTotal"), info.get("SwapFree")) {
            (Some(&0), Some(_)) => json!({"used": 0, "total": 0, "percent": null, "available": 0}),
            (Some(&total), Some(&free)) => {
                let free = free.min(total);
                json!({"used": total - free, "total": total,
                       "percent": py::round_json(100.0 * (total - free) as f64 / total as f64, 1), "available": free})
            }
            _ => Value::Null,
        };
        let loadavg_text = self.read("loadavg").unwrap_or_default();
        let loadavg: Vec<&str> = pc_common::pytext::split(&loadavg_text).into_iter().take(3).collect();
        let load = if loadavg.len() == 3 {
            loadavg
                .iter()
                .map(|v| v.parse::<f64>().ok().filter(|f| f.is_finite()).map(|f| py::round_json(f, 2)))
                .collect::<Option<Vec<Value>>>()
                .map(Value::Array)
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        let uptime_text = self.read("uptime").unwrap_or_default();
        let uptime = pc_common::pytext::split(&uptime_text)
            .first()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|f| f.is_finite())
            .map(|f| Value::from(f.trunc() as i64))
            .unwrap_or(Value::Null);
        let mut disk = self.disk_usage();
        for (key, value) in self.disk_io(state, elapsed) {
            disk.insert(key.into(), value);
        }
        json!({
            "cpu_percent": self.cpu_percent(state),
            "cores": self.config.cores,
            "load": load,
            "mem": Self::used(info.get("MemTotal").copied(), info.get("MemAvailable").copied()),
            "swap": swap,
            "disk": disk,
            "net": self.network(state, elapsed),
            "uptime_seconds": uptime,
            "containers": self.container_stats(state, now, elapsed),
        })
    }

    // --- protocols ------------------------------------------------------------------------

    fn discover(&self, state: &mut State, now: f64) {
        if state.ports_checked.is_some_and(|checked| now - checked < DISCOVERY_INTERVAL) {
            return;
        }
        state.ports_checked = Some(now);
        match (self.config.ports)() {
            Ok(found) => {
                let mut map = PortMap::new();
                for (protocol, mut ports) in found {
                    for list in [&mut ports.tcp, &mut ports.udp] {
                        list.sort_unstable();
                        list.dedup();
                    }
                    if !ports.tcp.is_empty() || !ports.udp.is_empty() {
                        map.insert(protocol, ports);
                    }
                }
                state.port_map = map;
            }
            // Keep the last known map.
            Err(err) => state.log_once("discover", format!("port discovery failed: {err}")),
        }
    }

    /// `_read_kernel`: our table's counters, (re)creating it when the port map changed.
    fn read_kernel(&self, state: &mut State, now: f64) -> Option<Vec<(String, i64)>> {
        if state.nft_failed_at.is_some_and(|failed| now - failed < NFT_RETRY_SECONDS) {
            return None;
        }
        let result = (|| {
            if state.applied.as_ref() != Some(&state.port_map) {
                self.config.nft.call(&["-f", "-"], Some(&render_ruleset(&state.port_map)))?;
                state.applied = Some(state.port_map.clone());
            }
            parse_counters(&self.config.nft.call(&["-j", "list", "counters", "table", "inet", TABLE], None)?)
        })();
        match result {
            Ok(counters) => {
                state.nft_failed_at = None;
                if state.nft_unavailable {
                    log::info!(target: LOG, "kernel counters available again");
                }
                state.nft_unavailable = false;
                Some(counters)
            }
            Err(err) => {
                state.nft_failed_at = Some(now);
                state.applied = None;
                if !state.nft_unavailable {
                    log::warn!(target: LOG, "kernel counters unavailable: {err}");
                }
                state.nft_unavailable = true;
                None
            }
        }
    }

    /// `_established`: established TCP connections per local port; `None` when unreadable.
    fn established(&self) -> Option<HashMap<u32, i64>> {
        let mut counts = HashMap::new();
        let mut readable = false;
        for name in ["net/tcp", "net/tcp6"] {
            let Some(text) = self.read(name) else { continue };
            readable = true;
            for line in pc_common::pytext::splitlines(&text).into_iter().skip(1) {
                let fields = pc_common::pytext::split(line);
                if fields.len() > 3 && fields[3] == "01" {
                    let port = fields[1].rsplit_once(':').map_or(fields[1], |(_, port)| port);
                    if let Ok(key) = u32::from_str_radix(port, 16) {
                        *counts.entry(key).or_insert(0) += 1;
                    }
                }
            }
        }
        readable.then_some(counts)
    }

    fn protocols(&self, state: &mut State, now: f64, elapsed: Option<f64>) -> (Value, &'static str) {
        self.discover(state, now);
        let elapsed = elapsed.filter(|e| *e != 0.0);
        let mut protocols: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        let counters = if state.port_map.is_empty() { None } else { self.read_kernel(state, now) };
        let kernel = if !state.port_map.is_empty() && counters.is_none() { "unavailable" } else { "ok" };
        if let Some(counters) = counters {
            // protocol → (up delta, up total), (down delta, down total)
            let mut totals: BTreeMap<String, [(i64, i64); 2]> = BTreeMap::new();
            for (name, value) in &counters {
                let Some((direction, protocol)) = counter_name(name) else { continue };
                let delta = state.kernel.update(name, *value);
                let key = (protocol.to_string(), direction.to_string());
                let total = state.proto_totals.entry(key).or_insert(0);
                *total += delta;
                let bucket =
                    &mut totals.entry(protocol.to_string()).or_insert([(0, 0); 2])[usize::from(direction == "down")];
                bucket.0 += delta;
                bucket.1 = *total;
            }
            state.kernel.forget_missing(counters.iter().map(|(name, _)| name.as_str()));
            for (protocol, [up, down]) in totals {
                if !state.port_map.contains_key(&protocol) {
                    continue;
                }
                let entry = json!({"up_bps": rate(up.0, elapsed), "down_bps": rate(down.0, elapsed), "up_bytes": up.1,
                                   "down_bytes": down.1, "source": "kernel"});
                protocols.insert(protocol, entry.as_object().cloned().unwrap_or_default());
            }
        }
        let awg: Vec<&(String, (i64, i64))> =
            state.net_delta.iter().filter(|(name, _)| name.starts_with("awg")).collect();
        if !awg.is_empty() {
            let up: i64 = awg.iter().map(|(_, (rx, _))| rx).sum();
            let down: i64 = awg.iter().map(|(_, (_, tx))| tx).sum();
            let up_bytes: i64 = awg.iter().map(|(name, _)| state.net.total(&format!("{name}:rx"))).sum();
            let down_bytes: i64 = awg.iter().map(|(name, _)| state.net.total(&format!("{name}:tx"))).sum();
            let entry = json!({"up_bps": rate(up, elapsed), "down_bps": rate(down, elapsed), "up_bytes": up_bytes,
                               "down_bytes": down_bytes, "source": "interface"});
            protocols.insert("amneziawg".into(), entry.as_object().cloned().unwrap_or_default());
        }
        // `connections`: established TCP on the protocol's TCP ports.
        let wanted = state.port_map.values().any(|ports| !ports.tcp.is_empty());
        let counts = if wanted { self.established() } else { None };
        for (protocol, entry) in protocols.iter_mut() {
            let tcp = state.port_map.get(protocol).map(|ports| ports.tcp.as_slice()).unwrap_or(&[]);
            let connections = match &counts {
                Some(counts) if !tcp.is_empty() => {
                    json!(tcp.iter().map(|port| counts.get(port).copied().unwrap_or(0)).sum::<i64>())
                }
                _ => Value::Null,
            };
            entry.insert("connections".into(), connections);
        }
        (Value::Object(protocols.into_iter().map(|(k, v)| (k, Value::Object(v))).collect()), kernel)
    }
}

/// `metrics_response()`: the cached sample, never a blocking read.
pub fn metrics_response(sampler: Option<&MetricsSampler>) -> (u16, Value) {
    match sampler.and_then(MetricsSampler::latest) {
        Some(sample) => (200, sample),
        None => (503, json!({"detail": "metrics_warming_up"})),
    }
}

/// The production sampler of an agent: discovery over the agent's Compose directory.
pub fn production(compose_dir: &Path, compose_files: &[String], runner: Arc<dyn CommandRunner>) -> MetricsSampler {
    let sources = crate::metrics_ports::Sources::new(compose_dir, compose_files);
    MetricsSampler::new(SamplerConfig {
        ports: Box::new(move || crate::metrics_ports::discover(&sources)),
        runner,
        ..SamplerConfig::default()
    })
}

#[cfg(test)]
pub(crate) mod tests;
