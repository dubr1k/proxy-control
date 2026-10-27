//! Which listening ports carry each protocol's client traffic, for the kernel byte counters
//! (`version_agent/metrics_ports.py`).
//!
//! The port map comes from files the installer already wrote (the Compose overlay list,
//! `.env*`, the mita server config) and an optional override file; it never runs a command.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

pub const OVERRIDE_FILE: &str = "/etc/proxy-control/metrics-ports.json";
pub const MITA_CONFIG: &str = "/var/lib/mita/server_config.json";
pub const KNOWN_PROTOCOLS: [&str; 4] = ["mtproxy", "naive", "mieru", "trusttunnel"];
pub const DEFAULT_MTPROXY_PORT: u32 = 8445;
pub const DEFAULT_NAIVE_PORT: u32 = 4443;
pub const DEFAULT_TRUSTTUNNEL_PORT: u32 = 4453;
/// A Mieru port range becomes one counter per port; an absurd one must not turn into thousands
/// of firewall rules.
pub const MAX_PORTS_PER_PROTOCOL: usize = 64;

/// The TCP and UDP ports of one protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ports {
    pub tcp: Vec<u32>,
    pub udp: Vec<u32>,
}

impl Ports {
    pub fn tcp(ports: &[u32]) -> Ports {
        Ports { tcp: ports.to_vec(), udp: Vec::new() }
    }

    fn transport(&mut self, name: &str) -> Option<&mut Vec<u32>> {
        match name {
            "tcp" => Some(&mut self.tcp),
            "udp" => Some(&mut self.udp),
            _ => None,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({"tcp": self.tcp, "udp": self.udp})
    }
}

/// `{protocol: {"tcp": [...], "udp": [...]}}`.
pub type PortMap = BTreeMap<String, Ports>;

/// A port map as JSON (the golden form).
pub fn to_json(map: &PortMap) -> Value {
    Value::Object(map.iter().map(|(protocol, ports)| (protocol.clone(), ports.to_json())).collect())
}

/// An env file's `KEY=VALUE` pairs; a missing or unreadable file is empty. `Err` where Python
/// raised out of discovery (a file that is not UTF-8).
pub type EnvReader = dyn Fn(&Path) -> Result<BTreeMap<String, String>, String> + Send + Sync;

static WARNED: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());

fn warn_once(key: &'static str, message: String) {
    if WARNED.lock().map(|mut warned| warned.insert(key)).unwrap_or(false) {
        log::warn!(target: "version_agent.metrics", "{message}");
    }
}

/// `read_env_file`: `KEY=VALUE` lines, comments skipped, matching quotes stripped.
pub fn read_env_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let Ok(data) = std::fs::read(path) else {
        return Ok(BTreeMap::new());
    };
    let text = String::from_utf8(data).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    Ok(parse_env(&text))
}

/// The parser behind [`read_env_file`].
pub fn parse_env(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in pc_common::pytext::splitlines(text) {
        let line = pc_common::pytext::strip(line);
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        let mut value = pc_common::pytext::strip(value);
        let chars: Vec<char> = value.chars().collect();
        if chars.len() >= 2 && chars[0] == chars[chars.len() - 1] && matches!(chars[0], '"' | '\'') {
            value = &value[1..value.len() - 1];
        }
        values.insert(pc_common::pytext::strip(key).to_string(), value.to_string());
    }
    values
}

/// `_valid_port`: an int (not a bool) in 1..=65535.
fn valid_port(value: &Value) -> Option<u32> {
    let port = crate::py::as_strict_int(value)?;
    u32::try_from(port).ok().filter(|port| (1..=65535).contains(port))
}

fn port_in_range(port: u64) -> Option<u32> {
    u32::try_from(port).ok().filter(|port| (1..=65535).contains(port))
}

/// `[0-9]{1,5}` as a number.
fn short_number(text: &str) -> Option<u64> {
    ((1..=5).contains(&text.len()) && pc_common::pytext::is_ascii_digits(text)).then(|| text.parse().unwrap_or(0))
}

/// `_port_from_listen`: `127.0.0.1:4453`, `[::1]:4453` or `4453` -> 4453; else the default.
fn port_from_listen(value: Option<&str>, default: u32) -> u32 {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return default;
    };
    let value = pc_common::pytext::strip(value);
    // `(?:.*:)?([0-9]{1,5})`: digits after the last colon (or alone); `.` stops at a newline.
    let digits = match value.rfind(':') {
        Some(colon) if !value[..colon].contains('\n') => &value[colon + 1..],
        Some(_) => return default,
        None => value,
    };
    short_number(digits).and_then(port_in_range).unwrap_or(default)
}

/// `_mieru_ports`: TCP/UDP ports from the mita server config's `portBindings`.
fn mieru_ports(config_path: &Path) -> Ports {
    let mut found = Ports::default();
    let Ok(data) = std::fs::read(config_path) else {
        return found;
    };
    let Ok(config) = serde_json::from_slice::<Value>(&data) else {
        return found;
    };
    let Some(config) = config.as_object() else {
        return found;
    };
    let bindings = match config.get("portBindings") {
        Some(Value::Array(items)) => items.as_slice(),
        _ => &[],
    };
    for binding in bindings {
        let Some(binding) = binding.as_object() else { continue };
        let transport = match binding.get("protocol") {
            Some(Value::String(text)) => text.to_lowercase(),
            _ => continue,
        };
        let ports: Vec<u32> = if let Some(port) = binding.get("port") {
            valid_port(port).into_iter().collect()
        } else {
            let range = match binding.get("portRange") {
                Some(Value::String(text)) => text.as_str(),
                _ => "",
            };
            match range.split_once('-') {
                Some((low, high)) => match (short_number(low), short_number(high)) {
                    (Some(low), Some(high)) => (low..=high).filter_map(port_in_range).collect(),
                    _ => Vec::new(),
                },
                None => Vec::new(),
            }
        };
        let Some(list) = found.transport(&transport) else { continue };
        for port in ports {
            if !list.contains(&port) {
                list.push(port);
            }
        }
    }
    found
}

/// `_lane_slot_ports`: `MIERU_LANE_SLOTS=1:46101:/sock:/state,2:46102:...` -> [46101, 46102].
fn lane_slot_ports(value: Option<&str>) -> Vec<u32> {
    let mut ports = Vec::new();
    for entry in value.unwrap_or("").split(',') {
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() >= 2 && pc_common::pytext::is_ascii_digits(parts[1]) {
            if let Some(port) = parts[1].parse::<u64>().ok().and_then(port_in_range) {
                ports.push(port);
            }
        }
    }
    ports
}

/// `load_override` without the logging: the validated file, or why it is ignored.
pub fn parse_override(text: &str) -> Result<PortMap, String> {
    let data: Value = serde_json::from_str(text).map_err(|err| err.to_string())?;
    let Some(data) = data.as_object() else {
        return Err("top level must be an object".into());
    };
    let mut result = PortMap::new();
    for (protocol, transports) in data {
        if !KNOWN_PROTOCOLS.contains(&protocol.as_str()) {
            return Err(format!("unknown protocol {}", pc_host::pytext::py_repr(protocol)));
        }
        let Some(transports) = transports.as_object().filter(|t| !t.is_empty()) else {
            return Err(format!("{protocol}: expected an object with tcp/udp lists"));
        };
        let mut entry = Ports::default();
        for (transport, ports) in transports {
            let (Some(list), Some(ports)) = (entry.transport(transport), ports.as_array()) else {
                return Err(format!("{protocol}: bad transport {}", pc_host::pytext::py_repr(transport)));
            };
            for port in ports {
                let Some(port) = valid_port(port) else {
                    return Err(format!("{protocol}: port out of range"));
                };
                if !list.contains(&port) {
                    list.push(port);
                }
            }
        }
        result.insert(protocol.clone(), entry);
    }
    Ok(result)
}

/// `load_override`: the validated override file; malformed content is ignored as a whole, with
/// one log line per process.
pub fn load_override(path: &Path) -> PortMap {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return PortMap::new(),
        Err(err) => {
            warn_once("override-read", format!("metrics port override unreadable: {}", crate::runner::os_class(&err)));
            return PortMap::new();
        }
    };
    match String::from_utf8(data).map_err(|_| "the file is not UTF-8".to_string()).and_then(|t| parse_override(&t)) {
        Ok(map) => map,
        Err(reason) => {
            warn_once("override-invalid", format!("metrics port override ignored: {reason}"));
            PortMap::new()
        }
    }
}

/// Where discovery reads from.
#[derive(Debug, Clone)]
pub struct Sources {
    pub compose_dir: PathBuf,
    pub compose_files: Vec<String>,
    pub override_path: PathBuf,
    pub mita_config: PathBuf,
}

impl Sources {
    pub fn new(compose_dir: impl Into<PathBuf>, compose_files: &[String]) -> Sources {
        Sources {
            compose_dir: compose_dir.into(),
            compose_files: compose_files.to_vec(),
            override_path: OVERRIDE_FILE.into(),
            mita_config: MITA_CONFIG.into(),
        }
    }
}

/// `discover_ports`: the protocols enabled on this host and their ports.
pub fn discover_ports(sources: &Sources, env_reader: &EnvReader) -> Result<PortMap, String> {
    let directory = &sources.compose_dir;
    let files: BTreeSet<&str> = sources.compose_files.iter().map(String::as_str).collect();
    let base = env_reader(&directory.join(".env"))?;
    let mut result = PortMap::new();

    let backend = base.get("MTPROXY_BACKEND_PORT").map(String::as_str).unwrap_or("");
    let mtproxy = if pc_common::pytext::is_ascii_digits(backend) {
        backend.parse::<u64>().ok().and_then(port_in_range).unwrap_or(DEFAULT_MTPROXY_PORT)
    } else {
        DEFAULT_MTPROXY_PORT
    };
    result.insert("mtproxy".into(), Ports::tcp(&[mtproxy]));

    if files.contains("compose.naive.yaml") {
        result.insert("naive".into(), Ports::tcp(&[DEFAULT_NAIVE_PORT]));
    }
    if files.contains("compose.trusttunnel.yaml") {
        let env = env_reader(&directory.join(".env.trusttunnel"))?;
        let port = port_from_listen(env.get("TT_LISTEN").map(String::as_str), DEFAULT_TRUSTTUNNEL_PORT);
        result.insert("trusttunnel".into(), Ports::tcp(&[port]));
    }
    if files.contains("compose.mieru.yaml") {
        let mut mieru = mieru_ports(&sources.mita_config);
        let mut lanes = env_reader(&directory.join(".env"))?;
        lanes.extend(env_reader(&directory.join(".env.mieru"))?);
        for port in lane_slot_ports(lanes.get("MIERU_LANE_SLOTS").map(String::as_str)) {
            if !mieru.tcp.contains(&port) {
                mieru.tcp.push(port);
            }
        }
        if !mieru.tcp.is_empty() || !mieru.udp.is_empty() {
            result.insert("mieru".into(), mieru);
        }
    }
    result.extend(load_override(&sources.override_path));
    for ports in result.values_mut() {
        ports.tcp.sort_unstable();
        ports.tcp.truncate(MAX_PORTS_PER_PROTOCOL);
        ports.udp.sort_unstable();
        ports.udp.truncate(MAX_PORTS_PER_PROTOCOL - ports.tcp.len());
    }
    Ok(result)
}

/// [`discover_ports`] with the real env reader.
pub fn discover(sources: &Sources) -> Result<PortMap, String> {
    discover_ports(sources, &read_env_file)
}

#[cfg(test)]
mod tests;
