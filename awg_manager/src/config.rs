//! Environment configuration, validated fail-closed at startup.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crate::ipnet::{ip_network, is_ip_address, Ipv4Net, Network};
use crate::util::{parse_int, py_repr};

pub const KNOWN_VERSIONS: [&str; 3] = ["1.5", "2.0", "3.1"];
/// Lab-only fallback: the installer and scripts/enable-amneziawg.sh always pass AWG_PORTS (free
/// pseudo-random ports); these well-known ports are fingerprinted, so never rely on them on a host.
pub const DEFAULT_PORTS: [(&str, &str); 3] = [("1.5", "51820"), ("2.0", "51821"), ("3.1", "51822")];
pub const DEFAULT_SUBNETS: [(&str, &str); 3] =
    [("1.5", "10.66.15.0/24"), ("2.0", "10.66.20.0/24"), ("3.1", "10.66.31.0/24")];
const LOG_LEVELS: [&str; 3] = ["verbose", "error", "silent"];
const PRIVATE: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// Startup configuration is invalid; the manager refuses to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn fail<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

pub fn interface_name(version: &str) -> String {
    format!("awg{}", version.replace('.', ""))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub token_file: PathBuf,
    pub socket: PathBuf,
    pub socket_mode: u32,
    pub state_dir: PathBuf,
    pub versions: Vec<String>,
    pub ports: BTreeMap<String, u16>,
    pub subnets: BTreeMap<String, Ipv4Net>,
    pub mtu: u64,
    pub dns: Vec<String>,
    pub nat: bool,
    pub log_level: String,
    pub obfuscation_file: Option<PathBuf>,
    /// v3.0.0: the persistent TUN device the Xray-router reads (variant 2), owned by the router's uid.
    pub router_tun: Option<String>,
    pub router_uid: u32,
}

fn pairs(raw: &str, name: &str, defaults: &[(&str, &str)]) -> Result<HashMap<String, String>, ConfigError> {
    let mut out: HashMap<String, String> = defaults.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let mut seen = Vec::new();
    for item in raw.split(',').map(str::trim) {
        if item.is_empty() {
            continue;
        }
        let (key, value) = match item.split_once('=') {
            Some((key, value)) => (key.trim(), value.trim()),
            None => ("", ""),
        };
        if !item.contains('=') || !KNOWN_VERSIONS.contains(&key) || value.is_empty() || seen.contains(&key) {
            return fail(format!("{name}: bad entry {}", py_repr(item)));
        }
        seen.push(key);
        out.insert(key.to_string(), value.to_string());
    }
    Ok(out)
}

fn boolean(raw: &str, name: &str) -> Result<bool, ConfigError> {
    match raw.trim().to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => fail(format!("{name}: expected true or false")),
    }
}

fn int(raw: &str, name: &str, base: u32) -> Result<i64, ConfigError> {
    parse_int(raw, base).ok_or_else(|| ConfigError(format!("{name}: not a number")))
}

/// `[a-z][a-z0-9]{1,14}`.
fn is_short_interface(name: &str) -> bool {
    let bytes = name.as_bytes();
    (2..=15).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

pub fn from_env(env: &HashMap<String, String>) -> Result<Config, ConfigError> {
    let get = |key: &str, default: &str| env.get(key).map(|v| v.trim().to_string()).unwrap_or_else(|| default.into());
    if get("AWG_MANAGER_TOKEN_FILE", "").is_empty() {
        return fail("AWG_MANAGER_TOKEN_FILE is required");
    }

    let raw_versions = get("AWG_VERSIONS", "1.5,2.0,3.1");
    let versions: Vec<String> =
        raw_versions.split(',').map(str::trim).filter(|v| !v.is_empty()).map(String::from).collect();
    let mut distinct = versions.clone();
    distinct.sort();
    distinct.dedup();
    if versions.is_empty() || distinct.len() != versions.len() {
        return fail("AWG_VERSIONS: empty or duplicated");
    }
    if let Some(unknown) = versions.iter().find(|v| !KNOWN_VERSIONS.contains(&v.as_str())) {
        return fail(format!("AWG_VERSIONS: unknown version {}", py_repr(unknown)));
    }

    let ports_raw = pairs(&get("AWG_PORTS", ""), "AWG_PORTS", &DEFAULT_PORTS)?;
    let mut ports = BTreeMap::new();
    for v in &versions {
        ports.insert(v.clone(), int(&ports_raw[v], &format!("AWG_PORTS[{v}]"), 10)?);
    }
    for v in &versions {
        if !(1024..=65535).contains(&ports[v]) {
            return fail(format!("AWG_PORTS[{v}]: must be 1024-65535"));
        }
    }
    let mut distinct_ports: Vec<i64> = ports.values().copied().collect();
    distinct_ports.sort_unstable();
    distinct_ports.dedup();
    if distinct_ports.len() != ports.len() {
        return fail("AWG_PORTS: ports must be distinct");
    }

    let subnets_raw = pairs(&get("AWG_SUBNETS", ""), "AWG_SUBNETS", &DEFAULT_SUBNETS)?;
    let private: Vec<Ipv4Net> = PRIVATE
        .iter()
        .map(|p| match ip_network(p, true) {
            Some(Network::V4(net)) => net,
            _ => unreachable!("constant private ranges"),
        })
        .collect();
    let mut subnets = BTreeMap::new();
    let mut nets = Vec::new();
    for v in &versions {
        let net = match ip_network(&subnets_raw[v], true) {
            None => return fail(format!("AWG_SUBNETS[{v}]: invalid network")),
            Some(Network::V4(net)) if (24..=28).contains(&net.prefix) => net,
            Some(_) => return fail(format!("AWG_SUBNETS[{v}]: must be an IPv4 /24 to /28")),
        };
        if !private.iter().any(|p| net.subnet_of(p)) {
            return fail(format!("AWG_SUBNETS[{v}]: must be inside a private range"));
        }
        subnets.insert(v.clone(), net);
        nets.push(net);
    }
    for (i, a) in nets.iter().enumerate() {
        if nets[i + 1..].iter().any(|b| a.overlaps(b)) {
            return fail("AWG_SUBNETS: subnets overlap");
        }
    }

    let mtu = int(&get("AWG_MTU", "1280"), "AWG_MTU", 10)?;
    if !(1280..=1420).contains(&mtu) {
        return fail("AWG_MTU: must be 1280-1420");
    }

    let raw_dns = get("AWG_DNS", "1.1.1.1,1.0.0.1");
    let dns: Vec<String> = raw_dns.split(',').map(str::trim).filter(|d| !d.is_empty()).map(String::from).collect();
    if !(1..=4).contains(&dns.len()) {
        return fail("AWG_DNS: 1 to 4 addresses");
    }
    if let Some(bad) = dns.iter().find(|d| !is_ip_address(d)) {
        return fail(format!("AWG_DNS: invalid address {}", py_repr(bad)));
    }

    let log_level = get("AWG_LOG_LEVEL", "error").to_lowercase();
    if !LOG_LEVELS.contains(&log_level.as_str()) {
        return fail("AWG_LOG_LEVEL: verbose, error or silent");
    }

    let mode = int(&get("AWG_MANAGER_SOCKET_MODE", "660"), "AWG_MANAGER_SOCKET_MODE", 8)?;
    if !(0 < mode && mode <= 0o777) || mode & 0o007 != 0 {
        return fail("AWG_MANAGER_SOCKET_MODE: must not grant access to others");
    }

    let socket = get("AWG_MANAGER_SOCKET", "/run/awg-manager/manager.sock");
    let state_dir = get("AWG_STATE_DIR", "/var/lib/awg-manager");
    if !socket.starts_with('/') || !state_dir.starts_with('/') {
        return fail("AWG_MANAGER_SOCKET and AWG_STATE_DIR must be absolute");
    }
    let obfuscation_file = get("AWG_OBFUSCATION_FILE", "");
    let router_tun = Some(get("AWG_EGRESS_ROUTER_TUN", "")).filter(|tun| !tun.is_empty());
    if router_tun.as_deref().is_some_and(|tun| !is_short_interface(tun)) {
        return fail("AWG_EGRESS_ROUTER_TUN: a short interface name");
    }
    let router_uid = int(&get("AWG_EGRESS_ROUTER_UID", "10006"), "AWG_EGRESS_ROUTER_UID", 10)?;
    if !(1..=65534).contains(&router_uid) {
        return fail("AWG_EGRESS_ROUTER_UID: a uid");
    }
    let nat = boolean(&get("AWG_NAT", "true"), "AWG_NAT")?;
    Ok(Config {
        token_file: PathBuf::from(get("AWG_MANAGER_TOKEN_FILE", "")),
        socket: PathBuf::from(socket),
        socket_mode: mode as u32,
        state_dir: PathBuf::from(state_dir),
        versions,
        ports: ports.into_iter().map(|(v, port)| (v, port as u16)).collect(),
        subnets,
        mtu: mtu as u64,
        dns,
        nat,
        log_level,
        obfuscation_file: (!obfuscation_file.is_empty()).then(|| PathBuf::from(obfuscation_file)),
        router_tun,
        router_uid: router_uid as u32,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::Path;

    pub fn make_env(dir: &Path, extra: &[(&str, &str)]) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = [
            ("AWG_MANAGER_TOKEN_FILE", dir.join("token")),
            ("AWG_MANAGER_SOCKET", dir.join("run/m.sock")),
            ("AWG_STATE_DIR", dir.join("state")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.display().to_string()))
        .collect();
        for (key, value) in extra {
            env.insert(key.to_string(), value.to_string());
        }
        env
    }

    #[test]
    fn config_defaults() {
        let cfg = from_env(&make_env(Path::new("/tmp/awg"), &[])).unwrap();
        assert_eq!(cfg.versions, ["1.5", "2.0", "3.1"]);
        assert_eq!(
            cfg.ports,
            BTreeMap::from([("1.5".to_string(), 51820), ("2.0".to_string(), 51821), ("3.1".to_string(), 51822)])
        );
        let subnets: Vec<String> = cfg.subnets.values().map(ToString::to_string).collect();
        assert_eq!(subnets, ["10.66.15.0/24", "10.66.20.0/24", "10.66.31.0/24"]);
        assert!(cfg.mtu == 1280 && cfg.dns == ["1.1.1.1", "1.0.0.1"] && cfg.nat);
        assert!(cfg.socket_mode == 0o660 && cfg.log_level == "error");
        assert_eq!((cfg.router_tun, cfg.router_uid, cfg.obfuscation_file), (None, 10006, None));
    }

    #[test]
    fn config_partial_override_and_subset() {
        let cfg = from_env(&make_env(
            Path::new("/tmp/awg"),
            &[
                ("AWG_VERSIONS", "3.1"),
                ("AWG_PORTS", "3.1=60000"),
                ("AWG_SUBNETS", "3.1=192.168.50.0/28"),
                ("AWG_NAT", "false"),
            ],
        ))
        .unwrap();
        assert_eq!(cfg.versions, ["3.1"]);
        assert_eq!(cfg.ports, BTreeMap::from([("3.1".to_string(), 60000)]));
        assert!(!cfg.nat);
    }

    #[test]
    fn config_fails_closed() {
        for (key, value) in [
            ("AWG_VERSIONS", ""),
            ("AWG_VERSIONS", "2.0,2.0"),
            ("AWG_VERSIONS", "4.0"),
            ("AWG_PORTS", "1.5=51821"),
            ("AWG_PORTS", "1.5=80"),
            ("AWG_PORTS", "1.5=99999"),
            ("AWG_PORTS", "9.9=51820"),
            ("AWG_PORTS", "garbage"),
            ("AWG_SUBNETS", "1.5=8.8.8.0/24"),
            ("AWG_SUBNETS", "1.5=10.66.15.0/23"),
            ("AWG_SUBNETS", "1.5=10.66.15.0/29"),
            ("AWG_SUBNETS", "1.5=10.66.15.5/24"),
            ("AWG_SUBNETS", "2.0=10.66.15.0/24"),
            ("AWG_SUBNETS", "1.5=fd00::/120"),
            ("AWG_MTU", "1000"),
            ("AWG_MTU", "x"),
            ("AWG_DNS", "not-an-ip"),
            ("AWG_DNS", ""),
            ("AWG_NAT", "maybe"),
            ("AWG_LOG_LEVEL", "debug"),
            ("AWG_MANAGER_SOCKET_MODE", "666"),
            ("AWG_MANAGER_SOCKET", "relative.sock"),
            ("AWG_EGRESS_ROUTER_TUN", "Bad-Name"),
            ("AWG_EGRESS_ROUTER_UID", "0"),
        ] {
            assert!(from_env(&make_env(Path::new("/tmp/awg"), &[(key, value)])).is_err(), "{key}={value}");
        }
    }

    #[test]
    fn config_requires_token_file() {
        assert!(from_env(&HashMap::new()).unwrap_err().0.contains("AWG_MANAGER_TOKEN_FILE"));
    }

    #[test]
    fn config_messages_quote_the_bad_value() {
        let error = from_env(&make_env(Path::new("/tmp/awg"), &[("AWG_PORTS", "garbage")])).unwrap_err();
        assert_eq!(error.0, "AWG_PORTS: bad entry 'garbage'");
        let error = from_env(&make_env(Path::new("/tmp/awg"), &[("AWG_SUBNETS", "1.5=fd00::/120")])).unwrap_err();
        assert_eq!(error.0, "AWG_SUBNETS[1.5]: must be an IPv4 /24 to /28");
        let cfg = from_env(&make_env(Path::new("/tmp/awg"), &[("AWG_EGRESS_ROUTER_TUN", "awgxr")])).unwrap();
        assert_eq!(cfg.router_tun.as_deref(), Some("awgxr"));
    }
}
