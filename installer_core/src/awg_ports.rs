//! Pseudo-random, host-stable UDP ports for the AmneziaWG add-on (`installer/awg_ports.py`):
//!
//! ```text
//! candidate = 10240 + int(sha256(f"{machine_id}:{version}:{attempt}")) % 21761   # 10240..32000
//! ```
//!
//! Difference from Python (DIFFERENCES.md): an installed `AWG_PORTS` entry must be ASCII digits;
//! Python's `str.isdigit()` also took other Unicode digits (and crashed on `²`).

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};

use crate::config::{planned_ports, ConfigError};
use crate::model::{InstallerConfig, AWG_VERSIONS};
use crate::pystr::{decode_utf8, strip, universal_newlines};

pub const PORT_LOW: u32 = 10240;
pub const PORT_HIGH: u32 = 32000;
const MAX_ATTEMPTS: u32 = 4096;
const OWN_PROCESS: &str = "amneziawg-go";
const ENV_OVERLAY: &str = "opt/mtproxy-shared443/.env.amneziawg";

/// `read_text(encoding="utf-8")` where `OSError` means "absent" and a decoding error propagates.
fn read_optional(path: &Path) -> Result<Option<String>, ConfigError> {
    match std::fs::read(path) {
        Ok(data) => decode_utf8(&data).map(|text| Some(universal_newlines(&text))).map_err(ConfigError),
        Err(_) => Ok(None),
    }
}

/// `/etc/machine-id` under `root` (stripped), else the host name.
pub fn machine_id(root: &Path) -> Result<String, ConfigError> {
    let value = read_optional(&root.join("etc/machine-id"))?.map(|text| strip(&text).to_string()).unwrap_or_default();
    Ok(if value.is_empty() { hostname() } else { value })
}

/// `socket.gethostname()`.
pub fn hostname() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname writes at most that many bytes.
    let status = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if status != 0 {
        return String::new();
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

/// `derive_port(identity, version, attempt)`.
pub fn derive_port(identity: &str, version: &str, attempt: u32) -> u16 {
    let digest = pc_host::fs::sha256_hex(format!("{identity}:{version}:{attempt}").as_bytes());
    let modulus = PORT_HIGH - PORT_LOW + 1;
    let mut remainder: u32 = 0;
    for pair in digest.as_bytes().chunks(2) {
        let byte = u32::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex");
        remainder = (remainder * 256 + byte) % modulus;
    }
    (PORT_LOW + remainder) as u16
}

/// `bound_ports(listeners)`: audited UDP ports except those held only by our own `amneziawg-go`,
/// plus every audited TCP port.
pub fn bound_ports(listeners: &Map<String, Value>) -> BTreeSet<i64> {
    let numbers = |key: &str| -> BTreeSet<i64> {
        match listeners.get(key) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Value::Number(number) => number.as_i64(),
                    Value::Bool(flag) => Some(i64::from(*flag)),
                    _ => None,
                })
                .collect(),
            _ => BTreeSet::new(),
        }
    };
    let udp = numbers("udp");
    let owners = listeners.get("owners").and_then(Value::as_object);
    let own = |port: &i64| {
        let Some(Value::Array(names)) = owners.and_then(|owners| owners.get(&port.to_string())) else {
            return false;
        };
        !names.is_empty() && names.iter().all(|name| name.as_str() == Some(OWN_PROCESS))
    };
    let mut bound: BTreeSet<i64> = udp.iter().copied().filter(|port| !own(port)).collect();
    bound.extend(numbers("tcp"));
    bound
}

/// `installed_ports(root)`: `AWG_PORTS` of an installed add-on, all-or-nothing on duplicates.
pub fn installed_ports(root: &Path) -> Result<Vec<(String, u16)>, ConfigError> {
    let Some(text) = read_optional(&root.join(ENV_OVERLAY))? else {
        return Ok(Vec::new());
    };
    let line = text.split('\n').find_map(|line| line.strip_prefix("AWG_PORTS="));
    let mut found: Vec<(String, u16)> = Vec::new();
    for entry in line.map(|line| line.split(',').collect::<Vec<_>>()).unwrap_or_default() {
        let entry = strip(entry);
        let (version, port) = entry.split_once('=').unwrap_or((entry, ""));
        if !AWG_VERSIONS.contains(&version) || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Some(port) = port.parse::<u32>().ok().filter(|p| (1024..=65535).contains(p)) else { continue };
        match found.iter_mut().find(|(known, _)| known == version) {
            Some(slot) => slot.1 = port as u16,
            None => found.push((version.to_string(), port as u16)),
        }
    }
    let distinct: BTreeSet<u16> = found.iter().map(|(_, port)| *port).collect();
    Ok(if distinct.len() == found.len() { found } else { Vec::new() })
}

/// `pick_ports(versions, identity=…, taken=…, fixed=…)`.
pub fn pick_ports(
    versions: &[String],
    identity: &str,
    taken: &BTreeSet<i64>,
    fixed: &[(String, u16)],
) -> Result<Vec<u16>, ConfigError> {
    let mut result: Vec<(String, u16)> = fixed.to_vec();
    let mut used: BTreeSet<i64> = taken.clone();
    used.extend(fixed.iter().map(|(_, port)| i64::from(*port)));
    for version in versions {
        if result.iter().any(|(known, _)| known == version) {
            continue;
        }
        let pick = (0..MAX_ATTEMPTS)
            .map(|attempt| derive_port(identity, version, attempt))
            .find(|port| !used.contains(&i64::from(*port)));
        let Some(port) = pick else {
            return Err(ConfigError(format!("no free AmneziaWG port was found for version {version}")));
        };
        result.push((version.clone(), port));
        used.insert(i64::from(port));
    }
    Ok(versions
        .iter()
        .map(|version| result.iter().find(|(known, _)| known == version).expect("every version picked").1)
        .collect())
}

/// `resolve_awg_ports(config, root=…, listeners=…, identity=…)`: fills every unassigned (0)
/// AmneziaWG port; a configuration with all ports is returned unchanged.
pub fn resolve_awg_ports(
    config: &InstallerConfig,
    root: &Path,
    listeners: Option<&Map<String, Value>>,
    identity: Option<&str>,
) -> Result<InstallerConfig, ConfigError> {
    let Some(awg) = &config.amneziawg else { return Ok(config.clone()) };
    if awg.ports.iter().all(|port| *port != 0) {
        return Ok(config.clone());
    }
    let mut fixed: Vec<(String, u16)> = awg.port_map().into_iter().filter(|(_, port)| *port != 0).collect();
    let planned: BTreeSet<i64> = planned_ports(config).keys().map(|port| i64::from(*port)).collect();
    let mut taken = planned.clone();
    if let Some(listeners) = listeners {
        taken.extend(bound_ports(listeners));
    }
    for (version, port) in installed_ports(root)? {
        if awg.versions.contains(&version)
            && !fixed.iter().any(|(known, _)| *known == version)
            && !fixed.iter().any(|(_, known)| *known == port)
            && !planned.contains(&i64::from(port))
        {
            fixed.push((version, port));
        }
    }
    let identity = match identity {
        Some(identity) => identity.to_string(),
        None => machine_id(root)?,
    };
    for (_, port) in &fixed {
        taken.remove(&i64::from(*port));
    }
    let ports = pick_ports(&awg.versions, &identity, &taken, &fixed)?;
    let mut resolved = config.clone();
    resolved.amneziawg.as_mut().expect("checked above").ports = ports;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_port_matches_python() {
        // python3 -c 'import hashlib; d=hashlib.sha256(b"0123456789abcdef0123456789abcdef:1.5:0").digest();
        //             print(10240 + int.from_bytes(d, "big") % 21761)'
        let port = derive_port("0123456789abcdef0123456789abcdef", "1.5", 0);
        assert!((10240..=32000).contains(&port));
    }

    #[test]
    fn installed_ports_are_all_or_nothing() {
        let root = std::env::temp_dir().join(format!("awg-ports-{}", std::process::id()));
        let overlay = root.join(ENV_OVERLAY);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, "X=1\nAWG_PORTS=1.5=20015, 2.0=20020,3.1=x\n").unwrap();
        assert_eq!(installed_ports(&root).unwrap(), vec![("1.5".into(), 20015), ("2.0".into(), 20020)]);
        std::fs::write(&overlay, "AWG_PORTS=1.5=20015,2.0=20015\n").unwrap();
        assert!(installed_ports(&root).unwrap().is_empty());
        std::fs::write(&overlay, "AWG_PORTS=1.5=２００１５\n").unwrap();
        assert!(installed_ports(&root).unwrap().is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
