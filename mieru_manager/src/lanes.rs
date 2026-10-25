//! Lanes for Mieru (v0.7, docs/spikes/CHAINS_PER_CLIENT.md): one mita daemon per lane.
//!
//! mita has one `egress` section per daemon and no per-user selector, so a lane — a group of
//! users whose traffic leaves through its own account on the node's Xray-router — is one of the
//! *slot* daemons the installer keeps running beside the managed one (`mita@<n>`: its own
//! port, UDS and state directory, idle until a lane is assigned). The main daemon stays the
//! source of truth for users; a slot mirrors its lane's users (name, stored hash, quotas) with
//! an egress that sends everything to the lane's ingress account. A lane user's share link
//! carries the slot's port, which is what makes the lane theirs.
//!
//! The installer names the slots in `MIERU_LANE_SLOTS`:
//!
//! ```text
//! 1:46101:/run/mita/lane-1.sock:/var/lib/mita/lanes/1,2:46102:/run/mita/lane-2.sock:/var/lib/mita/lanes/2
//! ```

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::{pyip, pyjson, pyurl};

pub const MAX_LANES: usize = 32;
pub const MAX_LANE_USERS: usize = 256;
pub const MAX_SLOTS: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub index: u32,
    pub port: u32,
    pub uds: String,
    pub state_dir: String,
}

/// One lane of a validated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneRequest {
    pub lane: String,
    pub users: Vec<String>,
    pub upstream: (String, String),
}

fn lanes_invalid(message: &str) -> Error {
    Error::LanesInvalid(message.into())
}

/// `grant:[A-Za-z0-9_-]{1,64}`.
pub fn is_lane_id(text: &str) -> bool {
    text.strip_prefix("grant:").is_some_and(|id| {
        (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

fn is_account_user(text: &str) -> bool {
    (1..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_account_password(text: &str) -> bool {
    (16..=128).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

/// `MIERU_LANE_SLOTS` as slots, in index order; unique indexes and ports.
pub fn parse_slots(value: Option<&str>) -> Result<Vec<Slot>> {
    let Some(value) = value.filter(|v| !v.is_empty()) else { return Ok(Vec::new()) };
    let mut slots = Vec::new();
    for item in value.split(',') {
        let parts: Vec<&str> = pyjson::strip(item).split(':').collect();
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if parts.len() != 4 || !digits(parts[0]) || !digits(parts[1]) {
            return Err(lanes_invalid("invalid lane slot list"));
        }
        let number = |s: &str| {
            s.trim_start_matches('0').parse::<u64>().unwrap_or(if s.bytes().all(|b| b == b'0') { 0 } else { u64::MAX })
        };
        let (index, port) = (number(parts[0]), number(parts[1]));
        if !(1..=u64::from(MAX_SLOTS)).contains(&index)
            || !(1..=65535).contains(&port)
            || !parts[2].starts_with('/')
            || !parts[3].starts_with('/')
        {
            return Err(lanes_invalid("invalid lane slot"));
        }
        slots.push(Slot { index: index as u32, port: port as u32, uds: parts[2].into(), state_dir: parts[3].into() });
    }
    let indexes: HashSet<u32> = slots.iter().map(|s| s.index).collect();
    let ports: HashSet<u32> = slots.iter().map(|s| s.port).collect();
    if indexes.len() != slots.len() || ports.len() != slots.len() {
        return Err(lanes_invalid("lane slots must have unique indexes and ports"));
    }
    slots.sort_by_key(|slot| slot.index);
    Ok(slots)
}

/// `{"lanes": [{"lane", "users": […], "upstream": {"user", "password"}}]}` normalised, or
/// `LanesInvalid`. Every named user must exist; a user sits in at most one lane.
pub fn validate_request(body: &Value, known_users: &HashSet<String>) -> Result<Vec<LaneRequest>> {
    let entries = match body.as_object() {
        Some(map) if map.len() == 1 => match map.get("lanes") {
            Some(Value::Array(entries)) => entries,
            _ => return Err(lanes_invalid("invalid lanes request")),
        },
        _ => return Err(lanes_invalid("invalid lanes request")),
    };
    if entries.len() > MAX_LANES {
        return Err(lanes_invalid("too many lanes"));
    }
    let mut seen_lanes: HashSet<String> = HashSet::new();
    let mut seen_users: HashSet<String> = HashSet::new();
    let mut lanes = Vec::new();
    for entry in entries {
        let entry = match entry.as_object() {
            Some(e) if e.len() == 3 && ["lane", "users", "upstream"].iter().all(|k| e.contains_key(*k)) => e,
            _ => return Err(lanes_invalid("invalid lane")),
        };
        let lane = match entry["lane"].as_str() {
            Some(lane) if is_lane_id(lane) && !seen_lanes.contains(lane) => lane.to_string(),
            _ => return Err(lanes_invalid("invalid lane id")),
        };
        let users = match &entry["users"] {
            Value::Array(users) if !users.is_empty() && users.len() <= MAX_LANE_USERS => users,
            _ => return Err(lanes_invalid("a lane names its users")),
        };
        let mut names = Vec::new();
        for user in users {
            let Some(user) = user.as_str().filter(|u| known_users.contains(*u)) else {
                return Err(lanes_invalid("unknown lane user"));
            };
            if !seen_users.insert(user.to_string()) {
                return Err(lanes_invalid("a user sits in one lane"));
            }
            names.push(user.to_string());
        }
        let upstream = entry["upstream"].as_object().filter(|u| u.len() == 2);
        let account = upstream.and_then(|u| {
            let user = u.get("user")?.as_str().filter(|s| is_account_user(s))?;
            let password = u.get("password")?.as_str().filter(|s| is_account_password(s))?;
            Some((user.to_string(), password.to_string()))
        });
        let Some(upstream) = account else { return Err(lanes_invalid("invalid lane upstream account")) };
        seen_lanes.insert(lane.clone());
        lanes.push(LaneRequest { lane, users: names, upstream });
    }
    Ok(lanes)
}

fn bindings_of(slot: &Slot) -> Value {
    json!([{"port": slot.port, "protocol": "TCP"}])
}

/// What an unassigned slot runs: its port, nobody, no egress — and it is stopped.
pub fn empty_config(slot: &Slot) -> Value {
    json!({"portBindings": bindings_of(slot), "loggingLevel": "INFO"})
}

/// A lane's mita config: the slot's port, the lane's users as the main daemon stores them
/// (hash, quotas, flags), one proxy — the router ingress with the lane's account — and one
/// rule sending everything through it.
pub fn slot_config(
    slot: &Slot,
    users: Vec<Value>,
    router: (String, u32),
    credential: (&Value, &Value),
    mtu: Option<&Value>,
) -> Value {
    let mut config = Map::new();
    config.insert("portBindings".into(), bindings_of(slot));
    config.insert("loggingLevel".into(), json!("INFO"));
    if !users.is_empty() {
        config.insert("users".into(), Value::Array(users));
    }
    if let Some(mtu) = mtu {
        config.insert("mtu".into(), mtu.clone());
    }
    let (host, port) = router;
    config.insert(
        "egress".into(),
        json!({
            "proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": host, "port": port,
                         "socks5Authentication": {"user": credential.0, "password": credential.1}}],
            "rules": [{"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["router"]}],
        }),
    );
    Value::Object(config)
}

/// The host of a link: an IPv6 literal in brackets.
pub fn link_host(host: &str) -> String {
    if pyip::address_version(host) == Some(6) {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// The link shape of a lane user — the panel fills the credential in.
pub fn share_template(username: &str, host: &str, port: u32, mtu: &Value) -> String {
    let query = pyurl::urlencode(&[
        ("profile", username.to_string()),
        ("port", port.to_string()),
        ("protocol", "TCP".into()),
        ("mtu", pyjson::py_str(mtu)),
    ]);
    format!("mierus://{{username}}:{{password}}@{}?{query}", link_host(host))
}

/// The `port`/`protocol` pairs of a config's bindings and its MTU, as a link carries them.
pub fn binding_query(bindings: &[Value], mtu: &Value) -> Vec<(&'static str, String)> {
    let mut query = Vec::new();
    for binding in bindings {
        let port = binding.get("port").or_else(|| binding.get("portRange")).unwrap_or(&Value::Null);
        query.push(("port", pyjson::py_str(port)));
        query.push(("protocol", pyjson::py_str(binding.get("protocol").unwrap_or(&Value::Null))));
    }
    query.push(("mtu", pyjson::py_str(mtu)));
    query
}

/// The link shape of a user on the main daemon (every port binding), with the profile left to
/// the panel — what a user leaving a lane goes back to.
pub fn service_share_template(host: &str, config: &Map<String, Value>) -> String {
    let bindings = config.get("portBindings").and_then(Value::as_array).cloned().unwrap_or_default();
    let mtu = config.get("mtu").cloned().unwrap_or_else(|| json!(1400));
    let query = pyurl::urlencode(&binding_query(&bindings, &mtu));
    format!("mierus://{{username}}:{{password}}@{}?profile={{profile}}&{query}", link_host(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOTS: &str =
        "1:46101:/run/mita/lane-1.sock:/var/lib/mita/lanes/1,2:46102:/run/mita/lane-2.sock:/var/lib/mita/lanes/2";

    #[test]
    fn parse_slots_reads_the_installer_list() {
        let slot = |index, port, uds: &str, state_dir: &str| Slot {
            index,
            port,
            uds: uds.into(),
            state_dir: state_dir.into(),
        };
        assert_eq!(
            parse_slots(Some(SLOTS)).unwrap(),
            [
                slot(1, 46101, "/run/mita/lane-1.sock", "/var/lib/mita/lanes/1"),
                slot(2, 46102, "/run/mita/lane-2.sock", "/var/lib/mita/lanes/2"),
            ]
        );
        assert!(parse_slots(Some("")).unwrap().is_empty() && parse_slots(None).unwrap().is_empty());
        for bad in [
            "x:46101:/s:/d",
            "1:70000:/s:/d",
            "1:46101:/s",
            "1:46101:/s:/d,1:46102:/t:/e",
            "1:46101:/s:/d,2:46101:/t:/e",
            "0:46101:/s:/d",
            "65:46101:/s:/d",
            "1:46101:s:/d",
        ] {
            assert!(matches!(parse_slots(Some(bad)), Err(Error::LanesInvalid(_))), "{bad}");
        }
        // Out of order in the list, in index order after it.
        let reversed = parse_slots(Some(" 2:46102:/b:/d , 1:46101:/a:/c ")).unwrap();
        assert_eq!(reversed.iter().map(|s| s.index).collect::<Vec<_>>(), [1, 2]);
    }

    #[test]
    fn links_bracket_ipv6_and_carry_every_binding() {
        assert_eq!(link_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(link_host("proxy.example.com"), "proxy.example.com");
        let config =
            json!({"portBindings": [{"port": 8443, "protocol": "TCP"}, {"portRange": "9000-9010", "protocol": "UDP"}]});
        assert_eq!(
            service_share_template("::1", config.as_object().unwrap()),
            "mierus://{username}:{password}@[::1]?profile={profile}&port=8443&protocol=TCP&port=9000-9010&protocol=UDP&mtu=1400"
        );
        assert_eq!(
            share_template("a b", "h.example", 46101, &json!(1280)),
            "mierus://{username}:{password}@h.example?profile=a+b&port=46101&protocol=TCP&mtu=1280"
        );
    }
}
