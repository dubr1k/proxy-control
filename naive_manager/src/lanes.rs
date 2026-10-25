//! The lanes block of the NaiveProxy Caddyfile (v0.7, docs/spikes/CHAINS_PER_CLIENT.md).
//!
//! A *lane* is a group of users whose traffic leaves through its own account on the node's
//! Xray-router ingress. With `probe_resistance` a `forward_proxy` handler whose `basic_auth`
//! does not match hands the request to the next handler, so one site carries one handler per
//! lane and the service's own handler comes last with everyone else. The manager owns the
//! block between the LANES markers at the top of `route { }`; a lane with no enabled user
//! renders no handler, and no lane at all renders no block.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::pyutil::{join_lines, leading_space, lstrip, strip};
use crate::text::{basic_auth_pair, starts_with_word};

pub const LANES_BEGIN: &str = "# BEGIN NAIVE-MANAGER LANES";
pub const LANES_END: &str = "# END NAIVE-MANAGER LANES";
pub const MAX_LANES: usize = 32;
pub const MAX_LANE_USERS: usize = 256;

fn chars_in(text: &str, min: usize, max: usize, allowed: impl Fn(u8) -> bool) -> bool {
    (min..=max).contains(&text.len()) && text.bytes().all(allowed)
}

/// `grant:[A-Za-z0-9_-]{1,64}\Z`.
pub fn is_lane_id(text: &str) -> bool {
    text.strip_prefix("grant:")
        .is_some_and(|rest| chars_in(rest, 1, 64, |b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
}

/// `[A-Za-z0-9._-]{1,64}\Z`.
pub fn is_account_user(text: &str) -> bool {
    chars_in(text, 1, 64, |b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `[A-Za-z0-9._~-]{16,128}\Z`.
pub fn is_account_password(text: &str) -> bool {
    chars_in(text, 16, 128, |b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

fn invalid(message: &str) -> Error {
    Error::LanesInvalid(message.into())
}

/// `^\s*forward_proxy(?:\s|$)`.
pub fn is_forward_proxy(line: &str) -> bool {
    starts_with_word(line, "forward_proxy")
}

/// `^\s*route\s*\{\s*(?:#.*)?$`.
fn is_route_open(line: &str) -> bool {
    lstrip(line).strip_prefix("route").is_some_and(|rest| {
        lstrip(rest).strip_prefix('{').is_some_and(|tail| {
            let tail = lstrip(tail);
            tail.is_empty() || tail.starts_with('#')
        })
    })
}

/// Indexes of the marker lines, `None` without a block, `LanesInvalid` when unpaired.
pub fn lanes_span(lines: &[&str]) -> Result<Option<(usize, usize)>> {
    let begins: Vec<usize> = (0..lines.len()).filter(|&i| strip(lines[i]) == LANES_BEGIN).collect();
    let ends: Vec<usize> = (0..lines.len()).filter(|&i| strip(lines[i]) == LANES_END).collect();
    if begins.is_empty() && ends.is_empty() {
        return Ok(None);
    }
    if begins.len() != 1 || ends.len() != 1 || begins[0] >= ends[0] {
        return Err(invalid("managed lanes block must have exactly one marker pair"));
    }
    Ok(Some((begins[0], ends[0])))
}

/// Every line index that is not inside the lanes block.
pub fn outside_lanes(lines: &[&str]) -> Result<Vec<usize>> {
    Ok(match lanes_span(lines)? {
        None => (0..lines.len()).collect(),
        Some((start, end)) => (0..lines.len()).filter(|&i| !(start <= i && i <= end)).collect(),
    })
}

/// One normalised lane of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lane {
    pub lane: String,
    pub users: Vec<String>,
    pub user: String,
    pub password: String,
}

fn keys_are(map: &Map<String, Value>, keys: &[&str]) -> bool {
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}

/// `{"lanes": [{"lane", "users": [...], "upstream": {"user", "password"}}]}`, normalised, or
/// `LanesInvalid`. Every named user must exist, a user sits in at most one lane.
pub fn validate_request(body: &Value, known_users: &HashSet<String>) -> Result<Vec<Lane>> {
    let entries = match body.as_object() {
        Some(map) if keys_are(map, &["lanes"]) => match &map["lanes"] {
            Value::Array(entries) => entries,
            _ => return Err(invalid("invalid lanes request")),
        },
        _ => return Err(invalid("invalid lanes request")),
    };
    if entries.len() > MAX_LANES {
        return Err(invalid("too many lanes"));
    }
    let mut seen_lanes = HashSet::new();
    let mut seen_users = HashSet::new();
    let mut lanes = Vec::new();
    for entry in entries {
        let entry = match entry.as_object() {
            Some(map) if keys_are(map, &["lane", "users", "upstream"]) => map,
            _ => return Err(invalid("invalid lane")),
        };
        let lane = match entry["lane"].as_str() {
            Some(lane) if is_lane_id(lane) && !seen_lanes.contains(lane) => lane.to_string(),
            _ => return Err(invalid("invalid lane id")),
        };
        let users = match &entry["users"] {
            Value::Array(users) if !users.is_empty() && users.len() <= MAX_LANE_USERS => users,
            _ => return Err(invalid("a lane names its users")),
        };
        let mut names = Vec::new();
        for user in users {
            let name = match user.as_str() {
                Some(name) if known_users.contains(name) => name,
                _ => return Err(invalid("unknown lane user")),
            };
            if !seen_users.insert(name.to_string()) {
                return Err(invalid("a user sits in one lane"));
            }
            names.push(name.to_string());
        }
        let (user, password) = match entry["upstream"].as_object() {
            Some(upstream) if keys_are(upstream, &["user", "password"]) => {
                match (upstream["user"].as_str(), upstream["password"].as_str()) {
                    (Some(user), Some(password)) if is_account_user(user) && is_account_password(password) => {
                        (user.to_string(), password.to_string())
                    }
                    _ => return Err(invalid("invalid lane upstream account")),
                }
            }
            _ => return Err(invalid("invalid lane upstream account")),
        };
        seen_lanes.insert(lane.clone());
        lanes.push(Lane { lane, users: names, user, password });
    }
    Ok(lanes)
}

/// One lane's `forward_proxy` handler: its enabled users, the fixed options of the service's
/// own handler, and the lane's upstream.
pub fn handler_lines(users: &[(String, String)], upstream_url: &str, indent: &str) -> Vec<String> {
    let inner = format!("{indent}    ");
    let mut lines = vec![format!("{indent}forward_proxy {{")];
    lines.extend(users.iter().map(|(name, password)| format!("{inner}basic_auth {name} {password}")));
    lines.extend([
        format!("{inner}hide_ip"),
        format!("{inner}hide_via"),
        format!("{inner}probe_resistance"),
        format!("{inner}upstream {upstream_url}"),
        format!("{indent}}}"),
    ]);
    lines
}

/// One lane as the renderer sees it: its enabled users and its upstream URL.
pub type LaneHandler = (Vec<(String, String)>, String);

/// The Caddyfile with the lanes block carrying `lanes`, in order, lanes without users
/// skipped — inserted at the top of `route { }` or replacing the block there; no lanes, no
/// block.
pub fn render(text: &str, lanes: &[LaneHandler]) -> Result<String> {
    let mut lines: Vec<String> = crate::pyutil::splitlines(text).into_iter().map(String::from).collect();
    let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
    let (position, indent) = match lanes_span(&borrowed)? {
        Some((start, end)) => {
            let indent = leading_space(&lines[start]).to_string();
            lines.drain(start..=end);
            (start, indent)
        }
        None => {
            let routes: Vec<usize> = (0..lines.len()).filter(|&i| is_route_open(&lines[i])).collect();
            if routes.len() != 1 {
                return Err(invalid("exactly one route block is required"));
            }
            (routes[0] + 1, format!("{}    ", leading_space(&lines[routes[0]])))
        }
    };
    let mut block = Vec::new();
    for (users, upstream_url) in lanes {
        if !users.is_empty() {
            block.extend(handler_lines(users, upstream_url, &indent));
        }
    }
    if !block.is_empty() {
        block.insert(0, format!("{indent}{LANES_BEGIN}"));
        block.push(format!("{indent}{LANES_END}"));
    }
    lines.splice(position..position, block);
    Ok(join_lines(&lines) + "\n")
}

/// The `basic_auth` pairs of every handler inside the lanes block, handler by handler — what
/// the consistency check compares with the state.
pub fn lane_credentials(text: &str) -> Result<Vec<Vec<(String, String)>>> {
    let lines = crate::pyutil::splitlines(text);
    let Some((start, end)) = lanes_span(&lines)? else { return Ok(Vec::new()) };
    let mut handlers: Vec<Vec<(String, String)>> = Vec::new();
    for line in &lines[start + 1..end] {
        if is_forward_proxy(line) {
            handlers.push(Vec::new());
        } else if let Some((name, password)) = basic_auth_pair(line) {
            match handlers.last_mut() {
                Some(current) => current.push((name.to_string(), password.to_string())),
                None => return Err(invalid("basic_auth outside a lane handler")),
            }
        }
    }
    Ok(handlers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_follow_the_python_patterns() {
        assert!(is_lane_id("grant:7f3a") && is_lane_id(&format!("grant:{}", "a".repeat(64))));
        assert!(!is_lane_id("grant:") && !is_lane_id("svc:naive") && !is_lane_id("grant:a b"));
        assert!(!is_lane_id(&format!("grant:{}", "a".repeat(65))));
        assert!(is_account_user("grant-7f3a") && !is_account_user("bad user"));
        assert!(is_account_password(&"A".repeat(43)) && !is_account_password("short"));
        assert!(is_route_open("    route {") && is_route_open("route{ # c") && !is_route_open("route { x"));
    }

    #[test]
    fn render_inserts_replaces_and_removes_the_block() {
        let text = "x {\n    route {\n        forward_proxy {\n        }\n    }\n}\n";
        let lane: LaneHandler = (vec![("a".into(), "p".into())], "socks5://u:k@127.0.0.1:1".into());
        let one = render(text, std::slice::from_ref(&lane)).unwrap();
        let lines = crate::pyutil::splitlines(&one);
        assert_eq!(lines[2], format!("        {LANES_BEGIN}"));
        assert_eq!(lines[3], "        forward_proxy {");
        assert_eq!(lines[4], "            basic_auth a p");
        assert_eq!(lane_credentials(&one).unwrap(), vec![vec![("a".to_string(), "p".to_string())]]);
        assert_eq!(render(&one, &[]).unwrap(), text);
        assert_eq!(render(text, &[(vec![], "u".into())]).unwrap(), text);
        assert!(lanes_span(&[LANES_BEGIN]).is_err());
    }
}
