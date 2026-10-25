//! The manager's own blocks of the Caddyfile: the USERS block inside the service's
//! `forward_proxy`, the ACCOUNTING log block before `route`, and the checks that nothing
//! else carries credentials. Every function works on the text only.

use serde_json::Value;

use crate::error::{Error, Result};
use crate::lanes::{self, LaneHandler};
use crate::pyutil::{join_lines, leading_space, splitlines, strip};
use crate::text::{basic_auth_pair, is_basic_auth, is_forward_proxy_block, is_route_start};
use crate::traffic::{ACCOUNTING_ROLL_KEEP, ACCOUNTING_ROLL_SIZE_BYTES, MIB};

pub const BEGIN: &str = "# BEGIN NAIVE-MANAGER USERS";
pub const END: &str = "# END NAIVE-MANAGER USERS";
pub const ACCOUNTING_BEGIN: &str = "# BEGIN NAIVE-MANAGER ACCOUNTING";
pub const ACCOUNTING_END: &str = "# END NAIVE-MANAGER ACCOUNTING";

/// The options of the accounting log writer. Caddy shares one writer per file name, so the
/// installer's bootstrap Caddyfile opens the log with exactly these
/// (`tests/test_installer_naive.py` reads this list).
pub const ACCOUNTING_WRITER: [&str; 5] =
    ["mode 0640", "roll_size 10MiB", "roll_keep 10", "roll_keep_for 168h", "roll_uncompressed"];

pub type Credentials = Vec<(String, String)>;

fn owned(pairs: Vec<(&str, &str)>) -> Credentials {
    pairs.into_iter().map(|(u, p)| (u.to_string(), p.to_string())).collect()
}

/// The service's own `forward_proxy` block, outside the lanes block.
pub fn forward_bounds(lines: &[&str]) -> Result<(usize, usize)> {
    let outside = lanes::outside_lanes(lines).map_err(|err| Error::conflict(err.message()))?;
    let directives: Vec<usize> = outside.into_iter().filter(|&i| lanes::is_forward_proxy(lines[i])).collect();
    if directives.len() != 1 {
        return Err(Error::conflict("exactly one forward_proxy block is required"));
    }
    let start = directives[0];
    if !is_forward_proxy_block(lines[start]) {
        return Err(Error::conflict("forward_proxy must use managed block form"));
    }
    let mut depth: i64 = 0;
    for (index, line) in lines.iter().enumerate().skip(start) {
        depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
        if index > start && depth == 0 {
            return Ok((start, index));
        }
    }
    Err(Error::conflict("unterminated forward_proxy block"))
}

/// The `basic_auth` lines of a Caddyfile the manager has not taken over yet.
pub fn legacy_credentials(text: &str) -> Result<Credentials> {
    let lines = splitlines(text);
    let (start, end) = forward_bounds(&lines)?;
    Ok(owned(lines[start + 1..end].iter().filter_map(|line| basic_auth_pair(line)).collect()))
}

pub fn managed_bounds(lines: &[&str]) -> Result<(usize, usize)> {
    let begins: Vec<usize> = (0..lines.len()).filter(|&i| strip(lines[i]) == BEGIN).collect();
    let ends: Vec<usize> = (0..lines.len()).filter(|&i| strip(lines[i]) == END).collect();
    if begins.len() != 1 || ends.len() != 1 {
        return Err(Error::conflict("managed credential block must have exactly one marker pair"));
    }
    let (start, end) = (begins[0], ends[0]);
    let (forward_start, forward_end) = forward_bounds(lines)?;
    if !(forward_start < start && start < end && end < forward_end) {
        return Err(Error::conflict("managed credential block is outside forward_proxy"));
    }
    let span = lanes::lanes_span(lines)?;
    for (index, line) in lines.iter().enumerate() {
        if is_basic_auth(line) && !(start < index && index < end) {
            if span.is_some_and(|(a, b)| a < index && index < b) {
                continue; // a lane handler's user (v0.7)
            }
            return Err(Error::conflict("basic_auth directive outside managed credential block"));
        }
    }
    Ok((start, end))
}

pub fn managed_credentials(text: &str) -> Result<Credentials> {
    let lines = splitlines(text);
    let (start, end) = managed_bounds(&lines)?;
    let mut credentials = Vec::new();
    for line in &lines[start + 1..end] {
        match basic_auth_pair(line) {
            Some(pair) => credentials.push(pair),
            None => return Err(Error::conflict("invalid managed credential directive")),
        }
    }
    Ok(owned(credentials))
}

fn users(state: &Value) -> &[Value] {
    state.get("users").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn text_of(row: &Value, key: &str) -> String {
    match row.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn enabled(row: &Value) -> bool {
    row.get("enabled").is_some_and(|v| matches!(v, Value::Bool(true)) || v.as_i64().is_some_and(|n| n != 0))
}

fn lane_of(row: &Value) -> &Value {
    row.get("lane").unwrap_or(&Value::Null)
}

/// The USERS block: enabled users outside any lane.
pub fn credential_lines(state: &Value, indent: &str) -> Vec<String> {
    let mut lines = vec![format!("{indent}{BEGIN}")];
    for row in users(state) {
        if enabled(row) && lane_of(row).is_null() {
            lines.push(format!("{indent}basic_auth {} {}", text_of(row, "username"), text_of(row, "password")));
        }
    }
    lines.push(format!("{indent}{END}"));
    lines
}

/// Per lane, in state order: its enabled users and its upstream URL.
pub fn lane_handlers(state: &Value) -> Vec<LaneHandler> {
    let Some(lanes) = state.get("lanes").and_then(Value::as_object) else { return Vec::new() };
    lanes
        .iter()
        .map(|(lane, entry)| {
            let members = users(state)
                .iter()
                .filter(|row| enabled(row) && lane_of(row).as_str() == Some(lane.as_str()))
                .map(|row| (text_of(row, "username"), text_of(row, "password")))
                .collect();
            (members, text_of(entry, "upstream"))
        })
        .collect()
}

pub fn accounting_lines(indent: &str) -> Vec<String> {
    debug_assert_eq!(ACCOUNTING_WRITER[1], format!("roll_size {}MiB", ACCOUNTING_ROLL_SIZE_BYTES / MIB));
    debug_assert_eq!(ACCOUNTING_WRITER[2], format!("roll_keep {ACCOUNTING_ROLL_KEEP}"));
    let inner = format!("{indent}    ");
    let deep = format!("{inner}    ");
    let mut lines = vec![
        format!("{indent}{ACCOUNTING_BEGIN}"),
        format!("{indent}log naive_accounting {{"),
        format!("{inner}output file /var/log/naive-proxy/access.json {{"),
    ];
    lines.extend(ACCOUNTING_WRITER.iter().map(|option| format!("{deep}{option}")));
    lines.extend([
        format!("{inner}}}"),
        format!("{inner}format filter {{"),
        format!("{deep}wrap json"),
        format!("{deep}fields {{"),
        format!("{deep}    request>headers>Proxy-Authorization delete"),
        format!("{deep}    user_id regexp ^(invalidbase64|invalidformat|invalid):.*$ invalid"),
        format!("{deep}}}"),
        format!("{inner}}}"),
        format!("{indent}}}"),
        format!("{indent}{ACCOUNTING_END}"),
    ]);
    lines
}

fn single_route(lines: &[String]) -> Result<usize> {
    let routes: Vec<usize> = (0..lines.len()).filter(|&i| is_route_start(&lines[i])).collect();
    if routes.len() != 1 {
        return Err(Error::conflict("exactly one route block is required"));
    }
    Ok(routes[0])
}

/// The first take-over: the `basic_auth` lines become the USERS block, the accounting block
/// goes before `route`.
pub fn render_initial(text: &str, state: &Value) -> Result<String> {
    let lines = splitlines(text);
    let markers = [BEGIN, END, ACCOUNTING_BEGIN, ACCOUNTING_END];
    if lines.iter().any(|line| markers.contains(&strip(line))) {
        return Err(Error::conflict("managed credential markers already present"));
    }
    let (start, end) = forward_bounds(&lines)?;
    let auth: Vec<usize> = (start + 1..end).filter(|&i| is_basic_auth(lines[i])).collect();
    if auth.is_empty() {
        return Err(Error::conflict("basic_auth directives not found"));
    }
    let indent = leading_space(lines[auth[0]]).to_string();
    let block = credential_lines(state, &indent);
    let first = auth[0];
    let mut kept: Vec<String> =
        lines.iter().enumerate().filter(|(i, _)| !auth.contains(i)).map(|(_, l)| l.to_string()).collect();
    kept.splice(first..first, block);
    let route = single_route(&kept)?;
    let site_indent = leading_space(&kept[route]).to_string();
    kept.splice(route..route, accounting_lines(&site_indent));
    Ok(join_lines(&kept) + "\n")
}

pub fn render_managed(text: &str, state: &Value) -> Result<String> {
    let lines = splitlines(text);
    let (start, end) = managed_bounds(&lines)?;
    let indent = leading_space(lines[start]).to_string();
    let mut owned_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    owned_lines.splice(start..=end, credential_lines(state, &indent));
    lanes::render(&(join_lines(&owned_lines) + "\n"), &lane_handlers(state)).map_err(|err| match err {
        Error::LanesInvalid(message) => Error::conflict(message),
        other => other,
    })
}

/// A Caddyfile from before accounting gets the accounting block.
pub fn render_accounting_migration(text: &str) -> Result<String> {
    let lines = splitlines(text);
    if lines.iter().any(|line| [ACCOUNTING_BEGIN, ACCOUNTING_END].contains(&strip(line))) {
        return Err(Error::conflict("partial accounting markers are not migratable"));
    }
    managed_bounds(&lines)?;
    let mut owned_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    let route = single_route(&owned_lines)?;
    let indent = leading_space(&owned_lines[route]).to_string();
    owned_lines.splice(route..route, accounting_lines(&indent));
    Ok(join_lines(&owned_lines) + "\n")
}

pub fn assert_accounting_config(text: &str) -> Result<()> {
    let lines = splitlines(text);
    let begins: Vec<usize> = (0..lines.len()).filter(|&i| strip(lines[i]) == ACCOUNTING_BEGIN).collect();
    let ends: Vec<usize> = (0..lines.len()).filter(|&i| strip(lines[i]) == ACCOUNTING_END).collect();
    if begins.len() != 1 || ends.len() != 1 || begins[0] >= ends[0] {
        return Err(Error::conflict("managed accounting block must have exactly one marker pair"));
    }
    let indent = leading_space(lines[begins[0]]);
    if lines[begins[0]..=ends[0]] != accounting_lines(indent)[..] {
        return Err(Error::conflict("managed accounting block changed outside manager"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounting_writer_options_derive_from_the_rotation_constants() {
        assert_eq!(ACCOUNTING_WRITER[1], format!("roll_size {}MiB", ACCOUNTING_ROLL_SIZE_BYTES / MIB));
        assert_eq!(ACCOUNTING_WRITER[2], format!("roll_keep {ACCOUNTING_ROLL_KEEP}"));
        let lines = accounting_lines("    ");
        assert_eq!(lines[2], "        output file /var/log/naive-proxy/access.json {");
        assert_eq!(lines[3], "            mode 0640");
        assert_eq!(lines.len(), 18);
        assert!(assert_accounting_config(&(join_lines(&lines) + "\n")).is_ok());
    }
}
