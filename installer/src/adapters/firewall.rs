//! Comment-scoped UFW ownership (`installer/adapters/firewall.py`).
//!
//! Planning and every lifecycle transition re-check the audited IPv6 mode. Only exact rules
//! carrying this installer's comments are claimed, repaired or deleted; pre-existing rules are
//! tracked by SHA-256 fingerprints and must survive byte-for-byte as logical UFW entries.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use pc_host::runner::{Bounded, BoundedError, HostRunner};
use serde_json::{json, Map, Value};

use crate::adapter::Adapter;
use crate::adapters::AdapterContext;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::{HostMode, InstallerConfig, ThreeXuiMode};
use crate::planner::{Action, AuditFacts, Evidence};

const STATUS_COMMAND: [&str; 3] = ["ufw", "status", "numbered"];
const IPV6_COMMAND: [&str; 4] = ["grep", "-E", "^IPV6=(yes|no)$", "/etc/default/ufw"];
const HEADER: [&str; 2] =
    ["To                         Action      From", "--                         ------      ----"];
const OWNER: &str = "proxy-control:firewall";
const OWNED_PREFIX: &str = "proxy-control:firewall:";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UfwRule {
    pub port: u16,
    pub protocol: String,
    pub action: String,
    pub source: String,
    pub ipv6: bool,
    pub comment: Option<String>,
    /// Set on forwarding rules only (`port == 0` then).
    pub interface: String,
}

impl UfwRule {
    pub fn logical_key(&self) -> String {
        format!("{}:{}", self.protocol, self.port)
    }
}

pub struct FirewallAdapter {
    runner: Arc<dyn HostRunner>,
}

impl FirewallAdapter {
    pub fn new(context: &AdapterContext) -> FirewallAdapter {
        FirewallAdapter { runner: context.runner.clone() }
    }

    fn authoritative_ipv6_enabled(&self) -> Result<bool, Error> {
        let result = match self.runner.bounded(&IPV6_COMMAND, Bounded::FIREWALL) {
            Ok(result) => result,
            Err(error @ BoundedError::Interrupted) => return Err(error.into()),
            Err(_) => return Err(firewall_error("UFW IPv6 state is unknown")),
        };
        if result.returncode != 0 {
            return Err(firewall_error("UFW IPv6 state is unknown"));
        }
        parse_ufw_ipv6_config(&result.stdout).ok_or_else(|| firewall_error("UFW IPv6 state is unknown"))
    }

    fn assert_ipv6_mode(&self, expected: bool) -> Result<bool, Error> {
        let observed = self.authoritative_ipv6_enabled()?;
        if observed != expected {
            return Err(firewall_error("UFW IPv6 configuration changed after audit"));
        }
        Ok(observed)
    }

    fn status(&self) -> Result<Vec<UfwRule>, Error> {
        let result = self.runner.bounded(&STATUS_COMMAND, Bounded::FIREWALL)?;
        if result.returncode != 0 {
            return Err(firewall_error("UFW status query failed"));
        }
        parse_ufw_status(&result.stdout)
    }

    fn run_checked(&self, argv: &[&str], message: &str) -> Result<(), Error> {
        if self.runner.bounded(argv, Bounded::FIREWALL)?.returncode != 0 {
            return Err(firewall_error(message));
        }
        Ok(())
    }

    fn enable_ufw(&self, ssh_port: u16) -> Result<(), Error> {
        // The SSH allow must succeed before enable: enabling first could lock the operator out.
        let port = ssh_port.to_string();
        self.run_checked(
            &[
                "ufw",
                "allow",
                "proto",
                "tcp",
                "from",
                "any",
                "to",
                "any",
                "port",
                &port,
                "comment",
                "proxy-control: preserved SSH",
            ],
            "refusing to enable UFW: the SSH allow rule could not be added",
        )?;
        self.run_checked(&["ufw", "--force", "enable"], "UFW could not be enabled")
    }

    fn ssh_port(&self, facts: &AuditFacts) -> Result<u16, Error> {
        let tcp = fact_ports(facts.listeners.get("tcp"));
        let socket_ports = fact_ports(facts.listeners.get("ssh_socket_tcp"));
        let Some(owners) = facts.listeners.get("owners").and_then(Value::as_object) else {
            return Err(firewall_error("active SSH listener is not observed"));
        };
        let mut discovered = BTreeSet::new();
        for port in &tcp {
            let Some(raw_names) = owners.get(&port.to_string()).and_then(Value::as_array) else {
                continue;
            };
            let names: BTreeSet<String> =
                raw_names.iter().filter_map(Value::as_str).map(|name| name.to_lowercase()).collect();
            if names.contains("ssh")
                || names.contains("sshd")
                || (socket_ports.contains(port) && names.contains("systemd"))
            {
                discovered.insert(*port);
            }
        }
        if discovered.is_empty() || !discovered.is_subset(&tcp) {
            return Err(firewall_error("active SSH listener is not observed"));
        }
        if discovered.len() != 1 {
            return Err(firewall_error("SSH listener preservation is ambiguous"));
        }
        Ok(*discovered.iter().next().expect("one SSH port"))
    }

    fn enable_needed(facts: &AuditFacts) -> bool {
        let Some(ufw) = facts.ownership.get("ufw").and_then(Value::as_object) else {
            return false;
        };
        if ufw.get("active") == Some(&Value::Bool(true)) {
            return false;
        }
        ufw.get("available") == Some(&Value::Bool(true))
            && ufw.get("mode").and_then(Value::as_str) == Some("managed")
            && ufw.get("observation").and_then(Value::as_str) == Some("observed")
    }

    fn validate_ownership(facts: &AuditFacts, enabling: bool) -> Result<(), Error> {
        let ufw = facts.ownership.get("ufw").and_then(Value::as_object);
        let valid = ufw.is_some_and(|ufw| {
            (enabling || ufw.get("active") == Some(&Value::Bool(true)))
                && ufw.get("available") == Some(&Value::Bool(true))
                && ufw.get("mode").and_then(Value::as_str) == Some("managed")
                && ufw.get("observation").and_then(Value::as_str) == Some("observed")
        });
        if !valid {
            return Err(firewall_error("active managed UFW ownership is not established"));
        }
        if let Some(foreign) = facts.ownership.get("firewall").filter(|value| !value.is_null()) {
            let valid = foreign.as_object().is_some_and(|foreign| {
                foreign.get("backend").is_none_or(|backend| backend.is_null() || backend == "ufw")
            });
            if !valid {
                return Err(firewall_error("foreign firewall ownership is present"));
            }
        }
        Ok(())
    }
}

impl Adapter for FirewallAdapter {
    fn name(&self) -> &str {
        "firewall"
    }

    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        if config.host_mode != HostMode::Fresh || !config.firewall.manage_ufw {
            return Ok(Vec::new());
        }
        if has_hard_stops(facts) {
            return Err(firewall_error("host audit contains blocking findings"));
        }
        let ssh_port = self.ssh_port(facts)?;
        // Planning observes an inactive fresh host; the enable is an apply-time mutation.
        let enable = Self::enable_needed(facts);
        Self::validate_ownership(facts, enable)?;
        let ipv6_enabled = audited_ipv6_enabled(facts)?;
        self.assert_ipv6_mode(ipv6_enabled)?;
        if !enable {
            assert_ssh_preserved(&self.status()?, ssh_port, ipv6_enabled)?;
        }
        let desired = selected_ports(config)?;
        let mut mutations = vec![format!("ssh={ssh_port}"), format!("ipv6={ipv6_enabled}"), format!("enable={enable}")];
        mutations.extend(desired.iter().map(|key| format!("rule={key}")));
        Ok(vec![Action::new(
            "firewall.ufw",
            "firewall",
            OWNER,
            mutations,
            vec![
                format!("active SSH listener on tcp/{ssh_port} has one unambiguous UFW allow rule"),
                "external cloud firewall reachability remains operator-verified".into(),
            ],
            vec!["exact selected-profile UFW rules are active".into()],
            vec!["delete exact comment-scoped rules added by this action".into()],
            false,
        )?])
    }

    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        let desired = action_rules(action)?;
        let ipv6_enabled = self.assert_ipv6_mode(action_ipv6_enabled(action)?)?;
        if action_enable(action) {
            return Ok(firewall_checkpoint_value(&action.owner, &[], &[], &[]));
        }
        let rules = self.status()?;
        assert_ssh_preserved(&rules, action_ssh_port(action)?, ipv6_enabled)?;
        let preexisting: Vec<String> =
            desired.iter().filter(|key| key_covered(&rules, key, ipv6_enabled).unwrap_or(false)).cloned().collect();
        Ok(firewall_checkpoint_value(&action.owner, &fingerprints(&rules), &preexisting, &[]))
    }

    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let desired = action_rules(action)?;
        let ipv6_enabled = self.assert_ipv6_mode(action_ipv6_enabled(action)?)?;
        let (initial, preexisting, recorded_added) = firewall_checkpoint(&checkpoint, &desired)?;
        if action_enable(action) {
            self.enable_ufw(action_ssh_port(action)?)?;
        }
        let mut current = self.status()?;
        assert_foreign_preserved(&initial, &current)?;
        assert_ssh_preserved(&current, action_ssh_port(action)?, ipv6_enabled)?;
        assert_owned_rules_recognized(&current)?;
        for key in &desired {
            if key_covered(&current, key, ipv6_enabled)? {
                continue;
            }
            let argv = allow_argv(key)?;
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run_checked(&refs, "UFW rule creation failed")?;
            current = self.status()?;
            assert_foreign_preserved(&initial, &current)?;
            if !has_exact_owned(&current, key)? {
                return Err(firewall_error("owned UFW rule was not created exactly"));
            }
        }
        let after = self.status()?;
        assert_foreign_preserved(&initial, &after)?;
        let mut installer_added = Vec::new();
        for key in &desired {
            if !preexisting.contains(key) && has_exact_owned(&after, key)? {
                installer_added.push(key.clone());
            }
        }
        let added_set: BTreeSet<&str> = installer_added.iter().map(String::as_str).collect();
        if recorded_added.iter().any(|key| !added_set.contains(key.as_str())) {
            return Err(firewall_error("owned UFW rule has drifted"));
        }
        for key in &desired {
            if !key_covered(&after, key, ipv6_enabled)? {
                return Err(firewall_error("selected-profile UFW rule is absent"));
            }
        }
        Ok(firewall_checkpoint_value(&action.owner, &initial, &preexisting, &installer_added))
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }

    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let desired = action_rules(action)?;
        let ipv6_enabled = self.assert_ipv6_mode(action_ipv6_enabled(action)?)?;
        let (initial, preexisting, installer_added) = firewall_checkpoint(&checkpoint, &desired)?;
        let mut current = self.status()?;
        assert_foreign_preserved(&initial, &current)?;
        assert_owned_rules_recognized(&current)?;
        assert_ssh_preserved(&current, action_ssh_port(action)?, ipv6_enabled)?;
        for key in &installer_added {
            if key_covered(&current, key, ipv6_enabled)? {
                continue;
            }
            let argv = allow_argv(key)?;
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run_checked(&refs, "UFW rule repair failed")?;
            current = self.status()?;
            assert_foreign_preserved(&initial, &current)?;
            if !has_exact_owned(&current, key)? || !key_covered(&current, key, ipv6_enabled)? {
                return Err(firewall_error("owned UFW rule was not repaired exactly"));
            }
        }
        for key in &desired {
            if !key_covered(&current, key, ipv6_enabled)? {
                return Err(firewall_error("selected-profile UFW rule is absent"));
            }
        }
        Ok(firewall_checkpoint_value(&action.owner, &initial, &preexisting, &installer_added))
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let desired = action_rules(action)?;
        let checked = (|| {
            let ipv6_enabled = self.assert_ipv6_mode(action_ipv6_enabled(action)?)?;
            let current = self.status()?;
            assert_owned_rules_recognized(&current)?;
            assert_ssh_preserved(&current, action_ssh_port(action)?, ipv6_enabled)?;
            for key in &desired {
                if !key_covered(&current, key, ipv6_enabled)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })();
        let success = match checked {
            Ok(success) => success,
            Err(error) if is_firewall_error(&error) => false,
            Err(error) => return Err(error),
        };
        let observation = if success {
            "selected-profile UFW rules are active"
        } else {
            "selected-profile UFW rules are absent or ambiguous"
        };
        Ok(Evidence::with_details(
            &action.id,
            success,
            vec![observation.into()],
            Map::from_iter([("rules".into(), json!(desired))]),
        )?)
    }

    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        _purge_data: bool,
        _target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        let desired = action_rules(action)?;
        self.assert_ipv6_mode(action_ipv6_enabled(action)?)?;
        if action_enable(action) {
            // This install switched UFW on, so restoring the host means switching it off. The
            // enabled firewall's rules go with it. Unlike Python, a failed disable is not ignored.
            self.run_checked(&["ufw", "--force", "disable"], "UFW could not be disabled")?;
            return Ok(Evidence::with_details(
                &action.id,
                true,
                vec!["the firewall this installation enabled is off again".into()],
                Map::from_iter([("disabled".into(), Value::Bool(true))]),
            )?);
        }
        let (initial, _preexisting, installer_added) = firewall_checkpoint(&checkpoint, &desired)?;
        let mut current = self.status()?;
        assert_foreign_preserved(&initial, &current)?;
        assert_owned_rules_recognized(&current)?;
        for key in installer_added.iter().rev() {
            if !has_exact_owned(&current, key)? {
                continue;
            }
            let argv = delete_argv(key)?;
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run_checked(&refs, "UFW rule rollback failed")?;
            current = self.status()?;
            assert_foreign_preserved(&initial, &current)?;
            if has_exact_owned(&current, key)? {
                return Err(firewall_error("owned UFW rule remains after rollback"));
            }
        }
        Ok(Evidence::with_details(
            &action.id,
            true,
            vec!["exact installer-owned UFW rules were removed".into()],
            Map::from_iter([("removed".into(), json!(installer_added))]),
        )?)
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        let desired = action_rules(action)?;
        self.assert_ipv6_mode(action_ipv6_enabled(action)?)?;
        let (initial, preexisting, installer_added) = firewall_checkpoint(&checkpoint, &desired)?;
        let current = self.status()?;
        assert_foreign_preserved(&initial, &current)?;
        let mut recovered: BTreeSet<String> = installer_added.into_iter().collect();
        for key in &desired {
            if !preexisting.contains(key) && has_exact_owned(&current, key)? {
                recovered.insert(key.clone());
            }
        }
        let recovered: Vec<String> = desired.iter().filter(|key| recovered.contains(*key)).cloned().collect();
        self.rollback(
            action,
            firewall_checkpoint_value(&action.owner, &initial, &preexisting, &recovered),
            purge_data,
            target,
        )
    }
}

fn firewall_error(message: &str) -> Error {
    Error::other("FirewallError", message)
}

fn is_firewall_error(error: &Error) -> bool {
    matches!(error, Error::Other { class, .. } if class == "FirewallError")
}

fn has_hard_stops(facts: &AuditFacts) -> bool {
    facts.prerequisites.get("hard_stops").and_then(Value::as_array).is_some_and(|stops| !stops.is_empty())
}

fn parse_ufw_ipv6_config(text: &str) -> Option<bool> {
    let assignments: Vec<&str> = py_splitlines(text).into_iter().map(py_trim).filter(|line| !line.is_empty()).collect();
    if assignments.len() != 1 {
        return None;
    }
    match assignments[0] {
        "IPV6=yes" => Some(true),
        "IPV6=no" => Some(false),
        _ => None,
    }
}

pub fn parse_ufw_status(text: &str) -> Result<Vec<UfwRule>, Error> {
    if text.contains('\0') {
        return Err(firewall_error("UFW status output is malformed"));
    }
    let lines = py_splitlines(text);
    if lines.first() != Some(&"Status: active") {
        return Err(firewall_error("UFW is inactive or its status is unknown"));
    }
    let mut cursor = 1;
    while cursor < lines.len() && py_trim(lines[cursor]).is_empty() {
        cursor += 1;
    }
    if cursor + 1 >= lines.len() || py_trim(lines[cursor]) != HEADER[0] || py_trim(lines[cursor + 1]) != HEADER[1] {
        return Err(firewall_error("UFW status output is nonstandard"));
    }
    cursor += 2;
    let mut rules = Vec::new();
    let mut expected_number = 1_u64;
    for line in &lines[cursor..] {
        if py_trim(line).is_empty() {
            continue;
        }
        let (body, raw_comment) = split_comment(line);
        let comment = match raw_comment {
            Some(comment) => {
                let comment = py_trim(comment);
                if comment.is_empty() || comment.chars().count() > 256 || comment.chars().any(|ch| (ch as u32) < 32) {
                    return Err(firewall_error("UFW status output is nonstandard"));
                }
                Some(comment.to_string())
            }
            None => None,
        };
        let Some((number, rest)) = numbered_prefix(body) else {
            return Err(firewall_error("UFW status output is nonstandard"));
        };
        if number != expected_number {
            return Err(firewall_error("UFW status output is nonstandard"));
        }
        expected_number += 1;
        let mut rule = parse_route_rule(rest)
            .or_else(|| parse_port_rule(rest))
            .ok_or_else(|| firewall_error("UFW status output is nonstandard"))?;
        rule.comment = comment;
        rules.push(rule);
    }
    Ok(rules)
}

fn numbered_prefix(line: &str) -> Option<(u64, &str)> {
    let mut cursor = TextCursor::new(line);
    cursor.consume("[")?;
    cursor.skip_whitespace();
    let number = cursor.take_digits();
    if number.is_empty() || number.starts_with('0') {
        return None;
    }
    let number = number.parse().ok()?;
    cursor.consume("]")?;
    cursor.require_whitespace()?;
    Some((number, cursor.remaining()))
}

fn parse_route_rule(text: &str) -> Option<UfwRule> {
    let mut cursor = TextCursor::new(text);
    cursor.consume("Anywhere")?;
    let to_v6 = cursor.consume(" (v6)").is_some();
    cursor.require_whitespace()?;
    cursor.consume("ALLOW FWD")?;
    cursor.require_whitespace()?;
    cursor.consume("Anywhere")?;
    let from_v6 = cursor.consume(" (v6)").is_some();
    cursor.consume(" on ")?;
    let interface = cursor.take_while(|ch| ch.is_ascii_alphanumeric());
    if !valid_route_interface(interface) || !cursor.remaining().is_empty() || to_v6 != from_v6 {
        return None;
    }
    Some(UfwRule {
        port: 0,
        protocol: String::new(),
        action: "ALLOW FWD".into(),
        source: "Anywhere".into(),
        ipv6: to_v6,
        comment: None,
        interface: interface.into(),
    })
}

fn parse_port_rule(text: &str) -> Option<UfwRule> {
    let mut cursor = TextCursor::new(text);
    let port_text = cursor.take_digits();
    if port_text.is_empty() || port_text.starts_with('0') || port_text.len() > 5 || cursor.consume("/").is_none() {
        return None;
    }
    let port: u16 = port_text.parse().ok().filter(|port| *port != 0)?;
    let protocol = if cursor.consume("tcp").is_some() {
        "tcp"
    } else if cursor.consume("udp").is_some() {
        "udp"
    } else {
        return None;
    };
    let to_v6 = cursor.consume(" (v6)").is_some();
    cursor.require_whitespace()?;
    cursor.consume("ALLOW IN")?;
    cursor.require_whitespace()?;
    let mut source_text = py_trim(cursor.remaining());
    if source_text.is_empty() {
        return None;
    }
    let source_v6 = source_text.ends_with(" (v6)");
    if source_v6 {
        source_text = &source_text[..source_text.len() - 5];
    }
    if to_v6 != source_v6 {
        return None;
    }
    Some(UfwRule {
        port,
        protocol: protocol.into(),
        action: "ALLOW IN".into(),
        source: canonical_source(source_text).ok()?,
        ipv6: to_v6,
        comment: None,
        interface: String::new(),
    })
}

struct TextCursor<'a> {
    text: &'a str,
    position: usize,
}

impl<'a> TextCursor<'a> {
    fn new(text: &'a str) -> TextCursor<'a> {
        TextCursor { text, position: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.text[self.position..]
    }

    fn consume(&mut self, prefix: &str) -> Option<&'a str> {
        let consumed = self.remaining().strip_prefix(prefix)?;
        self.position += prefix.len();
        Some(consumed)
    }

    fn skip_whitespace(&mut self) {
        self.position += self.remaining().len() - self.remaining().trim_start_matches(is_python_whitespace).len();
    }

    fn require_whitespace(&mut self) -> Option<()> {
        if !self.remaining().chars().next().is_some_and(is_python_whitespace) {
            return None;
        }
        self.skip_whitespace();
        Some(())
    }

    fn take_digits(&mut self) -> &'a str {
        self.take_while(|ch| ch.is_ascii_digit())
    }

    fn take_while(&mut self, predicate: impl Fn(char) -> bool) -> &'a str {
        let start = self.position;
        for (offset, ch) in self.remaining().char_indices() {
            if !predicate(ch) {
                self.position += offset;
                return &self.text[start..self.position];
            }
        }
        self.position = self.text.len();
        &self.text[start..]
    }
}

fn split_comment(line: &str) -> (&str, Option<&str>) {
    for (index, ch) in line.char_indices() {
        if ch != '#' {
            continue;
        }
        let before = &line[..index];
        let after = &line[index + 1..];
        if before.chars().next_back().is_some_and(is_python_whitespace)
            && after.chars().next().is_some_and(is_python_whitespace)
        {
            return (before.trim_end_matches(is_python_whitespace), Some(after));
        }
    }
    (line.trim_end_matches(is_python_whitespace), None)
}

fn canonical_source(value: &str) -> Result<String, Error> {
    if value == "Anywhere" {
        return Ok(value.into());
    }
    canonical_ip_network(value).ok_or_else(|| firewall_error("UFW status output is nonstandard"))
}

/// `ipaddress.ip_network(value, strict=False)` for the canonical sources UFW prints.
fn canonical_ip_network(value: &str) -> Option<String> {
    let (address, prefix) = value.split_once('/').map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    if prefix.is_some_and(|prefix| prefix.contains('/')) {
        return None;
    }
    if address.contains(':') {
        let (address, _scope) = address.split_once('%').map_or((address, None), |(address, scope)| {
            if scope.is_empty() || scope.contains('%') {
                ("", None)
            } else {
                (address, Some(scope))
            }
        });
        let address = Ipv6Addr::from_str(address).ok()?;
        let bits = match prefix {
            Some(prefix) => parse_prefix_number(prefix, 128)?,
            None => 128,
        };
        let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
        let network = Ipv6Addr::from(u128::from(address) & mask);
        Some(format!("{}/{bits}", canonical_ipv6(&network)))
    } else {
        let address = Ipv4Addr::from_str(address).ok()?;
        let bits = match prefix {
            Some(prefix) => match parse_prefix_number(prefix, 32) {
                Some(bits) => bits,
                None => ipv4_mask_prefix(Ipv4Addr::from_str(prefix).ok()?)?,
            },
            None => 32,
        };
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        let network = Ipv4Addr::from(u32::from(address) & mask);
        Some(format!("{network}/{bits}"))
    }
}

fn parse_prefix_number(prefix: &str, maximum: u32) -> Option<u32> {
    let digits = py_trim(prefix);
    let digits = digits.strip_prefix('+').unwrap_or(digits);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok().filter(|bits| *bits <= maximum)
}

fn ipv4_mask_prefix(mask: Ipv4Addr) -> Option<u32> {
    let mask = u32::from(mask);
    let ones = mask.count_ones();
    let netmask = if ones == 0 { 0 } else { u32::MAX << (32 - ones) };
    if mask == netmask {
        return Some(ones);
    }
    let hostmask = if ones == 0 { u32::MAX } else { (1_u32 << ones) - 1 };
    if mask == hostmask {
        return Some(32 - ones);
    }
    None
}

/// Python 3.13 IPv6 text: longest first zero run, lower-case hex, no special IPv4-mapped form.
fn canonical_ipv6(address: &Ipv6Addr) -> String {
    let groups = address.segments();
    let mut best = (0, 0);
    let mut index = 0;
    while index < groups.len() {
        if groups[index] != 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index < groups.len() && groups[index] == 0 {
            index += 1;
        }
        if index - start > best.1 {
            best = (start, index - start);
        }
    }
    if best.1 == 1 {
        best = (0, 0);
    }
    let mut output = String::new();
    let mut compressed = false;
    let mut index = 0;
    while index < groups.len() {
        if best.1 > 0 && index == best.0 {
            output.push_str("::");
            index += best.1;
            compressed = true;
            continue;
        }
        if index > 0 && !compressed {
            output.push(':');
        }
        output.push_str(&format!("{:x}", groups[index]));
        compressed = false;
        index += 1;
    }
    output
}

fn selected_ports(config: &InstallerConfig) -> Result<Vec<String>, Error> {
    let mut selected: BTreeSet<(String, u16)> = BTreeSet::from([("tcp".into(), 80), ("tcp".into(), 443)]);
    if config.profile.includes_mieru() {
        let Some(mieru) = &config.mieru else {
            return Err(firewall_error("Mieru ports are missing"));
        };
        selected.extend(mieru.tcp_ports.iter().map(|port| ("tcp".into(), *port)));
        selected.extend(mieru.udp_ports.iter().map(|port| ("udp".into(), *port)));
        selected.extend(mieru.slot_ports().into_iter().map(|port| ("tcp".into(), port)));
    }
    let egress = config.effective_egress();
    if egress.router && egress.relay_port != 0 {
        selected.insert(("tcp".into(), egress.relay_port));
    }
    if config.three_xui.mode == ThreeXuiMode::ManagedNew && config.three_xui.hysteria_domain.is_some() {
        selected.insert(("udp".into(), 443));
    }
    let mut routes = Vec::new();
    if let Some(amneziawg) = &config.amneziawg {
        selected.extend(amneziawg.ports.iter().map(|port| ("udp".into(), *port)));
        routes.extend(amneziawg.interfaces().into_iter().map(|interface| format!("route:{interface}")));
    }
    if selected.iter().any(|(_, port)| *port == 0) {
        return Err(Error::other("ValueError", "ports must be integers in 1..65535"));
    }
    let mut keys: Vec<String> = selected.into_iter().map(|(protocol, port)| format!("{protocol}:{port}")).collect();
    keys.extend(routes);
    sort_rule_keys(&mut keys);
    Ok(keys)
}

fn fact_ports(value: Option<&Value>) -> BTreeSet<u16> {
    let Some(values) = value.and_then(Value::as_array) else {
        return BTreeSet::new();
    };
    let mut ports = BTreeSet::new();
    for value in values {
        let Some(port) = value.as_u64().and_then(|port| u16::try_from(port).ok()) else {
            return BTreeSet::new();
        };
        if port == 0 || !ports.insert(port) {
            return BTreeSet::new();
        }
    }
    ports
}

fn audited_ipv6_enabled(facts: &AuditFacts) -> Result<bool, Error> {
    let Some(ufw) = facts.ownership.get("ufw").and_then(Value::as_object) else {
        return Err(firewall_error("active managed UFW ownership is not established"));
    };
    ufw.get("ipv6_enabled").and_then(Value::as_bool).ok_or_else(|| firewall_error("UFW IPv6 state is unknown"))
}

fn assert_ssh_preserved(rules: &[UfwRule], port: u16, ipv6_enabled: bool) -> Result<(), Error> {
    let families: &[bool] = if ipv6_enabled { &[false, true] } else { &[false] };
    for family in families {
        let candidates: BTreeSet<(u16, &str, &str, &str, Option<&str>)> = rules
            .iter()
            .filter(|rule| {
                rule.port == port
                    && rule.protocol == "tcp"
                    && rule.action == "ALLOW IN"
                    && rule.source == "Anywhere"
                    && rule.ipv6 == *family
            })
            .map(|rule| {
                (rule.port, rule.protocol.as_str(), rule.action.as_str(), rule.source.as_str(), rule.comment.as_deref())
            })
            .collect();
        if candidates.is_empty() {
            return Err(firewall_error(&format!(
                "active SSH listener has no preserving {} UFW rule",
                if *family { "IPv6" } else { "IPv4" }
            )));
        }
        if candidates.len() != 1 {
            return Err(firewall_error("SSH listener preservation is ambiguous"));
        }
    }
    Ok(())
}

fn action_rules(action: &Action) -> Result<Vec<String>, Error> {
    if action.adapter != "firewall" || action.id != "firewall.ufw" {
        return Err(firewall_error("firewall action is invalid"));
    }
    let mut values = Vec::new();
    let mut ssh_seen = false;
    let mut ipv6_seen = false;
    let mut enable_seen = false;
    for mutation in &action.mutations {
        let Some((key, value)) = mutation.split_once('=') else {
            return Err(firewall_error("firewall action is invalid"));
        };
        match key {
            "ssh" if !ssh_seen => {
                ssh_seen = true;
                parse_port(value)?;
            }
            "ipv6" if !ipv6_seen => {
                ipv6_seen = true;
                parse_boolean(value)?;
            }
            "enable" if !enable_seen => {
                enable_seen = true;
                parse_boolean(value)?;
            }
            "rule" => {
                validate_key(value)?;
                values.push(value.to_string());
            }
            _ => return Err(firewall_error("firewall action is invalid")),
        }
    }
    if !ssh_seen || !ipv6_seen {
        return Err(firewall_error("firewall action is invalid"));
    }
    let mut normalized = values.clone();
    sort_rule_keys(&mut normalized);
    normalized.dedup();
    if values != normalized {
        return Err(firewall_error("firewall action is invalid"));
    }
    Ok(normalized)
}

fn action_enable(action: &Action) -> bool {
    action.mutations.iter().any(|mutation| mutation == "enable=true")
}

fn action_ssh_port(action: &Action) -> Result<u16, Error> {
    action_value(action, "ssh").and_then(parse_port)
}

fn action_ipv6_enabled(action: &Action) -> Result<bool, Error> {
    action_value(action, "ipv6").and_then(parse_boolean)
}

fn action_value<'a>(action: &'a Action, wanted: &str) -> Result<&'a str, Error> {
    if action.adapter != "firewall" || action.id != "firewall.ufw" {
        return Err(firewall_error("firewall action is invalid"));
    }
    let values: Vec<&str> = action
        .mutations
        .iter()
        .filter_map(|mutation| mutation.split_once('='))
        .filter(|(key, _)| *key == wanted)
        .map(|(_, value)| value)
        .collect();
    if values.len() != 1 {
        return Err(firewall_error("firewall action is invalid"));
    }
    Ok(values[0])
}

fn parse_boolean(value: &str) -> Result<bool, Error> {
    match value {
        "false" => Ok(false),
        "true" => Ok(true),
        _ => Err(firewall_error("firewall action is invalid")),
    }
}

fn parse_port(value: &str) -> Result<u16, Error> {
    if value.is_empty() || value.len() > 5 || value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(firewall_error("firewall action is invalid"));
    }
    value.parse::<u16>().ok().filter(|port| *port != 0).ok_or_else(|| firewall_error("firewall action is invalid"))
}

fn split_key(key: &str) -> Result<(&str, u16), Error> {
    let Some((protocol, port)) = key.split_once(':') else {
        return Err(firewall_error("firewall rule is invalid"));
    };
    if !matches!(protocol, "tcp" | "udp")
        || port.is_empty()
        || port.len() > 5
        || port.starts_with('0')
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(firewall_error("firewall rule is invalid"));
    }
    let port =
        port.parse::<u16>().ok().filter(|port| *port != 0).ok_or_else(|| firewall_error("firewall rule is invalid"))?;
    Ok((protocol, port))
}

fn is_route(key: &str) -> bool {
    key.starts_with("route:")
}

fn route_interface(key: &str) -> Result<&str, Error> {
    let Some(interface) = key.strip_prefix("route:").filter(|interface| valid_route_interface(interface)) else {
        return Err(firewall_error("firewall rule is invalid"));
    };
    Ok(interface)
}

fn valid_route_interface(interface: &str) -> bool {
    let bytes = interface.as_bytes();
    bytes.len() == 5 && &bytes[..3] == b"awg" && bytes[3..].iter().all(u8::is_ascii_digit)
}

fn validate_key(key: &str) -> Result<(), Error> {
    if is_route(key) {
        route_interface(key)?;
    } else {
        split_key(key)?;
    }
    Ok(())
}

fn key_order(key: &str) -> Result<(&str, u16, &str), Error> {
    if is_route(key) {
        return Ok(("route", 0, route_interface(key)?));
    }
    let (protocol, port) = split_key(key)?;
    Ok((protocol, port, ""))
}

fn sort_rule_keys(keys: &mut [String]) {
    keys.sort_by(|left, right| {
        key_order(left).expect("validated rule key").cmp(&key_order(right).expect("validated rule key"))
    });
}

fn owned_comment(key: &str) -> Result<String, Error> {
    let comment = format!("{OWNED_PREFIX}{key}");
    let valid = (1..=128).contains(&comment.len())
        && comment.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'+' | b'-'));
    if !valid {
        return Err(firewall_error("firewall ownership comment is invalid"));
    }
    Ok(comment)
}

fn allow_argv(key: &str) -> Result<Vec<String>, Error> {
    if is_route(key) {
        return Ok(["ufw", "route", "allow", "in", "on", route_interface(key)?, "comment", &owned_comment(key)?]
            .into_iter()
            .map(String::from)
            .collect());
    }
    let (protocol, port) = split_key(key)?;
    let port = port.to_string();
    let comment = owned_comment(key)?;
    Ok(["ufw", "allow", "proto", protocol, "from", "any", "to", "any", "port", &port, "comment", &comment]
        .into_iter()
        .map(String::from)
        .collect())
}

fn delete_argv(key: &str) -> Result<Vec<String>, Error> {
    if is_route(key) {
        return Ok([
            "ufw",
            "--force",
            "route",
            "delete",
            "allow",
            "in",
            "on",
            route_interface(key)?,
            "comment",
            &owned_comment(key)?,
        ]
        .into_iter()
        .map(String::from)
        .collect());
    }
    let (protocol, port) = split_key(key)?;
    let port = port.to_string();
    let comment = owned_comment(key)?;
    Ok([
        "ufw", "--force", "delete", "allow", "proto", protocol, "from", "any", "to", "any", "port", &port, "comment",
        &comment,
    ]
    .into_iter()
    .map(String::from)
    .collect())
}

fn key_covered(rules: &[UfwRule], key: &str, ipv6_enabled: bool) -> Result<bool, Error> {
    if is_route(key) {
        let interface = route_interface(key)?;
        let families: BTreeSet<bool> = rules
            .iter()
            .filter(|rule| rule.action == "ALLOW FWD" && rule.interface == interface && rule.source == "Anywhere")
            .map(|rule| rule.ipv6)
            .collect();
        return Ok(families.contains(&false) && (!ipv6_enabled || families.contains(&true)));
    }
    let (protocol, port) = split_key(key)?;
    let families: BTreeSet<bool> = rules
        .iter()
        .filter(|rule| {
            rule.port == port && rule.protocol == protocol && rule.action == "ALLOW IN" && rule.source == "Anywhere"
        })
        .map(|rule| rule.ipv6)
        .collect();
    Ok(families.contains(&false) && (!ipv6_enabled || families.contains(&true)))
}

fn has_exact_owned(rules: &[UfwRule], key: &str) -> Result<bool, Error> {
    let (port, protocol, action, interface) = if is_route(key) {
        (0, "", "ALLOW FWD", route_interface(key)?)
    } else {
        let (protocol, port) = split_key(key)?;
        (port, protocol, "ALLOW IN", "")
    };
    let expected = owned_comment(key)?;
    let matches: Vec<&UfwRule> =
        rules.iter().filter(|rule| rule.comment.as_deref() == Some(expected.as_str())).collect();
    if matches.iter().any(|rule| {
        rule.port != port
            || rule.protocol != protocol
            || rule.action != action
            || rule.source != "Anywhere"
            || rule.interface != interface
    }) {
        return Err(firewall_error("owned UFW rule has drifted"));
    }
    let logical: BTreeSet<(u16, &str, &str, &str)> = matches
        .iter()
        .map(|rule| (rule.port, rule.protocol.as_str(), rule.action.as_str(), rule.source.as_str()))
        .collect();
    if logical.len() > 1 {
        return Err(firewall_error("owned UFW rule is ambiguous"));
    }
    Ok(!matches.is_empty())
}

fn assert_owned_rules_recognized(rules: &[UfwRule]) -> Result<(), Error> {
    for rule in rules {
        let Some(comment) = rule.comment.as_deref() else {
            continue;
        };
        let Some(key) = comment.strip_prefix(OWNED_PREFIX) else {
            continue;
        };
        validate_key(key)?;
        has_exact_owned(rules, key)?;
    }
    Ok(())
}

fn rule_fingerprint(rule: &UfwRule) -> String {
    let port = rule.port.to_string();
    let mut fields = vec![
        port.as_str(),
        &rule.protocol,
        &rule.action,
        &rule.source,
        if rule.ipv6 { "v6" } else { "v4" },
        rule.comment.as_deref().unwrap_or(""),
    ];
    // Older non-forwarding fingerprints did not have an interface component.
    if !rule.interface.is_empty() {
        fields.push(&rule.interface);
    }
    pc_host::fs::sha256_hex(fields.join("\0").as_bytes())
}

fn fingerprints(rules: &[UfwRule]) -> Vec<String> {
    let mut fingerprints: Vec<String> = rules.iter().map(rule_fingerprint).collect();
    fingerprints.sort();
    fingerprints
}

fn assert_foreign_preserved(initial: &[String], current: &[UfwRule]) -> Result<(), Error> {
    let mut remaining = fingerprints(current);
    for expected in initial {
        let Some(index) = remaining.iter().position(|fingerprint| fingerprint == expected) else {
            return Err(firewall_error("pre-existing UFW rule changed or disappeared"));
        };
        remaining.remove(index);
    }
    Ok(())
}

type FirewallCheckpoint = (Vec<String>, Vec<String>, Vec<String>);

fn firewall_checkpoint(checkpoint: &CheckpointData, desired: &[String]) -> Result<FirewallCheckpoint, Error> {
    const KEYS: [&str; 5] = ["initial_fingerprints", "installer_added", "owner", "ownership", "preexisting"];
    if checkpoint.len() != KEYS.len()
        || KEYS.iter().any(|key| !checkpoint.contains_key(*key))
        || checkpoint["owner"] != OWNER
        || checkpoint["ownership"] != json!({})
    {
        return Err(firewall_error("firewall checkpoint is invalid"));
    }
    let initial = string_tuple(&checkpoint["initial_fingerprints"], false)?;
    if !initial.windows(2).all(|pair| pair[0] <= pair[1])
        || initial
            .iter()
            .any(|item| item.len() != 64 || !item.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    {
        return Err(firewall_error("firewall checkpoint is invalid"));
    }
    let preexisting = string_tuple(&checkpoint["preexisting"], true)?;
    let installer_added = string_tuple(&checkpoint["installer_added"], true)?;
    let preexisting_set: BTreeSet<&str> = preexisting.iter().map(String::as_str).collect();
    let added_set: BTreeSet<&str> = installer_added.iter().map(String::as_str).collect();
    if preexisting_set.iter().any(|key| added_set.contains(key))
        || preexisting
            != desired.iter().filter(|key| preexisting_set.contains(key.as_str())).cloned().collect::<Vec<_>>()
        || installer_added != desired.iter().filter(|key| added_set.contains(key.as_str())).cloned().collect::<Vec<_>>()
    {
        return Err(firewall_error("firewall checkpoint is invalid"));
    }
    for key in preexisting.iter().chain(&installer_added) {
        validate_key(key)?;
    }
    Ok((initial, preexisting, installer_added))
}

fn string_tuple(value: &Value, unique: bool) -> Result<Vec<String>, Error> {
    let Some(values) = value.as_array() else {
        return Err(firewall_error("firewall checkpoint is invalid"));
    };
    let mut parsed = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(firewall_error("firewall checkpoint is invalid"));
        };
        if unique && !seen.insert(value) {
            return Err(firewall_error("firewall checkpoint is invalid"));
        }
        parsed.push(value.to_string());
    }
    Ok(parsed)
}

fn firewall_checkpoint_value(
    owner: &str,
    initial: &[String],
    preexisting: &[String],
    installer_added: &[String],
) -> CheckpointData {
    Map::from_iter([
        ("initial_fingerprints".into(), json!(initial)),
        ("installer_added".into(), json!(installer_added)),
        ("owner".into(), json!(owner)),
        ("ownership".into(), json!({})),
        ("preexisting".into(), json!(preexisting)),
    ])
}

fn py_trim(text: &str) -> &str {
    text.trim_matches(is_python_whitespace)
}

fn is_python_whitespace(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}')
}

/// Python `str.splitlines()` (including its non-ASCII line boundaries).
fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if !matches!(
            ch,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        ) {
            continue;
        }
        lines.push(&text[start..index]);
        if ch == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
            chars.next();
        }
        start = chars.peek().map_or(text.len(), |(next, _)| *next);
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use pc_host::runner::{CallKind, RecordingRunner, Reply};

    use super::*;
    use crate::journal::Status;
    use crate::testkit::{engine_for, plan_with, TempDir};

    #[derive(Default)]
    struct FakeUfw {
        rules: Vec<String>,
        ipv6: bool,
    }

    impl FakeUfw {
        fn status(&self) -> String {
            let mut lines = vec![
                "Status: active".to_string(),
                String::new(),
                format!("     {}", HEADER[0]),
                format!("     {}", HEADER[1]),
            ];
            lines.extend(self.rules.iter().enumerate().map(|(index, rule)| format!("[{:2}] {rule}", index + 1)));
            lines.join("\n") + "\n"
        }
    }

    fn config() -> InstallerConfig {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer/core.toml");
        installer_core::config::load_config(&path).unwrap()
    }

    fn facts() -> AuditFacts {
        AuditFacts {
            listeners: json!({"tcp": [22], "owners": {"22": ["sshd"]}, "ssh_socket_tcp": []}).as_object().unwrap().clone(),
            ownership: json!({"ufw": {"active": true, "available": true, "ipv6_enabled": false, "mode": "managed", "observation": "observed"}})
                .as_object()
                .unwrap()
                .clone(),
            ..AuditFacts::default()
        }
    }

    fn ufw_runner(rules: &[&str]) -> (Arc<RecordingRunner>, Arc<Mutex<FakeUfw>>) {
        let state =
            Arc::new(Mutex::new(FakeUfw { rules: rules.iter().map(|rule| (*rule).into()).collect(), ipv6: false }));
        let responder_state = state.clone();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            let argv: Vec<&str> = call.argv.iter().map(String::as_str).collect();
            let mut state = responder_state.lock().unwrap();
            if argv == IPV6_COMMAND {
                return Some(Reply::ok(if state.ipv6 { "IPV6=yes\n" } else { "IPV6=no\n" }));
            }
            if argv == STATUS_COMMAND {
                return Some(Reply::ok(&state.status()));
            }
            if argv.starts_with(&["ufw", "allow"]) {
                let protocol = argv[argv.iter().position(|part| *part == "proto").unwrap() + 1];
                let port = argv[argv.iter().position(|part| *part == "port").unwrap() + 1];
                let comment = argv[argv.iter().position(|part| *part == "comment").unwrap() + 1];
                let rendered = format!("{port}/{protocol} ALLOW IN Anywhere # {comment}");
                if !state.rules.contains(&rendered) {
                    state.rules.push(rendered);
                }
                if state.ipv6 {
                    state.rules.push(format!("{port}/{protocol} (v6) ALLOW IN Anywhere (v6) # {comment}"));
                }
                return Some(Reply::ok("Rule added"));
            }
            if argv.starts_with(&["ufw", "--force", "delete", "allow"]) {
                let protocol = argv[argv.iter().position(|part| *part == "proto").unwrap() + 1];
                let port = argv[argv.iter().position(|part| *part == "port").unwrap() + 1];
                let comment = argv[argv.iter().position(|part| *part == "comment").unwrap() + 1];
                state.rules.retain(|rule| {
                    !(rule.starts_with(&format!("{port}/{protocol}")) && rule.ends_with(&format!("# {comment}")))
                });
                return Some(Reply::ok("Rule deleted"));
            }
            if argv == ["ufw", "--force", "enable"] || argv == ["ufw", "--force", "disable"] {
                return Some(Reply::ok(""));
            }
            panic!("unexpected command: {argv:?}")
        }));
        (runner, state)
    }

    #[test]
    fn status_parser_reads_port_and_route_rules_and_canonicalizes_sources() {
        let text = concat!(
            "Status: active\n\n",
            "     To                         Action      From\n",
            "     --                         ------      ----\n",
            "[ 1] 22/tcp                     ALLOW IN    192.168.1.17/24          # keep\n",
            "[ 2] Anywhere                   ALLOW FWD   Anywhere on awg15          # proxy-control:firewall:route:awg15\n",
            "[ 3] Anywhere (v6)              ALLOW FWD   Anywhere (v6) on awg15     # proxy-control:firewall:route:awg15\n",
            "[ 4] 443/tcp (v6)               ALLOW IN    ::ffff:1.2.3.4 (v6)        # mapped\n",
        );
        let rules = parse_ufw_status(text).unwrap();
        assert_eq!(rules[0].source, "192.168.1.0/24");
        assert_eq!(rules[1].interface, "awg15");
        assert_eq!((rules[1].port, rules[1].action.as_str(), rules[1].ipv6), (0, "ALLOW FWD", false));
        assert!(rules[2].ipv6);
        assert_eq!(rules[3].source, "::ffff:102:304/128");
        let mut other_route = rules[1].clone();
        other_route.interface = "awg20".into();
        assert_eq!(rule_fingerprint(&rules[1]).len(), 64);
        assert_ne!(rule_fingerprint(&rules[1]), rule_fingerprint(&other_route));
        assert!(parse_ufw_status("Status: inactive\n").is_err());
        assert!(parse_ufw_status(&text.replace("[ 2]", "[ 3]")).is_err());
        assert!(parse_ufw_status(&text.replace("Anywhere (v6) on awg15", "Anywhere on awg15")).is_err());
    }

    #[test]
    fn real_engine_installs_repairs_and_rolls_back_only_owned_rules() {
        let dir = TempDir::new("firewall-engine");
        let (runner, state) = ufw_runner(&["22/tcp ALLOW IN Anywhere # operator:ssh"]);
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
        let adapter: Arc<dyn Adapter> = Arc::new(FirewallAdapter::new(&context));
        let action = adapter.plan(&config(), &facts()).unwrap().remove(0);
        assert_eq!(action.mutations, ["ssh=22", "ipv6=false", "enable=false", "rule=tcp:80", "rule=tcp:443"]);
        let plan = plan_with(vec![action], Map::new());
        let engine = engine_for(dir.path(), vec![adapter]);

        assert_eq!(engine.apply(&plan, &plan.digest()).unwrap().status, Status::Active);
        assert_eq!(state.lock().unwrap().rules.len(), 3);
        state.lock().unwrap().rules.retain(|rule| !rule.starts_with("80/tcp"));
        assert_eq!(engine.repair().unwrap().status, Status::Active);
        assert!(state.lock().unwrap().rules.iter().any(|rule| rule.starts_with("80/tcp")));
        assert!(runner.argvs().iter().any(|argv| argv.ends_with(&["proxy-control:firewall:tcp:80".into()])));
        assert_eq!(engine.uninstall(false).unwrap().status, Status::Uninstalled);
        assert_eq!(state.lock().unwrap().rules, ["22/tcp ALLOW IN Anywhere # operator:ssh"]);
        assert!(runner
            .calls()
            .iter()
            .all(|call| call.kind == CallKind::Bounded && call.timeout == Duration::from_secs(30)));
    }

    #[test]
    fn rollback_checks_whether_the_firewall_was_disabled() {
        let dir = TempDir::new("firewall-disable");
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(&["grep", "-E"], Reply::ok("IPV6=no\n"));
        runner.reply_once(&["ufw", "--force", "disable"], Reply::exit(1, "", "refused"));
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner };
        let adapter = FirewallAdapter::new(&context);
        let action = Action::new(
            "firewall.ufw",
            "firewall",
            OWNER,
            vec!["ssh=22".into(), "ipv6=false".into(), "enable=true".into(), "rule=tcp:80".into()],
            vec!["SSH is preserved".into()],
            vec!["rules are active".into()],
            vec!["disable UFW".into()],
            false,
        )
        .unwrap();
        let checkpoint = firewall_checkpoint_value(OWNER, &[], &[], &[]);
        let error = adapter.rollback(&action, checkpoint, false, RollbackTarget::RolledBack).unwrap_err();
        assert_eq!(
            (error.python_class_name(), error.message().as_str()),
            ("FirewallError", "UFW could not be disabled")
        );
    }
}
