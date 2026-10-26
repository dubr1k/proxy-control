//! The engine-neutral routing policy (ADR 006) and what compiling it produces
//! (`routing/models.py`).
//!
//! A policy says what the operator wants — a default for the whole service, then ordered
//! first-match rules — in one vocabulary for every backend. It never names an address, a path or a
//! raw directive. Limits are the spec's (§5): 128 rules, 64 domains and 64 CIDRs and 32 ports per
//! rule, a 120-character note.

use panel_core::errors::LocItem;
use panel_core::pytext::{self, PyValueError};
use serde_json::{json, Map, Value};

use super::{document, idna, net};
use crate::common::{literal_enum, wire_enum, Backend, Protocol, BACKENDS};
use crate::pyrepr;
use crate::validate::{
    boolean, list, list_too_long, nullable, string, value_error, Cx, Extra, Fields, Int, Model, Str,
};

wire_enum! {
    /// What a rule does with a match.
    pub enum Action {
        Direct => "direct",
        Block => "block",
        Egress => "egress",
    }
}

wire_enum! {
    /// What the service does with traffic no rule matched.
    pub enum DefaultAction {
        Direct => "direct",
        Egress => "egress",
    }
}

wire_enum! {
    /// What happens when the egress provider is unreachable.
    pub enum Fallback {
        FailClosed => "fail_closed",
        ApprovedDirect => "approved_direct",
    }
}

wire_enum! {
    /// Where a stored policy stands on its node.
    pub enum PolicyState {
        Draft => "draft",
        Applying => "applying",
        Applied => "applied",
        Failed => "failed",
        RolledBack => "rolled_back",
    }
}

wire_enum! {
    /// Whether the compiled document can be enforced.
    pub enum CompileStatus {
        Supported => "supported",
        Unsupported => "unsupported",
    }
}

/// `routing.models.Protocol` choices, in that module's order.
pub const ROUTING_PROTOCOLS: &[&str] = &["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"];

/// The native backend of each data plane (`BACKEND_FOR`, also `NATIVE_BACKEND_FOR`).
pub fn backend_for(protocol: &str) -> Option<Backend> {
    Some(match protocol {
        "naive" => Backend::NaiveNative,
        "mieru" => Backend::MieruNative,
        "mtproxy" => Backend::MtproxyNative,
        "trusttunnel" => Backend::TrusttunnelNative,
        "amneziawg" => Backend::AmneziawgNative,
        _ => return None,
    })
}

/// The backends a protocol's policy may target: its native one, and the router.
pub fn backends_for(protocol: &str) -> Vec<Backend> {
    backend_for(protocol).map(|native| vec![native, ROUTER_BACKEND]).unwrap_or_default()
}

pub const ROUTER_BACKEND: Backend = Backend::XrayRouter;
pub const AMNEZIAWG_WHOLE_ONLY: &str = "On its own AmneziaWG routes the whole tunnel: directly or through WARP. For rules by domain, address, port or protocol, custom exits and other nodes attach it to the node's Xray-router";
pub const LANES_UNSUPPORTED_AMNEZIAWG: &str = "AmneziaWG has no client lanes: the router sees its tunnels as one source, so the route is set for the whole service";
pub const LANES_UNSUPPORTED_TRUSTTUNNEL: &str = "TrustTunnel has no client lanes: its endpoint reaches the router as one anonymous SOCKS5 client, so the router cannot tell its users apart. Route the whole service instead";
/// Protocols whose users may get a lane of their own on the router.
pub const LANE_PROTOCOLS: &[&str] = &["naive", "mieru"];
pub const MAX_RULES: usize = 128;
pub const MAX_SELECTORS: usize = 64;
pub const MAX_PORTS: usize = 32;
pub const MAX_NOTE: usize = 120;
/// "2": geosite/geoip codes and ports alone (v0.5); "3": sniffed protocols and preset marks (v0.8).
pub const COMPILER_VERSION: &str = "3";
/// What Xray's sniffer reports and a rule may stand on (router only).
pub const SNIFFED_PROTOCOLS: &[&str] = &["http", "tls", "quic", "bittorrent"];
pub const MAX_PROTOCOLS: usize = 4;
/// The service's own lane.
pub const LANE_SERVICE: &str = "svc";
pub const MAX_CHAIN_HOPS: usize = 3;

fn ascii_class(text: &str, allowed: impl Fn(u8) -> bool, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len()) && text.bytes().all(allowed)
}

/// `[A-Za-z0-9_-]{1,64}\Z` (fullmatch).
fn is_guid(text: &str) -> bool {
    ascii_class(text, |b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-', 1, 64)
}

/// `grant:[A-Za-z0-9_-]{1,64}\Z`.
pub fn is_grant_lane(text: &str) -> bool {
    text.strip_prefix("grant:").is_some_and(is_guid)
}

fn invalid(message: impl Into<String>) -> PyValueError {
    PyValueError(message.into())
}

/// `warp`, `exit:<id>` or `node:<guid>[,<guid>…][:warp]` — lower-cased keyword and exit, ids as
/// given; a chain names each node once and at most three.
pub fn normalise_exit(value: &str) -> Result<String, PyValueError> {
    let general = || invalid("an egress must be warp, exit:<id> or node:<guid>");
    if value.is_empty() {
        return Err(general());
    }
    let text = pytext::strip(value);
    if pytext::lower(text) == "warp" {
        return Ok("warp".into());
    }
    let (kind, rest) = text.split_once(':').unwrap_or((text, ""));
    if pytext::lower(kind) == "exit" {
        if rest.is_empty() || !is_guid(rest) {
            return Err(invalid("an exit egress is exit:<id>"));
        }
        return Ok(format!("exit:{rest}"));
    }
    if pytext::lower(kind) != "node" || rest.is_empty() {
        return Err(general());
    }
    let (chain, via_warp) = match rest.split_once(':') {
        None => (rest, false),
        Some((chain, tail)) => {
            if pytext::lower(tail) != "warp" {
                return Err(invalid("a chain exits direct or through the last node's warp"));
            }
            (chain, true)
        }
    };
    let guids: Vec<&str> = chain.split(',').collect();
    let distinct = guids.iter().enumerate().all(|(index, guid)| !guids[..index].contains(guid));
    if !(1..=MAX_CHAIN_HOPS).contains(&guids.len()) || !distinct || !guids.iter().all(|guid| is_guid(guid)) {
        return Err(invalid("a chain names one to three distinct nodes"));
    }
    Ok(format!("node:{}{}", guids.join(","), if via_warp { ":warp" } else { "" }))
}

/// The node guids a normalised exit chains through and the last hop's exit (`"direct"` or
/// `"warp"`); `warp`, a custom exit and `None` have no hops.
pub fn exit_hops(value: Option<&str>) -> (Vec<String>, Option<&'static str>) {
    let Some(body) = value.and_then(|value| value.strip_prefix("node:")) else {
        return (Vec::new(), None);
    };
    let (body, via) = match body.strip_suffix(":warp") {
        Some(body) => (body, "warp"),
        None => (body, "direct"),
    };
    (body.split(',').map(str::to_string).collect(), Some(via))
}

pub fn is_node_exit(value: &str) -> bool {
    value.starts_with("node:")
}

pub fn is_custom_exit(value: &str) -> bool {
    value.starts_with("exit:")
}

/// `svc` (also for nothing or an empty string) or `grant:<id>`.
pub fn normalise_lane(value: Option<&str>) -> Result<String, PyValueError> {
    match value {
        None | Some("") | Some(LANE_SERVICE) => Ok(LANE_SERVICE.into()),
        Some(lane) if is_grant_lane(lane) => Ok(lane.into()),
        Some(_) => Err(invalid("a lane is svc or grant:<id>")),
    }
}

/// `(?=.{1,253}\Z)(?:LABEL\.)*LABEL\Z` with `LABEL = [a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`.
fn is_domain(host: &str) -> bool {
    let label = |text: &str| {
        let bytes = text.as_bytes();
        let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        (1..=63).contains(&bytes.len())
            && edge(bytes[0])
            && edge(bytes[bytes.len() - 1])
            && bytes.iter().all(|&b| edge(b) || b == b'-')
    };
    (1..=253).contains(&host.len()) && host.split('.').all(label)
}

/// Lower-cased IDNA, an optional `*.` prefix meaning "any subdomain".
pub fn normalise_domain(value: &str) -> Result<String, PyValueError> {
    let fail = || invalid(format!("invalid domain: {}", pytext::repr(value)));
    let candidate = pytext::lower(pytext::strip(value).trim_end_matches('.'));
    let (wildcard, host) = match candidate.strip_prefix("*.") {
        Some(host) => (true, host),
        None => (false, candidate.as_str()),
    };
    if host.is_empty() || host.contains('*') || host.contains('/') || host.chars().any(pytext::is_space) {
        return Err(fail());
    }
    let host = idna::encode(host).map_err(|_| fail())?;
    if !is_domain(&host) {
        return Err(fail());
    }
    Ok(if wildcard { format!("*.{host}") } else { host })
}

/// A network in canonical form; a bare address becomes its /32 or /128.
pub fn normalise_cidr(value: &str) -> Result<String, PyValueError> {
    let text = pytext::strip(value);
    if text.is_empty() {
        return Err(invalid("cidr must be a string"));
    }
    net::ip_network(text).ok_or_else(|| invalid(format!("invalid cidr: {}", pytext::repr(value))))
}

wire_enum! {
    /// The two kinds of Xray geodata codes.
    pub enum GeoKind {
        Geosite => "geosite",
        Geoip => "geoip",
    }
}

/// `[a-z0-9][a-z0-9@!_-]{0,63}\Z`.
fn is_geo_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"@!_-".contains(&b))
}

/// A `geosite:`/`geoip:` code as the Xray geodata names it (lower-case, no prefix); `geoip:private`
/// is the router's own bypass, never a rule.
pub fn normalise_geo_code(value: &str, kind: GeoKind) -> Result<String, PyValueError> {
    let lowered = pytext::lower(pytext::strip(value));
    let prefix = format!("{}:", kind.as_str());
    let code = lowered.strip_prefix(prefix.as_str()).unwrap_or(&lowered);
    if !is_geo_code(code) {
        return Err(invalid(format!("invalid {} code: {}", kind.as_str(), pytext::repr(value))));
    }
    if kind == GeoKind::Geoip && code == "private" {
        return Err(invalid("geoip:private is the router's bypass, not a rule"));
    }
    Ok(code.to_string())
}

/// A rule's port selector: one port, or an inclusive range as `"low-high"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Port {
    One(i64),
    Range(String),
}

impl Port {
    pub fn to_value(&self) -> Value {
        match self {
            Port::One(port) => json!(port),
            Port::Range(range) => json!(range),
        }
    }
}

/// `normalise_port`: an integer 1–65535, a string of digits (any script, as `int()` reads them) or
/// `"low-high"` in ASCII digits.
pub fn normalise_port(value: &Value) -> Result<Port, PyValueError> {
    let invalid_port = || invalid(format!("invalid port: {}", pyrepr::repr(value)));
    let in_range = |port: i128, shown: &dyn std::fmt::Display| {
        if (1..=65535).contains(&port) {
            Ok(Port::One(port as i64))
        } else {
            Err(invalid(format!("port out of range: {shown}")))
        }
    };
    match value {
        Value::Bool(_) => Err(invalid("invalid port")),
        Value::Number(number) if !number.is_f64() => {
            let port = number.as_i64().map(i128::from).or_else(|| number.as_u64().map(i128::from)).unwrap_or(i128::MAX);
            in_range(port, &pyrepr::number_repr(number))
        }
        Value::String(text) => {
            let text = pytext::strip(text);
            if !text.is_empty() && text.chars().all(idna::is_digit) {
                return match pytext::int_from_str(text) {
                    Ok(port) => in_range(i128::from(port), &port),
                    Err(error) if error.0.starts_with("int() value out of range") => {
                        let digits: String =
                            text.chars().filter_map(pytext::decimal).map(|d| char::from(b'0' + d as u8)).collect();
                        let shown = digits.trim_start_matches('0');
                        Err(invalid(format!("port out of range: {}", if shown.is_empty() { "0" } else { shown })))
                    }
                    Err(error) => Err(error),
                };
            }
            let parsed = text.split_once('-').and_then(|(low, high)| {
                let digits = |part: &str| (1..=5).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit());
                (digits(low) && digits(high)).then(|| (low.parse::<u32>().ok(), high.parse::<u32>().ok()))
            });
            match parsed {
                Some((Some(low), Some(high))) if 1 <= low && low <= high && high <= 65535 => {
                    Ok(Port::Range(format!("{low}-{high}")))
                }
                _ => Err(invalid_port()),
            }
        }
        _ => Err(invalid_port()),
    }
}

fn unique<T: PartialEq>(items: Vec<T>) -> Vec<T> {
    let mut seen: Vec<T> = Vec::with_capacity(items.len());
    for item in items {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

/// What a rule matches: any of its domains, geosite codes, CIDRs or geoip codes, on any of its
/// ports, for any of its sniffed protocols. A rule may stand on ports alone.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RuleMatch {
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    pub ports: Vec<Port>,
    pub geosites: Vec<String>,
    pub geoips: Vec<String>,
    pub protocols: Vec<String>,
}

impl RuleMatch {
    /// True when the rule narrows by destination name or address (not by port alone).
    pub fn selectors(&self) -> bool {
        !(self.domains.is_empty() && self.cidrs.is_empty() && self.geosites.is_empty() && self.geoips.is_empty())
    }

    fn is_empty(&self) -> bool {
        !self.selectors() && self.ports.is_empty() && self.protocols.is_empty()
    }
}

/// A `list[str]` field (with its length limit) whose items then go through `normalise`.
fn normalised_strings(
    input: &Value,
    loc: &[LocItem],
    cx: &mut Cx,
    max: usize,
    normalise: impl Fn(&str) -> Result<String, PyValueError>,
) -> Option<Vec<String>> {
    let items = list(input, loc, cx, Some(max), string)?;
    let mut out = Vec::with_capacity(items.len());
    for item in &items {
        match normalise(item) {
            Ok(value) => out.push(value),
            Err(error) => {
                cx.push(value_error(loc.to_vec(), input, error));
                return None;
            }
        }
    }
    Some(unique(out))
}

impl Model for RuleMatch {
    const TITLE: &'static str = "RuleMatch";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let domains = fields.optional(cx, "domains", Vec::new, |v, l, cx| {
            normalised_strings(v, l, cx, MAX_SELECTORS, normalise_domain)
        });
        let cidrs = fields
            .optional(cx, "cidrs", Vec::new, |v, l, cx| normalised_strings(v, l, cx, MAX_SELECTORS, normalise_cidr));
        let ports = fields.optional(cx, "ports", Vec::new, validate_ports);
        let geosites = fields.optional(cx, "geosites", Vec::new, |v, l, cx| {
            normalised_strings(v, l, cx, MAX_SELECTORS, |code| normalise_geo_code(code, GeoKind::Geosite))
        });
        let geoips = fields.optional(cx, "geoips", Vec::new, |v, l, cx| {
            normalised_strings(v, l, cx, MAX_SELECTORS, |code| normalise_geo_code(code, GeoKind::Geoip))
        });
        let protocols = fields.optional(cx, "protocols", Vec::new, |v, l, cx| {
            let items = list(v, l, cx, Some(MAX_PROTOCOLS), string)?;
            let mut cleaned = Vec::with_capacity(items.len());
            for item in &items {
                let word = pytext::lower(pytext::strip(item));
                if !SNIFFED_PROTOCOLS.contains(&word.as_str()) {
                    let message = format!(
                        "invalid protocol selector: {} (one of {})",
                        pytext::repr(item),
                        SNIFFED_PROTOCOLS.join(", ")
                    );
                    cx.push(value_error(l.to_vec(), v, message));
                    return None;
                }
                cleaned.push(word);
            }
            Some(unique(cleaned))
        });
        let whole = fields.input();
        let at_root = fields.loc().to_vec();
        if !fields.finish(cx, Extra::Forbid) {
            return None;
        }
        let rule = RuleMatch {
            domains: domains?,
            cidrs: cidrs?,
            ports: ports?,
            geosites: geosites?,
            geoips: geoips?,
            protocols: protocols?,
        };
        if rule.is_empty() {
            cx.push(value_error(
                at_root,
                whole,
                "a rule must name at least one domain, geosite, cidr, geoip, port or protocol",
            ));
            return None;
        }
        Some(rule)
    }

    fn dump(&self) -> Value {
        json!({
            "domains": self.domains,
            "cidrs": self.cidrs,
            "ports": self.ports.iter().map(Port::to_value).collect::<Vec<_>>(),
            "geosites": self.geosites,
            "geoips": self.geoips,
            "protocols": self.protocols,
        })
    }
}

/// `ports`: normalised and de-duplicated before the type and the length are checked (pydantic's
/// `mode="before"` validator), so 40 copies of one port are one port.
fn validate_ports(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Vec<Port>> {
    let Value::Array(items) = input else {
        cx.push(value_error(loc.to_vec(), input, "ports must be a list"));
        return None;
    };
    let mut ports = Vec::with_capacity(items.len());
    for item in items {
        match normalise_port(item) {
            Ok(port) => ports.push(port),
            Err(error) => {
                cx.push(value_error(loc.to_vec(), input, error));
                return None;
            }
        }
    }
    let ports = unique(ports);
    if ports.len() > MAX_PORTS {
        let shown = Value::Array(ports.iter().map(Port::to_value).collect());
        cx.push(list_too_long(loc, &shown, MAX_PORTS, ports.len()));
        return None;
    }
    Some(ports)
}

/// One first-match rule. `id` is the server's (a rule sent without one is new); `position` is the
/// order the server stored — on input the list order wins.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingRule {
    pub id: Option<String>,
    pub position: i64,
    pub enabled: bool,
    pub matcher: RuleMatch,
    pub action: Action,
    pub egress: Option<String>,
    pub note: String,
    /// The quick setting that created this rule; cleared once the rule is edited.
    pub preset: Option<String>,
}

/// `^[0-9a-f-]{36}$`.
fn is_rule_id(text: &str) -> bool {
    text.len() == 36 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}

/// `[a-z][a-z0-9_-]{0,31}\Z`.
fn is_preset(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// An optional egress field: a string through [`normalise_exit`].
fn egress_field(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Option<String>> {
    nullable(input, loc, cx, |v, l, cx| {
        let text = string(v, l, cx)?;
        match normalise_exit(&text) {
            Ok(value) => Some(value),
            Err(error) => {
                cx.push(value_error(l.to_vec(), v, error));
                None
            }
        }
    })
}

impl Model for RoutingRule {
    const TITLE: &'static str = "RoutingRule";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let id = fields.optional(
            cx,
            "id",
            || None,
            |v, l, cx| nullable(v, l, cx, |v, l, cx| Str::pattern("^[0-9a-f-]{36}$", is_rule_id).validate(v, l, cx)),
        );
        let position = fields.optional(cx, "position", || 0, |v, l, cx| Int::lax(Some(0), None).validate(v, l, cx));
        let enabled = fields.optional(cx, "enabled", || true, boolean);
        let matcher = fields.required(cx, "match", RuleMatch::validate_at);
        let action = fields.required(cx, "action", |v, l, cx| literal_enum(v, l, cx, &["direct", "block", "egress"]));
        let egress = fields.optional(cx, "egress", || None, egress_field);
        let note = fields.optional(cx, "note", String::new, |v, l, cx| Str::max(MAX_NOTE).validate(v, l, cx));
        let preset = fields.optional(
            cx,
            "preset",
            || None,
            |v, l, cx| {
                let preset = nullable(v, l, cx, |v, l, cx| Str::max(32).validate(v, l, cx))?;
                match preset.as_deref() {
                    None | Some("") => Some(None),
                    Some(name) if is_preset(name) => Some(preset),
                    Some(_) => {
                        cx.push(value_error(l.to_vec(), v, "invalid preset name"));
                        None
                    }
                }
            },
        );
        let whole = fields.input();
        let at_root = fields.loc().to_vec();
        if !fields.finish(cx, Extra::Forbid) {
            return None;
        }
        let rule = RoutingRule {
            id: id?,
            position: position?,
            enabled: enabled?,
            matcher: matcher?,
            action: action?,
            egress: egress?,
            note: note?,
            preset: preset?,
        };
        let problem = match (rule.action, &rule.egress) {
            (Action::Egress, None) => Some("an egress rule must name its egress"),
            (Action::Direct | Action::Block, Some(_)) => Some("only an egress rule names an egress"),
            _ => None,
        };
        if let Some(message) = problem {
            cx.push(value_error(at_root, whole, message));
            return None;
        }
        Some(rule)
    }

    fn dump(&self) -> Value {
        json!({
            "id": self.id,
            "position": self.position,
            "enabled": self.enabled,
            "match": self.matcher.dump(),
            "action": self.action.as_str(),
            "egress": self.egress,
            "note": self.note,
            "preset": self.preset,
        })
    }
}

/// The operator's intent: a default for the whole service, then first-match rules (`_Intent`).
#[derive(Debug, Clone, PartialEq)]
pub struct Intent {
    pub default_action: DefaultAction,
    pub default_egress: Option<String>,
    pub fallback: Fallback,
    pub rules: Vec<RoutingRule>,
}

impl Default for Intent {
    fn default() -> Self {
        Self {
            default_action: DefaultAction::Direct,
            default_egress: None,
            fallback: Fallback::FailClosed,
            rules: Vec::new(),
        }
    }
}

impl Intent {
    /// Every distinct egress the intent names, the default first, then enabled rules in order.
    pub fn exits(&self) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        let rules = self.rules.iter().filter(|rule| rule.enabled).map(|rule| rule.egress.as_ref());
        for value in std::iter::once(self.default_egress.as_ref()).chain(rules).flatten() {
            if !found.contains(value) {
                found.push(value.clone());
            }
        }
        found
    }

    /// The exits that chain through other nodes.
    pub fn node_exits(&self) -> Vec<String> {
        self.exits().into_iter().filter(|value| is_node_exit(value)).collect()
    }

    /// The ids of the custom exits used (`exit:<id>` without the prefix).
    pub fn custom_exits(&self) -> Vec<String> {
        self.exits().into_iter().filter(|value| is_custom_exit(value)).map(|value| value[5..].to_string()).collect()
    }

    /// The intent's fields, validated into `fields` (the caller declares its own afterwards).
    fn validate_fields(fields: &mut Fields<'_>, cx: &mut Cx) -> Option<Self> {
        let default_action = fields.optional(
            cx,
            "default_action",
            || DefaultAction::Direct,
            |v, l, cx| literal_enum(v, l, cx, &["direct", "egress"]),
        );
        let default_egress = fields.optional(cx, "default_egress", || None, egress_field);
        let fallback = fields.optional(
            cx,
            "fallback",
            || Fallback::FailClosed,
            |v, l, cx| literal_enum(v, l, cx, &["fail_closed", "approved_direct"]),
        );
        let rules = fields
            .optional(cx, "rules", Vec::new, |v, l, cx| list(v, l, cx, Some(MAX_RULES), RoutingRule::validate_at));
        Some(Intent {
            default_action: default_action?,
            default_egress: default_egress?,
            fallback: fallback?,
            rules: rules?,
        })
    }

    /// `_Intent._default_egress`.
    fn check(&self) -> Result<(), &'static str> {
        match (self.default_action, &self.default_egress) {
            (DefaultAction::Egress, None) => Err("a default of egress must name its egress"),
            (DefaultAction::Direct, Some(_)) => Err("only a default of egress names an egress"),
            _ => Ok(()),
        }
    }

    fn dump_into(&self, map: &mut Map<String, Value>) {
        map.insert("default_action".into(), json!(self.default_action.as_str()));
        map.insert("default_egress".into(), json!(self.default_egress));
        map.insert("fallback".into(), json!(self.fallback.as_str()));
        map.insert("rules".into(), Value::Array(self.rules.iter().map(RoutingRule::dump).collect()));
    }
}

/// Validates a model made of the intent plus its own fields (`declare`), runs the intent's check,
/// and builds it with `build`.
fn validate_intent_model<T, X>(
    input: &Value,
    loc: &[LocItem],
    cx: &mut Cx,
    title: &str,
    declare: impl FnOnce(&mut Fields<'_>, &mut Cx) -> X,
    build: impl FnOnce(Intent, X) -> Option<T>,
) -> Option<T> {
    let mut fields = Fields::open(input, loc, cx, title)?;
    let intent = Intent::validate_fields(&mut fields, cx);
    let own = declare(&mut fields, cx);
    let whole = fields.input();
    let at_root = fields.loc().to_vec();
    if !fields.finish(cx, Extra::Forbid) {
        return None;
    }
    let intent = intent?;
    if let Err(message) = intent.check() {
        cx.push(value_error(at_root, whole, message));
        return None;
    }
    build(intent, own)
}

/// What `PUT` accepts: the intent without the server's bookkeeping. A named `backend` must be one
/// the protocol can run on (`backends_for`, checked by the store).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PolicyInput {
    pub intent: Intent,
    pub backend: Option<Backend>,
}

impl PolicyInput {
    /// The intent of a stored policy, with its backend.
    pub fn from_policy(policy: &RoutingPolicy) -> Self {
        Self { intent: policy.intent.clone(), backend: Some(policy.backend) }
    }

    /// Validates the intent and `backend` plus whatever fields `declare` reads (for request bodies
    /// that extend the policy, like the route's `PolicyPut`).
    pub fn validate_extended<X>(
        input: &Value,
        loc: &[LocItem],
        cx: &mut Cx,
        title: &str,
        declare: impl FnOnce(&mut Fields<'_>, &mut Cx) -> X,
    ) -> Option<(Self, X)> {
        validate_intent_model(
            input,
            loc,
            cx,
            title,
            |fields, cx| {
                let backend = fields.optional(cx, "backend", || None, |v, l, cx| nullable(v, l, cx, backend_literal));
                (backend, declare(fields, cx))
            },
            |intent, (backend, extra)| Some((PolicyInput { intent, backend: backend? }, extra)),
        )
    }
}

fn backend_literal(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Backend> {
    literal_enum(input, loc, cx, BACKENDS)
}

impl Model for PolicyInput {
    const TITLE: &'static str = "PolicyInput";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        Self::validate_extended(input, loc, cx, Self::TITLE, |_, _| ()).map(|(policy, ())| policy)
    }

    fn dump(&self) -> Value {
        let mut map = Map::new();
        self.intent.dump_into(&mut map);
        map.insert("backend".into(), json!(self.backend.map(Backend::as_str)));
        Value::Object(map)
    }
}

/// A stored policy: the intent plus where it stands on the node. `lane` is `svc` (the service's
/// own policy) or `grant:<id>` (a client's own lane).
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingPolicy {
    pub intent: Intent,
    pub id: String,
    pub node_id: String,
    pub protocol: Protocol,
    pub lane: String,
    pub backend: Backend,
    pub revision: i64,
    pub state: PolicyState,
    pub applied_revision: Option<i64>,
    pub applied_digest: Option<String>,
    pub applied_at: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl RoutingPolicy {
    /// Applied, at the current revision.
    pub fn applied_current(&self) -> bool {
        self.state == PolicyState::Applied && self.applied_revision == Some(self.revision)
    }
}

struct PolicyOwn {
    id: Option<String>,
    node_id: Option<String>,
    protocol: Option<Protocol>,
    lane: Option<String>,
    backend: Option<Backend>,
    revision: Option<i64>,
    state: Option<PolicyState>,
    applied_revision: Option<Option<i64>>,
    applied_digest: Option<Option<String>>,
    applied_at: Option<Option<i64>>,
    last_error: Option<Option<String>>,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

fn optional_int(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Option<i64>> {
    nullable(input, loc, cx, |v, l, cx| Int::LAX.validate(v, l, cx))
}

fn optional_string(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Option<String>> {
    nullable(input, loc, cx, string)
}

impl Model for RoutingPolicy {
    const TITLE: &'static str = "RoutingPolicy";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        validate_intent_model(
            input,
            loc,
            cx,
            Self::TITLE,
            |f, cx| PolicyOwn {
                id: f.required(cx, "id", string),
                node_id: f.required(cx, "node_id", string),
                protocol: f.required(cx, "protocol", |v, l, cx| literal_enum(v, l, cx, ROUTING_PROTOCOLS)),
                lane: f.optional(cx, "lane", || LANE_SERVICE.into(), string),
                backend: f.required(cx, "backend", backend_literal),
                revision: f.required(cx, "revision", |v, l, cx| Int::lax(Some(1), None).validate(v, l, cx)),
                state: f.optional(
                    cx,
                    "state",
                    || PolicyState::Draft,
                    |v, l, cx| literal_enum(v, l, cx, &["draft", "applying", "applied", "failed", "rolled_back"]),
                ),
                applied_revision: f.optional(cx, "applied_revision", || None, optional_int),
                applied_digest: f.optional(cx, "applied_digest", || None, optional_string),
                applied_at: f.optional(cx, "applied_at", || None, optional_int),
                last_error: f.optional(cx, "last_error", || None, optional_string),
                created_at: f.optional(cx, "created_at", || 0, |v, l, cx| Int::LAX.validate(v, l, cx)),
                updated_at: f.optional(cx, "updated_at", || 0, |v, l, cx| Int::LAX.validate(v, l, cx)),
            },
            |intent, own| {
                Some(RoutingPolicy {
                    intent,
                    id: own.id?,
                    node_id: own.node_id?,
                    protocol: own.protocol?,
                    lane: own.lane?,
                    backend: own.backend?,
                    revision: own.revision?,
                    state: own.state?,
                    applied_revision: own.applied_revision?,
                    applied_digest: own.applied_digest?,
                    applied_at: own.applied_at?,
                    last_error: own.last_error?,
                    created_at: own.created_at?,
                    updated_at: own.updated_at?,
                })
            },
        )
    }

    fn dump(&self) -> Value {
        let mut map = Map::new();
        self.intent.dump_into(&mut map);
        map.insert("id".into(), json!(self.id));
        map.insert("node_id".into(), json!(self.node_id));
        map.insert("protocol".into(), json!(self.protocol.as_str()));
        map.insert("lane".into(), json!(self.lane));
        map.insert("backend".into(), json!(self.backend.as_str()));
        map.insert("revision".into(), json!(self.revision));
        map.insert("state".into(), json!(self.state.as_str()));
        map.insert("applied_revision".into(), json!(self.applied_revision));
        map.insert("applied_digest".into(), json!(self.applied_digest));
        map.insert("applied_at".into(), json!(self.applied_at));
        map.insert("last_error".into(), json!(self.last_error));
        map.insert("created_at".into(), json!(self.created_at));
        map.insert("updated_at".into(), json!(self.updated_at));
        Value::Object(map)
    }
}

/// Why a policy cannot compile as asked (a code of [`panel_core::errors::ErrorCode`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Reason {
    pub code: String,
    pub rule_id: Option<String>,
    pub message: String,
}

impl Reason {
    pub fn new(code: impl Into<String>, rule_id: Option<String>, message: impl Into<String>) -> Self {
        Self { code: code.into(), rule_id, message: message.into() }
    }
}

impl Model for Reason {
    const TITLE: &'static str = "Reason";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let code = fields.required(cx, "code", string);
        let rule_id = fields.optional(cx, "rule_id", || None, optional_string);
        let message = fields.optional(cx, "message", String::new, string);
        if !fields.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(Reason { code: code?, rule_id: rule_id?, message: message? })
    }

    fn dump(&self) -> Value {
        json!({"code": self.code, "rule_id": self.rule_id, "message": self.message})
    }
}

/// The honest preview: a document the backend can enforce, or the reasons it cannot.
#[derive(Debug, Clone, PartialEq)]
pub struct Compiled {
    pub status: CompileStatus,
    pub reasons: Vec<Reason>,
    pub warnings: Vec<String>,
    pub document: Option<Value>,
    pub digest: Option<String>,
    pub diff: Vec<String>,
    pub restart_required: bool,
    pub rollback: Option<Value>,
    pub compiler_version: String,
    pub backend: Option<String>,
    pub runtime_version: Option<String>,
    /// With `xray_router`: the native manager's document that keeps the service handed to the
    /// router, applied beside `document` when it is not in place.
    pub attach: Option<Value>,
}

impl Compiled {
    /// A compilation with every optional part at its default.
    pub fn new(status: CompileStatus) -> Self {
        Self {
            status,
            reasons: Vec::new(),
            warnings: Vec::new(),
            document: None,
            digest: None,
            diff: Vec::new(),
            restart_required: false,
            rollback: None,
            compiler_version: COMPILER_VERSION.into(),
            backend: None,
            runtime_version: None,
            attach: None,
        }
    }

    /// `model_dump()`.
    pub fn dump(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "reasons": self.reasons.iter().map(Reason::dump).collect::<Vec<_>>(),
            "warnings": self.warnings,
            "document": self.document,
            "digest": self.digest,
            "diff": self.diff,
            "restart_required": self.restart_required,
            "rollback": self.rollback,
            "compiler_version": self.compiler_version,
            "backend": self.backend,
            "runtime_version": self.runtime_version,
            "attach": self.attach,
        })
    }

    /// The API's form: a chain's relay accounts and exit credentials masked in the document and
    /// the diff.
    pub fn redacted(&self) -> Value {
        let mut value = self.dump();
        value["document"] = document::redact_document(&value["document"]);
        value["diff"] = json!(document::redact_diff(&self.diff));
        value
    }
}

#[cfg(test)]
mod tests;
