//! Policy → compiled document, per backend, with every limitation said out loud
//! (`routing/compiler.py`).
//!
//! The compiler never substitutes a backend and never quietly narrows a rule: whatever the backend
//! cannot enforce comes back as `unsupported` with the rule it concerns. What a backend *can* do is
//! what its manager declares in `capabilities`, plus the constraints no flag can express:
//!
//! - `naive_native` — one `upstream` per service, and forwardproxy skips its ACL when an upstream is
//!   set, so a block rule beside a WARP default cannot hold;
//! - `mieru_native` — mita matches `domainNames` as a suffix (`example.com` and `*.example.com` are
//!   one selector);
//! - `mtproxy_native`, `trusttunnel_native` — «direct, no rules» or handed whole to the router;
//! - `amneziawg_native` — the whole tunnel direct or through the manager's own WARP, no rules.
//!
//! Private destinations may be blocked but never opened by a `direct`/`egress` rule.

use panel_core::pytext::ip_address;
use panel_core::pyjson;
use panel_model::protocols::{AppliedDocument, EgressTarget, RouterTarget};
use panel_model::routing::document::{
    canonical, document_digest, router_direct_intent, telemt_direct_document, trusttunnel_direct_document,
};
use panel_model::routing::models::{
    backend_for, exit_hops, is_custom_exit, is_node_exit, Action, CompileStatus, Compiled, DefaultAction, Fallback,
    Port, Reason, RoutingPolicy, RoutingRule, AMNEZIAWG_WHOLE_ONLY, COMPILER_VERSION, LANES_UNSUPPORTED_AMNEZIAWG,
    LANES_UNSUPPORTED_TRUSTTUNNEL, LANE_SERVICE,
};
use panel_model::{Backend, Protocol};
use serde_json::{json, Map, Value};

use crate::error::Result;
use crate::intent;
use crate::net::{is_private_network, Network};

pub use crate::intent::ChainHop;

pub const MAX_DOCUMENT_BYTES: usize = 16384;
/// forwardproxy takes at most this many subjects per `deny` line (naive_manager/egress.py).
pub const ACL_SUBJECTS_PER_LINE: usize = 64;
pub const PRIVATE_DOMAINS: &[&str] = &["localhost", "*.localhost"];

/// A lookup the compiler asks the service for: the answer, or why it cannot be used; the outer
/// `Result` is a failure Python would have let escape (the database).
pub type Lookup<T> = Result<std::result::Result<T, Reason>>;

/// `chains.resolve(guid)`: a node exit's hop as this panel knows it, or the reason it cannot.
pub trait HopResolver {
    fn resolve(&mut self, guid: &str) -> Lookup<ChainHop>;
}

/// `exits(exit_id)`: a custom exit's spec (credential revealed for its node), or the reason.
pub type ExitLookup<'a> = &'a mut dyn FnMut(&str) -> Lookup<Value>;

/// The keyword arguments of `compile`.
#[derive(Default)]
pub struct Options<'a> {
    /// `node_egress_v1`: `False` for a node whose panel predates egress policies.
    pub old_node: bool,
    /// The service's section on the node's router; `None` when the panel knows of no router.
    pub router: Option<&'a RouterTarget>,
    /// The service's other policies (its own and the grant lanes) the router runs as one intent.
    pub lanes: &'a [RoutingPolicy],
    pub chains: Option<&'a mut dyn HopResolver>,
    /// The guids that name this node (a chain through one is a loop); empty means `{"local"}`.
    pub own_guids: Vec<String>,
    pub exits: Option<ExitLookup<'a>>,
}

/// The policy's enabled rules.
pub fn enabled_rules(policy: &RoutingPolicy) -> Vec<RoutingRule> {
    policy.intent.rules.iter().filter(|rule| rule.enabled).cloned().collect()
}

/// `_private(rule)`: the rule names a private domain or overlaps a private network.
pub fn private(rule: &RoutingRule) -> bool {
    if rule.matcher.domains.iter().any(|domain| PRIVATE_DOMAINS.contains(&domain.as_str())) {
        return true;
    }
    rule.matcher.cidrs.iter().any(|cidr| is_private_network(cidr))
}

fn needed(rule: &RoutingRule) -> Vec<String> {
    let kind = if rule.action == Action::Block { "block" } else { "selective" };
    let mut needed = Vec::new();
    if !rule.matcher.domains.is_empty() {
        needed.push(format!("{kind}_domain"));
    }
    if !rule.matcher.cidrs.is_empty() {
        needed.push(format!("{kind}_cidr"));
    }
    needed
}

/// `json.dumps(value, indent=1, sort_keys=True)`.
pub fn pretty(value: &Value) -> String {
    pyjson::dumps(value, &pyjson::Options { indent: Some(1), separators: None, sort_keys: true, ensure_ascii: true })
}

/// `_diff(before, after)`: the changed lines between the applied and the planned document.
pub fn diff(before: Option<&Value>, after: &Value) -> Vec<String> {
    let old = pretty(before.unwrap_or(&Value::Null));
    let new = pretty(after);
    let old: Vec<&str> = old.split('\n').collect();
    let new: Vec<&str> = new.split('\n').collect();
    crate::difflib::changed_lines(&old, &new)
}

/// The diff against what the runtime runs: a linked node reports only the digest — same digest,
/// no change to show; otherwise the whole planned document is the diff.
pub fn diff_against(applied: Option<&AppliedDocument>, document: &Value, digest: &str) -> Vec<String> {
    match applied {
        Some(applied) if applied.document.is_null() => {
            if applied.digest == digest {
                Vec::new()
            } else {
                diff(None, document)
            }
        }
        Some(applied) => diff(Some(&applied.document), document),
        None => diff(None, document),
    }
}

pub fn rollback_of(applied: Option<&AppliedDocument>) -> Option<Value> {
    applied.map(|applied| json!({"to_revision": applied.revision, "to_digest": applied.digest}))
}

fn naive_document(default_action: DefaultAction, rules: &[RoutingRule]) -> Value {
    let subjects: Vec<String> = rules
        .iter()
        .flat_map(|rule| rule.matcher.domains.iter().chain(rule.matcher.cidrs.iter()).cloned())
        .collect();
    let acl: Vec<Value> = subjects.chunks(ACL_SUBJECTS_PER_LINE).map(|chunk| json!({"deny": chunk})).collect();
    let upstream = if default_action == DefaultAction::Egress { json!({"provider": "warp"}) } else { Value::Null };
    json!({"schema": 1, "upstream": upstream, "acl": acl})
}

fn amneziawg_document(default_action: DefaultAction) -> Value {
    let upstream = if default_action == DefaultAction::Egress { json!({"provider": "warp"}) } else { Value::Null };
    json!({"schema": 1, "upstream": upstream})
}

/// `*.x` and `x` are the same suffix selector; kept once, in first-seen order.
pub fn suffixes(domains: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for domain in domains {
        let suffix = domain.strip_prefix("*.").unwrap_or(domain).to_string();
        if !out.contains(&suffix) {
            out.push(suffix);
        }
    }
    out
}

fn mieru_document(default_action: DefaultAction, rules: &[RoutingRule]) -> Value {
    let mut compiled: Vec<Value> = rules
        .iter()
        .map(|rule| {
            let action = match rule.action {
                Action::Direct => "DIRECT",
                Action::Block => "REJECT",
                Action::Egress => "PROXY",
            };
            let proxy = if rule.action == Action::Egress { json!("warp") } else { Value::Null };
            json!({"domains": suffixes(&rule.matcher.domains), "cidrs": rule.matcher.cidrs, "action": action, "proxy": proxy})
        })
        .collect();
    if default_action == DefaultAction::Egress {
        compiled.push(json!({"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"}));
    }
    let uses_warp = compiled.iter().any(|rule| rule["action"] == "PROXY");
    let proxies = if uses_warp { json!([{"name": "warp", "provider": "warp"}]) } else { json!([]) };
    json!({"schema": 1, "proxies": proxies, "rules": compiled})
}

/// `direct_document(backend)`: what «reset» applies — the whole service direct, no rules; on the
/// router the pass-through intent.
pub fn direct_document(backend: Backend) -> Value {
    match backend {
        Backend::XrayRouter => router_direct_intent(),
        Backend::MtproxyNative => telemt_direct_document(),
        Backend::TrusttunnelNative => trusttunnel_direct_document(),
        Backend::AmneziawgNative => amneziawg_document(DefaultAction::Direct),
        Backend::NaiveNative => naive_document(DefaultAction::Direct, &[]),
        Backend::MieruNative => mieru_document(DefaultAction::Direct, &[]),
    }
}

fn reason(code: &str, rule_id: Option<&String>, message: impl Into<String>) -> Reason {
    Reason::new(code, rule_id.cloned(), message)
}

/// What MTProxy's traffic can never match on the router, and its lanes.
fn mtproxy_rules(policy: &RoutingPolicy, lanes: &[RoutingPolicy]) -> Vec<Reason> {
    let mut reasons = Vec::new();
    for other in std::iter::once(policy).chain(lanes.iter()) {
        if other.lane != LANE_SERVICE {
            reasons.push(reason(
                "rule_kind_unsupported",
                None,
                "MTProxy has no client lanes: Telemt cannot tell its users apart upstream",
            ));
            continue;
        }
        for rule in &other.intent.rules {
            let named = &rule.matcher;
            if rule.enabled && (!named.domains.is_empty() || !named.geosites.is_empty() || !named.protocols.is_empty()) {
                reasons.push(reason(
                    "rule_kind_unsupported",
                    rule.id.as_ref(),
                    "MTProxy connects to Telegram data centres by address: match it by CIDR, geoip or port, not by domain, geosite or protocol",
                ));
            }
        }
    }
    reasons
}

fn unsupported_for(policy: &RoutingPolicy, target: Option<&EgressTarget>) -> Compiled {
    let mut compiled = Compiled::new(CompileStatus::Unsupported);
    compiled.backend = Some(policy.backend.as_str().to_string());
    compiled.runtime_version = target.and_then(|target| target.runtime_version.clone());
    compiled
}

fn refuse(mut compiled: Compiled, reasons: Vec<Reason>, warnings: Vec<String>) -> Compiled {
    compiled.reasons = reasons;
    compiled.warnings = warnings;
    compiled
}

/// `compile(policy, target, …)`: what the node would run for this policy, or exactly why it
/// cannot. `target` is the service's native manager, `None` when it reports none.
pub fn compile(policy: &RoutingPolicy, target: Option<&EgressTarget>, options: Options<'_>) -> Result<Compiled> {
    let mut unsupported = unsupported_for(policy, target);
    if backend_for(policy.protocol.as_str()).is_none() {
        unsupported.reasons.push(reason("protocol_out_of_scope", None, format!("{} has no egress", policy.protocol)));
        return Ok(unsupported);
    }
    if options.old_node {
        unsupported.reasons.push(reason(
            "node_lacks_egress_v1",
            None,
            "the node's panel does not support egress policies — update it",
        ));
        return Ok(unsupported);
    }
    let Some(target) = target else {
        unsupported.reasons.push(reason(
            "protocol_disabled_on_node",
            None,
            format!("{} reports no egress target on this node", policy.protocol),
        ));
        return Ok(unsupported);
    };
    let lanes = options.lanes;
    let is_lane = policy.lane != LANE_SERVICE || lanes.iter().any(|other| other.lane != LANE_SERVICE);
    if is_lane && policy.protocol == Protocol::Amneziawg {
        unsupported.reasons.push(reason("lanes_unsupported", None, LANES_UNSUPPORTED_AMNEZIAWG));
        return Ok(unsupported);
    }
    if is_lane && policy.protocol == Protocol::Trusttunnel {
        unsupported.reasons.push(reason("lanes_unsupported", None, LANES_UNSUPPORTED_TRUSTTUNNEL));
        return Ok(unsupported);
    }
    let router = options.router;
    let router_up = router.is_some_and(|router| router.available);
    if is_lane && !router_up {
        unsupported.reasons.push(reason("lane_requires_router", None, "a client lane runs only on the node's Xray-router"));
        return Ok(unsupported);
    }
    if policy.backend == Backend::XrayRouter {
        let Some(router) = router.filter(|router| router.available) else {
            let code = match router.and_then(|router| router.reason.as_deref()) {
                None | Some("router_unavailable") => "router_unavailable".to_string(),
                Some(other) => other.to_string(),
            };
            unsupported.reasons.push(Reason::new(code, None, "the node has no Xray-router to run this policy"));
            return Ok(unsupported);
        };
        if !target.router_attached {
            let code = if is_lane { "lane_not_attached" } else { "not_attached" };
            unsupported.reasons.push(reason(
                code,
                None,
                format!("{} is not attached to the node's Xray-router", policy.protocol),
            ));
            return Ok(unsupported);
        }
        if policy.protocol == Protocol::Mtproxy {
            let reasons = mtproxy_rules(policy, lanes);
            if !reasons.is_empty() {
                unsupported.reasons = reasons;
                return Ok(unsupported);
            }
        }
        let own_guids = if options.own_guids.is_empty() { vec!["local".to_string()] } else { options.own_guids };
        return intent::compile_intent(
            policy,
            router,
            intent::IntentOptions {
                warnings: target.warnings.clone(),
                lanes,
                resolver: options.chains,
                own_guids,
                exits_resolver: options.exits,
            },
        );
    }
    if is_lane {
        unsupported.reasons.push(reason("lane_requires_router", None, "a client lane runs only on the node's Xray-router"));
        return Ok(unsupported);
    }
    if policy.backend != target.backend {
        unsupported.reasons.push(reason(
            "backend_capability_missing",
            None,
            format!("the node runs {}, the policy targets {}", target.backend, policy.backend),
        ));
        return Ok(unsupported);
    }
    if target.router_attached {
        unsupported.reasons.push(reason(
            "backend_capability_missing",
            None,
            format!(
                "{} is attached to the node's Xray-router: the policy must target xray_router",
                policy.protocol
            ),
        ));
        return Ok(unsupported);
    }
    if matches!(target.backend, Backend::MtproxyNative | Backend::TrusttunnelNative) {
        return Ok(compile_direct_only(policy, target, unsupported));
    }

    let mut reasons: Vec<Reason> = Vec::new();
    let mut warnings: Vec<String> = target.warnings.clone();
    let mut rules = enabled_rules(policy);
    let mut default_action = policy.intent.default_action;
    let whole = if default_action == DefaultAction::Egress { "whole_warp" } else { "whole_direct" };
    if !target.capabilities.contains(whole) {
        reasons.push(reason("backend_capability_missing", None, format!("{} lacks {whole}", target.backend)));
    }
    if target.backend == Backend::AmneziawgNative && !rules.is_empty() {
        reasons.push(reason("rule_kind_unsupported", rules[0].id.as_ref(), AMNEZIAWG_WHOLE_ONLY));
        rules.clear();
    }
    let default_egress = policy.intent.default_egress.as_deref();
    if default_egress.is_some_and(|value| is_node_exit(value) || is_custom_exit(value)) {
        reasons.push(reason(
            "rule_kind_unsupported",
            None,
            "an exit through another node or a custom outbound is enforced only by xray_router",
        ));
    }
    for rule in &rules {
        if rule.egress.as_deref().is_some_and(|value| is_node_exit(value) || is_custom_exit(value)) {
            reasons.push(reason(
                "rule_kind_unsupported",
                rule.id.as_ref(),
                "an exit through another node or a custom outbound is enforced only by xray_router",
            ));
            continue;
        }
        let named = &rule.matcher;
        if !named.ports.is_empty() || !named.geosites.is_empty() || !named.geoips.is_empty() || !named.protocols.is_empty()
        {
            reasons.push(reason(
                "rule_kind_unsupported",
                rule.id.as_ref(),
                "matching by port, geosite, geoip or protocol is enforced only by xray_router",
            ));
            continue;
        }
        let mut missing: Vec<String> =
            needed(rule).into_iter().filter(|cell| !target.capabilities.contains(cell)).collect();
        missing.sort();
        if !missing.is_empty() {
            reasons.push(reason(
                "backend_capability_missing",
                rule.id.as_ref(),
                format!("{} lacks {}", target.backend, missing.join(", ")),
            ));
            continue;
        }
        if rule.action != Action::Block && private(rule) {
            reasons.push(reason(
                "private_destination",
                rule.id.as_ref(),
                "loopback, link-local and private networks may only be blocked",
            ));
            continue;
        }
        if target.backend == Backend::NaiveNative && rule.action == Action::Block && default_action == DefaultAction::Egress
        {
            reasons.push(reason(
                "rule_kind_unsupported",
                rule.id.as_ref(),
                "forwardproxy does not enforce a block beside an upstream: naive_native cannot block while the whole service goes through warp",
            ));
        }
    }
    let uses_warp = default_action == DefaultAction::Egress || rules.iter().any(|rule| rule.action == Action::Egress);
    if uses_warp {
        match target.providers.get("warp") {
            None => reasons.push(reason("provider_unavailable", None, "the node has no warp egress configured")),
            Some(provider) if provider.get("reachable") == Some(&Value::Bool(false)) => {
                if policy.intent.fallback == Fallback::ApprovedDirect {
                    warnings.push("provider_unreachable".into());
                    default_action = DefaultAction::Direct;
                    for rule in rules.iter_mut().filter(|rule| rule.action == Action::Egress) {
                        rule.action = Action::Direct;
                        rule.egress = None;
                    }
                } else {
                    reasons.push(reason(
                        "provider_unreachable",
                        None,
                        "warp does not answer on the node; the policy stays fail-closed",
                    ));
                }
            }
            Some(_) => {}
        }
    }
    if !reasons.is_empty() {
        return Ok(refuse(unsupported, reasons, warnings));
    }
    let document = match target.backend {
        Backend::AmneziawgNative => amneziawg_document(default_action),
        Backend::NaiveNative => naive_document(default_action, &rules),
        _ => mieru_document(default_action, &rules),
    };
    if canonical(&document).len() > MAX_DOCUMENT_BYTES {
        let reasons = vec![reason("document_too_large", None, "the compiled document exceeds 16 KiB")];
        return Ok(refuse(unsupported, reasons, warnings));
    }
    if default_action == DefaultAction::Direct && rules.is_empty() {
        warnings.push("policy_empty".into());
    }
    let digest = document_digest(&document);
    let mut compiled = Compiled::new(CompileStatus::Supported);
    compiled.warnings = warnings;
    compiled.diff = diff_against(target.applied.as_ref(), &document, &digest);
    compiled.document = Some(document);
    compiled.digest = Some(digest);
    compiled.restart_required = target.restart_required;
    compiled.rollback = rollback_of(target.applied.as_ref());
    compiled.compiler_version = COMPILER_VERSION.into();
    compiled.backend = Some(target.backend.as_str().into());
    compiled.runtime_version = target.runtime_version.clone();
    Ok(compiled)
}

/// Telemt's own upstream and the TrustTunnel endpoint's forward protocol: «direct, no rules» is
/// the one policy such a backend runs by itself; anything else needs the router.
fn compile_direct_only(policy: &RoutingPolicy, target: &EgressTarget, mut unsupported: Compiled) -> Compiled {
    if policy.intent.default_action != DefaultAction::Direct || policy.intent.rules.iter().any(|rule| rule.enabled) {
        let name = if target.backend == Backend::TrusttunnelNative { "TrustTunnel" } else { "MTProxy" };
        unsupported.reasons.push(reason(
            "not_attached",
            None,
            format!("{name} is routed only through the node's Xray-router: attach it first"),
        ));
        unsupported.warnings = target.warnings.clone();
        return unsupported;
    }
    let document = direct_document(target.backend);
    let digest = document_digest(&document);
    let mut warnings = target.warnings.clone();
    warnings.push("policy_empty".into());
    let mut compiled = Compiled::new(CompileStatus::Supported);
    compiled.warnings = warnings;
    compiled.diff = diff_against(target.applied.as_ref(), &document, &digest);
    compiled.document = Some(document);
    compiled.digest = Some(digest);
    compiled.restart_required = false;
    compiled.rollback = rollback_of(target.applied.as_ref());
    compiled.backend = Some(target.backend.as_str().into());
    compiled.runtime_version = target.runtime_version.clone();
    compiled
}

fn port_matches(ports: &[Port], port: i64) -> bool {
    ports.iter().any(|item| match item {
        Port::One(value) => *value == port,
        Port::Range(range) => {
            let (low, high) = range.split_once('-').unwrap_or((range, range));
            let (low, high) = (low.parse::<i64>().unwrap_or(i64::MAX), high.parse::<i64>().unwrap_or(i64::MIN));
            low <= port && port <= high
        }
    })
}

/// True/False when the rule's selectors decide on their own; `None` when only geodata (or the
/// sniffed protocol) could say — the router has those, the panel has not.
fn destination_matches(rule: &RoutingRule, host: &str, port: i64) -> Option<bool> {
    let named = &rule.matcher;
    if !named.ports.is_empty() && !port_matches(&named.ports, port) {
        return Some(false);
    }
    let address = ip_address(host).ok();
    let mut hit = false;
    if !named.domains.is_empty() {
        let lowered = panel_core::pytext::lower(host);
        let lowered = lowered.trim_end_matches('.');
        for domain in &named.domains {
            let suffix = domain.strip_prefix("*.").unwrap_or(domain);
            if lowered == suffix || lowered.ends_with(&format!(".{suffix}")) {
                hit = true;
            }
        }
    }
    if let Some(address) = &address {
        for cidr in &named.cidrs {
            if Network::parse(cidr).is_some_and(|network| network.contains(address)) {
                hit = true;
            }
        }
    }
    if hit {
        return Some(true);
    }
    if !named.geosites.is_empty() || !named.geoips.is_empty() || !named.protocols.is_empty() {
        return None;
    }
    if named.domains.is_empty() && named.cidrs.is_empty() {
        return Some(true); // a rule on ports alone, and the port matched
    }
    Some(false)
}

/// `explain(policy, host, port)`: the first rule that decides a destination, the lane's default
/// otherwise, and the rules before it only geodata could match (`uncertain`).
pub fn explain(policy: &RoutingPolicy, host: &str, port: i64) -> Map<String, Value> {
    let mut uncertain: Vec<String> = Vec::new();
    let mut winner: Option<&RoutingRule> = None;
    for rule in policy.intent.rules.iter().filter(|rule| rule.enabled) {
        match destination_matches(rule, host, port) {
            None => uncertain.push(rule.id.clone().unwrap_or_default()),
            Some(true) => {
                winner = Some(rule);
                break;
            }
            Some(false) => {}
        }
    }
    let (action, value) = match winner {
        Some(rule) => (rule.action.as_str(), rule.egress.clone()),
        None => (policy.intent.default_action.as_str(), policy.intent.default_egress.clone()),
    };
    let (hops, via) = exit_hops(value.as_deref());
    let mut out = Map::new();
    out.insert("lane".into(), json!(policy.lane));
    out.insert("rule_id".into(), json!(winner.and_then(|rule| rule.id.clone())));
    out.insert("action".into(), json!(action));
    out.insert("exit".into(), json!(value));
    out.insert("hops".into(), json!(hops));
    out.insert("via".into(), json!(via));
    out.insert("uncertain".into(), json!(uncertain));
    out
}
