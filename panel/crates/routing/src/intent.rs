//! Policy → the router's intent (`routing/adapters/xray_router.py`, `XrayRoutingIntent` of
//! `xray_router_manager/src/intent.rs`).
//!
//! The router enforces every cell the spike proved: domains and geosite codes, CIDRs and geoip
//! codes, ports, sniffed protocols, `block` beside a `warp` default, `direct` exceptions. What it
//! refuses is what no backend may do (open a private destination) and what the node lacks (the
//! `warp` provider, a relay, a custom-exit capable router). Lanes and chains (v0.7) and custom exits
//! (v0.8) make it a schema-2 intent.

use panel_model::protocols::RouterTarget;
use panel_model::routing::document::{attach_document, canonical, document_digest};
use panel_model::routing::models::{
    exit_hops, is_custom_exit, is_node_exit, Action, CompileStatus, Compiled, DefaultAction, Fallback, Port, Reason,
    RoutingPolicy, RoutingRule, COMPILER_VERSION, LANE_SERVICE,
};
use serde_json::{json, Map, Value};

use crate::compiler::{diff_against, enabled_rules, private, rollback_of, suffixes, ExitLookup, HopResolver};
use crate::error::Result;

pub const MAX_DOCUMENT_BYTES: usize = 16384;
/// Lanes multiply the volume (v0.7): the router's own ceiling for a schema-2 intent.
pub const MAX_DOCUMENT_BYTES_V2: usize = 65536;

/// A node's relay as this panel knows it: where to dial, the Reality public part, and the relay
/// accounts the central issued to *this* node — one for a direct exit, one (optional) for the
/// hop's WARP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHop {
    pub guid: String,
    pub address: String,
    pub port: i64,
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
    pub uuid_direct: String,
    pub uuid_warp: Option<String>,
}

fn needed(rule: &RoutingRule) -> Vec<String> {
    let kind = if rule.action == Action::Block { "block" } else { "selective" };
    let named = &rule.matcher;
    let mut needed = Vec::new();
    for (present, cell) in [
        (!named.domains.is_empty(), "domain"),
        (!named.geosites.is_empty(), "geosite"),
        (!named.cidrs.is_empty(), "cidr"),
        (!named.geoips.is_empty(), "geoip"),
        (!named.ports.is_empty(), "port"),
        (!named.protocols.is_empty(), "protocol"),
    ] {
        if present {
            needed.push(format!("{kind}_{cell}"));
        }
    }
    needed
}

/// One lane's effective default and enabled rules after the checks.
#[derive(Debug, Clone)]
pub struct CheckedLane {
    pub lane: String,
    pub default_action: DefaultAction,
    pub default_egress: Option<String>,
    pub rules: Vec<RoutingRule>,
}

/// `_lane_body`: the rules in order, the same selector vocabulary the policy uses; `egress_map`
/// turns a policy egress into the router's (`warp` stays, a node exit becomes `chain:<id>`).
fn lane_body(
    default_action: DefaultAction,
    default_egress: Option<&str>,
    rules: &[RoutingRule],
    egress_map: &mut dyn FnMut(&str) -> String,
) -> Map<String, Value> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        let named = &rule.matcher;
        let mut entry = Map::new();
        entry.insert("domains".into(), json!(suffixes(&named.domains)));
        entry.insert("geosites".into(), json!(named.geosites));
        entry.insert("cidrs".into(), json!(named.cidrs));
        entry.insert("geoips".into(), json!(named.geoips));
        entry.insert("ports".into(), Value::Array(named.ports.iter().map(Port::to_value).collect()));
        entry.insert("action".into(), json!(rule.action.as_str()));
        entry.insert("egress".into(), rule.egress.as_deref().map_or(Value::Null, |value| json!(egress_map(value))));
        if !named.protocols.is_empty() {
            // Only when named: a v0.7 router refuses an unknown rule field.
            entry.insert("protocols".into(), json!(named.protocols));
        }
        compiled.push(Value::Object(entry));
    }
    let egress = default_egress.map_or(Value::Null, |value| json!(egress_map(value)));
    let mut body = Map::new();
    body.insert("default".into(), json!({"action": default_action.as_str(), "egress": egress}));
    body.insert("rules".into(), Value::Array(compiled));
    body
}

/// `intent_of(default_action, rules)`: the schema-1 intent — one service, `warp` the only egress.
pub fn intent_of(default_action: DefaultAction, rules: &[RoutingRule]) -> Value {
    let egress = (default_action == DefaultAction::Egress).then_some("warp");
    let body = lane_body(default_action, egress, rules, &mut |value| value.to_string());
    let mut document = Map::new();
    document.insert("schema".into(), json!(1));
    document.extend(body);
    Value::Object(document)
}

/// `intent_v2(protocol, lanes, chains, exits)`: every lane of the service (the service's own
/// first), the chains they name and the custom exits (`exit:<id>` → `exit:eN` with its spec).
pub fn intent_v2(protocol: &str, lanes: &[CheckedLane], chains: &[(String, Value)], exits: &[(String, Value)]) -> Value {
    let mut ids: Vec<String> = Vec::new();
    let mut exit_ids: Vec<String> = Vec::new();
    let mut egress_map = |value: &str| -> String {
        if is_custom_exit(value) {
            let index = exit_ids.iter().position(|known| known == value).unwrap_or_else(|| {
                exit_ids.push(value.to_string());
                exit_ids.len() - 1
            });
            return format!("exit:e{}", index + 1);
        }
        if !is_node_exit(value) {
            return value.to_string();
        }
        let index = ids.iter().position(|known| known == value).unwrap_or_else(|| {
            ids.push(value.to_string());
            ids.len() - 1
        });
        format!("chain:c{}", index + 1)
    };
    let mut rendered = Map::new();
    for lane in lanes {
        let key = if lane.lane == LANE_SERVICE { format!("svc:{protocol}") } else { lane.lane.clone() };
        let body = lane_body(lane.default_action, lane.default_egress.as_deref(), &lane.rules, &mut egress_map);
        rendered.insert(key, Value::Object(body));
    }
    let lookup = |pairs: &[(String, Value)], value: &str| {
        pairs.iter().find(|(name, _)| name == value).map(|(_, spec)| spec.clone()).unwrap_or(Value::Null)
    };
    let chain_map: Map<String, Value> =
        ids.iter().enumerate().map(|(index, value)| (format!("c{}", index + 1), lookup(chains, value))).collect();
    let mut document = Map::new();
    document.insert("schema".into(), json!(2));
    document.insert("lanes".into(), Value::Object(rendered));
    document.insert("chains".into(), Value::Object(chain_map));
    if !exit_ids.is_empty() {
        let exit_map: Map<String, Value> =
            exit_ids.iter().enumerate().map(|(index, value)| (format!("e{}", index + 1), lookup(exits, value))).collect();
        document.insert("exits".into(), Value::Object(exit_map));
    }
    Value::Object(document)
}

/// `resolve_chain(value, resolver, own_guids)`: every hop's relay as this node may reach it, the
/// middle hops with their *direct* account, the last with the account its exit needs.
pub fn resolve_chain(
    value: &str,
    resolver: &mut dyn HopResolver,
    own_guids: &[String],
) -> Result<std::result::Result<Value, Reason>> {
    let (guids, via) = exit_hops(Some(value));
    if guids.iter().any(|guid| own_guids.contains(guid)) {
        return Ok(Err(Reason::new("chain_loop", None, "a chain cannot pass through this node")));
    }
    let mut hops = Vec::with_capacity(guids.len());
    for (index, guid) in guids.iter().enumerate() {
        let found = match resolver.resolve(guid)? {
            Ok(found) => found,
            Err(reason) => return Ok(Err(reason)),
        };
        let last = index == guids.len() - 1;
        let uuid = if last && via == Some("warp") { found.uuid_warp.clone() } else { Some(found.uuid_direct.clone()) };
        let Some(uuid) = uuid else {
            return Ok(Err(Reason::new("relay_no_warp", None, format!("node {guid} has no relay account for its warp"))));
        };
        hops.push(json!({"guid": guid, "address": found.address, "port": found.port, "server_name": found.server_name,
                         "public_key": found.public_key, "short_id": found.short_id, "uuid": uuid}));
    }
    Ok(Ok(json!({"hops": hops, "exit": via})))
}

fn with_rule(reason: Reason, rule_id: Option<&String>) -> Reason {
    Reason { rule_id: rule_id.cloned(), ..reason }
}

/// What the intent compiler collects across lanes.
struct Collect<'a, 'b> {
    router: &'a RouterTarget,
    reasons: Vec<Reason>,
    warnings: Vec<String>,
    chains: Vec<(String, Value)>,
    exits: Vec<(String, Value)>,
    resolver: Option<&'b mut dyn HopResolver>,
    own_guids: Vec<String>,
    exits_resolver: Option<ExitLookup<'b>>,
}

impl Collect<'_, '_> {
    /// `_check_lane`: capabilities, private destinations, this node's warp (with the lane's own
    /// fallback), every node exit resolved into `chains` and every custom exit into `exits`.
    fn check_lane(&mut self, policy: &RoutingPolicy) -> Result<CheckedLane> {
        let router = self.router;
        let mut rules = enabled_rules(policy);
        let (mut default_action, mut default_egress) = (policy.intent.default_action, policy.intent.default_egress.clone());
        let whole = if default_action == DefaultAction::Egress { "whole_warp" } else { "whole_direct" };
        if !router.capabilities.contains(whole) {
            self.reasons.push(Reason::new("backend_capability_missing", None, format!("xray_router lacks {whole}")));
        }
        for rule in &rules {
            let mut missing: Vec<String> =
                needed(rule).into_iter().filter(|cell| !router.capabilities.contains(cell)).collect();
            missing.sort();
            if !missing.is_empty() {
                self.reasons.push(Reason::new(
                    "backend_capability_missing",
                    rule.id.clone(),
                    format!("xray_router lacks {}", missing.join(", ")),
                ));
                continue;
            }
            if rule.action != Action::Block && private(rule) {
                self.reasons.push(Reason::new(
                    "private_destination",
                    rule.id.clone(),
                    "loopback, link-local and private networks may only be blocked",
                ));
            }
        }
        let egresses: Vec<(Option<String>, Option<String>)> = std::iter::once((None, default_egress.clone()))
            .chain(rules.iter().map(|rule| (rule.id.clone(), rule.egress.clone())))
            .collect();
        for (rule_id, value) in egresses {
            let Some(value) = value else { continue };
            if is_custom_exit(&value) {
                if self.exits.iter().any(|(known, _)| *known == value) {
                    continue;
                }
                let capable = router.capabilities.contains("custom_exits");
                match self.exits_resolver.as_mut().filter(|_| capable) {
                    None => self.reasons.push(Reason::new(
                        "backend_capability_missing",
                        rule_id,
                        "the node's router does not run custom exits (update the node)",
                    )),
                    Some(resolver) => match resolver(&value[5..])? {
                        Ok(spec) => self.exits.push((value.clone(), spec)),
                        Err(reason) => self.reasons.push(with_rule(reason, rule_id.as_ref())),
                    },
                }
                continue;
            }
            if !is_node_exit(&value) || self.chains.iter().any(|(known, _)| *known == value) {
                continue;
            }
            let Some(resolver) = self.resolver.as_deref_mut() else {
                // Python called `resolver.resolve` on `None`: an AttributeError, never reached by
                // the service (it always passes a resolver when it keeps a relay registry).
                return Err(crate::error::RoutingFailure::internal("no chain resolver for a node exit"));
            };
            match resolve_chain(&value, resolver, &self.own_guids)? {
                Ok(chain) => self.chains.push((value.clone(), chain)),
                Err(reason) => self.reasons.push(with_rule(reason, rule_id.as_ref())),
            }
        }
        let uses_warp = default_egress.as_deref() == Some("warp")
            || rules.iter().any(|rule| rule.egress.as_deref() == Some("warp"));
        if uses_warp {
            match router.providers.get("warp") {
                None => self.reasons.push(Reason::new(
                    "provider_unavailable",
                    None,
                    "the node's router has no warp egress configured",
                )),
                Some(provider) if provider.get("reachable") == Some(&Value::Bool(false)) => {
                    if policy.intent.fallback == Fallback::ApprovedDirect {
                        self.warnings.push("provider_unreachable".into());
                        if default_egress.as_deref() == Some("warp") {
                            (default_action, default_egress) = (DefaultAction::Direct, None);
                        }
                        for rule in rules.iter_mut().filter(|rule| rule.egress.as_deref() == Some("warp")) {
                            rule.action = Action::Direct;
                            rule.egress = None;
                        }
                    } else {
                        self.reasons.push(Reason::new(
                            "provider_unreachable",
                            None,
                            "warp does not answer on the node; the policy stays fail-closed",
                        ));
                    }
                }
                Some(_) => {}
            }
        }
        Ok(CheckedLane { lane: policy.lane.clone(), default_action, default_egress, rules })
    }
}

/// The keyword arguments of `compile_intent`.
pub struct IntentOptions<'a, 'b> {
    /// The native target's warnings, carried through.
    pub warnings: Vec<String>,
    /// The other policies of the same service, folded into the one intent the router runs.
    pub lanes: &'a [RoutingPolicy],
    pub resolver: Option<&'b mut dyn HopResolver>,
    pub own_guids: Vec<String>,
    pub exits_resolver: Option<ExitLookup<'b>>,
}

/// `compile_intent(policy, router, …)`.
pub fn compile_intent(policy: &RoutingPolicy, router: &RouterTarget, options: IntentOptions<'_, '_>) -> Result<Compiled> {
    let mut unsupported = Compiled::new(CompileStatus::Unsupported);
    unsupported.backend = Some("xray_router".into());
    unsupported.runtime_version = router.xray_version.clone();
    unsupported.restart_required = true;
    let every: Vec<&RoutingPolicy> =
        std::iter::once(policy).chain(options.lanes.iter().filter(|other| other.id != policy.id)).collect();
    let service: Vec<&RoutingPolicy> = every.iter().copied().filter(|item| item.lane == LANE_SERVICE).collect();
    let grants: Vec<&RoutingPolicy> = every.iter().copied().filter(|item| item.lane != LANE_SERVICE).collect();
    let mut collect = Collect {
        router,
        reasons: Vec::new(),
        warnings: options.warnings,
        chains: Vec::new(),
        exits: Vec::new(),
        resolver: options.resolver,
        own_guids: options.own_guids,
        exits_resolver: options.exits_resolver,
    };
    let mut checked = Vec::new();
    for item in service.iter().chain(grants.iter()) {
        checked.push(collect.check_lane(item)?);
    }
    let Collect { reasons, mut warnings, chains, exits, .. } = collect;
    if !reasons.is_empty() {
        unsupported.reasons = reasons;
        unsupported.warnings = warnings;
        return Ok(unsupported);
    }
    let schema_2 = !grants.is_empty() || !chains.is_empty() || !exits.is_empty();
    let (document, limit) = if schema_2 {
        (intent_v2(policy.protocol.as_str(), &checked, &chains, &exits), MAX_DOCUMENT_BYTES_V2)
    } else {
        (intent_of(checked[0].default_action, &checked[0].rules), MAX_DOCUMENT_BYTES)
    };
    if canonical(&document).len() > limit {
        unsupported.reasons = vec![Reason::new(
            "document_too_large",
            None,
            format!("the compiled document exceeds {} KiB", limit / 1024),
        )];
        unsupported.warnings = warnings;
        return Ok(unsupported);
    }
    if !schema_2 && checked[0].default_action == DefaultAction::Direct && checked[0].rules.is_empty() {
        warnings.push("policy_empty".into());
    }
    let digest = document_digest(&document);
    let mut compiled = Compiled::new(CompileStatus::Supported);
    compiled.diff = diff_against(router.applied.as_ref(), &document, &digest);
    compiled.document = Some(document);
    compiled.digest = Some(digest);
    compiled.warnings = warnings;
    compiled.restart_required = true;
    compiled.rollback = rollback_of(router.applied.as_ref());
    compiled.compiler_version = COMPILER_VERSION.into();
    compiled.backend = Some("xray_router".into());
    compiled.runtime_version = router.xray_version.clone();
    compiled.attach = attach_document(policy.protocol.as_str());
    Ok(compiled)
}
