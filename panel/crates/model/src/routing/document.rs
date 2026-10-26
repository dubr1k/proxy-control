//! The compiled egress document as the panel and the managers see it (`routing/document.py`).
//!
//! [`document_digest`] is the one canonical form the panel, the naive-manager and the mieru-manager
//! all hash — `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)` — so a policy
//! revision on the central, the `applied_digest` a node reports and the manager's journal entry
//! compare by the same bytes on every host.

use panel_core::{ids, pyjson, pytext};
use serde_json::{json, Map, Value};

use crate::pyrepr;

/// The codes the managers' egress APIs answer with (sorted). Any other code is a plain conflict or
/// an outage, so a manager never dictates panel copy.
pub const EGRESS_REASON_CODES: &[&str] = &[
    "artifact_mismatch",
    "egress_conflict",
    "egress_invalid",
    "egress_no_previous",
    "egress_readback_mismatch",
    "egress_unreachable",
    "geoip_unknown",
    "geosite_unknown",
    "lane_slots_exhausted",
    "lane_unknown",
    "lanes_invalid",
    "manual_intervention_required",
    "relay_disabled",
];

/// Where Telemt reaches the router: the `xray-router-ingress` bridge on the Compose network.
pub const MTPROXY_BRIDGE_ADDRESS: &str = "xray-router-ingress:45103";

/// The protocols that have an attach document, in `ATTACH_DOCUMENTS` order.
pub const ATTACH_PROTOCOLS: &[&str] = &["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"];

/// `ATTACH_DOCUMENTS[protocol]` (a fresh copy): the native document that hands a service's whole
/// traffic to the node's Xray-router. `None` for a protocol without one (Python's `KeyError`).
pub fn attach_document(protocol: &str) -> Option<Value> {
    Some(match protocol {
        "naive" => json!({"schema": 1, "upstream": {"provider": "router"}, "acl": []}),
        "mieru" => json!({"schema": 1, "proxies": [{"name": "router", "provider": "router"}],
                          "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "router"}]}),
        "mtproxy" => json!({"schema": 1, "upstream": {"provider": "router"}}),
        "trusttunnel" => json!({"mode": "socks5", "address": "127.0.0.1:45104"}),
        "amneziawg" => json!({"schema": 1, "upstream": {"provider": "router"}}),
        _ => return None,
    })
}

/// The TrustTunnel manager's document for «direct»: the endpoint dials destinations itself.
pub fn trusttunnel_direct_document() -> Value {
    json!({"mode": "direct"})
}

/// Telemt's own document for «direct»: the upstream it had before the router.
pub fn telemt_direct_document() -> Value {
    json!({"schema": 1, "upstream": null})
}

/// The router's intent that sends everything direct.
pub fn router_direct_intent() -> Value {
    json!({"schema": 1, "default": {"action": "direct", "egress": null}, "rules": []})
}

/// Whether a native manager's applied document hands the service to the router.
pub fn attached_to_router(protocol: &str, document: &Value) -> bool {
    let Value::Object(map) = document else {
        return false;
    };
    let router = json!({"provider": "router"});
    match protocol {
        "naive" | "mtproxy" | "amneziawg" => map.get("upstream").is_some_and(|upstream| pyrepr::eq(upstream, &router)),
        "trusttunnel" => pyrepr::eq(document, &attach_document("trusttunnel").expect("trusttunnel attaches")),
        "mieru" => {
            let proxies = truthy_list(map.get("proxies"));
            let rules = truthy_list(map.get("rules"));
            let attach = attach_document("mieru").expect("mieru attaches");
            proxies.iter().any(|proxy| proxy.as_object().and_then(|p| p.get("name")) == Some(&json!("router")))
                && rules.last().is_some_and(|last| pyrepr::eq(last, &attach["rules"][0]))
        }
        _ => false,
    }
}

/// `value or []` for a value that is a list when present.
fn truthy_list(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

/// `json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` — ASCII, so
/// its length in characters is its length in bytes.
pub fn canonical(document: &Value) -> String {
    pyjson::canonical(document)
}

/// The canonical text of an object.
pub fn canonical_map(document: &Map<String, Value>) -> String {
    canonical(&Value::Object(document.clone()))
}

/// `sha256(canonical(document))` as lowercase hex.
pub fn document_digest(document: &Value) -> String {
    ids::sha256_hex(canonical(document))
}

/// The digest of an object.
pub fn document_digest_map(document: &Map<String, Value>) -> String {
    document_digest(&Value::Object(document.clone()))
}

/// A router intent for the operator's eyes: the relay accounts a chain carries
/// (`chains.*.hops[].uuid`) and every custom exit's credential masked with `***`. Anything that
/// is not an intent with chains comes back unchanged.
pub fn redact_document(document: &Value) -> Value {
    let Some(map) = document.as_object() else {
        return document.clone();
    };
    if !map.get("chains").is_some_and(Value::is_object) {
        return document.clone();
    }
    let mut copy = document.clone();
    if let Some(Value::Object(chains)) = copy.get_mut("chains") {
        for chain in chains.values_mut() {
            if let Some(Value::Array(hops)) = chain.as_object_mut().and_then(|chain| chain.get_mut("hops")) {
                for hop in hops.iter_mut() {
                    if let Some(hop) = hop.as_object_mut() {
                        if hop.contains_key("uuid") {
                            hop.insert("uuid".into(), json!("***"));
                        }
                    }
                }
            }
        }
    }
    if let Some(Value::Object(exits)) = copy.get_mut("exits") {
        for exit in exits.values_mut() {
            if let Some(Value::Object(credential)) = exit.as_object_mut().and_then(|exit| exit.get_mut("credential")) {
                for value in credential.values_mut() {
                    *value = json!("***");
                }
            }
        }
    }
    copy
}

/// The diff lines with every `"uuid": "…"` / `"password": "…"` value masked
/// (`re.sub(r'("(?:uuid|password)":\s*")[^"]*(")', r"\1***\2", line)`).
pub fn redact_diff(lines: &[String]) -> Vec<String> {
    lines.iter().map(|line| redact_line(line)).collect()
}

fn redact_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    'scan: while !rest.is_empty() {
        for key in ["\"uuid\":", "\"password\":"] {
            if let Some(after_key) = rest.strip_prefix(key) {
                let spaces = after_key.len() - after_key.trim_start_matches(pytext::is_space).len();
                let after_spaces = &after_key[spaces..];
                if let Some(value_and_tail) = after_spaces.strip_prefix('"') {
                    if let Some(end) = value_and_tail.find('"') {
                        out.push_str(key);
                        out.push_str(&after_key[..spaces]);
                        out.push_str("\"***\"");
                        rest = &value_and_tail[end + 1..];
                        continue 'scan;
                    }
                }
            }
        }
        let ch = rest.chars().next().expect("not empty");
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    out
}

/// A schema-2 intent minus one lane and the chains (and custom exits) only it used — what a node
/// should run once a lane is withdrawn, until the service's policy is applied again. Anything else
/// comes back unchanged.
pub fn without_lane(document: &Value, lane: &str) -> Value {
    let Some(map) = document.as_object() else {
        return document.clone();
    };
    let lanes = match map.get("lanes") {
        Some(Value::Object(lanes)) => lanes,
        _ => return document.clone(),
    };
    if !pyrepr::eq(map.get("schema").unwrap_or(&Value::Null), &json!(2)) || !lanes.contains_key(lane) {
        return document.clone();
    }
    let kept: Map<String, Value> =
        lanes.iter().filter(|(name, _)| name.as_str() != lane).map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut used: Vec<Value> = Vec::new();
    for body in kept.values() {
        for rule in body.get("rules").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            used.push(rule.get("egress").cloned().unwrap_or(Value::Null));
        }
    }
    for body in kept.values() {
        used.push(body.get("default").and_then(|default| default.get("egress")).cloned().unwrap_or(Value::Null));
    }
    let names_used =
        |prefix: &str, id: &str| used.iter().any(|value| value.as_str() == Some(&format!("{prefix}:{id}")));
    let chains: Map<String, Value> = map
        .get("chains")
        .and_then(Value::as_object)
        .map(|chains| {
            chains.iter().filter(|(id, _)| names_used("chain", id)).map(|(k, v)| (k.clone(), v.clone())).collect()
        })
        .unwrap_or_default();
    let mut result = map.clone();
    result.insert("lanes".into(), Value::Object(kept));
    result.insert("chains".into(), Value::Object(chains));
    if map.contains_key("exits") {
        let exits: Map<String, Value> = map
            .get("exits")
            .and_then(Value::as_object)
            .map(|exits| {
                exits.iter().filter(|(id, _)| names_used("exit", id)).map(|(k, v)| (k.clone(), v.clone())).collect()
            })
            .unwrap_or_default();
        if exits.is_empty() {
            result.shift_remove("exits");
        } else {
            result.insert("exits".into(), Value::Object(exits));
        }
    }
    Value::Object(result)
}
