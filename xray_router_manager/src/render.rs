//! The Xray config one generation runs, rendered from the services' intents (spec §6).
//!
//! Everything here is a pure function of (intents, ingress credentials, provider endpoint): same
//! input, same bytes, same digest — byte for byte what the Python renderer wrote, since the
//! digest of a running generation is compared at every start. The shape is what the spike proved
//! on the stand (docs/spikes/XRAY_EGRESS_ROUTER.md):
//!
//! - one `socks` inbound per service on the host loopback, `auth: password` with exactly one
//!   account, `udp: false`, sniffing with `routeOnly`;
//! - outbounds `block` first (whatever nothing matches is refused), `direct` (`freedom` with
//!   `UseIP`), `warp` (`socks` to the node's WARP proxy-mode endpoint) only when an intent uses it;
//! - `routing.domainStrategy: IPOnDemand` and, per inbound tag, the immutable bypass
//!   (`geoip:private` and `localhost` → `block`) before the intent's first-match rules and a
//!   catch-all to the service's default. No `api`, no `stats`, no access log.
//!
//! Schema 2 adds lane accounts on the service's inbound (the service lane last, without a user
//! selector), a `vless` + `reality` outbound per chain hop dialled through the previous one, and
//! the node's relay inbound. v1.1 adds the `mtproxy` ingress (a `vless` inbound on a Unix socket
//! whose rules start with private networks on port 443 direct), v1.6 the no-auth `trusttunnel`
//! one, v3.0.0 the `amneziawg` `tun` inbound whose `warp` is a WireGuard outbound.

use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Map, Value};

use crate::errors::{Error, Result};
use crate::intent::{
    is_v2, provider_endpoint, uses_provider, NOAUTH_SERVICES, PORTS, SERVICES, TUN_SERVICES, WARP_WG_TAG,
};
use crate::pyjson;
use crate::util::sha256_hex;

/// What Telemt itself dials through its upstream besides Telegram: the TLS front of the `mask`
/// container on the Compose network. Loopback and link-local stay blocked.
pub const MTPROXY_PRIVATE_EXCEPTION: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
pub const RENDER_VERSION: &str = "2";
pub const RELAY_TAG: &str = "relay";
pub const RELAY_COVER: &str = "127.0.0.1:8443";
pub const TUN_MTU: i64 = 1280;

fn outbound_for(action: &str) -> &'static str {
    match action {
        "block" => "block",
        "egress" => "warp",
        _ => "direct",
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ingress {
    pub tag: String,
    pub port: i64,
    pub user: String,
    pub password: String,
    /// v1.1, `mtproxy`: the inbound listens on this Unix socket and admits this VLESS client.
    pub socket: Option<String>,
    pub uuid: Option<String>,
    /// v3.0.0, `amneziawg`: a `tun` inbound on this device (the router passes Xray its descriptor).
    pub tun: Option<String>,
}

impl Ingress {
    pub fn new(tag: &str, port: i64, user: &str, password: &str) -> Self {
        Self { tag: tag.into(), port, user: user.into(), password: password.into(), ..Self::default() }
    }
}

/// A `grant:<id>` lane's SOCKS account on its service's ingress.
#[derive(Debug, Clone, PartialEq)]
pub struct LaneAccount {
    pub lane: String,
    pub user: Value,
    pub password: Value,
}

/// This node's relay inbound: where other nodes' chains arrive.
#[derive(Debug, Clone, PartialEq)]
pub struct Relay {
    pub port: Value,
    pub server_name: Value,
    pub private_key: Value,
    pub short_ids: Vec<Value>,
    /// (email, uuid)
    pub accounts: Vec<(String, Value)>,
}

/// The ports of the authenticated ingresses (`PORTS` unless the environment moved them).
pub type Ports = BTreeMap<String, i64>;

pub fn default_ports() -> Ports {
    PORTS.iter().map(|(tag, port)| (tag.to_string(), *port)).collect()
}

fn sniffing() -> Value {
    json!({"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true})
}

/// The WireGuard outbound to WARP the `amneziawg` service's `warp` lands on (TCP and UDP);
/// Xray's own userspace stack (`noKernelTun`), so the router needs no capability for it.
pub fn warp_wg_outbound(account: &Value) -> Value {
    let address = match &account["address"] {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    json!({"tag": WARP_WG_TAG, "protocol": "wireguard", "settings": {
        "secretKey": account["private_key"], "address": [format!("{address}/32")],
        "peers": [{"publicKey": account["peer_public_key"], "endpoint": account["endpoint"],
                   "allowedIPs": ["0.0.0.0/0"], "keepAlive": 25}],
        "mtu": TUN_MTU, "noKernelTun": true}})
}

/// `example.com` and `*.example.com` both mean the suffix (Xray `domain:`), as mita does.
fn domain_selector(value: &str) -> String {
    format!("domain:{}", value.strip_prefix("*.").unwrap_or(value))
}

fn outbound_tag(action: &str, egress: &Value, chain_tags: &HashMap<String, String>) -> String {
    if action == "egress" {
        if let Some(egress) = egress.as_str() {
            if let Some(chain) = egress.strip_prefix("chain:") {
                // A validated intent names only its own chains and exits.
                return chain_tags.get(chain).cloned().unwrap_or_default();
            }
            if egress.starts_with("exit:") {
                return chain_tags.get(egress).cloned().unwrap_or_default();
            }
        }
    }
    outbound_for(action).to_string()
}

fn str_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn strings(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

/// The Xray outbound for one custom exit (v0.8): the protocol's settings, the transport and the
/// security layer as `validate_exit` normalised them.
pub fn exit_outbound(tag: &str, spec: &Value) -> Value {
    let (protocol, address, port) = (spec["protocol"].as_str().unwrap_or(""), &spec["address"], &spec["port"]);
    let empty = json!({});
    let credential = spec.get("credential").filter(|c| crate::util::py_truthy(c)).unwrap_or(&empty);
    let settings = match protocol {
        "socks" | "http" => {
            let mut server = Map::new();
            server.insert("address".into(), address.clone());
            server.insert("port".into(), port.clone());
            if credential.get("username").is_some_and(|u| !u.is_null()) {
                server
                    .insert("users".into(), json!([{"user": credential["username"], "pass": credential["password"]}]));
            }
            json!({"servers": [Value::Object(server)]})
        }
        "vless" => json!({"vnext": [{"address": address, "port": port, "users": [{
            "id": credential["uuid"], "encryption": "none", "flow": spec.get("flow").cloned().unwrap_or(json!(""))}]}]}),
        "trojan" => json!({"servers": [{"address": address, "port": port, "password": credential["password"]}]}),
        _ => {
            json!({"servers": [{"address": address, "port": port, "method": spec["method"], "password": credential["password"]}]})
        }
    };
    let tcp = json!({"network": "tcp"});
    let transport = spec.get("transport").filter(|t| crate::util::py_truthy(t)).unwrap_or(&tcp);
    let network = transport.get("network").and_then(Value::as_str).unwrap_or("tcp");
    let truthy = |value: Option<&Value>| value.is_some_and(crate::util::py_truthy);
    let path = |value: Option<&Value>| value.filter(|v| crate::util::py_truthy(v)).cloned().unwrap_or(json!("/"));
    let mut stream = Map::new();
    stream.insert("network".into(), json!(network));
    match network {
        "ws" | "xhttp" => {
            let mut settings = Map::new();
            settings.insert("path".into(), path(transport.get("path")));
            if truthy(transport.get("host")) {
                settings.insert("host".into(), transport["host"].clone());
            }
            let key = if network == "ws" { "wsSettings" } else { "xhttpSettings" };
            stream.insert(key.into(), Value::Object(settings));
        }
        "grpc" => {
            let service =
                transport.get("service_name").filter(|v| crate::util::py_truthy(v)).cloned().unwrap_or(json!(""));
            stream.insert("grpcSettings".into(), json!({"serviceName": service}));
        }
        _ => {}
    }
    let plain = json!({"kind": "none"});
    let security = spec.get("security").filter(|s| crate::util::py_truthy(s)).unwrap_or(&plain);
    let fingerprint = security.get("fingerprint").cloned().unwrap_or(json!("chrome"));
    match security.get("kind").and_then(Value::as_str).unwrap_or("none") {
        "tls" => {
            stream.insert("security".into(), json!("tls"));
            let mut tls = Map::new();
            tls.insert("fingerprint".into(), fingerprint);
            if truthy(security.get("server_name")) {
                tls.insert("serverName".into(), security["server_name"].clone());
            }
            if truthy(security.get("alpn")) {
                tls.insert("alpn".into(), security["alpn"].clone());
            }
            if truthy(security.get("insecure")) {
                tls.insert("allowInsecure".into(), json!(true));
            }
            stream.insert("tlsSettings".into(), Value::Object(tls));
        }
        "reality" => {
            stream.insert("security".into(), json!("reality"));
            stream.insert(
                "realitySettings".into(),
                json!({"serverName": security["server_name"], "fingerprint": fingerprint,
                       "publicKey": security["public_key"], "shortId": security.get("short_id").cloned().unwrap_or(json!(""))}),
            );
        }
        _ => {}
    }
    json!({"tag": tag, "protocol": protocol, "settings": settings, "streamSettings": Value::Object(stream)})
}

/// One first-match rule of an intent as an Xray routing rule.
pub fn rule(tag: &str, rule: &Value, user: Option<&Value>, chain_tags: &HashMap<String, String>) -> Value {
    let mut entry = Map::new();
    entry.insert("inboundTag".into(), json!([tag]));
    if let Some(user) = user {
        entry.insert("user".into(), json!([user]));
    }
    let mut domains: Vec<Value> = strings(&rule["domains"]).map(|d| json!(domain_selector(&str_of(d)))).collect();
    domains.extend(strings(&rule["geosites"]).map(|code| json!(format!("geosite:{}", str_of(code)))));
    let mut addresses: Vec<Value> = strings(&rule["cidrs"]).cloned().collect();
    addresses.extend(strings(&rule["geoips"]).map(|code| json!(format!("geoip:{}", str_of(code)))));
    if !domains.is_empty() {
        entry.insert("domain".into(), Value::Array(domains));
    }
    if !addresses.is_empty() {
        entry.insert("ip".into(), Value::Array(addresses));
    }
    let ports: Vec<String> = strings(&rule["ports"]).map(str_of).collect();
    if !ports.is_empty() {
        entry.insert("port".into(), json!(ports.join(",")));
    }
    if rule.get("protocols").is_some_and(crate::util::py_truthy) {
        // What the ingress sniffer saw (`sniffing.enabled` with `routeOnly`): bittorrent, tls, …
        entry.insert("protocol".into(), rule["protocols"].clone());
    }
    let action = rule["action"].as_str().unwrap_or("");
    entry.insert(
        "outboundTag".into(),
        json!(outbound_tag(action, rule.get("egress").unwrap_or(&Value::Null), chain_tags)),
    );
    Value::Object(entry)
}

fn bypass(tag: &str) -> [Value; 2] {
    [
        json!({"inboundTag": [tag], "ip": ["geoip:private"], "outboundTag": "block"}),
        json!({"inboundTag": [tag], "domain": ["domain:localhost", "full:localhost"], "outboundTag": "block"}),
    ]
}

fn hop_outbound(tag: &str, hop: &Value, previous: Option<&str>) -> Value {
    let mut outbound = json!({
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": hop["address"], "port": hop["port"],
                                "users": [{"id": hop["uuid"], "encryption": "none", "flow": ""}]}]},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "serverName": hop["server_name"], "fingerprint": "chrome", "publicKey": hop["public_key"],
            "shortId": hop["short_id"]}},
    });
    if let Some(previous) = previous {
        outbound["proxySettings"] = json!({"tag": previous});
    }
    outbound
}

/// One outbound per hop of every chain the service's intent names — the tag a rule lands on is the
/// chain's last hop — and one per custom exit (v0.8), keyed `exit:<id>`.
fn chain_outbounds(tag: &str, intent: &Value) -> (Vec<Value>, HashMap<String, String>) {
    let mut outbounds = Vec::new();
    let mut chain_tags = HashMap::new();
    for (chain_id, chain) in intent.get("chains").and_then(Value::as_object).into_iter().flatten() {
        let mut previous: Option<String> = None;
        for (index, hop) in strings(&chain["hops"]).enumerate() {
            let hop_tag = format!("chain:{tag}:{chain_id}:{}", index + 1);
            outbounds.push(hop_outbound(&hop_tag, hop, previous.as_deref()));
            previous = Some(hop_tag);
        }
        chain_tags.insert(chain_id.clone(), previous.unwrap_or_default());
    }
    for (exit_id, spec) in intent.get("exits").and_then(Value::as_object).into_iter().flatten() {
        let exit_tag = format!("exit:{tag}:{exit_id}");
        outbounds.push(exit_outbound(&exit_tag, spec));
        chain_tags.insert(format!("exit:{exit_id}"), exit_tag);
    }
    (outbounds, chain_tags)
}

/// Schema 2: every grant lane's rules and catch-all carry its account; the service lane comes last
/// **without** a user selector — it is everyone the ingress admits who has no lane of their own
/// in the intent, so nobody ever falls through to Xray's first outbound.
fn lane_rules(
    tag: &str,
    intent: &Value,
    accounts: &[LaneAccount],
    chain_tags: &HashMap<String, String>,
) -> Result<Vec<Value>> {
    let mut rules = Vec::new();
    let empty = Map::new();
    let lanes = intent.get("lanes").and_then(Value::as_object).unwrap_or(&empty);
    let ordered = lanes
        .keys()
        .filter(|lane| lane.starts_with("grant:"))
        .chain(lanes.keys().filter(|lane| lane.starts_with("svc:")));
    for lane in ordered {
        let user = if lane.starts_with("svc:") {
            None
        } else {
            // The last account wins, as a dict built from the list did.
            match accounts.iter().rev().find(|account| &account.lane == lane) {
                Some(account) => Some(&account.user),
                None => return Err(Error::invalid(format!("lane {lane} has no account on ingress {tag}"))),
            }
        };
        let body = &lanes[lane];
        rules.extend(strings(&body["rules"]).map(|r| rule(tag, r, user, chain_tags)));
        let default = &body["default"];
        let target = outbound_tag(default["action"].as_str().unwrap_or(""), &default["egress"], chain_tags);
        rules.push(match user {
            Some(user) => json!({"inboundTag": [tag], "user": [user], "outboundTag": target}),
            None => json!({"inboundTag": [tag], "outboundTag": target}),
        });
    }
    Ok(rules)
}

fn relay_inbound(relay: &Relay) -> Value {
    let clients: Vec<Value> =
        relay.accounts.iter().map(|(email, uuid)| json!({"id": uuid, "email": email, "flow": ""})).collect();
    json!({
        "tag": RELAY_TAG, "listen": "0.0.0.0", "port": relay.port, "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "dest": RELAY_COVER, "serverNames": [relay.server_name], "privateKey": relay.private_key,
            "shortIds": relay.short_ids}},
        "sniffing": sniffing(),
    })
}

/// What `render_config` renders from.
#[derive(Debug, Clone, Default)]
pub struct RenderInput<'a> {
    /// A validated document per service; a missing service runs pass-through.
    pub intents: Map<String, Value>,
    pub ingresses: Vec<Ingress>,
    pub warp_url: Option<&'a str>,
    /// `None` (or empty) is `PORTS`.
    pub ports: Option<Ports>,
    /// The grant lanes' accounts per service.
    pub lanes: BTreeMap<String, Vec<LaneAccount>>,
    /// This node's relay inbound when enabled.
    pub relay: Option<Relay>,
    /// The WARP WireGuard account AmneziaWG's `warp` uses.
    pub warp_wg: Option<Value>,
}

/// The full Xray config for these intents. `EgressInvalid` when something needs the `warp`
/// provider and this node has none, or a lane has no account.
pub fn render_config(input: &RenderInput) -> Result<Value> {
    let ports = input.ports.clone().filter(|ports| !ports.is_empty()).unwrap_or_else(default_ports);
    let port_of = |tag: &str| ports.get(tag).copied().ok_or_else(|| Error::Internal(format!("'{tag}'")));
    let mut by_tag: HashMap<&str, &Ingress> = HashMap::new();
    for ingress in &input.ingresses {
        by_tag.insert(ingress.tag.as_str(), ingress);
    }
    let services: Vec<&str> = SERVICES.iter().copied().filter(|tag| by_tag.contains_key(tag)).collect();
    let mut inbounds = Vec::new();
    for tag in &services {
        let ingress = by_tag[tag];
        if let Some(tun) = &ingress.tun {
            inbounds.push(json!({"tag": tag, "port": 0, "protocol": "tun", "settings": {"name": tun, "mtu": TUN_MTU},
                                 "sniffing": sniffing()}));
        } else if let Some(socket) = &ingress.socket {
            inbounds.push(json!({
                "tag": tag, "listen": socket, "port": 0, "protocol": "vless",
                "settings": {"clients": [{"id": ingress.uuid, "email": tag, "flow": ""}], "decryption": "none"},
                "streamSettings": {"network": "raw"}, "sniffing": sniffing(),
            }));
        } else if NOAUTH_SERVICES.contains(tag) {
            // The endpoint's SOCKS5 client has no credentials to present; the inbound is loopback-only.
            inbounds.push(json!({"tag": tag, "listen": "127.0.0.1", "port": port_of(tag)?, "protocol": "socks",
                                 "settings": {"auth": "noauth", "udp": false}, "sniffing": sniffing()}));
        } else {
            let mut accounts = vec![json!({"user": ingress.user, "pass": ingress.password})];
            accounts.extend(
                input
                    .lanes
                    .get(*tag)
                    .into_iter()
                    .flatten()
                    .map(|account| json!({"user": account.user, "pass": account.password})),
            );
            inbounds.push(json!({"tag": tag, "listen": "127.0.0.1", "port": port_of(tag)?, "protocol": "socks",
                                 "settings": {"auth": "password", "accounts": accounts, "udp": false},
                                 "sniffing": sniffing()}));
        }
    }
    if let Some(relay) = &input.relay {
        inbounds.push(relay_inbound(relay));
    }
    let mut outbounds = vec![
        json!({"tag": "block", "protocol": "blackhole"}),
        json!({"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}),
    ];
    let relay_warp: Vec<&String> = input
        .relay
        .iter()
        .flat_map(|relay| relay.accounts.iter())
        .map(|(email, _)| email)
        .filter(|e| e.ends_with(":warp"))
        .collect();
    let uses = |tag: &str| input.intents.get(tag).is_some_and(uses_provider);
    let needs_warp = services.iter().any(|tag| !TUN_SERVICES.contains(tag) && uses(tag)) || !relay_warp.is_empty();
    if needs_warp {
        let (host, port) = provider_endpoint(input.warp_url)?;
        outbounds.push(
            json!({"tag": "warp", "protocol": "socks", "settings": {"servers": [{"address": host, "port": port}]}}),
        );
    }
    if services.iter().any(|tag| TUN_SERVICES.contains(tag) && uses(tag)) {
        let Some(account) = &input.warp_wg else {
            return Err(Error::EgressInvalid {
                message: "this node has no WARP WireGuard account for AmneziaWG yet".into(),
                code: "egress_unreachable".into(),
            });
        };
        outbounds.push(warp_wg_outbound(account));
    }
    let passthrough = json!({"default": {"action": "direct", "egress": null}, "rules": []});
    let no_accounts = Vec::new();
    let mut rules: Vec<Value> = Vec::new();
    for tag in &services {
        let intent = input.intents.get(*tag).filter(|intent| crate::util::py_truthy(intent)).unwrap_or(&passthrough);
        let (extra, chain_tags) = chain_outbounds(tag, intent);
        outbounds.extend(extra);
        if by_tag[tag].socket.is_some() {
            rules.push(
                json!({"inboundTag": [tag], "ip": MTPROXY_PRIVATE_EXCEPTION, "port": "443", "outboundTag": "direct"}),
            );
        }
        rules.extend(bypass(tag));
        let start = rules.len();
        if is_v2(intent) {
            rules.extend(lane_rules(tag, intent, input.lanes.get(*tag).unwrap_or(&no_accounts), &chain_tags)?);
        } else {
            rules.extend(strings(&intent["rules"]).map(|r| rule(tag, r, None, &HashMap::new())));
            let action = intent["default"]["action"].as_str().unwrap_or("");
            rules.push(json!({"inboundTag": [tag], "outboundTag": outbound_for(action)}));
        }
        if TUN_SERVICES.contains(tag) {
            // The tunnels carry UDP as much as TCP: their `warp` is the WireGuard outbound.
            for rule in &mut rules[start..] {
                if rule.get("outboundTag").and_then(Value::as_str) == Some("warp") {
                    rule["outboundTag"] = json!(WARP_WG_TAG);
                }
            }
        }
    }
    if input.relay.is_some() {
        rules.extend(bypass(RELAY_TAG));
        if !relay_warp.is_empty() {
            rules.push(json!({"inboundTag": [RELAY_TAG], "user": relay_warp, "outboundTag": "warp"}));
        }
        rules.push(json!({"inboundTag": [RELAY_TAG], "outboundTag": "direct"}));
    }
    Ok(json!({
        "log": {"access": "none", "loglevel": "warning"},
        "dns": {"servers": ["localhost"]},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPOnDemand", "rules": rules},
    }))
}

/// The bytes a generation file carries: `json.dumps(sort_keys=True, separators=(",", ":"))` and
/// a newline.
pub fn config_bytes(config: &Value) -> Vec<u8> {
    let mut bytes = pyjson::dumps(config, &pyjson::SORTED).into_bytes();
    bytes.push(b'\n');
    bytes
}

/// SHA-256 of the exact bytes the generation file carries (credentials included: the digest
/// names what Xray runs).
pub fn generation_digest(config: &Value) -> String {
    sha256_hex(&config_bytes(config))
}

/// The config with every secret masked — ingress accounts, relay clients and the Reality private
/// key, chain hop credentials, the WARP key — what may reach a log or an error.
#[cfg(test)]
pub fn redact(config: &Value) -> Value {
    let mut masked = config.clone();
    for inbound in masked.get_mut("inbounds").and_then(Value::as_array_mut).into_iter().flatten() {
        if let Some(settings) = inbound.get_mut("settings") {
            for account in settings.get_mut("accounts").and_then(Value::as_array_mut).into_iter().flatten() {
                account["user"] = json!("***");
                account["pass"] = json!("***");
            }
            for client in settings.get_mut("clients").and_then(Value::as_array_mut).into_iter().flatten() {
                client["id"] = json!("***");
            }
        }
        let reality = inbound.get_mut("streamSettings").and_then(|s| s.get_mut("realitySettings"));
        if let Some(reality) = reality.and_then(Value::as_object_mut) {
            if reality.contains_key("privateKey") {
                reality.insert("privateKey".into(), json!("***"));
            }
        }
    }
    for outbound in masked.get_mut("outbounds").and_then(Value::as_array_mut).into_iter().flatten() {
        if let Some(settings) = outbound.get_mut("settings").and_then(Value::as_object_mut) {
            if settings.contains_key("secretKey") {
                settings.insert("secretKey".into(), json!("***"));
            }
            for server in settings.get_mut("vnext").and_then(Value::as_array_mut).into_iter().flatten() {
                for user in server.get_mut("users").and_then(Value::as_array_mut).into_iter().flatten() {
                    user["id"] = json!("***");
                }
            }
        }
    }
    masked
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::intent::{direct_document, tests::hop, tests::with, validate_document};

    const WARP: &str = "socks5://127.0.0.1:45000";

    pub fn ingresses() -> Vec<Ingress> {
        vec![
            Ingress::new("naive", 45101, "naive-abc", &"p".repeat(32)),
            Ingress::new("mieru", 45102, "mieru-def", &"q".repeat(32)),
        ]
    }

    fn intent(rules: Value, default: Option<Value>) -> Value {
        validate_document(&json!({"schema": 1, "default": default.unwrap_or(json!({"action": "direct", "egress": null})), "rules": rules}))
            .unwrap()
    }

    fn warp_default() -> Option<Value> {
        Some(json!({"action": "egress", "egress": "warp"}))
    }

    fn input(intents: Value, warp_url: Option<&str>) -> RenderInput<'_> {
        RenderInput {
            intents: intents.as_object().unwrap().clone(),
            ingresses: ingresses(),
            warp_url,
            ..RenderInput::default()
        }
    }

    fn tags(config: &Value, key: &str) -> Vec<String> {
        config[key].as_array().unwrap().iter().map(|item| item["tag"].as_str().unwrap().to_string()).collect()
    }

    fn rules_of(config: &Value, tag: &str) -> Vec<Value> {
        config["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["inboundTag"] == json!([tag]))
            .cloned()
            .collect()
    }

    #[test]
    fn render_is_deterministic_and_block_is_first_outbound() {
        let intents = json!({"naive": intent(json!([]), warp_default()), "mieru": direct_document()});
        let first = render_config(&input(intents.clone(), Some(WARP))).unwrap();
        let mut reversed = input(serde_json::from_str(&intents.to_string()).unwrap(), Some(WARP));
        reversed.ingresses.reverse();
        let second = render_config(&reversed).unwrap();
        assert_eq!(config_bytes(&first), config_bytes(&second));
        assert_eq!(generation_digest(&first), generation_digest(&second));
        assert_eq!(tags(&first, "outbounds"), ["block", "direct", "warp"]);
        assert_eq!(first["outbounds"][1]["settings"], json!({"domainStrategy": "UseIP"}));
        assert_eq!(
            first["outbounds"][2],
            json!({"tag": "warp", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": 45000}]}})
        );
        assert_eq!(first["routing"]["domainStrategy"], "IPOnDemand");
        assert_eq!(first["dns"], json!({"servers": ["localhost"]}));
        assert_eq!(first["log"], json!({"access": "none", "loglevel": "warning"}));
        assert!(first.get("api").is_none() && first.get("stats").is_none());
    }

    #[test]
    fn render_bypass_private_precedes_every_rule_per_tag() {
        let intents = json!({"naive": intent(json!([{"domains": ["example.com"], "action": "block"}]), warp_default()),
                             "mieru": intent(json!([{"geoips": ["cn"], "action": "direct"}]), None)});
        let config = render_config(&input(intents, Some(WARP))).unwrap();
        let naive = rules_of(&config, "naive");
        let mieru = rules_of(&config, "mieru");
        assert_eq!(naive[0], json!({"inboundTag": ["naive"], "ip": ["geoip:private"], "outboundTag": "block"}));
        assert_eq!(
            naive[1],
            json!({"inboundTag": ["naive"], "domain": ["domain:localhost", "full:localhost"], "outboundTag": "block"})
        );
        assert_eq!(
            naive[2],
            json!({"inboundTag": ["naive"], "domain": ["domain:example.com"], "outboundTag": "block"})
        );
        assert_eq!(naive.last().unwrap(), &json!({"inboundTag": ["naive"], "outboundTag": "warp"}));
        assert_eq!((&mieru[0]["ip"], &mieru[2]["ip"]), (&json!(["geoip:private"]), &json!(["geoip:cn"])));
        assert_eq!(mieru.last().unwrap()["outboundTag"], "direct");
        assert!(config["routing"]["rules"].as_array().unwrap().iter().all(|r| r.get("inboundTag").is_some()));
    }

    #[test]
    fn render_rule_matchers_domain_geosite_cidr_geoip_port() {
        let rule = json!({"domains": ["*.example.com", "exact.example"], "geosites": ["category-ads-all"], "cidrs": ["10.0.0.0/8"],
                          "geoips": ["cloudflare"], "ports": [80, "1000-2000"], "action": "egress", "egress": "warp"});
        let config = render_config(&input(json!({"naive": intent(json!([rule]), None)}), Some(WARP))).unwrap();
        assert_eq!(
            config["routing"]["rules"][2],
            json!({"inboundTag": ["naive"], "domain": ["domain:example.com", "domain:exact.example", "geosite:category-ads-all"],
                   "ip": ["10.0.0.0/8", "geoip:cloudflare"], "port": "80,1000-2000", "outboundTag": "warp"})
        );
    }

    #[test]
    fn render_default_egress_warp_needs_warp_url() {
        let intents = json!({"naive": intent(json!([]), warp_default())});
        let missing = render_config(&input(intents.clone(), None)).unwrap_err();
        assert!(missing.to_string().contains("warp"));
        assert!(matches!(
            render_config(&input(intents, Some("http://127.0.0.1:8118"))),
            Err(Error::EgressInvalid { .. })
        ));
    }

    #[test]
    fn render_omits_warp_outbound_when_unused() {
        let config =
            render_config(&input(json!({"naive": direct_document(), "mieru": direct_document()}), Some(WARP))).unwrap();
        assert_eq!(tags(&config, "outbounds"), ["block", "direct"]);
        let config = render_config(&input(json!({}), None)).unwrap();
        let catch_alls: Vec<&Value> = config["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r.get("ip").is_none() && r.get("domain").is_none())
            .map(|r| &r["outboundTag"])
            .collect();
        assert_eq!(catch_alls, [&json!("direct"), &json!("direct")]);
    }

    #[test]
    fn render_inbounds_have_password_auth_no_udp_and_sniffing_route_only() {
        let mut render = input(json!({}), None);
        render.ports = Some([("naive".to_string(), 1), ("mieru".to_string(), 2)].into());
        let config = render_config(&render).unwrap();
        let (naive, mieru) = (&config["inbounds"][0], &config["inbounds"][1]);
        assert_eq!(
            (&naive["tag"], &naive["listen"], &naive["port"], &naive["protocol"]),
            (&json!("naive"), &json!("127.0.0.1"), &json!(1), &json!("socks"))
        );
        assert_eq!(
            naive["settings"],
            json!({"auth": "password", "accounts": [{"user": "naive-abc", "pass": "p".repeat(32)}], "udp": false})
        );
        assert_eq!(
            naive["sniffing"],
            json!({"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true})
        );
        assert_eq!(
            (&mieru["port"], &mieru["settings"]["accounts"]),
            (&json!(2), &json!([{"user": "mieru-def", "pass": "q".repeat(32)}]))
        );
    }

    #[test]
    fn generation_digest_changes_with_credentials_and_redact_hides_accounts() {
        let plain = render_config(&input(json!({}), None)).unwrap();
        let mut rotated = input(json!({}), None);
        rotated.ingresses[0].password = "r".repeat(32);
        assert_ne!(generation_digest(&plain), generation_digest(&render_config(&rotated).unwrap()));
        let masked = pyjson::dumps(&redact(&plain), &pyjson::DEFAULT);
        assert!(
            !masked.contains(&"p".repeat(32)) && !masked.contains("naive-abc") && masked.contains("\"user\": \"***\"")
        );
        assert!(plain.to_string().contains(&"p".repeat(32)));
    }

    fn lanes() -> BTreeMap<String, Vec<LaneAccount>> {
        [(
            "naive".to_string(),
            vec![LaneAccount { lane: "grant:7f3a".into(), user: json!("grant-7f3a"), password: json!("x".repeat(32)) }],
        )]
        .into()
    }

    fn v2(lanes: Value, chains: Value) -> Value {
        validate_document(&json!({"schema": 2, "lanes": lanes, "chains": chains})).unwrap()
    }

    fn hop_c() -> Value {
        with(
            &hop(),
            json!({"guid": "c".repeat(32), "address": "203.0.113.7", "server_name": "panel.node-c.example.org",
                            "uuid": "9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e"}),
        )
    }

    #[test]
    fn render_lanes_are_accounts_on_the_service_ingress_and_rules_carry_the_user() {
        let intent = v2(
            json!({"grant:7f3a": {"default": {"action": "egress", "egress": "warp"},
                                  "rules": [{"geosites": ["category-ads-all"], "action": "block"}, {"geoips": ["ru"], "action": "direct"}]},
                   "svc:naive": {"default": {"action": "direct", "egress": null}, "rules": [{"domains": ["example.com"], "action": "block"}]}}),
            json!({}),
        );
        let mut render = input(json!({"naive": intent}), Some(WARP));
        render.lanes = lanes();
        let config = render_config(&render).unwrap();
        assert_eq!(
            config["inbounds"][0]["settings"]["accounts"],
            json!([{"user": "naive-abc", "pass": "p".repeat(32)}, {"user": "grant-7f3a", "pass": "x".repeat(32)}])
        );
        let rules = rules_of(&config, "naive");
        assert!(
            rules[0]["ip"] == json!(["geoip:private"])
                && rules[0].get("user").is_none()
                && rules[1].get("user").is_none()
        );
        assert_eq!(
            rules[2],
            json!({"inboundTag": ["naive"], "user": ["grant-7f3a"], "domain": ["geosite:category-ads-all"], "outboundTag": "block"})
        );
        assert_eq!(
            rules[3],
            json!({"inboundTag": ["naive"], "user": ["grant-7f3a"], "ip": ["geoip:ru"], "outboundTag": "direct"})
        );
        assert_eq!(rules[4], json!({"inboundTag": ["naive"], "user": ["grant-7f3a"], "outboundTag": "warp"}));
        assert_eq!(
            rules[5],
            json!({"inboundTag": ["naive"], "domain": ["domain:example.com"], "outboundTag": "block"})
        );
        assert_eq!(rules[6], json!({"inboundTag": ["naive"], "outboundTag": "direct"}));
        assert_eq!(rules.len(), 7);
        render.lanes = BTreeMap::new();
        assert!(render_config(&render).unwrap_err().to_string().contains("lane"));
    }

    #[test]
    fn render_chain_is_a_vless_reality_outbound_per_hop_dialled_through_the_previous() {
        let intent = v2(
            json!({"svc:naive": {"default": {"action": "egress", "egress": "chain:c1"},
                                 "rules": [{"domains": ["a.example"], "action": "egress", "egress": "chain:c2"}]}}),
            json!({"c1": {"hops": [hop()], "exit": "warp"}, "c2": {"hops": [hop(), hop_c()], "exit": "direct"}}),
        );
        let config = render_config(&input(json!({"naive": intent}), None)).unwrap();
        assert_eq!(
            tags(&config, "outbounds"),
            ["block", "direct", "chain:naive:c1:1", "chain:naive:c2:1", "chain:naive:c2:2"]
        );
        let first = &config["outbounds"][2];
        assert_eq!(first["protocol"], "vless");
        assert_eq!(
            first["settings"]["vnext"],
            json!([{"address": "panel.node-b.example.org", "port": 45443, "users": [{"id": hop()["uuid"], "encryption": "none", "flow": ""}]}])
        );
        assert_eq!(
            first["streamSettings"],
            json!({"network": "tcp", "security": "reality", "realitySettings": {
                "serverName": "panel.node-b.example.org", "fingerprint": "chrome", "publicKey": hop()["public_key"], "shortId": "0123abcd"}})
        );
        assert!(first.get("proxySettings").is_none());
        let second_hop = &config["outbounds"][4];
        assert_eq!(second_hop["proxySettings"], json!({"tag": "chain:naive:c2:1"}));
        assert_eq!(second_hop["settings"]["vnext"][0]["address"], "203.0.113.7");
        let rules = rules_of(&config, "naive");
        assert_eq!(
            (&rules[2]["outboundTag"], &rules.last().unwrap()["outboundTag"]),
            (&json!("chain:naive:c2:2"), &json!("chain:naive:c1:1"))
        );
        assert!(!tags(&config, "outbounds").contains(&"warp".to_string()));
    }

    fn relay(accounts: Vec<(String, Value)>) -> Relay {
        Relay {
            port: json!(45443),
            server_name: json!("panel.node-a.example.org"),
            private_key: json!("k".repeat(43)),
            short_ids: vec![json!("0123abcd")],
            accounts,
        }
    }

    #[test]
    fn render_relay_inbound_and_its_rules() {
        let b = "b".repeat(32);
        let accounts = vec![
            (format!("relay:{b}:direct"), hop()["uuid"].clone()),
            (format!("relay:{b}:warp"), hop_c()["uuid"].clone()),
        ];
        let mut render = input(json!({}), Some(WARP));
        render.relay = Some(relay(accounts));
        let config = render_config(&render).unwrap();
        let inbound = &config["inbounds"][2];
        assert_eq!(
            (&inbound["tag"], &inbound["listen"], &inbound["port"], &inbound["protocol"]),
            (&json!("relay"), &json!("0.0.0.0"), &json!(45443), &json!("vless"))
        );
        assert_eq!(
            inbound["settings"],
            json!({"clients": [{"id": hop()["uuid"], "email": format!("relay:{b}:direct"), "flow": ""},
                               {"id": hop_c()["uuid"], "email": format!("relay:{b}:warp"), "flow": ""}], "decryption": "none"})
        );
        assert_eq!(
            inbound["streamSettings"],
            json!({"network": "tcp", "security": "reality", "realitySettings": {
                "dest": "127.0.0.1:8443", "serverNames": ["panel.node-a.example.org"], "privateKey": "k".repeat(43), "shortIds": ["0123abcd"]}})
        );
        assert_eq!(
            inbound["sniffing"],
            json!({"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true})
        );
        let rules = rules_of(&config, "relay");
        assert_eq!(rules[0], json!({"inboundTag": ["relay"], "ip": ["geoip:private"], "outboundTag": "block"}));
        assert_eq!(rules[1]["domain"], json!(["domain:localhost", "full:localhost"]));
        assert_eq!(
            rules[2],
            json!({"inboundTag": ["relay"], "user": [format!("relay:{b}:warp")], "outboundTag": "warp"})
        );
        assert_eq!(rules[3], json!({"inboundTag": ["relay"], "outboundTag": "direct"}));
        assert_eq!(tags(&config, "outbounds"), ["block", "direct", "warp"]);
        render.warp_url = None;
        assert!(render_config(&render).unwrap_err().to_string().contains("warp"));
        render.relay = Some(relay(vec![]));
        assert_eq!(render_config(&render).unwrap()["inbounds"][2]["settings"]["clients"], json!([]));
    }

    #[test]
    fn render_schema_1_bytes_are_unchanged_by_the_new_parameters() {
        let intents = json!({"naive": intent(json!([]), warp_default()), "mieru": direct_document()});
        let before = config_bytes(&render_config(&input(intents.clone(), Some(WARP))).unwrap());
        let mut with_empty = input(intents, Some(WARP));
        with_empty.lanes = BTreeMap::new();
        with_empty.relay = None;
        assert_eq!(before, config_bytes(&render_config(&with_empty).unwrap()));
    }

    #[test]
    fn redact_masks_relay_and_chain_secrets_too() {
        let intent = v2(
            json!({"svc:naive": {"default": {"action": "egress", "egress": "chain:c1"}, "rules": []}}),
            json!({"c1": {"hops": [hop()], "exit": "direct"}}),
        );
        let mut render = input(json!({"naive": intent}), None);
        render.lanes = lanes();
        render.relay = Some(relay(vec![("relay:x:direct".into(), hop_c()["uuid"].clone())]));
        let masked = pyjson::dumps(&redact(&render_config(&render).unwrap()), &pyjson::DEFAULT);
        for secret in [
            hop()["uuid"].as_str().unwrap().to_string(),
            hop_c()["uuid"].as_str().unwrap().to_string(),
            "k".repeat(43),
            "x".repeat(32),
            "grant-7f3a".into(),
        ] {
            assert!(!masked.contains(&secret), "{secret}");
        }
        assert!(masked.contains(hop()["public_key"].as_str().unwrap()) && masked.contains("panel.node-a.example.org"));
    }

    const GOLDEN: &str = include_str!("../testdata/render.json");

    /// Every scenario of the golden set renders to the bytes (and digest) Python 3.13 wrote, or
    /// fails the same way.
    #[test]
    fn golden_render_matches_the_python_bytes() {
        let golden: Vec<Value> = serde_json::from_str(GOLDEN).unwrap();
        for scenario in &golden {
            let name = scenario["name"].as_str().unwrap();
            let intents: Map<String, Value> = scenario["intents"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(tag, document)| (tag.clone(), validate_document(document).unwrap()))
                .collect();
            let ingresses = scenario["ingresses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| Ingress {
                    tag: item["tag"].as_str().unwrap().into(),
                    port: item["port"].as_i64().unwrap(),
                    user: item["user"].as_str().unwrap().into(),
                    password: item["password"].as_str().unwrap().into(),
                    socket: item.get("socket").and_then(Value::as_str).map(str::to_string),
                    uuid: item.get("uuid").and_then(Value::as_str).map(str::to_string),
                    tun: item.get("tun").and_then(Value::as_str).map(str::to_string),
                })
                .collect();
            let lanes = scenario
                .get("lanes")
                .and_then(Value::as_object)
                .map(|lanes| {
                    lanes
                        .iter()
                        .map(|(tag, items)| {
                            let accounts = items
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|a| LaneAccount {
                                    lane: a[0].as_str().unwrap().into(),
                                    user: a[1].clone(),
                                    password: a[2].clone(),
                                })
                                .collect();
                            (tag.clone(), accounts)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let relay = scenario.get("relay").filter(|r| !r.is_null()).map(|r| Relay {
                port: r["port"].clone(),
                server_name: r["server_name"].clone(),
                private_key: r["private_key"].clone(),
                short_ids: r["short_ids"].as_array().unwrap().clone(),
                accounts: r["accounts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| (a[0].as_str().unwrap().into(), a[1].clone()))
                    .collect(),
            });
            let ports = scenario
                .get("ports")
                .and_then(Value::as_object)
                .map(|ports| ports.iter().map(|(tag, port)| (tag.clone(), port.as_i64().unwrap())).collect());
            let render = RenderInput {
                intents,
                ingresses,
                warp_url: scenario["warp_url"].as_str(),
                ports,
                lanes,
                relay,
                warp_wg: scenario.get("warp_wg").filter(|w| !w.is_null()).cloned(),
            };
            match (render_config(&render), scenario.get("ok")) {
                (Ok(config), Some(expected)) => {
                    assert_eq!(
                        String::from_utf8(config_bytes(&config)).unwrap(),
                        expected["bytes"].as_str().unwrap(),
                        "{name}"
                    );
                    assert_eq!(generation_digest(&config), expected["digest"].as_str().unwrap(), "{name}");
                    let redacted = String::from_utf8(config_bytes(&redact(&config))).unwrap();
                    assert_eq!(redacted, expected["redacted"].as_str().unwrap(), "{name}");
                }
                (Err(Error::EgressInvalid { message, code }), None) => {
                    assert_eq!(message, scenario["error"].as_str().unwrap(), "{name}");
                    assert_eq!(code, scenario["code"].as_str().unwrap(), "{name}");
                }
                (other, _) => panic!("{name}: {other:?}"),
            }
        }
    }
}
