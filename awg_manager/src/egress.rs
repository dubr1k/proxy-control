//! Where AmneziaWG clients' traffic leaves the node (v3.0.0): directly, or through WARP.
//!
//! The panel sends the compiled document `{"schema": 1, "upstream": {"provider": "warp"} | null}`, in
//! the same vocabulary as the NaiveProxy and Mieru managers (`GET /v1/egress`, plan, apply, rollback).
//! Through WARP, the manager runs one more amneziawg-go device, `awgwarp`, as a plain WireGuard client
//! of a WARP account of its own (`warp.rs`), and steers every AmneziaWG subnet into it by source:
//!
//! ```text
//! ip rule  from <subnet> lookup 51870 priority 5150      (one per enabled version)
//! table 51870: default dev awgwarp · blackhole default (metric 1024) · throw <private ranges>
//! ```
//!
//! The blackhole keeps the egress fail-closed: while the tunnel is down, client traffic is dropped,
//! never sent from the server's own address. Private, CGNAT and link-local destinations are thrown
//! back to the main table, so the server, its containers and an overlay network stay reachable. The
//! nft masquerade the manager already installs (`oifname != <awg iface>`) rewrites the source to the
//! tunnel address. TCP and UDP both go through: this is WireGuard, not a proxy.
//!
//! An apply that sets WARP waits for the tunnel's first handshake; without one it puts the previous
//! document back and fails, so a broken account never black-holes the clients.
//!
//! Through the Xray-router (`{"provider": "router"}`, variant 2): the same rules and table, the default
//! route into a persistent TUN device (`awgxr`, owned by the router's uid, 198.18.0.1/30) the manager
//! keeps; the router reads it as a `tun` inbound and routes by the panel's rules, its `warp` a
//! WireGuard outbound — TCP and UDP. An apply waits until the router reads the device (the link shows
//! LOWER_UP); while the router is down the device has no reader and the traffic is dropped, never
//! sent from the server's address.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use pc_common::ApiError;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::host::Proc;
use crate::ipnet::{ip_network, Network};
use crate::keys::{hex, hexkey};
use crate::service::{backoff, is_operation_id, AwgManager, Inner};
use crate::state::StateError;
use crate::util::parse_int;

pub const SCHEMA: i64 = 1;
pub const IFACE: &str = "awgwarp";
pub const TABLE: &str = "51870";
pub const PRIORITY: &str = "5150";
pub const BLACKHOLE_METRIC: &str = "1024";
pub const MTU: u32 = 1280;
pub const KEEPALIVE: u32 = 25;
pub const HANDSHAKE_FRESH: f64 = 180.0;
pub const HANDSHAKE_WAIT: f64 = 12.0;
pub const NETWORK_RECHECK: f64 = 30.0;
pub const MAX_HISTORY: usize = 10;
pub const CAPABILITIES: [&str; 2] = ["whole_direct", "whole_warp"];
pub const THROWN: [&str; 7] =
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4"];
pub const PROVIDERS: [&str; 2] = ["warp", "router"];
pub const ROUTER_ADDRESS: &str = "198.18.0.1/30";

pub fn direct() -> Value {
    json!({"schema": SCHEMA, "upstream": null})
}

fn egress_error(status: u16, code: &str, detail: &str) -> ApiError {
    ApiError::new(status, code, detail)
}

pub fn validate_document(document: &Value) -> Result<Value, ApiError> {
    let shape_ok = document.as_object().is_some_and(|doc| {
        doc.len() == 2
            && doc.contains_key("upstream")
            && doc.get("schema").and_then(Value::as_f64) == Some(SCHEMA as f64)
    });
    if !shape_ok {
        return Err(egress_error(422, "egress_invalid", "egress document must be {schema: 1, upstream}"));
    }
    let upstream = &document["upstream"];
    if upstream.is_null() {
        return Ok(direct());
    }
    let provider = upstream.as_object().filter(|up| up.len() == 1).and_then(|up| up.get("provider"));
    match provider.and_then(Value::as_str) {
        Some(provider) if PROVIDERS.contains(&provider) => {
            Ok(json!({"schema": SCHEMA, "upstream": {"provider": provider}}))
        }
        _ => Err(egress_error(422, "egress_invalid", "AmneziaWG's upstream is warp or router")),
    }
}

pub fn document_digest(document: &Value) -> String {
    hex(&Sha256::digest(crate::pyjson::canonical(document).as_bytes()))
}

/// The in-memory side of the egress: the `awgwarp` process and the data plane's bookkeeping.
pub struct Egress {
    pub proc: Option<Box<dyn Proc>>,
    pub configured: bool,
    pub failures: u32,
    pub next_start: f64,
    pub started_at: f64,
    pub last_network: f64,
    pub network_ok: bool,
}

impl Default for Egress {
    fn default() -> Self {
        Self {
            proc: None,
            configured: false,
            failures: 0,
            next_start: 0.0,
            started_at: 0.0,
            last_network: -NETWORK_RECHECK,
            network_ok: false,
        }
    }
}

/// The `egress` section of the state, created on first use.
fn section(inner: &mut Inner) -> &mut Map<String, Value> {
    let doc = inner.store.doc.as_object_mut().expect("a loaded document is an object");
    if !doc.get("egress").is_some_and(Value::is_object) {
        doc.insert("egress".into(), json!({"revision": 0, "history": [], "warp": null}));
    }
    doc["egress"].as_object_mut().expect("just made an object")
}

fn history(inner: &mut Inner) -> Vec<Value> {
    section(inner).get("history").and_then(Value::as_array).cloned().unwrap_or_default()
}

fn account(inner: &mut Inner) -> Option<Map<String, Value>> {
    section(inner).get("warp").and_then(Value::as_object).cloned()
}

fn document(inner: &mut Inner) -> Value {
    history(inner).last().map(|entry| entry["document"].clone()).unwrap_or_else(direct)
}

fn provider(inner: &mut Inner) -> Option<String> {
    document(inner)["upstream"].get("provider").and_then(Value::as_str).map(String::from)
}

fn wants_warp(inner: &mut Inner) -> bool {
    provider(inner).as_deref() == Some("warp")
}

fn revision(inner: &mut Inner) -> String {
    match section(inner).get("revision") {
        Some(Value::Number(number)) => number.to_string(),
        other => other.map(Value::to_string).unwrap_or_default(),
    }
}

fn bump_revision(inner: &mut Inner, by: i64) {
    let section = section(inner);
    let next = section.get("revision").and_then(Value::as_i64).unwrap_or(0) + by;
    section.insert("revision".into(), json!(next));
}

fn check_revision(inner: &mut Inner, expected: &Value) -> Result<(), ApiError> {
    if expected.as_str() != Some(revision(inner).as_str()) {
        return Err(egress_error(409, "egress_conflict", "the egress revision changed"));
    }
    Ok(())
}

fn fresh(stats: &Map<String, Value>, wall: f64) -> bool {
    let handshake = stats.get("last_handshake_time_sec").and_then(Value::as_i64).unwrap_or(0);
    handshake != 0 && wall - handshake as f64 <= HANDSHAKE_FRESH
}

/// The difflib lines of the plan: `json.dumps(…, indent=1, sort_keys=True)` of both documents.
fn plan_diff(before: &Value, after: &Value) -> Vec<String> {
    let lines = |value: &Value| crate::pyjson::state(value).lines().map(String::from).collect::<Vec<_>>();
    crate::difflib::changed_lines(&lines(before), &lines(after))
}

impl AwgManager {
    // ----- state ---------------------------------------------------------------------

    pub(crate) fn egress_load(&self, inner: &mut Inner) -> Result<(), StateError> {
        if inner.store.doc.get("egress").is_some_and(|section| !section.is_object()) {
            return Err(StateError("stored egress section is malformed".into()));
        }
        let section = section(inner);
        let revision_ok = section.get("revision").is_some_and(|r| r.is_i64() || r.is_u64());
        let history_ok = section.get("history").is_some_and(Value::is_array);
        let warp_ok = match section.get("warp") {
            None | Some(Value::Null) => true,
            Some(account) => crate::warp::valid_account(account),
        };
        if !(revision_ok && history_ok && warp_ok) {
            return Err(StateError("stored egress section is malformed".into()));
        }
        for entry in section["history"].as_array().expect("checked") {
            if validate_document(entry.get("document").unwrap_or(&Value::Null)).is_err() {
                return Err(StateError("stored egress history is malformed".into()));
            }
        }
        Ok(())
    }

    // ----- the router's device (variant 2) -----------------------------------------------

    /// The router device's link flags, or None when it does not exist.
    fn router_flags(&self) -> Option<Vec<String>> {
        let tun = self.config.router_tun.as_deref()?;
        let links = self.host.ip_json(&["link", "show", "dev", tun]).ok()?;
        let first = links.first()?;
        let flags = first.get("flags").and_then(Value::as_array).cloned().unwrap_or_default();
        Some(flags.iter().filter_map(Value::as_str).map(String::from).collect())
    }

    /// The router reads the device: a TUN with a reader is LOWER_UP, without one NO-CARRIER.
    fn router_attached(&self) -> bool {
        self.router_flags().is_some_and(|flags| flags.iter().any(|flag| flag == "LOWER_UP"))
    }

    /// The persistent device the router opens (made once, kept across restarts of either side).
    fn ensure_router_device(&self) {
        let Some(tun) = self.config.router_tun.as_deref() else { return };
        let uid = self.config.router_uid.to_string();
        let mtu = MTU.to_string();
        let ready = (|| {
            if self.router_flags().is_none() {
                self.host.ip(&["tuntap", "add", "dev", tun, "mode", "tun", "user", &uid, "group", &uid])?;
            }
            self.host.ip(&["addr", "replace", ROUTER_ADDRESS, "dev", tun])?;
            self.host.ip(&["link", "set", tun, "mtu", &mtu, "up"])
        })();
        if let Err(err) = ready {
            // Retried on the next pass.
            log::error!("the router device {tun} is not ready: {err}");
        }
    }

    // ----- views ---------------------------------------------------------------------

    fn egress_stats(&self, inner: &mut Inner) -> Map<String, Value> {
        let mut out = Map::new();
        if inner.egress.proc.is_none() || !inner.egress.configured {
            return out;
        }
        // A wedged device reads as no stats.
        let Ok(text) = self.host.uapi_get(IFACE) else { return out };
        for line in text.lines() {
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            if matches!(key, "last_handshake_time_sec" | "rx_bytes" | "tx_bytes") {
                if let Some(number) = parse_int(value, 10) {
                    out.insert(key.to_string(), json!(number));
                }
            }
        }
        out
    }

    fn tunnel_state(&self, inner: &mut Inner) -> &'static str {
        if provider(inner).as_deref() == Some("router") {
            return if inner.egress.network_ok && self.router_attached() { "up" } else { "down" };
        }
        if !wants_warp(inner) {
            return "off";
        }
        let stats = self.egress_stats(inner);
        if inner.egress.network_ok && fresh(&stats, (self.wall)()) {
            "up"
        } else {
            "down"
        }
    }

    pub(crate) fn egress_view_locked(&self, inner: &mut Inner) -> Value {
        let document = document(inner);
        let history = history(inner);
        let account = account(inner);
        let warp = wants_warp(inner);
        let stats = if warp { self.egress_stats(inner) } else { Map::new() };
        let reachable = warp.then(|| inner.egress.network_ok && fresh(&stats, (self.wall)()));
        let mut providers = Map::new();
        providers.insert("warp".into(), json!({"reachable": reachable}));
        let mut router = Value::Null;
        if let Some(tun) = self.config.router_tun.as_deref() {
            let attached = self.router_attached();
            providers.insert("router".into(), json!({"reachable": attached}));
            router = json!({"device": tun, "present": self.router_flags().is_some(), "attached": attached});
        }
        let current = history.last().map(|last| {
            let field = |key: &str| last.get(key).cloned().unwrap_or(Value::Null);
            json!({"operation_id": field("operation_id"), "applied_at": field("applied_at"), "digest": field("digest")})
        });
        let account_field = |key: &str| account.as_ref().map(|a| a.get(key).cloned().unwrap_or(Value::Null));
        let handshake = stats.get("last_handshake_time_sec").filter(|v| v.as_i64() != Some(0)).cloned();
        json!({
            "revision": revision(inner),
            "mode": if document["upstream"].is_null() { "direct" } else { "proxy" },
            "document": document,
            "managed": !history.is_empty(),
            "providers": providers,
            "router": router,
            "capabilities": CAPABILITIES,
            "restart_required": false,
            "warnings": [],
            "current": current,
            "warp": {
                "registered": account.is_some(),
                "address": account_field("address"),
                "endpoint": account_field("endpoint"),
                "account_type": account_field("account_type"),
                "tunnel": self.tunnel_state(inner),
                "latest_handshake": handshake,
                "rx": stats.get("rx_bytes").cloned().unwrap_or(json!(0)),
                "tx": stats.get("tx_bytes").cloned().unwrap_or(json!(0)),
            },
        })
    }

    pub(crate) fn egress_health(&self, inner: &mut Inner) -> Value {
        let mode = match provider(inner).as_deref() {
            Some("router") => "router",
            Some(_) => "proxy",
            None => "direct",
        };
        json!({"mode": mode, "tunnel": self.tunnel_state(inner)})
    }

    // ----- operations ----------------------------------------------------------------

    pub(crate) fn egress_plan_locked(
        &self,
        inner: &mut Inner,
        expected: &Value,
        document_in: &Value,
    ) -> Result<Value, ApiError> {
        let target = validate_document(document_in)?;
        check_revision(inner, expected)?;
        let diff = plan_diff(&document(inner), &target);
        let mut reachability = Map::new();
        match target["upstream"].get("provider").and_then(Value::as_str) {
            Some("warp") => {
                reachability.insert("warp".into(), json!(account(inner).is_some()));
            }
            Some("router") => {
                reachability.insert("router".into(), json!(self.router_attached()));
            }
            _ => {}
        }
        Ok(json!({"revision": revision(inner), "target": target, "diff": diff, "reachability": reachability,
                  "restart_required": false, "warnings": []}))
    }

    pub(crate) fn egress_apply_locked(
        &self,
        inner: &mut Inner,
        expected: &Value,
        document_in: &Value,
        operation_id: &Value,
    ) -> Result<Value, ApiError> {
        let operation_id = match operation_id.as_str() {
            Some(op) if is_operation_id(op) => op.to_string(),
            _ => return Err(egress_error(422, "egress_invalid", "invalid operation id")),
        };
        let target = validate_document(document_in)?;
        let mut history = history(inner);
        if let Some(last) =
            history.last().filter(|last| last.get("operation_id").and_then(Value::as_str) == Some(&operation_id))
        {
            if last["document"] != target {
                return Err(egress_error(409, "egress_conflict", "operation id already used for another request"));
            }
            return Ok(json!({"revision": revision(inner), "applied": target, "replayed": true}));
        }
        check_revision(inner, expected)?;
        history.push(json!({"document": target, "digest": document_digest(&target), "operation_id": operation_id,
                            "applied_at": crate::util::iso_seconds(SystemTime::now())}));
        let keep = history.len().saturating_sub(MAX_HISTORY);
        self.egress_switch(inner, history.split_off(keep), &target)?;
        Ok(json!({"revision": revision(inner), "applied": target, "replayed": false}))
    }

    pub(crate) fn egress_rollback_locked(&self, inner: &mut Inner, expected: &Value) -> Result<Value, ApiError> {
        check_revision(inner, expected)?;
        let mut rest = history(inner);
        if rest.pop().is_none() {
            return Err(egress_error(409, "egress_no_previous", "no previous egress to roll back to"));
        }
        let target = rest.last().map(|entry| entry["document"].clone()).unwrap_or_else(direct);
        self.egress_switch(inner, rest, &target)?;
        Ok(json!({"revision": revision(inner), "applied": target, "replayed": false}))
    }

    /// Commit the new history, converge the data plane, and for WARP wait for a handshake; without
    /// one, put the previous history back and fail.
    fn egress_switch(&self, inner: &mut Inner, history: Vec<Value>, target: &Value) -> Result<(), ApiError> {
        let previous = section(inner).clone();
        let provider = target["upstream"].get("provider").and_then(Value::as_str).map(String::from);
        if provider.as_deref() == Some("router") && self.config.router_tun.is_none() {
            return Err(egress_error(422, "egress_invalid", "this node's AmneziaWG has no Xray-router device"));
        }
        if provider.as_deref() == Some("warp") && account(inner).is_none() {
            let registered =
                crate::warp::register(&self.opener).map_err(|err| egress_error(503, "egress_unreachable", &err.0))?;
            section(inner).insert("warp".into(), registered);
        }
        section(inner).insert("history".into(), Value::Array(history));
        bump_revision(inner, 1);
        self.save_egress(inner)?;
        self.egress_reset_dataplane(inner);
        self.egress_converge(inner, (self.clock)(), true).map_err(|_| ApiError::internal())?;
        let Some(provider) = provider else { return Ok(()) };
        if self.egress_await_ready(inner, &provider) {
            return Ok(());
        }
        log::error!("the {provider} egress did not come up; egress goes back to the previous document");
        // The registration stays: it may work on the next attempt.
        let account = section(inner).get("warp").cloned().unwrap_or(Value::Null);
        let section = section(inner);
        *section = previous;
        section.insert("warp".into(), account);
        bump_revision(inner, 2);
        self.save_egress(inner)?;
        self.egress_reset_dataplane(inner);
        self.egress_converge(inner, (self.clock)(), true).map_err(|_| ApiError::internal())?;
        if provider == "router" {
            return Err(egress_error(503, "egress_unreachable", "the Xray-router does not read the AmneziaWG device"));
        }
        Err(egress_error(503, "egress_unreachable", "the WARP tunnel did not complete a handshake"))
    }

    fn save_egress(&self, inner: &mut Inner) -> Result<(), ApiError> {
        inner.store.save().map_err(|err| {
            log::error!("manager operation failed: cannot write state ({err})");
            ApiError::internal()
        })
    }

    fn sleep_half_second(&self) {
        match &self.sleep {
            Some(sleep) => sleep(0.5),
            None => std::thread::sleep(Duration::from_millis(500)),
        }
    }

    /// The caller holds the manager's lock, so the supervisor cannot run meanwhile: this loop keeps
    /// converging itself (a freshly started amneziawg-go needs a moment before its control socket
    /// takes the configuration).
    fn egress_await_ready(&self, inner: &mut Inner, provider: &str) -> bool {
        let mut waited = 0.0;
        while waited <= HANDSHAKE_WAIT {
            if let Err(err) = self.egress_converge(inner, (self.clock)(), false) {
                log::error!("egress supervision failed: {err}");
            }
            let ready = if provider == "warp" {
                let stats = self.egress_stats(inner);
                fresh(&stats, (self.wall)())
            } else {
                inner.egress.network_ok && self.router_attached()
            };
            if ready {
                return true;
            }
            self.sleep_half_second();
            waited += 0.5;
        }
        false
    }

    // ----- data plane ----------------------------------------------------------------

    /// Forget what was configured so the next converge sets the device and network again.
    fn egress_reset_dataplane(&self, inner: &mut Inner) {
        inner.egress.configured = false;
        inner.egress.last_network = -NETWORK_RECHECK;
    }

    pub(crate) fn egress_converge(&self, inner: &mut Inner, now: f64, force: bool) -> Result<(), String> {
        let account = account(inner);
        let provider = provider(inner);
        let recheck = now - inner.egress.last_network >= NETWORK_RECHECK;
        if self.config.router_tun.is_some()
            && (force || recheck || (provider.as_deref() == Some("router") && !inner.egress.network_ok))
        {
            self.ensure_router_device();
        }
        if provider.as_deref() == Some("router") {
            self.egress_stop_process(inner);
            let recheck = now - inner.egress.last_network >= NETWORK_RECHECK;
            if force || !inner.egress.network_ok || recheck {
                let device = self.config.router_tun.clone();
                self.egress_network(inner, now, device.as_deref());
            }
            return Ok(());
        }
        let Some(account) = account.filter(|_| provider.as_deref() == Some("warp")) else {
            // Cheap when already direct: a full sweep (stale rules after a crash) every 30 s.
            if force || inner.egress.proc.is_some() || now - inner.egress.last_network >= NETWORK_RECHECK {
                self.egress_teardown(inner);
                inner.egress.last_network = now;
            }
            return Ok(());
        };
        self.egress_supervise(inner, &account, now)?;
        if force || !inner.egress.network_ok || now - inner.egress.last_network >= NETWORK_RECHECK {
            self.egress_network(inner, now, None);
        }
        Ok(())
    }

    fn egress_supervise(&self, inner: &mut Inner, account: &Map<String, Value>, now: f64) -> Result<(), String> {
        let egress = &mut inner.egress;
        if let Some(code) = egress.proc.as_mut().and_then(|proc| proc.poll()) {
            log::warn!("{IFACE} exited with {code}");
            egress.proc = None;
            egress.configured = false;
            egress.failures += 1;
            egress.next_start = now + backoff(egress.failures);
        }
        if egress.proc.is_none() {
            if now < egress.next_start {
                return Ok(());
            }
            match self.host.start_process(IFACE, &self.config.log_level) {
                Err(err) => {
                    egress.failures += 1;
                    egress.next_start = now + backoff(egress.failures);
                    log::error!("cannot start {IFACE}: {err}");
                    return Ok(());
                }
                Ok(proc) => {
                    egress.proc = Some(proc);
                    egress.started_at = now;
                    egress.configured = false;
                }
            }
        }
        if egress.configured {
            return Ok(());
        }
        let text = |key: &str| account.get(key).and_then(Value::as_str).unwrap_or("");
        let private = hexkey(text("private_key")).map_err(|err| err.to_string())?;
        let peer = hexkey(text("peer_public_key")).map_err(|err| err.to_string())?;
        let lines = [
            format!("private_key={private}"),
            "replace_peers=true".to_string(),
            format!("public_key={peer}"),
            format!("endpoint={}", text("endpoint")),
            format!("persistent_keepalive_interval={KEEPALIVE}"),
            "replace_allowed_ips=true".to_string(),
            "allowed_ip=0.0.0.0/0".to_string(),
        ];
        let address = format!("{}/32", text("address"));
        let mtu = MTU.to_string();
        let configured = self
            .host
            .uapi_set(IFACE, &(lines.join("\n") + "\n"))
            .map_err(|err| err.0)
            .and_then(|()| self.host.ip(&["addr", "replace", &address, "dev", IFACE]).map_err(|err| err.0))
            .and_then(|()| self.host.ip(&["link", "set", IFACE, "mtu", &mtu, "up"]).map_err(|err| err.0));
        if let Err(err) = configured {
            // Not ready yet: the next tick tries again.
            log::warn!("{IFACE} not configured yet: {err}");
            if now - egress.started_at > 10.0 {
                if let Some(proc) = egress.proc.as_mut() {
                    proc.kill();
                }
            }
            return Ok(());
        }
        egress.configured = true;
        egress.failures = 0;
        egress.last_network = -NETWORK_RECHECK;
        Ok(())
    }

    fn subnets(inner: &Inner) -> BTreeSet<String> {
        inner.instances.iter().map(|inst| inst.subnet.to_string()).collect()
    }

    /// Sources that already have our rule (in our table at our priority).
    fn rules(&self) -> Result<BTreeSet<String>, String> {
        let mut found = BTreeSet::new();
        for rule in self.host.ip_json(&["-4", "rule", "show", "table", TABLE]).map_err(|err| err.0)? {
            let priority = match rule.get("priority") {
                Some(Value::String(text)) => text.clone(),
                Some(other) => other.to_string(),
                None => "None".into(),
            };
            let Some(src) = rule.get("src") else { continue };
            if priority != PRIORITY {
                continue;
            }
            let src = match src {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            let length = match rule.get("srclen") {
                None => "32".to_string(),
                Some(Value::String(text)) => text.clone(),
                Some(other) => other.to_string(),
            };
            match ip_network(&format!("{src}/{length}"), false) {
                Some(Network::V4(net)) => {
                    found.insert(net.to_string());
                }
                _ => return Err(format!("'{src}/{length}' does not appear to be an IPv4 network")),
            }
        }
        Ok(found)
    }

    fn egress_network(&self, inner: &mut Inner, now: f64, device: Option<&str>) {
        let device = device.unwrap_or(IFACE);
        let routed = device != IFACE || inner.egress.configured;
        inner.egress.last_network = now;
        let want = Self::subnets(inner);
        let applied = (|| -> Result<(), String> {
            let ip = |args: &[&str]| self.host.ip(args).map_err(|err| err.0);
            // The blackhole first: from here on nothing in the table can fall through to a leak.
            ip(&["route", "replace", "blackhole", "default", "table", TABLE, "metric", BLACKHOLE_METRIC])?;
            for net in THROWN {
                ip(&["route", "replace", "throw", net, "table", TABLE])?;
            }
            if routed {
                ip(&["route", "replace", "default", "dev", device, "table", TABLE])?;
            }
            let have = self.rules()?;
            for source in want.difference(&have) {
                ip(&["rule", "add", "from", source, "lookup", TABLE, "priority", PRIORITY])?;
            }
            for source in have.difference(&want) {
                ip(&["rule", "del", "from", source, "lookup", TABLE, "priority", PRIORITY])?;
            }
            Ok(())
        })();
        match applied {
            Ok(()) => inner.egress.network_ok = routed,
            Err(err) => {
                // Retried on the next pass.
                log::error!("WARP egress routing not applied: {err}");
                inner.egress.network_ok = false;
                inner.egress.last_network = -NETWORK_RECHECK;
            }
        }
    }

    /// Back to direct: rules out, table flushed, the tunnel stopped. Idempotent.
    pub(crate) fn egress_teardown(&self, inner: &mut Inner) {
        let removed = self.rules().and_then(|rules| {
            for source in rules {
                self.host
                    .ip(&["rule", "del", "from", &source, "lookup", TABLE, "priority", PRIORITY])
                    .map_err(|err| err.0)?;
            }
            Ok(())
        });
        if let Err(err) = removed {
            log::error!("cannot remove the WARP egress rules: {err}");
        }
        // An empty table answers with an error on some kernels.
        let _ = self.host.ip(&["route", "flush", "table", TABLE]);
        self.egress_stop_process(inner);
        inner.egress.network_ok = false;
    }

    fn egress_stop_process(&self, inner: &mut Inner) {
        if let Some(mut proc) = inner.egress.proc.take() {
            proc.terminate();
            if proc.wait(Duration::from_secs(5)).is_err() {
                proc.kill();
            }
        }
        inner.egress.configured = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_is_direct_warp_or_router_and_nothing_else() {
        let warp = json!({"schema": 1, "upstream": {"provider": "warp"}});
        assert_eq!(validate_document(&direct()).unwrap(), direct());
        assert_eq!(validate_document(&warp).unwrap(), warp);
        let router = validate_document(&json!({"schema": 1, "upstream": {"provider": "router"}})).unwrap();
        assert_eq!(router["upstream"], json!({"provider": "router"}));
        for bad in [
            json!({}),
            json!({"schema": 2, "upstream": null}),
            json!({"schema": 1, "upstream": {"provider": "socks"}}),
            json!({"schema": 1, "upstream": null, "acl": []}),
            json!({"schema": 1, "upstream": {"provider": "warp", "x": 1}}),
            Value::Null,
        ] {
            assert_eq!(validate_document(&bad).unwrap_err().code, "egress_invalid", "{bad}");
        }
    }

    #[test]
    fn digests_match_the_python_manager() {
        // From a live node's history, written by the Python manager.
        assert_eq!(document_digest(&direct()), "35c19df74c30d320cca413219c4582401b11a8cf848a51a3b09143d61f0772ab");
        assert_eq!(
            document_digest(&json!({"schema": 1, "upstream": {"provider": "warp"}})),
            "664488495d35f2e19b2ae6d5c7b3de92e163954ab1909121c66f595e5e018851"
        );
        assert_eq!(
            document_digest(&json!({"schema": 1, "upstream": {"provider": "router"}})),
            "913cfc1470f2796812f7f0ca78453d63714787aa2ef716cd6ccf4a583cb6934b"
        );
    }
}
