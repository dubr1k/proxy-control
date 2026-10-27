//! The Xray-router manager: one supervised Xray process, generations, a journal per service.
//!
//! Every change goes the same way (spec §5): validate the intent → render generation n+1 from the
//! intents of *all* services → `xray run -test` → stop the running process → start the new one →
//! wait until the ingresses accept → commit `current.json` and the service's journal. A
//! generation that does not come up hands the ingress back to the last known good one; if that
//! fails too the manager stays `broken` and says so until a person looks. A crash between the swap
//! and the commit is recovered at start from `state.json`. The Xray binary and its geodata are
//! checked against the release digests before anything runs.
//!
//! Files under the state directory (all `0600`, directory `0700`), byte-compatible with the Python
//! manager's (`json.dumps(sort_keys=True, separators=(",", ":"))` and a newline):
//!
//! ```text
//! generations/<n>.json   the config Xray runs for generation n (ingress accounts inside)
//! current.json           {generation, digest, since, services: {svc: {document, digest, revision}}}
//! journal.json           {svc: {current, previous, history[≤10]}}
//! state.json             {phase: idle|swapping|broken, candidate, failures}
//! lanes.json             {svc: {lane: {user, password, issued_at}}} — the grant lanes' accounts
//! relay.json             {enabled, port, server_name, private_key, public_key, short_ids, accounts}
//! warp-wg.json           {id, token, private_key, address, peer_public_key, endpoint, registered_at}
//! ingress-mtproxy.json   {uuid, username, password} — the MTProxy ingress, minted here once;
//!                        a copy for the `xray-router-ingress` bridge sits next to the socket
//! ```

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::difflib;
use crate::errors::{Error, Result};
use crate::geodata::{self, Fetcher, GeodataStore, Source, Staged, StagedPair};
use crate::https;
use crate::intent::{
    self, canonical, direct_document, document_digest, is_uuid, redact_intent, uses_provider, validate_document,
    validate_exit, CAPABILITIES, MTPROXY_BRIDGE_ADDRESS, NOAUTH_SERVICES, NO_LANE_SERVICES, SERVICES, TUN_SERVICES,
};
use crate::pyjson;
use crate::render::{
    self, config_bytes, generation_digest, Ingress, LaneAccount, Ports, Relay, RenderInput, RENDER_VERSION,
};
use crate::runner::{free_port, Handle, XrayRunner};
use crate::util::{
    atomic_write, now_iso, sha256_hex, token_hex, token_urlsafe, unlink_missing_ok, uuid4,
};
use crate::warp;
use pc_common::pytext::{
    head_chars as first_chars, is_space as py_isspace, strip as py_strip, tail_chars as last_chars,
};
use pc_common::pyvalue::{strict_int as json_int, truthy as py_truthy};

/// v0.7: what this manager enforces beyond CAPABILITIES (docs/spikes/CHAINS_PER_CLIENT.md).
pub const CAPABILITIES_V2: [&str; 3] = ["lanes", "chains", "relay"];
pub const HISTORY_LIMIT: usize = 10;
pub const MAX_START_FAILURES: i64 = 3;
pub const TRACE_HOST: &str = "www.cloudflare.com";

/// `[A-Za-z0-9._:-]{1,128}`
pub fn is_operation_id(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// `([A-Za-z0-9._-]{1,64}):([A-Za-z0-9._~-]{16,128})`: an ingress credential, split.
pub fn credential(text: &str) -> Option<(&str, &str)> {
    let (user, password) = text.split_once(':')?;
    let user_ok = (1..=64).contains(&user.len())
        && user.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    let password_ok = (16..=128).contains(&password.len())
        && password.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'));
    (user_ok && password_ok).then_some((user, password))
}

/// `relay:[A-Za-z0-9_-]{1,64}:(direct|warp)`
fn is_relay_email(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("relay:") else { return false };
    let Some((source, exit)) = rest.rsplit_once(':') else { return false };
    (1..=64).contains(&source.len())
        && source.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && matches!(exit, "direct" | "warp")
}

pub fn revision_of(generation: &Value, document: &Value) -> String {
    sha256_hex(&canonical(&json!({"generation": generation, "document": document})))
}

/// `xray run -test` refused a generation: a code it did not know is named as such.
fn test_failure(message: &str) -> Error {
    let lower = message.to_ascii_lowercase();
    let positions = [
        ("geosite", lower.find("code not found in geosite.dat")),
        ("geoip", lower.find("code not found in geoip.dat")),
    ];
    let found = positions.iter().filter_map(|(kind, at)| at.map(|at| (at, *kind))).min();
    let code = found.map_or("egress_invalid".to_string(), |(_, kind)| format!("{kind}_unknown"));
    Error::EgressInvalid { message: format!("xray refused the generation: {}", last_chars(message, 300)), code }
}

/// `str(value)` of a scalar JSON value (the phase in a message).
fn py_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".into(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(true)) => "True".into(),
        Some(Value::Bool(false)) => "False".into(),
        Some(other) => pc_common::json::dumps(other, &pyjson::DEFAULT),
    }
}

fn generation_number(current: &Value) -> Result<i64> {
    current.get("generation").and_then(Value::as_i64).ok_or_else(|| Error::Internal("'generation'".into()))
}

fn object(value: &Value, what: &str) -> Result<Map<String, Value>> {
    value.as_object().cloned().ok_or_else(|| Error::Internal(format!("{what} is not an object")))
}

pub type Reachability = dyn Fn(Option<&str>, f64) -> bool + Send + Sync;
pub type HopReachability = dyn Fn(&str, &Value, &str, f64) -> bool + Send + Sync;
pub type ExitProber = dyn Fn(u16, &str, f64) -> std::result::Result<Value, String> + Send + Sync;

/// What the manager is built from (`__main__.build_manager` reads it from the environment).
#[derive(Debug, Clone)]
pub struct Options {
    pub state_dir: PathBuf,
    pub ingress_files: BTreeMap<String, PathBuf>,
    pub warp_url: Option<String>,
    /// (name, path, expected sha256) — xray, geoip, geosite.
    pub artifacts: Vec<(String, PathBuf, String)>,
    pub ports: Option<Ports>,
    pub ready_timeout: f64,
    /// v1.1: the MTProxy ingress (a `vless` inbound on this Unix socket); `None` keeps the router
    /// what it was before: naive and mieru only.
    pub mtproxy_socket: Option<PathBuf>,
    /// v1.6: the TrustTunnel ingress (a no-auth SOCKS inbound on this loopback port).
    pub trusttunnel_port: Option<i64>,
    /// v3.0.0: the AmneziaWG ingress (a `tun` inbound on this device, made by the AWG manager).
    pub amneziawg_tun: Option<String>,
    pub net_root: PathBuf,
}

impl Options {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            ingress_files: BTreeMap::new(),
            warp_url: None,
            artifacts: Vec::new(),
            ports: None,
            ready_timeout: 10.0,
            mtproxy_socket: None,
            trusttunnel_port: None,
            amneziawg_tun: None,
            net_root: PathBuf::from("/sys/class/net"),
        }
    }
}

#[derive(Default)]
struct Inner {
    handle: Option<Handle>,
    artifact_error: Option<String>,
    artifact_report: Map<String, Value>,
    xray_version: Option<String>,
    started_at: Option<String>,
    /// What the running generation was started with: the AWG device's presence and ifindex.
    tun_rendered: Option<bool>,
    tun_ifindex: Option<String>,
}

pub struct XrayRouterManager {
    pub state_dir: PathBuf,
    pub services: Vec<&'static str>,
    pub ports: Ports,
    pub ingress_files: BTreeMap<String, PathBuf>,
    pub warp_url: Option<String>,
    pub artifacts: Vec<(String, PathBuf, String)>,
    pub ready_timeout: f64,
    pub mtproxy_socket: Option<PathBuf>,
    pub amneziawg_tun: Option<String>,
    pub net_root: PathBuf,
    pub runner: Arc<dyn XrayRunner>,
    pub reachability: Box<Reachability>,
    pub hop_reachability: Box<HopReachability>,
    /// v0.8: how an exit is tried — a TLS fetch of the trace page through a throwaway Xray.
    pub exit_prober: Box<ExitProber>,
    pub warp_opener: Box<warp::Opener>,
    /// The download every automatic update uses.
    pub fetcher: Arc<Fetcher>,
    /// v0.8: the geodata the router resolves codes against — seeded from the pinned pair.
    pub geodata: GeodataStore,
    inner: Mutex<Inner>,
    geodata_busy: Mutex<()>,
    exit_busy: Mutex<()>,
    geodata_thread: Mutex<Option<JoinHandle<()>>>,
}

fn default_fetch(url: &str, max_bytes: usize) -> Result<(Vec<u8>, String)> {
    geodata::fetch(url, max_bytes)
}

impl XrayRouterManager {
    pub fn new(options: Options, runner: Arc<dyn XrayRunner>) -> Self {
        let services = SERVICES
            .iter()
            .copied()
            .filter(|tag| {
                (*tag != "mtproxy" || options.mtproxy_socket.is_some())
                    && (*tag != "trusttunnel" || options.trusttunnel_port.is_some())
                    && (*tag != "amneziawg" || options.amneziawg_tun.is_some())
            })
            .collect();
        let mut ports = options.ports.clone().filter(|ports| !ports.is_empty()).unwrap_or_else(render::default_ports);
        if let Some(port) = options.trusttunnel_port {
            ports.insert("trusttunnel".into(), port);
        }
        let seed = ["geosite", "geoip"]
            .iter()
            .filter_map(|name| {
                options
                    .artifacts
                    .iter()
                    .find(|(artifact, _, _)| artifact == name)
                    .map(|(_, path, _)| (name.to_string(), path.clone()))
            })
            .collect();
        Self {
            geodata: GeodataStore::new(options.state_dir.join("geodata"), seed),
            state_dir: options.state_dir,
            services,
            ports,
            ingress_files: options.ingress_files,
            warp_url: options.warp_url.filter(|url| !url.is_empty()),
            artifacts: options.artifacts,
            ready_timeout: options.ready_timeout,
            mtproxy_socket: options.mtproxy_socket,
            amneziawg_tun: options.amneziawg_tun.filter(|tun| !tun.is_empty()),
            net_root: options.net_root,
            runner,
            reachability: Box::new(intent::check_reachable),
            hop_reachability: Box::new(|address, port, server_name, timeout| {
                json_int(port)
                    .and_then(|port| u16::try_from(port).ok())
                    .is_some_and(|port| https::check_hop_reachable(address, port, server_name, timeout))
            }),
            exit_prober: Box::new(https::probe_trace),
            warp_opener: Box::new(warp::urllib_opener),
            fetcher: Arc::new(default_fetch),
            inner: Mutex::new(Inner::default()),
            geodata_busy: Mutex::new(()),
            exit_busy: Mutex::new(()),
            geodata_thread: Mutex::new(None),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ------------------------------------------------------------------ files

    pub fn generations_dir(&self) -> PathBuf {
        self.state_dir.join("generations")
    }

    pub fn generation_path(&self, generation: i64) -> PathBuf {
        self.generations_dir().join(format!("{generation}.json"))
    }

    fn read_json(&self, name: &str, default: Value) -> Result<Value> {
        let path = self.state_dir.join(name);
        if !path.exists() {
            return Ok(default);
        }
        let data = fs::read(&path)?;
        serde_json::from_slice(&data).map_err(|_| Error::Manual(format!("{} is not valid JSON", path.display())))
    }

    fn write_json(&self, name: &str, value: &Value) -> Result<()> {
        let mut data = pc_common::json::dumps(value, &pyjson::SORTED).into_bytes();
        data.push(b'\n');
        atomic_write(&self.state_dir.join(name), &data, 0o600)?;
        Ok(())
    }

    fn state(&self) -> Result<Value> {
        self.read_json("state.json", json!({"phase": "idle", "candidate": null, "failures": 0}))
    }

    fn set_state(&self, phase: &str, candidate: Option<i64>, failures: i64) -> Result<()> {
        self.write_json("state.json", &json!({"phase": phase, "candidate": candidate, "failures": failures}))
    }

    fn phase(&self) -> Result<Option<Value>> {
        Ok(self.state()?.get("phase").cloned())
    }

    fn require_idle(&self) -> Result<()> {
        let phase = self.phase()?;
        if phase.as_ref().and_then(Value::as_str) != Some("idle") {
            return Err(Error::Manual(format!("the router is {}", py_str(phase.as_ref()))));
        }
        Ok(())
    }

    /// `current.json`, with every service this router serves present: a node updated from a
    /// release without the service (v1.1 `mtproxy`) runs it pass-through until it is applied.
    fn current(&self) -> Result<Option<Value>> {
        let current = self.read_json("current.json", Value::Null)?;
        let Value::Object(mut current) = current else {
            return if current.is_null() {
                Ok(None)
            } else {
                Err(Error::Internal("current.json is not an object".into()))
            };
        };
        let generation = current.get("generation").cloned().unwrap_or(Value::Null);
        let services = current.entry("services").or_insert_with(|| json!({}));
        let services = services.as_object_mut().ok_or_else(|| Error::Internal("'services'".into()))?;
        for tag in &self.services {
            if !services.contains_key(*tag) {
                let document = direct_document();
                let entry = json!({"document": document, "digest": document_digest(&document),
                                   "revision": revision_of(&generation, &document)});
                services.insert(tag.to_string(), entry);
            }
        }
        Ok(Some(Value::Object(current)))
    }

    fn journal(&self) -> Result<Map<String, Value>> {
        let mut journal = object(&self.read_json("journal.json", json!({}))?, "journal.json")?;
        for tag in &self.services {
            journal.entry(tag.to_string()).or_insert_with(|| json!({"current": null, "previous": null, "history": []}));
        }
        Ok(journal)
    }

    // ------------------------------------------------------------- credentials

    fn tun_present(&self) -> bool {
        self.amneziawg_tun.as_ref().is_some_and(|tun| self.net_root.join(tun).exists())
    }

    fn tun_index(&self) -> Option<String> {
        let tun = self.amneziawg_tun.as_ref()?;
        fs::read_to_string(self.net_root.join(tun).join("ifindex")).ok().map(|text| py_strip(&text).to_string())
    }

    fn warp_wg(&self) -> Result<Option<Value>> {
        let account = self.read_json("warp-wg.json", Value::Null)?;
        if account.is_null() {
            return Ok(None);
        }
        if !warp::valid_account(&account) {
            return Err(Error::Manual("warp-wg.json is malformed".into()));
        }
        Ok(Some(account))
    }

    /// The WARP device AmneziaWG's `warp` uses, registered on first use and kept.
    fn ensure_warp_wg(&self) -> Result<Value> {
        if let Some(account) = self.warp_wg()? {
            return Ok(account);
        }
        let registered = match self.runner.x25519() {
            Ok(pair) => warp::register(&pair, self.warp_opener.as_ref()).map_err(|err| err.to_string()),
            Err(Error::Xray(message)) => Err(message),
            Err(other) => return Err(other),
        };
        let account = registered
            .map_err(|err| Error::EgressUnreachable(format!("WARP registration for AmneziaWG failed: {err}")))?;
        self.write_json("warp-wg.json", &account)?;
        Ok(account)
    }

    /// Before an apply: a SOCKS service's `warp` must answer; AmneziaWG's needs its account.
    fn needs_warp(&self, service: &str, document: &Value) -> Result<()> {
        if !uses_provider(document) {
            return Ok(());
        }
        if TUN_SERVICES.contains(&service) {
            self.ensure_warp_wg()?;
        } else if !(self.reachability)(self.warp_url.as_deref(), 3.0) {
            return Err(Error::EgressUnreachable("egress provider warp is unreachable".into()));
        }
        Ok(())
    }

    fn render(&self, intents: &Map<String, Value>, warp_wg: Option<Value>) -> Result<Value> {
        let ingresses = self.ingresses()?;
        let lanes = self.lane_accounts()?;
        let relay = self.relay_settings()?;
        let warp_wg = match warp_wg {
            Some(account) => Some(account),
            None => self.warp_wg()?,
        };
        render::render_config(&RenderInput {
            intents: intents.clone(),
            ingresses,
            warp_url: self.warp_url.as_deref(),
            ports: Some(self.ports.clone()),
            lanes,
            relay,
            warp_wg,
        })
    }

    fn port(&self, tag: &str) -> Result<i64> {
        self.ports.get(tag).copied().ok_or_else(|| Error::Internal(format!("'{tag}'")))
    }

    fn ingresses(&self) -> Result<Vec<Ingress>> {
        let mut ingresses = Vec::new();
        for tag in &self.services {
            if TUN_SERVICES.contains(tag) {
                // Only while the device exists: the router cannot make it, and a tun inbound Xray
                // had to open itself would need a capability. The watchdog re-renders on a change.
                if self.tun_present() {
                    ingresses.push(Ingress {
                        tag: tag.to_string(),
                        tun: self.amneziawg_tun.clone(),
                        ..Ingress::default()
                    });
                }
                continue;
            }
            if *tag == "mtproxy" {
                let record = self.mtproxy_credential()?;
                ingresses.push(Ingress {
                    tag: tag.to_string(),
                    user: record["username"].as_str().unwrap_or("").into(),
                    password: record["password"].as_str().unwrap_or("").into(),
                    socket: self.mtproxy_socket.as_ref().map(|path| path.display().to_string()),
                    uuid: record["uuid"].as_str().map(str::to_string),
                    ..Ingress::default()
                });
                continue;
            }
            if NOAUTH_SERVICES.contains(tag) {
                ingresses.push(Ingress::new(tag, self.port(tag)?, "", ""));
                continue;
            }
            let path = self.ingress_files.get(*tag).ok_or_else(|| Error::Internal(format!("'{tag}'")))?;
            let text = fs::read_to_string(path)
                .map_err(|_| Error::Manual(format!("ingress credential for {tag} is unreadable")))?;
            let (user, password) = credential(py_strip(&text))
                .ok_or_else(|| Error::Manual(format!("ingress credential for {tag} is malformed")))?;
            ingresses.push(Ingress::new(tag, self.port(tag)?, user, password));
        }
        Ok(ingresses)
    }

    /// The MTProxy ingress's credential, minted on first use (v1.1): no Docker secret, so a node
    /// updated in place needs nothing new from the installer. `uuid` is the VLESS client the bridge
    /// presents; `username`/`password` what Telemt presents to the bridge.
    fn mtproxy_credential(&self) -> Result<Value> {
        let record = self.read_json("ingress-mtproxy.json", Value::Null)?;
        if record.is_null() {
            let record = json!({"uuid": uuid4(), "username": "telemt", "password": token_urlsafe(32)});
            self.write_json("ingress-mtproxy.json", &record)?;
            return Ok(record);
        }
        let field = |key: &str| record.get(key).and_then(Value::as_str);
        let valid = match (field("uuid"), field("username"), field("password")) {
            (Some(uuid), Some(username), Some(password)) => {
                is_uuid(uuid) && credential(&format!("{username}:{password}")).is_some()
            }
            _ => false,
        };
        if !valid {
            return Err(Error::Manual("ingress credential for mtproxy is malformed".into()));
        }
        Ok(record)
    }

    /// The bridge's copy, next to the socket in the volume the two containers share.
    fn publish_mtproxy_credential(&self) -> Result<()> {
        let Some(socket) = &self.mtproxy_socket else { return Ok(()) };
        let record = self.mtproxy_credential()?;
        let mut data = pc_common::json::dumps(&record, &pyjson::SORTED).into_bytes();
        data.push(b'\n');
        let directory = socket.parent().unwrap_or(Path::new("."));
        atomic_write(&directory.join("ingress-mtproxy.json"), &data, 0o600)?;
        Ok(())
    }

    /// Where and how a data plane outside the host network reaches its ingress (v1.1: only
    /// `mtproxy`, through the bridge) — for the panel, which writes it into Telemt.
    pub fn ingress(&self, service: &str) -> Result<Value> {
        if service != "mtproxy" || self.mtproxy_socket.is_none() {
            return Err(Error::Validation("unknown service".into()));
        }
        let _inner = self.lock();
        let record = self.mtproxy_credential()?;
        Ok(json!({"address": MTPROXY_BRIDGE_ADDRESS, "username": record["username"], "password": record["password"]}))
    }

    // ------------------------------------------------------ lanes and relay (v0.7)

    fn lanes_file(&self) -> Result<Map<String, Value>> {
        let lanes = object(&self.read_json("lanes.json", json!({}))?, "lanes.json")?;
        let mut out = Map::new();
        for tag in &self.services {
            out.insert(tag.to_string(), Value::Object(object(lanes.get(*tag).unwrap_or(&json!({})), "a lane set")?));
        }
        Ok(out)
    }

    fn lane_accounts(&self) -> Result<BTreeMap<String, Vec<LaneAccount>>> {
        let mut accounts = BTreeMap::new();
        for (tag, lanes) in self.lanes_file()? {
            let entries = lanes
                .as_object()
                .into_iter()
                .flatten()
                .map(|(lane, entry)| LaneAccount {
                    lane: lane.clone(),
                    user: entry["user"].clone(),
                    password: entry["password"].clone(),
                })
                .collect();
            accounts.insert(tag, entries);
        }
        Ok(accounts)
    }

    /// A schema-2 intent minus the grant lanes not in `known`: a lane whose account is gone cannot
    /// route anyone, so its rules go with it and the intent keeps rendering; the chains its rules
    /// named are dropped when unused.
    fn without_lanes(intent: &Value, known: &HashSet<String>) -> Value {
        if !intent::is_v2(intent) {
            return intent.clone();
        }
        let all = intent.get("lanes").and_then(Value::as_object).cloned().unwrap_or_default();
        let lanes: Map<String, Value> = all
            .iter()
            .filter(|(lane, _)| lane.starts_with("svc:") || known.contains(*lane))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if lanes == all {
            return intent.clone();
        }
        let mut used: HashSet<String> = HashSet::new();
        for body in lanes.values() {
            for rule in body.get("rules").and_then(Value::as_array).into_iter().flatten() {
                if let Some(egress) = rule.get("egress").and_then(Value::as_str) {
                    used.insert(egress.to_string());
                }
            }
            if let Some(egress) = body.get("default").and_then(|d| d.get("egress")).and_then(Value::as_str) {
                used.insert(egress.to_string());
            }
        }
        let chains: Map<String, Value> = intent
            .get("chains")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(chain_id, _)| used.contains(&format!("chain:{chain_id}")))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut out = intent.clone();
        out["lanes"] = Value::Object(lanes);
        out["chains"] = Value::Object(chains);
        out
    }

    fn known_lanes(lanes: &Map<String, Value>) -> BTreeMap<String, HashSet<String>> {
        lanes
            .iter()
            .map(|(tag, entries)| {
                (tag.clone(), entries.as_object().map(|e| e.keys().cloned().collect()).unwrap_or_default())
            })
            .collect()
    }

    /// The running intents with every lane that has no account any more stripped out.
    fn current_intents(&self, current: &Value) -> Result<Map<String, Value>> {
        let known = Self::known_lanes(&self.lanes_file()?);
        let empty = HashSet::new();
        let services =
            current.get("services").and_then(Value::as_object).ok_or_else(|| Error::Internal("'services'".into()))?;
        Ok(services
            .iter()
            .map(|(tag, entry)| {
                (tag.clone(), Self::without_lanes(&entry["document"], known.get(tag).unwrap_or(&empty)))
            })
            .collect())
    }

    fn relay_record(&self) -> Result<Value> {
        self.read_json("relay.json", Value::Null)
    }

    fn relay_settings(&self) -> Result<Option<Relay>> {
        let record = self.relay_record()?;
        if !py_truthy(&record) || !record.get("enabled").is_some_and(py_truthy) {
            return Ok(None);
        }
        let accounts = record["accounts"]
            .as_array()
            .ok_or_else(|| Error::Internal("'accounts'".into()))?
            .iter()
            .map(|account| {
                Ok((
                    account["email"].as_str().ok_or_else(|| Error::Internal("'email'".into()))?.to_string(),
                    account["uuid"].clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Relay {
            port: record["port"].clone(),
            server_name: record["server_name"].clone(),
            private_key: record["private_key"].clone(),
            short_ids: record["short_ids"].as_array().cloned().unwrap_or_default(),
            accounts,
        }))
    }

    fn relay_view(&self) -> Result<Value> {
        let record = self.relay_record()?;
        if !py_truthy(&record) {
            return Ok(
                json!({"enabled": false, "port": null, "server_name": null, "public_key": null, "short_ids": [], "accounts": 0}),
            );
        }
        let accounts = record["accounts"].as_array().cloned().unwrap_or_default();
        let mut emails: Vec<String> =
            accounts.iter().filter_map(|account| account["email"].as_str().map(str::to_string)).collect();
        emails.sort();
        // `emails` names the accounts the inbound carries — the node's report to the central
        // confirms exactly these (never a UUID).
        Ok(
            json!({"enabled": py_truthy(&record["enabled"]), "port": record["port"], "server_name": record["server_name"],
                  "public_key": record["public_key"], "short_ids": record["short_ids"], "accounts": accounts.len(),
                  "emails": emails}),
        )
    }

    /// Commit a new generation with the same intents: what changed is what the accounts and the
    /// relay say, not any service's document.
    fn rerender_current(&self, inner: &mut Inner) -> Result<()> {
        let current = self.current()?.ok_or_else(|| Error::Manual("the router has no current generation".into()))?;
        self.require_idle()?;
        let intents = self.current_intents(&current)?;
        self.commit_generation(inner, generation_number(&current)? + 1, &intents, &BTreeMap::new(), None, true)?;
        Ok(())
    }

    pub fn service(&self, service: &str) -> Result<()> {
        if !self.services.contains(&service) {
            return Err(Error::Validation("unknown service".into()));
        }
        Ok(())
    }

    /// Mint (or rotate) a grant lane's account, put it on the ingress now, return it once.
    pub fn lane_issue(&self, service: &str, lane: &Value) -> Result<Value> {
        self.service(service)?;
        if NO_LANE_SERVICES.contains(&service) {
            // One VLESS client behind the bridge (Telemt), one anonymous SOCKS client (TrustTunnel),
            // one tunnel device (AmneziaWG): none tells its users apart upstream.
            return Err(Error::Validation(format!("{service} has no lanes")));
        }
        let id = lane.as_str().and_then(|lane| lane.strip_prefix("grant:")).filter(|id| {
            (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        });
        let Some(id) = id else { return Err(Error::Validation("invalid lane".into())) };
        let lane = lane.as_str().expect("checked above");
        let mut inner = self.lock();
        let mut lanes = self.lanes_file()?;
        let account = json!({"user": format!("grant-{id}"), "password": token_urlsafe(32), "issued_at": now_iso()});
        lanes[service].as_object_mut().expect("a lane set is an object").insert(lane.to_string(), account.clone());
        self.write_json("lanes.json", &Value::Object(lanes))?;
        self.rerender_current(&mut inner)?;
        Ok(json!({"lane": lane, "user": account["user"], "password": account["password"]}))
    }

    /// Forget a lane's account: the running intent loses the lane's rules in the same generation,
    /// so nothing ever refers to an account that is gone. The file is written after the commit — a
    /// failed swap leaves the account (and the intent) as they were.
    pub fn lane_forget(&self, service: &str, lane: &str) -> Result<Value> {
        self.service(service)?;
        let mut inner = self.lock();
        let mut lanes = self.lanes_file()?;
        let set = lanes[service].as_object_mut().expect("a lane set is an object");
        if set.shift_remove(lane).is_none() {
            return Err(Error::conflict("unknown lane", "lane_unknown"));
        }
        let current = self.current()?.ok_or_else(|| Error::Manual("the router has no current generation".into()))?;
        self.require_idle()?;
        let known = Self::known_lanes(&lanes);
        let empty = HashSet::new();
        let intents: Map<String, Value> = current["services"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(tag, entry)| {
                (tag.clone(), Self::without_lanes(&entry["document"], known.get(tag).unwrap_or(&empty)))
            })
            .collect();
        let previous = self.read_json("lanes.json", json!({}))?;
        self.write_json("lanes.json", &Value::Object(lanes))?;
        let generation = generation_number(&current)? + 1;
        if let Err(err) = self.commit_generation(&mut inner, generation, &intents, &BTreeMap::new(), None, true) {
            self.write_json("lanes.json", &previous)?;
            return Err(err);
        }
        Ok(json!({"lane": lane, "forgotten": true}))
    }

    pub fn lanes(&self, service: &str) -> Result<Value> {
        self.service(service)?;
        let _inner = self.lock();
        let lanes = self.lanes_file()?;
        let mut names: Vec<String> =
            lanes[service].as_object().map(|set| set.keys().cloned().collect()).unwrap_or_default();
        names.sort();
        Ok(json!({"lanes": names}))
    }

    pub fn relay_enable(&self, server_name: &Value, port: &Value) -> Result<Value> {
        let name_ok = server_name
            .as_str()
            .is_some_and(|name| !name.is_empty() && name.chars().count() <= 253 && !name.chars().any(py_isspace));
        if !name_ok {
            return Err(Error::Validation("invalid relay server name".into()));
        }
        if !json_int(port).is_some_and(|port| (1..=65535).contains(&port)) {
            return Err(Error::Validation("invalid relay port".into()));
        }
        let mut inner = self.lock();
        let record = self.relay_record()?;
        let mut record = if py_truthy(&record) { object(&record, "relay.json")? } else { Map::new() };
        if !record.get("private_key").is_some_and(py_truthy) {
            let (private_key, public_key) = self.runner.x25519()?;
            record.insert("private_key".into(), json!(private_key));
            record.insert("public_key".into(), json!(public_key));
            record.insert("short_ids".into(), json!([token_hex(4)]));
            record.insert("accounts".into(), json!([]));
        }
        record.insert("enabled".into(), json!(true));
        record.insert("port".into(), port.clone());
        record.insert("server_name".into(), server_name.clone());
        self.write_json("relay.json", &Value::Object(record))?;
        self.rerender_current(&mut inner)?;
        self.relay_view()
    }

    pub fn relay_disable(&self) -> Result<Value> {
        let mut inner = self.lock();
        let record = self.relay_record()?;
        if py_truthy(&record) {
            let mut record = object(&record, "relay.json")?;
            record.insert("enabled".into(), json!(false));
            self.write_json("relay.json", &Value::Object(record))?;
            self.rerender_current(&mut inner)?;
        }
        self.relay_view()
    }

    pub fn relay_set_accounts(&self, accounts: &Value) -> Result<Value> {
        let invalid = || Error::Validation("invalid relay account".into());
        let accounts = match accounts {
            Value::Array(accounts) if accounts.len() <= 256 => accounts,
            _ => return Err(Error::Validation("invalid relay accounts".into())),
        };
        let mut cleaned = Vec::new();
        for account in accounts {
            let account = match account {
                Value::Object(account)
                    if account.len() == 2 && account.contains_key("email") && account.contains_key("uuid") =>
                {
                    account
                }
                _ => return Err(invalid()),
            };
            let email = account["email"].as_str().filter(|email| is_relay_email(email)).ok_or_else(invalid)?;
            let uuid = account["uuid"].as_str().filter(|uuid| is_uuid(uuid)).ok_or_else(invalid)?;
            cleaned.push(json!({"email": email, "uuid": uuid}));
        }
        if self.warp_url.is_none() {
            // The central mints a `direct` and a `warp` account for every source. Without a WARP
            // provider this node carries the rest and names only what it carries, so a chain through
            // its direct exit converges and «via warp» stays `relay_no_warp` on the central.
            cleaned.retain(|account| !account["email"].as_str().unwrap_or("").ends_with(":warp"));
        }
        let mut inner = self.lock();
        let record = self.relay_record()?;
        if !py_truthy(&record) || !record.get("enabled").is_some_and(py_truthy) {
            return Err(Error::conflict("the relay is not enabled", "relay_disabled"));
        }
        let mut record = object(&record, "relay.json")?;
        let previous = record.get("accounts").cloned().unwrap_or(json!([]));
        record.insert("accounts".into(), Value::Array(cleaned));
        self.write_json("relay.json", &Value::Object(record.clone()))?;
        if let Err(err) = self.rerender_current(&mut inner) {
            if matches!(err, Error::EgressInvalid { .. }) {
                record.insert("accounts".into(), previous);
                self.write_json("relay.json", &Value::Object(record))?;
            }
            return Err(err);
        }
        self.relay_view()
    }

    pub fn relay(&self) -> Result<Value> {
        let _inner = self.lock();
        self.relay_view()
    }

    /// Reachability of every hop an intent's chains name, keyed `chain:<id>:<n>`.
    fn check_hops(&self, normalised: &Value) -> Vec<(String, bool)> {
        let mut results = Vec::new();
        if !intent::is_v2(normalised) {
            return results;
        }
        for (chain_id, chain) in normalised["chains"].as_object().into_iter().flatten() {
            for (index, hop) in chain["hops"].as_array().into_iter().flatten().enumerate() {
                let reachable = (self.hop_reachability)(
                    hop["address"].as_str().unwrap_or(""),
                    &hop["port"],
                    hop["server_name"].as_str().unwrap_or(""),
                    3.0,
                );
                results.push((format!("chain:{chain_id}:{}", index + 1), reachable));
            }
        }
        results
    }

    // --------------------------------------------------------------- artifacts

    pub fn verify_artifacts(&self) -> Map<String, Value> {
        let mut report = Map::new();
        for (name, path, expected) in &self.artifacts {
            let actual = fs::read(path).ok().map(|data| sha256_hex(&data));
            let verified = actual
                .as_ref()
                .is_some_and(|actual| pc_common::constant_time_eq(actual.as_bytes(), expected.as_bytes()));
            report.insert(name.clone(), json!({"sha256": actual, "verified": verified}));
        }
        report
    }

    // ------------------------------------------------------------- lifecycle

    /// Verify, recover, then run the current generation (or the first one).
    pub fn bootstrap(&self) -> Result<()> {
        let mut inner = self.lock();
        let report = self.verify_artifacts();
        let mut failed: Vec<&String> =
            report.iter().filter(|(_, entry)| entry["verified"] != json!(true)).map(|(name, _)| name).collect();
        failed.sort();
        inner.artifact_report = report.clone();
        if !failed.is_empty() {
            let message = format!(
                "artifact digest mismatch: {}",
                failed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
            inner.artifact_error = Some(message.clone());
            return Err(Error::ArtifactMismatch(message));
        }
        inner.artifact_error = None;
        inner.xray_version = Some(self.runner.version()?);
        if self.geodata.seed.len() == 2 {
            self.geodata.ensure_seed()?;
            // A new Xray release brings a new seed; the pin as the source follows it.
            self.geodata.follow_seed()?;
        }
        self.recover()?;
        self.publish_mtproxy_credential()?;
        let Some(current) = self.current()? else {
            let intents: Map<String, Value> =
                self.services.iter().map(|tag| (tag.to_string(), direct_document())).collect();
            self.commit_generation(&mut inner, 1, &intents, &BTreeMap::new(), None, false)?;
            return Ok(());
        };
        let intents = self.current_intents(&current)?;
        let config = self.render(&intents, None)?;
        let generation = generation_number(&current)?;
        if Some(generation_digest(&config).as_str()) != current["digest"].as_str()
            || !self.generation_path(generation).exists()
        {
            // The credential files (or the renderer) changed since this generation was written: the
            // same intents, re-rendered, as a new generation.
            self.commit_generation(&mut inner, generation + 1, &intents, &BTreeMap::new(), None, true)?;
            return Ok(());
        }
        self.start_generation(&mut inner, generation)
    }

    fn recover(&self) -> Result<()> {
        let state = self.state()?;
        match state.get("phase").and_then(Value::as_str) {
            Some("swapping") => {
                if let Some(candidate) = state.get("candidate").and_then(json_int).and_then(|c| i64::try_from(c).ok()) {
                    let current = self.current()?;
                    let committed = match &current {
                        Some(current) => current.get("generation").and_then(Value::as_i64) == Some(candidate),
                        None => false,
                    };
                    if !committed {
                        unlink_missing_ok(&self.generation_path(candidate))?;
                    }
                }
                self.set_state("idle", None, 0)
            }
            // A person restarted us after a broken swap: try the current generation again.
            Some("broken") => self.set_state("idle", None, 0),
            _ => Ok(()),
        }
    }

    fn start_generation(&self, inner: &mut Inner, generation: i64) -> Result<()> {
        let path = self.generation_path(generation);
        if !path.exists() {
            return Err(Error::Manual(format!("generation file is missing: {}", path.display())));
        }
        let mut sockets = Vec::new();
        if let Some(socket) = &self.mtproxy_socket {
            // A socket left behind by a process that died keeps Xray from binding (proved on
            // 26.3.27: `bind: address already in use`); the previous process is stopped by now.
            unlink_missing_ok(socket)?;
            sockets.push(socket.display().to_string());
        }
        let tun = Self::tun_of(&path);
        let handle = self.runner.start(&path, tun.as_deref())?;
        inner.tun_rendered = self.amneziawg_tun.as_ref().map(|_| tun.is_some());
        inner.tun_ifindex = if tun.is_some() { self.tun_index() } else { None };
        let ports: Vec<i64> = self.services.iter().filter_map(|tag| self.ports.get(*tag).copied()).collect();
        if let Err(err) = self.runner.wait_ready(&ports, self.ready_timeout, &sockets) {
            self.runner.stop(&handle);
            return Err(err);
        }
        inner.handle = Some(handle);
        inner.started_at = Some(now_iso());
        Ok(())
    }

    /// The device the generation's `tun` inbound names, if it has one.
    fn tun_of(path: &Path) -> Option<String> {
        let config: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
        config["inbounds"]
            .as_array()?
            .iter()
            .find(|inbound| inbound["protocol"] == "tun")
            .and_then(|inbound| inbound["settings"]["name"].as_str().map(str::to_string))
    }

    /// The AmneziaWG device appeared, went away or was made anew since the running generation
    /// started: the router re-renders (or restarts with the new device).
    fn tun_changed(&self, inner: &Inner) -> bool {
        let Some(rendered) = inner.tun_rendered.filter(|_| self.amneziawg_tun.is_some()) else { return false };
        let present = self.tun_present();
        if present != rendered {
            return true;
        }
        present && self.tun_index() != inner.tun_ifindex
    }

    pub fn close(&self) {
        let mut inner = self.lock();
        if let Some(handle) = inner.handle.take() {
            self.runner.stop(&handle);
        }
    }

    /// Restart the current generation when the process died on its own; after
    /// `MAX_START_FAILURES` attempts in a row the router is `broken` and stays so.
    pub fn watchdog_tick(self: &Arc<Self>) -> Result<()> {
        self.geodata_tick();
        let mut inner = self.lock();
        let state = self.state()?;
        if state.get("phase").and_then(Value::as_str) != Some("idle") || inner.artifact_error.is_some() {
            return Ok(());
        }
        let alive = inner.handle.as_ref().is_some_and(|handle| self.runner.alive(handle));
        if alive && !self.tun_changed(&inner) {
            return Ok(());
        }
        let Some(current) = self.current()? else { return Ok(()) };
        if alive {
            // v3.0.0: the AmneziaWG device changed under the running process.
            return match self.rerender_current(&mut inner) {
                Err(Error::Xray(_) | Error::Manual(_) | Error::EgressInvalid { .. }) | Ok(()) => Ok(()),
                Err(other) => Err(other),
            };
        }
        match self.start_generation(&mut inner, generation_number(&current)?) {
            Ok(()) => self.set_state("idle", None, 0),
            Err(Error::Xray(_) | Error::Manual(_)) => {
                let failures = state.get("failures").and_then(Value::as_i64).unwrap_or(0) + 1;
                let phase = if failures >= MAX_START_FAILURES { "broken" } else { "idle" };
                self.set_state(phase, None, failures)
            }
            Err(other) => Err(other),
        }
    }

    // ------------------------------------------------------------------ views

    fn service_view(current: Option<&Value>, tag: &str) -> Value {
        match current {
            None => json!({"revision": null, "digest": null, "document": null}),
            Some(current) => {
                let entry = &current["services"][tag];
                json!({"revision": entry["revision"], "digest": entry["digest"], "document": redact_intent(&entry["document"])})
            }
        }
    }

    fn providers(&self) -> Value {
        match &self.warp_url {
            None => json!({}),
            Some(url) => json!({"warp": {"reachable": (self.reachability)(Some(url), 3.0)}}),
        }
    }

    fn capabilities() -> Value {
        json!(CAPABILITIES.iter().chain(CAPABILITIES_V2.iter()).collect::<Vec<_>>())
    }

    pub fn status(&self) -> Result<Value> {
        let inner = self.lock();
        let state = self.state()?;
        let current = self.current()?;
        let mut running = Value::Null;
        if let (Some(current), Some(handle)) = (&current, &inner.handle) {
            if self.runner.alive(handle) {
                running = json!({"generation": current["generation"], "digest": current["digest"], "since": inner.started_at});
            }
        }
        let services: Map<String, Value> =
            self.services.iter().map(|tag| (tag.to_string(), Self::service_view(current.as_ref(), tag))).collect();
        let lanes: Map<String, Value> = self
            .lanes_file()?
            .into_iter()
            .map(|(tag, set)| {
                let mut names: Vec<String> = set.as_object().map(|s| s.keys().cloned().collect()).unwrap_or_default();
                names.sort();
                (tag, json!(names))
            })
            .collect();
        Ok(json!({
            "version": RENDER_VERSION, "xray_version": inner.xray_version, "artifacts": inner.artifact_report,
            "artifact_error": inner.artifact_error, "phase": state.get("phase").cloned().unwrap_or(json!("idle")), "running": running,
            "services": services, "providers": self.providers(), "capabilities": Self::capabilities(),
            "restart_required": true, "lanes": lanes, "relay": self.relay_view()?, "geodata": self.geodata_summary(),
        }))
    }

    /// What identity/status carries to a central: the source and version, never the codes.
    fn geodata_summary(&self) -> Value {
        let meta = self.geodata.meta();
        let get = |key: &str| meta.get(key).cloned().unwrap_or(Value::Null);
        let files: Map<String, Value> = meta
            .get("files")
            .filter(|files| py_truthy(files))
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(name, entry)| {
                let field = |key: &str| entry.get(key).cloned().unwrap_or(Value::Null);
                (name.clone(), json!({"sha256": field("sha256"), "codes": field("codes")}))
            })
            .collect();
        json!({"source": get("source"), "origin": get("origin"), "version": get("version"), "updated_at": get("updated_at"),
               "auto_update": meta.get("auto_update").is_some_and(py_truthy), "interval_hours": get("interval_hours"),
               "last_error": get("last_error"), "update_hour": get("update_hour"), "last_check_at": get("last_check_at"),
               "files": files})
    }

    pub fn egress(&self, service: &str) -> Result<Value> {
        self.service(service)?;
        let inner = self.lock();
        let current = self.current()?;
        let journal = self.journal()?;
        let book = &journal[service];
        let view = Self::service_view(current.as_ref(), service);
        let document = &view["document"];
        let mut out = Map::new();
        if TUN_SERVICES.contains(&service) {
            // v3.0.0: whether the device exists and the running Xray reads it.
            let attached = inner.tun_rendered.unwrap_or(false)
                && inner.handle.as_ref().is_some_and(|handle| self.runner.alive(handle));
            out.insert(
                "tun".into(),
                json!({"device": self.amneziawg_tun, "present": self.tun_present(), "attached": attached,
                       "warp_registered": self.warp_wg()?.is_some()}),
            );
        }
        let previous = match &book["previous"] {
            Value::Null => Value::Null,
            previous => json!({"revision": previous["revision"]}),
        };
        let journal_current = match &book["current"] {
            Value::Null => Value::Null,
            entry => {
                let keys = ["revision", "digest", "generation", "operation_id", "applied_at"];
                Value::Object(
                    keys.iter().map(|key| (key.to_string(), entry.get(*key).cloned().unwrap_or(Value::Null))).collect(),
                )
            }
        };
        let mode = if !document.is_null() && uses_provider(document) { "proxy" } else { "direct" };
        let generation = current.as_ref().map_or(Value::Null, |current| current["generation"].clone());
        let rest = json!({
            "revision": view["revision"], "document": document, "mode": mode, "generation": generation,
            "providers": self.providers(), "capabilities": Self::capabilities(), "restart_required": true, "warnings": [],
            "runtime_version": inner.xray_version, "previous": previous, "current": journal_current,
        });
        out.extend(rest.as_object().expect("an object").clone());
        Ok(Value::Object(out))
    }

    // ----------------------------------------------------------- transactions

    fn target(
        &self,
        service: &str,
        expected_revision: &Value,
        document: &Value,
    ) -> Result<(Value, Value, Map<String, Value>)> {
        let normalised = validate_document(document)?;
        let current = self.current()?.ok_or_else(|| Error::Manual("the router has no current generation".into()))?;
        self.require_idle()?;
        let actual = current["services"][service]["revision"].as_str().unwrap_or("");
        let matches = expected_revision
            .as_str()
            .is_some_and(|expected| pc_common::constant_time_eq(actual.as_bytes(), expected.as_bytes()));
        if !matches {
            return Err(Error::conflict("egress revision does not match", "egress_conflict"));
        }
        let mut intents: Map<String, Value> = current["services"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(tag, entry)| (tag.clone(), entry["document"].clone()))
            .collect();
        intents.insert(service.to_string(), normalised.clone());
        Ok((current, normalised, intents))
    }

    fn diff(before: &Value, after: &Value) -> Vec<String> {
        let old = pc_common::json::dumps(before, &pyjson::INDENT1_SORTED);
        let new = pc_common::json::dumps(after, &pyjson::INDENT1_SORTED);
        let old: Vec<&str> = old.split('\n').collect();
        let new: Vec<&str> = new.split('\n').collect();
        difflib::changed_lines(&old, &new)
    }

    pub fn egress_plan(&self, service: &str, expected_revision: &Value, document: &Value) -> Result<Value> {
        self.service(service)?;
        let _inner = self.lock();
        let (current, normalised, intents) = self.target(service, expected_revision, document)?;
        let mut stand_in = None;
        if TUN_SERVICES.contains(&service) && uses_provider(&normalised) && self.warp_wg()?.is_none() {
            // Not registered yet (the apply registers): the plan renders with a stand-in account.
            let key = format!("{}=", "A".repeat(43));
            stand_in = Some(json!({"id": "plan", "token": "plan", "private_key": key, "address": "172.16.0.2",
                                   "peer_public_key": key, "endpoint": "162.159.192.1:2408"}));
        }
        let config = self.render(&intents, stand_in)?;
        let candidate = self.state_dir.join(".plan.json");
        atomic_write(&candidate, &config_bytes(&config), 0o600)?;
        let tested = self.runner.test(&candidate, None);
        unlink_missing_ok(&candidate)?;
        match tested {
            Err(Error::Xray(message)) => return Err(test_failure(&message)),
            Err(other) => return Err(other),
            Ok(()) => {}
        }
        let mut reachability = Map::new();
        if uses_provider(&normalised) {
            let warp = if TUN_SERVICES.contains(&service) {
                if self.warp_wg()?.is_some() {
                    json!(true)
                } else {
                    Value::Null
                }
            } else {
                json!((self.reachability)(self.warp_url.as_deref(), 3.0))
            };
            reachability.insert("warp".into(), warp);
        }
        for (key, reachable) in self.check_hops(&normalised) {
            reachability.insert(key, json!(reachable));
        }
        let generation = generation_number(&current)? + 1;
        let digest = generation_digest(&config);
        let before = redact_intent(&current["services"][service]["document"]);
        Ok(json!({
            "revision": current["services"][service]["revision"],
            "target_revision": revision_of(&json!(generation), &normalised),
            "generation_digest": digest, "rendered_sha256": digest,
            "diff": Self::diff(&before, &redact_intent(&normalised)),
            "warnings": [], "reachability": reachability, "restart_required": true,
        }))
    }

    pub fn egress_apply(
        &self,
        service: &str,
        expected_revision: &Value,
        document: &Value,
        operation_id: &Value,
    ) -> Result<Value> {
        self.service(service)?;
        let Some(operation_id) = operation_id.as_str().filter(|op| is_operation_id(op)) else {
            return Err(Error::Validation("invalid operation id".into()));
        };
        let mut inner = self.lock();
        let normalised = validate_document(document)?;
        let journal = self.journal()?;
        let current_entry = &journal[service]["current"];
        if !current_entry.is_null() && current_entry.get("operation_id").and_then(Value::as_str) == Some(operation_id) {
            if current_entry["document"] != normalised {
                return Err(Error::conflict("operation id already used for another request", "operation_conflict"));
            }
            return Ok(json!({"revision": current_entry["revision"], "applied": current_entry["document"],
                             "readback_sha256": current_entry["generation_digest"], "generation": current_entry["generation"],
                             "replayed": true}));
        }
        let (current, normalised, intents) = self.target(service, expected_revision, document)?;
        self.needs_warp(service, &normalised)?;
        for (key, reachable) in self.check_hops(&normalised) {
            if !reachable {
                let parts: Vec<&str> = key.split(':').collect();
                return Err(Error::EgressUnreachable(format!("chain {} hop {} is unreachable", parts[1], parts[2])));
            }
        }
        let operation_ids: BTreeMap<String, String> = [(service.to_string(), operation_id.to_string())].into();
        let entries =
            self.commit_generation(&mut inner, generation_number(&current)? + 1, &intents, &operation_ids, None, true)?;
        let entry = &entries[service];
        Ok(
            json!({"revision": entry["revision"], "applied": entry["document"], "readback_sha256": entry["generation_digest"],
                  "generation": entry["generation"], "replayed": false}),
        )
    }

    pub fn egress_rollback(&self, service: &str, expected_revision: &Value) -> Result<Value> {
        self.service(service)?;
        let mut inner = self.lock();
        let current = self.current()?.ok_or_else(|| Error::Manual("the router has no current generation".into()))?;
        let actual = current["services"][service]["revision"].as_str().unwrap_or("");
        if !expected_revision
            .as_str()
            .is_some_and(|expected| pc_common::constant_time_eq(actual.as_bytes(), expected.as_bytes()))
        {
            return Err(Error::conflict("egress revision does not match", "egress_conflict"));
        }
        let journal = self.journal()?;
        let previous = &journal[service]["previous"];
        if previous.is_null() {
            return Err(Error::conflict("no previous egress to roll back to", "egress_no_previous"));
        }
        // A previous entry may name a lane forgotten since: it goes back without that lane (an
        // account that is gone cannot route anyone), like a start or a re-render would.
        let mut intents = self.current_intents(&current)?;
        let known: HashSet<String> = self
            .lanes_file()?
            .get(service)
            .and_then(Value::as_object)
            .map(|set| set.keys().cloned().collect())
            .unwrap_or_default();
        let document = Self::without_lanes(&previous["document"], &known);
        intents.insert(service.to_string(), document.clone());
        self.needs_warp(service, &document)?;
        let entries = self.commit_generation(
            &mut inner,
            generation_number(&current)? + 1,
            &intents,
            &BTreeMap::new(),
            Some(service),
            true,
        )?;
        let entry = &entries[service];
        Ok(
            json!({"revision": entry["revision"], "applied": entry["document"], "readback_sha256": entry["generation_digest"],
                  "generation": entry["generation"]}),
        )
    }

    /// Render → test → swap → `current.json` → journal. The journal entry per service.
    fn commit_generation(
        &self,
        inner: &mut Inner,
        generation: i64,
        intents: &Map<String, Value>,
        operation_ids: &BTreeMap<String, String>,
        rollback_of: Option<&str>,
        keep_journal: bool,
    ) -> Result<Map<String, Value>> {
        let config = self.render(intents, None)?;
        let path = self.generation_path(generation);
        atomic_write(&path, &config_bytes(&config), 0o600)?;
        match self.runner.test(&path, None) {
            Ok(()) => {}
            Err(Error::Xray(message)) => {
                unlink_missing_ok(&path)?;
                return Err(test_failure(&message));
            }
            Err(other) => return Err(other),
        }
        let digest = generation_digest(&config);
        let previous_current = self.current()?;
        self.swap(inner, generation, previous_current.as_ref())?;
        let mut services = Map::new();
        for tag in &self.services {
            let document = intents.get(*tag).ok_or_else(|| Error::Internal(format!("'{tag}'")))?;
            services.insert(
                tag.to_string(),
                json!({"document": document, "digest": document_digest(document), "revision": revision_of(&json!(generation), document)}),
            );
        }
        self.write_json(
            "current.json",
            &json!({"generation": generation, "digest": digest, "since": now_iso(), "services": services}),
        )?;
        let mut journal = if keep_journal {
            self.journal()?
        } else {
            self.services
                .iter()
                .map(|tag| (tag.to_string(), json!({"current": null, "previous": null, "history": []})))
                .collect()
        };
        let mut entries = Map::new();
        for tag in &self.services {
            let document = &services[*tag]["document"];
            let entry = json!({"document": document, "digest": services[*tag]["digest"], "revision": services[*tag]["revision"],
                               "generation": generation, "generation_digest": digest, "operation_id": operation_ids.get(*tag),
                               "applied_at": now_iso()});
            let book = journal
                .get_mut(*tag)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| Error::Internal(format!("'{tag}'")))?;
            let mut history: Vec<Value> = book.get("history").and_then(Value::as_array).cloned().unwrap_or_default();
            let book_current = book.get("current").cloned().unwrap_or(Value::Null);
            let changed = book_current.is_null()
                || book_current.get("document") != Some(document)
                || rollback_of == Some(*tag)
                || operation_ids.contains_key(*tag);
            if !changed {
                // Another service's apply re-rendered this one unchanged: same document, new
                // generation — the current entry moves on, the stack does not grow.
                let mut moved = book_current.as_object().cloned().unwrap_or_default();
                moved.insert("revision".into(), entry["revision"].clone());
                moved.insert("generation".into(), json!(generation));
                moved.insert("generation_digest".into(), json!(digest));
                let moved = Value::Object(moved);
                book.insert("current".into(), moved.clone());
                if let Some(last) = history.last_mut() {
                    *last = moved;
                    book.insert("history".into(), Value::Array(history));
                }
            } else if rollback_of == Some(*tag) {
                history.pop();
                match history.last_mut() {
                    Some(last) => *last = entry,
                    None => history = vec![entry],
                }
                let previous = if history.len() > 1 { history[history.len() - 2].clone() } else { Value::Null };
                book.insert("current".into(), history[history.len() - 1].clone());
                book.insert("previous".into(), previous);
                book.insert("history".into(), Value::Array(history));
            } else {
                history.push(entry.clone());
                if history.len() > HISTORY_LIMIT {
                    history.drain(..history.len() - HISTORY_LIMIT);
                }
                let previous = if history.len() > 1 { history[history.len() - 2].clone() } else { Value::Null };
                book.insert("history".into(), Value::Array(history));
                book.insert("current".into(), entry);
                book.insert("previous".into(), previous);
            }
            entries.insert(tag.to_string(), book["current"].clone());
        }
        self.write_json("journal.json", &Value::Object(journal))?;
        self.set_state("idle", None, 0)?;
        Ok(entries)
    }

    /// Stop the running process, start `generation`; on failure, back to the last known good
    /// generation — or `broken` when even that will not come up.
    fn swap(&self, inner: &mut Inner, generation: i64, previous_current: Option<&Value>) -> Result<()> {
        self.set_state("swapping", Some(generation), 0)?;
        if let Some(handle) = inner.handle.take() {
            self.runner.stop(&handle);
        }
        match self.start_generation(inner, generation) {
            Ok(()) => Ok(()),
            Err(Error::Xray(_)) => {
                unlink_missing_ok(&self.generation_path(generation))?;
                let Some(previous) = previous_current else {
                    self.set_state("broken", None, MAX_START_FAILURES)?;
                    return Err(Error::Manual(format!(
                        "generation {generation} did not come up and there is no previous one"
                    )));
                };
                let previous_generation = generation_number(previous)?;
                match self.start_generation(inner, previous_generation) {
                    Ok(()) => {}
                    Err(Error::Xray(_)) => {
                        self.set_state("broken", None, MAX_START_FAILURES)?;
                        return Err(Error::Manual(format!(
                            "generation {generation} did not come up and generation {previous_generation} ({}) could not be restored",
                            self.generation_path(previous_generation).display()
                        )));
                    }
                    Err(other) => return Err(other),
                }
                self.set_state("idle", None, 0)?;
                Err(Error::Xray(format!(
                    "generation {generation} did not come up; generation {previous_generation} restored"
                )))
            }
            Err(other) => Err(other),
        }
    }

    // ------------------------------------------------------------------ exits

    /// Try one custom outbound: a throwaway Xray with a dokodemo-door on a loopback port to the
    /// trace host through that outbound, then one TLS fetch of the trace page through it. The
    /// running router is not touched. Returns what the far end saw of us.
    pub fn exit_test(&self, spec: &Value) -> Result<Value> {
        self.exit_test_with(spec, 8.0)
    }

    pub fn exit_test_with(&self, spec: &Value, timeout: f64) -> Result<Value> {
        let normalised = validate_exit(spec)?;
        let Ok(_busy) = self.exit_busy.try_lock() else {
            return Err(Error::conflict("an exit test is already running", "exit_test_busy"));
        };
        let started = Instant::now();
        let path = self.state_dir.join("exit-test.json");
        let mut handle = None;
        let result = self.run_exit_test(&normalised, &path, timeout, started, &mut handle);
        if let Some(handle) = handle {
            self.runner.stop(&handle);
        }
        unlink_missing_ok(&path)?;
        result
    }

    fn run_exit_test(
        &self,
        normalised: &Value,
        path: &Path,
        timeout: f64,
        started: Instant,
        handle: &mut Option<Handle>,
    ) -> Result<Value> {
        let latency = || started.elapsed().as_millis() as u64;
        let port = free_port()?;
        let config = json!({
            "log": {"access": "none", "loglevel": "warning"},
            "dns": {"servers": ["localhost"]},
            "inbounds": [{"tag": "probe", "listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
                          "settings": {"address": TRACE_HOST, "port": 443, "network": "tcp"}}],
            "outbounds": [render::exit_outbound("probe-exit", normalised), {"tag": "block", "protocol": "blackhole"}],
            "routing": {"rules": [{"inboundTag": ["probe"], "outboundTag": "probe-exit"}]},
        });
        atomic_write(path, &config_bytes(&config), 0o600)?;
        if let Err(err) = self.runner.test(path, None) {
            let Error::Xray(message) = err else { return Err(err) };
            let error = format!("xray refused the outbound: {message}");
            return Ok(json!({"ok": false, "error": first_chars(&error, 300), "code": "exit_invalid"}));
        }
        let start = self.runner.start(path, None).and_then(|started| {
            let ready = self.runner.wait_ready(&[i64::from(port)], timeout.min(5.0), &[]);
            *handle = Some(started);
            ready
        });
        if let Err(err) = start {
            let Error::Xray(message) = err else { return Err(err) };
            let error = format!("probe did not start: {message}");
            return Ok(json!({"ok": false, "error": first_chars(&error, 300), "code": "exit_test_failed"}));
        }
        match (self.exit_prober)(port, TRACE_HOST, timeout) {
            Err(text) => {
                let error = format!("no answer through the exit: {text}");
                Ok(
                    json!({"ok": false, "error": first_chars(&error, 300), "code": "exit_unreachable", "latency_ms": latency()}),
                )
            }
            Ok(result) => {
                let mut out = Map::new();
                out.insert("ok".into(), json!(true));
                out.extend(result.as_object().cloned().unwrap_or_default());
                out.insert("latency_ms".into(), json!(latency()));
                Ok(Value::Object(out))
            }
        }
    }

    // --------------------------------------------------------------- geodata

    pub fn geodata_view(&self) -> Value {
        self.geodata.view()
    }

    pub fn geodata_codes(&self) -> Value {
        json!({"codes": self.geodata.codes()})
    }

    pub fn geodata_settings(&self, body: &Map<String, Value>) -> Result<Value> {
        let source = match body.get("source") {
            Some(source) => Some(geodata::parse_source(source)?),
            None => None,
        };
        let auto = body.get("auto_update").filter(|value| !value.is_null());
        if auto.is_some_and(|auto| !auto.is_boolean()) {
            return Err(Error::geodata("auto_update must be a boolean", "geodata_invalid"));
        }
        let auto = auto.and_then(Value::as_bool);
        self.geodata.settings(source.as_ref(), auto, body.get("interval_hours"), body.get("update_hour"))
    }

    /// Fetch the source's pair, prove the running config still compiles against it, swap the files
    /// and restart the router on them. Serialised; the result view says `changed`.
    pub fn geodata_update(&self, fetcher: Option<&Fetcher>) -> Result<Value> {
        let Ok(_busy) = self.geodata_busy.try_lock() else {
            return Err(Error::conflict("a geodata update is already running", "geodata_busy"));
        };
        let default = self.fetcher.clone();
        let staged = match self.geodata.stage(fetcher.unwrap_or(default.as_ref())) {
            Ok(staged) => staged,
            Err(err) => {
                if matches!(err, Error::Geodata { .. }) {
                    self.geodata.record_failure(&err)?;
                }
                return Err(err);
            }
        };
        let Some(staged) = staged else {
            let mut view = self.geodata.view();
            view["changed"] = json!(false);
            return Ok(view);
        };
        self.install_geodata(&staged, "download")
    }

    /// Back to the installer's pinned pair — the source becomes `xray` again.
    pub fn geodata_restore(&self) -> Result<Value> {
        let Ok(_busy) = self.geodata_busy.try_lock() else {
            return Err(Error::conflict("a geodata update is already running", "geodata_busy"));
        };
        self.geodata.settings(Some(&Source::of("xray")), Some(false), None, None)?;
        let mut staged: StagedPair = Vec::new();
        for (name, path) in &self.geodata.seed {
            let (mut file, tmp) = crate::util::mkstemp(&self.geodata.directory, &format!("{name}."), ".dat.tmp")?;
            file.write_all(&fs::read(path)?)?;
            drop(file);
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
            staged.push((name.clone(), Staged { tmp, version: None }));
        }
        self.install_geodata(&staged, "seed")
    }

    fn install_geodata(&self, staged: &StagedPair, origin: &str) -> Result<Value> {
        let mut inner = self.lock();
        let current = self.current()?;
        let test_dir = self.geodata.staged_dir(staged)?;
        let tested = match &current {
            Some(current) => self.runner.test(&self.generation_path(generation_number(current)?), Some(&test_dir)),
            None => Ok(()),
        };
        let _ = fs::remove_dir_all(&test_dir);
        match tested {
            Ok(()) => {}
            Err(Error::Xray(message)) => {
                let text = format!("the running config does not compile against the new lists: {message}");
                let failure = Error::geodata(first_chars(&text, 300), "geodata_rejected");
                self.geodata.record_failure(&failure)?;
                return Err(failure);
            }
            Err(other) => return Err(other),
        }
        let view = match self.geodata.commit(staged, origin) {
            Ok(view) => view,
            Err(Error::Internal(message)) => {
                self.geodata.discard(staged);
                let failure = Error::geodata(
                    first_chars(&format!("could not install the lists: {message}"), 300),
                    "geodata_install_failed",
                );
                self.geodata.record_failure(&failure)?;
                return Err(failure);
            }
            Err(other) => return Err(other),
        };
        if let (Some(current), true) = (&current, inner.handle.is_some()) {
            // Xray reads the .dat files at start: the running process still holds the old ones.
            if let Some(handle) = inner.handle.take() {
                self.runner.stop(&handle);
            }
            if let Err(err) = self.start_generation(&mut inner, generation_number(current)?) {
                // The lists are in; the watchdog keeps restarting the router. Say so on the screen —
                // the container log shows nothing of it.
                let text = format!("lists installed, the router did not restart: {err}");
                self.geodata.record_failure(&Error::geodata(first_chars(&text, 300), "geodata_restart_failed"))?;
                return Err(err);
            }
        }
        let mut view = view;
        view["changed"] = json!(true);
        Ok(view)
    }

    /// Automatic updates at the configured interval; a failure is recorded and tried again after
    /// the interval. The download (up to minutes) runs in its own thread: the watchdog thread that
    /// calls this keeps restarting a dead Xray meanwhile.
    pub fn geodata_tick(self: &Arc<Self>) {
        if self.lock().artifact_error.is_some() || !self.geodata.due() {
            return;
        }
        let mut thread = self.geodata_thread.lock().unwrap_or_else(PoisonError::into_inner);
        if thread.as_ref().is_some_and(|running| !running.is_finished()) {
            return;
        }
        let manager = self.clone();
        let spawned = std::thread::Builder::new().name("geodata-update".into()).spawn(move || {
            match manager.geodata_update(None) {
                Ok(_) | Err(Error::Geodata { .. } | Error::Conflict { .. } | Error::Xray(_) | Error::Manual(_)) => {}
                Err(other) => log::warn!("geodata update failed: {other}"),
            }
        });
        match spawned {
            Ok(handle) => *thread = Some(handle),
            Err(_) => log::warn!("cannot start the geodata update thread"),
        }
    }

    /// Waits for an automatic update the watchdog started (tests, shutdown).
    pub fn join_geodata_thread(&self) {
        let handle = self.geodata_thread.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}
