//! The manager core: instances per protocol version, peers, reconciliation.

use std::sync::{Mutex, MutexGuard, PoisonError};

use indexmap::IndexMap;
use pc_common::ApiError;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::config::{interface_name, Config, KNOWN_VERSIONS};
use crate::egress::Egress;
use crate::host::{Host, Proc};
use crate::ipnet::{format_v4, parse_v4, Ipv4Net};
use crate::keys::{b64, hex, hexkey, public_key, unb64};
use crate::obfuscation::{self, Params, Rng};
use crate::state::{StateError, StateStore};
use crate::warp::Opener;

pub const FULL_RECONCILE_SECONDS: f64 = 30.0;
pub const DEVICE_READY_SECONDS: f64 = 10.0;
pub const MAX_BACKOFF_SECONDS: f64 = 30.0;
pub const STABLE_SECONDS: f64 = 60.0;
pub const ZERO_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub type Clock = Box<dyn Fn() -> f64 + Send + Sync>;
pub type Sleep = Box<dyn Fn(f64) + Send + Sync>;

/// `min(30, 2 ** (failures - 1))`.
pub fn backoff(failures: u32) -> f64 {
    MAX_BACKOFF_SECONDS.min(2f64.powi(failures.saturating_sub(1).min(16) as i32))
}

/// One amneziawg-go server: a protocol version on its interface, port and subnet.
pub struct Instance {
    pub version: String,
    pub iface: String,
    pub port: u16,
    pub subnet: Ipv4Net,
    pub process: Option<Box<dyn Proc>>,
    pub configured: bool,
    pub dirty: bool,
    pub failures: u32,
    pub started_at: f64,
    pub next_start: f64,
    pub last_full: f64,
}

impl Instance {
    pub fn gateway(&self) -> String {
        format_v4(self.subnet.gateway())
    }
}

pub fn peer_lines(pub_hex: &str, psk_hex: &str, address: &str) -> Vec<String> {
    vec![
        format!("public_key={pub_hex}"),
        format!("preshared_key={psk_hex}"),
        "replace_allowed_ips=true".into(),
        format!("allowed_ip={address}/32"),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePeer {
    pub allowed_ips: Vec<String>,
    pub preshared_key: String,
    pub rx: i64,
    pub tx: i64,
    pub handshake: i64,
}

/// Split a `get=1` reply into device keys and peers keyed by hex public key.
pub fn parse_uapi(text: &str) -> (IndexMap<String, String>, IndexMap<String, LivePeer>) {
    let mut device = IndexMap::new();
    let mut peers: IndexMap<String, LivePeer> = IndexMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        if key == "public_key" {
            peers.insert(
                value.to_string(),
                LivePeer { allowed_ips: Vec::new(), preshared_key: ZERO_KEY.into(), rx: 0, tx: 0, handshake: 0 },
            );
            current = Some(value.to_string());
            continue;
        }
        let Some(peer) = current.as_ref().and_then(|name| peers.get_mut(name)) else {
            device.insert(key.to_string(), value.to_string());
            continue;
        };
        match key {
            "allowed_ip" => peer.allowed_ips.push(value.to_string()),
            "preshared_key" => peer.preshared_key = value.to_string(),
            "rx_bytes" | "tx_bytes" | "last_handshake_time_sec" => {
                if let Some(number) = crate::util::parse_int(value, 10) {
                    match key {
                        "rx_bytes" => peer.rx = number,
                        "tx_bytes" => peer.tx = number,
                        _ => peer.handshake = number,
                    }
                }
            }
            _ => {}
        }
    }
    (device, peers)
}

/// `[a-z0-9][a-z0-9._-]{0,63}`.
fn is_username(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

/// `[A-Za-z0-9._:-]{1,128}`.
pub fn is_operation_id(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn invalid(detail: &str) -> ApiError {
    ApiError::invalid_request(detail)
}

fn str_field<'a>(rec: &'a Value, key: &str) -> &'a str {
    rec.get(key).and_then(Value::as_str).unwrap_or("")
}

/// What the manager is built from; tests replace the clocks, the randomness and the WARP API.
pub struct Options {
    pub overrides: IndexMap<String, Params>,
    pub clock: Clock,
    pub wall: Clock,
    pub rng: Box<dyn Rng>,
    pub warp_opener: Opener,
    pub sleep: Option<Sleep>,
    pub generate_private: fn() -> [u8; 32],
}

impl Options {
    pub fn production(overrides: IndexMap<String, Params>) -> Self {
        let started = std::time::Instant::now();
        Self {
            overrides,
            clock: Box::new(move || started.elapsed().as_secs_f64()),
            wall: Box::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0)
            }),
            rng: Box::new(obfuscation::SystemRng),
            warp_opener: crate::warp::https_opener(),
            sleep: None,
            generate_private: crate::keys::generate_private,
        }
    }
}

pub struct Inner {
    pub store: StateStore,
    /// In the configured version order.
    pub instances: Vec<Instance>,
    pub last_nft: f64,
    pub egress: Egress,
    rng: Box<dyn Rng>,
}

impl Inner {
    pub fn instance_index(&self, version: &str) -> Option<usize> {
        self.instances.iter().position(|inst| inst.version == version)
    }
}

pub struct AwgManager {
    pub config: Config,
    pub host: Box<dyn Host>,
    pub clock: Clock,
    pub wall: Clock,
    pub opener: Opener,
    pub sleep: Option<Sleep>,
    overrides: IndexMap<String, Params>,
    generate_private: fn() -> [u8; 32],
    inner: Mutex<Inner>,
}

impl AwgManager {
    pub fn new(config: Config, host: Box<dyn Host>, options: Options) -> Self {
        let instances = config
            .versions
            .iter()
            .map(|v| Instance {
                version: v.clone(),
                iface: interface_name(v),
                port: config.ports[v],
                subnet: config.subnets[v],
                process: None,
                configured: false,
                dirty: true,
                failures: 0,
                started_at: 0.0,
                next_start: 0.0,
                last_full: 0.0,
            })
            .collect();
        Self {
            inner: Mutex::new(Inner {
                store: StateStore::new(&config.state_dir),
                instances,
                last_nft: 0.0,
                egress: Egress::default(),
                rng: options.rng,
            }),
            config,
            host,
            clock: options.clock,
            wall: options.wall,
            opener: options.warp_opener,
            sleep: options.sleep,
            overrides: options.overrides,
            generate_private: options.generate_private,
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panicking request must not take the manager down with it: the state stays usable.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ----- lifecycle -------------------------------------------------------------------

    pub fn bootstrap(&self) -> Result<(), StateError> {
        let mut inner = self.lock();
        inner.store.load()?;
        self.egress_load(&mut inner)?;
        let mut changed = false;
        for version in &self.config.versions {
            changed |= self.ensure_instance_state(&mut inner, version)?;
        }
        // A peer stored for an enabled version must still fit its subnet.
        for (name, rec) in inner.store.peers() {
            let Some(idx) = inner.instance_index(str_field(rec, "version")) else { continue };
            let address = parse_v4(str_field(rec, "address"));
            if !address.is_some_and(|address| inner.instances[idx].subnet.contains(address)) {
                return Err(StateError(format!("peer {name} address is outside the configured subnet")));
            }
        }
        if changed {
            inner.store.save().map_err(|err| StateError(format!("cannot write state: {err}")))?;
        }
        self.apply_nft(&mut inner);
        self.tick_locked(&mut inner);
        Ok(())
    }

    fn ensure_instance_state(&self, inner: &mut Inner, version: &str) -> Result<bool, StateError> {
        let mtu = self.config.mtu;
        if let Some(existing) = inner.store.instances().get(version) {
            let checked = (|| -> Result<(), String> {
                let params = obfuscation::from_value(existing.get("obfuscation").ok_or("'obfuscation'")?)
                    .map_err(|err| err.0)?;
                obfuscation::validate(version, &params, mtu).map_err(|err| err.0)?;
                let private = unb64(existing.get("private_key").and_then(Value::as_str).ok_or("'private_key'")?)
                    .map_err(|err| err.0.to_string())?;
                if Some(b64(&public_key(&private)).as_str()) != existing.get("public_key").and_then(Value::as_str) {
                    return Err("key pair mismatch".into());
                }
                Ok(())
            })();
            return checked
                .map(|()| false)
                .map_err(|err| StateError(format!("stored instance {version} is invalid: {err}")));
        }
        let private = (self.generate_private)();
        let generated = obfuscation::generate(version, mtu, inner.rng.as_mut())
            .and_then(|params| match self.overrides.get(version) {
                Some(overrides) => obfuscation::apply_overrides(version, &params, overrides, mtu),
                None => Ok(params),
            })
            .map_err(|err| StateError(format!("obfuscation for {version}: {err}")))?;
        inner.store.instances_mut().insert(
            version.to_string(),
            json!({
                "private_key": b64(&private),
                "public_key": b64(&public_key(&private)),
                "obfuscation": obfuscation::to_value(&generated),
                "created_at": (self.wall)() as i64,
            }),
        );
        Ok(true)
    }

    pub fn shutdown(&self) {
        let mut inner = self.lock();
        for inst in &mut inner.instances {
            inst.configured = false;
            let Some(mut proc) = inst.process.take() else { continue };
            proc.terminate();
            if proc.wait(std::time::Duration::from_secs(5)).is_err() {
                proc.kill();
            }
        }
        self.egress_teardown(&mut inner);
        self.host.nft_delete();
    }

    // ----- supervision -----------------------------------------------------------------

    /// One supervision pass: restart dead processes, configure, reconcile periodically.
    pub fn tick(&self) {
        let mut inner = self.lock();
        self.tick_locked(&mut inner);
    }

    fn tick_locked(&self, inner: &mut Inner) {
        let now = (self.clock)();
        for idx in 0..inner.instances.len() {
            // One instance must not stop the others.
            if let Err(err) = self.supervise(inner, idx, now) {
                log::error!("supervision of {} failed: {err}", inner.instances[idx].iface);
            }
        }
        if now - inner.last_nft >= FULL_RECONCILE_SECONDS {
            self.apply_nft(inner);
        }
        // The egress must not stop the tunnels.
        if let Err(err) = self.egress_converge(inner, now, false) {
            log::error!("egress supervision failed: {err}");
        }
    }

    fn supervise(&self, inner: &mut Inner, idx: usize, now: f64) -> Result<(), String> {
        let inst = &mut inner.instances[idx];
        if let Some(code) = inst.process.as_mut().and_then(|proc| proc.poll()) {
            log::warn!("{} exited with {code}", inst.iface);
            if now - inst.started_at > STABLE_SECONDS {
                inst.failures = 0;
            }
            inst.failures += 1;
            inst.process = None;
            inst.configured = false;
            inst.next_start = now + backoff(inst.failures);
        }
        if inst.process.is_none() {
            if now < inst.next_start {
                return Ok(());
            }
            match self.host.start_process(&inst.iface, &self.config.log_level) {
                Err(err) => {
                    inst.failures += 1;
                    inst.next_start = now + backoff(inst.failures);
                    log::error!("cannot start {}: {err}", inst.iface);
                    return Ok(());
                }
                Ok(proc) => {
                    inst.process = Some(proc);
                    inst.started_at = now;
                    inst.configured = false;
                    inst.dirty = true;
                }
            }
        }
        let inst = &inner.instances[idx];
        if !inst.configured {
            self.configure(inner, idx, now)
        } else if inst.dirty || now - inst.last_full >= FULL_RECONCILE_SECONDS {
            self.reconcile_peers(inner, idx, now)
        } else {
            Ok(())
        }
    }

    pub fn device_lines(&self, inner: &Inner, idx: usize) -> Result<Vec<String>, String> {
        let inst = &inner.instances[idx];
        let stored = &inner.store.instances()[inst.version.as_str()];
        let private = hexkey(str_field(stored, "private_key")).map_err(|err| err.to_string())?;
        let params = obfuscation::from_value(&stored["obfuscation"]).map_err(|err| err.0)?;
        let mut lines = vec![format!("private_key={private}"), format!("listen_port={}", inst.port)];
        lines.extend(obfuscation::uapi_lines(&params).map_err(|err| err.to_string())?);
        Ok(lines)
    }

    fn configure(&self, inner: &mut Inner, idx: usize, now: f64) -> Result<(), String> {
        let body = self.device_lines(inner, idx)?.join("\n") + "\n";
        let inst = &mut inner.instances[idx];
        if let Err(err) = self.host.uapi_set(&inst.iface, &body) {
            if now - inst.started_at > DEVICE_READY_SECONDS {
                log::error!("{} control socket not usable ({err}); restarting", inst.iface);
                if let Some(proc) = inst.process.as_mut() {
                    proc.kill();
                }
            }
            return Ok(());
        }
        let address = format!("{}/{}", inst.gateway(), inst.subnet.prefix);
        let mtu = self.config.mtu.to_string();
        let set_up = self
            .host
            .ip(&["addr", "replace", &address, "dev", &inst.iface])
            .and_then(|()| self.host.ip(&["link", "set", &inst.iface, "mtu", &mtu, "up"]));
        if let Err(err) = set_up {
            log::error!("cannot set up {}: {err}", inst.iface);
            return Ok(());
        }
        inst.configured = true;
        self.reconcile_peers(inner, idx, now)
    }

    /// The enabled peers of a version: hex public key -> (hex preshared key, address).
    fn desired(inner: &Inner, version: &str) -> Result<IndexMap<String, (String, String)>, String> {
        let mut out = IndexMap::new();
        for rec in inner.store.peers().values() {
            if str_field(rec, "version") == version && rec.get("enabled") == Some(&Value::Bool(true)) {
                let public = hexkey(str_field(rec, "public_key")).map_err(|err| err.to_string())?;
                let psk = hexkey(str_field(rec, "preshared_key")).map_err(|err| err.to_string())?;
                out.insert(public, (psk, str_field(rec, "address").to_string()));
            }
        }
        Ok(out)
    }

    fn reconcile_peers(&self, inner: &mut Inner, idx: usize, now: f64) -> Result<(), String> {
        let iface = inner.instances[idx].iface.clone();
        let live = match self.host.uapi_get(&iface) {
            Ok(text) => parse_uapi(&text).1,
            Err(err) => {
                log::warn!("{iface} reconcile failed: {err}");
                inner.instances[idx].configured = false; // the process may be gone or wedged: configure again
                return Ok(());
            }
        };
        let desired = Self::desired(inner, &inner.instances[idx].version)?;
        let mut lines = Vec::new();
        for public in live.keys() {
            if !desired.contains_key(public) {
                lines.extend([format!("public_key={public}"), "remove=true".to_string()]);
            }
        }
        for (public, (psk, address)) in &desired {
            let have = live.get(public);
            let wanted = [format!("{address}/32")];
            if have.is_none_or(|peer| &peer.preshared_key != psk || peer.allowed_ips != wanted) {
                lines.extend(peer_lines(public, psk, address));
            }
        }
        let inst = &mut inner.instances[idx];
        if !lines.is_empty() {
            if let Err(err) = self.host.uapi_set(&iface, &(lines.join("\n") + "\n")) {
                log::warn!("{iface} reconcile failed: {err}");
                inst.configured = false;
                return Ok(());
            }
        }
        inst.dirty = false;
        inst.last_full = now;
        Ok(())
    }

    pub(crate) fn apply_nft(&self, inner: &mut Inner) {
        inner.last_nft = (self.clock)();
        let names: Vec<String> = inner.instances.iter().map(|inst| format!("\"{}\"", inst.iface)).collect();
        let rules = if self.config.nat {
            inner
                .instances
                .iter()
                .map(|inst| format!("    ip saddr {} oifname != \"{}\" masquerade", inst.subnet, inst.iface))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            String::new()
        };
        let names = names.join(", ");
        let script = format!(
            "table inet awg_manager\n\
             delete table inet awg_manager\n\
             table inet awg_manager {{\n  \
             chain forward {{\n    \
             type filter hook forward priority 0; policy accept;\n    \
             iifname {{ {names} }} accept\n    \
             oifname {{ {names} }} accept\n  \
             }}\n  \
             chain postrouting {{\n    \
             type nat hook postrouting priority srcnat; policy accept;\n\
             {rules}\n  \
             }}\n\
             }}\n"
        );
        if let Err(err) = self.host.nft_apply(&script) {
            log::error!("nft apply failed: {err}");
        }
    }

    /// Best effort live apply; the state is the truth and the next tick converges.
    fn live_change(&self, inner: &mut Inner, idx: Option<usize>, lines: &[String]) {
        let Some(inst) = idx.map(|idx| &mut inner.instances[idx]) else { return };
        if !inst.configured || lines.is_empty() {
            return;
        }
        if let Err(err) = self.host.uapi_set(&inst.iface, &(lines.join("\n") + "\n")) {
            log::warn!("{} live update failed: {err}", inst.iface);
            inst.dirty = true;
        }
    }

    // ----- views -----------------------------------------------------------------------

    fn instance_view(&self, inner: &Inner, idx: usize) -> Value {
        let inst = &inner.instances[idx];
        let stored = &inner.store.instances()[inst.version.as_str()];
        let params = obfuscation::from_value(&stored["obfuscation"]).unwrap_or_default();
        json!({
            "version": inst.version,
            "interface": inst.iface,
            "port": inst.port,
            "server_public_key": stored["public_key"],
            "gateway": inst.gateway(),
            "subnet": inst.subnet.to_string(),
            "mtu": self.config.mtu,
            "dns": self.config.dns,
            "obfuscation": obfuscation::to_value(&obfuscation::client_view(&params)),
        })
    }

    fn stats(&self, inner: &Inner, idx: Option<usize>) -> IndexMap<String, LivePeer> {
        let Some(inst) = idx.map(|idx| &inner.instances[idx]) else { return IndexMap::new() };
        if !inst.configured {
            return IndexMap::new();
        }
        self.host.uapi_get(&inst.iface).map(|text| parse_uapi(&text).1).unwrap_or_default()
    }

    fn peer_view(name: &str, rec: &Value, stats: &IndexMap<String, LivePeer>) -> Value {
        let live = hexkey(str_field(rec, "public_key")).ok().and_then(|public| stats.get(&public));
        json!({
            "username": name,
            "version": rec.get("version"),
            "enabled": rec.get("enabled"),
            "address": rec.get("address"),
            "public_key": rec.get("public_key"),
            "revision": rec.get("revision"),
            "rx": live.map_or(0, |peer| peer.rx),
            "tx": live.map_or(0, |peer| peer.tx),
            "latest_handshake": live.map(|peer| peer.handshake).filter(|handshake| *handshake != 0),
        })
    }

    pub fn health(&self) -> Value {
        let mut inner = self.lock();
        let forward = self.host.ip_forward_enabled();
        let mut out = Map::new();
        let mut ok = forward;
        for idx in 0..inner.instances.len() {
            let inst = &mut inner.instances[idx];
            let alive = inst.process.as_mut().is_some_and(|proc| proc.poll().is_none());
            let running = alive && inst.configured;
            ok &= running;
            let (version, iface, port) = (inst.version.clone(), inst.iface.clone(), inst.port);
            let peers = inner.store.peers().values().filter(|rec| str_field(rec, "version") == version).count();
            out.insert(version, json!({"interface": iface, "running": running, "port": port, "peers": peers}));
        }
        // The egress is reported beside the status, not folded into it: a WARP tunnel without a
        // handshake keeps the clients' traffic dropped (fail-closed), the tunnels themselves run.
        let egress = self.egress_health(&mut inner);
        json!({"status": if ok { "ok" } else { "degraded" }, "ip_forward": forward, "instances": out, "egress": egress})
    }

    pub fn list_instances(&self) -> Value {
        let inner = self.lock();
        let views: Vec<Value> = (0..inner.instances.len()).map(|idx| self.instance_view(&inner, idx)).collect();
        json!({"instances": views})
    }

    pub fn list_peers(&self) -> Value {
        let inner = self.lock();
        let stats: IndexMap<String, IndexMap<String, LivePeer>> = (0..inner.instances.len())
            .map(|idx| (inner.instances[idx].version.clone(), self.stats(&inner, Some(idx))))
            .collect();
        let mut names: Vec<&String> = inner.store.peers().keys().collect();
        names.sort();
        let empty = IndexMap::new();
        let peers: Vec<Value> = names
            .into_iter()
            .map(|name| {
                let rec = &inner.store.peers()[name.as_str()];
                Self::peer_view(name, rec, stats.get(str_field(rec, "version")).unwrap_or(&empty))
            })
            .collect();
        json!({"peers": peers})
    }

    // ----- egress (v3.0.0) -----------------------------------------------------------

    pub fn egress_view(&self) -> Value {
        let mut inner = self.lock();
        self.egress_view_locked(&mut inner)
    }

    pub fn egress_plan(&self, body: &Map<String, Value>) -> Result<Value, ApiError> {
        Self::fields(body, &["expected_revision", "document"])?;
        let mut inner = self.lock();
        self.egress_plan_locked(&mut inner, &body["expected_revision"], &body["document"])
    }

    pub fn egress_apply(&self, body: &Map<String, Value>) -> Result<Value, ApiError> {
        Self::fields(body, &["expected_revision", "document", "operation_id"])?;
        let mut inner = self.lock();
        self.egress_apply_locked(&mut inner, &body["expected_revision"], &body["document"], &body["operation_id"])
    }

    pub fn egress_rollback(&self, body: &Map<String, Value>) -> Result<Value, ApiError> {
        Self::fields(body, &["expected_revision"])?;
        let mut inner = self.lock();
        self.egress_rollback_locked(&mut inner, &body["expected_revision"])
    }

    // ----- peer operations -------------------------------------------------------------

    fn instance(inner: &Inner, version: &Value) -> Result<usize, ApiError> {
        let version = match version.as_str() {
            Some(version) if KNOWN_VERSIONS.contains(&version) => version,
            _ => return Err(ApiError::new(422, "unknown_version", "unknown protocol version")),
        };
        inner
            .instance_index(version)
            .ok_or_else(|| ApiError::new(409, "version_disabled", "protocol version is not enabled on this node"))
    }

    pub(crate) fn fields(body: &Map<String, Value>, required: &[&str]) -> Result<(), ApiError> {
        if body.len() != required.len() || !required.iter().all(|key| body.contains_key(*key)) {
            return Err(invalid("invalid request fields"));
        }
        Ok(())
    }

    fn operation_id(value: &Value) -> Result<String, ApiError> {
        match value.as_str() {
            Some(op) if is_operation_id(op) => Ok(op.to_string()),
            _ => Err(invalid("invalid operation_id")),
        }
    }

    fn key(value: &Value, name: &str) -> Result<String, ApiError> {
        let text = value.as_str().ok_or_else(|| invalid(&format!("invalid {name}")))?;
        let raw = unb64(text).map_err(|_| invalid(&format!("invalid {name}")))?;
        if raw.iter().all(|b| *b == 0) {
            return Err(invalid(&format!("invalid {name}")));
        }
        Ok(text.to_string())
    }

    fn digest(kind: &str, fields: &[(&str, &str)]) -> String {
        let mut blob = Map::new();
        blob.insert("kind".into(), json!(kind));
        for (key, value) in fields {
            blob.insert(key.to_string(), json!(value));
        }
        hex(&Sha256::digest(crate::pyjson::canonical(&Value::Object(blob)).as_bytes()))
    }

    fn commit(&self, inner: &mut Inner, mutate: impl FnOnce(&mut StateStore)) -> Result<(), ApiError> {
        let snapshot = inner.store.doc.clone();
        mutate(&mut inner.store);
        if let Err(err) = inner.store.save() {
            inner.store.doc = snapshot;
            log::error!("manager operation failed: cannot write state ({err})");
            return Err(ApiError::internal());
        }
        Ok(())
    }

    /// The username of an identical earlier operation, or None for a new one.
    fn replayed(inner: &Inner, op_id: &str, digest: &str) -> Result<Option<String>, ApiError> {
        let Some(known) = inner.store.operations().get(op_id) else { return Ok(None) };
        if str_field(known, "digest") != digest {
            return Err(ApiError::new(409, "operation_conflict", "operation id was used with a different request"));
        }
        let username = str_field(known, "username");
        Ok(inner.store.peers().contains_key(username).then(|| username.to_string()))
    }

    fn free_address(inner: &Inner, idx: usize) -> Result<String, ApiError> {
        let inst = &inner.instances[idx];
        let used: Vec<&str> = inner
            .store
            .peers()
            .values()
            .filter(|rec| str_field(rec, "version") == inst.version)
            .map(|rec| str_field(rec, "address"))
            .collect();
        inst.subnet
            .hosts()
            .skip(1)
            .map(format_v4)
            .find(|address| !used.contains(&address.as_str()))
            .ok_or_else(|| ApiError::new(409, "address_pool_exhausted", "no free address in the subnet"))
    }

    fn pubkey_taken(inner: &Inner, version: &str, public: &str, except_user: Option<&str>) -> bool {
        inner.store.peers().iter().any(|(name, rec)| {
            str_field(rec, "version") == version
                && str_field(rec, "public_key") == public
                && Some(name.as_str()) != except_user
        })
    }

    pub fn create_peer(&self, body: &Map<String, Value>) -> Result<(u16, Value), ApiError> {
        Self::fields(body, &["operation_id", "username", "version", "public_key", "preshared_key"])?;
        let op_id = Self::operation_id(&body["operation_id"])?;
        let username = match body["username"].as_str() {
            Some(name) if is_username(name) => name.to_string(),
            _ => return Err(invalid("invalid username")),
        };
        let public = Self::key(&body["public_key"], "public_key")?;
        let psk = Self::key(&body["preshared_key"], "preshared_key")?;
        let mut inner = self.lock();
        let idx = Self::instance(&inner, &body["version"])?;
        let version = inner.instances[idx].version.clone();
        let digest =
            Self::digest("create", &[("username", &username), ("version", &version), ("pub", &public), ("psk", &psk)]);
        if let Some(again) = Self::replayed(&inner, &op_id, &digest)? {
            return Ok((200, self.peer_response(&inner, &again, idx)));
        }
        if inner.store.peers().contains_key(&username) {
            return Err(ApiError::new(409, "username_taken", "username already exists"));
        }
        if Self::pubkey_taken(&inner, &version, &public, None) {
            return Err(ApiError::new(409, "public_key_in_use", "public key already in use"));
        }
        let address = Self::free_address(&inner, idx)?;
        let record = json!({
            "version": version,
            "public_key": public,
            "preshared_key": psk,
            "address": address,
            "enabled": true,
            "revision": 1,
            "created_at": (self.wall)() as i64,
            "operation_id": op_id,
        });
        self.commit(&mut inner, |store| {
            store.peers_mut().insert(username.clone(), record);
            store.operations_mut().insert(op_id.clone(), json!({"digest": digest, "username": username}));
        })?;
        let lines = peer_lines(&hexkey(&public).expect("validated"), &hexkey(&psk).expect("validated"), &address);
        self.live_change(&mut inner, Some(idx), &lines);
        Ok((201, self.peer_response(&inner, &username, idx)))
    }

    fn peer_response(&self, inner: &Inner, username: &str, idx: usize) -> Value {
        let rec = &inner.store.peers()[username];
        json!({
            "peer": Self::peer_view(username, rec, &self.stats(inner, Some(idx))),
            "instance": self.instance_view(inner, idx),
        })
    }

    fn record(inner: &Inner, username: &str) -> Result<Value, ApiError> {
        inner.store.peers().get(username).cloned().ok_or_else(|| ApiError::new(404, "not_found", "peer not found"))
    }

    fn peer_result(&self, inner: &Inner, username: &str, idx: Option<usize>) -> Value {
        let rec = &inner.store.peers()[username];
        json!({"peer": Self::peer_view(username, rec, &self.stats(inner, idx))})
    }

    pub fn set_enabled(&self, username: &str, enabled: bool) -> Result<Value, ApiError> {
        let mut inner = self.lock();
        let rec = Self::record(&inner, username)?;
        let idx = inner.instance_index(str_field(&rec, "version"));
        if enabled && idx.is_none() {
            return Err(ApiError::new(409, "version_disabled", "protocol version is not enabled on this node"));
        }
        if rec.get("enabled") != Some(&Value::Bool(enabled)) {
            self.commit(&mut inner, |store| {
                let rec = &mut store.peers_mut()[username];
                rec["enabled"] = json!(enabled);
                let revision = rec["revision"].as_i64().unwrap_or(0) + 1;
                rec["revision"] = json!(revision);
            })?;
            let (public, psk) = (hexkey(str_field(&rec, "public_key")), hexkey(str_field(&rec, "preshared_key")));
            let lines = match (public, psk) {
                (Ok(public), Ok(psk)) if enabled => peer_lines(&public, &psk, str_field(&rec, "address")),
                (Ok(public), _) if !enabled => vec![format!("public_key={public}"), "remove=true".into()],
                _ => Vec::new(),
            };
            self.live_change(&mut inner, idx, &lines);
        }
        Ok(self.peer_result(&inner, username, idx))
    }

    pub fn rotate(&self, username: &str, body: &Map<String, Value>) -> Result<Value, ApiError> {
        Self::fields(body, &["operation_id", "public_key", "preshared_key"])?;
        let op_id = Self::operation_id(&body["operation_id"])?;
        let public = Self::key(&body["public_key"], "public_key")?;
        let psk = Self::key(&body["preshared_key"], "preshared_key")?;
        let mut inner = self.lock();
        let rec = Self::record(&inner, username)?;
        let version = str_field(&rec, "version").to_string();
        let idx = inner.instance_index(&version);
        let digest = Self::digest("rotate", &[("username", username), ("pub", &public), ("psk", &psk)]);
        if Self::replayed(&inner, &op_id, &digest)?.is_some() {
            return Ok(self.peer_result(&inner, username, idx));
        }
        if Self::pubkey_taken(&inner, &version, &public, Some(username)) {
            return Err(ApiError::new(409, "public_key_in_use", "public key already in use"));
        }
        let old_public = hexkey(str_field(&rec, "public_key")).map_err(|_| ApiError::internal())?;
        self.commit(&mut inner, |store| {
            let rec = &mut store.peers_mut()[username];
            rec["public_key"] = json!(public);
            rec["preshared_key"] = json!(psk);
            rec["operation_id"] = json!(op_id);
            let revision = rec["revision"].as_i64().unwrap_or(0) + 1;
            rec["revision"] = json!(revision);
            store.operations_mut().insert(op_id.clone(), json!({"digest": digest, "username": username}));
        })?;
        let mut lines = vec![format!("public_key={old_public}"), "remove=true".to_string()];
        if rec.get("enabled") == Some(&Value::Bool(true)) {
            lines.extend(peer_lines(
                &hexkey(&public).expect("validated"),
                &hexkey(&psk).expect("validated"),
                str_field(&rec, "address"),
            ));
        }
        self.live_change(&mut inner, idx, &lines);
        Ok(self.peer_result(&inner, username, idx))
    }

    pub fn delete_peer(&self, username: &str) -> Result<(), ApiError> {
        let mut inner = self.lock();
        let rec = Self::record(&inner, username)?;
        let idx = inner.instance_index(str_field(&rec, "version"));
        self.commit(&mut inner, |store| {
            store.peers_mut().shift_remove(username);
        })?;
        if rec.get("enabled") == Some(&Value::Bool(true)) {
            if let Ok(public) = hexkey(str_field(&rec, "public_key")) {
                self.live_change(&mut inner, idx, &[format!("public_key={public}"), "remove=true".into()]);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uapi_splits_device_and_peers() {
        let text = "private_key=aa\nlisten_port=1\npublic_key=bb\npreshared_key=cc\nrx_bytes=5\ntx_bytes=6\n\
                    last_handshake_time_sec=9\nallowed_ip=10.0.0.2/32\n";
        let (device, peers) = parse_uapi(text);
        assert_eq!(
            device,
            IndexMap::from([
                ("private_key".to_string(), "aa".to_string()),
                ("listen_port".to_string(), "1".to_string())
            ])
        );
        assert_eq!(
            peers["bb"],
            LivePeer {
                allowed_ips: vec!["10.0.0.2/32".into()],
                preshared_key: "cc".into(),
                rx: 5,
                tx: 6,
                handshake: 9
            }
        );
    }

    #[test]
    fn names_and_operation_ids() {
        for good in ["a", "alice", "0x", "a.b_c-d", &"x".repeat(64)] {
            assert!(is_username(good), "{good}");
        }
        for bad in ["", "Bad Name", "-lead", "Alice", &"x".repeat(65), ".a"] {
            assert!(!is_username(bad), "{bad}");
        }
        assert!(is_operation_id("routing:attach:amneziawg:1792488535374:native"));
        assert!(!is_operation_id("has space") && !is_operation_id("") && !is_operation_id(&"o".repeat(129)));
    }

    #[test]
    fn backoff_doubles_up_to_thirty_seconds() {
        assert_eq!([1, 2, 3, 5, 6, 40].map(backoff), [1.0, 2.0, 4.0, 16.0, 30.0, 30.0]);
    }
}
