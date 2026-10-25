//! The manager core: client credentials, endpoint settings, restart coalescing, counters.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use base64::Engine;
use pc_common::ApiError;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::cert::{hex, inspect_certificate};
use crate::config::Config;
use crate::metrics;
use crate::state::{Client, EgressDocument, Operation, StateError, StateStore};
use crate::supervisor::Supervisor;

const MAX_BACKOFF_SECONDS: f64 = 30.0;
/// The endpoint panics on a credentials file without clients, so one internal client is always
/// present. It is never exposed, counted or reported.
pub const PLACEHOLDER_USERNAME: &str = "proxy-control-idle";
const CERT_CHECK_SECONDS: f64 = 60.0;

pub type Fetch = Box<dyn Fn() -> Option<Vec<Value>> + Send + Sync>;
pub type Clock = Box<dyn Fn() -> f64 + Send + Sync>;

/// A TOML basic string: only backslash, quote and control characters need escaping.
pub fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn chars_in(text: &str, range: std::ops::RangeInclusive<usize>, allowed: impl Fn(u8) -> bool) -> bool {
    range.contains(&text.len()) && text.bytes().all(allowed)
}

pub fn is_username(text: &str) -> bool {
    chars_in(text, 1..=64, |b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn is_password(text: &str) -> bool {
    chars_in(text, 8..=128, |b| (0x21..=0x7e).contains(&b))
}

fn is_operation_id(text: &str) -> bool {
    chars_in(text, 1..=128, |b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn is_egress_address(text: &str) -> bool {
    text.strip_prefix("127.0.0.1:").is_some_and(|port| {
        (4..=5).contains(&port.len())
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u32>().is_ok_and(|p| (1024..=65535).contains(&p))
    })
}

pub fn egress_revision(document: &EgressDocument) -> String {
    let canonical = json!({"mode": document.mode, "address": document.address}).to_string();
    hex(&Sha256::digest(canonical.as_bytes()))
}

fn egress_view(document: &EgressDocument) -> Value {
    json!({"mode": document.mode, "address": document.address, "revision": egress_revision(document)})
}

fn invalid(detail: &str) -> ApiError {
    ApiError::invalid_request(detail)
}

pub fn normalize_egress(body: &Map<String, Value>) -> Result<EgressDocument, ApiError> {
    if body.keys().any(|key| key != "mode" && key != "address") {
        return Err(invalid("invalid request fields"));
    }
    let address = body.get("address").unwrap_or(&Value::Null);
    match body.get("mode").and_then(Value::as_str) {
        Some("direct") => {
            if !(address.is_null() || address.as_str() == Some("")) {
                return Err(invalid("direct mode takes no address"));
            }
            Ok(EgressDocument::direct())
        }
        Some("socks5") => match address.as_str() {
            Some(address) if is_egress_address(address) => {
                Ok(EgressDocument { mode: "socks5".into(), address: Some(address.into()) })
            }
            _ => Err(invalid("address must be 127.0.0.1:PORT")),
        },
        _ => Err(invalid("mode must be direct or socks5")),
    }
}

fn check_fields(body: &Map<String, Value>, allowed: &[&str]) -> Result<(), ApiError> {
    if body.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("invalid request fields"));
    }
    Ok(())
}

fn operation_id(body: &Map<String, Value>) -> Result<String, ApiError> {
    match body.get("operation_id").and_then(Value::as_str) {
        Some(op) if is_operation_id(op) => Ok(op.into()),
        _ => Err(invalid("invalid operation_id")),
    }
}

fn password(body: &Map<String, Value>) -> Result<String, ApiError> {
    match body.get("password").and_then(Value::as_str) {
        Some(password) if is_password(password) => Ok(password.into()),
        _ => Err(invalid("invalid password")),
    }
}

fn fingerprint(kind: &str, username: &str, password: &str) -> String {
    hex(&Sha256::digest(format!("{kind}\0{username}\0{password}").as_bytes()))
}

/// What a failed state or settings write answers: the caller sees only that it failed.
fn write_failed(err: std::io::Error) -> ApiError {
    log::error!("manager operation failed: cannot write state ({:?})", err.kind());
    ApiError::internal()
}

struct Inner {
    store: StateStore,
    supervisor: Box<dyn Supervisor>,
    restart_at: Option<f64>,
    next_poll: f64,
    failures: u32,
    next_start: f64,
    started_at: f64,
    sessions: BTreeMap<String, u64>,
    next_cert_check: f64,
    applied_cert: Option<(String, String)>,
}

pub struct TrusttunnelManager {
    config: Config,
    fetch: Fetch,
    clock: Clock,
    wall: Clock,
    vpn_toml: PathBuf,
    hosts_toml: PathBuf,
    credentials_toml: PathBuf,
    inner: Mutex<Inner>,
}

impl TrusttunnelManager {
    pub fn new(config: Config, supervisor: Box<dyn Supervisor>, fetch: Fetch, clock: Clock, wall: Clock) -> Self {
        let dir = config.state_dir.clone();
        Self {
            fetch,
            clock,
            wall,
            vpn_toml: dir.join("vpn.toml"),
            hosts_toml: dir.join("hosts.toml"),
            credentials_toml: dir.join("credentials.toml"),
            inner: Mutex::new(Inner {
                store: StateStore::new(&dir),
                supervisor,
                restart_at: None,
                next_poll: 0.0,
                failures: 0,
                next_start: 0.0,
                started_at: 0.0,
                sessions: BTreeMap::new(),
                next_cert_check: 0.0,
                applied_cert: None,
            }),
            config,
        }
    }

    /// The production manager: the real endpoint process, its loopback metrics, real clocks.
    pub fn production(config: Config, supervisor: Box<dyn Supervisor>) -> Self {
        let address = config.metrics.clone();
        let started = std::time::Instant::now();
        Self::new(
            config,
            supervisor,
            Box::new(move || metrics::fetch_clients(&address)),
            Box::new(move || started.elapsed().as_secs_f64()),
            Box::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0)
            }),
        )
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panicking request must not take the manager down with it: the state stays usable.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ------------------------------------------------------------ lifecycle

    pub fn bootstrap(&self) -> Result<(), StateError> {
        let mut inner = self.lock();
        inner.store.load()?;
        if inner.store.doc.placeholder.as_deref().unwrap_or("").is_empty() {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|err| StateError(format!("no randomness: {err}")))?;
            inner.store.doc.placeholder = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
            inner.store.save().map_err(|err| StateError(format!("cannot write state: {err}")))?;
        }
        self.write_files(&inner).map_err(|err| StateError(format!("cannot write settings: {err}")))?;
        let now = (self.clock)();
        inner.next_poll = now + self.config.poll_interval;
        inner.next_cert_check = now + CERT_CHECK_SECONDS;
        self.maybe_start(&mut inner);
        Ok(())
    }

    pub fn tick(&self) {
        let mut inner = self.lock();
        let now = (self.clock)();
        if inner.restart_at.is_some_and(|at| now >= at) {
            inner.restart_at = None;
            self.restart(&mut inner);
            return;
        }
        if inner.supervisor.running() {
            if now - inner.started_at >= 60.0 {
                inner.failures = 0;
            }
            if now >= inner.next_cert_check {
                inner.next_cert_check = now + CERT_CHECK_SECONDS;
                self.reload_certificate(&mut inner);
            }
            if now >= inner.next_poll {
                inner.next_poll = now + self.config.poll_interval;
                self.poll(&mut inner);
            }
        } else {
            self.maybe_start(&mut inner);
        }
    }

    pub fn shutdown(&self) {
        let mut inner = self.lock();
        if inner.supervisor.running() {
            self.poll(&mut inner);
        }
        inner.supervisor.stop();
        if let Err(err) = inner.store.save() {
            log::error!("cannot save state on shutdown ({:?})", err.kind());
        }
    }

    // ------------------------------------------------------------ files

    fn credentials_text(&self, inner: &Inner) -> String {
        let placeholder = inner.store.doc.placeholder.as_deref().unwrap_or("");
        let mut lines = vec![
            "[[client]]".to_string(),
            format!("username = {}", toml_string(PLACEHOLDER_USERNAME)),
            format!("password = {}", toml_string(placeholder)),
            String::new(),
        ];
        for (name, client) in &inner.store.doc.clients {
            if client.enabled {
                lines.extend([
                    "[[client]]".to_string(),
                    format!("username = {}", toml_string(name)),
                    format!("password = {}", toml_string(&client.password)),
                    String::new(),
                ]);
            }
        }
        lines.join("\n")
    }

    fn forward_text(inner: &Inner) -> String {
        let document = &inner.store.doc.egress.document;
        if document.mode == "socks5" {
            // Plain no-auth SOCKS5: extended_auth offers method 0x80, which Xray's socks inbound
            // does not understand.
            return format!(
                "[forward_protocol.socks5]\naddress = {}\nextended_auth = false\n",
                toml_string(document.address.as_deref().unwrap_or(""))
            );
        }
        "[forward_protocol]\ndirect = {}\n".into()
    }

    fn vpn_text(&self, inner: &Inner) -> String {
        let cfg = &self.config;
        format!(
            "listen_address = {listen}\n\
             ipv6_available = false\n\
             allow_private_network_connections = false\n\
             tls_handshake_timeout_secs = 10\n\
             client_listener_timeout_secs = 600\n\
             connection_establishment_timeout_secs = 30\n\
             tcp_connections_timeout_secs = 604800\n\
             udp_connections_timeout_secs = 300\n\
             credentials_file = {credentials}\n\n\
             [listen_protocols.http1]\nupload_buffer_size = 32768\n\n\
             [listen_protocols.http2]\n\
             initial_connection_window_size = 8388608\n\
             initial_stream_window_size = 131072\n\
             max_concurrent_streams = 1000\n\
             max_frame_size = 16384\n\
             header_table_size = 65536\n\n\
             {forward}\n\
             [metrics]\naddress = {metrics}\nrequest_timeout_secs = 3\n\
             per_client_metrics = true\n",
            listen = toml_string(&cfg.listen),
            credentials = toml_string(&self.credentials_toml.display().to_string()),
            forward = Self::forward_text(inner),
            metrics = toml_string(&cfg.metrics),
        )
    }

    fn hosts_text(&self) -> String {
        let cfg = &self.config;
        format!(
            "[[main_hosts]]\nhostname = {}\ncert_chain_path = {}\nprivate_key_path = {}\n",
            toml_string(&cfg.hostname),
            toml_string(&cfg.cert.display().to_string()),
            toml_string(&cfg.key.display().to_string()),
        )
    }

    fn put(path: &Path, text: &str) -> std::io::Result<bool> {
        if std::fs::read(path).is_ok_and(|existing| existing == text.as_bytes()) {
            return Ok(false);
        }
        pc_common::fsutil::write_atomic(path, text.as_bytes(), 0o600)?;
        Ok(true)
    }

    /// Writes the three files; true when the credentials or the endpoint settings changed.
    fn write_files(&self, inner: &Inner) -> std::io::Result<bool> {
        let credentials = Self::put(&self.credentials_toml, &self.credentials_text(inner))?;
        let vpn = Self::put(&self.vpn_toml, &self.vpn_text(inner))?;
        let hosts = Self::put(&self.hosts_toml, &self.hosts_text())?;
        Ok(credentials || vpn || hosts)
    }

    fn mutated(&self, inner: &mut Inner) -> Result<(), ApiError> {
        inner.store.save().map_err(write_failed)?;
        if self.write_files(inner).map_err(write_failed)? {
            self.request_restart(inner);
        }
        Ok(())
    }

    // ------------------------------------------------------------ supervision

    fn request_restart(&self, inner: &mut Inner) {
        if inner.restart_at.is_none() {
            inner.restart_at = Some((self.clock)() + self.config.restart_delay);
        }
    }

    fn certificate_ready(&self) -> bool {
        self.config.cert.is_file() && self.config.key.is_file()
    }

    fn cert_identity(&self) -> Option<(String, String)> {
        let digest = |path: &Path| std::fs::read(path).ok().map(|bytes| hex(&Sha256::digest(bytes)));
        Some((digest(&self.config.cert)?, digest(&self.config.key)?))
    }

    fn reload_certificate(&self, inner: &mut Inner) {
        let Some(identity) = self.cert_identity() else { return };
        if inner.applied_cert.as_ref() == Some(&identity) {
            return;
        }
        if let Err(err) = inner.supervisor.reload() {
            // Never include file content: only the failure class. Retried on the next check.
            log::warn!("certificate reload failed ({:?}), will retry", err.kind());
            return;
        }
        log::info!("certificate changed, endpoint reloaded");
        inner.applied_cert = Some(identity);
    }

    fn maybe_start(&self, inner: &mut Inner) {
        let now = (self.clock)();
        if inner.supervisor.running() || !self.certificate_ready() || now < inner.next_start {
            return;
        }
        match inner.supervisor.start(&self.vpn_toml, &self.hosts_toml) {
            Err(err) => {
                log::error!("cannot start the endpoint: {err}");
                inner.failures += 1;
            }
            Ok(()) => {
                inner.started_at = now;
                inner.applied_cert = self.cert_identity();
                inner.failures += 1; // reset after a minute of uptime (see tick)
            }
        }
        inner.next_start = now + MAX_BACKOFF_SECONDS.min(2f64.powi(inner.failures.min(5) as i32));
    }

    fn restart(&self, inner: &mut Inner) {
        if inner.supervisor.running() {
            self.poll(inner); // the last reading before the counters reset
        }
        inner.supervisor.stop();
        for client in inner.store.doc.clients.values_mut() {
            client.last_in = 0;
            client.last_out = 0;
        }
        inner.sessions.clear();
        if let Err(err) = inner.store.save() {
            log::error!("cannot save state before a restart ({:?})", err.kind());
        }
        inner.failures = 0;
        inner.next_start = 0.0;
        self.maybe_start(inner);
    }

    fn poll(&self, inner: &mut Inner) {
        let Some(rows) = (self.fetch)() else { return };
        let readings = metrics::aggregate(&rows);
        inner.sessions = readings.iter().map(|(name, reading)| (name.clone(), reading.sessions)).collect();
        let mut changed = false;
        for (name, reading) in &readings {
            let Some(client) = inner.store.doc.clients.get_mut(name) else { continue };
            (client.rx, client.last_out) = metrics::fold(client.rx, client.last_out, reading.outbound);
            (client.tx, client.last_in) = metrics::fold(client.tx, client.last_in, reading.inbound);
            changed = true;
        }
        if changed {
            if let Err(err) = inner.store.save() {
                log::error!("cannot save traffic totals ({:?})", err.kind());
            }
        }
    }

    // ------------------------------------------------------------ reads

    fn view(inner: &Inner, name: &str) -> Value {
        let client = &inner.store.doc.clients[name];
        json!({
            "username": name,
            "enabled": client.enabled,
            "revision": client.revision,
            "rx": client.rx,
            "tx": client.tx,
            "sessions": inner.sessions.get(name).copied().unwrap_or(0),
        })
    }

    pub fn health(&self) -> Value {
        let mut inner = self.lock();
        let running = inner.supervisor.running();
        let pid = inner.supervisor.pid();
        let mut out = json!({
            "status": "ok",
            "endpoint": {"running": running, "pid": pid},
            "clients": inner.store.doc.clients.len(),
        });
        if !self.certificate_ready() {
            out["status"] = "degraded".into();
            out["code"] = "certificate_missing".into();
        } else if !running {
            out["status"] = "degraded".into();
            out["code"] = "endpoint_down".into();
        }
        out
    }

    pub fn endpoint(&self) -> Value {
        let cert = inspect_certificate(&self.config.cert, (self.wall)());
        let trusted = cert.as_ref().is_some_and(|c| c.trusted);
        json!({
            "hostname": self.config.hostname,
            "listen": self.config.listen,
            "public_port": self.config.public_port,
            "version": self.config.version,
            "certificate_trusted": trusted,
            "certificate_der_b64": cert
                .as_ref()
                .filter(|_| !trusted)
                .map(|c| base64::engine::general_purpose::STANDARD.encode(&c.der)),
            "fingerprint": cert.as_ref().map(|c| c.fingerprint.clone()),
        })
    }

    pub fn list_clients(&self) -> Value {
        let inner = self.lock();
        let clients: Vec<Value> = inner.store.doc.clients.keys().map(|name| Self::view(&inner, name)).collect();
        json!({"clients": clients})
    }

    // ------------------------------------------------------------ client writes

    fn replay(inner: &Inner, op: &str, fingerprint: &str) -> Result<Option<String>, ApiError> {
        match inner.store.doc.operations.get(op) {
            None => Ok(None),
            Some(known) if known.fingerprint != fingerprint => {
                Err(ApiError::new(409, "operation_conflict", "operation_id was used for another request"))
            }
            Some(known) => Ok(Some(known.username.clone())),
        }
    }

    pub fn create_client(&self, body: &Map<String, Value>) -> Result<Value, ApiError> {
        check_fields(body, &["operation_id", "username", "password"])?;
        let op = operation_id(body)?;
        let username = body.get("username");
        if username.and_then(Value::as_str) == Some(PLACEHOLDER_USERNAME) {
            return Err(ApiError::new(422, "reserved_username", "this username is reserved"));
        }
        let username = match username.and_then(Value::as_str) {
            Some(name) if is_username(name) => name.to_string(),
            _ => return Err(invalid("invalid username")),
        };
        let password = password(body)?;
        let fingerprint = fingerprint("create", &username, &password);
        let mut inner = self.lock();
        if let Some(replayed) = Self::replay(&inner, &op, &fingerprint)? {
            if inner.store.doc.clients.contains_key(&replayed) {
                return Ok(json!({"client": Self::view(&inner, &replayed)}));
            }
            return Err(ApiError::new(409, "operation_conflict", "the client of this operation was deleted"));
        }
        if inner.store.doc.clients.contains_key(&username) {
            return Err(ApiError::new(409, "exists", "client already exists"));
        }
        inner.store.doc.clients.insert(
            username.clone(),
            Client { password, enabled: true, revision: 1, rx: 0, tx: 0, last_out: 0, last_in: 0 },
        );
        inner.store.doc.operations.insert(op, Operation { fingerprint, username: username.clone() });
        self.mutated(&mut inner)?;
        Ok(json!({"client": Self::view(&inner, &username)}))
    }

    fn existing<'a>(inner: &'a mut Inner, username: &str) -> Result<&'a mut Client, ApiError> {
        inner.store.doc.clients.get_mut(username).ok_or_else(|| ApiError::new(404, "not_found", "client not found"))
    }

    pub fn set_enabled(&self, username: &str, enabled: bool) -> Result<Value, ApiError> {
        let mut inner = self.lock();
        let client = Self::existing(&mut inner, username)?;
        if client.enabled != enabled {
            client.enabled = enabled;
            client.revision += 1;
            self.mutated(&mut inner)?;
        }
        Ok(json!({"client": Self::view(&inner, username)}))
    }

    pub fn rotate(&self, username: &str, body: &Map<String, Value>) -> Result<Value, ApiError> {
        check_fields(body, &["operation_id", "password"])?;
        let op = operation_id(body)?;
        let password = password(body)?;
        let fingerprint = fingerprint("rotate", username, &password);
        let mut inner = self.lock();
        Self::existing(&mut inner, username)?;
        if Self::replay(&inner, &op, &fingerprint)?.is_some() {
            return Ok(json!({"client": Self::view(&inner, username)}));
        }
        let client = Self::existing(&mut inner, username)?;
        client.password = password;
        client.revision += 1;
        inner.store.doc.operations.insert(op, Operation { fingerprint, username: username.to_string() });
        self.mutated(&mut inner)?;
        Ok(json!({"client": Self::view(&inner, username)}))
    }

    pub fn delete_client(&self, username: &str) -> Result<(), ApiError> {
        let mut inner = self.lock();
        if inner.store.doc.clients.remove(username).is_some() {
            self.mutated(&mut inner)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ egress

    pub fn egress(&self) -> Value {
        egress_view(&self.lock().store.doc.egress.document)
    }

    pub fn egress_plan(&self, body: &Map<String, Value>) -> Result<Value, ApiError> {
        let proposed = normalize_egress(body)?;
        let inner = self.lock();
        let current = &inner.store.doc.egress.document;
        Ok(json!({
            "changed": &proposed != current,
            "current": egress_view(current),
            "proposed": egress_view(&proposed),
        }))
    }

    fn set_egress(
        &self,
        inner: &mut Inner,
        document: EgressDocument,
        previous: Option<EgressDocument>,
    ) -> Result<(), ApiError> {
        inner.store.doc.egress.document = document;
        inner.store.doc.egress.previous = previous;
        self.mutated(inner)
    }

    pub fn egress_apply(&self, body: &Map<String, Value>) -> Result<Value, ApiError> {
        let proposed = normalize_egress(body)?;
        let mut inner = self.lock();
        let current = inner.store.doc.egress.document.clone();
        if proposed != current {
            self.set_egress(&mut inner, proposed, Some(current))?;
        }
        Ok(egress_view(&inner.store.doc.egress.document))
    }

    pub fn egress_rollback(&self) -> Result<Value, ApiError> {
        let mut inner = self.lock();
        let Some(previous) = inner.store.doc.egress.previous.clone() else {
            return Err(ApiError::new(409, "no_previous", "nothing to roll back to"));
        };
        self.set_egress(&mut inner, previous, None)?;
        Ok(egress_view(&inner.store.doc.egress.document))
    }
}
