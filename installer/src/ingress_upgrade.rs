//! Bounded host migration for the installer's pre-client-IP Nginx templates.
//!
//! The foreign coexist frontend is never edited. Run without `--apply` to inspect the plan; the
//! one-command host updater applies this after its panel update succeeds.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pc_host::fs::{atomic_write, durable_mkdir, sha256_hex, token_hex};
use pc_host::runner::{Bounded, HostRunner};
use serde_json::Value;

use crate::engine::{agent_managed_paths, assert_owned, read_matching_plan};
use crate::handoff::{check_declaration, read_active_state, write_rebased};
use crate::journal::{Phase, TransactionState};
use crate::planner::InstallPlan;
use crate::store::TransactionStore;

const STREAM: &str = "etc/nginx/stream.d/proxy-control.conf";
const PANEL: &str = "etc/nginx/conf.d/proxy-control-panel.conf";
const STATE: &str = "var/lib/proxy-control/ingress-backups";
const PROXY_LISTENER: &str = "listen unix:/run/proxy-control-panel-tls.sock ssl proxy_protocol; set_real_ip_from unix:; real_ip_header proxy_protocol; ";
const MANUAL_REASON: &str = "foreign or legacy ingress is unchanged; verify client-IP forwarding separately";

#[derive(Debug)]
pub struct UpgradeError(String);

impl UpgradeError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UpgradeError {}

impl From<io::Error> for UpgradeError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<pc_host::TxError> for UpgradeError {
    fn from(error: pc_host::TxError) -> Self {
        Self(error.to_string())
    }
}

impl From<crate::error::Error> for UpgradeError {
    fn from(error: crate::error::Error) -> Self {
        Self(error.message())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeOutcome {
    CoexistManual,
    Current,
    Pending,
    Applied { backup: PathBuf },
}

impl UpgradeOutcome {
    /// `json.dumps(upgrade(...))`: insertion order, ASCII escaping and the default separators,
    /// with no newline here (the CLI adds exactly one).
    pub fn json(&self) -> String {
        match self {
            Self::CoexistManual => format!(
                "{{\"status\": \"coexist_manual\", \"client_ip\": \"not_verified\", \"reason\": {}}}",
                quoted(MANUAL_REASON)
            ),
            Self::Current => "{\"status\": \"current\", \"client_ip\": \"proxy_protocol\"}".into(),
            Self::Pending => "{\"status\": \"pending\", \"files\": [\"stream.d/proxy-control.conf\", \"conf.d/proxy-control-panel.conf\"]}".into(),
            Self::Applied { backup } => format!(
                "{{\"status\": \"applied\", \"client_ip\": \"proxy_protocol\", \"backup\": {}}}",
                quoted(&backup.to_string_lossy())
            ),
        }
    }
}

pub fn failed_json(message: &str) -> String {
    format!("{{\"status\": \"failed\", \"reason\": {}}}", quoted(message))
}

fn quoted(text: &str) -> String {
    let mut output = String::from("\"");
    for character in text.chars() {
        match character {
            '\"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", c as u32)),
            c if c.is_ascii() => output.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    output.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    output.push('\"');
    output
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

fn read_owned(path: &Path) -> Result<Vec<u8>, UpgradeError> {
    for parent in path.ancestors() {
        if is_symlink(parent) {
            return Err(UpgradeError::new("ingress path crosses a symlink"));
        }
    }
    let info = path.metadata()?;
    if !info.file_type().is_file()
        || info.mode() & 0o022 != 0
        || (info.uid() != 0 && info.uid() != unsafe { libc::geteuid() })
    {
        return Err(UpgradeError::new("ingress file ownership or permissions are unsafe"));
    }
    Ok(fs::read(path)?)
}

fn between<'a>(line: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let offset = line.find(start)? + start.len();
    let tail = &line[offset..];
    let length = tail.find(end)?;
    Some(&tail[..length])
}

fn listener_port(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("server { listen 127.0.0.1:")?;
    let end = rest.find(" ssl; ")?;
    let port = &rest[..end];
    (!port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())).then_some(port)
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-'))
}

fn valid_certificate(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn panel_proxy(app_port: &str) -> String {
    format!(
        "proxy_pass http://127.0.0.1:{app_port}; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $remote_addr; "
    )
}

fn vhost_prefix(domain: &str, certificate: &str, tls_port: &str) -> String {
    format!(
        "server {{ listen 127.0.0.1:{tls_port} ssl; {PROXY_LISTENER}server_name {domain}; ssl_certificate /etc/letsencrypt/live/{certificate}/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/{certificate}/privkey.pem; "
    )
}

/// `_panel_vhost_text`, `_subscription_vhost_text` and `_mcp_vhost_text`, kept here as well as in
/// Core because this recovery command must be able to run without constructing an adapter.
fn render_vhost(
    domain: &str,
    certificate: &str,
    app_port: &str,
    tls_port: &str,
    mcp: bool,
    subscription: bool,
) -> String {
    let prefix = vhost_prefix(domain, certificate, tls_port);
    let proxy = panel_proxy(app_port);
    if mcp {
        format!(
            "{prefix}access_log off; location = /healthz {{ return 404; }} location /mcp {{ proxy_pass http://127.0.0.1:{app_port}; proxy_http_version 1.1; proxy_set_header Connection \"\"; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $remote_addr; proxy_buffering off; proxy_read_timeout 3600s; }} location / {{ return 404; }} }}\n"
        )
    } else if subscription {
        format!("{prefix}access_log off; location ^~ /s/ {{ {proxy}}} location / {{ return 404; }} }}\n")
    } else {
        format!("{prefix}location ^~ /s/ {{ access_log off; return 404; }} location / {{ {proxy}}} }}\n")
    }
}

fn panel_template(data: &[u8]) -> Result<(Vec<u8>, String), UpgradeError> {
    let text = std::str::from_utf8(data).map_err(|error| UpgradeError::new(error.to_string()))?;
    let invalid = || UpgradeError::new("panel config differs from an owned template");
    let mut lines = String::new();
    let mut port: Option<String> = None;
    for line in text.split_inclusive('\n') {
        let tls = listener_port(line).ok_or_else(invalid)?;
        if port.as_deref().is_some_and(|previous| previous != tls) {
            return Err(UpgradeError::new("panel TLS listeners disagree"));
        }
        port = Some(tls.to_string());
        let domain = between(line, "server_name ", "; ").filter(|value| valid_domain(value)).ok_or_else(invalid)?;
        let certificate = between(line, "ssl_certificate /etc/letsencrypt/live/", "/fullchain.pem; ")
            .filter(|value| valid_certificate(value))
            .ok_or_else(invalid)?;
        let app = between(line, "proxy_pass http://127.0.0.1:", "; ")
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(invalid)?;
        let mcp = line.contains("location /mcp ");
        let subscription = line.contains("location / { return 404; }");
        let rendered = render_vhost(domain, certificate, app, tls, mcp, subscription);
        let legacy = if mcp {
            rendered.replace(PROXY_LISTENER, "").replace("proxy_set_header X-Forwarded-For $remote_addr; ", "")
        } else {
            rendered
                .replace(PROXY_LISTENER, "")
                .replace("X-Forwarded-For $remote_addr;", "X-Forwarded-For $proxy_add_x_forwarded_for;")
        };
        if line != rendered && line != legacy {
            return Err(invalid());
        }
        lines.push_str(&rendered);
    }
    let port = port.filter(|_| !lines.is_empty()).ok_or_else(invalid)?;
    Ok((lines.into_bytes(), format!("127.0.0.1:{port}")))
}

fn loopback_backend(backend: &str) -> bool {
    backend
        .strip_prefix("127.0.0.1:")
        .is_some_and(|port| (1..=5).contains(&port.len()) && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn client_ip_backend(backend: &str, panel_backend: &str) -> Result<String, UpgradeError> {
    if backend == panel_backend {
        return Ok("unix:/run/proxy-control-panel-tls.sock".into());
    }
    if !loopback_backend(backend) {
        return Err(UpgradeError::new("fresh client-IP relay requires a loopback TCP backend"));
    }
    Ok(format!("unix:/run/proxy-control-raw-{}.sock", backend.rsplit(':').next().expect("a colon")))
}

/// The byte-exact legacy/current `_render_fresh` forms used both by the adapter and this migration.
pub fn render_fresh(
    routes: &[(String, String)],
    panel_backend: &str,
    preserve_ip: bool,
) -> Result<Vec<u8>, UpgradeError> {
    let mut lines = vec![
        "# BEGIN PROXY-CONTROL GENERATED STREAM ROUTER".to_string(),
        "map $ssl_preread_server_name $proxy_control_backend {".to_string(),
    ];
    for (domain, backend) in routes {
        let mapped = if preserve_ip { client_ip_backend(backend, panel_backend)? } else { backend.clone() };
        lines.push(format!("    {domain} {mapped};"));
    }
    lines.push(if preserve_ip {
        "    default unix:/run/proxy-control-panel-tls.sock;".into()
    } else {
        "    default 127.0.0.1:8443;".into()
    });
    lines.extend(["}".into(), "server {".into(), "    listen 443;".into(), "    ssl_preread on;".into()]);
    if preserve_ip {
        lines.push("    proxy_protocol on;".into());
    }
    lines.extend(["    proxy_pass $proxy_control_backend;".into(), "}".into()]);
    if preserve_ip {
        let mut seen = BTreeSet::new();
        for (_domain, backend) in routes {
            if backend != panel_backend && seen.insert(backend.clone()) {
                lines.extend([
                    "server {".into(),
                    format!("    listen {} proxy_protocol;", client_ip_backend(backend, panel_backend)?),
                    format!("    proxy_pass {backend};"),
                    "}".into(),
                ]);
            }
        }
    }
    lines.extend(["# END PROXY-CONTROL GENERATED STREAM ROUTER".into(), String::new()]);
    Ok(lines.join("\n").into_bytes())
}

fn stream_template(data: &[u8], panel_backend: &str) -> Result<Vec<u8>, UpgradeError> {
    let invalid = || UpgradeError::new("stream config differs from an owned template");
    let text = std::str::from_utf8(data).map_err(|_| invalid())?;
    let prefix = "map $ssl_preread_server_name $proxy_control_backend {\n";
    let start = text.find(prefix).map(|position| position + prefix.len()).ok_or_else(invalid)?;
    let end = text[start..].find("    default ").map(|position| start + position).ok_or_else(invalid)?;
    let mut routes = Vec::new();
    for line in text[start..end].lines() {
        let entry = line.strip_prefix("    ").ok_or_else(invalid)?;
        let (domain, backend) = entry.split_once(' ').ok_or_else(invalid)?;
        let backend = backend.strip_suffix(';').ok_or_else(invalid)?;
        if !valid_domain(domain) || backend.is_empty() || backend.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(invalid());
        }
        let backend = if backend == "unix:/run/proxy-control-panel-tls.sock" {
            panel_backend.to_string()
        } else if let Some(port) = backend
            .strip_prefix("unix:/run/proxy-control-raw-")
            .and_then(|value| value.strip_suffix(".sock"))
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        {
            format!("127.0.0.1:{port}")
        } else {
            backend.to_string()
        };
        if !loopback_backend(&backend) {
            return Err(invalid());
        }
        routes.push((domain.to_string(), backend));
    }
    let legacy = render_fresh(&routes, panel_backend, false)?;
    let current = render_fresh(&routes, panel_backend, true)?;
    if (data != legacy && data != current) || routes.len() < 2 {
        return Err(invalid());
    }
    Ok(current)
}

fn run_checked(runner: &dyn HostRunner, argv: &[&str]) -> Result<(), UpgradeError> {
    let limits = Bounded::new(Duration::from_secs(30), 1024 * 1024).expect("valid limits");
    let output = runner.bounded(argv, limits).map_err(|error| UpgradeError::new(error.to_string()))?;
    if output.returncode != 0 {
        return Err(UpgradeError::new(format!("command failed with exit status {}", output.returncode)));
    }
    Ok(())
}

fn workers(runner: &dyn HostRunner) -> Result<(u32, BTreeSet<u32>), UpgradeError> {
    let limits = Bounded::new(Duration::from_secs(10), 1024 * 1024).expect("valid limits");
    let output = runner
        .bounded(&["systemctl", "show", "nginx", "--property=MainPID", "--value"], limits)
        .map_err(|error| UpgradeError::new(error.to_string()))?;
    if output.returncode != 0 {
        return Err(UpgradeError::new(format!("command failed with exit status {}", output.returncode)));
    }
    let master_text = output.stdout.trim();
    let master = master_text
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| UpgradeError::new("Nginx master process is unavailable"))?;
    let children = fs::read_to_string(format!("/proc/{master}/task/{master}/children"))?;
    let mut workers = BTreeSet::new();
    for child in children.split_whitespace() {
        let Ok(command) = fs::read(format!("/proc/{child}/cmdline")) else { continue };
        if command.starts_with(b"nginx: worker process")
            && !command.windows(b"shutting down".len()).any(|window| window == b"shutting down")
        {
            let pid = child.parse::<u32>().map_err(|error| UpgradeError::new(error.to_string()))?;
            workers.insert(pid);
        }
    }
    Ok((master, workers))
}

fn reload(runner: &dyn HostRunner) -> Result<(), UpgradeError> {
    reload_with(runner, &workers)
}

type WorkerObservation<'a> = dyn Fn(&dyn HostRunner) -> Result<(u32, BTreeSet<u32>), UpgradeError> + 'a;

fn reload_with(runner: &dyn HostRunner, observe: &WorkerObservation<'_>) -> Result<(), UpgradeError> {
    let (master, old) = observe(runner)?;
    if old.is_empty() {
        return Err(UpgradeError::new("Nginx has no serving workers before reload"));
    }
    run_checked(runner, &["systemctl", "reload", "nginx"])?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut previous = BTreeSet::new();
    while Instant::now() < deadline {
        let (current_master, current) = observe(runner)?;
        if current_master != master {
            return Err(UpgradeError::new("Nginx master changed during reload"));
        }
        let fresh: BTreeSet<u32> = current.difference(&old).copied().collect();
        if !fresh.is_disjoint(&previous) {
            return Ok(());
        }
        previous = fresh;
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(UpgradeError::new("Nginx did not activate a new worker generation"))
}

fn unix_sockets(contents: &[&[u8]]) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for data in contents {
        let text = String::from_utf8_lossy(data);
        let mut rest = text.as_ref();
        while let Some(position) = rest.find("listen unix:") {
            rest = &rest[position + "listen unix:".len()..];
            let end = rest.find([' ', ';']).unwrap_or(rest.len());
            result.insert(rest[..end].to_string());
            rest = &rest[end..];
        }
    }
    result
}

#[derive(Clone)]
struct FileMetadata {
    path: PathBuf,
    mode: u32,
    uid: u32,
    gid: u32,
}

fn metadata_json(stream: &FileMetadata, panel: &FileMetadata) -> Vec<u8> {
    fn entry(name: &str, metadata: &FileMetadata) -> String {
        format!(
            "\"{name}\": {{\"path\": {}, \"mode\": {}, \"uid\": {}, \"gid\": {}}}",
            quoted(&metadata.path.to_string_lossy()),
            metadata.mode,
            metadata.uid,
            metadata.gid
        )
    }
    format!("{{{}, {}}}", entry("stream.conf", stream), entry("panel.conf", panel)).into_bytes()
}

struct JournalHandoff {
    previous: TransactionState,
    updated: TransactionState,
    previous_plan: InstallPlan,
    updated_plan: InstallPlan,
}

fn replace_digest(declaration: &mut Value, digest: &str) -> Result<(), UpgradeError> {
    match declaration {
        Value::String(value) => *value = digest.to_string(),
        Value::Object(flags) if flags.get("sha256").is_some_and(Value::is_string) => {
            flags.insert("sha256".into(), Value::String(digest.into()));
        }
        _ => return Err(UpgradeError::new("ingress ownership declaration is invalid")),
    }
    Ok(())
}

impl JournalHandoff {
    fn prepare(
        store: &TransactionStore,
        project: &Path,
        before_stream: &[u8],
        before_panel: &[u8],
        new_stream: &[u8],
        new_panel: &[u8],
        backend: &str,
    ) -> Result<Option<Self>, UpgradeError> {
        if !store.state_exists() && fs::symlink_metadata(store.state_path()).is_err() {
            let legacy = store.root().join("var/lib/proxy-control/runtime.json");
            if legacy.exists() || is_symlink(&legacy) {
                return Err(UpgradeError::new("legacy runtime-v2 ingress requires an installer journal migration"));
            }
            return Ok(None);
        }
        if project != store.root().join("opt/mtproxy-shared443") {
            return Err(UpgradeError::new("ingress project does not match installer ownership"));
        }
        let previous = read_active_state(store, "ingress ownership requires an active installer transaction")?;
        let previous_plan = read_matching_plan(store, &previous)?;
        assert_owned(store.root(), &previous.ownership(true)?, &agent_managed_paths())?;
        let mut updated = previous.clone();
        for (id, adapter, host, before, after) in [
            ("core.runtime", "core", "/etc/nginx/conf.d/proxy-control-panel.conf", before_panel, new_panel),
            ("nginx.routes", "nginx", "/etc/nginx/stream.d/proxy-control.conf", before_stream, new_stream),
        ] {
            let checkpoint = updated
                .checkpoints
                .iter_mut()
                .find(|checkpoint| checkpoint.action_id == id && checkpoint.adapter == adapter)
                .filter(|checkpoint| checkpoint.phase == Phase::Verified)
                .ok_or_else(|| UpgradeError::new("active ingress checkpoint is unavailable"))?;
            check_declaration(checkpoint)?;
            let action = previous_plan
                .actions
                .iter()
                .find(|action| action.id == id && action.adapter == adapter)
                .ok_or_else(|| UpgradeError::new("ingress checkpoint does not belong to the approved plan"))?;
            if checkpoint.data.get("owner").and_then(Value::as_str) != Some(action.owner.as_str())
                || checkpoint.ownership.values().any(|entry| entry.action_id != id || entry.adapter != adapter)
            {
                return Err(UpgradeError::new("ingress checkpoint ownership identity is invalid"));
            }
            let before_digest = sha256_hex(before);
            let after_digest = sha256_hex(after);
            if adapter == "nginx" {
                if checkpoint.data.get("owned_sha256").and_then(Value::as_str) != Some(&before_digest) {
                    return Err(UpgradeError::new("Nginx checkpoint does not recognize the predecessor stream"));
                }
                let identity = checkpoint
                    .data
                    .get("route_identity")
                    .and_then(Value::as_object)
                    .ok_or_else(|| UpgradeError::new("Nginx route identity is invalid"))?;
                if identity.get("original_path").and_then(Value::as_str) != Some(host)
                    || identity.get("resolved_path").and_then(Value::as_str) != Some(host)
                    || !matches!(identity.get("path_kind").and_then(Value::as_str), Some("missing" | "file"))
                {
                    return Err(UpgradeError::new("Nginx route identity does not match the owned ingress"));
                }
                if !checkpoint.ownership.contains_key(host) {
                    let backup = checkpoint.data.get("backup_path").and_then(Value::as_str).unwrap_or("");
                    let original = identity.get("original_sha256").and_then(Value::as_str);
                    if identity.get("exists").and_then(Value::as_bool) != Some(true)
                        || original.is_none()
                        || !checkpoint.ownership.get(backup).is_some_and(|entry| {
                            entry.kind == "file"
                                && !entry.is_mutable()
                                && !entry.preserve
                                && Some(entry.sha256.as_str()) == original
                        })
                    {
                        return Err(UpgradeError::new("Nginx checkpoint does not own its original rollback backup"));
                    }
                }
                checkpoint.data.insert("owned_sha256".into(), Value::String(after_digest.clone()));
            }
            if let Some(entry) = checkpoint.ownership.get_mut(host) {
                if entry.kind != "file" || entry.is_mutable() || entry.preserve || entry.sha256 != before_digest {
                    return Err(UpgradeError::new("ingress checkpoint does not own the predecessor template"));
                }
                entry.sha256 = after_digest.clone();
                let declared = checkpoint
                    .data
                    .get_mut("ownership")
                    .and_then(Value::as_object_mut)
                    .and_then(|declaration| declaration.get_mut(host))
                    .ok_or_else(|| UpgradeError::new("ingress ownership declaration is missing"))?;
                replace_digest(declared, &after_digest)?;
            } else if adapter == "core" {
                return Err(UpgradeError::new("Core checkpoint does not own the panel vhost"));
            }
            // Core keeps its pre-apply declaration as rollback provenance as well.
            if adapter == "core" {
                if let Some(declared) = checkpoint
                    .data
                    .get_mut("planned_ownership")
                    .and_then(Value::as_object_mut)
                    .and_then(|declaration| declaration.get_mut(host))
                {
                    replace_digest(declared, &after_digest)?;
                }
            }
        }
        let mut updated_plan = previous_plan.clone();
        let action = updated_plan
            .actions
            .iter_mut()
            .find(|action| action.id == "nginx.routes" && action.adapter == "nginx")
            .ok_or_else(|| UpgradeError::new("active Nginx action is unavailable"))?;
        let mut values = BTreeMap::new();
        let mut routes = Vec::new();
        for mutation in &action.mutations {
            let (key, value) =
                mutation.split_once('=').ok_or_else(|| UpgradeError::new("Nginx action is malformed"))?;
            if key == "route" {
                let (domain, destination) =
                    value.split_once(' ').ok_or_else(|| UpgradeError::new("Nginx route is malformed"))?;
                routes.push((domain.to_string(), destination.to_string()));
            } else if values.insert(key, value).is_some() {
                return Err(UpgradeError::new("Nginx action is malformed"));
            }
        }
        let required = [
            ("mode", "fresh"),
            ("target", "/etc/nginx/stream.d/proxy-control.conf"),
            ("resolved_path", "/etc/nginx/stream.d/proxy-control.conf"),
            ("variable", "$proxy_control_backend"),
            ("symlink_target", "-"),
        ];
        if required.iter().any(|(key, expected)| values.get(key) != Some(expected))
            || !matches!(values.get("path_kind").copied(), Some("missing" | "file"))
            || !matches!(values.get("client_ip").copied(), None | Some("legacy" | "proxy"))
            || values.get("panel_tls_backend").is_some_and(|value| *value != backend)
            || !matches!(values.get("stream_context").copied(), None | Some("create" | "present"))
            || values.keys().any(|key| {
                ![
                    "mode",
                    "target",
                    "resolved_path",
                    "variable",
                    "symlink_target",
                    "path_kind",
                    "client_ip",
                    "panel_tls_backend",
                    "stream_context",
                ]
                .contains(key)
            })
            || crate::adapters::nginx::render_fresh(&routes, "proxy", backend)?.as_slice() != new_stream
        {
            return Err(UpgradeError::new("Nginx action differs from the recognized ingress upgrade"));
        }
        let client_ip = values.get("client_ip").copied();
        let backend_missing = !values.contains_key("panel_tls_backend");
        // Only the recognized template's client-IP semantics change. Keep all other actions,
        // routes, configuration, release identity and audit facts exactly as approved.
        if client_ip == Some("legacy") {
            *action.mutations.iter_mut().find(|entry| entry.starts_with("client_ip=")).expect("client-IP mutation") =
                "client_ip=proxy".into();
        } else if client_ip.is_none() {
            action.mutations.push("client_ip=proxy".into());
        }
        if backend_missing {
            action.mutations.push(format!("panel_tls_backend={backend}"));
        }
        updated.plan_digest = updated_plan.digest();
        updated.accepted_digest = updated.plan_digest.clone();
        Ok(Some(Self { previous, updated, previous_plan, updated_plan }))
    }

    fn commit(&self, store: &TransactionStore) -> Result<(), UpgradeError> {
        if store.read_state()? != self.previous || store.read_plan()? != self.previous_plan {
            return Err(UpgradeError::new("installer journal changed during ingress upgrade"));
        }
        if self.updated_plan != self.previous_plan {
            store.write_plan(&self.updated_plan)?;
        }
        write_rebased(store, &self.previous, &self.updated, "ingress ownership journal could not be restored")?;
        Ok(())
    }

    fn restore(&self, store: &TransactionStore) -> Result<(), UpgradeError> {
        if self.updated_plan != self.previous_plan {
            store.write_plan(&self.previous_plan)?;
        }
        write_rebased(store, &self.updated, &self.previous, "ingress ownership journal rollback failed")?;
        Ok(())
    }
}
fn upgrade_inner(
    project: &Path,
    root: &Path,
    apply: bool,
    runner: &dyn HostRunner,
    reload: &dyn Fn(&dyn HostRunner) -> Result<(), UpgradeError>,
    store: &TransactionStore,
) -> Result<UpgradeOutcome, UpgradeError> {
    let marker = project.join(".mtproxy-owned");
    let stream = root.join(STREAM);
    let panel = root.join(PANEL);
    if !marker.exists() || !stream.exists() {
        return Ok(UpgradeOutcome::CoexistManual);
    }
    read_owned(&marker)?;
    let before_stream = read_owned(&stream)?;
    let before_panel = read_owned(&panel)?;
    let (new_panel, backend) = panel_template(&before_panel)?;
    let new_stream = stream_template(&before_stream, &backend)?;
    if new_stream == before_stream && new_panel == before_panel {
        return Ok(UpgradeOutcome::Current);
    }
    if !apply {
        return Ok(UpgradeOutcome::Pending);
    }
    let handoff =
        JournalHandoff::prepare(store, project, &before_stream, &before_panel, &new_stream, &new_panel, &backend)?;
    let old_sockets = unix_sockets(&[&before_stream, &before_panel]);
    let new_sockets = unix_sockets(&[&new_stream, &new_panel]);
    for name in new_sockets.difference(&old_sockets) {
        let path = root.join(name.trim_start_matches('/'));
        if path.exists() || is_symlink(&path) {
            return Err(UpgradeError::new("a new ingress Unix socket path is occupied"));
        }
    }
    let state = root.join(STATE);
    let backup = loop {
        let candidate = state.join(format!("backup-{}", token_hex::<4>()));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };
    let stream_meta = fs::metadata(&stream)?;
    let panel_meta = fs::metadata(&panel)?;
    let stream_metadata = FileMetadata {
        path: stream.clone(),
        mode: stream_meta.mode() & 0o7777,
        uid: stream_meta.uid(),
        gid: stream_meta.gid(),
    };
    let panel_metadata = FileMetadata {
        path: panel.clone(),
        mode: panel_meta.mode() & 0o7777,
        uid: panel_meta.uid(),
        gid: panel_meta.gid(),
    };
    atomic_write(&backup.join("stream.conf"), &before_stream, 0o600, None)?;
    atomic_write(&backup.join("panel.conf"), &before_panel, 0o600, None)?;
    atomic_write(&backup.join("metadata.json"), &metadata_json(&stream_metadata, &panel_metadata), 0o600, None)?;
    if handoff.is_some() {
        for name in ["plan.json", "state.json", "ownership.json", "report.json"] {
            atomic_write(&backup.join(name), &read_owned(&store.directory().join(name))?, 0o600, None)?;
        }
    }

    let write = |stream_bytes: &[u8], panel_bytes: &[u8]| -> Result<(), UpgradeError> {
        for (path, bytes, metadata) in
            [(&stream, stream_bytes, &stream_metadata), (&panel, panel_bytes, &panel_metadata)]
        {
            atomic_write(path, bytes, metadata.mode, Some((metadata.uid, metadata.gid)))?;
        }
        Ok(())
    };
    if read_owned(&stream)? != before_stream || read_owned(&panel)? != before_panel {
        return Err(UpgradeError::new("ingress changed while preparing its backup"));
    }
    let mut journal_started = false;
    let result = (|| {
        write(&new_stream, &new_panel)?;
        run_checked(runner, &["nginx", "-t"])?;
        reload(runner)?;
        if read_owned(&stream)? != new_stream || read_owned(&panel)? != new_panel {
            return Err(UpgradeError::new("ingress changed during reload"));
        }
        if let Some(handoff) = &handoff {
            journal_started = true;
            handoff.commit(store)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let rollback = (|| {
            write(&before_stream, &before_panel)?;
            run_checked(runner, &["nginx", "-t"])?;
            reload(runner)
        })();
        // Even a failed rollback reload must not leave the new ownership behind.
        let journal_rollback =
            if journal_started { handoff.as_ref().expect("journal handoff started").restore(store) } else { Ok(()) };
        if rollback.is_err() || journal_rollback.is_err() {
            return Err(UpgradeError::new(format!("ingress rollback failed; private backup: {}", backup.display())));
        }
        return Err(UpgradeError::new(format!(
            "ingress upgrade failed ({error}); original configuration restored; private backup: {}",
            backup.display()
        )));
    }
    Ok(UpgradeOutcome::Applied { backup })
}

/// `upgrade(project, root=…, apply=…)`: read-only inspection unless `apply`, with the private
/// state-directory lock around the mutating double-check and write.
pub fn upgrade(
    project: &Path,
    root: &Path,
    apply: bool,
    runner: &dyn HostRunner,
) -> Result<UpgradeOutcome, UpgradeError> {
    upgrade_with_reload(project, root, apply, runner, &reload)
}

/// Test seam corresponding to Python's injectable `reload`; production callers use [`upgrade`].
pub fn upgrade_with_reload(
    project: &Path,
    root: &Path,
    apply: bool,
    runner: &dyn HostRunner,
    reload: &dyn Fn(&dyn HostRunner) -> Result<(), UpgradeError>,
) -> Result<UpgradeOutcome, UpgradeError> {
    let store = TransactionStore::new(root)?;
    if !apply {
        return upgrade_inner(project, root, false, runner, reload, &store);
    }
    if !project.is_dir() || is_symlink(project) {
        return Err(UpgradeError::new("project directory is unavailable or unsafe"));
    }
    let plan = upgrade_inner(project, root, false, runner, reload, &store)?;
    if plan != UpgradeOutcome::Pending {
        return Ok(plan);
    }
    // Serialize the templates and their handoff with repair, updates and uninstall.
    let _operation = store.locked()?;
    let state = root.join(STATE);
    for path in state.ancestors() {
        if is_symlink(path) {
            return Err(UpgradeError::new("ingress backup path crosses a symlink"));
        }
    }
    durable_mkdir(&state, 0o700)?;
    let info = fs::metadata(&state)?;
    if info.mode() & 0o077 != 0 || info.uid() != unsafe { libc::geteuid() } {
        return Err(UpgradeError::new("ingress backup directory ownership or permissions are unsafe"));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join(".lock"))?;
    // SAFETY: `lock` owns a valid descriptor for the duration of the guard.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let result = upgrade_inner(project, root, true, runner, reload, &store);
    // SAFETY: unlocking the still-open descriptor; close then happens through Drop.
    unsafe {
        libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_UN);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pc_host::runner::{RecordingRunner, Reply};

    use super::*;
    use crate::testkit::TempDir;

    fn golden(name: &str) -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures/host-golden/renders/ingress-upgrade")
                .join(name),
        )
        .unwrap()
    }

    fn predecessor(label: &str) -> (TempDir, PathBuf) {
        let directory = TempDir::new(label);
        let root = directory.path();
        let project = root.join("opt/mtproxy-shared443");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join(".mtproxy-owned"), b"0123456789abcdef0123456789abcdef\n").unwrap();
        fs::create_dir_all(root.join("etc/nginx/stream.d")).unwrap();
        fs::create_dir_all(root.join("etc/nginx/conf.d")).unwrap();
        fs::write(root.join(STREAM), golden("legacy/stream.conf")).unwrap();
        fs::write(root.join(PANEL), golden("legacy/panel.conf")).unwrap();
        (directory, project)
    }

    fn journal_predecessor(label: &str) -> (TempDir, PathBuf, TransactionStore) {
        use std::os::unix::fs::PermissionsExt;

        let (directory, project) = predecessor(label);
        let root = directory.path();
        let recorded = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/installs/core");
        let mut plan = InstallPlan::from_value(
            &serde_json::from_slice(&fs::read(recorded.join("journal/plan.json")).unwrap()).unwrap(),
        )
        .unwrap();
        let nginx = plan.actions.iter_mut().find(|action| action.adapter == "nginx").unwrap();
        nginx.mutations.retain(|entry| !entry.starts_with("client_ip=") && !entry.starts_with("panel_tls_backend="));
        let routes: Vec<_> = nginx
            .mutations
            .iter()
            .filter_map(|entry| entry.strip_prefix("route="))
            .map(|entry| {
                let (domain, backend) = entry.split_once(' ').unwrap();
                (domain.to_string(), backend.to_string())
            })
            .collect();
        fs::write(
            root.join(STREAM),
            crate::adapters::nginx::render_fresh(&routes, "legacy", "127.0.0.1:8443").unwrap(),
        )
        .unwrap();
        let old_panel = fs::read_to_string(recorded.join("root/files").join(PANEL))
            .unwrap()
            .replace(PROXY_LISTENER, "")
            .replace("X-Forwarded-For $remote_addr;", "X-Forwarded-For $proxy_add_x_forwarded_for;");
        fs::write(root.join(PANEL), old_panel).unwrap();
        for name in [".mtproxy-owned", ".env"] {
            fs::copy(recorded.join("root/files/opt/mtproxy-shared443").join(name), project.join(name)).unwrap();
        }
        let mut state = TransactionState::from_value(
            &serde_json::from_slice(&fs::read(recorded.join("journal/state.json")).unwrap()).unwrap(),
        )
        .unwrap();
        // Import the Python checkpoint shapes, narrowing only the unrelated fixture's scope.
        state.checkpoints.retain(|checkpoint| ["core", "nginx"].contains(&checkpoint.adapter.as_str()));
        for checkpoint in &mut state.checkpoints {
            checkpoint.ownership.retain(|path, _| {
                [
                    "/etc/nginx/conf.d/proxy-control-panel.conf",
                    "/etc/nginx/stream.d/proxy-control.conf",
                    "/opt/mtproxy-shared443/.mtproxy-owned",
                    "/opt/mtproxy-shared443/.env",
                ]
                .contains(&path.as_str())
            });
            checkpoint
                .data
                .get_mut("ownership")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .retain(|path, _| checkpoint.ownership.contains_key(path));
            for (path, entry) in &mut checkpoint.ownership {
                let digest = sha256_hex(&fs::read(root.join(path.trim_start_matches('/'))).unwrap());
                entry.sha256 = digest.clone();
                replace_digest(&mut checkpoint.data.get_mut("ownership").unwrap()[path], &digest).unwrap();
                if path.ends_with("/stream.d/proxy-control.conf") {
                    checkpoint.data.insert("owned_sha256".into(), Value::String(digest));
                }
            }
        }
        state.plan_digest = plan.digest();
        state.accepted_digest = state.plan_digest.clone();
        let store = TransactionStore::new(root).unwrap();
        store.write_plan(&plan).unwrap();
        crate::engine::persist(&store, &state).unwrap();
        fs::set_permissions(store.directory(), fs::Permissions::from_mode(0o700)).unwrap();
        durable_mkdir(&root.join(STATE), 0o700).unwrap();
        fs::write(project.join("operator.conf"), b"operator config remains untouched\n").unwrap();
        (directory, project, store)
    }

    fn journal_bytes(store: &TransactionStore) -> Vec<Vec<u8>> {
        ["plan.json", "state.json", "ownership.json", "report.json"]
            .iter()
            .map(|name| fs::read(store.directory().join(name)).unwrap())
            .collect()
    }

    #[test]
    fn journal_write_failures_restore_running_configs_plan_and_ownership() {
        use crate::store::JournalFile;
        use std::cell::RefCell;

        for fault in [JournalFile::Plan, JournalFile::State, JournalFile::Ownership, JournalFile::Report] {
            let (directory, project, store) = journal_predecessor("ingress-journal-failure");
            let root = directory.path();
            let before = journal_bytes(&store);
            let stream = fs::read(root.join(STREAM)).unwrap();
            let panel = fs::read(root.join(PANEL)).unwrap();
            let operator = fs::read(project.join(".env")).unwrap();
            let mut fired = false;
            store.set_fault_hook(Some(Box::new(move |file, _| {
                if file == fault && !fired {
                    fired = true;
                    return Err(crate::error::Error::other("OSError", "injected journal write"));
                }
                Ok(())
            })));
            let running = RefCell::new(Vec::new());
            let reload = |_runner: &dyn HostRunner| {
                running.borrow_mut().push((fs::read(root.join(STREAM))?, fs::read(root.join(PANEL))?));
                Ok(())
            };
            let runner = RecordingRunner::new();
            let error = upgrade_inner(&project, root, true, &runner, &reload, &store).unwrap_err();
            assert!(error.to_string().contains("original configuration restored"), "{fault:?}: {error}");
            assert_eq!(
                *running.borrow(),
                vec![
                    (stream_template(&stream, "127.0.0.1:8443").unwrap(), panel_template(&panel).unwrap().0),
                    (stream.clone(), panel.clone()),
                ]
            );
            assert_eq!(fs::read(root.join(STREAM)).unwrap(), stream);
            assert_eq!(fs::read(root.join(PANEL)).unwrap(), panel);
            assert_eq!(journal_bytes(&store), before, "{fault:?}");
            assert_eq!(fs::read(project.join(".env")).unwrap(), operator);
            assert_eq!(fs::read(project.join("operator.conf")).unwrap(), b"operator config remains untouched\n");
            let backup = fs::read_dir(root.join(STATE)).unwrap().next().unwrap().unwrap().path();
            assert_eq!(fs::read(backup.join("stream.conf")).unwrap(), stream);
            assert_eq!(fs::read(backup.join("panel.conf")).unwrap(), panel);
            for (index, name) in ["plan.json", "state.json", "ownership.json", "report.json"].iter().enumerate() {
                assert_eq!(fs::read(backup.join(name)).unwrap(), before[index]);
            }
            assert_owned(root, &store.read_state().unwrap().ownership(true).unwrap(), &agent_managed_paths()).unwrap();
        }
    }

    #[test]
    fn managed_reload_failure_keeps_original_journal_and_templates() {
        let (directory, project, store) = journal_predecessor("ingress-managed-reload");
        let root = directory.path();
        let journal = journal_bytes(&store);
        let stream = fs::read(root.join(STREAM)).unwrap();
        let panel = fs::read(root.join(PANEL)).unwrap();
        let runner = RecordingRunner::new();
        runner.reply_once(&["systemctl", "reload", "nginx"], Reply::exit(1, "", "failed"));
        let reload = |runner: &dyn HostRunner| run_checked(runner, &["systemctl", "reload", "nginx"]);
        let error = upgrade_with_reload(&project, root, true, &runner, &reload).unwrap_err();
        assert!(error.to_string().contains("original configuration restored"));
        assert_eq!(journal_bytes(&store), journal);
        assert_eq!(fs::read(root.join(STREAM)).unwrap(), stream);
        assert_eq!(fs::read(root.join(PANEL)).unwrap(), panel);
    }

    #[test]
    fn already_approved_proxy_semantics_keep_the_original_plan_digest() {
        let (directory, project, store) = journal_predecessor("ingress-current-plan");
        let mut plan = store.read_plan().unwrap();
        let action = plan.actions.iter_mut().find(|action| action.adapter == "nginx").unwrap();
        action.mutations.extend(["client_ip=proxy".into(), "panel_tls_backend=127.0.0.1:8443".into()]);
        let mut state = store.read_state().unwrap();
        state.plan_digest = plan.digest();
        state.accepted_digest = state.plan_digest.clone();
        store.write_plan(&plan).unwrap();
        crate::engine::persist(&store, &state).unwrap();
        let before = fs::read(store.plan_path()).unwrap();
        upgrade_with_reload(&project, directory.path(), true, &RecordingRunner::new(), &|_| Ok(())).unwrap();
        assert_eq!(fs::read(store.plan_path()).unwrap(), before);
        let updated = store.read_state().unwrap();
        assert_eq!(updated.plan_digest, state.plan_digest);
        assert_eq!(updated.accepted_digest, state.accepted_digest);
        assert_owned(directory.path(), &updated.ownership(true).unwrap(), &agent_managed_paths()).unwrap();
    }

    #[test]
    fn existing_router_keeps_its_original_rollback_backup_owned_through_repair() {
        use crate::adapter::Adapter;
        use crate::adapters::{nginx::NginxAdapter, AdapterContext};

        let (directory, project, store) = journal_predecessor("ingress-original-backup");
        let root = directory.path();
        let observed_root = root.to_path_buf();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            if call.argv == ["nginx", "-T"] {
                let stream = fs::read_to_string(observed_root.join(STREAM)).unwrap();
                return Some(Reply::ok(&format!(
                    "# configuration file /etc/nginx/nginx.conf:\nstream {{ include /etc/nginx/stream.d/*.conf; }}\n# configuration file /etc/nginx/stream.d/proxy-control.conf:\n{stream}"
                )));
            }
            Some(Reply::ok(""))
        }));
        let adapter =
            NginxAdapter::new(&AdapterContext { root: root.into(), tree: root.into(), runner: runner.clone() });
        let mut plan = store.read_plan().unwrap();
        let action = plan.actions.iter_mut().find(|action| action.adapter == "nginx").unwrap();
        *action.mutations.iter_mut().find(|entry| entry.starts_with("path_kind=")).unwrap() = "path_kind=file".into();
        let data = adapter.apply(action, adapter.prepare(action).unwrap()).unwrap();
        let backup = data["backup_path"].as_str().unwrap().to_string();
        let original = fs::read(root.join(backup.trim_start_matches('/'))).unwrap();
        let mut state = store.read_state().unwrap();
        let checkpoint = state.checkpoints.iter_mut().find(|checkpoint| checkpoint.adapter == "nginx").unwrap();
        let entry = checkpoint.ownership.remove("/etc/nginx/stream.d/proxy-control.conf").unwrap();
        checkpoint.ownership.insert(backup.clone(), entry);
        checkpoint.data = data;
        let original_ownership = checkpoint.ownership.clone();
        state.plan_digest = plan.digest();
        state.accepted_digest = state.plan_digest.clone();
        store.write_plan(&plan).unwrap();
        crate::engine::persist(&store, &state).unwrap();
        upgrade_with_reload(&project, root, true, runner.as_ref(), &|_| Ok(())).unwrap();
        let updated = store.read_state().unwrap();
        let nginx = updated.checkpoint("nginx.routes").unwrap();
        assert_eq!(nginx.ownership, original_ownership);
        let plan = store.read_plan().unwrap();
        let action = plan.actions.iter().find(|action| action.adapter == "nginx").unwrap();
        adapter.repair(action, nginx.data.clone()).unwrap();
        assert_eq!(fs::read(root.join(backup.trim_start_matches('/'))).unwrap(), original);
        assert_owned(root, &updated.ownership(true).unwrap(), &agent_managed_paths()).unwrap();
    }

    #[test]
    fn incompatible_or_drifted_journals_refuse_before_mutating_ingress() {
        for defect in
            ["origin", "interrupted", "declaration", "operator-drift", "plan", "derived", "owner", "missing-owner"]
        {
            let (directory, project, store) = journal_predecessor("ingress-preflight");
            let root = directory.path();
            let mut state = store.read_state().unwrap();
            match defect {
                "origin" => state.origin = "runtime-v2".into(),
                "interrupted" => state.status = crate::journal::Status::Applying,
                "declaration" => {
                    state.checkpoints[0].data.get_mut("ownership").unwrap().as_object_mut().unwrap().clear();
                }
                "owner" => {
                    state
                        .checkpoints
                        .iter_mut()
                        .find(|checkpoint| checkpoint.adapter == "core")
                        .unwrap()
                        .data
                        .insert("owner".into(), Value::String("operator".into()));
                }
                "missing-owner" => {
                    let core = state.checkpoints.iter_mut().find(|checkpoint| checkpoint.adapter == "core").unwrap();
                    core.ownership.remove("/etc/nginx/conf.d/proxy-control-panel.conf");
                    core.data
                        .get_mut("ownership")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove("/etc/nginx/conf.d/proxy-control-panel.conf");
                }
                "operator-drift" => fs::write(project.join(".env"), b"operator changed this\n").unwrap(),
                "plan" => {
                    let mut plan = store.read_plan().unwrap();
                    plan.actions
                        .iter_mut()
                        .find(|action| action.adapter == "nginx")
                        .unwrap()
                        .mutations
                        .push("unrecognized=operator-setting".into());
                    state.plan_digest = plan.digest();
                    state.accepted_digest = state.plan_digest.clone();
                    store.write_plan(&plan).unwrap();
                }
                _ => {}
            }
            crate::engine::persist(&store, &state).unwrap();
            if defect == "derived" {
                store.write_ownership(&Default::default()).unwrap();
            }
            let journal = journal_bytes(&store);
            let stream = fs::read(root.join(STREAM)).unwrap();
            let panel = fs::read(root.join(PANEL)).unwrap();
            let runner = RecordingRunner::new();
            let reload = |_runner: &dyn HostRunner| panic!("preflight must not reload");
            assert!(upgrade_with_reload(&project, root, true, &runner, &reload).is_err(), "{defect}");
            assert!(runner.calls().is_empty(), "{defect}");
            assert_eq!(journal_bytes(&store), journal, "{defect}");
            assert_eq!(fs::read(root.join(STREAM)).unwrap(), stream, "{defect}");
            assert_eq!(fs::read(root.join(PANEL)).unwrap(), panel, "{defect}");
        }
        let (directory, project) = predecessor("ingress-runtime-v2");
        let legacy = directory.path().join("var/lib/proxy-control/runtime.json");
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, b"{}\n").unwrap();
        let error =
            upgrade_with_reload(&project, directory.path(), true, &RecordingRunner::new(), &|_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("runtime-v2"));
        assert_eq!(fs::read(directory.path().join(STREAM)).unwrap(), golden("legacy/stream.conf"));
    }

    #[test]
    fn golden_templates_upgrade_byte_for_byte() {
        let (_directory, _project) = predecessor("ingress-golden");
        let panel = golden("legacy/panel.conf");
        let stream = golden("legacy/stream.conf");
        let (new_panel, backend) = panel_template(&panel).unwrap();
        assert_eq!(backend, "127.0.0.1:8443");
        assert_eq!(new_panel, golden("upgraded/panel.conf"));
        assert_eq!(stream_template(&stream, &backend).unwrap(), golden("upgraded/stream.conf"));
    }

    #[test]
    fn predecessor_plan_is_read_only_then_apply_is_idempotent() {
        let (directory, project) = predecessor("ingress-apply");
        let root = directory.path();
        let runner = Arc::new(RecordingRunner::new());
        let reload = |runner: &dyn HostRunner| run_checked(runner, &["systemctl", "reload", "nginx"]);
        assert_eq!(
            upgrade_with_reload(&project, root, false, runner.as_ref(), &reload).unwrap(),
            UpgradeOutcome::Pending
        );
        assert!(runner.calls().is_empty());
        let applied = upgrade_with_reload(&project, root, true, runner.as_ref(), &reload).unwrap();
        let UpgradeOutcome::Applied { backup } = applied else { panic!("not applied") };
        assert_eq!(fs::read(backup.join("stream.conf")).unwrap(), golden("legacy/stream.conf"));
        assert_eq!(fs::read(backup.join("panel.conf")).unwrap(), golden("legacy/panel.conf"));
        assert_eq!(fs::metadata(&backup).unwrap().mode() & 0o777, 0o700);
        let metadata = String::from_utf8(fs::read(backup.join("metadata.json")).unwrap()).unwrap();
        assert!(metadata.starts_with("{\"stream.conf\": {\"path\": "));
        assert!(metadata.contains("\", \"mode\": 420, \"uid\": "));
        assert_eq!(fs::read(root.join(STREAM)).unwrap(), golden("upgraded/stream.conf"));
        assert_eq!(fs::read(root.join(PANEL)).unwrap(), golden("upgraded/panel.conf"));
        assert_eq!(
            upgrade_with_reload(&project, root, true, runner.as_ref(), &reload).unwrap(),
            UpgradeOutcome::Current
        );
        assert_eq!(runner.argvs(), vec![vec!["nginx", "-t"], vec!["systemctl", "reload", "nginx"]]);
    }

    #[test]
    fn cli_inspection_prints_one_python_json_line() {
        let (directory, project) = predecessor("ingress-cli");
        let root = directory.path().to_path_buf();
        let runner = Arc::new(RecordingRunner::new());
        let compose = |root: &Path| {
            let context = crate::adapters::AdapterContext {
                root: root.to_path_buf(),
                tree: root.to_path_buf(),
                runner: runner.clone(),
            };
            crate::cli::Services::with_context(
                context,
                Box::new(|_| Ok(crate::planner::AuditFacts::default())),
                Box::new(|_, _| unreachable!("MCP is not part of ingress upgrade")),
            )
        };
        let arguments = vec![
            "--root".to_string(),
            root.to_string_lossy().into_owned(),
            "ingress-upgrade".to_string(),
            "--project-dir".to_string(),
            project.to_string_lossy().into_owned(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(crate::cli::run(&arguments, &compose, &mut stdout, &mut stderr), 0);
        assert_eq!(String::from_utf8(stdout).unwrap(), "{\"status\": \"pending\", \"files\": [\"stream.d/proxy-control.conf\", \"conf.d/proxy-control-panel.conf\"]}\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn failed_reload_restores_both_configs() {
        let (directory, project) = predecessor("ingress-rollback");
        let root = directory.path();
        let runner = RecordingRunner::new();
        runner.reply_once(&["systemctl", "reload", "nginx"], Reply::exit(1, "", "failed"));
        let reload = |runner: &dyn HostRunner| run_checked(runner, &["systemctl", "reload", "nginx"]);
        let error = upgrade_with_reload(&project, root, true, &runner, &reload).unwrap_err();
        assert!(error.to_string().contains("original configuration restored"));
        assert_eq!(fs::read(root.join(STREAM)).unwrap(), golden("legacy/stream.conf"));
        assert_eq!(fs::read(root.join(PANEL)).unwrap(), golden("legacy/panel.conf"));
        assert_eq!(
            runner.argvs(),
            vec![
                vec!["nginx", "-t"],
                vec!["systemctl", "reload", "nginx"],
                vec!["nginx", "-t"],
                vec!["systemctl", "reload", "nginx"],
            ]
        );
    }

    #[test]
    fn edited_owned_config_is_refused_and_foreign_missing_is_skipped() {
        let (directory, project) = predecessor("ingress-refuse");
        let root = directory.path();
        let panel = root.join(PANEL);
        fs::write(&panel, b"foreign\n").unwrap();
        let runner = RecordingRunner::new();
        let reload = |_runner: &dyn HostRunner| Ok(());
        assert!(upgrade_with_reload(&project, root, false, &runner, &reload).is_err());
        fs::remove_file(root.join(STREAM)).unwrap();
        assert_eq!(upgrade_with_reload(&project, root, true, &runner, &reload).unwrap(), UpgradeOutcome::CoexistManual);
    }

    #[test]
    fn reload_requires_a_live_new_worker_generation() {
        use std::sync::Mutex;

        let runner = RecordingRunner::new();
        let states = Mutex::new(vec![
            (10, BTreeSet::from([20])),
            (10, BTreeSet::from([20])),
            (10, BTreeSet::from([20, 21])),
            (10, BTreeSet::from([21])),
        ]);
        let observe = |_runner: &dyn HostRunner| {
            let mut states = states.lock().unwrap();
            if states.is_empty() {
                Err(UpgradeError::new("Nginx did not activate a new worker generation"))
            } else {
                Ok(states.remove(0))
            }
        };
        reload_with(&runner, &observe).unwrap();
        assert_eq!(runner.argvs(), vec![vec!["systemctl", "reload", "nginx"]]);
        assert!(states.lock().unwrap().is_empty());
    }

    #[test]
    fn socket_collision_is_refused_without_unlinking_foreign_path() {
        let (directory, project) = predecessor("ingress-collision");
        let root = directory.path();
        let occupied = root.join("run/proxy-control-panel-tls.sock");
        fs::create_dir_all(occupied.parent().unwrap()).unwrap();
        fs::write(&occupied, b"foreign").unwrap();
        let runner = RecordingRunner::new();
        let reload = |_runner: &dyn HostRunner| Ok(());
        assert!(upgrade_with_reload(&project, root, true, &runner, &reload).is_err());
        assert_eq!(fs::read(occupied).unwrap(), b"foreign");
        assert_eq!(fs::read(root.join(STREAM)).unwrap(), golden("legacy/stream.conf"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "root-only real Nginx in private mount/network namespaces"]
    fn native_journal_failure_restores_live_nginx_and_original_journal() {
        use crate::store::JournalFile;
        use std::cell::Cell;
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::process::{Child, Command, Stdio};
        use std::sync::atomic::{AtomicBool, Ordering};

        const NAME: &str = "ingress_upgrade::tests::native_journal_failure_restores_live_nginx_and_original_journal";
        if std::env::var_os("PC_INGRESS_PRIVATE_NAMESPACE").is_none() {
            let output = Command::new("unshare")
                .args(["--mount", "--net", "--propagation", "private"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--ignored", "--nocapture"])
                .env("PC_INGRESS_PRIVATE_NAMESPACE", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "native namespace: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        fn checked(program: &str, arguments: &[&std::ffi::OsStr]) {
            let output = Command::new(program).args(arguments).output().unwrap();
            assert!(output.status.success(), "{program}: {}", String::from_utf8_lossy(&output.stderr));
        }
        struct Process(Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let (directory, project, store) = journal_predecessor("ingress-live-journal");
        let root = directory.path();
        checked("mount", &["-t".as_ref(), "tmpfs".as_ref(), "tmpfs".as_ref(), "/run".as_ref()]);
        checked("ip", &["link".as_ref(), "set".as_ref(), "lo".as_ref(), "up".as_ref()]);
        let certificates = root.join("certificates");
        let certificate = certificates.join("live/relay.example.com");
        fs::create_dir_all(&certificate).unwrap();
        checked(
            "openssl",
            &[
                "req".as_ref(),
                "-x509".as_ref(),
                "-newkey".as_ref(),
                "rsa:2048".as_ref(),
                "-nodes".as_ref(),
                "-days".as_ref(),
                "1".as_ref(),
                "-subj".as_ref(),
                "/CN=panel.example.com".as_ref(),
                "-keyout".as_ref(),
                certificate.join("privkey.pem").as_os_str(),
                "-out".as_ref(),
                certificate.join("fullchain.pem").as_os_str(),
            ],
        );
        checked("mount", &["--bind".as_ref(), certificates.as_os_str(), "/etc/letsencrypt".as_ref()]);
        fs::write(root.join("etc/nginx/nginx.conf"), format!(
            "load_module /usr/lib/nginx/modules/ngx_stream_module.so;\nuser root;\npid {}/nginx.pid;\nerror_log {}/nginx.log;\nevents {{}}\nhttp {{ access_log off; include {}/{}; }}\nstream {{ include {}/{}; }}\n",
            root.display(), root.display(), root.display(), PANEL, root.display(), STREAM,
        )).unwrap();
        checked("mount", &["--bind".as_ref(), root.join("etc/nginx").as_os_str(), "/etc/nginx".as_ref()]);
        let listener = TcpListener::bind("127.0.0.1:8787").unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let upstream = std::thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                        let mut request = Vec::new();
                        let mut buffer = [0; 2048];
                        while !request.ends_with(b"\r\n\r\n") {
                            let size = socket.read(&mut buffer).unwrap();
                            if size == 0 {
                                break;
                            }
                            request.extend_from_slice(&buffer[..size]);
                        }
                        let request = String::from_utf8(request).unwrap();
                        let forwarded =
                            request.lines().find_map(|line| line.strip_prefix("X-Forwarded-For: ")).unwrap();
                        write!(socket, "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{forwarded}", forwarded.len())
                            .unwrap();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => panic!("native upstream: {error}"),
                }
            }
        });
        let nginx = Process(
            Command::new("nginx")
                .args(["-g", "daemon off;"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect("127.0.0.1:443").is_err() {
            assert!(Instant::now() < deadline, "private Nginx did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        let request = || {
            let output = Command::new("curl")
                .args([
                    "--silent",
                    "--show-error",
                    "--insecure",
                    "--noproxy",
                    "*",
                    "--max-time",
                    "3",
                    "--resolve",
                    "panel.example.com:443:127.0.0.1",
                    "-H",
                    "X-Forwarded-For: 203.0.113.7",
                    "https://panel.example.com/",
                ])
                .output()
                .unwrap();
            assert!(output.status.success(), "real request: {}", String::from_utf8_lossy(&output.stderr));
            String::from_utf8(output.stdout).unwrap()
        };
        assert_eq!(request(), "203.0.113.7, 127.0.0.1");
        let original = journal_bytes(&store);
        let mut fired = false;
        store.set_fault_hook(Some(Box::new(move |file, _| {
            if file == JournalFile::State && !fired {
                fired = true;
                return Err(crate::error::Error::other("OSError", "injected native state write"));
            }
            Ok(())
        })));
        let generation = Cell::new(0);
        let children = || -> BTreeSet<u32> {
            fs::read_to_string(format!("/proc/{}/task/{}/children", nginx.0.id(), nginx.0.id()))
                .unwrap()
                .split_whitespace()
                .map(|pid| pid.parse().unwrap())
                .collect()
        };
        let reload = |_runner: &dyn HostRunner| {
            let old = children();
            checked("nginx", &["-s".as_ref(), "reload".as_ref()]);
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut previous = BTreeSet::new();
            loop {
                let current = children();
                let fresh: BTreeSet<_> = current.difference(&old).copied().collect();
                // This smoke has no long-lived clients: wait for the old acceptors to exit,
                // not merely for their replacement to have forked.
                if current.is_disjoint(&old) && !fresh.is_disjoint(&previous) {
                    break;
                }
                assert!(Instant::now() < deadline, "private Nginx did not activate new workers");
                previous = fresh;
                std::thread::sleep(Duration::from_millis(20));
            }
            generation.set(generation.get() + 1);
            assert_eq!(request(), if generation.get() == 1 { "127.0.0.1" } else { "203.0.113.7, 127.0.0.1" });
            Ok(())
        };
        let error = upgrade_inner(&project, root, true, &pc_host::runner::SystemRunner, &reload, &store).unwrap_err();
        assert!(error.to_string().contains("original configuration restored"), "{error}");
        assert_eq!(generation.get(), 2);
        assert_eq!(journal_bytes(&store), original);
        assert_owned(root, &store.read_state().unwrap().ownership(true).unwrap(), &agent_managed_paths()).unwrap();
        drop(nginx);
        stop.store(true, Ordering::Relaxed);
        upstream.join().unwrap();
    }
}
