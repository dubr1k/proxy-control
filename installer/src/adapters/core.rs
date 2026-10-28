//! Core's owned Compose generation and acceptance (`installer/adapters/core.py`). The action
//! and checkpoint are deliberately strict: both survive in journals written by the Python
//! installer, and neither may acquire an unreviewed host path or a secret.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_long};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pc_host::fs::{
    atomic_write, durable_copy2, durable_mkdir, durable_remove, fsync_directory, fsync_tree, root_path, sha256_file,
    sha256_hex, sha256_reader, token_hex,
};
use pc_host::net::{ClientOptions, HttpsClient, NetError, Redirects, Request as HttpsRequest, Roots};
use pc_host::runner::{Bounded, Capture, HostRunner, RunOptions, RunOutput, QUERY_TIMEOUT};
use serde_json::{json, Map, Value};

use crate::adapter::Adapter;
use crate::adapters::AdapterContext;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::InstallerConfig;
use crate::planner::{Action, AuditFacts, Evidence};

const PROJECT: &str = "/opt/mtproxy-shared443";
const PROBE: &str = "/usr/local/libexec/mtproxy-respq-probe";
const PROBE_IMAGE: &str = "mtproxy-respq-probe:1.0.0";
const TDLIB_PIN: &str = "0.1008066.0";
const COMPOSE_PROJECT: &str = "proxy_panel_by_dubr1k";
const COMPOSE_PROJECTS: [&str; 2] = [COMPOSE_PROJECT, "mtproxy"];
const VERSION_OVERRIDE: &str = "version-overrides/compose.versions.yaml";
const PANEL_VHOST: &str = "/etc/nginx/conf.d/proxy-control-panel.conf";
const PANEL_APP_PORT: u16 = 8787;
const MCP_APP_PORT: u16 = 8793;
const ACCEPTANCE_PREFIX: &str = "pc-acceptance-";
const MARKER: &str = ".mtproxy-owned";
const BOOTSTRAP_MARKER: &str = ".panel-bootstrapped";
const ACCEPTANCE_OWNER: &str = ".core-acceptance-owner";
const ACCEPTANCE_PENDING: &str = ".core-acceptance-pending";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[path = "core_acceptance.rs"]
pub(super) mod core_acceptance;
use core_acceptance::require_acceptance;
pub use core_acceptance::CoreAcceptance;

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;

const COPY_FILES: &[&str] = &[
    "compose.yaml",
    "compose.mieru.yaml",
    "compose.naive.yaml",
    "compose.xray-router.yaml",
    "compose.amneziawg.yaml",
    "compose.trusttunnel.yaml",
    "compose.mcp.yaml",
    "uninstall.sh",
    "VERSION",
];
const COPY_DIRECTORIES: &[&str] = &[
    "docker",
    "installer",
    "mcp_server",
    "mieru_manager",
    "naive_manager",
    "panel",
    "xray_router_manager",
    "awg_manager",
    "trusttunnel_manager",
    "pc_common",
    // The Rust manager and installer images build from this same copied context.
    "pc_host",
    "installer_core",
];
const REQUIRED_CREDENTIALS: &[&str] =
    &["secrets/users.conf", "secrets/telemt-api-token", "secrets/panel-bootstrap-password"];
const PRESERVED_CREDENTIALS: &[&str] =
    &["secrets/users.conf", "secrets/telemt-api-token", "secrets/panel-bootstrap-password", "secrets/panel-master-key"];
const ADJACENT_CREDENTIALS: &[&str] = &[
    "secrets/naive-manager-token",
    "secrets/xray-router-manager-token",
    "secrets/xray-router-ingress-naive",
    "secrets/xray-router-ingress-mieru",
    "secrets/mcp-token",
    "secrets/mcp-panel-key",
    "secrets/awg-manager-token",
    "secrets/trusttunnel-manager-token",
];
const ADJACENT_SERVICES: &[&str] = &[
    "naive-manager",
    "mieru-manager",
    "xray-router",
    "xray-router-ingress",
    "awg-manager",
    "trusttunnel-manager",
    "mcp",
];
const CHECKPOINT_KEYS: &[&str] = &[
    "acceptance_name",
    "adoption",
    "owner",
    "ownership",
    "planned_ownership",
    "probe_expected_sha256",
    "probe_image_owner",
    "probe_image_preexisting",
    "probe_preexisting",
    "project_created",
    "project_marker_value",
];

fn core(message: impl Into<String>) -> Error {
    Error::other("CoreError", message)
}

fn acceptance(message: impl Into<String>) -> Error {
    Error::other("AcceptanceError", message)
}

fn collision() -> Error {
    Error::other("_AcceptanceCollision", "Core acceptance failed: temporary-user collision")
}

fn lexists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn mode(path: &Path) -> io::Result<u32> {
    Ok(fs::metadata(path)?.mode() & 0o7777)
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn safe_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && !value.starts_with(ACCEPTANCE_PREFIX)
}

fn acceptance_name(value: &str) -> bool {
    value.strip_prefix(ACCEPTANCE_PREFIX).is_some_and(|suffix| is_hex(suffix, 16))
}

fn domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels[..labels.len() - 1] {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            || !bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return false;
        }
    }
    let suffix = labels[labels.len() - 1];
    (2..=63).contains(&suffix.len()) && suffix.bytes().all(|byte| byte.is_ascii_alphabetic())
}

fn valid_backend(value: &str) -> bool {
    if value == "audited" {
        return true;
    }
    if let Some(path) = value.strip_prefix("unix:") {
        return path.starts_with('/')
            && !path.split('/').any(|part| part == "..")
            && !value.contains('\0')
            && !value.chars().any(char::is_whitespace)
            && !value.contains(['|', ';']);
    }
    let Some((host, port)) = value.rsplit_once(':') else { return false };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Ok(port) = port.parse::<u16>() else { return false };
    if port == 0 {
        return false;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|part| part.strip_suffix(']')) {
        return !inner.is_empty() && inner.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b':');
    }
    let bytes = host.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn validate_users(users: &[String]) -> Result<(), Error> {
    let mut unique = BTreeSet::new();
    if users.is_empty() || users.iter().any(|name| !safe_name(name) || !unique.insert(name)) {
        return Err(core("Core users must be unique safe names"));
    }
    Ok(())
}

fn decode_routes(value: &str) -> Result<Vec<(String, String)>, Error> {
    if value == "none" {
        return Ok(Vec::new());
    }
    let mut routes = Vec::new();
    let mut names = BTreeSet::new();
    for encoded in value.split(';') {
        let Some((name, backend)) = encoded.split_once('|') else {
            return Err(core("Core action has invalid adjacent SNI routes"));
        };
        if !domain(name) || !valid_backend(backend) {
            return Err(core("Core action has invalid adjacent SNI routes"));
        }
        let name = name.to_ascii_lowercase();
        if !names.insert(name.clone()) {
            return Err(core("Core action has duplicate adjacent SNI routes"));
        }
        routes.push((name, backend.to_string()));
    }
    routes.sort();
    Ok(routes)
}

fn encode_routes(routes: &[(String, String)]) -> String {
    if routes.is_empty() {
        "none".to_string()
    } else {
        routes.iter().map(|(domain, backend)| format!("{domain}|{backend}")).collect::<Vec<_>>().join(";")
    }
}

#[derive(Debug, Clone)]
struct Selection {
    proxy_domain: String,
    panel_domain: String,
    subscription_domain: Option<String>,
    mcp_domain: Option<String>,
    users: Vec<String>,
    proxy_backend_port: u16,
    panel_app_port: u16,
    panel_tls_port: u16,
    adjacent_sni: Vec<(String, String)>,
}

impl Selection {
    fn read(action: &Action) -> Result<Self, Error> {
        if action.adapter != "core" || action.id != "core.runtime" || action.owner != "proxy-control:core" {
            return Err(core("Core action is invalid"));
        }
        let mut values = BTreeMap::new();
        for mutation in &action.mutations {
            let Some((key, value)) = mutation.split_once('=') else { return Err(core("Core action is invalid")) };
            if key.is_empty() || values.insert(key, value).is_some() {
                return Err(core("Core action is invalid"));
            }
        }
        values.entry("panel-tls-port").or_insert("8443");
        const KEYS: &[&str] = &[
            "project",
            "proxy-domain",
            "panel-domain",
            "subscription-domain",
            "mcp-domain",
            "users",
            "proxy-backend-port",
            "panel-app-port",
            "panel-tls-port",
            "probe",
            "probe-image",
            "prebuilt-tdlib",
            "adjacent-sni",
        ];
        if values.len() != KEYS.len() || values.keys().any(|key| !KEYS.contains(key)) {
            return Err(core("Core action is invalid"));
        }
        let get = |key| values[key];
        let proxy = get("proxy-domain");
        let panel = get("panel-domain");
        let subscription = get("subscription-domain").to_ascii_lowercase();
        let mcp = get("mcp-domain").to_ascii_lowercase();
        let owned = [proxy.to_ascii_lowercase(), panel.to_ascii_lowercase()];
        if get("project") != PROJECT
            || get("probe") != PROBE
            || get("probe-image") != PROBE_IMAGE
            || get("prebuilt-tdlib") != TDLIB_PIN
            || !domain(proxy)
            || !domain(panel)
            || proxy == panel
            || (!subscription.is_empty() && (!domain(&subscription) || owned.contains(&subscription)))
            || (!mcp.is_empty() && (!domain(&mcp) || owned.contains(&mcp) || mcp == subscription))
        {
            return Err(core("Core action is invalid"));
        }
        let users: Vec<String> = get("users").split(',').map(str::to_string).collect();
        validate_users(&users)?;
        let adjacent_sni = decode_routes(get("adjacent-sni"))?;
        let port = |key| -> Result<u16, Error> {
            let value = get(key);
            // Python's int() accepts a sign, leading zeros and surrounding whitespace.
            let parsed = value.trim().parse::<i32>().map_err(|_| core("Core action is invalid"))?;
            u16::try_from(parsed).ok().filter(|number| *number >= 1024).ok_or_else(|| core("Core action is invalid"))
        };
        Ok(Selection {
            proxy_domain: proxy.to_ascii_lowercase(),
            panel_domain: panel.to_ascii_lowercase(),
            subscription_domain: (!subscription.is_empty()).then_some(subscription),
            mcp_domain: (!mcp.is_empty()).then_some(mcp),
            users,
            proxy_backend_port: port("proxy-backend-port")?,
            panel_app_port: port("panel-app-port")?,
            panel_tls_port: port("panel-tls-port")?,
            adjacent_sni,
        })
    }
}

fn ownership_entry(sha256: String, preserve: bool) -> Value {
    json!({"preserve": preserve, "sha256": sha256})
}

fn validate_ownership(entries: &Map<String, Value>) -> Result<(), Error> {
    for (path, value) in entries {
        let Some(entry) = value.as_object() else { return Err(core("Core checkpoint ownership is invalid")) };
        if !path.starts_with('/')
            || path.split('/').any(|part| part == "..")
            || entry.len() != 2
            || !entry.get("preserve").is_some_and(Value::is_boolean)
            || !entry.get("sha256").and_then(Value::as_str).is_some_and(|sha| is_hex(sha, 64))
        {
            return Err(core("Core checkpoint ownership is invalid"));
        }
    }
    Ok(())
}

/// A path the panel ownership handoff may have rebased onto a newer release: below the project
/// directory, in a synced entry (`PANEL_SYNC`). The journal's planned generation predates it.
fn rebased_panel_path(absolute: &str) -> bool {
    absolute.strip_prefix(PROJECT).and_then(|rest| rest.strip_prefix('/')).is_some_and(|relative| {
        let mut parts = relative.split('/');
        relative.split('/').all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains('\0'))
            && parts.next().is_some_and(pc_host::archive::handoff_allows)
    })
}

fn owned_path_in_scope(absolute: &str, selected: &Selection) -> bool {
    if absolute == PROBE || absolute == PANEL_VHOST {
        return true;
    }
    if let Some(domain) = absolute.strip_prefix("/var/www/").and_then(|rest| rest.strip_suffix("/index.html")) {
        return domain == selected.proxy_domain || domain == selected.panel_domain;
    }
    absolute.strip_prefix(PROJECT).and_then(|rest| rest.strip_prefix('/')).is_some_and(|relative| {
        !relative.is_empty()
            && relative.split('/').all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains('\0'))
            && (COPY_FILES.contains(&relative)
                || [MARKER, ACCEPTANCE_OWNER, ".env"].contains(&relative)
                // Prior installer journals own this exact retired file; permit its removal,
                // never arbitrary additional files below the old scripts directory.
                || relative == "scripts/proxyctl.py"
                || COPY_DIRECTORIES.iter().any(|directory| {
                    relative.strip_prefix(directory).is_some_and(|tail| tail.starts_with('/') && tail.len() > 1)
                }))
    })
}

#[derive(Debug, Clone)]
struct CoreCheckpoint {
    acceptance_name: String,
    adoption: String,
    owner: String,
    ownership: Map<String, Value>,
    planned_ownership: Map<String, Value>,
    probe_expected_sha256: String,
    probe_image_owner: String,
    probe_image_preexisting: Option<String>,
    probe_preexisting: bool,
    project_created: bool,
    project_marker_value: Option<String>,
}

impl CoreCheckpoint {
    fn read(data: &CheckpointData, action: &Action, applied: bool) -> Result<Self, Error> {
        if data.len() != CHECKPOINT_KEYS.len() || data.keys().any(|key| !CHECKPOINT_KEYS.contains(&key.as_str())) {
            return Err(core("Core checkpoint is invalid"));
        }
        let invalid = || core("Core checkpoint is invalid");
        let text = |key| data.get(key).and_then(Value::as_str).ok_or_else(invalid);
        let acceptance_name = text("acceptance_name")?.to_string();
        let adoption = text("adoption")?.to_string();
        let owner = text("owner")?.to_string();
        let ownership = data.get("ownership").and_then(Value::as_object).ok_or_else(invalid)?.clone();
        let planned_ownership = data.get("planned_ownership").and_then(Value::as_object).ok_or_else(invalid)?.clone();
        let probe_expected_sha256 = text("probe_expected_sha256")?.to_string();
        let probe_image_owner = text("probe_image_owner")?.to_string();
        let probe_image_preexisting = match data.get("probe_image_preexisting") {
            Some(Value::Null) => None,
            Some(Value::String(value)) => Some(value.clone()),
            _ => return Err(invalid()),
        };
        let probe_preexisting = data.get("probe_preexisting").and_then(Value::as_bool).ok_or_else(invalid)?;
        let project_created = data.get("project_created").and_then(Value::as_bool).ok_or_else(invalid)?;
        let project_marker_value = match data.get("project_marker_value") {
            Some(Value::Null) => None,
            Some(Value::String(value)) => Some(value.clone()),
            _ => return Err(invalid()),
        };
        if !self::acceptance_name(&acceptance_name)
            || !matches!(adoption.as_str(), "absent" | "recovery")
            || owner != action.owner
            || project_created != (adoption == "absent")
            || (adoption == "absent" && !project_marker_value.as_deref().is_some_and(|value| is_hex(value, 32)))
            || (adoption == "recovery" && project_marker_value.is_some())
            || planned_ownership.is_empty()
            || !is_hex(&probe_expected_sha256, 64)
            || !is_hex(&probe_image_owner, 32)
            || probe_image_preexisting.as_deref().is_some_and(|value| !image_identity(value))
            || (!applied && !ownership.is_empty())
        {
            return Err(invalid());
        }
        validate_ownership(&planned_ownership)?;
        if applied {
            validate_ownership(&ownership)?;
        }
        Ok(CoreCheckpoint {
            acceptance_name,
            adoption,
            owner,
            ownership,
            planned_ownership,
            probe_expected_sha256,
            probe_image_owner,
            probe_image_preexisting,
            probe_preexisting,
            project_created,
            project_marker_value,
        })
    }

    /// A journal digest authenticates bytes, not the paths an operator may roll back. Reject
    /// forged ownership outside this action's project and selected cover domains before any
    /// Compose stop, probe installation, or file removal.
    fn validate_paths(&self, selected: &Selection) -> Result<(), Error> {
        if self.planned_ownership.keys().any(|path| !owned_path_in_scope(path, selected)) {
            return Err(core("Core checkpoint ownership escapes the selected project"));
        }
        for path in self.ownership.keys() {
            let runtime_file = path
                .strip_prefix(PROJECT)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|relative| PRESERVED_CREDENTIALS.contains(&relative) || relative == BOOTSTRAP_MARKER);
            if !self.planned_ownership.contains_key(path) && path != PROBE && !runtime_file && !rebased_panel_path(path)
            {
                return Err(core("Core checkpoint ownership does not match the planned generation"));
            }
        }
        Ok(())
    }

    fn into_data(self) -> CheckpointData {
        let mut data = Map::new();
        data.insert("acceptance_name".into(), json!(self.acceptance_name));
        data.insert("adoption".into(), json!(self.adoption));
        data.insert("owner".into(), json!(self.owner));
        data.insert("ownership".into(), Value::Object(self.ownership));
        data.insert("planned_ownership".into(), Value::Object(self.planned_ownership));
        data.insert("probe_expected_sha256".into(), json!(self.probe_expected_sha256));
        data.insert("probe_image_owner".into(), json!(self.probe_image_owner));
        data.insert("probe_image_preexisting".into(), json!(self.probe_image_preexisting));
        data.insert("probe_preexisting".into(), json!(self.probe_preexisting));
        data.insert("project_created".into(), json!(self.project_created));
        data.insert("project_marker_value".into(), json!(self.project_marker_value));
        data
    }
}

fn image_identity(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedCore {
    compose_yaml: String,
    env_text: String,
    panel_vhost: String,
}

fn panel_vhost(selected: &Selection) -> String {
    let prefix = |name: &str| {
        format!(
            "server {{ listen 127.0.0.1:{} ssl; listen unix:/run/proxy-control-panel-tls.sock ssl proxy_protocol; \
             set_real_ip_from unix:; real_ip_header proxy_protocol; server_name {name}; \
             ssl_certificate /etc/letsencrypt/live/{}/fullchain.pem; \
             ssl_certificate_key /etc/letsencrypt/live/{}/privkey.pem; ",
            selected.panel_tls_port, selected.proxy_domain, selected.proxy_domain
        )
    };
    let panel_proxy = format!(
        "proxy_pass http://127.0.0.1:{}; proxy_set_header Host $host; \
         proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $remote_addr; ",
        selected.panel_app_port
    );
    let mut text = format!(
        "{}location ^~ /s/ {{ access_log off; return 404; }} location / {{ {panel_proxy}}} }}\n",
        prefix(&selected.panel_domain)
    );
    if let Some(subscription) = &selected.subscription_domain {
        text.push_str(&format!(
            "{}access_log off; location ^~ /s/ {{ {panel_proxy}}} location / {{ return 404; }} }}\n",
            prefix(subscription)
        ));
    }
    if let Some(mcp) = &selected.mcp_domain {
        let proxy = format!(
            "proxy_pass http://127.0.0.1:{MCP_APP_PORT}; proxy_http_version 1.1; \
             proxy_set_header Connection \"\"; proxy_set_header Host $host; \
             proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $remote_addr; \
             proxy_buffering off; proxy_read_timeout 3600s; "
        );
        text.push_str(&format!(
            "{}access_log off; location = /healthz {{ return 404; }} location /mcp {{ {proxy}}} \
             location / {{ return 404; }} }}\n",
            prefix(mcp)
        ));
    }
    text
}

fn compose_publishes_telemt_api(compose: &str) -> bool {
    let mut in_mtproxy = false;
    let mut in_ports = false;
    for line in compose.lines() {
        let stripped = line.trim();
        let indent = line.len() - line.trim_start().len();
        if line == "  mtproxy:" {
            in_mtproxy = true;
            in_ports = false;
            continue;
        }
        if in_mtproxy && indent <= 2 && !stripped.is_empty() {
            in_mtproxy = false;
            in_ports = false;
        }
        if !in_mtproxy {
            continue;
        }
        if stripped == "ports:" {
            in_ports = true;
            continue;
        }
        if in_ports && indent <= 4 && !stripped.is_empty() {
            in_ports = false;
        }
        if in_ports {
            for (offset, _) in stripped.match_indices("9091") {
                let before = stripped.as_bytes().get(offset.wrapping_sub(1));
                let after = stripped.as_bytes().get(offset + 4);
                if (offset == 0 || before.is_some_and(|byte| matches!(*byte, b':' | b'\"' | b'\'')))
                    && (after.is_none() || after.is_some_and(|byte| matches!(*byte, b'/' | b'\"' | b'\'')))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn path_sha256(path: &Path) -> Result<String, Error> {
    if is_symlink(path) {
        let target = fs::read_link(path)?;
        let mut text = b"symlink:".to_vec();
        text.extend_from_slice(target.as_os_str().as_bytes());
        Ok(sha256_hex(&text))
    } else {
        Ok(sha256_file(path)?)
    }
}

fn valid_users_file(text: &str) -> bool {
    let mut names = BTreeSet::new();
    let mut count = 0;
    for line in text.lines() {
        let Some((name, secret)) = line.split_once('=') else { return false };
        if !safe_name(name) || !is_hex(secret, 32) || !names.insert(name) {
            return false;
        }
        count += 1;
    }
    count > 0
}

fn valid_master_key_file(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else { return false };
    let Some(object) = value.as_object() else { return false };
    let Some(keys) = object.get("keys").and_then(Value::as_array) else { return false };
    if keys.is_empty() || object.get("schema").and_then(Value::as_i64) != Some(1) {
        return false;
    }
    let Some(active) = object.get("active_key_id").and_then(Value::as_str) else { return false };
    let mut seen = BTreeSet::new();
    for key in keys {
        let Some(entry) = key.as_object() else { return false };
        if !entry.get("state").and_then(Value::as_str).is_some_and(|state| matches!(state, "active" | "retiring"))
            || !entry.get("key_material").and_then(Value::as_str).is_some_and(valid_base64_key)
        {
            return false;
        }
        let Some(id) = entry.get("key_id").and_then(Value::as_str) else { return false };
        if !seen.insert(id) {
            return false;
        }
    }
    seen.contains(active)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let encoded = token_hex::<N>();
    let mut bytes = [0u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| -> u8 {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    bytes
}

fn base64_encode(bytes: &[u8], url_safe: bool, pad: bool) -> String {
    let table = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output.push(table[(first >> 2) as usize] as char);
        output.push(table[((first & 3) << 4 | second >> 4) as usize] as char);
        if chunk.len() > 1 {
            output.push(table[((second & 15) << 2 | third >> 6) as usize] as char);
        } else if pad {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(table[(third & 63) as usize] as char);
        } else if pad {
            output.push('=');
        }
    }
    output
}

fn token_urlsafe<const N: usize>() -> String {
    base64_encode(&random_bytes::<N>(), true, false)
}

fn valid_base64_key(encoded: &str) -> bool {
    let bytes = encoded.as_bytes();
    if !bytes.len().is_multiple_of(4) || bytes.is_empty() {
        return false;
    }
    let mut decoded = 0usize;
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let padding = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 || (padding != 0 && !last) {
            return false;
        }
        if chunk[..4 - padding].iter().any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/'))
            || chunk[..4 - padding].contains(&b'=')
        {
            return false;
        }
        decoded += 3 - padding;
    }
    decoded == 32
}

fn master_key_text(key_id: &str, created_at: u64, key_material: &str) -> String {
    format!(
        "{{\n  \"schema\": 1,\n  \"active_key_id\": \"{key_id}\",\n  \"keys\": [\n    {{\n      \
         \"key_id\": \"{key_id}\",\n      \"state\": \"active\",\n      \"created_at\": {created_at},\n      \
         \"key_material\": \"{key_material}\"\n    }}\n  ]\n}}\n"
    )
}

fn rendered_env(selected: &Selection) -> String {
    let mut allowed = selected.panel_domain.clone();
    if let Some(subscription) = &selected.subscription_domain {
        allowed.push(',');
        allowed.push_str(subscription);
    }
    let mut text = format!(
        "MTPROXY_DOMAIN={}\nMTPROXY_BACKEND_PORT={}\nMTPROXY_COVER_ROOT=/var/www/{}\n\
         MTPROXY_LETSENCRYPT_ROOT=/etc/letsencrypt\nPANEL_ALLOWED_HOSTS={}\nPANEL_HEALTHCHECK_HOST={}\n",
        selected.proxy_domain, selected.proxy_backend_port, selected.proxy_domain, allowed, selected.panel_domain
    );
    if let Some(subscription) = &selected.subscription_domain {
        text.push_str(&format!(
            "PANEL_SUBSCRIPTION_HOST={subscription}\nPANEL_SUBSCRIPTION_URL=https://{subscription}\n"
        ));
    }
    text
}

#[cfg(test)]
trait TestAcceptance: Send + Sync {
    fn run(&self, configured: usize) -> Result<CoreAcceptance, Error>;
    fn cleanup(&self) -> Result<(), Error>;
}

/// Owns Telemt, the panel, their shared Compose project and the TDLib resPQ probe.
pub struct CoreAdapter {
    root: PathBuf,
    tree: PathBuf,
    runner: Arc<dyn HostRunner>,
    #[cfg(test)]
    test_acceptance: Option<Arc<dyn TestAcceptance>>,
}

impl CoreAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self {
            root: context.root.clone(),
            tree: context.tree.clone(),
            runner: context.runner.clone(),
            #[cfg(test)]
            test_acceptance: None,
        }
    }

    fn host(&self, absolute: &str) -> Result<PathBuf, Error> {
        if !absolute.starts_with('/') || absolute.split('/').any(|part| part == "..") {
            return Err(core("Core host path is unsafe"));
        }
        Ok(root_path(&self.root, absolute)?)
    }

    fn host_name(&self, path: &Path) -> Result<String, Error> {
        let relative = path.strip_prefix(&self.root).map_err(|_| core("Core owned path escapes selected root"))?;
        Ok(format!("/{}", relative.to_string_lossy().replace('\\', "/")))
    }

    fn owner(&self) -> Option<(u32, u32)> {
        // On a temporary root, preserve the test operator's uid/gid. Production writes root:root.
        if self.root == Path::new("/") && unsafe { geteuid() } == 0 {
            Some((0, 0))
        } else {
            None
        }
    }

    fn atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
        atomic_write(path, bytes, mode, self.owner())?;
        Ok(())
    }

    fn render(&self, selected: &Selection) -> Result<RenderedCore, Error> {
        let compose_yaml = fs::read_to_string(self.tree.join("compose.yaml"))
            .map_err(|_| core("Core Compose source is unavailable"))?;
        if !compose_yaml.starts_with(&format!("name: {COMPOSE_PROJECT}\n")) {
            return Err(core("Core Compose project identity is invalid"));
        }
        if compose_publishes_telemt_api(&compose_yaml) {
            return Err(core("Telemt API must not be host-published"));
        }
        Ok(RenderedCore { compose_yaml, env_text: rendered_env(selected), panel_vhost: panel_vhost(selected) })
    }

    fn adjacent_routes(config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<(String, String)>, Error> {
        let nginx = facts.topology.get("nginx").and_then(Value::as_object);
        let routes = nginx.and_then(|nginx| nginx.get("sni_routes"));
        let routes = match routes {
            None => return Ok(Vec::new()),
            Some(Value::Object(routes)) => routes,
            _ => return Err(core("audited adjacent SNI routes are invalid")),
        };
        let mut owned =
            BTreeSet::from([config.domains.mtproxy.to_ascii_lowercase(), config.domains.panel.to_ascii_lowercase()]);
        for domain in [config.domains.subscription.as_ref(), config.domains.mcp.as_ref()].into_iter().flatten() {
            owned.insert(domain.to_ascii_lowercase());
        }
        let mut adjacent = Vec::new();
        for (name, backend) in routes {
            let Some(backend) = backend.as_str() else { return Err(core("audited adjacent SNI routes are invalid")) };
            let normalized = name.to_ascii_lowercase();
            if owned.contains(&normalized) {
                continue;
            }
            if !domain(&normalized) || !valid_backend(backend) {
                return Err(core("audited adjacent SNI routes are invalid"));
            }
            adjacent.push((normalized, backend.to_string()));
        }
        adjacent.sort();
        Ok(adjacent)
    }

    fn project_kind(&self, project: &Path) -> Result<&'static str, Error> {
        if !project.exists() {
            return Ok("absent");
        }
        if is_symlink(project) || !project.is_dir() {
            return Err(core("pre-existing project requires explicit migration; refusing overwrite"));
        }
        let names = names(project)?;
        if names.is_empty() {
            return Ok("absent");
        }
        let allowed = [MARKER, BOOTSTRAP_MARKER, ACCEPTANCE_OWNER, ACCEPTANCE_PENDING, "secrets"];
        if !names.contains(MARKER) || names.iter().any(|name| !allowed.contains(&name.as_str())) {
            return Err(core("pre-existing project requires explicit migration; refusing overwrite"));
        }
        self.marker_sha256()?;
        let bootstrap = project.join(BOOTSTRAP_MARKER);
        if lexists(&bootstrap)
            && (is_symlink(&bootstrap)
                || !bootstrap.is_file()
                || mode(&bootstrap)? != 0o600
                || !fs::read_to_string(&bootstrap)?.trim().bytes().all(|byte| byte.is_ascii_hexdigit())
                || !is_hex(fs::read_to_string(&bootstrap)?.trim(), 64))
        {
            return Err(core("panel bootstrap ownership has drifted"));
        }
        self.existing_acceptance_name(project)?;
        let credentials = project.join("secrets");
        if credentials.exists() && (is_symlink(&credentials) || !credentials.is_dir()) {
            return Err(core("pre-existing project credentials are unsafe"));
        }
        if credentials.is_dir() {
            self.validate_existing_credentials(&credentials, false)?;
        }
        Ok("recovery")
    }

    fn marker_sha256(&self) -> Result<String, Error> {
        let path = self.host(&format!("{PROJECT}/{MARKER}"))?;
        if is_symlink(&path)
            || !path.is_file()
            || mode(&path)? != 0o600
            || (self.root == Path::new("/") && (fs::metadata(&path)?.uid(), fs::metadata(&path)?.gid()) != (0, 0))
        {
            return Err(core("runtime project ownership has drifted"));
        }
        Ok(sha256_file(&path)?)
    }

    fn existing_acceptance_name(&self, project: &Path) -> Result<Option<String>, Error> {
        let owner = project.join(ACCEPTANCE_OWNER);
        let pending = project.join(ACCEPTANCE_PENDING);
        if !lexists(&owner) {
            if lexists(&pending) {
                return Err(core("temporary-user ownership has drifted"));
            }
            return Ok(None);
        }
        if is_symlink(&owner)
            || !owner.is_file()
            || mode(&owner)? != 0o600
            || (self.root == Path::new("/") && (fs::metadata(&owner)?.uid(), fs::metadata(&owner)?.gid()) != (0, 0))
        {
            return Err(core("temporary-user ownership has drifted"));
        }
        let value = fs::read_to_string(&owner)?.trim().to_string();
        if !acceptance_name(&value) {
            return Err(core("temporary-user ownership has drifted"));
        }
        if lexists(&pending)
            && (is_symlink(&pending)
                || !pending.is_file()
                || mode(&pending)? != 0o600
                || fs::read_to_string(&pending)?.trim() != value)
        {
            return Err(core("temporary-user ownership has drifted"));
        }
        Ok(Some(value))
    }

    fn validate_existing_credentials(&self, directory: &Path, require_all: bool) -> Result<(), Error> {
        let unsafe_credentials = || core("pre-existing project credentials are unsafe");
        if is_symlink(directory) || !directory.is_dir() {
            return Err(unsafe_credentials());
        }
        let meta = fs::metadata(directory)?;
        if meta.mode() & 0o7777 != 0o700 || (self.root == Path::new("/") && (meta.uid(), meta.gid()) != (0, 0)) {
            return Err(unsafe_credentials());
        }
        let owned: BTreeSet<_> = PRESERVED_CREDENTIALS.iter().map(|path| path.rsplit('/').next().unwrap()).collect();
        let adjacent: BTreeSet<_> = ADJACENT_CREDENTIALS.iter().map(|path| path.rsplit('/').next().unwrap()).collect();
        let present = names(directory)?;
        if present.iter().any(|name| !owned.contains(name.as_str()) && !adjacent.contains(name.as_str()))
            || (require_all
                && REQUIRED_CREDENTIALS.iter().any(|path| !present.contains(path.rsplit('/').next().unwrap())))
        {
            return Err(unsafe_credentials());
        }
        for relative in PRESERVED_CREDENTIALS {
            let name = relative.rsplit('/').next().unwrap();
            let path = directory.join(name);
            if !lexists(&path) {
                continue;
            }
            if is_symlink(&path) || !path.is_file() {
                return Err(unsafe_credentials());
            }
            let meta = fs::metadata(&path)?;
            if meta.mode() & 0o7777 != 0o600 || (self.root == Path::new("/") && (meta.uid(), meta.gid()) != (0, 0)) {
                return Err(unsafe_credentials());
            }
            let text = fs::read_to_string(&path).map_err(|_| unsafe_credentials())?;
            let valid = match name {
                "users.conf" => valid_users_file(&text),
                "telemt-api-token" => {
                    let token = text.trim_end_matches('\n').strip_prefix("Bearer ");
                    token.is_some_and(|token| {
                        (32..=256).contains(&token.len())
                            && token.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                    })
                }
                "panel-bootstrap-password" => {
                    let value = text.trim_end_matches('\n');
                    !value.is_empty() && !value.contains('\n')
                }
                "panel-master-key" => valid_master_key_file(&text),
                _ => unreachable!("only Core's credential names are checked"),
            };
            if !valid {
                return Err(unsafe_credentials());
            }
        }
        Ok(())
    }

    fn planned_ownership(
        &self,
        selected: &Selection,
        name: &str,
        marker_sha: &str,
    ) -> Result<Map<String, Value>, Error> {
        let rendered = self.render(selected)?;
        let mut planned = Map::new();
        let project = self.host(PROJECT)?;
        let mut add = |path: PathBuf, sha: String, preserve: bool| -> Result<(), Error> {
            planned.insert(self.host_name(&path)?, ownership_entry(sha, preserve));
            Ok(())
        };
        add(project.join(MARKER), marker_sha.to_string(), true)?;
        add(project.join(ACCEPTANCE_OWNER), sha256_hex(format!("{name}\n").as_bytes()), false)?;
        add(project.join(".env"), sha256_hex(rendered.env_text.as_bytes()), false)?;
        add(self.host(PANEL_VHOST)?, sha256_hex(rendered.panel_vhost.as_bytes()), false)?;
        for (domain, title) in [(&selected.proxy_domain, "Welcome"), (&selected.panel_domain, "Workspace")] {
            let cover = self.host(&format!("/var/www/{domain}/index.html"))?;
            if !lexists(&cover) {
                add(cover, sha256_hex(cover_text(title).as_bytes()), false)?;
            }
        }
        for relative in COPY_FILES {
            let source = self.tree.join(relative);
            if !source.is_file() {
                return Err(core("installer source generation is incomplete"));
            }
            add(project.join(relative), path_sha256(&source)?, false)?;
        }
        for directory in COPY_DIRECTORIES {
            let source = self.tree.join(directory);
            if !source.is_dir() {
                return Err(core("installer source generation is incomplete"));
            }
            let mut files = Vec::new();
            collect_source_files(&source, Path::new(""), &mut files)?;
            for relative in files {
                add(project.join(directory).join(&relative), path_sha256(&source.join(relative))?, false)?;
            }
        }
        Ok(planned)
    }

    fn safe_project_tree(&self, project: &Path) -> Result<(), Error> {
        let marker = project.join(MARKER);
        if lexists(&marker) && (is_symlink(&marker) || !marker.is_file() || mode(&marker)? != 0o600) {
            return Err(core("runtime project ownership has drifted"));
        }
        for relative in COPY_FILES {
            let path = project.join(relative);
            if let Some(parent) = path.parent() {
                if parent != project && parent.exists() && (is_symlink(parent) || !parent.is_dir()) {
                    return Err(core("runtime project ownership has drifted"));
                }
            }
            if lexists(&path) && (is_symlink(&path) || !path.is_file()) {
                return Err(core("runtime project ownership has drifted"));
            }
        }
        for directory in COPY_DIRECTORIES {
            let path = project.join(directory);
            if path.exists() && (is_symlink(&path) || !path.is_dir()) {
                return Err(core("runtime project ownership has drifted"));
            }
        }
        Ok(())
    }

    fn project_kind_for_apply(&self, project: &Path, recovery: bool) -> Result<bool, Error> {
        if is_symlink(project) || !project.is_dir() {
            return Ok(false);
        }
        let found = names(project)?;
        if found.is_empty() {
            return Ok(true);
        }
        if !found.contains(MARKER) {
            return Ok(false);
        }
        if found.iter().all(|name| matches!(name.as_str(), ".mtproxy-owned" | "secrets")) {
            return Ok(recovery);
        }
        let mut allowed: BTreeSet<&str> =
            BTreeSet::from([MARKER, BOOTSTRAP_MARKER, ACCEPTANCE_OWNER, ACCEPTANCE_PENDING, "secrets", ".env"]);
        for relative in COPY_FILES {
            allowed.insert(relative.split('/').next().unwrap());
        }
        allowed.extend(COPY_DIRECTORIES.iter().copied());
        Ok(recovery && found.iter().all(|name| allowed.contains(name.as_str())))
    }

    fn write_generation(&self, selected: &Selection, marker_value: Option<&str>) -> Result<(), Error> {
        let rendered = self.render(selected)?;
        let project = self.host(PROJECT)?;
        if project.exists() && !self.project_kind_for_apply(&project, true)? {
            return Err(core("pre-existing project requires explicit migration; refusing overwrite"));
        }
        durable_mkdir(&project, 0o777)?;
        self.safe_project_tree(&project)?;
        let marker = project.join(MARKER);
        if !marker.exists() {
            let generated;
            let value = match marker_value {
                Some(value) => value,
                None => {
                    generated = token_hex::<16>();
                    &generated
                }
            };
            self.atomic(&marker, format!("{value}\n").as_bytes(), 0o600)?;
        }
        if !self.tree.is_dir() {
            return Err(core("installer source directory does not exist"));
        }
        for relative in COPY_FILES {
            durable_copy2(&self.tree.join(relative), &project.join(relative))?;
        }
        for directory in COPY_DIRECTORIES {
            copy_tree(&self.root, &self.tree.join(directory), &project.join(directory))?;
            fsync_tree(&project.join(directory))?;
        }
        let secret_dir = project.join("secrets");
        if secret_dir.exists() && (is_symlink(&secret_dir) || !secret_dir.is_dir()) {
            return Err(core("pre-existing project credentials are unsafe"));
        }
        durable_mkdir(&secret_dir, 0o700)?;
        self.validate_existing_credentials(&secret_dir, false)?;
        fs::set_permissions(&secret_dir, fs::Permissions::from_mode(0o700))?;
        let existing = read_existing_users(&secret_dir.join("users.conf"))?;
        let mut users = String::new();
        for name in &selected.users {
            let generated;
            let value = match existing.get(name) {
                Some(value) => value,
                None => {
                    generated = token_hex::<16>();
                    &generated
                }
            };
            users.push_str(&format!("{name}={value}\n"));
        }
        self.atomic(&secret_dir.join("users.conf"), users.as_bytes(), 0o600)?;
        let api = secret_dir.join("telemt-api-token");
        if !api.exists() {
            self.atomic(&api, format!("Bearer {}\n", token_urlsafe::<48>()).as_bytes(), 0o600)?;
        }
        let bootstrap = secret_dir.join("panel-bootstrap-password");
        if !bootstrap.exists() {
            self.atomic(&bootstrap, format!("{}\n", self.panel_password()?).as_bytes(), 0o600)?;
        }
        let master = secret_dir.join("panel-master-key");
        if !master.exists() {
            let id = format!("k-{}", token_hex::<4>());
            let created =
                SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| core("system time is invalid"))?.as_secs();
            let material = base64_encode(&random_bytes::<32>(), false, true);
            self.atomic(&master, master_key_text(&id, created, &material).as_bytes(), 0o600)?;
        }
        self.atomic(&project.join(".env"), rendered.env_text.as_bytes(), 0o600)?;
        for (domain, title) in [(&selected.proxy_domain, "Welcome"), (&selected.panel_domain, "Workspace")] {
            let cover = self.host(&format!("/var/www/{domain}/index.html"))?;
            if !cover.exists() {
                self.atomic(&cover, cover_text(title).as_bytes(), 0o644)?;
            }
        }
        let vhost = self.host(PANEL_VHOST)?;
        if is_symlink(&vhost) || (vhost.exists() && !vhost.is_file()) {
            return Err(core("panel TLS vhost path is occupied"));
        }
        self.atomic(&vhost, rendered.panel_vhost.as_bytes(), 0o644)?;
        self.run(&["nginx", "-t"], None)?;
        self.reload_nginx()?;
        Ok(())
    }

    fn panel_password(&self) -> Result<String, Error> {
        let chosen = installer_core::credentials::staged_credentials(&self.root)
            .map_err(|err| core(format!("the staged credentials cannot be used: {err}")))?;
        Ok(chosen
            .and_then(|value| value.panel_password)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(token_urlsafe::<32>))
    }

    fn reload_nginx(&self) -> Result<(), Error> {
        // Same crash-recovery sequence as nginx::reload_nginx: a rejected config while the
        // daemon remains active is never hidden by a restart.
        let reload = self.runner.run(&["systemctl", "reload", "nginx"], &RunOptions::default())?;
        if reload.returncode == 0 {
            return Ok(());
        }
        let active = self.runner.run(&["systemctl", "is-active", "nginx"], &RunOptions::default())?;
        if active.returncode == 0 {
            let detail = sanitize_diagnostic(&String::from_utf8_lossy(&reload.stderr), 900);
            let message = if detail.is_empty() {
                "nginx reload failed".to_string()
            } else {
                format!("nginx reload failed: {detail}")
            };
            return Err(Error::other("TopologyError", message));
        }
        let _ = self.runner.run(&["systemctl", "restart", "nginx"], &RunOptions::default())?;
        let active = self.runner.run(&["systemctl", "is-active", "nginx"], &RunOptions::default())?;
        if active.returncode != 0 {
            return Err(Error::other("TopologyError", "nginx reload failed: Nginx did not come back after a restart"));
        }
        Ok(())
    }

    fn run(&self, argv: &[&str], stdin_path: Option<&Path>) -> Result<(), Error> {
        let options = RunOptions { stdin_path: stdin_path.map(Path::to_path_buf), ..RunOptions::default() };
        let result = self.runner.run(argv, &options)?;
        if result.returncode != 0 {
            return Err(core(command_failure(argv, &result)));
        }
        Ok(())
    }

    fn capture_checked(&self, argv: &[&str]) -> Result<String, Error> {
        self.runner.capture_checked(argv, QUERY_TIMEOUT).map_err(|err| core(err.to_string()))
    }

    fn compose_argv(&self, args: &[&str]) -> Result<Vec<String>, Error> {
        let mut argv = vec!["docker".into(), "compose".into(), "--project-directory".into(), PROJECT.into()];
        let override_path = self.host(&format!("{PROJECT}/{VERSION_OVERRIDE}"))?;
        if override_path.is_file() {
            argv.extend([
                "-f".into(),
                format!("{PROJECT}/compose.yaml"),
                "-f".into(),
                format!("{PROJECT}/{VERSION_OVERRIDE}"),
            ]);
        }
        argv.extend(args.iter().map(|arg| (*arg).to_string()));
        Ok(argv)
    }

    fn compose(&self, args: &[&str]) -> Result<(), Error> {
        let argv = self.compose_argv(args)?;
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.run(&args, None)
    }

    fn compose_present(&self) -> Result<bool, Error> {
        for project in COMPOSE_PROJECTS {
            for resource in ["container", "network"] {
                let label = format!("label=com.docker.compose.project={project}");
                if !self
                    .capture_checked(&["docker", resource, "ls", "--all", "--quiet", "--filter", &label])?
                    .trim()
                    .is_empty()
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn volumes_present(&self) -> Result<bool, Error> {
        for project in COMPOSE_PROJECTS {
            let label = format!("label=com.docker.compose.project={project}");
            if !self.capture_checked(&["docker", "volume", "ls", "--quiet", "--filter", &label])?.trim().is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn purge_runtime_volumes(&self) -> Result<(), Error> {
        const VOLUMES: &[&str] = &[
            "naive-manager-run",
            "mieru-manager-run",
            "xray-router-run",
            "awg-manager-run",
            "trusttunnel-manager-run",
        ];
        let mut selected = Vec::new();
        for project in COMPOSE_PROJECTS {
            let label = format!("label=com.docker.compose.project={project}");
            let present: BTreeSet<String> = self
                .capture_checked(&["docker", "volume", "ls", "--quiet", "--filter", &label])?
                .split_whitespace()
                .map(str::to_string)
                .collect();
            for volume in VOLUMES {
                let name = format!("{project}_{volume}");
                if !present.contains(&name) {
                    continue;
                }
                let raw = self.capture_checked(&["docker", "volume", "inspect", &name])?;
                let value = serde_json::from_str::<Value>(&raw)
                    .map_err(|_| core("runtime volume ownership could not be verified"))?;
                let valid = (|| {
                    let records = value.as_array()?;
                    let [record] = records.as_slice() else { return None };
                    let labels = record.get("Labels")?.as_object()?;
                    Some((record.get("Name")?.as_str()?, labels))
                })();
                let Some((actual_name, labels)) = valid else {
                    return Err(core("runtime volume ownership could not be verified"));
                };
                if actual_name != name
                    || labels.get("com.docker.compose.project").and_then(Value::as_str) != Some(project)
                    || labels.get("com.docker.compose.volume").and_then(Value::as_str) != Some(volume)
                {
                    return Err(core("runtime volume ownership does not match"));
                }
                selected.push(name);
            }
        }
        for name in selected {
            self.capture_checked(&["docker", "volume", "rm", &name])?;
        }
        Ok(())
    }

    fn probe_image_query(&self, format: &str) -> Result<Option<String>, Error> {
        let result = self
            .runner
            .bounded(
                &["docker", "image", "inspect", "--format", format, PROBE_IMAGE],
                Bounded { timeout: Duration::from_secs(30), max_output: 1024 * 1024 },
            )
            .map_err(|_| core("probe image query failed"))?;
        if result.returncode != 0 {
            return Ok(None);
        }
        let value = result.stdout.trim();
        if value.is_empty() || value == "<no value>" {
            return Ok(None);
        }
        if !image_identity(value) {
            return Err(core(if format == "{{.Id}}" {
                "probe image identity is invalid"
            } else {
                "probe image label is invalid"
            }));
        }
        Ok(Some(value.to_string()))
    }

    fn probe_image_identity(&self) -> Result<Option<String>, Error> {
        self.probe_image_query("{{.Id}}")
    }

    fn probe_image_label(&self, label: &str) -> Result<Option<String>, Error> {
        self.probe_image_query(&format!("{{{{ index .Config.Labels \"{label}\" }}}}"))
    }

    fn probe_image_owner(&self) -> Result<Option<String>, Error> {
        let owner = self.probe_image_label("org.proxy-control.respq-probe.owner")?;
        if owner.as_deref().is_some_and(|value| !is_hex(value, 32)) {
            return Err(core("probe image owner is invalid"));
        }
        Ok(owner)
    }

    fn probe_sources_digest(&self) -> Result<String, Error> {
        let root = self.tree.join("probe");
        let mut sources = File::open(root.join("src/index.cjs"))?
            .chain(File::open(root.join("Dockerfile"))?)
            .chain(File::open(root.join("package-lock.json"))?);
        Ok(sha256_reader(&mut sources)?)
    }

    fn probe_image_compatible(&self) -> Result<bool, Error> {
        let sources = self.probe_sources_digest().unwrap_or_default();
        for (label, expected) in
            [("version", "1.0.0"), ("tdlib", TDLIB_PIN), ("tdl", "8.1.0"), ("sources", sources.as_str())]
        {
            if self.probe_image_label(&format!("org.proxy-control.respq-probe.{label}"))?.as_deref() != Some(expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validate_probe(&self, path: &Path, expected: &str) -> Result<(), Error> {
        if is_symlink(path) || !path.is_file() {
            return Err(core("pre-existing protocol probe is not installer-owned"));
        }
        let meta = fs::metadata(path)?;
        if meta.mode() & 0o7777 != 0o750 || (self.root == Path::new("/") && (meta.uid(), meta.gid()) != (0, 0)) {
            return Err(core("protocol probe metadata is not root-owned mode 0750"));
        }
        if sha256_file(path)? != expected {
            return Err(core("pre-existing protocol probe is not installer-owned"));
        }
        Ok(())
    }

    fn install_probe(&self, checkpoint: &CoreCheckpoint) -> Result<(), Error> {
        let destination = self.host(PROBE)?;
        let source = self.tree.join("probe/mtproxy-respq-probe");
        let installer = self.tree.join("probe/install.sh");
        if !source.is_file() || !installer.is_file() {
            return Err(core("pinned TDLib probe sources are unavailable"));
        }
        let expected = sha256_file(&source)?;
        let current = self.probe_image_identity()?;
        if checkpoint.probe_image_preexisting.is_some() && current != checkpoint.probe_image_preexisting {
            return Err(core("pre-existing probe image identity has drifted"));
        }
        if lexists(&destination) {
            self.validate_probe(&destination, &expected)?;
            if current.is_some() {
                if checkpoint.probe_image_preexisting.is_none()
                    && self.probe_image_owner()?.as_deref() != Some(&checkpoint.probe_image_owner)
                {
                    return Err(core("Core owned probe image has drifted"));
                }
                return Ok(());
            }
        }
        if checkpoint.probe_image_preexisting.is_some() {
            durable_copy2(&source, &destination)?;
        } else if current.is_some() {
            if self.probe_image_owner()?.as_deref() != Some(&checkpoint.probe_image_owner) {
                return Err(core("probe image ownership is ambiguous"));
            }
            durable_copy2(&source, &destination)?;
        } else {
            // The release's script is the authoritative Docker build/install command. Its
            // Python lockfile check is being removed by the host-script integrator; check the
            // same pin here too so this adapter never accepts a mismatched build context.
            self.validate_probe_lockfile()?;
            let script = installer.to_string_lossy();
            self.run(&[&script, "--owner-id", &checkpoint.probe_image_owner], None)?;
            if !destination.exists() && self.root != Path::new("/") {
                durable_copy2(&source, &destination)?;
            }
            if self.probe_image_owner()?.as_deref() != Some(&checkpoint.probe_image_owner) {
                return Err(core("probe image ownership label is missing"));
            }
        }
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o750))?;
        self.validate_probe(&destination, &expected)
    }

    fn validate_probe_lockfile(&self) -> Result<(), Error> {
        let text = fs::read_to_string(self.tree.join("probe/package-lock.json"))?;
        let value: Value = serde_json::from_str(&text).map_err(|_| core("locked probe dependency mismatch"))?;
        let deps = value
            .pointer("/packages//dependencies")
            .and_then(Value::as_object)
            .ok_or_else(|| core("locked probe dependency mismatch"))?;
        if deps.len() != 2
            || deps.get("prebuilt-tdlib").and_then(Value::as_str) != Some(TDLIB_PIN)
            || deps.get("tdl").and_then(Value::as_str) != Some("8.1.0")
        {
            return Err(core("locked probe dependency mismatch"));
        }
        Ok(())
    }

    fn write_acceptance_owner(&self, name: &str) -> Result<(), Error> {
        let path = self.host(&format!("{PROJECT}/{ACCEPTANCE_OWNER}"))?;
        if lexists(&path) {
            if is_symlink(&path)
                || !path.is_file()
                || mode(&path)? != 0o600
                || fs::read_to_string(&path)?.trim() != name
            {
                return Err(core("temporary-user ownership has drifted"));
            }
            return Ok(());
        }
        self.atomic(&path, format!("{name}\n").as_bytes(), 0o600)
    }

    fn read_acceptance_owner(&self) -> Result<String, Error> {
        let path = self.host(&format!("{PROJECT}/{ACCEPTANCE_OWNER}"))?;
        if is_symlink(&path) || !path.is_file() || mode(&path)? != 0o600 {
            return Err(acceptance("temporary-user ownership is unavailable"));
        }
        let name = fs::read_to_string(&path)?.trim().to_string();
        if !acceptance_name(&name) {
            return Err(acceptance("temporary-user ownership has drifted"));
        }
        Ok(name)
    }

    fn bootstrap_panel(&self) -> Result<(), Error> {
        let marker = self.host(&format!("{PROJECT}/{BOOTSTRAP_MARKER}"))?;
        let credential = self.host(&format!("{PROJECT}/secrets/panel-bootstrap-password"))?;
        let mut password = b"owner\0".to_vec();
        let bytes = fs::read(&credential)?;
        password.extend_from_slice(bytes.trim_ascii_end_matches_crlf());
        let expected = sha256_hex(&password);
        if marker.is_file() && fs::read_to_string(&marker)?.trim() == expected {
            return Ok(());
        }
        if lexists(&marker) {
            return Err(core("panel bootstrap ownership has drifted"));
        }
        let argv = self.compose_argv(&[
            "exec",
            "-T",
            "panel",
            "/usr/local/bin/panel",
            "create-admin",
            "--username",
            "owner",
            "--role",
            "owner",
            "--password-stdin",
        ])?;
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.run(&args, Some(&credential))?;
        self.atomic(&marker, format!("{expected}\n").as_bytes(), 0o600)
    }

    fn compose_start(&self) -> Result<(), Error> {
        if let Err(original) = self.compose(&["up", "-d", "--build", "--wait"]) {
            if original.is_fatal() {
                return Err(original);
            }
            let compose = self.compose_argv(&[])?;
            let capture = |extra: &[&str], limit| -> String {
                let mut argv = compose.clone();
                argv.extend(extra.iter().map(|value| (*value).to_string()));
                let args: Vec<&str> = argv.iter().map(String::as_str).collect();
                sanitize_compose_diagnostic(&self.runner.capture(&args, limit, Capture::CORE), limit)
            };
            let ids = capture(&["ps", "-q", "panel"], 256);
            let id = ids.trim().lines().next_back().unwrap_or("");
            let health = if !id.is_empty()
                && id.len() <= 128
                && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
            {
                sanitize_compose_diagnostic(
                    &self.runner.capture(
                        &["docker", "inspect", "--format", "{{json .State.Health}}", id],
                        2400,
                        Capture::CORE,
                    ),
                    2400,
                )
            } else {
                "container id unavailable".to_string()
            };
            let logs = capture(&["logs", "--no-color", "--tail", "80", "panel"], 600);
            let ps = capture(&["ps"], 400);
            let summary = sanitize_compose_diagnostic(&original.message(), 300);
            return Err(core(format!(
                "compose startup failed: {summary}; startup diagnostics: panel health: {}; panel logs: {}; compose ps: {}",
                if health.is_empty() { "(empty)" } else { &health },
                if logs.is_empty() { "(empty)" } else { &logs },
                if ps.is_empty() { "(empty)" } else { &ps },
            )));
        }
        Ok(())
    }

    fn ownership(&self, probe_preserve: bool) -> Result<Map<String, Value>, Error> {
        let project = self.host(PROJECT)?;
        let mut ownership = Map::new();
        if project.is_dir() {
            let mut files = Vec::new();
            collect_owned_files(&project, &mut files)?;
            files.sort();
            for path in files {
                let relative =
                    path.strip_prefix(&project).map_err(|_| core("Core owned path escapes selected root"))?;
                let relative = relative.to_string_lossy();
                if ADJACENT_CREDENTIALS.contains(&relative.as_ref()) {
                    continue;
                }
                let preserve = PRESERVED_CREDENTIALS.contains(&relative.as_ref()) || relative == MARKER;
                ownership.insert(self.host_name(&path)?, ownership_entry(path_sha256(&path)?, preserve));
            }
        }
        for (absolute, preserve) in [(PANEL_VHOST, false), (PROBE, probe_preserve)] {
            let path = self.host(absolute)?;
            if lexists(&path) {
                ownership.insert(absolute.into(), ownership_entry(path_sha256(&path)?, preserve));
            }
        }
        if ownership.is_empty() {
            return Err(core("Core generation has no owned files"));
        }
        Ok(ownership)
    }

    fn assert_checkpoint_ownership(&self, checkpoint: &CoreCheckpoint) -> Result<(), Error> {
        for (absolute, entry) in &checkpoint.ownership {
            let path = self.host(absolute)?;
            let expected = entry["sha256"].as_str().unwrap();
            if !lexists(&path) || path_sha256(&path)? != expected {
                return Err(core(format!("Core owned file has drifted: {absolute}")));
            }
            if absolute == PROBE {
                self.validate_probe(&path, &checkpoint.probe_expected_sha256)?;
            }
        }
        Ok(())
    }

    fn remove_generation(
        &self,
        checkpoint: &CoreCheckpoint,
        preserve_credentials: bool,
        preserve_acceptance: bool,
    ) -> Result<(), Error> {
        let using_planned = checkpoint.ownership.is_empty();
        let entries = if using_planned { &checkpoint.planned_ownership } else { &checkpoint.ownership };
        let project = self.host(PROJECT)?;
        let marker_path = format!("{PROJECT}/{MARKER}");
        let marker = self.host(&marker_path)?;
        let owned_generation =
            entries.get(&marker_path).and_then(|entry| entry.get("sha256")).and_then(Value::as_str).is_some_and(
                |expected| lexists(&marker) && path_sha256(&marker).is_ok_and(|actual| actual == expected),
            );
        let mut directories = BTreeSet::new();
        for (absolute, entry) in entries.iter().rev() {
            if absolute == PROBE {
                continue;
            }
            let path = self.host(absolute)?;
            let in_project = absolute.starts_with(&format!("{PROJECT}/"));
            if absolute == PROJECT || (!in_project && !safe_cover(absolute) && absolute != PANEL_VHOST) {
                return Err(core("Core checkpoint ownership escapes the project"));
            }
            if in_project {
                add_owned_directories(&mut directories, &project, &path);
            }
            if preserve_credentials && entry["preserve"] == Value::Bool(true) {
                continue;
            }
            if preserve_acceptance && absolute == &format!("{PROJECT}/{ACCEPTANCE_OWNER}") {
                continue;
            }
            if !lexists(&path) {
                continue;
            }
            if path_sha256(&path)? != entry["sha256"].as_str().unwrap() {
                if using_planned {
                    continue;
                }
                return Err(core(format!("Core owned file has drifted: {absolute}")));
            }
            durable_remove(&path, false)?;
        }
        if !preserve_credentials && owned_generation {
            directories.insert(project.join("version-overrides"));
            for relative in
                PRESERVED_CREDENTIALS.iter().copied().chain([BOOTSTRAP_MARKER, ACCEPTANCE_OWNER, ACCEPTANCE_PENDING])
            {
                let path = project.join(relative);
                if lexists(&path) {
                    durable_remove(&path, false)?;
                }
                add_owned_directories(&mut directories, &project, &path);
            }
        }
        let mut directories: Vec<PathBuf> = directories.into_iter().collect();
        directories.sort_by_key(|directory| std::cmp::Reverse(directory.components().count()));
        for directory in directories {
            if is_symlink(&directory) || !directory.is_dir() {
                continue;
            }
            if fs::remove_dir(&directory).is_ok() {
                fsync_directory(directory.parent().unwrap())?;
            }
        }
        Ok(())
    }

    fn remove_owned_probe(&self, checkpoint: &CoreCheckpoint) -> Result<(), Error> {
        if checkpoint.probe_preexisting {
            return Ok(());
        }
        let probe = self.host(PROBE)?;
        if !lexists(&probe) {
            return Ok(());
        }
        if is_symlink(&probe) || !probe.is_file() || sha256_file(&probe)? != checkpoint.probe_expected_sha256 {
            return Err(core("Core owned protocol probe has drifted"));
        }
        durable_remove(&probe, false)?;
        Ok(())
    }

    fn remove_owned_probe_image(&self, checkpoint: &CoreCheckpoint) -> Result<(), Error> {
        let current = self.probe_image_identity()?;
        if let Some(preexisting) = &checkpoint.probe_image_preexisting {
            if current.as_ref() != Some(preexisting) {
                return Err(core("pre-existing probe image identity has drifted"));
            }
            return Ok(());
        }
        if current.is_some() {
            if self.probe_image_owner()?.as_deref() != Some(&checkpoint.probe_image_owner) {
                return Err(core("Core owned probe image has drifted"));
            }
            self.run(&["docker", "image", "rm", PROBE_IMAGE], None)?;
        }
        Ok(())
    }

    fn bounded_sensitive_scan(&self) -> bool {
        let Ok(project) = self.host(PROJECT) else { return false };
        let mut needles = Vec::new();
        for relative in PRESERVED_CREDENTIALS {
            let path = project.join(relative);
            let Ok(meta) = fs::metadata(&path) else { return false };
            if !meta.is_file() || meta.len() > 65_536 {
                return false;
            }
            let Ok(bytes) = fs::read(&path) else { return false };
            if *relative == "secrets/users.conf" {
                needles.extend(bytes.split(|byte| *byte == b'\n').filter_map(|line| {
                    line.iter().position(|byte| *byte == b'=').map(|index| line[index + 1..].to_vec())
                }));
            } else {
                needles.push(trim_ascii_whitespace(&bytes).to_vec());
            }
        }
        // The journal is under /installer/, not at /var/lib/proxy-control/*.json.
        let candidates = [
            Ok(project.join(".env")),
            Ok(project.join("compose.yaml")),
            Ok(project.join(MARKER)),
            Ok(project.join(BOOTSTRAP_MARKER)),
            self.host("/var/lib/proxy-control/installer/plan.json"),
            self.host("/var/lib/proxy-control/installer/state.json"),
            self.host("/var/lib/proxy-control/installer/ownership.json"),
            self.host("/var/lib/proxy-control/installer/report.json"),
            self.host("/var/lib/proxy-control/installer/runtime.json"),
        ];
        let mut scanned = 0u64;
        for candidate in candidates {
            let path = match candidate {
                Ok(path) => path,
                Err(_) => return false,
            };
            if !path.is_file() {
                continue;
            }
            let Ok(meta) = fs::metadata(&path) else { return false };
            if meta.len() > 1024 * 1024 || scanned + meta.len() > 4 * 1024 * 1024 {
                return false;
            }
            let Ok(bytes) = fs::read(&path) else { return false };
            scanned += meta.len();
            if needles
                .iter()
                .any(|needle| !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle))
            {
                return false;
            }
        }
        true
    }
}

impl Adapter for CoreAdapter {
    fn name(&self) -> &str {
        "core"
    }

    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        if facts.prerequisites.get("hard_stops").and_then(Value::as_array).is_some_and(|findings| !findings.is_empty())
        {
            return Err(core("host audit contains blocking findings"));
        }
        let users = vec![config.initial_user.clone()];
        validate_users(&users)?;
        let routes = Self::adjacent_routes(config, facts)?;
        Ok(vec![Action::new(
            "core.runtime",
            "core",
            "proxy-control:core",
            vec![
                format!("project={PROJECT}"),
                format!("proxy-domain={}", config.domains.mtproxy),
                format!("panel-domain={}", config.domains.panel),
                format!("subscription-domain={}", config.domains.subscription.as_deref().unwrap_or("")),
                format!("mcp-domain={}", config.domains.mcp.as_deref().unwrap_or("")),
                format!("users={}", users.join(",")),
                "proxy-backend-port=8445".into(),
                "panel-app-port=8787".into(),
                format!("panel-tls-port={}", config.panel_tls_port()),
                format!("probe={PROBE}"),
                format!("probe-image={PROBE_IMAGE}"),
                format!("prebuilt-tdlib={TDLIB_PIN}"),
                format!("adjacent-sni={}", encode_routes(&routes)),
            ],
            vec![
                "Nginx routes and certificates are verified".into(),
                "the existing mtproxy project boundary is absent or explicitly owned".into(),
            ],
            vec![
                "Compose model and all service health checks pass".into(),
                "panel health and an HTTPS authenticated session pass".into(),
                "Telemt management API remains private to Compose".into(),
                "every temporary MTProto credential returns validated resPQ".into(),
                "adjacent SNI routes and bounded sensitive-data scan pass".into(),
            ],
            vec![
                "stop only the mtproxy Compose project".into(),
                "preserve credentials and named volumes unless data purge is explicit".into(),
                "remove only Core-owned artifacts and the owned probe".into(),
            ],
            true,
        )?])
    }

    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        let selected = Selection::read(action)?;
        let project = self.host(PROJECT)?;
        let kind = self.project_kind(&project)?;
        if kind == "absent" && self.volumes_present()? {
            return Err(core(
                "orphaned mtproxy volumes require a proven owned recovery generation; restore its credentials or explicitly back up and purge the old lab data",
            ));
        }
        if kind == "absent" && self.compose_present()? {
            return Err(core("active mtproxy resources require a proven owned recovery generation"));
        }
        let name = self
            .existing_acceptance_name(&project)?
            .unwrap_or_else(|| format!("{ACCEPTANCE_PREFIX}{}", token_hex::<8>()));
        let marker_value = (kind == "absent").then(token_hex::<16>);
        let marker_sha = if let Some(value) = &marker_value {
            sha256_hex(format!("{value}\n").as_bytes())
        } else {
            self.marker_sha256()?
        };
        let source_probe = self.tree.join("probe/mtproxy-respq-probe");
        if !source_probe.is_file() {
            return Err(core("pinned TDLib probe sources are unavailable"));
        }
        let expected = sha256_file(&source_probe)?;
        let probe = self.host(PROBE)?;
        let probe_preexisting = lexists(&probe);
        if probe_preexisting {
            self.validate_probe(&probe, &expected)?;
        }
        let image_preexisting = self.probe_image_identity()?;
        if image_preexisting.is_some() && !self.probe_image_compatible()? {
            return Err(core("pre-existing probe image is not safely adoptable"));
        }
        let checkpoint = CoreCheckpoint {
            acceptance_name: name.clone(),
            adoption: kind.into(),
            owner: action.owner.clone(),
            ownership: Map::new(),
            planned_ownership: self.planned_ownership(&selected, &name, &marker_sha)?,
            probe_expected_sha256: expected,
            probe_image_owner: token_hex::<16>(),
            probe_image_preexisting: image_preexisting,
            probe_preexisting,
            project_created: kind == "absent",
            project_marker_value: marker_value,
        };
        Ok(checkpoint.into_data())
    }

    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let selected = Selection::read(action)?;
        let mut prepared = CoreCheckpoint::read(&checkpoint, action, false)?;
        prepared.validate_paths(&selected)?;
        self.install_probe(&prepared)?;
        self.write_generation(&selected, prepared.project_marker_value.as_deref())?;
        self.write_acceptance_owner(&prepared.acceptance_name)?;
        self.compose(&["config", "-q"])?;
        self.compose(&["pull", "-q"])?;
        self.compose_start()?;
        self.bootstrap_panel()?;
        let mut ownership = self.ownership(prepared.probe_preexisting)?;
        for (absolute, entry) in &prepared.planned_ownership {
            if absolute.starts_with(&format!("{PROJECT}/")) {
                continue;
            }
            let path = self.host(absolute)?;
            if lexists(&path) && path_sha256(&path)? == entry["sha256"].as_str().unwrap() {
                ownership.insert(absolute.clone(), entry.clone());
            }
        }
        prepared.ownership = ownership;
        Ok(prepared.into_data())
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let selected = Selection::read(action)?;
        let name = self.read_acceptance_owner()?;
        let pending = self.host(&format!("{PROJECT}/{ACCEPTANCE_PENDING}"))?;
        let recover_existing = lexists(&pending);
        if recover_existing {
            if is_symlink(&pending)
                || !pending.is_file()
                || mode(&pending)? != 0o600
                || fs::read_to_string(&pending)?.trim() != name
            {
                return Err(acceptance("temporary-user ownership has drifted"));
            }
        } else {
            self.atomic(&pending, format!("{name}\n").as_bytes(), 0o600)?;
        }
        let result = self.run_acceptance(&selected, &name, recover_existing);
        let mut failure = match result.as_ref() {
            Ok(value) => require_acceptance(value).err(),
            Err(err) => Some(core_or_acceptance(err)),
        };
        let cleanup_ok = if failure.as_ref().is_some_and(|err| err.python_class_name() == "_AcceptanceCollision")
            && !recover_existing
        {
            true
        } else {
            match self.cleanup_acceptance(&selected, &name) {
                Ok(()) => true,
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(acceptance("temporary-user and session cleanup failed"));
                    }
                    false
                }
            }
        };
        if cleanup_ok {
            durable_remove(&pending, true)?;
        }
        if let Some(err) = failure {
            return Err(err);
        }
        if !cleanup_ok {
            return Err(acceptance("temporary-user and session cleanup failed"));
        }
        let mut value = result.expect("a successful acceptance has a result");
        value.temporary_state_removed = true;
        Ok(Evidence::with_details(
            &action.id,
            true,
            vec![
                "Core Compose, panel, MTProto, isolation, and coexistence acceptance passed".into(),
                "temporary acceptance state was removed".into(),
            ],
            value.details(),
        )?)
    }

    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let selected = Selection::read(action)?;
        let prepared = CoreCheckpoint::read(&checkpoint, action, true)?;
        prepared.validate_paths(&selected)?;
        self.assert_checkpoint_ownership(&prepared)?;
        self.validate_existing_credentials(&self.host(&format!("{PROJECT}/secrets"))?, true)?;
        self.compose_start()?;
        Ok(prepared.into_data())
    }

    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        let selected = Selection::read(action)?;
        let prepared = CoreCheckpoint::read(&checkpoint, action, true)?;
        prepared.validate_paths(&selected)?;
        let destructive = target == RollbackTarget::Uninstalled && purge_data;
        let pending = self.host(&format!("{PROJECT}/{ACCEPTANCE_PENDING}"))?;
        let mut cleanup_pending = false;
        if lexists(&pending) {
            if self.cleanup_acceptance(&selected, &prepared.acceptance_name).is_err() {
                cleanup_pending = !destructive;
                if cleanup_pending {
                    self.write_acceptance_owner(&prepared.acceptance_name)?;
                }
            } else {
                durable_remove(&pending, true)?;
            }
            if destructive {
                durable_remove(&pending, true)?;
            }
        }
        if self.compose_present()? {
            self.compose(&["down", "--remove-orphans"])?;
        }
        if destructive && self.volumes_present()? {
            self.compose(&["down", "--remove-orphans", "--volumes"])?;
        }
        if destructive {
            self.purge_runtime_volumes()?;
        }
        self.remove_generation(&prepared, !destructive, cleanup_pending)?;
        self.remove_owned_probe(&prepared)?;
        self.remove_owned_probe_image(&prepared)?;
        Ok(Evidence::with_details(
            &action.id,
            true,
            vec![
                "Core runtime was removed".into(),
                if destructive { "persistent data was purged".into() } else { "persistent data was preserved".into() },
            ],
            serde_json::from_value(json!({
                "persistent_data_preserved": !destructive,
                "temporary_cleanup_pending": cleanup_pending,
            }))
            .expect("an object literal"),
        )?)
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.rollback(action, checkpoint, purge_data, target)
    }
}

fn core_or_acceptance(err: &Error) -> Error {
    if err.is_fatal() || matches!(err.python_class_name(), "AcceptanceError" | "_AcceptanceCollision") {
        match err {
            Error::Fatal { class, message } => Error::fatal(class.clone(), message.clone()),
            _ => Error::other(err.python_class_name().to_string(), err.message()),
        }
    } else {
        acceptance("Core acceptance execution failed")
    }
}

fn names(directory: &Path) -> Result<BTreeSet<String>, Error> {
    Ok(fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<BTreeSet<_>>>()?)
}

fn ignored_source(name: &str) -> bool {
    matches!(name, "tests" | "__pycache__" | "target") || name.ends_with(".pyc") || name.contains(".sqlite3")
}

fn collect_source_files(root: &Path, relative: &Path, files: &mut Vec<PathBuf>) -> Result<(), Error> {
    let mut entries: Vec<_> = fs::read_dir(root.join(relative))?.collect::<io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        if ignored_source(&name.to_string_lossy()) {
            continue;
        }
        let path = relative.join(name);
        let meta = fs::symlink_metadata(root.join(&path))?;
        if meta.is_dir() {
            collect_source_files(root, &path, files)?;
        } else if meta.is_file() || meta.file_type().is_symlink() {
            files.push(path);
        }
    }
    Ok(())
}

fn copy_tree(root: &Path, source: &Path, destination: &Path) -> Result<(), Error> {
    if lexists(destination) {
        if is_symlink(destination) || !destination.is_dir() {
            return Err(core("runtime project ownership has drifted"));
        }
    } else {
        durable_mkdir(destination, 0o777)?;
    }
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        if ignored_source(&name.to_string_lossy()) {
            continue;
        }
        let from = entry.path();
        let to = destination.join(name);
        pc_host::fs::assert_contained(root, &to)?;
        let meta = fs::metadata(&from)?;
        if meta.is_dir() {
            copy_tree(root, &from, &to)?;
        } else if meta.is_file() {
            if is_symlink(&to) {
                return Err(core("runtime project ownership has drifted"));
            }
            durable_copy2(&from, &to)?;
        } else {
            return Err(core("installer source generation is incomplete"));
        }
    }
    copy_directory_stats(source, destination)?;
    Ok(())
}

#[repr(C)]
struct Timespec {
    tv_sec: c_long,
    tv_nsec: c_long,
}

extern "C" {
    fn geteuid() -> u32;
    fn futimens(fd: c_int, times: *const Timespec) -> c_int;
}

fn copy_directory_stats(source: &Path, destination: &Path) -> io::Result<()> {
    let meta = fs::metadata(source)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(meta.mode() & 0o7777))?;
    let directory = File::open(destination)?;
    let times = [
        Timespec { tv_sec: meta.atime() as c_long, tv_nsec: meta.atime_nsec() as c_long },
        Timespec { tv_sec: meta.mtime() as c_long, tv_nsec: meta.mtime_nsec() as c_long },
    ];
    if unsafe { futimens(directory.as_raw_fd(), times.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn collect_owned_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), Error> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            collect_owned_files(&path, files)?;
        } else if meta.is_file() || meta.file_type().is_symlink() {
            files.push(path);
        }
    }
    Ok(())
}

fn add_owned_directories(directories: &mut BTreeSet<PathBuf>, project: &Path, path: &Path) {
    let mut cursor = path.parent();
    while let Some(directory) = cursor {
        if directory == project || directory.starts_with(project) {
            directories.insert(directory.to_path_buf());
            if directory == project {
                break;
            }
            cursor = directory.parent();
        } else {
            break;
        }
    }
}

fn safe_cover(absolute: &str) -> bool {
    let Some(domain) = absolute.strip_prefix("/var/www/").and_then(|rest| rest.strip_suffix("/index.html")) else {
        return false;
    };
    !domain.is_empty()
        && !domain.contains('/')
        && domain.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn cover_text(title: &str) -> String {
    format!("<!doctype html><title>{title}</title><h1>{title}</h1>\n")
}

fn read_existing_users(path: &Path) -> Result<BTreeMap<String, String>, Error> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    if is_symlink(path) || !path.is_file() || mode(path)? != 0o600 {
        return Err(core("existing Core credentials are unsafe"));
    }
    let text = fs::read_to_string(path).map_err(|_| core("existing Core credentials are unreadable"))?;
    if !valid_users_file(&text) {
        return Err(core("existing Core credentials are invalid"));
    }
    Ok(text
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, value)| (name.to_string(), value.to_string())))
        .collect())
}

trait TrimCrLf {
    fn trim_ascii_end_matches_crlf(&self) -> &[u8];
}

impl TrimCrLf for [u8] {
    fn trim_ascii_end_matches_crlf(&self) -> &[u8] {
        let mut end = self.len();
        while end > 0 && matches!(self[end - 1], b'\n' | b'\r') {
            end -= 1;
        }
        &self[..end]
    }
}

fn trim_ascii_whitespace(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(value.len());
    let end = value.iter().rposition(|byte| !byte.is_ascii_whitespace()).map_or(start, |index| index + 1);
    &value[start..end]
}

fn redact_assignments(value: &str, keywords: &[&str], word_boundary: bool) -> String {
    let mut redacted = String::with_capacity(value.len());
    let mut index = 0;
    let bytes = value.as_bytes();
    while index < bytes.len() {
        let matched = keywords.iter().find_map(|keyword| {
            let end = index + keyword.len();
            if end > bytes.len() || !bytes[index..end].eq_ignore_ascii_case(keyword.as_bytes()) {
                return None;
            }
            if word_boundary && index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_') {
                return None;
            }
            let mut separator_end = end;
            while separator_end < bytes.len()
                && (matches!(bytes[separator_end], b'=' | b':') || bytes[separator_end].is_ascii_whitespace())
            {
                separator_end += 1;
            }
            if separator_end == end || separator_end == bytes.len() || bytes[separator_end].is_ascii_whitespace() {
                return None;
            }
            let mut token_end = separator_end;
            while token_end < bytes.len() && !bytes[token_end].is_ascii_whitespace() {
                token_end += 1;
            }
            Some((separator_end, token_end))
        });
        if let Some((separator_end, token_end)) = matched {
            redacted.push_str(&value[index..separator_end]);
            redacted.push_str("[REDACTED]");
            index = token_end;
        } else {
            let ch = value[index..].chars().next().unwrap();
            redacted.push(ch);
            index += ch.len_utf8();
        }
    }
    redacted
}

fn sanitize_diagnostic(value: &str, max_chars: usize) -> String {
    let redacted = redact_assignments(value, &["password", "token", "secret", "auth"], false);
    pc_common::pytext::tail_chars(&redacted, max_chars).replace('\n', " ").trim().to_string()
}

fn sanitize_compose_diagnostic(value: &str, max_chars: usize) -> String {
    let clean = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let bearer = redact_bearer(&clean);
    let redacted = redact_assignments(&bearer, &["password", "secret", "token", "authorization"], true);
    pc_common::pytext::tail_chars(&redacted, max_chars).to_string()
}

fn redact_bearer(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        let bytes = value.as_bytes();
        if index + 6 <= bytes.len()
            && bytes[index..index + 6].eq_ignore_ascii_case(b"Bearer")
            && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric())
            && bytes.get(index + 6).is_some_and(u8::is_ascii_whitespace)
        {
            let mut end = index + 6;
            while end < bytes.len() && bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            if end < bytes.len() {
                while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                    end += 1;
                }
                out.push_str("Bearer [REDACTED]");
                index = end;
                continue;
            }
        }
        let ch = value[index..].chars().next().unwrap();
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn command_failure(argv: &[&str], result: &RunOutput) -> String {
    let program = argv
        .first()
        .and_then(|value| Path::new(value).file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("command");
    let mut named = format!("Core command failed: {program}");
    for word in argv.iter().skip(1).take(2) {
        if word.starts_with('-') || word.contains('/') {
            break;
        }
        named.push(' ');
        named.push_str(word);
    }
    let detail = sanitize_diagnostic(&String::from_utf8_lossy(&result.stderr), 900);
    if detail.is_empty() {
        named
    } else {
        format!("{named}: {detail}")
    }
}
