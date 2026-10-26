//! The two disjoint installation reports (`installer/report.py`): a public `report.json` with
//! allow-listed, non-secret acceptance facts, and a root-only `credentials/handoff.json`; plus the
//! operator notes and the evidence the CLI's `report` command derives from the journal
//! (`installer/cli.py:_write_reports`).
//!
//! Difference from Python (DIFFERENCES.md, host inventory §12 #2): the caller passes the plan's
//! real release tag; Python passed the transaction origin (`installer-v1`).

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::model::{HostMode, InstallerConfig};
use crate::planner::{compose_file_list, Evidence, Fact, PlanError};
use crate::secret::report_text_names_secret;

pub const PUBLIC_NAME: &str = "report.json";
pub const CREDENTIALS_DIR: &str = "credentials";
pub const CREDENTIALS_NAME: &str = "handoff.json";
pub const REPORT_SCHEMA: i64 = 1;

/// The only fact names a public report may publish.
pub const ALLOWED_FACTS: [&str; 40] = [
    "adjacent_listeners_ok",
    "adjacent_sni_ok",
    "admin_api_loopback",
    "authenticated_connect_ok",
    "certificate_expires",
    "certificate_sans",
    "client_count",
    "compose_config_ok",
    "connect_bytes",
    "cover_https_ok",
    "executable_digest_ok",
    "expected_services",
    "healthy_services",
    "identities_removed",
    "installed",
    "listener_owner",
    "log_boundary_ok",
    "manager_health_ok",
    "mita_status_running",
    "package_digest_ok",
    "panel_health_ok",
    "panel_login_ok",
    "persistent_data_preserved",
    "private_listener_ok",
    "public_host_ok",
    "recorded_bytes",
    "respq_expected",
    "respq_verified",
    "response_status",
    "route_result",
    "routes",
    "send_queue_drained",
    "sensitive_scan_ok",
    "telemt_api_internal",
    "temporary_state_removed",
    "transports_expected",
    "transports_verified",
    "tunnel_closed_ok",
    "uds_boundary_ok",
    "version_pinned",
];

/// `ReportError`: a report would publish something outside its schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportError(pub String);

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReportError {}

/// `[A-Za-z0-9_.:+@/ -]{1,256}\Z`.
fn safe_value(text: &str) -> bool {
    (1..=256).contains(&text.chars().count())
        && text.chars().all(|c| c.is_ascii_alphanumeric() || "_.:+@/ -".contains(c))
}

/// `AcceptanceReport`.
#[derive(Debug, Clone, PartialEq)]
pub struct AcceptanceReport {
    pub profile: String,
    pub release_tag: String,
    pub release_digest: String,
    pub actions: Vec<Value>,
    pub operator_notes: Vec<String>,
}

impl AcceptanceReport {
    pub fn new(profile: &str, release_tag: &str, release_digest: &str, operator_notes: Vec<String>) -> Self {
        AcceptanceReport {
            profile: profile.into(),
            release_tag: release_tag.into(),
            release_digest: release_digest.into(),
            actions: Vec::new(),
            operator_notes,
        }
    }

    /// `from_evidence(...)`.
    pub fn from_evidence(
        profile: &str,
        release_tag: &str,
        release_digest: &str,
        evidence: &[Evidence],
        operator_notes: Vec<String>,
    ) -> Self {
        let mut report = AcceptanceReport::new(profile, release_tag, release_digest, operator_notes);
        for item in evidence {
            report = report.with_evidence(item);
        }
        report
    }

    pub fn with_evidence(mut self, evidence: &Evidence) -> Self {
        self.actions.push(public_action(evidence));
        self
    }

    /// `public_document()`, refused when any key or string names a credential.
    pub fn public_document(&self) -> Result<Value, ReportError> {
        let document = json!({
            "actions": self.actions,
            "operator_notes": self.operator_notes,
            "profile": self.profile,
            "release": {"digest": self.release_digest, "tag": self.release_tag},
            "schema": REPORT_SCHEMA,
        });
        assert_public(&document, "report")?;
        Ok(document)
    }
}

fn public_action(evidence: &Evidence) -> Value {
    let mut facts = Map::new();
    for (key, value) in &evidence.details {
        if !ALLOWED_FACTS.contains(&key.as_str()) {
            continue;
        }
        let keep = match value {
            Value::Bool(_) => true,
            Value::Number(number) => number.is_i64() || number.is_u64(),
            Value::String(text) => safe_value(text),
            Value::Array(items) => items.iter().all(|item| item.as_str().is_some_and(safe_value)),
            _ => false,
        };
        if keep {
            facts.insert(key.clone(), value.clone());
        }
    }
    json!({
        "action_id": evidence.action_id,
        "facts": facts,
        "observations": evidence.observations,
        "success": evidence.success,
    })
}

fn assert_public(value: &Value, path: &str) -> Result<(), ReportError> {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                if report_text_names_secret(key) {
                    return Err(ReportError(format!("public report must not name {path}.{key}")));
                }
                assert_public(item, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_public(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::String(text) if report_text_names_secret(text) => {
            Err(ReportError(format!("public report must not describe a credential at {path}")))
        }
        _ => Ok(()),
    }
}

/// `CredentialHandoff`: root-only credentials, never summarised in the public report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialHandoff {
    pub entries: BTreeMap<String, String>,
}

impl CredentialHandoff {
    pub fn new(entries: BTreeMap<String, String>) -> Result<Self, ReportError> {
        if entries.values().any(String::is_empty) {
            return Err(ReportError("credential handoff entries must be named strings".into()));
        }
        Ok(CredentialHandoff { entries })
    }

    pub fn document(&self) -> Value {
        json!({"credentials": self.entries, "schema": REPORT_SCHEMA})
    }
}

/// Why writing a report failed.
#[derive(Debug)]
pub enum WriteError {
    Report(ReportError),
    Io(io::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::Report(err) => err.fmt(f),
            WriteError::Io(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for WriteError {}

/// `ReportWriter`: both reports with enforced, disjoint permissions.
#[derive(Debug, Clone)]
pub struct ReportWriter {
    pub root: PathBuf,
}

impl ReportWriter {
    pub fn new(root: &Path) -> Self {
        ReportWriter { root: root.to_path_buf() }
    }

    pub fn public_path(&self) -> PathBuf {
        self.root.join(PUBLIC_NAME)
    }

    pub fn credentials_path(&self) -> PathBuf {
        self.root.join(CREDENTIALS_DIR).join(CREDENTIALS_NAME)
    }

    /// `report.json`, mode 0644 (root:root when run as root).
    pub fn write_public(&self, report: &AcceptanceReport) -> Result<PathBuf, WriteError> {
        let document = report.public_document().map_err(WriteError::Report)?;
        pc_host::fs::durable_mkdir(&self.root, 0o755).map_err(WriteError::Io)?;
        let path = self.public_path();
        pc_host::fs::atomic_write(&path, encode(&document).as_bytes(), 0o644, owner()).map_err(WriteError::Io)?;
        Ok(path)
    }

    /// `credentials/handoff.json`, directory 0700, file 0600.
    pub fn write_credentials(&self, handoff: &CredentialHandoff) -> Result<PathBuf, WriteError> {
        let path = self.credentials_path();
        let directory = path.parent().expect("a file under the root").to_path_buf();
        pc_host::fs::durable_mkdir(&directory, 0o700).map_err(WriteError::Io)?;
        std::fs::set_permissions(&directory, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(WriteError::Io)?;
        pc_host::fs::atomic_write(&path, encode(&handoff.document()).as_bytes(), 0o600, owner())
            .map_err(WriteError::Io)?;
        Ok(path)
    }
}

fn owner() -> Option<(u32, u32)> {
    // SAFETY: geteuid has no preconditions.
    (unsafe { libc::geteuid() } == 0).then_some((0, 0))
}

/// `json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"`.
pub fn encode(document: &Value) -> String {
    pc_host::json::pretty2(document)
}

/// One checkpoint's recorded evidence as the `report` command reads it: `None` when the
/// checkpoint holds no mapping; observations default to `no observation was recorded`.
pub fn evidence_from_checkpoint(action_id: &str, recorded: &Value) -> Result<Option<Evidence>, PlanError> {
    let Value::Object(map) = recorded else { return Ok(None) };
    let success = match map.get("success") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(items)) => !items.is_empty(),
    };
    let mut observations: Vec<String> = match map.get("observations") {
        Some(Value::Array(items)) => items.iter().map(py_str).collect(),
        Some(Value::String(text)) => text.chars().map(String::from).collect(),
        Some(Value::Object(items)) => items.keys().cloned().collect(),
        _ => Vec::new(),
    };
    if observations.is_empty() {
        observations.push("no observation was recorded".into());
    }
    let details = match map.get("details") {
        Some(Value::Object(details)) => Fact::from(Value::Object(details.clone())),
        _ => Fact::Map(BTreeMap::new()),
    };
    Evidence::new(action_id, success, observations, details).map(Some)
}

/// `str(item)` of a JSON scalar the way the report command stringifies observations.
fn py_str(value: &Value) -> String {
    pc_host::archive::identity::py_str(value).unwrap_or_else(|| pc_host::json::dumps(value, &PY_REPR_LIKE))
}

const PY_REPR_LIKE: pc_host::json::Options =
    pc_host::json::Options { indent: None, separators: None, sort_keys: false, ensure_ascii: false };

/// The operator notes of the public report (`cli._write_reports`).
pub fn operator_notes(config: &InstallerConfig) -> Vec<String> {
    let mut notes = vec![format!("compose files: {}", compose_file_list(config).join(" "))];
    if let Some(mcp) = &config.domains.mcp {
        notes.push(format!("MCP server: enabled on {mcp}"));
    }
    if let Some(awg) = &config.amneziawg {
        let versions: Vec<String> = awg
            .port_map()
            .into_iter()
            .zip(awg.interfaces())
            .map(|((version, port), interface)| format!("{version} (udp/{port}, {interface})"))
            .collect();
        notes.push(format!("AmneziaWG: enabled, versions {}", versions.join(", ")));
        if !(config.host_mode == HostMode::Fresh && config.firewall.manage_ufw) {
            notes.push(
                "AmneziaWG: the installer does not manage the firewall here; keep these UDP ports open and \
                 forwarding allowed on the awg interfaces"
                    .into(),
            );
        }
        notes.push(
            "AmneziaWG: the exit is direct; «Routing» can send the whole tunnel through WARP (the manager's own \
             WireGuard tunnel, TCP and UDP), which needs outbound api.cloudflareclient.com:443 and UDP 2408"
                .into(),
        );
    }
    if let Some(tt) = &config.trusttunnel {
        notes.push(format!(
            "TrustTunnel: enabled on {} (TCP/443 through the SNI router, endpoint on 127.0.0.1:{}; no UDP port is \
             opened). The name needs an A record to this server and must not be proxied by a CDN",
            tt.hostname, tt.listen_port
        ));
    }
    notes
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
