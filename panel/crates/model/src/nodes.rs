//! What the panel shows about a node, separated from how the transport works (`nodes/models.py`).

use serde_json::{Map, Value};

/// The central host itself (reserved by migration 5): a node a grant can name, with no fleet
/// transport.
pub const LOCAL_NODE_ID: &str = "local";

/// One certificate of a fleet v1 node (kept for the node views; v1 itself is retired).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    pub serial: String,
    pub fingerprint_sha256: String,
    pub not_before: i64,
    pub not_after: i64,
    pub state: String,
    pub issued_at: i64,
    pub revoked_at: Option<i64>,
}

/// A node as the API shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeView {
    pub node_id: String,
    pub display_name: String,
    pub kind: String,
    pub disabled: bool,
    pub enrollment_state: String,
    pub connectivity_state: String,
    pub daemon_health: String,
    pub inventory: Map<String, Value>,
    pub capabilities: Vec<String>,
    pub last_seen_at: Option<i64>,
    pub last_checked_at: Option<i64>,
    pub certificates: Vec<CertificateInfo>,
    pub pending_commands: i64,
    /// `"v1"` (the retired mTLS agent transport) or `"panel"` (a linked panel over HTTPS).
    pub transport: String,
    /// The linked panel's connection; never the API key.
    pub link: Option<Map<String, Value>>,
}
