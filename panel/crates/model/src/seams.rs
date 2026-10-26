//! The seams between the domain packages: what Python passes as lambdas in `create_app`
//! (`app.py:221-245`) and the central's client to a linked node, as traits, so `clients`,
//! `routing`, `fleet` and `metrics` depend on these instead of on each other.
//!
//! The synchronous seams run inside the caller's SQLite transaction (they take its
//! [`panel_core::db::Conn`]) or open their own connection; call them from blocking code
//! (`spawn_blocking`), never across an `.await`. Closures implement them directly.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use panel_core::db::Conn;
use serde_json::{Map, Value};

use crate::fleet::{ObservedGeneration, PushRequest, PushResponse};
use crate::protocols::BoxFuture;
use crate::validate::ValidationError;

/// Whatever a seam's implementation failed with (a database error, a routing refusal, …); the
/// caller may downcast it.
pub type SeamError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// `ClientService.on_change` hooks: run inside the caller's transaction after every grant or
/// client change, so a rolled-back change bumps nothing (the subscription generation, the
/// per-linked-node `publish`).
pub trait ClientChangeHook: Send + Sync {
    fn on_change(&self, db: &Conn, client_id: &str) -> Result<(), SeamError>;
}

impl<F> ClientChangeHook for F
where
    F: Fn(&Conn, &str) -> Result<(), SeamError> + Send + Sync,
{
    fn on_change(&self, db: &Conn, client_id: &str) -> Result<(), SeamError> {
        self(db, client_id)
    }
}

/// `publish(db, node_id)`: compiles and stores the node's next generation inside the caller's
/// transaction; the new generation number, or `None` when the content did not change.
pub trait GenerationPublisher: Send + Sync {
    fn publish(&self, db: &Conn, node_id: &str) -> Result<Option<i64>, SeamError>;
}

impl<F> GenerationPublisher for F
where
    F: Fn(&Conn, &str) -> Result<Option<i64>, SeamError> + Send + Sync,
{
    fn publish(&self, db: &Conn, node_id: &str) -> Result<Option<i64>, SeamError> {
        self(db, node_id)
    }
}

/// `enabled(protocol)`: whether this panel serves a protocol at all (the `*_ENABLED` settings;
/// protocols without a switch answer `true`).
pub trait ProtocolSwitch: Send + Sync {
    fn enabled(&self, protocol: &str) -> bool;
}

impl<F> ProtocolSwitch for F
where
    F: Fn(&str) -> bool + Send + Sync,
{
    fn enabled(&self, protocol: &str) -> bool {
        self(protocol)
    }
}

/// `confirmed(node_id, email)`: the node's relay carries this account by its own last report
/// (always true for `local`). Opens its own connection.
pub trait RelayConfirmation: Send + Sync {
    fn confirmed(&self, node_id: &str, email: &str) -> Result<bool, SeamError>;
}

impl<F> RelayConfirmation for F
where
    F: Fn(&str, &str) -> Result<bool, SeamError> + Send + Sync,
{
    fn confirmed(&self, node_id: &str, email: &str) -> Result<bool, SeamError> {
        self(node_id, email)
    }
}

/// `node_client(node_id)` (`NodeLinkService.client_for`): a client to a linked panel, its API key
/// revealed from escrow. Opens its own connection; fails when the node is not linked.
pub trait NodeClientProvider: Send + Sync {
    fn client_for(&self, node_id: &str) -> Result<Arc<dyn NodeClient>, SeamError>;
}

impl<F> NodeClientProvider for F
where
    F: Fn(&str) -> Result<Arc<dyn NodeClient>, SeamError> + Send + Sync,
{
    fn client_for(&self, node_id: &str) -> Result<Arc<dyn NodeClient>, SeamError> {
        self(node_id)
    }
}

/// How a call to a linked node failed (`fleet_v2/client.py`).
#[derive(Debug, Clone, PartialEq)]
pub enum NodeError {
    /// Transport-level failure: DNS, connect, TLS handshake, timeout, a pin mismatch. The text is
    /// the error's class name (never anything carrying the key).
    Unreachable(String),
    /// 401 (bad or disabled key) or 403 (wrong scope); the body is not read.
    AuthFailed,
    /// Any other status ≥ 400 with the node's `{detail, code}` body (`detail` is `str()` of the
    /// body's value, `""` when absent).
    Rejected { status: u16, code: Option<String>, detail: String },
    /// A 2xx/3xx whose body the report model refused.
    InvalidAnswer(ValidationError),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Unreachable(kind) => f.write_str(kind),
            NodeError::AuthFailed => Ok(()),
            // `NodeRejected.__str__`: `detail or code or str(status)`.
            NodeError::Rejected { status, code, detail } => match (detail.as_str(), code) {
                ("", Some(code)) if !code.is_empty() => f.write_str(code),
                ("", _) => write!(f, "{status}"),
                (detail, _) => f.write_str(detail),
            },
            NodeError::InvalidAnswer(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// Why the central reads credentials back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePurpose {
    /// The credentials of users this central owns (the default; sent without `purpose`, so a
    /// strict older node accepts it).
    Escrow,
    /// The operator adopts the node's own users.
    Import,
}

/// One user to read back: `{protocol, runtime_username}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureItem {
    pub protocol: String,
    pub runtime_username: String,
}

/// The central's HTTPS client to one linked panel (`fleet_v2.client.NodeClient`), as the routing,
/// metrics and fleet packages call it. Bodies are the node's JSON objects (a non-object answer is
/// an empty one).
pub trait NodeClient: Send + Sync {
    fn identity(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>>;
    fn status(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>>;
    fn inventory(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>>;
    /// The node's live meters (`metrics.v1`); `timeout` replaces the read/write/pool waits
    /// (3 s in Python).
    fn metrics(&self, timeout: Duration) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>>;
    /// `GET /api/fleet/v2/metrics/history?series=a,b&range=…&points=…` (10 s in Python).
    fn metrics_history<'a>(
        &'a self,
        series: &'a [String],
        range: &'a str,
        points: i64,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>>;
    /// `GET /api/fleet/v2/metrics/summary?range=…` (10 s in Python).
    fn metrics_summary<'a>(
        &'a self,
        range: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>>;
    /// `PUT /api/fleet/v2/generation` with [`PushRequest::wire`]: the status (200 or 202) and the
    /// node's answer.
    fn push<'a>(&'a self, request: &'a PushRequest) -> BoxFuture<'a, Result<(u16, PushResponse), NodeError>>;
    fn observed(&self) -> BoxFuture<'_, Result<ObservedGeneration, NodeError>>;
    /// `POST /api/fleet/v2/credentials/capture` (at most
    /// [`crate::fleet::CAPTURE_MAX_RESOURCES`] items per call).
    fn capture<'a>(
        &'a self,
        resources: &'a [CaptureItem],
        purpose: CapturePurpose,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>>;
    fn update_version<'a>(
        &'a self,
        component: &'a str,
        version: &'a str,
        expected_current: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>>;
    fn check_versions(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>>;
    fn unlink(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>>;
    /// `POST /api/fleet/v2/exits/test {"exit": spec}` (the spec carries the exit's credential).
    fn exit_test<'a>(&'a self, spec: &'a Map<String, Value>) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>>;
    /// The node router's geodata: `view`, `codes`, `settings` (with `body`), or another action
    /// (`update`, `restore`) as `POST …/geodata/{action}`.
    fn geodata<'a>(
        &'a self,
        action: &'a str,
        body: Option<&'a Map<String, Value>>,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closures_are_seams() {
        let switch = |protocol: &str| protocol != "naive";
        let seam: &dyn ProtocolSwitch = &switch;
        assert!(!seam.enabled("naive") && seam.enabled("mieru"));
        let confirm = |node: &str, _email: &str| -> Result<bool, SeamError> { Ok(node == "local") };
        let seam: &dyn RelayConfirmation = &confirm;
        assert!(seam.confirmed("local", "relay:a:warp").unwrap());
    }

    #[test]
    fn rejected_reads_like_python() {
        let rejected = |code: Option<&str>, detail: &str| NodeError::Rejected {
            status: 502,
            code: code.map(str::to_string),
            detail: detail.into(),
        };
        assert_eq!(rejected(Some("x"), "boom").to_string(), "boom");
        assert_eq!(rejected(Some("x"), "").to_string(), "x");
        assert_eq!(rejected(None, "").to_string(), "502");
    }
}
