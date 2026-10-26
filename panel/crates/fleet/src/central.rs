//! The central side of fleet v2 — **not ported yet** (work package WP12b).
//!
//! Python: `fleet_v2/client.py` (the HTTPS client to a linked node), `links.py` (link handshake,
//! API-key escrow), `generations.py` (`publish`, `DesiredStore`), `pusher.py` (the sync loop),
//! `importing.py`, `central_routes.py` and `metrics_source.py`. This module only fixes the seams
//! WP12b fills, so the routing (WP10), metrics (WP13) and clients (WP7) packages can be wired
//! against them now:
//!
//! - [`NodeClientFactory`] builds a [`panel_model::seams::NodeClient`] for one link (reqwest with
//!   rustls; `verify` mode with the system roots, `pin` mode checking the leaf certificate's
//!   SHA-256 before the first request byte; the public-address resolver; the 1 MiB answer cap);
//! - [`Pusher`] is the background loop (`FleetPusher.run_forever`, 8 nodes at a time, backoff,
//!   resync on `stale_generation`/`digest_conflict`).
//!
//! The constants below are the Python client's and are part of the wire behaviour a mixed fleet
//! depends on (inventory §6.4).

use std::sync::Arc;
use std::time::Duration;

use panel_model::protocols::BoxFuture;
use panel_model::seams::{NodeClient, SeamError};

/// `TLS_MODES`: how the central checks a node's certificate.
pub const TLS_MODES: [&str; 2] = ["verify", "pin"];
/// `MAX_RESPONSE_BYTES`: a larger answer is `NodeRejected(status, "response_too_large", "")`.
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
/// The client's overall timeout (`timeout=30.0`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The connect budget, covering DNS and every address tried (`connect=5.0`).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Live meters override read/write/pool to 3 s.
pub const LIVE_METRICS_TIMEOUT: Duration = Duration::from_secs(3);
/// History and summary override read/write/pool to 10 s.
pub const METRICS_HISTORY_TIMEOUT: Duration = Duration::from_secs(10);
/// `FINGERPRINT_TIMEOUT` of `POST /api/nodes/fingerprint`.
pub const FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(5);

/// How the central reaches one linked node (a `node_links` row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLink {
    pub node_id: String,
    /// `https://host[:port][/base-path]`, no query, fragment or userinfo.
    pub panel_url: String,
    /// One of [`TLS_MODES`].
    pub tls_verify: String,
    /// Lowercase hex SHA-256 of the leaf certificate's DER (`pin` mode).
    pub pinned_cert_sha256: Option<String>,
    pub allow_private_address: bool,
}

/// WP12b: `NodeClient(url, key, …)` for one link; the key is revealed from escrow by the caller.
pub trait NodeClientFactory: Send + Sync {
    fn client(&self, link: &NodeLink, api_key: &str) -> Result<Arc<dyn NodeClient>, SeamError>;
}

/// WP12b: the central's sync loop (`FleetPusher`).
pub trait Pusher: Send + Sync {
    /// One sync cycle over every linked node.
    fn tick(&self) -> BoxFuture<'_, Result<(), SeamError>>;
    /// Ask a running loop to stop after the current cycle.
    fn stop(&self);
}
