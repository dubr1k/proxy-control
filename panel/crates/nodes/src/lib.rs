//! Nodes of the Proxy Control panel's Rust port (work package WP11): `panel/nodes/**`,
//! `panel/node_routes.py` and what fleet v2 and the node views still need of `panel/fleet.py`.
//!
//! - [`registry`] — node rows in the caller's transaction: the views' rows (`FleetStore._node`
//!   with the link attached), `insert`/`rename`/`set_disabled`, the grant and pending-command
//!   counts, and the pause/resume write of a linked panel (`NodeLinkService.write_enabled`), which
//!   the lifecycle service, the CLI and fleet v2 share;
//! - [`read_model`] — `derive`: enrollment, connectivity and health of a node as the operator sees
//!   them, and the `asdict` form of a view;
//! - [`service`] — [`service::NodeLifecycleService`]: list, get, rename, disable/enable with their
//!   audit rows, plus the CLI's `node-list`/`node-disable`/`node-enable` output;
//! - [`routes`] — `GET /api/nodes`, `GET /api/nodes/{node_id}`, `POST …/rename|disable|enable`:
//!   framework-free handlers over [`routes::NodesState`] (the web shell serves them behind its own
//!   gates) and a stand-alone axum router over [`routes::NodesHttp`];
//! - [`fleet_compat`] — the node-id grammar and the inventory allow-list of `fleet.py`;
//! - [`certificates`] — the certificate rows a fleet v1 node left behind (read only).
//!
//! Fleet v1 is retired (owner decision, 2026-10-25): its transport (`agent_transport.py`,
//! `agent_ingress.py`, `agent_service.py`, `node_agent.py`), the command registry of `FleetStore`
//! (`enqueue`, `poll_next`, `record_result`, `TypedCommand`), certificate binding/revocation, v1
//! node registration and the `/api/fleet/nodes*` routes are not ported ([`routes::RETIRED_ROUTES`]).
//! Fleet v2 never used the command registry: it reads only node rows, link rows and the counts here.
//!
//! Everything that touches SQLite blocks: call it from `spawn_blocking` (the routes do).

pub mod certificates;
pub mod error;
pub mod fleet_compat;
pub mod read_model;
pub mod registry;
pub mod routes;
pub mod service;

pub use error::NodesError;
pub use panel_model::nodes::{CertificateInfo, NodeView, LOCAL_NODE_ID};
pub use registry::{AuditContext, NodeRow};
pub use service::NodeLifecycleService;
