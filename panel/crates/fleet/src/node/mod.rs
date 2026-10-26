//! The node side of fleet v2 (WP12a): what a panel does for the central panel that manages it.
//!
//! | Python | Rust |
//! |---|---|
//! | `fleet_v2/managed.py` (`ManagedStore`) | [`managed`] |
//! | `fleet_v2/reconcile.py` (`Reconciler`) | [`reconcile`] |
//! | `fleet_v2/guard.py` (`require_unmanaged`) | [`guard`] |
//! | `fleet_v2/node_routes.py`, `metrics_node.py` | [`service::FleetNode`] (logic) + `panel-web` `routes/fleet_node.rs` (HTTP) |
//! | the request models of `node_routes.py` | [`models`] |
//! | `app.state.adapters`/`router`/`versions` | [`runtime`] |
//!
//! Wire compatibility with a Python central is the contract: the capability strings
//! (`panel_model::fleet::BASE_CAPABILITIES` …), `extra="forbid"` request models, the 409 codes
//! (`guid_mismatch`, `foreign_master`, `stale_generation`, `digest_conflict`,
//! `secret_store_disabled`), stored documents as pydantic dumps them, and the digest over them.

pub mod guard;
pub mod managed;
pub mod models;
pub mod reconcile;
pub mod runtime;
pub mod service;
pub mod traffic;

pub use managed::ManagedStore;
pub use reconcile::Reconciler;
pub use runtime::{FleetRouter, ManagerRuntime, NodeRuntime, VersionAgent};
pub use service::{FleetNode, NodeConfig, NodeFailure};
