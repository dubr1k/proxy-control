//! Fleet v2 of the Proxy Control panel (work package WP12; `panel/fleet_v2/`).
//!
//! Both ends of a link are panels. The **central** compiles a numbered generation per linked node
//! and pushes it; the **node** validates it, stores it, applies it to its runtime through the
//! protocol adapters and reports what it observed. The wire contract (documents, digests, reports)
//! lives in [`panel_model::fleet`]; this crate holds the behaviour on each side.
//!
//! - [`node`] (WP12a, ported): the `/api/fleet/v2/*` routes a central calls, the generation store
//!   ([`node::managed::ManagedStore`]), the reconcile ([`node::reconcile::Reconciler`]), the guard
//!   local writers pass ([`node::guard`]) and the node's metrics routes.
//! - [`central`] (WP12b, not ported yet): only the public seams the central side will fill.
//!
//! A mixed fleet is the normal state during an upgrade (a Python central with Rust nodes and the
//! reverse), so the node answers exactly what the Python node answered: the same capability
//! strings, `extra="forbid"` on every request model, the 409 codes, JSON bodies on its own 5xx and
//! the same digests over the same documents.

pub mod central;
pub mod node;
