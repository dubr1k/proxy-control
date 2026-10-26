//! Shared types and contracts of the Proxy Control panel's Rust port (work package WP2). No I/O.
//!
//! Every package of the panel speaks these types, so the cycles the Python modules tolerate
//! (`clients` ↔ `protocols` ↔ `fleet_v2`) are broken here:
//!
//! - [`clients`] — clients, grant intents, access grants and each protocol's options
//!   (`clients/models.py`), with `effective_enabled`/`within_validity`;
//! - [`protocols`] — the [`protocols::ProtocolAdapter`] trait, [`protocols::AdapterError`] and the
//!   values adapters exchange (`protocols/base.py`);
//! - [`routing`] — the routing policy, its normalisers (IDNA, CIDR, ports, exits, lanes) and the
//!   egress document helpers and digest (`routing/models.py`, `routing/document.py`);
//! - [`fleet`] — the fleet v2 wire documents, their wire form and canonical digest, the node's
//!   reports (`fleet_v2/protocol.py`);
//! - [`subscriptions`], [`nodes`], [`metrics`] — the small model modules of those packages;
//! - [`seams`] — the callbacks Python passes as lambdas (`publish`, `on_change`, `enabled`,
//!   `confirmed`, `node_client`) and the [`seams::NodeClient`] contract;
//! - [`validate`] — pydantic-shaped validation (lax coercion, `extra` rules, the 422 issue list and
//!   `str(ValidationError)`), shared by every request model of later packages;
//! - [`pyrepr`] — Python's `repr`/`str`/`==` of JSON values.
//!
//! Every model validates a [`serde_json::Value`] with [`validate::Model::validate`] (as
//! `Model.model_validate`) or [`validate::Model::validate_body`] (as a FastAPI request body) and
//! dumps back with [`validate::Model::dump`] (`model_dump()`) and [`validate::Model::dump_json`]
//! (`model_dump_json()`), byte-for-byte what the Python panel produces (golden tests in `tests/`).
//!
//! Limits of the JSON model (see DIFFERENCES.md): integers must fit `i64` (Python's are
//! unbounded; a larger one is an `int_parsing_size` issue) and `NaN`/`Infinity` never reach a
//! model.

pub mod clients;
pub mod common;
pub mod fleet;
pub mod metrics;
pub mod nodes;
pub mod protocols;
pub mod pyrepr;
pub mod routing;
pub mod seams;
pub mod subscriptions;
pub mod validate;

pub use common::{Backend, Protocol, SecretRef, WireEnum};
pub use validate::{Model, ValidationError};
