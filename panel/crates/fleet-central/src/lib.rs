//! The central side of fleet v2 (`panel/fleet_v2/`, WP12b).
//!
//! The wire models and the node-side implementation live in `panel-model` and `panel-fleet`.
//! This crate owns the outbound HTTPS client, linked-panel state, desired generations, the
//! delivery loop, adoption of existing node accounts and linked-node metrics fan-in.

pub mod client;
pub mod error;
pub mod generations;
pub mod importing;
pub mod links;
pub mod metrics_source;
pub mod pusher;

pub use error::{CentralError, CentralResult};
