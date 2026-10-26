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
pub mod routing;

pub use error::{CentralError, CentralResult};

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> CentralResult<T> + Send + 'static) -> CentralResult<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| CentralError::Internal(format!("fleet database task failed: {error}")))?
}

#[cfg(test)]
mod native_fixture;
