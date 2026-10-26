//! The clients domain of the Proxy Control panel's Rust port (work package WP7): `panel/clients/*`
//! and the request models of `panel/client_routes.py` (the routes themselves live in the web crate,
//! `panel/crates/web/src/routes/clients.rs`).
//!
//! - [`store`] — client and grant rows in the caller's transaction, the filtered and paged listing
//!   with its cursor (`clients/store.py`);
//! - [`service`] — [`ClientService`]: create, rename, label, state, delete, credential capture and
//!   adoption, access reconciliation, the change hooks (`clients/service.py`);
//! - [`provisioning`] — [`ProvisioningService`]: the saga with its journal, resume and
//!   compensation, remote steps finished by the fleet pusher, bundles and links
//!   (`clients/provisioning.py`);
//! - [`lifecycle`] — [`GrantLifecycle`]: enable/disable/rotate/delete of one grant, local or on a
//!   linked panel (`clients/lifecycle.py`);
//! - [`facade`] — [`DomainFacade`]: the domain writer behind the protocol pages, the only writer
//!   (`clients/facade.py`; `PANEL_VNEXT_WRITER=legacy` is retired);
//! - [`importer`] — the read-only import of runtime accounts (`clients/importer.py`);
//! - [`enforcement`] — [`AccessEnforcer`], the local deadline loop (`clients/enforcement.py`);
//! - [`managed`] — the ADR 003 gate (`fleet_v2/guard.py`, the reads of `fleet_v2/managed.py`);
//! - [`hosts`] — `public_hosts_for` of `fleet_v2/central_routes.py`;
//! - [`hooks`] — the `publish_for_client` change hook of `create_app`;
//! - [`subscriptions`] — the seam to the subscriptions package for `POST /api/clients`;
//! - [`models`] — the request models of the client API (`panel/schemas.py`);
//! - [`error`] — [`ClientsError`] and the bodies the app's exception handlers answer for manager
//!   failures that escaped an adapter.
//!
//! Database work blocks: the synchronous methods run in `spawn_blocking` (the async ones do that
//! themselves); no connection is held across an `.await`.

pub mod context;
pub mod enforcement;
pub mod error;
pub mod facade;
pub mod hooks;
pub mod hosts;
pub mod importer;
pub mod lifecycle;
pub mod managed;
pub mod models;
pub mod provisioning;
pub mod service;
pub mod store;
pub mod subscriptions;

mod cursor;

pub use context::AuditContext;
pub use enforcement::AccessEnforcer;
pub use error::ClientsError;
pub use facade::DomainFacade;
pub use lifecycle::GrantLifecycle;
pub use provisioning::ProvisioningService;
pub use service::{Adapters, ClientService};

/// `LOCAL_NODE_ID`.
pub const LOCAL_NODE_ID: &str = "local";
/// `DEFAULT_ENDPOINT`.
pub const DEFAULT_ENDPOINT: &str = "default";
/// The purpose of every grant credential in `secret_versions`.
pub const CREDENTIAL_PURPOSE: &str = "grant.credential";

/// Runs database work off the runtime; a panic in it is re-raised here.
pub async fn blocking<T, F>(work: F) -> Result<T, ClientsError>
where
    F: FnOnce() -> Result<T, ClientsError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => Err(ClientsError::Internal(error.to_string())),
    }
}

/// Python's truthiness of a JSON value.
pub(crate) fn truthy(value: &serde_json::Value) -> bool {
    use serde_json::Value;
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `hmac.compare_digest` over bytes.
pub(crate) fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
