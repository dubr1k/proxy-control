//! Client subscriptions of the Proxy Control panel's Rust port (work package WP9):
//! `panel/subscriptions/**` and the decisions of `panel/subscription_routes.py` (the routes
//! themselves live in the web crate: `routes/subscriptions_admin.rs`, `routes/subscriptions.rs`).
//!
//! - [`service`] — [`SubscriptionService`]: issue, rotate, revoke, the audited reveal of the
//!   escrowed token, the generation hook ([`service::BumpGeneration`]), fetch records and events,
//!   the effective manifest and its ETag, the reveal payload, the operator's overview; it also is
//!   the clients domain's [`panel_clients::subscriptions::SubscriptionIssuer`];
//! - [`store`] — the `client_subscriptions` rows;
//! - [`renderers`] — the five formats ([`renderers::Format`]) and [`renderers::resolve_artifacts`],
//!   the one place a credential is revealed;
//! - [`names`] — display names shared by every format;
//! - [`apps`], [`compatibility`] — the app catalogue and the verified compatibility matrix;
//! - [`page_assets`] — the page's inline style and script and the CSP that pins them;
//! - [`public`] — token shape, content negotiation and User-Agent sniffing of `/s/{token}`;
//! - [`text`] — `html.escape`, the deep-link guard, the UTC stamp.
//!
//! Database work blocks: run the service's methods in `spawn_blocking`.

pub mod apps;
pub mod compatibility;
pub mod names;
pub mod page_assets;
pub mod public;
pub mod renderers;
pub mod service;
pub mod store;
pub mod text;

pub use renderers::{Format, RenderError, RenderOptions};
pub use service::{BumpGeneration, SubscriptionService};

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
