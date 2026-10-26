//! Every route of the panel, in the Python registration order.
//!
//! **The order rule.** Starlette resolves overlapping templates by registration order (first match
//! wins; a later full match still beats an earlier method-only match). `app.py` mounts `/static`
//! first and then registers the route modules in this order (`app.py:301-318`); [`all`] must keep
//! it, and each module's [`Routes`] must list its routes in the order of its Python
//! `register_*_routes` function:
//!
//! | # | Python | Rust module | WP |
//! |---|---|---|---|
//! | 0 | `app.mount("/static", StaticFiles(...))` | [`Routes::static_mount`] | WP4 |
//! | 1 | `register_auth_admin_audit_routes` | [`auth`] | WP4 |
//! | 2 | `register_api_key_routes` | [`api_keys`] | WP4 |
//! | 3 | `register_fleet_v2_node_routes` | `fleet_node` | WP12 |
//! | 4 | `register_fleet_v2_central_routes` | `fleet_central` | WP12 |
//! | 5 | `register_version_routes` | `versions` | WP8 |
//! | 6 | `register_openapi_routes` | [`openapi`] | WP4 |
//! | 7 | `register_telemt_dashboard_routes` | `telemt` | WP8 |
//! | 8 | `register_naive_routes` | `naive` | WP8 |
//! | 9 | `register_mieru_routes` | `mieru` | WP8 |
//! | 10 | `register_amneziawg_routes` | `amneziawg` | WP8 |
//! | 11 | `register_trusttunnel_routes` | `trusttunnel` | WP8 |
//! | 12 | `register_fleet_routes` (fleet v1) | — retired (owner decision 2) | — |
//! | 13 | `register_node_routes` | [`nodes`] | WP11 |
//! | 14 | `register_client_routes` | [`clients`] | WP7 |
//! | 15 | `register_subscription_admin_routes` | `subscriptions_admin` | WP9 |
//! | 16 | `register_subscription_routes` (`/s/{token}`) | `subscriptions` | WP9 |
//! | 17 | `register_routing_routes` | `routing` | WP10 |
//! | 18 | `register_metrics_routes` | [`metrics`] | WP13 |
//! | — | test hooks (`test-hooks` feature) | `test_hooks` | WP4 |
//!
//! A package adds `pub mod <name>;` here, a `pub fn routes() -> Routes` in its module, and one
//! `.merge(<name>::routes())` at its row.

use crate::http::router::Routes;

pub mod amneziawg;
pub mod api_keys;
pub mod auth;
pub mod clients;
pub mod fleet_node;
mod gather;
pub mod metrics;
pub mod mieru;
pub mod naive;
pub mod nodes;
pub mod openapi;
pub mod readiness;
pub mod telemt;
#[cfg(feature = "test-hooks")]
pub mod test_hooks;
pub mod trusttunnel;
pub mod versions;

/// The whole route table.
pub fn all() -> Routes {
    let routes = Routes::new()
        .static_mount()
        .merge(auth::routes())
        .merge(api_keys::routes())
        .merge(fleet_node::routes())
        // 4: fleet v2 central routes (WP12b)
        .merge(versions::routes())
        .merge(openapi::routes())
        .merge(telemt::routes())
        .merge(naive::routes())
        .merge(mieru::routes())
        .merge(amneziawg::routes())
        .merge(trusttunnel::routes())
        .merge(nodes::routes())
        .merge(clients::routes())
        // 15-16: subscriptions (WP9); 17: routing (WP10)
        .merge(metrics::routes());
    #[cfg(feature = "test-hooks")]
    let routes = routes.merge(test_hooks::routes());
    routes
}
