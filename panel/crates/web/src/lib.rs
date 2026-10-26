//! The Proxy Control panel's HTTP shell (work package WP4) and its binary `panel`.
//!
//! - [`server`] — uvicorn's part and the middleware stack of `create_app` (security headers,
//!   body limit, trusted hosts, proxy headers, the bare 500), TCP or Unix-socket listener;
//! - [`http`] — Starlette/FastAPI semantics: first-match routing with Starlette's 404/405/307,
//!   request reading and FastAPI's check order, Python's `json.loads`, response shapes, cookies,
//!   the static mount;
//! - [`auth`] — the gates of `web_context.py` (session, CSRF, roles, API keys with their rate
//!   limit) and the audit helper;
//! - [`state`] — [`state::AppState`]: what `create_app` builds, plus the service map other
//!   packages fill;
//! - [`wiring`] — the composition root in `create_app`'s order;
//! - [`lifespan`] — the startup work and background loops with the 5 s shutdown grace;
//! - [`routes`] — the route table in Python's registration order (read its module docs before
//!   adding routes), with this package's routes: auth/admins/audit, API keys, OpenAPI, readiness,
//!   and the `test-hooks` routes;
//! - [`cli`], [`healthcheck`] — the `panel cli …`, `panel stage-secret …` and
//!   `panel healthcheck` subcommands.
//!
//! **Writing a handler (other packages).** `async fn h(State(app): State<AppState>, call: Call)
//! -> Handled`, then in FastAPI's order: `call.body_input()?` (routes with a body model), the gate
//! (`app.roles(&call, &["owner"]).await?` …), one [`http::request::Issues`] for path, query and
//! body, then the work. Path parameters: `call.param("name")`. Errors: [`http::response::Failure`]
//! (`Failure::detail(status, text)`, `ApiError` values, `Failure::internal` for the bare 500).
//! JSON answers: [`http::response::json`] (Starlette's compact UTF-8 rendering).

pub mod auth;
pub mod cli;
pub mod healthcheck;
pub mod http;
pub mod lifespan;
pub mod models;
pub mod routes;
pub mod server;
pub mod state;
pub mod wiring;

use std::path::PathBuf;

pub use state::AppState;

/// Whether this build carries the test hooks.
pub const TEST_HOOKS: bool = cfg!(feature = "test-hooks");

/// The settings, with the `PANEL_TEST_*` knobs applied in a `test-hooks` build.
pub fn settings_from_env() -> Result<panel_core::settings::Settings, String> {
    #[allow(unused_mut)]
    let mut settings = panel_core::settings::Settings::from_env().map_err(|error| error.to_string())?;
    #[cfg(feature = "test-hooks")]
    {
        let knob = |name: &str| -> Result<Option<i64>, String> {
            match std::env::var(name) {
                Ok(text) => {
                    panel_core::pytext::int_from_str(&text).map(Some).map_err(|error| format!("{name}: {}", error.0))
                }
                Err(_) => Ok(None),
            }
        };
        if let Some(value) = knob("PANEL_TEST_LOGIN_ATTEMPTS")? {
            settings.login_attempts = value;
        }
        if let Some(value) = knob("PANEL_TEST_LOGIN_WINDOW_SECONDS")? {
            settings.login_window_seconds = value;
        }
        if let Some(value) = knob("PANEL_TEST_REVEAL_TTL_SECONDS")? {
            settings.reveal_ttl_seconds = value;
        }
        if let Some(value) = knob("PANEL_TEST_SESSION_TTL_SECONDS")? {
            settings.session_ttl_seconds = value;
        }
        if let Some(value) = knob("PANEL_TEST_BODY_LIMIT_BYTES")? {
            settings.body_limit_bytes = value;
        }
        if let Some(value) = knob("PANEL_TEST_LOGIN_VERIFY_CONCURRENCY")? {
            settings.login_verify_concurrency = value;
        }
        if let Some(value) = knob("PANEL_TEST_API_KEY_RATE_PER_MINUTE")? {
            settings.api_key_rate_per_minute = value;
        }
        // Like Python's default (derived from the source tree): the checkout's VERSION.
        if std::env::var_os("PANEL_VERSION_FILE").is_none() {
            settings.panel_version_file = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../VERSION"));
        }
    }
    Ok(settings)
}

/// `PANEL_STATIC_DIR`, else the image's `/app/panel/static` (a `test-hooks` build: the checkout's
/// `panel/static`, as Python finds it next to its source).
pub fn static_dir_from_env() -> PathBuf {
    let default = if TEST_HOOKS {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../static"))
    } else {
        PathBuf::from(wiring::DEFAULT_STATIC_DIR)
    };
    std::env::var_os("PANEL_STATIC_DIR").filter(|value| !value.is_empty()).map(PathBuf::from).unwrap_or(default)
}

/// Serves until `shutdown` resolves: startup work, loops (paused with `test-hooks`), the
/// listener, then the graceful stop (requests first, then the loops with their grace).
pub async fn run(
    state: AppState,
    listen: server::Listen,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<(), String> {
    let supervisor = state.lifespan.start(TEST_HOOKS).await?;
    let dispatcher = routes::all().into_dispatcher(state.clone());
    let stack = server::Stack::new(state, dispatcher);
    let served = server::serve(stack, listen, shutdown).await.map_err(|error| error.to_string());
    supervisor.shutdown().await;
    served
}

/// SIGTERM or SIGINT.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
