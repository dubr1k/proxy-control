//! proxy-control-mcp (spec §9a): the panel's API as Model Context Protocol tools, on the
//! central panel only. `mcp-server` serves `/mcp` and `/healthz` on `MCP_BIND`;
//! `mcp-server healthcheck` is the container's health probe.

mod config;
mod curated;
mod panel;
mod py;
mod server;
mod tools;
mod transport;
mod util;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::panel::PanelClient;
use crate::server::{App, LOG};
use crate::tools::{Fail, ToolRegistry};

/// Threads for blocking work (name resolution); the container allows 64 processes.
const BLOCKING_THREADS: usize = 4;

fn environment() -> HashMap<String, String> {
    std::env::vars_os()
        .map(|(key, value)| (key.to_string_lossy().into_owned(), value.to_string_lossy().into_owned()))
        .collect()
}

/// `GET /healthz` on the loopback answers 200 with `{"status": "ok"}`; no token is needed for it.
fn healthcheck() -> i32 {
    let port = config::health_port(&environment());
    let Ok(response) =
        pc_common::client::tcp_get(&format!("127.0.0.1:{port}"), "/healthz", Duration::from_secs(3), 64 * 1024)
    else {
        return 1;
    };
    let healthy = response.status == 200
        && response.json().ok().and_then(|body| body.get("status").cloned()) == Some(serde_json::json!("ok"));
    i32::from(!healthy)
}

/// What ends the process: the exit code and the message.
struct Exit(i32, String);

async fn run(config: Config) -> Result<(), Exit> {
    let panel = PanelClient::new(&config).map_err(|err| Exit(1, err))?;
    let registry = Arc::new(ToolRegistry::new(panel));
    match registry.reload().await {
        Ok(count) => log::info!(
            target: LOG,
            "tools built from the panel's OpenAPI schema: {count} generated + {} curated",
            registry.curated.len()
        ),
        // The panel may still be starting; the curated tools work and `reload_tools` catches up.
        Err(Fail::Panel(err)) => log::warn!(
            target: LOG,
            "could not load the panel's OpenAPI schema ({}): generated tools are empty until reload_tools",
            err.detail
        ),
        // An OpenAPI document the builder cannot read fails the start, as the Python lifespan did.
        Err(Fail::Py(err)) => {
            return Err(Exit(3, format!("application startup failed: {}: {}", err.kind, err.message)))
        }
    }
    let app = Arc::new(App::new(registry, &config.token, &config.allowed_hosts));
    let listener = tokio::net::TcpListener::bind((config.bind_host.as_str(), config.bind_port))
        .await
        .map_err(|err| Exit(1, format!("cannot bind {}:{}: {err}", config.bind_host, config.bind_port)))?;
    log::info!(target: LOG, "listening on http://{}:{}", config.bind_host, config.bind_port);
    server::serve(app, listener).await;
    Ok(())
}

fn main() {
    if std::env::args_os().nth(1).is_some_and(|arg| arg == "healthcheck") {
        std::process::exit(healthcheck());
    }
    util::init_logger();
    let config = match Config::from_env(&environment()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("proxy-control-mcp: {err}");
            std::process::exit(2);
        }
    };
    let runtime =
        match tokio::runtime::Builder::new_current_thread().enable_all().max_blocking_threads(BLOCKING_THREADS).build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                log::error!(target: LOG, "cannot start the runtime: {err}");
                std::process::exit(1);
            }
        };
    if let Err(Exit(code, message)) = runtime.block_on(run(config)) {
        log::error!(target: LOG, "{message}");
        std::process::exit(code);
    }
}
