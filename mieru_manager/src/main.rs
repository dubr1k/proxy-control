//! Mieru manager: the transactional adapter for MieruProxy's separate `mita` process, serving
//! the panel's API on a Unix socket. `mieru-manager healthcheck` is the container's probe.

mod difflib;
mod egress;
mod error;
mod lanes;
mod mita;
mod pyip;
mod pyjson;
mod pyurl;
mod server;
mod service;
mod util;
mod validate;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pc_common::{ServerOptions, UdsServer};

use crate::mita::{Mita, MitaCli};
use crate::service::MieruManager;

const MITA: &str = "/usr/bin/mita";

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// `os.getenv(key, "").strip() or None`.
fn env_optional(key: &str) -> Option<String> {
    env(key).map(|v| pyjson::strip(&v).to_string()).filter(|v| !v.is_empty())
}

/// GET /v1/health with the token; healthy on any 200, as the Python probe was.
pub fn health_probe(socket: &std::path::Path, token_file: &std::path::Path) -> bool {
    let Ok(token) = pc_common::read_token(token_file) else { return false };
    if !token.is_ascii() {
        return false;
    }
    let headers = [(server::TOKEN_HEADER, token.as_str())];
    matches!(
        pc_common::client::request(socket, "GET", "/v1/health", &headers, None, Duration::from_secs(2)),
        Ok(response) if response.status == 200
    )
}

fn healthcheck() -> i32 {
    let socket = PathBuf::from(env("MIERU_MANAGER_SOCKET").unwrap_or_else(|| "/run/mieru-manager/manager.sock".into()));
    let token =
        PathBuf::from(env("MIERU_MANAGER_TOKEN_FILE").unwrap_or_else(|| "/run/secrets/mieru-manager-token".into()));
    if health_probe(&socket, &token) {
        0
    } else {
        1
    }
}

fn run() -> Result<(), String> {
    let token_file = env("MIERU_MANAGER_TOKEN_FILE").unwrap_or_else(|| "/etc/mieru-manager/token".into());
    let token = std::fs::read_to_string(&token_file).map_err(|err| format!("cannot read {token_file}: {err}"))?;
    let token = pyjson::strip(&token).to_string();
    let sha256 = env("MIERU_MITA_SHA256").ok_or("MIERU_MITA_SHA256 is required")?;
    let public_host = env("MIERU_PUBLIC_HOST").ok_or("MIERU_PUBLIC_HOST is required")?;
    let mita: Arc<dyn Mita> = Arc::new(MitaCli::new(MITA, Vec::new(), Some(sha256.clone())));
    // The installer's slot daemons for lanes (v0.7): `n:port:uds:state_dir,…`.
    let slots = lanes::parse_slots(env_optional("MIERU_LANE_SLOTS").as_deref()).map_err(|err| err.to_string())?;
    let factory = service::cli_slot_factory(PathBuf::from(MITA), Vec::new(), Some(sha256));
    let manager = MieruManager::new(
        mita,
        env("MIERU_MANAGER_STATE").unwrap_or_else(|| "/var/lib/mieru-manager".into()),
        public_host,
    )
    // The WARP proxy-mode endpoint (v0.4), this service's router ingress and its credential
    // file (v0.5).
    .with_providers(
        env_optional("MIERU_EGRESS_WARP"),
        env_optional("MIERU_EGRESS_ROUTER"),
        env_optional("MIERU_EGRESS_ROUTER_CREDENTIAL_FILE").map(PathBuf::from),
    )
    .with_lanes(slots, Some(factory));
    manager.bootstrap().map_err(|err| err.to_string())?;
    let manager = Arc::new(manager);
    let handler = server::handler(manager, token)?;
    let socket = env("MIERU_MANAGER_SOCKET").unwrap_or_else(|| "/run/mieru-manager/manager.sock".into());
    let mut options = ServerOptions::new(&socket);
    options.max_body = server::MAX_BODY;
    options.uid = match env("MIERU_PANEL_UID").filter(|v| !v.is_empty()) {
        Some(uid) => {
            Some(util::parse_int(&uid, 10).and_then(|n| u32::try_from(n).ok()).ok_or("MIERU_PANEL_UID: not a uid")?)
        }
        None => None,
    };
    let mode = env("MIERU_SOCKET_MODE").unwrap_or_else(|| "660".into());
    options.mode =
        util::parse_int(&mode, 8).and_then(|n| u32::try_from(n).ok()).ok_or("MIERU_SOCKET_MODE: not an octal mode")?;
    let server = UdsServer::bind(options).map_err(|err| format!("cannot bind {socket}: {err}"))?;
    pc_common::server::shutdown_on_signals(server.shutdown_handle(), || {}).map_err(|err| err.to_string())?;
    server.serve(handler);
    Ok(())
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(healthcheck());
    }
    pc_common::logger::init(log::LevelFilter::Info);
    if let Err(err) = run() {
        log::error!("{err}");
        std::process::exit(1);
    }
}
