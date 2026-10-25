//! AmneziaWG node manager: one amneziawg-go server per protocol version, served to the panel on a
//! Unix socket.
//!
//! Subcommands: `healthcheck` (the container's probe), `health` (prints the manager's health
//! document; the installer reads it inside the container) and `keys genkey|genpsk|pubkey`.

mod config;
mod difflib;
mod egress;
mod host;
mod ipnet;
mod keys;
mod obfuscation;
mod pyjson;
mod server;
mod service;
mod state;
mod util;
mod warp;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pc_common::{ServerOptions, UdsServer};

use crate::host::RealHost;
use crate::service::{AwgManager, Options};

const TICK: Duration = Duration::from_secs(1);

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

/// `GET /v1/health` with the token file; the body of a 200 answer.
fn fetch_health(socket: &Path, token_file: &Path) -> Option<Vec<u8>> {
    let token = pc_common::read_token(token_file).ok()?;
    let reply = pc_common::client::request(
        socket,
        "GET",
        "/v1/health",
        &[(server::TOKEN_HEADER, &token)],
        None,
        Duration::from_secs(2),
    )
    .ok()?;
    (reply.status == 200).then_some(reply.body)
}

/// Healthy only when the manager says `ok` and every enabled instance runs: 200 alone is not enough.
pub fn probe(socket: &Path, token_file: &Path) -> bool {
    let Some(body) = fetch_health(socket, token_file) else { return false };
    let Ok(health) = serde_json::from_slice::<serde_json::Value>(&body) else { return false };
    let instances_running = match health.get("instances") {
        None => true,
        Some(serde_json::Value::Object(instances)) => {
            instances.values().all(|instance| instance.get("running") == Some(&serde_json::Value::Bool(true)))
        }
        Some(_) => false,
    };
    health.get("status").and_then(|s| s.as_str()) == Some("ok") && instances_running
}

fn healthcheck() -> i32 {
    let socket = PathBuf::from(env("AWG_MANAGER_SOCKET", "/run/awg-manager/manager.sock"));
    let token = PathBuf::from(env("AWG_MANAGER_TOKEN_FILE", "/run/secrets/awg-manager-token"));
    if probe(&socket, &token) {
        0
    } else {
        1
    }
}

/// Prints the health document for the installer, which runs this inside the container: the token
/// never leaves it.
fn print_health() -> i32 {
    let Ok(token) = std::env::var("AWG_MANAGER_TOKEN_FILE") else { return 1 };
    let socket = PathBuf::from(env("AWG_MANAGER_SOCKET", "/run/awg-manager/manager.sock"));
    match fetch_health(&socket, Path::new(&token)) {
        Some(body) => {
            println!("{}", String::from_utf8_lossy(&body));
            0
        }
        None => 1,
    }
}

fn run() -> Result<(), String> {
    let config = config::from_env(&std::env::vars().collect()).map_err(|err| err.to_string())?;
    let token = pc_common::read_token(&config.token_file)?;
    let overrides = match &config.obfuscation_file {
        None => Default::default(),
        Some(path) => {
            let text = std::fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
            let raw = serde_json::from_slice(&text).map_err(|err| format!("{}: {err}", path.display()))?;
            obfuscation::load_overrides(&raw).map_err(|err| err.to_string())?
        }
    };
    let manager = Arc::new(AwgManager::new(config.clone(), Box::new(RealHost), Options::production(overrides)));
    // Whatever fails after the data plane came up, do not leave it behind.
    let served = serve(&manager, &config, token);
    manager.shutdown();
    served
}

fn serve(manager: &Arc<AwgManager>, config: &config::Config, token: String) -> Result<(), String> {
    manager.bootstrap().map_err(|err| err.to_string())?;
    let handler = server::handler(manager.clone(), token)?;
    let mut options = ServerOptions::new(&config.socket);
    options.mode = config.socket_mode;
    options.max_body = server::MAX_BODY;
    let server = UdsServer::bind(options).map_err(|err| format!("cannot bind {}: {err}", config.socket.display()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let supervise = {
        let (manager, stop) = (manager.clone(), stop.clone());
        std::thread::Builder::new()
            .name("supervisor".into())
            .spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(TICK);
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    // The supervisor loop must survive a failing tick.
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| manager.tick())).is_err() {
                        log::error!("supervision tick failed");
                    }
                }
            })
            .map_err(|err| err.to_string())?
    };
    let signal_stop = stop.clone();
    pc_common::server::shutdown_on_signals(server.shutdown_handle(), move || signal_stop.store(true, Ordering::SeqCst))
        .map_err(|err| err.to_string())?;
    server.serve(handler);
    stop.store(true, Ordering::SeqCst);
    let _ = supervise.join();
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("healthcheck") => std::process::exit(healthcheck()),
        Some("health") => std::process::exit(print_health()),
        Some("keys") => std::process::exit(keys::cli(&args[2..])),
        _ => {}
    }
    pc_common::logger::init(log::LevelFilter::Info);
    if let Err(err) = run() {
        log::error!("{err}");
        std::process::exit(1);
    }
}
