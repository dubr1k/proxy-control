//! TrustTunnel manager: supervises the pinned `trusttunnel_endpoint` and serves the panel's API
//! on a Unix socket. `trusttunnel-manager healthcheck` is the container's health probe.

mod cert;
mod config;
mod metrics;
mod server;
mod service;
mod state;
mod supervisor;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pc_common::{ServerOptions, UdsServer};

use crate::service::TrusttunnelManager;
use crate::supervisor::ProcessSupervisor;

const TICK: Duration = Duration::from_secs(1);
/// A manager that waits for the installer to issue the certificate is up; anything else that is
/// not "ok" fails the container health.
const TOLERATED: &[(&str, &str)] = &[("degraded", "certificate_missing")];

fn healthcheck() -> i32 {
    let env = |key: &str, default: &str| std::env::var(key).unwrap_or_else(|_| default.into());
    let socket = PathBuf::from(env("TT_MANAGER_SOCKET", "/run/trusttunnel-manager/manager.sock"));
    let token = PathBuf::from(env("TT_MANAGER_TOKEN_FILE", "/run/secrets/trusttunnel-manager-token"));
    if pc_common::client::health_probe(&socket, &token, server::TOKEN_HEADER, TOLERATED) {
        0
    } else {
        1
    }
}

/// `trusttunnel-manager health`: prints the manager's `/v1/health` body for the installer, which
/// runs it inside the container so the token never leaves it. Exit 1 unless the answer is 200.
fn print_health() -> i32 {
    let Ok(token_file) = std::env::var("TT_MANAGER_TOKEN_FILE") else { return 1 };
    let socket = std::env::var("TT_MANAGER_SOCKET").unwrap_or_else(|_| "/run/trusttunnel-manager/manager.sock".into());
    let Ok(token) = std::fs::read_to_string(&token_file) else { return 1 };
    let headers = [(server::TOKEN_HEADER, token.trim())];
    match pc_common::client::request(socket.as_ref(), "GET", "/v1/health", &headers, None, Duration::from_secs(5)) {
        Ok(reply) if reply.status == 200 => {
            println!("{}", String::from_utf8_lossy(&reply.body));
            0
        }
        _ => 1,
    }
}

fn run() -> Result<(), String> {
    let config = config::from_env(&std::env::vars().collect()).map_err(|err| err.to_string())?;
    let token = pc_common::read_token(&config.token_file)?;
    let mut options = ServerOptions::new(&config.socket);
    options.mode = config.socket_mode;
    options.max_body = server::MAX_BODY;
    let manager = Arc::new(TrusttunnelManager::production(
        config.clone(),
        Box::new(ProcessSupervisor::new(config.binary.clone())),
    ));
    manager.bootstrap().map_err(|err| err.to_string())?;
    let handler = server::handler(manager.clone(), token)?;
    let server = match UdsServer::bind(options) {
        Ok(server) => server,
        Err(err) => {
            manager.shutdown();
            return Err(format!("cannot bind {}: {err}", config.socket.display()));
        }
    };
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
    manager.shutdown();
    Ok(())
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("healthcheck") => std::process::exit(healthcheck()),
        Some("health") => std::process::exit(print_health()),
        _ => {}
    }
    pc_common::logger::init(log::LevelFilter::Info);
    if let Err(err) = run() {
        log::error!("{err}");
        std::process::exit(1);
    }
}
