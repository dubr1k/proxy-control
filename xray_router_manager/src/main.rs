//! The dedicated Xray egress-router of a node (v0.5, ADR 007): its supervisor and API.
//! `xray-router-manager healthcheck [--status | --relay | --relay-enable <name> <port>]` is the
//! container's probe and the installer's view of the manager.

mod difflib;
mod errors;
mod geodata;
mod healthcheck;
mod https;
mod intent;
mod ipaddr;
mod pyjson;
mod render;
mod runner;
mod server;
mod service;
mod util;
mod warp;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pc_common::{ServerOptions, UdsServer};

use crate::errors::Error;
use crate::intent::{MTPROXY_SOCKET, PORTS};
use crate::runner::SubprocessXrayRunner;
use crate::service::{Options, XrayRouterManager};
use crate::util::{py_int, py_strip};

const WATCHDOG: Duration = Duration::from_secs(2);

/// `_env(name, default)`: the stripped value, or `"<name> is required"`.
fn required(env: &HashMap<String, String>, name: &str, default: Option<&str>) -> Result<String, String> {
    match env.get(name).map(String::as_str).or(default) {
        Some(value) if !py_strip(value).is_empty() => Ok(py_strip(value).to_string()),
        _ => Err(format!("{name} is required")),
    }
}

fn integer(env: &HashMap<String, String>, name: &str, default: &str, base: u32) -> Result<i64, String> {
    let raw = env.get(name).map(String::as_str).unwrap_or(default);
    py_int(raw, base)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| format!("invalid literal for int() with base {base}: '{raw}'"))
}

/// The manager the environment describes (`XRAY_ROUTER_*`), checked in the Python order.
pub fn build_manager(env: &HashMap<String, String>) -> Result<XrayRouterManager, String> {
    let bin_dir = PathBuf::from(required(env, "XRAY_ROUTER_BIN_DIR", Some("/opt/xray"))?);
    let state_dir =
        PathBuf::from(env.get("XRAY_ROUTER_STATE_DIR").cloned().unwrap_or_else(|| "/var/lib/xray-router".into()));
    let default_port =
        |tag: &str| PORTS.iter().find(|(name, _)| *name == tag).map(|(_, port)| port.to_string()).unwrap_or_default();
    let ports: BTreeMap<String, i64> = [
        ("naive".to_string(), integer(env, "XRAY_ROUTER_PORT_NAIVE", &default_port("naive"), 10)?),
        ("mieru".to_string(), integer(env, "XRAY_ROUTER_PORT_MIERU", &default_port("mieru"), 10)?),
    ]
    .into();
    let ingress_files = [
        (
            "naive".to_string(),
            PathBuf::from(required(
                env,
                "XRAY_ROUTER_INGRESS_NAIVE_FILE",
                Some("/run/secrets/xray-router-ingress-naive"),
            )?),
        ),
        (
            "mieru".to_string(),
            PathBuf::from(required(
                env,
                "XRAY_ROUTER_INGRESS_MIERU_FILE",
                Some("/run/secrets/xray-router-ingress-mieru"),
            )?),
        ),
    ]
    .into();
    let optional = |name: &str, default: &str| {
        let value = py_strip(env.get(name).map(String::as_str).unwrap_or(default)).to_string();
        (!value.is_empty()).then_some(value)
    };
    // The WARP proxy-mode endpoint the router may send traffic through (v0.4 provider).
    let warp_url = optional("XRAY_ROUTER_EGRESS_WARP", "");
    let artifacts = vec![
        ("xray".to_string(), bin_dir.join("xray"), required(env, "XRAY_ROUTER_XRAY_SHA256", None)?),
        ("geoip".to_string(), bin_dir.join("geoip.dat"), required(env, "XRAY_ROUTER_GEOIP_SHA256", None)?),
        ("geosite".to_string(), bin_dir.join("geosite.dat"), required(env, "XRAY_ROUTER_GEOSITE_SHA256", None)?),
    ];
    // v1.1: the MTProxy ingress on a Unix socket the `xray-router-ingress` bridge shares; empty
    // turns it off (a router that serves naive and mieru only).
    let mtproxy_socket = optional("XRAY_ROUTER_INGRESS_MTPROXY_SOCKET", MTPROXY_SOCKET).map(PathBuf::from);
    // v1.6: the TrustTunnel ingress, a no-auth SOCKS inbound on this loopback port; empty turns it off.
    let trusttunnel = optional("XRAY_ROUTER_PORT_TRUSTTUNNEL", "").unwrap_or_else(|| "0".into());
    let trusttunnel_port = py_int(&trusttunnel, 10)
        .and_then(|port| i64::try_from(port).ok())
        .ok_or_else(|| format!("invalid literal for int() with base 10: '{trusttunnel}'"))?;
    // v3.0.0: the AmneziaWG ingress, a `tun` inbound on this device (made by the AWG manager,
    // owned by this container's uid); empty turns it off.
    let amneziawg_tun = optional("XRAY_ROUTER_TUN_AMNEZIAWG", "");
    let mut options = Options::new(state_dir.clone());
    options.ingress_files = ingress_files;
    options.warp_url = warp_url;
    options.artifacts = artifacts;
    options.ports = Some(ports);
    options.mtproxy_socket = mtproxy_socket;
    options.trusttunnel_port = (trusttunnel_port != 0).then_some(trusttunnel_port);
    options.amneziawg_tun = amneziawg_tun;
    // Xray resolves geosite/geoip codes against the manager's own copy (v0.8): the pinned pair
    // seeds it, updates replace it, the binary directory stays read-only.
    let runner = SubprocessXrayRunner::new(bin_dir.join("xray"), state_dir.join("geodata"));
    Ok(XrayRouterManager::new(options, Arc::new(runner)))
}

fn run() -> Result<(), String> {
    let env: HashMap<String, String> = std::env::vars().collect();
    let token_file = required(&env, "XRAY_ROUTER_MANAGER_TOKEN_FILE", Some("/run/secrets/xray-router-manager-token"))?;
    let token =
        std::fs::read_to_string(&token_file).map_err(|err| format!("{}: '{token_file}'", util::py_oserror(&err)))?;
    let token = py_strip(&token).to_string();
    let manager = Arc::new(build_manager(&env)?);
    match manager.bootstrap() {
        Ok(()) => {}
        // The API still answers (503 with the reason) so the panel can say what is wrong.
        Err(Error::ArtifactMismatch(message)) => log::error!("{message}"),
        Err(other) => return Err(other.to_string()),
    }
    let handler = server::handler(manager.clone(), token)?;
    let mut options = ServerOptions::new(
        env.get("XRAY_ROUTER_SOCKET").cloned().unwrap_or_else(|| "/run/xray-router/manager.sock".into()),
    );
    options.max_body = server::MAX_BODY;
    options.uid = match env.get("XRAY_ROUTER_PANEL_UID").filter(|uid| !uid.is_empty()) {
        Some(uid) => Some(
            py_int(uid, 10)
                .and_then(|uid| u32::try_from(uid).ok())
                .ok_or_else(|| format!("invalid XRAY_ROUTER_PANEL_UID: '{uid}'"))?,
        ),
        None => None,
    };
    let mode = integer(&env, "XRAY_ROUTER_SOCKET_MODE", "660", 8)?;
    options.mode = u32::try_from(mode)
        .ok()
        .filter(|mode| *mode <= 0o7777)
        .ok_or_else(|| format!("invalid socket mode {mode:o}"))?;
    let socket = options.socket_path.clone();
    let server = UdsServer::bind(options).map_err(|err| format!("cannot bind {}: {err}", socket.display()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let (manager, stop) = (manager.clone(), stop.clone());
        std::thread::Builder::new()
            .name("watchdog".into())
            .spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(WATCHDOG);
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    // The watchdog outlives one bad tick.
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| manager.watchdog_tick())) {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => log::warn!("watchdog tick failed: {err}"),
                        Err(_) => log::warn!("watchdog tick failed"),
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
    let _ = watchdog.join();
    manager.close();
    Ok(())
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.get(1).map(String::as_str) == Some("healthcheck") {
        std::process::exit(healthcheck::main(&arguments[2..]));
    }
    util::init_logger();
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
