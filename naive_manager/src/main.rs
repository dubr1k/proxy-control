//! NaiveProxy manager: owns the credential, lanes, egress and accounting blocks of the
//! Caddyfile, accounts completed CONNECT tunnels from Caddy's access log, and serves the
//! panel's API on a Unix socket.
//!
//! `naive-manager [--bootstrap-only]` runs it (the installer's first take-over uses
//! `--bootstrap-only`); `naive-manager healthcheck` is the container's health probe.

mod caddy;
mod caddyfile;
mod config;
mod difflib;
mod egress;
mod error;
mod fsops;
mod ipnet;
mod lanes;
mod pyjson;
mod pyutil;
mod routing;
mod server;
mod service;
mod state;
mod text;
mod traffic;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_egress;
#[cfg(test)]
mod tests_lanes;
#[cfg(test)]
mod tests_traffic;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pc_common::{ServerOptions, UdsServer};

const USAGE: &str = "usage: naive-manager [-h] [--bootstrap-only]";

fn healthcheck() -> i32 {
    let env = |key: &str, default: &str| std::env::var(key).unwrap_or_else(|_| default.into());
    let socket = PathBuf::from(env("NAIVE_MANAGER_SOCKET", "/run/naive-manager/manager.sock"));
    let token_file = PathBuf::from(env("NAIVE_MANAGER_TOKEN_FILE", "/run/secrets/naive-manager-token"));
    let Ok(token) = pc_common::read_token(&token_file) else { return 1 };
    let headers = [(server::TOKEN_HEADER, token.as_str())];
    match pc_common::client::request(&socket, "GET", "/v1/health", &headers, None, Duration::from_secs(3)) {
        Ok(reply) if reply.status == 200 => 0,
        _ => 1,
    }
}

/// argparse with one flag: `--bootstrap-only` (or an unambiguous prefix), `-h`.
fn parse_args(args: &[String]) -> Result<bool, i32> {
    let mut bootstrap_only = false;
    for arg in args {
        if arg == "-h" || (arg.len() >= 3 && "--help".starts_with(arg.as_str())) {
            println!("{USAGE}\n\noptions:\n  -h, --help        show this help message and exit\n  --bootstrap-only");
            return Err(0);
        }
        if arg.len() >= 3 && "--bootstrap-only".starts_with(arg.as_str()) {
            bootstrap_only = true;
            continue;
        }
        let message = match arg.split_once('=') {
            Some((flag, value)) if flag.len() >= 3 && "--bootstrap-only".starts_with(flag) => {
                format!("argument --bootstrap-only: ignored explicit argument '{value}'")
            }
            _ => format!("unrecognized arguments: {arg}"),
        };
        eprintln!("{USAGE}\nnaive-manager: error: {message}");
        return Err(2);
    }
    Ok(bootstrap_only)
}

fn run(bootstrap_only: bool) -> Result<(), String> {
    let env: HashMap<String, String> = std::env::vars().collect();
    let config = config::from_env(&env)?;
    let manager = config::build_manager(&config).map_err(|err| err.to_string())?;
    manager.bootstrap().map_err(|err| err.to_string())?;
    let traffic = manager.traffic().ok_or("traffic accounting is unavailable")?;
    if bootstrap_only {
        traffic.close();
        return Ok(());
    }
    traffic.collect().map_err(|err| err.to_string())?;
    let get = |key: &str, default: &str| env.get(key).cloned().unwrap_or_else(|| default.to_string());
    let token_file = PathBuf::from(get("NAIVE_MANAGER_TOKEN_FILE", "/etc/naive-manager/token"));
    let raw =
        std::fs::read_to_string(&token_file).map_err(|err| format!("cannot read {}: {err}", token_file.display()))?;
    let token = pyutil::strip(&raw).to_string();
    if token.chars().count() < 32 {
        return Err("manager token is missing or too short".into());
    }
    let mode = config::parse_int(&get("NAIVE_SOCKET_MODE", "600"), 8)
        .filter(|mode| (0..=0o7777).contains(mode))
        .ok_or("NAIVE_SOCKET_MODE: invalid literal for int() with base 8")?;
    let socket = PathBuf::from(get("NAIVE_MANAGER_SOCKET", "/run/naive-manager/manager.sock"));
    let mut options = ServerOptions::new(&socket);
    options.mode = mode as u32;
    options.uid = None;
    options.max_body = server::MAX_BODY;
    let server = UdsServer::bind(options).map_err(|err| format!("cannot bind {}: {err}", socket.display()))?;
    let interval = match env.get("NAIVE_QUOTA_INTERVAL_SECONDS") {
        Some(value) => {
            config::parse_float(value).ok_or("NAIVE_QUOTA_INTERVAL_SECONDS: could not convert string to float")?
        }
        None => config::QUOTA_INTERVAL_SECONDS,
    };
    let enforcing = manager.clone();
    let enforcer = server::QuotaEnforcer::start(
        Arc::new(move || enforcing.enforce_quotas()),
        interval,
        config::QUOTA_MAX_BACKOFF_SECONDS,
    )
    .map_err(|err| err.to_string())?;
    pc_common::server::shutdown_on_signals(server.shutdown_handle(), enforcer.stopper())
        .map_err(|err| err.to_string())?;
    server.serve(server::handler(manager.clone(), token));
    enforcer.stop();
    // A pass in flight finishes its transaction before the database closes.
    enforcer.join(Duration::from_secs(30));
    traffic.close();
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("healthcheck") {
        std::process::exit(healthcheck());
    }
    let bootstrap_only = match parse_args(&args) {
        Ok(flag) => flag,
        Err(code) => std::process::exit(code),
    };
    pc_common::logger::init(log::LevelFilter::Info);
    if let Err(err) = run(bootstrap_only) {
        log::error!("{err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_command_line_takes_bootstrap_only_like_argparse() {
        assert_eq!(parse_args(&args(&[])), Ok(false));
        assert_eq!(parse_args(&args(&["--bootstrap-only"])), Ok(true));
        assert_eq!(parse_args(&args(&["--boot"])), Ok(true));
        assert_eq!(parse_args(&args(&["--nope"])), Err(2));
        assert_eq!(parse_args(&args(&["--bootstrap-only=1"])), Err(2));
        assert_eq!(parse_args(&args(&["-h"])), Err(0));
    }
}
