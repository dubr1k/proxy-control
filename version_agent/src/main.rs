//! `proxy-control-version-agent`: the host's version-agent service (`python3 -m
//! version_agent.server` before 4.0). Configuration comes from the environment
//! (`/etc/proxy-control/version-agent.env` through the systemd unit).

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use version_agent::host::HostReader;
use version_agent::server::{self, Routes, StopSignal};
use version_agent::{hostmetrics, logging, py, AgentConfig, VersionAgent};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn integer(name: &str, default: &str) -> Result<i64, String> {
    let value = env(name).unwrap_or_else(|| default.to_string());
    py::int(&value)
        .ok_or_else(|| format!("{name}: invalid literal for int() with base 10: {}", pc_host::pytext::py_repr(&value)))
}

fn main() -> ExitCode {
    logging::init();
    let config = match AgentConfig::from_env(env) {
        Ok(config) => config,
        Err(message) => {
            logging::print(&message);
            return ExitCode::FAILURE;
        }
    };
    // buildx keeps its state under $DOCKER_CONFIG; the unit's ProtectHome leaves /root
    // read-only, so a build from the agent needs a writable config dir of its own. Set before
    // any thread starts.
    if std::env::var_os("DOCKER_CONFIG").is_none() {
        let directory = config.state_path.parent().unwrap_or(Path::new("/")).join("docker");
        std::env::set_var("DOCKER_CONFIG", directory);
    }
    let socket = env("PROXY_CONTROL_VERSION_SOCKET").unwrap_or_else(|| server::DEFAULT_SOCKET.to_string());
    let (gid, interval) = match (
        integer("PROXY_CONTROL_VERSION_SOCKET_GID", server::DEFAULT_SOCKET_GID),
        integer("PROXY_CONTROL_UPSTREAM_CHECK_INTERVAL", &server::AUTO_CHECK_INTERVAL.to_string()),
    ) {
        (Ok(gid), Ok(interval)) => match u32::try_from(gid) {
            Ok(gid) => (gid, interval),
            Err(_) => {
                logging::print("cannot set version-agent socket group");
                return ExitCode::FAILURE;
            }
        },
        (Err(message), _) | (_, Err(message)) => {
            logging::print(&message);
            return ExitCode::FAILURE;
        }
    };
    let compose_dir = config.compose_dir.clone().unwrap_or_else(|| "/opt/mtproxy-shared443".into());
    let compose_files = config.compose_files.clone();
    let agent = Arc::new(VersionAgent::new(config));
    match agent.recover_interrupted() {
        Ok(changes) => {
            for change in changes {
                log::warn!(target: "version_agent", "{change} at start-up");
            }
        }
        Err(error) => log::warn!(target: "version_agent", "start-up recovery skipped: {}", error.message()),
    }
    let server = match pc_common::UdsServer::bind(server::server_options(&socket, Some(0), gid)) {
        Ok(server) => server,
        Err(err) => {
            logging::print(&format!("cannot set version-agent socket group: {socket}: {err}"));
            return ExitCode::FAILURE;
        }
    };
    let stop = Arc::new(StopSignal::default());
    let sampler = Arc::new(hostmetrics::production(&compose_dir, &compose_files, agent.runner.clone()));
    if let Err(err) = sampler.start() {
        logging::print(&format!("metrics sampler could not start: {err}"));
    }
    if agent.config.upstream_enabled && interval > 0 {
        let (checked, waiter) = (agent.clone(), stop.clone());
        let started = std::thread::Builder::new().name("upstream-check".into()).spawn(move || {
            server::auto_check_upstream(&checked, interval, &|seconds| waiter.wait(seconds), &hostmetrics::wall_clock);
        });
        if let Err(err) = started {
            logging::print(&format!("automatic upstream check could not start: {err}"));
        }
    }
    let (stopping, sampling) = (stop.clone(), sampler.clone());
    if let Err(err) = pc_common::server::shutdown_on_signals(server.shutdown_handle(), move || {
        stopping.stop();
        sampling.stop();
    }) {
        logging::print(&format!("signal handlers could not be installed: {err}"));
    }
    let reader = Arc::new(HostReader::default());
    let routes = Routes {
        api: Some(Arc::new(agent.clone())),
        host: Arc::new(move || reader.host_metrics()),
        metrics: Some(sampler),
    };
    server::serve(server, routes);
    // A panel update or a manager rebuild in flight finishes and records its verdict before the
    // process exits (a stop past systemd's timeout is recorded by the start-up recovery).
    agent.updater.wait_idle();
    ExitCode::SUCCESS
}
