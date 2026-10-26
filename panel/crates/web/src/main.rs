//! `panel` — the Proxy Control panel.
//!
//! - `panel` (or `panel serve`): the HTTP server (`PANEL_LISTEN`, default `0.0.0.0:8787`);
//! - `panel healthcheck`: the container health check;
//! - `panel cli [--database PATH] <command> …`: the administration commands;
//! - `panel stage-secret verify SOURCE | stage SOURCE DEST`: the entrypoint's token staging.

fn serve() -> i32 {
    let settings = match panel_web::settings_from_env() {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("ERROR {error}");
            return 1;
        }
    };
    let listen = match panel_web::server::Listen::from_env(std::env::var("PANEL_LISTEN").ok().as_deref()) {
        Ok(listen) => listen,
        Err(error) => {
            eprintln!("ERROR {error}");
            return 1;
        }
    };
    // One process, a small worker pool: the hosts have two cores; SQLite and argon2 run on the
    // blocking pool.
    let workers = std::env::var("PANEL_WORKER_THREADS").ok().and_then(|value| value.parse().ok()).unwrap_or(2usize);
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(workers.max(1)).enable_all().build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ERROR cannot start the runtime: {error}");
            return 1;
        }
    };
    let static_dir = panel_web::static_dir_from_env();
    runtime.block_on(async move {
        let state = match tokio::task::spawn_blocking(move || panel_web::wiring::build(settings, static_dir)).await {
            Ok(Ok(state)) => state,
            Ok(Err(error)) => {
                eprintln!("ERROR the panel cannot start: {error}");
                return 1;
            }
            Err(error) => {
                eprintln!("ERROR the panel cannot start: {error}");
                return 1;
            }
        };
        match panel_web::run(state, listen, panel_web::shutdown_signal()).await {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("ERROR {error}");
                1
            }
        }
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None | Some("serve") => serve(),
        Some("healthcheck") => panel_web::healthcheck::run(),
        Some("cli") => panel_web::cli::main(&args[1..]),
        Some("stage-secret") => panel_web::cli::stage_secret(&args[1..]),
        Some(other) => {
            eprintln!("usage: panel [serve | healthcheck | cli … | stage-secret …]\npanel: unknown command {other:?}");
            2
        }
    };
    std::process::exit(code);
}
