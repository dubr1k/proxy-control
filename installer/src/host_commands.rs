//! Native host update and transition commands. Shell entry points only locate this binary.
//! Every process goes through HostRunner; tests use private roots and RecordingRunner.
mod agent;
mod compose;
mod update;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pc_host::runner::{HostRunner, RunOptions, SystemRunner};
use serde_json::Value;
type Result<T, E = String> = std::result::Result<T, E>;

pub(super) struct Host<'a> {
    pub root: PathBuf,
    pub source: PathBuf,
    pub runner: &'a dyn HostRunner,
    pub socket: PathBuf,
    pub env: PathBuf,
    pub poll: Duration,
}

impl Host<'_> {
    fn path(&self, host: &str) -> Result<PathBuf> {
        pc_host::fs::root_path(&self.root, host).map_err(|e| e.to_string())
    }

    fn query(&self, args: &[String]) -> Result<String> {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        self.runner.capture_checked(&argv, Duration::from_secs(60)).map_err(|e| e.to_string())
    }

    fn run(&self, args: &[String]) -> Result<()> {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        self.runner
            .run(&argv, &RunOptions { timeout: Duration::from_secs(1200), ..RunOptions::default() })
            .map_err(|e| e.to_string())
            .and_then(|output| {
                if output.returncode == 0 {
                    Ok(())
                } else {
                    Err(format!("command {} failed with exit status {}", args.join(" "), output.returncode))
                }
            })
    }

    fn agent(&self, endpoint: &str, body: Option<&Value>) -> Result<Value> {
        let mut args = strings(&["curl", "-fsS", "--max-time", "60", "--unix-socket", &self.socket.to_string_lossy()]);
        if let Some(body) = body {
            args.extend(strings(&["-X", "POST", "-H", "Content-Type: application/json", "-d"]));
            args.push(serde_json::to_string(body).map_err(|e| e.to_string())?);
        }
        args.push(format!("http://agent{endpoint}"));
        let data = self.query(&args)?;
        serde_json::from_str(&data).map_err(|_| format!("version-agent returned invalid JSON from {endpoint}"))
    }

    fn sleep(&self) {
        std::thread::sleep(self.poll);
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_string()).collect()
}

fn read_env(path: &Path) -> Result<BTreeMap<String, String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error.to_string()),
    };
    let mut values = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.to_string(), value.to_string());
        }
    }
    Ok(values)
}

fn check_version(value: &str) -> bool {
    let base = value.split_once('-').map_or(value, |(base, _)| base);
    let parts: Vec<&str> = base.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn safe_name(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Extra commands deliberately do not widen installer_core's frozen transaction CLI enum.
/// --root is a recovery/test seam; --source overrides the executable-derived release tree.
pub fn cli(arguments: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> Option<i32> {
    let command = arguments
        .iter()
        .position(|arg| matches!(arg.as_str(), "update-host" | "migrate-agent" | "migrate-compose-project"))?;
    let name = &arguments[command];
    let mut options = BTreeMap::new();
    let mut check = false;
    let mut index = 0;
    while index < arguments.len() {
        if index == command {
            index += 1;
            continue;
        }
        let key = &arguments[index];
        if matches!(key.as_str(), "--help" | "-h") {
            let _ = writeln!(
                stdout,
                "usage: proxy-control-installer [--root ROOT] [--source RELEASE] {name} {}",
                match name.as_str() {
                    "update-host" => "--version X.Y.Z --sha256 DIGEST [--lang ru|en]",
                    "migrate-agent" => "[--version X.Y.Z] [--lang ru|en]",
                    _ => "[--dir DIR] [--lang ru|en] [--check]",
                }
            );
            return Some(0);
        }
        if key == "--check" && name == "migrate-compose-project" {
            check = true;
            index += 1;
            continue;
        }
        let valid = matches!(key.as_str(), "--root" | "--source" | "--lang")
            || (name != "migrate-compose-project" && key == "--version")
            || (name == "update-host" && key == "--sha256")
            || (name == "migrate-compose-project" && key == "--dir");
        if !valid || index + 1 >= arguments.len() {
            let _ = writeln!(stderr, "BLOCKED: unknown or incomplete {name} option: {key}");
            return Some(2);
        }
        options.insert(key.clone(), arguments[index + 1].clone());
        index += 2;
    }
    let result = (|| {
        if unsafe { libc::geteuid() } != 0 {
            return Err("root is required".into());
        }
        let language = options.get("--lang").map_or("en", String::as_str);
        if !matches!(language, "en" | "ru") {
            return Err("--lang requires ru or en".into());
        }
        let root = PathBuf::from(options.get("--root").map_or("/", String::as_str));
        let rooted = |path| pc_host::fs::root_path(&root, path).map_err(|e| e.to_string());
        let host = Host {
            source: options.get("--source").map(PathBuf::from).unwrap_or_else(crate::cli::release_tree),
            socket: std::env::var_os("UPDATE_HOST_AGENT_SOCKET")
                .map(PathBuf::from)
                .unwrap_or(rooted("/run/proxy-control/version-agent.sock")?),
            env: std::env::var_os(if name == "migrate-compose-project" {
                "MIGRATE_AGENT_ENV"
            } else {
                "UPDATE_HOST_AGENT_ENV"
            })
            .map(PathBuf::from)
            .unwrap_or(rooted(crate::migration::AGENT_ENV)?),
            poll: Duration::from_secs_f64(
                std::env::var("UPDATE_HOST_POLL_SECONDS")
                    .ok()
                    .and_then(|s| s.parse::<f64>().ok())
                    .filter(|s| s.is_finite() && *s >= 0.0 && *s <= 60.0)
                    .unwrap_or(5.0),
            ),
            root,
            runner: &SystemRunner,
        };
        match name.as_str() {
            "migrate-compose-project" => {
                let project =
                    options.get("--dir").map(PathBuf::from).unwrap_or(host.path(pc_host::archive::PROJECT_DIR)?);
                compose::migrate(&host, &project, check)
            }
            _ => {
                let version = match options.get("--version") {
                    Some(version) => version.clone(),
                    None => std::fs::read_to_string(host.source.join("VERSION"))
                        .map_err(|e| e.to_string())?
                        .trim()
                        .to_string(),
                };
                if !check_version(&version) {
                    return Err("malformed version".into());
                }
                if name == "migrate-agent" {
                    agent::migrate(&host, &version)
                        .map(|_| "version-agent: verified Rust implementation and release version\n".into())
                } else {
                    let expected =
                        options.get("--sha256").filter(|s| digest(s)).ok_or("a verified --sha256 is required")?;
                    update::update(&host, &version, expected)
                }
            }
        }
    })();
    Some(match result {
        Ok(text) => {
            let _ = stdout.write_all(text.as_bytes());
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "BLOCKED: {}", installer_core::cli::bounded_text(&error));
            2
        }
    })
}

#[cfg(test)]
mod tests;
