//! Configuration of the MCP server (spec §9a), from the environment and the two secret files
//! the installer writes: the token MCP clients present and the panel API key the server uses
//! on their behalf.

use std::collections::HashMap;
use std::io;

pub const DEFAULT_PANEL_URL: &str = "http://panel:8787";
pub const DEFAULT_PANEL_KEY_FILE: &str = "/run/secrets/mcp-panel-key";
pub const DEFAULT_TOKEN_FILE: &str = "/run/secrets/mcp-token";
pub const DEFAULT_BIND: &str = "0.0.0.0:8793";
pub const MIN_TOKEN_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub panel_url: String,
    pub panel_host: String,
    pub panel_key: String,
    pub token: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub allowed_hosts: Vec<String>,
    pub public_url: String,
}

/// `OSError.strerror`: the OS message without Rust's ` (os error N)` suffix.
fn strerror(err: &io::Error) -> String {
    let text = err.to_string();
    match text.rfind(" (os error ") {
        Some(at) if err.raw_os_error().is_some() => text[..at].to_string(),
        _ => text,
    }
}

/// `port.isdigit() and 1 <= int(port) <= 65535`.
fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = port.trim_start_matches('0');
    if digits.is_empty() || digits.len() > 5 {
        return None;
    }
    digits.parse::<u32>().ok().filter(|n| (1..=65535).contains(n)).map(|n| n as u16)
}

fn read_secret(path: &str, variable: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|err| format!("{variable}: cannot read {path}: {}", strerror(&err)))?;
    let text = String::from_utf8(bytes).map_err(|err| {
        let at = err.utf8_error().valid_up_to();
        let byte = err.as_bytes()[at];
        format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {at}: invalid start byte")
    })?;
    let value = pc_common::pytext::strip(&text);
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(format!("{variable}: {path} must hold one non-empty line"));
    }
    Ok(value.to_string())
}

impl Config {
    pub fn from_env(env: &HashMap<String, String>) -> Result<Config, String> {
        let get = |key: &str, default: &str| env.get(key).cloned().unwrap_or_else(|| default.to_string());
        let panel_host = pc_common::pytext::strip(&get("MCP_PANEL_HOST", "")).to_string();
        if panel_host.is_empty() {
            return Err("MCP_PANEL_HOST is required: the panel's allowed host name".into());
        }
        let allowed: Vec<String> = get("MCP_ALLOWED_HOSTS", "")
            .split(',')
            .map(|part| pc_common::pytext::strip(part).to_string())
            .filter(|part| !part.is_empty())
            .collect();
        if allowed.is_empty() {
            return Err("MCP_ALLOWED_HOSTS is required: the MCP domain and 127.0.0.1:8793, comma separated".into());
        }
        let bind = get("MCP_BIND", DEFAULT_BIND);
        let bind = pc_common::pytext::strip(&bind);
        let (host, port) = bind.rsplit_once(':').unwrap_or(("", ""));
        let Some(port) = parse_port(port).filter(|_| !host.is_empty()) else {
            return Err("MCP_BIND must be host:port".into());
        };
        let token = read_secret(&get("MCP_TOKEN_FILE", DEFAULT_TOKEN_FILE), "MCP_TOKEN_FILE")?;
        if token.chars().count() < MIN_TOKEN_LENGTH {
            return Err(format!("MCP_TOKEN_FILE: the token must be at least {MIN_TOKEN_LENGTH} characters"));
        }
        let panel_key = read_secret(&get("MCP_PANEL_KEY_FILE", DEFAULT_PANEL_KEY_FILE), "MCP_PANEL_KEY_FILE")?;
        Ok(Config {
            panel_url: get("MCP_PANEL_URL", DEFAULT_PANEL_URL).trim_end_matches('/').to_string(),
            panel_host,
            panel_key,
            token,
            bind_host: host.to_string(),
            bind_port: port,
            allowed_hosts: allowed,
            public_url: pc_common::pytext::strip(&get("MCP_PUBLIC_URL", "")).to_string(),
        })
    }
}

/// The health probe's port: the part of `MCP_BIND` after its last colon, `8793` when empty.
pub fn health_port(env: &HashMap<String, String>) -> String {
    let bind = env.get("MCP_BIND").cloned().unwrap_or_else(|| DEFAULT_BIND.to_string());
    let port = bind.rsplit_once(':').map_or(bind.as_str(), |(_, port)| port);
    if port.is_empty() { "8793" } else { port }.to_string()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const TOKEN: &str = "test-mcp-token-0123456789abcdef0123456789abcdef";
    pub const PANEL_KEY: &str = "pc_deadbeef_test-panel-key";
    pub const PANEL_HOST: &str = "panel.example.com";

    pub fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mcp-server-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn config_reads_secrets_from_files_and_requires_allowed_hosts() {
        let dir = temp_dir("config");
        std::fs::write(dir.join("key"), format!("{PANEL_KEY}\n")).unwrap();
        std::fs::write(dir.join("token"), format!("{TOKEN}\n")).unwrap();
        let env: HashMap<String, String> = [
            ("MCP_PANEL_HOST", PANEL_HOST.to_string()),
            ("MCP_PANEL_KEY_FILE", dir.join("key").display().to_string()),
            ("MCP_TOKEN_FILE", dir.join("token").display().to_string()),
            ("MCP_ALLOWED_HOSTS", "mcp.example.com, 127.0.0.1:8793".to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let config = Config::from_env(&env).unwrap();
        assert_eq!(config.panel_url, "http://panel:8787");
        assert_eq!((config.panel_key.as_str(), config.token.as_str()), (PANEL_KEY, TOKEN));
        assert_eq!(config.allowed_hosts, ["mcp.example.com", "127.0.0.1:8793"]);
        assert_eq!((config.bind_host.as_str(), config.bind_port), ("0.0.0.0", 8793));
        let with = |key: &str, value: &str| {
            let mut changed = env.clone();
            changed.insert(key.into(), value.into());
            Config::from_env(&changed).unwrap_err()
        };
        assert!(with("MCP_ALLOWED_HOSTS", "").contains("MCP_ALLOWED_HOSTS"));
        assert!(with("MCP_PANEL_HOST", "").contains("MCP_PANEL_HOST"));
        assert!(with("MCP_BIND", "nonsense").contains("MCP_BIND"));
        assert_eq!(with("MCP_BIND", "0.0.0.0:70000"), "MCP_BIND must be host:port");
        assert_eq!(with("MCP_BIND", ":8793"), "MCP_BIND must be host:port");
        assert_eq!(
            with("MCP_TOKEN_FILE", "/nonexistent/token"),
            "MCP_TOKEN_FILE: cannot read /nonexistent/token: No such file or directory"
        );
        std::fs::write(dir.join("short"), "short\n").unwrap();
        assert_eq!(
            with("MCP_TOKEN_FILE", &dir.join("short").display().to_string()),
            "MCP_TOKEN_FILE: the token must be at least 32 characters"
        );
        std::fs::write(dir.join("two"), "one\ntwo\n").unwrap();
        let two = dir.join("two").display().to_string();
        assert_eq!(with("MCP_PANEL_KEY_FILE", &two), format!("MCP_PANEL_KEY_FILE: {two} must hold one non-empty line"));
        let custom = {
            let mut changed = env.clone();
            changed.insert("MCP_PANEL_URL".into(), "http://panel:8787///".into());
            changed.insert("MCP_BIND".into(), "127.0.0.1:0080".into());
            Config::from_env(&changed).unwrap()
        };
        assert_eq!((custom.panel_url.as_str(), custom.bind_port), ("http://panel:8787", 80));
        assert_eq!(health_port(&env), "8793");
        let _ = std::fs::remove_dir_all(dir);
    }
}
