//! The environment the manager reads (`build_manager` and `main` of the Python server).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::caddy::{https_probe, Admin};
use crate::error::Error;
use crate::service::{Hooks, NaiveManager, Settings};
use crate::traffic::{Options, TrafficCollector};

pub const QUOTA_INTERVAL_SECONDS: f64 = 60.0;
pub const QUOTA_MAX_BACKOFF_SECONDS: f64 = 900.0;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub public_host: String,
    pub caddyfile: PathBuf,
    pub state_file: PathBuf,
    pub backup_dir: PathBuf,
    pub provider_url: Option<String>,
    pub router_url: Option<String>,
    pub router_credential_file: Option<PathBuf>,
    pub traffic_log: PathBuf,
    pub traffic_database: PathBuf,
}

fn get<'a>(env: &'a HashMap<String, String>, key: &str, default: &'a str) -> &'a str {
    env.get(key).map(String::as_str).unwrap_or(default)
}

fn optional(env: &HashMap<String, String>, key: &str) -> Option<String> {
    let value = crate::pyutil::strip(get(env, key, "")).to_string();
    (!value.is_empty()).then_some(value)
}

/// `build_manager`'s reading of the environment.
pub fn from_env(env: &HashMap<String, String>) -> Result<Config, String> {
    let public_host = crate::pyutil::strip(get(env, "NAIVE_PUBLIC_HOST", "")).to_string();
    if public_host.is_empty() {
        return Err("NAIVE_PUBLIC_HOST is required".into());
    }
    let credential_file = optional(env, "NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE")
        .map(|_| PathBuf::from(get(env, "NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE", "")));
    Ok(Config {
        public_host,
        caddyfile: PathBuf::from(get(env, "NAIVE_CADDYFILE", "/data/Caddyfile")),
        state_file: PathBuf::from(get(env, "NAIVE_STATE_FILE", "/data/users.json")),
        backup_dir: PathBuf::from(get(env, "NAIVE_BACKUP_DIR", "/data/backups")),
        // The WARP proxy-mode endpoint the egress API may route the service through (v0.4).
        provider_url: optional(env, "NAIVE_EGRESS_WARP"),
        // This service's ingress on the node's Xray-router and its credential file (v0.5).
        router_url: optional(env, "NAIVE_EGRESS_ROUTER"),
        router_credential_file: credential_file,
        traffic_log: PathBuf::from(get(env, "NAIVE_TRAFFIC_LOG", "/logs/access.json")),
        traffic_database: PathBuf::from(get(env, "NAIVE_TRAFFIC_DATABASE", "/data/traffic.sqlite3")),
    })
}

/// The production manager: Caddy's admin API, the cover probe on 4443, real SOCKS5
/// greetings, and the accounting collector over the access log.
pub fn build_manager(config: &Config) -> Result<Arc<NaiveManager>, Error> {
    let mut settings = Settings::new(
        config.caddyfile.clone(),
        config.state_file.clone(),
        config.backup_dir.clone(),
        &config.public_host,
    );
    settings.provider_url = config.provider_url.clone();
    settings.router_url = config.router_url.clone();
    settings.router_credential_file = config.router_credential_file.clone();
    let (validate_admin, reload_admin) = (Admin::default(), Admin::default());
    let live = config.caddyfile.clone();
    let host = config.public_host.clone();
    let hooks = Hooks {
        validate: Box::new(move |path| validate_admin.adapt(path)),
        reload: Box::new(move || reload_admin.reload(&live)),
        probe: Box::new(move || https_probe(&host, 4443)),
        reachability: Box::new(crate::egress::check_reachable),
    };
    let manager = Arc::new(NaiveManager::new(settings, hooks));
    let weak = Arc::downgrade(&manager);
    let traffic = TrafficCollector::new(
        &config.traffic_log,
        &config.traffic_database,
        Box::new(move || match weak.upgrade() {
            Some(manager) => manager.managed_usernames(),
            None => Err(Error::runtime("managed-user state unavailable")),
        }),
        Options::production(),
    )?;
    manager.set_traffic(Some(Arc::new(traffic)));
    Ok(manager)
}

/// `int(text, base)`: surrounding whitespace, a sign, `_` between digits, `0o` in base 8.
pub fn parse_int(text: &str, base: u32) -> Option<i64> {
    let text = crate::pyutil::strip(text);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = if base == 8 {
        digits
            .strip_prefix("0o")
            .or_else(|| digits.strip_prefix("0O"))
            .map(|d| d.strip_prefix('_').unwrap_or(d))
            .unwrap_or(digits)
    } else {
        digits
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let value = i64::from_str_radix(&digits.replace('_', ""), base).ok()?;
    Some(if negative { -value } else { value })
}

/// `float(text)`: surrounding whitespace, `_` between digits, `inf`/`nan` spellings.
pub fn parse_float(text: &str) -> Option<f64> {
    let text = crate::pyutil::strip(text);
    if text.contains('_') {
        let bytes = text.as_bytes();
        let ok = bytes.iter().enumerate().all(|(i, b)| {
            *b != b'_'
                || (i > 0 && i + 1 < bytes.len() && bytes[i - 1].is_ascii_digit() && bytes[i + 1].is_ascii_digit())
        });
        if !ok {
            return None;
        }
    }
    text.replace('_', "").parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_manager_requires_explicit_public_host() {
        assert_eq!(from_env(&HashMap::new()).unwrap_err(), "NAIVE_PUBLIC_HOST is required");
        let blank: HashMap<String, String> = [("NAIVE_PUBLIC_HOST".to_string(), "  ".to_string())].into();
        assert!(from_env(&blank).is_err());
    }

    #[test]
    fn defaults_and_optional_providers() {
        let env: HashMap<String, String> = [
            ("NAIVE_PUBLIC_HOST", " naive.example.com "),
            ("NAIVE_EGRESS_WARP", " socks5://127.0.0.1:45000 "),
            ("NAIVE_EGRESS_ROUTER", ""),
            ("NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE", "/data/xray-router-ingress"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let config = from_env(&env).unwrap();
        assert_eq!(config.public_host, "naive.example.com");
        assert_eq!(config.caddyfile, PathBuf::from("/data/Caddyfile"));
        assert_eq!(config.state_file, PathBuf::from("/data/users.json"));
        assert_eq!(config.traffic_log, PathBuf::from("/logs/access.json"));
        assert_eq!(config.provider_url.as_deref(), Some("socks5://127.0.0.1:45000"));
        assert_eq!(config.router_url, None);
        assert_eq!(config.router_credential_file, Some(PathBuf::from("/data/xray-router-ingress")));
    }

    #[test]
    fn integers_and_floats_read_like_python() {
        assert_eq!(parse_int("600", 8), Some(0o600));
        assert_eq!(parse_int(" 0o660 ", 8), Some(0o660));
        assert_eq!(parse_int("8", 8), None);
        assert_eq!(parse_float(" 60 "), Some(60.0));
        assert_eq!(parse_float("1_0.5"), Some(10.5));
        assert_eq!(parse_float("6e1"), Some(60.0));
        assert_eq!(parse_float("_1"), None);
    }
}
