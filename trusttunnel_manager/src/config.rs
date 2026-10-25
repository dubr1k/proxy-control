//! Environment configuration, validated fail-closed at startup.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

/// Startup configuration is invalid; the manager refuses to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub token_file: PathBuf,
    pub socket: PathBuf,
    pub socket_mode: u32,
    pub state_dir: PathBuf,
    pub hostname: String,
    pub listen: String,
    pub metrics: String,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub binary: PathBuf,
    pub version: String,
    pub public_port: i64,
    pub restart_delay: f64,
    pub poll_interval: f64,
}

/// A DNS name of at least two labels whose last label starts with a letter.
pub fn is_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |label: &str| {
        let bytes = label.as_bytes();
        (1..=63).contains(&bytes.len())
            && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
    };
    let last = labels[labels.len() - 1];
    labels.iter().all(|label| label_ok(label)) && last.as_bytes()[0].is_ascii_lowercase()
}

pub fn loopback_address(raw: &str, name: &str) -> Result<String, ConfigError> {
    let ok = raw.rsplit_once(':').is_some_and(|(host, port)| {
        let loopback = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => ip.is_loopback(),
            Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
            Err(_) => false,
        };
        loopback && parse_int(port, 10).is_some_and(|port| (1024..=65535).contains(&port))
    });
    if !ok {
        return Err(ConfigError(format!("{name}: must be a loopback address with a port 1024-65535")));
    }
    Ok(raw.to_string())
}

/// An integer as Python's `int(text, base)` reads it: optional sign, `_` between digits, and a
/// `0o` prefix in base 8.
pub fn parse_int(text: &str, base: u32) -> Option<i64> {
    let text = text.trim();
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = if base == 8 {
        digits.strip_prefix("0o").or_else(|| digits.strip_prefix("0O")).unwrap_or(digits)
    } else {
        digits
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let value = i64::from_str_radix(&digits.replace('_', ""), base).ok()?;
    Some(if negative { -value } else { value })
}

fn int_value(raw: &str, name: &str, base: u32) -> Result<i64, ConfigError> {
    parse_int(raw, base).ok_or_else(|| ConfigError(format!("{name}: not a number")))
}

pub fn from_env(env: &HashMap<String, String>) -> Result<Config, ConfigError> {
    let get = |key: &str, default: &str| env.get(key).map(|v| v.trim().to_string()).unwrap_or_else(|| default.into());
    if get("TT_MANAGER_TOKEN_FILE", "").is_empty() {
        return Err(ConfigError("TT_MANAGER_TOKEN_FILE is required".into()));
    }
    let hostname = get("TT_HOSTNAME", "").to_lowercase();
    if !is_hostname(&hostname) {
        return Err(ConfigError("TT_HOSTNAME: a DNS name is required".into()));
    }
    let listen = loopback_address(&get("TT_LISTEN", "127.0.0.1:4453"), "TT_LISTEN")?;
    let metrics = loopback_address(&get("TT_METRICS", "127.0.0.1:1987"), "TT_METRICS")?;
    if listen == metrics {
        return Err(ConfigError("TT_LISTEN and TT_METRICS must differ".into()));
    }
    let mode = int_value(&get("TT_MANAGER_SOCKET_MODE", "660"), "TT_MANAGER_SOCKET_MODE", 8)?;
    if !(0 < mode && mode <= 0o777) || mode & 0o007 != 0 {
        return Err(ConfigError("TT_MANAGER_SOCKET_MODE: must not grant access to others".into()));
    }
    let paths = [
        ("TT_MANAGER_SOCKET", get("TT_MANAGER_SOCKET", "/run/trusttunnel-manager/manager.sock")),
        ("TT_STATE_DIR", get("TT_STATE_DIR", "/var/lib/trusttunnel-manager")),
        ("TT_CERT", get("TT_CERT", &format!("/etc/letsencrypt/live/{hostname}/fullchain.pem"))),
        ("TT_KEY", get("TT_KEY", &format!("/etc/letsencrypt/live/{hostname}/privkey.pem"))),
        ("TT_BINARY", get("TT_BINARY", "/usr/local/bin/trusttunnel_endpoint")),
    ];
    for (name, value) in &paths {
        if !value.starts_with('/') {
            return Err(ConfigError(format!("{name}: must be an absolute path")));
        }
    }
    let [socket, state_dir, cert, key, binary] = paths.map(|(_, value)| PathBuf::from(value));
    Ok(Config {
        token_file: PathBuf::from(get("TT_MANAGER_TOKEN_FILE", "")),
        socket,
        socket_mode: mode as u32,
        state_dir,
        hostname,
        listen,
        metrics,
        cert,
        key,
        binary,
        version: get("TT_VERSION", ""),
        public_port: int_value(&get("TT_PUBLIC_PORT", "443"), "TT_PUBLIC_PORT", 10)?,
        restart_delay: 2.0,
        poll_interval: 5.0, // per-client rows of the live monitor follow the endpoint within seconds
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::Path;

    pub fn make_env(dir: &Path, extra: &[(&str, &str)]) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = [
            ("TT_MANAGER_TOKEN_FILE", dir.join("token")),
            ("TT_MANAGER_SOCKET", dir.join("run/m.sock")),
            ("TT_STATE_DIR", dir.join("state")),
            ("TT_CERT", dir.join("cert.pem")),
            ("TT_KEY", dir.join("key.pem")),
            ("TT_BINARY", dir.join("trusttunnel_endpoint")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.display().to_string()))
        .collect();
        env.insert("TT_HOSTNAME".into(), "gate.example.com".into());
        for (key, value) in extra {
            env.insert(key.to_string(), value.to_string());
        }
        env
    }

    #[test]
    fn config_defaults_and_required_values() {
        let dir = Path::new("/tmp/tt");
        let config = from_env(&make_env(dir, &[])).unwrap();
        assert_eq!((config.listen.as_str(), config.metrics.as_str()), ("127.0.0.1:4453", "127.0.0.1:1987"));
        assert_eq!((config.public_port, config.socket_mode), (443, 0o660));
        let only_host: HashMap<String, String> = [("TT_HOSTNAME".to_string(), "gate.example.com".to_string())].into();
        assert!(from_env(&only_host).unwrap_err().0.contains("TT_MANAGER_TOKEN_FILE"));
        let defaults = from_env(&make_env(dir, &[])).unwrap();
        assert_eq!(defaults.cert, PathBuf::from("/tmp/tt/cert.pem"));
    }

    #[test]
    fn config_rejects_unsafe_values() {
        let dir = Path::new("/tmp/tt");
        for (key, value) in [
            ("TT_HOSTNAME", "10.0.0.1"),
            ("TT_HOSTNAME", ""),
            ("TT_LISTEN", "0.0.0.0:4453"),
            ("TT_LISTEN", "127.0.0.1:80"),
            ("TT_METRICS", "127.0.0.1:4453"),
            ("TT_MANAGER_SOCKET_MODE", "666"),
            ("TT_STATE_DIR", "relative"),
            ("TT_CERT", "cert.pem"),
        ] {
            assert!(from_env(&make_env(dir, &[(key, value)])).is_err(), "{key}={value} must be refused");
        }
    }

    #[test]
    fn hostnames_and_integers_follow_the_python_rules() {
        for good in ["gate.example.com", "a.b", "1.example.com", "x-y.example.org"] {
            assert!(is_hostname(good), "{good}");
        }
        for bad in ["example", "10.0.0.1", "-a.example.com", "a-.example.com", "a..com", "a.com.", "a.1com"] {
            assert!(!is_hostname(bad), "{bad}");
        }
        assert_eq!(parse_int("660", 8), Some(0o660));
        assert_eq!(parse_int("0o640", 8), Some(0o640));
        assert_eq!(parse_int(" 1_000 ", 10), Some(1000));
        assert_eq!(parse_int("9", 8), None);
        assert_eq!(parse_int("", 10), None);
        assert_eq!(parse_int("-5", 10), Some(-5));
    }
}
