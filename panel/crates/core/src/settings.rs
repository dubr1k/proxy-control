//! The panel's configuration (`panel/settings.py`): every environment variable, its default and
//! its parsing, plus the start-up checks `create_app` makes (`panel/app.py:103-110`).
//!
//! Python reads most variables once, at import; [`Settings::from_env`] reads them all once, at
//! start-up, which is the same thing for a process that never changes its own environment.
//!
//! Not carried over (owner decisions 2026-10-25): `PANEL_VNEXT_WRITER` (only the domain writer
//! exists; the variable is ignored, whatever its value) and the fleet v1 variables of
//! `agent_ingress`/`agent_service` (`FLEET_*`, `TELEMT_API_TIMEOUT`), which `Settings` never had.

use std::fmt;
use std::path::PathBuf;

use crate::pytext;

/// Where the release's `VERSION` file is in the image (Python derives it from its source path,
/// which is `/app/panel/settings.py` there).
pub const DEFAULT_VERSION_FILE: &str = "/app/VERSION";

/// A configuration the panel refuses to start with.
#[derive(Debug)]
pub enum SettingsError {
    /// A value Python's parsing rejects (`ValueError`), or a `create_app` check; the message is
    /// Python's.
    Invalid { variable: &'static str, message: String },
    /// A `*_FILE` variable names a file that cannot be read as UTF-8 text.
    TokenFile { variable: &'static str, path: PathBuf, error: std::io::Error },
    /// The variable's value is not valid UTF-8.
    NotUnicode { variable: &'static str },
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SettingsError::Invalid { message, .. } => f.write_str(message),
            SettingsError::TokenFile { variable, path, error } => {
                write!(f, "{variable}: cannot read {}: {error}", path.display())
            }
            SettingsError::NotUnicode { variable } => write!(f, "{variable} is not valid UTF-8"),
        }
    }
}

impl std::error::Error for SettingsError {}

/// The panel's settings. `Debug` hides the six tokens.
#[derive(Clone, PartialEq)]
pub struct Settings {
    /// `PANEL_DATABASE` (`/data/panel.sqlite3`).
    pub database_path: PathBuf,
    /// `TELEMT_API_URL` (`http://mtproxy:9091`).
    pub telemt_url: String,
    /// `TELEMT_API_TOKEN` / `TELEMT_API_TOKEN_FILE`.
    pub telemt_token: String,
    /// `NAIVE_MANAGER_SOCKET` (`/run/naive-manager/manager.sock`).
    pub naive_socket: String,
    /// `NAIVE_MANAGER_TOKEN` / `NAIVE_MANAGER_TOKEN_FILE`.
    pub naive_token: String,
    /// `NAIVE_PUBLIC_HOST`; also the fallback public host of AmneziaWG and TrustTunnel.
    pub naive_public_host: String,
    /// `MTPROXY_DOMAIN`: Telemt's Fake-TLS domain, the fallback host of an MTProxy link.
    pub mtproxy_public_host: String,
    /// `NAIVE_ENABLED` (`.lower() == "true"`).
    pub naive_enabled: bool,
    /// `MIERU_MANAGER_SOCKET` (`/run/mieru-manager/manager.sock`).
    pub mieru_socket: String,
    /// `MIERU_MANAGER_TOKEN` / `MIERU_MANAGER_TOKEN_FILE`.
    pub mieru_token: String,
    /// `MIERU_ENABLED`.
    pub mieru_enabled: bool,
    /// `AWG_MANAGER_SOCKET` (`/run/awg-manager/manager.sock`).
    pub amneziawg_socket: String,
    /// `AWG_MANAGER_TOKEN` / `AWG_MANAGER_TOKEN_FILE`.
    pub amneziawg_token: String,
    /// `AMNEZIAWG_ENABLED`.
    pub amneziawg_enabled: bool,
    /// `AMNEZIAWG_PUBLIC_HOST` (empty: `NAIVE_PUBLIC_HOST`).
    pub amneziawg_public_host: String,
    /// `TRUSTTUNNEL_MANAGER_SOCKET` (`/run/trusttunnel-manager/manager.sock`).
    pub trusttunnel_socket: String,
    /// `TRUSTTUNNEL_MANAGER_TOKEN` / `TRUSTTUNNEL_MANAGER_TOKEN_FILE`.
    pub trusttunnel_token: String,
    /// `TRUSTTUNNEL_ENABLED`.
    pub trusttunnel_enabled: bool,
    /// `TRUSTTUNNEL_PUBLIC_HOST` (empty: `NAIVE_PUBLIC_HOST`).
    pub trusttunnel_public_host: String,
    /// `XRAY_ROUTER_ENABLED`.
    pub xray_router_enabled: bool,
    /// `XRAY_ROUTER_MANAGER_SOCKET` (`/run/xray-router/manager.sock`).
    pub xray_router_socket: String,
    /// `XRAY_ROUTER_MANAGER_TOKEN` / `XRAY_ROUTER_MANAGER_TOKEN_FILE`.
    pub xray_router_token: String,
    /// `PANEL_SUBSCRIPTION_URL`: the public base of `/s/{token}` (empty: not published).
    pub subscription_url: String,
    /// `PANEL_SUBSCRIPTION_HOST` lower-cased, else the URL's host lower-cased; the only Host `/s/`
    /// answers on (empty: every `/s/` request is a 404).
    pub subscription_host: String,
    /// `PANEL_SINGBOX_FORK_CLIENTS`: comma-separated User-Agent substrings.
    pub singbox_fork_clients: String,
    /// `VERSION_AGENT_SOCKET` (`/run/proxy-control/version-agent.sock`).
    pub version_agent_socket: String,
    /// `PANEL_VERSION_FILE` ([`DEFAULT_VERSION_FILE`]).
    pub panel_version_file: PathBuf,
    /// `PANEL_MASTER_KEY_FILE` (unset or empty: no secret store).
    pub master_key_file: Option<PathBuf>,
    /// `PANEL_COOKIE_SECURE` (`true`).
    pub session_cookie_secure: bool,
    /// `PANEL_ALLOWED_HOSTS` split on `,`, empty items dropped, nothing trimmed.
    pub allowed_hosts: Vec<String>,
    pub session_ttl_seconds: i64,
    pub login_attempts: i64,
    pub login_window_seconds: i64,
    pub reveal_ttl_seconds: i64,
    pub body_limit_bytes: i64,
    pub login_verify_concurrency: i64,
    pub api_key_rate_per_minute: i64,
    /// `PANEL_FLEET_HEARTBEAT_SECONDS` (`15`).
    pub fleet_heartbeat_seconds: i64,
    /// `PANEL_METRICS_ENABLED`: off for `0`/`false`/`no`/`off` (stripped, any case).
    pub metrics_enabled: bool,
    /// `PANEL_METRICS_INTERVAL_SECONDS`, else `METRICS_INTERVAL_SECONDS`, else `2` — as given; the
    /// sampler uses [`Settings::metrics_interval`].
    pub metrics_interval_seconds: f64,
    /// `PANEL_METRICS_RING_POINTS` (`900`).
    pub metrics_ring_points: i64,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = |token: &str| if token.is_empty() { "" } else { "<redacted>" };
        f.debug_struct("Settings")
            .field("database_path", &self.database_path)
            .field("telemt_url", &self.telemt_url)
            .field("telemt_token", &redacted(&self.telemt_token))
            .field("naive_socket", &self.naive_socket)
            .field("naive_token", &redacted(&self.naive_token))
            .field("naive_public_host", &self.naive_public_host)
            .field("mtproxy_public_host", &self.mtproxy_public_host)
            .field("naive_enabled", &self.naive_enabled)
            .field("mieru_socket", &self.mieru_socket)
            .field("mieru_token", &redacted(&self.mieru_token))
            .field("mieru_enabled", &self.mieru_enabled)
            .field("amneziawg_socket", &self.amneziawg_socket)
            .field("amneziawg_token", &redacted(&self.amneziawg_token))
            .field("amneziawg_enabled", &self.amneziawg_enabled)
            .field("amneziawg_public_host", &self.amneziawg_public_host)
            .field("trusttunnel_socket", &self.trusttunnel_socket)
            .field("trusttunnel_token", &redacted(&self.trusttunnel_token))
            .field("trusttunnel_enabled", &self.trusttunnel_enabled)
            .field("trusttunnel_public_host", &self.trusttunnel_public_host)
            .field("xray_router_enabled", &self.xray_router_enabled)
            .field("xray_router_socket", &self.xray_router_socket)
            .field("xray_router_token", &redacted(&self.xray_router_token))
            .field("subscription_url", &self.subscription_url)
            .field("subscription_host", &self.subscription_host)
            .field("singbox_fork_clients", &self.singbox_fork_clients)
            .field("version_agent_socket", &self.version_agent_socket)
            .field("panel_version_file", &self.panel_version_file)
            .field("master_key_file", &self.master_key_file)
            .field("session_cookie_secure", &self.session_cookie_secure)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("fleet_heartbeat_seconds", &self.fleet_heartbeat_seconds)
            .field("metrics_enabled", &self.metrics_enabled)
            .field("metrics_interval_seconds", &self.metrics_interval_seconds)
            .field("metrics_ring_points", &self.metrics_ring_points)
            .finish_non_exhaustive()
    }
}

/// `pathlib.Path(text)`: repeated and trailing slashes and `.` components dropped, `""` is `.`.
pub fn py_path(text: &str) -> PathBuf {
    let root = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = text.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
    let joined = format!("{root}{}", parts.join("/"));
    PathBuf::from(if joined.is_empty() { ".".to_string() } else { joined })
}

/// Reads one variable (`os.getenv`): `Ok(None)` when unset.
type Lookup<'a> = dyn Fn(&'static str) -> Result<Option<String>, SettingsError> + 'a;

struct Env<'a> {
    lookup: &'a Lookup<'a>,
}

impl Env<'_> {
    fn get(&self, name: &'static str) -> Result<Option<String>, SettingsError> {
        (self.lookup)(name)
    }

    /// `os.getenv(name, default)`.
    fn str(&self, name: &'static str, default: &str) -> Result<String, SettingsError> {
        Ok(self.get(name)?.unwrap_or_else(|| default.to_string()))
    }

    /// `os.getenv(name, default).lower() == "true"`.
    fn flag(&self, name: &'static str, default: &str) -> Result<bool, SettingsError> {
        Ok(pytext::lower(&self.str(name, default)?) == "true")
    }

    /// `int(os.getenv(name, default))`.
    fn int(&self, name: &'static str, default: &str) -> Result<i64, SettingsError> {
        let text = self.str(name, default)?;
        pytext::int_from_str(&text).map_err(|error| SettingsError::Invalid { variable: name, message: error.0 })
    }

    /// `_secret_setting(name, file_name)`: the file's text, stripped, when `file_name` is set and
    /// non-empty; otherwise `name`'s value or `""`.
    fn secret(&self, name: &'static str, file_name: &'static str) -> Result<String, SettingsError> {
        match self.get(file_name)?.filter(|path| !path.is_empty()) {
            Some(path) => {
                let path = py_path(&path);
                let bytes = std::fs::read(&path).map_err(|error| SettingsError::TokenFile {
                    variable: file_name,
                    path: path.clone(),
                    error,
                })?;
                let text = String::from_utf8(bytes).map_err(|error| SettingsError::TokenFile {
                    variable: file_name,
                    path: path.clone(),
                    error: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
                })?;
                // `read_text()` opens in text mode: universal newlines.
                let text = text.replace("\r\n", "\n").replace('\r', "\n");
                Ok(pytext::strip(&text).to_string())
            }
            None => self.str(name, ""),
        }
    }
}

impl Settings {
    /// `Settings()` from the process environment.
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(SettingsError::NotUnicode { variable: name }),
        })
    }

    /// `Settings()` from any variable source (tests pass a map).
    pub fn from_lookup(
        lookup: impl Fn(&'static str) -> Result<Option<String>, SettingsError>,
    ) -> Result<Self, SettingsError> {
        let env = Env { lookup: &lookup };
        let interval_text = match env.get("PANEL_METRICS_INTERVAL_SECONDS")? {
            Some(text) => text,
            None => env.str("METRICS_INTERVAL_SECONDS", "2")?,
        };
        let interval_variable = "PANEL_METRICS_INTERVAL_SECONDS";
        let metrics_interval_seconds = pytext::float_from_str(&interval_text)
            .map_err(|error| SettingsError::Invalid { variable: interval_variable, message: error.0 })?;
        let subscription_url = env.str("PANEL_SUBSCRIPTION_URL", "")?;
        let mut subscription_host = pytext::lower(&env.str("PANEL_SUBSCRIPTION_HOST", "")?);
        if subscription_host.is_empty() && !subscription_url.is_empty() {
            let parts = pytext::urlsplit(&subscription_url)
                .map_err(|error| SettingsError::Invalid { variable: "PANEL_SUBSCRIPTION_URL", message: error.0 })?;
            subscription_host = pytext::lower(&parts.hostname().unwrap_or_default());
        }
        Ok(Settings {
            database_path: py_path(&env.str("PANEL_DATABASE", "/data/panel.sqlite3")?),
            telemt_url: env.str("TELEMT_API_URL", "http://mtproxy:9091")?,
            telemt_token: env.secret("TELEMT_API_TOKEN", "TELEMT_API_TOKEN_FILE")?,
            naive_socket: env.str("NAIVE_MANAGER_SOCKET", "/run/naive-manager/manager.sock")?,
            naive_token: env.secret("NAIVE_MANAGER_TOKEN", "NAIVE_MANAGER_TOKEN_FILE")?,
            naive_public_host: env.str("NAIVE_PUBLIC_HOST", "")?,
            mtproxy_public_host: env.str("MTPROXY_DOMAIN", "")?,
            naive_enabled: env.flag("NAIVE_ENABLED", "false")?,
            mieru_socket: env.str("MIERU_MANAGER_SOCKET", "/run/mieru-manager/manager.sock")?,
            mieru_token: env.secret("MIERU_MANAGER_TOKEN", "MIERU_MANAGER_TOKEN_FILE")?,
            mieru_enabled: env.flag("MIERU_ENABLED", "false")?,
            amneziawg_socket: env.str("AWG_MANAGER_SOCKET", "/run/awg-manager/manager.sock")?,
            amneziawg_token: env.secret("AWG_MANAGER_TOKEN", "AWG_MANAGER_TOKEN_FILE")?,
            amneziawg_enabled: env.flag("AMNEZIAWG_ENABLED", "false")?,
            amneziawg_public_host: env.str("AMNEZIAWG_PUBLIC_HOST", "")?,
            trusttunnel_socket: env.str("TRUSTTUNNEL_MANAGER_SOCKET", "/run/trusttunnel-manager/manager.sock")?,
            trusttunnel_token: env.secret("TRUSTTUNNEL_MANAGER_TOKEN", "TRUSTTUNNEL_MANAGER_TOKEN_FILE")?,
            trusttunnel_enabled: env.flag("TRUSTTUNNEL_ENABLED", "false")?,
            trusttunnel_public_host: env.str("TRUSTTUNNEL_PUBLIC_HOST", "")?,
            xray_router_enabled: env.flag("XRAY_ROUTER_ENABLED", "false")?,
            xray_router_socket: env.str("XRAY_ROUTER_MANAGER_SOCKET", "/run/xray-router/manager.sock")?,
            xray_router_token: env.secret("XRAY_ROUTER_MANAGER_TOKEN", "XRAY_ROUTER_MANAGER_TOKEN_FILE")?,
            subscription_url,
            subscription_host,
            singbox_fork_clients: env.str("PANEL_SINGBOX_FORK_CLIENTS", "")?,
            version_agent_socket: env.str("VERSION_AGENT_SOCKET", "/run/proxy-control/version-agent.sock")?,
            panel_version_file: py_path(&env.str("PANEL_VERSION_FILE", DEFAULT_VERSION_FILE)?),
            master_key_file: env
                .get("PANEL_MASTER_KEY_FILE")?
                .filter(|path| !path.is_empty())
                .map(|path| py_path(&path)),
            session_cookie_secure: env.flag("PANEL_COOKIE_SECURE", "true")?,
            allowed_hosts: env
                .str("PANEL_ALLOWED_HOSTS", "localhost,127.0.0.1")?
                .split(',')
                .filter(|host| !host.is_empty())
                .map(str::to_string)
                .collect(),
            session_ttl_seconds: 12 * 3600,
            login_attempts: 5,
            login_window_seconds: 300,
            reveal_ttl_seconds: 120,
            body_limit_bytes: 65536,
            login_verify_concurrency: 2,
            api_key_rate_per_minute: 120,
            fleet_heartbeat_seconds: env.int("PANEL_FLEET_HEARTBEAT_SECONDS", "15")?,
            metrics_enabled: !matches!(
                pytext::lower(pytext::strip(&env.str("PANEL_METRICS_ENABLED", "true")?)).as_str(),
                "0" | "false" | "no" | "off"
            ),
            metrics_interval_seconds,
            metrics_ring_points: env.int("PANEL_METRICS_RING_POINTS", "900")?,
        })
    }

    /// The checks `create_app` makes before it builds anything (`PANEL_VNEXT_WRITER` aside).
    pub fn validate(&self) -> Result<(), SettingsError> {
        let invalid = |variable, message: &str| Err(SettingsError::Invalid { variable, message: message.to_string() });
        if self.naive_enabled && pytext::strip(&self.naive_public_host).is_empty() {
            return invalid("NAIVE_PUBLIC_HOST", "NAIVE_PUBLIC_HOST is required when NaiveProxy is enabled");
        }
        if self.login_verify_concurrency < 1 {
            return invalid("login_verify_concurrency", "login_verify_concurrency must be positive");
        }
        if self.fleet_heartbeat_seconds < 1 {
            return invalid("PANEL_FLEET_HEARTBEAT_SECONDS", "PANEL_FLEET_HEARTBEAT_SECONDS must be positive");
        }
        Ok(())
    }

    /// `mtproxy_host`: the MTProxy endpoint for a link not learned from Telemt — `MTPROXY_DOMAIN`,
    /// else the first allowed host, else `""`.
    pub fn mtproxy_host(&self) -> &str {
        if !self.mtproxy_public_host.is_empty() {
            return &self.mtproxy_public_host;
        }
        self.allowed_hosts.first().map_or("", String::as_str)
    }

    /// The sampler's interval: `max(0.5, metrics_interval_seconds)` (`panel/metrics/__init__.py`;
    /// a NaN gives 0.5, like Python's `max`).
    pub fn metrics_interval(&self) -> f64 {
        if self.metrics_interval_seconds > 0.5 {
            self.metrics_interval_seconds
        } else {
            0.5
        }
    }

    /// The Telemt egress journal next to the database (`<db dir>/telemt-egress.json`).
    pub fn telemt_egress_journal(&self) -> PathBuf {
        self.database_path
            .parent()
            .map_or_else(|| PathBuf::from("telemt-egress.json"), |dir| dir.join("telemt-egress.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_normalise_like_pathlib() {
        assert_eq!(py_path(""), PathBuf::from("."));
        assert_eq!(py_path("/data//x/./panel.sqlite3/"), PathBuf::from("/data/x/panel.sqlite3"));
        assert_eq!(py_path("./db"), PathBuf::from("db"));
        assert_eq!(py_path("//host/x"), PathBuf::from("//host/x"));
        assert_eq!(py_path("///x"), PathBuf::from("/x"));
        assert_eq!(py_path("/"), PathBuf::from("/"));
    }

    #[test]
    fn debug_hides_tokens() {
        let settings =
            Settings::from_lookup(|name| Ok((name == "TELEMT_API_TOKEN").then(|| "secret".to_string()))).unwrap();
        let shown = format!("{settings:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("<redacted>"));
    }
}
