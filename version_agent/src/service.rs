//! `VersionAgent` (`version_agent/service.py`): the state file and its lock, the versions
//! listing, the upstream check and its cache, the generic part of an update, the managers'
//! `pending_rebuild` list, and the agent's configuration from the environment.
//!
//! What an update *does* per component (downloads, builds, restarts, rollbacks, the panel's
//! self-update and the manager rebuild) is behind [`Updater`], implemented by host WP7; the
//! default [`NotPorted`] refuses with the Python error shape.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::catalog::{entry_from_value, load_catalog, CatalogEntry};
use crate::errors::{AgentError, CatalogError, UpdateError};
use crate::runner::{Command, CommandError, CommandRunner, SystemRunner};
use crate::upstream::{compare_versions, Fetcher, HttpsFetcher};
use crate::{hostmetrics, py};

/// The Compose project (stack) since 3.0.
pub const COMPOSE_PROJECT: &str = "proxy_panel_by_dubr1k";
/// The project of a host not migrated yet (`scripts/migrate-compose-project.sh`).
pub const LEGACY_COMPOSE_PROJECT: &str = "mtproxy";
pub const ALL_COMPONENTS: [&str; 5] = ["telemt", "naive", "mita", "xray", "panel"];
pub const BASE_COMPONENTS: [&str; 4] = ["telemt", "naive", "mita", "panel"];
/// component → (Compose service, container, overlay that installs it, image env with the version).
pub const MANAGER_BUILDS: [(&str, &str, &str, &str, &str); 2] = [
    ("amneziawg", "awg-manager", "proxy-control-awg-manager", "compose.amneziawg.yaml", "AWG_GO_VERSION"),
    (
        "trusttunnel",
        "trusttunnel-manager",
        "proxy-control-trusttunnel-manager",
        "compose.trusttunnel.yaml",
        "TT_VERSION",
    ),
];
/// Images the agent does not rebuild with the panel: a change is reported as `pending_rebuild`.
pub const PANEL_MANAGERS: [&str; 7] = [
    "mieru_manager",
    "naive_manager",
    "xray_router_manager",
    "awg_manager",
    "trusttunnel_manager",
    "mcp_server",
    "docker",
];
/// Optional Compose service → the overlay that defines it.
pub const OPTIONAL_COMPOSE_SERVICES: [(&str, &str); 9] = [
    ("mcp", "compose.mcp.yaml"),
    ("naive-manager", "compose.naive.yaml"),
    ("mieru-manager", "compose.mieru.yaml"),
    ("xray-router", "compose.xray-router.yaml"),
    ("xray-router-ingress", "compose.xray-router.yaml"),
    ("awg-manager", "compose.amneziawg.yaml"),
    ("trusttunnel-manager", "compose.trusttunnel.yaml"),
    ("fleet-agent", "compose.agent.yaml"),
    ("fleet-ingress", "compose.fleet-central.yaml"),
];
/// Manager → the Compose services built from its sources (`docker` has none).
pub const MANAGER_SERVICES: [(&str, &[&str]); 6] = [
    ("mieru_manager", &["mieru-manager"]),
    ("naive_manager", &["naive-manager"]),
    ("xray_router_manager", &["xray-router", "xray-router-ingress"]),
    ("awg_manager", &["awg-manager"]),
    ("trusttunnel_manager", &["trusttunnel-manager"]),
    ("mcp_server", &["mcp"]),
];
/// A container whose image was built this many seconds before the panel update still counts
/// as rebuilt.
pub const REBUILT_SLACK: i64 = 10;
pub const REBUILD_STALE_AFTER: f64 = 1800.0;
/// `UPSTREAM_MIN_INTERVAL`: a check within this many seconds of the last one answers the cache.
pub const UPSTREAM_MIN_INTERVAL: i64 = 60;
pub const INTERRUPTED_PANEL_UPDATE: &str =
    "panel update was interrupted: the version-agent stopped while it ran; check the panel and update again";
pub const INTERRUPTED_REBUILD: &str = "manager rebuild was interrupted: the version-agent stopped while it ran";

/// `MANAGER_BUILDS[component]`.
pub fn manager_build(component: &str) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    MANAGER_BUILDS.iter().find(|entry| entry.0 == component).map(|e| (e.1, e.2, e.3, e.4))
}

fn optional_overlay(service: &str) -> Option<&'static str> {
    OPTIONAL_COMPOSE_SERVICES.iter().find(|(name, _)| *name == service).map(|(_, overlay)| *overlay)
}

fn manager_services(manager: &str) -> Option<&'static [&'static str]> {
    MANAGER_SERVICES.iter().find(|(name, _)| *name == manager).map(|(_, services)| *services)
}

/// The agent's settings (`VersionAgent.__init__`, `agent_from_env`).
#[derive(Debug, Clone, PartialEq)]
pub struct AgentConfig {
    pub catalog_path: PathBuf,
    pub state_path: PathBuf,
    pub compose_dir: Option<PathBuf>,
    pub compose_files: Vec<String>,
    pub binary_paths: BTreeMap<String, PathBuf>,
    pub service_names: BTreeMap<String, String>,
    pub checkers: BTreeMap<String, PathBuf>,
    pub caddyfiles: BTreeMap<String, PathBuf>,
    pub version_pins: BTreeMap<String, PathBuf>,
    /// component → (env overlay, key that pins the host binary by digest, Compose service).
    pub consumer_overlays: BTreeMap<String, (PathBuf, String, String)>,
    pub telemt_container: String,
    pub health_timeout: f64,
    pub upstream_enabled: bool,
    pub router_enabled: bool,
    pub xray_bin_dir: PathBuf,
    pub xray_overlay: PathBuf,
    pub xray_container: String,
    pub caddy_build_dir: PathBuf,
    pub caddy_image: String,
    pub agent_dir: PathBuf,
    /// `None`: named after the Compose project (`<project>-panel`).
    pub panel_image: Option<String>,
    pub panel_container: String,
    /// `None`: `<project>_panel-data`.
    pub panel_volume: Option<String>,
    /// Tests run the panel update inline.
    pub synchronous: bool,
    pub installer_root: Option<PathBuf>,
    pub auto_rebuild_managers: bool,
    pub manager_health_timeout: f64,
}

impl AgentConfig {
    /// `VersionAgent(catalog_path=…, state_path=…)` with every other argument at its default.
    pub fn new(catalog_path: impl Into<PathBuf>, state_path: impl Into<PathBuf>) -> AgentConfig {
        AgentConfig {
            catalog_path: catalog_path.into(),
            state_path: state_path.into(),
            compose_dir: None,
            compose_files: Vec::new(),
            binary_paths: BTreeMap::new(),
            service_names: BTreeMap::new(),
            checkers: BTreeMap::new(),
            caddyfiles: BTreeMap::new(),
            version_pins: BTreeMap::new(),
            consumer_overlays: BTreeMap::new(),
            telemt_container: "proxy-control-mtproxy".into(),
            health_timeout: 60.0,
            upstream_enabled: true,
            router_enabled: false,
            xray_bin_dir: "/usr/local/lib/proxy-control/xray-router".into(),
            xray_overlay: "/opt/mtproxy-shared443/.env.xray-router".into(),
            xray_container: "proxy-control-xray-router".into(),
            caddy_build_dir: "/var/lib/proxy-control/version-agent/caddy-build".into(),
            caddy_image: "proxy-control/caddy-naive:agent".into(),
            agent_dir: "/opt/proxy-control".into(),
            panel_image: None,
            panel_container: "proxy-control-panel".into(),
            panel_volume: None,
            synchronous: false,
            installer_root: None,
            auto_rebuild_managers: true,
            manager_health_timeout: 180.0,
        }
    }

    /// `agent_from_env()` over a variable lookup. Errors are what Python raised at start-up.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<AgentConfig, String> {
        let var = |name: &str, default: &str| get(name).unwrap_or_else(|| default.to_string());
        let pairs = |name: &str, default: &str| -> Vec<(String, String)> {
            var(name, default)
                .split(',')
                .filter_map(|part| part.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                .collect()
        };
        let paths = |name: &str, default: &str| -> BTreeMap<String, PathBuf> {
            pairs(name, default).into_iter().map(|(k, v)| (k, PathBuf::from(v))).collect()
        };
        let state_path =
            PathBuf::from(var("PROXY_CONTROL_VERSION_STATE", "/var/lib/proxy-control/version-agent/state.json"));
        let health = var("PROXY_CONTROL_VERSION_HEALTH_TIMEOUT", "60");
        let health_timeout = py::strip(&health)
            .parse::<f64>()
            .map_err(|_| format!("could not convert string to float: {}", pc_host::pytext::py_repr(&health)))?;
        let mut config =
            AgentConfig::new(var("PROXY_CONTROL_VERSION_CATALOG", "/etc/proxy-control/versions.json"), state_path);
        config.compose_dir = Some(var("PROXY_CONTROL_COMPOSE_DIR", "/opt/mtproxy-shared443").into());
        config.compose_files = var("PROXY_CONTROL_COMPOSE_FILES", "compose.yaml")
            .split(':')
            .filter(|f| !f.is_empty())
            .map(String::from)
            .collect();
        config.binary_paths = paths("PROXY_CONTROL_BINARY_PATHS", "naive=/usr/local/bin/caddy,mita=/usr/bin/mita");
        config.service_names =
            pairs("PROXY_CONTROL_SERVICE_NAMES", "naive=caddy-naive,mita=mita").into_iter().collect();
        config.checkers = paths("PROXY_CONTROL_CHECKERS", "naive=/usr/local/libexec/check-naive-caddy-build");
        config.caddyfiles = paths("PROXY_CONTROL_CADDYFILES", "naive=/var/lib/naive-manager/Caddyfile");
        config.version_pins = paths("PROXY_CONTROL_VERSION_PINS", "naive=/etc/proxy-control/caddy-naive.pin");
        config.consumer_overlays = consumer_overlays(&var(
            "PROXY_CONTROL_CONSUMER_OVERLAYS",
            "mita=/opt/mtproxy-shared443/.env.mieru:MIERU_MITA_SHA256:mieru-manager",
        ))?;
        config.telemt_container = var("PROXY_CONTROL_TELEMT_CONTAINER", "proxy-control-mtproxy");
        config.health_timeout = health_timeout;
        config.upstream_enabled = py::strip(&var("PROXY_CONTROL_UPSTREAM_CHECK", "on")).to_lowercase() != "off";
        config.router_enabled = matches!(
            py::strip(&var("PROXY_CONTROL_XRAY_ROUTER", "off")).to_lowercase().as_str(),
            "on" | "1" | "true" | "yes"
        );
        config.xray_bin_dir = var("PROXY_CONTROL_XRAY_BIN_DIR", "/usr/local/lib/proxy-control/xray-router").into();
        config.xray_overlay = var("PROXY_CONTROL_XRAY_OVERLAY", "/opt/mtproxy-shared443/.env.xray-router").into();
        config.xray_container = var("PROXY_CONTROL_XRAY_CONTAINER", "proxy-control-xray-router");
        config.caddy_build_dir =
            var("PROXY_CONTROL_CADDY_BUILD_DIR", "/var/lib/proxy-control/version-agent/caddy-build").into();
        config.agent_dir = var("PROXY_CONTROL_AGENT_DIR", "/opt/proxy-control").into();
        config.panel_image = get("PROXY_CONTROL_PANEL_IMAGE").filter(|v| !v.is_empty());
        config.panel_container = var("PROXY_CONTROL_PANEL_CONTAINER", "proxy-control-panel");
        config.panel_volume = get("PROXY_CONTROL_PANEL_VOLUME").filter(|v| !v.is_empty());
        config.auto_rebuild_managers = py::strip(&var("VERSION_AGENT_AUTO_REBUILD_MANAGERS", "1")) != "0";
        Ok(config)
    }
}

/// `_consumer_overlays`: `component=<overlay path>:<env key>:<compose service>[,…]`.
pub fn consumer_overlays(value: &str) -> Result<BTreeMap<String, (PathBuf, String, String)>, String> {
    let mut result = BTreeMap::new();
    for part in value.split(',') {
        let Some((component, spec)) = part.split_once('=') else { continue };
        let pieces: Vec<&str> = spec.rsplitn(3, ':').collect();
        if pieces.len() != 3 || pieces.iter().any(|p| p.is_empty()) {
            return Err(format!("invalid consumer overlay for {component}: expected path:key:service"));
        }
        result.insert(
            py::strip(component).to_string(),
            (PathBuf::from(pieces[2]), pieces[1].to_string(), pieces[0].to_string()),
        );
    }
    Ok(result)
}

/// What an applied non-panel update leaves behind (the state record's variable fields).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Applied {
    /// `installed_sha256`: the catalog's digest, or the installed binary's for a host build.
    pub sha256: Option<String>,
    pub runtime_version: Option<String>,
    /// Xray: member name → SHA-256.
    pub members: Option<Map<String, Value>>,
}

impl Applied {
    /// The defaults `update()` starts from: the entry's digest and runtime version.
    pub fn from_entry(entry: &CatalogEntry) -> Applied {
        Applied { sha256: entry.sha256.clone(), runtime_version: entry.runtime_version.clone(), members: None }
    }
}

/// The per-component work of an update (host WP7).
pub trait Updater: Send + Sync {
    /// `_update_telemt` / `_update_manager` / `_update_xray` / `_build_caddy` + `_update_binary`,
    /// called with the agent lock held. A `RollbackFailedError` is recorded as `rollback_failed`
    /// by the caller.
    fn apply(
        &self,
        agent: &Arc<VersionAgent>,
        component: &str,
        entry: &CatalogEntry,
        current: Option<&str>,
    ) -> Result<Applied, UpdateError>;

    /// `_update_panel_async`: validate, write the `updating` marker, start the worker.
    fn update_panel(
        &self,
        agent: &Arc<VersionAgent>,
        version: &str,
        expected: Option<&str>,
    ) -> Result<Value, AgentError>;

    /// `rebuild_managers(background=True)`.
    fn rebuild_managers(&self, agent: &Arc<VersionAgent>) -> Result<Value, AgentError>;
}

/// The stand-in until host WP7: every update is refused as `update_failed`; a rebuild with
/// nothing to rebuild answers the managers' state, as Python does.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotPorted;

pub const NOT_PORTED: &str = "updates are not available in this build of the version-agent";

impl Updater for NotPorted {
    fn apply(&self, _: &Arc<VersionAgent>, _: &str, _: &CatalogEntry, _: Option<&str>) -> Result<Applied, UpdateError> {
        Err(UpdateError::new(NOT_PORTED))
    }

    fn update_panel(&self, _: &Arc<VersionAgent>, _: &str, _: Option<&str>) -> Result<Value, AgentError> {
        Err(AgentError::update(NOT_PORTED))
    }

    fn rebuild_managers(&self, agent: &Arc<VersionAgent>) -> Result<Value, AgentError> {
        let services = {
            let _lock = agent.lock()?;
            let state = agent.load_state()?;
            agent.rebuild_preflight(&state)?
        };
        if services.is_empty() {
            return agent.managers_state();
        }
        Err(AgentError::update(format!("manager rebuild failed: {NOT_PORTED}")))
    }
}

/// The agent lock (`state.json.lock`, `flock(LOCK_EX)`): held while the guard lives.
pub struct AgentLock {
    _file: File,
}

fn internal(err: impl std::fmt::Display) -> AgentError {
    AgentError::Internal(err.to_string())
}

type Checker = dyn Fn(&BTreeMap<String, Option<String>>, &dyn Fetcher, bool) -> Map<String, Value> + Send + Sync;
type Clock = dyn Fn() -> f64 + Send + Sync;

/// `VersionAgent`.
pub struct VersionAgent {
    pub config: AgentConfig,
    pub runner: Arc<dyn CommandRunner>,
    pub fetcher: Arc<dyn Fetcher>,
    /// `upstream.check_all` (tests replace it).
    pub checker: Box<Checker>,
    /// `self.clock`: the upstream check's time.
    pub clock: Box<Clock>,
    /// `time.time()`: every other timestamp.
    pub now: Box<Clock>,
    pub updater: Arc<dyn Updater>,
}

impl VersionAgent {
    pub fn new(mut config: AgentConfig) -> VersionAgent {
        // The names an older installer wrote into the environment mean "after the project".
        if config.panel_image.as_deref() == Some(&format!("{LEGACY_COMPOSE_PROJECT}-panel")) {
            config.panel_image = None;
        }
        if config.panel_volume.as_deref() == Some(&format!("{LEGACY_COMPOSE_PROJECT}_panel-data")) {
            config.panel_volume = None;
        }
        VersionAgent {
            config,
            runner: Arc::new(SystemRunner),
            fetcher: Arc::new(HttpsFetcher::new()),
            checker: Box::new(crate::upstream::check_all),
            clock: Box::new(hostmetrics::wall_clock),
            now: Box::new(hostmetrics::wall_clock),
            updater: Arc::new(NotPorted),
        }
    }

    fn now_int(&self) -> i64 {
        (self.now)().floor() as i64
    }

    /// `state.json.lock` next to the state.
    pub fn lock_path(&self) -> PathBuf {
        let mut name = self.config.state_path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        self.config.state_path.with_file_name(name)
    }

    /// `_locked()`: a new open file description each time, so threads serialise too.
    pub fn lock(&self) -> Result<AgentLock, AgentError> {
        let path = self.lock_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(internal)?;
        }
        let file = OpenOptions::new().read(true).append(true).create(true).mode(0o666).open(&path).map_err(internal)?;
        loop {
            // SAFETY: a valid descriptor owned by `file`.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(AgentLock { _file: file });
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(internal(err));
            }
        }
    }

    /// `_load_state`.
    pub fn load_state(&self) -> Result<Map<String, Value>, UpdateError> {
        load_state(&self.config.state_path)
    }

    /// `_save_state`: `schema` 2, indent 2, sorted, ASCII, no trailing newline, mode 0600.
    pub fn save_state(&self, state: &mut Map<String, Value>) -> std::io::Result<()> {
        state.insert("schema".into(), json!(2));
        pc_host::fs::atomic_write(
            &self.config.state_path,
            pc_host::json::pretty2_ascii_nonl(&Value::Object(state.clone())).as_bytes(),
            0o600,
            None,
        )
    }

    // --- listing and the upstream check ------------------------------------------------------

    /// `_components()`.
    pub fn components(&self) -> Vec<&'static str> {
        let mut components: Vec<&'static str> =
            if self.config.router_enabled { ALL_COMPONENTS.to_vec() } else { BASE_COMPONENTS.to_vec() };
        for (component, _, _, overlay, _) in MANAGER_BUILDS {
            if self.config.compose_files.iter().any(|f| f == overlay) {
                components.push(component);
            }
        }
        components
    }

    fn run_text(&self, argv: &[&str], timeout: u64) -> Result<String, CommandError> {
        self.runner.run(&Command::new(argv).timeout(timeout))
    }

    /// `project()`: the Compose project the panel runs in, read on every call (the migration
    /// happens while the agent runs).
    pub fn project(&self) -> String {
        let label = self
            .run_text(
                &[
                    "docker",
                    "inspect",
                    "--format",
                    "{{index .Config.Labels \"com.docker.compose.project\"}}",
                    &self.config.panel_container,
                ],
                30,
            )
            .map(|text| py::strip(&text).to_string())
            .unwrap_or_default();
        if !label.is_empty() {
            return if label == LEGACY_COMPOSE_PROJECT { LEGACY_COMPOSE_PROJECT } else { COMPOSE_PROJECT }.to_string();
        }
        let filter = format!("label=com.docker.compose.project={LEGACY_COMPOSE_PROJECT}");
        let legacy = self
            .run_text(&["docker", "ps", "-a", "-q", "--filter", &filter], 30)
            .map(|text| py::strip(&text).to_string())
            .unwrap_or_default();
        if legacy.is_empty() { COMPOSE_PROJECT } else { LEGACY_COMPOSE_PROJECT }.to_string()
    }

    pub fn panel_image(&self) -> String {
        self.config.panel_image.clone().unwrap_or_else(|| format!("{}-panel", self.project()))
    }

    pub fn panel_volume(&self) -> String {
        self.config.panel_volume.clone().unwrap_or_else(|| format!("{}_panel-data", self.project()))
    }

    /// `_manager_version`: the version the manager's running image was built with.
    pub fn manager_version(&self, component: &str) -> Option<String> {
        let (_, container, _, key) = manager_build(component)?;
        let env = self
            .run_text(&["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container], 30)
            .ok()?;
        for line in py::splitlines(&env) {
            let (name, value) = py::strip(line).split_once('=').unwrap_or((py::strip(line), ""));
            if name == key && !value.is_empty() {
                return Some(value.strip_prefix('v').unwrap_or(value).to_string());
            }
        }
        None
    }

    /// `_component_state`.
    pub fn component_state(state: &Map<String, Value>, component: &str) -> Map<String, Value> {
        state.get("components").and_then(|c| c.get(component)).and_then(Value::as_object).cloned().unwrap_or_default()
    }

    /// `_panel_container_version`: `docker exec <panel> cat /app/VERSION`.
    pub fn panel_container_version(&self) -> Result<String, CommandError> {
        self.run_text(&["docker", "exec", &self.config.panel_container, "cat", "/app/VERSION"], 30)
            .map(|text| py::strip(&text).to_string())
    }

    /// `_panel_current`: the running container's version, else the project's `VERSION`, else
    /// the state.
    pub fn panel_current(&self, data: &Map<String, Value>) -> Option<String> {
        if let Some(compose_dir) = &self.config.compose_dir {
            let running = self.panel_container_version().unwrap_or_default();
            if !running.is_empty() {
                return Some(running);
            }
            let file = std::fs::read(compose_dir.join("VERSION"))
                .ok()
                .and_then(|data| String::from_utf8(data).ok())
                .map(|text| py::strip(&text).to_string())
                .unwrap_or_default();
            if !file.is_empty() {
                return Some(file);
            }
        }
        data.get("version").and_then(Value::as_str).map(String::from)
    }

    /// `_current_versions`: what each component runs, for the upstream check.
    pub fn current_versions(&self, state: &Map<String, Value>) -> BTreeMap<String, Option<String>> {
        let mut result = BTreeMap::new();
        for component in self.components() {
            let data = Self::component_state(state, component);
            let mut current = data.get("version").and_then(Value::as_str).map(String::from);
            if component == "panel" {
                current = self.panel_current(&data);
            } else if manager_build(component).is_some() {
                current = self.manager_version(component).or(current);
            }
            result.insert(component.to_string(), current);
        }
        result
    }

    fn cached_probe(&self, state: &Map<String, Value>, component: &str) -> Map<String, Value> {
        state
            .get("upstream")
            .and_then(|u| u.get("components"))
            .and_then(|c| c.get(component))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    }

    /// `list_versions(heal=…)`: the catalog entries and the cached upstream candidates per
    /// component, each marked `newer` than what runs. May heal `pending_rebuild` (and write).
    pub fn list_versions(&self, heal: bool) -> Result<Value, AgentError> {
        let catalog = load_catalog(&self.config.catalog_path)?;
        let state = self.load_state()?;
        let checked_at = state.get("upstream").and_then(|u| u.get("checked_at")).cloned().unwrap_or(Value::Null);
        let upstream_enabled = self.config.upstream_enabled;
        let mut components = Map::new();
        for component in self.components() {
            let mut current = Self::component_state(&state, component);
            let mut entries: Vec<Map<String, Value>> =
                catalog.entries(component).iter().map(CatalogEntry::public).collect();
            let mut seen: Vec<String> =
                entries.iter().filter_map(|e| e["version"].as_str().map(String::from)).collect();
            let probe = if upstream_enabled { self.cached_probe(&state, component) } else { Map::new() };
            if let Some(Value::Array(candidates)) = probe.get("candidates") {
                for candidate in candidates {
                    let Some(candidate) = candidate.as_object() else { continue };
                    let Some(version) = candidate.get("version").and_then(Value::as_str) else { continue };
                    if !seen.iter().any(|known| known == version) {
                        seen.push(version.to_string());
                        entries.push(candidate.clone());
                    }
                }
            }
            let state_version = current.get("version").cloned().unwrap_or(Value::Null);
            let installed: Value = if component == "panel" {
                self.panel_current(&current).map(Value::String).unwrap_or(Value::Null)
            } else if manager_build(component).is_some() {
                self.manager_version(component).map(Value::String).unwrap_or(state_version.clone())
            } else {
                state_version.clone()
            };
            for entry in &mut entries {
                let version = entry["version"].as_str().unwrap_or_default().to_string();
                // The Versions screen splits the list into updates and roll-backs.
                let newer = match installed.as_str() {
                    Some(installed) => compare_versions(&version, installed) > 0,
                    None => true,
                };
                entry.insert("newer".into(), Value::Bool(newer));
            }
            let field = |key: &str| probe.get(key).cloned().unwrap_or(Value::Null);
            let mut listed = json!({
                "current": if manager_build(component).is_some() || component == "panel" { installed.clone() } else { state_version },
                "status": current.get("status").cloned().unwrap_or_else(|| json!("ready")),
                "available": entries,
                "upstream": {
                    "checked_at": if upstream_enabled { checked_at.clone() } else { Value::Null },
                    "latest": field("latest"),
                    "installable": probe.get("installable").is_some_and(py::truthy),
                    "reason": field("reason"),
                    "last_error": field("last_error"),
                },
            });
            if component == "panel" {
                if heal && current.get("pending_rebuild").is_some_and(py::truthy) {
                    current = self.heal_pending(current);
                }
                for key in ["last_error", "pending_rebuild", "previous_version", "rebuild_error", "managers_rebuilt_at"]
                {
                    if let Some(value) = current.get(key) {
                        listed[key] = value.clone();
                    }
                }
                if self.rebuilding(&current) {
                    listed["rebuilding_managers"] = Value::Bool(true);
                }
            }
            components.insert(component.to_string(), listed);
        }
        Ok(json!({
            "enabled": true,
            "upstream_enabled": upstream_enabled,
            "checked_at": if upstream_enabled { checked_at } else { Value::Null },
            "components": components,
        }))
    }

    /// `upstream_checked_at()`: when the cache was filled, for the automatic check.
    pub fn upstream_checked_at(&self) -> Result<Option<i64>, AgentError> {
        let state = self.load_state()?;
        Ok(state.get("upstream").and_then(|u| u.get("checked_at")).and_then(py::as_int))
    }

    /// `check_upstream(force=…)`: probe every source (at most once a minute unless forced),
    /// keep a failed source's previous candidates beside its error, cache, and list.
    pub fn check_upstream(&self, force: bool) -> Result<Value, AgentError> {
        if !self.config.upstream_enabled {
            return Err(AgentError::update("upstream check is disabled on this host"));
        }
        {
            let _lock = self.lock()?;
            let mut state = self.load_state()?;
            let cached = state.get("upstream").and_then(Value::as_object).cloned().unwrap_or_default();
            let now = (self.clock)().floor() as i64;
            let last = cached.get("checked_at").and_then(py::as_int);
            if !force && last.is_some_and(|last| (0..UPSTREAM_MIN_INTERVAL).contains(&(now - last))) {
                return self.list_versions(false);
            }
            let mut probes =
                (self.checker)(&self.current_versions(&state), self.fetcher.as_ref(), self.config.router_enabled);
            let previous = cached.get("components").and_then(Value::as_object).cloned().unwrap_or_default();
            for (component, probe) in probes.iter_mut() {
                // A source that failed keeps its previous candidates; the error rides alongside.
                let error = probe.get("last_error").filter(|e| py::truthy(e)).cloned();
                if let (Some(error), Some(Value::Object(before))) = (error, previous.get(component)) {
                    let mut kept = before.clone();
                    kept.insert("last_error".into(), error);
                    *probe = Value::Object(kept);
                }
            }
            state.insert("upstream".into(), json!({"checked_at": now, "components": probes}));
            self.save_state(&mut state).map_err(internal)?;
        }
        self.list_versions(true)
    }

    /// `_resolve`: the catalog first, then the cached upstream candidates (which must be
    /// `source: upstream`).
    pub fn resolve(
        &self,
        component: &str,
        version: &str,
        state: &Map<String, Value>,
    ) -> Result<CatalogEntry, CatalogError> {
        let catalog = load_catalog(&self.config.catalog_path)?;
        if let Ok(entry) = catalog.entry(component, version) {
            return Ok(entry.clone());
        }
        if self.config.upstream_enabled {
            if let Some(Value::Array(candidates)) = self.cached_probe(state, component).get("candidates") {
                for candidate in candidates.iter().filter_map(Value::as_object) {
                    if candidate.get("version").and_then(Value::as_str) == Some(version) {
                        let raw: Map<String, Value> = candidate
                            .iter()
                            .filter(|(key, _)| key.as_str() != "tag" && key.as_str() != "published_at")
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        let entry = entry_from_value(component, &Value::Object(raw))?;
                        if entry.source != "upstream" {
                            return Err(CatalogError::new("cached upstream candidate is malformed"));
                        }
                        return Ok(entry);
                    }
                }
            }
        }
        Err(CatalogError(format!("version is not approved for {component}")))
    }

    // --- update ------------------------------------------------------------------------------

    /// `update(component, version, expected_current)`.
    pub fn update(
        self: &Arc<Self>,
        component: &str,
        version: &str,
        expected: Option<&str>,
    ) -> Result<Value, AgentError> {
        if !self.components().contains(&component) {
            return Err(CatalogError::new("unsupported component").into());
        }
        if component == "panel" {
            return self.updater.update_panel(self, version, expected);
        }
        let _lock = self.lock()?;
        let mut state = self.load_state()?;
        let entry = self.resolve(component, version, &state)?;
        let current_data = Self::component_state(&state, component);
        if !state.contains_key("components") {
            state.insert("components".into(), json!({}));
        }
        let mut current = current_data.get("version").cloned().unwrap_or(Value::Null);
        if manager_build(component).is_some() {
            if let Some(running) = self.manager_version(component) {
                current = Value::String(running);
            }
        }
        if current_data.get("status").and_then(Value::as_str) == Some("rollback_failed") {
            return Err(UpdateError::rollback_failed(format!(
                "{component} has an unverified rollback; operator recovery is required"
            ))
            .into());
        }
        if let Some(expected) = expected {
            if current.as_str() != Some(expected) {
                return Err(AgentError::conflict("runtime version changed; reload the versions page"));
            }
        }
        if current.as_str() == Some(version) {
            return Ok(json!({"component": component, "version": version, "changed": false}));
        }
        let applied = match self.updater.apply(self, component, &entry, current.as_str()) {
            Ok(applied) => applied,
            Err(error) if error.state == crate::errors::UpdateState::RollbackFailed => {
                let mut failed = current_data.clone();
                failed.insert("status".into(), json!("rollback_failed"));
                failed.insert("failed_at".into(), json!(self.now_int()));
                state["components"][component] = Value::Object(failed);
                if let Err(save) = self.save_state(&mut state) {
                    return Err(UpdateError::rollback_failed(format!(
                        "{component} rollback failed and the failure state could not be persisted"
                    ))
                    .caused_by(crate::errors::Cause {
                        class: crate::runner::os_class(&save).into(),
                        message: save.to_string(),
                        stderr: None,
                    })
                    .caused_by_update(&error)
                    .into());
                }
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        let mut record = json!({
            "version": version,
            "kind": entry.kind,
            "source": entry.source,
            "image": entry.image,
            "url": entry.url,
            "sha256": applied.sha256,
            "archive": entry.archive,
            "runtime_version": applied.runtime_version,
            "updated_at": self.now_int(),
        });
        if let Some(base) = entry.base_image.as_ref().filter(|b| !b.is_empty()) {
            record["base_image"] = json!(base);
        }
        if let Some(members) = applied.members {
            record["members"] = Value::Object(members);
        }
        if let Some(build) = &entry.build {
            record["build"] = Value::Object(build.clone());
        }
        state["components"][component] = record;
        self.save_state(&mut state).map_err(internal)?;
        Ok(json!({"component": component, "version": version, "changed": true}))
    }

    // --- managers the panel update does not rebuild (`pending_rebuild`) -----------------------

    /// `_services_of`: the Compose services of one manager that exist on this host.
    pub fn services_of(&self, manager: &str) -> Vec<String> {
        let mut found = Vec::new();
        for service in manager_services(manager).unwrap_or(&[]) {
            let Some(overlay) = optional_overlay(service) else { continue };
            if !self.config.compose_files.iter().any(|f| f == overlay) {
                continue;
            }
            if *service == "xray-router-ingress" {
                let Some(dir) = &self.config.compose_dir else { continue };
                let Some(text) = std::fs::read(dir.join(overlay)).ok().and_then(|d| String::from_utf8(d).ok()) else {
                    continue;
                };
                if !text.split('\n').any(|line| line.starts_with("  xray-router-ingress:")) {
                    continue;
                }
            }
            found.push(service.to_string());
        }
        found
    }

    /// `_service_containers`: every container (running or not) of a Compose service.
    pub fn service_containers(&self, service: &str) -> Result<Vec<String>, CommandError> {
        let project = format!("label=com.docker.compose.project={}", self.project());
        let service = format!("label=com.docker.compose.service={service}");
        let listed = self.run_text(&["docker", "ps", "-a", "--filter", &project, "--filter", &service, "-q"], 30)?;
        Ok(py::splitlines(&listed).into_iter().map(py::strip).filter(|l| !l.is_empty()).map(String::from).collect())
    }

    /// `_service_rebuilt`: nothing runs for the service, or its containers' images were created
    /// at or after `since` (minus the slack).
    pub fn service_rebuilt(&self, service: &str, since: i64) -> Result<bool, String> {
        for container in self.service_containers(service).map_err(|e| e.to_string())? {
            let image = self
                .run_text(&["docker", "inspect", "--format", "{{.Image}}", &container], 30)
                .map_err(|e| e.to_string())?;
            let image = py::strip(&image);
            if !image.strip_prefix("sha256:").is_some_and(crate::catalog::is_sha256) {
                return Err("container image identity is unavailable".into());
            }
            let created = self
                .run_text(&["docker", "image", "inspect", "--format", "{{.Created}}", image], 30)
                .map_err(|e| e.to_string())?;
            if docker_epoch(&created)? < since - REBUILT_SLACK {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `_rebuilding`: a rebuild marked less than `REBUILD_STALE_AFTER` seconds ago.
    pub fn rebuilding(&self, panel: &Map<String, Value>) -> bool {
        match panel.get("rebuilding_managers") {
            Some(Value::Number(started)) if started.is_i64() || started.is_u64() => {
                let age = (self.now)() - started.as_f64().unwrap_or(0.0);
                (0.0..REBUILD_STALE_AFTER).contains(&age)
            }
            _ => false,
        }
    }

    /// `_heal_pending`: drop the managers that were rebuilt since the panel update (by
    /// `update-host.sh` or by hand). Any Docker error leaves the list as it is.
    pub fn heal_pending(&self, panel: Map<String, Value>) -> Map<String, Value> {
        let pending: Vec<Value> = match panel.get("pending_rebuild") {
            Some(Value::Array(items)) => items.clone(),
            _ => return panel,
        };
        let since = panel.get("updated_at").and_then(py::as_int);
        let ready = panel.get("status").is_none_or(|s| s == "ready");
        let Some(since) = since
            .filter(|_| !pending.is_empty() && self.config.compose_dir.is_some() && ready && !self.rebuilding(&panel))
        else {
            return panel;
        };
        let mut kept = Vec::new();
        for name in &pending {
            let rebuilt = match name.as_str().filter(|n| manager_services(n).is_some()) {
                Some(manager) => {
                    let mut all = true;
                    for service in self.services_of(manager) {
                        match self.service_rebuilt(&service, since) {
                            Ok(true) => {}
                            Ok(false) => {
                                all = false;
                                break;
                            }
                            Err(_) => return panel,
                        }
                    }
                    all
                }
                None => false,
            };
            if !rebuilt {
                kept.push(name.clone());
            }
        }
        if kept == pending {
            return panel;
        }
        if let Ok(_lock) = self.lock() {
            if let Ok(mut state) = self.load_state() {
                let mut stored = Self::component_state(&state, "panel");
                if stored.get("pending_rebuild") == Some(&Value::Array(pending.clone())) {
                    stored.insert("pending_rebuild".into(), Value::Array(kept.clone()));
                    if let Some(components) = state.get_mut("components").and_then(Value::as_object_mut) {
                        components.insert("panel".into(), Value::Object(stored));
                        let _ = self.save_state(&mut state);
                    }
                }
            }
        }
        let mut healed = panel;
        healed.insert("pending_rebuild".into(), Value::Array(kept));
        healed
    }

    /// `managers_state()`: `{"pending_rebuild", "rebuilding"[, "rebuild_error"][, "managers_rebuilt_at"]}`.
    pub fn managers_state(&self) -> Result<Value, AgentError> {
        let panel = Self::component_state(&self.load_state()?, "panel");
        let mut result = json!({"pending_rebuild": pending_list(panel.get("pending_rebuild")), "rebuilding": self.rebuilding(&panel)});
        for key in ["rebuild_error", "managers_rebuilt_at"] {
            if let Some(value) = panel.get(key) {
                result[key] = value.clone();
            }
        }
        Ok(result)
    }

    /// `ack_managers(names)`: `update-host.sh` (or an operator) reports managers it rebuilt.
    pub fn ack_managers(&self, names: &Value) -> Result<Value, AgentError> {
        let names: Vec<&str> = match names {
            Value::Array(items) if !items.is_empty() => {
                let names: Vec<&str> =
                    items.iter().filter_map(Value::as_str).filter(|n| PANEL_MANAGERS.contains(n)).collect();
                if names.len() != items.len() {
                    return Err(AgentError::Invalid("names must be a non-empty list of known managers".into()));
                }
                names
            }
            _ => return Err(AgentError::Invalid("names must be a non-empty list of known managers".into())),
        };
        {
            let _lock = self.lock()?;
            let mut state = self.load_state()?;
            let mut panel = Self::component_state(&state, "panel");
            if let Some(pending) = panel.get("pending_rebuild") {
                let left: Vec<Value> = match pending {
                    Value::Array(items) => {
                        items.iter().filter(|n| !n.as_str().is_some_and(|n| names.contains(&n))).cloned().collect()
                    }
                    _ => Vec::new(),
                };
                panel.insert("pending_rebuild".into(), Value::Array(left));
                let components = state.entry("components").or_insert_with(|| json!({}));
                if let Some(components) = components.as_object_mut() {
                    components.insert("panel".into(), Value::Object(panel));
                }
                self.save_state(&mut state).map_err(internal)?;
            }
        }
        self.managers_state()
    }

    /// The checks `rebuild_managers` makes under the lock before it marks a rebuild, and the
    /// services to rebuild (empty: nothing to do).
    pub fn rebuild_preflight(&self, state: &Map<String, Value>) -> Result<Vec<String>, AgentError> {
        let panel = Self::component_state(state, "panel");
        let status = panel.get("status").and_then(Value::as_str);
        if status == Some("updating") || self.rebuilding(&panel) {
            return Err(AgentError::conflict("panel update or manager rebuild is already running"));
        }
        if status == Some("rollback_failed") {
            return Err(UpdateError::rollback_failed(
                "panel has an unverified rollback; operator recovery is required",
            )
            .into());
        }
        let mut services: Vec<String> = Vec::new();
        for name in pending_list(panel.get("pending_rebuild")).iter().filter_map(Value::as_str) {
            for service in self.services_of(name) {
                if !services.contains(&service) {
                    services.push(service);
                }
            }
        }
        Ok(services)
    }

    /// `rebuild_managers(background=True)` from HTTP.
    pub fn rebuild_managers(self: &Arc<Self>) -> Result<Value, AgentError> {
        self.updater.rebuild_managers(self)
    }

    /// Start-up: no update or rebuild can still be running in a process that just started, so a
    /// panel `status: "updating"` marker becomes `update_failed` and a `rebuilding_managers`
    /// marker a `rebuild_error` (Python kept both forever: DIFFERENCES). Returns what changed.
    pub fn recover_interrupted(&self) -> Result<Vec<String>, AgentError> {
        let _lock = self.lock()?;
        let mut state = self.load_state()?;
        let mut panel = Self::component_state(&state, "panel");
        let mut changes = Vec::new();
        if panel.get("status").and_then(Value::as_str) == Some("updating") {
            panel = json!({
                "version": panel.get("version").cloned().unwrap_or(Value::Null),
                "kind": "release",
                "status": "update_failed",
                "last_error": INTERRUPTED_PANEL_UPDATE,
                "failed_at": self.now_int(),
            })
            .as_object()
            .cloned()
            .unwrap_or_default();
            changes.push("an interrupted panel update was marked update_failed".to_string());
        }
        if panel.remove("rebuilding_managers").is_some() {
            panel.insert("rebuild_error".into(), json!(INTERRUPTED_REBUILD));
            changes.push("an interrupted manager rebuild was recorded as rebuild_error".to_string());
        }
        if !changes.is_empty() {
            let components = state.entry("components").or_insert_with(|| json!({}));
            if let Some(components) = components.as_object_mut() {
                components.insert("panel".into(), Value::Object(panel));
            }
            self.save_state(&mut state).map_err(internal)?;
        }
        Ok(changes)
    }
}

/// `list(panel.get("pending_rebuild") or [])` for the shapes the state can hold.
fn pending_list(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items.clone(),
        Some(Value::String(text)) => text.chars().map(|c| Value::String(c.to_string())).collect(),
        Some(Value::Object(map)) => map.keys().map(|k| Value::String(k.clone())).collect(),
        _ => Vec::new(),
    }
}

/// `_load_state`: a missing file is an empty state; schema 1 or 2 with dict `components` and
/// `upstream`.
pub fn load_state(path: &Path) -> Result<Map<String, Value>, UpdateError> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"schema": 2, "components": {}}).as_object().cloned().unwrap_or_default());
        }
        Err(_) => return Err(UpdateError::new("version state is unreadable")),
    };
    let value = pc_host::json::loads(&data).map_err(|_| UpdateError::new("version state is unreadable"))?;
    let Value::Object(state) = value else {
        return Err(UpdateError::new("version state is invalid"));
    };
    let schema_ok = match state.get("schema") {
        None => true,
        Some(Value::Bool(_)) => state.get("schema") == Some(&json!(true)),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f == 1.0 || f == 2.0),
        Some(_) => false,
    };
    let is_dict = |key: &str| state.get(key).is_none_or(Value::is_object);
    if !schema_ok || !is_dict("components") || !is_dict("upstream") {
        return Err(UpdateError::new("version state is invalid"));
    }
    Ok(state)
}

/// `_docker_epoch`: Docker's `Created` (RFC 3339 with an optional fraction) as epoch seconds.
pub fn docker_epoch(value: &str) -> Result<i64, String> {
    let text = py::strip(value);
    let unreadable = || format!("unreadable image creation time {}", pc_host::pytext::py_repr(value));
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !text.is_ascii() {
        return Err(unreadable());
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = &text[range];
        py::is_digits(part).then(|| part.parse().unwrap_or(0))
    };
    let shape = bytes[4] == b'-' && bytes[7] == b'-' && bytes[10] == b'T' && bytes[13] == b':' && bytes[16] == b':';
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (digits(0..4), digits(5..7), digits(8..10), digits(11..13), digits(14..16), digits(17..19))
    else {
        return Err(unreadable());
    };
    if !shape {
        return Err(unreadable());
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let end = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if end == 0 {
            return Err(unreadable());
        }
        rest = &fraction[end..];
    }
    let offset = match rest {
        "Z" => 0,
        zone if zone.len() == 6 && matches!(zone.as_bytes()[0], b'+' | b'-') && zone.as_bytes()[3] == b':' => {
            let (Some(h), Some(m)) = (digits_of(&zone[1..3]), digits_of(&zone[4..6])) else { return Err(unreadable()) };
            let seconds = h * 3600 + m * 60;
            if zone.starts_with('+') {
                seconds
            } else {
                -seconds
            }
        }
        _ => return Err(unreadable()),
    };
    // `time.strptime` refuses impossible dates and times.
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&month)
        || day < 1
        || day > month_days[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 61
    {
        return Err(format!(
            "time data {} does not match format '%Y-%m-%dT%H:%M:%S'",
            pc_host::pytext::py_repr(&text[..19])
        ));
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

fn digits_of(text: &str) -> Option<i64> {
    py::is_digits(text).then(|| text.parse().unwrap_or(0))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests;
