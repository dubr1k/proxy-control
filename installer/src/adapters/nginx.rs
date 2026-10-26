//! Nginx stream routing (`installer/adapters/nginx.py`): the effective-configuration parser,
//! the owned map patcher, and the transactional router adapter.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use pc_host::fs::{atomic_write, durable_copy2, durable_remove, sha256_hex};
use pc_host::runner::{bounded_capture, Bounded, HostRunner};
use serde_json::{json, Map, Value};

use crate::adapter::Adapter;
use crate::adapters::AdapterContext;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::{HostMode, InstallerConfig, ThreeXuiMode};
use crate::planner::{Action, AuditFacts, Evidence};

pub const OWNERSHIP_BEGIN: &str = "# BEGIN PROXY-CONTROL ROUTES";
pub const OWNERSHIP_END: &str = "# END PROXY-CONTROL ROUTES";
pub const GENERATED_BEGIN: &str = "# BEGIN PROXY-CONTROL GENERATED STREAM ROUTER";
pub const GENERATED_END: &str = "# END PROXY-CONTROL GENERATED STREAM ROUTER";
const NGINX_CONF: &str = "/etc/nginx/nginx.conf";
const DEFAULT_FRESH_PATH: &str = "/etc/nginx/stream.d/proxy-control.conf";

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn topology<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::other("TopologyError", message))
}

pub use installer_core::nginx_topology::{MapRoute, NginxMap, NginxTopology, RouteTarget, StreamServer};

fn variable(value: &str) -> bool {
    installer_core::nginx_topology::is_variable(value)
}

fn topology_error(error: installer_core::nginx_topology::TopologyError) -> Error {
    Error::other("TopologyError", error.to_string())
}

// Audit offsets count code points; mutations slice UTF-8 bytes.
fn byte_offsets(text: &str, mut observed: NginxTopology) -> NginxTopology {
    if !text.is_ascii() {
        let offsets: Vec<usize> =
            text.char_indices().map(|(offset, _)| offset).chain(std::iter::once(text.len())).collect();
        for mapping in &mut observed.maps {
            mapping.start = offsets[mapping.start];
            mapping.end = offsets[mapping.end];
            for route in &mut mapping.routes {
                route.start = offsets[route.start];
            }
        }
    }
    observed
}

/// The effective topology the host audit observes, with byte offsets for mutation.
pub fn parse_effective_nginx(text: &str) -> Result<NginxTopology> {
    installer_core::nginx_topology::parse_effective_nginx(text)
        .map(|observed| byte_offsets(text, observed))
        .map_err(topology_error)
}

fn parse_file_nginx(text: &str) -> Result<NginxTopology> {
    installer_core::nginx_topology::parse_file_nginx(text)
        .map(|observed| byte_offsets(text, observed))
        .map_err(topology_error)
}

fn posix_parts(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty() && *part != ".").collect()
}

fn normalize_include_pattern(pattern: &str) -> Result<String> {
    installer_core::nginx_topology::normalize_include_pattern(pattern).map_err(topology_error)
}

fn resolve_include(pattern: &str, prefix: &str) -> Result<String> {
    installer_core::nginx_topology::resolve_include(pattern, prefix).map_err(topology_error)
}

fn nginx_runtime_prefix(output: &str) -> Result<String> {
    let mut prefixes = BTreeSet::new();
    for line in output.split_inclusive('\n') {
        let mut rest = line;
        while let Some(index) = rest.find("--prefix=") {
            if index > 0 && !rest[..index].chars().next_back().is_some_and(char::is_whitespace) {
                rest = &rest[index + 9..];
                continue;
            }
            let value = &rest[index + 9..];
            let prefix = match value.chars().next() {
                Some(quote @ ('\'' | '"')) => {
                    value[quote.len_utf8()..].split_once(quote).map(|(value, _)| value).unwrap_or("")
                }
                _ => value.split_whitespace().next().unwrap_or(""),
            };
            if !prefix.is_empty() && !prefix.contains(['\r', '\n']) {
                prefixes.insert(prefix.to_string());
            }
            rest = &value[prefix.len().min(value.len())..];
        }
    }
    if prefixes.len() != 1 {
        return topology("fresh router path is not proven included by Nginx");
    }
    let prefix = normalize_include_pattern(prefixes.first().expect("one prefix"))?;
    if !prefix.starts_with('/') {
        return topology("fresh router path is not proven included by Nginx");
    }
    Ok(prefix)
}

fn glob_path_matches(path: &str, pattern: &str) -> bool {
    installer_core::nginx_topology::glob_path_matches(path, pattern)
}

/// Select the same active route as the host audit.
pub fn select_route_target(observed: &NginxTopology, listener_port: u16) -> Result<RouteTarget> {
    if listener_port == 0 {
        return Err(Error::other("ValueError", "listener port must be in 1..65535"));
    }
    installer_core::nginx_topology::select_route_target(observed, u32::from(listener_port)).map_err(topology_error)
}

/// The map used by Core's adjacent-route acceptance check.
pub(crate) fn active_sni_routes(text: &str) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::<String, BTreeSet<String>>::new();
    for (domain, backend) in select_route_target(&parse_effective_nginx(text)?, 443)?.routes {
        let normalized = domain.to_ascii_lowercase();
        if valid_domain(&normalized) {
            values.entry(normalized).or_default().insert(backend);
        }
    }
    Ok(values.into_iter().map(|(domain, backends)| (domain, backends.into_iter().next().expect("nonempty"))).collect())
}

pub fn derive_owned_route_variable(text: &str, routes: &[(String, String)], ownership_id: &str) -> Result<String> {
    let observed = parse_file_nginx(text)?;
    let sni_maps: Vec<&NginxMap> =
        observed.maps.iter().filter(|mapping| mapping.source_variable == "$ssl_preread_server_name").collect();
    let mut exact = Vec::new();
    for mapping in &sni_maps {
        if remove_owned_map_block(&text.as_bytes()[mapping.start..mapping.end], routes, ownership_id).is_ok() {
            exact.push(*mapping);
        }
    }
    if exact.len() == 1 {
        return Ok(exact[0].variable.clone());
    }
    if text.contains(&format!("{OWNERSHIP_BEGIN} {ownership_id}")) || sni_maps.len() != 1 {
        return topology("legacy owned route topology is ambiguous");
    }
    Ok(sni_maps[0].variable.clone())
}

pub fn patch_owned_map(
    text: &str,
    variable_name: &str,
    routes: &[(String, String)],
    ownership_id: &str,
) -> Result<String> {
    let observed = parse_file_nginx(text)?;
    let matches: Vec<&NginxMap> = observed
        .maps
        .iter()
        .filter(|mapping| mapping.variable == variable_name && mapping.source_variable == "$ssl_preread_server_name")
        .collect();
    if matches.len() != 1 {
        return topology("selected route file does not contain exactly one effective map");
    }
    if routes.is_empty() || routes.iter().any(|(domain, backend)| domain.is_empty() || backend.is_empty()) {
        return Err(Error::other("ValueError", "owned routes must be non-empty"));
    }
    let mapping = matches[0];
    let mut existing = BTreeMap::new();
    for route in &mapping.routes {
        if existing.insert(&route.key, &route.value).is_some() {
            return topology("duplicate routes make the selected map ambiguous");
        }
    }
    for (domain, backend) in routes {
        if existing.get(domain).is_some_and(|current| *current != backend) {
            return topology(format!("domain already routed: {domain}"));
        }
    }
    let begin = format!("{OWNERSHIP_BEGIN} {ownership_id}");
    let end = format!("{OWNERSHIP_END} {ownership_id}");
    let mut managed_lines = vec![begin.clone()];
    managed_lines.extend(routes.iter().map(|(domain, backend)| format!("{domain} {backend};")));
    managed_lines.push(end.clone());
    if text.contains(OWNERSHIP_BEGIN) || text.contains(OWNERSHIP_END) {
        let lines: Vec<&str> = text.lines().collect();
        let begins: Vec<usize> =
            lines.iter().enumerate().filter_map(|(i, line)| (line.trim() == begin).then_some(i)).collect();
        let ends: Vec<usize> =
            lines.iter().enumerate().filter_map(|(i, line)| (line.trim() == end).then_some(i)).collect();
        if begins.len() != 1
            || ends.len() != 1
            || begins[0] >= ends[0]
            || lines[begins[0]..=ends[0]].iter().map(|line| line.trim()).collect::<Vec<_>>() != managed_lines
        {
            return topology(if begins.len() == 1 && ends.len() == 1 && begins[0] < ends[0] {
                "owned route block differs from requested configuration"
            } else {
                "malformed or foreign route ownership markers"
            });
        }
        return Ok(text.to_string());
    }
    let defaults: Vec<&MapRoute> = mapping.routes.iter().filter(|route| route.key == "default").collect();
    if defaults.len() != 1 {
        return topology("selected SNI map must contain exactly one default route");
    }
    let insertion = defaults[0].start;
    let line_start = text[..insertion].rfind('\n').map_or(0, |index| index + 1);
    let mut indent = &text[line_start..insertion];
    if !indent.trim().is_empty() {
        indent = "    ";
    }
    let managed = managed_lines.iter().map(|line| format!("{indent}{line}\n")).collect::<String>();
    Ok(format!("{}{managed}{}", &text[..line_start], &text[line_start..]))
}

pub fn remove_owned_map_block(content: &[u8], routes: &[(String, String)], ownership_id: &str) -> Result<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(content) else { return topology("owned route file has drifted") };
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let begin = format!("{OWNERSHIP_BEGIN} {ownership_id}");
    let end = format!("{OWNERSHIP_END} {ownership_id}");
    let begins: Vec<usize> =
        lines.iter().enumerate().filter_map(|(i, line)| (line.trim() == begin).then_some(i)).collect();
    let ends: Vec<usize> = lines.iter().enumerate().filter_map(|(i, line)| (line.trim() == end).then_some(i)).collect();
    let mut expected = vec![begin];
    expected.extend(routes.iter().map(|(domain, backend)| format!("{domain} {backend};")));
    expected.push(end);
    if begins.len() != 1
        || ends.len() != 1
        || begins[0] >= ends[0]
        || lines[begins[0]..=ends[0]].iter().map(|line| line.trim()).collect::<Vec<_>>() != expected
    {
        return topology("owned route file has drifted");
    }
    Ok(format!("{}{}", lines[..begins[0]].concat(), lines[ends[0] + 1..].concat()).into_bytes())
}

#[derive(Debug, Clone)]
struct RouteSpec {
    mode: String,
    stream_context: String,
    target: String,
    variable: String,
    path_kind: String,
    resolved_path: String,
    symlink_target: Option<String>,
    routes: Vec<(String, String)>,
    client_ip: String,
    panel_tls_backend: String,
}

#[derive(Debug, Clone)]
struct RouteIdentity {
    exists: bool,
    original_path: String,
    path_kind: String,
    resolved_path: String,
    mode: u32,
    uid: u32,
    gid: u32,
    original_sha256: Option<String>,
    symlink_target: Option<String>,
}

impl RouteIdentity {
    fn to_value(&self) -> Value {
        json!({
            "exists": self.exists,
            "original_path": self.original_path,
            "path_kind": self.path_kind,
            "resolved_path": self.resolved_path,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "original_sha256": self.original_sha256,
            "symlink_target": self.symlink_target,
        })
    }
}

/// Transactional owner of the generated router or one selected map block.
pub struct NginxAdapter {
    context: AdapterContext,
    root: PathBuf,
    runner: Arc<dyn HostRunner>,
    fresh_path: String,
}

impl NginxAdapter {
    pub fn new(context: &AdapterContext) -> NginxAdapter {
        NginxAdapter {
            context: context.clone(),
            root: fs::canonicalize(&context.root).unwrap_or_else(|_| context.root.clone()),
            runner: context.runner.clone(),
            fresh_path: DEFAULT_FRESH_PATH.into(),
        }
    }

    fn plan_routes(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<(String, String)>> {
        let panel = format!("127.0.0.1:{}", config.panel_tls_port());
        let mut routes = vec![
            (config.domains.mtproxy.clone(), "127.0.0.1:8445".into()),
            (config.domains.panel.clone(), panel.clone()),
        ];
        for domain in [&config.domains.subscription, &config.domains.mcp].into_iter().flatten() {
            routes.push((domain.clone(), panel.clone()));
        }
        if config.profile.includes_naive() {
            let Some(domain) = &config.domains.naive else { return topology("Naive route domain is missing") };
            routes.push((domain.clone(), "127.0.0.1:4443".into()));
        }
        if let Some(trusttunnel) = &config.trusttunnel {
            routes.push((trusttunnel.hostname.clone(), format!("127.0.0.1:{}", trusttunnel.listen_port)));
        }
        if config.three_xui.mode != ThreeXuiMode::None {
            routes.extend(super::three_xui::ThreeXuiAdapter::new(&self.context).planned_routes(config)?);
        }
        if let Some(bridge) = config.ingress.as_ref().and_then(|ingress| ingress.proxy_protocol_bridge.as_ref()) {
            let port = bridge.rsplit_once(':').and_then(|(_, port)| port.parse::<u16>().ok());
            let listening = facts.listeners.get("tcp").and_then(Value::as_array).is_some_and(|tcp| {
                port.is_some_and(|port| tcp.iter().any(|value| value.as_u64() == Some(u64::from(port))))
            });
            if port.is_none() {
                return topology("configured PROXY-protocol bridge is invalid");
            }
            if !listening {
                return topology("configured PROXY-protocol bridge is not listening");
            }
            routes = routes.into_iter().map(|(domain, _)| (domain, bridge.clone())).collect();
        }
        Ok(routes)
    }

    fn stock_nginx_conf(&self) -> bool {
        let Ok(path) = self.root_path(NGINX_CONF) else { return false };
        if path.is_symlink() || !path.is_file() {
            return false;
        }
        fs::read_to_string(path).is_ok_and(|text| !has_stream_context(&text))
    }

    fn planned_path_identity(
        &self,
        host_path: &str,
        must_be_missing: bool,
    ) -> Result<(String, String, Option<String>)> {
        let path = self.root_path(host_path)?;
        let exists = path_exists(&path);
        if must_be_missing {
            if exists {
                return topology("fresh router path is already occupied");
            }
            return Ok(("missing".into(), host_path.into(), None));
        }
        if !exists {
            return topology("selected route file does not exist");
        }
        let resolved = fs::canonicalize(&path)
            .map_err(|_| Error::other("TopologyError", "selected route file cannot be resolved"))?;
        self.assert_contained(&resolved)?;
        if !resolved.is_file() {
            return topology("selected route path is not a regular file");
        }
        let kind = if path.is_symlink() { "symlink" } else { "file" };
        let target = if path.is_symlink() { Some(fs::read_link(&path)?.to_string_lossy().into_owned()) } else { None };
        Ok((kind.into(), self.host_path(&resolved)?, target))
    }

    fn validate_planned_path(&self, spec: &RouteSpec, allow_created: bool) -> Result<PathBuf> {
        let original = self.root_path(&spec.target)?;
        match spec.path_kind.as_str() {
            "missing" if !allow_created => {
                if path_exists(&original) {
                    return topology("Nginx route path identity changed");
                }
                return self.root_path(&spec.resolved_path);
            }
            "missing" if original.is_symlink() || !original.is_file() => {
                return topology("Nginx route path identity changed")
            }
            "symlink" => {
                if !original.is_symlink()
                    || fs::read_link(&original).ok().map(|path| path.to_string_lossy().into_owned()).as_deref()
                        != spec.symlink_target.as_deref()
                {
                    return topology("Nginx route path identity changed");
                }
            }
            "file" if original.is_symlink() || !original.is_file() => {
                return topology("Nginx route path identity changed")
            }
            "missing" | "file" => {}
            _ => return topology("Nginx action path identity is invalid"),
        }
        let resolved = fs::canonicalize(&original)
            .map_err(|_| Error::other("TopologyError", "Nginx route path identity changed"))?;
        if self.host_path(&resolved)? != spec.resolved_path {
            return topology("Nginx route path identity changed");
        }
        Ok(resolved)
    }

    fn root_path(&self, host_path: &str) -> Result<PathBuf> {
        let normalized = safe_host_path(host_path)?;
        let path = self.root.join(normalized.trim_start_matches('/'));
        let mut nearest = path.clone();
        while !path_exists(&nearest) {
            if nearest == self.root {
                return Ok(path);
            }
            nearest = nearest
                .parent()
                .ok_or_else(|| Error::other("TopologyError", "selected route parent cannot be resolved"))?
                .to_path_buf();
        }
        let resolved = fs::canonicalize(&nearest)
            .map_err(|_| Error::other("TopologyError", "selected route parent cannot be resolved"))?;
        self.assert_contained(&resolved)?;
        Ok(path)
    }

    fn host_path(&self, path: &Path) -> Result<String> {
        self.assert_contained(path)?;
        Ok(format!(
            "/{}",
            path.strip_prefix(&self.root)
                .map_err(|_| Error::other("TopologyError", "selected route path escapes the supplied root"))?
                .display()
        ))
    }

    fn assert_contained(&self, path: &Path) -> Result<()> {
        if path.strip_prefix(&self.root).is_err() {
            return topology("selected route path escapes the supplied root");
        }
        Ok(())
    }

    fn backup_path(&self, action: &Action, identity: &RouteIdentity) -> Result<PathBuf> {
        let suffix = identity.original_sha256.clone().unwrap_or_else(|| sha256_hex(action.id.as_bytes()));
        self.root_path(&format!("/var/lib/proxy-control/installer/nginx/{suffix}.backup"))
    }

    fn fresh_path_is_included(&self, observed: &NginxTopology) -> Result<bool> {
        let mut relative = Vec::new();
        for pattern in &observed.stream_includes {
            if pattern.starts_with('/') {
                if glob_path_matches(&self.fresh_path, pattern) {
                    return Ok(true);
                }
            } else {
                relative.push(pattern);
            }
        }
        if relative.is_empty() {
            return Ok(false);
        }
        let result = self.runner.bounded(&["nginx", "-V"], Bounded::NGINX)?;
        if result.returncode != 0 {
            return topology("fresh router path is not proven included by Nginx");
        }
        let prefix = nginx_runtime_prefix(&format!("{}\n{}", result.stdout, result.stderr))?;
        for pattern in relative {
            if glob_path_matches(&self.fresh_path, &resolve_include(pattern, &prefix)?) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn authenticate_source(&self, effective: &str, source_file: &str) -> Result<()> {
        let sections = effective_source_sections(effective);
        let Some(sections) = sections.get(source_file).filter(|sections| sections.len() == 1) else {
            return topology("effective Nginx source marker is not authenticated");
        };
        let path = self.root_path(&safe_host_path(source_file)?)?;
        let resolved = fs::canonicalize(&path)
            .map_err(|_| Error::other("TopologyError", "effective Nginx source marker is not authenticated"))?;
        self.assert_contained(&resolved)?;
        if !resolved.is_file() {
            return topology("effective Nginx source marker is not authenticated");
        }
        let bytes = fs::read(&resolved)
            .map_err(|_| Error::other("TopologyError", "effective Nginx source marker is not authenticated"))?;
        let Ok(content) = std::str::from_utf8(&bytes) else {
            return topology("effective Nginx source marker is not authenticated");
        };
        if sections[0] != content && sections[0] != format!("{content}\n") {
            return topology("effective Nginx source marker is not authenticated");
        }
        Ok(())
    }

    fn run_checked(&self, argv: &[&str], message: &str) -> Result<()> {
        if self.runner.bounded(argv, Bounded::NGINX)?.returncode != 0 {
            return Err(Error::other("RuntimeError", message));
        }
        Ok(())
    }

    fn create_stream_context(&self) -> Result<bool> {
        let config = self.root_path(NGINX_CONF)?;
        if !config.is_file() || config.is_symlink() {
            return Ok(false);
        }
        let backup = config.with_file_name("nginx.conf.proxy-control-backup");
        let backup_created = !path_exists(&backup);
        if backup_created {
            durable_copy2(&config, &backup)?;
        } else if backup.is_symlink() || !backup.is_file() {
            return topology("Nginx stream context backup is unsafe");
        }
        let outcome = (|| {
            let directory = self.root_path(
                Path::new(&self.fresh_path).parent().expect("router parent").to_str().expect("UTF-8 router"),
            )?;
            fs::create_dir_all(directory)?;
            if !ensure_stream_context(&config, &self.fresh_path)? {
                return Ok(false);
            }
            let result = self.runner.bounded(&["nginx", "-t"], Bounded::NGINX)?;
            if result.returncode != 0 {
                return topology(format!(
                    "adding the stream context left Nginx unable to start: {}",
                    sanitize_diagnostic(&format!("{}\n{}", result.stderr, result.stdout), 800)
                ));
            }
            reload_nginx(self.runner.as_ref(), Bounded::NGINX, "Nginx reload after adding the stream context")?;
            Ok(true)
        })();
        match outcome {
            Ok(changed) => Ok(changed),
            Err(error) => {
                self.restore_stream_context_files()?;
                if backup_created {
                    self.discard_stream_context_backup()?;
                }
                Err(error)
            }
        }
    }

    fn restore_stream_context_files(&self) -> Result<bool> {
        let config = self.root_path(NGINX_CONF)?;
        let backup = config.with_file_name("nginx.conf.proxy-control-backup");
        if !path_exists(&backup) {
            if fs::read_to_string(&config)?.contains("# Added by Proxy Control: the shared 443 router lives here.") {
                return topology("Nginx stream context rollback backup is missing");
            }
            return Ok(false);
        }
        if backup.is_symlink() || !backup.is_file() {
            return topology("Nginx stream context backup is unsafe");
        }
        let metadata = fs::metadata(&config)?;
        atomic_write(&config, &fs::read(&backup)?, metadata.mode() & 0o7777, Some((metadata.uid(), metadata.gid())))?;
        Ok(true)
    }

    fn discard_stream_context_backup(&self) -> Result<()> {
        let config = self.root_path(NGINX_CONF)?;
        durable_remove(&config.with_file_name("nginx.conf.proxy-control-backup"), true)?;
        Ok(())
    }

    fn restore_failed_stream_context(&self) -> Result<()> {
        self.restore_stream_context_files()?;
        self.discard_stream_context_backup()
    }

    fn assert_active_route(&self, action: &Action, spec: &RouteSpec, require_owned: bool) -> Result<()> {
        let target = (|| -> Result<RouteTarget> {
            let effective = bounded_capture(self.runner.as_ref(), &["nginx", "-T"], Bounded::NGINX)?;
            let target = select_route_target(&parse_effective_nginx(&effective)?, 443)?;
            self.authenticate_source(&effective, &target.source_file)?;
            Ok(target)
        })()
        .map_err(|_| Error::other("TopologyError", "owned route is not on the active 443 path"))?;
        if target.source_file != spec.target || target.variable != spec.variable {
            return topology("owned route is not on the active 443 path");
        }
        let path = self.validate_planned_path(spec, true)?;
        let content = fs::read(path)?;
        let owned = if spec.mode == "fresh" {
            content == render_fresh_spec(spec)?
        } else {
            owned_block_in_selected_map(&content, spec, &action.id)
        };
        if require_owned && !owned {
            return topology("owned route is not on the active 443 path");
        }
        Ok(())
    }

    fn applied_checkpoint(
        &self,
        action: &Action,
        checkpoint: &CheckpointData,
        identity: &RouteIdentity,
        desired: &[u8],
    ) -> Result<CheckpointData> {
        let mut result = CheckpointData::new();
        result.insert("owner".into(), checkpoint.get("owner").cloned().unwrap_or(Value::Null));
        result.insert("route_identity".into(), identity.to_value());
        result.insert("owned_sha256".into(), json!(sha256_hex(desired)));
        if identity.exists {
            let backup = self.backup_path(action, identity)?;
            let host = self.host_path(&backup)?;
            result.insert("backup_path".into(), json!(host));
            result.insert("ownership".into(), json!({host: {"preserve": false, "sha256": identity.original_sha256}}));
        } else {
            result.insert("backup_path".into(), json!(""));
            result.insert(
                "ownership".into(),
                json!({identity.original_path.clone(): {"preserve": false, "sha256": sha256_hex(desired)}}),
            );
        }
        Ok(result)
    }
}

impl Adapter for NginxAdapter {
    fn name(&self) -> &str {
        "nginx"
    }

    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>> {
        if facts.prerequisites.get("hard_stops").and_then(Value::as_array).is_some_and(|stops| !stops.is_empty()) {
            return topology("host audit contains blocking findings");
        }
        let Some(nginx) = facts.topology.get("nginx").and_then(Value::as_object) else {
            return topology("Nginx observation is missing");
        };
        let observation = nginx.get("observation").and_then(Value::as_str);
        if observation == Some("unknown") {
            return topology("Nginx topology is unknown");
        }
        let routes = self.plan_routes(config, facts)?;
        let mut known_domains = BTreeSet::new();
        if let Some(observed) = nginx.get("sni_routes").and_then(Value::as_object) {
            known_domains.extend(observed.keys().cloned());
        }
        if let Some(domains) = nginx.get("http_domains").and_then(Value::as_array) {
            known_domains.extend(domains.iter().filter_map(Value::as_str).map(str::to_string));
        }
        let owned_router = nginx
            .get("route_target")
            .and_then(Value::as_object)
            .and_then(|target| target.get("source_file"))
            .and_then(Value::as_str)
            == Some(self.fresh_path.as_str());
        let empty = Map::new();
        let observed = nginx.get("sni_routes").and_then(Value::as_object).unwrap_or(&empty);
        for (domain, backend) in &routes {
            if !known_domains.contains(domain) {
                continue;
            }
            let expected = if config.host_mode == HostMode::Fresh {
                client_ip_backend(backend, &format!("127.0.0.1:{}", config.panel_tls_port()))?
            } else {
                backend.clone()
            };
            if observed
                .get(domain)
                .and_then(Value::as_str)
                .is_some_and(|current| current == backend || current == expected)
            {
                continue;
            }
            return topology(format!("domain already routed: {domain}"));
        }
        let (mode, stream_context, target_path, variable_name) = if config.host_mode == HostMode::Fresh {
            if observation != Some("observed") {
                return topology("fresh router path is not proven included by Nginx");
            }
            let effective = bounded_capture(self.runner.as_ref(), &["nginx", "-T"], Bounded::NGINX)?;
            let observed_topology = parse_effective_nginx(&effective)?;
            if !owned_router && observed_topology.servers.iter().any(|server| server.listener_ports.contains(&443)) {
                return topology("fresh mode cannot replace an active stream router");
            }
            let stream_context = if self.fresh_path_is_included(&observed_topology)? {
                "present"
            } else {
                if observed_topology.stream_enabled || !self.stock_nginx_conf() {
                    return topology("fresh router path is not included by the stream context");
                }
                "create"
            };
            ("fresh", stream_context, self.fresh_path.clone(), "$proxy_control_backend".to_string())
        } else {
            if observation != Some("observed") {
                return topology("Nginx is unavailable in coexist mode");
            }
            let effective = bounded_capture(self.runner.as_ref(), &["nginx", "-T"], Bounded::NGINX)?;
            let target = select_route_target(&parse_effective_nginx(&effective)?, 443)?;
            self.authenticate_source(&effective, &target.source_file)?;
            let existing: BTreeMap<_, _> = target.routes.iter().cloned().collect();
            for (domain, backend) in &routes {
                if existing.get(domain).is_some_and(|current| current != backend) {
                    return topology(format!("domain already routed: {domain}"));
                }
            }
            ("coexist", "present", safe_host_path(&target.source_file)?, target.variable)
        };
        let (path_kind, resolved_path, symlink_target) =
            self.planned_path_identity(&target_path, mode == "fresh" && !owned_router)?;
        let mut mutations = vec![format!("mode={mode}")];
        if mode == "fresh" {
            mutations.push("client_ip=proxy".into());
            mutations.push(format!("panel_tls_backend=127.0.0.1:{}", config.panel_tls_port()));
        }
        mutations.extend([
            format!("stream_context={stream_context}"),
            format!("target={target_path}"),
            format!("variable={variable_name}"),
            format!("path_kind={path_kind}"),
            format!("resolved_path={resolved_path}"),
            format!("symlink_target={}", symlink_target.as_deref().unwrap_or("-")),
        ]);
        mutations.extend(routes.iter().map(|(domain, backend)| format!("route={domain} {backend}")));
        let mut preconditions = vec!["effective Nginx topology is observed and unambiguous".to_string()];
        if config.ingress.as_ref().and_then(|ingress| ingress.proxy_protocol_bridge.as_ref()).is_some() {
            preconditions.push("the configured loopback PROXY-protocol bridge is listening".into());
        }
        if stream_context == "create" {
            preconditions.push("Nginx has no stream context: one including the router is added first".into());
        }
        let mut verification = Vec::new();
        if stream_context == "create" {
            verification.push("the router path is included by the stream context".into());
        }
        verification.push("Nginx configuration test passes before reload".into());
        Ok(vec![Action::new(
            "nginx.routes",
            "nginx",
            "proxy-control:nginx",
            mutations,
            preconditions,
            verification,
            vec!["restore content, owner, group, mode, and symlink identity".into()],
            false,
        )?])
    }

    fn prepare(&self, action: &Action) -> Result<CheckpointData> {
        let spec = action_specification(action)?;
        let path = self.validate_planned_path(&spec, false)?;
        let exists = spec.path_kind != "missing";
        let (original_sha256, mode, uid, gid) = if exists {
            let metadata = path.metadata()?;
            let content = fs::read(path)?;
            (Some(sha256_hex(&content)), metadata.mode() & 0o7777, metadata.uid(), metadata.gid())
        } else {
            let (uid, gid) = current_uid_gid();
            (None, 0o640, uid, gid)
        };
        let identity = RouteIdentity {
            exists,
            original_path: spec.target,
            path_kind: spec.path_kind,
            resolved_path: spec.resolved_path,
            mode,
            uid,
            gid,
            original_sha256,
            symlink_target: spec.symlink_target,
        };
        Ok(Map::from_iter([
            ("owner".into(), json!(action.owner)),
            ("ownership".into(), json!({})),
            ("route_identity".into(), identity.to_value()),
        ]))
    }

    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData> {
        let spec = action_specification(action)?;
        let identity = checkpoint_identity(&checkpoint, &spec, &action.owner)?;
        let path = self.validate_planned_path(&spec, false)?;
        if spec.stream_context == "create" {
            self.create_stream_context()?;
            let proof = (|| {
                let effective = bounded_capture(self.runner.as_ref(), &["nginx", "-T"], Bounded::NGINX)?;
                self.fresh_path_is_included(&parse_effective_nginx(&effective)?)
            })();
            match proof {
                Ok(true) => {}
                Ok(false) => {
                    self.restore_failed_stream_context()?;
                    return topology("fresh router path is not included by the stream context");
                }
                Err(error) => {
                    self.restore_failed_stream_context()?;
                    return Err(error);
                }
            }
        }
        let result = (|| {
            let original = if identity.exists { fs::read(&path)? } else { Vec::new() };
            let desired = desired_content(&spec, &original)?;
            let reentered =
                identity.exists && sha256_hex(&original) != identity.original_sha256.as_deref().unwrap_or("");
            if reentered && desired != original {
                return topology("selected route file changed after planning");
            }
            let backup = self.backup_path(action, &identity)?;
            if identity.exists && !reentered {
                atomic_write(&backup, &original, 0o600, None)?;
            }
            self.validate_planned_path(&spec, false)?;
            atomic_write(&path, &desired, identity.mode, Some((identity.uid, identity.gid)))?;
            if let Err(error) = (|| {
                self.assert_active_route(action, &spec, true)?;
                self.run_checked(&["nginx", "-t"], "nginx configuration test failed")?;
                reload_nginx(self.runner.as_ref(), Bounded::NGINX, "nginx reload failed")?;
                Ok(())
            })() {
                if identity.exists {
                    atomic_write(&path, &original, identity.mode, Some((identity.uid, identity.gid)))?;
                } else {
                    durable_remove(&path, true)?;
                }
                return Err(error);
            }
            self.applied_checkpoint(action, &checkpoint, &identity, &desired)
        })();
        if result.is_err() && spec.stream_context == "create" {
            self.restore_failed_stream_context()?;
        }
        result
    }

    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData> {
        let spec = action_specification(action)?;
        let identity = checkpoint_identity(&checkpoint, &spec, &action.owner)?;
        let target = self.root_path(&identity.resolved_path)?;
        if target.is_file() {
            let current = fs::read(&target)?;
            let recognized = if spec.mode == "fresh" {
                current == render_fresh_spec(&spec)?
            } else {
                owned_block_in_selected_map(&current, &spec, &action.id)
            };
            if recognized {
                self.assert_active_route(action, &spec, true)?;
                let backup = self.backup_path(action, &identity)?;
                if identity.exists
                    && (!backup.is_file()
                        || sha256_hex(&fs::read(&backup)?) != identity.original_sha256.clone().unwrap_or_default())
                {
                    return topology("Nginx rollback backup is missing or drifted");
                }
                self.run_checked(&["nginx", "-t"], "nginx configuration test failed")?;
                reload_nginx(self.runner.as_ref(), Bounded::NGINX, "nginx reload failed")?;
                return self.applied_checkpoint(action, &checkpoint, &identity, &current);
            }
        }
        self.apply(action, checkpoint)
    }

    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData> {
        self.reconcile_apply(action, checkpoint)
    }

    fn verify(&self, action: &Action) -> Result<Evidence> {
        let spec = action_specification(action)?;
        let success = (|| -> Result<bool> {
            let path = self.validate_planned_path(&spec, true)?;
            self.assert_active_route(action, &spec, true)?;
            let content = fs::read(path)?;
            Ok(if spec.mode == "coexist" {
                owned_block_in_selected_map(&content, &spec, &action.id)
            } else {
                content == render_fresh_spec(&spec)?
            })
        })()
        .unwrap_or(false);
        Ok(if success {
            Evidence::ok(&action.id, &["owned Nginx route verified"])?
        } else {
            Evidence::failed(&action.id, &["owned Nginx route is absent or drifted"])?
        })
    }

    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        _purge_data: bool,
        _target: RollbackTarget,
    ) -> Result<Evidence> {
        let spec = action_specification(action)?;
        let identity = checkpoint_identity(&checkpoint, &spec, &action.owner)?;
        let path = self.validate_planned_path(&spec, true)?;
        let current = fs::read(&path)?;
        self.assert_active_route(action, &spec, true)?;
        let config = self.root_path(NGINX_CONF)?;
        let current_config =
            if spec.stream_context == "create" && config.is_file() { Some(fs::read(&config)?) } else { None };
        if spec.mode == "fresh" {
            if current != render_fresh_spec(&spec)? {
                return topology("owned route file has drifted");
            }
            durable_remove(&path, true)?;
        } else {
            let restored = remove_owned_map_block(&current, &spec.routes, &action.id)?;
            self.validate_planned_path(&spec, true)?;
            atomic_write(&path, &restored, identity.mode, Some((identity.uid, identity.gid)))?;
        }
        let outcome = (|| {
            if spec.stream_context == "create" {
                self.restore_stream_context_files()?;
            }
            self.run_checked(&["nginx", "-t"], "nginx configuration test failed")?;
            reload_nginx(self.runner.as_ref(), Bounded::NGINX, "nginx reload failed")?;
            Ok(())
        })();
        if let Err(error) = outcome {
            let _ = atomic_write(&path, &current, identity.mode, Some((identity.uid, identity.gid)));
            if let Some(content) = current_config {
                if let Ok(metadata) = fs::metadata(&config) {
                    let _ = atomic_write(
                        &config,
                        &content,
                        metadata.permissions().mode(),
                        Some((metadata.uid(), metadata.gid())),
                    );
                }
            }
            return Err(error);
        }
        durable_remove(&self.backup_path(action, &identity)?, true)?;
        if spec.stream_context == "create" {
            self.discard_stream_context_backup()?;
        }
        Evidence::ok(&action.id, &["owned Nginx route rolled back"]).map_err(Into::into)
    }

    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence> {
        let spec = action_specification(action)?;
        let identity = checkpoint_identity(&checkpoint, &spec, &action.owner)?;
        let original = self.root_path(&spec.target)?;
        let exact_marker = format!("{OWNERSHIP_BEGIN} {}", action.id);
        let committed = if spec.mode == "fresh" && !path_exists(&original) {
            self.root_path(&spec.resolved_path)?;
            true
        } else if spec.mode == "coexist" {
            let path = self.validate_planned_path(&spec, true)?;
            let committed =
                !fs::read(&path)?.windows(exact_marker.len()).any(|window| window == exact_marker.as_bytes());
            if committed {
                self.assert_active_route(action, &spec, false)?;
            }
            committed
        } else {
            false
        };
        if !committed {
            return self.rollback(action, checkpoint, purge_data, target);
        }
        if spec.stream_context == "create" {
            self.restore_stream_context_files()?;
        }
        self.run_checked(&["nginx", "-t"], "nginx configuration test failed")?;
        reload_nginx(self.runner.as_ref(), Bounded::NGINX, "nginx reload failed")?;
        durable_remove(&self.backup_path(action, &identity)?, true)?;
        if spec.stream_context == "create" {
            self.discard_stream_context_backup()?;
        }
        Evidence::ok(&action.id, &["Nginx rollback side effects reconciled"]).map_err(Into::into)
    }
}

fn checkpoint_identity(checkpoint: &CheckpointData, spec: &RouteSpec, owner: &str) -> Result<RouteIdentity> {
    let prepared = checkpoint.len() == 3
        && checkpoint.contains_key("owner")
        && checkpoint.contains_key("ownership")
        && checkpoint.contains_key("route_identity");
    let applied = checkpoint.len() == 5
        && checkpoint.contains_key("owner")
        && checkpoint.contains_key("ownership")
        && checkpoint.contains_key("route_identity")
        && checkpoint.contains_key("owned_sha256")
        && checkpoint.contains_key("backup_path");
    if !(prepared || applied)
        || checkpoint.get("owner").and_then(Value::as_str) != Some(owner)
        || !checkpoint.get("ownership").is_some_and(Value::is_object)
        || (prepared && !checkpoint["ownership"].as_object().unwrap().is_empty())
        || (applied
            && (!checkpoint["owned_sha256"].as_str().is_some_and(hex64) || !checkpoint["backup_path"].is_string()))
    {
        return topology("Nginx checkpoint is invalid");
    }
    let required: BTreeSet<&str> = [
        "exists",
        "original_path",
        "path_kind",
        "resolved_path",
        "mode",
        "uid",
        "gid",
        "original_sha256",
        "symlink_target",
    ]
    .into();
    let Some(identity) = checkpoint.get("route_identity").and_then(Value::as_object) else {
        return topology("Nginx checkpoint is invalid");
    };
    if identity.keys().map(String::as_str).collect::<BTreeSet<_>>() != required {
        return topology("Nginx checkpoint is invalid");
    }
    let exists = identity["exists"].as_bool();
    let mode = identity["mode"].as_u64().filter(|mode| *mode <= 0o7777);
    let uid = identity["uid"].as_u64().filter(|uid| *uid <= u64::from(u32::MAX));
    let gid = identity["gid"].as_u64().filter(|gid| *gid <= u64::from(u32::MAX));
    let original_sha256 = identity["original_sha256"].as_str().map(str::to_string);
    if exists.is_none()
        || mode.is_none()
        || uid.is_none()
        || gid.is_none()
        || exists != Some(spec.path_kind != "missing")
        || identity["original_path"].as_str() != Some(spec.target.as_str())
        || identity["path_kind"].as_str() != Some(spec.path_kind.as_str())
        || identity["resolved_path"].as_str() != Some(spec.resolved_path.as_str())
        || identity["symlink_target"].as_str().map(str::to_string) != spec.symlink_target
        || (exists == Some(true) && !original_sha256.as_deref().is_some_and(hex64))
        || (exists == Some(false) && !identity["original_sha256"].is_null())
    {
        return topology("Nginx checkpoint is invalid");
    }
    Ok(RouteIdentity {
        exists: exists.expect("checked"),
        original_path: spec.target.clone(),
        path_kind: spec.path_kind.clone(),
        resolved_path: spec.resolved_path.clone(),
        mode: mode.expect("checked") as u32,
        uid: uid.expect("checked") as u32,
        gid: gid.expect("checked") as u32,
        original_sha256,
        symlink_target: spec.symlink_target.clone(),
    })
}

fn owned_block_in_selected_map(content: &[u8], spec: &RouteSpec, ownership_id: &str) -> bool {
    let Ok(text) = std::str::from_utf8(content) else { return false };
    let Ok(topology) = parse_file_nginx(text) else { return false };
    let matches: Vec<&NginxMap> = topology
        .maps
        .iter()
        .filter(|mapping| mapping.variable == spec.variable && mapping.source_variable == "$ssl_preread_server_name")
        .collect();
    matches.len() == 1
        && remove_owned_map_block(&text.as_bytes()[matches[0].start..matches[0].end], &spec.routes, ownership_id)
            .is_ok()
}

fn action_specification(action: &Action) -> Result<RouteSpec> {
    if action.adapter != "nginx" || action.id != "nginx.routes" {
        return topology("Nginx action identity is invalid");
    }
    let mut values = BTreeMap::new();
    let mut routes = Vec::new();
    for mutation in &action.mutations {
        let Some((key, value)) = mutation.split_once('=') else { return topology("Nginx action is malformed") };
        if key == "route" {
            let Some((domain, backend)) = value.split_once(' ') else { return topology("Nginx action is malformed") };
            routes.push((domain.to_string(), backend.to_string()));
        } else if values.insert(key, value).is_some() {
            return topology("Nginx action is malformed");
        }
    }
    let stream_context = values.remove("stream_context").unwrap_or("present").to_string();
    let client_ip = values.remove("client_ip").unwrap_or("legacy").to_string();
    let panel_tls_backend = values.remove("panel_tls_backend").unwrap_or("127.0.0.1:8443").to_string();
    let required: BTreeSet<&str> =
        ["mode", "target", "variable", "path_kind", "resolved_path", "symlink_target"].into();
    if values.keys().copied().collect::<BTreeSet<_>>() != required
        || !["fresh", "coexist"].contains(&values["mode"])
        || !["legacy", "proxy"].contains(&client_ip.as_str())
        || (client_ip == "proxy" && values["mode"] != "fresh")
        || !loopback_tcp(&panel_tls_backend)
        || !["present", "create"].contains(&stream_context.as_str())
        || (stream_context == "create" && values["mode"] != "fresh")
        || !["missing", "file", "symlink"].contains(&values["path_kind"])
        || !(2..=12).contains(&routes.len())
        || routes.iter().map(|(domain, _)| domain).collect::<BTreeSet<_>>().len() != routes.len()
    {
        return topology("Nginx action is malformed");
    }
    let target = safe_host_path(values["target"])?;
    let resolved_path = safe_host_path(values["resolved_path"])?;
    if !variable(values["variable"]) {
        return topology("Nginx action is malformed");
    }
    let symlink_target = (values["symlink_target"] != "-").then(|| values["symlink_target"].to_string());
    if (values["path_kind"] == "symlink") != symlink_target.is_some()
        || symlink_target.as_ref().is_some_and(|target| target.is_empty() || target.contains('\0'))
        || (values["path_kind"] == "missing" && resolved_path != target)
        || routes.iter().any(|(domain, backend)| !valid_domain(domain) || !literal_backend(backend))
    {
        return topology("Nginx action is malformed");
    }
    Ok(RouteSpec {
        mode: values["mode"].into(),
        stream_context,
        target,
        variable: values["variable"].into(),
        path_kind: values["path_kind"].into(),
        resolved_path,
        symlink_target,
        routes,
        client_ip,
        panel_tls_backend,
    })
}

fn desired_content(spec: &RouteSpec, original: &[u8]) -> Result<Vec<u8>> {
    if spec.mode == "fresh" {
        if !original.is_empty() && original != render_fresh_spec(spec)? {
            return topology("fresh router path is already occupied");
        }
        return render_fresh_spec(spec);
    }
    let Ok(text) = std::str::from_utf8(original) else { return topology("selected route file is not UTF-8") };
    Ok(patch_owned_map(text, &spec.variable, &spec.routes, "nginx.routes")?.into_bytes())
}

fn loopback_tcp(value: &str) -> bool {
    value
        .strip_prefix("127.0.0.1:")
        .is_some_and(|port| !port.is_empty() && port.len() <= 5 && port.chars().all(|c| c.is_ascii_digit()))
}

fn client_ip_backend(backend: &str, panel_backend: &str) -> Result<String> {
    if backend == panel_backend {
        return Ok("unix:/run/proxy-control-panel-tls.sock".into());
    }
    if !loopback_tcp(backend) {
        return topology("fresh client-IP relay requires a loopback TCP backend");
    }
    Ok(format!("unix:/run/proxy-control-raw-{}.sock", backend.rsplit_once(':').expect("loopback port").1))
}

fn render_fresh_spec(spec: &RouteSpec) -> Result<Vec<u8>> {
    render_fresh(&spec.routes, &spec.client_ip, &spec.panel_tls_backend)
}

/// Render a fresh stream router. `client_ip` is `legacy` or `proxy`.
pub fn render_fresh(routes: &[(String, String)], client_ip: &str, panel_tls_backend: &str) -> Result<Vec<u8>> {
    if !["legacy", "proxy"].contains(&client_ip) || !loopback_tcp(panel_tls_backend) || routes.is_empty() {
        return topology("Nginx action is malformed");
    }
    let preserve = client_ip == "proxy";
    let mapped: Vec<(String, String)> = routes
        .iter()
        .map(|(domain, backend)| {
            Ok((
                domain.clone(),
                if preserve { client_ip_backend(backend, panel_tls_backend)? } else { backend.clone() },
            ))
        })
        .collect::<Result<_>>()?;
    let mut lines = vec![GENERATED_BEGIN.to_string(), "map $ssl_preread_server_name $proxy_control_backend {".into()];
    lines.extend(mapped.iter().map(|(domain, backend)| format!("    {domain} {backend};")));
    lines.push(if preserve {
        "    default unix:/run/proxy-control-panel-tls.sock;".into()
    } else {
        "    default 127.0.0.1:8443;".into()
    });
    lines.extend(["}".into(), "server {".into(), "    listen 443;".into(), "    ssl_preread on;".into()]);
    if preserve {
        lines.push("    proxy_protocol on;".into());
    }
    lines.extend(["    proxy_pass $proxy_control_backend;".into(), "}".into()]);
    if preserve {
        let mut seen = BTreeSet::new();
        for (_, backend) in routes.iter().filter(|(_, backend)| backend != panel_tls_backend) {
            if seen.insert(backend.clone()) {
                lines.extend([
                    "server {".into(),
                    format!("    listen {} proxy_protocol;", client_ip_backend(backend, panel_tls_backend)?),
                    format!("    proxy_pass {backend};"),
                    "}".into(),
                ]);
            }
        }
    }
    lines.extend([GENERATED_END.into(), String::new()]);
    Ok(lines.join("\n").into_bytes())
}

pub fn render_fresh_legacy(routes: &[(String, String)]) -> Result<Vec<u8>> {
    render_fresh(routes, "legacy", "127.0.0.1:8443")
}

pub fn render_fresh_current(routes: &[(String, String)], panel_tls_backend: &str) -> Result<Vec<u8>> {
    render_fresh(routes, "proxy", panel_tls_backend)
}

fn source_marker(text: &str, start: usize) -> Option<(String, usize)> {
    let rest = &text[start + "# configuration file ".len()..];
    if !rest.starts_with('/') {
        return None;
    }
    let colon = rest.find(':')?;
    let path = &rest[..colon];
    if path.contains(['\r', '\n']) {
        return None;
    }
    let after = start + "# configuration file ".len() + colon + 1;
    let end = if text[after..].starts_with("\r\n") {
        after + 2
    } else if text[after..].starts_with('\n') {
        after + 1
    } else if after == text.len() {
        after
    } else {
        return None;
    };
    Some((path.to_string(), end))
}

fn literal_backend(value: &str) -> bool {
    installer_core::nginx_topology::literal_backend(value)
}

pub(crate) fn sanitize_diagnostic(value: &str, max_chars: usize) -> String {
    let mut output = String::new();
    let mut index = 0;
    while index < value.len() {
        let rest = &value[index..];
        let lower = rest.to_lowercase();
        let keyword = ["password", "token", "secret"].into_iter().find(|keyword| lower.starts_with(keyword));
        if let Some(keyword) = keyword {
            let after = &rest[keyword.len()..];
            let separator_len = after
                .chars()
                .take_while(|c| matches!(c, '=' | ':' | ' ' | '\t' | '\r' | '\n') || c.is_whitespace())
                .map(char::len_utf8)
                .sum::<usize>();
            if separator_len > 0 {
                let credential = &after[separator_len..];
                let credential_len = credential
                    .chars()
                    .next()
                    .filter(|c| !c.is_whitespace())
                    .map(|_| credential.find(char::is_whitespace).unwrap_or(credential.len()))
                    .unwrap_or(0);
                if credential_len > 0 {
                    output.push_str(&rest[..keyword.len() + separator_len]);
                    output.push_str("[REDACTED]");
                    index += keyword.len() + separator_len + credential_len;
                    continue;
                }
            }
        }
        let character = rest.chars().next().expect("character");
        output.push(character);
        index += character.len_utf8();
    }
    let tail: String = output.chars().rev().take(max_chars).collect::<Vec<_>>().into_iter().rev().collect();
    tail.replace('\n', " ").trim().to_string()
}

pub(crate) fn safe_host_path(path: &str) -> Result<String> {
    if !path.starts_with('/')
        || path.contains('\0')
        || path.chars().any(char::is_whitespace)
        || Path::new(path).components().any(|component| component == Component::ParentDir)
    {
        return topology("Nginx route path must be a normalized absolute path");
    }
    let double = path.starts_with("//") && !path.starts_with("///");
    let normalized = format!("{}{}", if double { "//" } else { "/" }, posix_parts(path).join("/"));
    Ok(normalized)
}

pub(crate) fn valid_domain(domain: &str) -> bool {
    if !(4..=253).contains(&domain.len()) {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && labels[..labels.len() - 1].iter().all(|label| valid_domain_label(label, false))
        && valid_domain_label(labels[labels.len() - 1], true)
}

fn valid_domain_label(label: &str, final_label: bool) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && label.chars().next().is_some_and(|c| {
            if final_label {
                c.is_ascii_lowercase()
            } else {
                c.is_ascii_lowercase() || c.is_ascii_digit()
            }
        })
        && label.chars().next_back().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

pub(crate) fn effective_source_sections(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut markers = Vec::new();
    let mut line_start = 0;
    for line in text.split_inclusive('\n') {
        if line.starts_with("# configuration file ") {
            if let Some((path, end)) = source_marker(text, line_start) {
                markers.push((line_start, end, path));
            }
        }
        line_start += line.len();
    }
    if line_start < text.len() && text[line_start..].starts_with("# configuration file ") {
        if let Some((path, end)) = source_marker(text, line_start) {
            markers.push((line_start, end, path));
        }
    }
    let mut sections = BTreeMap::<String, Vec<String>>::new();
    for (index, (_, end, path)) in markers.iter().enumerate() {
        let section_end = markers.get(index + 1).map_or(text.len(), |(start, _, _)| *start);
        sections.entry(path.clone()).or_default().push(text[*end..section_end].to_string());
    }
    sections
}

fn has_stream_context(text: &str) -> bool {
    for (line_index, _) in text.match_indices('\n').map(|(index, _)| (index + 1, ())).chain(std::iter::once((0, ()))) {
        let mut cursor = line_index;
        while cursor < text.len() {
            let character = text[cursor..].chars().next().expect("character");
            if !character.is_whitespace() {
                break;
            }
            cursor += character.len_utf8();
        }
        if text[cursor..].starts_with("stream") {
            cursor += 6;
            while cursor < text.len() {
                let character = text[cursor..].chars().next().expect("character");
                if !character.is_whitespace() {
                    break;
                }
                cursor += character.len_utf8();
            }
            if text[cursor..].starts_with('{') {
                return true;
            }
        }
    }
    false
}

/// Add the stock stream context with an atomic, metadata-preserving write.
pub fn ensure_stream_context(config_path: &Path, router_path: &str) -> Result<bool> {
    let text = fs::read_to_string(config_path)?;
    if has_stream_context(&text) {
        return Ok(false);
    }
    let directory = Path::new(router_path).parent().expect("router path has a parent").display();
    let addition = format!("\n# Added by Proxy Control: the shared 443 router lives here.\nstream {{\n    include {directory}/*.conf;\n}}\n");
    let metadata = fs::metadata(config_path)?;
    atomic_write(
        config_path,
        format!("{}\n{addition}", text.trim_end_matches('\n')).as_bytes(),
        metadata.mode() & 0o7777,
        Some((metadata.uid(), metadata.gid())),
    )?;
    Ok(true)
}

pub(crate) fn reload_nginx(runner: &dyn HostRunner, limits: Bounded, message: &str) -> Result<bool> {
    let result = runner.bounded(&["systemctl", "reload", "nginx"], limits)?;
    if result.returncode == 0 {
        return Ok(false);
    }
    if runner.bounded(&["systemctl", "is-active", "nginx"], limits)?.returncode == 0 {
        let detail = sanitize_diagnostic(&format!("{}\n{}", result.stderr, result.stdout), 800);
        return topology(if detail.is_empty() { message.to_string() } else { format!("{message}: {detail}") });
    }
    let _ = runner.bounded(&["systemctl", "restart", "nginx"], limits)?;
    if runner.bounded(&["systemctl", "is-active", "nginx"], limits)?.returncode != 0 {
        return topology(format!("{message}: Nginx did not come back after a restart"));
    }
    Ok(true)
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

pub(crate) fn current_uid_gid() -> (u32, u32) {
    unsafe extern "C" {
        fn getuid() -> u32;
        fn getgid() -> u32;
    }
    // SAFETY: these libc getters have no preconditions.
    unsafe { (getuid(), getgid()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempDir;
    use pc_host::runner::{CallKind, RecordingRunner, Reply};
    use std::time::Duration;

    fn fixture(path: &str) -> String {
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden").join(path))
            .unwrap()
    }

    #[test]
    fn patch_owned_map_matches_python_goldens() {
        let vectors: Value = serde_json::from_str(&fixture("renders/nginx/patch-owned-map.json")).unwrap();
        let routes = vec![
            ("panel.example.com".into(), "127.0.0.1:8443".into()),
            ("relay.example.com".into(), "127.0.0.1:8445".into()),
        ];
        for (name, vector) in vectors.as_object().unwrap() {
            let input = vector["input"].as_str().unwrap();
            if let Some(output) = vector["output"].as_str() {
                let patched = patch_owned_map(input, "$sni_backend", &routes, "nginx.routes").unwrap();
                assert_eq!(patched, output, "{name}");
                assert_eq!(patch_owned_map(&patched, "$sni_backend", &routes, "nginx.routes").unwrap(), patched);
                assert_eq!(
                    remove_owned_map_block(patched.as_bytes(), &routes, "nginx.routes").unwrap(),
                    vector["removed"].as_str().unwrap().as_bytes()
                );
            } else {
                let message = patch_owned_map(input, "$sni_backend", &routes, "nginx.routes").unwrap_err().to_string();
                assert_eq!(format!("TopologyError: {message}"), vector["error"].as_str().unwrap(), "{name}");
            }
        }
    }

    #[test]
    fn fresh_renderers_match_python_goldens() {
        let spec: Value =
            serde_json::from_str(&fixture("renders/managed-three-xui-warp/nginx/specification.json")).unwrap();
        let routes: Vec<(String, String)> = spec["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| (route[0].as_str().unwrap().into(), route[1].as_str().unwrap().into()))
            .collect();
        assert_eq!(
            render_fresh_legacy(&routes).unwrap(),
            fixture("renders/managed-three-xui-warp/nginx/stream-router.legacy.conf").as_bytes()
        );
        assert_eq!(
            render_fresh_current(&routes, spec["panel_tls_backend"].as_str().unwrap()).unwrap(),
            fixture("renders/managed-three-xui-warp/nginx/stream-router.conf").as_bytes()
        );
    }

    #[test]
    fn ensure_stream_context_matches_goldens_atomically() {
        let vectors: Value = serde_json::from_str(&fixture("renders/nginx/ensure-stream-context.json")).unwrap();
        for (name, vector) in vectors.as_object().unwrap() {
            let dir = TempDir::new("stream-context");
            let path = dir.path().join("nginx.conf");
            fs::write(&path, vector["input"].as_str().unwrap()).unwrap();
            assert_eq!(
                ensure_stream_context(&path, DEFAULT_FRESH_PATH).unwrap(),
                vector["changed"].as_bool().unwrap(),
                "{name}"
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), vector["output"].as_str().unwrap(), "{name}");
        }
    }

    #[test]
    fn recording_runner_uses_nginx_bounds_and_recovers_reload() {
        let runner = RecordingRunner::new();
        runner.reply(&["systemctl", "reload", "nginx"], Reply::exit(1, "", "crash"));
        runner.reply_once(&["systemctl", "is-active", "nginx"], Reply::exit(3, "", ""));
        assert!(reload_nginx(&runner, Bounded::NGINX, "nginx reload failed").unwrap());
        assert_eq!(
            runner.argvs(),
            vec![
                vec!["systemctl", "reload", "nginx"],
                vec!["systemctl", "is-active", "nginx"],
                vec!["systemctl", "restart", "nginx"],
                vec!["systemctl", "is-active", "nginx"]
            ]
        );
        assert!(runner
            .calls()
            .iter()
            .all(|call| call.kind == CallKind::Bounded && call.timeout == Duration::from_secs(5)));
    }

    #[test]
    fn recording_runner_drives_fresh_nginx_lifecycle() {
        let dir = TempDir::new("nginx-lifecycle");
        let root = dir.path().to_path_buf();
        let config_path = root.join("etc/nginx/nginx.conf");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, "events {}\nhttp {}\n").unwrap();
        let responder_root = root.clone();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            if call.argv == ["nginx", "-T"] {
                let router = responder_root.join("etc/nginx/stream.d/proxy-control.conf");
                let config = fs::read_to_string(responder_root.join("etc/nginx/nginx.conf")).unwrap();
                let mut output = format!("# configuration file /etc/nginx/nginx.conf:\n{config}\n");
                if let Ok(content) = fs::read_to_string(router) {
                    output.push_str("# configuration file /etc/nginx/stream.d/proxy-control.conf:\n");
                    output.push_str(&content);
                    output.push('\n');
                }
                Some(Reply::ok(&output))
            } else {
                Some(Reply::ok(""))
            }
        }));
        let adapter =
            NginxAdapter::new(&AdapterContext { root: root.clone(), tree: root.clone(), runner: runner.clone() });
        let action = Action::new(
            "nginx.routes",
            "nginx",
            "proxy-control:nginx",
            vec![
                "mode=fresh".into(),
                "client_ip=proxy".into(),
                "panel_tls_backend=127.0.0.1:8443".into(),
                "stream_context=create".into(),
                "target=/etc/nginx/stream.d/proxy-control.conf".into(),
                "variable=$proxy_control_backend".into(),
                "path_kind=missing".into(),
                "resolved_path=/etc/nginx/stream.d/proxy-control.conf".into(),
                "symlink_target=-".into(),
                "route=relay.example.com 127.0.0.1:8445".into(),
                "route=panel.example.com 127.0.0.1:8443".into(),
            ],
            vec!["effective Nginx topology is observed and unambiguous".into()],
            vec!["Nginx configuration test passes before reload".into()],
            vec!["restore content, owner, group, mode, and symlink identity".into()],
            false,
        )
        .unwrap();
        let prepared = adapter.prepare(&action).unwrap();
        let applied = adapter.apply(&action, prepared).unwrap();
        assert!(root.join("etc/nginx/nginx.conf.proxy-control-backup").exists());
        assert!(fs::read_to_string(&config_path).unwrap().contains("stream {"));
        assert!(root.join("etc/nginx/stream.d/proxy-control.conf").is_file());
        assert_eq!(applied["ownership"]["/etc/nginx/stream.d/proxy-control.conf"]["sha256"], applied["owned_sha256"]);
        assert!(adapter.verify(&action).unwrap().success);
        assert!(adapter.rollback(&action, applied, false, RollbackTarget::RolledBack).unwrap().success);
        assert!(!root.join("etc/nginx/stream.d/proxy-control.conf").exists());
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "events {}\nhttp {}\n");
        assert!(!root.join("etc/nginx/nginx.conf.proxy-control-backup").exists());
        assert!(runner
            .calls()
            .iter()
            .all(|call| call.kind == CallKind::Bounded && call.timeout == Duration::from_secs(5)));
    }

    #[test]
    fn stream_context_failure_restores_config_and_removes_backup() {
        let dir = TempDir::new("stream-rollback");
        let config_path = dir.path().join("etc/nginx/nginx.conf");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, "events {}\nhttp {}\n").unwrap();
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(&["nginx", "-t"], Reply::exit(1, "", "bad stream"));
        let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
        let adapter = NginxAdapter::new(&context);
        let error = adapter.create_stream_context().unwrap_err();
        assert!(error.to_string().contains("adding the stream context left Nginx unable to start"));
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "events {}\nhttp {}\n");
        assert!(!dir.path().join("etc/nginx/nginx.conf.proxy-control-backup").exists());
    }
}

#[cfg(test)]
#[path = "nginx_smoke.rs"]
mod smoke;

#[cfg(test)]
#[path = "nginx_regressions.rs"]
mod regressions;
