//! Installer-owned version-agent: complete release tree, binary unit, mutable operator env.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::services::{compose_files, env_key, env_values, hex, mutations, tree_files, Host};
use super::AdapterContext;
use crate::adapter::Adapter;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::InstallerConfig;
use crate::planner::{compose_file_list, Action, AuditFacts, Evidence};
use pc_host::runner::{is_in_band_failure, Capture};
use serde_json::{json, Map, Value};

const PROJECT: &str = "/opt/mtproxy-shared443";
const CODE: &str = "/opt/proxy-control/version_agent";
const BINARY: &str = "bin/linux-amd64/proxy-control-version-agent";
const UNIT: &str = "/etc/systemd/system/version-agent.service";
const TMPFILES: &str = "/etc/tmpfiles.d/proxy-control-version-agent.conf";
const ENV: &str = "/etc/proxy-control/version-agent.env";
const CATALOG: &str = "/etc/proxy-control/versions.json";
const STATE_DIR: &str = "/var/lib/proxy-control/version-agent";
const STATE: &str = "/var/lib/proxy-control/version-agent/state.json";
const SOCKET: &str = "/run/proxy-control/version-agent.sock";
const MARKER: &str = "/etc/proxy-control/version-agent-owned";

pub struct VersionAgentAdapter {
    host: Host,
}
impl VersionAgentAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self { host: Host::new(context, "VersionAgentError", "version-agent") }
    }
    fn selection(&self, action: &Action) -> Result<BTreeMap<String, String>, Error> {
        let values = mutations(
            action,
            "version_agent",
            "proxy-control:version-agent",
            &["project", "agent-dir", "socket", "socket-gid", "compose-files", "router", "naive", "mieru", "upstream"],
            "VersionAgentError",
        )?;
        let files = compose_files(&values["compose-files"])
            .ok_or_else(|| self.host.error("version-agent action is invalid"))?;
        if values["project"] != PROJECT
            || values["agent-dir"] != "/opt/proxy-control"
            || values["socket"] != SOCKET
            || values["socket-gid"] != "10001"
            || values["upstream"] != "on"
            || ["router", "naive", "mieru"].iter().any(|k| !matches!(values[*k].as_str(), "on" | "off"))
            || [
                ("naive", "compose.naive.yaml"),
                ("mieru", "compose.mieru.yaml"),
                ("router", "compose.xray-router.yaml"),
            ]
            .iter()
            .any(|(k, f)| files.contains(f) != (values[*k] == "on"))
        {
            return Err(self.host.error("version-agent action is invalid"));
        }
        Ok(values)
    }
    pub fn env_text(&self, selected: &BTreeMap<String, String>, existing: &str) -> Result<String, Error> {
        let example = self.source_text("deploy/version-agent.env.example")?;
        let defaults = env_values(&example);
        let old = env_values(existing);
        let overrides = [
            ("PROXY_CONTROL_COMPOSE_DIR", PROJECT.to_owned()),
            ("PROXY_CONTROL_COMPOSE_FILES", selected["compose-files"].clone()),
            ("PROXY_CONTROL_XRAY_ROUTER", selected["router"].clone()),
            // Upstream checking is operator-owned once the file exists.
            (
                "PROXY_CONTROL_UPSTREAM_CHECK",
                old.get("PROXY_CONTROL_UPSTREAM_CHECK").cloned().unwrap_or_else(|| "on".into()),
            ),
            (
                "PROXY_CONTROL_CONSUMER_OVERLAYS",
                if selected["mieru"] == "on" {
                    old.get("PROXY_CONTROL_CONSUMER_OVERLAYS")
                        .or(defaults.get("PROXY_CONTROL_CONSUMER_OVERLAYS"))
                        .cloned()
                        .unwrap_or_default()
                } else {
                    String::new()
                },
            ),
            ("PROXY_CONTROL_VERSION_SOCKET", SOCKET.to_owned()),
            ("PROXY_CONTROL_VERSION_SOCKET_GID", "10001".into()),
            // Catalog/state are operator-selected; only a fresh env gets these defaults.
            (
                "PROXY_CONTROL_VERSION_CATALOG",
                old.get("PROXY_CONTROL_VERSION_CATALOG").cloned().unwrap_or_else(|| CATALOG.into()),
            ),
            (
                "PROXY_CONTROL_VERSION_STATE",
                old.get("PROXY_CONTROL_VERSION_STATE").cloned().unwrap_or_else(|| STATE.into()),
            ),
        ];
        let overrides: BTreeMap<_, _> = overrides.into_iter().collect();
        let mut seen = BTreeSet::new();
        let mut rendered = Vec::new();
        for line in example.lines() {
            if let Some(key) = env_key(line) {
                if !seen.insert(key.to_owned()) {
                    continue;
                }
                if let Some(value) = overrides.get(key).or_else(|| old.get(key)) {
                    rendered.push(format!("{key}={value}"));
                } else {
                    rendered.push(line.into());
                }
            } else {
                rendered.push(line.into());
            }
        }
        // Match the Python insertion order for missing installer-controlled keys.
        for key in [
            "PROXY_CONTROL_COMPOSE_DIR",
            "PROXY_CONTROL_COMPOSE_FILES",
            "PROXY_CONTROL_XRAY_ROUTER",
            "PROXY_CONTROL_UPSTREAM_CHECK",
            "PROXY_CONTROL_CONSUMER_OVERLAYS",
            "PROXY_CONTROL_VERSION_SOCKET",
            "PROXY_CONTROL_VERSION_SOCKET_GID",
            "PROXY_CONTROL_VERSION_CATALOG",
            "PROXY_CONTROL_VERSION_STATE",
        ] {
            if seen.insert(key.into()) {
                rendered.push(format!("{key}={}", overrides[key]));
            }
        }
        for line in existing.lines() {
            if let Some(key) = env_key(line) {
                if seen.insert(key.into()) {
                    rendered.push(line.into());
                }
            }
        }
        Ok(rendered.join("\n") + "\n")
    }
    fn source_text(&self, relative: &str) -> Result<String, Error> {
        let path = self.host.context.tree.join(relative);
        if fs::symlink_metadata(&path).map_or(true, |m| !m.is_file()) {
            return Err(self.host.error("installer source generation is incomplete"));
        }
        Ok(fs::read_to_string(path)?)
    }
    fn install_code(&self, data: &CheckpointData) -> Result<(), Error> {
        let source = self.host.context.tree.join("version_agent");
        let files = tree_files(&source)?;
        if !files.contains_key(BINARY) || fs::metadata(&files[BINARY])?.mode() & 0o111 == 0 {
            return Err(self.host.error("installer source generation has no executable version-agent binary"));
        }
        let destination = self.host.path(CODE)?;
        let before = tree_files(&destination)?;
        let owned = data["ownership"].as_object().unwrap();
        for (name, path) in before {
            if files.contains_key(&name) {
                continue;
            }
            let key = format!("{CODE}/{name}");
            if owned.contains_key(&key) || name.split('/').any(|p| p == "__pycache__") || name.ends_with(".pyc") {
                pc_host::fs::durable_remove(&path, false)?;
            } else {
                return Err(self.host.error(format!("foreign file in version-agent code directory: {name}")));
            }
        }
        pc_host::fs::durable_mkdir(&destination, 0o755)?;
        for (name, path) in files {
            let absolute = format!("{CODE}/{name}");
            self.host.write(&absolute, &fs::read(&path)?, fs::metadata(path)?.mode() & 0o777)?;
        }
        pc_host::fs::fsync_tree(&destination)?;
        Ok(())
    }
    fn ownership(&self) -> Result<Value, Error> {
        let mut owned = self.host.ownership(&[UNIT, TMPFILES, MARKER])?;
        owned.insert(ENV.into(), json!({"sha256":self.host.digest(ENV)?,"mutable":true}));
        for (name, path) in tree_files(&self.host.path(CODE)?)? {
            owned.insert(format!("{CODE}/{name}"), json!(pc_host::fs::sha256_file(&path)?));
        }
        Ok(Value::Object(owned))
    }
    fn binary_digest(&self, absolute: &str, label: &str) -> Result<String, Error> {
        if !self.host.path(absolute)?.is_file() {
            return Err(self
                .host
                .error(format!("the installed {label} is missing; the version-agent state cannot record it")));
        }
        self.host.digest(absolute)
    }
    fn installed_components(&self, selected: &BTreeMap<String, String>) -> Result<Value, Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let compose = self.source_text("compose.yaml")?;
        let mut inside = false;
        let mut image = None;
        for line in compose.lines() {
            if line.starts_with("  ") && !line.starts_with("   ") && line.trim().ends_with(':') {
                inside = line.trim() == "mtproxy:";
            } else if inside {
                if let Some(("image", value)) = line.trim().split_once(':') {
                    image = Some(value.trim().trim_matches(['\'', '"']).to_owned());
                    break;
                }
            }
        }
        let image = image.ok_or_else(|| self.host.error("compose.yaml names no Telemt image"))?;
        let digest = image
            .rsplit_once("@sha256:")
            .map(|(_, d)| d)
            .filter(|d| hex(d, 64))
            .ok_or_else(|| self.host.error("compose.yaml does not pin the Telemt image by digest"))?;
        let mut components = Map::new();
        components.insert("telemt".into(), json!({"version":format!("sha256:{}", &digest[..12]),"kind":"image","source":"catalog","image":image,"updated_at":now}));
        if selected["naive"] == "on" {
            let pin = self.host.path("/etc/proxy-control/caddy-naive.pin")?;
            let runtime = if pin.is_file() { fs::read_to_string(pin)?.trim().to_owned() } else { String::new() };
            components.insert("naive".into(), json!({"version":"2.11.7","kind":"build","source":"catalog","sha256":self.binary_digest("/usr/local/bin/caddy","caddy")?,"runtime_version":if runtime.is_empty(){"v2.11.7 h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4=".to_owned()}else{runtime},"updated_at":now}));
        }
        if selected["mieru"] == "on" {
            components.insert("mita".into(), json!({"version":"3.38.1","kind":"binary","source":"catalog","sha256":self.binary_digest("/usr/bin/mita","mita")?,"updated_at":now}));
        }
        if selected["router"] == "on" {
            let members: BTreeMap<_, _> = ["xray", "geoip.dat", "geosite.dat"]
                .into_iter()
                .map(|name| {
                    Ok((name, self.binary_digest(&format!("/usr/local/lib/proxy-control/xray-router/{name}"), name)?))
                })
                .collect::<Result<_, Error>>()?;
            components.insert("xray".into(), json!({"version":"26.10.17","kind":"binary","source":"catalog","sha256":"ecdd54eccd24c4c21a8f00968e7dbf7f5996da92383d2321170b560dc4a95158","members":members,"updated_at":now}));
        }
        Ok(Value::Object(components))
    }
    fn agent_json(&self, endpoint: &str) -> Result<Value, Error> {
        let url = format!("http://version-agent{endpoint}");
        let output = self.host.capture(
            &["curl", "--fail", "--silent", "--show-error", "--max-time", "5", "--unix-socket", SOCKET, &url],
            1_048_576,
            Capture::VERSION_AGENT,
        );
        if is_in_band_failure(&output) {
            return Err(self.host.error(format!("the version-agent did not answer {endpoint}")));
        }
        let value: Value = serde_json::from_str(&output)
            .map_err(|_| self.host.error(format!("the version-agent answer to {endpoint} is not JSON")))?;
        if !value.is_object() {
            return Err(self.host.error(format!("the version-agent answer to {endpoint} is not an object")));
        }
        Ok(value)
    }
    fn healthy(value: &Value) -> bool {
        value.get("status").and_then(Value::as_str) == Some("ok")
            && value.get("implementation").is_none_or(|v| v == "rust")
    }
    fn wait_healthy(&self) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.agent_json("/v1/health").is_ok_and(|v| Self::healthy(&v)) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(self.host.error("the version-agent did not answer /v1/health within 30 seconds"));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    fn teardown(&self, action: &Action, data: CheckpointData, purge: bool, reconcile: bool) -> Result<Evidence, Error> {
        self.selection(action)?;
        self.host.checkpoint(action, &data)?;
        self.host.marker(MARKER, &data, reconcile)?;
        if self.host.path(UNIT)?.exists() {
            self.host.run(&["systemctl", "disable", "--now", "version-agent"])?;
        }
        // A complete tree is owned, but never remove unexpected files from a partially migrated tree.
        let source = tree_files(&self.host.context.tree.join("version_agent"))?;
        let owned = data["ownership"].as_object().unwrap();
        let code = self.host.path(CODE)?;
        for (name, _) in tree_files(&code)? {
            if !source.contains_key(&name)
                && !owned.contains_key(&format!("{CODE}/{name}"))
                && !name.split('/').any(|p| p == "__pycache__")
                && !name.ends_with(".pyc")
            {
                return Err(self.host.error(format!("foreign file in version-agent code directory: {name}")));
            }
        }
        for path in [UNIT, TMPFILES, ENV, SOCKET, CODE] {
            self.host.remove(path)?;
        }
        let parent = self.host.path("/opt/proxy-control")?;
        if parent.is_dir() && fs::read_dir(&parent)?.next().is_none() {
            pc_host::fs::durable_remove(&parent, false)?;
        }
        if purge {
            self.host.remove(STATE_DIR)?;
            self.host.remove(CATALOG)?;
        }
        self.host.remove(MARKER)?;
        self.host.run(&["systemctl", "daemon-reload"])?;
        let mut evidence = Evidence::ok(&action.id, &["the version-agent unit, code, env and marker were removed"])?;
        evidence.details.insert("persistent_data_preserved".into(), json!(!purge));
        Ok(evidence)
    }
}
impl Adapter for VersionAgentAdapter {
    fn name(&self) -> &str {
        "version_agent"
    }
    fn plan(&self, config: &InstallerConfig, _: &AuditFacts) -> Result<Vec<Action>, Error> {
        let flag = |v| if v { "on" } else { "off" };
        Ok(vec![Action::new(
            "version_agent.runtime",
            self.name(),
            "proxy-control:version-agent",
            vec![
                format!("project={PROJECT}"),
                "agent-dir=/opt/proxy-control".into(),
                format!("socket={SOCKET}"),
                "socket-gid=10001".into(),
                format!("compose-files={}", compose_file_list(config).join(":")),
                format!("router={}", flag(config.effective_egress().router)),
                format!("naive={}", flag(config.profile.includes_naive())),
                format!("mieru={}", flag(config.profile.includes_mieru())),
                "upstream=on".into(),
            ],
            vec![
                "the Core runtime is verified".into(),
                "no foreign version-agent unit, env or code directory exists without the ownership marker".into(),
            ],
            vec![
                "the version-agent unit is active and enabled".into(),
                "/v1/health answers ok over the group-10001 socket".into(),
                "/v1/versions lists the profile's components at the versions the installer recorded".into(),
                "the env names the profile's Compose overlays and the router flag".into(),
            ],
            vec![
                "disable the unit and remove only the owned unit, tmpfiles, env, code and marker".into(),
                "preserve the catalog and the agent state unless purge is explicit".into(),
            ],
            false,
        )?])
    }
    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        self.selection(action)?;
        self.host.prepare(action, MARKER, &[UNIT, CODE])
    }
    fn apply(&self, action: &Action, mut data: CheckpointData) -> Result<CheckpointData, Error> {
        let selected = self.selection(action)?;
        self.host.checkpoint(action, &data)?;
        self.host.claim(MARKER, &data)?;
        let active = self.host.capture(&["systemctl", "is-active", "version-agent"], 64, Capture::VERSION_AGENT).trim()
            == "active";
        self.install_code(&data)?;
        let unit = self.source_text("deploy/version-agent.service")?;
        let unit =
            unit.replace("ExecStart=/usr/bin/python3 -m version_agent.server", &format!("ExecStart={CODE}/{BINARY}"));
        if !unit.lines().any(|l| l == format!("ExecStart={CODE}/{BINARY}")) {
            return Err(self.host.error("version-agent unit does not execute the release binary"));
        }
        self.host.write(UNIT, unit.as_bytes(), 0o644)?;
        self.host.write(
            TMPFILES,
            self.source_text("deploy/proxy-control-version-agent.tmpfiles.conf")?.as_bytes(),
            0o644,
        )?;
        let existing = if self.host.path(ENV)?.exists() { self.host.text(ENV)? } else { String::new() };
        self.host.write(ENV, self.env_text(&selected, &existing)?.as_bytes(), 0o600)?;
        if !self.host.path(CATALOG)?.exists() {
            self.host.write(CATALOG, b"{\n  \"schema\": 1,\n  \"components\": {}\n}\n", 0o600)?;
        }
        if !self.host.path(STATE)?.exists() {
            let dir = self.host.path(STATE_DIR)?;
            pc_host::fs::durable_mkdir(&dir, 0o700)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            self.host.write(
                STATE,
                pc_host::json::pretty2(&json!({"schema":2,"components":self.installed_components(&selected)?}))
                    .as_bytes(),
                0o600,
            )?;
        }
        self.host.run(&["systemctl", "daemon-reload"])?;
        self.host.run(&["systemd-tmpfiles", "--create", TMPFILES])?;
        self.host.run(&["systemctl", "enable", "--now", "version-agent"])?;
        if active {
            self.host.run(&["systemctl", "restart", "version-agent"])?;
        }
        self.wait_healthy()?;
        data.insert("ownership".into(), self.ownership()?);
        Ok(data)
    }
    fn reconcile_apply(&self, action: &Action, data: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, data)
    }
    fn repair(&self, action: &Action, data: CheckpointData) -> Result<CheckpointData, Error> {
        self.host.checkpoint(action, &data)?;
        self.host.marker(MARKER, &data, false)?;
        self.apply(action, data)
    }
    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let selected = self.selection(action)?;
        for (check, expected) in [("is-active", "active"), ("is-enabled", "enabled")] {
            if self.host.capture(&["systemctl", check, "version-agent"], 64, Capture::VERSION_AGENT).trim() != expected
            {
                return Err(self.host.error("the version-agent unit is not active and enabled"));
            }
        }
        let info = fs::symlink_metadata(self.host.path(SOCKET)?)
            .map_err(|_| self.host.error("the version-agent socket is absent"))?;
        use std::os::unix::fs::FileTypeExt;
        if !info.file_type().is_socket() || info.mode() & 0o777 != 0o660 {
            return Err(self.host.error("the version-agent socket is not a 0660 socket"));
        }
        if self.host.context.root == std::path::Path::new("/") && info.gid() != 10001 {
            return Err(self.host.error("the version-agent socket is not group 10001"));
        }
        if !Self::healthy(&self.agent_json("/v1/health")?) {
            return Err(self.host.error("the version-agent did not answer /v1/health with ok"));
        }
        let versions = self.agent_json("/v1/versions")?;
        if versions["enabled"] != true {
            return Err(self.host.error("the version-agent reports itself not enabled"));
        }
        let listed = versions["components"]
            .as_object()
            .ok_or_else(|| self.host.error("the version-agent lists no components"))?;
        let env = pc_host::envfile::read(&self.host.path(ENV)?)?;
        let state_path = env.get("PROXY_CONTROL_VERSION_STATE").map_or(STATE, String::as_str);
        let recorded: Value = serde_json::from_str(&self.host.text(state_path)?)
            .map_err(|_| self.host.error("the version-agent state is unreadable"))?;
        let recorded =
            recorded["components"].as_object().ok_or_else(|| self.host.error("the version-agent state is invalid"))?;
        let mut current = Map::new();
        for name in ["telemt", "naive", "mita", "xray"] {
            if name != "telemt"
                && selected[match name {
                    "mita" => "mieru",
                    "xray" => "router",
                    _ => name,
                }] != "on"
            {
                continue;
            }
            let entry = listed
                .get(name)
                .filter(|v| v.is_object())
                .ok_or_else(|| self.host.error(format!("the version-agent does not list the {name} component")))?;
            if entry.get("current").unwrap_or(&Value::Null)
                != recorded.get(name).and_then(|v| v.get("version")).unwrap_or(&Value::Null)
            {
                return Err(self
                    .host
                    .error(format!("the version-agent reports {name} at a version the state does not record")));
            }
            current.insert(name.into(), entry.get("current").cloned().unwrap_or(Value::Null));
        }
        for (key, value) in [
            ("PROXY_CONTROL_COMPOSE_FILES", &selected["compose-files"]),
            ("PROXY_CONTROL_XRAY_ROUTER", &selected["router"]),
        ] {
            if env.get(key) != Some(value) {
                return Err(self.host.error(format!("the version-agent env does not set {key} as planned")));
            }
        }
        let mut evidence = Evidence::ok(
            &action.id,
            &[
                "the version-agent is active, enabled and healthy over its socket",
                "it lists the profile's components at the recorded versions",
            ],
        )?;
        evidence.details.insert("components".into(), Value::Object(current));
        Ok(evidence)
    }
    fn rollback(
        &self,
        action: &Action,
        data: CheckpointData,
        purge: bool,
        _: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.teardown(action, data, purge, false)
    }
    fn reconcile_rollback(
        &self,
        action: &Action,
        data: CheckpointData,
        purge: bool,
        _: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.teardown(action, data, purge, true)
    }
}
