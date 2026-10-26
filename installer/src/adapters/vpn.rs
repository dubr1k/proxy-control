//! Shared host ownership mechanics for the two host-network VPN managers.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use installer_core::planner::{Action, Evidence};
use pc_host::fs::{atomic_write, durable_mkdir, durable_remove, sha256_file, token_hex};
use pc_host::runner::{is_in_band_failure, Capture, RunOptions};
use serde_json::{json, Map, Value};

use super::AdapterContext;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};

pub(super) const PROJECT: &str = "/opt/mtproxy-shared443";
pub(super) const SYSCTL: &str = "/etc/sysctl.d/99-proxy-control-amneziawg.conf";
pub(super) const SYSCTL_TEXT: &str = "# Managed by Proxy Control (AmneziaWG): the tunnels forward clients' packets to the Internet.\nnet.ipv4.ip_forward = 1\n";
pub(super) const OVERRIDE: &str = "version-overrides/compose.versions.yaml";

#[derive(Clone)]
pub(super) struct Runtime {
    pub context: AdapterContext,
    pub awg: bool,
}
impl Runtime {
    pub fn name(&self) -> &'static str {
        if self.awg {
            "amneziawg"
        } else {
            "trusttunnel"
        }
    }
    pub fn title(&self) -> &'static str {
        if self.awg {
            "AmneziaWG"
        } else {
            "TrustTunnel"
        }
    }
    pub fn service(&self) -> &'static str {
        if self.awg {
            "awg-manager"
        } else {
            "trusttunnel-manager"
        }
    }
    pub fn container(&self) -> String {
        format!("proxy-control-{}", self.service())
    }
    pub fn state(&self) -> String {
        format!("/var/lib/{}", self.service())
    }
    pub fn marker(&self) -> String {
        format!("/etc/proxy-control/{}-owned", self.name())
    }
    pub fn token(&self) -> String {
        format!("{PROJECT}/secrets/{}-token", self.service())
    }
    pub fn env(&self) -> String {
        format!("{PROJECT}/.env.{}", self.name())
    }
    pub fn error(&self, text: impl Into<String>) -> Error {
        Error::other(if self.awg { "AmneziaWgError" } else { "TrustTunnelError" }, text)
    }
    pub fn invalid(&self) -> Error {
        self.error(format!("{} action is invalid", self.title()))
    }
    pub fn host(&self, absolute: &str) -> Result<PathBuf, Error> {
        if !absolute.starts_with('/') || absolute.split('/').any(|p| p == "..") {
            return Err(self.error(format!("{} host path is unsafe", self.title())));
        }
        let root = &self.context.root;
        if root.is_symlink() || !root.is_dir() {
            return Err(self.error(format!("{} root is unsafe", self.title())));
        }
        let mut cursor = root.clone();
        let parts: Vec<_> = absolute.trim_start_matches('/').split('/').collect();
        for part in &parts[..parts.len().saturating_sub(1)] {
            cursor.push(part);
            if cursor.is_symlink() || (cursor.exists() && !cursor.is_dir()) {
                return Err(self.error(format!("{} host path crosses an unsafe parent", self.title())));
            }
        }
        Ok(root.join(absolute.trim_start_matches('/')))
    }
    pub fn write(&self, absolute: &str, bytes: &[u8], mode: u32) -> Result<(), Error> {
        let path = self.host(absolute)?;
        let owner = if self.context.root == std::path::Path::new("/") && unsafe { libc::geteuid() } == 0 {
            Some((0, 0))
        } else {
            None
        };
        atomic_write(&path, bytes, mode, owner)?;
        Ok(())
    }
    pub fn run(&self, argv: &[&str]) -> Result<(), Error> {
        let output = self.context.runner.run(argv, &RunOptions::default()).map_err(Error::from).map_err(|e| {
            if e.is_fatal() {
                e
            } else {
                self.command_error(argv)
            }
        })?;
        if output.returncode != 0 {
            return Err(self.command_error(argv));
        }
        Ok(())
    }
    fn command_error(&self, argv: &[&str]) -> Error {
        let mut label = argv
            .first()
            .and_then(|p| std::path::Path::new(p).file_name())
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        for arg in argv.iter().skip(1).take(2) {
            if arg.starts_with('-') || arg.contains('/') {
                break;
            }
            label.push(' ');
            label.push_str(arg);
        }
        self.error(format!("{} command failed: {label}", self.title()))
    }
    pub fn capture(&self, argv: &[&str], limit: usize) -> String {
        self.context.runner.capture(argv, limit, Capture::CORE)
    }
    pub fn present(&self) -> bool {
        ["proxy_panel_by_dubr1k", "mtproxy"].iter().any(|project| {
            let output = self.capture(
                &[
                    "docker",
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    &format!("label=com.docker.compose.project={project}"),
                    "--filter",
                    &format!("label=com.docker.compose.service={}", self.service()),
                ],
                512,
            );
            !output.trim().is_empty() && !is_in_band_failure(output.trim())
        })
    }
    pub fn compose(&self, args: &[&str]) -> Result<(), Error> {
        let mut envs = vec![format!("{PROJECT}/.env")];
        let mut files = vec![format!("{PROJECT}/compose.yaml")];
        for sibling in ["naive", "mieru", "xray-router", "amneziawg", "trusttunnel"] {
            if sibling != self.name() && self.host(&format!("{PROJECT}/.env.{sibling}"))?.is_file() {
                envs.push(format!("{PROJECT}/.env.{sibling}"));
                files.push(format!("{PROJECT}/compose.{sibling}.yaml"));
            }
        }
        envs.push(self.env());
        files.push(format!("{PROJECT}/compose.{}.yaml", self.name()));
        if self.host(&format!("{PROJECT}/{OVERRIDE}"))?.is_file() {
            files.push(format!("{PROJECT}/{OVERRIDE}"));
        }
        let mut argv = vec!["docker".into(), "compose".into(), "--project-directory".into(), PROJECT.into()];
        for env in envs {
            argv.extend(["--env-file".into(), env]);
        }
        for file in files {
            argv.extend(["-f".into(), file]);
        }
        argv.extend(args.iter().map(|s| s.to_string()));
        self.run(&argv.iter().map(String::as_str).collect::<Vec<_>>())
    }
    pub fn values<'a>(&self, action: &'a Action, keys: &[&str]) -> Result<BTreeMap<&'a str, &'a str>, Error> {
        if action.id != format!("{}.runtime", self.name())
            || action.adapter != self.name()
            || action.owner != format!("proxy-control:{}", self.name())
        {
            return Err(self.invalid());
        }
        let mut values = BTreeMap::new();
        for item in &action.mutations {
            let (k, v) = item.split_once('=').ok_or_else(|| self.invalid())?;
            if values.insert(k, v).is_some() {
                return Err(self.invalid());
            }
        }
        if values.keys().copied().collect::<BTreeSet<_>>() != keys.iter().copied().collect() {
            return Err(self.invalid());
        }
        if values["project"] != PROJECT
            || values["state-dir"] != self.state()
            || values["container"] != self.container()
            || values["socket-gid"] != if self.awg { "10007" } else { "10008" }
        {
            return Err(self.invalid());
        }
        Ok(values)
    }
    pub fn tun(&self) -> Result<(), Error> {
        if !self.host("/dev/net/tun")?.exists() {
            return Err(self.error("/dev/net/tun is missing on the host"));
        }
        Ok(())
    }
    pub fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        if self.awg {
            self.tun()?;
        }
        let marker = self.host(&self.marker())?;
        let recovery = marker.is_file() && !marker.is_symlink();
        if !recovery && self.present() {
            return Err(
                self.error(format!("an active {} service requires a proven owned recovery generation", self.service()))
            );
        }
        if self.awg && !recovery {
            let path = self.host(SYSCTL)?;
            if (path.exists() || path.is_symlink())
                && (path.is_symlink() || !path.is_file() || fs::read_to_string(&path)? != SYSCTL_TEXT)
            {
                return Err(self.error(format!("a foreign file occupies {SYSCTL}")));
            }
        }
        let mut data=json!({"owner":action.owner,"adoption":if recovery {"recovery"}else{"absent"},"marker_value":if recovery {None}else{Some(token_hex::<16>())},"state_preexisting":self.host(&self.state())?.is_dir(),"token_preexisting":self.host(&self.token())?.is_file(),"ownership":{}}).as_object().unwrap().clone();
        if self.awg {
            data.insert("sysctl_preexisting".into(), json!(self.host(SYSCTL)?.is_file()));
            let previous = self.capture(&["sysctl", "-n", "net.ipv4.ip_forward"], 64);
            let previous = previous.trim();
            if !["0", "1"].contains(&previous) {
                return Err(self.error("the previous IPv4 forwarding value is unavailable"));
            }
            data.insert("ip_forward_previous".into(), json!(previous));
        }
        Ok(data)
    }
    pub fn checkpoint(&self, action: &Action, data: &CheckpointData, applied: bool) -> Result<(), Error> {
        let invalid = || self.error(format!("{} checkpoint is invalid", self.title()));
        let mut keys = BTreeSet::from([
            "owner",
            "adoption",
            "marker_value",
            "state_preexisting",
            "token_preexisting",
            "ownership",
        ]);
        if self.awg {
            keys.insert("sysctl_preexisting");
            if data.contains_key("ip_forward_previous") {
                keys.insert("ip_forward_previous");
            }
        }
        if data.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys
            || data.get("owner") != Some(&json!(action.owner))
        {
            return Err(invalid());
        }
        let marker = &data["marker_value"];
        match data["adoption"].as_str() {
            Some("absent") if marker.as_str().is_some_and(|s| hex(s, 32)) => {}
            Some("recovery") if marker.is_null() => {}
            _ => return Err(invalid()),
        }
        if data["ownership"].as_object().is_none_or(|m| !applied && !m.is_empty())
            || ["state_preexisting", "token_preexisting"].iter().any(|k| !data[*k].is_boolean())
            || (self.awg && !data["sysctl_preexisting"].is_boolean())
        {
            return Err(invalid());
        }
        if let Some(value) = data.get("ip_forward_previous") {
            if !matches!(value.as_str(), Some("0" | "1")) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn certificate(&self, hostname: &str) -> Result<(), Error> {
        let path = self.host(&format!("/etc/letsencrypt/live/{hostname}"))?;
        if !path.join("fullchain.pem").is_file() || !path.join("privkey.pem").is_file() {
            return Err(self.error(format!(
                "the certificate for {hostname} is missing: the certificates step must issue it first"
            )));
        }
        Ok(())
    }
    fn state_dir(&self) -> Result<(), Error> {
        let path = self.host(&self.state())?;
        if path.is_symlink() || (path.exists() && !path.is_dir()) {
            return Err(self.error(if self.awg {
                "AmneziaWG state path is occupied"
            } else {
                "TrustTunnel directory path is occupied"
            }));
        }
        durable_mkdir(path.parent().unwrap(), 0o755)?;
        durable_mkdir(&path, 0o700)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        if self.context.root == std::path::Path::new("/") && unsafe { libc::geteuid() } == 0 {
            let p = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| self.invalid())?;
            if unsafe { libc::chown(p.as_ptr(), 0, 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
    fn write_token(&self) -> Result<(), Error> {
        let token = self.host(&self.token())?;
        durable_mkdir(token.parent().unwrap(), 0o700)?;
        if !token.exists() && !token.is_symlink() {
            self.write(&self.token(), format!("{}\n", token_hex::<32>()).as_bytes(), 0o600)?;
        }
        if token.is_symlink() || !token.is_file() {
            return Err(self.error(format!("pre-existing {} secret is unsafe", self.title())));
        }
        let meta = token.metadata()?;
        if meta.mode() & 0o077 != 0 || (self.context.root == std::path::Path::new("/") && meta.uid() != 0) {
            return Err(self.error(format!("pre-existing {} secret is unsafe", self.title())));
        }
        if !(32..=512).contains(&fs::read_to_string(token)?.trim().chars().count()) {
            return Err(self.error(format!("the {} manager secret is malformed", self.title())));
        }
        Ok(())
    }
    pub fn apply(
        &self,
        action: &Action,
        mut data: CheckpointData,
        env: &str,
        hostname: Option<&str>,
        repair: bool,
    ) -> Result<CheckpointData, Error> {
        self.checkpoint(action, &data, repair)?;
        if self.awg {
            self.tun()?;
            self.write(SYSCTL, SYSCTL_TEXT.as_bytes(), 0o644)?;
            self.run(&["sysctl", "-p", SYSCTL])?;
        }
        self.state_dir()?;
        if let Some(host) = hostname {
            self.certificate(host)?;
        }
        self.write_token()?;
        self.write(&self.env(), env.as_bytes(), 0o600)?;
        if !repair {
            if let Some(marker) = data["marker_value"].as_str() {
                self.write(&self.marker(), format!("{marker}\n").as_bytes(), 0o600)?;
            }
        }
        self.compose(if repair { &["up", "-d", "--wait"] } else { &["up", "-d", "--build", "--wait"] })?;
        let mut ownership = Map::new();
        let mut paths = vec![self.env(), self.marker()];
        if self.awg {
            paths.push(SYSCTL.into());
        }
        for absolute in paths {
            let path = self.host(&absolute)?;
            if path.is_file() {
                ownership.insert(absolute, json!(sha256_file(&path)?));
            }
        }
        data.insert("ownership".into(), Value::Object(ownership));
        Ok(data)
    }
    pub fn health(&self) -> Result<Value, Error> {
        let container = self.container();
        let health = self.capture(
            &[
                "docker",
                "inspect",
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                &container,
            ],
            64,
        );
        if health.trim() != "healthy" {
            return Err(self.error(format!("the {} container is not healthy", self.service())));
        }
        let binary = format!("/usr/local/bin/{}", self.service());
        let output = self
            .context
            .runner
            .capture_checked(&["docker", "exec", &container, &binary, "health"], pc_host::runner::QUERY_TIMEOUT)
            .map_err(|error| self.error(error.to_string()))?;
        let report: Value = serde_json::from_str(&output)
            .map_err(|_| self.error(format!("{} manager health is not JSON", self.title())))?;
        if !report.is_object() {
            return Err(self.error(format!("{} manager health is not an object", self.title())));
        }
        Ok(report)
    }
    pub fn listener(&self, port: u16) -> bool {
        let output =
            self.capture(&["ss", "-H", if self.awg { "-lun" } else { "-ltn" }, &format!("sport = :{port}")], 4096);
        !is_in_band_failure(&output) && output.lines().any(|line| line.split_whitespace().count() >= 4)
    }
    pub fn verify_state(&self) -> Result<(), Error> {
        let path = self.host(&self.state())?;
        if path.is_symlink() || !path.is_dir() {
            return Err(self.error(format!("the {} state directory is missing", self.title())));
        }
        Ok(())
    }
    pub fn rollback(
        &self,
        action: &Action,
        data: CheckpointData,
        purge: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.checkpoint(action, &data, true)?;
        let destructive = target == RollbackTarget::Uninstalled && purge;
        if self.present() {
            self.compose(&["rm", "--stop", "--force", self.service()])?;
        }
        for absolute in [self.env(), self.marker()] {
            durable_remove(&self.host(&absolute)?, true)?;
        }
        if self.awg {
            // Old Python checkpoints do not know the original value: never guess and disable a host's forwarding.
            if let Some(previous) = data.get("ip_forward_previous").and_then(Value::as_str) {
                self.run(&["sysctl", "-w", &format!("net.ipv4.ip_forward={previous}")])?;
            }
            if data["sysctl_preexisting"] != true {
                durable_remove(&self.host(SYSCTL)?, true)?;
            }
        }
        let path = self.host(&format!("{PROJECT}/{OVERRIDE}"))?;
        if path.is_file() && !path.is_symlink() {
            let text = fs::read_to_string(&path)?;
            let filtered = without_override_service(&text, self.service());
            if filtered != text {
                self.write(&format!("{PROJECT}/{OVERRIDE}"), filtered.as_bytes(), 0o640)?;
            }
        }
        let state = self.host(&self.state())?;
        if state.is_dir()
            && !state.is_symlink()
            && (destructive || (data["state_preexisting"] == false && fs::read_dir(&state)?.next().is_none()))
        {
            durable_remove(&state, false)?;
        }
        if destructive {
            durable_remove(&self.host(&self.token())?, true)?;
        }
        Ok(Evidence {
            action_id: action.id.clone(),
            success: true,
            observations: vec![
                format!("the {} runtime was removed", self.title()),
                if destructive {
                    "the state directory and the manager secret were purged".into()
                } else {
                    format!(
                        "the state directory ({}) and the manager secret were preserved",
                        if self.awg { "server keys" } else { "credentials" }
                    )
                },
            ],
            details: json!({"persistent_data_preserved":!destructive}).as_object().unwrap().clone(),
        })
    }
}
pub(super) fn hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn domain(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value
            .rsplit('.')
            .next()
            .is_some_and(|tld| (2..=63).contains(&tld.len()) && tld.bytes().all(|b| b.is_ascii_alphabetic()))
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub(super) fn without_override_service(text: &str, service: &str) -> String {
    let mut skipping = false;
    let mut output = String::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with("  ") && !line.starts_with("    ") && line.trim_end().ends_with(':') {
            skipping = line.trim().trim_end_matches(':') == service;
        } else if !line.starts_with("    ") {
            skipping = false;
        }
        if !skipping {
            output.push_str(line);
        }
    }
    output
}
