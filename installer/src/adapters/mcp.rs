//! MCP service ownership and the panel binary CLI boundary.
use super::services::{compose_files, mutations, Host};
use super::AdapterContext;
use crate::adapter::Adapter;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::InstallerConfig;
use crate::planner::{compose_file_list, Action, AuditFacts, Evidence};
use pc_host::runner::{is_in_band_failure, Capture};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;

const PROJECT: &str = "/opt/mtproxy-shared443";
const MARKER: &str = "/etc/proxy-control/mcp-owned";
const ENV: &str = "/opt/mtproxy-shared443/.env.mcp";
const TOKEN: &str = "/opt/mtproxy-shared443/secrets/mcp-token";
const KEY: &str = "/opt/mtproxy-shared443/secrets/mcp-panel-key";
const INITIALIZE: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"installer\",\"version\":\"0\"}}}";
pub struct McpAdapter {
    host: Host,
}
impl McpAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self { host: Host::new(context, "McpError", "MCP") }
    }
    fn selection(&self, action: &Action) -> Result<BTreeMap<String, String>, Error> {
        let values = mutations(
            action,
            "mcp",
            "proxy-control:mcp",
            &["project", "domain", "panel-domain", "port", "compose-files"],
            "McpError",
        )?;
        let valid_domain = |name: &str| {
            installer_core::config::domain_shape_ok(name)
                && name
                    .rsplit('.')
                    .next()
                    .is_some_and(|s| (2..=63).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase()))
        };
        if values["project"] != PROJECT
            || values["port"] != "8793"
            || !valid_domain(&values["domain"])
            || !valid_domain(&values["panel-domain"])
            || values["domain"] == values["panel-domain"]
            || !compose_files(&values["compose-files"]).is_some_and(|v| v.contains(&"compose.mcp.yaml"))
        {
            return Err(self.host.error("MCP action is invalid"));
        }
        Ok(values)
    }
    fn compose(&self, selected: &BTreeMap<String, String>, args: &[&str]) -> Result<Vec<String>, Error> {
        let project = self.host.capture(
            &[
                "docker",
                "inspect",
                "--format",
                "{{index .Config.Labels \"com.docker.compose.project\"}}",
                "proxy-control-panel",
            ],
            128,
            Capture::MCP,
        );
        let project = if project.trim() == "mtproxy" { "mtproxy" } else { "proxy_panel_by_dubr1k" };
        let mut argv = vec![
            "docker".into(),
            "compose".into(),
            "--project-name".into(),
            project.into(),
            "--project-directory".into(),
            PROJECT.into(),
            "--env-file".into(),
            format!("{PROJECT}/.env"),
        ];
        for sibling in ["naive", "mieru", "xray-router", "amneziawg", "trusttunnel", "mcp"] {
            let env = format!("{PROJECT}/.env.{sibling}");
            if self.host.path(&env)?.is_file() {
                argv.extend(["--env-file".into(), env]);
            }
        }
        for file in selected["compose-files"].split(':') {
            argv.extend(["-f".into(), format!("{PROJECT}/{file}")]);
        }
        let versions = format!("{PROJECT}/version-overrides/compose.versions.yaml");
        if self.host.path(&versions)?.is_file() {
            argv.extend(["-f".into(), versions]);
        }
        argv.extend(args.iter().map(|s| (*s).to_owned()));
        Ok(argv)
    }
    pub fn read_token(&self) -> Result<String, Error> {
        let value = self.host.text(TOKEN).map_err(|_| self.host.error("the MCP token is missing"))?;
        let value = value.trim();
        if !token_valid(value) {
            return Err(self.host.error("the MCP token is invalid"));
        }
        Ok(value.into())
    }
    fn status(&self, domain: &str, extra: &[&str]) -> String {
        let resolve = format!("{domain}:8443:127.0.0.1");
        let url = format!("https://{domain}:8443/mcp");
        let mut argv = vec![
            "curl",
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--max-time",
            "15",
            "--resolve",
            &resolve,
        ];
        argv.extend_from_slice(extra);
        argv.push(&url);
        let output = self.host.capture(&argv, 64, Capture::MCP);
        if is_in_band_failure(&output) {
            String::new()
        } else {
            output.trim().into()
        }
    }
    fn teardown(&self, action: &Action, data: CheckpointData, reconcile: bool) -> Result<Evidence, Error> {
        let selected = self.selection(action)?;
        self.host.checkpoint(action, &data)?;
        self.host.marker(MARKER, &data, reconcile)?;
        let argv = self.compose(&selected, &["rm", "-sf", "mcp"])?;
        self.host.run(&argv.iter().map(String::as_str).collect::<Vec<_>>())?;
        let argv = self.compose(
            &selected,
            &["exec", "-T", "panel", "/usr/local/bin/panel", "cli", "api-key-revoke", "--name", "mcp"],
        )?;
        let output = self.host.capture(&argv.iter().map(String::as_str).collect::<Vec<_>>(), 256, Capture::MCP);
        for path in [ENV, KEY, TOKEN, MARKER] {
            self.host.remove(path)?;
        }
        let mut evidence = Evidence::ok(&action.id, &["the mcp service, its env, secrets and marker were removed"])?;
        evidence.details.insert("persistent_data_preserved".into(), json!(true));
        // Revocation is best effort during rollback; do not claim it happened on failure.
        if !is_in_band_failure(&output) {
            evidence.observations.push("the panel API key of the MCP server was revoked".into());
        }
        Ok(evidence)
    }
}
fn token_valid(value: &str) -> bool {
    (32..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn plaintext_of(output: &str) -> Option<String> {
    output.lines().rev().filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok()).find_map(|v| {
        v.get("plaintext")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && !s.contains(['\n', '\r', '\0']))
            .map(str::to_owned)
    })
}
impl Adapter for McpAdapter {
    fn name(&self) -> &str {
        "mcp"
    }
    fn plan(&self, config: &InstallerConfig, _: &AuditFacts) -> Result<Vec<Action>, Error> {
        let domain =
            config.domains.mcp.as_deref().ok_or_else(|| self.host.error("the MCP adapter requires domains.mcp"))?;
        Ok(vec![Action::new(
            "mcp.runtime",
            "mcp",
            "proxy-control:mcp",
            vec![
                format!("project={PROJECT}"),
                format!("domain={domain}"),
                format!("panel-domain={}", config.domains.panel),
                "port=8793".into(),
                format!("compose-files={}", compose_file_list(config).join(":")),
            ],
            vec![
                "the Core runtime is verified".into(),
                "no foreign MCP env or secrets exist without the ownership marker".into(),
            ],
            vec![
                "the proxy-control-mcp container is healthy".into(),
                "the MCP name answers 401 without a token and 200 to initialize with it".into(),
            ],
            vec!["remove the mcp service, revoke its panel API key, remove only the owned env, secrets and marker"
                .into()],
            true,
        )?])
    }
    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        self.selection(action)?;
        let secret_dir = self.host.path(&format!("{PROJECT}/secrets"))?;
        let mut foreign = vec![ENV.to_owned()];
        if secret_dir.is_dir() {
            for entry in fs::read_dir(secret_dir)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if name.starts_with("mcp-") {
                    foreign.push(format!("{PROJECT}/secrets/{name}"));
                }
            }
        }
        self.host.prepare(action, MARKER, &foreign.iter().map(String::as_str).collect::<Vec<_>>())
    }
    fn apply(&self, action: &Action, mut data: CheckpointData) -> Result<CheckpointData, Error> {
        let selected = self.selection(action)?;
        self.host.checkpoint(action, &data)?;
        self.host.claim(MARKER, &data)?;
        self.host.write(
            ENV,
            format!("MCP_DOMAIN={}\nMCP_PANEL_HOST={}\n", selected["domain"], selected["panel-domain"]).as_bytes(),
            0o600,
        )?;
        let token = self.host.path(TOKEN)?;
        if !token.is_file() || !token_valid(fs::read_to_string(token)?.trim()) {
            use base64::Engine;
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| self.host.error("could not generate the MCP token"))?;
            let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            self.host.write(TOKEN, format!("{value}\n").as_bytes(), 0o440)?;
        }
        self.host.own_secret(TOKEN)?;
        if !self.host.path(KEY)?.is_file() {
            let argv = self.compose(
                &selected,
                &[
                    "exec",
                    "-T",
                    "panel",
                    "/usr/local/bin/panel",
                    "cli",
                    "api-key-create",
                    "--name",
                    "mcp",
                    "--scope",
                    "admin",
                ],
            )?;
            let output = self.host.capture(&argv.iter().map(String::as_str).collect::<Vec<_>>(), 4096, Capture::MCP);
            if is_in_band_failure(&output) {
                return Err(self.host.error("the panel did not issue the MCP API key"));
            }
            let key = plaintext_of(&output)
                .ok_or_else(|| self.host.error("the panel's answer to api-key-create carries no key"))?;
            self.host.write(KEY, format!("{key}\n").as_bytes(), 0o440)?;
        }
        self.host.own_secret(KEY)?;
        let argv = self.compose(&selected, &["up", "-d", "--build", "--no-deps", "--wait", "mcp"])?;
        self.host.run(&argv.iter().map(String::as_str).collect::<Vec<_>>())?;
        data.insert("ownership".into(), Value::Object(self.host.ownership(&[ENV, TOKEN, KEY, MARKER])?));
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
        if self
            .host
            .capture(
                &["docker", "inspect", "--format", "{{.State.Health.Status}}", "proxy-control-mcp"],
                64,
                Capture::MCP,
            )
            .trim()
            != "healthy"
        {
            return Err(self.host.error("the proxy-control-mcp container is not healthy"));
        }
        let anonymous = self.status(&selected["domain"], &[]);
        if anonymous != "401" {
            return Err(self.host.error(format!("the MCP name answered {anonymous} without a token instead of 401")));
        }
        let bearer = format!("Authorization: Bearer {}", self.read_token()?);
        let authenticated = self.status(
            &selected["domain"],
            &[
                "--request",
                "POST",
                "--header",
                "Accept: application/json, text/event-stream",
                "--header",
                "Content-Type: application/json",
                "--header",
                &bearer,
                "--data",
                INITIALIZE,
            ],
        );
        if authenticated != "200" {
            return Err(self.host.error(format!("the MCP name answered {authenticated} to initialize instead of 200")));
        }
        let mut evidence = Evidence::ok(
            &action.id,
            &[
                "the proxy-control-mcp container is healthy",
                "the MCP name refuses an anonymous request and answers initialize with a bearer",
            ],
        )?;
        evidence.details = json!({"response_status":200,"public_host_ok":true}).as_object().unwrap().clone();
        Ok(evidence)
    }
    fn rollback(&self, action: &Action, data: CheckpointData, _: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        self.teardown(action, data, false)
    }
    fn reconcile_rollback(
        &self,
        action: &Action,
        data: CheckpointData,
        _: bool,
        _: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.teardown(action, data, true)
    }
}
