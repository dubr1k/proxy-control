//! Pinned host Xray members and the router's owned Compose boundary.
use super::{router_host as h, AdapterContext};
use crate::adapter::Adapter;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use installer_core::model::InstallerConfig;
use installer_core::planner::{Action, AuditFacts, Evidence, PlanError};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
const BIN: &str = "/usr/local/lib/proxy-control/xray-router";
const STATE: &str = "/var/lib/xray-router";
const MARKER: &str = "/etc/proxy-control/xray-router-owned";
const ENV: &str = "/opt/mtproxy-shared443/.env.xray-router";
const ARCHIVE: &str = "/var/lib/proxy-control/Xray-linux-64.zip";
const SECRETS: [&str; 3] = [
    "/opt/mtproxy-shared443/secrets/xray-router-manager-token",
    "/opt/mtproxy-shared443/secrets/xray-router-ingress-naive",
    "/opt/mtproxy-shared443/secrets/xray-router-ingress-mieru",
];
const HELPERS: [(&str, &str); 2] = [
    ("scripts/prepare-xray-router-state.sh", "/usr/local/libexec/prepare-xray-router-state"),
    ("scripts/rotate-xray-router-ingress.sh", "/usr/local/libexec/rotate-xray-router-ingress"),
];
pub struct XrayRouterAdapter {
    context: AdapterContext,
}
impl XrayRouterAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self { context: context.clone() }
    }
    fn selection(&self, action: &Action) -> Result<BTreeMap<String, String>, Error> {
        if action.id != "xray_router.runtime" {
            return Err(h::err("Xray-router action is invalid"));
        }
        let values = h::selection(action, "xray_router", "proxy-control:xray-router")?;
        let pin = h::pin(&self.context, "xray")?;
        let fixed = [
            ("project", "/opt/mtproxy-shared443"),
            ("xray-version", pin.version.as_str()),
            ("architecture", "amd64"),
            ("archive", ARCHIVE),
            ("archive-url", pin.url.as_str()),
            ("archive-digest", pin.sha256.as_str()),
            ("bin-dir", BIN),
            ("state-dir", STATE),
            ("router-uid", "10006"),
            ("router-gid", "10006"),
            ("port-naive", "45101"),
            ("port-mieru", "45102"),
        ];
        for (key, value) in fixed {
            if values.get(key).map(String::as_str) != Some(value) {
                return Err(h::err("Xray-router action is invalid"));
            }
        }
        for member in ["xray", "geoip.dat", "geosite.dat"] {
            if values.get(&format!("{member}-digest")) != pin.member(member).map(|pin| &pin.sha256) {
                return Err(h::err("Xray-router action is invalid"));
            }
        }
        let allowed = [
            "project",
            "xray-version",
            "architecture",
            "archive",
            "archive-url",
            "archive-digest",
            "xray-digest",
            "geoip.dat-digest",
            "geosite.dat-digest",
            "bin-dir",
            "state-dir",
            "router-uid",
            "router-gid",
            "port-naive",
            "port-mieru",
            "port-trusttunnel",
            "warp-provider",
            "relay-port",
            "relay-server-name",
            "mtproxy-bridge",
        ];
        if values.keys().any(|key| !allowed.contains(&key.as_str())) || !values.contains_key("warp-provider") {
            return Err(h::err("Xray-router action is invalid"));
        }
        let provider = &values["warp-provider"];
        if !provider.is_empty()
            && provider
                .strip_prefix("socks5h://127.0.0.1:")
                .or_else(|| provider.strip_prefix("socks5://127.0.0.1:"))
                .and_then(|port| port.parse::<u16>().ok())
                .is_none_or(|port| port < 1024)
        {
            return Err(h::err("Xray-router WARP provider is invalid"));
        }
        if values.get("port-trusttunnel").is_some_and(|p| p != "45104")
            || values.get("mtproxy-bridge").is_some_and(|v| v != "xray-router-ingress:45103")
        {
            return Err(h::err("Xray-router action is invalid"));
        }
        let port = values
            .get("relay-port")
            .map(String::as_str)
            .unwrap_or("0")
            .parse::<u16>()
            .map_err(|_| h::err("invalid relay port"))?;
        let server = values.get("relay-server-name").map(String::as_str).unwrap_or("");
        if port != 0 && (port < 1024 || [443, 80, 45101, 45102, 45104].contains(&port) || !valid_domain(server))
            || port == 0 && !server.is_empty()
        {
            return Err(h::err("invalid relay selection"));
        }
        Ok(values)
    }
    /// Both numeric ownership and named identities are checked on the live host, not optional runner hooks.
    fn identities(&self) -> Result<BTreeMap<String, bool>, Error> {
        let mut missing = BTreeMap::new();
        for (database, kind) in [("passwd", "UID"), ("group", "GID")] {
            let numeric = h::capture(&self.context, &["getent", database, "10006"]);
            if !numeric.is_empty()
                && !pc_host::runner::is_in_band_failure(&numeric)
                && numeric.split(':').next() != Some("xray-router")
            {
                return Err(h::err(&format!("{kind} 10006 collision")));
            }
            let named = h::capture(&self.context, &["getent", database, "xray-router"]);
            if !named.is_empty() && !pc_host::runner::is_in_band_failure(&named) {
                if named.split(':').nth(2) != Some("10006") {
                    return Err(h::err("xray-router identity has an unexpected numeric identifier"));
                }
                missing.insert(database.into(), false);
            } else {
                missing.insert(database.into(), true);
            }
        }
        Ok(missing)
    }
    fn checkpoint(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let required = [
            "owner",
            "adoption",
            "marker_value",
            "identities_created",
            "bin_preexisting",
            "state_preexisting",
            "secrets_preexisting",
            "ownership",
        ];
        if checkpoint.len() != required.len()
            || required.iter().any(|key| !checkpoint.contains_key(*key))
            || ["bin_preexisting", "state_preexisting"].iter().any(|key| !checkpoint[*key].is_boolean())
            || ["identities_created", "secrets_preexisting"]
                .iter()
                .any(|key| checkpoint[*key].as_object().is_none_or(|map| map.values().any(|value| !value.is_boolean())))
        {
            return Err(h::err("Xray-router checkpoint is invalid"));
        }
        if checkpoint.get("owner") != Some(&json!(action.owner))
            || !checkpoint.get("ownership").is_some_and(Value::is_object)
        {
            return Err(h::err("Xray-router checkpoint is invalid"));
        }
        let adoption = checkpoint.get("adoption").and_then(Value::as_str);
        if adoption != Some("absent") && adoption != Some("recovery") {
            return Err(h::err("Xray-router checkpoint is invalid"));
        }
        let marker = checkpoint.get("marker_value").unwrap_or(&Value::Null);
        if adoption == Some("absent")
            && !marker
                .as_str()
                .is_some_and(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
            || adoption == Some("recovery") && !marker.is_null()
        {
            return Err(h::err("Xray-router checkpoint is invalid"));
        }
        Ok(checkpoint)
    }
    fn env(&self, selected: &BTreeMap<String, String>) -> String {
        format!("XRAY_ROUTER_BIN_DIR={BIN}\nXRAY_ROUTER_STATE_DIR={STATE}\nXRAY_ROUTER_XRAY_SHA256={}\nXRAY_ROUTER_GEOIP_SHA256={}\nXRAY_ROUTER_GEOSITE_SHA256={}\nXRAY_ROUTER_EGRESS_WARP={}\n",selected["xray-digest"],selected["geoip.dat-digest"],selected["geosite.dat-digest"],selected["warp-provider"])
    }
    fn set_agent(&self, on: bool) -> Result<(), Error> {
        let path = h::host(&self.context, "/etc/proxy-control/version-agent.env")?;
        if !on && !path.exists() {
            return Ok(());
        }
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file()) {
            return Err(h::err("version-agent env file is a symlink"));
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        let mut lines: Vec<_> = text
            .lines()
            .filter(|line| line.split('=').next().unwrap_or("").trim() != "PROXY_CONTROL_XRAY_ROUTER")
            .map(str::to_owned)
            .collect();
        lines.push(format!("PROXY_CONTROL_XRAY_ROUTER={}", if on { "on" } else { "off" }));
        h::atomic(
            &self.context,
            "/etc/proxy-control/version-agent.env",
            format!("{}\n", lines.join("\n")).as_bytes(),
            0o600,
        )?;
        if h::capture(&self.context, &["systemctl", "is-active", "version-agent"]).trim() == "active" {
            let _ = h::run(&self.context, &["systemctl", "restart", "version-agent"], None);
        }
        Ok(())
    }
    fn enable_relay(&self, selected: &BTreeMap<String, String>) -> Result<(), Error> {
        if selected.get("relay-port").is_none_or(|port| port == "0") {
            return Ok(());
        }
        let output = h::checked(
            &self.context,
            &[
                "docker",
                "exec",
                "proxy-control-xray-router",
                "/usr/local/bin/xray-router-manager",
                "healthcheck",
                "--relay-enable",
                &selected["relay-server-name"],
                &selected["relay-port"],
            ],
        )?;
        let view: Value = serde_json::from_str(&output).map_err(|_| h::err("invalid relay response"))?;
        if view["enabled"] != true
            || view["port"].as_u64().map(|p| p.to_string()).as_ref() != selected.get("relay-port")
        {
            return Err(h::err("the Xray-router did not enable its relay"));
        }
        Ok(())
    }
    fn present(&self, service: &str) -> bool {
        ["proxy_panel_by_dubr1k", "mtproxy"].iter().any(|project| {
            let output = h::capture(
                &self.context,
                &[
                    "docker",
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    &format!("label=com.docker.compose.project={project}"),
                    "--filter",
                    &format!("label=com.docker.compose.service={service}"),
                ],
            );
            !output.trim().is_empty() && !pc_host::runner::is_in_band_failure(&output)
        })
    }
}
fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
impl Adapter for XrayRouterAdapter {
    fn name(&self) -> &str {
        "xray_router"
    }
    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        let egress = config.effective_egress();
        if !egress.router {
            return Ok(vec![]);
        }
        if facts.prerequisites.get("hard_stops").and_then(Value::as_array).is_some_and(|stops| !stops.is_empty()) {
            return Err(h::err("host audit contains blocking findings"));
        }
        if !config.profile.includes_naive() && !config.profile.includes_mieru() && config.trusttunnel.is_none() {
            return Err(PlanError::new("the Xray-router needs NaiveProxy, Mieru or TrustTunnel to feed").into());
        }
        for kind in ["uid", "gid"] {
            if let Some(holder) =
                facts.ownership.get("identities").and_then(|v| v.get(kind)).and_then(|v| v.get("10006"))
            {
                if holder != &Value::Null && holder != "" && holder != "xray-router" {
                    return Err(PlanError::new(format!(
                        "{} 10006 collision: {}",
                        kind.to_uppercase(),
                        holder.as_str().unwrap_or("invalid identity")
                    ))
                    .into());
                }
            }
        }
        for port in [45101, 45102, 45104, egress.relay_port] {
            if port != 0
                && facts
                    .listeners
                    .get("tcp")
                    .and_then(Value::as_array)
                    .is_some_and(|ports| ports.contains(&json!(port)))
            {
                let holders = facts
                    .listeners
                    .get("owners")
                    .and_then(|owners| owners.get(port.to_string()))
                    .and_then(Value::as_array);
                if holders.is_none_or(|holders| holders.is_empty() || holders.iter().any(|holder| holder != "xray")) {
                    return Err(PlanError::new(format!(
                        "router ingress port {port} is already claimed by another listener"
                    ))
                    .into());
                }
            }
        }
        let pin = h::pin(&self.context, "xray")?;
        let mut mutations = vec![
            "project=/opt/mtproxy-shared443".into(),
            format!("xray-version={}", pin.version),
            "architecture=amd64".into(),
            format!("archive={ARCHIVE}"),
            format!("archive-url={}", pin.url),
            format!("archive-digest={}", pin.sha256),
        ];
        for member in ["xray", "geoip.dat", "geosite.dat"] {
            mutations.push(format!(
                "{member}-digest={}",
                pin.member(member).ok_or_else(|| h::err("Xray member pin is missing"))?.sha256
            ));
        }
        mutations.extend([
            format!("bin-dir={BIN}"),
            format!("state-dir={STATE}"),
            "router-uid=10006".into(),
            "router-gid=10006".into(),
            "port-naive=45101".into(),
            "port-mieru=45102".into(),
            "port-trusttunnel=45104".into(),
            format!("warp-provider={}", egress.provider_url().unwrap_or_default()),
            format!("relay-port={}", egress.relay_port),
            format!(
                "relay-server-name={}",
                if egress.relay_port != 0 { config.domains.panel.to_lowercase() } else { String::new() }
            ),
            "mtproxy-bridge=xray-router-ingress:45103".into(),
        ]);
        Ok(vec![Action::new(
            "xray_router.runtime",
            "xray_router",
            "proxy-control:xray-router",
            mutations,
            vec![
                "the Core runtime is verified".into(),
                "the pinned archive is staged in /var/lib/proxy-control or fetched from its pin".into(),
                "loopback ports 45101, 45102 and 45104 are free or held by the owned router".into(),
                "fixed router identity 10006 is free or already owned".into(),
            ]
            .into_iter()
            .chain((egress.relay_port != 0).then(|| "the relay port is free or held by the owned router".into()))
            .collect(),
            vec![
                "archive and member digests match the pinned release".into(),
                "the manager reports verified artifacts and a running generation".into(),
                "the naive, mieru and trusttunnel ingresses listen on the loopback only".into(),
                "one authenticated CONNECT through the NaiveProxy ingress reaches the Internet".into(),
                "the MTProxy ingress bridge answers on the Compose network".into(),
            ]
            .into_iter()
            .chain(
                (egress.relay_port != 0)
                    .then(|| "the relay inbound is enabled on its port behind the panel name".into()),
            )
            .collect(),
            vec![
                "stop and remove only the xray-router and xray-router-ingress Compose services".into(),
                "remove only the owned binaries, helpers and env overlay".into(),
                "preserve manager state and secrets unless purge is explicit".into(),
            ],
            true,
        )?])
    }
    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        self.selection(action)?;
        self.identities()?;
        h::ensure_archive(&self.context, ARCHIVE, &h::pin(&self.context, "xray")?)?;
        let marker = h::host(&self.context, MARKER)?;
        if fs::symlink_metadata(&marker).is_ok_and(|metadata| !metadata.is_file()) {
            return Err(h::err("invalid Xray ownership marker"));
        }
        let recovery = match fs::read_to_string(&marker) {
            Ok(value) => {
                if value.trim().len() != 32
                    || !value.trim().bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(h::err("invalid Xray ownership marker"));
                }
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        if !recovery && self.present("xray-router") {
            return Err(h::err("an active xray-router service requires a proven owned recovery generation"));
        }
        Ok(json!({"owner":action.owner,"adoption":if recovery{"recovery"}else{"absent"},"marker_value":if recovery{Value::Null}else{json!(pc_host::fs::token_hex::<16>())},"identities_created":{},"bin_preexisting":h::host(&self.context,BIN)?.is_dir(),"state_preexisting":h::host(&self.context,STATE)?.is_dir(),"secrets_preexisting":{"manager_token":h::host(&self.context,SECRETS[0])?.is_file(),"ingress_naive":h::host(&self.context,SECRETS[1])?.is_file(),"ingress_mieru":h::host(&self.context,SECRETS[2])?.is_file()},"ownership":{}}).as_object().unwrap().clone())
    }
    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let selected = self.selection(action)?;
        let mut checkpoint = self.checkpoint(action, checkpoint)?;
        let pin = h::pin(&self.context, "xray")?;
        let archive = h::ensure_archive(&self.context, ARCHIVE, &pin)?;
        let members = pin.members.as_ref().ok_or_else(|| h::err("Xray members are not pinned"))?;
        pc_host::fs::durable_mkdir(h::host(&self.context, BIN)?.parent().expect("binary directory parent"), 0o755)?;
        pc_host::archive::safe_extract_zip_default(&archive, &h::host(&self.context, BIN)?, members)
            .map_err(|error| Error::other("ArtifactError", format!("Xray archive extraction failed: {error}")))?;
        let missing = self.identities()?;
        if missing["group"] {
            h::run(&self.context, &["groupadd", "--system", "--gid", "10006", "xray-router"], None)?;
        }
        if missing["passwd"] {
            h::run(
                &self.context,
                &[
                    "useradd",
                    "--system",
                    "--uid",
                    "10006",
                    "--gid",
                    "10006",
                    "--home-dir",
                    STATE,
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "xray-router",
                ],
                None,
            )?;
        }
        for (source, target) in HELPERS {
            h::atomic(&self.context, target, &fs::read(self.context.tree.join(source))?, 0o755)?;
        }
        h::run(&self.context, &[HELPERS[0].1, "prepare", STATE], None)?;
        for (index, path) in SECRETS.iter().enumerate() {
            let file = h::host(&self.context, path)?;
            if file.exists() {
                let metadata = fs::symlink_metadata(&file)?;
                if !metadata.is_file() || metadata.mode() & 0o007 != 0 {
                    return Err(h::err("router secret permissions are unsafe"));
                }
                let value = fs::read_to_string(&file)?;
                if index == 0 && !(value.trim().len() == 64 && value.trim().bytes().all(|b| b.is_ascii_hexdigit()))
                    || index > 0
                        && !value.trim().split_once(':').is_some_and(|(u, p)| {
                            !u.is_empty()
                                && u.len() <= 64
                                && (16..=128).contains(&p.len())
                                && u.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
                        })
                {
                    return Err(h::err("router secret is invalid"));
                }
            } else {
                let value = if index == 0 {
                    pc_host::fs::token_hex::<32>()
                } else {
                    format!("{}:{}", if index == 1 { "naive" } else { "mieru" }, pc_host::fs::token_hex::<24>())
                };
                h::atomic(&self.context, path, format!("{value}\n").as_bytes(), 0o440)?;
            }
            fs::set_permissions(&file, fs::Permissions::from_mode(0o440))?;
            if self.context.root == std::path::Path::new("/") {
                h::run(&self.context, &["chown", "0:10006", path], None)?;
            }
        }
        h::atomic(&self.context, ENV, self.env(&selected).as_bytes(), 0o600)?;
        if let Some(marker) = checkpoint.get("marker_value").and_then(Value::as_str) {
            h::atomic(&self.context, MARKER, format!("{marker}\n").as_bytes(), 0o600)?;
        }
        h::compose(&self.context, &["up", "-d", "--build", "--wait", "xray-router", "xray-router-ingress"])?;
        self.enable_relay(&selected)?;
        self.set_agent(true)?;
        checkpoint.insert("identities_created".into(), json!({"user":missing["passwd"],"group":missing["group"]}));
        let mut paths = vec![
            (ENV, false, false),
            (MARKER, false, false),
            (HELPERS[0].1, false, false),
            (HELPERS[1].1, false, false),
            (SECRETS[0], true, false),
            (SECRETS[1], true, false),
            (SECRETS[2], true, false),
        ];
        let member_paths = [format!("{BIN}/xray"), format!("{BIN}/geoip.dat"), format!("{BIN}/geosite.dat")];
        for path in &member_paths {
            paths.push((path, false, false));
        }
        checkpoint.insert("ownership".into(), h::ownership(&self.context, &paths)?);
        Ok(checkpoint)
    }
    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }
    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let selected = self.selection(action)?;
        for member in ["xray", "geoip.dat", "geosite.dat"] {
            let path = h::host(&self.context, &format!("{BIN}/{member}"))?;
            let pinned = &selected[&format!("{member}-digest")];
            if pc_host::archive::verify_artifact(&path, pinned).is_err() {
                let state_path = h::host(&self.context, "/var/lib/proxy-control/version-agent/state.json")?;
                let state: Value = fs::read(state_path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                    .unwrap_or(Value::Null);
                let component = &state["components"]["xray"];
                let accepted = component["members"][member].as_str().filter(|digest| {
                    digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                });
                if component["status"] == "rollback_failed"
                    || accepted.is_none_or(|digest| pc_host::archive::verify_artifact(&path, digest).is_err())
                {
                    return Err(Error::other(
                        "ArtifactError",
                        format!("installed Xray member does not match its pin: {member}"),
                    ));
                }
            }
        }
        let output = h::checked(
            &self.context,
            &[
                "docker",
                "exec",
                "proxy-control-xray-router",
                "/usr/local/bin/xray-router-manager",
                "healthcheck",
                "--status",
            ],
        )?;
        let status: Value = serde_json::from_str(&output).map_err(|_| h::err("invalid router status"))?;
        if ["xray", "geoip", "geosite"].iter().any(|name| status["artifacts"][name]["verified"] != true)
            || status["running"]["generation"].as_u64().is_none_or(|g| g < 1)
            || status["phase"] != "idle"
        {
            return Err(h::err("the Xray-router is not running a committed generation"));
        }
        for port in [45101, 45102, 45104] {
            let output = h::checked(&self.context, &["ss", "-H", "-lnt", &format!("sport = :{port}")])?;
            let addresses: std::collections::BTreeSet<_> =
                output.lines().filter_map(|line| line.split_whitespace().nth(3)).collect();
            let expected = format!("127.0.0.1:{port}");
            if addresses != std::collections::BTreeSet::from([expected.as_str()]) {
                return Err(h::err("router ingresses must listen on loopback only"));
            }
        }
        let credential = fs::read_to_string(h::host(&self.context, SECRETS[1])?)?;
        if !credential.trim().split_once(':').is_some_and(|(user, password)| {
            !user.is_empty()
                && user.len() <= 64
                && (16..=128).contains(&password.len())
                && user.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && password.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
        }) {
            return Err(h::err("the naive ingress credential is malformed"));
        }
        let probe = "/var/lib/proxy-control/router-probe.conf";
        h::atomic(&self.context, probe, format!("proxy-user = \"{}\"\n", credential.trim()).as_bytes(), 0o600)?;
        let output = h::checked(
            &self.context,
            &[
                "curl",
                "--config",
                h::host(&self.context, probe)?.to_str().ok_or_else(|| h::err("invalid probe path"))?,
                "--fail",
                "--silent",
                "--show-error",
                "--noproxy",
                "",
                "--socks5-hostname",
                "127.0.0.1:45101",
                "--max-time",
                "20",
                "https://www.cloudflare.com/cdn-cgi/trace",
            ],
        );
        h::remove(&self.context, probe)?;
        if !output?.lines().any(|line| line.starts_with("ip=")) {
            return Err(h::err("an authenticated CONNECT through the NaiveProxy ingress did not reach the Internet"));
        }
        h::checked(
            &self.context,
            &["docker", "exec", "proxy-control-xray-router-ingress", "/usr/local/bin/mtproxy-bridge", "--check"],
        )?;
        if selected.get("relay-port").is_some_and(|p| p != "0") {
            let relay: Value = serde_json::from_str(&h::checked(
                &self.context,
                &[
                    "docker",
                    "exec",
                    "proxy-control-xray-router",
                    "/usr/local/bin/xray-router-manager",
                    "healthcheck",
                    "--relay",
                ],
            )?)
            .map_err(|_| h::err("invalid relay status"))?;
            if relay["enabled"] != true
                || relay["server_name"] != selected["relay-server-name"]
                || relay["port"].as_u64().map(|p| p.to_string()).as_ref() != selected.get("relay-port")
                || relay["public_key"].as_str().is_none_or(str::is_empty)
            {
                return Err(h::err("the relay inbound is not enabled on its port behind the panel name"));
            }
            let port = &selected["relay-port"];
            let output = h::checked(&self.context, &["ss", "-H", "-lnt", &format!("sport = :{port}")])?;
            if !output.lines().filter_map(|line| line.split_whitespace().nth(3)).any(|address| {
                [format!("0.0.0.0:{port}"), format!("*:{port}"), format!("[::]:{port}")].contains(&address.to_owned())
            }) {
                return Err(h::err("the relay inbound does not listen on its public port"));
            }
        }
        h::evidence(
            action,
            "pinned Xray members, verified artifacts and a running generation",
            json!({"generation":status["running"]["generation"],"ports":{"naive":45101,"mieru":45102},"trusttunnel_port":45104}),
        )
    }
    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        let selected = self.selection(action)?;
        let checkpoint = self.checkpoint(action, checkpoint)?;
        self.identities()?;
        h::run(&self.context, &[HELPERS[0].1, "verify", STATE], None)?;
        h::atomic(&self.context, ENV, self.env(&selected).as_bytes(), 0o600)?;
        h::compose(&self.context, &["up", "-d", "--wait", "xray-router", "xray-router-ingress"])?;
        self.enable_relay(&selected)?;
        Ok(checkpoint)
    }
    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.selection(action)?;
        let checkpoint = self.checkpoint(action, checkpoint)?;
        for service in ["xray-router-ingress", "xray-router"] {
            if self.present(service) {
                h::compose(&self.context, &["rm", "--stop", "--force", service])?;
            }
        }
        self.set_agent(false)?;
        for path in [ENV, MARKER, HELPERS[0].1, HELPERS[1].1] {
            h::remove(&self.context, path)?;
        }
        for member in ["xray", "geoip.dat", "geosite.dat"] {
            h::remove(&self.context, &format!("{BIN}/{member}"))?;
        }
        let bin = h::host(&self.context, BIN)?;
        if bin.is_dir() && fs::read_dir(&bin)?.next().is_none() {
            pc_host::fs::durable_remove(&bin, true)?;
        }
        let destructive = purge && target == RollbackTarget::Uninstalled;
        if destructive {
            let state = h::host(&self.context, STATE)?;
            if state.is_dir() && !state.is_symlink() {
                fs::remove_dir_all(state)?;
            }
            for path in SECRETS {
                h::remove(&self.context, path)?;
            }
            if checkpoint.get("identities_created").and_then(|v| v.get("user")) == Some(&json!(true)) {
                let _ = h::run(&self.context, &["userdel", "xray-router"], None);
            }
            if checkpoint.get("identities_created").and_then(|v| v.get("group")) == Some(&json!(true)) {
                let _ = h::run(&self.context, &["groupdel", "xray-router"], None);
            }
        }
        h::evidence(
            action,
            "the owned Xray-router generation was removed",
            json!({"persistent_data_preserved":!destructive}),
        )
    }
    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.rollback(action, checkpoint, purge, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempDir;
    use pc_host::runner::RecordingRunner;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    fn tree() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().into()
    }
    #[test]
    fn env_bytes_match_python_kitchen_sink_golden() {
        let root = TempDir::new("router-env-golden");
        let context =
            AdapterContext { root: root.path().into(), tree: tree(), runner: Arc::new(RecordingRunner::new()) };
        let config = installer_core::config::load_config(
            &tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"),
        )
        .unwrap();
        let adapter = XrayRouterAdapter::new(&context);
        let action = adapter.plan(&config, &AuditFacts::default()).unwrap().remove(0);
        assert_eq!(
            adapter.env(&adapter.selection(&action).unwrap()).as_bytes(),
            fs::read(tree().join("tests/fixtures/host-golden/renders/kitchen-sink/xray_router/env")).unwrap()
        );
    }
    #[test]
    fn checkpoint_rejects_missing_unknown_and_wrong_typed_fields() {
        let root = TempDir::new("router-checkpoint");
        let context =
            AdapterContext { root: root.path().into(), tree: tree(), runner: Arc::new(RecordingRunner::new()) };
        let config = installer_core::config::load_config(
            &tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"),
        )
        .unwrap();
        let adapter = XrayRouterAdapter::new(&context);
        let action = adapter.plan(&config, &AuditFacts::default()).unwrap().remove(0);
        let valid = json!({"owner":action.owner,"adoption":"absent","marker_value":"a".repeat(32),"identities_created":{},"bin_preexisting":false,"state_preexisting":false,"secrets_preexisting":{},"ownership":{}}).as_object().unwrap().clone();
        assert!(adapter.checkpoint(&action, valid.clone()).is_ok());
        let mut bad = valid.clone();
        bad.insert("unknown".into(), json!(true));
        assert!(adapter.checkpoint(&action, bad).is_err());
        let mut bad = valid.clone();
        bad.remove("bin_preexisting");
        assert!(adapter.checkpoint(&action, bad).is_err());
        let mut bad = valid;
        bad.insert("identities_created".into(), json!({"user":"true"}));
        assert!(adapter.checkpoint(&action, bad).is_err());
    }
}
