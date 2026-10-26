use super::super::router_host as h;
use super::ThreeXuiAdapter;
use crate::adapter::Adapter;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::three_xui_api::{ThreeXuiApi, ThreeXuiClient};
use crate::three_xui_templates::{managed_inbounds, parse_reality_keypair};
use installer_core::model::{InstallerConfig, ThreeXuiMode};
use installer_core::planner::{Action, AuditFacts, Evidence, PlanError};
use pc_host::archive::{ArchiveEntry, ArchiveManifest};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
const ROOT: &str = "/usr/local/x-ui";
const UNIT: &str = "/etc/systemd/system/x-ui.service";
const DATABASE: &str = "/etc/x-ui/x-ui.db";
const MARKER: &str = "/etc/proxy-control/three-xui-owned";
fn fail(message: &str) -> Error {
    Error::other("ThreeXuiError", message)
}
pub(super) fn domain(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
impl ThreeXuiAdapter {
    fn runtime_selection(&self, action: &Action) -> Result<BTreeMap<String, String>, Error> {
        if action.id != "three_xui.runtime" {
            return Err(fail("3x-ui action is invalid"));
        }
        let selected = h::selection(action, "three_xui", "proxy-control:three-xui")?;
        let pin = h::pin(&self.context, "three_xui")?;
        for (key, value) in [
            ("version", "3.10.2"),
            ("architecture", "amd64"),
            ("release-url", pin.url.as_str()),
            ("release-digest", pin.sha256.as_str()),
            ("root", ROOT),
            ("unit", UNIT),
            ("database", DATABASE),
            ("vless-tcp-backend", "8449"),
            ("vless-xhttp-backend", "8450"),
            ("panel-backend", "8451"),
        ] {
            if selected.get(key).map(String::as_str) != Some(value) {
                return Err(fail("3x-ui action is invalid"));
            }
        }
        for key in ["panel-domain", "hysteria-domain", "vless-tcp-domain", "vless-xhttp-domain"] {
            if !selected.get(key).is_some_and(|value| domain(value)) {
                return Err(fail("3x-ui action names an invalid domain"));
            }
        }
        if ![Some("true"), Some("false")].contains(&selected.get("warp").map(String::as_str))
            || selected.get("warp-port").and_then(|v| v.parse::<u16>().ok()).is_none_or(|p| p < 1024)
        {
            return Err(fail("3x-ui WARP selection is invalid"));
        }
        if selected.get("subscription-domain").is_some_and(|v| !v.is_empty() && !domain(v)) {
            return Err(fail("3x-ui subscription domain is invalid"));
        }
        let allowed = [
            "version",
            "architecture",
            "release-url",
            "release-digest",
            "root",
            "unit",
            "database",
            "vless-tcp-backend",
            "vless-xhttp-backend",
            "panel-backend",
            "panel-domain",
            "hysteria-domain",
            "vless-tcp-domain",
            "vless-xhttp-domain",
            "warp",
            "warp-port",
            "warp-domains",
            "subscription-domain",
        ];
        if selected.len() != allowed.len() || selected.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(fail("3x-ui action is invalid"));
        }
        Ok(selected)
    }
    fn assert_absent(&self) -> Result<(), Error> {
        for (label, path) in
            [("database", DATABASE), ("database directory", "/etc/x-ui"), ("binary tree", ROOT), ("unit", UNIT)]
        {
            if fs::symlink_metadata(h::host(&self.context, path)?).is_ok() {
                return Err(fail(&format!("managed 3x-ui refuses a pre-existing {label}: {path}")));
            }
        }
        let identity = h::capture(&self.context, &["getent", "passwd", "x-ui"]);
        if identity.lines().any(|line| line.starts_with("x-ui:")) {
            return Err(fail("managed 3x-ui refuses a pre-existing service user"));
        }
        if h::capture(&self.context, &["systemctl", "is-active", "x-ui"]).trim() == "active" {
            return Err(fail("managed 3x-ui refuses an active x-ui unit"));
        }
        Ok(())
    }
    pub fn archive_manifest(&self, digest: &str) -> Result<ArchiveManifest, Error> {
        let document: Value =
            serde_json::from_slice(&fs::read(self.context.tree.join("release/three-xui-layout-amd64.json"))?)
                .map_err(|_| fail("3x-ui release layout is unavailable"))?;
        let entries = document["entries"]
            .as_array()
            .filter(|entries| !entries.is_empty())
            .ok_or_else(|| fail("3x-ui release layout is empty"))?;
        let entries = entries
            .iter()
            .map(|entry| {
                Ok(ArchiveEntry {
                    path: entry["path"].as_str().ok_or_else(|| fail("invalid release layout"))?.into(),
                    kind: entry["kind"].as_str().ok_or_else(|| fail("invalid release layout"))?.into(),
                    mode: entry["mode"].as_u64().map(|v| v as u32),
                    sha256: entry["sha256"].as_str().map(str::to_owned),
                    link_target: entry["link_target"].as_str().map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(ArchiveManifest::new(entries, digest))
    }
    fn await_panel(&self) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if listening(&h::checked(&self.context, &["ss", "-lntH"])?).contains(&8451) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(fail("the 3x-ui panel did not start listening on its private port"));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    fn route_map(&self, action: &Action) -> Result<BTreeMap<String, String>, Error> {
        if action.adapter != "three_xui" || action.id != "three_xui.routes" || action.owner != "nginx.routes.three_xui"
        {
            return Err(fail("3x-ui action is invalid"));
        }
        let mut routes = BTreeMap::new();
        for mutation in &action.mutations {
            if let Some(value) = mutation.strip_prefix("route=") {
                let (name, backend) = value.split_once(' ').ok_or_else(|| fail("3x-ui route is invalid"))?;
                if !domain(name)
                    || backend.strip_prefix("127.0.0.1:").and_then(|p| p.parse::<u16>().ok()).is_none_or(|p| p == 0)
                    || routes.insert(name.into(), backend.into()).is_some()
                {
                    return Err(fail("3x-ui route is invalid"));
                }
            } else if !["mode=existing", "mode=managed-new"].contains(&mutation.as_str()) {
                return Err(fail("3x-ui route is invalid"));
            }
        }
        if routes.is_empty() {
            return Err(fail("3x-ui route action declares no route"));
        }
        Ok(routes)
    }
    fn warp_domains(&self, action: &Action) -> Result<Vec<String>, Error> {
        if action.id != "three_xui.warp"
            || action.adapter != "three_xui"
            || action.owner != "proxy-control:three-xui-warp"
        {
            return Err(fail("3x-ui action is invalid"));
        }
        let domains: Vec<_> = action
            .mutations
            .iter()
            .filter_map(|mutation| mutation.strip_prefix("warp-domain=").map(str::to_owned))
            .collect();
        if domains.is_empty() || domains.iter().any(|value| !warp_selector(value)) {
            return Err(fail("3x-ui WARP action declares no valid domain"));
        }
        Ok(domains)
    }
    fn bootstrap(
        &self,
        selected: &BTreeMap<String, String>,
        username: &str,
        password: &str,
        path: &str,
    ) -> Result<(), Error> {
        let payload = json!({"port":2053,"panel_port":8451,"certificate":format!("/etc/letsencrypt/live/{}/fullchain.pem",selected["panel-domain"]),"private_key":format!("/etc/letsencrypt/live/{}/privkey.pem",selected["panel-domain"]),"initial_username":"admin","initial_password":"admin","username":username,"password":password,"web_path":path});
        let payload_path = format!("/var/lib/proxy-control/three-xui/bootstrap-{}.json", pc_host::fs::token_hex::<8>());
        h::atomic(&self.context, &payload_path, pc_host::json::canonical(&payload).as_bytes(), 0o600)?;
        h::run(&self.context, &["ip", "netns", "add", "proxy-control-x-ui"], None)?;
        let result = (|| {
            h::run(
                &self.context,
                &["ip", "netns", "exec", "proxy-control-x-ui", "ip", "link", "set", "lo", "up"],
                None,
            )?;
            h::run(
                &self.context,
                &[
                    "systemd-run",
                    "--unit=x-ui-bootstrap",
                    "--property=NetworkNamespacePath=/run/netns/proxy-control-x-ui",
                    "--property=WorkingDirectory=/usr/local/x-ui",
                    "/usr/local/x-ui/x-ui",
                    "run",
                ],
                None,
            )?;
            let binary = std::env::current_exe()?;
            h::run(
                &self.context,
                &[
                    "ip",
                    "netns",
                    "exec",
                    "proxy-control-x-ui",
                    binary.to_str().ok_or_else(|| fail("invalid installer executable path"))?,
                    "three-xui-bootstrap",
                ],
                Some(h::host(&self.context, &payload_path)?),
            )
        })();
        let stop = h::run(&self.context, &["systemctl", "stop", "x-ui-bootstrap.service"], None);
        let remove = h::run(&self.context, &["ip", "netns", "delete", "proxy-control-x-ui"], None);
        h::remove(&self.context, &payload_path)?;
        result?;
        stop?;
        remove?;
        Ok(())
    }
    fn provision(&self, selected: &BTreeMap<String, String>) -> Result<Value, Error> {
        // Reuse the validated staged credentials; never put a credential in a journal or argv.
        let chosen = installer_core::credentials::staged_credentials(&self.context.root)
            .map_err(|_| fail("the staged credentials cannot be used"))?;
        let username = chosen.as_ref().and_then(|c| c.three_xui_username.as_deref()).unwrap_or("owner");
        let generated = pc_host::fs::token_hex::<32>();
        let password = chosen.as_ref().and_then(|c| c.three_xui_password.as_deref()).unwrap_or(&generated);
        let web_path = format!("/{}/", pc_host::fs::token_hex::<8>());
        self.bootstrap(selected, username, password, &web_path)?;
        h::run(&self.context, &["systemctl", "restart", "x-ui"], None)?;
        self.await_panel()?;
        let certificate =
            h::host(&self.context, &format!("/etc/letsencrypt/live/{}/fullchain.pem", selected["panel-domain"]))?;
        let mut api = ThreeXuiApi::new(ThreeXuiClient::new("127.0.0.1", 8451, Some(&certificate))?, &web_path)?;
        api.login(username, password)?;
        let keypair = h::checked(&self.context, &["/usr/local/x-ui/bin/xray-linux-amd64", "x25519"])?;
        let (private, public) = parse_reality_keypair(&keypair)?;
        let subscription =
            if selected["subscription-domain"].is_empty() { None } else { Some(pc_host::fs::token_hex::<24>()) };
        for inbound in managed_inbounds(selected, &private, &public, subscription.as_deref())? {
            api.add_inbound(inbound)?;
        }
        if selected["warp"] == "true" {
            let domains =
                selected["warp-domains"].split(',').filter(|d| !d.is_empty()).map(str::to_owned).collect::<Vec<_>>();
            if domains.iter().any(|d| !warp_selector(d)) {
                return Err(fail("WARP domains must be valid"));
            }
            api.configure_warp(selected["warp-port"].parse().map_err(|_| fail("invalid WARP port"))?, &domains)?;
        }
        if let Some(subscription) = &subscription {
            let domain = &selected["subscription-domain"];
            api.configure_subscription(
                domain,
                &format!("/etc/letsencrypt/live/{domain}/fullchain.pem"),
                &format!("/etc/letsencrypt/live/{domain}/privkey.pem"),
            )?;
            h::atomic(
                &self.context,
                "/var/lib/proxy-control/three-xui/subscription-url",
                format!("https://{domain}/sub/{subscription}\n").as_bytes(),
                0o600,
            )?;
        }
        for index in 0..3 {
            api.delete_acceptance_client(&format!("acceptance-{index}"), true)?;
        }
        let effective = api.effective_config()?;
        if effective["client_emails"].as_array().is_none_or(|emails| {
            emails.iter().any(|email| email.as_str().is_some_and(|email| email.starts_with("acceptance-")))
        }) {
            return Err(fail("an acceptance client is still present in the effective configuration"));
        }
        h::run(&self.context, &["systemctl", "restart", "x-ui"], None)?;
        self.await_panel()?;
        let access = format!(
            "url = {}\nusername = {}\npassword = {}\n",
            json!(format!("https://{}{web_path}", selected["panel-domain"])),
            json!(username),
            json!(password)
        );
        h::atomic(&self.context, "/var/lib/proxy-control/three-xui/panel-access", access.as_bytes(), 0o600)?;
        Ok(json!({"inbounds":3,"acceptance_clients_removed":3,"warp_outbounds":if selected["warp"]=="true"{1}else{0}}))
    }
}
fn warp_selector(value: &str) -> bool {
    if let Some(selector) = value.strip_prefix("geosite:") {
        !selector.is_empty()
            && selector.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
    } else {
        domain(value.strip_prefix("domain:").unwrap_or(value))
    }
}
fn listening(output: &str) -> std::collections::BTreeSet<u16> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(3))
        .filter_map(|address| address.rsplit(':').next()?.parse().ok())
        .collect()
}
fn copy_tree(source: &Path, target: &Path) -> Result<(), Error> {
    pc_host::fs::durable_mkdir(target, 0o755)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if metadata.is_file() {
            pc_host::fs::durable_copy2(&entry.path(), &target)?;
        } else {
            return Err(fail("3x-ui extracted tree contains a non-regular member"));
        }
    }
    pc_host::fs::fsync_directory(target)?;
    Ok(())
}
impl Adapter for ThreeXuiAdapter {
    fn name(&self) -> &str {
        "three_xui"
    }
    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        if facts.prerequisites.get("hard_stops").and_then(Value::as_array).is_some_and(|stops| !stops.is_empty()) {
            return Err(fail("host audit contains blocking findings"));
        }
        if config.three_xui.mode == ThreeXuiMode::None {
            return Ok(vec![]);
        }
        let routes = self.planned_routes(config)?;
        let mut mutations = vec![format!("mode={}", config.three_xui.mode.value())];
        mutations.extend(routes.into_iter().map(|(domain, backend)| format!("route={domain} {backend}")));
        let mut actions = vec![Action::new(
            "three_xui.routes",
            "three_xui",
            "nginx.routes.three_xui",
            mutations,
            vec![
                "the shared 443 router is owned and verified".into(),
                "every routed 3x-ui inbound answers on loopback".into(),
            ],
            vec!["each owned SNI route reaches its loopback 3x-ui backend".into()],
            vec!["remove only the owned 3x-ui route block".into()],
            false,
        )?];
        if config.three_xui.mode == ThreeXuiMode::Existing {
            return Ok(actions);
        }
        let pin = h::pin(&self.context, "three_xui")?;
        if pin.version != "3.10.2" {
            return Err(fail("release manifest pins an unexpected 3x-ui version"));
        }
        let x = &config.three_xui;
        let hysteria =
            x.hysteria_domain.as_deref().ok_or_else(|| PlanError::new("managed 3x-ui requires a Hysteria2 domain"))?;
        let mutations = vec![
            "version=3.10.2".into(),
            "architecture=amd64".into(),
            format!("release-url={}", pin.url),
            format!("release-digest={}", pin.sha256),
            format!("root={ROOT}"),
            format!("unit={UNIT}"),
            format!("database={DATABASE}"),
            format!("panel-domain={}", x.panel_domain.as_deref().unwrap_or("")),
            format!("hysteria-domain={hysteria}"),
            format!("vless-tcp-domain={}", x.vless_tcp_domain.as_deref().unwrap_or("")),
            format!("vless-xhttp-domain={}", x.vless_xhttp_domain.as_deref().unwrap_or("")),
            "vless-tcp-backend=8449".into(),
            "vless-xhttp-backend=8450".into(),
            "panel-backend=8451".into(),
            format!("warp={}", x.warp),
            format!("warp-port={}", x.warp_port),
            format!("warp-domains={}", x.warp_domains.join(",")),
            format!("subscription-domain={}", x.subscription_domain.as_deref().unwrap_or("")),
        ];
        actions.push(Action::new(
            "three_xui.runtime",
            "three_xui",
            "proxy-control:three-xui",
            mutations,
            vec![
                "no x-ui database, binary tree, unit, user, or listener exists".into(),
                "the pinned release digest matches before and after extraction".into(),
            ],
            vec![
                "the staged binary reports the pinned version".into(),
                "the panel answers only on loopback under its private path".into(),
                "every promised inbound exists and its port is open".into(),
            ],
            vec!["stop the staged unit and remove only the staged generation".into()],
            true,
        )?);
        if x.warp {
            if x.warp_domains.is_empty() {
                return Err(PlanError::new("WARP requires operator-confirmed domains").into());
            }
            let mut domains = x.warp_domains.clone();
            domains.sort();
            let mut mutations = vec!["warp=true".into(), format!("warp-egress=127.0.0.1:{}", x.warp_port)];
            for domain in domains {
                if !warp_selector(&domain) {
                    return Err(PlanError::new("WARP domains must be valid").into());
                }
                mutations.push(format!("warp-domain={domain}"));
            }
            actions.push(Action::new(
                "three_xui.warp",
                "three_xui",
                "proxy-control:three-xui-warp",
                mutations,
                vec![
                    "the managed 3x-ui generation is installed and verified".into(),
                    "the operator confirmed every WARP domain".into(),
                ],
                vec!["the WARP outbound exists and the mandatory final policy is last".into()],
                vec!["remove only the owned WARP outbound and its rules".into()],
                true,
            )?);
        }
        Ok(actions)
    }
    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        if action.id == "three_xui.routes" {
            return Ok(json!({"owner":action.owner,"routes":self.route_map(action)?}).as_object().unwrap().clone());
        }
        if action.id == "three_xui.warp" {
            return Ok(json!({"owner":action.owner,"warp_domains":self.warp_domains(action)?})
                .as_object()
                .unwrap()
                .clone());
        }
        self.runtime_selection(action)?;
        self.assert_absent()?;
        Ok(json!({"marker_value":pc_host::fs::token_hex::<16>(),"owner":action.owner,"ownership":{},"staged":false})
            .as_object()
            .unwrap()
            .clone())
    }
    fn apply(&self, action: &Action, mut checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        if action.id == "three_xui.routes" {
            self.route_map(action)?;
            return Ok(checkpoint);
        }
        if action.id == "three_xui.warp" {
            self.warp_domains(action)?;
            return Ok(checkpoint);
        }
        let selected = self.runtime_selection(action)?;
        if checkpoint.get("owner") != Some(&json!(action.owner))
            || !checkpoint.get("marker_value").and_then(Value::as_str).is_some_and(|value| {
                value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
        {
            return Err(fail("3x-ui checkpoint is invalid"));
        }
        let pin = h::pin(&self.context, "three_xui")?;
        let archive = h::ensure_archive(
            &self.context,
            &format!("/var/cache/proxy-control/three-xui-{}.tar.gz", pin.sha256),
            &pin,
        )?;
        self.assert_absent()?;
        let staging = h::host(
            &self.context,
            &format!("/var/lib/proxy-control/three-xui/staging-{}", pc_host::fs::token_hex::<8>()),
        )?;
        pc_host::fs::durable_mkdir(&staging, 0o700)?;
        let result = (|| {
            let extracted = staging.join("release");
            pc_host::archive::safe_extract_tar(&archive, &extracted, &self.archive_manifest(&pin.sha256)?)
                .map_err(|error| Error::other("ArtifactError", format!("3x-ui release layout/digest does not match: {error}")))?;
            let nested = extracted.join("x-ui");
            let tree = if nested.is_dir() { &nested } else { &extracted };
            let binary = tree.join("x-ui");
            if !binary.is_file() || binary.is_symlink() {
                return Err(fail("3x-ui release has no x-ui binary"));
            }
            let version =
                h::checked(&self.context, &[binary.to_str().ok_or_else(|| fail("invalid staging path"))?, "-v"])?;
            if !version.contains("3.10.2") {
                return Err(fail("staged 3x-ui reports an unpinned version"));
            }
            h::atomic(
                &self.context,
                MARKER,
                format!("{}\n", checkpoint["marker_value"].as_str().unwrap()).as_bytes(),
                0o600,
            )?;
            copy_tree(tree, &h::host(&self.context, ROOT)?)?;
            let unit = if tree.join("x-ui.service").is_file() {
                tree.join("x-ui.service")
            } else {
                tree.join("x-ui.service.debian")
            };
            h::atomic(
                &self.context,
                UNIT,
                &fs::read(unit).map_err(|_| fail("pinned 3x-ui archive has no Debian service unit"))?,
                0o644,
            )?;
            h::run(&self.context, &["systemctl", "daemon-reload"], None)?;
            let provisioned = self.provision(&selected)?;
            h::run(&self.context, &["systemctl", "enable", "x-ui"], None)?;
            checkpoint.insert("staged".into(), json!(true));
            checkpoint.insert("provisioned".into(), provisioned);
            checkpoint.insert(
                "ownership".into(),
                h::ownership(&self.context, &[(UNIT, false, false), (MARKER, false, false)])?,
            );
            Ok(checkpoint)
        })();
        let cleanup = fs::remove_dir_all(staging);
        result.and_then(|checkpoint| {
            cleanup?;
            Ok(checkpoint)
        })
    }
    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, checkpoint)
    }
    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        if action.id == "three_xui.warp" {
            return h::evidence(
                action,
                "the owned WARP outbound covers only confirmed domains",
                json!({"warp_domains":self.warp_domains(action)?.len()}),
            );
        }
        if action.id == "three_xui.routes" {
            let routes = self.route_map(action)?;
            let audit = self.audit_existing()?;
            let installed = audit["installed"] == true;
            if installed {
                let ports = listening(&h::checked(&self.context, &["ss", "-lntH"])?);
                for backend in routes.values() {
                    let port = backend.rsplit(':').next().and_then(|port| port.parse::<u16>().ok()).ok_or_else(|| fail("invalid route backend"))?;
                    let own_listener = [8451, 2096].contains(&port) && ports.contains(&port);
                    let audited = audit["inbounds"].as_array().into_iter().flatten().any(|item| {
                        item["port"].as_u64() == Some(u64::from(port))
                            && ["127.0.0.1", "::1", "localhost"].contains(&item["listen"].as_str().unwrap_or(""))
                    });
                    if !own_listener && !audited {
                        return Err(fail("a routed 3x-ui backend is not an audited loopback inbound"));
                    }
                }
            }
            return h::evidence(
                action,
                "owned 3x-ui routes reach audited loopback inbounds",
                json!({"routes":routes.len(),"installed":installed}),
            );
        }
        self.runtime_selection(action)?;
        if !h::checked(&self.context, &["/usr/local/x-ui/x-ui", "-v"])?.contains("3.10.2") {
            return Err(fail("the installed 3x-ui is not the pinned version"));
        }
        let mut ports = listening(&h::checked(&self.context, &["ss", "-lntH"])?);
        ports.extend(listening(&h::checked(&self.context, &["ss", "-lnuH"])?));
        for port in [8451, 8449, 8450, 443] {
            if !ports.contains(&port) {
                return Err(fail(&format!("a provisioned 3x-ui inbound is not listening on port {port}")));
            }
        }
        h::evidence(
            action,
            "every provisioned inbound is listening",
            json!({"version_pinned":true,"inbounds_listening":3}),
        )
    }
    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error> {
        if action.id == "three_xui.routes" {
            self.route_map(action)?;
            return Ok(checkpoint);
        }
        if action.id == "three_xui.warp" {
            self.warp_domains(action)?;
            return Ok(checkpoint);
        }
        self.runtime_selection(action)?;
        let ownership = checkpoint
            .get("ownership")
            .and_then(Value::as_object)
            .ok_or_else(|| fail("3x-ui checkpoint is invalid"))?;
        for (path, entry) in ownership {
            if pc_host::fs::sha256_file(&h::host(&self.context, path)?)? != entry["sha256"].as_str().unwrap_or("") {
                return Err(fail("3x-ui owned file has drifted"));
            }
        }
        h::run(&self.context, &["systemctl", "restart", "x-ui"], None)?;
        self.await_panel()?;
        Ok(checkpoint)
    }
    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        if action.id == "three_xui.routes" {
            self.route_map(action)?;
            return h::evidence(
                action,
                "no 3x-ui state was mutated by this action",
                json!({"persistent_data_preserved":true}),
            );
        }
        if action.id == "three_xui.warp" {
            self.warp_domains(action)?;
            return h::evidence(
                action,
                "no 3x-ui state was mutated by this action",
                json!({"persistent_data_preserved":true}),
            );
        }
        self.runtime_selection(action)?;
        let marker_path = h::host(&self.context, MARKER)?;
        if fs::symlink_metadata(&marker_path).is_ok_and(|metadata| !metadata.is_file()) {
            return Err(fail("3x-ui ownership marker is not a regular file"));
        }
        let expected = checkpoint
            .get("marker_value")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("3x-ui checkpoint is invalid"))?;
        match fs::read_to_string(&marker_path) {
            Ok(marker) if marker.trim() == expected => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return h::evidence(
                    action,
                    "no owned 3x-ui generation was staged",
                    json!({"persistent_data_preserved":true}),
                );
            }
            _ => return Err(fail("3x-ui ownership marker does not match the staged generation")),
        }
        let _ = h::run(&self.context, &["systemctl", "disable", "--now", "x-ui"], None);
        let status = h::capture(&self.context, &["systemctl", "is-active", "x-ui"]);
        if !["inactive", "failed", "unknown"].contains(&status.trim()) {
            return Err(fail("3x-ui is still active or its stop is unconfirmed"));
        }
        let destructive = purge && target == RollbackTarget::Uninstalled;
        let ownership = checkpoint
            .get("ownership")
            .and_then(Value::as_object)
            .ok_or_else(|| fail("3x-ui checkpoint is invalid"))?;
        for path in ownership.keys() {
            if ![UNIT, MARKER].contains(&path.as_str()) {
                return Err(fail("3x-ui checkpoint is invalid"));
            }
            h::remove(&self.context, path)?;
        }
        let tree = h::host(&self.context, ROOT)?;
        if tree.is_dir() && !tree.is_symlink() {
            fs::remove_dir_all(&tree)?;
        } else if tree.exists() || tree.is_symlink() {
            return Err(fail("3x-ui binary tree is unsafe"));
        }
        h::remove(&self.context, MARKER)?;
        if destructive {
            for path in [DATABASE, "/etc/x-ui/x-ui.db-wal", "/etc/x-ui/x-ui.db-shm", "/etc/x-ui/system_metrics.gob"] {
                if fs::symlink_metadata(h::host(&self.context, path)?).is_ok_and(|m| !m.is_file()) {
                    return Err(fail("3x-ui data path is not a regular file"));
                }
                h::remove(&self.context, path)?;
            }
            let directory = h::host(&self.context, "/etc/x-ui")?;
            if directory.is_dir() && fs::read_dir(&directory)?.next().is_none() {
                pc_host::fs::durable_remove(&directory, true)?;
            }
        }
        let _ = h::run(&self.context, &["systemctl", "daemon-reload"], None);
        h::evidence(
            action,
            "the staged 3x-ui generation was removed",
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

/// Hidden executable dialogue; all credentials arrive over stdin inside the isolated namespace.
pub fn bootstrap_dialogue(payload: &Value) -> Result<(), Error> {
    let text = |key: &str| payload[key].as_str().ok_or_else(|| fail("invalid bootstrap payload"));
    let port =
        payload["port"].as_u64().and_then(|p| u16::try_from(p).ok()).ok_or_else(|| fail("invalid bootstrap port"))?;
    let panel_port = payload["panel_port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .ok_or_else(|| fail("invalid bootstrap port"))?;
    let mut api = ThreeXuiApi::new(ThreeXuiClient::new("127.0.0.1", port, None)?, "/")?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match api.login(text("initial_username")?, text("initial_password")?) {
            Ok(()) => break,
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    }
    api.rotate_credentials(text("initial_username")?, text("initial_password")?, text("username")?, text("password")?)?;
    api.login(text("username")?, text("password")?)?;
    if api.login(text("initial_username")?, text("initial_password")?).is_ok() {
        return Err(fail("the upstream first-run credential still works"));
    }
    api.login(text("username")?, text("password")?)?;
    api.configure_panel(
        text("web_path")?,
        panel_port,
        "127.0.0.1",
        Some(text("certificate")?),
        Some(text("private_key")?),
    )
}
