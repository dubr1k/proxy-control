//! Mieru host adapter. Packages remain external artifacts, extracted with host dpkg-deb, never installed.
use super::proxy_common::*;
use super::AdapterContext;
use crate::adapter::Adapter;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use installer_core::model::InstallerConfig;
use installer_core::planner::{Action, AuditFacts, Evidence};
use pc_host::archive::{validate_release_url, verify_artifact, ArtifactPin};
use pc_host::fs::{atomic_write, sha256_file, sha256_hex, token_hex};
use pc_host::net::{ClientOptions, HttpsClient, UPSTREAM_HOSTS};
use serde_json::{json, Map, Value};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const VERSION: &str = "3.38.1";
pub const BINARY: &str = "/usr/bin/mita";
pub const PACKAGE_URL: &str = "https://github.com/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb";
pub const PACKAGE_DIGEST: &str = "2c7c0be33d34cf126187d97c17484a34b5c62b764c96b0a88ec4cbc7660d72c9";
pub const EXECUTABLE_DIGEST: &str = "991179df309924d86251fa9b8109d67dc178d4161f0b83e4a5092940a79aa207";
pub const CLIENT_URL: &str = "https://github.com/enfein/mieru/releases/download/v3.38.1/mieru_3.38.1_amd64.deb";
pub const CLIENT_DIGEST: &str = "f758f886039efcceb6aa9e88c6393ad1d7326e533e0e9a01d378e49bedaa5563";
pub const CLIENT_EXECUTABLE: &str = "3529fc7190e073d89da1ea9bbf08aa481edca59866c466725b8231325b0b6577";
pub const CLIENT_IMAGE: &str = "proxy-control-mieru-client:3.38.1";
const LICENSE: &str = "/usr/share/doc/mita/copyright";
pub const LICENSE_NOTICE:&[u8]=b"Upstream-Name: mieru / mita\nSource: https://github.com/enfein/mieru\nLicense: GPL-3.0-or-later\n\nThe mita executable installed next to this notice is unmodified upstream\nsoftware distributed under the GNU General Public License version 3 or\nlater. Its complete source and licence text are published at the address\nabove. Proxy Control installs only the executable and this notice; the\npackage itself is never installed.\n";
const STATE: &str = "/var/lib/mita";
const CONFIG: &str = "/var/lib/mita/server_config.json";
const BOOTSTRAP: &str = "/var/lib/mita/bootstrap-input.json";
const UNIT: &str = "/etc/systemd/system/mita.service";
const SLOT_UNIT: &str = "/etc/systemd/system/mita@.service";
const TMPFILES: &str = "/etc/tmpfiles.d/mita.conf";
pub(super) const SOCKET: &str = "/run/mita/mita.sock";
const TOKEN: &str = "/etc/mieru-manager/token";
const MANAGER_STATE: &str = "/var/lib/mieru-manager";
const STATE_PREPARER: &str = "/usr/local/libexec/prepare-mieru-state";
const TOKEN_PREPARER: &str = "/usr/local/libexec/prepare-mieru-token";
const ENV: &str = "/opt/mtproxy-shared443/.env.mieru";
const RUNNING: &str = "mita server status is \"RUNNING\"";
const IDLE: &str = "mita server status is \"IDLE\"";
const HELPERS: &[(&str, &str, u32)] = &[
    ("scripts/prepare-mieru-state.sh", STATE_PREPARER, 0o755),
    ("prepare-mieru-token", TOKEN_PREPARER, 0o755),
    ("deploy/mita.service", UNIT, 0o644),
    ("deploy/mita.tmpfiles.conf", TMPFILES, 0o644),
    ("deploy/mita@.service", SLOT_UNIT, 0o644),
];
const OWNED: &[(&str, bool, bool)] = &[
    ("/etc/proxy-control/mieru-owned", true, false),
    (UNIT, false, false),
    (SLOT_UNIT, false, false),
    (TMPFILES, false, false),
    (STATE_PREPARER, false, false),
    (TOKEN_PREPARER, false, false),
    (LICENSE, false, false),
    (ENV, false, false),
    ("/etc/proxy-control/mieru-acceptance-owner", false, true),
    (TOKEN, true, false),
    (CONFIG, true, true),
];
const KEYS: &[&str] = &[
    "acceptance_name",
    "adoption",
    "binary_preexisting",
    "identities_created",
    "marker_value",
    "owner",
    "ownership",
    "planned_ownership",
    "state_preexisting",
    "token_preexisting",
];
#[derive(Debug, Clone)]
pub struct MieruSelection {
    pub host: String,
    pub panel: String,
    pub architecture: String,
    pub package: String,
    pub package_url: String,
    pub package_digest: String,
    pub executable_digest: String,
    pub bootstrap_user: String,
    pub transports: Vec<(String, u16)>,
    pub egress: String,
    pub warp_port: u16,
    pub warp_provider: String,
    pub router_provider: String,
    pub lane_slots: u32,
    pub adjacent_listeners: Vec<(String, u16)>,
}
/// The private extraction tree is removed on every return path, including failures.
pub struct StagedMita {
    pub binary: PathBuf,
    pub license: PathBuf,
    pub version: String,
    pub package_sha256: String,
    pub executable_sha256: String,
    _directory: PrivateDirectory,
}
pub(super) struct PrivateDirectory {
    pub path: PathBuf,
}
impl PrivateDirectory {
    pub fn new(parent: &Path, prefix: &str) -> Result<Self, Error> {
        fs::create_dir_all(parent)?;
        for _ in 0..32 {
            let path = parent.join(format!("{prefix}{}", token_hex::<8>()));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(Error::other("ArtifactError", "cannot create private staging directory"))
    }
}
use std::os::unix::fs::DirBuilderExt;
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
pub struct MieruAdapter {
    pub(super) host: Host,
    pin: Option<ArtifactPin>,
    #[cfg(test)]
    pub(super) test_acceptance: Option<super::proxy_acceptance::TestAcceptance>,
    #[cfg(test)]
    pub(super) client_pins: Option<(String, String, String)>,
}
impl MieruAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self {
            host: Host { context: context.clone(), name: "mieru", label: "Mieru" },
            pin: None,
            #[cfg(test)]
            test_acceptance: None,
            #[cfg(test)]
            client_pins: None,
        }
    }
    pub fn with_pin(context: &AdapterContext, pin: ArtifactPin) -> Result<Self, Error> {
        let mut adapter = Self::new(context);
        adapter.pin = Some(pin);
        adapter.pins()?;
        Ok(adapter)
    }
    fn pins(&self) -> Result<(&str, &str, &str), Error> {
        if let Some(pin) = &self.pin {
            if pin.name != "mita"
                || pin.version != VERSION
                || pin.architecture != "amd64"
                || pin.executable_path.as_deref() != Some("usr/bin/mita")
                || pin.executable_sha256.is_none()
            {
                return Err(self.host.artifact("release pin does not describe pinned mita"));
            }
            validate_release_url(&pin.url, "enfein/mieru", "v3.38.1", "amd64")
                .map_err(|_| self.host.artifact("release pin does not describe pinned mita"))?;
            return Ok((&pin.url, &pin.sha256, pin.executable_sha256.as_deref().unwrap()));
        }
        Ok((PACKAGE_URL, PACKAGE_DIGEST, EXECUTABLE_DIGEST))
    }
    pub fn selection(&self, action: &Action) -> Result<MieruSelection, Error> {
        let values = mutations(
            action,
            "mieru",
            &[
                "project",
                "mieru-host",
                "panel-domain",
                "mita-version",
                "architecture",
                "package-url",
                "package-digest",
                "executable-digest",
                "binary",
                "unit",
                "socket",
                "manager-uid",
                "manager-gid",
                "bootstrap-user",
                "transports",
                "egress",
            ],
            &["package", "warp-port", "warp-provider", "router-provider", "lane-slots", "adjacent-listeners"],
        )?;
        let expected = [
            ("project", PROJECT),
            ("binary", BINARY),
            ("unit", UNIT),
            ("socket", SOCKET),
            ("mita-version", VERSION),
            ("architecture", "amd64"),
            ("manager-uid", "10005"),
            ("manager-gid", "10005"),
        ];
        if expected.iter().any(|(key, value)| values[*key] != *value)
            || !domain(&values["mieru-host"])
            || !domain(&values["panel-domain"])
            || !safe_chars(&values["bootstrap-user"], 1, 64, "_-")
            || !is_hex(&values["package-digest"], 64)
            || !is_hex(&values["executable-digest"], 64)
            || !matches!(values["egress"].as_str(), "direct" | "proxy" | "router")
        {
            return Err(self.host.error("Mieru action is invalid"));
        }
        validate_release_url(&values["package-url"], "enfein/mieru", "v3.38.1", "amd64")
            .map_err(|_| self.host.error("Mieru action has an invalid package URL"))?;
        let package = values
            .get("package")
            .cloned()
            .unwrap_or_else(|| format!("/var/lib/proxy-control/mita_{VERSION}_amd64.deb"));
        self.host.host(&package)?;
        let (warp_port, warp_provider, router_provider) = providers(&values, 45102, &self.host)?;
        let count = values.get("lane-slots").map(String::as_str).unwrap_or("0");
        if count.is_empty() || !count.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(self.host.error("invalid lane slot count"));
        }
        let lane_slots = count
            .parse::<u32>()
            .ok()
            .filter(|count| *count <= 8)
            .ok_or_else(|| self.host.error("invalid lane slot count"))?;
        if lane_slots > 0 && router_provider.is_empty() {
            return Err(self.host.error("lane slots need the node's Xray-router"));
        }
        let transports = decode_transports(&values["transports"])?;
        if transports
            .iter()
            .any(|(protocol, port)| protocol == "TCP" && (1..=lane_slots).any(|i| *port == 46100 + i as u16))
        {
            return Err(self.host.error("Mieru lane slot ports collide with the selected listeners"));
        }
        let mut adjacent_listeners = Vec::new();
        if let Some(value) = values.get("adjacent-listeners") {
            for encoded in value.split(';') {
                let (protocol, port) =
                    encoded.split_once(':').ok_or_else(|| self.host.error("invalid adjacent listener selection"))?;
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| self.host.error("invalid adjacent listener selection"))?;
                if !["TCP", "UDP"].contains(&protocol) || adjacent_listeners.contains(&(protocol.to_string(), port)) {
                    return Err(self.host.error("invalid adjacent listener selection"));
                }
                adjacent_listeners.push((protocol.to_string(), port));
            }
            adjacent_listeners.sort();
        }
        Ok(MieruSelection {
            host: values["mieru-host"].clone(),
            panel: values["panel-domain"].clone(),
            architecture: values["architecture"].clone(),
            package,
            package_url: values["package-url"].clone(),
            package_digest: values["package-digest"].clone(),
            executable_digest: values["executable-digest"].clone(),
            bootstrap_user: values["bootstrap-user"].clone(),
            transports,
            egress: values["egress"].clone(),
            warp_port,
            warp_provider,
            router_provider,
            lane_slots,
            adjacent_listeners,
        })
    }
    pub fn bootstrap_config(
        &self,
        selected: &MieruSelection,
        password: &str,
        router: Option<(&str, &str)>,
    ) -> Result<Value, Error> {
        let mut document = json!({"portBindings":selected.transports.iter().map(|(protocol,port)|json!({"port":port,"protocol":protocol})).collect::<Vec<_>>(),"users":[{"name":selected.bootstrap_user,"password":password}],"loggingLevel":"INFO","mtu":1400});
        document["egress"] = if selected.egress == "router" {
            let (user, password) = router
                .ok_or_else(|| self.host.error("the Xray-router ingress credential is required for egress=router"))?;
            json!({"proxies":[{"name":"router","protocol":"SOCKS5_PROXY_PROTOCOL","host":"127.0.0.1","port":45102,"socks5Authentication":{"user":user,"password":password}}],"rules":[{"action":"PROXY","ipRanges":["*"],"domainNames":["*"],"proxyNames":["router"]}]})
        } else {
            json!({"proxies":[{"name":"warp","protocol":"SOCKS5_PROXY_PROTOCOL","host":"127.0.0.1","port":selected.warp_port}],"rules":[{"ipRanges":["0.0.0.0/0","::/0"],"domainNames":[],"action":if selected.egress=="proxy"{"PROXY"}else{"DIRECT"},"proxyNames":if selected.egress=="proxy"{vec!["warp"]}else{Vec::new()}}]})
        };
        Ok(document)
    }
    /// Python's transient bootstrap JSON retains insertion order without a global ordered-map feature.
    pub fn bootstrap_input(
        &self,
        selected: &MieruSelection,
        password: &str,
        router: Option<(&str, &str)>,
    ) -> Result<Vec<u8>, Error> {
        let scalar = |text: &str| serde_json::to_string(text).expect("JSON string serializes");
        let bindings = selected
            .transports
            .iter()
            .map(|(protocol, port)| format!("{{\"port\":{port},\"protocol\":{}}}", scalar(protocol)))
            .collect::<Vec<_>>()
            .join(",");
        let egress = if selected.egress == "router" {
            let (user, password) = router
                .ok_or_else(|| self.host.error("the Xray-router ingress credential is required for egress=router"))?;
            format!("{{\"proxies\":[{{\"name\":\"router\",\"protocol\":\"SOCKS5_PROXY_PROTOCOL\",\"host\":\"127.0.0.1\",\"port\":45102,\"socks5Authentication\":{{\"user\":{},\"password\":{}}}}}],\"rules\":[{{\"action\":\"PROXY\",\"ipRanges\":[\"*\"],\"domainNames\":[\"*\"],\"proxyNames\":[\"router\"]}}]}}",scalar(user),scalar(password))
        } else {
            format!("{{\"proxies\":[{{\"name\":\"warp\",\"protocol\":\"SOCKS5_PROXY_PROTOCOL\",\"host\":\"127.0.0.1\",\"port\":{}}}],\"rules\":[{{\"ipRanges\":[\"0.0.0.0/0\",\"::/0\"],\"domainNames\":[],\"action\":\"{}\",\"proxyNames\":{}}}]}}",selected.warp_port,if selected.egress=="proxy"{"PROXY"}else{"DIRECT"},if selected.egress=="proxy"{"[\"warp\"]"}else{"[]"})
        };
        Ok(format!("{{\"portBindings\":[{bindings}],\"users\":[{{\"name\":{},\"password\":{}}}],\"loggingLevel\":\"INFO\",\"mtu\":1400,\"egress\":{egress}}}\n",scalar(&selected.bootstrap_user),scalar(password)).into_bytes())
    }
    pub fn env_text(&self, selected: &MieruSelection, gid: u32) -> String {
        let slots = (1..=selected.lane_slots)
            .map(|i| format!("{i}:{}:/run/mita/lane-{i}.sock:/var/lib/mita/lanes/{i}", 46100 + i))
            .collect::<Vec<_>>()
            .join(",");
        format!("MIERU_PUBLIC_HOST={}\nMIERU_MITA_BIN={BINARY}\nMIERU_MITA_SHA256={}\nMIERU_MITA_GID={gid}\nMIERU_MANAGER_STATE_DIR={MANAGER_STATE}\nMIERU_MANAGER_TOKEN_FILE={TOKEN}\nMIERU_EGRESS_WARP={}\nMIERU_EGRESS_ROUTER={}\nMIERU_EGRESS_ROUTER_CREDENTIAL_FILE={}\nMIERU_LANE_SLOTS={slots}\n",selected.host,selected.executable_digest,selected.warp_provider,selected.router_provider,if selected.router_provider.is_empty(){String::new()}else{format!("{MANAGER_STATE}/xray-router-ingress")})
    }
    fn live_identities(&self) -> Result<(), Error> {
        for kind in ["uid", "gid"] {
            if let Some(name) = self.host.identity(kind, 10005) {
                if !["mita", "mieru-manager"].contains(&name.as_str()) {
                    return Err(self.host.error(format!("{} 10005 collision: {name}", kind.to_uppercase())));
                }
            }
        }
        Ok(())
    }
    fn identity_named(&self, database: &str) -> bool {
        let output = self.host.capture(&["getent", database, "mita"], 512);
        let fields: Vec<_> = output.trim().split(':').collect();
        fields.len() >= 4 && fields[0] == "mita" && fields[2].parse::<u32>().is_ok()
    }
    fn mita_identity(&self) -> Result<(u32, u32), Error> {
        let output = self.host.capture(&["getent", "passwd", "mita"], 512);
        for line in output.lines() {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() >= 4 && fields[0] == "mita" {
                if let (Ok(uid), Ok(gid)) = (fields[2].parse::<u32>(), fields[3].parse::<u32>()) {
                    if uid > 0 && gid > 0 {
                        return Ok((uid, gid));
                    }
                }
            }
        }
        Err(self.host.error("mita service identity is unavailable"))
    }
    fn ensure_identities(&self) -> Result<Value, Error> {
        self.live_identities()?;
        let group = !self.identity_named("group");
        let user = !self.identity_named("passwd");
        if group {
            self.host.run(&["groupadd", "--system", "mita"])?;
        }
        if user {
            self.host.run(&[
                "useradd",
                "--system",
                "--gid",
                "mita",
                "--home",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "mita",
            ])?;
        }
        Ok(json!({"group":group,"user":user}))
    }
    fn fetch(&self, package: &Path, url: &str, digest: &str) -> Result<(), Error> {
        ensure_pinned_package(package, url, digest, |url, staging| {
            let mut output = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(staging)?;
            let client = HttpsClient::new(ClientOptions {
                user_agent: "proxy-control".into(),
                timeout: Duration::from_secs(120),
                ..ClientOptions::default()
            })
            .map_err(|_| self.host.artifact("fetching the pinned package failed"))?;
            let response = client
                .download(url, UPSTREAM_HOSTS, &[], 256 * 1024 * 1024, &mut output)
                .map_err(|_| self.host.artifact("fetching the pinned package failed"))?;
            if response.status != 200 {
                return Err(self.host.artifact(format!("fetching the pinned package returned {}", response.status)));
            }
            output.sync_all()?;
            Ok(())
        })
    }
    pub fn stage(&self, action: &Action) -> Result<StagedMita, Error> {
        let selected = self.selection(action)?;
        let package = self.host.host(&selected.package)?;
        // The URL carried by the reviewed action is authoritative, not the built-in default pin.
        self.fetch(&package, &selected.package_url, &selected.package_digest)?;
        verify_artifact(&package, &selected.package_digest)
            .map_err(|_| self.host.artifact("mita package digest does not match"))?;
        let directory = PrivateDirectory::new(&self.host.host("/var/tmp")?, "proxy-control-mita-")?;
        self.host.run(&["dpkg-deb", "-x", &package.to_string_lossy(), &directory.path.to_string_lossy()])?;
        let binary = checked_extracted(&directory.path, "usr/bin/mita")?;
        if sha256_file(&binary)? != selected.executable_digest {
            return Err(self.host.artifact("mita executable digest does not match"));
        }
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
        let version = self.host.checked(&[&binary.to_string_lossy(), "version"])?;
        if version.split_whitespace().last() != Some(VERSION) {
            return Err(self.host.artifact("mita executable reports an unpinned version"));
        }
        let license = directory.path.join("usr/share/doc/mita/copyright");
        if fs::symlink_metadata(&license).is_ok() {
            checked_extracted(&directory.path, "usr/share/doc/mita/copyright")?;
        } else {
            for parent in ["usr", "usr/share", "usr/share/doc", "usr/share/doc/mita"] {
                let path = directory.path.join(parent);
                if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_dir()) {
                    return Err(self.host.artifact("mita license material is unsafe"));
                }
                fs::create_dir_all(path)?;
            }
            atomic_write(&license, LICENSE_NOTICE, 0o644, None)?;
        }
        Ok(StagedMita {
            binary,
            license,
            version: version.trim().into(),
            package_sha256: selected.package_digest,
            executable_sha256: selected.executable_digest,
            _directory: directory,
        })
    }
    fn client_pins(&self) -> (&str, &str, &str) {
        #[cfg(test)]
        if let Some((url, digest, executable)) = &self.client_pins {
            return (url, digest, executable);
        }
        (CLIENT_URL, CLIENT_DIGEST, CLIENT_EXECUTABLE)
    }
    fn build_client_image(&self) -> Result<(), Error> {
        let (url, digest, executable) = self.client_pins();
        let package = self.host.host(&format!("/var/lib/proxy-control/mieru_{VERSION}_amd64.deb"))?;
        self.fetch(&package, url, digest)?;
        verify_artifact(&package, digest)
            .map_err(|_| self.host.artifact("mieru client package digest does not match"))?;
        let directory = PrivateDirectory::new(&self.host.host("/var/tmp")?, "proxy-control-mieru-client-")?;
        let extracted = directory.path.join("package");
        self.host.run(&["dpkg-deb", "-x", &package.to_string_lossy(), &extracted.to_string_lossy()])?;
        let binary = checked_extracted(&extracted, "usr/bin/mieru")?;
        if sha256_file(&binary)? != executable {
            return Err(self.host.artifact("mieru client executable digest does not match"));
        }
        let context = directory.path.join("context");
        fs::create_dir(&context)?;
        atomic_write(&context.join("mieru"), &fs::read(binary)?, 0o755, None)?;
        for name in ["Dockerfile", "Cargo.toml", "Cargo.lock"] {
            let source = self.host.context.tree.join("deploy/mieru-client").join(name);
            let bytes =
                fs::read(source).map_err(|_| self.host.artifact("installer source generation is incomplete"))?;
            atomic_write(&context.join(name), &bytes, 0o644, None)?;
        }
        copy_probe_sources(&self.host.context.tree.join("deploy/mieru-client/src"), &context.join("src"))?;
        self.host.run(&["docker", "build", "--tag", CLIENT_IMAGE, &context.to_string_lossy()])
    }
    fn checkpoint(&self, data: &CheckpointData, action: &Action, applied: bool) -> Result<(), Error> {
        let mut paths: Vec<_> = OWNED.iter().map(|(p, _, _)| *p).collect();
        paths.push(BINARY);
        self.host.validate_checkpoint(data, action, KEYS, applied, &paths)
    }
    fn planned(&self, name: &str, marker: &str) -> Result<Value, Error> {
        let mut planned = Map::new();
        planned.insert(self.host.marker(), json!({"preserve":true,"sha256":marker}));
        planned.insert(self.host.acceptance_owner(), declaration(false, format!("{name}\n").as_bytes()));
        self.host.planned_helpers(HELPERS, &mut planned)?;
        Ok(Value::Object(planned))
    }
    fn prepare_mita_state(&self) -> Result<(), Error> {
        let path = self.host.host(STATE)?;
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_dir()) {
            return Err(self.host.error("mita state path is occupied"));
        }
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        if self.host.owner().is_some() {
            let (uid, gid) = self.mita_identity()?;
            let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(|_| self.host.error("mita state path is unsafe"))?;
            if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
    fn bootstrap(&self, selected: &MieruSelection, data: &CheckpointData) -> Result<(), Error> {
        if let Some(marker) = data["marker_value"].as_str() {
            self.host.atomic(&self.host.marker(), format!("{marker}\n").as_bytes(), 0o600)?;
        }
        self.host.write_acceptance(data["acceptance_name"].as_str().unwrap())?;
        if self.host.exists(CONFIG)? {
            let info = fs::symlink_metadata(self.host.host(CONFIG)?)?;
            if !info.is_file() {
                return Err(self.host.error("mita config is unsafe"));
            }
            return Ok(());
        }
        let router = if selected.egress == "router" { Some(self.host.router_credential()?) } else { None };
        let bytes = self.bootstrap_input(
            selected,
            &super::proxy_acceptance::random_urlsafe::<24>()?,
            router.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
        )?;
        self.host.atomic(BOOTSTRAP, &bytes, 0o600)?;
        if self.host.owner().is_some() {
            let (uid, gid) = self.mita_identity()?;
            self.host.chown(BOOTSTRAP, uid, gid, 0o600)?;
        }
        self.host.best_effort(&["systemctl", "reset-failed", "mita-bootstrap.service"])?;
        let result: Result<(), Error> = (|| {
            self.host.run(&[
                "systemd-run",
                "--unit=mita-bootstrap",
                "--property=User=mita",
                "--property=Group=mita",
                &format!("--setenv=MITA_CONFIG_JSON_FILE={CONFIG}"),
                &format!("--setenv=MITA_UDS_PATH={SOCKET}"),
                BINARY,
                "run",
            ])?;
            for arguments in [&["apply", "config", BOOTSTRAP][..], &["start"][..], &["stop"][..]] {
                let mut argv = strings(&["sudo", "-u", "mita", "env", &format!("MITA_UDS_PATH={SOCKET}"), BINARY]);
                argv.extend(arguments.iter().map(|s| s.to_string()));
                self.host.run(&refs(&argv))?;
            }
            Ok(())
        })();
        let stop = self.host.best_effort(&["systemctl", "stop", "mita-bootstrap.service"]);
        let reset = self.host.best_effort(&["systemctl", "reset-failed", "mita-bootstrap.service"]);
        let remove = self.host.remove(BOOTSTRAP);
        result?;
        stop?;
        reset?;
        remove
    }
    pub(super) fn running(&self) -> bool {
        self.host
            .checked(&["env", &format!("MITA_UDS_PATH={SOCKET}"), BINARY, "status"])
            .is_ok_and(|s| s.trim() == RUNNING)
    }
    fn assert_running(&self) -> Result<(), Error> {
        if !self.running() {
            return Err(self.host.error("mita did not reach the exact RUNNING status"));
        }
        Ok(())
    }
    fn slots(&self, selected: &MieruSelection, start: bool) -> Result<(), Error> {
        for index in 1..=selected.lane_slots {
            if start {
                self.host.run(&["systemctl", "enable", "--now", &format!("mita@{index}")])?;
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let output = self
                    .host
                    .checked(&["env", &format!("MITA_UDS_PATH=/run/mita/lane-{index}.sock"), BINARY, "status"])
                    .unwrap_or_default();
                if [IDLE, RUNNING].contains(&output.trim()) {
                    break;
                }
                if !start && output.trim().is_empty() {
                    return Err(self.host.error(format!("lane slot {index} did not answer on its socket")));
                }
                if !sleep_poll(deadline) {
                    return Err(self.host.error(format!("lane slot {index} did not answer on its socket")));
                }
            }
        }
        Ok(())
    }
    fn prepare_manager(&self, selected: &MieruSelection, gid: u32) -> Result<(), Error> {
        if !self.host.exists(TOKEN)? {
            self.host.atomic(TOKEN, format!("{}\n", token_hex::<32>()).as_bytes(), 0o600)?;
        }
        self.host.run(&[TOKEN_PREPARER, "prepare", TOKEN])?;
        let state = self.host.host(MANAGER_STATE)?;
        let mode = if state.is_dir() && fs::read_dir(&state)?.next().is_some() { "verify" } else { "prepare" };
        self.host.run(&[STATE_PREPARER, mode, MANAGER_STATE])?;
        let ingress = format!("{MANAGER_STATE}/xray-router-ingress");
        if selected.router_provider.is_empty() {
            self.host.remove(&ingress)?;
        } else {
            let (user, password) = self.host.router_credential()?;
            self.host.atomic(&ingress, format!("{user}:{password}\n").as_bytes(), 0o400)?;
            self.host.chown(&ingress, 10005, 10005, 0o400)?;
        }
        self.host.atomic(ENV, self.env_text(selected, gid).as_bytes(), 0o600)
    }
    fn complete_partial_inverse(
        &self,
        action: &Action,
        selected: &MieruSelection,
        data: &mut CheckpointData,
    ) -> Result<(), Error> {
        if !data["ownership"].as_object().expect("validated checkpoint").is_empty() {
            return Ok(());
        }
        let mut additional = Vec::new();
        if data["binary_preexisting"] == false && self.host.exists(BINARY)? {
            let actual = sha256_file(&self.host.host(BINARY)?)?;
            if actual != selected.executable_digest
                && self.host.agent_value("mita", "sha256").as_deref() != Some(&actual)
            {
                return Err(self.host.error("Mieru owned binary has drifted"));
            }
            if self.host.exists(LICENSE)? {
                // A failed apply cannot return its ownership. Re-prove the cached package
                // instead of guessing which license bytes the interrupted stage installed.
                let staged = self.stage(action)?;
                additional.push((LICENSE, declaration(false, &fs::read(&staged.license)?)));
            }
        }
        if self.host.exists(ENV)? {
            if let Ok(socket) = fs::symlink_metadata(self.host.host(SOCKET)?) {
                if socket.file_type().is_socket() {
                    additional.push((ENV, declaration(false, self.env_text(selected, socket.gid()).as_bytes())));
                }
            }
        }
        let planned = data["planned_ownership"].as_object_mut().expect("validated checkpoint");
        for (path, entry) in additional {
            planned.insert(path.into(), entry);
        }
        Ok(())
    }
    // An agent may refresh only the executable SHA line. Reconstruct all other bytes from the
    // approved action and the live socket group before accepting that ownership handoff.
    fn rebase_agent_env(&self, selected: &MieruSelection, data: &mut CheckpointData) -> Result<(), Error> {
        let Some(digest) = self.host.agent_value("mita", "sha256") else {
            return Ok(());
        };
        if pc_host::archive::verify_artifact(&self.host.host(BINARY)?, &digest).is_err() {
            return Ok(());
        }
        let Ok(info) = fs::symlink_metadata(self.host.host(SOCKET)?) else {
            return Ok(());
        };
        if !info.file_type().is_socket() {
            return Ok(());
        }
        let mut current = selected.clone();
        current.executable_digest = digest;
        let Ok(actual) = fs::read(self.host.host(ENV)?) else {
            return Ok(());
        };
        if actual == self.env_text(&current, info.gid()).as_bytes() {
            if let Some(entry) =
                data.get_mut("ownership").and_then(Value::as_object_mut).and_then(|entries| entries.get_mut(ENV))
            {
                entry["sha256"] = sha256_hex(&actual).into();
            }
        }
        Ok(())
    }
}
impl Adapter for MieruAdapter {
    fn name(&self) -> &str {
        "mieru"
    }
    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        if !config.profile.includes_mieru() {
            return Ok(Vec::new());
        }
        if !safe_chars(&config.initial_user, 1, 64, "_-") {
            return Err(plan_error("a valid bootstrap user is required"));
        }
        let host = config
            .domains
            .mieru
            .as_deref()
            .filter(|s| domain(s))
            .ok_or_else(|| plan_error("Mieru public host is missing or invalid"))?;
        let mieru = config.mieru.as_ref().ok_or_else(|| plan_error("Mieru listener selection is missing"))?;
        let mut transports: Vec<_> = mieru
            .tcp_ports
            .iter()
            .map(|p| ("TCP".to_string(), *p))
            .chain(mieru.udp_ports.iter().map(|p| ("UDP".to_string(), *p)))
            .collect();
        if transports.is_empty() {
            return Err(plan_error("at least one Mieru listener is required"));
        }
        if transports.iter().any(|(_, p)| *p == 443) {
            return Err(plan_error("Mieru must not claim the shared 443 listener"));
        }
        if transports.iter().any(|(_, p)| *p == 0) {
            return Err(plan_error("Mieru listener ports must be valid"));
        }
        transports.sort();
        if transports.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(plan_error("Mieru listeners must be unique"));
        }
        let slots: Vec<_> = (1..=mieru.lane_slots).map(|i| ("TCP".to_string(), 46100 + i as u16)).collect();
        if slots.iter().any(|slot| transports.contains(slot)) {
            return Err(plan_error("Mieru lane slot ports collide with the selected listeners"));
        }
        audited_identities(facts, &[("uid", 10005, Some("mieru-manager")), ("gid", 10005, Some("mieru-manager"))])?;
        for (protocol, port) in transports.iter().chain(&slots) {
            let claimed = facts
                .listeners
                .get(&protocol.to_lowercase())
                .and_then(Value::as_array)
                .is_some_and(|ports| ports.iter().any(|p| p.as_u64() == Some(*port as u64)));
            if claimed {
                let own = facts
                    .listeners
                    .get("owners")
                    .and_then(|v| v.get(port.to_string()))
                    .and_then(Value::as_array)
                    .is_some_and(|owners| !owners.is_empty() && owners.iter().all(|o| o == "mita"));
                if !own {
                    return Err(plan_error(format!("{protocol} port {port} is already claimed by another listener")));
                }
            }
        }
        let (url, package_digest, executable_digest) = self.pins()?;
        let egress = config.effective_egress();
        let mut mutations = vec![
            format!("project={PROJECT}"),
            format!("mieru-host={host}"),
            format!("panel-domain={}", config.domains.panel),
            format!("mita-version={VERSION}"),
            "architecture=amd64".into(),
            format!("package-url={url}"),
            format!("package-digest={package_digest}"),
            format!("executable-digest={executable_digest}"),
            format!("binary={BINARY}"),
            format!("unit={UNIT}"),
            format!("socket={SOCKET}"),
            "manager-uid=10005".into(),
            "manager-gid=10005".into(),
            format!("bootstrap-user={}", config.initial_user),
            format!("transports={}", encode_transports(&transports)),
            format!("egress={}", seed(egress.mieru)),
            format!("warp-port={}", egress.warp_port),
            format!("warp-provider={}", egress.provider_url().unwrap_or_default()),
            format!("router-provider={}", egress.router_url("mieru").unwrap_or_default()),
            format!("lane-slots={}", mieru.lane_slots),
        ];
        let mut adjacent = Vec::new();
        for protocol in ["TCP", "UDP"] {
            if let Some(ports) = facts.listeners.get(&protocol.to_lowercase()).and_then(Value::as_array) {
                for port in
                    ports.iter().filter_map(Value::as_u64).filter_map(|p| u16::try_from(p).ok()).filter(|p| *p > 0)
                {
                    if !transports.iter().chain(&slots).any(|(p, n)| p == protocol && *n == port) {
                        adjacent.push((protocol.to_string(), port));
                    }
                }
            }
        }
        adjacent.sort();
        adjacent.dedup();
        if !adjacent.is_empty() {
            mutations.push(format!("adjacent-listeners={}", encode_transports(&adjacent)));
        }
        let mut preconditions = strings(&[
            "the Core runtime is verified",
            "the selected Mieru listeners are free",
            "fixed manager identity 10005 is free or already owned",
        ]);
        let mut verification = strings(&[
            "package and executable digests match the pinned release",
            "mita reports the exact status \"RUNNING\"",
            "the management UDS keeps its owner and 0770 mode",
            "the official client reaches the Internet over every transport",
            "manager and panel health pass and adjacent listeners are intact",
        ]);
        if mieru.lane_slots > 0 {
            preconditions.push("the lane slot ports are free".into());
            verification.push("every lane slot daemon answers on its own socket".into());
        }
        Ok(vec![Action {
            id: "mieru.runtime".into(),
            adapter: "mieru".into(),
            owner: "proxy-control:mieru".into(),
            mutations,
            preconditions,
            verification,
            inverse: strings(&[
                "stop only the mita unit, the lane slot units and the mieru-manager service",
                "preserve manager state, token, and mita config unless purge",
                "remove only the owned binary, units, tmpfiles, and helpers",
            ]),
            credentials_required: true,
        }])
    }
    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        self.selection(action)?;
        self.live_identities()?;
        let recovery = self.host.exists(&self.host.marker())?;
        if !recovery && (self.host.exists(UNIT)? || self.host.service_present()) {
            return Err(self.host.error("active Mieru resources require a proven owned recovery generation"));
        }
        let name = self.host.existing_acceptance()?.unwrap_or(self.host.fresh_name()?);
        let marker = if recovery { Value::Null } else { token_hex::<16>().into() };
        let digest = if let Some(marker) = marker.as_str() {
            sha256_hex(format!("{marker}\n").as_bytes())
        } else {
            self.host.marker_sha256()?
        };
        Ok(json!({"acceptance_name":name,"adoption":if recovery{"recovery"}else{"absent"},"binary_preexisting":self.host.exists(BINARY)?,"identities_created":{},"marker_value":marker,"owner":action.owner,"ownership":{},"planned_ownership":self.planned(&name,&digest)?,"state_preexisting":self.host.host(MANAGER_STATE)?.is_dir(),"token_preexisting":self.host.host(TOKEN)?.is_file()}).as_object().unwrap().clone())
    }
    fn apply(&self, action: &Action, mut data: CheckpointData) -> Result<CheckpointData, Error> {
        let selected = self.selection(action)?;
        self.checkpoint(&data, action, false)?;
        {
            let staged = self.stage(action)?;
            if data["binary_preexisting"] == true {
                let actual = sha256_file(&self.host.host(BINARY)?)?;
                if actual != selected.executable_digest
                    && self.host.agent_value("mita", "sha256").as_deref() != Some(&actual)
                {
                    return Err(self.host.artifact("a pre-existing mita binary does not match the pinned digest"));
                }
            } else {
                self.host.atomic(BINARY, &fs::read(&staged.binary)?, 0o755)?;
                self.host.atomic(LICENSE, &fs::read(&staged.license)?, 0o644)?;
            }
        }
        let identities = self.ensure_identities()?;
        self.build_client_image()?;
        self.host.install_helpers(HELPERS)?;
        self.host.run(&["systemd-tmpfiles", "--create", TMPFILES])?;
        self.prepare_mita_state()?;
        self.host.run(&["systemctl", "daemon-reload"])?;
        self.bootstrap(&selected, &data)?;
        self.host.run(&["systemctl", "enable", "--now", "mita"])?;
        self.assert_running()?;
        self.slots(&selected, true)?;
        let info = fs::symlink_metadata(self.host.host(SOCKET)?)?;
        if !info.file_type().is_socket() || info.gid() == 0 || info.mode() & 0o7777 != 0o770 {
            return Err(self.host.error("management socket group is unavailable"));
        }
        self.prepare_manager(&selected, info.gid())?;
        self.host.compose(&["up", "-d", "--build", "--wait"])?;
        data.insert("identities_created".into(), identities);
        data.insert("ownership".into(), self.host.ownership(OWNED, BINARY, data["binary_preexisting"] == true)?);
        Ok(data)
    }
    fn reconcile_apply(&self, action: &Action, mut data: CheckpointData) -> Result<CheckpointData, Error> {
        data.insert("ownership".into(), json!({}));
        self.apply(action, data)
    }
    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let selected = self.selection(action)?;
        let (name, recover) = self.host.begin_acceptance()?;
        let result = self.acceptance(&selected, &name, recover).and_then(|value| {
            super::proxy_acceptance::require_mieru(&value)?;
            Ok(value)
        });
        let collision =
            result.as_ref().err().is_some_and(|e| e.python_class_name() == "_AcceptanceCollision") && !recover;
        let cleanup = if collision { Ok(()) } else { self.cleanup(&selected.panel, &name) };
        if cleanup.is_ok() {
            self.host.remove(&self.host.pending())?;
        }
        let mut value = result?;
        cleanup.map_err(|_| self.host.acceptance("temporary-user and session cleanup failed"))?;
        self.slots(&selected, false)?;
        value["temporary_state_removed"] = true.into();
        value["lane_slots"] =
            json!((1..=selected.lane_slots).map(|index| json!({"index":index,"port":46100+index})).collect::<Vec<_>>());
        let mut evidence = evidence(
            action,
            &[
                "pinned mita, UDS boundary, and official-client acceptance passed",
                "temporary acceptance state was removed",
            ],
            value,
        );
        if selected.lane_slots > 0 {
            evidence.observations.push(format!("{} lane slot daemon(s) answer on their sockets", selected.lane_slots));
        }
        Ok(evidence)
    }
    fn repair(&self, action: &Action, mut data: CheckpointData) -> Result<CheckpointData, Error> {
        let selected = self.selection(action)?;
        self.checkpoint(&data, action, true)?;
        self.rebase_agent_env(&selected, &mut data)?;
        self.host.assert_ownership(&data)?;
        self.live_identities()?;
        self.host.install_helpers(&[("prepare-mieru-token", TOKEN_PREPARER, 0o755)])?;
        self.host.run(&[TOKEN_PREPARER, "verify", TOKEN])?;
        self.host.run(&[STATE_PREPARER, "verify", MANAGER_STATE])?;
        self.host.run(&["systemctl", "restart", "mita"])?;
        self.assert_running()?;
        self.slots(&selected, true)?;
        self.host.compose(&["up", "-d", "--wait"])?;
        data.insert("ownership".into(), self.host.ownership(OWNED, BINARY, data["binary_preexisting"] == true)?);
        Ok(data)
    }
    fn rollback(
        &self,
        action: &Action,
        mut data: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        let selected = self.selection(action)?;
        self.checkpoint(&data, action, true)?;
        self.rebase_agent_env(&selected, &mut data)?;
        self.complete_partial_inverse(action, &selected, &mut data)?;
        let purge = purge_data && target == RollbackTarget::Uninstalled;
        let mut pending = false;
        if self.host.exists(&self.host.pending())? {
            let name =
                self.host.existing_acceptance()?.unwrap_or_else(|| data["acceptance_name"].as_str().unwrap().into());
            if self.cleanup(&selected.panel, &name).is_err() {
                pending = !purge;
                if pending {
                    self.host.write_acceptance(&name)?;
                }
            }
            if !pending {
                self.host.remove(&self.host.pending())?;
            }
        }
        if self.host.exists(UNIT)? {
            self.host.best_effort(&["systemctl", "disable", "--now", "mita"])?;
        }
        for index in 1..=selected.lane_slots {
            self.host.best_effort(&["systemctl", "disable", "--now", &format!("mita@{index}")])?;
        }
        if self.host.service_present() {
            self.host.compose(&["rm", "--stop", "--force", "mieru-manager"])?;
        }
        self.host.remove_generation(&data, BINARY, !purge, pending)?;
        self.host.remove_binary(&data, BINARY, "binary_preexisting")?;
        self.host.best_effort(&["systemctl", "daemon-reload"])?;
        if purge {
            for path in [TOKEN, CONFIG, BOOTSTRAP] {
                self.host.remove(path)?;
            }
            for directory in [MANAGER_STATE, "/var/lib/mita/lanes"] {
                clear_directory(&self.host.host(directory)?)?;
            }
            if data["identities_created"]["user"] == true {
                self.host.best_effort(&["userdel", "mita"])?;
            }
            if data["identities_created"]["group"] == true {
                self.host.best_effort(&["groupdel", "mita"])?;
            }
        }
        Ok(evidence(
            action,
            &[
                "the Mieru runtime was removed",
                if purge {
                    "manager state, token, and mita config were purged"
                } else {
                    "manager state, token, and mita config were preserved"
                },
            ],
            json!({"persistent_data_preserved":!purge,"identities_removed":purge,"temporary_cleanup_pending":pending}),
        ))
    }
    fn reconcile_rollback(
        &self,
        action: &Action,
        data: CheckpointData,
        purge: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.rollback(action, data, purge, target)
    }
}
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
fn checked_extracted(root: &Path, relative: &str) -> Result<PathBuf, Error> {
    let mut cursor = root.to_path_buf();
    for component in relative.split('/') {
        cursor.push(component);
        let info = fs::symlink_metadata(&cursor)
            .map_err(|_| Error::other("ArtifactError", "executable or license material is missing from the package"))?;
        if info.file_type().is_symlink() || cursor != root.join(relative) && !info.is_dir() {
            return Err(Error::other("ArtifactError", "package extraction traverses an unsafe parent"));
        }
    }
    let info = fs::symlink_metadata(&cursor)?;
    if !info.is_file() || info.nlink() != 1 {
        return Err(Error::other("ArtifactError", "executable or license material is unsafe"));
    }
    Ok(cursor)
}
pub fn encode_transports(values: &[(String, u16)]) -> String {
    values.iter().map(|(protocol, port)| format!("{protocol}:{port}")).collect::<Vec<_>>().join(";")
}
pub fn decode_transports(value: &str) -> Result<Vec<(String, u16)>, Error> {
    let mut values = Vec::new();
    let invalid = || Error::other("MieruError", "Mieru action has invalid transports");
    for item in value.split(';') {
        let (protocol, port) = item.split_once(':').ok_or_else(invalid)?;
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let port = port.parse::<u16>().ok().filter(|p| *p != 0 && *p != 443).ok_or_else(invalid)?;
        if !["TCP", "UDP"].contains(&protocol) || values.iter().any(|(p, n)| p == protocol && *n == port) {
            return Err(invalid());
        }
        values.push((protocol.to_string(), port));
    }
    values.sort();
    Ok(values)
}

pub(super) fn ensure_pinned_package(
    package: &Path,
    url: &str,
    digest: &str,
    fetch: impl FnOnce(&str, &Path) -> Result<(), Error>,
) -> Result<(), Error> {
    if fs::symlink_metadata(package).is_ok() {
        return Ok(());
    }
    if !url.starts_with("https://") {
        return Err(Error::other("ArtifactError", "a pinned artifact must be fetched over HTTPS"));
    }
    let parent = package.parent().ok_or_else(|| Error::other("ArtifactError", "artifact path has no parent"))?;
    fs::create_dir_all(parent)?;
    let directory = PrivateDirectory::new(parent, ".artifact-fetch-")?;
    let staging = directory.path.join("payload");
    fetch(url, &staging)?;
    verify_artifact(&staging, digest)
        .map_err(|_| Error::other("ArtifactError", "the fetched package digest does not match its pin"))?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o644))?;
    // Exclusive linking never replaces an operator-staged file that appears during the fetch.
    match fs::hard_link(&staging, package) {
        Ok(()) => pc_host::fs::fsync_directory(parent)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn copy_probe_sources(source: &Path, destination: &Path) -> Result<(), Error> {
    let info = fs::symlink_metadata(source)?;
    if !info.is_dir() {
        return Err(Error::other("ArtifactError", "native client probe source is unsafe"));
    }
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let info = fs::symlink_metadata(entry.path())?;
        let path = destination.join(entry.file_name());
        if info.is_dir() {
            copy_probe_sources(&entry.path(), &path)?;
        } else if info.is_file() {
            atomic_write(&path, &fs::read(entry.path())?, 0o644, None)?;
        } else {
            return Err(Error::other("ArtifactError", "native client probe source is unsafe"));
        }
    }
    Ok(())
}
