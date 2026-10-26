//! Official pinned WARP package, resumable owner claim and loopback tunneled-egress acceptance.
use super::services::{hex, mutations, Host};
use super::AdapterContext;
use crate::adapter::Adapter;
use crate::error::Error;
use crate::journal::{CheckpointData, RollbackTarget};
use crate::model::InstallerConfig;
use crate::planner::{Action, AuditFacts, Evidence};
use pc_host::runner::{Bounded, BoundedError, BoundedOutput};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::time::{Duration, Instant};

pub const VERSION: &str = "2026.7.1377.0";
const PACKAGE_URL: &str =
    "https://pkg.cloudflareclient.com/pool/noble/main/c/cloudflare-warp/cloudflare-warp_2026.7.1377.0_amd64.deb";
const PACKAGE_SHA256: &str = "a73429701c47ee9dc3c8307a0ead67054530787239bd71a12e7f93acdbe96f65";
const KEY_SHA256: &str = "0f37fc298c98e88ee3c0ee68c95b69f1dba9eb477abe3167e13982105911264d";
const KEY: &str = "/usr/share/keyrings/proxy-control-warp.asc";
const REPO_PATH: &str = "/etc/apt/sources.list.d/proxy-control-warp.list";
const REPO: &[u8] = b"deb [arch=amd64 signed-by=/usr/share/keyrings/proxy-control-warp.asc] https://pkg.cloudflareclient.com/ noble main\n";
const DIRECTORY: &str = "/var/lib/proxy-control/warp";
const OWNER: &str = "/var/lib/proxy-control/warp/owner";
const STATE: &str = "/var/lib/cloudflare-warp";
const TRACE: &str = "https://www.cloudflare.com/cdn-cgi/trace";

pub struct WarpAdapter {
    host: Host,
}
impl WarpAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self { host: Host::new(context, "WarpError", "WARP") }
    }
    fn port(&self, action: &Action) -> Result<u16, Error> {
        let values = mutations(action, "warp", "proxy-control:warp", &["port"], "WarpError")?;
        values["port"].parse::<u16>().ok().filter(|p| *p >= 1024).ok_or_else(|| self.host.error("invalid WARP port"))
    }
    fn bounded(&self, argv: &[&str]) -> Result<BoundedOutput, Error> {
        Ok(self.host.context.runner.bounded(argv, Bounded::WARP)?)
    }
    fn run(&self, argv: &[&str]) -> Result<String, Error> {
        let output = self.bounded(argv)?;
        if output.returncode != 0 {
            return Err(self.host.error(format!("WARP command failed: {} {}", argv[0], argv.get(1).unwrap_or(&""))));
        }
        Ok(output.stdout)
    }
    fn version(&self) -> Result<Option<String>, Error> {
        let output = self.bounded(&["dpkg-query", "-W", "-f=${Version}", "cloudflare-warp"])?;
        Ok((output.returncode == 0).then(|| output.stdout.trim().into()))
    }
    fn package_state(&self) -> Result<String, Error> {
        Ok(self.run(&["dpkg-query", "-W", "-f=${db:Status-Status}", "cloudflare-warp"])?.trim().into())
    }
    fn checkpoint<'a>(&self, action: &Action, data: &'a CheckpointData) -> Result<&'a str, Error> {
        if data.len() != 3
            || data.get("owner").and_then(Value::as_str) != Some(&action.owner)
            || !data.get("ownership").is_some_and(Value::is_object)
        {
            return Err(self.host.error("invalid WARP ownership checkpoint"));
        }
        data.get("marker")
            .and_then(Value::as_str)
            .filter(|v| hex(v, 32))
            .ok_or_else(|| self.host.error("invalid WARP ownership checkpoint"))
    }
    fn assert_owned(&self, action: &Action, data: &CheckpointData) -> Result<bool, Error> {
        let nonce = self.checkpoint(action, data)?;
        let marker = self.host.path(OWNER)?;
        if marker.exists() && fs::read_to_string(marker)? != nonce {
            return Err(self.host.error("WARP ownership drifted"));
        }
        Ok(self.host.path(OWNER)?.exists())
    }
    fn pending(&self, nonce: &str) -> Result<std::path::PathBuf, Error> {
        let pending = self.host.path(&format!("{DIRECTORY}/.owner.{nonce}.tmp"))?;
        if let Some(parent) = pending.parent().filter(|p| p.exists()) {
            for entry in fs::read_dir(parent)? {
                if entry?.path() != pending {
                    return Err(self.host.error("foreign WARP staging state appeared after planning"));
                }
            }
        }
        if pending.exists() {
            let info = fs::symlink_metadata(&pending)?;
            if !info.is_file() || info.nlink() != 1 || info.uid() != unsafe { libc::geteuid() } {
                return Err(self.host.error("WARP pending owner is unsafe"));
            }
            if info.len() > 32 || !nonce.as_bytes().starts_with(&fs::read(&pending)?) {
                return Err(self.host.error("WARP pending owner drifted"));
            }
        }
        Ok(pending)
    }
    fn claim(&self, nonce: &str) -> Result<(), Error> {
        let pending = self.pending(nonce)?;
        let directory = self.host.path(DIRECTORY)?;
        pc_host::fs::durable_mkdir(&directory, 0o700)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&pending)?;
        let info = file.metadata()?;
        if !info.is_file() || info.nlink() != 1 || info.uid() != unsafe { libc::geteuid() } {
            return Err(self.host.error("WARP pending owner is unsafe"));
        }
        let mut before = Vec::new();
        Read::by_ref(&mut file).take(33).read_to_end(&mut before)?;
        if !nonce.as_bytes().starts_with(&before) {
            return Err(self.host.error("WARP pending owner drifted"));
        }
        file.seek(SeekFrom::Start(0))?;
        file.write_all(nonce.as_bytes())?;
        file.set_len(32)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.sync_all()?;
        fs::rename(pending, self.host.path(OWNER)?)?;
        pc_host::fs::fsync_directory(&directory)?;
        Ok(())
    }
    fn repositories(&self, owned: bool, data: &CheckpointData) -> Result<(), Error> {
        for (path, digest) in [(KEY, KEY_SHA256.to_owned()), (REPO_PATH, pc_host::fs::sha256_hex(REPO))] {
            if self.host.path(path)?.exists() {
                if !owned || self.host.digest(path)? != digest {
                    return Err(self.host.error("WARP repository ownership drifted"));
                }
            } else if data["ownership"].get(path).is_some() {
                return Err(self.host.error("WARP repository ownership is missing"));
            }
        }
        Ok(())
    }
    fn install_package(&self) -> Result<(), Error> {
        let absolute = format!("{DIRECTORY}/download-{}", pc_host::fs::token_hex::<16>());
        let stage = self.host.path(&absolute)?;
        // mkdir, not create_dir_all: an existing stage is never reused.
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&stage)?;
        let install = (|| {
            let key = stage.join("key.asc");
            let key_name = key.to_string_lossy();
            self.run(&[
                "curl",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--max-time",
                "180",
                "--output",
                &key_name,
                "https://pkg.cloudflareclient.com/pubkey.gpg",
            ])?;
            if pc_host::fs::sha256_file(&key)? != KEY_SHA256 {
                return Err(self.host.error("official Cloudflare signing key digest mismatch"));
            }
            self.host.write(KEY, &fs::read(key)?, 0o644)?;
            self.host.write(REPO_PATH, REPO, 0o644)?;
            self.run(&["apt-get", "update"])?;
            let package = stage.join("cloudflare-warp.deb");
            let package_name = package.to_string_lossy();
            self.run(&[
                "curl",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--max-time",
                "300",
                "--output",
                &package_name,
                PACKAGE_URL,
            ])?;
            if pc_host::fs::sha256_file(&package)? != PACKAGE_SHA256 {
                return Err(self.host.error("official WARP package digest mismatch"));
            }
            self.run(&["apt-get", "install", "--yes", "--no-install-recommends", &package_name])?;
            Ok(())
        })();
        // Keep the owner, but never a downloaded key/package, on failure or success.
        let cleanup = pc_host::fs::durable_remove(&stage, true);
        match install {
            Err(e) => Err(e),
            Ok(()) => {
                cleanup?;
                Ok(())
            }
        }
    }
    fn cli(&self, deadline: Instant, args: &[&str]) -> Result<BoundedOutput, Error> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(self.host.error("WARP readiness deadline expired"));
        }
        let mut argv = vec!["warp-cli", "--accept-tos"];
        argv.extend_from_slice(args);
        match self
            .host
            .context
            .runner
            .bounded(&argv, Bounded { timeout: remaining.min(Duration::from_secs(5)), ..Bounded::WARP })
        {
            Ok(output) => Ok(output),
            Err(BoundedError::Interrupted) => Err(BoundedError::Interrupted.into()),
            Err(_) => Ok(BoundedOutput { returncode: 124, stdout: String::new(), stderr: String::new() }),
        }
    }
    fn wait(&self, deadline: Instant) {
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(2)));
    }
    fn listeners(&self, port: u16) -> Result<Vec<(String, String)>, Error> {
        let mut out = Vec::new();
        for line in self.run(&["ss", "-H", "-ltnp"])?.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 5 {
                return Err(self.host.error("cannot parse host listeners"));
            }
            if let Some((address, value)) = fields[3].rsplit_once(':') {
                if value == port.to_string() {
                    out.push((address.trim_matches(['[', ']']).into(), line.into()));
                }
            }
        }
        Ok(out)
    }
    pub fn validate_egress(direct: &str, proxied: &str) -> Result<(), Error> {
        let parse = |text: &str| {
            text.lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let a = parse(direct);
        let b = parse(proxied);
        let ip = |map: &std::collections::BTreeMap<String, String>| {
            map.get("ip")
                .and_then(|v| v.parse::<IpAddr>().ok())
                .ok_or_else(|| Error::other("WarpError", "egress trace did not contain valid IP addresses"))
        };
        if ip(&a)? == ip(&b)? || !matches!(b.get("warp").map(String::as_str), Some("on" | "plus")) {
            return Err(Error::other("WarpError", "WARP did not provide a distinct tunneled egress"));
        }
        Ok(())
    }
    fn teardown(&self, action: &Action, data: CheckpointData) -> Result<Evidence, Error> {
        self.port(action)?;
        let owned = self.assert_owned(action, &data)?;
        // Missing repository files are expected during a resumed purge.
        for (path, digest) in [(KEY, KEY_SHA256.to_owned()), (REPO_PATH, pc_host::fs::sha256_hex(REPO))] {
            if self.host.path(path)?.exists() && (!owned || self.host.digest(path)? != digest) {
                return Err(self.host.error("WARP repository ownership drifted"));
            }
        }
        let current = self.version()?;
        if !owned {
            if self.host.path(STATE)?.exists() || current.is_some() {
                return Err(self.host.error("WARP state exists without ownership marker"));
            }
            let pending = self.pending(self.checkpoint(action, &data)?)?;
            pc_host::fs::durable_remove(&pending, true)?;
        } else {
            if current.as_deref().is_some_and(|v| v != VERSION) {
                return Err(self.host.error("foreign WARP package version prevents rollback"));
            }
            if current.is_some() {
                if self.bounded(&["systemctl", "disable", "--now", "warp-svc"])?.returncode != 0 {
                    let status = self.run(&["systemctl", "show", "warp-svc", "--property=LoadState,ActiveState"])?;
                    let props: std::collections::BTreeMap<_, _> =
                        status.lines().filter_map(|l| l.split_once('=')).collect();
                    if props
                        != std::collections::BTreeMap::from([("LoadState", "not-found"), ("ActiveState", "inactive")])
                    {
                        return Err(self.host.error("WARP service could not be safely stopped"));
                    }
                }
                self.run(&["apt-get", "purge", "--yes", "cloudflare-warp"])?;
            }
            if self.version()?.is_some() {
                return Err(self.host.error("WARP package remains after rollback"));
            }
            for path in [KEY, REPO_PATH, STATE] {
                self.host.remove(path)?;
            }
            let directory = self.host.path(DIRECTORY)?;
            for child in fs::read_dir(directory)? {
                let child = child?.path();
                if child != self.host.path(OWNER)? {
                    pc_host::fs::durable_remove(&child, false)?;
                }
            }
            self.host.remove(OWNER)?;
        }
        if self.version()?.is_some() {
            return Err(self.host.error("WARP package remains after rollback"));
        }
        if self.host.path(DIRECTORY)?.exists() {
            if fs::read_dir(self.host.path(DIRECTORY)?)?.next().is_some() {
                return Err(self.host.error("WARP cleanup left unexpected state"));
            }
            self.host.remove(DIRECTORY)?;
        }
        Ok(Evidence::ok(&action.id, &["owned WARP removed"])?)
    }
}
impl Adapter for WarpAdapter {
    fn name(&self) -> &str {
        "warp"
    }
    fn plan(&self, config: &InstallerConfig, _: &AuditFacts) -> Result<Vec<Action>, Error> {
        if !config.effective_egress().warp {
            return Ok(Vec::new());
        }
        Ok(vec![Action::new(
            "warp.runtime",
            "warp",
            "proxy-control:warp",
            vec![format!("port={}", config.effective_egress().warp_port)],
            vec!["no foreign WARP package, registration or listener exists".into()],
            vec!["official WARP proxy returns a distinct tunneled external IP".into()],
            vec!["remove only the installer-owned WARP package and registration".into()],
            false,
        )?])
    }
    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error> {
        self.port(action)?;
        if self.version()?.is_some()
            || [STATE, KEY, REPO_PATH, DIRECTORY]
                .iter()
                .map(|p| self.host.path(p))
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|p| p.exists())
        {
            return Err(self.host.error("foreign WARP installation or state requires explicit migration"));
        }
        Ok(json!({"owner":action.owner,"marker":pc_host::fs::token_hex::<16>(),"ownership":{}})
            .as_object()
            .unwrap()
            .clone())
    }
    fn apply(&self, action: &Action, mut data: CheckpointData) -> Result<CheckpointData, Error> {
        let port = self.port(action)?;
        let owned = self.assert_owned(action, &data)?;
        self.repositories(owned, &data)?;
        if !owned {
            if self.version()?.is_some() || self.host.path(STATE)?.exists() {
                return Err(self.host.error("foreign WARP package or state appeared after planning"));
            }
            self.pending(self.checkpoint(action, &data)?)?;
            if !self.listeners(port)?.is_empty() {
                return Err(self.host.error("WARP proxy port is occupied"));
            }
            self.claim(self.checkpoint(action, &data)?)?;
        }
        match self.version()?.as_deref() {
            None => self.install_package()?,
            Some(VERSION) => (),
            Some(_) => return Err(self.host.error("WARP package version drifted")),
        }
        if self.version()?.as_deref() != Some(VERSION) {
            return Err(self.host.error("WARP installation did not produce the pinned package"));
        }
        if matches!(self.package_state()?.as_str(), "unpacked" | "half-configured") {
            self.run(&["dpkg", "--configure", "cloudflare-warp"])?;
        }
        if self.package_state()? != "installed" {
            return Err(self.host.error("WARP package is not fully configured"));
        }
        self.run(&["systemctl", "enable", "--now", "warp-svc"])?;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if self.cli(deadline, &["registration", "show"])?.returncode == 0
                || self.cli(deadline, &["registration", "new"])?.returncode == 0
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(self.host.error("WARP registration readiness deadline expired"));
            }
            self.wait(deadline);
        }
        let port_text = port.to_string();
        for args in [vec!["mode", "proxy"], vec!["proxy", "port", &port_text], vec!["connect"]] {
            if self.cli(deadline, &args)?.returncode != 0 {
                return Err(self.host.error("WARP proxy configuration failed"));
            }
        }
        loop {
            let status = self.cli(deadline, &["status"])?;
            if status.returncode == 0 && status.stdout.lines().any(|l| l == "Status update: Connected") {
                break;
            }
            if Instant::now() >= deadline {
                return Err(self.host.error("WARP did not connect within 90 seconds"));
            }
            self.wait(deadline);
        }
        let mut ownership = self.host.ownership(&[OWNER])?;
        for path in [KEY, REPO_PATH] {
            if self.host.path(path)?.exists() {
                ownership.insert(path.into(), json!(self.host.digest(path)?));
            }
        }
        data.insert("ownership".into(), Value::Object(ownership));
        Ok(data)
    }
    fn reconcile_apply(&self, action: &Action, data: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, data)
    }
    fn repair(&self, action: &Action, data: CheckpointData) -> Result<CheckpointData, Error> {
        self.apply(action, data)
    }
    fn verify(&self, action: &Action) -> Result<Evidence, Error> {
        let port = self.port(action)?;
        if self.version()?.as_deref() != Some(VERSION) || self.package_state()? != "installed" {
            return Err(self.host.error("WARP package is not fully installed at the pinned version"));
        }
        for (check, expected) in [("is-active", "active"), ("is-enabled", "enabled")] {
            if self.run(&["systemctl", check, "warp-svc"])?.trim() != expected {
                return Err(self.host.error("WARP service is not active and enabled"));
            }
        }
        let rows = self.listeners(port)?;
        if !rows.iter().any(|(a, _)| a == "127.0.0.1") {
            return Err(self.host.error("WARP loopback listener is absent"));
        }
        if rows.iter().any(|(a, row)| !matches!(a.as_str(), "127.0.0.1" | "::1") || !row.contains("(\"warp-svc\",pid="))
        {
            return Err(self.host.error("WARP listener is public or foreign"));
        }
        let direct =
            self.run(&["curl", "--fail", "--silent", "--show-error", "--noproxy", "*", "--max-time", "30", TRACE])?;
        let socks = format!("127.0.0.1:{port}");
        let proxied = self.run(&[
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--noproxy",
            "",
            "--socks5-hostname",
            &socks,
            "--max-time",
            "30",
            TRACE,
        ])?;
        Self::validate_egress(&direct, &proxied)?;
        let mut evidence = Evidence::ok(&action.id, &["official WARP has distinct tunneled egress"])?;
        evidence.details = json!({"port":port,"distinct_egress":true}).as_object().unwrap().clone();
        Ok(evidence)
    }
    fn rollback(&self, action: &Action, data: CheckpointData, _: bool, _: RollbackTarget) -> Result<Evidence, Error> {
        self.teardown(action, data)
    }
    fn reconcile_rollback(
        &self,
        action: &Action,
        data: CheckpointData,
        _: bool,
        _: RollbackTarget,
    ) -> Result<Evidence, Error> {
        self.teardown(action, data)
    }
}
