//! Bounded host migration for the installer's pre-client-IP Nginx templates.
//!
//! The foreign coexist frontend is never edited. Run without `--apply` to inspect the plan; the
//! one-command host updater applies this after its panel update succeeds.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pc_host::fs::{atomic_write, durable_mkdir, token_hex};
use pc_host::runner::{Bounded, HostRunner};

const STREAM: &str = "etc/nginx/stream.d/proxy-control.conf";
const PANEL: &str = "etc/nginx/conf.d/proxy-control-panel.conf";
const STATE: &str = "var/lib/proxy-control/ingress-backups";
const PROXY_LISTENER: &str = "listen unix:/run/proxy-control-panel-tls.sock ssl proxy_protocol; set_real_ip_from unix:; real_ip_header proxy_protocol; ";
const MANUAL_REASON: &str = "foreign or legacy ingress is unchanged; verify client-IP forwarding separately";

#[derive(Debug)]
pub struct UpgradeError(String);

impl UpgradeError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UpgradeError {}

impl From<io::Error> for UpgradeError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<pc_host::TxError> for UpgradeError {
    fn from(error: pc_host::TxError) -> Self {
        Self(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeOutcome {
    CoexistManual,
    Current,
    Pending,
    Applied { backup: PathBuf },
}

impl UpgradeOutcome {
    /// `json.dumps(upgrade(...))`: insertion order, ASCII escaping and the default separators,
    /// with no newline here (the CLI adds exactly one).
    pub fn json(&self) -> String {
        match self {
            Self::CoexistManual => format!(
                "{{\"status\": \"coexist_manual\", \"client_ip\": \"not_verified\", \"reason\": {}}}",
                quoted(MANUAL_REASON)
            ),
            Self::Current => "{\"status\": \"current\", \"client_ip\": \"proxy_protocol\"}".into(),
            Self::Pending => "{\"status\": \"pending\", \"files\": [\"stream.d/proxy-control.conf\", \"conf.d/proxy-control-panel.conf\"]}".into(),
            Self::Applied { backup } => format!(
                "{{\"status\": \"applied\", \"client_ip\": \"proxy_protocol\", \"backup\": {}}}",
                quoted(&backup.to_string_lossy())
            ),
        }
    }
}

pub fn failed_json(message: &str) -> String {
    format!("{{\"status\": \"failed\", \"reason\": {}}}", quoted(message))
}

fn quoted(text: &str) -> String {
    let mut output = String::from("\"");
    for character in text.chars() {
        match character {
            '\"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", c as u32)),
            c if c.is_ascii() => output.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    output.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    output.push('\"');
    output
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

fn read_owned(path: &Path) -> Result<Vec<u8>, UpgradeError> {
    for parent in path.ancestors() {
        if is_symlink(parent) {
            return Err(UpgradeError::new("ingress path crosses a symlink"));
        }
    }
    let info = path.metadata()?;
    if !info.file_type().is_file()
        || info.mode() & 0o022 != 0
        || (info.uid() != 0 && info.uid() != unsafe { libc::geteuid() })
    {
        return Err(UpgradeError::new("ingress file ownership or permissions are unsafe"));
    }
    Ok(fs::read(path)?)
}

fn between<'a>(line: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let offset = line.find(start)? + start.len();
    let tail = &line[offset..];
    let length = tail.find(end)?;
    Some(&tail[..length])
}

fn listener_port(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("server { listen 127.0.0.1:")?;
    let end = rest.find(" ssl; ")?;
    let port = &rest[..end];
    (!port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())).then_some(port)
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-'))
}

fn valid_certificate(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn panel_proxy(app_port: &str) -> String {
    format!(
        "proxy_pass http://127.0.0.1:{app_port}; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $remote_addr; "
    )
}

fn vhost_prefix(domain: &str, certificate: &str, tls_port: &str) -> String {
    format!(
        "server {{ listen 127.0.0.1:{tls_port} ssl; {PROXY_LISTENER}server_name {domain}; ssl_certificate /etc/letsencrypt/live/{certificate}/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/{certificate}/privkey.pem; "
    )
}

/// `_panel_vhost_text`, `_subscription_vhost_text` and `_mcp_vhost_text`, kept here as well as in
/// Core because this recovery command must be able to run without constructing an adapter.
fn render_vhost(
    domain: &str,
    certificate: &str,
    app_port: &str,
    tls_port: &str,
    mcp: bool,
    subscription: bool,
) -> String {
    let prefix = vhost_prefix(domain, certificate, tls_port);
    let proxy = panel_proxy(app_port);
    if mcp {
        format!(
            "{prefix}access_log off; location = /healthz {{ return 404; }} location /mcp {{ proxy_pass http://127.0.0.1:{app_port}; proxy_http_version 1.1; proxy_set_header Connection \"\"; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $remote_addr; proxy_buffering off; proxy_read_timeout 3600s; }} location / {{ return 404; }} }}\n"
        )
    } else if subscription {
        format!("{prefix}access_log off; location ^~ /s/ {{ {proxy}}} location / {{ return 404; }} }}\n")
    } else {
        format!("{prefix}location ^~ /s/ {{ access_log off; return 404; }} location / {{ {proxy}}} }}\n")
    }
}

fn panel_template(data: &[u8]) -> Result<(Vec<u8>, String), UpgradeError> {
    let text = std::str::from_utf8(data).map_err(|error| UpgradeError::new(error.to_string()))?;
    let invalid = || UpgradeError::new("panel config differs from an owned template");
    let mut lines = String::new();
    let mut port: Option<String> = None;
    for line in text.split_inclusive('\n') {
        let tls = listener_port(line).ok_or_else(invalid)?;
        if port.as_deref().is_some_and(|previous| previous != tls) {
            return Err(UpgradeError::new("panel TLS listeners disagree"));
        }
        port = Some(tls.to_string());
        let domain = between(line, "server_name ", "; ").filter(|value| valid_domain(value)).ok_or_else(invalid)?;
        let certificate = between(line, "ssl_certificate /etc/letsencrypt/live/", "/fullchain.pem; ")
            .filter(|value| valid_certificate(value))
            .ok_or_else(invalid)?;
        let app = between(line, "proxy_pass http://127.0.0.1:", "; ")
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(invalid)?;
        let mcp = line.contains("location /mcp ");
        let subscription = line.contains("location / { return 404; }");
        let rendered = render_vhost(domain, certificate, app, tls, mcp, subscription);
        let legacy = if mcp {
            rendered.replace(PROXY_LISTENER, "").replace("proxy_set_header X-Forwarded-For $remote_addr; ", "")
        } else {
            rendered
                .replace(PROXY_LISTENER, "")
                .replace("X-Forwarded-For $remote_addr;", "X-Forwarded-For $proxy_add_x_forwarded_for;")
        };
        if line != rendered && line != legacy {
            return Err(invalid());
        }
        lines.push_str(&rendered);
    }
    let port = port.filter(|_| !lines.is_empty()).ok_or_else(invalid)?;
    Ok((lines.into_bytes(), format!("127.0.0.1:{port}")))
}

fn loopback_backend(backend: &str) -> bool {
    backend
        .strip_prefix("127.0.0.1:")
        .is_some_and(|port| (1..=5).contains(&port.len()) && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn client_ip_backend(backend: &str, panel_backend: &str) -> Result<String, UpgradeError> {
    if backend == panel_backend {
        return Ok("unix:/run/proxy-control-panel-tls.sock".into());
    }
    if !loopback_backend(backend) {
        return Err(UpgradeError::new("fresh client-IP relay requires a loopback TCP backend"));
    }
    Ok(format!("unix:/run/proxy-control-raw-{}.sock", backend.rsplit(':').next().expect("a colon")))
}

/// The byte-exact legacy/current `_render_fresh` forms used both by the adapter and this migration.
pub fn render_fresh(
    routes: &[(String, String)],
    panel_backend: &str,
    preserve_ip: bool,
) -> Result<Vec<u8>, UpgradeError> {
    let mut lines = vec![
        "# BEGIN PROXY-CONTROL GENERATED STREAM ROUTER".to_string(),
        "map $ssl_preread_server_name $proxy_control_backend {".to_string(),
    ];
    for (domain, backend) in routes {
        let mapped = if preserve_ip { client_ip_backend(backend, panel_backend)? } else { backend.clone() };
        lines.push(format!("    {domain} {mapped};"));
    }
    lines.push(if preserve_ip {
        "    default unix:/run/proxy-control-panel-tls.sock;".into()
    } else {
        "    default 127.0.0.1:8443;".into()
    });
    lines.extend(["}".into(), "server {".into(), "    listen 443;".into(), "    ssl_preread on;".into()]);
    if preserve_ip {
        lines.push("    proxy_protocol on;".into());
    }
    lines.extend(["    proxy_pass $proxy_control_backend;".into(), "}".into()]);
    if preserve_ip {
        let mut seen = BTreeSet::new();
        for (_domain, backend) in routes {
            if backend != panel_backend && seen.insert(backend.clone()) {
                lines.extend([
                    "server {".into(),
                    format!("    listen {} proxy_protocol;", client_ip_backend(backend, panel_backend)?),
                    format!("    proxy_pass {backend};"),
                    "}".into(),
                ]);
            }
        }
    }
    lines.extend(["# END PROXY-CONTROL GENERATED STREAM ROUTER".into(), String::new()]);
    Ok(lines.join("\n").into_bytes())
}

fn stream_template(data: &[u8], panel_backend: &str) -> Result<Vec<u8>, UpgradeError> {
    let invalid = || UpgradeError::new("stream config differs from an owned template");
    let text = std::str::from_utf8(data).map_err(|_| invalid())?;
    let prefix = "map $ssl_preread_server_name $proxy_control_backend {\n";
    let start = text.find(prefix).map(|position| position + prefix.len()).ok_or_else(invalid)?;
    let end = text[start..].find("    default ").map(|position| start + position).ok_or_else(invalid)?;
    let mut routes = Vec::new();
    for line in text[start..end].lines() {
        let entry = line.strip_prefix("    ").ok_or_else(invalid)?;
        let (domain, backend) = entry.split_once(' ').ok_or_else(invalid)?;
        let backend = backend.strip_suffix(';').ok_or_else(invalid)?;
        if !valid_domain(domain) || backend.is_empty() || backend.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(invalid());
        }
        let backend = if backend == "unix:/run/proxy-control-panel-tls.sock" {
            panel_backend.to_string()
        } else if let Some(port) = backend
            .strip_prefix("unix:/run/proxy-control-raw-")
            .and_then(|value| value.strip_suffix(".sock"))
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        {
            format!("127.0.0.1:{port}")
        } else {
            backend.to_string()
        };
        if !loopback_backend(&backend) {
            return Err(invalid());
        }
        routes.push((domain.to_string(), backend));
    }
    let legacy = render_fresh(&routes, panel_backend, false)?;
    let current = render_fresh(&routes, panel_backend, true)?;
    if (data != legacy && data != current) || routes.len() < 2 {
        return Err(invalid());
    }
    Ok(current)
}

fn run_checked(runner: &dyn HostRunner, argv: &[&str]) -> Result<(), UpgradeError> {
    let limits = Bounded::new(Duration::from_secs(30), 1024 * 1024).expect("valid limits");
    let output = runner.bounded(argv, limits).map_err(|error| UpgradeError::new(error.to_string()))?;
    if output.returncode != 0 {
        return Err(UpgradeError::new(format!("command failed with exit status {}", output.returncode)));
    }
    Ok(())
}

fn workers(runner: &dyn HostRunner) -> Result<(u32, BTreeSet<u32>), UpgradeError> {
    let limits = Bounded::new(Duration::from_secs(10), 1024 * 1024).expect("valid limits");
    let output = runner
        .bounded(&["systemctl", "show", "nginx", "--property=MainPID", "--value"], limits)
        .map_err(|error| UpgradeError::new(error.to_string()))?;
    if output.returncode != 0 {
        return Err(UpgradeError::new(format!("command failed with exit status {}", output.returncode)));
    }
    let master_text = output.stdout.trim();
    let master = master_text
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| UpgradeError::new("Nginx master process is unavailable"))?;
    let children = fs::read_to_string(format!("/proc/{master}/task/{master}/children"))?;
    let mut workers = BTreeSet::new();
    for child in children.split_whitespace() {
        let Ok(command) = fs::read(format!("/proc/{child}/cmdline")) else { continue };
        if command.starts_with(b"nginx: worker process")
            && !command.windows(b"shutting down".len()).any(|window| window == b"shutting down")
        {
            let pid = child.parse::<u32>().map_err(|error| UpgradeError::new(error.to_string()))?;
            workers.insert(pid);
        }
    }
    Ok((master, workers))
}

fn reload(runner: &dyn HostRunner) -> Result<(), UpgradeError> {
    reload_with(runner, &workers)
}

type WorkerObservation<'a> = dyn Fn(&dyn HostRunner) -> Result<(u32, BTreeSet<u32>), UpgradeError> + 'a;

fn reload_with(runner: &dyn HostRunner, observe: &WorkerObservation<'_>) -> Result<(), UpgradeError> {
    let (master, old) = observe(runner)?;
    if old.is_empty() {
        return Err(UpgradeError::new("Nginx has no serving workers before reload"));
    }
    run_checked(runner, &["systemctl", "reload", "nginx"])?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut previous = BTreeSet::new();
    while Instant::now() < deadline {
        let (current_master, current) = observe(runner)?;
        if current_master != master {
            return Err(UpgradeError::new("Nginx master changed during reload"));
        }
        let fresh: BTreeSet<u32> = current.difference(&old).copied().collect();
        if !fresh.is_disjoint(&previous) {
            return Ok(());
        }
        previous = fresh;
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(UpgradeError::new("Nginx did not activate a new worker generation"))
}

fn unix_sockets(contents: &[&[u8]]) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for data in contents {
        let text = String::from_utf8_lossy(data);
        let mut rest = text.as_ref();
        while let Some(position) = rest.find("listen unix:") {
            rest = &rest[position + "listen unix:".len()..];
            let end = rest.find([' ', ';']).unwrap_or(rest.len());
            result.insert(rest[..end].to_string());
            rest = &rest[end..];
        }
    }
    result
}

#[derive(Clone)]
struct FileMetadata {
    path: PathBuf,
    mode: u32,
    uid: u32,
    gid: u32,
}

fn metadata_json(stream: &FileMetadata, panel: &FileMetadata) -> Vec<u8> {
    fn entry(name: &str, metadata: &FileMetadata) -> String {
        format!(
            "\"{name}\": {{\"path\": {}, \"mode\": {}, \"uid\": {}, \"gid\": {}}}",
            quoted(&metadata.path.to_string_lossy()),
            metadata.mode,
            metadata.uid,
            metadata.gid
        )
    }
    format!("{{{}, {}}}", entry("stream.conf", stream), entry("panel.conf", panel)).into_bytes()
}

fn upgrade_inner(
    project: &Path,
    root: &Path,
    apply: bool,
    runner: &dyn HostRunner,
    reload: &dyn Fn(&dyn HostRunner) -> Result<(), UpgradeError>,
) -> Result<UpgradeOutcome, UpgradeError> {
    let marker = project.join(".mtproxy-owned");
    let stream = root.join(STREAM);
    let panel = root.join(PANEL);
    if !marker.exists() || !stream.exists() {
        return Ok(UpgradeOutcome::CoexistManual);
    }
    read_owned(&marker)?;
    let before_stream = read_owned(&stream)?;
    let before_panel = read_owned(&panel)?;
    let (new_panel, backend) = panel_template(&before_panel)?;
    let new_stream = stream_template(&before_stream, &backend)?;
    if new_stream == before_stream && new_panel == before_panel {
        return Ok(UpgradeOutcome::Current);
    }
    if !apply {
        return Ok(UpgradeOutcome::Pending);
    }
    let old_sockets = unix_sockets(&[&before_stream, &before_panel]);
    let new_sockets = unix_sockets(&[&new_stream, &new_panel]);
    for name in new_sockets.difference(&old_sockets) {
        let path = root.join(name.trim_start_matches('/'));
        if path.exists() || is_symlink(&path) {
            return Err(UpgradeError::new("a new ingress Unix socket path is occupied"));
        }
    }
    let state = root.join(STATE);
    let backup = loop {
        let candidate = state.join(format!("backup-{}", token_hex::<4>()));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };
    let stream_meta = fs::metadata(&stream)?;
    let panel_meta = fs::metadata(&panel)?;
    let stream_metadata = FileMetadata {
        path: stream.clone(),
        mode: stream_meta.mode() & 0o7777,
        uid: stream_meta.uid(),
        gid: stream_meta.gid(),
    };
    let panel_metadata = FileMetadata {
        path: panel.clone(),
        mode: panel_meta.mode() & 0o7777,
        uid: panel_meta.uid(),
        gid: panel_meta.gid(),
    };
    atomic_write(&backup.join("stream.conf"), &before_stream, 0o600, None)?;
    atomic_write(&backup.join("panel.conf"), &before_panel, 0o600, None)?;
    atomic_write(&backup.join("metadata.json"), &metadata_json(&stream_metadata, &panel_metadata), 0o600, None)?;

    let write = |stream_bytes: &[u8], panel_bytes: &[u8]| -> Result<(), UpgradeError> {
        for (path, bytes, metadata) in
            [(&stream, stream_bytes, &stream_metadata), (&panel, panel_bytes, &panel_metadata)]
        {
            atomic_write(path, bytes, metadata.mode, Some((metadata.uid, metadata.gid)))?;
        }
        Ok(())
    };
    if read_owned(&stream)? != before_stream || read_owned(&panel)? != before_panel {
        return Err(UpgradeError::new("ingress changed while preparing its backup"));
    }
    let result = (|| {
        write(&new_stream, &new_panel)?;
        run_checked(runner, &["nginx", "-t"])?;
        reload(runner)
    })();
    if result.is_err() {
        let rollback = (|| {
            write(&before_stream, &before_panel)?;
            run_checked(runner, &["nginx", "-t"])?;
            reload(runner)
        })();
        if rollback.is_err() {
            return Err(UpgradeError::new(format!("ingress rollback failed; private backup: {}", backup.display())));
        }
        return Err(UpgradeError::new(format!(
            "ingress upgrade failed; original configuration restored; private backup: {}",
            backup.display()
        )));
    }
    Ok(UpgradeOutcome::Applied { backup })
}

/// `upgrade(project, root=…, apply=…)`: read-only inspection unless `apply`, with the private
/// state-directory lock around the mutating double-check and write.
pub fn upgrade(
    project: &Path,
    root: &Path,
    apply: bool,
    runner: &dyn HostRunner,
) -> Result<UpgradeOutcome, UpgradeError> {
    upgrade_with_reload(project, root, apply, runner, &reload)
}

/// Test seam corresponding to Python's injectable `reload`; production callers use [`upgrade`].
pub fn upgrade_with_reload(
    project: &Path,
    root: &Path,
    apply: bool,
    runner: &dyn HostRunner,
    reload: &dyn Fn(&dyn HostRunner) -> Result<(), UpgradeError>,
) -> Result<UpgradeOutcome, UpgradeError> {
    if !apply {
        return upgrade_inner(project, root, false, runner, reload);
    }
    if !project.is_dir() || is_symlink(project) {
        return Err(UpgradeError::new("project directory is unavailable or unsafe"));
    }
    let plan = upgrade_inner(project, root, false, runner, reload)?;
    if plan != UpgradeOutcome::Pending {
        return Ok(plan);
    }
    let state = root.join(STATE);
    for path in state.ancestors() {
        if is_symlink(path) {
            return Err(UpgradeError::new("ingress backup path crosses a symlink"));
        }
    }
    durable_mkdir(&state, 0o700)?;
    let info = fs::metadata(&state)?;
    if info.mode() & 0o077 != 0 || info.uid() != unsafe { libc::geteuid() } {
        return Err(UpgradeError::new("ingress backup directory ownership or permissions are unsafe"));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join(".lock"))?;
    // SAFETY: `lock` owns a valid descriptor for the duration of the guard.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let result = upgrade_inner(project, root, true, runner, reload);
    // SAFETY: unlocking the still-open descriptor; close then happens through Drop.
    unsafe {
        libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_UN);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pc_host::runner::{RecordingRunner, Reply};

    use super::*;
    use crate::testkit::TempDir;

    fn golden(name: &str) -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures/host-golden/renders/ingress-upgrade")
                .join(name),
        )
        .unwrap()
    }

    fn predecessor(label: &str) -> (TempDir, PathBuf) {
        let directory = TempDir::new(label);
        let root = directory.path();
        let project = root.join("opt/mtproxy-shared443");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join(".mtproxy-owned"), b"0123456789abcdef0123456789abcdef\n").unwrap();
        fs::create_dir_all(root.join("etc/nginx/stream.d")).unwrap();
        fs::create_dir_all(root.join("etc/nginx/conf.d")).unwrap();
        fs::write(root.join(STREAM), golden("legacy/stream.conf")).unwrap();
        fs::write(root.join(PANEL), golden("legacy/panel.conf")).unwrap();
        (directory, project)
    }

    #[test]
    fn golden_templates_upgrade_byte_for_byte() {
        let (_directory, _project) = predecessor("ingress-golden");
        let panel = golden("legacy/panel.conf");
        let stream = golden("legacy/stream.conf");
        let (new_panel, backend) = panel_template(&panel).unwrap();
        assert_eq!(backend, "127.0.0.1:8443");
        assert_eq!(new_panel, golden("upgraded/panel.conf"));
        assert_eq!(stream_template(&stream, &backend).unwrap(), golden("upgraded/stream.conf"));
    }

    #[test]
    fn predecessor_plan_is_read_only_then_apply_is_idempotent() {
        let (directory, project) = predecessor("ingress-apply");
        let root = directory.path();
        let runner = Arc::new(RecordingRunner::new());
        let reload = |runner: &dyn HostRunner| run_checked(runner, &["systemctl", "reload", "nginx"]);
        assert_eq!(
            upgrade_with_reload(&project, root, false, runner.as_ref(), &reload).unwrap(),
            UpgradeOutcome::Pending
        );
        assert!(runner.calls().is_empty());
        let applied = upgrade_with_reload(&project, root, true, runner.as_ref(), &reload).unwrap();
        let UpgradeOutcome::Applied { backup } = applied else { panic!("not applied") };
        assert_eq!(fs::read(backup.join("stream.conf")).unwrap(), golden("legacy/stream.conf"));
        assert_eq!(fs::read(backup.join("panel.conf")).unwrap(), golden("legacy/panel.conf"));
        assert_eq!(fs::metadata(&backup).unwrap().mode() & 0o777, 0o700);
        let metadata = String::from_utf8(fs::read(backup.join("metadata.json")).unwrap()).unwrap();
        assert!(metadata.starts_with("{\"stream.conf\": {\"path\": "));
        assert!(metadata.contains("\", \"mode\": 420, \"uid\": "));
        assert_eq!(fs::read(root.join(STREAM)).unwrap(), golden("upgraded/stream.conf"));
        assert_eq!(fs::read(root.join(PANEL)).unwrap(), golden("upgraded/panel.conf"));
        assert_eq!(
            upgrade_with_reload(&project, root, true, runner.as_ref(), &reload).unwrap(),
            UpgradeOutcome::Current
        );
        assert_eq!(runner.argvs(), vec![vec!["nginx", "-t"], vec!["systemctl", "reload", "nginx"]]);
    }

    #[test]
    fn cli_inspection_prints_one_python_json_line() {
        let (directory, project) = predecessor("ingress-cli");
        let root = directory.path().to_path_buf();
        let runner = Arc::new(RecordingRunner::new());
        let compose = |root: &Path| {
            let context = crate::adapters::AdapterContext {
                root: root.to_path_buf(),
                tree: root.to_path_buf(),
                runner: runner.clone(),
            };
            crate::cli::Services::with_context(
                context,
                Box::new(|_| Ok(crate::planner::AuditFacts::default())),
                Box::new(|_, _| unreachable!("MCP is not part of ingress upgrade")),
            )
        };
        let arguments = vec![
            "--root".to_string(),
            root.to_string_lossy().into_owned(),
            "ingress-upgrade".to_string(),
            "--project-dir".to_string(),
            project.to_string_lossy().into_owned(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(crate::cli::run(&arguments, &compose, &mut stdout, &mut stderr), 0);
        assert_eq!(String::from_utf8(stdout).unwrap(), "{\"status\": \"pending\", \"files\": [\"stream.d/proxy-control.conf\", \"conf.d/proxy-control-panel.conf\"]}\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn failed_reload_restores_both_configs() {
        let (directory, project) = predecessor("ingress-rollback");
        let root = directory.path();
        let runner = RecordingRunner::new();
        runner.reply_once(&["systemctl", "reload", "nginx"], Reply::exit(1, "", "failed"));
        let reload = |runner: &dyn HostRunner| run_checked(runner, &["systemctl", "reload", "nginx"]);
        let error = upgrade_with_reload(&project, root, true, &runner, &reload).unwrap_err();
        assert!(error.to_string().contains("original configuration restored"));
        assert_eq!(fs::read(root.join(STREAM)).unwrap(), golden("legacy/stream.conf"));
        assert_eq!(fs::read(root.join(PANEL)).unwrap(), golden("legacy/panel.conf"));
        assert_eq!(
            runner.argvs(),
            vec![
                vec!["nginx", "-t"],
                vec!["systemctl", "reload", "nginx"],
                vec!["nginx", "-t"],
                vec!["systemctl", "reload", "nginx"],
            ]
        );
    }

    #[test]
    fn edited_owned_config_is_refused_and_foreign_missing_is_skipped() {
        let (directory, project) = predecessor("ingress-refuse");
        let root = directory.path();
        let panel = root.join(PANEL);
        fs::write(&panel, b"foreign\n").unwrap();
        let runner = RecordingRunner::new();
        let reload = |_runner: &dyn HostRunner| Ok(());
        assert!(upgrade_with_reload(&project, root, false, &runner, &reload).is_err());
        fs::remove_file(root.join(STREAM)).unwrap();
        assert_eq!(upgrade_with_reload(&project, root, true, &runner, &reload).unwrap(), UpgradeOutcome::CoexistManual);
    }

    #[test]
    fn reload_requires_a_live_new_worker_generation() {
        use std::sync::Mutex;

        let runner = RecordingRunner::new();
        let states = Mutex::new(vec![
            (10, BTreeSet::from([20])),
            (10, BTreeSet::from([20])),
            (10, BTreeSet::from([20, 21])),
            (10, BTreeSet::from([21])),
        ]);
        let observe = |_runner: &dyn HostRunner| {
            let mut states = states.lock().unwrap();
            if states.is_empty() {
                Err(UpgradeError::new("Nginx did not activate a new worker generation"))
            } else {
                Ok(states.remove(0))
            }
        };
        reload_with(&runner, &observe).unwrap();
        assert_eq!(runner.argvs(), vec![vec!["systemctl", "reload", "nginx"]]);
        assert!(states.lock().unwrap().is_empty());
    }

    #[test]
    fn socket_collision_is_refused_without_unlinking_foreign_path() {
        let (directory, project) = predecessor("ingress-collision");
        let root = directory.path();
        let occupied = root.join("run/proxy-control-panel-tls.sock");
        fs::create_dir_all(occupied.parent().unwrap()).unwrap();
        fs::write(&occupied, b"foreign").unwrap();
        let runner = RecordingRunner::new();
        let reload = |_runner: &dyn HostRunner| Ok(());
        assert!(upgrade_with_reload(&project, root, true, &runner, &reload).is_err());
        assert_eq!(fs::read(occupied).unwrap(), b"foreign");
        assert_eq!(fs::read(root.join(STREAM)).unwrap(), golden("legacy/stream.conf"));
    }
}
