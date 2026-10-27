//! The Xray binary: `xray run -test` as the gate, a child process as the runtime, `xray x25519` for
//! Reality keys, `xray version` for the status.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::errors::{Error, Result};
use crate::util::py_oserror;
use pc_common::pytext::{splitlines as py_splitlines, strip as py_strip, tail_chars as last_chars};

/// A started Xray: the child process of the real runner, or the id a test runner hands out.
#[derive(Debug)]
pub struct Handle {
    pub id: u64,
    pub child: Option<Mutex<Child>>,
}

pub trait XrayRunner: Send + Sync {
    fn version(&self) -> Result<String>;
    fn x25519(&self) -> Result<(String, String)>;
    /// `asset_dir` points Xray at candidate geodata files instead of the live ones.
    fn test(&self, config: &Path, asset_dir: Option<&Path>) -> Result<()>;
    fn start(&self, config: &Path, tun: Option<&str>) -> Result<Handle>;
    fn stop(&self, handle: &Handle);
    fn alive(&self, handle: &Handle) -> bool;
    fn wait_ready(&self, ports: &[i64], timeout: f64, sockets: &[String]) -> Result<()>;
}

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

/// Attach to the persistent TUN device the AWG manager made for this uid (TUNSETIFF on a device one
/// owns needs no capability); the descriptor goes to Xray as `XRAY_TUN_FD`. The error is the
/// `OSError` text Python printed.
pub fn open_tun(name: &str) -> std::result::Result<OwnedFd, String> {
    let path = c"/dev/net/tun";
    // SAFETY: open(2) on a constant NUL-terminated path; the result is checked.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("{}: '/dev/net/tun'", py_oserror(&std::io::Error::last_os_error())));
    }
    // SAFETY: `fd` was just opened and is owned here alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // struct ifreq: the name (16 bytes, truncated like `struct.pack("16s")`), then the flags.
    let mut request = [0u8; 40];
    let bytes = name.as_bytes();
    request[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
    request[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    // SAFETY: TUNSETIFF reads and writes a `struct ifreq` (40 bytes on Linux), which `request` is.
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, request.as_mut_ptr()) } < 0 {
        return Err(py_oserror(&std::io::Error::last_os_error()));
    }
    Ok(fd)
}

/// `str(subprocess.TimeoutExpired)`.
fn timed_out(argv: &[String], seconds: &str) -> String {
    let quoted: Vec<String> = argv.iter().map(|arg| format!("'{arg}'")).collect();
    format!("Command '[{}]' timed out after {seconds} seconds", quoted.join(", "))
}

/// `str(OSError)` of a program that did not start: the path it named is part of the text.
fn spawn_error(err: &std::io::Error, program: &Path) -> String {
    match err.raw_os_error() {
        Some(_) => format!("{}: '{}'", py_oserror(err), program.display()),
        None => err.to_string(),
    }
}

/// The real thing: `xray run -test` for the gate, a child process for the runtime.
pub struct SubprocessXrayRunner {
    pub binary: PathBuf,
    pub asset_dir: PathBuf,
    pub test_timeout: Duration,
    pub stop_timeout: Duration,
}

impl SubprocessXrayRunner {
    pub fn new(binary: PathBuf, asset_dir: PathBuf) -> Self {
        Self { binary, asset_dir, test_timeout: Duration::from_secs(20), stop_timeout: Duration::from_secs(5) }
    }

    fn command(&self, args: &[&str], asset_dir: Option<&Path>) -> Command {
        let mut command = Command::new(&self.binary);
        command.args(args).env_clear();
        command.env("XRAY_LOCATION_ASSET", asset_dir.unwrap_or(&self.asset_dir));
        command.env("PATH", std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()));
        command
    }

    fn argv(&self, args: &[&str]) -> Vec<String> {
        std::iter::once(self.binary.display().to_string()).chain(args.iter().map(|a| a.to_string())).collect()
    }

    fn run(
        &self,
        args: &[&str],
        asset_dir: Option<&Path>,
        timeout: Duration,
        seconds: &str,
    ) -> std::result::Result<pc_common::process::Output, String> {
        match pc_common::process::run_command(self.command(args, asset_dir), None, timeout) {
            Ok(output) => Ok(output),
            Err(pc_common::process::RunError::Timeout { .. }) => Err(timed_out(&self.argv(args), seconds)),
            Err(pc_common::process::RunError::Spawn(err)) => Err(spawn_error(&err, &self.binary)),
            Err(pc_common::process::RunError::Io(err)) => Err(py_oserror(&err)),
        }
    }
}

fn wait_for(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return true,
            Ok(None) if Instant::now() >= deadline => return false,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

impl XrayRunner for SubprocessXrayRunner {
    fn version(&self) -> Result<String> {
        let output = self
            .run(&["version"], None, Duration::from_secs(10), "10")
            .map_err(|err| Error::Xray(format!("xray version: {err}")))?;
        let stdout = output.stdout_text();
        let text = if stdout.is_empty() { output.stderr_text() } else { stdout };
        Ok(py_splitlines(py_strip(&text))
            .first()
            .map_or("unknown".into(), |line| pc_common::pytext::head_chars(line, 120).to_string()))
    }

    /// A fresh Reality keypair from the pinned binary, read off its labelled lines:
    /// "PrivateKey:" / "Password (PublicKey):" on 26.x, "Private key:" / "Public key:" on older
    /// builds — anything else is an error, never an empty key.
    fn x25519(&self) -> Result<(String, String)> {
        let output = self
            .run(&["x25519"], None, self.test_timeout, "20.0")
            .map_err(|err| Error::Xray(format!("xray x25519 did not finish: {err}")))?;
        let stdout = output.stdout_text();
        match (private_key_line(&stdout), public_key_line(&stdout)) {
            (Some(private), Some(public)) if output.success() => Ok((private, public)),
            _ => Err(Error::Xray("xray x25519 printed no keypair".into())),
        }
    }

    fn test(&self, config: &Path, asset_dir: Option<&Path>) -> Result<()> {
        let config = config.display().to_string();
        let output = self
            .run(&["run", "-test", "-config", &config], asset_dir, self.test_timeout, "20.0")
            .map_err(|err| Error::Xray(format!("xray -test did not finish: {err}")))?;
        if !output.success() {
            let text = format!("{}{}", output.stdout_text(), output.stderr_text());
            return Err(Error::Xray(last_chars(py_strip(&text), 600).to_string()));
        }
        Ok(())
    }

    fn start(&self, config: &Path, tun: Option<&str>) -> Result<Handle> {
        let failed = |text: String| Error::Xray(format!("xray did not start: {text}"));
        let config = config.display().to_string();
        let mut command = self.command(&["run", "-config", &config], None);
        // Nothing of Xray's own output is kept: `-test` already said everything a config has to
        // say, and a pipe nobody drains would stall the process.
        command.stdout(Stdio::null()).stderr(Stdio::null());
        // v3.0.0: the AmneziaWG ingress — Xray takes the device as a descriptor and touches neither
        // the link nor its addresses, so it needs no capability.
        let fd = match tun {
            Some(name) => Some(open_tun(name).map_err(failed)?),
            None => None,
        };
        if let Some(fd) = &fd {
            let raw = fd.as_raw_fd();
            command.env("XRAY_TUN_FD", raw.to_string());
            // SAFETY: only fcntl(2) runs between fork and exec; it is async-signal-safe.
            unsafe {
                command.pre_exec(move || {
                    if libc::fcntl(raw, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = command.spawn().map_err(|err| failed(spawn_error(&err, &self.binary)))?;
        // The child holds its own copy of the descriptor.
        drop(fd);
        Ok(Handle { id: u64::from(child.id()), child: Some(Mutex::new(child)) })
    }

    fn stop(&self, handle: &Handle) {
        let Some(child) = &handle.child else { return };
        let mut child = child.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        // SAFETY: kill(2) on our own child, not reaped while we hold it.
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        if !wait_for(&mut child, self.stop_timeout) {
            let _ = child.kill();
            wait_for(&mut child, self.stop_timeout);
        }
    }

    fn alive(&self, handle: &Handle) -> bool {
        let Some(child) = &handle.child else { return false };
        matches!(child.lock().unwrap_or_else(std::sync::PoisonError::into_inner).try_wait(), Ok(None))
    }

    fn wait_ready(&self, ports: &[i64], timeout: f64, sockets: &[String]) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs_f64(timeout);
        while Instant::now() < deadline {
            if ports.iter().all(|port| port_open(*port)) && sockets.iter().all(|path| socket_open(path)) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(Error::Xray("the ingress ports did not open in time".into()))
    }
}

/// `^Private ?[Kk]ey:[ \t]*([A-Za-z0-9_-]{43})[ \t]*$`, line by line.
pub fn private_key_line(text: &str) -> Option<String> {
    key_line(text, &["PrivateKey:", "Privatekey:", "Private Key:", "Private key:"])
}

/// `^(?:Public ?[Kk]ey|Password \(PublicKey\)):[ \t]*([A-Za-z0-9_-]{43})[ \t]*$`
pub fn public_key_line(text: &str) -> Option<String> {
    key_line(text, &["PublicKey:", "Publickey:", "Public Key:", "Public key:", "Password (PublicKey):"])
}

/// The first line that is one of `labels`, blanks, 43 key characters, blanks.
fn key_line(text: &str, labels: &[&str]) -> Option<String> {
    text.split('\n').find_map(|line| {
        labels.iter().find_map(|label| {
            let key = line.strip_prefix(label)?.trim_matches([' ', '\t']);
            crate::intent::is_public_key(key).then(|| key.to_string())
        })
    })
}

pub fn port_open(port: i64) -> bool {
    let Ok(port) = u16::try_from(port) else { return false };
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok()
}

pub fn socket_open(path: &str) -> bool {
    UnixStream::connect(path).is_ok()
}

/// A loopback port nothing listens on right now.
pub fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_lines_of_both_xray_generations() {
        let key = "a".repeat(43);
        let new = format!("PrivateKey: {key}\nPassword (PublicKey): {}\nHash32: x\n", "b".repeat(43));
        assert_eq!((private_key_line(&new), public_key_line(&new)), (Some(key.clone()), Some("b".repeat(43))));
        let old = format!("Private key: {key}\nPublic key: {}\n", "c".repeat(43));
        assert_eq!(public_key_line(&old), Some("c".repeat(43)));
        assert_eq!(private_key_line(&format!("Private key: {key}x\n")), None);
        assert_eq!(private_key_line(&format!("Private key: {key}\r\n")), None);
        assert_eq!(private_key_line(&format!("  Private key: {key}\n")), None);
        assert_eq!(private_key_line(&format!("Private key:\t{key} \t\n")), Some(key));
    }

    #[test]
    fn a_missing_binary_does_not_start() {
        let runner = SubprocessXrayRunner::new("/nonexistent/xray".into(), "/tmp".into());
        let err = runner.version().unwrap_err().to_string();
        assert_eq!(err, "xray version: [Errno 2] No such file or directory: '/nonexistent/xray'");
        assert!(runner
            .start(Path::new("/tmp/x.json"), None)
            .unwrap_err()
            .to_string()
            .starts_with("xray did not start: [Errno 2]"));
        assert!(runner.wait_ready(&[i64::from(free_port().unwrap())], 0.2, &[]).is_err());
    }

    /// Against the pinned Xray of the host when there is one (the lab host has the installer's
    /// copy): its version line, a Reality keypair read off `xray x25519`, and `-test` of what this
    /// renderer writes — the golden scenario, a geosite rule and a code the lists do not know.
    #[test]
    fn the_pinned_xray_reads_what_the_renderer_writes() {
        let dir = PathBuf::from(
            std::env::var("XRAY_ROUTER_TEST_BIN_DIR")
                .unwrap_or_else(|_| "/usr/local/lib/proxy-control/xray-router".into()),
        );
        if !dir.join("xray").is_file() {
            eprintln!("no pinned xray in {}: skipped", dir.display());
            return;
        }
        let runner = SubprocessXrayRunner::new(dir.join("xray"), dir.clone());
        assert!(runner.version().unwrap().starts_with("Xray "));
        let (private, public) = runner.x25519().unwrap();
        assert!(crate::intent::is_public_key(&private) && crate::intent::is_public_key(&public) && private != public);
        let work = std::env::temp_dir().join(format!("xr-pinned-{}", std::process::id()));
        std::fs::create_dir_all(&work).unwrap();
        let ingresses = vec![
            crate::render::Ingress::new("naive", 45101, "naive-abc", &"p".repeat(32)),
            crate::render::Ingress::new("mieru", 45102, "mieru-def", &"q".repeat(32)),
        ];
        let document = |code: &str| {
            crate::intent::validate_document(
                &serde_json::json!({"schema": 1, "default": {"action": "egress", "egress": "warp"},
                "rules": [{"geosites": [code], "domains": ["example.com"], "ports": [25], "action": "block"}]}),
            )
            .unwrap()
        };
        for (code, accepted) in [("category-ads-all", true), ("no-such-code-anywhere", false)] {
            let input = crate::render::RenderInput {
                intents: [("naive".to_string(), document(code))].into_iter().collect(),
                ingresses: ingresses.clone(),
                warp_url: Some("socks5://127.0.0.1:45000"),
                ..Default::default()
            };
            let path = work.join(format!("{code}.json"));
            std::fs::write(&path, crate::render::config_bytes(&crate::render::render_config(&input).unwrap())).unwrap();
            let tested = runner.test(&path, None);
            assert_eq!(tested.is_ok(), accepted, "{code}: {tested:?}");
            // Xray 26.10 words an unknown code "failed to check code … from geosite.dat", which the
            // Python manager's `code not found in` pattern did not name either: `egress_invalid`.
            if let Err(Error::Xray(message)) = tested {
                assert!(message.contains("geosite.dat"), "{message}");
            }
        }
        let _ = std::fs::remove_dir_all(work);
    }

    #[test]
    fn a_real_process_starts_and_stops() {
        let dir = std::env::temp_dir().join(format!("xr-runner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("xray");
        std::fs::write(&script, "#!/bin/sh\n[ \"$1\" = version ] && { echo 'Xray 26.3.27 (Xray, Penetrates Everything.)'; exit 0; }\n[ \"$2\" = -test ] && { echo \"bad $XRAY_LOCATION_ASSET\" >&2; exit 23; }\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let runner = SubprocessXrayRunner::new(script, dir.join("assets"));
        assert_eq!(runner.version().unwrap(), "Xray 26.3.27 (Xray, Penetrates Everything.)");
        let refused = runner.test(Path::new("/x.json"), Some(Path::new("/candidates"))).unwrap_err();
        assert_eq!(refused, Error::Xray("bad /candidates".into()));
        let handle = runner.start(Path::new("/x.json"), None).unwrap();
        assert!(runner.alive(&handle));
        runner.stop(&handle);
        assert!(!runner.alive(&handle));
        let _ = std::fs::remove_dir_all(dir);
    }
}
