//! Everything the manager does to the machine, behind one injectable seam.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pc_common::process::run;
use serde_json::Value;

pub const AMNEZIAWG_BINARY: &str = "/usr/local/bin/amneziawg-go";
pub const UAPI_DIR: &str = "/var/run/amneziawg";
pub const NFT_TABLE: &str = "awg_manager";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const UAPI_TIMEOUT: Duration = Duration::from_secs(5);

/// An ip/nft command failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostError(pub String);

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The amneziawg-go control socket is unreachable or returned a non-zero errno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UapiError(pub String);

impl std::fmt::Display for UapiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A started amneziawg-go process, as `subprocess.Popen` offered it.
pub trait Proc: Send {
    /// The exit code once it exited (`-signal` when killed by one), `None` while it runs.
    fn poll(&mut self) -> Option<i32>;
    fn terminate(&mut self);
    fn kill(&mut self);
    /// Waits up to `timeout`; `Err` when it is still running.
    fn wait(&mut self, timeout: Duration) -> Result<i32, ()>;
}

pub trait Host: Send + Sync {
    fn start_process(&self, iface: &str, log_level: &str) -> io::Result<Box<dyn Proc>>;
    fn ip(&self, args: &[&str]) -> Result<(), HostError>;
    /// `ip -j …` parsed (the egress reads its own rules and the router's device back this way).
    fn ip_json(&self, args: &[&str]) -> Result<Vec<Value>, HostError>;
    fn nft_apply(&self, script: &str) -> Result<(), HostError>;
    fn nft_delete(&self);
    fn uapi_set(&self, iface: &str, body: &str) -> Result<(), UapiError>;
    fn uapi_get(&self, iface: &str) -> Result<String, UapiError>;
    fn ip_forward_enabled(&self) -> bool;
}

/// One request on an amneziawg-go control socket; the reply minus its `errno=0` trailer.
pub fn uapi_exchange(path: &str, request: &[u8], timeout: Duration) -> Result<String, UapiError> {
    let unavailable = |err: io::Error| UapiError(format!("control socket unavailable: {err}"));
    let mut sock = UnixStream::connect(path).map_err(unavailable)?;
    sock.set_read_timeout(Some(timeout)).map_err(unavailable)?;
    sock.set_write_timeout(Some(timeout)).map_err(unavailable)?;
    sock.write_all(request).map_err(unavailable)?;
    let mut data = Vec::new();
    let mut chunk = vec![0u8; 65536];
    // The reply always ends with `errno=<n>\n\n`.
    while !(data.ends_with(b"\n\n") && data.windows(6).any(|w| w == b"errno=")) {
        let read = sock.read(&mut chunk).map_err(unavailable)?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&data).into_owned();
    let trimmed = text.trim_end_matches('\n');
    let tail = trimmed.rsplit('\n').next().unwrap_or("");
    if !tail.starts_with("errno=") {
        return Err(UapiError("truncated control reply".into()));
    }
    if tail != "errno=0" {
        return Err(UapiError(format!("control socket replied {tail}")));
    }
    Ok(text[..text.rfind("errno=").expect("the tail holds errno=")].to_string())
}

/// A real child process.
pub struct ChildProc(Child);

impl Proc for ChildProc {
    fn poll(&mut self) -> Option<i32> {
        use std::os::unix::process::ExitStatusExt;
        match self.0.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or_else(|| -status.signal().unwrap_or(0))),
            _ => None,
        }
    }

    fn terminate(&mut self) {
        if self.poll().is_none() {
            // SAFETY: kill(2) on our own child, which is not reaped while poll() says it runs.
            unsafe { libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM) };
        }
    }

    fn kill(&mut self) {
        if self.poll().is_none() {
            let _ = self.0.kill();
        }
    }

    fn wait(&mut self, timeout: Duration) -> Result<i32, ()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(code) = self.poll() {
                return Ok(code);
            }
            if Instant::now() >= deadline {
                return Err(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

pub struct RealHost;

impl RealHost {
    fn run(argv: &[&str], stdin: Option<&str>) -> Result<String, HostError> {
        match run(argv, stdin.map(str::as_bytes), COMMAND_TIMEOUT) {
            Err(err) => Err(HostError(format!("{} failed to run: {err}", argv[0]))),
            Ok(out) if !out.success() => {
                let stderr: String = out.stderr_text().trim().chars().take(300).collect();
                Err(HostError(format!("{} failed: {stderr}", argv[..argv.len().min(3)].join(" "))))
            }
            Ok(out) => Ok(out.stdout_text()),
        }
    }
}

impl Host for RealHost {
    fn start_process(&self, iface: &str, log_level: &str) -> io::Result<Box<dyn Proc>> {
        let child = Command::new(AMNEZIAWG_BINARY)
            .args(["-f", iface])
            .env("LOG_LEVEL", log_level)
            .stdin(Stdio::null())
            .spawn()?;
        Ok(Box::new(ChildProc(child)))
    }

    fn ip(&self, args: &[&str]) -> Result<(), HostError> {
        let argv: Vec<&str> = std::iter::once("ip").chain(args.iter().copied()).collect();
        Self::run(&argv, None).map(|_| ())
    }

    fn ip_json(&self, args: &[&str]) -> Result<Vec<Value>, HostError> {
        let argv: Vec<&str> = ["ip", "-j"].into_iter().chain(args.iter().copied()).collect();
        let stdout = match run(&argv, None, COMMAND_TIMEOUT) {
            Err(err) => return Err(HostError(format!("ip failed to run: {err}"))),
            Ok(out) if !out.success() => {
                let stderr: String = out.stderr_text().trim().chars().take(300).collect();
                return Err(HostError(format!("ip -j {} failed: {stderr}", args[..args.len().min(3)].join(" "))));
            }
            Ok(out) => out.stdout_text(),
        };
        let text = if stdout.is_empty() { "[]" } else { stdout.as_str() };
        match serde_json::from_str::<Value>(text) {
            Ok(Value::Array(items)) => Ok(items),
            Ok(_) => Ok(Vec::new()),
            Err(_) => Err(HostError("ip -j answered something that is not JSON".into())),
        }
    }

    fn nft_apply(&self, script: &str) -> Result<(), HostError> {
        Self::run(&["nft", "-f", "-"], Some(script)).map(|_| ())
    }

    fn nft_delete(&self) {
        // Already absent is fine.
        let _ = Self::run(&["nft", "delete", "table", "inet", NFT_TABLE], None);
    }

    fn uapi_set(&self, iface: &str, body: &str) -> Result<(), UapiError> {
        let request = [b"set=1\n", body.as_bytes(), b"\n"].concat();
        uapi_exchange(&format!("{UAPI_DIR}/{iface}.sock"), &request, UAPI_TIMEOUT).map(|_| ())
    }

    fn uapi_get(&self, iface: &str) -> Result<String, UapiError> {
        uapi_exchange(&format!("{UAPI_DIR}/{iface}.sock"), b"get=1\n\n", UAPI_TIMEOUT)
    }

    fn ip_forward_enabled(&self) -> bool {
        std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").is_ok_and(|text| text.trim() == "1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn serve_once(path: &std::path::Path, reply: &'static [u8]) -> std::thread::JoinHandle<Vec<u8>> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let read = stream.read(&mut buf).unwrap();
            stream.write_all(reply).unwrap();
            buf.truncate(read);
            buf
        })
    }

    #[test]
    fn uapi_exchange_reads_to_the_errno_trailer() {
        let dir = crate::state::tests::tempdir("uapi");
        let ok = dir.join("ok.sock");
        let server = serve_once(&ok, b"private_key=aa\nlisten_port=1\nerrno=0\n\n");
        let reply = uapi_exchange(ok.to_str().unwrap(), b"get=1\n\n", UAPI_TIMEOUT).unwrap();
        assert_eq!(reply, "private_key=aa\nlisten_port=1\n");
        assert_eq!(server.join().unwrap(), b"get=1\n\n");
        let bad = dir.join("bad.sock");
        let _server = serve_once(&bad, b"errno=22\n\n");
        let err = uapi_exchange(bad.to_str().unwrap(), b"set=1\n\n", UAPI_TIMEOUT).unwrap_err();
        assert_eq!(err.0, "control socket replied errno=22");
        let cut = dir.join("cut.sock");
        let _server = serve_once(&cut, b"private_key=aa\n");
        assert_eq!(
            uapi_exchange(cut.to_str().unwrap(), b"get=1\n\n", UAPI_TIMEOUT).unwrap_err().0,
            "truncated control reply"
        );
        assert!(uapi_exchange(dir.join("none.sock").to_str().unwrap(), b"get=1\n\n", UAPI_TIMEOUT)
            .unwrap_err()
            .0
            .starts_with("control socket unavailable"));
    }

    #[test]
    fn a_real_child_is_polled_terminated_and_reaped() {
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let mut proc = ChildProc(child);
        assert_eq!(proc.poll(), None);
        proc.terminate();
        assert_eq!(proc.wait(Duration::from_secs(5)), Ok(-libc::SIGTERM));
        assert_eq!(proc.poll(), Some(-libc::SIGTERM));
        proc.kill(); // already gone: a no-op
    }
}
