//! Read-only Caddy CONNECT meter; independent from health probes and quota accounting.
use crate::error::{Error, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

const LIMIT: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(1);
pub const SOCKET: &str = "/run/caddy-naive/live.sock";

fn invalid() -> Error {
    Error::runtime("live meter unavailable")
}

/// Whitelist a small, versioned non-credential-bearing snapshot.
pub fn validate(value: &Value) -> Result<Value> {
    let epoch = value.get("process_epoch").and_then(Value::as_str).ok_or_else(invalid)?;
    if value.get("schema").and_then(Value::as_u64) != Some(1)
        || value.get("semantics").and_then(Value::as_str) != Some("authenticated_connect_payload")
        || epoch.is_empty()
        || epoch.len() > 128
    {
        return Err(invalid());
    }
    let number = |key| value.get(key).and_then(Value::as_u64).ok_or_else(invalid);
    Ok(json!({"schema":1,"semantics":"authenticated_connect_payload","process_epoch":epoch,
        "sampled_at_ms":number("sampled_at_ms")?,"upload_bytes":number("upload_bytes")?,
        "download_bytes":number("download_bytes")?,"active_tunnels":number("active_tunnels")?}))
}

/// A full Unix listen backlog must fail rather than hold a manager worker forever.
fn connect(socket: &Path, deadline: Instant) -> Result<UnixStream> {
    let bytes = socket.as_os_str().as_bytes();
    // sockaddr_un is a plain C struct with an integer family and byte array.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(invalid());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (out, byte) in address.sun_path.iter_mut().zip(bytes) {
        *out = *byte as libc::c_char;
    }
    // OwnedFd closes every error path; CLOEXEC prevents leaking it to child processes.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(invalid());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let length = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    let result = unsafe { libc::connect(fd.as_raw_fd(), (&address as *const libc::sockaddr_un).cast(), length) };
    if result < 0 {
        // AF_UNIX reports EAGAIN for a full backlog: it is not an in-progress connect.
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(invalid());
        }
        loop {
            let wait = deadline.checked_duration_since(Instant::now()).ok_or_else(invalid)?;
            let mut pollfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
            let ready = unsafe { libc::poll(&mut pollfd, 1, wait.as_millis().min(i32::MAX as u128).max(1) as i32) };
            if ready < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if ready <= 0 {
                return Err(invalid());
            }
            let mut error: libc::c_int = 0;
            let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut libc::c_int).cast(),
                    &mut size,
                )
            } < 0
                || error != 0
            {
                return Err(invalid());
            }
            break;
        }
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false).map_err(|_| invalid())?;
    Ok(stream)
}

/// No manager/state/accounting locks, no probe, and no cached zero on failure.
pub fn read(socket: &Path) -> Result<Value> {
    let deadline = Instant::now() + TIMEOUT;
    let mut stream = connect(socket, deadline)?;
    stream
        .set_write_timeout(Some(deadline.checked_duration_since(Instant::now()).ok_or_else(invalid)?))
        .map_err(|_| invalid())?;
    stream
        .write_all(b"GET /v1/live HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|_| invalid())?;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or_else(invalid)?;
        stream.set_read_timeout(Some(remaining)).map_err(|_| invalid())?;
        let count = stream.read(&mut buffer).map_err(|_| invalid())?;
        if count == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..count]);
        if raw.len() > LIMIT {
            return Err(invalid());
        }
    }
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(invalid)?;
    let header = std::str::from_utf8(&raw[..at]).map_err(|_| invalid())?;
    let mut lines = header.split("\r\n");
    if lines.next().and_then(|line| line.split_whitespace().nth(1)) != Some("200") {
        return Err(invalid());
    }
    let headers: Vec<_> = lines.filter_map(|line| line.split_once(':')).collect();
    if headers.iter().any(|(key, _)| key.eq_ignore_ascii_case("transfer-encoding")) {
        return Err(invalid());
    }
    let length = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, n)| n.trim().parse::<usize>().ok())
        .ok_or_else(invalid)?;
    let body = &raw[at + 4..];
    if body.len() != length {
        return Err(invalid());
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| invalid())?;
    validate(&value)
}

#[cfg(test)]
mod socket_tests {
    use super::*;
    use crate::tests::{self, TestHooks};
    use std::os::unix::net::UnixListener;

    fn sample() -> Value {
        json!({"schema":1,"semantics":"authenticated_connect_payload","process_epoch":"test",
            "sampled_at_ms":2000,"upload_bytes":123,"download_bytes":456,"active_tunnels":1})
    }
    fn reply(listener: UnixListener, payload: Vec<u8>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let n = conn.read(&mut request).unwrap();
            assert!(std::str::from_utf8(&request[..n]).unwrap().starts_with("GET /v1/live HTTP/1.1"));
            conn.write_all(&payload).unwrap();
        })
    }
    fn http(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
    }
    #[test]
    fn authenticated_route_reads_live_socket_without_probing_or_accounting() {
        let dir = tests::tempdir("live-route");
        let socket = dir.join("meter.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let hooks = TestHooks::default();
        let mut settings = crate::service::Settings::new(
            dir.join("absent-caddy"),
            dir.join("absent-state"),
            dir.join("backups"),
            "naive.example.com",
        );
        settings.live_socket = socket;
        let manager = tests::manager_with(&dir, &hooks, settings);
        let api = tests::serve(&manager, &dir, "test-token");
        assert_eq!(tests::call(&api, "GET", "/v1/traffic/live", None, None).0, 401);
        let source = reply(listener, http(&sample().to_string()));
        let (status, body) = tests::call(&api, "GET", "/v1/traffic/live", None, Some("test-token"));
        assert_eq!(status, 200);
        assert_eq!(tests::parse(&body), sample());
        source.join().unwrap();
        assert_eq!(tests::call(&api, "GET", "/v1/traffic/live", None, Some("test-token")).0, 503);
        assert!(manager.traffic().is_none());
        let state = hooks.0.lock().unwrap();
        assert_eq!(state.probes, 0);
        assert_eq!(state.reloads, 0);
        assert!(state.validated.is_empty());
    }
    #[test]
    fn bounded_reader_rejects_truncated_or_oversized_responses() {
        for (name, raw) in [
            ("truncated", b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec()),
            ("oversized", http(&"x".repeat(LIMIT))),
            ("wrong-source", http("{}")),
        ] {
            let dir = tests::tempdir(name);
            let socket = dir.join("meter.sock");
            let source = reply(UnixListener::bind(&socket).unwrap(), raw);
            assert!(read(&socket).is_err());
            source.join().unwrap();
        }
    }
}

#[cfg(test)]
mod backlog_test {
    use super::*;
    use crate::tests;
    use std::os::unix::net::UnixListener;
    #[test]
    fn full_backlog_does_not_hold_a_manager_worker() {
        let dir = tests::tempdir("live-backlog");
        let path = dir.join("live.sock");
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let _queued = UnixStream::connect(&path).unwrap();
        let start = Instant::now();
        assert!(read(&path).is_err());
        assert!(start.elapsed() < TIMEOUT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_only_versioned_payload_counters_and_strips_extra_fields() {
        let mut sample = json!({"schema":1,"semantics":"authenticated_connect_payload",
            "process_epoch":"test-process","sampled_at_ms":1234,"upload_bytes":42,
            "download_bytes":84,"active_tunnels":2,"username":"must-not-escape"});
        let clean = validate(&sample).unwrap();
        assert!(clean.get("username").is_none());
        assert_eq!(clean["upload_bytes"], 42);
        for key in ["sampled_at_ms", "upload_bytes", "download_bytes", "active_tunnels"] {
            sample[key] = json!(-1);
            assert!(validate(&sample).is_err());
            sample[key] = json!(0);
        }
        sample["semantics"] = json!("kernel");
        assert!(validate(&sample).is_err());
    }

    #[test]
    fn missing_socket_is_unavailable_without_state_or_probe() {
        assert!(read(std::path::Path::new("/nonexistent/naive-live.sock")).is_err());
    }
}
