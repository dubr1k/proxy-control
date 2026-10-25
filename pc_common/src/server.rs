//! A thread-per-connection HTTP/1.1 server on a Unix socket.
//!
//! The managers answer a handful of small requests from the panel, so the server stays
//! deliberately plain: one request per connection, bounded headers and body, a cap on
//! concurrent connections, and a shutdown that wakes the accept loop by connecting to itself.

use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::error::ApiError;
use crate::http::{Body, Request, Response};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 64;

#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub socket_path: PathBuf,
    pub mode: u32,
    /// Owner of the socket file; `None` keeps the process's own.
    pub uid: Option<u32>,
    /// Group of the socket file; `None` keeps the process's own.
    pub gid: Option<u32>,
    pub max_body: usize,
    pub io_timeout: Duration,
    pub max_connections: usize,
}

impl ServerOptions {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            mode: 0o600,
            uid: None,
            gid: None,
            max_body: 32 * 1024,
            io_timeout: Duration::from_secs(30),
            max_connections: 64,
        }
    }
}

pub type Handler = dyn Fn(&Request) -> Response + Send + Sync;

pub struct UdsServer {
    listener: UnixListener,
    options: ServerOptions,
    stop: Arc<AtomicBool>,
}

/// Stops a running [`UdsServer`] from any thread or signal handler thread.
#[derive(Clone)]
pub struct ShutdownHandle {
    stop: Arc<AtomicBool>,
    socket_path: PathBuf,
}

impl ShutdownHandle {
    pub fn shutdown(&self) {
        if !self.stop.swap(true, Ordering::SeqCst) {
            // Wake the blocking accept; the loop sees the flag and returns.
            let _ = UnixStream::connect(&self.socket_path);
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

impl UdsServer {
    /// Binds the socket: creates its directory, replaces a stale socket file, then applies the
    /// mode and ownership before the first connection can be accepted.
    pub fn bind(options: ServerOptions) -> io::Result<Self> {
        let path = &options.socket_path;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let listener = UnixListener::bind(path)?;
        let prepared = std::fs::set_permissions(path, std::fs::Permissions::from_mode(options.mode)).and_then(|()| {
            match (options.uid, options.gid) {
                (None, None) => Ok(()),
                (uid, gid) => std::os::unix::fs::chown(path, uid, gid),
            }
        });
        if let Err(err) = prepared {
            let _ = std::fs::remove_file(path);
            return Err(err);
        }
        Ok(Self { listener, options, stop: Arc::new(AtomicBool::new(false)) })
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle { stop: self.stop.clone(), socket_path: self.options.socket_path.clone() }
    }

    pub fn socket_path(&self) -> &Path {
        &self.options.socket_path
    }

    /// Serves until [`ShutdownHandle::shutdown`]; removes the socket file on return.
    pub fn serve(self, handler: Arc<Handler>) {
        let active = Arc::new(AtomicUsize::new(0));
        for stream in self.listener.incoming() {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = stream else { continue };
            if active.load(Ordering::SeqCst) >= self.options.max_connections {
                let mut stream = stream;
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let busy = ApiError::new(503, "busy", "manager is busy").into_response();
                let _ = stream.write_all(&busy.encode());
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);
            let handler = handler.clone();
            let active = active.clone();
            let options = self.options.clone();
            let spawned = std::thread::Builder::new().name("conn".into()).spawn(move || {
                handle_connection(stream, &options, handler.as_ref());
                active.fetch_sub(1, Ordering::SeqCst);
            });
            if spawned.is_err() {
                log::warn!("cannot start a connection thread");
            }
        }
        let _ = std::fs::remove_file(&self.options.socket_path);
    }
}

/// Stops the server on SIGTERM or SIGINT, like the Python managers' signal handlers.
pub fn shutdown_on_signals(handle: ShutdownHandle, also: impl Fn() + Send + 'static) -> io::Result<()> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    let mut signals = signal_hook::iterator::Signals::new([SIGTERM, SIGINT])?;
    std::thread::Builder::new().name("signals".into()).spawn(move || {
        if signals.forever().next().is_some() {
            also();
            handle.shutdown();
        }
    })?;
    Ok(())
}

fn handle_connection(mut stream: UnixStream, options: &ServerOptions, handler: &Handler) {
    let _ = stream.set_read_timeout(Some(options.io_timeout));
    let _ = stream.set_write_timeout(Some(options.io_timeout));
    let response = match read_request(&mut stream, options.max_body) {
        Ok(Some(request)) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&request))) {
            Ok(response) => response,
            Err(_) => {
                log::error!("manager operation failed: handler panicked");
                ApiError::internal().into_response()
            }
        },
        Ok(None) => return,
        Err(_) => ApiError::new(400, "bad_request", "bad request").into_response(),
    };
    let _ = stream.write_all(&response.encode());
    let _ = stream.flush();
    linger(&mut stream);
}

/// Closes gracefully: a peer still sending a body the server did not read (one over the limit)
/// would otherwise get a reset instead of the response already written.
fn linger(stream: &mut UnixStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut sink = [0u8; 8192];
    let mut drained = 0usize;
    while drained < 1024 * 1024 {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// Reads one request. `Ok(None)` means the peer closed or stalled before sending a full head.
pub(crate) fn read_request(stream: &mut impl Read, max_body: usize) -> io::Result<Option<Request>> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let head_len = loop {
        if let Some(end) = find_head_end(&buffer) {
            break end;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "header too large"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
            Err(err) => return Err(err),
        }
    };
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed.parse(&buffer[..head_len]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed request")),
    }
    let method = parsed.method.unwrap_or("").to_string();
    let target = parsed.path.unwrap_or("").to_string();
    let headers: Vec<(String, String)> =
        parsed.headers.iter().map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned())).collect();
    let declared = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>());
    let body = match declared {
        None => Body::Read(Vec::new()),
        Some(Ok(length)) if length <= max_body => {
            let mut body = buffer[head_len..].to_vec();
            while body.len() < length {
                match stream.read(&mut chunk) {
                    Ok(0) => return Ok(None),
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                        return Ok(None)
                    }
                    Err(err) => return Err(err),
                }
            }
            body.truncate(length);
            Body::Read(body)
        }
        Some(_) => Body::Invalid,
    };
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (target.clone(), None),
    };
    // An absolute-form target (`http://host/path`) reaches the same routes as its path, as
    // `urlsplit(self.path).path` did.
    let path = match path.split_once("://") {
        Some((_, rest)) => rest.find('/').map(|i| rest[i..].to_string()).unwrap_or_else(|| "/".into()),
        None => path,
    };
    Ok(Some(Request { method, target, path, query, headers, body }))
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client;
    use serde_json::json;

    fn parse(raw: &[u8], max_body: usize) -> Request {
        read_request(&mut &raw[..], max_body).unwrap().unwrap()
    }

    #[test]
    fn parses_head_body_and_query() {
        let req = parse(b"POST /v1/x?a=1 HTTP/1.1\r\nHost: m\r\nContent-Length: 2\r\n\r\n{}", 10);
        assert_eq!((req.method.as_str(), req.path.as_str()), ("POST", "/v1/x"));
        assert_eq!(req.query.as_deref(), Some("a=1"));
        assert_eq!(req.body, Body::Read(b"{}".to_vec()));
        assert_eq!(req.header("host"), Some("m"));
    }

    #[test]
    fn oversized_or_invalid_length_leaves_body_invalid() {
        let big = parse(b"POST / HTTP/1.1\r\nContent-Length: 11\r\n\r\n", 10);
        assert_eq!(big.body, Body::Invalid);
        let bad = parse(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 10);
        assert_eq!(bad.body, Body::Invalid);
    }

    #[test]
    fn absolute_targets_route_by_path() {
        let req = parse(b"GET http://manager/v1/health HTTP/1.1\r\n\r\n", 10);
        assert_eq!(req.path, "/v1/health");
    }

    #[test]
    fn truncated_head_is_no_request() {
        assert!(read_request(&mut &b"GET / HTTP/1.1\r\n"[..], 10).unwrap().is_none());
    }

    #[test]
    fn serves_over_a_real_socket_and_shuts_down() {
        let dir = std::env::temp_dir().join(format!("pc-common-{}", std::process::id()));
        let socket = dir.join("nested/manager.sock");
        let mut options = ServerOptions::new(&socket);
        options.mode = 0o660;
        let server = UdsServer::bind(options).unwrap();
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        let handle = server.shutdown_handle();
        let thread = std::thread::spawn(move || {
            server.serve(Arc::new(|req: &Request| {
                if let Err(denied) = crate::check_token(req, "X-Test-Token", "t".repeat(32).as_str()) {
                    return denied;
                }
                match req.json_object() {
                    Ok(body) => Response::json(200, &json!({"path": req.path, "body": body})),
                    Err(err) => err.into_response(),
                }
            }))
        });
        let token = "t".repeat(32);
        let ok = client::request(
            &socket,
            "POST",
            "/v1/echo",
            &[("X-Test-Token", &token)],
            Some(b"{\"a\":1}"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(ok.status, 200);
        assert_eq!(ok.json().unwrap(), json!({"path": "/v1/echo", "body": {"a": 1}}));
        let denied = client::request(&socket, "GET", "/v1/echo", &[], None, Duration::from_secs(5)).unwrap();
        assert_eq!(
            (denied.status, denied.json().unwrap()),
            (401, json!({"detail": "unauthorized", "code": "unauthorized"}))
        );
        handle.shutdown();
        thread.join().unwrap();
        assert!(!socket.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_panicking_handler_answers_500_without_detail() {
        let dir = std::env::temp_dir().join(format!("pc-common-panic-{}", std::process::id()));
        let socket = dir.join("m.sock");
        let server = UdsServer::bind(ServerOptions::new(&socket)).unwrap();
        let handle = server.shutdown_handle();
        let thread = std::thread::spawn(move || server.serve(Arc::new(|_: &Request| panic!("secret detail"))));
        let reply = client::request(&socket, "GET", "/", &[], None, Duration::from_secs(5)).unwrap();
        assert_eq!(
            (reply.status, reply.json().unwrap()),
            (500, json!({"detail": "manager operation failed", "code": "internal_error"}))
        );
        handle.shutdown();
        thread.join().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
