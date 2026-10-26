//! A panel served in-process on a Unix socket, and raw HTTP/1.1 over it.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use panel_core::settings::Settings;
use panel_web::server::Listen;
use panel_web::AppState;

pub struct Panel {
    pub dir: PathBuf,
    pub socket: PathBuf,
    pub state: AppState,
    runtime: Option<tokio::runtime::Runtime>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Panel {
    /// The server's runtime.
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.as_ref().expect("running").handle().clone()
    }
}

impl Drop for Panel {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(std::time::Duration::from_secs(10));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn static_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../static")
}

/// Starts a panel with these extra environment variables (on top of a database, a keyring, the
/// test hosts and `PANEL_COOKIE_SECURE=false`).
pub fn start(extra: &[(&str, &str)]) -> Panel {
    start_with(extra, |_| {})
}

/// [`start`] with the hard-coded settings changed (the `PANEL_TEST_*` knobs of the harness).
pub fn start_with(extra: &[(&str, &str)], tweak: impl FnOnce(&mut Settings)) -> Panel {
    let dir = std::env::temp_dir().join(format!("panel-web-test-{}", panel_core::ids::token_hex(6)));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("master-key");
    panel_secrets::keyring::Keyring::generate().save(&key).unwrap();
    std::fs::write(dir.join("VERSION"), "9.9.9\n").unwrap();
    let none = dir.join("none.sock").to_string_lossy().into_owned();
    let mut env: HashMap<String, String> = [
        ("PANEL_DATABASE", dir.join("panel.db").to_string_lossy().into_owned()),
        ("PANEL_MASTER_KEY_FILE", key.to_string_lossy().into_owned()),
        ("PANEL_ALLOWED_HOSTS", "testserver".to_string()),
        ("PANEL_COOKIE_SECURE", "false".to_string()),
        ("PANEL_METRICS_ENABLED", "false".to_string()),
        ("PANEL_VERSION_FILE", dir.join("VERSION").to_string_lossy().into_owned()),
        ("NAIVE_MANAGER_SOCKET", none.clone()),
        ("MIERU_MANAGER_SOCKET", none.clone()),
        ("AWG_MANAGER_SOCKET", none.clone()),
        ("TRUSTTUNNEL_MANAGER_SOCKET", none.clone()),
        ("VERSION_AGENT_SOCKET", none),
        ("TELEMT_API_URL", "http://127.0.0.1:9".to_string()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value))
    .collect();
    for (name, value) in extra {
        env.insert((*name).to_string(), (*value).to_string());
    }
    let mut settings = Settings::from_lookup(|name| Ok(env.get(name).cloned())).unwrap();
    tweak(&mut settings);
    let state = panel_web::wiring::build(settings, static_dir()).unwrap();
    let socket = dir.join("panel.sock");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = state.clone();
    let listen = Listen::Unix(socket.clone());
    runtime.spawn(async move {
        panel_web::run(served, listen, async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Panel { dir, socket, state, runtime: Some(runtime), stop: Some(stop) }
}

/// The raw answer to a raw request (the request should carry `Connection: close`).
pub fn exchange(socket: &Path, raw: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30))).unwrap();
    if let Err(error) = stream.write_all(raw) {
        // A declared body-limit refusal can close the connection before the client has sent the
        // entire body. The response (still parsed and checked by the caller), not write_all, is
        // the HTTP verdict. Other I/O failures are not valid early refusals.
        assert!(
            matches!(error.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset),
            "sending raw HTTP request: {error}"
        );
    }
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

/// Status, headers (lower-cased names, in order) and the de-chunked body.
pub fn parse(raw: &[u8], head: bool) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("a complete head");
    let head_text: String = raw[..split].iter().map(|byte| char::from(*byte)).collect();
    let mut body = raw[split + 4..].to_vec();
    let mut lines = head_text.split("\r\n");
    let status: u16 = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers: Vec<(String, String)> = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            (name.trim().to_ascii_lowercase(), value.trim().to_string())
        })
        .collect();
    if headers.iter().any(|(name, value)| name == "transfer-encoding" && value.contains("chunked")) {
        let mut decoded = Vec::new();
        let mut rest = &body[..];
        loop {
            let end = rest.windows(2).position(|window| window == b"\r\n").unwrap();
            let size_text = String::from_utf8_lossy(&rest[..end]).to_string();
            let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16).unwrap();
            rest = &rest[end + 2..];
            if size == 0 {
                break;
            }
            decoded.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
        body = decoded;
    }
    if head {
        body.clear();
    }
    (status, headers, body)
}

/// One answer, parsed.
#[derive(Debug, Clone)]
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(&self.body)))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    /// The value a `Set-Cookie` gives `name`.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.headers.iter().filter(|(key, _)| key == "set-cookie").find_map(|(_, value)| {
            value.strip_prefix(&format!("{name}=")).map(|rest| rest.split(';').next().unwrap_or_default().to_string())
        })
    }
}

/// A browser-like client: a cookie jar and `Host: testserver`.
#[derive(Debug, Clone, Default)]
pub struct Client {
    pub cookies: Vec<(String, String)>,
}

impl Client {
    pub fn set_cookie(&mut self, name: &str, value: &str) {
        self.cookies.retain(|(key, _)| key != name);
        if !value.is_empty() && value != "\"\"" {
            self.cookies.push((name.to_string(), value.to_string()));
        }
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.cookies.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone())
    }

    /// Sends one request; `headers` are extra header lines; the answer's cookies go into the jar.
    pub fn send(
        &mut self,
        panel: &Panel,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Answer {
        let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n");
        if !self.cookies.is_empty() {
            let jar: Vec<String> = self.cookies.iter().map(|(key, value)| format!("{key}={value}")).collect();
            raw.push_str(&format!("Cookie: {}\r\n", jar.join("; ")));
        }
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = body {
            raw.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
        }
        raw.push_str("\r\n");
        if let Some(body) = body {
            raw.push_str(body);
        }
        let (status, headers, body) = parse(&exchange(&panel.socket, raw.as_bytes()), method == "HEAD");
        let answer = Answer { status, headers, body };
        for name in ["panel_session", "panel_csrf"] {
            if let Some(value) = answer.cookie(name) {
                self.set_cookie(name, &value);
            }
        }
        answer
    }

    /// `login_user(client, username, password)` of the Python tests.
    pub fn login(&mut self, panel: &Panel, username: &str, password: &str) -> Answer {
        self.send(panel, "GET", "/login", &[], None);
        let csrf = self.cookie("panel_csrf").unwrap();
        let body = serde_json::json!({"username": username, "password": password}).to_string();
        self.send(panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(&body))
    }

    /// The session's CSRF header.
    pub fn csrf(&self) -> String {
        self.cookie("panel_csrf").unwrap_or_default()
    }
}

/// A header's first value.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}
