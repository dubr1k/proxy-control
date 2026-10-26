//! Test servers: a recording HTTP/1.1 endpoint on a Unix socket or a TCP port that answers every
//! request with a scripted reply and keeps the raw request bytes.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the server does with the next request.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Status and raw body (`Content-Length` is set; 204 gets `Content-Length: 0`).
    Answer(u16, Vec<u8>),
    /// Read the request, then close without a word.
    Close,
    /// Read the request, then say nothing for this long.
    Hang(Duration),
}

impl Reply {
    pub fn json(status: u16, body: serde_json::Value) -> Self {
        Reply::Answer(status, serde_json::to_vec(&body).unwrap())
    }
}

/// One recorded request.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub raw: Vec<u8>,
}

impl Recorded {
    pub fn parsed(&self) -> ParsedRequest {
        ParsedRequest::parse(&self.raw)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequest {
    pub line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ParsedRequest {
    pub fn parse(raw: &[u8]) -> Self {
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a complete head");
        let head = String::from_utf8(raw[..split].to_vec()).unwrap();
        let mut lines = head.split("\r\n");
        let line = lines.next().unwrap().to_string();
        let headers = lines
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.trim().to_ascii_lowercase(), value.trim().to_string())
            })
            .collect();
        Self { line, headers, body: raw[split + 4..].to_vec() }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

type Script = Arc<Mutex<Box<dyn FnMut(&ParsedRequest) -> Reply + Send>>>;

/// A scripted server; dropping it stops nothing (the accept thread ends with the process), which
/// is fine for tests that each use their own socket or port.
pub struct FakeServer {
    pub socket: Option<PathBuf>,
    pub address: Option<String>,
    requests: Arc<Mutex<Vec<Recorded>>>,
    script: Script,
    _dir: Option<TempDir>,
}

impl FakeServer {
    /// A Unix-socket server in a fresh temporary directory.
    pub fn unix() -> Self {
        let dir = TempDir::new("wp5-uds");
        let socket = dir.path().join("manager.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = Self::empty(Some(socket), None, Some(dir));
        let (requests, script) = (server.requests.clone(), server.script.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (requests, script) = (requests.clone(), script.clone());
                std::thread::spawn(move || serve(stream, &requests, &script));
            }
        });
        server
    }

    /// A TCP server on 127.0.0.1.
    pub fn tcp() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = Self::empty(None, Some(address), None);
        let (requests, script) = (server.requests.clone(), server.script.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (requests, script) = (requests.clone(), script.clone());
                std::thread::spawn(move || serve(stream, &requests, &script));
            }
        });
        server
    }

    fn empty(socket: Option<PathBuf>, address: Option<String>, dir: Option<TempDir>) -> Self {
        Self {
            socket,
            address,
            requests: Arc::new(Mutex::new(Vec::new())),
            script: Arc::new(Mutex::new(Box::new(|_| Reply::Answer(200, b"{}".to_vec())))),
            _dir: dir,
        }
    }

    pub fn socket(&self) -> &Path {
        self.socket.as_deref().unwrap()
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.address.as_deref().unwrap())
    }

    /// Answers every request with `reply`.
    pub fn always(&self, reply: Reply) {
        self.respond(move |_| reply.clone());
    }

    pub fn respond(&self, script: impl FnMut(&ParsedRequest) -> Reply + Send + 'static) {
        *self.script.lock().unwrap() = Box::new(script);
    }

    pub fn take(&self) -> Vec<Recorded> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

fn serve<S: Read + Write>(mut stream: S, requests: &Mutex<Vec<Recorded>>, script: &Script) {
    let mut raw = Vec::new();
    let mut buffer = [0u8; 65536];
    let head_end = loop {
        if let Some(position) = raw.windows(4).position(|w: &[u8]| w == b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let length = head
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while raw.len() < head_end + length {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
        }
    }
    let parsed = ParsedRequest::parse(&raw);
    requests.lock().unwrap().push(Recorded { raw });
    let reply = (script.lock().unwrap())(&parsed);
    match reply {
        Reply::Answer(status, body) => {
            let head = format!(
                "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
        Reply::Close => {}
        Reply::Hang(duration) => std::thread::sleep(duration),
    }
}

/// A temporary directory removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let mut bytes = [0u8; 8];
        std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut bytes).unwrap();
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("{prefix}-{name}"));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
